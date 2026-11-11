#!/usr/bin/env python3
"""Report a verified pin bump as one GitHub issue per family (#3420).

The pin-freshness workflow used to push a branch and open a PR with the
workflow token. That needs the repository setting that lets Actions create
pull requests, and the same setting lets workflows approve them, so it stays
off. Every run since 2026-10-05 failed, and each failure left an orphan branch
that blocked the next run.

This script opens no PR and pushes nothing. For one family it:

1. verifies the upstream release with `bump_pins`' own checks, in this process,
   so nothing is reported that did not verify;
2. keeps exactly one open issue, authored by `github-actions[bot]`, titled
   `pin-freshness: <family> <pinned> -> <latest>`: it creates it, edits the
   newest one to the latest version and closes any duplicates, or closes them
   all once the pin has caught up (or moved past what was reported);
3. writes a job-summary line and an annotation, and exits non-zero when
   verification or any gh call fails, so a run is never silently green.

Applying a bump stays a reviewed hand change: `bump_pins.py <family> --write`.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess
import sys

if __name__ == "__main__":  # run by path: puts skill/ on sys.path (#3505)
    import runpy
    runpy.run_path(os.path.join(os.path.dirname(os.path.realpath(__file__)), "_skill_bootstrap.py"))
import bump_pins
import issue_bot

# The gh plumbing lives in issue_bot (#3563); these names stay for this script's callers.
TRUSTED_PATH = issue_bot.TRUSTED_PATH
PROCESS_TIMEOUT = issue_bot.PROCESS_TIMEOUT
BOT = issue_bot.BOT
ERROR_TEXT_CAP = issue_bot.ERROR_TEXT_CAP
PAGE = issue_bot.PAGE
TITLE_PREFIX = "pin-freshness: "
BODY_CAP = 4000

_REPO = issue_bot.REPO
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_NUMBER = issue_bot.NUMBER
_ARCH = re.compile(r"[A-Z0-9]{1,16}\Z")

FAMILIES = ("tinyproxy", "rustup", "trivy", "rust-toolchain")
CAUGHT_UP = "The pin has caught up with upstream; closing."
DUPLICATE = "Duplicate of #%s; closing."
_DUPLICATE = re.compile(r"Duplicate of #[1-9][0-9]{0,9}; closing\.\Z")
_TITLE = re.compile(r"pin-freshness: (tinyproxy|rustup|trivy|rust-toolchain) "
                    r"(\S{1,80}) -> (\S{1,80})( \((checksums changed|pinned is ahead)\))?\Z")
REVIEW = {
    "tinyproxy": ("Review the image at docker.io/%s@<latest digest> and update PROXY_IMAGE in "
                  "%s by hand after testing the egress proxy on linux/amd64 and linux/arm64. "
                  "The digest is the SHA256 of the registry's multi-platform manifest, which "
                  "covers both architectures." % (bump_pins.PROXY_REPOSITORY,
                                                   bump_pins.PROXY_SOURCE)),
    "rustup": ("Both SHA256 values were read from upstream's .sha256 files and verified against "
               "the downloaded rustup-init artifacts. Apply with "
               "`python3 devtools/bump_pins.py rustup --write` and review the image build."),
    "trivy": ("Both SHA256 values came from the official Trivy release checksums file and "
              "matched the downloaded AMD64 and ARM64 archives. Apply with "
              "`python3 devtools/bump_pins.py trivy --write`. A Trivy bump can change scan "
              "results, so it needs the usual review."),
    "rust-toolchain": ("The version came from Rust's stable channel manifest after its companion "
                       "SHA256 matched the downloaded manifest. Apply with "
                       "`python3 devtools/bump_pins.py rust-toolchain --write`. A toolchain bump "
                       "can change scan results, so it needs the usual review."),
}


class Bump:
    """One family's verified state: what is pinned, what is latest, and the
    verified values behind `latest`. Every field is validated on construction,
    so nothing unvalidated from upstream can reach a gh argument."""

    def __init__(self, family: str, pinned: str, latest: str, values: dict[str, str],
                 stale: bool):
        if family not in FAMILIES:
            raise RuntimeError("unknown pin family")
        pattern = _DIGEST if family == "tinyproxy" else _VERSION
        for name, value in (("pinned", pinned), ("latest", latest)):
            if not isinstance(value, str) or not pattern.fullmatch(value):
                raise RuntimeError("%s %s value failed validation; refusing to report"
                                   % (family, name))
        for arch, sha in values.items():
            if not (isinstance(arch, str) and _ARCH.fullmatch(arch)
                    and isinstance(sha, str) and _SHA.fullmatch(sha)):
                raise RuntimeError("%s checksum failed validation; refusing to report" % family)
        self.family, self.pinned, self.latest = family, pinned, latest
        self.values, self.stale = dict(values), stale

    def _short(self, value: str) -> str:
        return value[:len("sha256:") + 12] if self.family == "tinyproxy" else value

    @property
    def kind(self) -> str:
        """'current', 'bump', or one of the two cases that are not a bump (#3557 review):
        'checksums' (same version, re-released archive: a supply-chain signal) and 'ahead'
        (the pin is newer than upstream's latest, e.g. a yanked release)."""
        if not self.stale:
            return "current"
        if self.family != "tinyproxy" and _version(self.pinned) > _version(self.latest):
            return "ahead"
        return "checksums" if self.pinned == self.latest else "bump"

    @property
    def warns(self) -> bool:
        return self.family == "tinyproxy" or self.kind in ("checksums", "ahead")

    @property
    def title(self) -> str:
        suffix = {"checksums": " (checksums changed)", "ahead": " (pinned is ahead)"}
        return "%s%s %s -> %s%s" % (TITLE_PREFIX, self.family, self._short(self.pinned),
                                    self._short(self.latest), suffix.get(self.kind, ""))

    @property
    def body(self) -> str:
        if self.kind == "ahead":
            lines = [("The pin-freshness workflow found the `%s` pin newer than upstream's "
                      + "latest release.") % self.family,
                     "", "- pinned: `%s`" % self.pinned,
                     "- upstream latest: `%s`" % self.latest, "",
                     ("Check whether `%s` was yanked upstream. Do not run `bump_pins.py %s "
                      + "--write`: it would downgrade the pin.") % (self.pinned, self.family)]
        else:
            if self.kind == "checksums":
                lead = ("The pin-freshness workflow found changed checksums for the same `%s` "
                        "version. Checksums changed for the same version: verify before "
                        "applying. A re-released upstream archive is a supply-chain signal, so "
                        "confirm its maintainers re-published it." % self.family)
            else:
                lead = "The pin-freshness workflow found a verified update for `%s`." % self.family
            lines = [lead, "", "- pinned: `%s`" % self.pinned, "- latest: `%s`" % self.latest]
            lines += ["- %s SHA256: `%s`" % (arch, sha)
                      for arch, sha in sorted(self.values.items())]
            lines += ["", REVIEW[self.family]]
        lines += ["", ("This issue is kept current by the workflow: it is edited when upstream "
                       + "moves again and closed once the pin catches up.")]
        return "\n".join(lines)


def _version(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split("."))


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def verify(family: str, dockerfile: str = "Dockerfile",
           proxy_source: str = bump_pins.PROXY_SOURCE) -> Bump:
    """The family's state, verified by `bump_pins`; raises before anything is reported."""
    if family == "tinyproxy":
        pinned = bump_pins.current_proxy_digest(_read(proxy_source))
        latest = bump_pins.latest_proxy_digest()
        return Bump(family, pinned, latest, {}, pinned != latest)
    text = _read(dockerfile)
    if family == "rustup":
        pinned, pinned_shas = bump_pins.current_rustup_pin(text)
        if not pinned or set(pinned_shas) != set(bump_pins.RUSTUP_TRIPLES):
            raise RuntimeError("rustup pin is incomplete in %s" % dockerfile)
        latest = bump_pins.latest_rustup_version()
        if latest == pinned:
            return Bump(family, pinned, latest, pinned_shas, False)
        if _version(pinned) > _version(latest):        # ahead: nothing to download or apply
            return Bump(family, pinned, latest, {}, True)
        return Bump(family, pinned, latest, bump_pins.verified_rustup_shas(latest), True)
    if family == "trivy":
        pinned, pinned_shas = bump_pins.current_trivy_pin(text)
        latest = bump_pins.latest_trivy_version()
        shas = bump_pins.verified_trivy_shas(latest)
        return Bump(family, pinned, latest, shas, latest != pinned or shas != pinned_shas)
    if family == "rust-toolchain":
        pinned = bump_pins.current_rust_toolchain_pin(text)
        latest = bump_pins.latest_rust_toolchain_version()
        return Bump(family, pinned, latest, {}, latest != pinned)
    raise RuntimeError("unknown pin family")


def _allowed_command(command: list[str]) -> bool:
    """Only the gh argv shapes this script emits; data stays in its own arguments."""
    if not isinstance(command, list) or not all(isinstance(a, str) and a for a in command):
        return False
    if command[:2] == ["gh", "api"] and len(command) == 3:
        return issue_bot.is_lookup(command[2], "open")
    if command[:3] == ["gh", "issue", "create"] and len(command) == 9:
        return (command[3] == "--repo" and bool(_REPO.fullmatch(command[4]))
                and command[5] == "--title" and bool(_TITLE.fullmatch(command[6]))
                and command[7] == "--body" and _body_ok(command[8]))
    if command[:3] == ["gh", "issue", "edit"] and len(command) == 10:
        return (bool(_NUMBER.fullmatch(command[3])) and command[4] == "--repo"
                and bool(_REPO.fullmatch(command[5])) and command[6] == "--title"
                and bool(_TITLE.fullmatch(command[7])) and command[8] == "--body"
                and _body_ok(command[9]))
    if command[:3] == ["gh", "issue", "close"] and len(command) == 8:
        return (bool(_NUMBER.fullmatch(command[3])) and command[4] == "--repo"
                and bool(_REPO.fullmatch(command[5])) and command[6] == "--comment"
                and (command[7] == CAUGHT_UP or bool(_DUPLICATE.fullmatch(command[7]))))
    return False


def _body_ok(body: str) -> bool:
    return (len(body) <= BODY_CAP and body.startswith("The pin-freshness workflow found ")
            and not any(ord(ch) < 32 and ch != "\n" for ch in body))


def _run(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    """Run only this script's gh commands, through issue_bot's trusted runner."""
    return issue_bot.run_gh(command, cwd, _allowed_command)


_error_text = issue_bot.error_text
_checked = issue_bot.checked


def bot_issues(repo: str, family: str, cwd: Path, runner) -> list[dict]:
    """This family's open issues authored by the workflow bot, newest first."""
    prefix = TITLE_PREFIX + family + " "
    return issue_bot.bot_issues(repo, cwd, runner, lambda title: title.startswith(prefix))


def report(bump: Bump, repo: str, *, cwd: Path = Path("."), runner=None) -> str:
    """Converge the family's bot issues to the verified state; returns what was done."""
    runner = runner or _run
    if not _REPO.fullmatch(repo or ""):
        raise RuntimeError("invalid repository")
    issues = bot_issues(repo, bump.family, cwd, runner)
    if not bump.stale:
        for issue in issues:
            _checked(["gh", "issue", "close", str(issue["number"]), "--repo", repo,
                      "--comment", CAUGHT_UP], cwd, runner)
        return ("up to date; closed %d issue(s)" % len(issues)) if issues else "up to date"
    if not issues:
        _checked(["gh", "issue", "create", "--repo", repo, "--title", bump.title,
                  "--body", bump.body], cwd, runner)
        return "opened an issue"
    newest, *duplicates = issues
    for issue in duplicates:
        _checked(["gh", "issue", "close", str(issue["number"]), "--repo", repo,
                  "--comment", DUPLICATE % newest["number"]], cwd, runner)
    if newest["title"] == bump.title and newest["body"] == bump.body:
        done = "issue #%d is current" % newest["number"]
    else:
        _checked(["gh", "issue", "edit", str(newest["number"]), "--repo", repo,
                  "--title", bump.title, "--body", bump.body], cwd, runner)
        done = "updated issue #%d" % newest["number"]
    return done + ("; closed %d duplicate(s)" % len(duplicates) if duplicates else "")


def _summary(bump: Bump, outcome: str) -> None:
    """One job-summary line and one annotation. Only validated values reach either."""
    line = "%s: pinned %s, latest %s; %s" % (bump.family, bump.pinned, bump.latest, outcome)
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("- %s\n" % line)
    if bump.stale:
        heading = {"checksums": "checksums changed for the same version",
                   "ahead": "pin is ahead of upstream"}.get(bump.kind, "pin update available")
        print("::%s title=%s %s::%s" % ("warning" if bump.warns else "notice", bump.family,
                                        heading, line))
    else:
        print("report-pin-bump: %s" % line)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("family", choices=FAMILIES)
    args = parser.parse_args(argv)
    try:
        bump = verify(args.family)
        outcome = report(bump, os.environ.get("GITHUB_REPOSITORY", ""))
        _summary(bump, outcome)
    except (RuntimeError, OSError, ValueError) as exc:
        print("report-pin-bump: %s: %s" % (args.family, exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
