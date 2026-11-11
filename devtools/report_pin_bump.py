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
import functools
import json
import os
from pathlib import Path
import re
import subprocess
import sys

if __name__ == "__main__":  # run by path: puts skill/ on sys.path (#3505)
    import runpy
    runpy.run_path(os.path.join(os.path.dirname(os.path.realpath(__file__)), "_skill_bootstrap.py"))
import bump_pins
# The checked-out repository supplies this audited resolver, but it is never
# searched for the gh executable.
from scripts.executable import resolve
from scripts import inert
from scripts import redact


TRUSTED_PATH = "/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin"
PROCESS_TIMEOUT = 120
BOT = "github-actions[bot]"
TITLE_PREFIX = "pin-freshness: "
# The most of a gh error this script prints (#3420). The text is gh's, not
# ours, so it is redacted and made inert before it is cut.
ERROR_TEXT_CAP = 600
BODY_CAP = 4000

_REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_NUMBER = re.compile(r"[1-9][0-9]{0,9}\Z")
_ARCH = re.compile(r"[A-Z0-9]{1,16}\Z")

FAMILIES = ("tinyproxy", "rustup", "trivy", "rust-toolchain")
CAUGHT_UP = "The pin has caught up with upstream; closing."
DUPLICATE = "Duplicate of #%s; closing."
_DUPLICATE = re.compile(r"Duplicate of #[1-9][0-9]{0,9}; closing\.\Z")
_TITLE = re.compile(r"pin-freshness: (tinyproxy|rustup|trivy|rust-toolchain) "
                    r"(\S{1,80}) -> (\S{1,80})( \((checksums changed|pinned is ahead)\))?\Z")
# One lookup page. A full page could hide an existing issue, and a run that missed it would
# file a duplicate, so a full page is refused rather than guessed past (#3557 review).
PAGE = 100

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
        match = re.fullmatch(r"repos/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/issues\?state=open"
                             r"&creator=github-actions%5Bbot%5D&per_page=100", command[2])
        return bool(match)
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
    """Run only this script's gh commands with a trusted gh and GH_TOKEN.

    Even a mistaken new call site cannot turn this into a generic process
    runner; the child gets no ambient PATH or interpreter/loader startup hooks.
    """
    if not _allowed_command(command):
        raise RuntimeError("unexpected pin-report executable or arguments")
    selected = resolve(command[0], cwd, path=TRUSTED_PATH)
    env = {"HOME": os.path.expanduser("~"), "PATH": selected.path_env, "LC_ALL": "C"}
    if os.environ.get("GH_TOKEN"):
        env["GH_TOKEN"] = os.environ["GH_TOKEN"]
    elif os.environ.get("GH_CONFIG_DIR"):
        env["GH_CONFIG_DIR"] = os.environ["GH_CONFIG_DIR"]
    # Same bounded, injectable subprocess.run partial pattern as
    # devtools/file_issues.py; the executable is absolute and the environment
    # is built above rather than inherited from the checkout.
    runner = functools.partial(subprocess.run, cwd=cwd, env=env,
                               timeout=PROCESS_TIMEOUT, text=True,
                               capture_output=True, check=False)
    try:
        return runner([selected.path, *command[1:]])
    except subprocess.TimeoutExpired:
        raise RuntimeError("gh timed out") from None


def _error_text(text: str | None) -> str:
    """A gh error as one bounded, inert line (#3420).

    The workflow token is masked by value and known secret shapes by
    `redact`. Every control character, escape and line break is spelled
    (`\\x1b`, `\\x0a`), so the text can't style the log or start a new
    line, such as an Actions `::` command. The output is at most
    ERROR_TEXT_CAP characters, and a cut never splits a spelling.
    """
    raw = (text or "").strip()
    token = os.environ.get("GH_TOKEN", "")
    if token:
        raw = raw.replace(token, "[REDACTED]")
    raw = redact.redact_diagnostic(raw, ERROR_TEXT_CAP + 1)
    pieces = [inert.spelled(ord(ch)) if ord(ch) in inert.INERT_ESCAPE_CODE_POINTS
              else ch for ch in raw]
    if sum(map(len, pieces)) > ERROR_TEXT_CAP:
        kept, used = [], 0
        for piece in pieces:
            if used + len(piece) > ERROR_TEXT_CAP - 3:
                break
            kept.append(piece)
            used += len(piece)
        pieces = kept + ["..."]
    return "".join(pieces) or "(no error text)"


def _checked(command: list[str], cwd: Path, runner) -> str:
    result = runner(command, cwd)
    if result.returncode:
        raise RuntimeError("gh %s failed: %s" % (command[1], _error_text(result.stderr)))
    return result.stdout


def bot_issues(repo: str, family: str, cwd: Path, runner) -> list[dict]:
    """This family's open issues authored by the workflow bot, newest first.

    The REST `creator` filter does the author check server-side and each entry
    is checked again here, so a look-alike issue opened by anyone else never
    counts: it can neither silence a report nor be edited or closed by it.
    """
    lookup = ("repos/%s/issues?state=open&creator=github-actions%%5Bbot%%5D&per_page=%d"
              % (repo, PAGE))
    raw = _checked(["gh", "api", lookup], cwd, runner)
    try:
        entries = json.loads(raw)
    except ValueError:
        raise RuntimeError("gh api returned malformed issue JSON") from None
    if not isinstance(entries, list):
        raise RuntimeError("gh api returned malformed issue JSON")
    if len(entries) >= PAGE:
        raise RuntimeError("the issue lookup returned a full page of %d; refusing to report "
                           "rather than risk filing a duplicate" % PAGE)
    found = []
    for entry in entries:
        if not isinstance(entry, dict) or "pull_request" in entry:
            continue
        user = entry.get("user")
        number, title = entry.get("number"), entry.get("title")
        if (isinstance(user, dict) and user.get("login") == BOT and user.get("type") == "Bot"
                and isinstance(number, int) and not isinstance(number, bool) and number > 0
                and isinstance(title, str) and title.startswith(TITLE_PREFIX + family + " ")):
            found.append({"number": number, "title": title, "body": entry.get("body") or ""})
    return sorted(found, key=lambda issue: issue["number"], reverse=True)


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
