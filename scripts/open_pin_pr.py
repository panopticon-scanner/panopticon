#!/usr/bin/env python3
"""Open a reviewed pin-bump PR, including recovery after a failed PR creation."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import quote


FAMILIES = {
    "rustup": (
        "RUSTUP_VERSION", ("RUSTUP_INIT_SHA256_AMD64", "RUSTUP_INIT_SHA256_ARM64"),
        "chore(docker): bump rustup pin to {version}",
        "Both SHA256 values were read from upstream's .sha256 files and verified "
        "against the downloaded artifacts by bump_pins.py. Review the rustup "
        "release and image build before merging."),
    "trivy": (
        "TRIVY_VERSION", ("TRIVY_SHA256_AMD64", "TRIVY_SHA256_ARM64"),
        "chore(deps): bump Trivy pin to {version}",
        "Both SHA256 values came from the official Trivy release checksums file "
        "and matched the downloaded AMD64 and ARM64 archives. Review the "
        "release and image build before merging."),
    "rust-toolchain": (
        "RUST_TOOLCHAIN_VERSION", (),
        "chore(deps): bump Rust toolchain pin to {version}",
        "The version came from Rust's stable channel manifest after its companion "
        "SHA256 matched the downloaded manifest, and both image Linux GNU targets "
        "were marked available. Review the compiler release and image build "
        "before merging."),
}


def _run(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)


def _checked(command: list[str], cwd: Path, runner) -> str:
    result = runner(command, cwd)
    if result.returncode:
        raise RuntimeError("%s failed: %s" % (command[0], result.stderr.strip()))
    return result.stdout


def _arg(text: str, name: str, pattern: str) -> str:
    matches = re.findall(r"^ARG " + re.escape(name) + r"=(\S+)[ \t]*$", text, re.M)
    if len(matches) != 1 or not re.fullmatch(pattern, matches[0]):
        raise RuntimeError("Dockerfile has invalid or duplicate %s" % name)
    return matches[0]


def _expected(base: str, generated: str, family: str) -> str:
    version_arg, digest_args, _title, _body = FAMILIES[family]
    result = base
    for name in (version_arg, *digest_args):
        pattern = r"[0-9]+\.[0-9]+\.[0-9]+" if name == version_arg else r"[0-9a-f]{64}"
        old = _arg(base, name, pattern)
        new = _arg(generated, name, pattern)
        result = re.sub(r"^ARG " + name + "=" + re.escape(old) + r"[ \t]*$",
                        "ARG %s=%s" % (name, new), result, count=1, flags=re.M)
    if result != generated or result == base:
        raise RuntimeError("generated Dockerfile is not exclusively the expected %s pin update" % family)
    return _arg(generated, version_arg, r"[0-9]+\.[0-9]+\.[0-9]+")


def _prs(repo: str, branch: str, base: str, cwd: Path, gh_runner) -> list[dict]:
    owner = repo.split("/")[0]
    query = ("repos/%s/pulls?state=all&base=%s&head=%s&per_page=100"
             % (repo, quote(base, safe=""), quote(owner + ":" + branch, safe="")))
    raw = _checked(["gh", "api", query], cwd, gh_runner)
    try:
        data = json.loads(raw)
        if not isinstance(data, list):
            raise ValueError("expected a list")
        for pr in data:
            if (not isinstance(pr, dict) or not isinstance(pr.get("number"), int)
                    or pr.get("state") not in {"open", "closed"}
                    or not isinstance(pr.get("head"), dict)
                    or not isinstance(pr.get("base"), dict)):
                raise ValueError("invalid PR entry")
            head = pr["head"]
            if (not isinstance(head.get("repo"), dict)
                    or not isinstance(pr["base"].get("repo"), dict)):
                raise ValueError("invalid PR repository")
            if (head.get("ref") != branch or head.get("repo", {}).get("full_name") != repo
                    or pr["base"].get("ref") != base
                    or pr["base"].get("repo", {}).get("full_name") != repo):
                raise ValueError("PR response did not match exact repository, base, and head")
    except (ValueError, TypeError, KeyError) as exc:
        raise RuntimeError("invalid PR lookup response") from exc
    return data


def _remote_branch(branch: str, cwd: Path, git_runner) -> str | None:
    ref = "refs/heads/" + branch
    raw = _checked(["git", "ls-remote", "--heads", "origin", ref], cwd, git_runner)
    if not raw:
        return None
    lines = raw.splitlines()
    if len(lines) != 1 or not re.fullmatch(r"[0-9a-f]{40}\t" + re.escape(ref), lines[0]):
        raise RuntimeError("invalid remote branch lookup response")
    return lines[0][:40]


def _main_baseline(cwd: Path, git_runner) -> str:
    """Bind this run to the remote main commit and make its ancestry available."""
    shallow = _checked(["git", "rev-parse", "--is-shallow-repository"],
                       cwd, git_runner).strip()
    if shallow not in {"true", "false"}:
        raise RuntimeError("invalid shallow-repository response")
    fetch = ["git", "fetch", "--no-tags"]
    if shallow == "true":
        fetch.append("--unshallow")
    _checked(fetch + ["origin", "refs/heads/main"], cwd, git_runner)
    baseline = _checked(["git", "rev-parse", "FETCH_HEAD"], cwd, git_runner).strip()
    head = _checked(["git", "rev-parse", "HEAD"], cwd, git_runner).strip()
    if head != baseline:
        raise RuntimeError("checkout is not current main; refusing pin PR")
    return baseline


def open_pin_pr(family: str, repo: str, *, cwd: Path = Path("."),
                gh_runner=_run, git_runner=_run) -> str:
    if family not in FAMILIES:
        raise RuntimeError("unknown pin family")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise RuntimeError("invalid repository")
    cwd = Path(cwd)
    base = "main"
    version_arg, _digest_args, title_template, body = FAMILIES[family]
    baseline = _main_baseline(cwd, git_runner)
    base_dockerfile = _checked(["git", "show", baseline + ":Dockerfile"], cwd, git_runner)
    generated = (cwd / "Dockerfile").read_text(encoding="utf-8")
    version = _expected(base_dockerfile, generated, family)
    branch = "chore/bump-%s-%s" % (family, version)
    # A dedicated workflow checkout should contain only the generated Dockerfile.
    status = _checked(["git", "status", "--porcelain", "--untracked-files=normal"], cwd, git_runner)
    if status != " M Dockerfile\n":
        raise RuntimeError("checkout must contain only an unstaged generated Dockerfile")
    existing = _prs(repo, branch, base, cwd, gh_runner)
    if any(pr["state"] == "open" for pr in existing):
        return "open PR already exists"
    if existing:
        raise RuntimeError("a closed or merged PR already uses this pin branch; recover manually")

    remote = _remote_branch(branch, cwd, git_runner)
    if remote is None:
        _checked(["git", "config", "user.name", "github-actions[bot]"], cwd, git_runner)
        _checked(["git", "config", "user.email",
                  "41898282+github-actions[bot]@users.noreply.github.com"], cwd, git_runner)
        _checked(["git", "checkout", "-b", branch], cwd, git_runner)
        _checked(["git", "add", "--", "Dockerfile"], cwd, git_runner)
        _checked(["git", "commit", "-m", title_template.format(version=version),
                  "-m", "Generated by the pin-freshness workflow. " + body], cwd, git_runner)
        try:
            _checked(["git", "push", "origin", "HEAD:refs/heads/" + branch], cwd, git_runner)
        except RuntimeError:
            # A concurrent run may have pushed the branch first. Verify it below.
            pass
        remote = _remote_branch(branch, cwd, git_runner)
        if remote is None:
            raise RuntimeError("pin branch push failed and no remote branch exists")

    _checked(["git", "fetch", "--no-tags", "origin", "refs/heads/" + branch], cwd, git_runner)
    fetched = _checked(["git", "rev-parse", "FETCH_HEAD"], cwd, git_runner).strip()
    if fetched != remote:
        raise RuntimeError("remote pin branch changed during verification")
    parent = _checked(["git", "rev-parse", "FETCH_HEAD^"], cwd, git_runner).strip()
    parents = _checked(["git", "rev-list", "--parents", "-n", "1", fetched],
                       cwd, git_runner).split()
    if parents != [fetched, parent]:
        raise RuntimeError("orphan branch is not a single pin commit; recover manually")
    ancestor = git_runner(["git", "merge-base", "--is-ancestor", parent, baseline], cwd)
    if ancestor.returncode == 1:
        raise RuntimeError("orphan branch is not based on an ancestor of current main; recover manually")
    if ancestor.returncode:
        raise RuntimeError("git ancestry lookup failed: %s" % ancestor.stderr.strip())
    branch_commits = _checked(["git", "rev-list", baseline + ".." + fetched],
                              cwd, git_runner).splitlines()
    if branch_commits != [fetched]:
        raise RuntimeError("orphan branch has unrelated committed changes; recover manually")
    changed = _checked(["git", "diff", "--name-only", parent, fetched], cwd, git_runner)
    remote_file = _checked(["git", "show", "FETCH_HEAD:Dockerfile"], cwd, git_runner)
    if changed != "Dockerfile\n" or remote_file != generated:
        raise RuntimeError("orphan branch differs from the verified generated Dockerfile; recover manually")

    try:
        _checked(["gh", "pr", "create", "--repo", repo, "--base", base,
                  "--head", branch, "--title", title_template.format(version=version),
                  "--body", body, "--label", "dependencies"], cwd, gh_runner)
    except RuntimeError as exc:
        if any(pr["state"] == "open" for pr in _prs(repo, branch, base, cwd, gh_runner)):
            return "open PR appeared during creation"
        raise RuntimeError("PR creation failed and no open PR exists") from exc
    return "created PR"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("family", choices=FAMILIES)
    args = parser.parse_args(argv)
    try:
        print(open_pin_pr(args.family, os.environ.get("GITHUB_REPOSITORY", "")))
    except (RuntimeError, OSError) as exc:
        print("open-pin-pr: %s" % exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
