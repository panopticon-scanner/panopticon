"""Shared helpers for discovery tests. Not collected by pytest."""
import contextlib
import io
import json
import os
import subprocess
import sys
import types

SCRIPTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "skill", "scripts")

from tools.git_repo import make_git_repo  # noqa: E402

import scripts.discovery as discovery  # noqa: E402
import scripts.discovery as orch  # noqa: E402
import scripts.setup_flow as setup_flow  # noqa: E402

orchestrator = orch

GIT_TIMEOUT = 30
SCRIPT_TIMEOUT = 120

__all__ = [
    "SCRIPTS",
    "GIT_TIMEOUT",
    "SCRIPT_TIMEOUT",
    "discovery",
    "orchestrator",
    "setup_flow",
    "make_git_repo",
    "run_script",
    "git_output",
    "touch",
    "run_scan_helper",
    "run_scan",
    "run_scan_with_err",
    "grouped",
    "git_cmd",
    "init_repo",
    "FakeRun",
    "repo_with_matrix",
    "repo_with_scalar_match_group",
    "repo_with_exclude",
]


def run_script(script, *args, cwd=None):
    try:
        return subprocess.run(
            [sys.executable, os.path.join(SCRIPTS, script), *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=SCRIPT_TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        raise AssertionError(
            f"script subprocess timed out after {SCRIPT_TIMEOUT}s: {exc.cmd}"
        ) from exc


def git_output(repo, *args):
    try:
        return subprocess.run(
            ["git", *args],
            cwd=str(repo),
            check=True,
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT,
        ).stdout
    except subprocess.TimeoutExpired as exc:
        raise AssertionError(
            f"git subprocess timed out after {GIT_TIMEOUT}s: {exc.cmd}"
        ) from exc


def touch(root, rel, content=""):
    full = os.path.join(root, rel)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as fh:
        fh.write(content)


def run_scan_helper(d, *extra):
    buf = io.StringIO()
    err = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
        rc = orch.main(["--repo", d, "--repo-scan", *extra])
    val = buf.getvalue().strip()
    data = json.loads(val) if val else {}
    return rc, data, err.getvalue()


def run_scan(d, *extra):
    rc, data, _err = run_scan_helper(d, *extra)
    assert rc == 0
    return data


def run_scan_with_err(d, *extra):
    rc, data, err = run_scan_helper(d, *extra)
    assert rc == 0
    return data, err


def grouped(out):
    return [f for g in out["groups"] for f in g["files"]]


def git_cmd(d, *args):
    try:
        subprocess.run(
            ["git", "-C", d, *args],
            check=True,
            capture_output=True,
            timeout=GIT_TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        raise AssertionError(
            f"git subprocess timed out after {GIT_TIMEOUT}s: {exc.cmd}"
        ) from exc


def init_repo(d):
    try:
        subprocess.run(
            ["git", "init", "-q", d],
            check=True,
            capture_output=True,
            timeout=GIT_TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        raise AssertionError(
            f"git subprocess timed out after {GIT_TIMEOUT}s: {exc.cmd}"
        ) from exc
    git_cmd(d, "config", "user.email", "t@e.com")
    git_cmd(d, "config", "user.name", "Test")


class FakeRun:
    """Fake subprocess.run: returncode 0 iff the git ref arg is in ok_refs."""
    def __init__(self, ok_refs):
        self.ok = set(ok_refs)
        self.calls = []

    def __call__(self, argv, **kw):
        self.calls.append(argv)
        return types.SimpleNamespace(
            returncode=0 if argv[-1] in self.ok else 1,
            stdout="", stderr="")


def repo_with_matrix(tmp_path):
    import os
    repo = tmp_path
    (repo / ".panopticon").mkdir(parents=True)
    for p in ["src/auth/login.py", "src/checkout/pay.py", "src/checkout/cart.py",
              "src/misc/other.py"]:
        os.makedirs(os.path.dirname(repo / p), exist_ok=True)
        (repo / p).write_text("x=1\n")
    (repo / ".panopticon" / "groups.yml").write_text(
        "groups:\n"
        "  Auth:\n    match: ['src/auth/**']\n    panels: [SEC]\n"
        "  Checkout:\n    match: ['src/checkout/**']\n    panels: [SEC, DAT]\n")
    git_cmd(repo, "init", "-q")
    git_cmd(repo, "add", "-A")
    git_cmd(repo, "-c", "user.email=t@t", "-c", "user.name=t",
            "commit", "-qm", "x")
    return repo


def repo_with_scalar_match_group(tmp_path):
    repo = tmp_path
    (repo / ".panopticon").mkdir(parents=True)
    for p in ["src/auth/login.py", "src/bad/thing.py"]:
        os.makedirs(os.path.dirname(repo / p), exist_ok=True)
        (repo / p).write_text("x=1\n")
    (repo / ".panopticon" / "groups.yml").write_text(
        "groups:\n"
        "  Bad:\n    match: src/bad/**\n"
        "  Auth:\n    match: ['src/auth/**']\n")
    git_cmd(repo, "init", "-q")
    git_cmd(repo, "add", "-A")
    git_cmd(repo, "-c", "user.email=t@t", "-c", "user.name=t",
            "commit", "-qm", "x")
    return repo


def repo_with_exclude(tmp_path):
    import os
    repo = tmp_path
    (repo / ".panopticon").mkdir(parents=True)
    for p in ["src/checkout/pay.py", "vendor/dep.py"]:
        os.makedirs(os.path.dirname(repo / p), exist_ok=True)
        (repo / p).write_text("x=1\n")
    (repo / ".panopticon" / "groups.yml").write_text(
        "groups:\n"
        "  Checkout:\n    match: ['src/checkout/**']\n    panels: [SEC]\n"
        "exclude_paths: ['vendor/**']\n")
    git_cmd(repo, "init", "-q")
    git_cmd(repo, "add", "-A")
    git_cmd(repo, "-c", "user.email=t@t", "-c", "user.name=t",
            "commit", "-qm", "x")
    return repo
