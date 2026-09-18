"""Shared git-repo scaffolding for tests.

Replaces the duplicated "init -> config -> touch -> add -> commit" fixtures
across test_driver.py, test_discovery.py, and test_diff_map.py.
"""

import os
import shutil
import subprocess
import tempfile


GIT_TIMEOUT = 30


def _git(repo, *args):
    try:
        subprocess.run(
            ["git", "-C", repo, *args],
            check=True,
            capture_output=True,
            timeout=GIT_TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        raise AssertionError(
            f"git subprocess timed out after {GIT_TIMEOUT}s: {exc.cmd}"
        ) from exc


def make_git_repo(
    test_case=None,
    tmp_path=None,
    files=None,
    groups_yml=None,
    panopticon=False,
    branch="main",
    user_email="t@t",
    user_name="t",
    commit_msg="init",
    realpath=True,
):
    """Create a temporary git repo and return its path.

    Args:
        test_case: Optional unittest.TestCase; cleanup is scheduled via
            ``addCleanup``.
        tmp_path: Optional pytest ``tmp_path``; if provided the repo is created
            there and cleanup is left to pytest.
        files: Optional dict mapping relative paths to file contents.  A value
            of ``None`` creates an empty file.  When omitted, an empty ``a.py``
            is created for parity with the legacy helpers.
        groups_yml: Optional `groups:` body.  Written to the root
            ``panopticon.yml`` (under a ``version: 1`` line) before the initial
            commit -- the one config discovery reads (#1681).
        panopticon: If True, create an empty ``.panopticon`` artifact directory
            after the initial commit (untracked).  ``groups_yml`` implies it:
            a repo with a config is one a run writes artifacts into, and the
            legacy matrix write used to create the directory on the way past.
        branch: Branch name to rename the default branch to, or ``None`` to
            leave the default branch name untouched.
        user_email, user_name: Git committer identity for the initial commit.
        commit_msg: Message for the initial commit.
        realpath: Resolve symlinks in the returned path.

    Returns:
        Absolute path to the repo root.
    """
    if tmp_path is not None:
        repo = str(tmp_path)
    else:
        repo = tempfile.mkdtemp()

    if realpath:
        repo = os.path.realpath(repo)

    if test_case is not None:
        test_case.addCleanup(shutil.rmtree, repo, ignore_errors=True)

    try:
        subprocess.run(
            ["git", "init", "-q", repo],
            check=True,
            capture_output=True,
            timeout=GIT_TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        raise AssertionError(
            f"git subprocess timed out after {GIT_TIMEOUT}s: {exc.cmd}"
        ) from exc
    _git(repo, "config", "user.email", user_email)
    _git(repo, "config", "user.name", user_name)

    if files is None:
        files = {"a.py": ""}

    for rel, content in files.items():
        path = os.path.join(repo, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("" if content is None else content)

    if groups_yml is not None:
        with open(os.path.join(repo, "panopticon.yml"), "w", encoding="utf-8") as fh:
            fh.write("version: 1\n" + groups_yml)

    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", commit_msg)

    if panopticon or groups_yml is not None:
        os.makedirs(os.path.join(repo, ".panopticon"), exist_ok=True)

    if branch:
        _git(repo, "branch", "-M", branch)

    return repo
