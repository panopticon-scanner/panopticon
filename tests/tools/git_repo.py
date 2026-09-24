"""Shared git-repo scaffolding for tests.

Replaces the duplicated "init -> config -> touch -> add -> commit" fixtures
across test_driver.py, test_discovery.py, and test_diff_map.py.

`plant_fsmonitor_command`, `plant_clean_filter` and `path_shim_git` (#2006) are
the hostile-target fixtures #1985 introduced, written once here so every caller
that must be proved confined -- validate, discovery, the run manifest -- plants
the SAME command and asserts on the SAME marker rather than re-deriving one.
"""

import os
import shlex
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


def hostile_marker(repo, name="probe-marker"):
    """The file a planted hostile Git command writes if Git ever runs it.

    Inside `<repo>/.panopticon` (created here): a marker whose parent directory
    does not exist cannot be written, and a test asserting its ABSENCE would
    then pass for the wrong reason.
    """
    marker = os.path.join(repo, ".panopticon", name)
    os.makedirs(os.path.dirname(marker), exist_ok=True)
    return marker


def _marker_command(marker):
    # `cat` keeps the command well-behaved for the protocols that pipe through
    # it (the fsmonitor hook, a clean filter), so the only observable is the
    # marker.
    return "printf hit > %s; cat" % shlex.quote(marker)


def plant_fsmonitor_command(repo, marker=None):
    """Configure `core.fsmonitor` in `repo` to a command. Returns the marker."""
    marker = marker or hostile_marker(repo)
    _git(repo, "config", "core.fsmonitor", _marker_command(marker))
    return marker


def plant_filter_command(repo, setting="clean", rel="a.py", marker=None):
    """Commit `rel` under a `filter=fixture` attribute, then configure
    `filter.fixture.<setting>` to the marker command. Returns the marker.

    The rewrite at the end is the same SIZE as the committed content: a
    size-only stat difference would let Git call the file modified without ever
    running the filter, and the fixture would prove nothing.

    `setting="process"` (#2013) plants the long-running filter protocol
    instead. Git STARTS the command and then fails its pkt-line handshake
    (`error: initialization for subprocess ... failed`, rc 0 -- measured), and
    the start is what writes the marker, which is all the fixture needs.
    """
    marker = marker or hostile_marker(repo)
    with open(os.path.join(repo, rel), "w", encoding="utf-8") as fh:
        fh.write("before\n")
    with open(os.path.join(repo, ".gitattributes"), "w", encoding="utf-8") as fh:
        fh.write("%s filter=fixture\n" % rel)
    _git(repo, "add", rel, ".gitattributes")
    _git(repo, "commit", "-qm", "filter fixture")
    _git(repo, "config", "filter.fixture." + setting, _marker_command(marker))
    with open(os.path.join(repo, rel), "w", encoding="utf-8") as fh:
        fh.write("after!\n")
    return marker


def plant_clean_filter(repo, rel="a.py", marker=None):
    """`filter.fixture.clean`, the #1985/#2006 fixture. Returns the marker."""
    return plant_filter_command(repo, "clean", rel, marker)


def path_shim_git(directory, marker, stdout=""):
    """An executable `git` in `directory` that records having been run.

    The counterpart to the config fixtures: those prove the target cannot make
    a TRUSTED git run its commands, this proves the target cannot BE the git
    that runs. Returns the shim path.
    """
    os.makedirs(directory, exist_ok=True)
    shim = os.path.join(directory, "git")
    with open(shim, "w", encoding="utf-8") as fh:
        fh.write("#!/bin/sh\nprintf hit > %s\nprintf '%%s' %s\n"
                 % (shlex.quote(marker), shlex.quote(stdout)))
    os.chmod(shim, 0o700)
    return shim


def plant_hook(repo, name, marker=None):
    """An executable `.git/hooks/<name>` that records having been run.

    Needs no configuration at all: git looks in `.git/hooks` by default, so
    this vector is reachable in any target checkout and no config refusal can
    ever catch it (#2006 fix round 2, C2). Returns the marker.
    """
    marker = marker or hostile_marker(repo, "hook-marker")
    hooks = os.path.join(repo, ".git", "hooks")
    os.makedirs(hooks, exist_ok=True)
    path = os.path.join(hooks, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("#!/bin/sh\nprintf hit >> %s\nexit 0\n" % shlex.quote(marker))
    os.chmod(path, 0o700)
    return marker


def add_plumbing_submodule(repo, child, name="sub"):
    """Register `child` as a submodule of `repo` using PLUMBING only.

    `git submodule add` is a shell script that shells out to `sed`, `basename`
    and friends, so it cannot run in a bare PATH environment (the git-only CI
    leg) -- the existing #1985 submodule tests fail there for exactly that
    reason. `update-index --add --cacheinfo 160000` writes the same gitlink,
    and a hand-written `.gitmodules` registers it, with no helper binaries.
    Returns the submodule worktree path.
    """
    sha = subprocess.run(["git", "-C", child, "rev-parse", "HEAD"], check=True,
                         capture_output=True, text=True, timeout=GIT_TIMEOUT).stdout.strip()
    worktree = os.path.join(repo, name)
    shutil.copytree(child, worktree, symlinks=True)
    with open(os.path.join(repo, ".gitmodules"), "w", encoding="utf-8") as fh:
        fh.write('[submodule "%s"]\n\tpath = %s\n\turl = %s\n' % (name, name, child))
    _git(repo, "update-index", "--add", "--cacheinfo", "160000,%s,%s" % (sha, name))
    _git(repo, "add", ".gitmodules")
    _git(repo, "commit", "-qm", "register submodule")
    return worktree
