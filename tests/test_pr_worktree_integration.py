"""Local Git integration for PR acquisition, with only gh metadata supplied."""

import json
import os
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace

import pytest

import scripts.diff_map as diff_map


def _git(repo, *args, env):
    return subprocess.run(["git", "-C", str(repo), *args], env=env, check=True,
                          capture_output=True, text=True, timeout=30).stdout.strip()


@pytest.fixture
def local_pr(tmp_path, monkeypatch):
    assert shutil.which("git"), "real Git is required for this integration fixture"
    home = tmp_path / "home"
    home.mkdir()
    env = {**os.environ, "HOME": str(home), "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0"}
    for key in tuple(env):
        if key.startswith("GIT_CONFIG_KEY_") or key.startswith("GIT_CONFIG_VALUE_"):
            env.pop(key)
    env.pop("GIT_CONFIG_COUNT", None)
    origin, seed, clone = (tmp_path / name for name in ("origin.git", "seed", "clone"))
    _git(tmp_path, "init", "--bare", "-b", "main", str(origin), env=env)
    _git(tmp_path, "init", "-b", "main", str(seed), env=env)
    _git(seed, "config", "user.email", "fixture@example.invalid", env=env)
    _git(seed, "config", "user.name", "Fixture", env=env)
    (seed / "payload.txt").write_text("base\n")
    (seed / "panopticon.yml").write_text("version: 1\noperator: base\n")
    _git(seed, "add", "-A", env=env)
    _git(seed, "commit", "-m", "base", env=env)
    _git(seed, "remote", "add", "origin", str(origin), env=env)
    _git(seed, "push", "origin", "main", env=env)
    _git(seed, "checkout", "-b", "pr", env=env)
    (seed / "payload.txt").write_text("PR content\n")
    (seed / "panopticon.yml").write_text("version: 1\noperator: PR\n")
    _git(seed, "add", "-A", env=env)
    _git(seed, "commit", "-m", "PR", env=env)
    sha = _git(seed, "rev-parse", "HEAD", env=env)
    _git(seed, "push", "origin", "pr", env=env)
    _git(origin, "update-ref", "refs/pull/7/head", sha, env=env)
    _git(tmp_path, "clone", str(origin), str(clone), env=env)
    (clone / "panopticon.yml").write_text("version: 1\noperator: local\n")
    monkeypatch.setattr(diff_map.tempfile, "gettempdir", lambda: str(tmp_path))
    calls = []

    def runner(argv, **kwargs):
        assert kwargs["timeout"] <= diff_map._PR_TIMEOUT
        calls.append(list(argv))
        if argv[:3] == ["gh", "pr", "view"]:
            assert argv == ["gh", "pr", "view", "7", "--json", "baseRefName"]
            return SimpleNamespace(returncode=0, stdout=json.dumps({"baseRefName": "main"}), stderr="")
        assert Path(argv[0]).name == "git"
        kwargs.setdefault("env", env)
        return subprocess.run(argv, **kwargs)

    yield clone, sha, env, runner, calls
    wt = diff_map._worktree_dir(str(clone), 7)
    if os.path.isdir(wt) and not os.path.islink(wt):
        diff_map.release_worktree(wt, repo=str(clone), runner=runner)


def test_acquire_checkout_reuse_refresh_and_release(local_pr):
    clone, sha, env, runner, calls = local_pr
    first = diff_map.acquire_pr(7, repo=str(clone), runner=runner)
    wt = Path(first["worktree"])
    assert wt.parent == clone.parent.resolve()
    assert first["base"] == "main"
    assert first["head_sha"] == sha
    assert _git(wt, "rev-parse", "HEAD", env=env) == sha
    assert (wt / "payload.txt").read_text() == "PR content\n"
    assert (wt / "panopticon.yml").read_text() == "version: 1\noperator: local\n"
    assert _git(clone, "for-each-ref", "--format=%(refname)", "refs/panopticon", env=env) == ""
    fetches = sum("fetch" in argv for argv in calls)
    (clone / "panopticon.yml").write_text("version: 1\noperator: refreshed\n")
    second = diff_map.acquire_pr(7, repo=str(clone), runner=runner)
    assert second == first
    assert sum("fetch" in argv for argv in calls) == fetches == 1
    assert _git(wt, "rev-parse", "HEAD", env=env) == sha
    assert (wt / "panopticon.yml").read_text() == "version: 1\noperator: refreshed\n"
    assert len(_git(clone, "worktree", "list", env=env).splitlines()) == 2
    diff_map.release_worktree(str(wt), repo=str(clone), runner=runner)
    assert not wt.exists()
    assert len(_git(clone, "worktree", "list", env=env).splitlines()) == 1


@pytest.mark.parametrize("planted", ["symlink", "occupied"])
def test_planted_destination_is_refused_without_mutating_target(local_pr, planted):
    clone, _sha, _env, runner, calls = local_pr
    wt = Path(diff_map._worktree_dir(str(clone), 7))
    sentinel = clone.parent / "sentinel"
    sentinel.mkdir()
    (sentinel / "keep.txt").write_text("untouched")
    if planted == "symlink":
        wt.symlink_to(sentinel, target_is_directory=True)
    else:
        wt.mkdir()
        (wt / "keep.txt").write_text("untouched")
    with pytest.raises(RuntimeError):
        diff_map.acquire_pr(7, repo=str(clone), runner=runner)
    assert (sentinel / "keep.txt").read_text() == "untouched"
    if planted == "symlink":
        assert wt.is_symlink()
        assert not any("fetch" in argv for argv in calls)
    else:
        assert (wt / "keep.txt").read_text() == "untouched"
    assert not any("worktree" in argv and "add" in argv for argv in calls
                   if planted == "symlink")
