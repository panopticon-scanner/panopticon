"""Bounded trusted probes; temporary repositories contain only harmless commands."""
import os
import subprocess
from unittest import mock

import pytest

from scripts import executable, safe_git


def test_allowlisted_environment_and_injected_runner(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.fsmonitor")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "untrusted")
    monkeypatch.setenv("GIT_DIR", "/wrong")
    monkeypatch.setenv("GIT_EXEC_PATH", "/wrong/bin")
    runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0, "/root\n", ""))
    resolved = executable.ResolvedExecutable("/trusted/git", "/trusted/bin")
    with mock.patch.object(executable, "resolve", return_value=resolved) as resolve:
        result = safe_git.probe(str(tmp_path), ["rev-parse", "--show-toplevel"], runner=runner)
    resolve.assert_called_once_with("git", str(tmp_path), os.environ.get("PATH", ""))
    assert result.stdout == "/root\n"
    args, options = runner.call_args
    assert args[0] == ["/trusted/git", "-C", str(tmp_path), "-c", "core.fsmonitor=false",
                       "rev-parse", "--show-toplevel"]
    assert options == {"capture_output": True, "text": True, "timeout": 15,
                       "env": {"PATH": "/trusted/bin", "LC_ALL": "C",
                               "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": os.devnull,
                               "GIT_CONFIG_GLOBAL": os.devnull}}


def test_status_preflights_share_the_fifteen_second_budget(tmp_path):
    runner = mock.Mock(side_effect=[subprocess.CompletedProcess([], 0, "", "")] * 3)
    with mock.patch.object(safe_git.time, "monotonic", side_effect=[100, 102, 105, 109]):
        safe_git.probe(str(tmp_path), ["status", "--porcelain", "-z"], runner=runner)
    assert [call.kwargs["timeout"] for call in runner.call_args_list] == [13, 10, 6]
    assert runner.call_args_list[-1].args[0][-4:] == ["status", "--porcelain", "-z", "--ignore-submodules=none"]


def test_expired_preflight_budget_never_runs_status(tmp_path):
    runner = mock.Mock()
    with mock.patch.object(safe_git.time, "monotonic", side_effect=[100, 116]):
        with pytest.raises(subprocess.TimeoutExpired):
            safe_git.probe(str(tmp_path), ["status", "--porcelain", "-z"], runner=runner)
    runner.assert_not_called()


@pytest.mark.parametrize("setting", ["filter.fixture.clean", "filter.fixture.process"])
def test_filter_commands_fail_closed_before_status(tmp_path, setting):
    runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0, setting + "\nfixture-command-value-must-not-appear\0", ""))
    with pytest.raises(OSError, match="filter") as error:
        safe_git.probe(str(tmp_path), ["status", "--porcelain", "-z"], runner=runner)
    assert setting in str(error.value)
    assert "fixture-command-value-must-not-appear" not in str(error.value)
    assert runner.call_count == 1


def test_preflight_failure_is_returned_without_status(tmp_path):
    failure = subprocess.CompletedProcess([], 128, "", "fatal: not a git repository")
    runner = mock.Mock(return_value=failure)
    assert safe_git.probe(str(tmp_path), ["status", "--porcelain", "-z"], runner=runner) is failure
    assert runner.call_count == 1


def test_global_system_and_inherited_config_are_suppressed(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "visible").write_text("untracked")
    excludes = tmp_path / "excludes"
    excludes.write_text("visible\n")
    config = tmp_path / "external-config"
    config.write_text('[core]\n excludesFile = "%s"\n' % excludes)
    home = tmp_path / "home"
    home.mkdir()
    (home / ".gitconfig").write_text(config.read_text())
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", str(config))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.excludesFile")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", str(excludes))
    result = safe_git.probe(str(repo), ["status", "--porcelain", "-z"])
    assert result.returncode == 0
    assert result.stdout == "?? visible\0"


def test_uninitialized_submodule_is_not_rejected(tmp_path):
    runner = mock.Mock(side_effect=[subprocess.CompletedProcess([], 0, "", ""),
                                   subprocess.CompletedProcess([], 0, "160000 " + "a" * 40 + " 0\tabsent\0", ""),
                                   subprocess.CompletedProcess([], 0, "", "")])
    assert safe_git.probe(str(tmp_path), ["status", "--porcelain", "-z"], runner=runner).returncode == 0
    assert runner.call_count == 3


@pytest.mark.parametrize("rel", ["../escape", "/absolute", "sub/../escape", "."])
def test_unsafe_submodule_paths_fail_closed(tmp_path, rel):
    runner = mock.Mock(side_effect=[subprocess.CompletedProcess([], 0, "", ""),
                                   subprocess.CompletedProcess([], 0, "160000 " + "a" * 40 + " 0\t" + rel + "\0", "")])
    with pytest.raises(OSError, match="unsafe submodule path"):
        safe_git.probe(str(tmp_path), ["status", "--porcelain", "-z"], runner=runner)
    assert runner.call_count == 2


def test_repository_traversal_limit_fails_closed(tmp_path):
    paths = ["sub%d" % i for i in range(64)]
    for path in paths:
        (tmp_path / path).mkdir()
        (tmp_path / path / ".git").mkdir()
    index = "".join("160000 " + "a" * 40 + " 0\t" + path + "\0" for path in paths)
    runner = mock.Mock(side_effect=[subprocess.CompletedProcess([], 0, "", ""),
                                   subprocess.CompletedProcess([], 0, index, "")])
    with pytest.raises(OSError, match="64 repositories"):
        safe_git.probe(str(tmp_path), ["status", "--porcelain", "-z"], runner=runner)
    assert runner.call_count == 2


def test_duplicate_submodule_worktree_fails_closed(tmp_path):
    (tmp_path / "sub" / ".git").mkdir(parents=True)
    index = ("160000 " + "a" * 40 + " 0\tsub\0") * 2
    runner = mock.Mock(side_effect=[subprocess.CompletedProcess([], 0, "", ""),
                                   subprocess.CompletedProcess([], 0, index, "")])
    with pytest.raises(OSError, match="cyclic or duplicate"):
        safe_git.probe(str(tmp_path), ["status", "--porcelain", "-z"], runner=runner)


def test_symlink_submodule_escape_fails_closed(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "sub").symlink_to(tmp_path, target_is_directory=True)
    runner = mock.Mock(side_effect=[subprocess.CompletedProcess([], 0, "", ""),
                                   subprocess.CompletedProcess([], 0, "160000 " + "a" * 40 + " 0\tsub\0", "")])
    with pytest.raises(OSError, match="unsafe submodule path"):
        safe_git.probe(str(repo), ["status", "--porcelain", "-z"], runner=runner)


@pytest.mark.parametrize("failure_at", ["root", "config", "index"])
def test_initialized_submodule_probe_failure_never_becomes_non_git(tmp_path, failure_at):
    child = tmp_path / "sub"
    (child / ".git").mkdir(parents=True)
    success = subprocess.CompletedProcess([], 0, "", "")
    replies = [success, subprocess.CompletedProcess([], 0, "160000 " + "a" * 40 + " 0\tsub\0", "")]
    if failure_at != "root":
        replies.append(subprocess.CompletedProcess([], 0, str(child) + "\n", ""))
    if failure_at == "index":
        replies.append(success)
    replies.append(subprocess.CompletedProcess([], 128, "", "fatal: not a git repository"))
    runner = mock.Mock(side_effect=replies)
    with pytest.raises(OSError, match="submodule"):
        safe_git.probe(str(tmp_path), ["status", "--porcelain", "-z"], runner=runner)
    assert runner.call_count == len(replies)


def test_only_effective_filter_command_is_refused(tmp_path):
    config = "filter.fixture.clean\nold-command\0filter.fixture.clean\n\0"
    runner = mock.Mock(side_effect=[subprocess.CompletedProcess([], 0, config, ""),
                                   subprocess.CompletedProcess([], 0, "", ""),
                                   subprocess.CompletedProcess([], 0, "", "")])
    assert safe_git.probe(str(tmp_path), ["status", "--porcelain", "-z"], runner=runner).returncode == 0
    assert runner.call_count == 3
