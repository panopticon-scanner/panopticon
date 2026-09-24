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


def test_root_probe_uses_outer_checkout_boundary_but_keeps_requested_cwd(tmp_path):
    outer = tmp_path / "outer"
    inner = outer / "inner"
    start = inner / "src"
    start.mkdir(parents=True)
    (outer / ".git").mkdir()
    (inner / ".git").write_text("gitdir: /unused/linked-metadata\n")
    alias = tmp_path / "alias"
    alias.symlink_to(start, target_is_directory=True)
    runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0, str(inner), ""))
    resolved = executable.ResolvedExecutable("/trusted/git", "/trusted/bin")
    with mock.patch.object(executable, "resolve", return_value=resolved) as resolve:
        safe_git.probe(str(alias), ["rev-parse", "--show-toplevel"], runner=runner)
    assert resolve.call_args.args[1] == str(outer)
    assert runner.call_args.args[0][:3] == ["/trusted/git", "-C", str(alias)]


def test_unreadable_checkout_boundary_does_not_launch_git(tmp_path):
    runner = mock.Mock()
    with mock.patch.object(safe_git.os, "lstat", side_effect=PermissionError("unreadable")):
        with pytest.raises(OSError):
            safe_git.probe(str(tmp_path), ["rev-parse", "--show-toplevel"], runner=runner)
    runner.assert_not_called()


# --- #2006: the preflight gate is a CAPABILITY check, not argv equality -------
# #1985 gated the preflight on `args != ["status", "--porcelain", "-z"]`, so
# every other spelling of the same command -- a reordered flag, a pathspec,
# `--porcelain=v1` -- took the single unpreflighted call and skipped both the
# filter refusal and the submodule bound. These pin the direction the gate
# fails in: a spelling nobody enumerated preflights.

_PLANTED_FILTER = "filter.fixture.clean\nfixture-command-value-must-not-appear\0"


def _preflight_refusing_runner():
    """A runner whose first (config) reply plants a command filter.

    The refusal is raised from the preflight and nowhere else, so
    "did this argv preflight?" is exactly "did this raise on call 1?".
    """
    return mock.Mock(return_value=subprocess.CompletedProcess([], 0, _PLANTED_FILTER, ""))


@pytest.mark.parametrize("args", [
    ["status", "-z", "--porcelain"],                     # flag order reversed
    ["status", "--porcelain=v1", "-z"],                  # equals-form spelling
    ["status", "--porcelain", "-z", "--", "src"],        # a pathspec
    ["status"],                                          # the bare subcommand
])
def test_every_spelling_of_status_preflights(tmp_path, args):
    runner = _preflight_refusing_runner()
    with pytest.raises(OSError, match="filter"):
        safe_git.probe(str(tmp_path), args, runner=runner)
    assert runner.call_count == 1


@pytest.mark.parametrize("args", [
    ["fsck"],                                            # never enumerated
    ["diff", "--name-only", "-z", "HEAD"],               # runs diff/textconv drivers
    ["merge-base", "HEAD", "main"],
    ["ls-files", "--eol"],                               # the one filtered ls-files mode
    ["-c", "core.quotepath=false", "diff", "--name-only"],   # a global option first
    ["--no-pager", "rev-parse", "HEAD"],                 # an option we cannot classify
])
def test_unknown_and_content_reading_spellings_preflight(tmp_path, args):
    runner = _preflight_refusing_runner()
    with pytest.raises(OSError, match="filter"):
        safe_git.probe(str(tmp_path), args, runner=runner)
    assert runner.call_count == 1


@pytest.mark.parametrize("args", [
    ["rev-parse", "--show-toplevel"],
    ["rev-parse", "--verify", "-q", "main^{commit}"],
    ["ls-files", "--cached", "--others", "--exclude-standard", "-z"],
    ["symbolic-ref", "--short", "HEAD"],
    ["rev-list", "-1", "HEAD"],
])
def test_allowlisted_plumbing_runs_once_without_a_preflight(tmp_path, args):
    runner = _preflight_refusing_runner()
    result = safe_git.probe(str(tmp_path), args, runner=runner)
    assert result.returncode == 0
    assert runner.call_count == 1
    assert runner.call_args.args[0][5:] == args


def test_only_status_is_pinned_to_report_submodule_dirt(tmp_path):
    # `--ignore-submodules=none` is a status flag; appending it to any other
    # preflighted subcommand would either be rejected by git or change what the
    # caller asked for.
    runner = mock.Mock(side_effect=[subprocess.CompletedProcess([], 0, "", "")] * 3)
    safe_git.probe(str(tmp_path), ["diff", "--name-only", "-z", "HEAD"], runner=runner)
    assert runner.call_args.args[0][5:] == ["diff", "--name-only", "-z", "HEAD"]


def test_caller_timeout_and_bytes_contract_survive_the_preflight(tmp_path):
    # discovery's `_git` asks for 30 s and bytes; the preflight parses text and
    # must keep doing so, so only the FINAL call carries the caller's contract.
    runner = mock.Mock(side_effect=[subprocess.CompletedProcess([], 0, "", ""),
                                    subprocess.CompletedProcess([], 0, "", ""),
                                    subprocess.CompletedProcess([], 0, b"", b"")])
    with mock.patch.object(safe_git.time, "monotonic", side_effect=[100, 101, 102, 103]):
        safe_git.probe(str(tmp_path), ["status", "--porcelain", "-z"], runner=runner,
                       timeout=30, text=False)
    assert [call.kwargs["text"] for call in runner.call_args_list] == [True, True, False]
    assert [call.kwargs["timeout"] for call in runner.call_args_list] == [29, 28, 27]


# --- #2006 fix round 1 --------------------------------------------------------

@pytest.mark.parametrize("args,replies,fragment", [
    (["status", "--porcelain", "-z"],
     [subprocess.CompletedProcess([], 0, "filter.fixture.clean\ncmd\0", "")],
     "command filter"),
    (["status", "--porcelain", "-z"],
     [subprocess.CompletedProcess([], 0, "", ""),
      subprocess.CompletedProcess([], 0, "160000 " + "a" * 40 + " 0\t../escape\0", "")],
     "unsafe submodule path"),
])
def test_every_target_refusal_is_one_named_class(tmp_path, args, replies, fragment):
    # The callers need to tell "this tree is refused" apart from "git failed or
    # is absent" (also an OSError), because only the first is a hostile-target
    # finding the operator must SEE. Still an OSError, so every existing
    # `except OSError` handler keeps catching it.
    runner = mock.Mock(side_effect=replies)
    with pytest.raises(safe_git.RepositoryRefused, match=fragment):
        safe_git.probe(str(tmp_path), args, runner=runner)
    assert issubclass(safe_git.RepositoryRefused, OSError)


def test_a_failed_root_preflight_answers_in_the_callers_type(tmp_path):
    # The preflight always reads text; a caller that asked for bytes must not
    # be handed str on the failure path (#2006 concern 3).
    failure = subprocess.CompletedProcess([], 128, "", "fatal: not a git repository")
    runner = mock.Mock(return_value=failure)
    proc = safe_git.probe(str(tmp_path), ["status", "--porcelain", "-z"],
                          runner=runner, text=False)
    assert proc.returncode == 128
    assert proc.stdout == b""
    assert proc.stderr == b"fatal: not a git repository"
    # ... and a text caller still gets exactly the object the preflight saw.
    assert safe_git.probe(str(tmp_path), ["status", "--porcelain", "-z"],
                          runner=runner) is failure


def test_a_failed_root_index_preflight_answers_in_the_callers_type(tmp_path):
    runner = mock.Mock(side_effect=[subprocess.CompletedProcess([], 0, "", ""),
                                    subprocess.CompletedProcess([], 128, "", "bad index")])
    proc = safe_git.probe(str(tmp_path), ["status", "--porcelain", "-z"],
                          runner=runner, text=False)
    assert (proc.returncode, proc.stdout, proc.stderr) == (128, b"", b"bad index")
