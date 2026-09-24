"""Bounded trusted probes; temporary repositories contain only harmless commands."""
import os
import subprocess
from unittest import mock

import pytest

from scripts import executable, safe_git

# The two canned preflight replies every mock-runner sequence below is built
# from: `config --null --list --includes` output (NUL-terminated records), and
# "this launch said nothing".
def _config(*records):
    return subprocess.CompletedProcess([], 0, "".join(r + "\0" for r in records), "")


def _ok(stdout=""):
    return subprocess.CompletedProcess([], 0, stdout, "")


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
    assert args[0] == ["/trusted/git", "-C", str(tmp_path),
                       "-c", "core.fsmonitor=false",
                       "-c", "core.hooksPath=" + safe_git._no_hooks_path(),
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
    # The pin sits immediately after the subcommand, never after caller argv (I1).
    assert runner.call_args_list[-1].args[0][-4:] == ["status", "--ignore-submodules=none",
                                                     "--porcelain", "-z"]


def test_expired_preflight_budget_never_runs_status(tmp_path):
    runner = mock.Mock()
    with mock.patch.object(safe_git.time, "monotonic", side_effect=[100, 116]):
        with pytest.raises(subprocess.TimeoutExpired):
            safe_git.probe(str(tmp_path), ["status", "--porcelain", "-z"], runner=runner)
    runner.assert_not_called()


@pytest.mark.parametrize("setting", ["filter.fixture.clean", "filter.fixture.process",
                                     "filter.fixture.smudge"])
def test_filter_commands_are_neutralized_before_status(tmp_path, setting):
    """#2013: overridden with `-c <key>=`, then CONFIRMED empty, then run.

    #2006 refused this target outright, which made a git-lfs or git-crypt
    checkout unreviewable. The value is still never executed and still never
    printed -- it is emptied on every launch that follows the collection.
    """
    runner = mock.Mock(side_effect=[
        _config(setting + "\nfixture-command-value-must-not-appear"),  # root config
        _ok(),                                                         # root index
        _config(setting + "\n"),                                       # confirmation
        _ok(),                                                         # the status
    ])
    suppressed = []
    proc = safe_git.probe(str(tmp_path), ["status", "--porcelain", "-z"],
                          runner=runner, suppressed=suppressed)
    assert proc.returncode == 0
    assert suppressed == [(".", setting)]
    # Every launch AFTER the collecting read carries the override, and it sits
    # in the global position, before the subcommand.
    for call in runner.call_args_list[1:]:
        argv = call.args[0]
        assert setting + "=" in argv
        assert argv[argv.index(setting + "=") - 1] == "-c"
    assert "fixture-command-value-must-not-appear" not in " ".join(
        str(call.args[0]) for call in runner.call_args_list)


def test_a_required_filter_flag_is_neutralized_with_its_command(tmp_path):
    """An emptied clean command plus `required = true` is `fatal: clean filter
    'x' failed` (measured), so the whole driver has to come off, not just the
    command line."""
    runner = mock.Mock(side_effect=[
        _config("filter.fixture.clean\ncmd", "filter.fixture.required\ntrue"),
        _ok(),
        _config("filter.fixture.clean\n", "filter.fixture.required\n"),
        _ok(),
    ])
    suppressed = []
    safe_git.probe(str(tmp_path), ["status", "--porcelain", "-z"], runner=runner,
                   suppressed=suppressed)
    assert suppressed == [(".", "filter.fixture.clean"),
                          (".", "filter.fixture.required")]


def test_a_required_flag_without_a_command_is_left_alone(tmp_path):
    # Nothing to neutralize: the probe never invented the target's breakage and
    # must not claim a suppression it did not make.
    runner = mock.Mock(side_effect=[_config("filter.fixture.required\ntrue"), _ok(), _ok()])
    suppressed = []
    safe_git.probe(str(tmp_path), ["status", "--porcelain", "-z"], runner=runner,
                   suppressed=suppressed)
    assert suppressed == []
    assert runner.call_count == 3        # no confirmation read: nothing overridden


def test_an_override_that_does_not_take_effect_is_refused(tmp_path):
    """Ruling 3's fail-closed fallback: the probe proves the override, and a
    key that still reads non-empty is refused by name rather than run."""
    runner = mock.Mock(side_effect=[
        _config("filter.fixture.clean\ncmd"),
        _ok(),
        _config("filter.fixture.clean\nstill-here"),    # the override did nothing
    ])
    suppressed = []
    with pytest.raises(safe_git.RepositoryRefused, match="filter.fixture.clean"):
        safe_git.probe(str(tmp_path), ["status", "--porcelain", "-z"], runner=runner,
                       suppressed=suppressed)
    assert suppressed == []              # nothing is disclosed as suppressed
    assert runner.call_count == 3        # the status never ran


def test_a_caller_that_asks_for_nothing_is_suppressed_silently(tmp_path):
    # The manifest is the disclosure of record; every other caller just gets a
    # working probe (`suppressed` defaults to None).
    runner = mock.Mock(side_effect=[_config("filter.fixture.clean\ncmd"), _ok(),
                                    _config("filter.fixture.clean\n"), _ok()])
    assert safe_git.probe(str(tmp_path), ["status", "--porcelain", "-z"],
                          runner=runner).returncode == 0


def test_preflight_failure_is_returned_without_status(tmp_path):
    failure = subprocess.CompletedProcess([], 128, "", "fatal: not a git repository")
    runner = mock.Mock(return_value=failure)
    proc = safe_git.probe(str(tmp_path), ["status", "--porcelain", "-z"], runner=runner)
    # The preflight's returncode and stderr, verbatim -- that is the real cause.
    # No longer the same OBJECT: it now carries the argv the caller asked for,
    # so a `check=True` caller's error names `status` and not the preflight's
    # own `config --null --list` (#2006 fix round 2, M5).
    assert (proc.returncode, proc.stdout, proc.stderr) == (128, "", "fatal: not a git repository")
    assert proc.args[-3:] == ["status", "--porcelain", "-z"]
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


def _unprovable_override_runner():
    """A runner that plants a command filter and never honours the override.

    Every reply is the same config listing, so the confirmation read still sees
    the value and the probe refuses (#2013 ruling 3) -- raised from the
    preflight and nowhere else, so "did this argv preflight?" is exactly "did
    this raise?", as it was when the planted filter refused outright.
    """
    return mock.Mock(return_value=subprocess.CompletedProcess([], 0, _PLANTED_FILTER, ""))


@pytest.mark.parametrize("args", [
    ["status", "-z", "--porcelain"],                     # flag order reversed
    ["status", "--porcelain=v1", "-z"],                  # equals-form spelling
    ["status", "--porcelain", "-z", "--", "src"],        # a pathspec
    ["status"],                                          # the bare subcommand
])
def test_every_spelling_of_status_preflights(tmp_path, args):
    runner = _unprovable_override_runner()
    with pytest.raises(OSError, match="filter"):
        safe_git.probe(str(tmp_path), args, runner=runner)
    # config, index, confirmation -- and never the command itself.
    assert runner.call_count == 3


@pytest.mark.parametrize("args", [
    ["fsck"],                                            # never enumerated
    ["diff", "--name-only", "-z", "HEAD"],               # runs diff/textconv drivers
    ["merge-base", "HEAD", "main"],
    ["ls-files", "--eol"],                               # the one filtered ls-files mode
    ["-c", "core.quotepath=false", "diff", "--name-only"],   # a global option first
    ["--no-pager", "rev-parse", "HEAD"],                 # an option we cannot classify
])
def test_unknown_and_content_reading_spellings_preflight(tmp_path, args):
    runner = _unprovable_override_runner()
    with pytest.raises(OSError, match="filter"):
        safe_git.probe(str(tmp_path), args, runner=runner)
    assert runner.call_count == 3


@pytest.mark.parametrize("args", [
    ["rev-parse", "--show-toplevel"],
    ["rev-parse", "--verify", "-q", "main^{commit}"],
    ["ls-files", "--cached", "--others", "--exclude-standard", "-z"],
    ["symbolic-ref", "--short", "HEAD"],
    ["rev-list", "-1", "HEAD"],
])
def test_allowlisted_plumbing_runs_once_without_a_preflight(tmp_path, args):
    runner = _unprovable_override_runner()
    result = safe_git.probe(str(tmp_path), args, runner=runner)
    assert result.returncode == 0
    assert runner.call_count == 1
    assert runner.call_args.args[0][-len(args):] == args
    # No config was read, so nothing was collected and nothing is overridden.
    assert "filter.fixture.clean=" not in runner.call_args.args[0]


def test_only_status_is_pinned_to_report_submodule_dirt(tmp_path):
    # `--ignore-submodules=none` is a status flag; appending it to any other
    # preflighted subcommand would either be rejected by git or change what the
    # caller asked for.
    runner = mock.Mock(side_effect=[subprocess.CompletedProcess([], 0, "", "")] * 3)
    safe_git.probe(str(tmp_path), ["diff", "--name-only", "-z", "HEAD"], runner=runner)
    # The driver flags are ours (C1); `--ignore-submodules=none` is status-only.
    assert runner.call_args.args[0][-6:] == ["diff", "--no-ext-diff", "--no-textconv",
                                            "--name-only", "-z", "HEAD"]
    assert "--ignore-submodules=none" not in runner.call_args.args[0]


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
     [subprocess.CompletedProcess([], 0, "filter.fixture.clean\ncmd\0", ""),
      subprocess.CompletedProcess([], 0, "", ""),
      subprocess.CompletedProcess([], 0, "filter.fixture.clean\ncmd\0", "")],
     "did not take effect"),
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
    # ... and a text caller gets the same values, as str.
    text_proc = safe_git.probe(str(tmp_path), ["status", "--porcelain", "-z"],
                               runner=runner)
    assert (text_proc.stdout, text_proc.stderr) == ("", "fatal: not a git repository")


def test_a_failed_root_index_preflight_answers_in_the_callers_type(tmp_path):
    runner = mock.Mock(side_effect=[subprocess.CompletedProcess([], 0, "", ""),
                                    subprocess.CompletedProcess([], 128, "", "bad index")])
    proc = safe_git.probe(str(tmp_path), ["status", "--porcelain", "-z"],
                          runner=runner, text=False)
    assert (proc.returncode, proc.stdout, proc.stderr) == (128, b"", b"bad index")


def test_every_launch_suppresses_hooks_and_the_fsmonitor(tmp_path):
    # #2006 fix round 2, C2: `.git/hooks` is git's default, so no config
    # refusal can reach it -- every launch, preflight included, must point git
    # at a directory we own. One assertion over EVERY call, because a launch
    # site that forgets is exactly the regression.
    runner = mock.Mock(side_effect=[subprocess.CompletedProcess([], 0, "", "")] * 3)
    safe_git.probe(str(tmp_path), ["status", "--porcelain", "-z"], runner=runner)
    assert runner.call_count == 3
    for call in runner.call_args_list:
        argv = call.args[0]
        assert "core.fsmonitor=false" in argv
        assert "core.hooksPath=" + safe_git._no_hooks_path() in argv


def test_the_hooks_directory_is_ours_and_stays_empty(tmp_path):
    path = safe_git._no_hooks_path()
    assert os.path.isdir(path)
    assert os.listdir(path) == []
    assert safe_git._no_hooks_path() is path      # once per process, not per call


@pytest.mark.parametrize("setting", ["diff.external", "diff.hostile.command",
                                     "diff.hostile.textconv"])
def test_diff_command_drivers_are_neutralized_like_filters(tmp_path, setting):
    # #2006 fix round 2, C1: every one of these is a repository-authored
    # command line that `diff` will execute, and an external driver's output
    # REPLACES git's. #2013 empties it instead of refusing the target; the
    # `--no-ext-diff --no-textconv` pair stays on beside the override.
    runner = mock.Mock(side_effect=[
        _config(setting + "\nfixture-command-value-must-not-appear"),
        _ok(), _config(setting + "\n"), _ok(),
    ])
    suppressed = []
    safe_git.probe(str(tmp_path), ["diff", "--name-only", "HEAD"], runner=runner,
                   suppressed=suppressed)
    assert suppressed == [(".", setting)]
    argv = runner.call_args.args[0]
    assert setting + "=" in argv
    assert "--no-ext-diff" in argv and "--no-textconv" in argv
    assert "fixture-command-value-must-not-appear" not in " ".join(argv)


@pytest.mark.parametrize("args,expected", [
    (["diff", "--unified=0", "main"],
     ["diff", "--no-ext-diff", "--no-textconv", "--unified=0", "main"]),
    (["log", "-p", "-1"], ["log", "--no-ext-diff", "--no-textconv", "-p", "-1"]),
    (["show", "--oneline"], ["show", "--no-ext-diff", "--no-textconv", "--oneline"]),
    (["-c", "core.quotepath=false", "diff", "-z", "--", "a.py"],
     ["-c", "core.quotepath=false", "diff", "--no-ext-diff", "--no-textconv",
      "-z", "--", "a.py"]),
])
def test_every_diff_producing_launch_disables_the_drivers(tmp_path, args, expected):
    # Belt and braces beside the refusal: inserted after the SUBCOMMAND, so a
    # `--` pathspec cannot turn them into filenames, and `git status` -- which
    # rejects both flags -- never sees them.
    runner = mock.Mock(side_effect=[subprocess.CompletedProcess([], 0, "", "")] * 3)
    safe_git.probe(str(tmp_path), args, runner=runner)
    assert runner.call_args.args[0][-len(expected):] == expected


def test_status_never_receives_the_diff_flags(tmp_path):
    # `git status --no-ext-diff` is rc=129, unknown option.
    runner = mock.Mock(side_effect=[subprocess.CompletedProcess([], 0, "", "")] * 3)
    safe_git.probe(str(tmp_path), ["status", "--porcelain", "-z"], runner=runner)
    assert "--no-ext-diff" not in runner.call_args.args[0]


@pytest.mark.parametrize("args", [
    ["-C", "/etc", "rev-parse", "HEAD"],
    ["--git-dir=/tmp/elsewhere", "status", "--porcelain", "-z"],
    ["--git-dir", "/tmp/elsewhere", "status"],
    ["--work-tree=/tmp/elsewhere", "status"],
    ["--exec-path=/tmp", "status"],
    ["--namespace=x", "rev-parse", "HEAD"],
    ["--config-env=core.fsmonitor=EVIL", "status"],
])
def test_a_repo_redirecting_global_option_is_rejected_not_parsed_past(tmp_path, args):
    # #2006 fix round 2, M3: the preflight validates `root`, so an argv that
    # sends the FINAL call somewhere else would be preflighted against one
    # repository and run against another. No caller does this; a probe whose
    # whole point is failing closed should refuse rather than parse past it.
    runner = mock.Mock()
    with pytest.raises(ValueError, match="redirect"):
        safe_git.probe(str(tmp_path), args, runner=runner)
    runner.assert_not_called()


def test_our_own_dash_c_settings_are_still_allowed(tmp_path):
    runner = mock.Mock(side_effect=[subprocess.CompletedProcess([], 0, "", "")] * 3)
    safe_git.probe(str(tmp_path), ["-c", "core.quotepath=false", "diff", "--name-only"],
                   runner=runner)
    assert runner.call_count == 3


def test_a_failed_root_preflight_names_the_command_the_caller_asked_for(tmp_path):
    # #2006 fix round 2, M5: the failure was returned as the caller's own
    # result, so `discovery._git` raised CalledProcessError naming
    # `config --null --list --includes` and the operator read
    # "git diff failed: ... config ...".
    failure = subprocess.CompletedProcess(
        ["/trusted/git", "-C", str(tmp_path), "config", "--null", "--list", "--includes"],
        128, "", "fatal: not a git repository")
    runner = mock.Mock(return_value=failure)
    proc = safe_git.probe(str(tmp_path), ["diff", "--name-only", "HEAD"], runner=runner)
    assert proc.returncode == 128
    assert proc.stderr == "fatal: not a git repository"
    assert "diff" in proc.args and "config" not in proc.args


@pytest.mark.parametrize("args", [
    ["-c", "core.hooksPath=/somewhere/else", "status", "--porcelain", "-z"],
    ["-c", "core.fsmonitor=printf hit", "status", "--porcelain", "-z"],
    ["-c", "CORE.HOOKSPATH=/x", "rev-parse", "HEAD"],
    ["diff", "--ext-diff", "HEAD"],
    ["diff", "--textconv", "HEAD"],
    # #2013 ruling 5: a caller re-enabling a driver the probe empties is the
    # same hole as a caller undoing `core.hooksPath`.
    ["-c", "filter.lfs.clean=git-lfs clean", "status", "--porcelain", "-z"],
    ["-c", "FILTER.lfs.CLEAN=x", "status", "--porcelain", "-z"],
    ["-c", "filter.lfs.required=true", "status", "--porcelain", "-z"],
    ["-c", "diff.external=x", "diff", "--name-only"],
    ["-c", "diff.d.textconv=x", "diff", "--name-only"],
    # #2012 review M2: an included file's settings come after the pins and win.
    ["-c", "include.path=/nowhere/evil.cfg", "status", "--porcelain", "-z"],
    ["-c", "includeIf.gitdir:/.path=/nowhere/evil.cfg", "status", "--porcelain", "-z"],
    ["-c", "INCLUDE.PATH=/nowhere/evil.cfg", "worktree", "add", "--detach", "x", "HEAD"],
])
def test_a_caller_cannot_undo_what_the_probe_pins(tmp_path, args):
    """#2006 review N2: a caller's `-c` for a key the probe sets, or a flag
    re-enabling a diff driver, comes later in argv and would win. Refused."""
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True, timeout=30)
    entry = safe_git.mutate if "worktree" in args else safe_git.probe
    with pytest.raises(ValueError, match="override|re-enable"):
        entry(str(repo), args)


# --- #2012: `mutate`, the one entry point allowed to write -------------------

@pytest.mark.parametrize("args", [
    ["checkout", "main"],
    ["reset", "--hard", "HEAD"],
    ["worktree", "prune"],
    ["clean", "-fdx"],
    ["commit", "-am", "x"],
    ["status", "--porcelain", "-z"],
    # A write, but not the DELETE shape: the verb alone is not the permission.
    ["update-ref", "refs/heads/x", "deadbeef"],
    # Redirection and pin-undoing are refused here exactly as in `probe`, and
    # before the shape is even considered, so the message names what is wrong.
    ["-C", "/etc", "worktree", "add", "/tmp/wt", "deadbeef"],
    ["-c", "core.hooksPath=/somewhere/else", "worktree", "add", "/tmp/wt", "x"],
    ["-c", "filter.lfs.smudge=git-lfs smudge", "worktree", "add", "/tmp/wt", "x"],
])
def test_mutate_refuses_everything_but_the_pr_worktree_lifecycle(tmp_path, args):
    """#2012: an allowlist of one lifecycle, not a write permit.

    `worktree prune` and `checkout` are the near misses that matter -- both are
    a token away from a shape this does run -- and no git runs before the
    refusal.
    """
    runner = mock.Mock()
    with pytest.raises(ValueError):
        safe_git.mutate(str(tmp_path), args, runner=runner)
    runner.assert_not_called()


@pytest.mark.parametrize("args", [
    ["worktree", "add", "--detach", "/tmp/wt", "deadbeef"],
    ["worktree", "remove", "--force", "/tmp/wt"],
    ["update-ref", "-d", "refs/panopticon/pr-7-abc"],
])
def test_mutate_runs_the_three_shapes_the_pr_lifecycle_needs(tmp_path, args):
    runner = mock.Mock(side_effect=[_config(), _ok(), _ok()])
    proc = safe_git.mutate(str(tmp_path), args, runner=runner)
    assert proc.returncode == 0
    assert runner.call_args.args[0][-len(args):] == args


def test_a_mutating_call_preflights_even_if_its_subcommand_is_allowlisted(tmp_path):
    """`_NO_CONFIGURED_COMMAND` answers "can this subcommand run a
    repository-configured command?"; a WRITE does not get to ask. Pinned by
    adding the entry a future classifier might, and requiring the preflight
    anyway -- two saved launches are not worth the guarantee."""
    runner = mock.Mock(side_effect=[_config(), _ok(), _ok()])
    with mock.patch.dict(safe_git._NO_CONFIGURED_COMMAND, {"update-ref": ()}):
        safe_git.mutate(str(tmp_path), ["update-ref", "-d", "refs/x"], runner=runner)
    assert runner.call_count == 3          # config, index, then the command
    # The same argv through `probe` is the one-launch fast path, unchanged.
    fast = mock.Mock(side_effect=[_ok()])
    with mock.patch.dict(safe_git._NO_CONFIGURED_COMMAND, {"update-ref": ()}):
        safe_git.probe(str(tmp_path), ["update-ref", "-d", "refs/x"], runner=fast)
    assert fast.call_count == 1


def test_mutate_carries_the_hooks_pin_and_the_emptied_drivers(tmp_path):
    """The whole point of #2012, at the argv level.

    `worktree add` is a CHECKOUT, so the target's `filter.*.smudge` runs on its
    content and its `post-checkout` hook runs from whatever `core.hooksPath` the
    repository asked for. Both are closed by tokens in the GLOBAL position of
    this launch; the target's command line never appears in the argv at all.
    """
    runner = mock.Mock(side_effect=[
        _config("filter.evil.smudge\nsh ./evil.sh-must-not-appear",
                "filter.evil.required\ntrue",
                "core.hooksPath\n.githooks"),          # root config
        _ok(),                                         # root index
        _config("filter.evil.smudge\n", "filter.evil.required\n",
                "core.hooksPath\n.githooks"),          # confirmation
        _ok(),                                         # the worktree add
    ])
    suppressed = []
    resolved = executable.ResolvedExecutable("/trusted/git", "/trusted/bin")
    with mock.patch.object(executable, "resolve", return_value=resolved):
        proc = safe_git.mutate(str(tmp_path),
                               ["worktree", "add", "--detach", "/tmp/wt", "deadbeef"],
                               runner=runner, timeout=180, suppressed=suppressed)
    assert proc.returncode == 0
    # Sorted, as every disclosure from this module is.
    assert suppressed == [(".", "filter.evil.required"), (".", "filter.evil.smudge")]
    argv, options = runner.call_args.args[0], runner.call_args.kwargs
    assert argv[:3] == ["/trusted/git", "-C", str(tmp_path)]
    assert argv[-5:] == ["worktree", "add", "--detach", "/tmp/wt", "deadbeef"]
    assert "core.fsmonitor=false" in argv
    # The pin wins over the target's `core.hooksPath = .githooks`, which points
    # INTO the tree being checked out.
    assert "core.hooksPath=" + safe_git._no_hooks_path() in argv
    for key in ("filter.evil.smudge=", "filter.evil.required="):
        assert argv[argv.index(key) - 1] == "-c"
    assert "evil.sh-must-not-appear" not in " ".join(argv)
    assert options["env"] == {"PATH": "/trusted/bin", "LC_ALL": "C",
                              "GIT_CONFIG_NOSYSTEM": "1",
                              "GIT_CONFIG_SYSTEM": os.devnull,
                              "GIT_CONFIG_GLOBAL": os.devnull}
    assert 0 < options["timeout"] <= 180        # the caller's shared deadline


def test_the_public_hooks_path_is_the_one_every_launch_pins(tmp_path):
    # `diff_map`'s fetch keeps the operator's environment and pins this same
    # directory by hand; a second, unproved empty directory would be a second
    # thing to keep empty.
    assert safe_git.no_hooks_path() == safe_git._no_hooks_path()
    assert os.listdir(safe_git.no_hooks_path()) == []


# #2041: the keys a FETCH executes, or can be made to execute, from the
# checkout's own config -- the one call that keeps the operator's environment.
# `credential.<url>.helper` carries a URL, whose dots make it a multi-part
# subsection; `protocol.allow`/`protocol.ext.allow` are what unlock an `ext::`
# helper a repo-local `remote.<name>.url` can name -- and only those two:
# `protocol.file.allow` is the documented local-submodule setting and runs
# nothing.
TRANSPORT_KEYS = ("core.sshcommand", "core.gitproxy", "remote.origin.uploadpack",
                  "remote.origin.vcs", "credential.helper",
                  "credential.https://example.com.helper", "protocol.allow",
                  "protocol.ext.allow")
# Neighbours in the same sections that run nothing: a URL, a refspec, a key
# whose variable merely starts the same way, a username, a number.
NOT_TRANSPORT_KEYS = ("remote.origin.url", "remote.origin.fetch", "core.sshcommandx",
                      "credential.username", "protocol.version",
                      "protocol.file.allow", "protocol.https.allow")


def test_every_transport_command_key_is_refused_and_its_neighbours_are_not():
    for key in TRANSPORT_KEYS:
        assert safe_git._is_transport_command_setting(key), key
        assert safe_git.transport_command_keys({key: "cmd"}) == [key], key
    for key in NOT_TRANSPORT_KEYS:
        assert not safe_git._is_transport_command_setting(key), key
        assert safe_git.transport_command_keys({key: "value"}) == [], key


def test_transport_command_keys_are_sorted_and_only_the_set_values_count():
    """Sorted, like every other list this module hands out, so the refusal
    message is stable; a key set and then EMPTIED (`git config core.sshCommand
    ""`) executes nothing and is not refused (#2041)."""
    settings = {"remote.origin.uploadpack": "up.sh", "core.sshcommand": "ssh.sh",
                "core.gitproxy": "", "remote.origin.url": "git@example.invalid:x"}
    assert safe_git.transport_command_keys(settings) == ["core.sshcommand",
                                                        "remote.origin.uploadpack"]
    assert safe_git.transport_command_keys({"core.sshcommand": ""}) == []


def test_a_transport_key_normalizes_the_way_git_compares_it():
    """Section and variable case-insensitively, the SUBSECTION case-sensitively
    -- `_canonical_key`'s semantics, because that is what git does. The key is
    reported exactly as the config read printed it."""
    assert safe_git._is_transport_command_setting("Core.sshCommand")
    assert safe_git._is_transport_command_setting("REMOTE.Origin.UPLOADPACK")
    assert safe_git.transport_command_keys({"remote.Origin.uploadpack": "up.sh"}) == [
        "remote.Origin.uploadpack"]


def test_a_transport_key_is_refused_never_emptied():
    """These are NOT suppressible (#2041 owner ruling: refuse with a remedy).

    The probe empties `filter.*`/`diff.*` commands on every launch, but the
    fetch runs with the operator's environment and `core.sshCommand` is
    legitimately how a private repository is reached -- emptying it would break
    the case the fetch exemption exists for, so the refusal is the answer and
    the remedy is the operator's own global config.
    """
    for key in TRANSPORT_KEYS:
        assert not safe_git._is_command_setting(key), key
        assert not safe_git._is_suppressible(key), key
    assert safe_git._driver_keys({key: "cmd" for key in TRANSPORT_KEYS}) == []


def _scoped(*records):
    """`config --null --list --show-scope` output: (scope, key, value) triples."""
    return "".join("%s\0%s\n%s\0" % triple for triple in records)


def test_repository_settings_keeps_only_the_repositorys_own_scopes():
    """#2041 C1: `local` (its `.git/config` and every file that includes into
    it) and `worktree` (`$GIT_DIR/config.worktree`) are the repository's; the
    operator's `global`/`system` -- the remedy the refusal points at -- and this
    probe's own `command` pins are not."""
    stdout = _scoped(
        ("local", "core.sshcommand", "/repo/ssh.sh"),
        ("worktree", "remote.origin.uploadpack", "/repo/up.sh"),
        ("global", "core.sshcommand", "/home/me/ssh.sh"),
        ("system", "credential.helper", "osxkeychain"),
        ("command", "core.hookspath", "/tmp/none"),
        ("unknown", "credential.helper", "osxkeychain"))
    assert safe_git.repository_settings(stdout) == {
        "core.sshcommand": "/repo/ssh.sh",
        "remote.origin.uploadpack": "/repo/up.sh"}


def test_repository_settings_survives_newline_values_and_a_ragged_tail():
    """The pairing is positional over NUL-terminated records, so a value
    containing a NEWLINE cannot shift it (that is why `--null` is passed), and
    a later scope wins for the same key, as git's own precedence does."""
    stdout = _scoped(("local", "core.sshcommand", "ssh\nsecond line"),
                     ("worktree", "core.sshcommand", "wins"))
    assert safe_git.repository_settings(stdout) == {"core.sshcommand": "wins"}
    assert safe_git.repository_settings("") == {}
    # A valueless key (`[extensions]\n\tworktreeConfig`) prints with no value and
    # reads as empty, which `transport_command_keys` treats as "runs nothing".
    assert safe_git.repository_settings("local\0core.sshcommand\0") == {
        "core.sshcommand": ""}
    # A record with no partner is dropped rather than guessed at. A scope whose
    # key arrived but whose trailing NUL did not is indistinguishable from a
    # valueless key, and reads as one -- empty, so it refuses nothing, and a
    # read truncated that way failed its rc in `_safe` first.
    assert safe_git.repository_settings(
        _scoped(("local", "core.gitproxy", "proxy.sh")) + "local") == {
            "core.gitproxy": "proxy.sh"}
