import json
import os
import subprocess
from types import SimpleNamespace
from unittest import mock

import pytest

from scripts import codex_host
from scripts.runners import base, codex, outage


@pytest.fixture(autouse=True)
def registered(tmp_path, monkeypatch):
    """A registration directory holding every role shell.

    Autouse so no test in this file can read the operator's real
    ~/.codex/agents: Codex is enforced-only (I-1), so `prepare` now refuses a
    directory that is missing a driver role's shell, and that answer must come
    from this fixture rather than from whatever the machine happens to have.
    """
    import dataclasses

    from scripts import dispatch, hosts
    directory = tmp_path / "codex-agents"
    directory.mkdir()
    for role_file in dispatch.ROLE_FILES.values():
        (directory / dispatch.registered_agent_filename("codex", role_file)).write_text(
            "", encoding="utf-8")
    monkeypatch.setitem(hosts.HOSTS, "codex", dataclasses.replace(
        hosts.spec("codex"), registration_dir=str(directory)))
    return directory


def envelope(*events):
    return "\n".join(json.dumps(event) for event in events)


START = {"type": "thread.started", "thread_id": "session-1"}
REPLY = {"type": "item.completed", "item": {"type": "agent_message", "text": '{"domains": []}'}}
DONE = {"type": "turn.completed", "usage": {
    "input_tokens": 100, "cached_input_tokens": 60, "output_tokens": 20}}


def test_the_host_surface_is_the_failed_turns_own_error_not_the_agent_message():
    # #1623 C1: the `turn.failed`/`error` event IS the host talking; an
    # agent_message about a 403 handler is not.
    failed = {"type": "turn.failed", "error": {"type": "rate_limit_error",
                                               "message": "429 Too Many Requests"}}
    result = codex.Runner.parse_envelope("e", envelope(START, failed), 1)
    assert result.failure_class == outage.HOST_FAILURE
    finding = {"type": "item.completed",
               "item": {"type": "agent_message", "text": "/admin returns 403 Forbidden"}}
    result = codex.Runner.parse_envelope("e", envelope(START, finding), 1)
    assert result.host_error is None
    assert result.failure_class == outage.ENTRY_FAILURE


def test_a_rate_limited_launch_that_printed_nothing_reads_its_stderr():
    # The codex outage shape #1623 names: the JSONL never starts, and the
    # reason is on stderr.
    result = codex.Runner.parse_envelope("e", "", 1, stderr="stream error: exceeded rate limit\n")
    assert result.failure_class == outage.HOST_FAILURE
    assert codex.Runner.parse_envelope("e", "", 1).failure_class == outage.ENTRY_FAILURE


def test_a_failed_codex_launch_carries_the_redacted_head_of_stderr():
    # #1732 part 3: the same stderr this family already hands the classifier
    # is also kept ON the result, bounded and redacted, so the ledger row can
    # say what the CLI actually complained about. `host_error` and its
    # classification are untouched -- the new field is never fed to the
    # classifier.
    noisy = "boom " * 200 + "sk-ant-api03-AAAABBBBCCCCDDDDEEEEFFFF"
    result = codex.Runner.parse_envelope("e", "", 1, stderr=noisy)
    assert not result.ok
    assert len(result.stderr) == base.STDERR_HEAD
    assert result.stderr.startswith("boom")
    assert "sk-ant-" not in result.stderr


def test_a_successful_codex_launch_carries_no_stderr():
    result = codex.Runner.parse_envelope("e", envelope(START, REPLY, DONE), 0,
                                         stderr="a warning nobody needs")
    assert result.ok
    assert result.stderr is None


def test_exec_jsonl_preserves_final_reply_and_session_without_inventing_cost_or_model():
    result = codex.Runner.parse_envelope("e", envelope(START, REPLY, DONE), 0)
    assert result.ok
    assert result.entry_id == "e"
    assert result.text == '{"domains": []}'
    assert result.session_id == "session-1"
    assert result.cost_usd is None
    assert result.model is None
    assert result.usage == {"input_tokens": 40, "output_tokens": 20,
                            "cache_read_input_tokens": 60, "cache_creation_input_tokens": 0}
    assert sum(result.usage.values()) == 120


def test_final_message_replaces_commentary():
    comment = {"type": "item.completed", "item": {"type": "agent_message", "text": "Inspecting."}}
    result = codex.Runner.parse_envelope("e", envelope(comment, REPLY, DONE), 0)
    assert result.text == REPLY["item"]["text"]


@pytest.mark.parametrize("stdout,code,why", [
    ("not JSON", 0, "JSONL"),
    ("[]", 0, "object"),
    (envelope(REPLY), 0, "turn.completed"),
    (envelope(DONE), 0, "final message"),
    (envelope(REPLY, DONE), 2, "status 2"),
    (envelope({"type": "turn.failed", "error": {"message": "quota exhausted"}}), 0, "quota"),
    (envelope({"type": "error", "message": "disconnected"}), 0, "disconnected"),
    (envelope({"type": "turn.completed", "usage": []}, REPLY), 0, "usage is not an object"),
])
def test_bad_or_incomplete_envelopes_fail(stdout, code, why):
    result = codex.Runner.parse_envelope("e", stdout, code)
    assert not result.ok
    assert why in result.error


@pytest.mark.parametrize("usage", [
    {"input_tokens": -1}, {"input_tokens": True}, {"input_tokens": "10"},
    {"input_tokens": 5, "cached_input_tokens": 6}, [1],
])
def test_invalid_usage_is_not_fabricated(usage):
    result = codex.Runner.parse_envelope("e", envelope(REPLY, {"type": "turn.completed", "usage": usage}), 0)
    assert not result.ok
    assert "JSONL" in result.error


def test_failed_launch_keeps_preceding_usage_and_denials():
    denied = {"type": "mcp_tool_call", "tool": "read_file", "result": {
        "isError": True, "content": [{"type": "text", "text": "outside entry scope"}]}}
    result = codex.Runner.parse_envelope("e", envelope(
        START, {"type": "item.completed", "item": denied}, REPLY, DONE,
        {"type": "turn.failed", "error": "transport failed"}), 1)
    assert not result.ok
    assert result.usage["output_tokens"] == 20
    assert result.denials == [denied]


def test_native_failed_mcp_item_retains_denial_without_is_error_flag():
    # Captured shape from codex-cli 0.153.4, including calls nested in Code
    # Mode: isError is absent and error is null even when the broker denies.
    allowed = {
        "type": "mcp_tool_call", "server": "panopticon_scope", "tool": "read_file",
        "status": "completed", "error": None,
        "result": {"content": [{"type": "text", "text": "inside.txt:1:allowed"}],
                   "structured_content": None},
    }
    denied = {
        "type": "mcp_tool_call", "server": "panopticon_scope", "tool": "read_file",
        "status": "failed", "error": None,
        "result": {"content": [{"type": "text", "text":
                    "Read tool refused: Denied: outside.txt is outside this entry's read scope"}],
                   "structured_content": None},
    }
    result = codex.Runner.parse_envelope("e", envelope(
        START, {"type": "item.completed", "item": allowed},
        {"type": "item.completed", "item": denied}, REPLY, DONE), 0)
    assert result.ok
    assert result.denials == [denied]
    assert result.usage["output_tokens"] == 20


def entry():
    return {"id": "review-app-SEC", "agent": "panopticon-domain-panel",
            "enforced": True, "model": "fixture-model", "delivery": "return_json",
            "prompt": "panopticon-entry: review-app-SEC\nReview.",
            "scope": {"files": [], "dirs": [], "reads": []}}


def scratch_argv(tmp_path, name="codex-cwd"):
    """An argv shaped like `codex_host.command`'s, whose `--cd` scratch is
    registered exactly as a real launch registers it.

    #1657 step 2: the launch cwd is now looked up in codex_host's own registry
    (`codex_host.launch_cwd`), so a fake argv with no `--cd` is no longer a
    launchable one. `run_entry`'s `finally` releases the registration through
    `cleanup_command`, the same way a real launch does.
    """
    scratch = tmp_path / name
    scratch.mkdir()
    runtime = tmp_path / (name + "-runtime")
    runtime.mkdir()
    with codex_host._COMMAND_LOCK:
        codex_host._COMMAND_DIRS[str(scratch)] = (str(runtime), str(tmp_path))
    return ["codex", "exec", "--cd", str(scratch), "--json", "-"]


@pytest.fixture(autouse=True)
def _release_registered_scratches(tmp_path):
    yield
    for path in tuple(codex_host._COMMAND_DIRS):
        if path.startswith(str(tmp_path)):
            codex_host.cleanup_command(["--cd", path])


def test_the_launch_runs_in_the_scratch_directory_cd_names(tmp_path):
    # #1657 step 2 / CX-9: the process cwd used to be the REVIEW ROOT while
    # `--cd` named an external scratch, so a target's `.codex/skills`,
    # `AGENTS.md` and `.codex/config.toml` were still one discovery walk away
    # from the child, depending on which root the CLI keys off. Same directory
    # now, and the question stops mattering.
    seen = {}

    def fake_run(command, **kwargs):
        seen.update(command=command, **kwargs)
        return SimpleNamespace(stdout=envelope(START, REPLY, DONE), stderr="", returncode=0)

    argv = scratch_argv(tmp_path)
    overlay = {base.ENV_ENTRY_ID: entry()["id"], base.ENV_READ_SCOPE: str(tmp_path / "scope.json"),
               base.ENV_WRITE_ALLOWLIST: str(tmp_path / "allow.json")}
    review_root = tmp_path / "review"
    review_root.mkdir()
    with mock.patch.object(codex.codex_host, "command", return_value=argv), \
            mock.patch.object(codex.codex_host, "validate_command"):
        runner = codex.Runner(runner=fake_run)
        runner.prepare(str(tmp_path), str(review_root))
        assert runner.run_entry(entry(), overlay).ok
    assert seen["cwd"] == argv[argv.index("--cd") + 1]
    assert seen["cwd"] != str(review_root)


def test_an_unregistered_scratch_is_never_launched_in(tmp_path):
    # The refusal is codex_host.launch_cwd's, and `run_entry` turns it into a
    # failed entry rather than a launch in a directory nothing allocated.
    fake_run = mock.Mock(side_effect=AssertionError("must not launch"))
    foreign = tmp_path / "not-ours"
    foreign.mkdir()
    with mock.patch.object(codex.codex_host, "command",
                           return_value=["codex", "exec", "--cd", str(foreign), "-"]), \
            mock.patch.object(codex.codex_host, "validate_command"):
        runner = codex.Runner(runner=fake_run)
        runner.prepare(str(tmp_path), str(tmp_path))
        result = runner.run_entry(entry(), {base.ENV_ENTRY_ID: entry()["id"]})
    assert not result.ok
    assert "not allocated" in result.error
    fake_run.assert_not_called()


def test_run_entry_inherits_environment_and_passes_prompt_on_stdin(tmp_path):
    seen = {}

    def fake_run(command, **kwargs):
        seen.update(command=command, **kwargs)
        return SimpleNamespace(stdout=envelope(START, REPLY, DONE), stderr="", returncode=0)

    overlay = {base.ENV_ENTRY_ID: entry()["id"], base.ENV_READ_SCOPE: str(tmp_path / "scope.json"),
               base.ENV_WRITE_ALLOWLIST: str(tmp_path / "allow.json")}
    with mock.patch.dict(os.environ, {"PATH": "/fixture/bin", "HOME": str(tmp_path)}, clear=True), \
            mock.patch.object(codex.codex_host, "command", return_value=scratch_argv(tmp_path)) as command, \
            mock.patch.object(codex.codex_host, "validate_command") as validate:
        runner = codex.Runner(runner=fake_run)
        runner.prepare(str(tmp_path), str(tmp_path))
        result = runner.run_entry(entry(), overlay)
    assert result.ok
    assert seen["env"] == {"PATH": "/fixture/bin", "HOME": str(tmp_path), **overlay}
    assert seen["input"] == entry()["prompt"]
    assert entry()["prompt"] not in seen["command"]
    # The child runs in the run-owned `--cd` scratch, never the review root
    # (#1657 step 2); test_the_launch_runs_in_the_scratch_directory_cd_names
    # is where that rule is stated.
    assert seen["cwd"] == seen["command"][seen["command"].index("--cd") + 1]
    assert seen["timeout"] == runner.entry_timeout
    # D10 ruling 3: the schema pair is computed by the SEAM helper and handed
    # to codex_host, which owns the argv -- empty here, since this entry names
    # no schema.
    command.assert_called_once_with(entry(), seen["env"], str(tmp_path), str(tmp_path),
                                    runner=fake_run, schema_argv=[])
    validate.assert_called_once_with(seen["command"], seen["env"], str(tmp_path))


def test_run_entry_prepares_its_environment_through_launch_env(tmp_path):
    # #1626 I2: ONE env preparation per runner. Codex's was already exactly
    # the seam's default (os.environ plus the overlay), so it inherits
    # `HostRunner.launch_env` rather than overriding it -- and `run_entry`
    # calls it instead of rebuilding the dict, so a probe that needs the same
    # environment has somewhere to get it.
    assert codex.Runner.launch_env is base.HostRunner.launch_env

    def fake_run(command, **kwargs):
        return SimpleNamespace(stdout=envelope(START, REPLY, DONE), stderr="", returncode=0)

    runner = codex.Runner(runner=fake_run)
    runner.prepare(str(tmp_path), str(tmp_path))
    with mock.patch.object(codex.codex_host, "command", return_value=scratch_argv(tmp_path)), \
            mock.patch.object(codex.codex_host, "validate_command"), \
            mock.patch.object(runner, "launch_env", wraps=runner.launch_env) as prepared:
        assert runner.run_entry(entry(), {base.ENV_ENTRY_ID: entry()["id"]}).ok
    assert prepared.call_count == 1


@pytest.mark.parametrize("error", [FileNotFoundError("codex"), ValueError("launch failure"),
                                  subprocess.TimeoutExpired("codex", 1)])
def test_launch_exceptions_never_escape(tmp_path, error):
    def fake_run(*args, **kwargs):
        raise error
    runner = codex.Runner(runner=fake_run)
    runner.prepare(str(tmp_path), str(tmp_path))
    with mock.patch.object(codex.codex_host, "command", return_value=scratch_argv(tmp_path)), \
            mock.patch.object(codex.codex_host, "validate_command"):
        result = runner.run_entry(entry(), {base.ENV_ENTRY_ID: entry()["id"]})
    assert not result.ok
    assert ("timed out" if isinstance(error, subprocess.TimeoutExpired) else str(error)) in result.error


def test_missing_preparation_binding_or_return_delivery_never_launches(tmp_path):
    fake_run = mock.Mock(side_effect=AssertionError("must not launch"))
    runner = codex.Runner(runner=fake_run)
    assert not runner.run_entry(entry(), {}).ok
    runner.prepare(str(tmp_path), str(tmp_path))
    assert not runner.run_entry(entry(), {}).ok
    assert not runner.run_entry(entry(), {base.ENV_ENTRY_ID: "another-entry"}).ok
    assert not runner.run_entry(dict(entry(), delivery=None), {base.ENV_ENTRY_ID: entry()["id"]}).ok
    assert not runner.run_entry(None, {}).ok
    fake_run.assert_not_called()


def test_prepare_is_idempotent_and_leaves_guard_arming_to_the_loop(tmp_path):
    # The subject is the RUN directory, which is what prepare is handed and
    # what it must leave untouched; the registration fixture lives beside it.
    run = tmp_path / "run"
    run.mkdir()
    runner = codex.Runner(runner=mock.Mock())
    runner.prepare(str(run), str(tmp_path))
    runner.prepare(str(run), str(tmp_path))
    assert list(run.iterdir()) == []


# --- I-5 / M-5: the seam's launcher is a module attribute, and the suite
# refuses to reach the real CLI through it ------------------------------------


def test_the_launcher_is_a_module_attribute_read_at_construction(monkeypatch):
    def sentinel(*args, **kwargs):
        raise AssertionError("never called")

    monkeypatch.setattr(codex, "DEFAULT_RUNNER", sentinel)
    assert codex.Runner().runner is sentinel


def test_the_seam_names_its_cli_and_the_flags_that_print_the_envelope(tmp_path):
    from types import SimpleNamespace as NS

    from scripts import codex_host

    def catalog(argv, **kwargs):
        return NS(returncode=0, stdout=json.dumps({"models": [{"slug": "m"}]}), stderr="")

    root = tmp_path / "review"
    root.mkdir()
    env = {"PANOPTICON_ENTRY_ID": "setup-scan",
           "PANOPTICON_WRITE_ALLOWLIST": str(root / "w.json"),
           "PANOPTICON_READ_SCOPE": str(root / "s.json")}
    argv = codex_host.command({"id": "setup-scan", "agent": None, "model": "m"},
                              env, root, tmp_path / "run", runner=catalog)
    codex_host.cleanup_command(argv)
    assert argv[0] == codex.Runner.CLI
    assert codex.Runner.ENVELOPE_FLAGS
    assert all(flag in argv for flag in codex.Runner.ENVELOPE_FLAGS)


def test_the_suite_guard_refuses_a_live_codex_launch():
    from scripts import codex_host

    for module in (codex, codex_host):
        with pytest.raises(codex_host.LaunchRefused):
            module.DEFAULT_RUNNER(["codex", "--version"])
    assert codex.Runner().runner is not subprocess.run


# --- I-1: Codex is enforced-only, and says so once, up front -----------------


def test_prepare_refuses_once_when_a_role_shell_is_missing(tmp_path, registered):
    from scripts import dispatch
    missing = registered / dispatch.registered_agent_filename("codex", "scout.md")
    missing.unlink()
    launcher = mock.Mock(side_effect=AssertionError("must not launch"))
    runner = codex.Runner(runner=launcher)
    with pytest.raises(ValueError) as caught:
        runner.prepare(str(tmp_path), str(tmp_path))
    message = str(caught.value)
    assert "enforced-only" in message
    assert missing.name in message
    assert "python3 skill/scripts/dispatch.py --emit-host-agents codex" in message
    launcher.assert_not_called()


def test_prepare_accepts_a_fully_registered_directory(tmp_path, registered):
    codex.Runner(runner=mock.Mock()).prepare(str(tmp_path), str(tmp_path))


def test_prepare_skips_the_shell_check_for_the_setup_namespace(tmp_path, registered):
    # setup-scan is dispatched with no `agent` and runs off safety_config()
    # alone, so `driver loop --setup --host codex` is exactly how a fresh
    # machine is meant to start -- before anything is registered. The
    # enforced-only refusal is about REVIEWER entries and must not fire here.
    from scripts import dispatch
    for role_file in dispatch.ROLE_FILES.values():
        (registered / dispatch.registered_agent_filename("codex", role_file)).unlink()
    runner = codex.Runner(runner=mock.Mock(side_effect=AssertionError("must not launch")))
    runner.namespace = "setup"
    runner.prepare(str(tmp_path), str(tmp_path))
    runner.namespace = None
    with pytest.raises(ValueError, match="enforced-only"):
        runner.prepare(str(tmp_path), str(tmp_path))


# --- M-2: a transient error the turn recovered from is not a failed entry ----


def test_a_recovered_turn_clears_an_earlier_transient_error():
    for event in ({"type": "error", "message": "stream reset"},
                  {"type": "turn.failed", "error": {"message": "retrying"}}):
        result = codex.Runner.parse_envelope("e", envelope(START, event, REPLY, DONE), 0)
        assert result.ok, result.error
        assert result.error is None
        assert result.text == REPLY["item"]["text"]


def test_commentary_before_the_failure_does_not_clear_it():
    # N-I3: `if text:` treated "some agent_message has been seen" as "this
    # turn produced its final message", and commentary legitimately precedes
    # the final JSON (the parser's own docstring says so). The turn below
    # never recovered: the entry must stay failed, exactly as the PR head had
    # it, or the loop ledgers a success, discards the error text and never
    # counts the strike.
    commentary = {"type": "item.completed",
                  "item": {"type": "agent_message",
                           "text": "Let me start by reading the files."}}
    aborted = {"type": "error", "message": "model stream aborted before the final answer"}
    result = codex.Runner.parse_envelope("e", envelope(
        START, commentary, aborted, DONE), 0)
    assert not result.ok
    assert "model stream aborted" in result.error


def test_a_reply_after_the_failure_is_a_recovery():
    # The other side of the same ordering: the final message ARRIVED after the
    # failure event, so the turn did recover.
    aborted = {"type": "error", "message": "stream reset"}
    result = codex.Runner.parse_envelope("e", envelope(START, aborted, REPLY, DONE), 0)
    assert result.ok, result.error
    assert result.error is None
    assert result.text == REPLY["item"]["text"]


def test_a_failure_after_the_completed_turn_still_fails():
    result = codex.Runner.parse_envelope("e", envelope(
        START, REPLY, DONE, {"type": "turn.failed", "error": "transport failed"}), 0)
    assert not result.ok
    assert "transport failed" in result.error


# --- M-9: a flag the runner cannot honour says so ----------------------------


def test_the_seam_declares_whether_it_honours_max_turns():
    assert base.HostRunner.HONOURS_MAX_TURNS is True
    assert codex.Runner.HONOURS_MAX_TURNS is False


def test_the_family_declares_the_output_schema_flag_its_argv_carries():
    # D10 ruling 3, the seam-to-argv binding (ENVELOPE_FLAGS' own pattern):
    # `codex exec --output-schema <file>` is what constrains the final message,
    # and the attribute the loop-side helper reads must name that same flag.
    assert codex.Runner.OUTPUT_SCHEMA_FLAG == ("--output-schema",)


def test_a_review_cell_launch_hands_the_published_schema_to_the_argv_builder(tmp_path):
    # The family half of D10 ruling 3: the Runner reads the entry's schema
    # through the seam helper and hands the pair to `codex_host.command`, which
    # owns the argv (and places it before the trailing stdin marker -- see
    # tests/test_codex_host.py, where the finished argv and its validator live).
    import scripts._version as version
    schema = os.path.abspath(version.reference_path("findings-envelope-schema.json"))
    cell = dict(entry(), output_schema=schema)

    def fake_run(command, **kwargs):
        return SimpleNamespace(stdout=envelope(START, REPLY, DONE), stderr="", returncode=0)

    overlay = {base.ENV_ENTRY_ID: cell["id"], base.ENV_READ_SCOPE: str(tmp_path / "scope.json"),
               base.ENV_WRITE_ALLOWLIST: str(tmp_path / "allow.json")}
    with mock.patch.object(codex.codex_host, "command", return_value=scratch_argv(tmp_path)) as command, \
            mock.patch.object(codex.codex_host, "validate_command"):
        runner = codex.Runner(runner=fake_run)
        runner.prepare(str(tmp_path), str(tmp_path))
        runner.run_entry(cell, overlay)
    assert command.call_args.kwargs["schema_argv"] == ["--output-schema", schema]


def test_a_timed_out_launch_keeps_its_partial_jsonl_and_the_usage_in_it(tmp_path):
    # D10 ruling 5: exec prints a line per event, so a killed launch's stdout
    # still carries every usage line it emitted. Those tokens were spent --
    # `Ledger.usage_document` counts failed rows for exactly this reason -- and
    # the partial output is the only evidence of what the entry was doing.
    partial = envelope(START, REPLY, DONE) + '\n{"type": "item.completed", "item"'

    def slow(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs.get("timeout"), output=partial.encode())

    overlay = {base.ENV_ENTRY_ID: entry()["id"], base.ENV_READ_SCOPE: str(tmp_path / "scope.json"),
               base.ENV_WRITE_ALLOWLIST: str(tmp_path / "allow.json")}
    with mock.patch.object(codex.codex_host, "command", return_value=scratch_argv(tmp_path)), \
            mock.patch.object(codex.codex_host, "validate_command"):
        runner = codex.Runner(runner=slow)
        runner.prepare(str(tmp_path), str(tmp_path))
        result = runner.run_entry(entry(), overlay)
    assert not result.ok
    assert "timed out after" in result.error
    assert result.text == partial
    assert result.usage == {"input_tokens": 40, "output_tokens": 20,
                            "cache_read_input_tokens": 60, "cache_creation_input_tokens": 0}


def test_a_timed_out_launch_carries_the_killed_childs_stderr(tmp_path):
    # #1732 fix round 2: the `TimeoutExpired` path kept the partial JSONL and
    # dropped stderr, so the failure that costs a whole entry timeout ledgered
    # no diagnosis. `TimeoutExpired` carries both streams UNDECODED even from a
    # text-mode launch (see `base.partial_output`), so bytes is the usual case.
    noisy = "stream error: exceeded rate limit sk-ant-api03-AAAABBBBCCCCDDDDEEEEFFFF"

    def slow(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs.get("timeout"),
                                        stderr=noisy.encode())

    overlay = {base.ENV_ENTRY_ID: entry()["id"], base.ENV_READ_SCOPE: str(tmp_path / "scope.json"),
               base.ENV_WRITE_ALLOWLIST: str(tmp_path / "allow.json")}
    with mock.patch.object(codex.codex_host, "command", return_value=scratch_argv(tmp_path)), \
            mock.patch.object(codex.codex_host, "validate_command"):
        runner = codex.Runner(runner=slow)
        runner.prepare(str(tmp_path), str(tmp_path))
        result = runner.run_entry(entry(), overlay)
    assert not result.ok
    assert "timed out after" in result.error
    assert "exceeded rate limit" in result.stderr
    assert "sk-ant-" not in result.stderr
    assert len(result.stderr) <= base.STDERR_HEAD


def test_a_foreign_agent_name_is_refused_before_any_launch(tmp_path):
    """#1720. Codex is enforced-only and looks its shell up by name in a TOML
    registry, so a foreign name could not traverse -- but it failed LATER, as
    an unreadable registration file, and only after the launch machinery had
    been built. The allowlist refuses it here, for the same reason and in the
    same shape as every other family."""
    launched = []

    def fake_run(command, **kwargs):
        launched.append(command)
        return SimpleNamespace(stdout=envelope(START, REPLY, DONE), stderr="", returncode=0)

    runner = codex.Runner(runner=fake_run)
    runner.prepare(str(tmp_path), str(tmp_path))
    foreign = dict(entry(), agent="panopticon-domain-panel-evil")
    result = runner.run_entry(foreign, {base.ENV_ENTRY_ID: foreign["id"]})
    assert not result.ok
    assert "not a registered panopticon shell" in result.error
    assert repr("panopticon-domain-panel-evil") in result.error
    assert launched == []


def test_an_enforced_entry_with_no_agent_is_refused_before_any_launch(tmp_path):
    launched = []

    def fake_run(command, **kwargs):
        launched.append(command)
        return SimpleNamespace(stdout=envelope(START, REPLY, DONE), stderr="", returncode=0)

    runner = codex.Runner(runner=fake_run)
    runner.prepare(str(tmp_path), str(tmp_path))
    result = runner.run_entry(dict(entry(), agent=None),
                              {base.ENV_ENTRY_ID: entry()["id"]})
    assert not result.ok
    assert "not a registered panopticon shell" in result.error
    assert launched == []


def test_a_json_array_or_object_agent_is_refused_rather_than_crashing(tmp_path):
    """Fix round 1, item 1: the membership test used to raise `TypeError:
    unhashable type` on an array or object `agent`. Codex's `run_entry` catches
    everything, so it did not escape -- it became a crash-shaped failure whose
    message named a Python type instead of the security refusal it is."""
    launched = []

    def fake_run(command, **kwargs):
        launched.append(command)
        return SimpleNamespace(stdout=envelope(START, REPLY, DONE), stderr="", returncode=0)

    runner = codex.Runner(runner=fake_run)
    runner.prepare(str(tmp_path), str(tmp_path))
    for agent in ([], {}, {"a": {"b": "panopticon-domain-panel"}},
                  ["panopticon-domain-panel"]):
        result = runner.run_entry(dict(entry(), agent=agent),
                                  {base.ENV_ENTRY_ID: entry()["id"]})
        assert not result.ok
        assert "not a registered panopticon shell" in result.error, agent
        assert repr(str(agent)) in result.error
    assert launched == []


def test_a_registered_but_misrouted_shell_is_refused(tmp_path):
    """#1727: `runner.roles` carries the checkpoint's own role set, and the
    same allowlist narrows to it. A `verify` entry naming the review round's
    write-granting shell is a charter swap, not a typo."""
    launched = []

    def fake_run(command, **kwargs):
        launched.append(command)
        return SimpleNamespace(stdout=envelope(START, REPLY, DONE), stderr="", returncode=0)

    runner = codex.Runner(runner=fake_run)
    runner.prepare(str(tmp_path), str(tmp_path))
    runner.roles = ("advisor", "domain_advisor")
    misrouted = dict(entry(), agent="panopticon-domain-panel")
    result = runner.run_entry(misrouted, {base.ENV_ENTRY_ID: misrouted["id"]})
    assert not result.ok
    assert "not a registered panopticon shell for this checkpoint" in result.error
    assert "panopticon-advisor, panopticon-domain-advisor" in result.error
    assert launched == []
