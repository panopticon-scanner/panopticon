import json
import os
import subprocess
from types import SimpleNamespace
from unittest import mock

import pytest

from scripts.runners import base, codex


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


def test_run_entry_inherits_environment_and_passes_prompt_on_stdin(tmp_path):
    seen = {}

    def fake_run(command, **kwargs):
        seen.update(command=command, **kwargs)
        return SimpleNamespace(stdout=envelope(START, REPLY, DONE), stderr="", returncode=0)

    overlay = {base.ENV_ENTRY_ID: entry()["id"], base.ENV_READ_SCOPE: str(tmp_path / "scope.json"),
               base.ENV_WRITE_ALLOWLIST: str(tmp_path / "allow.json")}
    with mock.patch.dict(os.environ, {"PATH": "/fixture/bin", "HOME": str(tmp_path)}, clear=True), \
            mock.patch.object(codex.codex_host, "command", return_value=["codex", "exec", "-"]) as command, \
            mock.patch.object(codex.codex_host, "validate_command") as validate:
        runner = codex.Runner(runner=fake_run)
        runner.prepare(str(tmp_path), str(tmp_path))
        result = runner.run_entry(entry(), overlay)
    assert result.ok
    assert seen["env"] == {"PATH": "/fixture/bin", "HOME": str(tmp_path), **overlay}
    assert seen["input"] == entry()["prompt"]
    assert entry()["prompt"] not in seen["command"]
    assert seen["cwd"] == str(tmp_path)
    assert seen["timeout"] == runner.entry_timeout
    command.assert_called_once_with(entry(), seen["env"], str(tmp_path), str(tmp_path), runner=fake_run)
    validate.assert_called_once_with(seen["command"], seen["env"], str(tmp_path))


@pytest.mark.parametrize("error", [FileNotFoundError("codex"), ValueError("launch failure"),
                                  subprocess.TimeoutExpired("codex", 1)])
def test_launch_exceptions_never_escape(tmp_path, error):
    def fake_run(*args, **kwargs):
        raise error
    runner = codex.Runner(runner=fake_run)
    runner.prepare(str(tmp_path), str(tmp_path))
    with mock.patch.object(codex.codex_host, "command", return_value=["codex", "exec", "-"]), \
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
