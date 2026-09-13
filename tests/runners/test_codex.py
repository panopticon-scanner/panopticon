import json
import os
import subprocess
from types import SimpleNamespace
from unittest import mock

import pytest

from scripts.runners import base, codex


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
    runner = codex.Runner(runner=mock.Mock())
    runner.prepare(str(tmp_path), str(tmp_path))
    runner.prepare(str(tmp_path), str(tmp_path))
    assert list(tmp_path.iterdir()) == []
