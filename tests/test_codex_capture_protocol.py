"""Exercise the localhost Responses measuring instrument with inert clients."""

import http.client
import json
import socket
import threading
import tomllib
from types import SimpleNamespace

import pytest

import scripts.codex_host as host


def _request(port, method, path, body=None, length=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        connection.putrequest(method, path)
        if length is not None:
            connection.putheader("Content-Length", str(length))
        connection.endheaders(body)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def _events(raw):
    records = []
    for block in raw.decode().strip().split("\n\n"):
        event, data = block.split("\n", 1)
        records.append((event.removeprefix("event: "), json.loads(data.removeprefix("data: "))))
    return records


def _registered_argv(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    directory = run / "entry"
    directory.mkdir()
    cwd = tmp_path / "launch"
    cwd.mkdir()
    with host._COMMAND_LOCK:
        host._COMMAND_DIRS[str(cwd)] = (str(directory), str(run))
    return ["codex", "exec", "--cd", str(cwd), "-"]


@pytest.mark.parametrize("fail", [False, True])
def test_live_capture_protocol_and_shutdown(tmp_path, fail):
    argv = _registered_argv(tmp_path)
    script = "text('inert probe')"
    observed = {}

    def runner(launched, **kwargs):
        assert launched[:len(argv) - 1] == argv[:-1]
        assert launched[-1] == "-"
        assert kwargs["cwd"] == str(tmp_path / "launch")
        assert kwargs["timeout"] == host.PROBE_TIMEOUT
        assert kwargs["input"] == "Inspect the probe tools."
        config = tomllib.loads("\n".join(
            launched[index + 1] for index, arg in enumerate(launched[:-1]) if arg == "-c"))
        provider = config["model_providers"]["panopticon_probe"]
        assert provider["requires_openai_auth"] is False
        assert provider["supports_websockets"] is False
        assert provider["request_max_retries"] == 0
        assert provider["stream_max_retries"] == 0
        assert config["model_provider"] == "panopticon_probe"
        port = int(provider["base_url"].rsplit(":", 1)[1].split("/", 1)[0])
        observed["port"] = port
        observed["thread"] = next(
            thread for thread in threading.enumerate()
            if thread.name.endswith("(serve_forever)"))
        status, body = _request(port, "GET", "/v1/models")
        assert status == 200
        assert json.loads(body) == {"models": []}
        assert _request(port, "GET", "/v1/unknown")[0] == 404
        for body, length, path in (
            (b"{", 1, "/v1/responses"),
            (b"[]", 2, "/v1/responses"),
            (b"{}", 0, "/v1/responses"),
            (b"{}", host.MAX_BYTES + 1, "/v1/responses"),
            (b"{}", "bad", "/v1/responses"),
            (b"{}", 2, "/v1/wrong"),
        ):
            assert _request(port, "POST", path, body, length)[0] == 400
        planted = [{"model": "first", "input": [{"type": "message"}]},
                   {"model": "second", "input": [{"type": "custom_tool_call_output"}]}]
        for index, payload in enumerate(planted):
            body = json.dumps(payload).encode()
            status, raw = _request(port, "POST", "/v1/responses", body, len(body))
            assert status == 200
            events = _events(raw)
            assert [name for name, _ in events] == [
                "response.created", "response.output_item.added",
                "response.output_item.done", "response.completed"]
            assert [event["type"] for _, event in events] == [name for name, _ in events]
            assert events[0][1]["response"]["status"] == "in_progress"
            item = events[1][1]["item"]
            assert events[2][1]["item"] == item
            assert events[3][1]["response"]["output"] == [item]
            assert events[3][1]["response"]["status"] == "completed"
            if index == 0:
                assert item == {"id": "call_probe", "type": "custom_tool_call",
                                "name": "exec", "namespace": "functions",
                                "call_id": "tool_probe", "input": script}
            else:
                assert item == {"id": "msg_probe", "type": "message", "role": "assistant",
                                "content": [{"type": "output_text", "text": "probe complete"}]}
        assert _request(port, "POST", "/v1/responses", b"{}", 2)[0] == 400
        if fail:
            raise RuntimeError("inert runner failure")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    try:
        if fail:
            with pytest.raises(RuntimeError, match="inert runner failure"):
                host._capture_requests(argv, {}, runner, script)
        else:
            assert host._capture_requests(argv, {}, runner, script) == [
                {"model": "first", "input": [{"type": "message"}]},
                {"model": "second", "input": [{"type": "custom_tool_call_output"}]}]
        with pytest.raises((ConnectionRefusedError, OSError, socket.timeout)):
            _request(observed["port"], "GET", "/v1/models")
        observed["thread"].join(timeout=1)
        assert not observed["thread"].is_alive()
    finally:
        host.cleanup_command(argv)
    assert not (tmp_path / "launch").exists()
    assert not (tmp_path / "run" / "entry").exists()
    assert str(tmp_path / "launch") not in host._COMMAND_DIRS
