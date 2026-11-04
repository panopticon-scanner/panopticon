"""The Codex effective-surface inspection harness (#3403).

The host module builds a confined Codex command. This module replaces only
that command's model endpoint with a localhost fixture, records the effective
tool surface, and returns the observation to the Codex family probes.
"""
from typing import Any

import http.server
import json
import re
import threading

from scripts import codex_read_tools
from scripts.codex_host import (
    DEFAULT_RUNNER,
    MAX_BYTES,
    PROBE_TIMEOUT,
    WRITE_SURFACE_IMPORTS,
    _overrides,
    cleanup_command,
    command,
    launch_cwd,
)


def _probe_script(probe_paths, probe_module="file:///panopticon-probe.mjs"):
    """The inspection script, reading each of `probe_paths` through the broker.

    The paths are the inside/outside PAIR the codex probe writes: the granted
    file and its sibling outside the grant. A measurement that carried only one
    would leave the probe's out-of-scope refusal row unmeasured. All of 0 or all
    of 2; never a subset.
    """
    paths = list(probe_paths or ())
    if len(paths) not in (0, 2) or any(not isinstance(path, str) for path in paths):
        raise ValueError("probe_paths must be the inside/outside probe pair")
    probe_module = probe_module or "file:///panopticon-probe.mjs"
    if not isinstance(probe_module, str) or not probe_module.startswith("file:"):
        raise ValueError("probe_module must be a file URL")
    server_key = codex_read_tools.MCP_SERVER_KEY
    read_tool = "mcp__%s__read_file" % server_key
    imports = (*WRITE_SURFACE_IMPORTS, probe_module)
    return ("const attempt = async call => { try { return {ok: true, value: await call()}; } "
            "catch (error) { return {ok: false, error: String(error)}; } }; "
            "const result = {tools: ALL_TOOLS.map(t => t.name), globals: "
            "Object.getOwnPropertyNames(globalThis).sort(), mcp_servers: Array.from(new Set("
            "ALL_TOOLS.map(t => t.name.split('__')).filter(p => p[0] === 'mcp' && p.length > 2)"
            ".map(p => p[1]))).sort(), imports: {}, resources: {}, forbidden: {"
            "exec: typeof tools.exec_command, patch: typeof tools.apply_patch, "
            "spawn: typeof tools.multi_agent_v1__spawn_agent, fetch: typeof fetch, "
            "process: typeof process, require: typeof require}, reads: []}; "
            "for (const specifier of " + json.dumps(imports) + ") { "
            "result.imports[specifier] = await attempt(async () => "
            "Object.keys(await import(specifier)).sort()); } "
            "result.resources.list = await attempt(async () => await tools.list_mcp_resources({})); "
            "result.resources.templates = await attempt(async () => "
            "await tools.list_mcp_resource_templates({})); "
            "result.resources.read = await attempt(async () => await tools.read_mcp_resource("
            "{server: '" + server_key + "', uri: 'panopticon://write-surface-probe'})); "
            "for (const path of " + json.dumps(paths) + ") { "
            "try { result.reads.push(await tools." + read_tool + "({path})); } "
            "catch (error) { result.reads.push({isError: true, error: String(error)}); } } "
            "text({panopticon_surface: result});")


def _events(item):
    return [
        {"type": "response.created", "response": {"id": "resp_probe", "object": "response",
                                                    "status": "in_progress", "output": []}},
        {"type": "response.output_item.added", "output_index": 0, "item": item},
        {"type": "response.output_item.done", "output_index": 0, "item": item},
        {"type": "response.completed", "response": {"id": "resp_probe", "object": "response",
          "status": "completed", "output": [item],
          "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}}},
    ]


def _launch_error(proc):
    detail = re.sub(r"(?i)(?:sk-[a-z0-9_-]+|Bearer\s+\S+)", "[redacted]", proc.stderr or "")
    detail = re.sub(r"(?im)((?:api[_-]?key|access[_-]?token|authorization)\s*[:=]).*$",
                    r"\1[redacted]", detail)
    return "Codex effective-surface launch failed (exit %s): %s" % (proc.returncode, detail[:2000])


def _capture_requests(argv, env, runner, script):
    requests: list[dict[str, Any]] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            self.send_response(200 if self.path.startswith("/v1/models") else 404)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"models":[]}')

        def do_POST(self):
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= MAX_BYTES or self.path != "/v1/responses" or len(requests) >= 2:
                    raise ValueError("invalid local probe request")
                request = json.loads(self.rfile.read(size))
                if not isinstance(request, dict):
                    raise ValueError("invalid local probe envelope")
            except (ValueError, TypeError):
                self.send_error(400)
                return
            requests.append(request)
            first = len(requests) == 1
            item = ({"id": "call_probe", "type": "custom_tool_call", "name": "exec",
                     "namespace": "functions", "call_id": "tool_probe", "input": script}
                    if first else {"id": "msg_probe", "type": "message", "role": "assistant",
                                   "content": [{"type": "output_text", "text": "probe complete"}]})
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            for event in _events(item):
                self.wfile.write(("event: " + event["type"] + "\ndata: " + json.dumps(event) + "\n\n").encode())
            self.wfile.flush()

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    provider = {"model_provider": "panopticon_probe", "model_providers": {"panopticon_probe": {
        "name": "Panopticon localhost-only surface probe",
        "base_url": "http://127.0.0.1:%d/v1" % server.server_port,
        "requires_openai_auth": False, "supports_websockets": False,
        "request_max_retries": 0, "stream_max_retries": 0,
    }}}
    try:
        # #1657: the same rule as the entry launch -- no codex child runs with
        # the reviewed tree as its process cwd. This one used to pass no `cwd`
        # at all, so it inherited the driver's, and its output is what
        # host-capabilities.json is built from. `argv` is still registered
        # here: `inspect_surface` releases it in its own `finally`.
        proc = runner([*argv[:-1], *_overrides(provider), "-"], env=env, input="Inspect the probe tools.",
                      text=True, capture_output=True, cwd=launch_cwd(argv),
                      timeout=PROBE_TIMEOUT)
        if proc.returncode:
            raise ValueError(_launch_error(proc))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)
    return requests


def _surface_result(requests):
    if len(requests) != 2:
        raise ValueError("Codex did not return its effective tool surface")
    for item in requests[1].get("input", []):
        if item.get("type") != "custom_tool_call_output" or item.get("call_id") != "tool_probe":
            continue
        for part in item.get("output", []):
            try:
                surface = json.loads(part.get("text", "")).get("panopticon_surface")
            except (ValueError, AttributeError):
                continue
            if (not isinstance(surface, dict) or not isinstance(surface.get("tools"), list)
                    or any(not isinstance(tool, str) for tool in surface["tools"])
                    or not isinstance(surface.get("forbidden"), dict)
                    or not isinstance(surface.get("reads"), list)):
                continue
            direct = []
            # Native tools may also arrive on the Responses top-level channel.
            # This adapter proves Code Mode only; a newly exposed parallel
            # surface must refute the allowlist, never disappear in parsing.
            if any(request.get("tools") for request in requests):
                direct.append("unproven Responses top-level tool surface")
            for message in requests[0].get("input", []):
                if message.get("type") == "additional_tools":
                    for namespace in message.get("tools", []):
                        if namespace.get("type") == "namespace":
                            direct.extend(namespace["name"] + "." + tool["name"]
                                          for tool in namespace.get("tools", []))
                        else:
                            direct.append(namespace.get("name", namespace.get("type")))
            return {**surface, "direct_tools": direct, "model": requests[0].get("model")}
    raise ValueError("Codex effective tool enumeration was absent or malformed")


def inspect_surface(entry, env, review_root, run_dir, runner=None,
                    registration_dir=None, probe_paths=None, probe_module=None,
                    catalog=None):
    """Interrogate the same native launch, replacing only its model endpoint.

    All real-runtime work is explicit here, never in unit tests. Callers map
    unavailable localhost/runtime facilities to unknown rather than guessing.
    """
    runner = DEFAULT_RUNNER if runner is None else runner
    argv = command(entry, env, review_root, run_dir, runner, registration_dir, catalog)
    try:
        requests = _capture_requests(
            argv, env, runner, _probe_script(probe_paths, probe_module))
        return _surface_result(requests)
    finally:
        cleanup_command(argv)
