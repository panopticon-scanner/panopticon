"""Codex-native launch policy and a free, effective-runtime surface probe.

The mock Responses provider never forwards traffic. It asks the installed
runtime to enumerate its actual callable tools, including deferred Code Mode
tools, and optionally exercises the same read broker used by real entries.
This is transport/configuration only: review workflow stays in the driver.
"""
import copy
import http.server
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import threading
import tomllib

import scripts.codex_read_tools as codex_read_tools
import scripts.hosts as hosts


ENV_KEYS = ("PANOPTICON_ENTRY_ID", "PANOPTICON_WRITE_ALLOWLIST", "PANOPTICON_READ_SCOPE")
# Same reason as runners/codex.DEFAULT_RUNNER: a module attribute the suite can
# swap for a refusal, where a default argument could not be reached.
DEFAULT_RUNNER = subprocess.run
MAX_BYTES = 8 * 1024 * 1024
PROBE_TIMEOUT = 45
_COMMAND_DIRS = set()
_COMMAND_LOCK = threading.Lock()


class LaunchRefused(RuntimeError):
    """The suite's guard refusing to start the real CLI (tests/conftest.py).

    Its own type, deliberately: `_codex_measure` maps every other exception to
    UNKNOWN, which would turn a test that actually reached a live `codex` into
    a green "runtime unavailable". This one is re-raised instead.
    """


_POLICY_FEATURES = (
    "shell_tool", "unified_exec", "shell_snapshot", "apps", "plugins", "hooks",
    "multi_agent", "multi_agent_v2", "browser_use", "computer_use", "image_generation",
    "code_mode", "skill_mcp_dependency_install", "skill_search", "goals", "sleep_tool",
    "tool_suggest", "workspace_dependencies", "view_image",
)


def safety_config():
    """Native TOML values, shared by emission and the unregistered setup scan.

    Role-specific Read/Grep/Glob vocabulary mapping belongs to the emitter.
    Code Mode remains enabled: its isolated V8 has no filesystem/network and
    current model metadata requires it even when features.code_mode is false.
    """
    return {
        "approval_policy": "never", "sandbox_mode": "read-only", "web_search": "disabled",
        "check_for_update_on_startup": False, "history": {"persistence": "none"},
        "project_doc_max_bytes": 0, "suppress_unstable_features_warning": True,
        "otel": {"exporter": "none", "metrics_exporter": "none"},
        "features": {**dict.fromkeys(_POLICY_FEATURES, False),
                     "skip_host_skill_discovery": True, "code_mode_host": True},
        "mcp_servers": {"panopticon_scope": {
            "command": sys.executable,
            "args": ["-I", str(Path(codex_read_tools.__file__).resolve())],
            "required": True,
            "enabled_tools": [tool["name"] for tool in codex_read_tools.TOOLS],
        }},
    }


def _shell(entry, registration_dir):
    agent = entry.get("agent")
    if not agent:
        if entry.get("id") != "setup-scan":
            raise ValueError("Codex reviewer requires a registered shell")
        return safety_config()
    if not isinstance(agent, str) or not re.fullmatch(r"panopticon-[a-z0-9-]+", agent):
        raise ValueError("invalid Codex registered shell name")
    directory = registration_dir if registration_dir is not None else hosts.spec("codex").registration_dir
    path = Path(directory) / (agent + ".toml")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Codex registered shell must be a regular file")
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("oversized Codex registered shell")
    config = tomllib.loads(data.decode("utf-8"))
    if config.get("name") != agent:
        raise ValueError("Codex registered shell name mismatch")
    # Never load arbitrary provider, notification or hook commands from a
    # registration file. The effective probe still sees changes to its policy.
    permitted = set(safety_config()) | {"developer_instructions", "model_reasoning_effort"}
    return {key: value for key, value in config.items() if key in permitted}


def _overrides(config, prefix=""):
    for key, value in config.items():
        path = prefix + key
        if isinstance(value, dict) and value:
            yield from _overrides(value, path + ".")
        else:
            # JSON scalar/list syntax is also TOML; an empty table is special.
            yield "-c"
            yield path + "=" + ("{}" if value == {} else json.dumps(value))


def _catalog(model, directory, runner, env):
    proc = runner(["codex", "debug", "models", "--bundled"], text=True,
                  capture_output=True, timeout=PROBE_TIMEOUT, cwd=str(directory), env=env)
    if proc.returncode or len(proc.stdout) > MAX_BYTES:
        raise ValueError("Codex bundled catalog unavailable")
    models = json.loads(proc.stdout).get("models", [])
    selected = [copy.deepcopy(row) for row in models
                if isinstance(row, dict) and (model is None or row.get("slug") == model)]
    if not selected or (model is not None and len(selected) != 1):
        raise ValueError("entry model %r is absent or ambiguous in Codex bundled catalog" % model)
    # Feature flags alone do not remove these metadata-forced tools. Keep the
    # requested model, reasoning, prompt and every other catalog field intact.
    for row in selected:
        row["apply_patch_tool_type"] = None
        row["multi_agent_version"] = None
        row["experimental_supported_tools"] = []
    path = directory / "model-catalog.json"
    # directory is an unpredictable, newly-created mode-0700 run-owned folder;
    # exclusive no-follow creation also rejects a planted destination link.
    fd, staging = tempfile.mkstemp(prefix=".catalog-", dir=directory)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump({"models": selected}, stream)
    os.replace(staging, path)
    return str(path)


def command(entry, env, review_root, run_dir, runner=None, registration_dir=None):
    """Build one stdin-prompt launch from its registered, effective policy."""
    runner = DEFAULT_RUNNER if runner is None else runner
    config = _shell(entry, registration_dir)
    model = entry.get("model")
    if model is not None and (not isinstance(model, str) or not model or any(c in model for c in "\r\n\0")):
        raise ValueError("Codex requires an explicit entry model")
    if model is None and entry.get("id") != "setup-scan":
        raise ValueError("Codex reviewer requires an explicit entry model")
    if any(not isinstance(env.get(key), str) or not env[key] for key in ENV_KEYS):
        raise ValueError("missing Codex entry scope binding")
    if env[ENV_KEYS[0]] != entry.get("id"):
        raise ValueError("mismatched Codex entry scope binding")
    run_path = Path(run_dir).absolute()
    if str(run_path.resolve()) != str(run_path):
        raise ValueError("Codex runtime directory must not traverse symlinks")
    run_path.mkdir(parents=True, exist_ok=True)
    server = config.get("mcp_servers", {}).get("panopticon_scope", {})
    enabled = server.get("enabled_tools")
    if not isinstance(enabled, list) or any(not isinstance(name, str) for name in enabled):
        raise ValueError("Codex shell lacks its native MCP tool allowlist")
    broker = safety_config()["mcp_servers"]["panopticon_scope"]
    broker["enabled_tools"] = enabled
    broker["env"] = {**{key: env[key] for key in ENV_KEYS},
                     "PANOPTICON_REVIEW_ROOT": str(Path(review_root).resolve())}
    config["mcp_servers"] = {"panopticon_scope": broker}
    directory = Path(tempfile.mkdtemp(prefix="codex-entry-", dir=run_path))
    config.update({"model_catalog_json": _catalog(model, directory, runner, env),
                   "log_dir": str(directory / "logs"), "sqlite_home": str(directory / "sqlite")})
    overrides = list(_overrides(config))
    # A fresh cwd UNDER the target would still discover its ancestor .codex
    # config. Keep cwd outside it, while run configuration remains run-owned.
    cwd = str(Path(tempfile.mkdtemp(prefix="panopticon-codex-cwd-")).resolve())
    if Path(cwd).is_relative_to(Path(review_root).resolve()):
        os.rmdir(cwd)
        raise ValueError("Codex scratch cwd must be outside the review root; choose an external TMPDIR")
    with _COMMAND_LOCK:
        _COMMAND_DIRS.add(cwd)
    return ["codex", "exec", "--ignore-user-config", "--ignore-rules", "--ephemeral",
            "--strict-config", "--sandbox", "read-only", "--skip-git-repo-check",
            "--cd", cwd, *(["--model", model] if model else []), "--json", *overrides, "-"]


def cleanup_command(argv):
    """Release only an empty-cwd temporary directory allocated by this module."""
    if not argv or "--cd" not in argv:
        return
    cwd = argv[argv.index("--cd") + 1]
    with _COMMAND_LOCK:
        if cwd not in _COMMAND_DIRS:
            return
        _COMMAND_DIRS.remove(cwd)
    # Never accept an arbitrary argv path as a deletion target. Only this
    # process's recorded, unpredictable temp allocation is owned by us.
    try:
        os.rmdir(cwd)
    except OSError:
        # Do not recursively remove unexpected files, and never turn cleanup
        # failure into an exception escaping Runner.run_entry's contract.
        pass


def validate_command(argv, env, review_root):
    """Refuse a changed registration before any real model request.

    Probing deliberately omits this preflight so the localhost fixture can
    measure a broken native restriction and refute it. Real entries validate
    the finished argv, not a second read of a registration file that could
    change between validation and command construction.
    """
    overrides = [argv[i + 1] for i, value in enumerate(argv[:-1]) if value == "-c"]
    config = tomllib.loads("\n".join(overrides))
    expected = safety_config()
    dynamic = {"developer_instructions", "model_reasoning_effort", "model_catalog_json", "log_dir", "sqlite_home"}
    if set(config) - set(expected) - dynamic:
        raise ValueError("Codex command includes an unapproved policy override")
    for key, value in expected.items():
        if key != "mcp_servers" and config.get(key) != value:
            raise ValueError("Codex registered policy changed or lacks required control: " + key)
    broker = expected["mcp_servers"]["panopticon_scope"]
    broker["env"] = {**{key: env[key] for key in ENV_KEYS},
                     "PANOPTICON_REVIEW_ROOT": str(Path(review_root).resolve())}
    if config.get("mcp_servers") != {"panopticon_scope": broker}:
        raise ValueError("Codex command does not bind exactly the scope-only read broker")
    return config


def _probe_script(probe_paths):
    paths = list(probe_paths or ())
    if len(paths) not in (0, 2) or any(not isinstance(path, str) for path in paths):
        raise ValueError("probe_paths must be an inside/outside path pair")
    return ("const result = {tools: ALL_TOOLS.map(t => t.name), forbidden: {"
            "exec: typeof tools.exec_command, patch: typeof tools.apply_patch, "
            "spawn: typeof tools.multi_agent_v1__spawn_agent, fetch: typeof fetch, "
            "process: typeof process, require: typeof require}, reads: []}; "
            "for (const path of " + json.dumps(paths) + ") { "
            "try { result.reads.push(await tools.mcp__panopticon_scope__read_file({path})); } "
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
    requests = []

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
        proc = runner([*argv[:-1], *_overrides(provider), "-"], env=env, input="Inspect the probe tools.",
                      text=True, capture_output=True, timeout=PROBE_TIMEOUT)
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
                    registration_dir=None, probe_paths=None):
    """Interrogate the same native launch, replacing only its model endpoint.

    All real-runtime work is explicit here, never in unit tests. Callers map
    unavailable localhost/runtime facilities to unknown rather than guessing.
    """
    runner = DEFAULT_RUNNER if runner is None else runner
    argv = command(entry, env, review_root, run_dir, runner, registration_dir)
    try:
        requests = _capture_requests(argv, env, runner, _probe_script(probe_paths))
        return _surface_result(requests)
    finally:
        cleanup_command(argv)
