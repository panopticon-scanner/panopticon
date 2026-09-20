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
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import tomllib

import scripts.codex_read_tools as codex_read_tools
import scripts.hosts as hosts
import scripts.runners.base as runners_base
import scripts.runners.schema as runners_schema


ENV_KEYS = ("PANOPTICON_ENTRY_ID", "PANOPTICON_WRITE_ALLOWLIST", "PANOPTICON_READ_SCOPE")
# The constrained-output flag this module puts on the argv; the runner
# declares the same token as its `OUTPUT_SCHEMA_FLAG` seam attribute and a
# test binds the two, exactly as ENVELOPE_FLAGS is bound to `exec --json`.
SCHEMA_FLAG = "--output-schema"
# Same reason as runners/codex.DEFAULT_RUNNER: a module attribute the suite can
# swap for a refusal, where a default argument could not be reached.
DEFAULT_RUNNER = subprocess.run
# The one remedy for every "no registered shell" refusal, spelled the way an
# operator can paste it. Codex is ENFORCED-ONLY: unlike Claude there is no
# unenforced fallback, so an unregistered machine has to be told what to run.
REGISTER_REMEDY = "run: python3 skill/scripts/dispatch.py --emit-host-agents codex"
MAX_BYTES = 8 * 1024 * 1024
PROBE_TIMEOUT = 45
# Everything one launch allocated, keyed by the scratch cwd -- the one path
# cleanup can recover from argv. The value is (per-entry runtime dir, run
# path): BOTH are removed, and only ever when this module recorded them.
_COMMAND_DIRS = {}
_COMMAND_LOCK = threading.Lock()


# The suite's guard refusing to start the real CLI (tests/conftest.py). Its own
# type, deliberately: `_codex_measure` maps every other exception to UNKNOWN,
# which would turn a test that actually reached a live `codex` into a green
# "runtime unavailable". This one is re-raised instead.
#
# THE class, not a second one: it was first needed here and the Kimi family PR
# independently wrote one of the same name on its runner, so the definition
# moved to the seam contract every launch path already shares
# (`runners/base.py`) and this name is an alias of it. Legal under layout rule
# 4, which bans only a PACKAGE module re-exporting a SIBLING's name; this
# module is outside `runners/`.
LaunchRefused = runners_base.LaunchRefused


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
        # `skip_host_skill_discovery` is kept, but it is NOT what closes a
        # target's project skills: the #1657 spike MEASURED a planted
        # `.codex/skills/<x>/SKILL.md` and `.agents/skills/<x>/SKILL.md`
        # reaching the developer-role message with this flag set (CX-2/CX-3),
        # and `codex features list` calls it "under development". What keeps
        # the target's files out of reach is the launch running in an empty
        # run-owned directory -- `--cd` AND the process cwd, see `launch_cwd`.
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
            raise ValueError("Codex reviewer requires a registered shell; " + REGISTER_REMEDY)
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
    #
    # M-7: `model` is deliberately NOT in this set while `model_reasoning_
    # effort` is, so the two halves of one decision come from two places. The
    # entry's model wins because it is override-aware (`resolve_model` honours
    # PANOPTICON_MODEL_<ROLE>; a persisted shell must not, or an ambient
    # override would outlive the run that set it) and because `command()`
    # fails closed on a slug the installed catalog does not list -- which the
    # entry's value can be corrected for and a file on disk cannot. Reasoning
    # effort has no such override and no catalog to disagree with, so it stays
    # where emission put it. The emitted TOML therefore advertises a `model`
    # that never binds; `model_binding` is unclaimed precisely because of this.
    permitted = set(safety_config()) | {"developer_instructions", "model_reasoning_effort"}
    return {key: value for key, value in config.items() if key in permitted}


def require_registered_shells(registration_dir=None):
    """Refuse ONCE, before any launch, when a driver role has no shell.

    Codex is enforced-only: `_shell` raises for every reviewer entry whose
    shell is absent, so on a machine that has not run `--emit-host-agents
    codex` -- or after a CLI upgrade that leaves the tool-policy probe
    unproven, which sets `entry["agent"] = None` for every entry -- the loop
    produced three failed launches per entry and an `error` naming the entry
    rather than the remedy. The runner calls this from `prepare`, so the
    operator gets one refusal naming the command that fixes it.
    """
    from scripts import dispatch
    directory = (registration_dir if registration_dir is not None
                 else hosts.spec("codex").registration_dir)
    missing = sorted(
        dispatch.registered_agent_filename("codex", role_file)
        for role_file in dispatch.ROLE_FILES.values()
        if not os.path.isfile(os.path.join(
            directory, dispatch.registered_agent_filename("codex", role_file))))
    if missing:
        raise ValueError(
            "Codex is enforced-only: %d registered shell(s) missing from %s (%s); %s"
            % (len(missing), directory, ", ".join(missing), REGISTER_REMEDY))


def _overrides(config, prefix=""):
    for key, value in config.items():
        path = prefix + key
        if isinstance(value, dict) and value:
            yield from _overrides(value, path + ".")
        else:
            # JSON scalar/list syntax is also TOML; an empty table is special.
            yield "-c"
            yield path + "=" + ("{}" if value == {} else json.dumps(value))


def _dump_catalog(runner, env=None):
    """One `codex debug models --bundled` launch, parsed.

    cwd is a fresh empty temp directory rather than the run-owned entry folder
    it used to be: that folder sits under the reviewed tree's `.panopticon/`,
    from which the CLI can discover the target's ancestor `.codex` config --
    the same hazard the launch's `--cd` exists to avoid.
    """
    with tempfile.TemporaryDirectory(prefix="panopticon-codex-catalog-") as scratch:
        proc = runner(["codex", "debug", "models", "--bundled"], text=True,
                      capture_output=True, timeout=PROBE_TIMEOUT, cwd=scratch, env=env)
    if proc.returncode or len(proc.stdout) > MAX_BYTES:
        raise ValueError("Codex bundled catalog unavailable")
    models = json.loads(proc.stdout).get("models", [])
    return models if isinstance(models, list) else []


def catalog_loader(runner=None, env=None):
    """A memoising, thread-safe catalog reader shared across one probe run.

    I-6: the dump is a local JSON print, but it was one process launch PER
    ROLE inside `command()` -- five per `run_probes`, and `driver loop` probes
    on every iteration. Every role reads the same installed catalog, so one
    dump per call is enough. Returned as a callable rather than a value so a
    caller that never reaches a launch (an injected inspector, a missing
    shell) never pays for it either.
    """
    runner = DEFAULT_RUNNER if runner is None else runner
    cache, lock = [], threading.Lock()

    def load():
        with lock:
            if not cache:
                cache.append(_dump_catalog(runner, env))
            return cache[0]
    return load


def _catalog(model, directory, runner, env, models=None):
    models = _dump_catalog(runner, env) if models is None else models
    selected = [copy.deepcopy(row) for row in models
                if isinstance(row, dict) and (model is None or row.get("slug") == model)]
    if not selected or (model is not None and len(selected) != 1):
        raise ValueError(
            "entry model %r is absent or ambiguous in Codex bundled catalog; if your Codex "
            "build spells the tier differently, set PANOPTICON_MODEL_<ROLE> (e.g. "
            "PANOPTICON_MODEL_DOMAIN_PANEL) to a slug `codex debug models --bundled` lists"
            % model)
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


def command(entry, env, review_root, run_dir, runner=None, registration_dir=None,
            catalog=None, schema_argv=()):
    """Build one stdin-prompt launch from its registered, effective policy.

    `schema_argv` is `runners.schema.schema_argv`'s output -- `["--output-schema",
    <published schema>]` or nothing (D10 ruling 3). It is placed BEFORE the
    trailing `-`, which is not a flag but the stdin marker, and `validate_command`
    re-checks the path it carries."""
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
    # N-M4: from here to the registry write, NOTHING may leave the runtime
    # directory behind. It exists before _catalog() runs, and _catalog() is
    # the documented fail-closed path (I-8: a CLI build whose bundled catalog
    # spells the tier differently refuses every entry of that role, three
    # times each) -- and it is not yet in _COMMAND_DIRS, so cleanup_command
    # could never find it afterwards.
    try:
        config.update({"model_catalog_json": _catalog(model, directory, runner, env,
                                                      catalog() if catalog is not None else None),
                       "log_dir": str(directory / "logs"), "sqlite_home": str(directory / "sqlite")})
        overrides = list(_overrides(config))
        # A fresh cwd UNDER the target would still discover its ancestor .codex
        # config. Keep cwd outside it, while run configuration remains run-owned.
        cwd = str(Path(tempfile.mkdtemp(prefix="panopticon-codex-cwd-")).resolve())
        if Path(cwd).is_relative_to(Path(review_root).resolve()):
            os.rmdir(cwd)
            raise ValueError("Codex scratch cwd must be outside the review root; choose an external TMPDIR")
    except BaseException:
        shutil.rmtree(directory, ignore_errors=True)
        raise
    with _COMMAND_LOCK:
        _COMMAND_DIRS[cwd] = (str(directory), str(run_path))
    return ["codex", "exec", "--ignore-user-config", "--ignore-rules", "--ephemeral",
            "--strict-config", "--sandbox", "read-only", "--skip-git-repo-check",
            "--cd", cwd, *(["--model", model] if model else []), "--json", *overrides,
            *schema_argv, "-"]


def launch_cwd(argv):
    """The directory the child PROCESS must run in: the `--cd` scratch this
    module allocated for that same launch.

    CX-9 (the #1657 spike): `codex debug prompt-input` takes no `--cd`, so
    "which root drives discovery -- `--cd` or the process cwd" could not be
    settled read-only. Making the two the SAME directory removes the question:
    whichever root the CLI keys off, it is this empty, run-owned scratch and
    not the reviewed tree. `_dump_catalog` already launches that way, and says
    why; this is the same rule for the entry launch.

    Lookup discipline is `cleanup_command`'s: the value is read off argv ONLY
    to look up what this process recorded in `_COMMAND_DIRS`. An argv naming a
    directory nothing here allocated is refused -- a launch is not the place to
    trust a path someone else chose.
    """
    if not argv or "--cd" not in argv:
        raise ValueError("Codex argv carries no --cd scratch directory to launch in")
    index = argv.index("--cd") + 1
    if index >= len(argv):
        raise ValueError("Codex argv ends at --cd with no scratch directory after it")
    cwd = argv[index]
    with _COMMAND_LOCK:
        known = cwd in _COMMAND_DIRS
    if not known:
        raise ValueError("Codex --cd directory was not allocated by this process: %s" % cwd)
    return cwd


def cleanup_command(argv):
    """Release BOTH temporary directories this module allocated for one launch.

    I-7: the per-entry runtime folder (the launch-local catalog copy, `logs/`
    and `sqlite/`) used to survive every launch, so a real run accumulated
    hundreds of them -- carrying Codex logs -- under the run folder.

    Deletion targets come from this process's own registry, never from argv:
    the only thing read off argv is the `--cd` value used to LOOK UP what was
    recorded. The runtime folder is additionally required to still sit
    directly under the run path it was allocated in, so a registry entry
    cannot be talked into deleting anything else.
    """
    if not argv or "--cd" not in argv:
        return
    cwd = argv[argv.index("--cd") + 1]
    with _COMMAND_LOCK:
        allocated = _COMMAND_DIRS.pop(cwd, None)
    if allocated is None:
        return
    directory, run_path = allocated
    try:
        os.rmdir(cwd)
    except OSError:
        # Do not recursively remove unexpected files, and never turn cleanup
        # failure into an exception escaping Runner.run_entry's contract.
        pass
    if str(Path(directory).parent) == run_path:
        shutil.rmtree(directory, ignore_errors=True)


def validate_command(argv, env, review_root):
    """Refuse a changed registration before any real model request.

    Probing deliberately omits this preflight so the localhost fixture can
    measure a broken native restriction and refute it. Real entries validate
    the finished argv, not a second read of a registration file that could
    change between validation and command construction.
    """
    # D10 ruling 3: the argv allowlist gains exactly two tokens, and the second
    # is a PATH -- the only value on this argv that reaches it from the entry,
    # which travels through `.panopticon/dispatch-request.json` inside the
    # reviewed tree. Held to the schemas panopticon publishes, by the same rule
    # the runner applied when it built the pair, because this validator's whole
    # job is to re-check the FINISHED argv rather than trust how it was made.
    if SCHEMA_FLAG in argv:
        index = argv.index(SCHEMA_FLAG) + 1
        if index >= len(argv) or not runners_schema.published_schema(argv[index]):
            raise ValueError("Codex command names an output schema that is not one "
                             "panopticon publishes under skill/reference/")
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
    surface = set(broker.pop("enabled_tools"))
    servers = config.get("mcp_servers")
    launched = servers.get("panopticon_scope") if isinstance(servers, dict) else None
    if (not isinstance(servers, dict) or set(servers) != {"panopticon_scope"}
            or not isinstance(launched, dict)
            or {key: value for key, value in launched.items() if key != "enabled_tools"} != broker):
        raise ValueError("Codex command does not bind exactly the scope-only read broker")
    # I-2: the allowlist is a non-empty SUBSET, not an equality. The emitter
    # narrows it per role from that role's template (Read/Grep/Glob ->
    # read_file/search/list_files), so demanding the full list in TOOLS order
    # made that narrowing dead code AND meant the day a template drops Glob or
    # reorders `allowed:`, every launch of that role fails with a message
    # blaming the broker rather than the template. Order is irrelevant; what
    # matters is that nothing outside the scope-only surface gets enabled and
    # that the role is left with at least one read tool.
    enabled = launched.get("enabled_tools")
    if (not isinstance(enabled, list) or not enabled
            or any(not isinstance(name, str) for name in enabled)
            or not set(enabled) <= surface):
        raise ValueError("Codex command does not bind exactly the scope-only read broker's tools")
    return config


def _probe_script(probe_paths):
    """The inspection script, reading each of `probe_paths` through the broker.

    The paths are the inside/outside/hard-link TRIPLE the codex probe plants
    (#1642): the third is a hard link inside the directory grant naming the file
    outside it, and a measurement that carried only the first two would leave
    the probe's hard-link refutation row unmeasured -- which is the shape the
    row exists to catch. All of 0 or all of 3; never a subset.
    """
    paths = list(probe_paths or ())
    if len(paths) not in (0, 3) or any(not isinstance(path, str) for path in paths):
        raise ValueError("probe_paths must be the inside/outside/hard-link probe triple")
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
                    registration_dir=None, probe_paths=None, catalog=None):
    """Interrogate the same native launch, replacing only its model endpoint.

    All real-runtime work is explicit here, never in unit tests. Callers map
    unavailable localhost/runtime facilities to unknown rather than guessing.
    """
    runner = DEFAULT_RUNNER if runner is None else runner
    argv = command(entry, env, review_root, run_dir, runner, registration_dir, catalog)
    try:
        requests = _capture_requests(argv, env, runner, _probe_script(probe_paths))
        return _surface_result(requests)
    finally:
        cleanup_command(argv)
