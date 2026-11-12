"""Capability probes for the `agy` (Google Antigravity CLI) host family (#3493).

All five first-class capabilities are measured against the real `agy` CLI and
the real `agy_guard_hook.py` script inside an isolated `<run_home>` with `cwd`
pinned to `<run_home>/workspace`:
- `agy-shell-surface`     -> `tool_policy_enforced`
- `agy-read-guard-armed`  -> `read_scope_confined`
- `agy-write-guard-armed` -> `artifact_write_guard`
- `agy-model-bound`       -> `model_binding`
- `agy-usage-envelope`    -> `usage_ledger`
"""
import json
import os
import re
import shutil
import sys
import tempfile

import scripts.agy_guard_hook as agy_guard_hook
import scripts.dispatch as dispatch
import scripts.hosts as hosts
import scripts.model_resolver as model_resolver
import scripts.probes.common as common
import scripts.read_guard_hook as read_guard_hook
import scripts.runners.agy as agy_runner
import scripts.runners.agy_home as agy_home
import scripts.runners.base as runners_base
import scripts.runners.children as children


_BINARY = "agy"
AGY_SHELL_SURFACE = "agy-shell-surface"
AGY_READ_GUARD_ARMED = "agy-read-guard-armed"
AGY_WRITE_GUARD_ARMED = "agy-write-guard-armed"
AGY_READ_GUARD = AGY_READ_GUARD_ARMED
AGY_WRITE_GUARD = AGY_WRITE_GUARD_ARMED
AGY_MODEL_BOUND = "agy-model-bound"
AGY_USAGE_ENVELOPE = "agy-usage-envelope"

DEFAULT_RUNNER = children.launch
PROBE_TIMEOUT = 45
_VERSION_RE = re.compile(r"\b(\d+\.\d+)(?:\.\d+)?\b")


def _frontmatter_field(path, key):
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except (OSError, ValueError):
        return None
    fences = 0
    prefix = key + ":"
    for line in lines:
        if line.strip() == "---":
            fences += 1
            if fences == 2:
                return None
            continue
        if fences == 1 and line.startswith(prefix):
            return line.split(":", 1)[1].strip() or None
    return None


def _run_agy(argv, home, *, runner=None, extra_env=None, timeout=PROBE_TIMEOUT):
    run = DEFAULT_RUNNER if runner is None else runner
    env = dict(os.environ, HOME=home, NO_COLOR="1")
    for marker in ("ANTIGRAVITY_CLI", "ANTIGRAVITY_CLI_ALIAS"):
        env.pop(marker, None)
    if extra_env:
        env.update(extra_env)
    try:
        proc = run([_BINARY, *argv], env=env, cwd=agy_home.workspace_dir(home),
                   capture_output=True, text=True, timeout=timeout,
                   stop_on=agy_runner.INTERACTIVE_AUTH)
    except children.HostStopped as exc:
        # #3576: ended before a browser sign-in could open; said as the auth it is.
        raise agy_home.AgyAuthUnreachable() from exc
    if agy_runner.reached_interactive_auth(getattr(proc, "stderr", None)):
        raise agy_home.AgyAuthUnreachable()
    return proc


def _check_hooks_registered(home, probe_id, *, runner=None):
    """Verify `agy -p '/hooks' --output-format json` reports our `*` PreToolUse hook."""
    try:
        proc = _run_agy(["-p", "/hooks", "--output-format", "json"], home, runner=runner)
    except runners_base.LaunchRefused:
        raise
    except Exception as exc:  # noqa: BLE001
        return (hosts.UNKNOWN, probe_id,
                common.failure_detail(exc, "invocation of `agy -p /hooks`"))
    if getattr(proc, "returncode", 1) != 0:
        return (hosts.REFUTED, probe_id,
                "`agy -p /hooks` exited %s: %s" % (
                    getattr(proc, "returncode", 1),
                    (getattr(proc, "stderr", "") or "").strip()[:200]))
    try:
        doc = json.loads(getattr(proc, "stdout", "") or "")
    except ValueError as exc:
        return (hosts.REFUTED, probe_id,
                "`agy -p /hooks` returned non-JSON stdout (%s)" % exc)
    if not isinstance(doc, dict):
        return (hosts.REFUTED, probe_id, "`agy -p /hooks` JSON is not an object")
    script_path = os.path.abspath(agy_guard_hook.__file__)
    actions: list[dict] = []
    cmd_block = doc.get("command")
    hooks_list = ((cmd_block.get("data") or {}).get("hooks")
                  if isinstance(cmd_block, dict) and isinstance(cmd_block.get("data"), dict)
                  else None)
    if isinstance(hooks_list, list):
        for group in hooks_list:
            if isinstance(group, dict) and group.get("enabled", True):
                actions.extend(a for a in (group.get("actions") or []) if isinstance(a, dict))
    elif isinstance(doc.get("actions"), list):
        actions = [a for a in doc["actions"] if isinstance(a, dict)]
    if actions:
        pre = [a for a in actions
               if a.get("event") == "PreToolUse" and script_path in str(a.get("command", ""))]
        if not pre:
            return (hosts.REFUTED, probe_id,
                    "`agy -p /hooks` lists no PreToolUse hook invoking %s" % script_path)
        matchers = [a.get("matcher") for a in pre]
        if matchers != ["*"]:
            return (hosts.REFUTED, probe_id,
                    "PreToolUse hook matcher in `agy -p /hooks` is %r, expected ['*'] "
                    "(a narrowed matcher skips the hook for unlisted tools)" % (matchers,))
        return None
    resp = str(doc.get("response") or "")
    if ("PreToolUse\t*\t" in resp or "**PreToolUse** (`*`)" in resp) and script_path in resp:
        return None
    return (hosts.REFUTED, probe_id,
            "`agy -p /hooks` did not report wildcard PreToolUse (*) invoking %s: %r"
            % (script_path, resp[:200]))


def _invoke_hook(argv, payload, env):
    """Run `agy_guard_hook.py` in an isolated `-I` child interpreter via `children.launch`."""
    python = os.path.realpath(sys.executable)
    child_env = {"PATH": "",
                 "PANOPTICON_STATE_DIR": os.environ.get("PANOPTICON_STATE_DIR", "")}
    child_env.update(env)
    proc = children.launch(
        [python, "-I", os.path.abspath(agy_guard_hook.__file__), *argv],
        input=json.dumps(payload), env=child_env,
        capture_output=True, text=True, timeout=15)
    if getattr(proc, "returncode", 1) != 0:
        return None, "hook exited %s: %s" % (
            getattr(proc, "returncode", 1), getattr(proc, "stderr", ""))
    try:
        body = json.loads(getattr(proc, "stdout", "") or "")
    except ValueError as exc:
        return None, "hook printed non-JSON stdout: %s" % exc
    if not isinstance(body, dict) or body.get("decision") not in ("allow", "deny"):
        return None, "hook printed unexpected decision payload: %r" % (body,)
    return body["decision"] == "allow", str(body.get("reason", ""))


def probe_agy_shell_surface(host, registration_dir=None, *, runner=None):
    """Prove `tool_policy_enforced` for `agy` via frontmatter + `agy agents` under `<run_home>`."""
    if host != "agy":
        return (hosts.UNKNOWN, None,
                "probe %s applies only to host 'agy'" % AGY_SHELL_SURFACE)
    row = hosts.spec("agy")
    reg_dir = registration_dir or (row.registration_dir if row else "")
    if not reg_dir or not os.path.isdir(reg_dir):
        return (hosts.REFUTED, AGY_SHELL_SURFACE,
                "no shell registration directory at %s: run "
                "`python3 skill/scripts/dispatch.py --emit-host-agents agy`"
                % reg_dir)
    run = DEFAULT_RUNNER if runner is None else runner
    try:
        ver_proc = run([_BINARY, "--version"], capture_output=True, text=True,
                       timeout=common.CLI_HELP_TIMEOUT)
    except runners_base.LaunchRefused:
        raise
    except Exception as exc:  # noqa: BLE001
        return (hosts.UNKNOWN, AGY_SHELL_SURFACE,
                common.failure_detail(exc, "invocation of `agy --version`"))
    ver_out = (getattr(ver_proc, "stdout", "") or "").strip()
    m = _VERSION_RE.search(ver_out)
    ver_key = m.group(1) if m else ""
    vocab = agy_home.TOOL_VOCABULARY.get(ver_key)
    if vocab is None:
        return (hosts.UNKNOWN, AGY_SHELL_SURFACE,
                "`agy --version` reported %r (series %r has no pinned tool "
                "vocabulary in runners.agy_home.TOOL_VOCABULARY)"
                % (ver_out, ver_key))

    expected_by_agent = {}
    faults = []
    for role in common.DRIVER_ROLES:
        role_file = dispatch.ROLE_FILES[role]
        agent_name = dispatch.registered_agent_name(role_file)
        path = os.path.join(reg_dir, dispatch.registered_agent_filename("agy", role_file))
        if not os.path.isfile(path):
            faults.append("no shell at %s" % path)
            continue
        tp = dispatch.load_template(role_file)[0]["tool_policy"]
        expected_tools = dispatch._agy_tools(tp)
        expected_by_agent[agent_name] = expected_tools
        granted = common._frontmatter_tools(path)
        if granted is None:
            faults.append("%s: shell has no readable `tools:` list" % role)
            continue
        unknown = sorted(set(granted) - vocab)
        if unknown:
            faults.append("%s: shell tool(s) %s match nothing in agy %s vocabulary"
                          % (role, unknown, ver_key))
        elif sorted(granted) != sorted(expected_tools):
            faults.append("%s: shell grants %s, expected %s"
                          % (role, sorted(granted), sorted(expected_tools)))
    if faults:
        return (hosts.REFUTED, AGY_SHELL_SURFACE, "; ".join(faults))

    home = None
    try:
        home = agy_home.build(
            "/nonexistent/read-scope.json",
            "/nonexistent/write-allowlist.json",
            registration_dir=reg_dir)
        proc = _run_agy(["agents"], home, runner=runner)
    except runners_base.LaunchRefused:
        raise
    except Exception as exc:  # noqa: BLE001
        return (hosts.UNKNOWN, AGY_SHELL_SURFACE,
                common.failure_detail(exc, "invocation of `agy agents`"))
    finally:
        if home:
            agy_home.teardown(home, "complete")

    if getattr(proc, "returncode", 1) != 0:
        return (hosts.REFUTED, AGY_SHELL_SURFACE,
                "`agy agents` exited %s" % getattr(proc, "returncode", 1))
    out_text = getattr(proc, "stdout", "") or ""
    if "[project]" in out_text:
        return (hosts.REFUTED, AGY_SHELL_SURFACE,
                "`agy agents` reported a [project] shadow shell instead of [user] scope")
    discovered = set()
    for line in out_text.splitlines():
        s = line.strip()
        if not s or s.startswith(("Available", "Tools:")):
            continue
        if s.startswith("- "):
            s = s[2:].split()[0]
        discovered.add(s)
    missing_agents = sorted(set(expected_by_agent) - discovered)
    extra_agents = sorted(a for a in (discovered - set(expected_by_agent))
                          if a.startswith("panopticon-"))
    if missing_agents:
        return (hosts.REFUTED, AGY_SHELL_SURFACE,
                "`agy agents` did not load expected shell(s): %s"
                % ", ".join(missing_agents))
    if extra_agents:
        return (hosts.REFUTED, AGY_SHELL_SURFACE,
                "`agy agents` loaded unexpected panopticon shell(s): %s"
                % ", ".join(extra_agents))
    return (hosts.PROVEN, AGY_SHELL_SURFACE,
            "%d/%d agy shells verified against agy %s vocabulary in %s and "
            "loaded cleanly by `agy agents`"
            % (len(expected_by_agent), len(common.DRIVER_ROLES), ver_key, reg_dir))


def probe_agy_read_guard(host, *, runner=None, hooks_runner=None,
                         matcher=agy_home.HOOK_MATCHER):
    """Prove `read_scope_confined` via `/hooks` matcher verification, 0-quota
    hook round-trips, and a live `agy` unknown-tool + out-of-scope read canary."""
    if host != "agy":
        return (hosts.UNKNOWN, None,
                "probe %s applies only to host 'agy'" % AGY_READ_GUARD_ARMED)
    eff_runner = hooks_runner if hooks_runner is not None else runner
    sandbox = os.path.realpath(tempfile.mkdtemp(prefix="panopticon-agy-rg-"))
    home = None
    try:
        in_dir = os.path.join(sandbox, "granted_dir")
        os.makedirs(in_dir, exist_ok=True)
        in_file = os.path.join(in_dir, "allowed.py")
        out_file = os.path.join(sandbox, "outside.py")
        sentinel = "PANOPTICON_READ_CANARY_OUTSIDE_SECRET_9f8e7d"
        for p, text in ((in_file, "x = 1\n"), (out_file, "secret = %r\n" % sentinel)):
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(text)
        escape_link = os.path.join(in_dir, "escape.py")
        os.symlink(out_file, escape_link)

        scope_path = os.path.join(sandbox, "read-scope.json")
        allowlist_path = os.path.join(sandbox, "write-allowlist.json")
        scopes = read_guard_hook.scope_from_plan([
            {"id": "probe-entry", "scope": {"files": [in_file],
                                            "dirs": [in_dir],
                                            "reads": []}}
        ])
        with open(scope_path, "w", encoding="utf-8") as fh:
            json.dump(read_guard_hook.stamp_rows(scopes), fh)
        with open(allowlist_path, "w", encoding="utf-8") as fh:
            json.dump({"version": 2, "entries": {}, "paths": []}, fh)

        canary_agents = os.path.join(sandbox, "agents")
        os.makedirs(canary_agents, exist_ok=True)
        canary_shell = os.path.join(canary_agents, "panopticon-read-canary.md")
        with open(canary_shell, "w", encoding="utf-8") as fh:
            fh.write(
                "---\nname: panopticon-read-canary\n"
                "description: Read guard canary\nmodel: flash\n"
                "tools:\n  - read_file\n  - run_command\n  - finish\n---\n"
                "Follow the prompt exactly.\n")

        home = agy_home.build(
            scope_path, allowlist_path,
            registration_dir=canary_agents, matcher=matcher)

        hook_err = _check_hooks_registered(
            home, AGY_READ_GUARD_ARMED, runner=eff_runner)
        if hook_err is not None:
            return hook_err

        argv = [scope_path, allowlist_path]
        bound_env = {"PANOPTICON_ENTRY_ID": "probe-entry"}
        prompt = "<!-- panopticon-entry: probe-entry -->\nReview."

        allow_cases = (
            ("read_file(in_file)", {"lastUserInput": prompt, "toolCall": {"name": "read_file", "args": {"Path": in_file}}}),
            ("grep_search(in_file)", {"lastUserInput": prompt, "toolCall": {"name": "grep_search", "args": {"SearchPath": in_file, "Query": "x"}}}),
            ("list_dir(in_dir)", {"lastUserInput": prompt, "toolCall": {"name": "list_dir", "args": {"DirectoryPath": in_dir}}}),
            ("find_by_name(in_dir, *.py)", {"lastUserInput": prompt, "toolCall": {"name": "find_by_name", "args": {"SearchDirectory": in_dir, "Pattern": "allowed.py"}}}),
            ("finish", {"lastUserInput": prompt, "toolCall": {"name": "finish", "args": {}}}),
        )
        for label, payload in allow_cases:
            ok, reason = _invoke_hook(argv, payload, bound_env)
            if ok is not True:
                return (hosts.REFUTED, AGY_READ_GUARD_ARMED,
                        "read guard denied allowed case %s: %s" % (label, reason))

        deny_cases = (
            ("read_file(outside)", {"lastUserInput": prompt, "toolCall": {"name": "read_file", "args": {"Path": out_file}}}, bound_env),
            ("read_file(relative)", {"lastUserInput": prompt, "toolCall": {"name": "read_file", "args": {"Path": "allowed.py"}}}, bound_env),
            ("read_file(dotdot_relative)", {"lastUserInput": prompt, "toolCall": {"name": "read_file", "args": {"Path": "../workspace/allowed.py"}}}, bound_env),
            ("read_file(symlink_escape)", {"lastUserInput": prompt, "toolCall": {"name": "read_file", "args": {"Path": escape_link}}}, bound_env),
            ("grep_search(outside)", {"lastUserInput": prompt, "toolCall": {"name": "grep_search", "args": {"SearchPath": out_file, "Query": "secret"}}}, bound_env),
            ("grep_search(ungranted_dir)", {"lastUserInput": prompt, "toolCall": {"name": "grep_search", "args": {"SearchPath": sandbox, "Query": "secret"}}}, bound_env),
            ("list_dir(sandbox)", {"lastUserInput": prompt, "toolCall": {"name": "list_dir", "args": {"DirectoryPath": sandbox}}}, bound_env),
            ("find_by_name(climb)", {"lastUserInput": prompt, "toolCall": {"name": "find_by_name", "args": {"SearchDirectory": in_dir, "Pattern": "../outside.py"}}}, bound_env),
            ("find_by_name(.git)", {"lastUserInput": prompt, "toolCall": {"name": "find_by_name", "args": {"SearchDirectory": in_dir, "Pattern": ".git/config"}}}, bound_env),
            ("unbound_session", {"lastUserInput": prompt, "toolCall": {"name": "read_file", "args": {"Path": in_file}}}, {"PANOPTICON_ENTRY_ID": ""}),
            ("mismatched_marker", {"lastUserInput": "<!-- panopticon-entry: other-entry -->\nReview.", "toolCall": {"name": "read_file", "args": {"Path": in_file}}}, bound_env),
            ("unknown_tool(run_command)", {"lastUserInput": prompt, "toolCall": {"name": "run_command", "args": {"CommandLine": "echo pwn"}}}, bound_env),
            ("unknown_tool(view_file)", {"lastUserInput": prompt, "toolCall": {"name": "view_file", "args": {"Path": in_file}}}, bound_env),
        )
        for label, payload, env in deny_cases:
            ok, reason = _invoke_hook(argv, payload, env)
            if ok is not False:
                return (hosts.REFUTED, AGY_READ_GUARD_ARMED,
                        "read guard failed to deny %s (got ok=%r, reason=%r)" % (label, ok, reason))

        denial_log = os.path.join(sandbox, "canary-denials.jsonl")
        canary_prompt = (
            "<!-- panopticon-entry: probe-entry -->\n"
            "First call `run_command` with CommandLine=\"echo canary\", "
            "WaitMsBeforeAsync=1000, toolSummary=\"Canary\". "
            "Second call `read_file` with Path=%r. "
            "Then call `finish` with response=\"done\"." % out_file)
        try:
            canary_proc = _run_agy(
                ["--agent", "panopticon-read-canary",
                 "--model", "gemini-3.8-flash-medium",
                 "--disable-slash-commands",
                 "--output-format", "json",
                 "--json-schema",
                 "{\"type\":\"object\",\"properties\":{\"status\":{\"type\":\"string\"}},\"required\":[\"status\"]}",
                 "-p", canary_prompt],
                home,
                runner=eff_runner,
                extra_env={
                    "PANOPTICON_ENTRY_ID": "probe-entry",
                    agy_guard_hook.ENV_DENIAL_LOG: denial_log,
                },
                timeout=PROBE_TIMEOUT)
        except runners_base.LaunchRefused:
            raise
        except Exception as exc:  # noqa: BLE001
            return (hosts.UNKNOWN, AGY_READ_GUARD_ARMED,
                    common.failure_detail(exc, "live agy read-guard canary"))
        if getattr(canary_proc, "returncode", 1) != 0:
            return (hosts.UNKNOWN, AGY_READ_GUARD_ARMED,
                    "live agy read-guard canary exited %s"
                    % getattr(canary_proc, "returncode", 1))
        denied_tools = set()
        if os.path.isfile(denial_log):
            with open(denial_log, encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        rec = json.loads(line)
                        if isinstance(rec, dict) and rec.get("tool"):
                            denied_tools.add(rec["tool"])
        if not {"run_command", "read_file"} <= denied_tools:
            return (hosts.REFUTED, AGY_READ_GUARD_ARMED,
                    "live agy read-guard canary did not record both hook denials "
                    "(recorded: %s)" % sorted(denied_tools))
        canary_stdout = getattr(canary_proc, "stdout", "") or ""
        if sentinel in canary_stdout:
            return (hosts.REFUTED, AGY_READ_GUARD_ARMED,
                    "live agy read-guard canary leaked outside file sentinel in output")

        total = len(allow_cases) + len(deny_cases)
        return (hosts.PROVEN, AGY_READ_GUARD_ARMED,
                "agy PreToolUse (*) hook verified via `/hooks`, %d/%d payloads, "
                "and live canary denials (%s)"
                % (total, total, ", ".join(sorted(denied_tools))))
    except agy_home.AgyAuthUnreachable as exc:
        # #3576: no sign-in reachable from a run home, so nothing could be measured.
        return (hosts.UNKNOWN, AGY_READ_GUARD_ARMED, str(exc))
    finally:
        if home:
            agy_home.teardown(home, "complete")
        shutil.rmtree(sandbox, ignore_errors=True)


def probe_agy_write_guard(host, *, runner=None, hooks_runner=None,
                          matcher=agy_home.HOOK_MATCHER):
    """Prove `artifact_write_guard` via `/hooks` matcher verification and
    0-quota hook round-trips over v2 per-entry grants."""
    if host != "agy":
        return (hosts.UNKNOWN, None,
                "probe %s applies only to host 'agy'" % AGY_WRITE_GUARD_ARMED)
    eff_runner = hooks_runner if hooks_runner is not None else runner
    sandbox = os.path.realpath(tempfile.mkdtemp(prefix="panopticon-agy-wg-"))
    home = None
    try:
        run_dir = os.path.join(sandbox, agy_guard_hook.ARTIFACT_DIR, "runs", "probe")
        os.makedirs(run_dir, exist_ok=True)
        own_out = os.path.join(run_dir, "findings-g1-COD.json")
        peer_out = os.path.join(run_dir, "findings-g2-SEC.json")
        outside_out = os.path.join(sandbox, "outside.json")
        symlink_out = os.path.join(run_dir, "symlink.json")
        os.symlink(outside_out, symlink_out)

        scope_path = os.path.join(run_dir, "read-scope.json")
        allowlist_path = os.path.join(run_dir, "write-allowlist.json")
        v1_path = os.path.join(run_dir, "write-allowlist-v1.json")
        with open(scope_path, "w", encoding="utf-8") as fh:
            json.dump({}, fh)
        with open(allowlist_path, "w", encoding="utf-8") as fh:
            json.dump({
                "version": 2,
                "entries": {"writer-1": [own_out], "writer-2": [peer_out]},
                "paths": [own_out, peer_out],
            }, fh)
        with open(v1_path, "w", encoding="utf-8") as fh:
            json.dump([own_out], fh)

        home = agy_home.build(scope_path, allowlist_path, matcher=matcher)
        hook_err = _check_hooks_registered(
            home, AGY_WRITE_GUARD_ARMED, runner=eff_runner)
        if hook_err is not None:
            return hook_err

        argv = [scope_path, allowlist_path]
        bound_env = {"PANOPTICON_ENTRY_ID": "writer-1"}
        prompt = "<!-- panopticon-entry: writer-1 -->\nWrite findings."

        def _wcall(path, entry_prompt=prompt, name="write_file"):
            args = {"Path": path} if name != "write_file" else {"Path": path, "Content": "{}"}
            return {"lastUserInput": entry_prompt, "toolCall": {"name": name, "args": args}}

        ok, reason = _invoke_hook(argv, _wcall(own_out), bound_env)
        if ok is not True:
            return (hosts.REFUTED, AGY_WRITE_GUARD_ARMED,
                    "write guard denied own declared out_file: %s" % reason)

        deny_cases = (
            ("peer_out_file", argv, _wcall(peer_out), bound_env),
            ("relative_path", argv, _wcall("findings-g1-COD.json"), bound_env),
            ("dotdot_relative", argv, _wcall("../workspace/findings-g1-COD.json"), bound_env),
            ("outside_file", argv, _wcall(outside_out), bound_env),
            ("symlink_target", argv, _wcall(symlink_out), bound_env),
            ("dotdot_traversal", argv, _wcall(os.path.join(run_dir, "..", "escape.json")), bound_env),
            ("unbound_session", argv, _wcall(own_out), {"PANOPTICON_ENTRY_ID": ""}),
            ("unknown_entry", argv, _wcall(own_out, "<!-- panopticon-entry: ghost -->\nWrite."),
             {"PANOPTICON_ENTRY_ID": "ghost"}),
            ("v1_flat_allowlist", [scope_path, v1_path], _wcall(own_out), bound_env),
            ("unlisted_tool(edit_file)", argv, _wcall(own_out, name="edit_file"), bound_env),
        )
        for label, case_argv, payload, env in deny_cases:
            ok, reason = _invoke_hook(case_argv, payload, env)
            if ok is not False:
                return (hosts.REFUTED, AGY_WRITE_GUARD_ARMED,
                        "write guard failed to deny %s (got ok=%r)" % (label, ok))

        total = 1 + len(deny_cases)
        return (hosts.PROVEN, AGY_WRITE_GUARD_ARMED,
                "agy PreToolUse (*) write guard verified via `/hooks` and %d/%d "
                "payloads" % (total, total))
    except agy_home.AgyAuthUnreachable as exc:
        # #3576: no sign-in reachable from a run home, so nothing could be measured.
        return (hosts.UNKNOWN, AGY_WRITE_GUARD_ARMED, str(exc))
    finally:
        if home:
            agy_home.teardown(home, "complete")
        shutil.rmtree(sandbox, ignore_errors=True)


def _model_id_matches(data, model, effort):
    """Whether `/model`'s `command.data` names the bound model (#3564 owner capture).

    With an effort set, agy reports `<model>-<effort>` (`gemini-4-carbon-high`) and the
    level in `data.effort`; both must agree. Without one, the id is the model itself."""
    actual = data.get("id") if isinstance(data, dict) else None
    if not isinstance(actual, str):
        return False
    if actual == model:
        return True
    return bool(effort) and actual == model + "-" + effort and data.get("effort") == effort


def probe_agy_model_bound(host, registration_dir=None, *, runner=None):
    """Prove `model_binding` for `agy` by checking both emitted shell frontmatter
    tiers and `agy --agent <shell> --model <slug> [--effort <level>] -p /model`
    runtime resolution. A role with an effort also reads back `-p /effort` (#3564)."""
    if host != "agy":
        return (hosts.UNKNOWN, None,
                "probe %s applies only to host 'agy'" % AGY_MODEL_BOUND)
    row = hosts.spec("agy")
    reg_dir = registration_dir or (row.registration_dir if row else "")
    if not reg_dir or not os.path.isdir(reg_dir):
        return (hosts.REFUTED, AGY_MODEL_BOUND,
                "no registration directory at %s" % reg_dir)

    faults = []
    runtime_checks = []
    for role in common.DRIVER_ROLES:
        role_file = dispatch.ROLE_FILES[role]
        agent_name = dispatch.registered_agent_name(role_file)
        path = os.path.join(reg_dir, dispatch.registered_agent_filename("agy", role_file))
        if not os.path.isfile(path):
            faults.append("%s: missing shell at %s" % (role, path))
            continue
        reg_cfg = model_resolver.registration_config("agy", role)
        expected_tier = reg_cfg.get("tier")
        actual_tier = _frontmatter_field(path, "model") or _frontmatter_field(path, "tier")
        if actual_tier != expected_tier:
            faults.append("%s: shell declares tier %r != expected %r"
                          % (role, actual_tier, expected_tier))
            continue
        policy = model_resolver.entry_policy("agy", role)
        resolved_model = policy.get("model")
        if expected_tier is not None and not resolved_model:
            faults.append("%s: resolve_model returned no model" % role)
            continue
        if resolved_model:
            try:
                effort = agy_runner.effort_argv(policy.get("effort"), resolved_model)
            except ValueError as exc:
                faults.append("%s: %s" % (role, exc))
                continue
            runtime_checks.append((role, agent_name, resolved_model, effort,
                                   bool(policy.get("model_override"))))
    if faults:
        return (hosts.REFUTED, AGY_MODEL_BOUND, "; ".join(faults))
    if not runtime_checks:
        return (hosts.UNKNOWN, AGY_MODEL_BOUND,
                "no role carries an entry model, so no model binding could be measured")

    home = None
    bound_names = []
    try:
        route = agy_home.auth_route()
        home = agy_home.build(
            "/nonexistent/read-scope.json",
            "/nonexistent/write-allowlist.json",
            registration_dir=reg_dir, route=route)
        listed: frozenset = frozenset()
        if route == "key":
            listing = _run_agy(["models"], home, runner=runner)
            listed = agy_runner.listed_models(getattr(listing, "stdout", ""))
            if getattr(listing, "returncode", 1) != 0 or not listed:
                return (hosts.UNKNOWN, AGY_MODEL_BOUND,
                        "`agy models` on the API-key route exited %s with %d listed models, "
                        "so no binding could be measured (#3576)"
                        % (getattr(listing, "returncode", 1), len(listed)))
        for role, agent_name, resolved_model, effort, explicit in runtime_checks:
            if route == "key":
                # #3576: the key route folds the effort into the name and takes no --effort.
                try:
                    launch_model = agy_runner.key_route_model(
                        resolved_model, effort[1] if effort else None, listed,
                        explicit=explicit)
                except ValueError as exc:
                    faults.append("%s: %s" % (role, exc))
                    continue
                launch_effort: list[str] = []
            else:
                launch_model, launch_effort = resolved_model, effort
            bound_names.append(launch_model + (" " + launch_effort[1] if launch_effort else ""))
            proc = _run_agy(
                ["--agent", agent_name, "--model", launch_model, *launch_effort,
                 "--output-format", "json", "-p", "/model"],
                home, runner=runner)
            if getattr(proc, "returncode", 1) != 0:
                faults.append("%s: `agy -p /model` exited %s"
                              % (role, getattr(proc, "returncode", 1)))
                continue
            try:
                doc = json.loads(getattr(proc, "stdout", "") or "")
            except ValueError:
                faults.append("%s: `agy -p /model` returned non-JSON stdout" % role)
                continue
            data_block = _command_data(doc)
            level = launch_effort[1] if launch_effort else None
            if not _model_id_matches(data_block, launch_model, level):
                actual_slug = data_block.get("id") if isinstance(data_block, dict) else None
                faults.append("%s: `agy -p /model` did not report effective model %r%s "
                              "in command.data (got id %r)"
                              % (role, launch_model, " at effort %r" % level if level else "",
                                 actual_slug))
                continue
            if launch_effort:
                fault = _effort_readback(role, agent_name, launch_model, launch_effort, home,
                                         runner)
                if fault:
                    faults.append(fault)
    except runners_base.LaunchRefused:
        raise
    except Exception as exc:  # noqa: BLE001
        return (hosts.UNKNOWN, AGY_MODEL_BOUND,
                common.failure_detail(exc, "invocation of `agy -p /model`"))
    finally:
        if home:
            agy_home.teardown(home, "complete")

    if faults:
        return (hosts.REFUTED, AGY_MODEL_BOUND, "; ".join(faults))
    return (hosts.PROVEN, AGY_MODEL_BOUND,
            "all %d driver roles match frontmatter tiers and runtime `/model` "
            "resolution (%s)%s; %s" % (len(common.DRIVER_ROLES), ", ".join(sorted(set(bound_names))),
                                       " on the API-key route" if route == "key" else "",
                                       agy_runner.NO_ANSWERING_MODEL))


def _command_data(doc):
    """`command.data` of a print-mode slash-command payload, or None."""
    cmd_block = doc.get("command") if isinstance(doc, dict) else None
    return cmd_block.get("data") if isinstance(cmd_block, dict) else None


def _effort_readback(role, agent_name, model, effort, home, runner):
    """Read back the documented read-only `-p /effort` for a role with an effort (#3564).

    The owner's capture shape is `command.data` = {adjustable, current, available}. The
    level holds when `current` is the requested one and `available` lists it; a model
    whose effort is not adjustable cannot honor `--effort` at all. Returns a fault or None."""
    proc = _run_agy(
        ["--agent", agent_name, "--model", model, *effort,
         "--output-format", "json", "-p", "/effort"], home, runner=runner)
    if getattr(proc, "returncode", 1) != 0:
        return "%s: `agy -p /effort` exited %s" % (role, getattr(proc, "returncode", 1))
    try:
        doc = json.loads(getattr(proc, "stdout", "") or "")
    except ValueError:
        return "%s: `agy -p /effort` returned non-JSON stdout" % role
    data = _command_data(doc)
    level = effort[1]
    if not isinstance(data, dict):
        return "%s: `agy -p /effort` carried no command.data" % role
    if data.get("adjustable") is not True:
        return "%s: `agy -p /effort` reports %s's effort is not adjustable" % (role, model)
    available = data.get("available")
    if data.get("current") != level or not isinstance(available, list) or level not in available:
        return ("%s: `agy -p /effort` did not report effort %r as current and available "
                "(current %r, available %r)" % (role, level, data.get("current"), available))
    return None


def _ledger_carries_usage(ledger_path):
    """Verify every `ok` `agy` entry in `dispatch-ledger.jsonl` carries token usage."""
    checked = 0
    try:
        with open(ledger_path, encoding="utf-8") as fh:
            for idx, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                rec = json.loads(line)
                if (not isinstance(rec, dict)
                        or not rec.get("ok")
                        or rec.get("host") != "agy"):
                    continue
                checked += 1
                usage = rec.get("usage")
                total = (int(usage.get("total_tokens") or 0)
                         + int(usage.get("input_tokens") or 0)
                         + int(usage.get("output_tokens") or 0)) if isinstance(usage, dict) else 0
                if total <= 0:
                    return False, ("dispatch-ledger.jsonl entry %r (line %d) carries no "
                                   "token counts: %r" % (rec.get("entry_id") or rec.get("id"), idx, usage))
    except (OSError, ValueError) as exc:
        return False, "cannot read ledger %s: %s" % (ledger_path, exc)
    if checked == 0:
        return None, "dispatch-ledger.jsonl at %s has no completed agy entries yet" % ledger_path
    return True, "dispatch-ledger.jsonl (%d agy entries carry usage)" % checked


def probe_agy_usage_envelope(host, settings_path=None, *, runner=None):
    """Prove `usage_ledger` for `agy` via `--help` flag check, synthetic
    `parse_envelope` usage mapping check, and `dispatch-ledger.jsonl` verification."""
    if host != "agy":
        return (hosts.UNKNOWN, None,
                "probe %s applies only to host 'agy'" % AGY_USAGE_ENVELOPE)
    run = DEFAULT_RUNNER if runner is None else runner
    try:
        proc = run([_BINARY, "--help"], capture_output=True, text=True,
                   timeout=common.CLI_HELP_TIMEOUT)
    except runners_base.LaunchRefused:
        raise
    except Exception as exc:  # noqa: BLE001
        return (hosts.UNKNOWN, AGY_USAGE_ENVELOPE,
                common.failure_detail(exc, "invocation of `agy --help`"))
    help_text = (getattr(proc, "stdout", "") or "") + "\n" + (getattr(proc, "stderr", "") or "")
    missing = [flag for flag in agy_runner.Runner.ENVELOPE_FLAGS
               if not common._flag_advertised(flag, help_text)]
    if missing:
        return (hosts.REFUTED, AGY_USAGE_ENVELOPE,
                "`agy --help` does not advertise required envelope flag(s): %s"
                % ", ".join(missing))

    synthetic = json.dumps({
        "conversation_id": "probe-conv",
        "status": "SUCCESS",
        "response": "{\"ok\":true}",
        "duration_seconds": 0.5,
        "num_turns": 1,
        "usage": {
            "input_tokens": 120,
            "output_tokens": 30,
            "thinking_tokens": 15,
            "cache_read_tokens": 10,
            "total_tokens": 150,
        },
    })
    parsed = agy_runner.Runner("agy").parse_envelope("probe", synthetic, 0)
    usage = getattr(parsed, "usage", None)
    if (not isinstance(usage, dict)
            or usage.get("input_tokens") != 120
            or usage.get("output_tokens") != 30
            or usage.get("cache_read_input_tokens") != 10
            or usage.get("thinking_tokens") != 15
            or usage.get("total_tokens") != 150):
        return (hosts.REFUTED, AGY_USAGE_ENVELOPE,
                "runners.agy.Runner.parse_envelope failed to extract usage block: %r"
                % (usage,))

    if not settings_path:
        return (hosts.UNKNOWN, AGY_USAGE_ENVELOPE,
                "`agy --help` advertises %s and parse_envelope maps usage fields, "
                "but no run ledger path was provided to verify real agy usage"
                % ", ".join(agy_runner.Runner.ENVELOPE_FLAGS))

    ledger_path = os.path.join(
        os.path.dirname(os.path.abspath(settings_path)),
        runners_base.LEDGER_FILE)
    if not os.path.isfile(ledger_path):
        return (hosts.UNKNOWN, AGY_USAGE_ENVELOPE,
                "`agy --help` advertises %s and parse_envelope maps usage fields, "
                "but no dispatch-ledger.jsonl exists at %s yet"
                % (", ".join(agy_runner.Runner.ENVELOPE_FLAGS), ledger_path))

    ok, detail = _ledger_carries_usage(ledger_path)
    if ok is False:
        return (hosts.REFUTED, AGY_USAGE_ENVELOPE, detail)
    if ok is None:
        return (hosts.UNKNOWN, AGY_USAGE_ENVELOPE,
                "%s; %s" % (detail, agy_runner.NO_ANSWERING_MODEL))
    return (hosts.PROVEN, AGY_USAGE_ENVELOPE,
            "`agy --help` advertises %s, parse_envelope maps usage, "
            "and %s; %s"
            % (", ".join(agy_runner.Runner.ENVELOPE_FLAGS), detail,
               agy_runner.NO_ANSWERING_MODEL))
