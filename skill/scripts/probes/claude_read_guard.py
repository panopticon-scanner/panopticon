"""Private Claude read-guard installation and launch measurement."""
import json
import os
import shlex
import sys
import subprocess
import tempfile

from scripts import executable, read_guard_hook
import scripts.runners.children as children
from . import common


def _fake_subagent(parent_transcript, agent_id, entry_id, layout="direct"):
    """A subagent transcript with the dispatch prompt as its first user
    record, marker on line 1, in one of the two layouts the read guard binds
    through: the Agent-tool layout the plan-5 spike measured (`direct`,
    `<stem>/subagents/agent-<id>.jsonl`) or the Workflow-tool layout the
    shipped session-mode dispatch workflow relies on (`workflow`,
    `<stem>/subagents/workflows/<run>/agent-<id>.jsonl`)."""
    stem = parent_transcript[:-len(".jsonl")]
    directory = os.path.join(stem, "subagents")
    if layout == "workflow":
        directory = os.path.join(directory, "workflows", "wf-probe")
    os.makedirs(directory, exist_ok=True)
    record = {"type": "user", "isSidechain": True, "agentId": agent_id,
              "message": {"role": "user", "content": [
                  {"type": "text", "text": read_guard_hook.marker_line(entry_id) + "\nDo the work."}]}}
    with open(os.path.join(directory, "agent-%s.jsonl" % agent_id), "w", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")


def _round_trip_confines_reads():
    """Install the read hook in a sandbox and execute its trusted command.

    Hook unit tests own the rule and binding matrices. The probe owns the one
    machine-dependent fact they cannot: whether the installed command starts
    under this interpreter and allows/denies through the subprocess boundary.
    """
    try:
        with tempfile.TemporaryDirectory(prefix="panopticon-read ' ; $() ") as sandbox:
            settings = os.path.join(sandbox, "settings.json")
            scope_file = os.path.join(sandbox, "read-scope.json")
            inside = os.path.join(sandbox, "cell", "a.py")
            outside = os.path.join(sandbox, "elsewhere", "b.py")
            for p in (inside, outside):
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "w", encoding="utf-8") as fh:
                    fh.write("")
            parent = os.path.join(sandbox, "session.jsonl")
            with open(parent, "w", encoding="utf-8") as fh:
                fh.write("")
            _fake_subagent(parent, "agent-x", "probe-cell")
            read_guard_hook.install(
                [{"id": "probe-cell",
                  "scope": {"files": [inside], "dirs": [], "reads": []}}],
                settings_path=settings, scope_path=scope_file)
            if not read_guard_hook.guard_state(settings_path=settings, scope_path=scope_file)["armed"]:
                return False, "install() did not register the PreToolUse hook"
            ok, detail = _measure_installed_hook(settings, scope_file, parent,
                                                 inside, outside, sandbox)
            if not ok:
                return False, detail
            read_guard_hook.uninstall(settings_path=settings, scope_path=scope_file)
    except (OSError, RuntimeError, ValueError, TypeError) as exc:
        return False, common.failure_detail(
            exc, "the read-guard sandbox round-trip could not run")
    return True, detail


class _ReadHookProcess(children.ChildProcesses):
    """Private Python proof: enforce the driver's precise isolated command.

    The shared launcher supplies executable provenance, startup environment
    filtering and bounded process-group cleanup; this boundary additionally
    binds the only interpreter, script and scope this proof may execute.
    """

    def __init__(self, scope_file, sandbox):
        self.review_root = sandbox
        self.expected = (os.path.realpath(sys.executable), "-I",
                         os.path.abspath(read_guard_hook.__file__),
                         os.path.abspath(scope_file))

    def launch(self, argv, **kwargs):
        if tuple(argv) != self.expected:
            raise ValueError("read-guard command differs from the trusted isolated tuple")
        resolved = executable.resolve(argv[0], self.review_root,
                                      kwargs["env"].get("PATH", ""))
        if resolved.path != argv[0]:
            raise ValueError("read-guard executable resolution changed emitted identity")
        return super().launch(argv, **kwargs)


def _measure_installed_hook(settings, scope_file, parent, inside, outside, sandbox):
    """Compare settings with the driver's command, then execute trusted argv.

    Settings text is data, never shell source here. A corrupt or planted
    command cannot become the program this proof executes.
    """
    with open(settings, encoding="utf-8") as fh:
        configured = json.load(fh)
    if not isinstance(configured, dict) or not isinstance(configured.get("hooks"), dict):
        return False, "installed read-guard settings are malformed"
    entries = configured["hooks"].get("PreToolUse", [])
    expected = read_guard_hook._hook_entry(scope_file)
    if entries != [expected]:
        return False, "installed read-guard command differs from the driver's emitted command"
    argv = shlex.split(expected["hooks"][0]["command"])
    # M6 (#3411): the scope file is baked in, so the hook never infers it from its CWD.
    if argv != list(read_guard_hook._trusted_hook_argv()) + [os.path.abspath(scope_file)]:
        return False, "installed read-guard command is not the trusted argv plus the probe's scope file"
    process = _ReadHookProcess(scope_file, sandbox)
    payload = {"tool_name": "Read", "agent_id": "agent-x",
               "transcript_path": parent, "cwd": sandbox,
               "tool_input": {"file_path": inside}}
    for label, path, denied in (("allowed", inside, False),
                                ("denied", outside, True)):
        payload["tool_input"] = {"file_path": path}
        env = os.environ.copy()
        env.pop(read_guard_hook.ENV_ENTRY_ID, None)
        env.pop("PANOPTICON_READ_SCOPE", None)
        try:
            result = process.launch(argv, input=json.dumps(payload), text=True,
                                    capture_output=True, cwd=sandbox, env=env,
                                    timeout=5)
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            return False, "read-guard subprocess %s failed: %s" % (label, exc)
        if result.returncode != 0 or result.stderr:
            return False, "read-guard subprocess %s failed (exit %s): %s" % (
                label, result.returncode, result.stderr[:500])
        if not denied:
            if result.stdout.strip():
                return False, "read-guard subprocess allowed request emitted an unexpected decision"
            continue
        try:
            response = json.loads(result.stdout)
            hook = response["hookSpecificOutput"]
            valid = (hook["hookEventName"] == "PreToolUse"
                     and hook["permissionDecision"] == "deny"
                     and isinstance(hook["permissionDecisionReason"], str)
                     and bool(hook["permissionDecisionReason"]))
        except (ValueError, KeyError, TypeError):
            valid = False
        if not valid:
            return False, "read-guard subprocess denied request had a malformed or wrong decision"
    return True, "subprocess allow/deny ok"
