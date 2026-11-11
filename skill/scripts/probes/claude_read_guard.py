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


class _InstalledHookProcess(children.ChildProcesses):
    """Private Python proof: enforce a driver's precise isolated command.

    The shared launcher supplies executable provenance, startup environment
    filtering and bounded process-group cleanup; this boundary additionally
    binds the only interpreter, hook script and artifact this proof may execute.
    """

    def __init__(self, hook, artifact, sandbox):
        self.review_root = sandbox
        self.expected = (os.path.realpath(sys.executable), "-I",
                         os.path.abspath(hook.__file__),
                         os.path.abspath(artifact))

    def launch(self, argv, **kwargs):
        if tuple(argv) != self.expected:
            raise ValueError("guard command differs from the trusted isolated tuple")
        resolved = executable.resolve(argv[0], self.review_root,
                                      kwargs["env"].get("PATH", ""))
        if resolved.path != argv[0]:
            raise ValueError("guard executable resolution changed emitted identity")
        return super().launch(argv, **kwargs)


def _measure_installed_hook(settings, artifact, parent, inside, outside, sandbox,
                            *, hook=read_guard_hook, tool_name="Read",
                            artifact_name="the probe's scope file",
                            legacy_env="PANOPTICON_READ_SCOPE"):
    """Compare settings with the driver's command, then execute trusted argv.

    Settings text is data, never shell source here. A corrupt or planted
    command cannot become the program this proof executes. Read and Write use
    this same launch boundary so its tests own both probes' machine-dependent
    proof rather than two copies that can drift.
    """
    guard_name = "%s-guard" % tool_name.lower()
    with open(settings, encoding="utf-8") as fh:
        configured = json.load(fh)
    if not isinstance(configured, dict) or not isinstance(configured.get("hooks"), dict):
        return False, "installed %s settings are malformed" % guard_name
    entries = configured["hooks"].get("PreToolUse", [])
    expected = hook._hook_entry(artifact)
    if entries != [expected]:
        return False, "installed %s command differs from the driver's emitted command" % guard_name
    argv = shlex.split(expected["hooks"][0]["command"])
    # M6 (#3411): the artifact is baked in, so the hook never infers it from its CWD.
    if argv != list(hook._trusted_hook_argv()) + [os.path.abspath(artifact)]:
        return False, "installed %s command is not the trusted argv plus %s" % (
            guard_name, artifact_name)
    process = _InstalledHookProcess(hook, artifact, sandbox)
    payload = {"tool_name": tool_name, "agent_id": "agent-x",
               "transcript_path": parent, "cwd": sandbox,
               "tool_input": {"file_path": inside}}
    for label, path, denied in (("allowed", inside, False),
                                ("denied", outside, True)):
        payload["tool_input"] = {"file_path": path}
        env = os.environ.copy()
        env.pop(hook.ENV_ENTRY_ID, None)
        env.pop(legacy_env, None)
        try:
            result = process.launch(argv, input=json.dumps(payload), text=True,
                                    capture_output=True, cwd=sandbox, env=env,
                                    timeout=5)
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            return False, "%s subprocess %s failed: %s" % (guard_name, label, exc)
        if result.returncode != 0 or result.stderr:
            return False, "%s subprocess %s failed (exit %s): %s" % (
                guard_name, label, result.returncode, result.stderr[:500])
        if not denied:
            if result.stdout.strip():
                return False, "%s subprocess allowed request emitted an unexpected decision" % guard_name
            continue
        try:
            response = json.loads(result.stdout)
            decision = response["hookSpecificOutput"]
            valid = (decision["hookEventName"] == "PreToolUse"
                     and decision["permissionDecision"] == "deny"
                     and isinstance(decision["permissionDecisionReason"], str)
                     and bool(decision["permissionDecisionReason"]))
        except (ValueError, KeyError, TypeError):
            valid = False
        if not valid:
            return False, "%s subprocess denied request had a malformed or wrong decision" % guard_name
    return True, "%s subprocess allow/deny ok" % guard_name
