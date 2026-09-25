"""Private Claude read-guard round-trip fixtures and launch measurement."""
from typing import Any
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
    """Arm the read guard in a throwaway sandbox, bind four fake subagents
    through fake transcripts, and drive the thirteen payloads of design spec 5,
    plus four env-binding payloads of spec 5.3 (plan 6) and the planted-hard-link
    check of #1917, through adjudicate(), then launch the installed hook for
    allow and deny payloads. Never touches the session's real settings, scope
    file or transcripts.

    Returns (ok, detail), where `ok` is True, False -- or None for the one
    outcome that is neither (#1917): the planted-hard-link fixture could not be
    established, so that sub-check went unmeasured. The caller reports None as
    UNKNOWN, never as a refutation."""
    try:
        with tempfile.TemporaryDirectory(prefix="panopticon-read ' ; $() ") as sandbox:
            settings = os.path.join(sandbox, "settings.json")
            scope_file = os.path.join(sandbox, "read-scope.json")
            inside = os.path.join(sandbox, "cell", "a.py")
            outside = os.path.join(sandbox, "elsewhere", "b.py")
            root = os.path.join(sandbox, "root")
            for p in (inside, outside, os.path.join(root, "c.py")):
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "w", encoding="utf-8") as fh:
                    fh.write("")
            parent = os.path.join(sandbox, "session.jsonl")
            with open(parent, "w", encoding="utf-8") as fh:
                fh.write("")
            _fake_subagent(parent, "agent-x", "probe-cell")
            _fake_subagent(parent, "agent-z", "probe-scan")
            _fake_subagent(parent, "agent-w", "probe-cell", layout="workflow")
            _fake_subagent(parent, "agent-v", "probe-links")
            # #1917: the refutation fixture the Codex probe has carried since
            # #1642 (probes/codex.py). A hard link INSIDE a directory grant
            # naming an inode OUTSIDE it is the one case where "this name is
            # under the grant" and "this content is in scope" come apart, and a
            # directory-argument Grep is adjudicated ONCE, by path, then
            # traversed by the host's own tool. Its own grant, so the clean
            # `probe-scan` rows keep measuring a clean tree. The recorded list
            # is built by the DRIVER's walker (phases/hard_links), which is what
            # makes this the whole rule rather than the hook's half of it.
            import scripts.phases.hard_links as hard_links
            links_root = os.path.join(sandbox, "links")
            clean = os.path.join(links_root, "clean")
            os.makedirs(clean, exist_ok=True)
            planted = os.path.join(links_root, "planted.py")
            try:
                os.link(outside, planted)
            except OSError as exc:
                # F3, as codex does it: a volume with no links to plant has not
                # refuted a healthy host. None -> UNKNOWN for this row, and no
                # stand-in path -- a grant whose list nobody walked must not
                # pass for one that was measured.
                return None, ("the hard-link refutation fixture could not be "
                              "planted at %s: %s" % (planted, exc))
            # ...and the same tolerance one volume class narrower (fix round 1,
            # finding 2): `os.link` can SUCCEED where `lstat` does not report the
            # link count (some FUSE and network mounts), and the walker then
            # legitimately records nothing. Measuring the plant is the only way
            # to tell that unestablished fixture from a walker gone blind, so
            # the count is taken here and the refutation below is narrowed to
            # "the volume DID report a link and the walk still missed it".
            try:
                planted_links = os.lstat(planted).st_nlink
            except OSError as exc:
                return None, ("the hard-link refutation fixture planted at %s could not be "
                              "measured: %s" % (planted, exc))
            if planted_links <= 1:
                return None, ("the hard-link refutation fixture was planted at %s, but the "
                              "volume reports st_nlink=%d: it does not count links, so there "
                              "is nothing here to record" % (planted, planted_links))
            recorded = hard_links.hard_links_under(links_root)[0]
            if not recorded:
                # The plant SUCCEEDED, the volume counts links, and the walk
                # still found nothing: half the rule is missing, which is a
                # refutation and not a fixture problem (and the rows below would
                # otherwise have no path to name).
                return False, ("the guard's own walker recorded no hard link beneath %s "
                               "after one was planted at %s (st_nlink=%d)"
                               % (links_root, planted, planted_links))
            read_guard_hook.install(
                [{"id": "probe-cell", "scope": {"files": [inside], "dirs": [], "reads": []}},
                 {"id": "probe-scan", "scope": {"files": [], "dirs": [root], "reads": []}},
                 {"id": "probe-links",
                  "scope": hard_links.scope(dirs=[links_root], hard_linked=recorded)}],
                settings_path=settings, scope_path=scope_file)
            if not read_guard_hook.guard_state(settings_path=settings, scope_path=scope_file)["armed"]:
                return False, "install() did not register the PreToolUse hook"

            def adjudicated(tool, agent, **tool_input):
                payload = {"tool_name": tool, "tool_input": tool_input,
                           "transcript_path": parent, "cwd": sandbox}
                if agent:
                    payload["agent_id"] = agent
                # A stray PANOPTICON_ENTRY_ID in the operator's shell must
                # never change this probe's verdict -- env is explicit here.
                return read_guard_hook.adjudicate(payload, scope_file, env={})

            def call(tool, agent, **tool_input):
                return adjudicated(tool, agent, **tool_input)[0]

            cell_dir = os.path.dirname(inside)
            rows = (
                ("bound Read inside scope", call("Read", "agent-x", file_path=inside), True),
                ("bound Read outside scope", call("Read", "agent-x", file_path=outside), False),
                ("bound Grep of an in-scope file", call("Grep", "agent-x", pattern="x", path=inside), True),
                ("bound Grep over a directory", call("Grep", "agent-x", pattern="x", path=cell_dir), False),
                ("bound Glob", call("Glob", "agent-x", pattern="*.py", path=cell_dir), False),
                ("unbound subagent Read", call("Read", "agent-y", file_path=inside), False),
                ("orchestrator Read outside any scope", call("Read", None, file_path=outside), True),
                ("directory-scoped Grep inside its dir", call("Grep", "agent-z", pattern="x", path=root), True),
                ("directory-scoped Glob inside its dir", call("Glob", "agent-z", pattern="*.py", path=root), True),
                ("directory-scoped Read outside its dir", call("Read", "agent-z", file_path=outside), False),
                # The Workflow-tool transcript layout (Claude family PR): the
                # shipped dispatch workflow binds every entry through it.
                ("workflow-layout Read inside scope", call("Read", "agent-w", file_path=inside), True),
                ("workflow-layout Read outside scope", call("Read", "agent-w", file_path=outside), False),
                # #1917: a clean subdirectory of a grant that recorded a link
                # elsewhere keeps its Grep -- the rule denies the traversals
                # that would cross a link, not the grant.
                ("directory-scoped Grep of a clean subdirectory",
                 call("Grep", "agent-v", pattern="x", path=clean), True),
            )
            for name, got, want in rows:
                if got != want:
                    return False, "the guard %s: %s" % ("ALLOWED" if got else "DENIED", name)

            # ...and the row whose WORDING is the measurement (#1917, the N-2
            # argument from codex's probe): every entry here would deny this
            # path for some other reason on a build where the directory-grant
            # rule was gone, so a bare denial proves nothing. The sentence is
            # taken from the hook's own constant, so a reworded rule is a
            # reworded expectation and never a silent pass.
            allowed, reason = adjudicated("Grep", "agent-v", pattern="x", path=links_root)
            # A SUBSTRING test, not equality: adjudicate() appends which entry
            # the call was bound to, and that suffix is not this rule's wording.
            expected = read_guard_hook.DIRECTORY_LINK_DENIAL % ("Grep", links_root, recorded[0])
            if allowed or expected not in reason:
                return False, ("the guard did not refuse a directory Grep over a planted "
                               "hard-link by the hard-link rule: %s"
                               % ("ALLOWED" if allowed else reason))

            # Spec 5.3 (plan 6): the env binding the headless runner relies on.
            env_rows: tuple[tuple[str, dict[str, Any], dict[str, str], bool], ...] = (
                ("env-bound read inside its entry",
                 {"tool_name": "Read", "tool_input": {"file_path": inside}},
                 {read_guard_hook.ENV_ENTRY_ID: "probe-cell"}, True),
                ("env-bound read outside its entry",
                 {"tool_name": "Read", "tool_input": {"file_path": outside}},
                 {read_guard_hook.ENV_ENTRY_ID: "probe-cell"}, False),
                ("agent_type with no binding",
                 {"tool_name": "Read", "tool_input": {"file_path": inside},
                  "agent_type": "panopticon-scout"}, {}, False),
                # The real headless payload shape: agent_type AND the env id
                # both present. The env binding governs either way (#1344
                # plan 6 review finding 1).
                ("env-bound read inside its entry despite agent_type",
                 {"tool_name": "Read", "tool_input": {"file_path": inside},
                  "agent_type": "panopticon-domain-panel"},
                 {read_guard_hook.ENV_ENTRY_ID: "probe-cell"}, True),
            )
            for name, env_payload, env, want in env_rows:
                got = read_guard_hook.adjudicate(env_payload, scope_file, env=env)[0]
                if got != want:
                    return False, "env binding: the guard %s: %s" % (
                        "ALLOWED" if got else "DENIED", name)
            ok, detail = _measure_installed_hook(settings, scope_file, parent,
                                                 inside, outside, sandbox)
            if not ok:
                return False, detail
            read_guard_hook.uninstall(settings_path=settings, scope_path=scope_file)
    except (OSError, RuntimeError, ValueError, TypeError) as exc:
        return False, common.failure_detail(
            exc, "the read-guard sandbox round-trip could not run")
    return True, ("arm/bind/deny round-trip ok (%d rows), and a directory Grep over a hard link "
                  "planted inside a directory grant refused as hard-linked; subprocess "
                  "allow/deny ok" % (len(rows) + len(env_rows)))


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
