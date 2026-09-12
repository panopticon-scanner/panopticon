"""PreToolUse read-guard hook: a dispatched subagent may Read/Grep/Glob only
inside the scope its dispatch entry declares (#1070, first-class-hosts spec 7.2;
design spec 2026-09-12-panopticon-5.2-claude-read-confinement-design.md).

THE CRUX (design 1): a hook registered in `.claude/settings.local.json` is
session-wide, so the payload identifies the AGENT (`agent_id`), never the
dispatch ENTRY. The write guard sidesteps this with one union allowlist; a
union of read scopes would approximate the whole repository. So this hook
BINDS `agent_id` to an entry through the subagent's own transcript: Claude
Code writes it beside the parent transcript the payload names
(`<stem>/subagents/agent-<id>.jsonl`, or `<stem>/subagents/workflows/<wf>/`
for a Workflow-dispatched agent), and its FIRST user record is the dispatch
prompt verbatim -- measured in the spike, both layouts, present at the first
tool call. Every entry prompt therefore begins with one line,
``panopticon-entry: <entry id>``, rendered by the driver (phases/requests.py)
and never by a template. Only the orchestrator writes that first record, so
hostile target content -- which reaches an agent only through tool results --
cannot re-bind it.

SCOPE, STATED PLAINLY: this covers `_READ_TOOLS` only. No fan-out shell grants
Bash (`registered-shell-tools` proves that), so Bash needs no adjudication
here and gets none. The orchestrator -- a payload with no `agent_id` -- is
never confined, exactly as the write guard trusts it: it runs the driver.

FAIL-CLOSED WHILE ARMED: a subagent that cannot be bound, an entry id the
armed scope does not name, an unresolvable path, or a missing/malformed scope
file all DENY, with a reason the agent can read. Never a crash, never a
silent allow.

CLAUDE-ONLY BY CONSTRUCTION, like the write guard. Other families confine
reads their own way (spec 7.2). Stdlib-only and self-locating: Claude Code
runs this as ``python3 "<abs path>" "<abs scope path>"`` with no package on
sys.path, which is why the settings plumbing below is a copy of
write_guard_hook's rather than an import (plan 5, R-P5-5).
"""
import glob
import json
import os
import sys

_READ_TOOLS_LIST = ["Read", "Grep", "Glob"]
_READ_TOOLS = set(_READ_TOOLS_LIST)
_MATCHER = "|".join(_READ_TOOLS_LIST)

MARKER_PREFIX = "panopticon-entry: "
SCOPE_KEYS = ("files", "dirs", "reads")


def marker_line(entry_id):
    """Line 1 of an entry's prompt, WITHOUT its newline (the builder adds it).

    Any single-line id round-trips -- group names may carry spaces or colons
    -- so the only thing refused is an id that cannot be one line."""
    entry_id = "" if entry_id is None else str(entry_id)
    if not entry_id or "\n" in entry_id or "\r" in entry_id:
        raise ValueError("entry id must be a non-empty single line: %r" % entry_id)
    return MARKER_PREFIX + entry_id


def marker_of(text):
    """The entry id `text`'s FIRST line names, or None. Only the first line:
    a marker anywhere else is content, not a binding."""
    if not isinstance(text, str):
        return None
    first = text.split("\n", 1)[0].rstrip("\r")
    if not first.startswith(MARKER_PREFIX):
        return None
    return first[len(MARKER_PREFIX):].strip() or None


def _realpaths(paths):
    out = set()
    for p in paths or []:
        if isinstance(p, str) and p:
            try:
                out.add(os.path.realpath(os.path.abspath(p)))
            except (ValueError, OSError):
                continue
    return sorted(out)


def scope_from_plan(plan):
    """{entry id: {"files": [...], "dirs": [...], "reads": [...]}}, realpath-
    normalised, for every entry that carries an id and a `scope` dict.

    `plan` is a SEQUENCE OF ENTRIES, never the dispatch-request wrapper --
    the #1482 shape the write guard rejects for the same reason: a mapping's
    keys are strings, match nothing, and would arm an empty scope silently."""
    if isinstance(plan, (dict, str, bytes)):
        raise TypeError(
            "plan must be a sequence of dispatch entries, not %s -- pass the "
            "dispatch request's `entries` list, not the request object itself"
            % type(plan).__name__)
    out = {}
    for entry in plan:
        if not isinstance(entry, dict):
            continue
        eid, scope = entry.get("id"), entry.get("scope")
        if not isinstance(eid, str) or not eid or not isinstance(scope, dict):
            continue
        out[eid] = {k: _realpaths(scope.get(k)) for k in SCOPE_KEYS}
    return out


def _under(path, directory):
    """Separator-bounded prefix test: /repo admits /repo/x, never /repo-other."""
    directory = directory.rstrip(os.sep) or os.sep
    return path == directory or path.startswith(directory + os.sep)


def _resolve_path(raw):
    """realpath of a payload path, or None when it cannot be resolved -- a
    non-string, empty or NUL-bearing path is malformed and fails closed."""
    if not isinstance(raw, str) or not raw:
        return None
    try:
        return os.path.realpath(os.path.abspath(raw))
    except (ValueError, OSError, TypeError):
        return None


def _readable(target, scope):
    return (target in scope["files"] or target in scope["reads"]
            or any(_under(target, d) for d in scope["dirs"]))


def decide(tool_name, tool_input, scope):
    """(allow, reason) for a subagent's call. `scope` is the bound entry's
    scope dict, or None for an unbound subagent (deny). Design spec 4.3."""
    if tool_name not in _READ_TOOLS:
        return True, ""
    if scope is None:
        return False, (
            "%s is denied: this subagent is not bound to a dispatch entry (its "
            "dispatch prompt did not begin with '%s<entry id>'), and reads are "
            "confined while the read guard is armed" % (tool_name, MARKER_PREFIX))
    if not isinstance(tool_input, dict):
        return False, "%s is denied: malformed tool input" % tool_name
    if tool_name == "Read":
        raw = tool_input.get("file_path")
        target = _resolve_path(raw)
        if target is None:
            return False, "Read is denied: unresolvable path %r" % (raw,)
        if _readable(target, scope):
            return True, ""
        return False, ("Read of %s is outside your cell's scope; the files you may "
                       "read are listed in your prompt" % raw)
    raw = tool_input.get("path")
    target = _resolve_path(raw)
    if target is None:
        return False, ("%s is denied: pass `path` explicitly -- a file from the list "
                       "in your prompt" % tool_name)
    if os.path.isdir(target):
        if any(_under(target, d) for d in scope["dirs"]):
            return True, ""
        if tool_name == "Grep":
            return False, ("Grep over a directory is denied in a confined cell: grep a "
                           "file by its path; your cell's files are listed in your prompt")
        return False, ("Glob is not available in a confined cell: your file list is in "
                       "your prompt")
    if tool_name == "Grep":
        if _readable(target, scope):
            return True, ""
        return False, ("Grep of %s is outside your cell's scope; the files you may "
                       "search are listed in your prompt" % raw)
    return False, "Glob is not available in a confined cell: your file list is in your prompt"


def subagent_transcript(transcript_path, agent_id):
    """The calling subagent's own transcript, or None.

    The payload's `transcript_path` is the PARENT session's file (spike,
    design spec 3); the subagent's lives beside it, keyed by `agent_id`, in
    one of two layouts. `agent_id` is used as a path segment, so anything
    path-shaped is refused outright."""
    if not isinstance(transcript_path, str) or not isinstance(agent_id, str):
        return None
    if not agent_id or "/" in agent_id or os.sep in agent_id or agent_id in (".", ".."):
        return None
    stem = transcript_path[:-len(".jsonl")] if transcript_path.endswith(".jsonl") else transcript_path
    name = "agent-%s.jsonl" % agent_id
    direct = os.path.join(stem, "subagents", name)
    if os.path.isfile(direct):
        return direct
    found = sorted(glob.glob(os.path.join(glob.escape(stem), "subagents", "workflows", "*", name)))
    return found[0] if found else None


def _first_text(record):
    msg = record.get("message")
    content = msg.get("content") if isinstance(msg, dict) else None
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        for part in content:
            if (isinstance(part, dict) and part.get("type") == "text"
                    and isinstance(part.get("text"), str)):
                return part["text"]
    return ""


def bind(agent_id, transcript_path):
    """The entry id this subagent was dispatched for, or None (unbound).

    Reads the transcript only up to its FIRST `type: user` record -- the
    dispatch prompt -- and requires that record's `agentId` to be the caller.
    A later user turn is a tool result and can never re-bind (design 4.4)."""
    path = subagent_transcript(transcript_path, agent_id)
    if path is None:
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(record, dict) or record.get("type") != "user":
                    continue
                if record.get("agentId") != agent_id:
                    return None
                return marker_of(_first_text(record))
    except (OSError, ValueError):
        return None
    return None


def _load_scope(scope_path):
    """(scopes, error): the armed {entry id: scope} map, or (None, why)."""
    try:
        with open(scope_path, encoding="utf-8") as fh:
            loaded = json.load(fh)
    except (OSError, ValueError) as exc:
        return None, "read guard scope is unavailable: %s" % exc
    if not isinstance(loaded, dict):
        return None, "read guard scope is malformed"
    out = {}
    for eid, scope in loaded.items():
        if not isinstance(eid, str) or not isinstance(scope, dict):
            return None, "read guard scope is malformed"
        out[eid] = {k: [p for p in (scope.get(k) or []) if isinstance(p, str)]
                    for k in SCOPE_KEYS}
    return out, ""


def adjudicate(payload, scope_path):
    """(allow, reason) for one hook payload against the scope file at
    `scope_path`. The orchestrator (no `agent_id`) is never confined; every
    subagent is, fail-closed."""
    if not isinstance(payload, dict):
        return True, ""
    tool_name = payload.get("tool_name", "")
    if tool_name not in _READ_TOOLS:
        return True, ""
    agent_id = payload.get("agent_id")
    if not agent_id:
        return True, ""
    scopes, error = _load_scope(scope_path)
    if scopes is None:
        return False, error
    tool_input = payload.get("tool_input")
    # R-P5-7: Claude Code defaults a pathless Grep/Glob to the working
    # directory; adjudicate the same directory rather than guessing.
    if (isinstance(tool_input, dict) and tool_name in ("Grep", "Glob")
            and not tool_input.get("path")):
        tool_input = dict(tool_input, path=payload.get("cwd") or os.getcwd())
    entry_id = bind(agent_id, payload.get("transcript_path"))
    if entry_id is None:
        return decide(tool_name, tool_input, None)
    scope = scopes.get(entry_id)
    if scope is None:
        return False, ("%s is denied: this subagent is bound to entry %r, which the "
                       "armed read scope does not name" % (tool_name, entry_id))
    return decide(tool_name, tool_input, scope)


def _deny_response(reason):
    return json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    })


def _resolve_scope_path(argv_path=None):
    """Env override, then the absolute path install() baked into the hook
    command (returned even when absent: fail-closed), then a CWD walk --
    the same order and reasons as write_guard_hook._resolve_allowlist_path."""
    env_path = os.environ.get("PANOPTICON_READ_SCOPE")
    if env_path and os.path.isfile(env_path):
        return env_path
    if argv_path:
        return argv_path
    cur = os.path.abspath(os.getcwd())
    while True:
        candidate = os.path.join(cur, ".panopticon", "read-scope.json")
        if os.path.isfile(candidate):
            return candidate
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return os.path.join(".panopticon", "read-scope.json")


def main(argv=None):
    """`argv` is the argument list AFTER the program name; [] exercises a bare
    invocation with no baked-in scope path."""
    args = sys.argv[1:] if argv is None else argv
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        return 0  # tolerant: a malformed hook payload never blocks legitimate work
    if not isinstance(payload, dict):
        return 0
    if payload.get("tool_name", "") not in _READ_TOOLS:
        return 0
    allow, reason = adjudicate(payload, _resolve_scope_path(args[0] if args else None))
    if allow:
        return 0
    print(_deny_response(reason))
    return 0


if __name__ == "__main__":
    sys.exit(main())
