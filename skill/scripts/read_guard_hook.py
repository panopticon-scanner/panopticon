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
here and gets none. The orchestrator -- a payload with no `agent_id` and no
`agent_type` -- is never confined, exactly as the write guard trusts it: it
runs the driver. Plan 6 adds a second identity, `agent_type` with no
`agent_id`: the headless runner's `claude -p` process IS the reviewer, so
this payload shape is a session nothing bound, not the orchestrator, and
ENV_ENTRY_ID (below) is how the runner binds it (spec 5.3).

FAIL-CLOSED WHILE ARMED: a subagent that cannot be bound, an entry id the
armed scope does not name, an unresolvable path, or a missing/malformed scope
file all DENY, with a reason the agent can read. Never a crash, never a
silent allow.

CLAUDE-ONLY BY CONSTRUCTION, like the write guard. Other families confine
reads their own way (spec 7.2). Stdlib-only and self-locating: Claude Code
runs this as ``python3 <abs path> <abs scope path>`` -- one SHELL STRING, every
element shell-quoted (#1633) -- with no package on sys.path, which is why the
settings plumbing below is a copy of write_guard_hook's rather than an import
(plan 5, R-P5-5).
"""
import glob
import json
import os
import shlex
import stat
import sys

_READ_TOOLS_LIST = ["Read", "Grep", "Glob"]
_READ_TOOLS = set(_READ_TOOLS_LIST)
_MATCHER = "|".join(_READ_TOOLS_LIST)

MARKER_PREFIX = "panopticon-entry: "
# `hard_linked` (#1683) is the driver's ONE walk of a directory grant, taken
# when it is built (phases/hard_links, via phases/setup): the paths beneath it
# a directory-argument Grep/Glob must not traverse. An older scope file has no
# such key and loads as an empty list.
SCOPE_KEYS = ("files", "dirs", "reads", "hard_linked")

# Spec 5.3 (plan 6): the headless runner exports this per subprocess. It is
# the FIRST binding source -- a headless `claude -p` session is the reviewer
# itself (agent_type, no agent_id), so a transcript-only rule would fail
# OPEN for every headless entry.
ENV_ENTRY_ID = "PANOPTICON_ENTRY_ID"


def marker_line(entry_id):
    """Line 1 of an entry's prompt, WITHOUT its newline (the builder adds it).

    Entry ids are DRIVER-GENERATED, never user input, and already constrained
    to `^[A-Za-z0-9._:-]+$` in practice (design spec 4.4; groups_schema's
    `_GROUP_NAME_RE` forbids both spaces and colons in a group name, so no
    real id ever carries either) -- but this function does not enforce that
    grammar. It is permissive BY DESIGN: any single-line id round-trips, and
    the only thing refused is an id that cannot be one line, so a future id
    shape needs no change here to keep working."""
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
    if not isinstance(paths, (list, tuple)):
        paths = []
    out = set()
    for p in paths:
        if isinstance(p, str) and p:
            try:
                out.add(os.path.realpath(os.path.abspath(p)))
            except (ValueError, OSError):
                continue
    return sorted(out)


def scope_from_plan(plan):
    """{entry id: {key: [paths] for key in SCOPE_KEYS}}, realpath-normalised,
    for every entry that carries an id and a `scope` dict.

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


# #1642: one wording for one rule, across three read brokers.
# `codex_read_tools.HARD_LINK_DENIAL` is the original, and
# tests/test_codex_read_tools.py::test_the_hard_link_denial_is_one_wording pins
# the copies equal. Copied rather than imported for the reason everything in
# this module is: the hook runs standing alone, with no package on sys.path.
HARD_LINK_DENIAL = "read scope denies a hard-linked file inside a directory grant (st_nlink=%d)"

# #1683: the same rule, for the read whose argument is the DIRECTORY -- one
# wording across both hooks, pinned in tests/test_codex_read_tools.py beside
# the one above. Takes (tool, raw argument, the recorded path that fired).
DIRECTORY_LINK_DENIAL = (
    "%s of directory %s is denied: this tool traverses the directory itself, "
    "and the read scope recorded a hard-linked file beneath it (%s) -- a link "
    "can name an inode outside the granted tree. Grep a narrower directory, "
    "or a file by its path.")


def _hard_link_reason(tool_name, raw, target, scope):
    """The denial for a multiply-linked REGULAR file that only a DIRECTORY grant
    admits, or "" (#1642).

    realpath resolves SYMlinks; nothing resolves a hard link, because the link
    IS the file -- and a directory grant is matched by NAME, so a target that
    plants one inside the granted subtree, naming a file outside it, read as
    in-scope. An EXACT grant (`files`/`reads`) is the file the orchestrator
    chose and is unaffected whatever its link count, including when a directory
    grant covers it too (the normal cell shape).

    Directories are not the subject: a directory's st_nlink is its subdirectory
    count, and the rule is about reading content. A path that cannot be stat'ed
    DENIES and a path with NO INODE passes through, for the reasons the two
    `except` clauses below give (fix rounds 1 and 2, F4 and N2).

    THE OTHER HALF (#1683). This rule reaches reads whose argument is a FILE.
    A `Grep`/`Glob` argued with a granted DIRECTORY is adjudicated by path and
    then traversed by the host's own tool; `decide` refuses those from
    `scope["hard_linked"]` -- a hook may not walk the tree on every call.

    Unlike the Codex broker, which reads the count off the descriptor it then
    reads FROM, a PreToolUse hook adjudicates a NAME the host reopens: as
    path-based as the realpath check beside it, and carrying the same race.
    """
    if target in scope["files"] or target in scope["reads"]:
        return ""
    try:
        info = os.stat(target)
    except (FileNotFoundError, NotADirectoryError):
        # Fix round 2 (N2): ENOENT/ENOTDIR -- a dangling symlink included --
        # are not "could not measure". They measure that there is NO INODE at
        # that name: nothing for a read fence to confine, nothing an attacker
        # gains by inducing one, and the tool's own not-found is the honest
        # answer (a denial reads as a fence to the scout probing for absent
        # marker files).
        return ""
    except OSError as exc:
        # Fix round 1 (F4): a guard that cannot measure DENIES -- every other
        # errno (EACCES, ELOOP, ENAMETOOLONG, EIO). This used to answer "" --
        # allow -- guessing that the host's own read of an unstattable name
        # fails the same way, from the one component whose job is to be sure.
        return ("%s of %s is denied: the read guard could not stat it to apply "
                "the hard-link rule: %s" % (tool_name, raw, exc))
    if not stat.S_ISREG(info.st_mode) or info.st_nlink <= 1:
        return ""
    return "%s of %s is denied: %s" % (tool_name, raw, HARD_LINK_DENIAL % info.st_nlink)


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
            denial = _hard_link_reason(tool_name, raw, target, scope)
            return (False, denial) if denial else (True, "")
        return False, ("Read of %s is outside your cell's scope; the files you may "
                       "read are listed in your prompt" % raw)
    raw = tool_input.get("path")
    target = _resolve_path(raw)
    if target is None:
        return False, ("%s is denied: pass `path` explicitly -- a file from the list "
                       "in your prompt" % tool_name)
    if os.path.isdir(target):
        if any(_under(target, d) for d in scope["dirs"]):
            # #1683. Both directions: a link recorded BENEATH the argument is
            # what the traversal would reach, and the argument beneath a
            # recorded path is the walker's overflow encoding (the granted
            # directory itself) or an unreadable subtree.
            for p in scope.get("hard_linked") or ():
                if _under(p, target) or _under(target, p):
                    return False, DIRECTORY_LINK_DENIAL % (tool_name, raw, p)
            return True, ""
        if tool_name == "Grep":
            return False, ("Grep over a directory is denied in a confined cell: grep a "
                           "file by its path; your cell's files are listed in your prompt")
        return False, ("Glob is not available in a confined cell: your file list is in "
                       "your prompt")
    if tool_name == "Grep":
        if _readable(target, scope):
            denial = _hard_link_reason(tool_name, raw, target, scope)
            return (False, denial) if denial else (True, "")
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
        entry: dict[str, list[str]] = {}
        for k in SCOPE_KEYS:
            val = scope.get(k)
            if val is None:
                entry[k] = []
                continue
            if not isinstance(val, list):
                return None, "read guard scope is malformed"
            entry[k] = [p for p in val if isinstance(p, str)]
        out[eid] = entry
    return out, ""


def adjudicate(payload, scope_path, env=None):
    """(allow, reason) for one hook payload against the scope file at
    `scope_path`. Binding order (spec 5.3): the environment's ENV_ENTRY_ID,
    else the subagent transcript marker, else an `agent_type` with no binding
    is DENIED, else the orchestrator is never confined. `env` defaults to
    os.environ; the probe and the tests pass their own."""
    if not isinstance(payload, dict):
        return True, ""
    tool_name = payload.get("tool_name", "")
    if tool_name not in _READ_TOOLS:
        return True, ""
    env = os.environ if env is None else env
    env_id = env.get(ENV_ENTRY_ID)
    agent_id = payload.get("agent_id")
    agent_type = payload.get("agent_type")
    if not env_id and not agent_id:
        if agent_type:
            return False, ("%s is denied: this session runs as agent_type %r but "
                           "nothing bound it to a panopticon entry (no %s in the "
                           "environment, no subagent transcript)"
                           % (tool_name, agent_type, ENV_ENTRY_ID))
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
    if env_id:
        entry_id = env_id if isinstance(env_id, str) else None
    else:
        entry_id = bind(agent_id, payload.get("transcript_path"))
    if entry_id is None:
        return decide(tool_name, tool_input, None)
    scope = scopes.get(entry_id)
    if scope is None:
        return False, ("%s is denied: this agent is bound to entry %r, which the "
                       "armed read scope does not name" % (tool_name, entry_id))
    allow, reason = decide(tool_name, tool_input, scope)
    if not allow and reason:
        # decide() is entry-agnostic (plan 5, unchanged); name the bound
        # entry here so a denial is actionable without re-deriving the bind.
        reason = "%s (bound to entry %r)" % (reason, entry_id)
    return allow, reason


def _deny_response(reason):
    return json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    })


def hook_command(*argv):
    """One hook `command` string, every element shell-quoted (#1633, SEC-A1A).

    A registered PreToolUse command is SHELL SOURCE: Claude Code runs it
    through `sh -c`, so an element interpolated into it is not an argument. The
    `"%s"` this replaces stopped a space and nothing else, which left a `"`, a
    backtick or a `$(...)` in the scope path -- or in the checkout this script
    sits in -- executing on every tool call. Copied into each guard hook rather
    than imported, for the same reason the settings plumbing is (R-P5-5).
    """
    return " ".join(shlex.quote(a) for a in argv)


# #495: self-locate, shell-quoted -- the install path may contain spaces, or
# worse (#1633).
_HOOK_ARGV = ("python3", os.path.abspath(__file__))
_HOOK_CMD = hook_command(*_HOOK_ARGV)
_HOOK_ENTRY = {"matcher": _MATCHER,
               "hooks": [{"type": "command", "command": _HOOK_CMD}]}

DEFAULT_SETTINGS_PATH = ".claude/settings.local.json"
DEFAULT_SCOPE_PATH = ".panopticon/read-scope.json"


def _hook_entry(scope_path=None):
    """The PreToolUse entry to register; with `scope_path` the absolute scope
    file is baked into the command so the hook never infers it from CWD."""
    if not scope_path:
        return _HOOK_ENTRY
    cmd = hook_command(*_HOOK_ARGV, os.path.abspath(scope_path))
    return {"matcher": _MATCHER, "hooks": [{"type": "command", "command": cmd}]}


def _runs_this_script(command):
    """True when `command` invokes THIS module -- quoted (#1633) or in the bare
    form an earlier version wrote.

    Tokenizing is what keeps our own entry recognisable once the script path is
    quoted: a checkout path that needed escaping no longer appears verbatim in
    the command, and an entry uninstall cannot recognise is one it orphans,
    leaving the guard armed. Both legacy spellings tokenize cleanly, so the
    substring test is the fallback for a command no shell can parse: one that
    still names this script is ours (and removable), one that does not
    answers False rather than raising."""
    mine = os.path.abspath(__file__)
    try:
        tokens = shlex.split(command)
    except ValueError:                  # unbalanced quotes in a foreign entry
        tokens = []
    return mine in tokens or mine in command


def _is_our_entry(entry):
    """True for any PreToolUse entry that runs THIS module (never the write
    guard's -- the two coexist in one settings file, each keyed on its own
    script path)."""
    if not isinstance(entry, dict):
        return False
    for h in entry.get("hooks", []) or []:
        if isinstance(h, dict) and _runs_this_script(str(h.get("command", ""))):
            return True
    return False


def _load(settings_path):
    try:
        with open(settings_path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        # #1098: never re-serialize over a file we could not read.
        raise RuntimeError(
            "refusing to overwrite unreadable %s: %s" % (settings_path, exc)) from exc


def _atomic_write_json(path, data, indent=None):
    """Stage at `<path>.tmp`, then rename -- never writing THROUGH a symlink
    planted at that temp name (I7).

    A plain `open(tmp, "w")` follows a link. The settings, allowlist and scope
    files this writes all live where an untrusted target can reach: the run
    folder sits inside the scanned tree, and a redteam target can commit
    `<name>.tmp` as a link to any file the invoking user can write (a dotfile,
    authorized_keys), whose contents this would then replace with the guard's
    own JSON. Same class as #run9 SEC-X0X, which `runio._open_w_nofollow`
    closed for `.panopticon` artifacts.

    Spelled with os flags rather than by calling that helper: a guard hook is
    executed as its own subprocess by the host's PreToolUse command and has to
    import standing alone, so it may not reach into the driver's packages.
    O_EXCL|O_NOFOLLOW refuses both a symlink and a stale regular leftover, so
    the leftover is removed first and the open then creates a fresh file or
    fails loudly -- it never silently writes somewhere else.
    """
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    tmp = path + ".tmp"
    if os.path.islink(tmp) or os.path.exists(tmp):
        os.unlink(tmp)                  # drop the LINK, never follow it
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=indent)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _write_hook_entry(settings_path, scope_path=None):
    settings = _load(settings_path)
    hooks = settings.setdefault("hooks", {})
    pre = [h for h in hooks.get("PreToolUse", []) if not _is_our_entry(h)]
    pre.append(_hook_entry(scope_path))
    hooks["PreToolUse"] = pre
    _atomic_write_json(settings_path, settings, indent=2)


def _remove_hook_entry(settings_path):
    settings = _load(settings_path)
    hooks = settings.get("hooks", {})
    if "PreToolUse" not in hooks:
        return
    hooks["PreToolUse"] = [h for h in hooks["PreToolUse"] if not _is_our_entry(h)]
    if not hooks["PreToolUse"]:
        del hooks["PreToolUse"]
    if not hooks:
        settings.pop("hooks", None)
    _atomic_write_json(settings_path, settings, indent=2)


def _read_scope_file(scope_path):
    """The on-disk {entry id: scope} map, or {} when absent or malformed.
    (Enforcement fails closed on a malformed file in `_load_scope`; this only
    feeds the union arithmetic.)"""
    try:
        with open(scope_path, encoding="utf-8") as fh:
            loaded = json.load(fh)
    except (OSError, ValueError):
        return {}
    if not isinstance(loaded, dict):
        return {}
    return {k: v for k, v in loaded.items() if isinstance(k, str) and isinstance(v, dict)}


def _resolve(settings_path, scope_path, session_root):
    """(settings_path, scope_path, used_defaults) -- write_guard_hook._resolve's
    rules, verbatim (#1493): session_root OR explicit paths, never both."""
    explicit = settings_path is not None or scope_path is not None
    if session_root is not None:
        if explicit:
            raise ValueError(
                "pass session_root OR explicit settings_path/scope_path, not both "
                "-- they resolve to different files and the guard would arm "
                "somewhere other than where it was checked")
        return (os.path.join(session_root, DEFAULT_SETTINGS_PATH),
                os.path.join(session_root, DEFAULT_SCOPE_PATH), False)
    return (settings_path or DEFAULT_SETTINGS_PATH,
            scope_path or DEFAULT_SCOPE_PATH, not explicit)


def install(plan, settings_path=None, scope_path=None, *, session_root=None):
    """Arm the read guard for `plan`'s entries. UNIONS by entry id with any
    scope already on disk (#11: a concurrent fan-out's grants survive), ours
    winning on a shared id (R-P5-4: an id we dispatch is never left to a
    planted entry) -- INCLUDING an entry whose scope is empty: a dispatched
    id with an empty scope (e.g. a verify-tool-<fingerprint> advisor for a
    redacted/absent finding location) must overwrite any planted row for
    that id too, since decide() denies everything for an empty scope and
    that IS what "confines to nothing" (R-P5-2) intends -- never a hole that
    lets a planted grant survive under an id we are dispatching. Returns the
    {id: scope} map this call added (now including empty ones). Refuses
    only when `scope_from_plan(plan)` is itself empty -- no entry in `plan`
    carried a `scope` dict at all (e.g. a driver-plan checkpoint) -- since
    arming zero ids is a caller mistake, not a plan that legitimately
    confines some ids to nothing."""
    settings_path, scope_path, used_defaults = _resolve(settings_path, scope_path, session_root)
    if used_defaults and not os.path.exists(settings_path):
        raise ValueError(
            "refusing to arm the read-guard at %s: that settings file does not "
            "exist, so this would CREATE one -- which means the current directory "
            "(%s) is almost certainly not the session root, and the guard would "
            "never be consulted. Pass session_root=<the directory the session was "
            "started in>, or explicit settings_path/scope_path if you really mean "
            "this location." % (os.path.abspath(settings_path), os.path.abspath(os.curdir)))
    added = scope_from_plan(plan)
    if not added:
        raise ValueError(
            "refusing to install a read-guard that confines nothing: no entry "
            "carried a `scope` dict. Use uninstall() to tear the guard down.")
    merged = dict(_read_scope_file(scope_path))
    merged.update(added)
    _atomic_write_json(scope_path, merged)
    _write_hook_entry(settings_path, scope_path)
    return added


def guard_state(settings_path=None, scope_path=None, *, session_root=None):
    settings_path, scope_path, _ = _resolve(settings_path, scope_path, session_root)
    armed, entries = is_armed(settings_path, scope_path)
    return {"armed": armed, "entries": entries,
            "settings_path": os.path.abspath(settings_path),
            "scope_path": os.path.abspath(scope_path),
            "settings_exists": os.path.exists(settings_path)}


def is_armed(settings_path=None, scope_path=None, *, session_root=None):
    """(armed, entries): is the guard registered, and over how many entries?"""
    settings_path, scope_path, _ = _resolve(settings_path, scope_path, session_root)
    try:
        with open(settings_path, encoding="utf-8") as fh:
            settings = json.load(fh)
    except (OSError, ValueError):
        return False, 0
    hooks = (settings.get("hooks") or {}).get("PreToolUse") or []
    armed = any(_is_our_entry(entry) for entry in hooks)
    if not armed:
        return False, 0
    return True, len(_read_scope_file(scope_path))


def uninstall(settings_path=None, scope_path=None, *, plan=None, session_root=None):
    """With `plan`, drop only that fan-out's entry ids and keep the guard
    armed while any other fan-out's remain (#11); without it, tear the whole
    guard down."""
    settings_path, scope_path, _ = _resolve(settings_path, scope_path, session_root)
    if plan is not None:
        remaining = _read_scope_file(scope_path)
        for eid in scope_from_plan(plan):
            remaining.pop(eid, None)
        if remaining:
            _atomic_write_json(scope_path, remaining)
            return
    _remove_hook_entry(settings_path)
    try:
        os.remove(scope_path)
    except OSError:
        pass


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
    try:
        allow, reason = adjudicate(payload, _resolve_scope_path(args[0] if args else None))
    except Exception as exc:  # noqa: BLE001 -- fail CLOSED, never crash the hook
        # A non-2 exit is NON-blocking in Claude Code (the tool proceeds), so
        # an uncaught exception here would fail OPEN despite every tolerant
        # early return above being deliberately fail-closed-on-purpose.
        print(_deny_response("read guard crashed: %s" % exc))
        return 0
    if allow:
        return 0
    print(_deny_response(reason))
    return 0


if __name__ == "__main__":
    sys.exit(main())
