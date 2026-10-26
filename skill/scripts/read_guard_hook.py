"""PreToolUse read-guard hook: a dispatched subagent may Read/Grep/Glob only
inside the scope its dispatch entry declares (#1070, first-class-hosts spec 7.2;
design spec 2026-09-12-panopticon-5.2-claude-read-confinement-design.md).

THE CRUX (design 1): a hook registered in `.claude/settings.local.json` is
session-wide, so the payload identifies the AGENT (`agent_id`), never the
dispatch ENTRY. The write guard sidesteps this with one union allowlist; a
union of read scopes would approximate the whole repository. So this hook
BINDS `agent_id` to an entry through the subagent's own transcript, which
Claude Code writes beside the parent transcript the payload names
(`<stem>/subagents/agent-<id>.jsonl`, or `<stem>/subagents/workflows/<wf>/`
for a Workflow-dispatched agent) and whose FIRST user record is the dispatch
prompt verbatim -- measured in the spike, both layouts, present at the first
tool call. Every entry prompt therefore begins with ``panopticon-entry: <entry
id>``, rendered by the driver (phases/requests.py) and never by a template.
Only the orchestrator writes that first record, so hostile target content --
which reaches an agent only through tool results -- cannot re-bind it.

SCOPE, STATED PLAINLY: this covers `_READ_TOOLS` only. No fan-out shell grants
Bash (`registered-shell-tools` proves that), so Bash needs no adjudication here
and gets none. The orchestrator -- no `agent_id` and no `agent_type` -- is
never confined, exactly as the write guard trusts it: it runs the driver. Plan
6 adds a second identity, `agent_type` with no `agent_id`: the headless
runner's `claude -p` process IS the reviewer, so that payload shape is a
session nothing bound, and ENV_ENTRY_ID binds it (spec 5.3).

FAIL-CLOSED WHILE ARMED: a subagent that cannot be bound, an entry id the armed
scope does not name, an unresolvable path, or a missing/malformed scope file all
DENY, with a reason the agent can read. Never a crash, never a silent allow --
which is why the trusted launch argv below is computed on ACCESS rather than at
import (#2006). In the hook PROCESS a crash is fail-OPEN: Claude Code treats
exit 2 as a block and any other non-zero as a non-blocking error, so the Read
proceeds. `main()`'s `except Exception` is this module's only never-crash
envelope, and nothing may raise outside it.

CLAUDE-ONLY BY CONSTRUCTION, like the write guard; other families confine
reads their own way (spec 7.2). Stdlib-only and self-locating: Claude Code
runs this as ONE SHELL STRING with every element shell-quoted (#1633) -- the
trusted absolute interpreter, ``-I``, this standalone script, and the absolute
scope path. The interpreter is the driver's own, resolved, because PATH must
not choose it; ``-I`` keeps PYTHONPATH, the user site and the script's
directory off sys.path (#1996), though not that interpreter's own
site-packages or a `sitecustomize` installed there. With no package on
sys.path (plan 5, R-P5-5), the rules this hook shares with the other two are
loaded BY PATH from `guard_rules.py` beside it, where they used to be copied
(#3273 cut 11; the loader stanza below).
"""
import json
import os
import sys

_READ_TOOLS_LIST = ["Read", "Grep", "Glob"]
_READ_TOOLS = set(_READ_TOOLS_LIST)
_MATCHER = "|".join(_READ_TOOLS_LIST)

# Every name this hook reads from guard_rules; the loader refuses a module that
# lacks one, so a renamed rule denies at load rather than crashing mid-call.
_GUARD_RULES_USED = (
    "MARKER_PREFIX", "SCOPE_KEYS", "ENV_ENTRY_ID", "GLOB_PATTERN_DENIAL", "GIT_STORE_DENIAL",
    "_resolve_path", "_readable", "_in_dir_grant", "_glob_pattern_climbs", "_names_git_store",
    "_load_scope", "bind", "hook_command", "_trusted_hook_argv", "_is_our_entry", "_load",
    "atomic_write_json", "_write_hook_entry", "_remove_hook_entry", "_armed")

# --- GUARD RULES LOADER (#3273 cut 11) ---
# Byte-identical in the three guard hooks (tests/test_guard_rules.py). Run as a
# hook (`<python> -I <abs path>`) this module has no package, so guard_rules.py
# is loaded by PATH from this file's real directory -- never `import scripts.*`,
# which a foreign `scripts` package in site-packages could answer. Imported
# under our package (the driver, the tests, `python -m`), it is the sibling
# module, so a patch lands where the hook looks. ANY failure -- a missing file,
# a raise or a SyntaxError in it, a name it lacks -- leaves `guard_rules` None,
# and every call this hook guards is then DENIED: an import-time crash here
# would fail OPEN.
def _load_guard_rules():
    spec = globals().get("__spec__")
    if spec is not None and spec.parent:
        from . import guard_rules as rules
    else:
        import importlib.util
        path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "guard_rules.py")
        found = importlib.util.spec_from_file_location("panopticon_guard_rules", path)
        if found is None or found.loader is None:
            raise ImportError("no loader for %s" % path)
        rules = importlib.util.module_from_spec(found)
        found.loader.exec_module(rules)
    missing = [name for name in _GUARD_RULES_USED if not hasattr(rules, name)]
    if missing:
        raise AttributeError("guard_rules lacks %s" % ", ".join(missing))
    return rules


try:
    guard_rules = _load_guard_rules()
    _GUARD_RULES_FAULT = ""
except Exception as exc:  # noqa: BLE001 -- see above: never an import-time raise
    guard_rules = None
    _GUARD_RULES_FAULT = "the shared guard rules could not load (%s: %s)" % (
        type(exc).__name__, exc)
# --- END GUARD RULES LOADER ---

if guard_rules is not None:
    # The shared constants, under the names this hook's consumers already read.
    MARKER_PREFIX = guard_rules.MARKER_PREFIX
    SCOPE_KEYS = guard_rules.SCOPE_KEYS
    ENV_ENTRY_ID = guard_rules.ENV_ENTRY_ID
    GLOB_PATTERN_DENIAL = guard_rules.GLOB_PATTERN_DENIAL
    GIT_STORE_DENIAL = guard_rules.GIT_STORE_DENIAL


def marker_line(entry_id):
    """Line 1 of an entry's prompt, WITHOUT its newline (the builder adds it).

    Permissive BY DESIGN, enforcing no grammar: driver-generated ids already
    match `^[A-Za-z0-9._:-]+$` in practice (design spec 4.4; groups_schema's
    `_GROUP_NAME_RE` forbids spaces and colons in a group name), but any
    single-line id round-trips here and only an id that cannot be one line is
    refused -- so a future id shape needs no change."""
    entry_id = "" if entry_id is None else str(entry_id)
    if not entry_id or "\n" in entry_id or "\r" in entry_id:
        raise ValueError("entry id must be a non-empty single line: %r" % entry_id)
    return guard_rules.MARKER_PREFIX + entry_id


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

    `plan` is a SEQUENCE OF ENTRIES, never the dispatch-request wrapper -- the
    #1482 shape the write guard rejects for the same reason: a mapping's keys
    are strings, match nothing, and would arm an empty scope silently."""
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
        out[eid] = {k: _realpaths(scope.get(k)) for k in guard_rules.SCOPE_KEYS}
    return out


def decide(tool_name, tool_input, scope):
    """(allow, reason) for a subagent's call. `scope` is the bound entry's
    scope dict, or None for an unbound subagent (deny). Design spec 4.3."""
    if tool_name not in _READ_TOOLS:
        return True, ""
    if scope is None:
        return False, ("%s is denied: this subagent is not bound to a dispatch "
                       "entry (its dispatch prompt did not begin with '%s<entry "
                       "id>'), and reads are confined while the guard is armed"
                       % (tool_name, guard_rules.MARKER_PREFIX))
    if not isinstance(tool_input, dict):
        return False, "%s is denied: malformed tool input" % tool_name
    if tool_name == "Read":
        raw = tool_input.get("file_path")
        target = guard_rules._resolve_path(raw)
        if target is None:
            return False, "Read is denied: unresolvable path %r" % (raw,)
        if guard_rules._readable(target, scope):
            return True, ""
        return False, ("Read of %s is outside your cell's scope; the files you may "
                       "read are listed in your prompt" % raw)
    raw = tool_input.get("path")
    target = guard_rules._resolve_path(raw)
    if target is None:
        return False, ("%s is denied: pass `path` explicitly -- a file from the list "
                       "in your prompt" % tool_name)
    if os.path.isdir(target):
        if any(guard_rules._in_dir_grant(target, d) for d in scope["dirs"]):
            # #1917: and for Glob, the second argument -- the only one of these
            # tools whose pattern is a PATH pattern, expanded against `path`.
            pattern = tool_input.get("pattern")
            if tool_name == "Glob" and guard_rules._glob_pattern_climbs(pattern):
                return False, guard_rules.GLOB_PATTERN_DENIAL % (pattern,)
            if tool_name == "Glob" and guard_rules._names_git_store(pattern):
                return False, guard_rules.GIT_STORE_DENIAL % (pattern,)
            return True, ""
        if tool_name == "Grep":
            return False, ("Grep over a directory is denied in a confined cell: grep a "
                           "file by its path; your cell's files are listed in your prompt")
        return False, ("Glob is not available in a confined cell: your file list is in "
                       "your prompt")
    if tool_name == "Grep":
        if guard_rules._readable(target, scope):
            return True, ""
        return False, ("Grep of %s is outside your cell's scope; the files you may "
                       "search are listed in your prompt" % raw)
    return False, "Glob is not available in a confined cell: your file list is in your prompt"


def adjudicate(payload, scope_path, env=None):
    """(allow, reason) for one hook payload against the scope file at
    `scope_path`. Binding order (spec 5.3): the environment's ENV_ENTRY_ID,
    else the subagent transcript marker, else an `agent_type` with no binding
    DENIES, else the orchestrator is never confined. `env` defaults to
    os.environ; the probe and the tests pass their own.

    With the shared rules unloaded, every call denies, before anything else is
    asked: the loader stanza's contract (#3273 cut 11)."""
    if guard_rules is None:
        return False, "read guard: %s" % _GUARD_RULES_FAULT
    if not isinstance(payload, dict):
        return True, ""
    tool_name = payload.get("tool_name", "")
    if tool_name not in _READ_TOOLS:
        return True, ""
    env = os.environ if env is None else env
    env_id = env.get(guard_rules.ENV_ENTRY_ID)
    agent_id = payload.get("agent_id")
    agent_type = payload.get("agent_type")
    if not env_id and not agent_id:
        if agent_type:
            return False, ("%s is denied: this session runs as agent_type %r but "
                           "nothing bound it to a panopticon entry (no %s in the "
                           "environment, no subagent transcript)"
                           % (tool_name, agent_type, guard_rules.ENV_ENTRY_ID))
        return True, ""
    scopes, error = guard_rules._load_scope(scope_path)
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
        entry_id = guard_rules.bind(agent_id, payload.get("transcript_path"))
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


# #495: self-locate, shell-quoted -- the install path may contain spaces, or
# worse (#1633). The interpreter is the trusted process already running the
# driver; PATH and PYTHONPATH must not choose code for a dispatched read.
def _trusted_hook_argv():
    return guard_rules._trusted_hook_argv(__file__, "read guard")


def __getattr__(name):
    """`_HOOK_ARGV` / `_HOOK_CMD` / `_HOOK_ENTRY`, computed on ACCESS (#2006).

    These were module constants, so `_trusted_hook_argv()` ran while the module
    body executed and its RuntimeError escaped as an IMPORT-time raise --
    outside `main()`'s `except Exception`, this module's only never-crash
    envelope, and in the hook process a crash is fail-OPEN (any non-2 exit is a
    non-blocking error, so the Read proceeds). Reproduced:
    `python3 -c "import sys; sys.executable=''; import read_guard_hook"`.

    PEP 562 keeps every existing consumer's spelling (`rg._HOOK_CMD`) while
    moving the evaluation to the point of use. Every one of those uses is on
    the DRIVER side -- `install`, the readiness probe, the tests -- where a
    raise is a loud refusal to arm, which is the fail-closed direction. The
    hook process reaches the same check through `main()`, where it denies.
    Deliberately uncached: `_hook_entry` re-derives the argv per call for the
    same reason, and three path calls are not worth a stale answer.
    """
    if name == "_HOOK_ARGV":
        return _trusted_hook_argv()
    if name == "_HOOK_CMD":
        return guard_rules.hook_command(*_trusted_hook_argv())
    if name == "_HOOK_ENTRY":
        return {"matcher": _MATCHER,
                "hooks": [{"type": "command",
                           "command": guard_rules.hook_command(*_trusted_hook_argv())}]}
    raise AttributeError("module %r has no attribute %r" % (__name__, name))

DEFAULT_SETTINGS_PATH = ".claude/settings.local.json"
DEFAULT_SCOPE_PATH = ".panopticon/read-scope.json"


def _hook_entry(scope_path=None):
    """The PreToolUse entry to register; `scope_path` bakes the absolute scope
    file into the command, so the hook never infers it from CWD."""
    argv = list(_trusted_hook_argv())
    if scope_path:
        argv.append(os.path.abspath(scope_path))
    cmd = guard_rules.hook_command(*argv)
    return {"matcher": _MATCHER, "hooks": [{"type": "command", "command": cmd}]}


def _is_our_entry(entry):
    """True for any PreToolUse entry that runs THIS module (never the write
    guard's -- the two coexist in one settings file, each keyed on its own
    script path)."""
    return guard_rules._is_our_entry(entry, __file__)


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
    planted entry) -- INCLUDING an entry whose scope is empty: a dispatched id
    with an empty scope (e.g. a verify-tool-<fingerprint> advisor for a
    redacted/absent finding location) must overwrite any planted row for that
    id too, since decide() denies everything for an empty scope and that IS
    what "confines to nothing" (R-P5-2) intends. Returns the {id: scope} map
    this call added (now including empty ones). Refuses only when
    `scope_from_plan(plan)` is itself empty -- no entry in `plan` carried a
    `scope` dict at all (e.g. a driver-plan checkpoint) -- since arming zero
    ids is a caller mistake, not a plan that legitimately confines some ids
    to nothing."""
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
    _trusted_hook_argv()  # refuse before writing either private artifact
    merged = dict(_read_scope_file(scope_path))
    merged.update(added)
    guard_rules.atomic_write_json(scope_path, merged)
    guard_rules._write_hook_entry(settings_path, __file__, _hook_entry(scope_path))
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
    if not guard_rules._armed(settings_path, __file__):
        return False, 0
    return True, len(_read_scope_file(scope_path))


def uninstall(settings_path=None, scope_path=None, *, plan=None, session_root=None):
    """With `plan`, drop only that fan-out's entry ids and keep the guard armed
    while any other fan-out's remain (#11); without it, tear the guard down."""
    settings_path, scope_path, _ = _resolve(settings_path, scope_path, session_root)
    if plan is not None:
        remaining = _read_scope_file(scope_path)
        for eid in scope_from_plan(plan):
            remaining.pop(eid, None)
        if remaining:
            guard_rules.atomic_write_json(scope_path, remaining)
            return
    guard_rules._remove_hook_entry(settings_path, __file__)
    try:
        os.remove(scope_path)
    except OSError:
        pass


def _resolve_scope_path(argv_path=None):
    """Env override, then the absolute path install() baked into the hook command
    (returned even when absent: fail-closed), then a CWD walk -- the order and
    reasons of write_guard_hook._resolve_allowlist_path."""
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
    """`argv`: the argument list AFTER the program name; [] = a bare invocation, no baked-in scope."""
    args = sys.argv[1:] if argv is None else argv
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        return 0  # tolerant: a malformed hook payload never blocks legitimate work
    except (RecursionError, MemoryError) as exc:     # #3186: a crash here would fail OPEN
        print(_deny_response("read guard: payload too deep to adjudicate (%s)" % type(exc).__name__))
        return 0
    if not isinstance(payload, dict):
        return 0
    try:
        # #2006: the interpreter check, INSIDE the envelope -- it used to run at import, where its
        # RuntimeError crashed the hook, and a crashed hook is a permitted read; here it becomes the
        # deny below. #2394: the roster test sits inside too, so a bad tool_name denies, never crashes.
        if payload.get("tool_name", "") not in _READ_TOOLS:
            return 0
        if guard_rules is None:            # #3273 cut 11: before the argv check, which needs it
            allow, reason = adjudicate(payload, None)
        else:
            _trusted_hook_argv()
            allow, reason = adjudicate(payload, _resolve_scope_path(args[0] if args else None))
    except Exception as exc:  # noqa: BLE001 -- fail CLOSED, never crash the hook
        # A non-2 exit is NON-blocking in Claude Code (the tool proceeds), so an uncaught
        # exception here would fail OPEN despite every tolerant early return above.
        print(_deny_response("read guard crashed: %s" % exc))
        return 0
    if allow:
        return 0
    print(_deny_response(reason))
    return 0


if __name__ == "__main__":
    sys.exit(main())
