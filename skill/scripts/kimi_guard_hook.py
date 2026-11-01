#!/usr/bin/env python3
"""Kimi PreToolUse guard hook: read-scope and write-allowlist adjudication for
headless panopticon reviewers (#1344, FAMILY-PR-GUARDRAILS).

THE SHAPE OF THE THING. Kimi Code registers hooks only in
``$KIMI_CODE_HOME/config.toml`` (``[[hooks]]`` tables; there is no
``--settings`` flag and no project-level hooks file), so the headless runner
(runners/kimi.py) builds a PER-RUN Kimi home whose config names this script
twice::

    [[hooks]] matcher = "Read|ReadMediaFile|Grep|Glob"
                            -> <the driver's python> -I <this file> read  <scope path>
    [[hooks]] matcher = "Write|Edit"
                            -> <the driver's python> -I <this file> write <allowlist path>

The scope and allowlist DATA files are the ones the loop already arms through
read_guard_hook.install / write_guard_hook.install (orchestrate.Guards):
``read-scope.json`` is ``{entry id: {"files": [...], "dirs": [...],
"reads": [...]}}`` -- a `hard_linked` key an older version wrote is ignored
(#3271: out-of-tree hard links are a first-contact halt) -- and
``write-allowlist.json`` is the v2
document
``{"version": 2, "entries": {entry id: [path, ...]}, "paths": [...]}`` (#1571;
version 1 was a flat list and is refused, not read). Kimi runs hooks as
``<interpreter> -I <abs path> <mode> <abs data path>`` -- one SHELL STRING,
shell-quoted by `guard_rules.hook_command` (#1633) -- with no package on
sys.path, so the loaders and rules this hook shares with the Claude guards are
loaded BY PATH from `guard_rules.py` beside it (#3273 cut 11; the loader
stanza below). That interpreter is the DRIVER's own `sys.executable`, resolved
(`runners/kimi_home._interpreter`, ARC-1774133676), never a bare name the
child's own PATH would resolve. ``-I`` keeps PYTHONPATH, the user site and the
script's directory off sys.path (#1996/#2163), though not that interpreter's
own site-packages or a `sitecustomize` installed there.

BINDING. A headless child IS one dispatch entry (spec 5.3), so the entry id
arrives in the environment as PANOPTICON_ENTRY_ID (orchestrate.Guards.env_for),
never through a transcript. The per-run Kimi home runs nothing but panopticon
children, so an UNBOUND payload (no env id) is not "the orchestrator" the way
Claude's session-wide guard reads it -- it is a session nothing confined, and
reads/writes DENY.

KIMI PAYLOAD. Kimi's PreToolUse payload names the tool in ``tool_name`` and
carries ``tool_input`` whose path field is ``path`` for Read, Write, Edit,
Grep and Glob alike (measured on kimi-code 0.42.0 -- NOT Claude's
``file_path``). Glob's SECOND argument is ASSUMED to arrive as ``pattern``
(#1917, adjudicated by ``_glob_refusal``, whose #2063 symlink refusals assume the same key):
UNMEASURED on kimi-code, so
the next real launch should check it -- under another name every Glob over a
directory grant is denied as ``pattern None``, fail-closed but a functional
break of the setup scan, and puzzling from the denial alone. The deny protocol
is the shared JSON one: print
``hookSpecificOutput.permissionDecision = "deny"`` on stdout and exit 0.

FAIL-CLOSED, AND THE PLATFORM CAVEAT. Kimi hooks fail OPEN on script error or
timeout ("other non-zero values default to allow"), so this script must never
raise and never exit non-zero: every internal failure path prints a deny and
returns 0. The one deliberate exception is a payload that is not a JSON object
-- the CLI's own shape, not the model's, where denying would block every
legitimate call on a platform change; a bad ARGV, which is the config's doing,
denies. The one failure it cannot catch is its own interpreter failing to
start; that residual is documented in the runner and is why the shells' tool
allowlists remain the primary control and this hook is the confinement layer
on top.
"""
import json
import os
import sys


# ReadMediaFile is a READ tool and belongs here (I1): a read tool the guard
# does not adjudicate returns (True, "") and reads any file on the machine from
# an entry whose Read is confined. runners/kimi_home.py's READ_MATCHER names
# it so the hook is actually invoked for it.
_READ_TOOLS = frozenset({"Read", "ReadMediaFile", "Grep", "Glob"})
_WRITE_TOOLS = frozenset({"Write", "Edit"})

ENV_READ_SCOPE = "PANOPTICON_READ_SCOPE"
ENV_WRITE_ALLOWLIST = "PANOPTICON_WRITE_ALLOWLIST"

# Every name this hook reads from guard_rules; the loader refuses a module that
# lacks one, so a renamed rule denies at load rather than crashing mid-call.
_GUARD_RULES_USED = (
    "ENV_ENTRY_ID", "UNBOUND_ENTRY", "SCOPE_KEYS", "GLOB_PATTERN_DENIAL", "GIT_STORE_DENIAL",
    "ARTIFACT_DIR", "SYMLINKED_COMPONENT", "UNMEASURABLE_COMPONENT", "ESCAPED_ARTIFACT_TREE",
    "PARENT_COMPONENT", "_resolve_path", "_readable", "_in_dir_grant", "_glob_pattern_climbs",
    "_names_git_store", "_load_scope", "_load_allowlist", "_escaped_component", "_glob_refusal")

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
    ENV_ENTRY_ID = guard_rules.ENV_ENTRY_ID
    UNBOUND_ENTRY = guard_rules.UNBOUND_ENTRY
    SCOPE_KEYS = guard_rules.SCOPE_KEYS
    GLOB_PATTERN_DENIAL = guard_rules.GLOB_PATTERN_DENIAL
    GIT_STORE_DENIAL = guard_rules.GIT_STORE_DENIAL
    ARTIFACT_DIR = guard_rules.ARTIFACT_DIR
    SYMLINKED_COMPONENT = guard_rules.SYMLINKED_COMPONENT
    UNMEASURABLE_COMPONENT = guard_rules.UNMEASURABLE_COMPONENT
    ESCAPED_ARTIFACT_TREE = guard_rules.ESCAPED_ARTIFACT_TREE
    PARENT_COMPONENT = guard_rules.PARENT_COMPONENT


def _deny(reason):
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }))


def _decide_read(tool_name, tool_input, scope, cwd):
    """(allow, reason) for a bound entry's Read/Grep/Glob. Mirrors
    read_guard_hook.decide's rules with Kimi's `path` field."""
    if not isinstance(tool_input, dict):
        return False, "%s is denied: malformed tool input" % tool_name
    raw = tool_input.get("path")
    if raw is None and tool_name in ("Grep", "Glob"):
        # A pathless Grep/Glob defaults to the working directory; adjudicate
        # THAT directory rather than guessing (R-P5-7).
        raw = cwd
    target = guard_rules._resolve_path(raw)
    if target is None:
        return False, ("%s is denied: pass `path` explicitly -- a file from the "
                       "list in your prompt" % tool_name)
    if os.path.isdir(target):
        if any(guard_rules._in_dir_grant(target, d) for d in scope["dirs"]):
            # #1917: for Glob, the second argument -- the only one of these
            # tools whose pattern is a PATH pattern, expanded against `path`.
            # #2063: and through no symlink out of the grant (guard_rules._glob_refusal).
            refusal = (guard_rules._glob_refusal(target, tool_input.get("pattern"), scope)
                       if tool_name == "Glob" else None)
            return (False, refusal) if refusal else (True, "")
        if tool_name in ("Read", "ReadMediaFile"):
            return False, ("%s of directory %s is outside your cell's scope; the "
                           "files you may read are listed in your prompt"
                           % (tool_name, raw))
        if tool_name == "Grep":
            return False, ("Grep over a directory is denied in a confined cell: grep "
                           "a file by its path; your cell's files are listed in your prompt")
        return False, ("Glob is not available in a confined cell: your file list is "
                       "in your prompt")
    if tool_name in ("Read", "ReadMediaFile"):
        if guard_rules._readable(target, scope):
            return True, ""
        return False, ("%s of %s is outside your cell's scope; the files you may "
                       "read are listed in your prompt" % (tool_name, raw))
    if tool_name == "Grep":
        if guard_rules._readable(target, scope):
            return True, ""
        return False, ("Grep of %s is outside your cell's scope; the files you may "
                       "search are listed in your prompt" % raw)
    return False, ("Glob is not available in a confined cell: your file list is in "
                   "your prompt")


def _decide_write(tool_name, tool_input, allowlist, entry_id):
    """(allow, reason) for Write/Edit against THIS entry's grants.

    #1571 (run-13 AGT-2297383423): this used to take the flat union of every
    in-flight out_file and ask only whether the target was in it. The id was
    already here -- `adjudicate` requires it, and the READ branch selects an
    entry's scope with it -- so a writer-capable reviewer could overwrite any
    peer's findings artifact, while the denial below promised the opposite.
    Unknown id denies by name, exactly as the read branch does."""
    # Refused by NAME, before the lookup, exactly as write_guard_hook does:
    # the driver's id grammar makes this unreachable today, and a guard whose
    # refusal rests on that is one grammar change from being a hole. Two write
    # guards, one failure mode.
    granted = None if entry_id == guard_rules.UNBOUND_ENTRY else allowlist.get(entry_id)
    if granted is None:
        # `adjudicate` appends the bound entry to every denial, so name the
        # condition here and let it name the id -- saying it twice was how the
        # first draft of this read.
        return False, ("%s is denied: the armed write allowlist names no grant "
                       "for this entry" % tool_name)
    if not isinstance(tool_input, dict):
        return False, "%s is denied: malformed tool input" % tool_name
    raw = tool_input.get("path")
    if not isinstance(raw, str) or not raw:
        return False, "%s is denied: unresolvable path %r" % (tool_name, raw)
    try:
        absolute = os.path.abspath(raw)
        if os.path.islink(absolute):
            return False, ("%s to %s is denied: findings targets must not be "
                           "symlinks" % (tool_name, raw))
        # `raw`, not `absolute`: `abspath` has already collapsed any `..`, and
        # that collapse is part of what the walk refuses (#1640 fix round 1).
        fault = guard_rules._escaped_component(raw)               # #1640
        if fault:
            return False, "%s to %s is denied: %s" % (tool_name, raw, fault)
        target = os.path.realpath(absolute)
    except (ValueError, OSError, TypeError):
        return False, "%s is denied: unresolvable path %r" % (tool_name, raw)
    if target in set(granted):
        return True, ""
    if any(target in paths for paths in allowlist.values()):
        return False, ("%s to %s is denied: this reviewer may write only its own "
                       "declared out_file; a peer entry's artifact is not writable"
                       % (tool_name, raw))
    # In nobody's grant, so not a peer's artifact either: claim only what is
    # true, and point at the likelier cause (a guard armed over another run's
    # grants). `adjudicate` names the bound entry on the way out.
    return False, ("%s to %s is denied: it is not in this entry's grant -- a "
                   "reviewer may write only its own declared out_file, and an "
                   "armed allowlist that does not name it may be stale or from "
                   "another run" % (tool_name, raw))


def adjudicate(payload, mode, data_path, env=None):
    """(allow, reason) for one hook payload. `env` defaults to os.environ;
    probes and tests pass their own.

    With the shared rules unloaded, every call denies, before anything else is
    asked: the loader stanza's contract (#3273 cut 11)."""
    if guard_rules is None:
        return False, "kimi guard: %s" % _GUARD_RULES_FAULT
    if not isinstance(payload, dict):
        # Deliberately ALLOW, mirroring read_guard_hook/write_guard_hook: this
        # is the host's payload, and a hook that denied on an unrecognised
        # payload shape would block every tool call the moment the CLI's JSON
        # moved. The argv paths in `main` are the opposite case and deny (I6).
        return True, ""
    tool_name = payload.get("tool_name", "")
    guarded = _READ_TOOLS if mode == "read" else _WRITE_TOOLS
    if tool_name not in guarded:
        return True, ""
    env = os.environ if env is None else env
    entry_id = env.get(guard_rules.ENV_ENTRY_ID)
    if not entry_id or not isinstance(entry_id, str):
        return False, ("%s is denied: this session is not bound to a panopticon "
                       "entry (no %s in the environment), and the per-run guard "
                       "confines everything it cannot bind"
                       % (tool_name, guard_rules.ENV_ENTRY_ID))
    if mode == "read":
        scopes, error = guard_rules._load_scope(data_path)
        if scopes is None:
            return False, error
        scope = scopes.get(entry_id)
        if scope is None:
            return False, ("%s is denied: this agent is bound to entry %r, which "
                           "the armed read scope does not name" % (tool_name, entry_id))
        allow, reason = _decide_read(tool_name, payload.get("tool_input"), scope,
                                     payload.get("cwd") or os.getcwd())
    else:
        allowlist, error = guard_rules._load_allowlist(data_path)
        if allowlist is None:
            return False, error
        allow, reason = _decide_write(tool_name, payload.get("tool_input"),
                                      allowlist, entry_id)
    if not allow and reason:
        reason = "%s (bound to entry %r)" % (reason, entry_id)
    return allow, reason


def _data_path(argv_path, env_var, env):
    """The argv path the config baked in wins; the env overlay is the fallback
    a hand-run child can set. Returned even when absent: fail-closed."""
    if argv_path:
        return argv_path
    return env.get(env_var) or ""


def main(argv=None, env=None):
    """`argv` is [mode, data_path]; `env` defaults to os.environ. Always
    returns 0: a non-zero exit is NON-blocking on Kimi (fail-open), so every
    refusal travels as a printed deny."""
    args = sys.argv[1:] if argv is None else argv
    env = os.environ if env is None else env
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        return 0  # tolerant: a malformed hook payload never blocks legitimate work
    except (RecursionError, MemoryError) as exc:     # #3186: a crash here would fail OPEN
        _deny("kimi guard: payload too deep to adjudicate (%s)" % type(exc).__name__)
        return 0
    if not isinstance(payload, dict):
        # Same call as `adjudicate`'s, and as Claude's hook makes: the PAYLOAD
        # is the CLI's, not the model's, so a shape this version does not
        # recognise is a platform change and denying on it would refuse every
        # legitimate tool call. argv below is a different thing entirely.
        return 0
    if len(args) < 2 or args[0] not in ("read", "write"):
        # I6: argv is the CONFIG's, written by runners/kimi.py -- a hook the
        # config invoked wrongly (a mis-generated config, an edit to
        # `_hook_entry`) is precisely the case that must fail CLOSED. This
        # used to return 0 in silence, i.e. allow everything, which is the one
        # outcome a guard may never produce by accident.
        _deny("kimi guard: bad hook invocation %r -- expected [read|write, "
              "<data path>]; refusing the tool call rather than allowing it "
              "unguarded" % (list(args),))
        return 0
    mode = args[0]
    data_path = _data_path(args[1], ENV_READ_SCOPE if mode == "read" else ENV_WRITE_ALLOWLIST, env)
    try:
        allow, reason = adjudicate(payload, mode, data_path, env=env)
    except Exception as exc:  # noqa: BLE001 -- fail CLOSED, never crash the hook
        _deny("kimi %s guard crashed: %s" % (mode, exc))
        return 0
    if not allow:
        _deny(reason)
    return 0


if __name__ == "__main__":
    sys.exit(main())
