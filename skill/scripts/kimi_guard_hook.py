#!/usr/bin/env python3
"""Kimi PreToolUse guard hook: read-scope and write-allowlist adjudication for
headless panopticon reviewers (#1344, FAMILY-PR-GUARDRAILS).

THE SHAPE OF THE THING. Kimi Code registers hooks only in
``$KIMI_CODE_HOME/config.toml`` (``[[hooks]]`` tables; there is no
``--settings`` flag and no project-level hooks file), so the headless runner
(runners/kimi.py) builds a PER-RUN Kimi home whose config names this script
twice::

    [[hooks]] matcher = "Read|ReadMediaFile|Grep|Glob"
                                          -> python3 <this file> read  <scope path>
    [[hooks]] matcher = "Write|Edit"      -> python3 <this file> write <allowlist path>

The scope and allowlist DATA files are the ones the loop already arms through
read_guard_hook.install / write_guard_hook.install (orchestrate.Guards):
``read-scope.json`` is ``{entry id: {"files": [...], "dirs": [...],
"reads": [...]}}`` and ``write-allowlist.json`` is the v2 document
``{"version": 2, "entries": {entry id: [path, ...]}, "paths": [...]}`` (#1571;
version 1 was a flat list and is refused, not read). This
script re-implements the small loaders rather than importing those modules:
Kimi runs hooks as ``python3 <abs path> <mode> <abs data path>`` -- one SHELL
STRING, which is why the command is built here, shell-quoted, by
`hook_command` (#1633) -- with no package on sys.path, the same constraint that
keeps the Claude hooks stdlib-only and self-locating (R-P5-5).

BINDING. A headless child IS one dispatch entry (spec 5.3), so the entry id
arrives in the environment as PANOPTICON_ENTRY_ID (orchestrate.Guards.env_for),
never through a transcript. The per-run Kimi home runs nothing but panopticon
children, so an UNBOUND payload (no env id) is not "the orchestrator" the way
Claude's session-wide guard reads it -- it is a session nothing confined, and
reads/writes DENY.

KIMI PAYLOAD. Kimi's PreToolUse payload names the tool in ``tool_name`` and
carries ``tool_input`` whose path field is ``path`` for Read, Write, Edit,
Grep and Glob alike (measured on kimi-code 0.42.0 -- NOT Claude's
``file_path``). The deny protocol is the shared JSON one: print
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
import shlex
import stat
import sys


def hook_command(*argv):
    """One `[[hooks]] command` string, every element shell-quoted (#1633,
    SEC-A1A).

    Kimi runs a registered hook command through `sh -c`, so every element
    interpolated into it is SHELL SOURCE, not an argument: the `"%s"` this
    replaces stopped a space and nothing else, leaving a `"`, a backtick or a
    `$(...)` in this run's scope/allowlist path (or in the checkout this script
    sits in) to execute on every tool call. It lives beside the hook's OWN argv
    contract rather than in runners/kimi.py, because the two halves -- what the
    config writes and what `main` parses back -- are one protocol; the runner
    calls it.
    """
    return " ".join(shlex.quote(a) for a in argv)


# ReadMediaFile is a READ tool and belongs here (I1): a read tool the guard
# does not adjudicate returns (True, "") and reads any file on the machine from
# an entry whose Read is confined. runners/kimi_home.py's READ_MATCHER names
# it so the hook is actually invoked for it.
_READ_TOOLS = frozenset({"Read", "ReadMediaFile", "Grep", "Glob"})
_WRITE_TOOLS = frozenset({"Write", "Edit"})

ENV_ENTRY_ID = "PANOPTICON_ENTRY_ID"
# #1571: the write allowlist's format version. Checked, never sniffed -- a
# stale v1 flat list records no per-entry grants, so honouring one would
# restore the batch-wide write authority this version exists to end.
ALLOWLIST_VERSION = 2
# The bucket write_guard_hook.install puts a plan entry that declared no `id`
# into. Those grants belong to the unbound orchestrator; no bound child may
# select the key. Spelled here rather than imported for the reason everything
# in this module is (a hook runs standing alone, with no package on sys.path),
# and pinned equal to the write guard's in tests/test_write_guard_hook.py.
UNBOUND_ENTRY = "<unbound>"
ENV_READ_SCOPE = "PANOPTICON_READ_SCOPE"
ENV_WRITE_ALLOWLIST = "PANOPTICON_WRITE_ALLOWLIST"


def _deny(reason):
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }))


def _resolve_path(raw):
    """realpath of a payload path, or None when it cannot be resolved -- a
    non-string, empty or NUL-bearing path is malformed and fails closed."""
    if not isinstance(raw, str) or not raw:
        return None
    try:
        return os.path.realpath(os.path.abspath(raw))
    except (ValueError, OSError, TypeError):
        return None


def _under(path, directory):
    """Separator-bounded prefix test: /repo admits /repo/x, never /repo-other."""
    directory = directory.rstrip(os.sep) or os.sep
    return path == directory or path.startswith(directory + os.sep)


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
        # `hard_linked` (#1683) is the driver's one walk of a directory grant,
        # written by phases/setup; absent from an older file, which loads as
        # an empty list. The file's FORMAT is unchanged -- a new optional key
        # in a schema-less object -- so there is no version to bump: the
        # `read-scope.json` contract has no version field, and the one that
        # does (the v2 write allowlist) is not this file.
        for key in ("files", "dirs", "reads", "hard_linked"):
            val = scope.get(key)
            if val is None:
                entry[key] = []
                continue
            if not isinstance(val, list):
                return None, "read guard scope is malformed"
            entry[key] = [p for p in val if isinstance(p, str)]
        out[eid] = entry
    return out, ""


def _load_allowlist(allowlist_path):
    """(mapping, error): the armed {entry id: [path]} grants, or (None, why).

    Mirrors write_guard_hook._parse_allowlist -- a copy for the same reason
    the rest of this module is one (the hook runs standing alone, with no
    package on sys.path). The version is part of the contract: a v1 flat list
    is refused by NAME rather than read as a set of paths nobody owns."""
    try:
        with open(allowlist_path, encoding="utf-8") as fh:
            loaded = json.load(fh)
    except (OSError, ValueError) as exc:
        return None, "write guard allowlist is unavailable: %s" % exc
    if isinstance(loaded, list):
        return None, ("write guard allowlist is a version-1 flat list, not version "
                      "%d: it records no per-entry grants, so the guard cannot tell "
                      "whose out_file a path is and denies every write until the "
                      "loop re-arms it" % ALLOWLIST_VERSION)
    if not isinstance(loaded, dict):
        return None, "write guard allowlist is malformed"
    if loaded.get("version") != ALLOWLIST_VERSION:
        return None, ("write guard allowlist is version %r, not version %d "
                      "(per-entry grants); re-arm the guard"
                      % (loaded.get("version"), ALLOWLIST_VERSION))
    entries = loaded.get("entries")
    if not isinstance(entries, dict):
        return None, "write guard allowlist is malformed"
    out = {}
    for eid, paths in entries.items():
        if not isinstance(eid, str) or not isinstance(paths, list):
            return None, "write guard allowlist is malformed"
        out[eid] = [p for p in paths if isinstance(p, str)]
    return out, ""


# --- BINDING: a VERBATIM COPY of write_guard_hook's nested-component walk,
# pinned AST-identical by
# tests/test_write_guard_hook.py::TestBindingHelpersAreACopy. This module's
# write branch IS that module's rules with Kimi's `path` field, so the two
# have to refuse the same paths; copied and not imported for the reason
# everything here is one (the hook runs standing alone, with no package on
# sys.path).
#
# #1640 (run-13 AGT-861284148). The `.panopticon` segment is found LEXICALLY,
# so every directory between the review root and the findings file is a
# component whose NAME the guard trusted and whose target it never looked at.
# The old rule refused only a symlinked LEAF, and a real findings path is
# `<root>/.panopticon/runs/<tag>/findings-<group>-<domain>.json` -- so a
# target repo that commits `.panopticon/runs` as a link had the Claude guard's
# `allowlist_from_plan` store the EXTERNAL realpath as a grant and this branch
# resolve the reviewer's Write to that same external path. Install and
# enforcement AGREED on a destination outside the artifact tree.
ARTIFACT_DIR = ".panopticon"
SYMLINKED_COMPONENT = "findings output cannot pass through a symlinked directory: %s"
UNMEASURABLE_COMPONENT = ("findings output cannot pass through a directory the guard "
                          "could not measure: %s (%s)")
ESCAPED_ARTIFACT_TREE = ("findings output resolves outside the review artifact tree: "
                         "%s is not a %s path under %s")
# Refused on the DECLARED path, before anything normalises it. `abspath`
# collapses `..` lexically, so `<root>/.panopticon/runs/r1/../../../src/x.json`
# arrives at `_components` as `<root>/src/x.json` -- no `.panopticon` segment,
# therefore no walk and no anchor, therefore a grant on a source file. Today
# that path cannot be built (`groups_schema._invalid_name` rejects `..` in a
# group name and out_files are `findings-<group>-<domain>.json`), and a guard
# whose correctness rests on an upstream regex is one edit from being a hole.
# The rule is the COMPONENT, not where it lands: a `..` that stays inside the
# tree is refused too, because a declared findings path has no business
# carrying one and deciding from the destination would have to be re-decided
# at every enforcement. It names the offending out_file like its three
# siblings name theirs: `allowlist_from_plan` re-raises these with no context
# of its own, so a fan-out aborting on one bad path out of two hundred would
# otherwise say only that a `..` exists somewhere in it.
PARENT_COMPONENT = "findings output cannot contain '..': %s"


def _components(path):
    """(review root, [directory component, ...]) for a path anchored in a
    `.panopticon` tree: every directory from the `.panopticon` segment's
    PARENT -- the review root -- down to the file's own parent, outermost
    first.

    (None, []) when the path carries no `.panopticon` segment. There is no
    artifact tree to anchor on then, so there is nothing for this rule to say;
    `_confined_to_artifact_roots` already refuses to carry such a grant
    forward, and the probes' sandbox plans legitimately declare out_files that
    live nowhere near an artifact tree.

    The review root itself is the outermost component checked, and nothing
    ABOVE it is: `os.path.islink` tests only a path's final component, so a
    checkout reached through a symlinked ancestor (a macOS `/tmp`, a home
    directory on another volume) is not the subject -- a review root whose own
    name is a link is.
    """
    parts = os.path.abspath(path).split(os.sep)
    if ARTIFACT_DIR not in parts:
        return None, []
    start = parts.index(ARTIFACT_DIR)
    return (os.sep.join(parts[:start]) or os.sep,
            [os.sep.join(parts[:i + 1]) or os.sep for i in range(start - 1, len(parts) - 1)])


def _component_fault(component):
    """Why this directory component may not be traversed, or "".

    A component with NO INODE passes: the plan is written before the run
    folder is created, and refusing an absent component would refuse every
    first run. A component that exists but cannot be measured DENIES -- the
    same rule `_hard_link_reason` applies one layer down (#1642, fix round 1):
    a guard may not answer "allowed" about something it could not look at.
    """
    try:
        info = os.lstat(component)
    except (FileNotFoundError, NotADirectoryError):
        return ""
    except (OSError, ValueError) as exc:
        return UNMEASURABLE_COMPONENT % (component, exc)
    if stat.S_ISLNK(info.st_mode):
        return SYMLINKED_COMPONENT % component
    return ""


def _escaped_component(path):
    """Why `path` may not be trusted as a findings destination, or "".

    Two rules, and the second is not redundant. The walk is a check at a
    moment in time; the ANCHOR is what the destination must satisfy whatever
    the components looked like -- a link swapped in after the walk, a bind
    mount, a leaf that is itself a link into another tree. So the resolved
    path must still carry a `.panopticon` segment and still lie under the
    resolved review root the declared path named.
    """
    if os.pardir in str(path).split(os.sep):
        return PARENT_COMPONENT % (path,)
    root, components = _components(path)
    if root is None:
        return ""
    for component in components:
        fault = _component_fault(component)
        if fault:
            return fault
    real = os.path.realpath(path)
    real_root = os.path.realpath(root)
    if ARTIFACT_DIR not in real.split(os.sep) or not (
            real == real_root or real.startswith(real_root + os.sep)):
        return ESCAPED_ARTIFACT_TREE % (real, ARTIFACT_DIR, real_root)
    return ""


# --- end of the write_guard_hook copy ---


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
    DENIES (fix round 1, F4): a guard may not answer "allowed" about something
    it could not measure. A path with NO INODE (ENOENT/ENOTDIR, a dangling
    symlink included) is the exception and passes through (fix round 2, N2):
    that is a successful measurement of nothing to confine, not a failure to
    measure, and the tool's own not-found is what the caller should see.

    THE OTHER HALF (#1683). This rule reaches reads whose argument is a FILE.
    A `Grep`/`Glob` argued with a granted DIRECTORY is adjudicated by path and
    then traversed by the host's own tool; `_decide_read` refuses those from
    `scope["hard_linked"]` -- the walk the driver takes once when the grant is
    built, because a hook may not walk the tree on every call.

    Unlike the Codex broker, which reads the count off the descriptor it then
    reads FROM, a PreToolUse hook adjudicates a NAME the host reopens: as
    path-based as the realpath check beside it, and carrying the same race.
    """
    if target in scope["files"] or target in scope["reads"]:
        return ""
    try:
        info = os.stat(target)
    except (FileNotFoundError, NotADirectoryError):
        # Fix round 2 (N2): ENOENT/ENOTDIR -- including a dangling symlink --
        # are not "could not measure". They are a successful measurement that
        # there is NO INODE at that name, so there is nothing for a read fence
        # to confine and nothing an attacker gains by inducing one. The tool's
        # own not-found is the honest answer; a denial here reads as a fence to
        # the scout probing an unknown tree for absent marker files.
        return ""
    except OSError as exc:
        # Fix round 1 (F4): a guard that cannot measure DENIES -- every other
        # errno (EACCES, ELOOP, ENAMETOOLONG, EIO). This used to answer "" --
        # allow -- reasoning that the host's own read of an unstattable name
        # fails the same way; that is a guess about another process's syscall,
        # made by the one component whose job is to be sure.
        return ("%s of %s is denied: the read guard could not stat it to apply "
                "the hard-link rule: %s" % (tool_name, raw, exc))
    if not stat.S_ISREG(info.st_mode) or info.st_nlink <= 1:
        return ""
    return "%s of %s is denied: %s" % (tool_name, raw, HARD_LINK_DENIAL % info.st_nlink)


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
    target = _resolve_path(raw)
    if target is None:
        return False, ("%s is denied: pass `path` explicitly -- a file from the "
                       "list in your prompt" % tool_name)
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
        if _readable(target, scope):
            denial = _hard_link_reason(tool_name, raw, target, scope)
            return (False, denial) if denial else (True, "")
        return False, ("%s of %s is outside your cell's scope; the files you may "
                       "read are listed in your prompt" % (tool_name, raw))
    if tool_name == "Grep":
        if _readable(target, scope):
            denial = _hard_link_reason(tool_name, raw, target, scope)
            return (False, denial) if denial else (True, "")
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
    granted = None if entry_id == UNBOUND_ENTRY else allowlist.get(entry_id)
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
        fault = _escaped_component(raw)           # #1640, and the walk is the copy above
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
    probes and tests pass their own."""
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
    entry_id = env.get(ENV_ENTRY_ID)
    if not entry_id or not isinstance(entry_id, str):
        return False, ("%s is denied: this session is not bound to a panopticon "
                       "entry (no %s in the environment), and the per-run guard "
                       "confines everything it cannot bind" % (tool_name, ENV_ENTRY_ID))
    if mode == "read":
        scopes, error = _load_scope(data_path)
        if scopes is None:
            return False, error
        scope = scopes.get(entry_id)
        if scope is None:
            return False, ("%s is denied: this agent is bound to entry %r, which "
                           "the armed read scope does not name" % (tool_name, entry_id))
        allow, reason = _decide_read(tool_name, payload.get("tool_input"), scope,
                                     payload.get("cwd") or os.getcwd())
    else:
        allowlist, error = _load_allowlist(data_path)
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
