"""PreToolUse write-guard hook: reviewers may write only the fan-out findings
files declared in the dispatch plan. Any other Write/Edit is denied. This is the
harness-enforced replacement for the read-only-reviewer convention (#436).

SCOPE, STATED PLAINLY (#680): this guard backstops the file-mutation TOOLS in
``_WRITE_TOOLS`` only. It does NOT — and structurally cannot — cover Bash. The
hook is registered session-wide, so it cannot distinguish the orchestrator's
own legitimate shell use (git, python, progress checks while the guard is
installed) from a reviewer subagent's; denying Bash wholesale would break the
pipeline that installs it. The real control against a shell-capable reviewer is
an ENFORCED shell (a registered ``panopticon-*`` agent whose tool policy omits
Bash).

THE CONTRACT, then, and where the rest of the tool surface is closed
(#1753, AGT-1426146063): this hook adjudicates the write tools it names and
allows every other tool name outright, BY DESIGN — a reviewer's ``Bash`` and
``Agent`` are kept away from it one layer earlier, on the launch, not here. An
enforced entry is launched into a registered shell whose ``tools:`` frontmatter
never grants either; an unenforced entry (every claude argv that binds no
``--agent`` shell) carries ``runners/claude.UNENFORCED_DENIED_TOOLS`` as an
explicit ``--disallowedTools=`` token, and deny beats the operator's own
user-scope allow rules. So "the write guard does not mediate Bash" is a statement about this
hook's job, not a hole: the hole would be a launch that grants Bash at all.

THIS HOOK IS CLAUDE-ONLY BY CONSTRUCTION, not by omission: it is registered in
``.claude/settings.local.json`` as a Claude Code PreToolUse hook, so it cannot
run for any other host. ``driver run`` therefore REFUSES to dispatch the
write-capable reviewer roles on a host that cannot mediate Write (currently
anything but ``claude``); ``--allow-unenforced`` accepts that residual risk
explicitly and records it in the run's ``unenforced-ack.json``, which
``synth.integrity`` reports as ``meta.integrity.unenforced_acknowledged``
(#1519). An earlier version of this refusal lived in ``dispatch.py`` and was
retired in run-10, and this docstring went on citing it after the fact -- a
compensating control named in a docstring but absent from the code is worse
than none, because it stops people looking. Full per-host write mediation is
tracked as #1344.

The matcher and ``_WRITE_TOOLS`` are derived from one source below so they can
never silently drift apart from each other.
"""
import glob
import json
import os
import re
import shlex
import stat
import sys

_WRITE_TOOLS_LIST = ["Write", "Edit", "NotebookEdit"]
_WRITE_TOOLS = set(_WRITE_TOOLS_LIST)
_MATCHER = "|".join(_WRITE_TOOLS_LIST)

# #1571. Version 1 was a flat JSON list of writable paths, with nothing in it
# saying whose grant each path was; version 2 is
# ``{"version": 2, "entries": {<entry id>: [path, ...]}, "paths": [...]}``.
# The version is CHECKED, not sniffed: a stale v1 file left in a run folder
# must deny rather than quietly restore the batch-wide grant.
ALLOWLIST_VERSION = 2
# The bucket for a plan entry that declares no `id` (the probes' sandbox plans
# and much of the suite). Its paths stay writable by the unbound orchestrator
# and are reachable by NO bound agent: the driver's entry ids match
# ``^[A-Za-z0-9._:-]+$``, so the brackets cannot collide with a real id, and
# `adjudicate` refuses this key explicitly rather than resting on that.
UNBOUND_ENTRY = "<unbound>"

# --- BINDING: a VERBATIM COPY of read_guard_hook's, pinned AST-identical by
# tests/test_write_guard_hook.py::TestBindingHelpersAreACopy. It is copied and
# not imported for the reason every other shared piece in these hooks is (the
# settings plumbing, R-P5-5; `hook_command`, #1633): a guard hook is invoked by
# absolute path as its own process with no package on sys.path, so there is no
# module for the two of them to share. Edit read_guard_hook's copy and this one
# together; the parity test fails loudly if you do not.
MARKER_PREFIX = "panopticon-entry: "
ENV_ENTRY_ID = "PANOPTICON_ENTRY_ID"


# --- BINDING: the nested-component walk below is a VERBATIM COPY of
# kimi_guard_hook's, pinned AST-identical by
# tests/test_write_guard_hook.py::TestBindingHelpersAreACopy. Kimi's write
# branch IS this module's rules with Kimi's `path` field, and a copy that
# drifts means one of the two guards quietly stops refusing a nested symlink.
# Copied and not imported for the reason the binding helpers above are.
#
# #1640 (run-13 AGT-861284148). The `.panopticon` segment is found LEXICALLY
# -- here and in `_is_run_folder` -- so every directory between the review
# root and the findings file is a component whose NAME the guard trusted and
# whose target it never looked at. The old rule refused a symlink only when
# the out_file's IMMEDIATE parent was named `.panopticon`; a real findings
# path is `<root>/.panopticon/runs/<tag>/findings-<group>-<domain>.json`,
# whose immediate parent is the run folder, so a target repo that commits
# `.panopticon/runs` as a link had `allowlist_from_plan` store the EXTERNAL
# realpath as a grant and `_resolve_target` resolve the reviewer's Write to
# that same external path. Install and enforcement AGREED on a destination
# outside the artifact tree, which is what makes it a hole rather than a
# mismatch -- so both of them walk, and both of them anchor.
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
    `_carried_paths_this_run_owns` already refuses to carry such a grant
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


# --- end of the kimi_guard_hook copy ---


def allowlist_from_plan(plan):
    """{entry id: [realpath, ...]} -- every out_file the plan declares, keyed
    by the entry that declared it.

    #1571: this used to return a FLAT SET of every out_file in the fan-out,
    which is the whole defect. `install` wrote that set as the one allowlist
    and `decide` asked only "is this path in it", so every in-flight reviewer
    was authorized against every OTHER cell's findings file -- a subverted
    reviewer could blank or forge a sibling domain's findings before the run
    consumed them. Keeping the paths attributed to their entry is what lets a
    bound agent be adjudicated against its own grant alone (`adjudicate`).

    `plan` is a SEQUENCE OF ENTRIES (``[{"out_file": ...}, ...]``), never the
    dispatch-request object that wraps them. #1482: handed the wrapper, this
    used to iterate the mapping's KEYS -- plain strings -- match no `out_file`,
    and return an empty set with no error. `install` then wrote that empty set
    over every live grant, and `uninstall(plan=...)` subtracted nothing and
    silently kept the guard armed. The two shapes are indistinguishable at a
    call site holding a parsed dispatch-request, so reject the wrapper here
    rather than let it degrade into an empty success.
    """
    if isinstance(plan, (dict, str, bytes)):
        raise TypeError(
            "plan must be a sequence of dispatch entries, not %s -- pass the "
            "dispatch request's `entries` list, not the request object itself"
            % type(plan).__name__)
    out: dict[str, set[str]] = {}
    for entry in plan:
        path = entry.get("out_file") if isinstance(entry, dict) else None
        if not isinstance(path, str) or not path:
            continue
        fault = _escaped_component(path)
        if fault:
            raise ValueError(fault)
        eid = entry.get("id")
        if not isinstance(eid, str) or not eid:
            eid = UNBOUND_ENTRY
        out.setdefault(eid, set()).add(os.path.realpath(path))
    return {eid: sorted(paths) for eid, paths in out.items()}


def union_paths(allowlist):
    """Every granted path in an entry mapping, flat -- the batch-wide set.

    What the ORCHESTRATOR is adjudicated against (it is bound to no entry and
    writes the run's own artifacts) and what `is_armed` counts. NOT what the
    carry-forward confinement anchors on: that needs each path's entry id, so it
    reads the mapping (`_run_folders`)."""
    out: set[str] = set()
    for paths in (allowlist or {}).values():
        out.update(p for p in paths if isinstance(p, str))
    return out


def allowlist_document(allowlist):
    """The v2 file `install` writes: the per-entry mapping plus its union.

    `paths` is redundant with `entries` by construction and kept deliberately:
    every reader that legitimately wants the batch-wide set (`is_armed`'s
    count, the probes, the orchestrator branch) gets it without re-deriving
    it, and a reader that opens the file by hand sees the same two answers the
    guard does."""
    return {"version": ALLOWLIST_VERSION,
            "entries": {eid: sorted(paths) for eid, paths in allowlist.items()},
            "paths": sorted(union_paths(allowlist))}


def _resolve_target(file_path):
    """(realpath, denial reason) -- exactly one of the two is None.

    Shared by `decide` (the batch-wide question) and `adjudicate`'s bound
    branch (the per-entry one) so the symlink and unresolvable-path refusals
    have one definition and cannot drift between them."""
    try:
        raw = os.path.abspath(file_path or "")
        if os.path.islink(raw):
            return None, (
                "write to %s is denied: findings targets must not be symlinks" % file_path)
        # The DECLARED string, not `raw`: `abspath` has already collapsed any
        # `..` by this point, and that collapse is the thing being refused.
        fault = _escaped_component(file_path or "")
        if fault:
            return None, "write to %s is denied: %s" % (file_path, fault)
        return os.path.realpath(raw), None
    except (ValueError, OSError, TypeError):
        # TypeError: a non-string file_path (int/list/dict) — os.path.* rejects
        # it. A write payload whose path isn't a string is malformed/suspicious;
        # fail closed (deny) rather than crash the hook (#768).
        return None, ("write to %r is denied: unresolvable path" % file_path)


def decide(tool_name, file_path, allowlist):
    """(allow, reason) against a flat SET of paths. Non-write tools always
    allowed; writes only to the set.

    Entry-agnostic by design, and after #1571 it answers only the BATCH-WIDE
    question -- "may anything in this fan-out write here?" -- which is the
    right question for the orchestrator and the wrong one for a reviewer.
    `adjudicate` is what binds a reviewer to its own entry.

    Handed the per-entry MAPPING it raises, rather than testing the path
    against that mapping's keys and denying in silence. `decide(tool, path,
    allowlist_from_plan(plan))` was the pre-#1571 call shape -- the exact
    expression this change had to rewrite at four call sites -- so the two
    argument shapes are indistinguishable at any site holding "the allowlist".
    That is the #1482 hazard again, where a wrong-shaped argument degraded
    into an empty success nobody noticed, and it gets the same loud refusal.
    """
    if tool_name not in _WRITE_TOOLS:
        return True, ""
    if isinstance(allowlist, dict):
        raise TypeError("decide takes the flat union; pass union_paths(allowlist)")
    target, reason = _resolve_target(file_path)
    if target is None:
        return False, reason
    if target in allowlist:
        return True, ""
    return False, ("write to %s is outside the fan-out allowlist; reviewers may "
                   "write only to plan-declared findings files" % file_path)


def _deny_response(reason):
    return json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    })


def marker_of(text):
    """The entry id `text`'s FIRST line names, or None. Only the first line:
    a marker anywhere else is content, not a binding."""
    if not isinstance(text, str):
        return None
    first = text.split("\n", 1)[0].rstrip("\r")
    if not first.startswith(MARKER_PREFIX):
        return None
    return first[len(MARKER_PREFIX):].strip() or None

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


# --- end of the read_guard_hook copy ---


def _parse_allowlist(loaded):
    """(mapping, error) for a parsed allowlist document. Version 2 only.

    #1571: a version-1 file is a flat list with no attribution, so honouring
    one would silently restore the batch-wide grant this format exists to
    end. A stale file must never widen a guard -- name the version and deny.
    """
    if isinstance(loaded, list):
        return None, ("write guard allowlist is a version-1 flat list, not version "
                      "%d: it records no per-entry grants, so the guard cannot tell "
                      "whose out_file a path is and denies every write until the "
                      "loop re-arms it" % ALLOWLIST_VERSION)
    if not isinstance(loaded, dict):
        return None, "write guard allowlist is malformed"
    version = loaded.get("version")
    if version != ALLOWLIST_VERSION:
        return None, ("write guard allowlist is version %r, not version %d "
                      "(per-entry grants); re-arm the guard"
                      % (version, ALLOWLIST_VERSION))
    entries = loaded.get("entries")
    if not isinstance(entries, dict):
        return None, "write guard allowlist is malformed"
    out = {}
    for eid, paths in entries.items():
        if not isinstance(eid, str) or not isinstance(paths, list):
            return None, "write guard allowlist is malformed"
        out[eid] = [p for p in paths if isinstance(p, str)]
    return out, ""


def _load_allowlist(allowlist_path):
    """(mapping, error): the armed {entry id: [path]} map, or (None, why)."""
    try:
        with open(allowlist_path, encoding="utf-8") as fh:
            loaded = json.load(fh)
    except (OSError, ValueError) as exc:
        return None, "write guard allowlist is unavailable: %s" % exc
    return _parse_allowlist(loaded)


def _payload_path(tool_name, tool_input):
    """The path THIS tool writes to.

    #run7 ARC-F2C: NotebookEdit keys its target as `notebook_path`, NOT
    `file_path`. Reading file_path uniformly checked NotebookEdit against the
    wrong (empty) path -- benign fail-closed for an ordinary notebook edit, but
    a decoy payload {file_path: <allowlisted>, notebook_path: <outside>} would be
    ALLOWED while the write lands outside the fence. Extract the tool's own key
    and do NOT fall back to file_path for NotebookEdit."""
    if not isinstance(tool_input, dict):
        return ""
    return tool_input.get(
        "notebook_path" if tool_name == "NotebookEdit" else "file_path", "")


def adjudicate(payload, allowlist_path, env=None):
    """(allow, reason) for one hook payload against the allowlist at
    `allowlist_path`. `env` defaults to os.environ; the probe and the tests
    pass their own.

    #1571. Binding order is the read guard's (spec 5.3), for the same reasons
    and with the same three outcomes:

      * the environment's ENV_ENTRY_ID first -- a headless `claude -p` child IS
        the reviewer (agent_type, no agent_id), so a transcript-only rule would
        fail OPEN for every headless entry;
      * else the subagent transcript's marker -- session mode, where the hook
        is registered session-wide and the payload names the AGENT, never the
        entry;
      * an agent that could not be bound DENIES. It is a reviewer whose cell we
        cannot name, and naming the cell is the whole control.

    A BOUND agent is adjudicated against `entries[<its id>]` alone: its own
    declared out_file, never the batch's union. Nothing bound (no id, no
    agent_id, no agent_type) is the ORCHESTRATOR -- it runs the driver and
    writes the run's own artifacts -- and keeps the union, exactly as the read
    guard never confines it.
    """
    if not isinstance(payload, dict):
        return True, ""
    tool_name = payload.get("tool_name", "")
    if tool_name not in _WRITE_TOOLS:
        return True, ""
    file_path = _payload_path(tool_name, payload.get("tool_input"))
    allowlist, error = _load_allowlist(allowlist_path)
    if allowlist is None:
        return False, error
    env = os.environ if env is None else env
    env_id = env.get(ENV_ENTRY_ID)
    agent_id = payload.get("agent_id")
    agent_type = payload.get("agent_type")
    if env_id or agent_id:
        # Shaped exactly like the read guard's: an id that is present but not
        # usable (a non-string) is an agent we could not bind, never the
        # orchestrator -- degrading it into the union is the fail-OPEN this
        # whole change is about.
        entry_id = (env_id if isinstance(env_id, str) else None) if env_id \
            else bind(agent_id, payload.get("transcript_path"))
        if entry_id is None:
            return False, (
                "%s to %s is denied: this reviewer is not bound to a dispatch "
                "entry (no usable %s, and its dispatch prompt did not begin "
                "with '%s<entry id>'), and a reviewer may write only its own "
                "declared out_file"
                % (tool_name, file_path, ENV_ENTRY_ID, MARKER_PREFIX))
    elif agent_type:
        return False, ("%s is denied: this session runs as agent_type %r but "
                       "nothing bound it to a panopticon entry (no %s in the "
                       "environment, no subagent transcript)"
                       % (tool_name, agent_type, ENV_ENTRY_ID))
    else:
        return decide(tool_name, file_path, union_paths(allowlist))
    # UNBOUND_ENTRY holds the grants of plan entries that declared no id. They
    # belong to the orchestrator; no bound agent may select that bucket, and
    # refusing it here does not rest on the id grammar making it unreachable.
    granted = None if entry_id == UNBOUND_ENTRY else allowlist.get(entry_id)
    if granted is None:
        return False, ("%s is denied: this agent is bound to entry %r, which the "
                       "armed write allowlist does not name"
                       % (tool_name, entry_id))
    target, reason = _resolve_target(file_path)
    if target is None:
        return False, "%s (bound to entry %r)" % (reason, entry_id)
    if target in set(granted):
        return True, ""
    if target in union_paths(allowlist):
        return False, ("write to %s is denied: entry %r may write only its own "
                       "declared out_file; a peer entry's artifact is not writable"
                       % (file_path, entry_id))
    # NOT a peer's artifact: the target is in nobody's grant. Saying "peer"
    # here would accuse the reviewer of the one thing it did not do, when the
    # likely cause is the guard armed on the wrong tree or over a previous
    # round's grants -- the #calibration-4 / gotify shape, where 44 advisors
    # lost finished work to an allowlist that was live but stale, and every
    # denial pointed away from it.
    return False, ("write to %s is denied: it is not in entry %r's grant -- a "
                   "reviewer may write only its own declared out_file, and an "
                   "armed allowlist that does not name this one may be stale or "
                   "from another run" % (file_path, entry_id))


def _resolve_allowlist_path(argv_path=None):
    """Where this hook invocation should read its allowlist from.

    Order: explicit env override, then the absolute path `install()` baked into
    the registered hook command, then the legacy walk up from CWD.

    #calibration-4 (gotify): the CWD walk alone is only correct when the hook
    process's CWD is the same tree the allowlist was installed into. That holds
    for a self-scan and fails for an EXTERNAL target: `install()` run from the
    target repo writes `<target>/.panopticon/write-allowlist.json`, while the
    hook runs with the CONTROLLER session's CWD and resolves
    `<session>/.panopticon/write-allowlist.json` -- a different file, left over
    from a previous round. Every verdict write was then denied against a stale
    findings-only allowlist, and 44 advisors that had finished adjudicating lost
    their work to a guard that was armed on the wrong tree. Same shape as #495
    (the hook could not locate its own script from a relative path) and #1454
    (--project-dir was the scanned target, not the session): a path that only
    resolves when session root and target happen to be one directory. So bind
    the allowlist into the command absolutely, exactly as #495 did the script.

    The env override stays first: group_runner sets it deliberately for a
    subprocess, and that is a narrower, more explicit signal than a path baked
    in at install time."""
    env_path = os.environ.get("PANOPTICON_WRITE_ALLOWLIST")
    if env_path and os.path.isfile(env_path):
        return env_path
    if argv_path:
        # Returned even when absent: the guard is fail-closed, and an install
        # that named a file which then vanished must DENY, never silently fall
        # back to some other tree's allowlist and allow the wrong writes.
        return argv_path
    cur = os.path.abspath(os.getcwd())
    while True:
        candidate = os.path.join(cur, ".panopticon", "write-allowlist.json")
        if os.path.isfile(candidate):
            return candidate
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return os.path.join(".panopticon", "write-allowlist.json")


def main(argv=None):
    """`argv` is the argument list AFTER the program name. It defaults to the
    real one; pass [] to exercise a bare invocation with no baked-in allowlist."""
    args = sys.argv[1:] if argv is None else argv
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        return 0  # tolerant: a malformed hook payload never blocks legitimate work
    if not isinstance(payload, dict):
        return 0  # tolerant: a well-formed-but-unexpected-shape payload never blocks
    if payload.get("tool_name", "") not in _WRITE_TOOLS:
        return 0
    argv_path = args[0] if args else None
    allow, reason = adjudicate(payload, _resolve_allowlist_path(argv_path))
    if allow:
        return 0
    print(_deny_response(reason))
    return 0


def hook_command(*argv):
    """One hook `command` string, every element shell-quoted (#1633, SEC-A1A).

    A registered PreToolUse command is SHELL SOURCE: the host runs it through
    `sh -c`, so an element interpolated into it is not an argument. The
    `"%s"` this replaces stopped a space and nothing else, which left a `"`,
    a backtick or a `$(...)` in an install path -- the allowlist path, the
    scope path, the checkout the script itself sits in -- executing on every
    tool call. Copied into each guard hook rather than imported, for the same
    reason the settings plumbing is a copy (R-P5-5): a hook runs standing
    alone, with no package on sys.path.
    """
    return " ".join(shlex.quote(a) for a in argv)


# #495: self-locate. The old literal "skill/scripts/..." only resolved when
# the skill lived INSIDE the target repo (the self-scan layout); installed
# under a skills dir the hook silently never ran. The module's own absolute
# path works under both layouts (shell-quoted: install paths may contain
# spaces -- or worse, #1633).
_HOOK_ARGV = ("python3", os.path.abspath(__file__))
_HOOK_CMD = hook_command(*_HOOK_ARGV)
# Ordering is fixed to the original string so install()/uninstall() never
# produce a duplicate or stale entry when upgrading from a settings.local.json
# written by an earlier version. #1633 changed the command's QUOTING, so that
# promise no longer rests on dict equality across versions -- `_is_our_entry`,
# which matches on the script path rather than on the text, is what carries it
# (measured in tests/test_hook_command_quoting.py). The entry's shape is
# unchanged.
_HOOK_ENTRY = {"matcher": _MATCHER,
               "hooks": [{"type": "command", "command": _HOOK_CMD}]}


def _hook_entry(allowlist_path=None):
    """The PreToolUse entry to register.

    With `allowlist_path`, the absolute allowlist is baked into the command so
    the hook never has to infer it from its CWD (see _resolve_allowlist_path).
    Without one, this is the legacy bare entry -- the same entry an earlier
    version wrote, now shell-quoted (#1633), so it is recognised as ours by
    `_is_our_entry` rather than by comparing equal to the older text."""
    if not allowlist_path:
        return _HOOK_ENTRY
    cmd = hook_command(*_HOOK_ARGV, os.path.abspath(allowlist_path))
    return {"matcher": _MATCHER, "hooks": [{"type": "command", "command": cmd}]}


def _runs_this_script(command):
    """True when `command` invokes THIS module -- quoted (#1633) or in the bare
    form an earlier version wrote.

    Tokenizing is what keeps our own entry recognisable once the script path is
    quoted: a checkout path that needed escaping no longer appears verbatim in
    the command, and an unrecognised entry is one uninstall would orphan,
    leaving the guard armed and every later write denied. Both legacy
    spellings tokenize cleanly, so the substring test is the fallback for a
    command no shell can parse: one that still names this script is ours (and
    removable), one that does not answers False rather than raising."""
    mine = os.path.abspath(__file__)
    try:
        tokens = shlex.split(command)
    except ValueError:                  # unbalanced quotes in a foreign entry
        tokens = []
    return mine in tokens or mine in command


def _is_our_entry(entry):
    """True for any PreToolUse entry that runs THIS module, bare or with an
    allowlist argument. Removal matches on the script path rather than on dict
    equality so uninstall still clears an entry written by a different version
    (or with a different allowlist baked in) instead of orphaning it."""
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
        return {}                       # absent is fine -> a fresh settings file
    except (OSError, ValueError) as exc:
        # #1098: present but unreadable/corrupt. Returning {} let install()
        # unconditionally re-serialize a minimal file, DESTROYING the user's
        # permissions.allow/deny and unrelated hooks (a fail-open that can widen
        # session policy). Refuse instead so install() never overwrites a file it
        # could not read.
        raise RuntimeError(
            "refusing to overwrite unreadable %s: %s" % (settings_path, exc)) from exc


def _read_allowlist(allowlist_path):
    """The current on-disk {entry id: [path]} mapping; empty when absent,
    malformed, or written in a version this code does not carry forward.

    (The hook itself fails closed on any of those, so treating them as empty
    HERE only affects the merge arithmetic, never enforcement. A v1 file
    reading as empty is the wanted behaviour on both sides: its paths carry no
    attribution, so they may not be carried into a v2 grant either.)"""
    return _load_allowlist(allowlist_path)[0] or {}


# The dispatch families that write into a run folder, and the ONE artifact each
# family's entry id declares. Spelled here rather than imported, for the reason
# `_atomic_write_json` carries the os-flag form itself: this hook is executed as
# its own subprocess by the host's PreToolUse command and has to import standing
# alone, so it may not reach into the driver's packages.
# tests/test_write_guard_hook.py pins every one of these against the phase builder
# that owns it (`phases/review.py:334+354`, `phases/verify.py:57-64+262`,
# `phases/verify_tools.py:149+212`, `phases/coverage.py:97+102`), so a rename on
# either side fails a test instead of silently revoking a live grant.
RUNS_DIR = "runs"
VERDICTS_DIR = "verdicts"
_REVIEW_PREFIX = "review-"
_TOOL_VERIFY_PREFIX = "verify-tool-"
_VERIFY_PREFIX = "verify-"
_SCOUT_PREFIX = "scout-"
# A tool-finding advisor's queue id: `evidence.finding_fingerprint`'s 16-char
# sha256 prefix, plus `build_verify_queue`'s `-<n>` collision suffix
# (`evidence.py:243` and `:445`, the only producer of either).
#
# This GRAMMAR, not the prefix order, is what separates the two verify families
# (#1831 fix round 2, NI-1). `verify-tool-<queue id>` and
# `verify-<group>-<domain>-<stage>` are ambiguous by prefix alone, and
# `groups_schema._GROUP_NAME_RE` accepts a group literally named `tool` or
# `tool-adapters` -- this repo has `tools/` and `tools-image/`, so the naming is
# not exotic. Trying the tool branch first therefore derived
# `verdicts/adapters-SEC-primary.json` for that group's advisor, which is not the
# bundle it writes: the next arm dropped its in-flight grant and the advisor was
# denied its OWN verdict mid-flight, the #11 harm the per-family rule exists to
# prevent. Gated on the grammar the two families are disjoint rather than ordered:
# no queue id can spell `<group>-<domain>-<stage>` (a domain is three letters and
# a stage is `primary`/`backup`, neither of which a 16-hex token can be), and no
# cell id can spell a queue id. `\A...\Z`, not `^...$`, for the reason
# `dispatch.py`'s validator of this same grammar gives: `$` also matches just
# BEFORE a trailing newline, and the id lands straight in a filename.
_QUEUE_ID_RE = re.compile(r"\A[0-9a-f]{16}(-[0-9]+)?\Z")
# `verify-<group>-<domain>-<stage>[-part<N>]`. A group name may carry hyphens
# (`groups_schema._GROUP_NAME_RE`); a domain and a stage may not -- so the stage is
# the last token once the optional part suffix is off. Stripped in that ORDER, the
# way `_verify_out_file` appends it: one regex with an optional trailing group
# would let a greedy cell swallow the stage and read `part2` as the stage instead.
_VERIFY_PART_RE = re.compile(r"-part[0-9]+$")
_VERIFY_CELL_STAGE_RE = re.compile(r"^(?P<cell>.+)-(?P<stage>[A-Za-z0-9]+)$")


def _claimed_relpath(eid):
    """The one path, RELATIVE to a run folder, that entry `eid` may hold -- or
    None when no dispatch family would grant that id anything in a run folder.

    DERIVED from the id, never matched against a path's name (#1831 fix round 1).
    Matching was the hole: cells are `<group>-<domain>` and a group name may carry
    hyphens, so "does this id end with the cell this name declares" is true
    whenever one group's name ends with another's -- `Core` and `X-Core`, or an
    ordinary collision like `API` and `Public-API`. The target authors the group
    names, so `review-X-Core-SEC` claimed `findings-Core-SEC.json` and a subverted
    reviewer could forge a PEER cell's findings with no integrity trace, the file
    being plan-declared. Reading the pairing the builders establish BACKWARDS is
    exact, and it is exact for every family rather than for one of them.

    `setup-scan` is deliberately absent: it writes `.panopticon/setup-proposal.json`,
    a TOP-LEVEL artifact outside every run folder (`phases/runio.py:_TOP_LEVEL`), so
    no run folder can own it and its grant is never carried -- and because the
    allowlist file is top-level as well, a setup arm and a review run share one,
    which is what makes that a revocation rather than a separate namespace (see
    `_carried_paths_this_run_owns`). `UNBOUND_ENTRY` is absent for the same
    structural reason -- it names no entry, so there is nothing to derive a path
    from, and `adjudicate` refuses that bucket to every bound agent anyway.

    An id carrying a path separator or a `..` is refused outright. No builder can
    produce one (group names admit neither, domains and stages are alphanumeric,
    and a queue id is a 16-char sha prefix), and without the refusal a planted
    `verify-tool-../../x` would derive a suffix that strips back OUT of the run
    folder."""
    if not isinstance(eid, str) or not eid:
        return None
    if os.sep in eid or "/" in eid or ".." in eid or "\x00" in eid:
        return None
    if eid.startswith(_REVIEW_PREFIX):
        cell = eid[len(_REVIEW_PREFIX):]
        return "findings-%s.json" % cell if cell else None
    if eid.startswith(_TOOL_VERIFY_PREFIX):
        queue_id = eid[len(_TOOL_VERIFY_PREFIX):]
        if _QUEUE_ID_RE.match(queue_id):
            return os.path.join(VERDICTS_DIR, "%s.json" % queue_id)
        # Not a queue id: this is a verify CELL of a group whose name begins
        # `tool`, so fall through rather than inventing a path under `verdicts/`
        # for it. It also means a planted `verify-tool-verdicts-Core-SEC` cannot
        # name a peer's bundle (fix round 2, NN-1).
    if eid.startswith(_VERIFY_PREFIX):
        rest = eid[len(_VERIFY_PREFIX):]
        part = _VERIFY_PART_RE.search(rest)
        part_suffix = part.group(0) if part else ""
        m = _VERIFY_CELL_STAGE_RE.match(rest[:part.start()] if part else rest)
        if m is None:
            return None
        return os.path.join(VERDICTS_DIR, "verdicts-%s%s%s.json"
                            % (m.group("cell"),
                               "-backup" if m.group("stage") == "backup" else "",
                               part_suffix))
    if eid.startswith(_SCOUT_PREFIX):
        group = eid[len(_SCOUT_PREFIX):]
        return "scout-%s.json" % group if group else None
    return None


def _run_folder_of(eid, path):
    """The run folder that would make `path` EXACTLY the artifact `eid` declares,
    or None when nothing would. The one predicate both sides use: it turns an
    added grant into an anchor and it decides whether a carried grant is real."""
    rel = _claimed_relpath(eid)
    if rel is None:
        return None
    suffix = os.sep + rel
    p = str(path)
    if not p.endswith(suffix):
        return None
    return p[:-len(suffix)] or None


def _is_run_folder(path):
    """Is `path` a per-run artifact folder, `<review root>/.panopticon/runs/<tag>`?

    #1831: the anchor used to be the `.panopticon` segment, which made the whole
    artifact tree the root -- everything the target commits under it included. The
    run folder is where `runio._pano` puts every non-top-level artifact, so it is
    the narrowest anchor a plan can establish, and a previous round's tag is a
    different folder."""
    parts = str(path).split(os.sep)
    return len(parts) >= 3 and parts[-3] == ARTIFACT_DIR and parts[-2] == RUNS_DIR


def _run_folders(added):
    """The run folders the `added` grants write into -- derived ONLY from the plan
    this install was handed, never from the file on disk.

    Anchoring on each out_file's own `dirname` was wrong because the families do
    not share a directory: review and scout write into the run folder itself,
    verify and the tool-verdict arm write into `<run>/verdicts/` (#1831 fix round
    1). A verify arm therefore anchored on `<run>/verdicts` and carried nothing at
    all -- the #11 revocation harm for three families out of four. Stripping each
    family's own declared suffix lands on the run folder for all of them."""
    roots = set()
    for eid, paths in (added or {}).items():
        for p in paths:
            root = _run_folder_of(eid, p)
            if root is not None and _is_run_folder(root):
                roots.add(root)
    return roots


# Target-authored text reaches the operator's terminal here, so every field is
# bounded with a MARKED cut and rendered with `%r` -- which escapes newlines and
# control bytes, so a planted id can neither forge a line of its own nor erase
# one. `_parse_allowlist` checks only that an id is a str: no grammar, no length.
_ANNOUNCE_TEXT_CAP = 64
_ANNOUNCE_IDS_MAX = 10
_DROP_NOT_THIS_RUN = ("not this run's folder, or not the artifact that entry "
                      "itself declares")
_DROP_NO_ANCHOR = "no run folder among the added out_files"


def _bounded(text):
    """One field of untrusted text, safe to put on a line of operator output."""
    s = text if isinstance(text, str) else str(text)
    if len(s) <= _ANNOUNCE_TEXT_CAP:
        return "%r" % s
    return "%r (+%d chars cut)" % (s[:_ANNOUNCE_TEXT_CAP],
                                   len(s) - _ANNOUNCE_TEXT_CAP)


def _dropped_counts(existing):
    """{entry id: how many paths it holds} -- what is lost when nothing anchors."""
    return {eid: len(paths) for eid, paths in (existing or {}).items() if paths}


def _announce_dropped_grants(dropped, why):
    """ONE line on stderr: the counts first, then the entry ids that lost paths.

    A grant narrowed in silence is the #calibration-4 / gotify shape: every later
    write denied, and nothing in the output pointing at the allowlist. The paths
    themselves are deliberately not printed -- the entry id is what an operator
    needs to tell a previous round's leftovers from a planted file."""
    if not dropped:
        return
    ids = sorted(dropped)
    named = ", ".join("%s (%d)" % (_bounded(eid), dropped[eid])
                      for eid in ids[:_ANNOUNCE_IDS_MAX])
    if len(ids) > _ANNOUNCE_IDS_MAX:
        named += ", and %d more entry(ies)" % (len(ids) - _ANNOUNCE_IDS_MAX)
    print("write guard: dropped %d carried allowlist path(s) in %d entry(ies) "
          "-- %s: %s" % (sum(dropped.values()), len(ids), why, named),
          file=sys.stderr)


def _carried_paths_this_run_owns(existing, added):
    """The `existing` mapping's grants that are a real in-flight grant from a
    concurrent fan-out, still keyed by the entry that holds them.

    One condition, applied per (entry id, path) pair: the path must be EXACTLY the
    artifact that entry declares (`_claimed_relpath`), in one of the run folders
    `added` writes into (`_run_folders`). So an entry keyed with a REAL reviewer id
    may carry only that reviewer's own out_file and never a peer's, a previous
    round's tag is not in flight, and the run's own integrity artifacts
    (`out-file-hashes.json`, `dispatch-plan-driver.json`) are no entry's grant at
    all. A concurrent fan-out's grant IS its own declared artifact in this run's
    folder, whichever family it belongs to, so the #11 property survives.

    With no anchor -- a plan whose out_files establish no run folder -- nothing is
    carried forward: fail closed rather than trust an unanchored file. Every drop
    is announced, including that one. Two ways to reach it, both narrower than the
    `.panopticon`-wide anchor this replaced and neither silent:

      * NO USABLE MANIFEST. `runio._pano` falls back to the flat
        `.panopticon/<name>` whenever `run_manifest.load_manifest` returns nothing
        -- absent, unparseable, or TORN mid-run -- so a run in that state anchors
        nothing and every carried grant is dropped. A re-arm re-adds whatever is
        still pending, and the announcement names the run folder as the thing that
        was missing.
      * A `setup-scan` ARM. Setup writes `.panopticon/setup-proposal.json`, a
        top-level artifact, so it establishes no run folder -- and the allowlist
        is top-level too (`runio._TOP_LEVEL`), shared with every review run on the
        tree rather than separated by setup's own namespace. So a setup arm drops
        a concurrent review fan-out's grants. Same direction as the rule itself,
        still narrower than carrying everything under `.panopticon`."""
    roots = _run_folders(added)
    if not roots:
        _announce_dropped_grants(_dropped_counts(existing), _DROP_NO_ANCHOR)
        return {}
    out = {}
    dropped: dict[str, int] = {}
    for eid, paths in existing.items():
        kept = [str(p) for p in paths if _run_folder_of(eid, str(p)) in roots]
        lost = len(paths) - len(kept)
        if lost:
            dropped[eid] = lost
        if kept:
            out[eid] = kept
    _announce_dropped_grants(dropped, _DROP_NOT_THIS_RUN)
    return out


def _merge_grants(*mappings):
    """One {entry id: [path]} mapping from several, unioning per entry id."""
    out: dict[str, list[str]] = {}
    for mapping in mappings:
        for eid, paths in mapping.items():
            out[eid] = sorted(set(out.get(eid, ())) | set(paths))
    return out


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


def _write_hook_entry(settings_path, allowlist_path=None):
    settings = _load(settings_path)
    hooks = settings.setdefault("hooks", {})
    entry = _hook_entry(allowlist_path)
    pre = [h for h in hooks.get("PreToolUse", []) if not _is_our_entry(h)]
    pre.append(entry)
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


DEFAULT_SETTINGS_PATH = ".claude/settings.local.json"
DEFAULT_ALLOWLIST_PATH = ".panopticon/write-allowlist.json"


def _resolve(settings_path, allowlist_path, session_root):
    """(settings_path, allowlist_path, used_defaults).

    #1493: the defaults are CWD-RELATIVE, but the settings file a running session
    actually consults is the one at its SESSION ROOT. The driver is invoked from
    the target repo, so a caller that armed the guard "from where the driver runs"
    wrote `<target>/.claude/settings.local.json` -- a file nothing reads -- while
    the live guard kept the PREVIOUS round's allowlist. 47 advisors then completed
    and had every write rejected, and `is_armed()` reported (True, 47) throughout
    because it read back the same inert file it had just written.

    `session_root` lets a caller that knows the root (the driver has --session-dir)
    declare it instead of inheriting CWD. `used_defaults` tells install() whether
    it may apply the existence check below -- explicit paths are trusted, because
    the tests and other callers legitimately point at temp dirs.
    """
    explicit = settings_path is not None or allowlist_path is not None
    if session_root is not None:
        if explicit:
            raise ValueError(
                "pass session_root OR explicit settings_path/allowlist_path, "
                "not both -- they resolve to different files and the guard would "
                "arm somewhere other than where it was checked")
        return (os.path.join(session_root, DEFAULT_SETTINGS_PATH),
                os.path.join(session_root, DEFAULT_ALLOWLIST_PATH), True)
    return (settings_path or DEFAULT_SETTINGS_PATH,
            allowlist_path or DEFAULT_ALLOWLIST_PATH, not explicit)


def install(plan, settings_path=None, allowlist_path=None, *, session_root=None):
    # #11: UNION with any existing allowlist rather than REPLACING it wholesale.
    # A re-arm while a prior fan-out is still in flight (an overlapping/nested
    # install) used to overwrite the allowlist with only the new set, silently
    # revoking every still-running agent whose out_file wasn't in it (run-6: cost
    # 8 findings). Unioning keeps prior grants live. out_files are unique per cell
    # (findings-<group>-<domain>.json), so a paired uninstall(plan=...) can later
    # drop exactly this call's paths without disturbing another fan-out's.
    settings_path, allowlist_path, used_defaults = _resolve(
        settings_path, allowlist_path, session_root)
    # #1493: arming a guard into a settings file that does not yet exist means
    # CREATING one -- and a session root essentially always already has one,
    # because that is where its permissions live. So a missing file here is the
    # signature of being in the wrong directory, which is exactly the failure
    # that produced an inert guard. Fail closed and name the resolved path,
    # rather than writing a decorative file and reporting success.
    if used_defaults and not os.path.exists(settings_path):
        raise ValueError(
            "refusing to arm the write-guard at %s: that settings file does not "
            "exist, so this would CREATE one -- which means the current directory "
            "(%s) is almost certainly not the session root, and the guard would "
            "never be consulted. Pass session_root=<the directory the session was "
            "started in>, or explicit settings_path/allowlist_path if you really "
            "mean this location."
            % (os.path.abspath(settings_path), os.path.abspath(os.curdir)))
    added = allowlist_from_plan(plan)
    # #1482: an install that grants NOTHING is always a caller error -- a
    # malformed plan, or a plan whose entries declare no out_file. Letting it
    # through is destructive rather than merely useless: `added` is what anchors
    # the confinement filter below, so with no anchor every carried grant is
    # dropped as unconfined and the write returns an EMPTY allowlist -- revoking
    # every agent in a still-running fan-out, which is the failure #11 exists to
    # prevent. Teardown has its own entry point (`uninstall`, scoped via
    # `plan=`); this one only ever adds.
    if not added:
        raise ValueError(
            "refusing to install a write-guard that grants nothing: the plan "
            "declared no out_file. This would clear %d existing grant(s) and "
            "deny every in-flight write. Use uninstall() to tear the guard "
            "down." % len(union_paths(_read_allowlist(allowlist_path))))
    # #run10 SEC-C1D: the union above trusted whatever was already on disk. A
    # target repo can ship its own `.panopticon/write-allowlist.json` (the path is
    # inside the scanned tree), so a planted entry -- `~/.ssh/authorized_keys`, a
    # source file -- was unioned in and became a WRITABLE target for every agent
    # in the fan-out. Keep the #11 in-flight property, but only for entries that
    # could plausibly be a real in-flight grant: its OWN cell's findings file, in
    # one of the RUN FOLDERS this install writes into. Anything else -- another
    # run's folder, the run's integrity artifacts, a peer cell's findings file
    # under a real reviewer's id (#1831 SEC-611772336) -- was not written by a
    # trusted install and is dropped, with a count on stderr.
    carried = _carried_paths_this_run_owns(_read_allowlist(allowlist_path), added)
    # #1571: the union is merged PER ENTRY ID, so a concurrent fan-out's grant
    # survives (the #11 property) without becoming writable by this batch's
    # reviewers -- which is exactly what a flat union made it.
    _atomic_write_json(allowlist_path,
                       allowlist_document(_merge_grants(carried, added)))
    _write_hook_entry(settings_path, allowlist_path)
    return added


def guard_state(settings_path=None, allowlist_path=None, *, session_root=None):
    """The full answer `is_armed` cannot give: which files were consulted.

    #1493: `is_armed()` returning (True, 47) is not evidence the guard is live --
    it only says "a guard is registered at the path I looked at". When that path
    is not the one the session reads, the tuple is true and useless. Callers
    diagnosing a guard that "is armed" but rejects every write need the resolved
    paths, so return them.
    """
    settings_path, allowlist_path, _ = _resolve(
        settings_path, allowlist_path, session_root)
    armed, grants = is_armed(settings_path, allowlist_path)
    return {"armed": armed, "grants": grants,
            "settings_path": os.path.abspath(settings_path),
            "allowlist_path": os.path.abspath(allowlist_path),
            "settings_exists": os.path.exists(settings_path)}


def is_armed(settings_path=None, allowlist_path=None, *, session_root=None):
    """(armed, grants): is the guard registered, and over how many paths?

    The guard is fail-closed while registered, and the allowlist IS the complete
    set of permitted writes -- so a guard left armed after a fan-out finishes
    denies EVERY subsequent Write/Edit in the session, including the operator's
    own, with only the hook's per-write reason to say why. Teardown is a host
    duty (docs/guide/driver-run-loop.md) that nothing previously verified; this
    makes the
    state checkable in one call so a host, a test, or CI can assert it.
    """
    settings_path, allowlist_path, _ = _resolve(
        settings_path, allowlist_path, session_root)
    try:
        with open(settings_path, encoding="utf-8") as fh:
            settings = json.load(fh)
    except (OSError, ValueError):
        return False, 0
    hooks = (settings.get("hooks") or {}).get("PreToolUse") or []
    # #1633: the same predicate uninstall removes by. A literal `_HOOK_CMD`
    # comparison read an entry written by ANY other version -- including every
    # pre-quoting one -- as disarmed, so a guard that was in fact armed
    # reported clear.
    armed = any(_is_our_entry(entry) for entry in hooks)
    if not armed:
        return False, 0
    try:
        return True, len(union_paths(_read_allowlist(allowlist_path)))
    except Exception:              # noqa: BLE001 - unreadable == armed over nothing
        return True, 0


def uninstall(settings_path=None, allowlist_path=None, *, plan=None,
              session_root=None):
    # #11: with `plan` given, remove ONLY that fan-out's paths (scoped teardown)
    # and keep the guard armed while any OTHER fan-out's paths remain -- so
    # tearing down one fan-out never revokes a concurrent one. With no `plan`
    # (the legacy default), tear the whole guard down.
    settings_path, allowlist_path, _ = _resolve(
        settings_path, allowlist_path, session_root)
    if plan is not None:
        # #1571: subtract PER ENTRY ID. out_files are unique per cell, so this
        # drops the same paths the flat subtraction did -- but a path granted
        # to a still-running entry can no longer be dropped by another entry's
        # teardown, whatever a future plan's shape.
        drop = allowlist_from_plan(plan)
        remaining = {}
        for eid, paths in _read_allowlist(allowlist_path).items():
            kept = sorted(set(paths) - set(drop.get(eid, ())))
            if kept:
                remaining[eid] = kept
        if remaining:
            _atomic_write_json(allowlist_path, allowlist_document(remaining))
            return   # other fan-outs still armed -> keep the hook entry + file
    _remove_hook_entry(settings_path)
    try:
        os.remove(allowlist_path)
    except OSError:
        pass


if __name__ == "__main__":
    sys.exit(main())
