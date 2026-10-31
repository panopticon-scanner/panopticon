"""The rules the three guard hooks share: read scope, binding, the findings
component walk, the v2 allowlist, and the settings plumbing (#3273 cut 11).

`read_guard_hook`, `write_guard_hook` and `kimi_guard_hook` each used to carry
their own copy of these, pinned AST-identical by tests, because a hook runs as
its own process (``<interpreter> -I <abs path>``) and cannot import a sibling
the ordinary way. Under ``-I`` sys.path is the stdlib plus site-packages: a bare
``import guard_rules`` raises, and ``from scripts import guard_rules`` would let
a foreign `scripts` package installed in site-packages answer for ours. So each
hook LOADS this file by path, from its own real directory, with the loader
stanza at the top of each hook -- and denies every tool call it guards when the
load fails, for any reason. Imported as part of our package (the driver, the
tests), a hook takes ``from . import guard_rules`` instead, so there is one
module object and a patch lands where the hook looks.

The file sits in the same directory as the hooks it serves, and they run in
place: whoever can rewrite it could already rewrite the hook. No new trust.

Rules for this module: stdlib-only, no import of anything under `scripts`, and
no `__file__` identity -- a function that needs to know WHICH hook is asking
takes the hook's script path as a parameter.

The Codex read broker (`codex_read_tools`) keeps its own byte-identical copy
of `SCOPE_KEYS`, `_under` and `_in_dir_grant`, pinned in
tests/test_guard_rules.py: it is an MCP server rather than a hook, those 24
lines are all it shares, and a loader would cost it more lines than that plus
a second failure path in its protocol.
"""
import glob
import json
import os
import shlex
import stat
import sys

MARKER_PREFIX = "panopticon-entry: "
# Spec 5.3 (plan 6): the headless runner exports this per subprocess, and it
# is the FIRST binding source -- a headless `claude -p` session is the
# reviewer itself, so a transcript-only rule would fail OPEN for every entry.
ENV_ENTRY_ID = "PANOPTICON_ENTRY_ID"
# #3271: a hard link out of the tree is a first-contact halt (H4), not a key
# here; a scope file from an older version may still carry `hard_linked`, and
# it is ignored.
SCOPE_KEYS = ("files", "dirs", "reads")
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
# both write guards refuse this key explicitly rather than resting on that.
UNBOUND_ENTRY = "<unbound>"


# --- READ SCOPE -------------------------------------------------------------

def _under(path, directory):
    """Separator-bounded prefix test: /repo admits /repo/x, never /repo-other.

    The `or os.sep` is the ROOT edge: with `/` as the grant, `rstrip(os.sep)`
    leaves "" and every absolute path starts with os.sep, so without it the
    grant would admit the whole filesystem (ARC-1784455652/#1767)."""
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


def _in_dir_grant(target, directory):
    """`_under`, except that a directory grant never covers its own `.git`
    store (#3271 G-a): first contact does not count `<root>/.git`, so no grant
    may read it. A path COMPONENT, never a prefix: `.github/` still reads."""
    if not _under(target, directory):
        return False
    rest = target[len(directory.rstrip(os.sep)):].lstrip(os.sep)
    first = rest.split(os.sep, 1)[0]
    if first.casefold() == ".git":      # `.GIT/config` opens `.git/config` on APFS/NTFS
        return False
    try:                                # and any other alias of the store the volume makes
        return not (first and os.path.samefile(os.path.join(directory, first),
                                               os.path.join(directory, ".git")))
    except (OSError, ValueError):
        return True


def _names_git_store(pattern):
    """True when a Glob pattern names a `.git` component (#3271 G-a)."""
    return isinstance(pattern, str) and ".git" in [
        part.casefold() for part in pattern.replace("\\", "/").split("/")]


def _readable(target, scope):
    # Byte-exact by design: folding a GRANT would widen it.
    return (target in scope["files"] or target in scope["reads"]
            or any(_in_dir_grant(target, d) for d in scope["dirs"]))


# #1917: Glob's SECOND argument. `path` says where the expansion starts and is
# adjudicated by each hook; the pattern says what it expands to, and it is a
# PATH pattern, so `../Src/*` under a clean granted directory names entries the
# grant never covered. One wording, both read guards, pinned in
# tests/test_codex_read_tools.py.
GLOB_PATTERN_DENIAL = ("Glob pattern %r is denied: patterns are relative to `path` and may "
                       "not climb out of it")
# #3271 G-a: and may not name the repository's `.git` store, which no directory
# grant covers. Same pinning as the line above.
GIT_STORE_DENIAL = "Glob pattern %r is denied: no directory grant covers the .git store"


def _glob_pattern_climbs(pattern):
    """True when a `Glob` pattern could name entries outside the `path` it is
    relative to (#1917).

    Glob is the one read primitive with TWO path-shaped arguments, and only the
    first was ever adjudicated: a pattern is expanded against `path`, so
    `../Src/*` under a granted directory names entries the `dirs` grant does not
    cover. Names, not content -- a following `Read` still meets the per-file
    rule -- but a confined cell should not be able to enumerate the tree.

    Absent, empty or non-string DENIES: there is no pattern to reason about,
    and fail-closed is the hooks' rule everywhere else. Absolute and
    `~`-rooted patterns ignore `path` outright. A `..` SEGMENT climbs; a name
    that merely begins with two dots (`..hidden`) does not, which is why this
    splits on separators instead of searching for the substring. Both
    separators, because a Windows-style pattern is still a pattern here.

    Grep's `pattern` is a REGEX over content, not a path, and is not this
    rule's subject."""
    if not isinstance(pattern, str) or not pattern:
        return True
    if pattern.startswith("~") or pattern.startswith("/") or os.path.isabs(pattern):
        return True
    return any(part == ".." for part in pattern.replace("\\", "/").split("/"))


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


# --- BINDING (Claude's two hooks; Kimi binds by environment only) -----------

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


# --- THE FINDINGS COMPONENT WALK (both write guards) ------------------------
#
# #1640 (run-13 AGT-861284148). The `.panopticon` segment is found LEXICALLY
# -- here and in `write_guard_hook._is_run_folder` -- so every directory
# between the review root and the findings file is a component whose NAME the
# guard trusted and whose target it never looked at. The old rule refused a
# symlink only when the out_file's IMMEDIATE parent was named `.panopticon`; a
# real findings path is `<root>/.panopticon/runs/<tag>/findings-<group>-<domain>.json`,
# whose immediate parent is the run folder, so a target repo that commits
# `.panopticon/runs` as a link had `allowlist_from_plan` store the EXTERNAL
# realpath as a grant and the write guard resolve the reviewer's Write to
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
    `write_guard_hook._carried_paths_this_run_owns` already refuses to carry
    such a grant forward, and the probes' sandbox plans legitimately declare
    out_files that live nowhere near an artifact tree.

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
    same fail-closed rule the read guards apply (#1642, fix round 1):
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


# --- THE V2 WRITE ALLOWLIST (both write guards) -----------------------------

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


# --- SETTINGS PLUMBING (driver side: install, uninstall, is_armed) ----------
#
# Every function that has to know WHICH hook it is about takes that hook's
# script path: moved here naively, `__file__` would name this module, and
# `_is_our_entry` would stop recognising any hook's entry -- an uninstall that
# orphans the entry leaves the guard armed and every later call denied.

def hook_command(*argv):
    """One hook `command` string, every element shell-quoted (#1633, SEC-A1A).

    A registered PreToolUse command is SHELL SOURCE: the host runs it through
    `sh -c`, so an interpolated element is not an argument. The `"%s"` this
    replaces stopped a space and nothing else, so a `"`, a backtick or a
    `$(...)` in an install path -- the allowlist path, the scope path, the
    checkout a hook sits in -- executed on every tool call."""
    return " ".join(shlex.quote(a) for a in argv)


def _trusted_hook_argv(script, label):
    """THIS process's interpreter, `-I`, and `script`'s absolute path (#495).

    #2161: a bare `python3` resolves in the CHILD's rewritten PATH
    (`executable.resolve` drops the review root) -- a fail-OPEN. `-I` keeps
    PYTHONPATH, the user site and the script's directory out of sys.path
    (#1996); it does NOT stop the interpreter's own site-packages, its `.pth`
    files or a `sitecustomize` there, which is why the interpreter is the
    driver's own, resolved here, and never a name PATH picks. `label` names
    the guard in the refusal."""
    executable = sys.executable
    if not executable or not os.path.isabs(executable):
        raise RuntimeError("%s interpreter is unavailable or not absolute: %r"
                           % (label, executable))
    executable = os.path.realpath(executable)
    if not os.path.isfile(executable) or not os.access(executable, os.X_OK):
        raise RuntimeError("%s interpreter is unavailable: %s" % (label, executable))
    return executable, "-I", os.path.abspath(script)


def _runs_script(command, script):
    """True when `command` invokes `script` -- quoted (#1633) or in the bare
    form an earlier version wrote.

    Tokenizing is what keeps a hook's own entry recognisable once its path is
    quoted: an escaped checkout path no longer appears verbatim, and an entry
    uninstall cannot recognise is one it orphans, leaving the guard armed. The
    substring test is the fallback for a command no shell can parse: naming
    the script is ours, else False, never a raise."""
    mine = os.path.abspath(script)
    try:
        tokens = shlex.split(command)
    except ValueError:                  # unbalanced quotes in a foreign entry
        tokens = []
    return mine in tokens or mine in command


def _is_our_entry(entry, script):
    """True for any PreToolUse entry that runs `script`, with or without a
    data path baked in. Matched on the script path rather than on dict
    equality, so uninstall still clears an entry an earlier version wrote; and
    keyed per script, so the read and write guards coexist in one file."""
    if not isinstance(entry, dict):
        return False
    for h in entry.get("hooks", []) or []:
        if isinstance(h, dict) and _runs_script(str(h.get("command", "")), script):
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


def atomic_write_json(path, data, indent=None):
    """Stage at `<path>.tmp`, then rename -- never writing THROUGH a symlink
    planted at that temp name (I7).

    A plain `open(tmp, "w")` follows a link. The settings, allowlist and scope
    files this writes all live where an untrusted target can reach: the run
    folder sits inside the scanned tree, and a redteam target can commit
    `<name>.tmp` as a link to any file the invoking user can write (a dotfile,
    authorized_keys), whose contents this would then replace with the guard's
    own JSON. Same class as #run9 SEC-X0X, which `runio._open_w_nofollow`
    closed for `.panopticon` artifacts.

    Spelled with os flags rather than by calling that helper: this module may
    import nothing under `scripts` (see the module docstring).
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


def _write_hook_entry(settings_path, script, entry):
    """Register `entry` in place of every PreToolUse entry that runs `script`."""
    settings = _load(settings_path)
    hooks = settings.setdefault("hooks", {})
    pre = [h for h in hooks.get("PreToolUse", []) if not _is_our_entry(h, script)]
    pre.append(entry)
    hooks["PreToolUse"] = pre
    atomic_write_json(settings_path, settings, indent=2)


def _remove_hook_entry(settings_path, script):
    settings = _load(settings_path)
    hooks = settings.get("hooks", {})
    if "PreToolUse" not in hooks:
        return
    hooks["PreToolUse"] = [h for h in hooks["PreToolUse"] if not _is_our_entry(h, script)]
    if not hooks["PreToolUse"]:
        del hooks["PreToolUse"]
    if not hooks:
        settings.pop("hooks", None)
    atomic_write_json(settings_path, settings, indent=2)


def _armed(settings_path, script):
    """Whether the settings file at `settings_path` registers `script`; an
    unreadable file is not armed."""
    try:
        with open(settings_path, encoding="utf-8") as fh:
            settings = json.load(fh)
    except (OSError, ValueError):
        return False
    # #1633: the same predicate uninstall removes by. A literal command comparison
    # read an entry written by ANY other version -- including every pre-quoting one
    # -- as disarmed, so a guard that was in fact armed reported clear.
    hooks = (settings.get("hooks") or {}).get("PreToolUse") or []
    return any(_is_our_entry(entry, script) for entry in hooks)


# --- WHERE A HOOK'S POLICY FILE IS, AND WHAT IT DENIED -----------------------

def resolve_policy_path(env_name, argv_path, filename):
    """The env override, then the path `install()` baked into the hook command, then a
    walk up from the cwd: `_resolve_allowlist_path`'s order, whose docstring says why."""
    env_path = os.environ.get(env_name)
    if env_path and os.path.isfile(env_path):
        return env_path
    if argv_path:
        # Returned even when absent: the guard is fail-closed, and an install that named a file which
        # then vanished must DENY, never fall back to some other tree's policy and its grants.
        return argv_path
    cur = os.path.abspath(os.getcwd())
    while True:
        candidate = os.path.join(cur, ARTIFACT_DIR, filename)
        if os.path.isfile(candidate):
            return candidate
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return os.path.join(ARTIFACT_DIR, filename)


# #3234: a host's denial row says what was denied, never why, and only the hook knows why. So the
# hook leaves its own reason beside the policy file, for `Ledger.record` to join by `tool_use_id`.
# Nothing else reads this file: no done predicate, no tally. A launched agent reaches it through no
# grant: its read scope is exact files, and its write grant is its own out_file.
DENIALS_FILE = "guard-denials.jsonl"
DENIALS_CAP = 4 * 1024 * 1024         # one looping agent must not fill the run folder
DENIAL_REASON_CAP = 400
_DENIAL_ID_CAP = 128
_DENIAL_WAIT_SECONDS = 0.25


def _append_denial(path, line):
    """One `O_APPEND` write per line, so parallel launches sharing the file cannot interleave."""
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if (stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_size < DENIALS_CAP):
            os.write(fd, line)
    finally:
        os.close(fd)


def _append_denial_quietly(path, line):
    try:
        _append_denial(path, line)
    except OSError:
        pass                          # the deny is already out; the record is only a record


def record_denial(policy_path, payload, reason):
    """Leave `reason` for the ledger, AFTER the hook has printed its deny. Never raises, and waits
    at most `_DENIAL_WAIT_SECONDS`: the host waits for this process, so a slow or full disk must
    not hold up a decision that is already made.

    Not in the flat `.panopticon/` of a setup run: `setup-scan` alone holds a directory grant, over
    the whole root, so that one role could read the file."""
    try:
        import threading              # here: an allowed call never pays for it
        run_dir = os.path.dirname(os.path.abspath(policy_path))
        tool_use_id = payload.get("tool_use_id")
        if os.path.basename(run_dir) == ARTIFACT_DIR or not isinstance(tool_use_id, str):
            return
        line = json.dumps({"tool_use_id": tool_use_id[:_DENIAL_ID_CAP],
                           "tool_name": str(payload.get("tool_name"))[:_DENIAL_ID_CAP],
                           "reason": str(reason)[:DENIAL_REASON_CAP]}) + "\n"
        writer = threading.Thread(target=_append_denial_quietly, daemon=True,
                                  args=(os.path.join(run_dir, DENIALS_FILE), line.encode()))
        writer.start()
        writer.join(_DENIAL_WAIT_SECONDS)
    except Exception:  # noqa: BLE001 -- the deny is already printed; nothing here may change it
        pass


# --- THE LOADER --------------------------------------------------------------
#
# The loader stanza is the one piece that cannot live here, because it is what
# finds this file. Each guard hook carries it byte for byte between these two
# markers, and tests/test_guard_rules.py pins the three copies equal to each
# other: edit one, paste the result into the other two.
LOADER_BEGIN = "# --- GUARD RULES LOADER (#3273 cut 11) ---"
LOADER_END = "# --- END GUARD RULES LOADER ---"
