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
Bash). ``dispatch.py`` refuses to emit an unenforced reviewer plan by default
for exactly this reason; ``--allow-unenforced`` accepts the residual risk
explicitly and records that this guard does not cover Bash-based writes in that
mode. The matcher and ``_WRITE_TOOLS`` are derived from one source below so
they can never silently drift apart from each other.
"""
import json
import os
import sys

_WRITE_TOOLS_LIST = ["Write", "Edit", "NotebookEdit"]
_WRITE_TOOLS = set(_WRITE_TOOLS_LIST)
_MATCHER = "|".join(_WRITE_TOOLS_LIST)


def allowlist_from_plan(plan):
    """Realpath-normalized set of every out_file the plan declares.

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
    out = set()
    for entry in plan:
        path = entry.get("out_file") if isinstance(entry, dict) else None
        if not isinstance(path, str) or not path:
            continue
        artifact_dir = os.path.dirname(os.path.abspath(path))
        if os.path.basename(artifact_dir) == ".panopticon" and os.path.islink(artifact_dir):
            raise ValueError("findings output cannot use a symlinked .panopticon directory")
        out.add(os.path.realpath(path))
    return out


def decide(tool_name, file_path, allowlist):
    """(allow, reason). Non-write tools always allowed; writes only to allowlist."""
    if tool_name not in _WRITE_TOOLS:
        return True, ""
    try:
        raw = os.path.abspath(file_path or "")
        if os.path.islink(raw):
            return False, (
                "write to %s is denied: findings targets must not be symlinks" % file_path)
        target = os.path.realpath(raw)
    except (ValueError, OSError, TypeError):
        # TypeError: a non-string file_path (int/list/dict) — os.path.* rejects
        # it. A write payload whose path isn't a string is malformed/suspicious;
        # fail closed (deny) rather than crash the hook (#768).
        return False, ("write to %r is denied: unresolvable path" % file_path)
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
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input")
    # #run7 ARC-F2C: NotebookEdit keys its target as `notebook_path`, NOT
    # `file_path`. Reading file_path uniformly checked NotebookEdit against the
    # wrong (empty) path -- benign fail-closed for an ordinary notebook edit, but
    # a decoy payload {file_path: <allowlisted>, notebook_path: <outside>} would be
    # ALLOWED while the write lands outside the fence. Extract the tool's own key
    # and do NOT fall back to file_path for NotebookEdit.
    if isinstance(tool_input, dict):
        path_key = "notebook_path" if tool_name == "NotebookEdit" else "file_path"
        file_path = tool_input.get(path_key, "")
    else:
        file_path = ""
    if tool_name not in _WRITE_TOOLS:
        return 0
    argv_path = args[0] if args else None
    try:
        with open(_resolve_allowlist_path(argv_path), encoding="utf-8") as fh:
            loaded = json.load(fh)
    except (OSError, ValueError) as exc:
        loaded = None
        load_error = "write guard allowlist is unavailable: %s" % exc
    else:
        load_error = "write guard allowlist is malformed"
    if not isinstance(loaded, list) or not all(isinstance(p, str) for p in loaded):
        print(_deny_response(load_error))
        return 0
    allowlist = set(loaded)
    allow, reason = decide(tool_name, file_path, allowlist)
    if allow:
        return 0
    print(_deny_response(reason))
    return 0


# #495: self-locate. The old literal "skill/scripts/..." only resolved when
# the skill lived INSIDE the target repo (the self-scan layout); installed
# under a skills dir the hook silently never ran. The module's own absolute
# path works under both layouts (quoted: install paths may contain spaces).
_HOOK_CMD = 'python3 "%s"' % os.path.abspath(__file__)
# Ordering is fixed to the original string so install()/uninstall() dict-equality
# never produces a duplicate or stale entry when upgrading from a
# settings.local.json written by an earlier version.
_HOOK_ENTRY = {"matcher": _MATCHER,
               "hooks": [{"type": "command", "command": _HOOK_CMD}]}


def _hook_entry(allowlist_path=None):
    """The PreToolUse entry to register.

    With `allowlist_path`, the absolute allowlist is baked into the command so
    the hook never has to infer it from its CWD (see _resolve_allowlist_path).
    Without one, this is the legacy bare entry -- kept identical so a
    settings.local.json written by an earlier version still compares equal."""
    if not allowlist_path:
        return _HOOK_ENTRY
    cmd = '%s "%s"' % (_HOOK_CMD, os.path.abspath(allowlist_path))
    return {"matcher": _MATCHER, "hooks": [{"type": "command", "command": cmd}]}


def _is_our_entry(entry):
    """True for any PreToolUse entry that runs THIS module, bare or with an
    allowlist argument. Removal matches on the script path rather than on dict
    equality so uninstall still clears an entry written by a different version
    (or with a different allowlist baked in) instead of orphaning it."""
    if not isinstance(entry, dict):
        return False
    for h in entry.get("hooks", []) or []:
        if isinstance(h, dict) and os.path.abspath(__file__) in str(h.get("command", "")):
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
    """The current on-disk allowlist as a set of paths; empty when absent or
    malformed. (The hook itself fails closed on a malformed file, so treating it
    as empty HERE only affects the union arithmetic, never enforcement.)"""
    try:
        with open(allowlist_path, encoding="utf-8") as fh:
            loaded = json.load(fh)
    except (OSError, ValueError):
        return set()
    if not isinstance(loaded, list):
        return set()
    return {p for p in loaded if isinstance(p, str)}


def _artifact_roots(paths):
    """The `.panopticon` directory of each path that has one -- the only place a
    legitimate findings out_file lives (#run10 SEC-C1D)."""
    roots = set()
    for p in paths:
        parts = str(p).split(os.sep)
        if ".panopticon" in parts:
            roots.add(os.sep.join(parts[:parts.index(".panopticon") + 1]))
    return roots


def _confined_to_artifact_roots(existing, added):
    """`existing` entries that sit under the same `.panopticon` tree as `added`.

    An in-flight grant from a concurrent fan-out is always a findings out_file in
    that tree, so it survives (the #11 property). A pre-planted entry pointing
    anywhere else -- a source file, a dotfile in $HOME -- does not, and can no
    longer buy write access off the back of our install. With no anchor (a plan
    whose out_files carry no `.panopticon` segment) nothing is carried forward:
    fail closed rather than trust an unanchored file."""
    roots = _artifact_roots(added)
    if not roots:
        return set()
    return {p for p in existing
            if any(str(p) == r or str(p).startswith(r + os.sep) for r in roots)}


def _atomic_write_json(path, data, indent=None):
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
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


def install(plan, settings_path=".claude/settings.local.json",
            allowlist_path=".panopticon/write-allowlist.json"):
    # #11: UNION with any existing allowlist rather than REPLACING it wholesale.
    # A re-arm while a prior fan-out is still in flight (an overlapping/nested
    # install) used to overwrite the allowlist with only the new set, silently
    # revoking every still-running agent whose out_file wasn't in it (run-6: cost
    # 8 findings). Unioning keeps prior grants live. out_files are unique per cell
    # (findings-<group>-<domain>.json), so a paired uninstall(plan=...) can later
    # drop exactly this call's paths without disturbing another fan-out's.
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
            "down." % len(_read_allowlist(allowlist_path)))
    # #run10 SEC-C1D: the union above trusted whatever was already on disk. A
    # target repo can ship its own `.panopticon/write-allowlist.json` (the path is
    # inside the scanned tree), so a planted entry -- `~/.ssh/authorized_keys`, a
    # source file -- was unioned in and became a WRITABLE target for every agent
    # in the fan-out. Keep the #11 in-flight property, but only for entries that
    # could plausibly be a real in-flight grant: a findings out_file lives under
    # the SAME `.panopticon` tree as the paths we are adding. Anything outside it
    # was not written by a trusted install and is dropped.
    carried = _confined_to_artifact_roots(_read_allowlist(allowlist_path), added)
    _atomic_write_json(allowlist_path, sorted(carried | added))
    _write_hook_entry(settings_path, allowlist_path)
    return added


def uninstall(settings_path=".claude/settings.local.json",
              allowlist_path=".panopticon/write-allowlist.json", *, plan=None):
    # #11: with `plan` given, remove ONLY that fan-out's paths (scoped teardown)
    # and keep the guard armed while any OTHER fan-out's paths remain -- so
    # tearing down one fan-out never revokes a concurrent one. With no `plan`
    # (the legacy default), tear the whole guard down.
    if plan is not None:
        remaining = _read_allowlist(allowlist_path) - allowlist_from_plan(plan)
        if remaining:
            _atomic_write_json(allowlist_path, sorted(remaining))
            return   # other fan-outs still armed -> keep the hook entry + file
    _remove_hook_entry(settings_path)
    try:
        os.remove(allowlist_path)
    except OSError:
        pass


if __name__ == "__main__":
    sys.exit(main())
