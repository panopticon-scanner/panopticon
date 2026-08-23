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
    """Realpath-normalized set of every out_file the plan declares."""
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


def _resolve_allowlist_path():
    env_path = os.environ.get("PANOPTICON_WRITE_ALLOWLIST")
    if env_path and os.path.isfile(env_path):
        return env_path
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


def main():
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        return 0  # tolerant: a malformed hook payload never blocks legitimate work
    if not isinstance(payload, dict):
        return 0  # tolerant: a well-formed-but-unexpected-shape payload never blocks
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input")
    file_path = tool_input.get("file_path", "") if isinstance(tool_input, dict) else ""
    if tool_name not in _WRITE_TOOLS:
        return 0
    try:
        with open(_resolve_allowlist_path(), encoding="utf-8") as fh:
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


def _atomic_write_json(path, data, indent=None):
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=indent)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _write_hook_entry(settings_path):
    settings = _load(settings_path)
    hooks = settings.setdefault("hooks", {})
    pre = [h for h in hooks.get("PreToolUse", []) if h != _HOOK_ENTRY]
    pre.append(_HOOK_ENTRY)
    hooks["PreToolUse"] = pre
    _atomic_write_json(settings_path, settings, indent=2)


def _remove_hook_entry(settings_path):
    settings = _load(settings_path)
    hooks = settings.get("hooks", {})
    if "PreToolUse" not in hooks:
        return
    hooks["PreToolUse"] = [h for h in hooks["PreToolUse"] if h != _HOOK_ENTRY]
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
    _atomic_write_json(allowlist_path, sorted(_read_allowlist(allowlist_path) | added))
    _write_hook_entry(settings_path)
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
