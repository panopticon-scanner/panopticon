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

# The write-capable tools this guard adjudicates. The PreToolUse matcher is
# DERIVED from this set (see _MATCHER) so the two can never drift: adding a
# write tool here automatically widens the matcher, and test_write_guard_hook
# asserts they stay in lockstep. Bash is deliberately absent — see the module
# docstring; it is out of scope by construction, not by omission.
_WRITE_TOOLS = {"Write", "Edit", "NotebookEdit"}


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
            return False, ("write to %s is denied: findings targets must not be symlinks" % file_path)
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
        with open(".panopticon/write-allowlist.json", encoding="utf-8") as fh:
            loaded = json.load(fh)
    except (OSError, ValueError) as exc:
        loaded = None
        load_error = "write guard allowlist is unavailable: %s" % exc
    else:
        load_error = "write guard allowlist is malformed"
    if not isinstance(loaded, list) or not all(isinstance(p, str) for p in loaded):
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": load_error}}))
        return 0
    allowlist = set(loaded)
    allow, reason = decide(tool_name, file_path, allowlist)
    if allow:
        return 0
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason}}))
    return 0


# #495: self-locate. The old literal "skill/scripts/..." only resolved when
# the skill lived INSIDE the target repo (the self-scan layout); installed
# under a skills dir the hook silently never ran. The module's own absolute
# path works under both layouts (quoted: install paths may contain spaces).
_HOOK_CMD = 'python3 "%s"' % os.path.abspath(__file__)
# Ordering is fixed to the original string so install()/uninstall() dict-equality
# never produces a duplicate or stale entry when upgrading from a
# settings.local.json written by an earlier version.  The assert below is the
# import-time drift-lock: if _WRITE_TOOLS and _MATCHER diverge, the module fails
# to load rather than silently registering the wrong set of tools (#680).
_MATCHER = "Write|Edit|NotebookEdit"
assert set(_MATCHER.split("|")) == _WRITE_TOOLS, (  # pragma: no cover
    "_MATCHER and _WRITE_TOOLS have drifted — update _MATCHER to match _WRITE_TOOLS")
_HOOK_ENTRY = {"matcher": _MATCHER,
               "hooks": [{"type": "command", "command": _HOOK_CMD}]}


def _load(settings_path):
    try:
        with open(settings_path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def install(plan, settings_path=".claude/settings.local.json",
            allowlist_path=".panopticon/write-allowlist.json"):
    os.makedirs(os.path.dirname(allowlist_path) or ".", exist_ok=True)
    with open(allowlist_path, "w", encoding="utf-8") as fh:
        json.dump(sorted(allowlist_from_plan(plan)), fh)
    settings = _load(settings_path)
    hooks = settings.setdefault("hooks", {})
    pre = [h for h in hooks.get("PreToolUse", []) if h != _HOOK_ENTRY]
    pre.append(_HOOK_ENTRY)
    hooks["PreToolUse"] = pre
    os.makedirs(os.path.dirname(settings_path) or ".", exist_ok=True)
    with open(settings_path, "w", encoding="utf-8") as fh:
        json.dump(settings, fh, indent=2)


def uninstall(settings_path=".claude/settings.local.json",
              allowlist_path=".panopticon/write-allowlist.json"):
    settings = _load(settings_path)
    hooks = settings.get("hooks", {})
    if "PreToolUse" in hooks:
        hooks["PreToolUse"] = [h for h in hooks["PreToolUse"] if h != _HOOK_ENTRY]
        if not hooks["PreToolUse"]:
            del hooks["PreToolUse"]
        if not hooks:
            settings.pop("hooks", None)
        with open(settings_path, "w", encoding="utf-8") as fh:
            json.dump(settings, fh, indent=2)
    try:
        os.remove(allowlist_path)
    except OSError:
        pass


if __name__ == "__main__":
    sys.exit(main())
