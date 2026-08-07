"""PreToolUse write-guard hook: reviewers may write only the fan-out findings
files declared in the dispatch plan. Any other Write/Edit is denied. This is the
harness-enforced replacement for the read-only-reviewer convention (#436).
"""
import json
import os
import sys

_WRITE_TOOLS = {"Write", "Edit", "NotebookEdit"}


def allowlist_from_plan(plan):
    """Absolute-normalized set of every out_file the plan declares."""
    return {os.path.abspath(e["out_file"]) for e in plan
            if isinstance(e, dict) and isinstance(e.get("out_file"), str) and e.get("out_file")}


def decide(tool_name, file_path, allowlist):
    """(allow, reason). Non-write tools always allowed; writes only to allowlist."""
    if tool_name not in _WRITE_TOOLS:
        return True, ""
    target = os.path.abspath(file_path or "")
    if os.path.islink(target):
        return False, ("write to %s is denied: findings targets must not be symlinks" % file_path)
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
    try:
        with open(".panopticon/write-allowlist.json", encoding="utf-8") as fh:
            loaded = json.load(fh)
    except (OSError, ValueError):
        return 0  # no allowlist installed -> guard inactive, do not block
    if not isinstance(loaded, list):
        return 0  # tolerant: a malformed allowlist file never blocks legitimate work
    allowlist = set(loaded)
    allow, reason = decide(tool_name, file_path, allowlist)
    if allow:
        return 0
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason}}))
    return 0


_HOOK_CMD = "python3 skill/scripts/write_guard_hook.py"
_HOOK_ENTRY = {"matcher": "Write|Edit|NotebookEdit",
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
