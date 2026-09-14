#!/usr/bin/env python3
"""Gemini guard hook for Antigravity (agy).

Implements read and write confinement for Gemini agents by intercepting
tool calls via agy's PreToolUse hook.
"""
import json
import os
import sys

def get_scope_path():
    env_path = os.environ.get("PANOPTICON_READ_SCOPE")
    if env_path and os.path.isfile(env_path):
        return env_path
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

def get_allowlist_path():
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
        return 0
    if not isinstance(payload, dict):
        return 0

    tool_call = payload.get("toolCall", {})
    if not isinstance(tool_call, dict):
        return 0
    
    tool_name = tool_call.get("name", "")
    args = tool_call.get("args", {})
    entry_id = os.environ.get("PANOPTICON_ENTRY_ID")
    
    # 1. Read Guard
    if tool_name in ("view_file", "grep_search", "find_by_name", "list_dir", "run_command"):
        # For run_command, we could just block it or rely on it not being in the shell.
        # But if it's there, we should be careful. Actually, tool_policy_enforced handles Bash.
        
        scope_path = get_scope_path()
        try:
            with open(scope_path, "r", encoding="utf-8") as f:
                scope_map = json.load(f)
        except (OSError, ValueError):
            scope_map = {}
            
        if not entry_id:
            # If no entry ID, it's either the orchestrator or not a confined agent.
            # We let it pass if it's orchestrator, but typically hooks apply to all.
            # In panopticon, if no PANOPTICON_ENTRY_ID, we allow it (orchestrator).
            pass
        elif entry_id not in scope_map:
            print(json.dumps({"decision": "deny", "reason": "No read scope defined for this entry"}))
            return 0
        else:
            scope = scope_map[entry_id]
            if not scope:
                print(json.dumps({"decision": "deny", "reason": "Entry is confined to an empty scope"}))
                return 0
                
            # Check paths
            path = None
            if tool_name == "view_file":
                path = args.get("AbsolutePath")
            elif tool_name == "grep_search":
                path = args.get("SearchPath")
            elif tool_name == "find_by_name":
                path = args.get("SearchDirectory")
            elif tool_name == "list_dir":
                path = args.get("DirectoryPath")
                
            if path:
                # Path resolution
                path = os.path.abspath(path)
                allowed = False
                for d in scope.get("dirs", []):
                    if path == d or path.startswith(d + os.sep):
                        allowed = True
                        break
                for f in scope.get("files", []):
                    if path == f:
                        allowed = True
                        break
                
                if not allowed:
                    print(json.dumps({"decision": "deny", "reason": f"Path {path} is outside the allowed read scope"}))
                    return 0

    # 2. Write Guard
    if tool_name == "write_to_file":
        allowlist_path = get_allowlist_path()
        try:
            with open(allowlist_path, "r", encoding="utf-8") as f:
                allowlist_map = json.load(f)
        except (OSError, ValueError):
            allowlist_map = {}
            
        if not entry_id:
            pass
        elif entry_id not in allowlist_map:
            print(json.dumps({"decision": "deny", "reason": "No write allowlist defined for this entry"}))
            return 0
        else:
            allowlist = allowlist_map[entry_id]
            if not allowlist:
                print(json.dumps({"decision": "deny", "reason": "Entry is confined to an empty write allowlist"}))
                return 0
            
            target = args.get("TargetFile")
            if target:
                target = os.path.abspath(target)
                if target not in allowlist:
                    print(json.dumps({"decision": "deny", "reason": f"Path {target} is not in the write allowlist"}))
                    return 0

    print(json.dumps({"decision": "allow"}))
    return 0

if __name__ == "__main__":
    sys.exit(main())
