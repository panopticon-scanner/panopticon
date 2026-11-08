#!/usr/bin/env python3
"""Gemini CLI (`@google/gemini-cli`) BeforeTool guard hook: read-scope,
write-allowlist, and strict tool-name + parameter allowlist adjudication for
headless panopticon reviewers (#3494, FAMILY-PR-GUARDRAILS).

`@google/gemini-cli` loads user/global hooks from ``~/.gemini/settings.json``
under ``hooks.BeforeTool`` and has no CLI flag for supplying a per-invocation
hooks file. Because `gemini`'s native ``BeforeTool`` matcher is a tool-name
regex or wildcard, narrowing the matcher to a fixed tool list would cause
`gemini` to skip the hook completely for any tool outside that list (e.g.
``run_shell_command``, ``replace``, ``read_many_files``) if an admin-policy
file ever drifted. The per-run home (``runners/gemini_home.py``) therefore
registers ONE ``BeforeTool`` hook entry with ``"matcher": "*"`` so every tool
call in the session is routed through this script:

    "matcher": "*" -> <driver python> -I <this file> <read_scope_path> <write_allowlist_path>

This script enforces four boundaries on every tool call:
1. Tool-name allowlist: only ``READ_TOOLS | WRITE_TOOLS`` may be adjudicated;
   any other tool name (``run_shell_command``, ``replace``, ``read_many_files``,
   ``web_fetch``, ``google_web_search``, etc.) is denied immediately.
2. Strict per-tool parameter allow-set (`TOOL_INPUT_KEYS`): any call whose
   ``tool_input`` carries a key outside the pinned ``@google/gemini-cli`` 0.55
   schema for that tool is denied before path resolution.
3. Entry binding: ``PANOPTICON_ENTRY_ID`` must be present and non-empty in the
   per-entry subprocess environment (``@google/gemini-cli`` ``BeforeTool`` stdin
   carries ``{session_id, transcript_path, cwd, hook_event_name, timestamp,
   tool_name, tool_input, mcp_context}`` and never includes the prompt).
4. Authoritative ``argv`` policy paths & path confinement: policy paths come
   exclusively from ``argv`` (never from environment variables). ``write_file``
   is checked against the v2 per-entry ``write-allowlist.json``; ``read_file``,
   ``grep_search``, ``list_directory``, and ``glob`` are checked against the
   per-entry ``read-scope.json``. Every tool requires an explicit absolute path
   (``file_path`` or ``dir_path``); omitted or relative paths, climbing globs,
   and git pathspec magic (``:(top)``, ``:``) are denied.

`@google/gemini-cli` unmarshals ``BeforeTool`` stdout as ``DefaultHookOutput``
JSON: ``{"decision": "allow"}`` or ``{"decision": "deny", "reason": "..."}``.
Every internal failure path prints a deny and exits 0 (fail-closed).
"""
import json
import os
import sys


READ_TOOLS = frozenset({"read_file", "grep_search", "glob", "list_directory"})
WRITE_TOOLS = frozenset({"write_file"})
ALLOWED_TOOLS = READ_TOOLS | WRITE_TOOLS

# Pinned parameter schema from @google/gemini-cli 0.55.1
# (`packages/core/dist/src/tools/definitions/base-declarations.js` in
# `chunk-32XQ54AJ.js`). Any key outside a tool's allow-set is denied.
TOOL_INPUT_KEYS = {
    "read_file": frozenset({"file_path", "start_line", "end_line"}),
    "grep_search": frozenset({
        "pattern", "dir_path", "include_pattern", "exclude_pattern",
        "names_only", "max_matches_per_file", "total_max_matches",
        "fixed_strings", "case_sensitive", "context",
    }),
    "list_directory": frozenset({
        "dir_path", "ignore", "file_filtering_options",
    }),
    "glob": frozenset({
        "pattern", "dir_path", "case_sensitive",
        "respect_git_ignore", "respect_gemini_ignore",
    }),
    "write_file": frozenset({"file_path", "content"}),
}

ENV_DENIAL_LOG = "PANOPTICON_GEMINI_DENIAL_LOG"

# Every name this hook reads from guard_rules; the loader refuses a module that
# lacks one, so a renamed rule denies at load rather than crashing mid-call.
_GUARD_RULES_USED = (
    "MARKER_PREFIX", "ENV_ENTRY_ID", "UNBOUND_ENTRY", "SCOPE_KEYS",
    "ALLOWLIST_VERSION", "GLOB_PATTERN_DENIAL", "GIT_STORE_DENIAL",
    "ARTIFACT_DIR", "SYMLINKED_COMPONENT", "UNMEASURABLE_COMPONENT",
    "ESCAPED_ARTIFACT_TREE", "PARENT_COMPONENT", "_resolve_path", "_readable",
    "_in_dir_grant", "_glob_pattern_climbs", "_names_git_store", "_load_scope",
    "_load_allowlist", "_escaped_component", "_glob_refusal", "marker_of",
    "hook_command", "_trusted_hook_argv", "record_denial")

# NOTE: The loader stanza between LOADER_BEGIN and LOADER_END is byte-pinned
# across all five guard hooks by `tests/test_guard_rules.py::TestTheVendoredBytes`
# and must remain byte-identical to `read_guard_hook.py` / `write_guard_hook.py` /
# `kimi_guard_hook.py` / `agy_guard_hook.py`.
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
    MARKER_PREFIX = guard_rules.MARKER_PREFIX
    ENV_ENTRY_ID = guard_rules.ENV_ENTRY_ID
    UNBOUND_ENTRY = guard_rules.UNBOUND_ENTRY
    SCOPE_KEYS = guard_rules.SCOPE_KEYS
    ALLOWLIST_VERSION = guard_rules.ALLOWLIST_VERSION
    GLOB_PATTERN_DENIAL = guard_rules.GLOB_PATTERN_DENIAL
    GIT_STORE_DENIAL = guard_rules.GIT_STORE_DENIAL
    ARTIFACT_DIR = guard_rules.ARTIFACT_DIR
    SYMLINKED_COMPONENT = guard_rules.SYMLINKED_COMPONENT
    UNMEASURABLE_COMPONENT = guard_rules.UNMEASURABLE_COMPONENT
    ESCAPED_ARTIFACT_TREE = guard_rules.ESCAPED_ARTIFACT_TREE
    PARENT_COMPONENT = guard_rules.PARENT_COMPONENT


def _allow():
    print(json.dumps({"decision": "allow"}), flush=True)


def _deny(reason):
    print(json.dumps({"decision": "deny", "reason": str(reason)}), flush=True)


def _bind_entry(env, tool_name):
    """Bind the call to `PANOPTICON_ENTRY_ID` from the per-entry child environment.

    `@google/gemini-cli`'s `BeforeTool` stdin payload carries no prompt field
    (`HookEventHandler.fireBeforeToolEvent` in `chunk-32XQ54AJ.js`), so binding
    is enforced via `PANOPTICON_ENTRY_ID` on the one-entry-per-subprocess launch.
    """
    entry_id = env.get(guard_rules.ENV_ENTRY_ID)
    if not entry_id or not isinstance(entry_id, str) or not entry_id.strip():
        return None, ("%s is denied: this session is not bound to a panopticon "
                      "entry (no %s in the environment), and the per-run guard "
                      "confines everything it cannot bind"
                      % (tool_name, guard_rules.ENV_ENTRY_ID))
    return entry_id.strip(), ""


def _check_tool_input_keys(tool_name, tool_input):
    """Verify `tool_input` is a dict whose keys are a subset of `TOOL_INPUT_KEYS[tool_name]`."""
    if not isinstance(tool_input, dict):
        return "%s is denied: malformed tool input" % tool_name
    allowed_keys = TOOL_INPUT_KEYS.get(tool_name)
    if allowed_keys is None:
        return "%s is denied: tool is not on the reviewer allowlist" % tool_name
    unknown = sorted(str(k) for k in tool_input
                     if not isinstance(k, str) or k not in allowed_keys)
    if unknown:
        return ("%s is denied: unsupported tool_input key(s): %s"
                % (tool_name, ", ".join(unknown)))
    return ""


def _has_git_pathspec_magic(pattern):
    """True when `pattern` uses git pathspec magic (`:(top)`, `:^`, `:!`, etc.).

    `@google/gemini-cli`'s `grep_search` passes `include_pattern` and
    `exclude_pattern` after `--` to `git grep`, where leading `:` or `:(`
    invokes git pathspec magic (e.g. `:(top)**` escapes `cwd`/`dir_path` to the
    repository root).
    """
    stripped = pattern.lstrip()
    return stripped.startswith(":") or ":(" in pattern


def _validate_filter_pattern(tool_name, field_name, pattern):
    """Validate a glob/pathspec filter parameter (`include_pattern`, `exclude_pattern`, `pattern`)."""
    if not isinstance(pattern, str):
        return "%s is denied: malformed `%s` pattern" % (tool_name, field_name)
    if _has_git_pathspec_magic(pattern):
        return ("%s is denied: git pathspec magic in `%s` (%r) is forbidden"
                % (tool_name, field_name, pattern))
    if guard_rules._glob_pattern_climbs(pattern):
        return guard_rules.GLOB_PATTERN_DENIAL
    if guard_rules._names_git_store(pattern):
        return guard_rules.GIT_STORE_DENIAL
    return ""


def _decide_read(tool_name, tool_input, scope):
    """(allow, reason) for a bound entry's read_file/grep_search/list_directory/glob."""
    key_err = _check_tool_input_keys(tool_name, tool_input)
    if key_err:
        return False, key_err
    if tool_name == "read_file":
        raw = tool_input.get("file_path")
        if not isinstance(raw, str) or not os.path.isabs(raw):
            return False, "read_file is denied: file_path %r must be an absolute path" % (raw,)
        target = guard_rules._resolve_path(raw)
        if target is None:
            return False, "read_file is denied: unresolvable file_path %r" % (raw,)
        if os.path.isdir(target):
            return False, ("read_file of directory %s is outside your cell's scope; "
                           "the files you may read are listed in your prompt" % raw)
        if guard_rules._readable(target, scope):
            return True, ""
        return False, ("read_file of %s is outside your cell's scope; the files "
                       "you may read are listed in your prompt" % raw)
    if tool_name == "grep_search":
        raw = tool_input.get("dir_path")
        if not isinstance(raw, str) or not os.path.isabs(raw):
            return False, ("grep_search is denied: pass an absolute `dir_path` "
                           "from the list in your prompt (got %r)" % (raw,))
        target = guard_rules._resolve_path(raw)
        if target is None:
            return False, ("grep_search is denied: pass `dir_path` explicitly -- "
                           "a path from the list in your prompt")
        include_pattern = tool_input.get("include_pattern")
        if include_pattern is not None:
            pat_err = _validate_filter_pattern("grep_search", "include_pattern", include_pattern)
            if pat_err:
                return False, pat_err
        exclude_pattern = tool_input.get("exclude_pattern")
        if exclude_pattern is not None:
            pat_err = _validate_filter_pattern("grep_search", "exclude_pattern", exclude_pattern)
            if pat_err:
                return False, pat_err
        if os.path.isdir(target):
            if any(guard_rules._in_dir_grant(target, d) for d in scope["dirs"]):
                if include_pattern is not None:
                    refusal = guard_rules._glob_refusal(target, include_pattern, scope)
                    if refusal:
                        return False, refusal
                return True, ""
            return False, ("grep_search over a directory is denied in a confined cell: "
                           "search a file by its path; your cell's files are listed in "
                           "your prompt")
        if guard_rules._readable(target, scope):
            return True, ""
        return False, ("grep_search of %s is outside your cell's scope; the files "
                       "you may search are listed in your prompt" % raw)
    if tool_name == "list_directory":
        raw = tool_input.get("dir_path")
        if not isinstance(raw, str) or not os.path.isabs(raw):
            return False, ("list_directory is denied: pass an absolute `dir_path` "
                           "(got %r)" % (raw,))
        target = guard_rules._resolve_path(raw)
        if target is None:
            return False, "list_directory is denied: pass `dir_path` explicitly"
        if os.path.isdir(target) and any(
                guard_rules._in_dir_grant(target, d) for d in scope["dirs"]):
            return True, ""
        return False, ("list_directory is not available in a confined cell: your file "
                       "list is in your prompt")
    if tool_name == "glob":
        raw = tool_input.get("dir_path")
        if not isinstance(raw, str) or not os.path.isabs(raw):
            return False, ("glob is denied: pass an absolute `dir_path` "
                           "(got %r)" % (raw,))
        target = guard_rules._resolve_path(raw)
        if target is None:
            return False, "glob is denied: pass `dir_path` explicitly"
        if os.path.isdir(target) and any(
                guard_rules._in_dir_grant(target, d) for d in scope["dirs"]):
            pattern = tool_input.get("pattern")
            if pattern is not None:
                pat_err = _validate_filter_pattern("glob", "pattern", pattern)
                if pat_err:
                    return False, pat_err
            refusal = guard_rules._glob_refusal(
                target, "*" if pattern is None else pattern, scope)
            return (False, refusal) if refusal else (True, "")
        return False, ("glob is not available in a confined cell: your "
                       "file list is in your prompt")
    return False, "%s is denied: tool is not on the reviewer read allowlist" % tool_name


def _decide_write(tool_name, tool_input, allowlist, entry_id):
    """(allow, reason) for write_file against THIS entry's v2 allowlist grants."""
    granted = None if entry_id == guard_rules.UNBOUND_ENTRY else allowlist.get(entry_id)
    if granted is None:
        return False, ("%s is denied: the armed write allowlist names no grant "
                       "for this entry" % tool_name)
    key_err = _check_tool_input_keys(tool_name, tool_input)
    if key_err:
        return False, key_err
    raw = tool_input.get("file_path")
    if not isinstance(raw, str) or not os.path.isabs(raw):
        return False, "%s is denied: file_path %r must be an absolute path" % (tool_name, raw)
    try:
        absolute = os.path.abspath(raw)
        if os.path.islink(absolute):
            return False, ("%s to %s is denied: findings targets must not be "
                           "symlinks" % (tool_name, raw))
        fault = guard_rules._escaped_component(raw)
        if fault:
            return False, "%s to %s is denied: %s" % (tool_name, raw, fault)
        target = os.path.realpath(absolute)
    except (ValueError, OSError, TypeError):
        return False, "%s is denied: unresolvable file_path %r" % (tool_name, raw)
    if target in set(granted):
        return True, ""
    if any(target in paths for paths in allowlist.values()):
        return False, ("%s to %s is denied: this reviewer may write only its own "
                       "declared out_file; a peer entry's artifact is not writable"
                       % (tool_name, raw))
    return False, ("%s to %s is denied: it is not in this entry's grant -- a "
                   "reviewer may write only its own declared out_file, and an "
                   "armed allowlist that does not name it may be stale or from "
                   "another run" % (tool_name, raw))


def adjudicate(payload, read_scope_path="", write_allowlist_path="", *,
               mode=None, env=None):
    """(allow, reason) for one `gemini` BeforeTool hook payload."""
    if guard_rules is None:
        return False, "gemini guard: %s" % _GUARD_RULES_FAULT
    if not isinstance(payload, dict):
        return False, "gemini guard: malformed payload (not a JSON object)"
    tool_name = payload.get("tool_name", "")
    if not isinstance(tool_name, str) or not tool_name:
        return False, "gemini guard: missing tool_name in BeforeTool payload"
    if mode == "read" and tool_name not in READ_TOOLS:
        return False, ("%s is denied: tool is not on the reviewer read allowlist"
                       % tool_name)
    if mode == "write" and tool_name not in WRITE_TOOLS:
        return False, ("%s is denied: tool is not on the reviewer write allowlist"
                       % tool_name)
    if tool_name not in ALLOWED_TOOLS:
        return False, ("%s is denied: tool is not on the reviewer allowlist"
                       % tool_name)
    env = os.environ if env is None else env
    entry_id, bind_err = _bind_entry(env, tool_name)
    if entry_id is None:
        return False, bind_err
    tool_input = payload.get("tool_input")
    if tool_name in WRITE_TOOLS:
        allowlist, error = guard_rules._load_allowlist(write_allowlist_path)
        if allowlist is None:
            return False, error
        allow, reason = _decide_write(tool_name, tool_input, allowlist, entry_id)
    else:
        scopes, error = guard_rules._load_scope(read_scope_path)
        if scopes is None:
            return False, error
        scope = scopes.get(entry_id)
        if scope is None:
            return False, ("%s is denied: this agent is bound to entry %r, which "
                           "the armed read scope does not name"
                           % (tool_name, entry_id))
        allow, reason = _decide_read(tool_name, tool_input, scope)
    if not allow and reason:
        reason = "%s (bound to entry %r)" % (reason, entry_id)
    return allow, reason


def _sanitize_denial_args(args):
    """Drop `content`/`Content` (logging only `file_path` and `content_length`)
    and bound string values."""
    if not isinstance(args, dict):
        return {}
    if "content" in args or "Content" in args:
        content = args.get("content") if "content" in args else args.get("Content")
        return {
            "file_path": (args.get("file_path") if "file_path" in args
                          else args.get("Path", args.get("path"))),
            "content_length": len(content) if isinstance(content, str) else 0,
        }
    sanitized = {}
    for key, value in args.items():
        if isinstance(value, str) and len(value) > 200:
            sanitized[key] = value[:200]
        else:
            sanitized[key] = value
    return sanitized


def _record_gemini_denial(payload, reason, env):
    """Append a structured denial record to `PANOPTICON_GEMINI_DENIAL_LOG` when set."""
    log_path = (env.get(ENV_DENIAL_LOG) or "").strip()
    if not log_path:
        return
    try:
        tool_name = payload.get("tool_name", "") if isinstance(payload, dict) else ""
        raw_args = payload.get("tool_input") if isinstance(payload, dict) else {}
        args = _sanitize_denial_args(raw_args)
        line = json.dumps({"tool": str(tool_name), "args": args,
                           "reason": str(reason)}) + "\n"
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(line)
    except Exception:  # noqa: BLE001 -- never interfere with the printed decision
        pass


def main(argv=None, env=None):
    """`argv` is `[read_scope_path, write_allowlist_path]` (or `[mode, data_path]`).
    `argv` is strictly authoritative (environment variables never override policy
    paths). Always exits 0 and prints a `DefaultHookOutput` JSON object."""
    args = sys.argv[1:] if argv is None else list(argv)
    env = os.environ if env is None else env
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        _deny("gemini guard: malformed JSON on stdin")
        return 0
    except (RecursionError, MemoryError) as exc:
        _deny("gemini guard: payload too deep to adjudicate (%s)" % type(exc).__name__)
        return 0
    if not isinstance(payload, dict):
        _deny("gemini guard: payload is not a JSON object")
        return 0
    mode = None
    if len(args) >= 2 and args[0] in ("read", "write"):
        mode = args[0]
        read_scope_path = args[1] if mode == "read" else ""
        write_allowlist_path = args[1] if mode == "write" else ""
    elif len(args) >= 2:
        read_scope_path, write_allowlist_path = args[0], args[1]
    else:
        _deny("gemini guard: bad hook invocation %r -- expected "
              "[<read_scope_path>, <write_allowlist_path>]" % (args,))
        return 0
    try:
        allow, reason = adjudicate(
            payload, read_scope_path, write_allowlist_path, mode=mode, env=env)
    except Exception as exc:  # noqa: BLE001 -- fail CLOSED, never crash the hook
        _deny("gemini guard crashed: %s" % exc)
        return 0
    if allow:
        _allow()
        return 0
    _deny(reason)
    _record_gemini_denial(payload, reason, env)
    policy_path = write_allowlist_path or read_scope_path
    if guard_rules is not None and policy_path:
        guard_rules.record_denial(
            policy_path,
            {"tool_use_id": payload.get("session_id") and str(payload.get("session_id")) or "gemini",
             "tool_name": payload.get("tool_name", "")},
            reason)
    return 0


if __name__ == "__main__":
    sys.exit(main())
