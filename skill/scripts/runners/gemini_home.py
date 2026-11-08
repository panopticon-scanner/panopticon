"""Per-run isolated `GEMINI_CLI_HOME` for headless `gemini` (`@google/gemini-cli`)
reviewer launches (#3494).

`@google/gemini-cli` resolves all user/global state relative to
``homedir()`` (``GEMINI_CLI_HOME || os.homedir()``, `paths.js` in
`chunk-32XQ54AJ.js`):
- User settings and `BeforeTool` hooks: ``$GEMINI_CLI_HOME/.gemini/settings.json``
- User policies (Tier 4): ``$GEMINI_CLI_HOME/.gemini/policies/*.toml``
- User subagents: ``$GEMINI_CLI_HOME/.gemini/agents/*.md`` and ``$GEMINI_CLI_HOME/.agents/agents/*.md``
- User skills: ``$GEMINI_CLI_HOME/.gemini/skills/`` and ``$GEMINI_CLI_HOME/.agents/skills/``
- User memory: ``$GEMINI_CLI_HOME/.gemini/GEMINI.md``
- User OAuth credentials: ``$GEMINI_CLI_HOME/.gemini/oauth_creds.json`` and
  ``$GEMINI_CLI_HOME/.gemini/google_accounts.json``

To confine every headless `gemini` launch without touching the operator's real
``~/.gemini/`` tree and without letting the operator's global hooks, MCP
servers, extensions, skills, user policies, `GEMINI.md`, or `.gemini/agents/`
shadow shells leak into the review:

1. `build()` creates a fresh `0700` directory `<run_home>` outside `review_root`
   (under `/tmp` or `/var/tmp`, space-free) and outside `.panopticon`.
2. Inside `<run_home>/.gemini/` (mode `0700`), ONLY the operator's active auth
   credential files (`oauth_creds.json`, `google_accounts.json`) are copied
   with `O_NOFOLLOW` and mode `0600` (`state.json`, `installation_id`, `mcp/`,
   `extensions/`, `skills/`, `agents/`, `policies/`, `GEMINI.md`, and the
   operator's `settings.json` are never copied or linked).
3. `<run_home>/.gemini/settings.json` (mode `0600`) locks down every ambient
   discovery surface:
   - `admin.mcp.enabled = false`
   - `admin.extensions.enabled = false`
   - `admin.skills.enabled = false`
   - `experimental.enableAgents = false`
   - `general.plan.enabled = false`
   - `context.fileName = ".panopticon-no-context.md"` and
     `context.loadMemoryFromIncludeDirectories = false`
   - `security.folderTrust.enabled = false` (so `<run_home>/workspace` is
     trusted and `HookRegistry` loads the `BeforeTool` hook without prompting)
   - `hooks.BeforeTool`: a single entry with `"matcher": "*"` invoking
     `gemini_guard_hook.py` via `<driver python> -I`.
4. Inside `<run_home>/workspace/`, a minimal Git ceiling
   `.git/{HEAD,objects,refs}` stops `gemini`'s ancestor walk at
   `<run_home>/workspace`.
5. `teardown(path, status)` removes `<run_home>` completely on
   `status == "complete"` and strips `CREDENTIAL_FILES` on any other status,
   backed by `atexit` and `SIGTERM` cleanup handlers.
"""
import atexit
import json
import os
import shutil
import signal
import sys
import tempfile

import scripts.guard_rules as guard_rules
import scripts.hosts as hosts
import scripts.toml_values as toml_values


TOOL_VOCABULARY = {
    "0.55": frozenset({
        "read_file", "grep_search", "glob", "list_directory",
        "write_file", "replace", "run_shell_command", "read_many_files",
        "web_fetch", "google_web_search", "activate_skill", "ask_user",
        "invoke_agent", "codebase_investigator", "cli_help",
        "enter_plan_mode", "exit_plan_mode", "write_todos",
        "get_internal_docs", "update_topic", "complete_task",
        "tracker_create_task", "tracker_update_task", "tracker_get_task",
        "tracker_list_tasks", "tracker_add_dependency", "tracker_visualize",
        "read_mcp_resource", "list_mcp_resources", "save_memory",
    }),
}

HOOK_MATCHER = "*"
HOOK_TIMEOUT_MS = 30000
CREDENTIAL_FILES = ("oauth_creds.json", "google_accounts.json")
ALLOWED_AUTH_TYPES = frozenset({
    "oauth-personal",
    "gemini-api-key",
    "vertex-ai",
    "cloud-shell",
    "compute-default-credentials",
})
SETTINGS_FILE = "settings.json"
POLICIES_DIR = "policies"
UNENFORCED_POLICY_FILE = "unenforced.toml"
WORKSPACE_DIR = "workspace"
NO_CONTEXT_FILENAME = "%s-no-context.md" % guard_rules.ARTIFACT_DIR
_HOME_PARENTS = ("/tmp", "/var/tmp")

_LIVE_HOMES: set[str] = set()
_PREV_SIGTERM = None
_SIGNAL_INSTALLED = False


def _hook_script():
    return os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "gemini_guard_hook.py")


def _interpreter():
    executable = sys.executable
    if not executable or not os.path.isabs(executable):
        raise RuntimeError(
            "gemini guard hook interpreter is unavailable or not absolute: %r"
            % (executable,))
    executable = os.path.realpath(executable)
    if not os.path.isfile(executable) or not os.access(executable, os.X_OK):
        raise RuntimeError(
            "gemini guard hook interpreter is unavailable: %s" % executable)
    return executable


def hook_command(read_scope_path, write_allowlist_path):
    """Shell-quoted command string for `<run_home>/.gemini/settings.json`."""
    return guard_rules.hook_command(
        _interpreter(), "-I", _hook_script(),
        os.path.abspath(read_scope_path),
        os.path.abspath(write_allowlist_path))


def _detect_auth_type(real_user_home, seeded_oauth):
    """Return a validated `security.auth.selectedType` string when no env-based
    auth variable overrides it, or None when env auth (`GEMINI_API_KEY`, etc.)
    should take precedence."""
    for env_key in ("GEMINI_API_KEY", "GOOGLE_GENAI_USE_VERTEXAI",
                    "GOOGLE_GENAI_USE_GCA"):
        if (os.environ.get(env_key) or "").strip():
            return None
    user_settings = os.path.join(real_user_home, ".gemini", SETTINGS_FILE)
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(user_settings, flags)
        try:
            with os.fdopen(fd, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
        except Exception:
            doc = None
        if isinstance(doc, dict):
            sec = doc.get("security")
            auth = sec.get("auth") if isinstance(sec, dict) else None
            selected = auth.get("selectedType") if isinstance(auth, dict) else None
            if isinstance(selected, str) and selected in ALLOWED_AUTH_TYPES:
                return selected
    except OSError:
        pass
    if seeded_oauth:
        return "oauth-personal"
    return None


def settings_document(read_scope_path, write_allowlist_path, *,
                      matcher=HOOK_MATCHER, auth_type=None):
    """The `settings.json` structure written to `<run_home>/.gemini/settings.json`."""
    security: dict[str, object] = {
        "folderTrust": {"enabled": False},
    }
    if isinstance(auth_type, str) and auth_type in ALLOWED_AUTH_TYPES:
        security["auth"] = {"selectedType": auth_type}
    return {
        "admin": {
            "mcp": {"enabled": False},
            "extensions": {"enabled": False},
            "skills": {"enabled": False},
        },
        "experimental": {
            "enableAgents": False,
        },
        "general": {
            "plan": {"enabled": False},
        },
        "context": {
            "fileName": NO_CONTEXT_FILENAME,
            "loadMemoryFromIncludeDirectories": False,
        },
        "security": security,
        "hooksConfig": {
            "enabled": True,
        },
        "hooks": {
            "BeforeTool": [
                {
                    "matcher": matcher,
                    "hooks": [
                        {
                            "name": "panopticon-guard",
                            "type": "command",
                            "command": hook_command(read_scope_path, write_allowlist_path),
                            "timeout": HOOK_TIMEOUT_MS,
                        }
                    ],
                }
            ]
        },
    }


def render_policy_toml(allowed_tools, *, role=None, agent_name=None, model=None,
                       vocabulary=None):
    """Render a Tier 5 `--admin-policy` TOML document allowing `allowed_tools`
    (priority 900) and denying every other tool in `TOOL_VOCABULARY` plus all
    MCP tools (priority 950)."""
    vocab = (TOOL_VOCABULARY["0.55"] if vocabulary is None
             else frozenset(vocabulary))
    allowed_list = list(allowed_tools)
    allowed_set = frozenset(allowed_list)
    denied_list = sorted(vocab - allowed_set)
    lines = [
        "# Generated by panopticon dispatch.py -- DO NOT EDIT",
    ]
    if role is not None:
        lines.append("# panopticon-role: %s" % role)
    if agent_name is not None:
        lines.append("# panopticon-agent: %s" % agent_name)
    if role is not None or model is not None:
        lines.append("# panopticon-model: %s" % (model if model else "inherit"))
    lines.append("")
    for tool in allowed_list:
        lines.extend([
            "[[rule]]",
            "toolName = %s" % toml_values.value(str(tool), "toolName"),
            'decision = "allow"',
            "priority = 900",
            "",
        ])
    for tool in denied_list:
        lines.extend([
            "[[rule]]",
            "toolName = %s" % toml_values.value(str(tool), "toolName"),
            'decision = "deny"',
            "priority = 950",
            "",
        ])
    lines.extend([
        "[[rule]]",
        'mcpName = "*"',
        'toolName = "*"',
        'decision = "deny"',
        "priority = 950",
        "",
    ])
    return "\n".join(lines)


def unenforced_policy_path(home):
    return os.path.join(home, ".gemini", POLICIES_DIR, UNENFORCED_POLICY_FILE)


def _inside(path, root):
    if not root:
        return False
    real_path = os.path.realpath(path)
    real_root = os.path.realpath(root)
    return real_path == real_root or real_path.startswith(real_root + os.sep)


def _create_home(review_root=None):
    candidates = []
    default = tempfile.gettempdir()
    if " " not in default and not _inside(default, review_root):
        candidates.append(default)
    for parent in _HOME_PARENTS:
        if parent not in candidates and os.path.isdir(parent) \
                and " " not in parent and not _inside(parent, review_root):
            candidates.append(parent)
    for parent in candidates:
        try:
            home = tempfile.mkdtemp(prefix="panopticon-gemini-", dir=parent)
        except OSError:
            continue
        if " " not in home and not _inside(home, review_root):
            os.chmod(home, 0o700)
            return home
        shutil.rmtree(home, ignore_errors=True)
    raise RuntimeError(
        "cannot create a space-free temporary directory for the gemini home outside %r "
        "(tried TMPDIR=%r and %s)" % (review_root, default, ", ".join(_HOME_PARENTS)))


def _copy_credential_file(src, dst):
    """Copy a regular file with `O_NOFOLLOW` on both ends and mode `0600`.
    Refuses symlinks and non-regular files silently (returns False)."""
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        src_fd = os.open(src, os.O_RDONLY | nofollow)
    except OSError:
        return False
    try:
        st = os.fstat(src_fd)
        if not os.path.samestat(st, os.lstat(src)):
            return False
        with os.fdopen(src_fd, "rb") as rfh:
            src_fd = -1
            data = rfh.read()
    except OSError:
        if src_fd >= 0:
            os.close(src_fd)
        return False
    try:
        dst_fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, 0o600)
    except OSError:
        return False
    try:
        with os.fdopen(dst_fd, "wb") as wfh:
            dst_fd = -1
            wfh.write(data)
        os.chmod(dst, 0o600)
        return True
    except OSError:
        if dst_fd >= 0:
            os.close(dst_fd)
        try:
            os.unlink(dst)
        except OSError:
            pass
        return False


def _write_private_file(path, text):
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | nofollow, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.chmod(path, 0o600)


def _init_workspace_ceiling(home):
    """Create `<home>/workspace/.git/{HEAD,objects,refs}` so `gemini` stops its
    ancestor walk at `<home>/workspace`."""
    ws = os.path.join(home, WORKSPACE_DIR)
    git_dir = os.path.join(ws, ".git")
    os.makedirs(os.path.join(git_dir, "objects"), exist_ok=True)
    os.makedirs(os.path.join(git_dir, "refs"), exist_ok=True)
    with open(os.path.join(git_dir, "HEAD"), "w", encoding="utf-8") as fh:
        fh.write("ref: refs/heads/main\n")
    return ws


def workspace_dir(home):
    return os.path.join(home, WORKSPACE_DIR)


def build(read_scope_path="", write_allowlist_path="", *, user_home=None,
          registration_dir=None, review_root=None, matcher=HOOK_MATCHER):
    """Create and populate the isolated per-run `GEMINI_CLI_HOME` for `gemini`."""
    _ensure_signal_handler()
    real_user_home = (os.path.abspath(user_home) if user_home
                      else os.path.expanduser("~"))
    _ = registration_dir or hosts.spec("gemini")

    home = _create_home(review_root)
    _LIVE_HOMES.add(home)
    try:
        gemini_dir = os.path.join(home, ".gemini")
        policies_dir = os.path.join(gemini_dir, POLICIES_DIR)
        os.makedirs(gemini_dir, mode=0o700, exist_ok=True)
        os.makedirs(policies_dir, mode=0o700, exist_ok=True)
        os.chmod(gemini_dir, 0o700)
        os.chmod(policies_dir, 0o700)

        # P5: copy ONLY actual auth credential files (`oauth_creds.json`,
        # `google_accounts.json`) with `O_NOFOLLOW` and mode `0600`. Never copy
        # `state.json`, `installation_id`, `settings.json`, `GEMINI.md`, `mcp/`,
        # `extensions/`, `skills/`, or `agents/`.
        seeded_oauth = False
        for fname in CREDENTIAL_FILES:
            src_cred = os.path.join(real_user_home, ".gemini", fname)
            dst_cred = os.path.join(gemini_dir, fname)
            copied = _copy_credential_file(src_cred, dst_cred)
            if copied and fname == "oauth_creds.json":
                seeded_oauth = True

        auth_type = _detect_auth_type(real_user_home, seeded_oauth)
        settings_path = os.path.join(gemini_dir, SETTINGS_FILE)
        guard_rules.atomic_write_json(
            settings_path,
            settings_document(read_scope_path, write_allowlist_path,
                              matcher=matcher, auth_type=auth_type),
            indent=2)
        os.chmod(settings_path, 0o600)

        # Fallback policy for explicitly `--allow-unenforced` launches where
        # emitted per-role `.toml` shells may not be installed on disk: still
        # confines `gemini` to the 5 reviewer tools and denies shell/edit/web/MCP.
        _write_private_file(
            unenforced_policy_path(home),
            render_policy_toml(
                ("read_file", "grep_search", "glob", "list_directory", "write_file"),
                role="unenforced"))

        _init_workspace_ceiling(home)
    except Exception:
        _LIVE_HOMES.discard(home)
        if not _LIVE_HOMES:
            _restore_signal_handler()
        shutil.rmtree(home, ignore_errors=True)
        raise
    return home


def _strip_secrets(path):
    """Remove copied credential files when retaining a failed `<run_home>`."""
    for fname in CREDENTIAL_FILES:
        target = os.path.join(path, ".gemini", fname)
        try:
            if os.path.islink(target) or os.path.isfile(target):
                os.unlink(target)
        except OSError:
            pass


def teardown(path, status):
    """Remove `<run_home>` on completion; strip secrets when retained."""
    if not path:
        return
    _LIVE_HOMES.discard(path)
    if not _LIVE_HOMES:
        _restore_signal_handler()
    if status == "complete":
        shutil.rmtree(path, ignore_errors=True)
    else:
        _strip_secrets(path)


def _atexit_cleanup():
    for path in list(_LIVE_HOMES):
        _LIVE_HOMES.discard(path)
        shutil.rmtree(path, ignore_errors=True)
    _restore_signal_handler()


def _ensure_signal_handler():
    global _SIGNAL_INSTALLED, _PREV_SIGTERM
    if _SIGNAL_INSTALLED:
        return
    try:
        prev = signal.getsignal(signal.SIGTERM)

        def _on_sigterm(signum, frame):
            _atexit_cleanup()
            if callable(prev):
                prev(signum, frame)
            else:
                signal.signal(signal.SIGTERM, signal.SIG_DFL)
                os.kill(os.getpid(), signal.SIGTERM)

        signal.signal(signal.SIGTERM, _on_sigterm)
        _PREV_SIGTERM = prev
        _SIGNAL_INSTALLED = True
    except (ValueError, OSError):
        pass


def _restore_signal_handler():
    global _SIGNAL_INSTALLED, _PREV_SIGTERM
    if not _SIGNAL_INSTALLED:
        return
    prev = _PREV_SIGTERM
    _SIGNAL_INSTALLED = False
    _PREV_SIGTERM = None
    try:
        signal.signal(signal.SIGTERM, signal.SIG_DFL if prev is None else prev)
    except (ValueError, OSError):
        pass


atexit.register(_atexit_cleanup)
