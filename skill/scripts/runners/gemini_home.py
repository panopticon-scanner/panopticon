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
   with `O_NOFOLLOW | O_NONBLOCK`, `S_ISREG` verification, and mode `0600`
   (`state.json`, `installation_id`, `mcp/`, `extensions/`, `skills/`,
   `agents/`, `policies/`, `GEMINI.md`, and the operator's `settings.json` are
   never copied or linked).
3. `<run_home>/.gemini/settings.json` (mode `0600`) locks down every user-level
   ambient discovery surface (`SETTINGS_SCHEMA` in `chunk-CBP73R2W.js`):
   - `mcpServers = {}` and `mcp.allowed = []`
   - `skills.enabled = false`
   - `experimental.enableAgents = false`
   - `general.plan.enabled = false`
   - `context.loadMemoryFromIncludeDirectories = false` (and `context.fileName`
     is omitted so `DEFAULT_CONTEXT_FILENAME = "GEMINI.md"` is not expanded by
     additive `setGeminiMdFilename`)
   - `security.folderTrust.enabled = false` (so `<run_home>/workspace` is
     trusted and `HookRegistry` loads the `BeforeTool` hook without prompting)
   - `hooks.BeforeTool`: a single entry with `"matcher": "*"` invoking
     `gemini_guard_hook.py` via `<driver python> -I`.
4. Inside `<run_home>/workspace/`, a minimal Git ceiling
   `.git/{HEAD,objects,refs}` stops `gemini`'s ancestor walk at
   `<run_home>/workspace`.
5. `teardown(path, status)` removes `<run_home>` completely on
   `status == "complete"` and wipes `<run_home>/.gemini/` apart from diagnostic
   `settings.json` and `policies/` on any other status, backed by `atexit` and
   `SIGTERM` cleanup handlers.
"""
import atexit
import json
import os
import shutil
import signal
import stat
import sys
import tempfile

import scripts.guard_rules as guard_rules
import scripts.model_resolver as model_resolver
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

GEMINI_TOOL_FOR = {
    "Read": "read_file",
    "Grep": "grep_search",
    "Glob": "glob",
    "Write": "write_file",
}

HOOK_MATCHER = "*"
HOOK_TIMEOUT_MS = 30000
CREDENTIAL_FILES = ("oauth_creds.json", "google_accounts.json")
RUNTIME_SECRET_FILES = (
    "oauth_creds.json",
    "google_accounts.json",
    "gemini-credentials.json",
    "mcp-oauth-tokens.json",
)
ALLOWED_AUTH_TYPES = frozenset({
    "oauth-personal",
    "gemini-api-key",
    "vertex-ai",
    "cloud-shell",
    "compute-default-credentials",
})
SETTINGS_FILE = "settings.json"
SYSTEM_DEFAULTS_FILE = "system-defaults.json"
POLICIES_DIR = "policies"
UNENFORCED_POLICY_FILE = "unenforced.toml"
WORKSPACE_DIR = "workspace"
DIAGNOSTIC_PRESERVE = frozenset({SETTINGS_FILE, POLICIES_DIR})
ENV_SYSTEM_SETTINGS = "GEMINI_CLI_SYSTEM_SETTINGS_PATH"
ENV_SYSTEM_DEFAULTS = "GEMINI_CLI_SYSTEM_DEFAULTS_PATH"
_HOME_PARENTS = ("/tmp", "/var/tmp")

_LIVE_HOMES: set[str] = set()
_PREV_SIGTERM = None
_SIGNAL_INSTALLED = False


def gemini_tools(tp):
    """Map a neutral template `tool_policy` dict to `@google/gemini-cli` tool names."""
    reads = [GEMINI_TOOL_FOR[t] for t in tp["allowed"]
             if t in GEMINI_TOOL_FOR and t != "Write"]
    return (reads
            + (["list_directory"] if reads else [])
            + (["write_file"] if "Write" in tp["allowed"] else []))


def render_shell(role, agent, _meta, tp):
    """Render one `panopticon-<role>.toml` Tier 5 `--admin-policy` shell."""
    model = model_resolver.registration_model("gemini", role)
    return render_policy_toml(gemini_tools(tp), role=role, agent_name=agent, model=model)


def default_system_config_dir(platform=None):
    """Return `@google/gemini-cli`'s `Storage.getSystemConfigDir()` path."""
    plat = sys.platform if platform is None else platform
    if plat == "darwin":
        return "/Library/Application Support/GeminiCli"
    if plat.startswith("win"):
        return r"C:\ProgramData\gemini-cli"
    return "/etc/gemini-cli"


def system_policy_hazards(env=None, system_config_dir=None):
    """Return a list of system-level `@google/gemini-cli` files or env overrides
    that would supersede `--admin-policy` or `<run_home>/.gemini/settings.json`.

    In `chunk-32XQ54AJ.js` (`createPolicyEngineConfig`), if any `*.toml` exists
    in `Storage.getSystemPoliciesDir()`, `adminPolicyPaths` (`--admin-policy`)
    is silently discarded (`adminPolicyPaths = void 0`). And in
    `chunk-CBP73R2W.js` (`loadSettings`), system `settings.json` and
    `system-defaults.json` merge above/around user settings.
    """
    check_env = os.environ if env is None else env
    sys_dir = (default_system_config_dir() if system_config_dir is None
               else system_config_dir)
    hazards: list[str] = []
    for var in (ENV_SYSTEM_SETTINGS, ENV_SYSTEM_DEFAULTS):
        val = (check_env.get(var) or "").strip()
        if val:
            hazards.append("env %s=%r is set" % (var, val))
    if not sys_dir:
        return hazards
    policies_dir = os.path.join(sys_dir, POLICIES_DIR)
    try:
        entries = sorted(os.listdir(policies_dir))
    except (FileNotFoundError, NotADirectoryError):
        entries = []
    except OSError as exc:
        hazards.append(
            "system policies directory %s is unreadable (%s), cannot rule out --admin-policy override"
            % (policies_dir, exc.strerror or exc))
        entries = []
    toml_files = [name for name in entries if name.lower().endswith(".toml")]
    if toml_files:
        hazards.append(
            "system policy file(s) in %s (%s) silently disable --admin-policy"
            % (policies_dir, ", ".join(toml_files)))
    for fname in (SETTINGS_FILE, SYSTEM_DEFAULTS_FILE):
        fpath = os.path.join(sys_dir, fname)
        try:
            if os.path.lexists(fpath):
                hazards.append("system config file %s is present" % fpath)
        except OSError as exc:
            hazards.append("system config file %s could not be stat'd (%s)"
                           % (fpath, exc.strerror or exc))
    return hazards


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


MISSING_API_KEY_REMEDY = (
    "export GEMINI_API_KEY in the shell that runs panopticon. "
    "A key saved through gemini's sign-in dialog is not visible to the isolated run home."
)


def _read_user_selected_auth_type(real_user_home):
    """Read `security.auth.selectedType` (or legacy `selectedAuthType`) from
    `<real_user_home>/.gemini/settings.json` without following symlinks."""
    if not real_user_home:
        return None
    user_settings = os.path.join(real_user_home, ".gemini", SETTINGS_FILE)
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(user_settings, flags)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                os.close(fd)
                fd = -1
                doc = None
            else:
                with os.fdopen(fd, "r", encoding="utf-8") as fh:
                    fd = -1
                    doc = json.load(fh)
        except Exception:
            if fd >= 0:
                os.close(fd)
            doc = None
        if isinstance(doc, dict):
            sec = doc.get("security")
            auth = sec.get("auth") if isinstance(sec, dict) else None
            selected = auth.get("selectedType") if isinstance(auth, dict) else None
            if not (isinstance(selected, str) and selected):
                selected = doc.get("selectedAuthType")
            if isinstance(selected, str) and selected in ALLOWED_AUTH_TYPES:
                return selected
    except OSError:
        pass
    return None


def _detect_auth_type(real_user_home, seeded_oauth, env=None):
    """Return a validated `security.auth.selectedType` string when no env-based
    auth variable overrides it, or None when env auth (`GEMINI_API_KEY`, etc.)
    should take precedence."""
    check_env = os.environ if env is None else env
    for env_key in ("GEMINI_API_KEY", "GOOGLE_GENAI_USE_VERTEXAI",
                    "GOOGLE_GENAI_USE_GCA"):
        val = check_env.get(env_key)
        if isinstance(val, str) and val.strip():
            return None
    selected = _read_user_selected_auth_type(real_user_home)
    if selected:
        return selected
    if seeded_oauth:
        return "oauth-personal"
    return None


def auth_hazard(env=None, real_user_home=None):
    """Return an actionable remedy when `selectedType == 'gemini-api-key'` in
    `~/.gemini/settings.json` and `GEMINI_API_KEY` (or Vertex/GCA env auth) is
    unset or empty in the launch environment. Never reads or echoes any secret."""
    home = os.path.expanduser("~") if real_user_home is None else real_user_home
    if _detect_auth_type(home, False, env=env) == "gemini-api-key":
        return (
            "gemini auth selectedType is 'gemini-api-key' in ~/.gemini/settings.json, "
            "but GEMINI_API_KEY is unset or empty in the launch environment: %s"
            % MISSING_API_KEY_REMEDY
        )
    return None


def host_auth_hazard(host, env=None, real_user_home=None):
    """Host-agnostic wrapper for readiness checks."""
    if host != "gemini":
        return None
    return auth_hazard(env=env, real_user_home=real_user_home)


def ledger_model_reroute(ledger_path, bound_by_role=None):
    """Inspect `dispatch-ledger.jsonl` for silent Gemini model reroutes.

    Returns `(False, detail)` if any `gemini` entry recorded an envelope `model`
    different from its `requested_model` (or its role's bound model), else
    `(True, 'ok')`."""
    if not ledger_path or not os.path.isfile(ledger_path):
        return True, "no ledger"
    try:
        with open(ledger_path, encoding="utf-8") as fh:
            for idx, raw in enumerate(fh, 1):
                line = raw.strip()
                if not line:
                    continue
                rec = json.loads(line)
                if not isinstance(rec, dict) or rec.get("host") != "gemini":
                    continue
                actual = rec.get("model")
                requested = rec.get("requested_model")
                if not (isinstance(requested, str) and requested.strip()) and isinstance(bound_by_role, dict):
                    role = rec.get("role") or ("scout" if rec.get("checkpoint") == "scout" else None)
                    requested = bound_by_role.get(role) if isinstance(role, str) else None
                if (isinstance(requested, str) and requested.strip()
                        and isinstance(actual, str) and actual.strip()
                        and actual != requested):
                    entry_id = rec.get("entry_id") or rec.get("id") or ("line-%d" % idx)
                    return False, (
                        "dispatch-ledger.jsonl entry %r (line %d) bound model %r, "
                        "but the envelope reported %r (silent model reroute)"
                        % (entry_id, idx, requested, actual)
                    )
    except (OSError, ValueError):
        pass
    return True, "ok"


def settings_document(read_scope_path, write_allowlist_path, *,
                      matcher=HOOK_MATCHER, auth_type=None):
    """The `settings.json` structure written to `<run_home>/.gemini/settings.json`."""
    security: dict[str, object] = {
        "folderTrust": {"enabled": False},
    }
    if isinstance(auth_type, str) and auth_type in ALLOWED_AUTH_TYPES:
        security["auth"] = {"selectedType": auth_type}
    return {
        "mcpServers": {},
        "mcp": {
            "allowed": [],
        },
        "skills": {
            "enabled": False,
        },
        "experimental": {
            "enableAgents": False,
        },
        "general": {
            "plan": {"enabled": False},
        },
        "context": {
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
    (priority 900), explicitly denying every other tool in `TOOL_VOCABULARY`
    plus all MCP tools (priority 950), and installing a Tier 5 catch-all deny
    (`toolName = "*"`, priority 100) that outranks `yolo.toml` (Tier 1, 1.998)."""
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
        'toolName = "*"',
        'decision = "deny"',
        "priority = 100",
        "",
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
    """Copy a regular file with `O_NOFOLLOW | O_NONBLOCK` on open, `S_ISREG`
    verification on `fstat`, and mode `0600` on destination. Refuses symlinks,
    FIFOs, and non-regular files silently (returns False)."""
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    nonblock = getattr(os, "O_NONBLOCK", 0)
    try:
        src_fd = os.open(src, os.O_RDONLY | nofollow | nonblock)
    except OSError:
        return False
    try:
        st = os.fstat(src_fd)
        if not stat.S_ISREG(st.st_mode) or not os.path.samestat(st, os.lstat(src)):
            os.close(src_fd)
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
          review_root=None, matcher=HOOK_MATCHER):
    """Create and populate the isolated per-run `GEMINI_CLI_HOME` for `gemini`."""
    _ensure_signal_handler()
    real_user_home = (os.path.abspath(user_home) if user_home
                      else os.path.expanduser("~"))

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
        # `google_accounts.json`) with `O_NOFOLLOW | O_NONBLOCK`, `S_ISREG`,
        # and mode `0600`. Never copy `state.json`, `installation_id`,
        # `settings.json`, `GEMINI.md`, `mcp/`, `extensions/`, `skills/`, or
        # `agents/`.
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

        # Fallback policy for explicitly `--allow-unenforced` launches: grants
        # read-only reviewer tools (`read_file`, `grep_search`, `glob`,
        # `list_directory`) and denies `write_file`, shell, edit, web, and MCP.
        _write_private_file(
            unenforced_policy_path(home),
            render_policy_toml(
                ("read_file", "grep_search", "glob", "list_directory"),
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
    """Wipe credentials and runtime state under `<run_home>/.gemini/` when
    retaining a failed `<run_home>`, preserving only diagnostic `settings.json`
    and `policies/`."""
    gemini_dir = os.path.join(path, ".gemini")
    for fname in RUNTIME_SECRET_FILES:
        target = os.path.join(gemini_dir, fname)
        try:
            if os.path.islink(target) or os.path.isfile(target):
                os.unlink(target)
        except OSError:
            pass
    try:
        entries = list(os.listdir(gemini_dir))
    except OSError:
        return
    for name in entries:
        if name in DIAGNOSTIC_PRESERVE:
            continue
        target = os.path.join(gemini_dir, name)
        try:
            if os.path.islink(target) or not os.path.isdir(target):
                os.unlink(target)
            else:
                shutil.rmtree(target, ignore_errors=True)
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
