"""Per-run isolated `HOME` for headless `agy` reviewer launches (#3493).

`agy` discovers user/global hooks from ``~/.gemini/config/hooks.json``,
registered agent shells from ``~/.gemini/config/agents/``, MCP servers from
``~/.gemini/antigravity-cli/mcp/``, and project customizations by walking up
from `cwd` to the repository root (`.git`). It offers no `--hooks-file` or
`--setting-sources` CLI flag.

To confine every headless `agy` launch without touching the operator's real
``~/.gemini/`` tree and without letting the operator's global hooks, MCP
servers, rules, skills, or `.gemini/agents/` shadow shells leak into the review:

1. `build()` creates a fresh `0700` directory `<run_home>` outside `review_root`
   (under `/tmp` or `/var/tmp`, space-free).
2. Inside `<run_home>/.gemini/antigravity-cli/`, ONLY `antigravity-oauth-token`
   is symlinked from the operator's `~/.gemini/antigravity-cli/` (never `mcp/`,
   `brain/`, `knowledge/`, `implicit/`, `annotations/`, or the operator's
   `settings.json`), plus a minimal `settings.json` with
   `{"agentMode": "accept-edits", "allowNonWorkspaceAccess": true}`. Setting
   `agentMode: "accept-edits"` allows `write_file` to execute non-interactively
   in headless `-p` mode once our `PreToolUse` hook allows the entry's declared
   `out_file`. Setting `allowNonWorkspaceAccess: true` turns off `agy`'s own
   workspace sandbox so the child (running in `<run_home>/workspace`) can reach
   `review_root`, making our `PreToolUse` hook (`agy_guard_hook.py`) the only
   read/write boundary.
3. Inside `<run_home>/.gemini/config/`, `agents` is symlinked to the emitted
   `~/.gemini/config/agents` directory, and `hooks.json` registers a single
   `PreToolUse` hook with `"matcher": "*"` invoking `agy_guard_hook.py`.
4. Inside `<run_home>/workspace/`, a minimal Git ceiling
   `.git/{HEAD,objects,refs}` stops `agy`'s ancestor walk at
   `<run_home>/workspace`.
"""
import atexit
import os
import signal
import shutil
import sys
import tempfile

import scripts.guard_rules as guard_rules
import scripts.hosts as hosts


TOOL_VOCABULARY = {
    "1.5": frozenset({
        "read_file", "grep_search", "find_by_name", "list_dir",
        "write_file", "edit_file", "run_command", "manage_task",
        "invoke_subagent", "define_subagent", "manage_subagents",
        "send_message", "schedule", "search_web", "ask_question",
        "finish",
    }),
}

HOOK_MATCHER = "*"
HOOK_TIMEOUT_SECONDS = 30
OAUTH_TOKEN_FILE = "antigravity-oauth-token"

# #3576: what an operator is told when no agy sign-in is reachable from a run home.
# agy 1.5.6 keeps its token in the macOS login Keychain, which an isolated HOME
# cannot reach, and the token file is only its fallback: an interactive agy
# session that refreshes the token deletes the file.
AUTH_UNREACHABLE = (
    "agy auth not reachable from the isolated HOME: agy is not authenticated there "
    "(~/.gemini/antigravity-cli/%s is missing; agy may now keep its sign-in only in "
    "the macOS Keychain, which a panopticon run home cannot reach). Sign in with an "
    "interactive `agy` session until that file exists, then re-run (#3576)." % OAUTH_TOKEN_FILE)


class AgyAuthUnreachable(RuntimeError):
    """No agy sign-in would be reachable from the run home (#3576).

    Raised by `build()` before any child launches, so no paid work starts and
    no child can fall back to a browser sign-in."""

    def __init__(self):
        super().__init__(AUTH_UNREACHABLE)
SETTINGS_FILE = "settings.json"
HOOKS_FILE = "hooks.json"
WORKSPACE_DIR = "workspace"
_HOME_PARENTS = ("/tmp", "/var/tmp")

_LIVE_HOMES: set[str] = set()
_PREV_SIGTERM = None
_SIGNAL_INSTALLED = False


def _hook_script():
    return os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "agy_guard_hook.py")


def _interpreter():
    executable = sys.executable
    if not executable or not os.path.isabs(executable):
        raise RuntimeError(
            "agy guard hook interpreter is unavailable or not absolute: %r"
            % (executable,))
    executable = os.path.realpath(executable)
    if not os.path.isfile(executable) or not os.access(executable, os.X_OK):
        raise RuntimeError(
            "agy guard hook interpreter is unavailable: %s" % executable)
    return executable


def hook_command(read_scope_path, write_allowlist_path):
    """Shell-quoted command string for `<run_home>/.gemini/config/hooks.json`."""
    return guard_rules.hook_command(
        _interpreter(), "-I", _hook_script(),
        os.path.abspath(read_scope_path),
        os.path.abspath(write_allowlist_path))


def hooks_document(read_scope_path, write_allowlist_path, *, matcher=HOOK_MATCHER):
    """The `hooks.json` structure written to `<run_home>/.gemini/config/hooks.json`."""
    return {
        "panopticon-guard": {
            "PreToolUse": [
                {
                    "matcher": matcher,
                    "hooks": [
                        {
                            "type": "command",
                            "command": hook_command(read_scope_path, write_allowlist_path),
                            "timeout": HOOK_TIMEOUT_SECONDS,
                        }
                    ],
                }
            ]
        }
    }


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
            home = tempfile.mkdtemp(prefix="panopticon-agy-", dir=parent)
        except OSError:
            continue
        if " " not in home and not _inside(home, review_root):
            os.chmod(home, 0o700)
            return home
        shutil.rmtree(home, ignore_errors=True)
    raise RuntimeError(
        "cannot create a space-free temporary directory for the agy home outside %r "
        "(tried TMPDIR=%r and %s)" % (review_root, default, ", ".join(_HOME_PARENTS)))


def _init_workspace_ceiling(home):
    """Create `<home>/workspace/.git/{HEAD,objects,refs}` so `agy` stops its
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
    """Create and populate the isolated per-run `HOME` for `agy`."""
    real_user_home = (os.path.abspath(user_home) if user_home
                      else os.path.expanduser("~"))
    row = hosts.spec("agy")
    reg_dir = (registration_dir
               if registration_dir is not None
               else (row.registration_dir if row else ""))
    if user_home and registration_dir is None:
        reg_dir = os.path.join(real_user_home, ".gemini", "config", "agents")

    # #3576: refuse before a home exists. A missing or dangling token file used to
    # be skipped silently, and every child then fell back to a browser sign-in.
    src_token = os.path.join(real_user_home, ".gemini", "antigravity-cli", OAUTH_TOKEN_FILE)
    if not os.path.isfile(src_token):
        raise AgyAuthUnreachable()

    _ensure_signal_handler()
    home = _create_home(review_root)
    _LIVE_HOMES.add(home)
    try:
        cli_dir = os.path.join(home, ".gemini", "antigravity-cli")
        cfg_dir = os.path.join(home, ".gemini", "config")
        os.makedirs(cli_dir, mode=0o700, exist_ok=True)
        os.makedirs(cfg_dir, mode=0o700, exist_ok=True)

        # Change 1: symlink ONLY `antigravity-oauth-token` from the user's
        # `~/.gemini/antigravity-cli/`. Never symlink `mcp/`, `brain/`,
        # `knowledge/`, `implicit/`, `annotations/`, or user `settings.json`.
        dst_token = os.path.join(cli_dir, OAUTH_TOKEN_FILE)
        os.symlink(os.path.abspath(src_token), dst_token)

        # Minimal isolated CLI settings: allow reaching `review_root` outside
        # `<run_home>/workspace` and enable `accept-edits` so `write_file`
        # executes in headless `-p` mode once our `"*"` PreToolUse hook allows
        # the entry's declared `out_file`.
        guard_rules.atomic_write_json(
            os.path.join(cli_dir, SETTINGS_FILE),
            {"agentMode": "accept-edits", "allowNonWorkspaceAccess": True},
            indent=2)

        # Link the registered enforcement shells into `<run_home>/.gemini/config/agents`.
        dst_agents = os.path.join(cfg_dir, "agents")
        if reg_dir and os.path.isdir(reg_dir):
            os.symlink(os.path.abspath(reg_dir), dst_agents)
        else:
            os.makedirs(dst_agents, mode=0o700, exist_ok=True)

        # Write the `"*"` PreToolUse guard hook configuration.
        guard_rules.atomic_write_json(
            os.path.join(cfg_dir, HOOKS_FILE),
            hooks_document(read_scope_path, write_allowlist_path, matcher=matcher),
            indent=2)

        # Create `<run_home>/workspace/.git` ceiling.
        _init_workspace_ceiling(home)
    except Exception:
        _LIVE_HOMES.discard(home)
        if not _LIVE_HOMES:
            _restore_signal_handler()
        shutil.rmtree(home, ignore_errors=True)
        raise
    return home


def _strip_secrets(path):
    """Remove the OAuth token and agents links when retaining a failed `<run_home>`."""
    for rel in (os.path.join(".gemini", "antigravity-cli", OAUTH_TOKEN_FILE),
                os.path.join(".gemini", "config", "agents")):
        target = os.path.join(path, rel)
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
