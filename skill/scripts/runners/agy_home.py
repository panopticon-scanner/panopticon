"""Per-run configuration directory for headless `agy` reviewer launches
(#3493, #3613).

`agy` discovers user/global hooks, registered agent shells, MCP servers and
CLI settings under its gemini directory (``~/.gemini`` by default), and project
customizations by walking up from `cwd` to the repository root (`.git`).

Since agy's 2026-11-13 self-update its consumer sign-in lives only in the
macOS login Keychain, which Security.framework finds through the child's
`HOME` (#3605). So a child keeps the operator's real `HOME` and agy reaches
its own sign-in; panopticon never touches the Keychain. What is isolated is
agy's gemini directory: every launch passes `--gemini_dir <run>/gemini`, an
undocumented flag that REPLACES ``~/.gemini`` for hooks, agents, MCP and
settings (#3605 P1), so nothing the operator configured there leaks in.

1. `build()` creates a fresh `0700` directory `<run>` outside `review_root`
   (under `/tmp` or `/var/tmp`, space-free). Nothing is copied or linked from
   ``~/.gemini``.
2. `<run>/gemini/antigravity-cli/settings.json` holds
   `{"agentMode": "accept-edits", "allowNonWorkspaceAccess": true}`, plus
   `modelProvider: "gemini"` on the API-key route. `accept-edits` lets
   `write_file` run in headless `-p` mode once our `PreToolUse` hook allows the
   entry's declared `out_file`; `allowNonWorkspaceAccess` turns off agy's own
   workspace sandbox so the child (in `<run>/workspace`) can reach
   `review_root`, making our hook (`agy_guard_hook.py`) the read/write
   boundary, with #3607's Keychain path rules inside it.
3. `<run>/gemini/config/agents` links the emitted shells, `hooks.json`
   registers a single `"matcher": "*"` `PreToolUse` hook invoking
   `agy_guard_hook.py`, and `mcp_config.json` lists no servers: agy launches
   every listed server at start-up, even for `agy agents`.
4. `<run>/workspace/.git/{HEAD,objects,refs}` stops agy's ancestor walk at
   `<run>/workspace`.

The child still reads the rest of the operator's HOME as any process does (a
global gitconfig, for one); `--gemini_dir`, our hook and #3607's path rules
are the boundary, not HOME.
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

# #3576/#3613: the two ways an agy child can be signed in.
# - "signin": agy's own consumer sign-in, which it keeps in the macOS login
#   Keychain and reads through the operator's real HOME. panopticon cannot check
#   it beforehand without touching the Keychain, so the runner's preflight turn
#   is the check.
# - "key": a Gemini API key, `GEMINI_API_KEY` in the child's environment, with
#   `modelProvider: "gemini"` in the run's settings.json
#   (https://antigravity.google/docs/cli/reference/). Never written to disk.
# The sign-in is the default (owner rulings, 2026-11-12 and 2026-11-13): the
# consumer plan carries Carbon, the key route does not, and a stray key in a shell
# must not move a run to another model and per-token billing. The key route runs
# only when AUTH_ENV names it; nothing ever switches routes on its own.
AUTH_ENV = "PANOPTICON_AGY_AUTH"
AUTH_ROUTES = ("signin", "key")
KEY_ENV = "GEMINI_API_KEY"

AUTH_UNREACHABLE = (
    "agy is not authenticated: its preflight turn could not sign in. agy keeps its "
    "sign-in in the macOS Keychain and reads it itself through your HOME; panopticon "
    "never reads it. Sign in with an interactive `agy` session, or set %s=key with "
    "%s exported (API-key runs use gemini-4-argon-high in place of Carbon, which that "
    "route does not offer), then re-run (#3613)." % (AUTH_ENV, KEY_ENV))
# R2 (#3613): a failed sign-in never moves a run to the key route by itself.
KEY_NOT_CHOSEN = (" %s is set, but the key route runs only when you choose it: set "
                  "%s=key to use it." % (KEY_ENV, AUTH_ENV))


class AgyAuthUnreachable(RuntimeError):
    """No agy sign-in could be proven for the run (#3576, #3613).

    Raised before any entry launches, so no paid work starts and no child can
    fall back to a browser sign-in."""

    def __init__(self, message=AUTH_UNREACHABLE):
        super().__init__(message)


def auth_route(env=None):
    """"signin" or "key": the sign-in an agy child will use (#3576, #3613).

    Raises `AgyAuthUnreachable` when AUTH_ENV names a route that does not exist,
    or names the key route with no key. Never echoes the key."""
    env = os.environ if env is None else env
    forced = (env.get(AUTH_ENV) or "").strip()
    if forced and forced not in AUTH_ROUTES:
        raise AgyAuthUnreachable("%s must be one of %s" % (AUTH_ENV, ", ".join(AUTH_ROUTES)))
    if forced == "key":
        if not (env.get(KEY_ENV) or "").strip():
            raise AgyAuthUnreachable("%s=key but %s is not set (#3576)" % (AUTH_ENV, KEY_ENV))
        return "key"
    return "signin"


def unreachable(env=None):
    """The sign-in failure, naming the key route when a key is set but not chosen."""
    env = os.environ if env is None else env
    has_key = bool((env.get(KEY_ENV) or "").strip())
    return AgyAuthUnreachable(AUTH_UNREACHABLE + (KEY_NOT_CHOSEN if has_key else ""))


SETTINGS_FILE = "settings.json"
HOOKS_FILE = "hooks.json"
MCP_FILE = "mcp_config.json"
GEMINI_DIR = "gemini"
WORKSPACE_DIR = "workspace"
GEMINI_DIR_FLAG = "--gemini_dir"
# #3613: the line agy's own log writes when it loads our hooks.json from the run's
# gemini directory (agy 1.5.x, #3605 P1). The preflight's proof that --gemini_dir
# took effect; a format change fails closed with HOOK_LOAD_UNPROVEN.
HOOK_LOAD_PROOF = "loaded 1 named hooks from 1 hooks.json file(s)"
HOOK_LOAD_UNPROVEN = ("agy hook-load proof missing: no %r line in %s; agy's log format may "
                      "have changed, or --gemini_dir (undocumented) no longer moves its "
                      "configuration (#3613)")
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
    """Shell-quoted command string for `<run>/gemini/config/hooks.json`."""
    return guard_rules.hook_command(
        _interpreter(), "-I", _hook_script(),
        os.path.abspath(read_scope_path),
        os.path.abspath(write_allowlist_path))


def hooks_document(read_scope_path, write_allowlist_path, *, matcher=HOOK_MATCHER):
    """The `hooks.json` structure written to `<run>/gemini/config/hooks.json`."""
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


def gemini_dir(home):
    """The run's `--gemini_dir`: agy's configuration for this run, and nothing else."""
    return os.path.join(home, GEMINI_DIR)


def gemini_dir_argv(home):
    """`["--gemini_dir", <run>/gemini]`, which leads every agy argv (#3613)."""
    return [GEMINI_DIR_FLAG, gemini_dir(home)]


def agents_dir(home):
    return os.path.join(gemini_dir(home), "config", "agents")


def expected_agents(home):
    """The shell names the run links: each `<name>.md` in its agents directory."""
    try:
        names = os.listdir(agents_dir(home))
    except OSError:
        return frozenset()
    return frozenset(n[:-3] for n in names if n.endswith(".md") and len(n) > 3)


def listed_agents(stdout):
    """The agent names `agy agents` prints, one per line or as `- <name> ...`."""
    found = set()
    for line in (stdout or "").splitlines():
        s = line.strip()
        if not s or s.startswith(("Available", "Tools:")):
            continue
        if s.startswith("- "):
            s = (s[2:].split() or [""])[0]
        if s:
            found.add(s)
    return frozenset(found)


def _run_logs(home):
    """agy's own logs under this run, oldest first. The run directory is fresh, so
    every one of them is this run's -- written only if --gemini_dir took effect."""
    log_dir = os.path.join(gemini_dir(home), "antigravity-cli", "log")
    try:
        names = sorted(n for n in os.listdir(log_dir) if n.startswith("cli-") and n.endswith(".log"))
    except OSError:
        names = []
    return log_dir, [os.path.join(log_dir, n) for n in names]


def run_log_says(home, text):
    """Whether any of this run's agy logs contains `text`."""
    for path in _run_logs(home)[1]:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                if any(text in line for line in fh):
                    return True
        except OSError:
            continue
    return False


def hook_load_proven(home):
    """(True, "") when one of agy's logs under the run loaded our hooks.json, else
    (False, why). Any of them counts: on the key route `agy models` writes its own
    log before `agy agents` does (#3613)."""
    log_dir, logs = _run_logs(home)
    if logs and run_log_says(home, HOOK_LOAD_PROOF):
        return True, ""
    return False, HOOK_LOAD_UNPROVEN % (HOOK_LOAD_PROOF, log_dir)


def build(read_scope_path="", write_allowlist_path="", *, user_home=None,
          registration_dir=None, review_root=None, matcher=HOOK_MATCHER, route=None):
    """Create and populate the per-run directory whose `gemini/` is `--gemini_dir`.

    `route` is `auth_route()`'s answer when the caller already has it. `user_home`
    only locates the emitted shells when no `registration_dir` is given."""
    row = hosts.spec("agy")
    reg_dir = (registration_dir
               if registration_dir is not None
               else (row.registration_dir if row else ""))
    if user_home and registration_dir is None:
        reg_dir = os.path.join(os.path.abspath(user_home), ".gemini", "config", "agents")
    if route is None:
        route = auth_route()
    if route not in AUTH_ROUTES:
        raise AgyAuthUnreachable("unknown agy auth route (#3576)")

    _ensure_signal_handler()
    home = _create_home(review_root)
    _LIVE_HOMES.add(home)
    try:
        cli_dir = os.path.join(gemini_dir(home), "antigravity-cli")
        cfg_dir = os.path.join(gemini_dir(home), "config")
        os.makedirs(cli_dir, mode=0o700, exist_ok=True)
        os.makedirs(cfg_dir, mode=0o700, exist_ok=True)

        settings = {"agentMode": "accept-edits", "allowNonWorkspaceAccess": True}
        if route == "key":
            # agy reads GEMINI_API_KEY from the child's environment; the key itself
            # is never written here (#3576).
            settings["modelProvider"] = "gemini"
        guard_rules.atomic_write_json(os.path.join(cli_dir, SETTINGS_FILE), settings, indent=2)

        dst_agents = agents_dir(home)
        if reg_dir and os.path.isdir(reg_dir):
            os.symlink(os.path.abspath(reg_dir), dst_agents)
        else:
            os.makedirs(dst_agents, mode=0o700, exist_ok=True)

        guard_rules.atomic_write_json(
            os.path.join(cfg_dir, HOOKS_FILE),
            hooks_document(read_scope_path, write_allowlist_path, matcher=matcher),
            indent=2)
        # No MCP server starts with a review child (#3613).
        guard_rules.atomic_write_json(os.path.join(cfg_dir, MCP_FILE), {"mcpServers": {}},
                                      indent=2)

        _init_workspace_ceiling(home)
    except Exception:
        _LIVE_HOMES.discard(home)
        if not _LIVE_HOMES:
            _restore_signal_handler()
        shutil.rmtree(home, ignore_errors=True)
        raise
    return home


def _strip_secrets(path):
    """Remove the agents link when retaining a failed `<run>`; no credential is
    ever written there (#3613)."""
    for rel in (os.path.join(GEMINI_DIR, "config", "agents"),):
        target = os.path.join(path, rel)
        try:
            if os.path.islink(target) or os.path.isfile(target):
                os.unlink(target)
        except OSError:
            pass


def teardown(path, status):
    """Remove `<run>` on completion; strip the agents link when retained."""
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
