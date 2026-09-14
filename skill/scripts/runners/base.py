"""The runner seam (spec 4.4): one entry in, its final text out.

A family PR ships `runners/<host>.py` with a `Runner(host)` class deriving
HostRunner; the loop owns the pool, the guards and the ledger. R-P6-1: the
contract lives here rather than in __init__ (layout rule: docstring-only).
"""
import concurrent.futures
import dataclasses
import importlib

import scripts.read_guard_hook as read_guard_hook

# An alias of a definition from OUTSIDE this package (read_guard_hook is a
# top-level script, not a runners/ sibling) -- legal under layout rule 4,
# which bans only a package module re-exporting a SIBLING's name (the
# two-patch-target hazard rule 1 exists for). One env var, one owner
# (read_guard_hook), read here so callers never hand-spell the string.
ENV_ENTRY_ID = read_guard_hook.ENV_ENTRY_ID
ENV_WRITE_ALLOWLIST = "PANOPTICON_WRITE_ALLOWLIST"
ENV_READ_SCOPE = "PANOPTICON_READ_SCOPE"
SETTINGS_FILE = "host-settings.json"
# M5: the two guard files the loop writes into the run folder and the
# runner bakes into host-settings.json's hook commands. Both sides have to
# name the SAME file -- the guards are fail-closed while registered, so a
# hook pointed at a path nothing writes denies every guarded Read and Write
# in the fan-out. One owner, read by module attribute (layout rule 1).
ALLOWLIST_FILE = "write-allowlist.json"
SCOPE_FILE = "read-scope.json"
MODES = ("headless", "session")


@dataclasses.dataclass
class RunResult:
    entry_id: str
    ok: bool                 # the runner got a final text back
    text: str                # the agent's final message (empty when not ok)
    usage: dict              # {"input_tokens", "output_tokens", "cache_read_input_tokens", ...} or {}
    cost_usd: object         # float | None
    model: object            # str | None
    session_id: object       # str | None
    denials: list            # the host's permission_denials, verbatim
    error: object            # str | None: launch failure, non-zero exit, budget stop, timeout

    @classmethod
    def failed(cls, entry_id, error):
        return cls(entry_id=entry_id, ok=False, text="", usage={}, cost_usd=None,
                    model=None, session_id=None, denials=[], error=str(error))


class HostRunner:
    host = ""
    mode = "headless"
    default_concurrency = 1

    def __init__(self, host=None):
        if host:
            self.host = host

    def prepare(self, run_dir, review_root):
        """Write whatever the host needs before the first entry; idempotent."""

    def teardown(self, status=None):
        """Release whatever `prepare` acquired. The loop calls it exactly once,
        from `orchestrate._finish`, on every TERMINAL status -- never between
        iterations, which must be able to resume.

        `status` is that terminal status ("complete" | "error" | ...) so a
        runner can drop a scratch area on a clean finish and KEEP it for
        debugging otherwise; the kimi runner's per-run home (C1) is the first
        thing that needs it. Claude has nothing to release, so the default is
        nothing.
        """

    def run_entry(self, entry, env):
        raise NotImplementedError("a host runner must implement run_entry")

    def run_batch(self, entries, concurrency, env_for):
        """Run every entry through run_entry on a thread pool; results in entry
        order; an exception becomes RunResult.failed. The session runner
        overrides this to return None."""
        entries = list(entries)
        if not entries:
            return []
        width = max(1, int(concurrency or self.default_concurrency))
        results = [None] * len(entries)

        def one(i, entry):
            try:
                results[i] = self.run_entry(entry, env_for(entry))
            except Exception as exc:          # a runner crash is a failed entry, never a crashed loop
                results[i] = RunResult.failed(entry.get("id"), exc)

        with concurrent.futures.ThreadPoolExecutor(max_workers=width) as pool:
            futures = [pool.submit(one, i, e) for i, e in enumerate(entries)]
            for f in futures:
                f.result()
        return results


def _headless_module(host):
    """Import runners/<host>.py, or None when no such module exists.

    Narrow on purpose: a bare `except ImportError` would also swallow a
    genuinely broken runners/<host>.py (one whose own body fails to import
    something it needs), reading it as merely absent. Only a
    ModuleNotFoundError naming THIS module -- "scripts.runners.<host>" is not
    findable at all -- means "no headless runner"; any other ImportError
    (including a ModuleNotFoundError for a DIFFERENT, missing dependency
    inside runners/<host>.py) is the family's bug and must surface."""
    modname = "scripts.runners.%s" % host
    try:
        return importlib.import_module(modname)
    except ModuleNotFoundError as exc:
        if exc.name == modname:
            return None
        raise


def headless_available(host):
    mod = _headless_module(host)
    return mod is not None and hasattr(mod, "Runner")


def runner_for(host, mode):
    """The runner for (host, mode). Session mode always exists; headless mode
    exists only when the family shipped runners/<host>.py (spec 4.4, O3)."""
    if mode not in MODES:
        raise ValueError("unknown runner mode %r (expected one of %s)" % (mode, ", ".join(MODES)))
    if mode == "session":
        import scripts.runners.session as session_runner
        return session_runner.SessionRunner(host)
    mod = _headless_module(host)
    if mod is None or not hasattr(mod, "Runner"):
        raise ValueError("no headless runner for host %r; use --mode session" % host)
    return mod.Runner(host)
