"""The runner seam (spec 4.4): one entry in, its final text out.

A family PR ships `runners/<host>.py` with a `Runner(host)` class deriving
HostRunner; the loop owns the pool, the guards and the ledger. R-P6-1: the
contract lives here rather than in __init__ (layout rule: docstring-only).
"""
import concurrent.futures
import dataclasses
import importlib
import os
import time

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
# The loop's per-launch ledger, beside the settings file in the run folder.
# Named here for the same one-owner reason: `orchestrate.Ledger` writes it
# and the usage probe names it as the headless evidence surface, and the two
# must not spell it differently.
LEDGER_FILE = "dispatch-ledger.jsonl"
MODES = ("headless", "session")


def _utc(epoch):
    """The one UTC stamp format the run's evidence is written in -- the same
    one `orchestrate.Ledger` writes its `ts` in, so a row's three stamps sort
    against each other as plain strings."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


class LaunchRefused(RuntimeError):
    """The suite's structural guard refusing to start a real host CLI.

    Raised only by the fake `tests/conftest.py` installs over every seam's
    `DEFAULT_RUNNER` (`LAUNCH_SEAMS`). It lives HERE, on the seam contract,
    because it is the one exception every family's launch path has to agree
    about: the Codex family PR first needed it and the Kimi family PR wrote a
    second class of the same name, and a refusal that two `except` clauses
    disagree about guarantees nothing. `scripts.codex_host.LaunchRefused`
    still names this class, so every call site that already caught it is
    unchanged.

    Its own type, deliberately, and NOT an OSError: the probes map every other
    exception to UNKNOWN and an `except OSError` on a launch path would
    swallow it, so a test that actually reached a live `claude` / `codex` /
    `kimi` would read as a green "runtime unavailable". Every seam re-raises
    this one instead.
    """


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
    # The binary this runner launches, and the argv tokens that make ONE
    # launch print the parseable envelope its usage figures are read from
    # (claude: `-p --output-format`; codex: `exec --json`).
    #
    # Declared here because they are part of the seam, not a private detail:
    # `probes.claude._headless_usage_source` reads both off a claiming host's
    # runner, asks the CLI it finds on PATH to advertise exactly these flags
    # in its `--help`, and only then believes the ledger. Before #1626 I3
    # they were requirements a family could learn about only from an
    # `except Exception` whose detail then named the wrong problem.
    #
    # Empty is legal and honest, not a stub to fill in: a runner leaving
    # either empty reads `unknown` for `usage_ledger`, with a detail saying
    # which one is missing. A host whose usage evidence is not a launch
    # envelope at all (kimi reads a session wire file, and maps
    # `usage_ledger` to its own probe) leaves ENVELOPE_FLAGS empty on
    # purpose. What must NOT happen is a vacuous `proven` -- no flags means
    # no flags missing from `--help`, which is why the probe decides on the
    # VALUE rather than merely on the attribute existing.
    CLI = ""
    ENVELOPE_FLAGS = ()
    # A scratch directory OUTSIDE the reviewed tree that this runner's children
    # write into, once `prepare` has made one; None for a host that needs none
    # (claude arms a settings file in the run folder and keeps nothing else).
    # The loop reads it off the runner after `prepare` and hands it to the
    # probes, so an effective-surface probe can find this run's children
    # without opening a file in the target -- N2: a path recorded in the
    # reviewed tree is the target's to rewrite, and evidence read through it
    # is the target's to forge.
    run_home = None
    # Handed over by the loop BEFORE prepare(), so a runner can decide what to
    # arm from the namespace it is preparing for -- `"setup"` under `--setup`,
    # None otherwise -- and can name the request its entries came from.
    # runners/session.py documents both in full; they live here because every
    # runner is given them and the Codex runner reads `namespace` in prepare().
    dispatch_request = None
    namespace = None
    # M-9: whether `--max-turns` reaches anything on this host. The loop sets
    # `runner.max_turns` unconditionally, so a runner with no native turn
    # limit accepted the flag and ignored it in silence. True by default --
    # the seam's reference implementation honours it -- and a family that
    # cannot says so here, once, instead of documenting it in prose.
    HONOURS_MAX_TURNS = True

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

    def launch_env(self, overlay=None):
        """The environment a child of THIS runner starts under.

        ONE env preparation per runner (#1626 I2). `run_entry` used to build
        its child environment inline, which meant `host_probes` -- which
        launches the SAME binary to read its `--help` and decide whether the
        usage ledger is real -- had no way to reuse it and passed no `env` at
        all. The interrogation therefore ran under an environment the runner
        never uses: it works today only because `--help` is answered at
        argparse level, and the day a host's nested-session refusal moves
        earlier in start-up, every self-scan run from inside a session
        measures the wrong thing.

        `overlay` is the loop's three-key BINDING OVERLAY (spec 4.4), or None
        where there is no entry to bind -- a probe's `--help` has none. The
        default is `os.environ` plus the overlay, and a family that needs
        more overrides this ONE method: claude drops `CLAUDECODE` (a nested
        `claude -p` refuses to start inside a Claude Code session), kimi
        points `KIMI_CODE_HOME` at this run's home and drops its own
        nested-session markers, codex needs nothing beyond the default and so
        does not override it.

        Always a fresh dict: callers hand the result straight to a subprocess
        call and some of them mutate it, and returning `os.environ` itself
        would leak one launch's preparation into this process.
        """
        env = dict(os.environ)
        env.update(overlay or {})
        return env

    def run_entry(self, entry, env):
        raise NotImplementedError("a host runner must implement run_entry")

    def iter_batch(self, entries, concurrency, env_for):
        """Run every entry through run_entry on a thread pool, yielding
        `(entry, result, timing)` in COMPLETION order; an exception becomes
        RunResult.failed. `timing` is
        `{"started_at", "finished_at", "duration_ms"}`, measured around
        run_entry INSIDE the worker -- the only place that knows when this
        entry really ran -- and `duration_ms` is what the loop's ledger row
        records.

        A family implements `run_entry` and inherits this; nothing here is
        host-specific, and no family overrides it (only the session runner
        overrides `run_batch`, below). P07 (#1636): the loop persists and
        ledgers each entry AS IT ARRIVES, so a batch that is interrupted keeps
        everything already yielded. Entries still running when the interrupt
        lands finish during the pool drain and are NOT persisted -- their
        futures are never consumed; capturing them is out of scope.

        The pool's `with` block still JOINS every future on exit: nothing is
        cancelled, whether this generator is exhausted, closed, or unwound by
        an exception raised at the yield. Deliberate, and depended upon --
        children already launched are registered under guard files the loop
        tears down afterwards, so a runner that stripped its scratch config
        before the drain would leave every remaining child running fail-open
        (tests/runners/test_kimi.py). Callers that may abandon the generator
        mid-batch should close it deterministically (`contextlib.closing`)
        rather than leave the drain to garbage collection.
        """
        entries = list(entries)
        if not entries:
            return
        width = max(1, int(concurrency or self.default_concurrency))

        def one(entry):
            started, clock = time.time(), time.monotonic()
            try:
                result = self.run_entry(entry, env_for(entry))
            except Exception as exc:          # a runner crash is a failed entry, never a crashed loop
                result = RunResult.failed(entry.get("id"), exc)
            # elapsed off the MONOTONIC clock, the stamps off it too (a wall
            # clock that steps mid-entry must not print a finish before its
            # own start, nor a negative duration into the ledger).
            elapsed = time.monotonic() - clock
            return entry, result, {"started_at": _utc(started),
                                   "finished_at": _utc(started + elapsed),
                                   "duration_ms": int(elapsed * 1000)}

        with concurrent.futures.ThreadPoolExecutor(max_workers=width) as pool:
            futures = [pool.submit(one, e) for e in entries]
            for f in concurrent.futures.as_completed(futures):
                yield f.result()

    def run_batch(self, entries, concurrency, env_for):
        """Drain iter_batch; results in ENTRY order, one per entry. The session
        runner overrides this to print the batch and return None; every other
        caller that wants progress uses iter_batch instead."""
        entries = list(entries)
        slots = {}
        for i, entry in enumerate(entries):
            slots.setdefault(id(entry), []).append(i)   # by identity: entries are dicts
        results = [None] * len(entries)
        for entry, result, _timing in self.iter_batch(entries, concurrency, env_for):
            results[slots[id(entry)].pop(0)] = result
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
