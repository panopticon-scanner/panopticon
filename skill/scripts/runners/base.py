"""The runner seam (spec 4.4): one entry in, its final text out.

A family PR ships `runners/<host>.py` with a `Runner(host)` class deriving
HostRunner; the loop owns the pool, the guards and the ledger. R-P6-1: the
contract lives here rather than in __init__ (layout rule: docstring-only).
"""
import concurrent.futures
import dataclasses
import importlib
import os
import re
import shlex
import sys
import time

import scripts._version as version
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
# Named here for the same one-owner reason: `ledger.Ledger` writes it
# and the usage probe names it as the headless evidence surface, and the two
# must not spell it differently.
LEDGER_FILE = "dispatch-ledger.jsonl"
MODES = ("headless", "session")


def _utc(epoch):
    """The one UTC stamp format the run's evidence is written in -- the same
    one `ledger.Ledger` writes its `ts` in, so a row's three stamps sort
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


# #1623: the two classes a failed launch can belong to. `host` is the run's
# problem, not this entry's -- auth, quota, a rate limit, the provider down --
# and the loop refuses to charge an entry's attempt budget for one.
HOST_FAILURE = "host"
ENTRY_FAILURE = "entry"
# The provider-side symptoms, read case-insensitively out of the failure TEXT,
# which is where all three shipped families put the host's own words: claude
# composes "claude -p exited %s: %s" and "claude -p reported is_error: %s" from
# the envelope, kimi "kimi -p exited %s: %s" from stdout-or-stderr, and codex
# takes its `turn.failed`/`error` event's message verbatim. One host-agnostic
# reader therefore covers the shipped text, and a family that knows better
# passes `failure_class` at its own RunResult construction instead of teaching
# this list a fourth dialect.
_HOST_FAILURE_TEXT = (
    # the credential is refused
    "unauthorized", "unauthorised", "forbidden", "authentication",
    "invalid api key", "api key not", "no api key", "token expired",
    "expired token", "oauth", "please log in", "please login", "not logged in",
    "/login",
    # there is no money or allowance left
    "quota", "insufficient_quota", "billing", "payment required",
    "out of credits", "credit balance", "usage limit",
    # too fast
    "rate limit", "rate_limit", "ratelimit", "too many requests", "overloaded",
    # the provider itself
    "service unavailable", "bad gateway", "gateway timeout", "upstream",
    "temporarily unavailable", "internal server error",
)
# ...and the statuses they arrive as. Bounded on BOTH sides so that a duration
# ("kimi -p timed out after 403s"), a version, a path and a line number are not
# read as an HTTP status: no word character, dot, dash or slash before it, and
# no word character after.
_HOST_FAILURE_STATUS = re.compile(r"(?<![\w./-])(401|402|403|429|502|503|504|529)(?!\w)")


def classify_failure(error):
    """`HOST_FAILURE` when this failure was the HOST's rather than this entry's
    -- auth, quota, a rate limit, or the provider being down -- else
    `ENTRY_FAILURE` (#1623).

    Deliberately asymmetric. An unrecognised failure stays the entry's, which
    is what every failure was before this existed, so nothing a family already
    returns changes meaning. A false negative costs exactly what #1623 cost; a
    false positive stops a run that could have retried -- and the loop acts on
    it only when EVERY failure in a batch says the same thing, so one
    misread line in a mixed batch changes nothing at all.
    """
    text = ("" if error is None else str(error)).lower()
    if not text:
        return ENTRY_FAILURE
    if _HOST_FAILURE_STATUS.search(text) or any(m in text for m in _HOST_FAILURE_TEXT):
        return HOST_FAILURE
    return ENTRY_FAILURE


@dataclasses.dataclass
class RunResult:
    entry_id: str
    ok: bool                 # the runner got a final text back
    text: str                # the agent's final message; on a FAILED result, whatever partial
                             # output the launch had printed (D10 ruling 5) -- never persisted
                             # as an artifact, retained by the loop as evidence
    usage: dict              # {"input_tokens", "output_tokens", "cache_read_input_tokens", ...} or {}
    cost_usd: object         # float | None
    model: object            # str | None
    session_id: object       # str | None
    denials: list            # the host's permission_denials, verbatim
    error: object            # str | None: launch failure, non-zero exit, budget stop, timeout
    failure_class: object = None   # "host" | "entry" (#1623); None means "classify it for me"

    def __post_init__(self):
        """Classify any result that did not say (#1623).

        Here rather than only in `failed` because a family's non-zero-exit
        failure is built through the plain constructor -- `claude.parse_envelope`
        turns exit 1 into `RunResult(ok=False, error="claude -p exited 1: ...")`,
        which is precisely the shape a 403 arrives in on that host. A family
        that passes its own value keeps it: `dataclasses.replace` re-runs this,
        and an already-set class is never re-derived.
        """
        if self.failure_class is None:
            self.failure_class = classify_failure(self.error)

    @classmethod
    def failed(cls, entry_id, error, usage=None, text="", failure_class=None):
        """A failed entry, with whatever evidence the launch did produce.

        D10 ruling 5: a timed-out entry is often the most expensive one in a
        run, and this used to hard-code `usage={}` and drop the partial output
        -- so `Ledger.usage_document`, which counts failed rows precisely
        because those tokens were really spent, had nothing to count, and the
        one artefact that said what the entry had been doing was gone. A family
        passes what its envelope actually allows it to recover and nothing
        more: both default to empty, which is the honest answer for a host that
        prints its figures only at the end.
        """
        return cls(entry_id=entry_id, ok=False, text=text, usage=usage or {}, cost_usd=None,
                    model=None, session_id=None, denials=[], error=str(error),
                    failure_class=failure_class)


# #1623: the sentence a host-wide outage ends a run with. Two constants, the
# way the interrupt's are, because `docs/PANOPTICON.md` quotes the clause back
# and the guide test reads it off here rather than re-typing it.
HOST_OUTAGE_CLAUSE = ("no entry's attempt budget was charged and nothing was written, so "
                      "re-running the loop resumes this run where it stopped")
HOST_OUTAGE = ("paused: the %s host failed %d of this batch's %d launches with a %s-class "
               "failure (auth, quota, a rate limit, or the provider itself) rather than an "
               "entry-class one; last: %s; " + HOST_OUTAGE_CLAUSE + ", with the same flags, "
               "once the host is back: `%s`")


class FailureTally:
    """The loop's failure bookkeeping for one INVOCATION: which entries are
    stuck, and whether a batch was really the host going down (#1623).

    Consecutive failed launches per entry id, and that entry's last failure
    message (fix round 2). A launch the runner failed and a reply persist
    refused both count: neither advanced the entry, and neither gets likelier
    on the fortieth attempt. A clean, accepted launch clears the streak -- this
    bounds an entry that is STUCK, not one that is merely flaky.

    In memory, and per INVOCATION. In session mode that means a re-entry starts
    every entry at zero, deliberately: nothing there advances except a human
    persisting a reply that passes the phase's own done predicate, so the
    disk-evidence gate already bounds it -- there is no runaway to cap, and a
    streak that survived across invocations would refuse an operator their
    fourth honest attempt at a cell.

    Nothing is charged as it lands, though: "whose failure was that" is not
    answerable one result at a time. 243 of the 247 failed launches in the Kimi
    evidence run were a single 403, and charging each of them the moment it
    arrived is what spent every pending cell's budget on an outage and ended
    the run `complete` with an empty review axis. So a batch is charged when it
    CLOSES (`settle`), by which time the loop knows whether every failure in it
    said the same thing.

    It lives beside the classifier rather than in orchestrate.py so that the
    classification and every decision read off it have one owner -- and because
    orchestrate.py is an entry script at its line ceiling, where this would
    have gone in as forty more lines of loop body.
    """

    def __init__(self, host, args=None):
        self.host = host
        # The loop's own `args`, read ONLY through getattr and only to compose
        # the resume line: an operator told "re-run it" has to be told with
        # what. Nothing here imports argparse or requires a Namespace.
        self.args = args
        self.streaks = {}        # entry id -> consecutive CHARGED failures
        self.last_error = {}     # entry id -> that entry's last failure message
        self._batch = []         # (entry id, message, class or None) for the open batch

    def record(self, entry_id, result, refusal=None):
        """One landed entry: `result` as the runner returned it, and `refusal`
        the loop's own persist refusal -- which is panopticon's verdict on a
        launch that DID come back, so it is always the entry's own failure
        whatever the host would have said about it."""
        if refusal is not None:
            self._batch.append((entry_id, refusal, ENTRY_FAILURE))
        elif getattr(result, "ok", False):
            self._batch.append((entry_id, None, None))
        else:
            self._batch.append((entry_id, getattr(result, "error", None),
                                getattr(result, "failure_class", None) or ENTRY_FAILURE))

    def settle(self):
        """Close the batch: charge what it really proved, and return the
        operator's `paused` message when the whole of it was the host (else
        None). Called once per batch, whatever the outcome -- it is the charge,
        not just the verdict."""
        batch, self._batch = self._batch, []
        failures = [(eid, err, cls) for eid, err, cls in batch if cls is not None]
        for eid, err, cls in batch:
            if cls is None:
                self.streaks.pop(eid, None)          # a clean launch clears the streak
                continue
            self.last_error[eid] = err
            if cls == ENTRY_FAILURE:
                self.streaks[eid] = self.streaks.get(eid, 0) + 1
        if not failures or any(cls != HOST_FAILURE for _eid, _err, cls in failures):
            return None
        return HOST_OUTAGE % (self.host, len(failures), len(batch), HOST_FAILURE,
                              failures[-1][1], self.resume_command())

    def exhausted(self, pending, cap):
        """The `error` message for the first pending entry that has spent `cap`
        consecutive charged launches, or None. An entry the HOST failed never
        reaches it, because a host-class failure is never charged."""
        for entry in pending or ():
            eid = entry.get("id") if isinstance(entry, dict) else None
            if self.streaks.get(eid, 0) >= cap:
                return ("driver loop: entry %s failed %d consecutive launches; last: %s"
                        % (eid, self.streaks[eid], self.last_error.get(eid)))
        return None

    def resume_command(self):
        """The command that resumes this run once the host is back.

        The flags that RESOLVE the run, and no others: the review root
        (`target`, plus `--pr`/`--base`, whose worktree is the review root),
        the namespace, and the host and mode the loop settled on. Everything
        else the operator passed has to be passed again too -- the engine
        refuses a changed flag as run drift -- which is what "with the same
        flags" in the message says.
        """
        target = getattr(self.args, "target", None) or "."
        cmd = ["python3 skill/scripts/driver.py loop", shlex.quote(str(target))]
        if getattr(self.args, "pr", None):
            cmd += ["--pr", str(self.args.pr)]
        elif getattr(self.args, "base", None):
            cmd += ["--base", shlex.quote(str(self.args.base))]
        if getattr(self.args, "setup", False):
            cmd.append("--setup")
        cmd += ["--host", str(self.host),
                "--mode", str(getattr(self.args, "mode", None) or "headless")]
        return " ".join(cmd)


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
    # The argv flag that makes ONE launch constrain its final message to a
    # JSON Schema file, as a tuple of tokens the schema path follows
    # (`("--json-schema",)` for claude, `("--output-schema",)` for codex).
    #
    # D10 ruling 3, and the ONE optional attribute this seam gained for it
    # (docs/FAMILY-PR-GUARDRAILS.md section 3). Empty is the default and needs
    # no explanation: a CLI that advertises no such flag -- kimi today -- takes
    # none, and its `command()` is unchanged. A family that DOES declare one
    # appends `schema_argv(self.OUTPUT_SCHEMA_FLAG, entry)` to its argv, which
    # is empty unless the entry names a schema panopticon publishes; the
    # entry's `output_schema` key is stamped by the driver
    # (phases.persist.role_schema), because the runners package may not import
    # phases and should not have to know what a role is.
    OUTPUT_SCHEMA_FLAG = ()
    # The argv that makes this CLI print the help text listing the flags above
    # -- everything before the family's own `--help`, i.e. the SUBCOMMAND the
    # runner actually drives. `("--help",)` (claude, kimi) asks the binary
    # itself; codex overrides it with `("exec", "--help")` because
    # `--output-schema` belongs to `codex exec` and `codex --help` lists
    # subcommands, not their options (D10 N1).
    #
    # The second optional attribute this seam gained for ruling 3
    # (docs/FAMILY-PR-GUARDRAILS.md section 3), and it exists because the
    # cli-flags probe must not re-spell any family's argv: a family that moves
    # its flags behind a different subcommand moves this with them, and the
    # probe follows. It is a HELP read and nothing else -- no prompt, no
    # sandbox, no side effect -- and it goes through `Runner.runner`, the one
    # launcher the suite refuses live launches at.
    HELP_ARGV = ("--help",)
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
    # #1662: how long a terminated child is given to exit before it is killed,
    # and the bound on how long an INTERRUPTED batch waits for the workers
    # that were holding those children. Short on purpose -- a Ctrl-C means
    # stop, and the operator is watching a terminal.
    INTERRUPT_GRACE = 5.0

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

    def register_child(self, proc):
        """Record a live child, so a Ctrl-C can end it (#1662).

        `proc` is anything `subprocess.Popen`-shaped -- `terminate()`,
        `kill()`, `wait(timeout=)` are all this seam uses.

        Stored on the INSTANCE dict lazily rather than in `__init__`: a family
        (and several fakes in this suite) may define its own `__init__`
        without chaining to this one, and a registry that only exists when
        somebody remembered to call `super()` is a registry that silently
        holds nothing on the one host that needed it. `setdefault` and
        `append` are each atomic under the GIL, which is all the synchronising
        a list appended to from the pool's workers and read from the main
        thread needs.

        The three families shipped today launch through a blocking
        `subprocess.run`, which hands back no handle at all, so they register
        nothing and `terminate_children` is a no-op for them: an operator's
        terminal Ctrl-C already SIGINTs every child in the foreground process
        group, and what this module adds for those hosts is refusing to LAUNCH
        the rest of the batch and refusing to wait the running ones out. A
        family that adopts `Popen` -- or any host whose children leave the
        foreground group -- registers here and gets the path below.
        """
        self.__dict__.setdefault("_children", []).append(proc)

    def terminate_children(self, grace=None):
        """End every child this runner still has in flight -- `terminate()`
        (SIGTERM on POSIX), then `kill()` (SIGKILL) for whatever has not
        exited within `grace` -- and return the children it acted on (#1662).

        Called by `iter_batch` on the interrupt path, before the loop tears
        the guard files down. It installs NO signal handler and replaces none:
        `runners/kimi.py` chains a SIGTERM secret-stripper onto whatever was
        already registered, and an interrupt path that installed its own would
        unlink that chain. The registry is EMPTIED as it is read, so a second
        call is a no-op rather than a second kill at a pid the OS may since
        have reused.
        """
        grace = self.INTERRUPT_GRACE if grace is None else grace
        children = list(self.__dict__.get("_children") or ())
        self.__dict__["_children"] = []
        for proc in children:
            try:
                proc.terminate()
            except (OSError, ValueError):        # already gone
                pass
        deadline = time.monotonic() + max(0.0, float(grace))
        for proc in children:
            try:
                proc.wait(timeout=max(0.0, deadline - time.monotonic()))
            except Exception:    # noqa: BLE001 -- TimeoutExpired, or a handle that cannot wait
                try:
                    proc.kill()
                except (OSError, ValueError):
                    pass
        return children

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
        everything already yielded.

        #1662 -- Ctrl-C means complete stoppage. An interrupt (or a close:
        both arrive here as a BaseException at the yield) does three things,
        in this order:

        1. `shutdown(cancel_futures=True)`, so every work item still QUEUED is
           dropped and never launches. It used to be the opposite:
           `shutdown(wait=True)` queues its stop sentinel BEHIND every work
           item, so an interrupted batch still launched everything it had
           queued, persisted none of it (the futures are never consumed) and
           re-launched all of it on the resume. On a wide batch of slow
           entries that is minutes of work paid for and thrown away.
        2. `terminate_children()`, which ends what is already RUNNING rather
           than waiting it out. This runs BEFORE the loop tears the guard
           files down (`orchestrate._rolled_back` does that on the interrupt
           path, `_finish` otherwise -- both after this returns),
           because a child that outlived its guard would run unconfined --
           the ordering `tests/runners/test_kimi.py` pins.
        3. a BOUNDED wait on the workers that were holding those children
           (`INTERRUPT_GRACE`), instead of the unbounded join the `with`
           block used to perform.

        Up to `width` entries can still LAUNCH between the last yield and the
        cancel: every worker that finishes an entry takes the next queued item
        immediately, and nothing the consumer does can beat it, so a batch of
        twenty at width four can start eight before the cancel lands. That is
        the bound -- the pool, not a single slot, and never the whole batch.

        Callers that may abandon the generator mid-batch should close it
        deterministically (`contextlib.closing`) rather than leave the
        cancellation to garbage collection.
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

        pool = concurrent.futures.ThreadPoolExecutor(max_workers=width)
        futures, stopped = [], False
        try:
            futures = [pool.submit(one, e) for e in entries]
            for f in concurrent.futures.as_completed(futures):
                yield f.result()
        except BaseException:      # noqa: BLE001 -- KeyboardInterrupt and GeneratorExit both
            stopped = True
            pool.shutdown(wait=False, cancel_futures=True)
            try:
                self.terminate_children()
            except Exception as exc:   # noqa: BLE001 -- a family's teardown must not
                # replace the interrupt it was called for: the operator gets the
                # line, the loop gets its KeyboardInterrupt back below.
                print("%s: terminating this batch's children failed: %s: %s"
                      % (self.host or "runner", type(exc).__name__, exc),
                      file=sys.stderr, flush=True)
            concurrent.futures.wait([f for f in futures if not f.done()],
                                    timeout=self.INTERRUPT_GRACE)
            raise
        finally:
            # The normal path joins exactly as the old `with` block did (every
            # future is already done by then); the interrupted one has just
            # bounded its own wait and must not block again here.
            pool.shutdown(wait=not stopped)

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


def partial_output(exc):
    """Whatever a killed child had printed, as text (D10 ruling 5).

    `subprocess.TimeoutExpired` carries it UNDECODED even from a text-mode
    launch -- `communicate()` translates newlines only after it returns, and
    the timeout raises before that -- so bytes is the normal case and `errors
    ="replace"` keeps a truncated multi-byte character at the cut from
    throwing away the whole transcript. Empty for a launch that printed
    nothing, which is the same "no evidence" every other failure has.
    """
    out = getattr(exc, "stdout", None)
    if isinstance(out, bytes):
        return out.decode("utf-8", "replace")
    return out if isinstance(out, str) else ""


def published_schema(path):
    """`path` resolved, when it is one of the JSON Schemas panopticon PUBLISHES
    under `skill/reference/`; None for anything else.

    The containment rule for the one argv value a target could otherwise
    choose. An entry travels through `.panopticon/dispatch-request.json`, which
    lives inside the reviewed tree, so `output_schema` is the only path on a
    launch's argv that did not come from this process's own constants. Only a
    published schema is ever handed to a host CLI: a file that does not exist,
    or one outside that directory, reads as no schema at all rather than as an
    argument. `codex_host.validate_command` re-applies this to the FINISHED
    argv -- one rule, two places it has to hold.
    """
    if not isinstance(path, str) or not path:
        return None
    root = os.path.realpath(version.reference_path())
    real = os.path.realpath(path)
    if not real.startswith(root + os.sep) or not os.path.isfile(real):
        return None
    return real


def schema_argv(flag, entry):
    """The two argv tokens that constrain one launch's output, or [] (D10
    ruling 3). Empty whenever the family declares no flag, the entry names no
    schema, or the path it names is not published -- so a caller can append the
    result unconditionally."""
    schema = published_schema(entry.get("output_schema") if isinstance(entry, dict) else None)
    return [*flag, schema] if (flag and schema) else []


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
