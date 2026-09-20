"""The runner seam (spec 4.4): one entry in, its final text out.

A family PR ships `runners/<host>.py` with a `Runner(host)` class deriving
HostRunner; the loop owns the pool, the guards and the ledger. R-P6-1: the
contract lives here rather than in __init__ (layout rule: docstring-only).
"""
import concurrent.futures
import dataclasses
import importlib
import json
import os
import sys
import time

import scripts._version as version
import scripts.dispatch as dispatch
import scripts.read_guard_hook as read_guard_hook
import scripts.redact as redact
import scripts.runners.outage as outage

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
    host_error: object = None      # the HOST's own error surface (#1623): str | dict | None
                                   # -- the CLI's error line or the provider error object it
                                   # printed, NEVER the agent's text. `error` is the operator's
                                   # message and may quote the agent; this is what is classified.
    failure_class: object = None   # "host" | "entry" (#1623); None means "classify it for me"

    def __post_init__(self):
        """Classify any result that did not say (#1623).

        Here rather than only in `failed` because a family's non-zero-exit
        failure is built through the plain constructor -- `claude.parse_envelope`
        turns exit 1 into `RunResult(ok=False, error=...)`, which is one of the
        shapes a 403 arrives in. A family that passes its own value keeps it:
        `dataclasses.replace` re-runs this, and an already-set class is never
        re-derived.
        """
        if self.failure_class is None:
            self.failure_class = outage.classify_failure(self.host_error)

    @classmethod
    def failed(cls, entry_id, error, usage=None, text="", host_error=None,
               failure_class=None):
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
                    host_error=host_error, failure_class=failure_class)


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
    # JSON Schema, as a tuple of tokens the schema follows. Two shapes: codex's
    # `("--output-schema",)` takes the schema's PATH, claude's
    # `("--json-schema",)` takes its TEXT -- `schema_argv(..., inline=True)`,
    # see `inline_schema` for the measurement.
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
    # #1727: the sha256 the run manifest recorded for THAT file. Session mode
    # prints it so a host that reads the request itself can check it is
    # reading what this run wrote; a headless runner is handed its entries in
    # memory and needs nothing from it. Re-set per checkpoint, because the
    # request is rolling.
    request_sha256 = None
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

    def iter_batch(self, entries, concurrency, env_for, stop=None):
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

        #1721 -- `stop` is the COOPERATIVE version of that cancel, for the one
        thing the consumer knows and this seam cannot: the host has gone down,
        so launching the rest of the batch is 78 more launches at ~3 s each,
        each of them charged, before anyone can ask the question. It is
        evaluated once after each yield returns -- never before the first
        result -- and when it is true every work item still QUEUED is
        cancelled, exactly as the interrupt cancels it. Then the difference:
        the entries already IN FLIGHT are drained, yielded and persisted as
        usual, and NO child is terminated. An outage is not an interrupt; a
        launch in flight during one fails fast on its own, and killing it
        would throw away a reply that may still land.

        The bound on launches after `stop` says yes is the same pool width as
        above: up to `width` entries were already running when the answer came
        back, and those are the ones drained. Cancelled futures are skipped,
        never `.result()`-ed. A `stop` that RAISES is read as "carry on": it is
        the consumer's own predicate, not an interrupt, and letting it reach
        the arm below would terminate this batch's children.
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
            yielded, asked = set(), False
            for f in concurrent.futures.as_completed(futures):
                yielded.add(f)
                yield f.result()
                try:
                    asked = stop is not None and bool(stop())
                except Exception:      # noqa: BLE001 -- the consumer's own predicate, and
                    # a broken one means "carry on". Unwrapped it fell into the arm
                    # below, which terminates this batch's children -- the one thing
                    # the stop path promises never to do -- and re-raised into the loop.
                    asked = False
                if asked:
                    break
            if asked:
                # The cancel has to come first and the SURVIVORS be listed after
                # it: `shutdown(cancel_futures=True)` leaves a dropped work item
                # CANCELLED but never notified (nothing ever calls
                # `set_running_or_notify_cancel` on it), and `as_completed` waits
                # on such a future for ever. So the second pass is built from what
                # is left once the queue is provably drained -- the futures still
                # running, plus any that finished while the consumer was deciding.
                pool.shutdown(wait=False, cancel_futures=True)
                for f in concurrent.futures.as_completed(
                        [x for x in futures if x not in yielded and not x.cancelled()]):
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


# The largest token `inline_schema` will put on an argv. Linux caps a single
# argv string at MAX_ARG_STRLEN (128 KiB) and `execve` answers E2BIG, which
# the runner reports as a failed entry -- three burned launches per entry,
# the exact failure this helper exists to prevent. `skill/reference/` also
# publishes `ocrdb-0.5.0.json` (176 KB compacted), and a rewritten
# `dispatch-request.json` can name any published file (#1727 is unshipped),
# so the cap is what keeps "published" from meaning "launchable". Half the
# kernel limit, well above every schema stamped on an entry today (the
# largest, report-schema.json, compacts to ~40 KB).
INLINE_SCHEMA_MAX = 65536


def inline_schema(path):
    """The published schema at `path` as one line of JSON, for a CLI that takes
    the schema TEXT on its argv; None when `path` is not a published schema
    (`published_schema` is applied HERE, not only by the caller: a helper that
    opened whatever it was handed would turn the one target-chosen argv value
    into an arbitrary-file read that reaches the CLI), when the file is not a
    JSON object, or when the text exceeds `INLINE_SCHEMA_MAX`.

    Two CLIs, two shapes, one helper that used to know only one of them:
    codex's `--output-schema <FILE>` takes a path, claude's `--json-schema
    <schema>` takes the JSON itself. MEASURED 2026-09-20 on claude 2.1.276:
    the path form is refused ("--json-schema is not valid JSON: JSON Parse
    error: Unrecognized token '/'"), exit 1 in ~120 ms with no envelope -- so
    every return_json entry of every checkpoint burned its three launches, and
    run 14's tool-verify round (103 entries) stopped the driver. The `--help`
    probe that marks the flag `advertised` reads the flag's NAME and cannot
    see its shape; this is where the shape lives.

    None, not a raise, for a file that does not parse: the persist layer
    validates the reply against the same schema on receipt, so a launch
    without the flag is the fail-safe and a launch the CLI refuses is not."""
    path = published_schema(path)
    if path is None:
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    text = json.dumps(data, separators=(",", ":"))
    if len(text) > INLINE_SCHEMA_MAX:
        return None
    return text


def schema_argv(flag, entry, inline=False):
    """The two argv tokens that constrain one launch's output, or [] (D10
    ruling 3). Empty whenever the family declares no flag, the entry names no
    schema, or the path it names is not published -- so a caller can append the
    result unconditionally. `inline=True` hands the CLI the schema's JSON text
    instead of its path (`inline_schema`); the containment rule is the same
    either way, only a published file is ever read."""
    schema = published_schema(entry.get("output_schema") if isinstance(entry, dict) else None)
    if not (flag and schema):
        return []
    if inline:
        schema = inline_schema(schema)
        if schema is None:
            return []
    return [*flag, schema]


# The four registered enforcement shells, DERIVED from the one table that
# decides what a driver role is (#1720). Not a hand-kept list: a role added,
# renamed or retired in `dispatch.ROLE_FILES` moves the emitter, the
# readiness probe and this allowlist together, and a second spelling here
# would fail closed on exactly the shells the run had just registered.
REGISTERED_AGENT_NAMES = frozenset(
    dispatch.registered_agent_name(role_file)
    for role_file in dispatch.ROLE_FILES.values())
# `%r`, never `%s`: the value is the TARGET's, and this message is printed to
# the operator's stderr and stored in the ledger row. repr() renders a control
# character, an ANSI escape or an embedded newline as its escape sequence, so a
# refused value cannot repaint the terminal or forge a second log line.
UNREGISTERED_AGENT = "entry names an agent that is not a registered panopticon shell: %r"


def registered_agent(entry):
    """`entry["agent"]` when it is one of the four registered shells; None
    otherwise (#1720).

    The second containment rule on this seam, and for the same reason as
    `published_schema`: an entry travels through
    `.panopticon/dispatch-request.json`, which lives INSIDE the reviewed
    tree, so `agent` is a value a target can choose. Every family puts it on
    a launch's argv -- kimi joins it into a filesystem path and hands the
    result to `--agent-file=`, which IS the reviewer's governing
    instructions -- so a name outside this set is never launched and never
    silently downgraded to a bare launch.
    """
    name = entry.get("agent") if isinstance(entry, dict) else None
    # `isinstance` FIRST. The request is JSON from inside the reviewed tree, so
    # `agent` is as likely to arrive as an array or an object as it is a
    # string -- and `value in <frozenset>` raises `TypeError: unhashable type`
    # on either, straight out of `run_entry`, which never raises (spec 4.4).
    # A type check is what makes this a refusal rather than a crash.
    return name if isinstance(name, str) and name in REGISTERED_AGENT_NAMES else None


def refuse_unregistered_agent(entry):
    """The refusal every family returns for an enforced entry whose `agent` is
    not a registered shell -- including one carrying no `agent` at all, which
    used to fall through to the bare branch and launch unenforced while the
    ledger recorded an enforced entry. One message, one owner: three families
    refusing the same thing in three wordings is how a grep for this control
    finds two of them."""
    value = entry.get("agent") if isinstance(entry, dict) else None
    entry_id = entry.get("id") if isinstance(entry, dict) else None
    return RunResult.failed(entry_id, UNREGISTERED_AGENT % redact.redact(str(value)[:200]))


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
