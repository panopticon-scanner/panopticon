"""The runner seam (spec 4.4): one entry in, its final text out.

A family PR ships `runners/<host>.py` with a `Runner(host)` class deriving
HostRunner; the loop owns the pool, the guards and the ledger. R-P6-1: the
contract lives here rather than in __init__ (layout rule: docstring-only).
"""
import concurrent.futures
import dataclasses
import importlib
import os
import sys
import time

import scripts.dispatch as dispatch
import scripts.read_guard_hook as read_guard_hook
import scripts.runners.children as children
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
# #1576 (OPS-2112448973): the ONE ceiling on how many host CLIs a batch runs
# at once. `driver loop --concurrency` is a `_positive_int` with no upper
# bound and `default_concurrency` is whatever a family declares, so nothing
# stopped a 500-wide pool of real process trees, each one charged.
#
# A flat number, and the largest measured family default (claude's 8; kimi
# bursted into exit-1s at 8 and ships 4). NOT cpu-derived: these children are
# network-bound CLIs whose cost is tokens and rate limit, not local cores, and
# a 2-core CI runner running 8 of them is the shape this suite already
# assumes. Applied in exactly one place -- `HostRunner.batch_width` -- because
# a second clamp in `driver.py`'s argument parser is a second ceiling, and two
# ceilings can disagree.
MAX_CONCURRENCY = 8


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
    stderr: object = None          # #1732: what the CLI printed on stderr, on a FAILED result
                                   # only -- `stderr_head` characters, already redacted. The
                                   # DIAGNOSIS, beside `error`'s symptom: run 14 failed 309
                                   # launches with "claude -p printed no JSON envelope (exit 1)"
                                   # while the reason ("--json-schema is not valid JSON: JSON
                                   # Parse error: Unrecognized token '/'") sat on a stream this
                                   # family never read. Deliberately NOT fed to the classifier:
                                   # `host_error` is what decides whose failure it was, and
                                   # widening that input would read an entry's own stderr noise
                                   # as an outage.
    models: dict = dataclasses.field(default_factory=dict)  # host-reported per-model usage

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
               failure_class=None, stderr=None):
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
                    host_error=host_error, failure_class=failure_class, stderr=stderr)


class HostRunner(children.ChildProcesses):
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
    ENVELOPE_FLAGS: tuple[str, ...] = ()
    # The argv flag that makes ONE launch constrain its final message to a
    # JSON Schema, as a tuple of tokens the schema follows. Two shapes: codex's
    # `("--output-schema",)` takes the schema's PATH, claude's
    # `("--json-schema",)` takes its TEXT -- `schema.schema_argv(...,
    # inline=True)`, see `runners/schema.py` for both and for the
    # measurement.
    #
    # D10 ruling 3, and the ONE optional attribute this seam gained for it
    # (docs/FAMILY-PR-GUARDRAILS.md section 3). Empty is the default and needs
    # no explanation: a CLI that advertises no such flag -- kimi today -- takes
    # none, and its `command()` is unchanged. A family that DOES declare one
    # appends `schema.schema_argv(self.OUTPUT_SCHEMA_FLAG, entry)` to its
    # argv, which is empty unless the entry names a schema panopticon
    # publishes; the
    # entry's `output_schema` key is stamped by the driver
    # (phases.persist.role_schema), because the runners package may not import
    # phases and should not have to know what a role is.
    OUTPUT_SCHEMA_FLAG: tuple[str, ...] = ()
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
    HELP_ARGV: tuple[str, ...] = ("--help",)
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
    # #1727: the `dispatch.ROLE_FILES` keys THIS checkpoint dispatches, set by
    # the loop from its own routing table before each batch -- like `max_turns`,
    # set whether or not a runner reads it. None means "any registered shell",
    # which is the pre-#1727 behaviour and what a runner used outside the loop
    # gets.
    roles = None
    # M-9: whether `--max-turns` reaches anything on this host. The loop sets
    # `runner.max_turns` unconditionally, so a runner with no native turn
    # limit accepted the flag and ignored it in silence. True by default --
    # the seam's reference implementation honours it -- and a family that
    # cannot says so here, once, instead of documenting it in prose.
    HONOURS_MAX_TURNS = True
    # `INTERRUPT_GRACE`, `launch`, `register_child`, `unregister_child` and
    # `terminate_children` come from `runners/children.py` (#1575): one
    # subject, one module, and this one was at the 700-line ratchet.

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

    def batch_width(self, concurrency=None):
        """How many entries this runner may have in flight at once (#1576).

        `concurrency` is what the operator asked for (`driver loop
        --concurrency`), or None/0 for "whatever this family declares".
        The answer is bounded below by 1 -- a `ThreadPoolExecutor` refuses
        `max_workers <= 0`, so a bad number must degrade rather than crash --
        and above by `MAX_CONCURRENCY`.

        The clamp announces itself ONCE per requested value rather than once
        per call: `iter_batch` asks for the width of every batch and
        `orchestrate.loop` asks for the same number to bound its outage tally,
        so a per-call line would print twice a checkpoint and say nothing new.
        Remembered on the instance dict, lazily, for the same reason the child
        registry is: a family may not chain `super().__init__`.
        """
        requested = int(concurrency or self.default_concurrency)
        if requested > MAX_CONCURRENCY and self.__dict__.get("_clamped") != requested:
            self.__dict__["_clamped"] = requested
            print("concurrency %d clamped to the ceiling %d"
                  % (requested, MAX_CONCURRENCY), file=sys.stderr)
        return max(1, min(requested, MAX_CONCURRENCY))

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
           files down (`loop_batch.rolled_back` does that on the interrupt
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
        width = self.batch_width(concurrency)

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
        slots: dict[int, list[int]] = {}
        for i, entry in enumerate(entries):
            slots.setdefault(id(entry), []).append(i)   # by identity: entries are dicts
        results = [None] * len(entries)
        for entry, result, _timing in self.iter_batch(entries, concurrency, env_for):
            results[slots[id(entry)].pop(0)] = result
        return results


# #1732: how much of a failed launch's stderr travels with the result, and
# how much of it the ledger row keeps. ONE number, on the seam every family
# and the ledger already share: the families bound it on the way out and
# `ledger.Ledger.record` bounds it again on the way in, and two spellings of
# "200" would be two different guarantees about the same field.
#
# 200 for the same reason `error` quotes 200 characters of the reply: enough
# for a CLI's own refusal line (the one run 14 needed is 84 characters), far
# short of a transcript, and a fixed cost per row in a file the budget gate
# reads back on every batch.
STDERR_HEAD = 200


def stderr_head(text):
    """A failed launch's stderr, redacted and bounded (#1732); None for nothing.

    REDACTED FIRST, then cut -- never the other way round. `redact.redact`
    rewrites a whole secret to its placeholder, so redacting the truncated
    text would leave whatever fragment of an API key the cut happened to end
    in, verbatim, in a file the loop appends to on every launch. The one
    message whose PURPOSE is to surface an auth failure is the likeliest of
    all of them to be carrying a credential.

    None rather than "" for an empty stream, so a caller can put the field on
    a row only when there is something to say (`Ledger.record` writes no key
    at all in that case, which is what keeps a completed row's shape exactly
    what every existing reader parses).
    """
    text = redact.redact(_stream_text(text).strip())
    return text[:STDERR_HEAD] or None


def _stream_text(stream):
    """One of a child's streams as text, whatever the caller was handed.

    `subprocess.TimeoutExpired` carries stdout AND stderr UNDECODED even from a
    text-mode launch -- `communicate()` translates newlines only after it
    returns, and the timeout raises before that -- so bytes is the normal case
    on the timeout path, while the ordinary completed launch hands `str`.
    `errors="replace"` keeps a multi-byte character truncated at the kill from
    throwing away the whole stream. Empty for a launch that printed nothing,
    which is the same "no evidence" every other failure has.
    """
    if isinstance(stream, bytes):
        return stream.decode("utf-8", "replace")
    return stream if isinstance(stream, str) else ""


def partial_output(exc):
    """Whatever a killed child had printed, as text (D10 ruling 5)."""
    return _stream_text(getattr(exc, "stdout", None))


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
# #1727: the same refusal once the checkpoint's own roles are known. A separate
# string rather than an optional clause, because the two say different things:
# the first means "we never registered this", the second "we registered it for
# a different round".
UNREGISTERED_AGENT_FOR_CHECKPOINT = ("entry names an agent that is not a registered "
                                     "panopticon shell for this checkpoint "
                                     "(allowed: %s): %r")


def allowed_agent_names(roles=None):
    """The shell names acceptable for `roles` -- the whole allowlist when
    `roles` is None (#1727).

    `roles` is an iterable of `dispatch.ROLE_FILES` KEYS, supplied by the loop
    from the checkpoint it is dispatching. Derived through `ROLE_FILES` for the
    same reason `REGISTERED_AGENT_NAMES` is: a role renamed there moves the
    emitter, the readiness probe and this together. A key that is not a role
    contributes nothing -- narrowing, never widening, is the only direction a
    lookup failure may take a containment rule -- and `()` therefore accepts
    NOTHING, which is exactly right for the `scan` checkpoint, whose one entry
    is dispatched shell-less by design.
    """
    if roles is None:
        return REGISTERED_AGENT_NAMES
    return frozenset(dispatch.registered_agent_name(dispatch.ROLE_FILES[role])
                     for role in roles if role in dispatch.ROLE_FILES)


def registered_agent(entry, roles=None):
    """`entry["agent"]` when it is one of the four registered shells; None
    otherwise (#1720) -- narrowed to `roles` when the caller has them (#1727).

    The second containment rule on this seam, and for the same reason as
    `schema.published_schema`: an entry travels through
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
    return name if isinstance(name, str) and name in allowed_agent_names(roles) else None


def refuse_unregistered_agent(entry, roles=None):
    """The refusal every family returns for an enforced entry whose `agent` is
    not a registered shell -- including one carrying no `agent` at all, which
    used to fall through to the bare branch and launch unenforced while the
    ledger recorded an enforced entry. One message, one owner: three families
    refusing the same thing in three wordings is how a grep for this control
    finds two of them."""
    value = entry.get("agent") if isinstance(entry, dict) else None
    entry_id = entry.get("id") if isinstance(entry, dict) else None
    shown = redact.redact(str(value)[:200])
    if roles is None:
        return RunResult.failed(entry_id, UNREGISTERED_AGENT % shown)
    allowed = ", ".join(sorted(allowed_agent_names(roles))) or "none"
    return RunResult.failed(entry_id,
                            UNREGISTERED_AGENT_FOR_CHECKPOINT % (allowed, shown))


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
