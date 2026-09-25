"""The orchestrator on rails (spec 4): `driver loop` and `driver persist`.

`loop` calls driver.run in-process and, at every checkpoint, does the host duties
itself: recompute the pending set from disk, arm both guards, run the batch through the
host's runner -- persisting and ledgering each entry the moment it completes -- tear the
guards down, and call driver.run again. The engine's done predicates are the only way
forward (O2); a runner's claim advances nothing.
"""
from typing import Any
import contextlib
import os
import sys

import scripts.driver as driver
import scripts.hosts as hosts
import scripts.ledger as ledger_mod
import scripts.loop_batch as loop_batch
import scripts.money as money
import scripts.phases.engine as engine
import scripts.phases.persist as persist
import scripts.phases.requests as requests
import scripts.phases.runio as runio
import scripts.phases.setup_readiness as setup_readiness
import scripts.read_guard_hook as read_guard_hook
import scripts.repo_config as repo_config
import scripts.runners.base as runners_base
import scripts.runners.batch as batch_mod
import scripts.runners.outage as outage
import scripts.write_guard_hook as write_guard_hook

DEFAULT_MAX_ITERATIONS = 50
# Consecutive failed launches of ONE entry before the loop gives up on the run (fix round 2). Not
# a CLI flag: it is a safety rail, not a tuning knob -- an operator who wants a fourth attempt
# re-runs, which resumes from disk and starts every streak at zero.
MAX_ENTRY_FAILURES = 3


def _after_first_run(review_root):
    """Test seam: called once, after the first driver.run of a loop. Returns whether `loop`
    must re-derive `status` with another `driver.run` call before entering the while
    loop.

    Production always returns False -- a no-op, never patched outside
    tests/test_orchestrate.py. This is load-bearing, not decorative: a resume whose very
    first `driver.run` already lands on the `review` checkpoint (coverage was
    established by an earlier, now-dead process) would, with an UNCONDITIONAL second
    call here, re-run `review_execute` a second time with ZERO launches in between --
    and `review_execute` bumps `cell-attempts.json` on every call that finds a cell
    pending, launch or no launch. That burns one third of a cell's `MAX_CELL_ATTEMPTS`
    retry budget for nothing, on every single resume that happens to land on `review`.
    Only the test seam, which mutates review_root BETWEEN the two calls (seeding
    coverage so the checkpoint the test observes is `review` rather than `scout`), has a
    reason to ask for the second derive."""
    return False


class Guards:
    """Arm and disarm both guards for one mode (spec 5.1)."""

    def __init__(self, mode, run_dir=None, session_root=None):
        self.mode = mode
        # I4: the union of entries THIS process armed, in arm() order. Session mode is the only
        # mode whose grants outlive an invocation (a `dispatch` exit returns without disarming, by
        # design), so an invocation that errors must drop exactly what it armed -- nothing, when
        # it never got that far -- and leave the previous fan-out's grants standing. `complete`
        # still disarms totally (spec 5.1).
        self.armed_entries = []
        if mode == "headless":
            self.settings_path = os.path.join(run_dir, runners_base.SETTINGS_FILE)
            self.allowlist_path = os.path.join(run_dir, runners_base.ALLOWLIST_FILE)
            self.scope_path = os.path.join(run_dir, runners_base.SCOPE_FILE)
        else:
            self.session_root = session_root
            self.settings_path, self.allowlist_path, _ = write_guard_hook._resolve(None, None, session_root)
            _s, self.scope_path, _ = read_guard_hook._resolve(None, None, session_root)

    def arm(self, entries):
        if not entries:
            return
        armed = {e.get("id") for e in self.armed_entries}
        self.armed_entries += [e for e in entries
                               if isinstance(e, dict) and e.get("id") not in armed]
        if self.mode == "headless":
            write_guard_hook.install(entries, settings_path=self.settings_path,
                                     allowlist_path=self.allowlist_path)
            read_guard_hook.install(entries, settings_path=self.settings_path,
                                    scope_path=self.scope_path)
        else:
            write_guard_hook.install(entries, session_root=self.session_root)
            read_guard_hook.install(entries, session_root=self.session_root)

    def disarm(self, entries=None):
        """Scoped to `entries` when given (another fan-out may still be live), else total."""
        if self.mode == "headless":
            write_guard_hook.uninstall(plan=entries, settings_path=self.settings_path,
                                       allowlist_path=self.allowlist_path)
            read_guard_hook.uninstall(plan=entries, settings_path=self.settings_path,
                                      scope_path=self.scope_path)
        else:
            write_guard_hook.uninstall(plan=entries, session_root=self.session_root)
            read_guard_hook.uninstall(plan=entries, session_root=self.session_root)

    def env_for(self, entry):
        return {runners_base.ENV_ENTRY_ID: entry["id"],
                runners_base.ENV_WRITE_ALLOWLIST: os.path.abspath(self.allowlist_path),
                runners_base.ENV_READ_SCOPE: os.path.abspath(self.scope_path)}


def _status(kind, message, **extra):
    st = {"status": kind, "phase": None, "checkpoint": None, "group": None,
          "dispatch_request": None, "request_sha256": None, "advanced": [],
          "message": message}
    st.update(extra)
    return st


def _resolve_mode(args, host):
    """(mode, stderr_note) -- spec 4.4 (I8).

    `--mode` when the operator gave one. Otherwise headless when this host has a runner
    and session when it does not: "A host with no headless runner registered gets
    session mode with a stderr line saying so; `--mode headless` on such a host is an
    error." That last case is left to `runner_for`, which refuses with the sentence
    naming `--mode session`.
    """
    mode = getattr(args, "mode", None)
    if mode:
        return mode, None
    if runners_base.headless_available(host):
        return "headless", None
    return "session", (
        "driver loop: no headless runner for host %r (no skill/scripts/runners/%s.py); "
        "running in session mode -- the loop will print each batch for you to "
        "dispatch. Pass --mode headless to require a runner instead." % (host, host))


class _BudgetStop:
    """#1760: has this run reached `--max-budget-usd`? -- asked after every entry
    lands, as the batch's THIRD stop rule.

    The same question the top of every `while` iteration asks, off the same
    `Ledger`, so the two cannot disagree about what has been spent. It is asked
    twice because a checkpoint is ONE batch: the top-of-iteration gate is one
    comparison per batch, so a whole review round -- every pending cell, all of
    it charged -- launched before the cap was looked at a second time, where
    the guide says launching stops once the ledger's cumulative reported cost
    crosses it. Nothing else moves: the terminal `--max-budget-usd ... reached`
    status stays that gate's, reached on the next iteration once this batch has
    drained, and the residual overshoot falls to the pool (up to `width` already
    in flight, plus the one worker that can turn over while the loop is still
    ledgering the result that trips this) -- the bound #1721 established for an
    outage.

    Never RAISES, and answers True on a ledger line it cannot read as money:
    `runners/base.iter_batch` reads "A `stop` that RAISES ... as 'carry on'"
    (its docstring), so a `money.LedgerCorrupt` allowed out of here would be
    swallowed and the rest of the checkpoint launched and paid for -- #1648's
    fail-open again, one level down. Fail CLOSED; the next iteration's gate
    turns the same fault into the `error` status that names the line.

    `stopped` is what the loop's "stopped launching after ..." line reads:
    which of the three rules cancelled the queue. Kept here rather than as a
    counter beside `FailureTally.stopped_uniform` because `runners/outage`
    classifies FAILURES and reaching a cap is not one -- nothing failed, no
    entry is charged or refunded on its account, and `settle` is asked for no
    verdict about it. One instance per batch, so the flag cannot outlive the
    batch that set it.
    """

    def __init__(self, ledger, budget):
        self.ledger, self.budget = ledger, budget
        self.stopped = ""               # which rule fired, in the loop's own words

    def __call__(self):
        if self.budget is None:
            return False
        try:
            over = self.ledger.total_cost() >= self.budget
        except Exception:  # noqa: BLE001 -- fail CLOSED on ANY read fault, not only
            # LedgerCorrupt: a non-UTF-8 byte raises UnicodeDecodeError out of
            # `total_cost`, and iter_batch reads a raising stop as "carry on".
            over, self.stopped = True, "an unreadable ledger cost"
        if over and not self.stopped:
            self.stopped = "the --max-budget-usd cap"
        return over


def loop(args):
    """spec 4.3. Returns the final status dict; never exits (the CLI owns exit)."""
    max_iterations = getattr(args, "max_iterations", None) or DEFAULT_MAX_ITERATIONS
    budget = getattr(args, "max_budget_usd", None)
    # #1648: the CLI already refused a non-finite or negative budget
    # (money.budget_arg), so this re-read is for the OTHER caller -- the hand-built
    # args every loop test and any embedder passes. Refused, never defaulted: a
    # budget nothing can be compared against is the gate silently off.
    if budget is not None:
        budget, given = money._money(budget), budget
        if budget is None or budget < 0:
            return _status("error", "driver loop: --max-budget-usd %r is not a finite, "
                           "non-negative dollar amount" % (given,))
    namespace = "setup" if getattr(args, "setup", False) else None
    guards = ledger = None
    # R-P6-6: review_root resolved ONCE, up front -- BEFORE `_first_run` below calls
    # driver.run()/run_setup_flow(), which rewrites dispatch-request.json for whatever checkpoint
    # this invocation lands on. A fresh run has no manifest/run folder yet, so load_dispatch_request
    # (just below) reads back None -- "no previous entries", never an error (Task 6 ruling 3). A
    # resolve failure (a bad --pr, e.g.) is reported the same way driver.run() itself reports it
    # rather than raising out of loop(), which must never raise.
    try:
        resolved = _resolve_target(args)
    except (RuntimeError, ValueError, OSError) as exc:
        return _status("error", "driver loop: could not resolve review root: %s" % exc)
    review_root = resolved[0]
    # I5 then I8: the mode fallback asks whether THIS host has a runner, so the
    # host has to be resolved first.
    host, _source = runio.resolve_host(
        getattr(args, "host", None), review_root,
        reset=getattr(args, "reset", False))
    # #1621: the resolved host can be one the driver no longer accepts -- a run started under a
    # row a family PR has since lost (gemini) or never earned (kimi, codex) resumes off its own
    # manifest, which `driver.run` treats as authoritative. `runner_for` builds a SessionRunner
    # for ANY string, so nothing further down would have objected: the loop would have gone on
    # dispatching for a host `--host` now refuses to name. Read off the registry, never a
    # host-name literal, so a family PR that flips its row needs no edit here. The remedy is the
    # parser's, plus `--reset`, because it is the MANIFEST that has to change.
    # #1624: the sentence itself lives in the registry, because `driver.run` now refuses
    # the same manifest on the same grounds and two copies of one paragraph drift.
    if host not in hosts.driver_hosts():
        return _status("error", hosts.unselectable_host_message(host, "loop"))
    mode, note = _resolve_mode(args, host)
    if note:
        print(note, file=sys.stderr, flush=True)
    # I-3: the budget branch below reads the ledger's cumulative cost, and a host that reports no
    # dollars leaves that at 0 for ever -- so the flag is accepted and then does nothing. Say so
    # once, here, rather than letting an operator believe an unbounded run is bounded. Keyed on
    # the CLAIM, not a host name: declaring no usage_ledger IS the statement that no cost comes
    # back.
    if budget is not None and not hosts.declares(host, hosts.USAGE_LEDGER):
        print("driver loop: --max-budget-usd has no effect on host %r (no usage ledger); "
              "bound the run with --max-iterations and --entry-timeout" % host,
              file=sys.stderr, flush=True)
    # Both are resolved BEFORE `_first_run`, and the resolved mode is written back onto `args`,
    # deliberately. `driver._establish_host_posture` reads `args.mode` to decide WHICH settings
    # file the guard probes measure (spec 5.4: the run folder's in headless mode, the session
    # root's otherwise), and it runs on EVERY `driver.run` call. Leaving `args.mode` at None for
    # the first call and resolving afterwards would probe the session root once and the run folder
    # from then on -- and on any machine whose session root has no settings file (the #1493 case)
    # those two disagree about artifact_write_guard, so the run would refuse ITSELF as mid-run
    # posture drift on its second invocation. This is why host resolution reads the manifest here
    # rather than after `_first_run`; `--reset` is handled in `_resolve_host` so the outgoing
    # manifest cannot steer a re-minted run.
    args.mode = mode
    try:
        runner = runners_base.runner_for(host, mode)
    except ValueError as exc:
        return _status("error", str(exc))
    # M-9: the attribute is set on the runner below whether or not the runner reads it.
    # Say so once here rather than leaving the operator to find out from the guide.
    if getattr(args, "max_turns", None) and not getattr(runner, "HONOURS_MAX_TURNS", True):
        print("driver loop: --max-turns has no effect on host %r (its runner has no native "
              "turn limit); bound each entry with --entry-timeout" % host,
              file=sys.stderr, flush=True)
    # R-P6 Task 5 ruling 1: the SAME rule driver.run() applies to manifest["session_dir"] -- never
    # read off the on-disk manifest, which never persists it (driver.run() sets it in memory, post
    # write-manifest, precisely so a resume that omits --session-dir legitimately falls back to
    # cwd). Re-deriving it from run_manifest.load_manifest(...) here would silently resolve the
    # OPERATOR's real session root in session mode.
    session_root = (os.path.abspath(args.session_dir) if getattr(args, "session_dir", None)
                    else os.getcwd())
    # The OUTGOING dispatch request, read BEFORE `_first_run` rewrites it (R-P6-6):
    # reading it afterwards would see the very request this same invocation just
    # produced and disarm nothing. Read in every mode -- it is one JSON load -- so that
    # the READ and the ACT can sit on opposite sides of `_first_run`, which I4 requires.
    # #1727: read BOUND -- uninstall is keyed by strings that file supplies.
    prev_req = requests.previous_request(review_root, namespace)
    if not getattr(args, "reset", False):
        try:
            # #1912: `--discard-batch <n>` is the operator's acceptance for ONE
            # record whose owner cannot be checked for liveness -- read here,
            # where recovery is, and refused alongside `--reset` at the parser
            # (the two are contradictory, and `--reset` skips this call).
            loop_batch.recover_stale(review_root, prev_req, host, mode, namespace,
                                     discard=getattr(args, "discard_batch", None))
        except (ValueError, OSError) as exc:
            return _status("error", "driver loop: %s" % exc)
    if mode == "session":
        # Guards constructed HERE, before `_first_run`, and unconditionally -- not only once this
        # invocation reaches a fresh checkpoint. Session mode is the only mode whose guards can
        # stay armed ACROSS invocations (a `dispatch` exit returns before ever disarming, by
        # design -- the host has not run anything yet), so an invocation whose OWN `_first_run`
        # lands directly on complete -- the run's last checkpoint having been finished externally,
        # with no `while` iteration of THIS call to disarm it -- would otherwise leave the
        # PREVIOUS invocation's grants armed forever: `_finish` can only disarm a `guards` it was
        # handed, and building one only after a checkpoint survives skips exactly this case.
        # `run_dir` is not needed here: `Guards` ignores it outside headless mode, and the
        # settings/allowlist/scope paths it resolves depend only on `session_root`, which does not
        # change across a run.
        guards = Guards(mode, session_root=session_root)
    status = _first_run(args, namespace, resolved)
    # `--reset` is CONSUMED by that call. `driver.run` reads `args.reset` on every invocation and
    # the loop hands it the same `args` each iteration, so left set it cleared the run folder and
    # re-minted the manifest on every `_run` below: the run restarted at its first checkpoint
    # forever. Found twice, independently. By the Claude family PR's second real `driver loop
    # --reset`, which re-launched the same three scouts ten times (30 identical ledger rows)
    # before it was stopped; and by the kimi family PR, where the second call deleted the run
    # folder the runner had just prepared (the kimi run's kimi-home/config.toml -- every child
    # then failed "Model ... is not configured"; claude's host-settings.json is the same file in
    # the same path), re-minted a fresh tag each time, and left the ledger, runner and guards
    # writing to the first mint's folder while the manifest pointed at the last. `driver loop
    # --reset` could never have worked headless; single `driver run --reset` calls never noticed
    # because they invoke driver.run exactly once. From here on the loop resumes the run it just
    # started, which is what every later iteration is for.
    args.reset = False
    if status.get("status") != "checkpoint":
        return _finish(status, review_root, guards, ledger, namespace, mode, runner)
    if mode == "session":
        # I4: only now. This invocation has a live checkpoint of its own, so its pending set is
        # the authority on what is still running. An entry now done falls away here; one still
        # pending is re-armed below by this iteration's own `guards.arm(pending)`, computed from
        # the FRESH request `_first_run` just wrote (Task 6 ruling 3).
        loop_batch.disarm_previous(guards, prev_req)
    if _after_first_run(review_root):
        status = _run(args, namespace, resolved)      # re-derive after the seam
    iterations = 0
    # The per-entry failure streaks, and (#1623) the verdict on whether a whole batch was
    # really the HOST going down. `runners.outage.FailureTally` documents and owns both.
    tally = outage.FailureTally(host, args)
    done, total = 0, 0        # this batch's progress, read by the handlers below
    # #1662: what a Ctrl-C has to take back. Bound BEFORE the try, because the
    # interrupt can land before the first batch ever opens one.
    batch = None
    pending = []
    handled: list[dict[str, Any]] = []
    req = {}
    try:
        # M8: the pre-loop setup lives INSIDE the try. `loop` never raises (review round 1, item
        # 3), but every line of it touches the filesystem -- resolving the run folder, writing
        # host-settings.json, resolving the guard paths -- and an OSError (a read-only run folder,
        # an unwritable settings path) escaped as a traceback rather than the reported `error`
        # status every other failure here produces.
        #
        # Task 6 fix round 1, item 2: derived through persist.run_dir, which is
        # probes.common.headless_settings_path (namespace-aware), never a bare
        # `runio._pano(review_root, SETTINGS_FILE)` -- for namespace == "setup" that would follow
        # whatever run-manifest.json a PRIOR review run left on review_root and route setup's own
        # host-settings.json/dispatch-ledger.jsonl/usage.json into that run's runs/<tag>/ folder.
        run_dir = persist.run_dir(review_root, namespace)
        # C2/M4: the session runner prints the batch itself, so it needs the two facts only the
        # loop holds -- which request file these entries came from, and whether this is the setup
        # namespace (which every command it hints at must carry as `--setup`). Set
        # unconditionally.
        #
        # BEFORE prepare(), not after: a headless runner does read `namespace` there. The Codex
        # runner's enforced-only preflight has to stand down for `--setup`, whose single entry is
        # dispatched with no registered shell by design -- a fresh machine runs setup before it
        # registers anything.
        runner.dispatch_request = os.path.abspath(
            requests.request_path(review_root, namespace))
        runner.namespace = namespace
        runner.prepare(run_dir, review_root)
        # N2: the runner's scratch home travels to the probes IN PROCESS, on `args`,
        # because every later `driver.run` in this loop re-establishes posture and the
        # effective-surface probes need to find this run's children. Host-agnostic: a
        # runner with no scratch area leaves it None, and nothing reads a path out of
        # the reviewed tree to get it. AFTER prepare(), which is what mints it.
        args.run_home = getattr(runner, "run_home", None)
        for attr in ("max_turns", "entry_timeout"):
            if getattr(args, attr, None):
                setattr(runner, attr, getattr(args, attr))
        if guards is None:
            guards = Guards(mode, run_dir=run_dir, session_root=session_root)
        ledger = ledger_mod.Ledger(run_dir)
        while status.get("status") == "checkpoint":
            iterations += 1
            # #1727, FIRST: everything below reads fields off a file in the
            # reviewed tree. `status` is what THIS iteration's `_run` returned,
            # so its `request_sha256` is the writing phase's, held in memory.
            req, refusal = requests.load_bound_request(
                review_root, namespace, expected_sha256=status.get("request_sha256"))
            if refusal:
                return _finish(_status("error", "driver loop: " + refusal), review_root,
                               guards, ledger, namespace, mode, runner)
            req = req or {}
            # What a session host is told the file must hash to, and which
            # shells this checkpoint dispatches (the runner narrows its own
            # per-entry allowlist to them). Per checkpoint: the request rolls.
            runner.request_sha256 = requests.recorded_request_hash(review_root, namespace)[0]
            runner.roles = loop_batch.checkpoint_roles(req.get("checkpoint"))
            entries = [e for e in req.get("entries") or [] if isinstance(e, dict)]
            pending = loop_batch._pending(entries)
            # #1720 + #1727: does what it SAYS match this run's own evidence
            # and plan? Before anything is armed or launched.
            refusal = loop_batch.request_refusal(review_root, host, namespace, req, pending)
            if refusal:
                return _finish(_status("error", refusal), review_root, guards, ledger,
                               namespace, mode, runner)
            pending_ids = ", ".join(e.get("id") for e in pending)
            if iterations > max_iterations:
                return _finish(_status("error", "driver loop: %d iterations without "
                                       "completing; still pending: %s"
                                       % (max_iterations, pending_ids)),
                               review_root, guards, ledger, namespace, mode, runner)
            if budget is not None:
                # #1648: exact, and fail-CLOSED. `total_cost` raises rather than
                # summing past a ledger line it cannot read as money -- the old
                # float sum swallowed a NaN cost, and `NaN >= budget` is False,
                # so the gate went quiet and the loop kept launching paid entries.
                try:
                    spent = ledger.total_cost()
                except money.LedgerCorrupt as exc:
                    return _finish(_status("error", "driver loop: %s; refusing to spend past "
                                           "an unreadable cost; ledger at %s; still pending: %s"
                                           "; delete or repair that line, or re-run with "
                                           "`--reset`"
                                           % (exc, ledger.path, pending_ids)),
                                   review_root, guards, ledger, namespace, mode, runner)
                if spent >= budget:
                    return _finish(_status("error", "driver loop: --max-budget-usd %s reached; "
                                           "ledger at %s; still pending: %s"
                                           % (budget, ledger.path, pending_ids)),
                                   review_root, guards, ledger, namespace, mode, runner)
            stuck = tally.exhausted(pending, MAX_ENTRY_FAILURES)
            if stuck:
                return _finish(_status("error", stuck), review_root, guards, ledger,
                               namespace, mode, runner)
            # #1698: a crash record this batch must not overwrite, refused
            # before a single grant is installed. `recover_stale` has already
            # dealt with the ones it is allowed to; anything still here under
            # `--reset` (which skips recovery) used to reach `Batch.open`'s
            # O_EXCL and come back out of `loop` as a traceback.
            in_use = loop_batch.batch_in_use(run_dir, iterations)
            if in_use:
                return _finish(_status("error", in_use), review_root, guards, ledger,
                               namespace, mode, runner)
            guards.arm(pending)
            if mode == "session":
                # Branched on the MODE, not on a None the headless path can no
                # longer return: the session runner prints the batch, launches
                # nothing, and the loop exits `dispatch` still armed (spec 4.3).
                runner.run_batch(pending, getattr(args, "concurrency", None), guards.env_for)
                return _dispatch_exit(review_root, req, pending, namespace, runner.request_sha256)
            done, total = 0, len(pending)
            handled = []
            # #1732: the run's ONE shape proof, here rather than at posture
            # time -- the guards are armed NOW, so it is confined like a cell.
            loop_batch.prove_output_schema_shape(run_dir, host, runner, pending,
                                                 guards.env_for)
            # #1721: the pool is FIFO, so an entry's index in `pending` is its
            # LAUNCH order -- which is what tells the tally a success that
            # proves the host is back from one that was merely in flight when
            # it went down. `width` is the same number iter_batch resolves.
            # #1576: the ONE ceiling, asked of the runner rather than
            # re-derived here -- this number and `iter_batch`'s pool
            # width have to be the same number, and they were two
            # copies of one expression.
            width = runner.batch_width(getattr(args, "concurrency", None))
            order = {e.get("id"): i for i, e in enumerate(pending)}
            # #1662: the list the rollback deletes, written BEFORE the first
            # submit -- taking a cancelled batch back must never be a glob
            # over the run folder, which would reach a prior phase's outputs
            # and, on a redteam target, whatever the tree planted next to them.
            try:
                batch = batch_mod.Batch(run_dir, iterations,
                                        req.get("checkpoint"), pending).open()
            except FileExistsError:       # the race the check above cannot close
                return _finish(_status("error", loop_batch.BATCH_IN_USE
                                       % batch_mod.manifest_path(run_dir, iterations)),
                               review_root, guards, ledger, namespace, mode, runner)
            # P07 (#1636): persisted, ledgered and counted into usage.json the moment EACH entry
            # finishes, so an interrupt keeps everything already yielded and `done`/`total` say
            # how much that was. `closing` because an exception here abandons the generator: it
            # drains the pool now, before `_finish` tears the guards and the runner's scratch area
            # down, rather than at GC's convenience.
            # #1732 then #1760: THREE stop rules. `outage` asks whether the HOST
            # went down; `uniform` asks whether the LAUNCH is being refused (run
            # 14: 103 launches, ~120 ms each, one identical message, one wrong
            # argv token); `over_budget` asks whether the operator's cap has been
            # reached. Neither of the first two can be true of the same results,
            # and the third is built per batch so its flag cannot outlive the
            # batch that set it.
            over_budget = _BudgetStop(ledger, budget)
            with contextlib.closing(runner.iter_batch(
                    pending, getattr(args, "concurrency", None), guards.env_for,
                    stop=lambda: (tally.outage(width) or tally.uniform(width)
                                  or over_budget()))) as stream:
                for entry, result, timing in stream:
                    eid = entry.get("id")
                    refusal = loop_batch.record_entry(
                        entry, result, timing, run_dir, batch, ledger, req,
                        mode, runner)
                    handled.append(eid)
                    tally.record(eid, result, refusal, seq=order.get(eid),
                                 duration_ms=timing.get("duration_ms"))
                    done += 1
                    # Best-effort, exactly as `_finish`'s own call is (F1): derived
                    # from a ledger already on disk, and `_finish` rewrites it. Fatal
                    # here, it discarded every entry still in flight -- drained, paid
                    # for, never persisted -- the very loss P07 exists to stop.
                    try:
                        loop_batch.write_usage(review_root, ledger, namespace)
                    except Exception as exc:   # noqa: BLE001 -- progress, not evidence
                        print("driver loop: usage.json not updated: %s: %s"
                              % (type(exc).__name__, exc), file=sys.stderr, flush=True)
                    # "progress visible without inspecting processes": one
                    # line, stderr; stdout's status contract is untouched.
                    print("driver loop: %s done (%s ms, %d/%d)"
                          % (eid, timing.get("duration_ms"), done, total),
                          file=sys.stderr, flush=True)
            # #1721: what the short-circuit stopped. Never-launched entries wrote
            # nothing and are charged nothing, so `batch.close()` and `disarm`
            # below are unchanged -- there is nothing of theirs to take back.
            unlaunched = [e for e in pending if e.get("id") not in handled]
            if unlaunched:
                # What the STOP saw, not what is left over: a success drained
                # afterwards may have closed the run, and the settle verdict
                # below is the only thing entitled to call this an outage.
                #
                # #1732, then #1760: which RULE fired, too. One wording for
                # each, because a batch stopped for an argv defect -- or for a
                # cap the operator set themselves -- reported as "N host-class
                # failure(s)" sends them to wait for a host that is perfectly
                # healthy, and a budget stop would render that N as zero.
                # Exclusive by construction, not by precedence: the `stop`
                # above is `outage or uniform or over_budget`, so its
                # short-circuit means the rule that answered True is the only
                # one that recorded anything before the break.
                if tally.stopped_uniform:
                    rule = "%d identical instant failure(s)" % tally.stopped_uniform
                elif over_budget.stopped:
                    rule = over_budget.stopped
                else:
                    rule = "%d host-class failure(s)" % (tally.stopped_at or 0)
                print("driver loop: stopped launching after %s; %d of %d entries "
                      "not launched" % (rule, len(unlaunched), len(pending)),
                      file=sys.stderr, flush=True)
            for note in batch.close():        # a clean batch leaves no manifest
                print("driver loop: batch manifest not removed: %s" % note,
                      file=sys.stderr, flush=True)
            batch = None
            guards.disarm(pending)                    # armed per batch, dropped per batch
            # #1623: the batch is charged HERE, not as each entry landed, because a
            # host-wide outage (auth, quota, rate limit) is not the entries' failure --
            # and three iterations of one used to spend every pending cell's attempt
            # budget and end the run `complete` with an empty review axis. The queue is
            # already drained and the grants are down, and the failed launches wrote
            # nothing, so no ARTIFACT is rolled back; the per-dispatch attempt marker is
            # given back exactly as the interrupt gives it back, or three paused runs
            # exhaust the same budget the automatic iterations used to.
            paused = tally.settle(len(unlaunched), width)
            # NOT every pending entry (#1721): an entry-class failure during an
            # outage is still the entry's own and keeps its charge, and a cell
            # that landed is done. What is given back is what the host took
            # down, plus what the short-circuit never launched -- and it is
            # given back whether or not the batch PAUSED, because the two are
            # different predicates: a success from a later launch closes the
            # trailing run, so a batch that stopped launching can still settle
            # to None, and those cancelled cells would otherwise keep an
            # attempt charged at dispatch for a launch that never happened.
            give_back = unlaunched + [e for e in pending if e.get("id") in tally.uncharged]
            if give_back:
                persist.rollback_markers(review_root, req.get("checkpoint"), give_back)
            if paused:
                return _finish(_status("paused", paused), review_root, guards, ledger,
                               namespace, mode, runner)
            status = _run(args, namespace, resolved)
    except KeyboardInterrupt:
        status = _status("error", loop_batch.rolled_back(
            review_root, batch, pending, handled, req, ledger, mode, runner,
            guards, done, total))
    except Exception as exc:                # noqa: BLE001 -- `loop` never raises (review round 1, item 3)
        status = _status("error", "driver loop: %s: %s" % (type(exc).__name__, exc))
    return _finish(status, review_root, guards, ledger, namespace, mode, runner)


def _resolve_target(args):
    """`(review_root, worktree, pr_base)` -- resolved ONCE per invocation and passed down (#1616 item 6):
    `driver.run` takes it as `resolved=`, not a `gh pr view` and a worktree acquisition per iteration."""
    return runio.resolve_review_root(args.target, base=args.base, pr=args.pr)


def _run(args, namespace, resolved=None):
    if namespace == "setup":
        import scripts.phases.setup as setup
        # #1616 item 3: the posture step `driver.run` does on every invocation, handed in
        # because `phases/*` may not import an entry script (tests/test_layout.py rule 3).
        return setup.run_setup_flow(args, posture=driver._establish_host_posture)
    return driver.run(args, resolved=resolved)


def _first_run(args, namespace, resolved=None):
    return _run(args, namespace, resolved)


def _dispatch_exit(review_root, req, pending, namespace, request_sha256=None):
    """Session mode: the runner printed the batch; exit with a dispatch status and leave
    the guards armed (spec 4.3).

    C2: `dispatch_request` comes from `requests.request_path` -- the one accessor that
    knows a review's request is per-run (`runs/<tag>/dispatch-request.json`) while setup
    keeps its own top-level file (#1507). It used to be read off the request DOCUMENT,
    which carries no such key (schema_version, run_id, checkpoint, group, entries), so
    the field was None on every dispatch and the host had no path to cross-reference the
    printed entries against.

    M4: the hints carry `--setup` in the setup namespace. Without it both `driver
    persist <id>` and the follow-up `driver loop` resolve the REVIEW namespace, where
    the entry does not exist.
    """
    setup = " --setup" if namespace == "setup" else ""
    return _status("dispatch", "session mode: run the printed entries, persist each "
                   "return-persist reply with `driver persist <id>%s`, then re-run "
                   "`driver loop%s --mode session`" % (setup, setup),
                   dispatch_request=os.path.abspath(
                       requests.request_path(review_root, namespace)),
                   request_sha256=request_sha256,
                   pending=[e.get("id") for e in pending],
                   checkpoint=req.get("checkpoint"))


def _finish(status, review_root, guards, ledger, namespace, mode="headless", runner=None):
    """The terminal teardown, executed for every non-checkpoint status. Disarm first, then attempt
    a final write_usage on BOTH `complete` and `error` (review round 2): the `except Exception`
    catch-all (round 1, item 3) can land here after a batch already recorded a ledger line but
    before that iteration's own in-loop write_usage ran, and a `complete`-only write would leave
    usage.json stale against the ledger. Wrapped so a failure here can never mask the real status
    -- it is appended to the message instead. `review_root` is `loop`'s own (#1616 item 6)."""
    # C1 (kimi family PR review): the runner's own terminal hook, on EVERY terminal status, before the
    # guards are touched -- a host whose runner holds a scratch area outside the tree (kimi's per-run
    # KIMI_CODE_HOME, which carries the operator's credential surface and the children's verbatim wire
    # files) has nowhere else to release it, and `loop` has exactly one terminal path. Wrapped: a
    # teardown failure must not mask the run's real status, exactly as the final write_usage below is
    # wrapped.
    if runner is not None:
        try:
            runner.teardown(status.get("status"))
        except (Exception, KeyboardInterrupt) as exc:      # noqa: BLE001 -- never mask the status
            print("driver loop: %s teardown failed: %s: %s"
                  % (getattr(runner, "host", "?"), type(exc).__name__, exc),
                  file=sys.stderr, flush=True)
            if isinstance(exc, KeyboardInterrupt):     # a THIRD Ctrl-C: `loop` still never raises
                status["message"] = "%s; teardown interrupted: KeyboardInterrupt" % status.get("message")
    if guards is not None:
        if status.get("status") == "complete":
            guards.disarm()                          # total (spec 5.1)
        elif status.get("status") in ("error", "paused") and guards.armed_entries:
            # I4: exactly what THIS invocation armed, and nothing else. In session mode
            # the grants outlive an invocation, so a total teardown here would revoke a
            # fan-out the PREVIOUS invocation started and that is still running. An
            # invocation that armed nothing (an errored re-entry) disarms nothing.
            guards.disarm(guards.armed_entries)
    # M9: the ledger-derived usage.json belongs to headless runs only. In session mode
    # the loop launches nothing, so the ledger is empty and this document is all zeros
    # -- while the run's REAL figures come from the host's own transcripts via
    # collect_usage, which synthesize wires in and which deliberately never overwrites
    # an existing usage.json. Writing here would replace the real counts with zeros.
    if (mode == "headless" and ledger is not None
            and status.get("status") in ("complete", "error", "paused")):
        try:
            loop_batch.write_usage(review_root, ledger, namespace)
        except Exception as exc:      # noqa: BLE001 -- must not mask the original status
            status["message"] = "%s; usage.json not written: %s: %s" % (
                status.get("message"), type(exc).__name__, exc)
    if namespace == "setup" and status.get("status") == "complete":
        # spec 4.6, R-P6-10: `driver loop --setup` names its own artifacts and the promotion
        # command, superseding whatever message run_setup_flow's own `complete` branch composed
        # (that wording is for `driver setup` run directly, not for `driver loop --setup`'s
        # on-rails contract). Fix round 1, item 1: ONLY when a draft actually exists -- the
        # vocab-absent fallback (phases/setup.py's _scan_fallback) seeds the root config directly
        # and writes NEITHER setup-report.md NOR a draft, so unconditionally naming them here
        # would send the operator to files that were never written and a promotion `mv` that would
        # fail. run_setup_flow's own `complete` branch already composed the right message for that
        # path (readiness gaps and limitations included) -- leave `status["message"]` exactly as
        # it is when there is no draft to promote.
        draft = repo_config.draft_path(review_root)
        if os.path.isfile(draft):
            status = dict(status, message=(
                "setup complete: read %s, review %s, then promote it: mv %s %s (setup never "
                "overwrites a committed %s)" % (
                    runio._pano(review_root, "setup-report.md"), draft, draft,
                    os.path.join(review_root, repo_config.CONFIG_NAMES[0]),
                    repo_config.CONFIG_NAMES[0]))
                # #1603: superseding the wording must not supersede the
                # DISCLOSURE. Readiness runs on this path now (phases/setup.py's
                # ingest_execute), and this message is the only one a
                # `driver loop --setup` operator reads -- so 5.1's surface 4
                # rides along, off the report this line already names. Same
                # helper, same clause, same artifact as `driver setup`'s own
                # completion line; an artifact with no readiness rows adds
                # nothing.
                + setup_readiness._readiness_tail(runio._load_json(
                    runio._pano(review_root, "setup-report.json"))))
    return status


def persist_cli(args):
    """`driver persist ENTRY_ID [--file PATH] [--setup] [--pr N] [--base REF] [target]` ->
    exit code.

    I6: base/pr are threaded exactly as `driver run` threads them. A `--pr` run's review
    root is the PR worktree, and resolving `target` alone read the dispatch request from
    the operator's own checkout instead -- so every persist against a `--pr` run refused
    with "no entry in the current dispatch request", with nothing to say which run it
    had looked in.
    """
    review_root, _wt, _pr = runio.resolve_review_root(
        args.target, base=getattr(args, "base", None), pr=getattr(args, "pr", None))
    entry, refusal = persist.find_entry(review_root, args.entry_id,
                                        namespace="setup" if args.setup else None)
    if refusal:
        # #1727: not the request this run wrote -- and it names the out_file.
        print("driver persist: %s" % refusal, file=sys.stderr)
        return 1
    if entry is None:
        print("driver persist: no entry %r in the current dispatch request"
              % args.entry_id, file=sys.stderr)
        return 1
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            text = fh.read()
    else:
        text = sys.stdin.read()
    ok, reason = persist.write_reply(entry, text)
    if not ok:
        # D10 ruling 1, session half: the operator is holding the only copy of this reply,
        # so the mode a human drives keeps it exactly as the loop does -- same folder, shape
        # and attempt numbering -- and (F10) says where, since the refusal line is all they see.
        kept = persist.retain_rejected(persist.run_dir(review_root, "setup" if args.setup else None),
                                       entry, text, reason, kind=persist.REFUSAL)
        print("driver persist: %s%s" % (reason, " (reply kept at %s)" % kept if kept else ""), file=sys.stderr)
        return 1
    print(os.path.abspath(entry["out_file"]))
    return 0


def main_verb(args):
    if args.verb == "persist":
        return persist_cli(args)
    return engine.emit_status(loop(args))
