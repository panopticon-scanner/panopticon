"""`driver loop`'s setup and its stop rules, out of `orchestrate.loop` (ARC-4087467862).

`resolve` is everything the loop settles before its first `_first_run`: the budget argument, the
review root and first contact, the host and its mode, the runner, the session root, the outgoing
dispatch request and stale-batch recovery. `batch_refusal` is the per-iteration check before a
batch is armed: the iteration cap, the budget, an entry out of attempts, a batch still in use.
`BudgetStop` is the in-batch budget rule. Moved verbatim -- the same messages, in the same order;
the loop itself (arm, launch, record, settle) stays in `orchestrate`.
"""
import os
import sys

import scripts.first_contact as first_contact
import scripts.hosts as hosts
import scripts.loop_batch as loop_batch
import scripts.money as money
import scripts.phases.requests as requests
import scripts.phases.runio as runio
import scripts.runners.base as runners_base


def resolve(args):
    """(setup, None), or (None, the error message `loop` returns as an `error` status).

    `setup` is `(budget, namespace, resolved, review_root, host, mode, runner, session_root,
    prev_req)`. Never raises for the cases `loop` reported; prints the same stderr notes."""
    budget = getattr(args, "max_budget_usd", None)
    # #1648: the CLI already refused a non-finite or negative budget
    # (money.budget_arg), so this re-read is for the OTHER caller -- the hand-built
    # args every loop test and any embedder passes. Refused, never defaulted: a
    # budget nothing can be compared against is the gate silently off.
    if budget is not None:
        budget, given = money._money(budget), budget
        if budget is None or budget < 0:
            return None, ("driver loop: --max-budget-usd %r is not a finite, "
                           "non-negative dollar amount" % (given,))
    namespace = "setup" if getattr(args, "setup", False) else None
    # R-P6-6: review_root resolved ONCE, up front -- BEFORE `_first_run` below calls
    # driver.run()/run_setup_flow(), which rewrites dispatch-request.json for whatever checkpoint
    # this invocation lands on. A fresh run has no manifest/run folder yet, so load_dispatch_request
    # (just below) reads back None -- "no previous entries", never an error (Task 6 ruling 3). A
    # resolve failure (a bad --pr, e.g.) is reported the same way driver.run() itself reports it
    # rather than raising out of loop(), which must never raise.
    try:
        resolved = loop_batch._resolve_target(args)
        first_contact.assess_loop(args, resolved)         # #3271 B2: before ANY read below
    except first_contact.FirstContactHalt as exc:
        return None, str(exc)
    except (RuntimeError, ValueError, OSError) as exc:
        return None, "driver loop: could not resolve review root: %s" % exc
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
        return None, hosts.unselectable_host_message(host, "loop")
    mode, note = resolve_mode(args, host)
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
    # deliberately. `driver._establish_host_posture` reads `args.mode` to choose the probe inputs
    # for this host, and it runs on EVERY `driver.run` call. For Claude's guard probes, headless
    # mode measures the run folder's settings and session mode measures the session root's
    # (spec 5.4). Resolving after the first call would therefore measure different controls across
    # invocations and make the run refuse ITSELF as posture drift (#1493). Other hosts may prove
    # the same capability by a different mechanism; mode still has to be stable before probing.
    # This is why host resolution reads the manifest here rather than after `_first_run`;
    # `--reset` is handled in `_resolve_host` so the outgoing manifest cannot steer a re-minted run.
    args.mode = mode
    try:
        runner = runners_base.runner_for(host, mode)
    except ValueError as exc:
        return None, str(exc)
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
            return None, "driver loop: %s" % exc
    return (budget, namespace, resolved, review_root, host, mode, runner, session_root,
            prev_req), None


def batch_refusal(iterations, max_iterations, budget, ledger, pending, tally, max_entry_failures,
                  run_dir):
    """The message `loop` ends this iteration on before arming a batch, or None: the iteration
    cap, the budget (fail-closed on an unreadable cost), an entry out of attempts, a batch whose
    record is still in use -- in that order."""
    pending_ids = ", ".join("%r" % e.get("id") for e in pending)
    if iterations > max_iterations:
        return ("driver loop: %d iterations without "
                "completing; still pending: %s"
                % (max_iterations, pending_ids))
    if budget is not None:
        # #1648: exact, and fail-CLOSED. `total_cost` raises rather than
        # summing past a ledger line it cannot read as money -- the old
        # float sum swallowed a NaN cost, and `NaN >= budget` is False,
        # so the gate went quiet and the loop kept launching paid entries.
        try:
            spent = ledger.total_cost()
        except money.LedgerCorrupt as exc:
            return ("driver loop: %s; refusing to spend past "
                    "an unreadable cost; ledger at %s; still pending: %s"
                    "; delete or repair that line, or re-run with "
                    "`--reset`"
                    % (exc, ledger.path, pending_ids))
        if spent >= budget:
            return ("driver loop: --max-budget-usd %s reached; "
                    "ledger at %s; still pending: %s"
                    % (budget, ledger.path, pending_ids))
    stuck = tally.exhausted(pending, max_entry_failures)
    if stuck:
        return stuck
    # #1698: a crash record this batch must not overwrite, refused before a single grant is
    # installed. `recover_stale` has already dealt with the ones it is allowed to; anything still
    # here under `--reset` (which skips recovery) used to reach `Batch.open`'s O_EXCL and come
    # back out of `loop` as a traceback.
    in_use = loop_batch.batch_in_use(run_dir, iterations)
    if in_use:
        return in_use
    return None


def resolve_mode(args, host):
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


class BudgetStop:
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
    which of the two rules cancelled the queue. Kept here rather than as a
    counter beside `FailureTally.stopped_at` because `runners/outage`
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
