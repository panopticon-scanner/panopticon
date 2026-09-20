"""The driver loop's per-batch bookkeeping: what happens to ONE entry that
came back, and the two reads/writes that bound a batch.

Split out of `orchestrate.py` (a pure move) so the entry script keeps room
under its 700-line instruction. It holds no control flow: `loop` still owns
the iteration, the guards, the tally and the interrupt, and the state a
Ctrl-C rolls back (`batch`, `handled`, `done`/`total`) stays in `loop`'s own
frame, where `_rolled_back` reads it.

A flat module rather than `runners/loop_batch.py`: `runners/*` may not import
`scripts.phases.*` (tests/test_layout.py rule 3) and every function here
does. Same shape, and the same reason, as `money.py` and `ledger.py`.
"""
import os
import sys

import scripts.dispatch as dispatch
import scripts.hosts as hosts
import scripts.phases.persist as persist
import scripts.phases.runio as runio

SETUP_NAMESPACE = "setup"

# #1727: which enforcement shells each checkpoint DISPATCHES -- `ROLE_FILES`
# keys, one row per `runio.CHECKPOINT_KINDS` member, pinned by a test that
# reads the shells back out of the phase builders.
#
# #1720 bound `agent` to the four registered shells; it did not bind it to the
# ROUND. Any of the four therefore passed for any checkpoint, so a `verify`
# entry naming `panopticon-domain-panel` got a reviewer's WRITE-granting
# charter in a round that only adjudicates -- a registered name, an allowlisted
# launch, and a governing instruction set nobody in this run chose. The driver
# owns the routing, so the driver states it, here, once.
#
# `scan` is deliberately EMPTY: `--setup`'s single entry is dispatched
# shell-less by design (it is not in ROLE_FILES, so no host registers a shell
# for it), and an empty row accepts no name at all rather than any.
CHECKPOINT_ROLES = {"scout": ("scout",),
                    "review": ("domain_panel",),
                    "verify": ("advisor", "domain_advisor"),
                    "scan": ()}


def expected_enforced(review_root, host, namespace=None):
    """Whether THIS run's own evidence says its entries launch enforced (#1720).

    The one owner of the expression. `enforced` travels to the runners in
    `.panopticon/dispatch-request.json`, a file inside the reviewed tree, and
    every family read it as the launch's posture -- so a request that said
    `false` got a bare launch (no shell, no tool policy) while the ledger
    recorded the entry the driver had dispatched. It is fully re-derivable:
    the phases set it from exactly this, so the loop can check the request
    against the run rather than take its word.

    Two postures are not read off the capability evidence at all:

    * the `setup` namespace, whose single `setup-scan` entry is dispatched
      SHELL-LESS by design (phases/setup.py: it is not in
      `dispatch.ROLE_FILES`, so no host registers a shell for it, and a fresh
      machine runs `--setup` before it has registered anything);
    * `hosts.is_unenforced_fallback` -- `--host generic` is the permanent
      unenforced fallback (owner ruling D1), ack-gated and disclosed.
    """
    if namespace == SETUP_NAMESPACE or hosts.is_unenforced_fallback(host):
        return False
    return (hosts.posture(host, runio.host_evidence(review_root))
            [hosts.TOOL_POLICY_ENFORCED] == hosts.PROVEN)


def refuse_disagreeing(pending, expected):
    """The ids of the pending entries whose self-asserted `enforced` does not
    match what this run's evidence says (`expected`)."""
    return [entry.get("id") for entry in pending
            if isinstance(entry, dict) and bool(entry.get("enforced")) != expected]


def enforcement_refusal(disagreeing, expected):
    """The operator's message for such a request. A REQUEST-INTEGRITY refusal,
    raised before the batch opens: nothing has launched and nothing is
    charged, so it is not any entry's failure -- and the remedy is to rebuild
    the request from evidence, not to retry the cell."""
    claimed, actual = ("unenforced", "enforced") if expected else ("enforced", "unenforced")
    return ("driver loop: entry %s claims %s launch on a host whose posture is %s; "
            "the dispatch request does not match this run's own evidence -- re-run "
            "with --reset, or re-run readiness" % (disagreeing[0], claimed, actual))


def refuse_misrouted(pending, checkpoint):
    """The ids whose `agent` is not one this checkpoint dispatches (#1727).

    Two shapes are refused, and they are the same statement read from either
    side: an ENFORCED entry whose agent is not one of `CHECKPOINT_ROLES[
    checkpoint]`, and an UNENFORCED entry that names a shell at all (the
    phases set `agent` to None on those, so a name on one is a claim this run
    never made). An unknown checkpoint gets the empty row, which refuses every
    name -- fail-closed, since the checkpoint is read off the same
    target-writable file.
    """
    allowed = {dispatch.registered_agent_name(dispatch.ROLE_FILES[role])
               for role in CHECKPOINT_ROLES.get(checkpoint) or ()
               if role in dispatch.ROLE_FILES}
    misrouted = []
    for entry in pending:
        if not isinstance(entry, dict):
            continue
        agent = entry.get("agent")
        if entry.get("enforced"):
            if not (isinstance(agent, str) and agent in allowed):
                misrouted.append(entry.get("id"))
        elif agent is not None:
            misrouted.append(entry.get("id"))
    return misrouted


def misroute_refusal(misrouted, checkpoint):
    """The operator's message for such a request -- a REQUEST-INTEGRITY
    refusal like `enforcement_refusal`, raised before the batch opens, so
    nothing has launched and nothing is charged.

    `%r` on every value that came out of the request (the id and the
    checkpoint both did): they reach the operator's stderr and the status
    JSON, and repr renders a control character, an ANSI escape or an embedded
    newline as its escape sequence -- the reason `base.UNREGISTERED_AGENT`
    does the same.
    """
    allowed = ", ".join(sorted(
        dispatch.registered_agent_name(dispatch.ROLE_FILES[role])
        for role in CHECKPOINT_ROLES.get(checkpoint) or ()
        if role in dispatch.ROLE_FILES)) or "no enforcement shell"
    return ("driver loop: entry %r names an enforcement shell its checkpoint does "
            "not dispatch (checkpoint %r dispatches: %s); the dispatch request does "
            "not match this run's own plan -- re-run with --reset"
            % (misrouted[0], checkpoint, allowed))


def request_refusal(review_root, host, namespace, req, pending):
    """The refusal this batch must not proceed past, or None.

    Both request-integrity checks in the order the loop needs them, behind one
    call so `orchestrate.loop` carries the DECISION and not the derivation:
    does the entry's self-asserted `enforced` match this run's own evidence
    (#1720), and is the shell it names one this checkpoint dispatches (#1727).
    Raised before the batch opens -- nothing has launched and nothing is
    charged -- so neither is any entry's failure; the remedy is to rebuild the
    request from the run, not to retry the cell.
    """
    expected = expected_enforced(review_root, host, namespace)
    disagreeing = refuse_disagreeing(pending, expected)
    if disagreeing:
        return enforcement_refusal(disagreeing, expected)
    misrouted = refuse_misrouted(pending, req.get("checkpoint"))
    if misrouted:
        return misroute_refusal(misrouted, req.get("checkpoint"))
    return None


def write_usage(review_root, ledger, namespace=None):
    """R-P6-4: rewritten after every ENTRY (P07; it was every batch) so synthesize --
    which runs inside the engine, before `complete` -- finds it; never estimated.

    `namespace` mirrors `probes.common.headless_settings_path`'s namespace-aware
    resolution (Task 6 fix round 1, item 2): `runio._pano(review_root, "usage.json")`
    alone follows whatever run-manifest.json happens to be on review_root, and for
    `namespace == "setup"` that can be a STALE review run's manifest, routing usage.json
    into that prior run's `runs/<tag>/` folder and clobbering it. Deriving the directory
    from `headless_settings_path` instead -- the SAME helper `loop`'s `run_dir` and the
    guard probes consult -- keeps this write in the one folder everything else for this
    invocation already agrees on: the flat `.panopticon/` for setup, the per-run tag
    folder for a review."""
    run_dir = persist.run_dir(review_root, namespace)
    # atomic (F6): rewritten per ENTRY now, so a reader can catch it truncated.
    runio._write_json(os.path.join(run_dir, "usage.json"), ledger.usage_document(), atomic=True)


def _pending(entries):
    """The resume set, from disk: every entry whose out_file is not yet good."""
    return [e for e in entries if isinstance(e, dict) and not persist.is_done(e)]


def record_entry(entry, result, timing, run_dir, batch, ledger, req, mode, runner):
    """Persist one finished entry's reply, keep what was refused, write its
    ledger row; returns the `refusal` note the caller's tally needs.

    Everything the loop does with a result that is not progress accounting.
    The ORDER is the contract: the reply is written (or retained) before the
    ledger row, so a row can record a refusal as the failed launch it was.
    """
    eid = entry.get("id")
    # The reply is persisted BEFORE the ledger row is written, so
    # the row can record a refusal as the failed launch it is.
    refusal = rejected = None
    if result.ok and entry.get("delivery") == "return_json":
        ok, reason = persist.write_reply(entry, result.text)
        if not ok:
            refusal = "persist refused: %s" % (reason or "shape check failed")
            # D10 ruling 1: the reply is kept, redacted, instead of
            # being dropped on the floor -- `_materialize_prompts`
            # reads it back into the retry prompt (ruling 2).
            rejected = persist.retain_rejected(run_dir, entry, result.text, reason,
                                              kind=persist.REFUSAL)
            print("driver loop: %s" % reason, file=sys.stderr, flush=True)
    elif not result.ok:
        # D10 ruling 5: a failed launch that PRINTED something keeps it
        # -- the timeout path is the one that has partial output, and it
        # is the entry that was most expensive to lose. `retain_rejected`
        # writes nothing for a failure with no output, so an ordinary
        # launch failure is exactly what it was.
        rejected = persist.retain_rejected(run_dir, entry, result.text, result.error,
                                          kind=persist.LAUNCH_FAILURE)
        print("driver loop: entry %s failed: %s" % (eid, result.error),
              file=sys.stderr, flush=True)
    if rejected:
        # #1662: not knowable at `open` (retain_rejected names
        # the record only once it has written it), and it is
        # this batch's output like any other.
        batch.add_artifact(eid, rejected)
    ledger.record(entry, req.get("checkpoint"), result, mode, runner.host,
                  refusal=refusal, timing=timing, rejected_file=rejected)
    return refusal
