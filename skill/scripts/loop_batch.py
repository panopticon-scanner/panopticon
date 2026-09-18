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

import scripts.phases.persist as persist
import scripts.phases.runio as runio


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
