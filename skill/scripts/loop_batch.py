"""The driver loop's per-batch bookkeeping: what happens to ONE entry that
came back, and the two reads/writes that bound a batch.

Split out of `orchestrate.py` (a pure move) so the entry script keeps room
under its 700-line instruction. It holds no control flow: `loop` still owns
the iteration, the guards, the tally and the interrupt, and the state a
Ctrl-C rolls back (`batch`, `handled`, `done`/`total`) stays in `loop`'s own
frame and is handed to `rolled_back` from there.

A flat module rather than `runners/loop_batch.py`: `runners/*` may not import
`scripts.phases.*` (tests/test_layout.py rule 3) and every function here
does. Same shape, and the same reason, as `money.py` and `ledger.py`.
"""
import os
import re
import sys

import scripts.dispatch as dispatch
import scripts.hosts as hosts
import scripts.ledger as ledger_mod
import scripts.plan_contract as plan_contract
import scripts.phases.persist as persist
import scripts.phases.requests as requests
import scripts.phases.runio as runio
import scripts.phases.setup as setup
import scripts.probes.shape as shape_probe
import scripts.run_manifest as run_manifest
from scripts.runners.batch import Batch

SETUP_NAMESPACE = "setup"

# #1662: the two sentences a Ctrl-C ends a run with. Constants because
# docs/PANOPTICON.md quotes the first one back and the guide test reads it off
# here. "had been HANDLED", not completed: the count is every entry the loop
# got back, a failed launch included -- ledgered as the failure it was rather
# than persisted (F2), and rolled back either way.
INTERRUPTED = ("interrupted: %d of %d entries had been handled and have been rolled "
               "back; the phase will re-run from its checkpoint on the next "
               "`driver loop`; use `--reset` to discard the whole run")
INTERRUPTED_IDLE = ("interrupted: no batch was in flight, so nothing was rolled back; "
                    "re-run to resume, or use `--reset` to discard the whole run")


def recover_stale(review_root, request, host, mode, namespace=None):
    """Validate every crash record before deleting anything, then retry the phase.

    The manifest lists artifacts, but the bound outgoing request supplies the
    authority: entries, output paths and checkpoint must agree. Nothing from a
    foreign run is followed; the normal first-run path discards that run.
    """
    plan_contract.artifact_root(review_root)
    manifest = (setup.load_setup_manifest(review_root) if namespace == "setup"
                else run_manifest.load_manifest(review_root))
    mpath = (setup._setup_manifest_path(review_root) if namespace == "setup"
             else run_manifest.manifest_path(review_root))
    if manifest is None or runio._foreign_manifest(manifest, review_root, mpath):
        return
    folder = persist.run_dir(review_root, namespace)
    runio._confine_artifact_path(folder)
    root = os.path.realpath(folder)
    if not os.path.isdir(root):
        return
    batches, claimed = [], set()
    declared = {e["id"]: e for e in request.get("entries", [])
                if isinstance(e, dict) and isinstance(e.get("id"), str)}
    for name in sorted(os.listdir(root)):
        match = re.fullmatch(r"batch-([0-9]+)\.json", name)
        if not match:
            continue
        path = os.path.join(root, name)
        doc = None if os.path.islink(path) else runio._load_json(path)
        refusal = "cannot recover stale batch %s; use --reset: " % name
        if (not isinstance(doc, dict) or doc.get("schema_version") != 1
                or doc.get("batch") != int(match[1])
                or doc.get("checkpoint") != request.get("checkpoint")
                or not isinstance(doc.get("entries"), list) or not doc["entries"]):
            raise ValueError(refusal + "invalid manifest or unbound checkpoint")
        if doc.get("recovering"):
            raise ValueError(refusal + "a previous recovery was interrupted")
        pending, seen = [], set()
        for row in doc["entries"]:
            if not isinstance(row, dict) or not isinstance(row.get("id"), str):
                raise ValueError(refusal + "invalid entry")
            eid = row["id"]
            entry = declared.get(eid)
            paths = row.get("artifacts")
            if (entry is None or not isinstance(entry.get("out_file"), str)
                    or persist.role_of(entry) is None or eid in seen
                    or not isinstance(paths, list) or not paths
                    or paths[0] != os.path.abspath(entry.get("out_file") or "")):
                raise ValueError(refusal + "entry differs from the bound dispatch request")
            seen.add(eid)
            if eid in claimed:
                raise ValueError(refusal + "several stale batches claim the same entry")
            claimed.add(eid)
            safe_id = requests._PROMPT_FILE_SAFE.sub("_", eid) or "entry"
            for i, artifact in enumerate(paths):
                if (not isinstance(artifact, str) or not os.path.isabs(artifact)
                        or os.path.commonpath((root, os.path.realpath(os.path.dirname(artifact)))) != root):
                    raise ValueError(refusal + "artifact escapes the run folder")
                if i and (os.path.realpath(os.path.dirname(artifact)) != os.path.join(root, persist.REJECTED_DIR)
                          or not re.fullmatch(re.escape(safe_id) + r"-[0-9]+\.json",
                                              os.path.basename(artifact))):
                    raise ValueError(refusal + "unexpected retained-reply artifact")
            pending.append(entry)
        batch = Batch(root, doc["batch"], doc["checkpoint"], pending)
        batch.opened_at = doc.get("opened_at")
        batch.entries = doc["entries"]
        batches.append((batch, pending))
    ledger = ledger_mod.Ledger(root)
    for batch, pending in batches:
        batch.begin_recovery()
        completed = {row["id"] for row in batch.entries
                     if any(os.path.lexists(p) for p in row["artifacts"])}
        removed, problems = batch.roll_back(close=False)
        if problems:
            raise OSError("stale batch rollback incomplete: " + "; ".join(problems))
        ledger.rollback_rows(pending, completed, batch.checkpoint, mode, host,
                             reason="previous process stopped")
        persist.rollback_markers(review_root, batch.checkpoint, pending)
        problems = batch.close()
        if problems:
            raise OSError("stale batch rollback incomplete: " + "; ".join(problems))
        print("driver loop: recovered stale batch %s; removed %d artifact(s); "
              "retrying %s" % (batch.number, len(removed), batch.checkpoint),
              file=sys.stderr, flush=True)


def rolled_back(review_root, batch, pending, handled, req, ledger, mode, runner,
                guards, done, total):
    """The Ctrl-C path (#1662): cancel, roll back to the checkpoint, and say so.

    Returns the operator's MESSAGE; `orchestrate.loop` is what turns it into
    an `error` status. It lives beside `recover_stale` because the two are the
    same mechanism read from either end -- this one takes a batch back while
    the process is still here, that one finishes the job for a process that
    is not -- and they have to agree, file for file, on what a rollback owes.

    `iter_batch` has already stopped the batch: nothing queued was launched,
    and what was running has been terminated. What is left, in this order:

    * this batch's grants come down FIRST, before a single artifact is deleted.
      A child that outlived the termination (no shipped family holds a handle
      on its children, so "terminated" means the terminal's process-group
      SIGINT) would otherwise re-create the very file the rollback had handed
      back, and the resume would read that cell as done and never dispatch it
      again -- the one outcome the rollback exists to prevent. The guard is
      fail-closed the moment its allowlist is unlinked, so disarming first
      denies the straggler's Write; `_finish`'s own disarm is then a no-op.
    * the batch's entries are ledgered as the interrupt left them
      (`Ledger.rollback_rows`): `cancelled` for one it cut, a `rolled_back`
      marker BESIDE the real row of one that had completed. The real rows
      stand untouched -- spend is a fact -- and the marker is what says the
      artifact that spend bought was then deleted.
    * the batch's artifacts go, as a unit and by the list the manifest holds.
    * the interrupted phase's per-dispatch marker is given back, so the re-run
      starts with the retry budget it had rather than one interrupt poorer.
      Only `review` has one today (`persist.rollback_markers`: one charge per
      dispatched cell in `cell-attempts.json`); scout's and verify's counters
      are charges against a PREVIOUS reply and are left standing.

    Every step is wrapped in `except BaseException`, not `except Exception`: an
    operator who holds the key down -- or presses it again because the first
    Ctrl-C did not look like it had done anything -- raises a SECOND
    KeyboardInterrupt in the middle of this, and that is a BaseException, so an
    `except Exception` did not hold it. Escaping skipped `_finish` entirely:
    both guards stayed armed over the whole session and the kimi run home kept
    its config.toml and its credential symlinks. Every failure on the way out
    is reported under one `rollback incomplete:` clause instead.
    """
    if batch is None:
        return INTERRUPTED_IDLE
    notes, checkpoint, finished = [], req.get("checkpoint"), set(handled)
    try:
        if guards is not None:
            guards.disarm(pending)
    except BaseException as exc:          # noqa: BLE001 -- `loop` never raises
        notes.append("guards not disarmed: %s: %s" % (type(exc).__name__, exc))
    try:
        ledger.rollback_rows(pending, finished, checkpoint, mode, runner.host)
    except BaseException as exc:          # noqa: BLE001 -- `loop` never raises
        notes.append("the interrupt's own rows not written: %s: %s"
                     % (type(exc).__name__, exc))
    try:
        _removed, problems = batch.roll_back()
        notes += problems
        persist.rollback_markers(review_root, checkpoint, pending)
    except BaseException as exc:          # noqa: BLE001 -- `loop` never raises
        notes.append("%s: %s" % (type(exc).__name__, exc))
    return (INTERRUPTED % (done, total)
            + ("; rollback incomplete: " + "; ".join(notes) if notes else ""))


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


def checkpoint_roles(checkpoint):
    """The roles `checkpoint` dispatches -- `()` for anything else (#1727).

    `isinstance` FIRST, for the reason `base.registered_agent` does it: the
    checkpoint is read off the same target-writable request as `agent`, so it
    arrives as whatever the JSON says, and `dict.get` on an array or an object
    raises `TypeError: unhashable type`. `loop`'s catch-all turned that into
    an `error` naming a Python type rather than the routing refusal it is.
    `()` narrows -- it accepts no shell at all -- so an unknown or unhashable
    checkpoint fails CLOSED, exactly as `scan` does by design.
    """
    if not isinstance(checkpoint, str):
        return ()
    return CHECKPOINT_ROLES.get(checkpoint) or ()


def _allowed_shells(checkpoint):
    """The registered shell NAMES this checkpoint dispatches."""
    return {dispatch.registered_agent_name(dispatch.ROLE_FILES[role])
            for role in checkpoint_roles(checkpoint)
            if role in dispatch.ROLE_FILES}


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
    allowed = _allowed_shells(checkpoint)
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
    allowed = ", ".join(sorted(_allowed_shells(checkpoint))) or "no enforcement shell"
    return ("driver loop: entry %r names an enforcement shell its checkpoint does "
            "not dispatch (checkpoint %r dispatches: %s); the dispatch request does "
            "not match this run's own plan -- re-run with --reset"
            % (misrouted[0], checkpoint, allowed))


def disarm_previous(guards, prev_req):
    """R-P6-6 (session mode): on re-entry, drop the PREVIOUS request's grants
    before arming the current pending set. Uninstall is scoped by id/out_file
    and install unions, so an entry still pending is re-armed a few lines
    below (this iteration's own `guards.arm(pending)`, computed from the
    FRESH request `_first_run` just wrote) and only a FINISHED entry actually
    falls away -- no bookkeeping file needed to tell the two apart.

    `prev_req` must be the dispatch request as it stood BEFORE this
    invocation's own `driver.run`/`run_setup_flow` call rewrote
    dispatch-request.json (`loop` reads it first thing, before `_first_run`)
    -- reading it fresh here instead would see the very request this same
    invocation just produced, never the previous one, and disarm nothing.

    I4: CALLED only once this invocation has a live checkpoint of its own. An
    invocation that lands on complete/error instead never reaches here, so an
    errored re-entry (flag drift, a bad --pr) leaves the previous fan-out's
    grants exactly as it found them -- that fan-out is still running under
    them. Deferring the teardown past `_first_run`'s posture probe changes
    nothing that probe measures: probe_write_guard_armed proves the MECHANISM
    and the settings file, explicitly not live arming."""
    entries = [e for e in (prev_req or {}).get("entries") or [] if isinstance(e, dict)]
    if entries:
        guards.disarm(entries)


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


# #1732: the one line an operator gets when the CLI refuses the very flag it
# advertises. Said once per run, from the batch that measured it, because it
# is the one verdict that changes what the run does.
SHAPE_REFUTED_NOTICE = (
    "driver loop: host %r advertises %s but REFUSED it on one probe launch (%s) -- this "
    "run's entries launch without the flag and reply in fenced JSON, which the driver "
    "validates against the same schema on receipt")


def prove_output_schema_shape(run_dir, host, runner, pending, env_for):
    """Spend this run's ONE shape-proof launch, if it is owed (#1732).

    Called from `orchestrate.loop` after `Guards.arm(pending)` and before the
    batch's first `iter_batch`. That position is the whole point: the launch
    goes out under the read scope and write allowlist this batch just armed,
    and under the settings file `arm` just wrote -- confined exactly as a cell
    is. Proving it at posture time instead (where this started) meant one
    unconfined turn in the reviewed tree per run, before anything was armed,
    naming a settings file that did not exist yet.

    ONCE PER RUN, and the record is the run's own evidence artifact rather
    than anything in memory: a `paused` run resumed tomorrow reads the verdict
    back and launches nothing. `--reset` starts a new run folder and therefore
    measures again, which is exactly when a CLI upgrade should be re-measured.

    Owed only when there is something to measure AND something to measure it
    with: the flag is advertised (the `--help` read), the family declares one,
    no verdict is recorded yet, and this batch carries at least one
    schema-stamped `return_json` entry to clone a binding from. A checkpoint
    of self-writing entries, or a host that stamps nothing, simply waits for
    one that does.

    On `refuted` the flag comes off THIS batch's entries in memory, before
    they launch. The request FILE is left exactly as written -- its sha256 is
    what `load_bound_request` binds, and rewriting it mid-iteration would
    break that binding to save a stamp that the next `_run` will not re-apply
    anyway (`requests._materialize_prompts` consults the recorded shape).

    Returns the verdict, or None when no launch was owed. Never raises: this
    is one measurement, and a run must not end on it.
    """
    path = os.path.join(run_dir, runio.HOST_CAPABILITIES)
    body = runio._load_json(path)
    fact = ((body.get(hosts.CLI_FLAGS) if isinstance(body, dict) else None)
            or {}).get(hosts.OUTPUT_SCHEMA)
    if not isinstance(fact, dict) or fact.get(hosts.SHAPE):
        return None                       # never asked, or already answered
    if fact.get("advertised") is not True:
        return None
    if not (getattr(runner, "OUTPUT_SCHEMA_FLAG", ()) or ()):
        return None
    template = next((e for e in pending or ()
                     if isinstance(e, dict) and e.get("delivery") == "return_json"
                     and e.get("output_schema")), None)
    if template is None:
        return None
    entry = shape_probe.probe_entry(template, run_dir)
    if entry is None:
        return None                       # the probe schema is not published
    verdict = shape_probe.prove(host, runner, entry, env_for(entry))
    fact.update(verdict)
    try:
        runio._write_json(path, body)
    except (OSError, ValueError) as exc:   # noqa: BLE001 -- a lost record costs
        # one repeated launch next invocation; raising costs the run.
        print("driver loop: the output-schema shape verdict was not recorded (%s: %s)"
              % (type(exc).__name__, exc), file=sys.stderr, flush=True)
    if verdict.get(hosts.SHAPE) != hosts.SHAPE_REFUTED:
        return verdict
    for candidate in pending or ():
        if isinstance(candidate, dict):
            candidate.pop("output_schema", None)
    print(SHAPE_REFUTED_NOTICE
          % (host, fact.get("flag") or "an output-schema flag",
             verdict.get(hosts.SHAPE_DETAIL) or "no detail recorded"),
          file=sys.stderr, flush=True)
    return verdict
