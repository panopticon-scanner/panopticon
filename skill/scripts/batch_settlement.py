"""Crash-settlement proof and recovery helpers (#3351).

This is a flat module because artifact acceptance belongs to ``phases.persist``
while receipt signing belongs to the runner-side batch record.  Keeping the
join here preserves the ``runners -> phases`` boundary and gives the helpers
room without growing ``loop_batch.py`` past its pinned flat-module ceiling.

A receipt is only authority when all three layers still agree: its HMAC binds
the run and dispatch request, its ledger locator names the exact real row, and
its artifact list names schema-valid bytes.  Anything missing or changed is
unproved and follows the conservative rollback path.
"""
import hashlib
import os
import stat
import sys

import scripts.phases.persist as persist
import scripts.phases.requests as requests
import scripts.runners.outage as outage
import scripts.runners.settlement as settlement_mod


def context(review_root, namespace, request, request_sha256):
    """The #1727/run identity every receipt is authenticated against."""
    return {"run_id": request.get("run_id"),
            "review_root": os.path.abspath(review_root),
            "namespace": namespace or "", "request_sha256": request_sha256}


def recovery_context(review_root, namespace, request):
    """Rebuild the live writer's context from the request's recorded hash."""
    request_sha256 = requests.recorded_request_hash(review_root, namespace)[0]
    return context(review_root, namespace, request, request_sha256)


def _regular_sha256(path):
    """Digest one regular, unaliased artifact without following its leaf."""
    flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_NONBLOCK", 0))
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise OSError("settlement artifact is not a singly-linked regular file")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)
    finally:
        os.close(fd)


def _retained_artifact_valid(path, entry_id, run_id):
    record = persist._read_rejection(path)
    required = {"schema_version", "entry_id", "attempt", "kind", "run_id",
                "reason", "recorded_at", "reply"}
    return (isinstance(record, dict)
            and required <= set(record) <= required | {"truncated"}
            and record.get("schema_version") == 1
            and record.get("entry_id") == entry_id and record.get("run_id") == run_id
            and type(record.get("attempt")) is int and record["attempt"] >= 1
            and record.get("kind") in (persist.REFUSAL, persist.LAUNCH_FAILURE)
            and isinstance(record.get("reason"), str)
            and isinstance(record.get("recorded_at"), str)
            and isinstance(record.get("reply"), str)
            and ("truncated" not in record or type(record["truncated"]) is bool))


def artifact_proofs(entry, batch, run_id):
    """Artifact digests for a receipt, or None when an existing one fails shape."""
    entry_id = entry.get("id")
    primary = os.path.abspath(entry.get("out_file") or "")
    proofs = []
    for path in batch.entry_artifacts(entry_id):
        if not os.path.lexists(path):
            continue
        valid = (persist.is_done(entry) if path == primary
                 else _retained_artifact_valid(path, entry_id, run_id))
        if not valid:
            return None
        proofs.append({"path": path, "sha256": _regular_sha256(path)})
    return proofs


def _receipt_artifacts_match(entry, batch, receipt, run_id):
    """Recheck every artifact byte and the same acceptance boundary as settle."""
    try:
        paths = batch.entry_artifacts(entry.get("id"))
        existing = [path for path in paths if os.path.lexists(path)]
        proofs = receipt.get("artifacts")
        if (not isinstance(proofs, list)
                or [row.get("path") for row in proofs if isinstance(row, dict)] != existing):
            return False
        primary = os.path.abspath(entry.get("out_file") or "")
        for path, proof in zip(existing, proofs):
            valid = (persist.is_done(entry) if path == primary else
                     _retained_artifact_valid(path, entry.get("id"), run_id))
            if not valid or _regular_sha256(path) != proof.get("sha256"):
                return False
        return True
    except (OSError, ValueError):
        return False


def _settled_receipts(batch, pending, receipt_context, ledger, run_id):
    """Valid receipts, reason counts, and receipts proving a real row."""
    declared = {entry.get("id"): entry for entry in pending}
    settled, proved_rows = {}, set()
    counts = {"no receipt": 0, "ledger mismatch": 0, "artifact mismatch": 0}
    for row in batch.entries:
        entry_id = row.get("id")
        receipt = row.get("settlement")
        if receipt is None:
            counts["no receipt"] += 1
            continue
        if (not settlement_mod.verifies(
                receipt, context=receipt_context, batch=batch.number, nonce=batch.nonce,
                checkpoint=batch.checkpoint, entry_id=entry_id)
                or not ledger.matches_settlement(
                    receipt.get("ledger") if isinstance(receipt, dict) else None,
                    entry_id, batch.checkpoint)):
            counts["ledger mismatch"] += 1
            continue
        proved_rows.add(entry_id)
        if not _receipt_artifacts_match(declared[entry_id], batch, receipt, run_id):
            counts["artifact mismatch"] += 1
            continue
        settled[entry_id] = receipt
    return settled, counts, proved_rows


def partition_recovery(batch, pending, receipt_context, ledger, run_id, accounted):
    """Narrow a fresh crash to unproved entries, or resume prior accounting."""
    if accounted:
        # Re-stamp with this recovery pid. Receipts no longer participate once
        # a prior process published the recovering replay barrier.
        batch.begin_recovery()
        return pending, {}, None, set()
    settled, counts, proved_rows = _settled_receipts(
        batch, pending, receipt_context, ledger, run_id)
    unfinished = [entry for entry in pending if entry.get("id") not in settled]
    # One atomic write both removes proved entries from the deletion account
    # and publishes the replay barrier before any rollback effect.
    batch.narrow([entry.get("id") for entry in unfinished])
    return unfinished, settled, counts, proved_rows


def completed_entry_ids(batch, proved_rows):
    """Entries that need a ROLLED_BACK marker rather than CANCELLED."""
    return ({row["id"] for row in batch.entries
             if any(os.path.lexists(path) for path in row["artifacts"])}
            | proved_rows)


def account_rollback(review_root, batch, pending, unfinished, settled,
                     completed, ledger, mode, host):
    """Write fresh-crash rollback rows and refund every owed attempt."""
    ledger.rollback_rows(unfinished, completed, batch.checkpoint, mode, host,
                         reason="previous process stopped")
    refundable = [entry for entry in pending
                  if (receipt := settled.get(entry.get("id"))) is not None
                  and receipt.get("refund_attempt") is True]
    persist.rollback_markers(
        review_root, batch.checkpoint, unfinished + refundable)


def publish(entry, result, refusal, batch, ledger_span, request):
    """Best-effort publication after the real ledger row is already durable."""
    receipt_context = getattr(batch, "settlement_context", None)
    if not isinstance(receipt_context, dict) or not isinstance(ledger_span, dict):
        return
    entry_id = entry.get("id")
    try:
        artifacts = artifact_proofs(entry, batch, request.get("run_id"))
        if artifacts is not None:
            batch.settle(
                entry_id, context=receipt_context, ledger=ledger_span, artifacts=artifacts,
                refund_attempt=(outage.landed_class(result, refusal) == outage.HOST_FAILURE))
    except Exception as exc:  # noqa: BLE001 -- best-effort crash evidence
        print("driver loop: %s settlement receipt not recorded (%s); a crash "
              "will roll this entry back" % (entry_id, type(exc).__name__),
              file=sys.stderr, flush=True)


def report_recovery(batch, accounted, settled, unfinished, reason_counts, removed):
    """Print bounded proof counts, then the longstanding recovery summary."""
    if reason_counts is not None:
        print("driver loop: stale batch %s settlement proof: kept %d entries; "
              "rolled back %d (no receipt %d, ledger mismatch %d, "
              "artifact mismatch %d)"
              % (batch.number, len(settled), len(unfinished),
                 reason_counts["no receipt"], reason_counts["ledger mismatch"],
                 reason_counts["artifact mismatch"]),
              file=sys.stderr, flush=True)
    action = ("finished the interrupted recovery of stale batch %s" % batch.number
              if accounted else "recovered stale batch %s" % batch.number)
    print("driver loop: %s; removed %d artifact(s); retrying %s"
          % (action, len(removed), batch.checkpoint), file=sys.stderr, flush=True)
