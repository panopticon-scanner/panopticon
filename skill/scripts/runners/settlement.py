"""Authenticated per-entry settlement receipts for crash recovery (#3351).

The receipt lives in the target-writable batch record, so its bytes alone are
not authority.  Its HMAC key is the existing machine-local run-stamp key under
``$PANOPTICON_STATE_DIR``; dispatched agents never receive that key.  This is
the same boundary as first contact's #3271 stamp: another process running as
the invoking user can read the key and can therefore forge either kind.

This module deliberately knows nothing about artifact schemas or dispatch
requests.  The loop supplies already-derived facts and, on recovery, checks
them against the bound request and the files on disk.  Keeping that half out
of ``runners`` preserves the package boundary pinned by ``tests/test_layout``.
"""
import hashlib
import hmac
import json
import os
import re

import scripts.run_stamp as run_stamp


VERSION = 1
DOMAIN = "panopticon-batch-settlement-1"
_DOMAIN_BYTES = (DOMAIN + "\0").encode("ascii")
_HEX_64 = re.compile(r"[0-9a-f]{64}")
_HEX_32 = re.compile(r"[0-9a-f]{32}")


def _canonical(body):
    return json.dumps(body, ensure_ascii=True, separators=(",", ":"),
                      sort_keys=True).encode("utf-8")


def _mac(body):
    return hmac.new(run_stamp.key(), _DOMAIN_BYTES + _canonical(body),
                    hashlib.sha256).hexdigest()


def _context_ok(context):
    return (isinstance(context, dict)
            and isinstance(context.get("run_id"), str) and bool(context["run_id"])
            and isinstance(context.get("review_root"), str)
            and os.path.isabs(context["review_root"])
            and isinstance(context.get("namespace"), str)
            and isinstance(context.get("request_sha256"), str)
            and _HEX_64.fullmatch(context["request_sha256"]) is not None)


def _ledger_ok(ledger):
    return (isinstance(ledger, dict) and ledger.get("version") == 1
            and type(ledger.get("start")) is int and ledger["start"] >= 0
            and type(ledger.get("end")) is int and ledger["end"] > ledger["start"]
            and isinstance(ledger.get("sha256"), str)
            and _HEX_64.fullmatch(ledger["sha256"]) is not None)


def _artifacts_ok(artifacts):
    if not isinstance(artifacts, list) or len(artifacts) > 8:
        return False
    paths = set()
    for artifact in artifacts:
        if (not isinstance(artifact, dict) or set(artifact) != {"path", "sha256"}
                or not isinstance(artifact.get("path"), str)
                or not os.path.isabs(artifact["path"])
                or artifact["path"] in paths
                or not isinstance(artifact.get("sha256"), str)
                or _HEX_64.fullmatch(artifact["sha256"]) is None):
            return False
        paths.add(artifact["path"])
    return True


def _body_ok(body):
    return (isinstance(body, dict)
            and body.get("version") == VERSION and body.get("domain") == DOMAIN
            and _context_ok(body.get("context"))
            and type(body.get("batch")) is int and body["batch"] >= 1
            and isinstance(body.get("nonce"), str)
            and _HEX_32.fullmatch(body["nonce"]) is not None
            and isinstance(body.get("checkpoint"), str) and bool(body["checkpoint"])
            and isinstance(body.get("entry_id"), str) and bool(body["entry_id"])
            and _ledger_ok(body.get("ledger"))
            and _artifacts_ok(body.get("artifacts"))
            and type(body.get("refund_attempt")) is bool)


def issue(*, context, batch, nonce, checkpoint, entry_id, ledger, artifacts,
          refund_attempt):
    """Return one versioned receipt, signed after the ledger append landed."""
    body = {"version": VERSION, "domain": DOMAIN, "context": dict(context),
            "batch": batch, "nonce": nonce, "checkpoint": checkpoint,
            "entry_id": entry_id, "ledger": dict(ledger),
            "artifacts": [dict(row) for row in artifacts],
            "refund_attempt": refund_attempt}
    if not _body_ok(body):
        raise ValueError("invalid settlement receipt fields")
    return {**body, "hmac_sha256": _mac(body)}


def verifies(receipt, *, context, batch, nonce, checkpoint, entry_id):
    """Whether ``receipt`` is ours and names this exact batch entry."""
    if not isinstance(receipt, dict):
        return False
    signature = receipt.get("hmac_sha256")
    body = {key: value for key, value in receipt.items() if key != "hmac_sha256"}
    if (set(receipt) != set(body) | {"hmac_sha256"}
            or not isinstance(signature, str) or _HEX_64.fullmatch(signature) is None
            or not _body_ok(body)
            or body["context"] != context or body["batch"] != batch
            or body["nonce"] != nonce or body["checkpoint"] != checkpoint
            or body["entry_id"] != entry_id):
        return False
    try:
        return hmac.compare_digest(signature, _mac(body))
    except (TypeError, ValueError, run_stamp.KeyUnavailable):
        return False
