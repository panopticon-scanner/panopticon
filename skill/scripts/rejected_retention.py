"""Retention for `<run_dir>/rejected/` (#1664).

`rejected_replies.retain_rejected` keeps every refused or failed reply, capped per
attempt, and before this nothing ever removed one: the per-run total was
attempts x entries x 256 KiB. The rule, decided once and applied by both
writers (the loop after each batch closes, `driver persist` after its own
record):

1. Keep the last `KEEP_PER_ENTRY` records of each entry, and NEVER the
   newest. Attempt numbers are read back from the folder listing, so pruning
   the newest would let numbering go backwards and reuse a path an older
   ledger row names; the newest is also what the retry prompt quotes.
2. Over `RUN_CEILING` bytes, evict the oldest records across entries, still
   never an entry's newest. The ceiling can therefore be exceeded by at most
   entries x one record.

Only this run's own records are counted or touched. `rejected/` is in the
reviewed tree (flat `.panopticon/` under `--setup`), so a file that does not
parse and bind -- right name, schema-valid, this run's id -- is a target's
file: it neither counts toward the ceiling nor gets evicted, and a planted
1 GiB file cannot force real evidence out.

A record any batch manifest on disk still lists is protected (#3351): a
receipt proves the exact set of a batch's artifacts that exist, so deleting
one while its manifest stands would roll a settled entry back on recovery.
An unreadable manifest protects everything: nothing is pruned.

Each prune appends a tombstone row to `rejected/pruned.jsonl` BEFORE the
file goes, so a ledger row's `rejected_file` either still exists or can be
shown as pruned (`resolve`).
"""
import hashlib
import json
import os
import sys
import time

import scripts.batch_settlement as batch_settlement
import scripts.phases.persist as persist
import scripts.phases.rejected_replies as rejected_replies
import scripts.phases.requests as requests
import scripts.runners.batch as batch_mod
import scripts.safe_write as safe_write

KEEP_PER_ENTRY = 3
RUN_CEILING = 32 * 1024 * 1024
TOMBSTONE = "pruned.jsonl"
# A record's reply is capped at REJECTED_CAP before JSON escaping, which can
# grow it up to 6x (`\u0000`). Anything larger was not written by this build.
RECORD_MAX = 8 * rejected_replies.REJECTED_CAP
TOMBSTONE_MAX = 16 * 1024 * 1024
PER_ENTRY = "per_entry"
CEILING = "ceiling"


def _bound_records(directory, run_id):
    """{entry_id: [record row]} for this run's own records; foreign files are left out."""
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return {}
    bound: dict[str, list[dict]] = {}
    for name in names:
        path = os.path.join(directory, name)
        try:
            raw = safe_write.read_regular_bytes(path, RECORD_MAX)
            record = json.loads(raw.decode("utf-8"))
        except (OSError, ValueError):
            continue
        entry_id = record.get("entry_id") if isinstance(record, dict) else None
        if (not isinstance(entry_id, str)
                or not batch_settlement.retained_record_valid(record, entry_id, run_id)
                or name != "%s-%d.json" % (requests.entry_file_component(entry_id),
                                           record["attempt"])):
            continue
        bound.setdefault(entry_id, []).append({
            "path": os.path.realpath(path), "entry_id": entry_id,
            "attempt": record["attempt"], "recorded_at": record["recorded_at"],
            "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    return bound


def _manifest_artifacts(run_folder):
    """Every artifact any batch manifest on disk lists, or None when one cannot be read."""
    try:
        names = os.listdir(run_folder)
    except FileNotFoundError:
        return set()
    except OSError:
        return None
    listed: set[str] = set()
    for name in names:
        if not batch_mod.MANIFEST_RE.fullmatch(name):
            continue
        try:
            doc = safe_write.read_manifest_json(os.path.join(run_folder, name))
            for row in doc["entries"]:
                listed.update(os.path.realpath(path) for path in row["artifacts"])
        except (OSError, ValueError, KeyError, TypeError):
            return None
    return listed


def plan(run_folder, run_id):
    """[(row, rule)] to prune, oldest first; empty when nothing may go."""
    if not run_folder or not run_id:
        return []
    protected = _manifest_artifacts(run_folder)
    if protected is None:
        return []
    bound = _bound_records(os.path.join(run_folder, persist.REJECTED_DIR), run_id)
    doomed, kept = [], []
    for rows in bound.values():
        rows.sort(key=lambda row: row["attempt"], reverse=True)
        protected.add(rows[0]["path"])
        for index, row in enumerate(rows):
            if index >= KEEP_PER_ENTRY and row["path"] not in protected:
                doomed.append((row, PER_ENTRY))
            else:
                kept.append(row)
    total = sum(row["bytes"] for row in kept)
    for row in sorted(kept, key=lambda row: (row["recorded_at"], row["attempt"], row["path"])):
        if total <= RUN_CEILING:
            break
        if row["path"] not in protected:
            doomed.append((row, CEILING))
            total -= row["bytes"]
    return doomed


def prune(run_folder, run_id):
    """Apply the rule; returns the paths removed. Best-effort: retention is
    housekeeping, so a failure here is reported and never fails the caller."""
    removed = []
    try:
        tombstone = os.path.join(run_folder, persist.REJECTED_DIR, TOMBSTONE)
        for row, rule in plan(run_folder, run_id):
            line = {"schema_version": 1, "run_id": run_id, "rule": rule,
                    "pruned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    **{key: row[key] for key in ("path", "entry_id", "attempt", "sha256", "bytes")}}
            with safe_write.open_a_nofollow(tombstone) as fh:
                fh.write(json.dumps(line, sort_keys=True) + "\n")
            safe_write.remove_artifact(row["path"])
            removed.append(row["path"])
    except Exception as exc:  # noqa: BLE001 -- housekeeping must not fail the run
        print("driver: rejected/ retention stopped: %s: %s" % (type(exc).__name__, exc),
              file=sys.stderr, flush=True)
    return removed


def resolve(run_folder, rejected_file, run_id):
    """What a ledger row's `rejected_file` names now: ("present", path),
    ("pruned", rule) or ("missing", None).

    The tombstone is in the reviewed tree too, so only a row of THIS run that
    names exactly this path counts; malformed lines are skipped."""
    if not rejected_file:
        return "missing", None
    if os.path.isfile(rejected_file) and not os.path.islink(rejected_file):
        return "present", rejected_file
    target = os.path.realpath(rejected_file)
    try:
        raw = safe_write.read_regular_bytes(
            os.path.join(run_folder, persist.REJECTED_DIR, TOMBSTONE), TOMBSTONE_MAX)
        lines = raw.decode("utf-8", "replace").splitlines()
    except (OSError, ValueError):
        return "missing", None
    for text in reversed(lines):
        try:
            row = json.loads(text)
        except ValueError:
            continue
        if (isinstance(row, dict) and run_id and row.get("run_id") == run_id
                and row.get("path") == target and row.get("rule") in (PER_ENTRY, CEILING)):
            return "pruned", row["rule"]
    return "missing", None
