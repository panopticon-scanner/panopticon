"""The driver plan, review-output snapshot and prompt index artifacts.

These helpers moved whole from :mod:`scripts.phases.requests` when that module
reached the 700-line ceiling.  ``requests`` re-exports both private names so
the review, verify, synthesize, and test call sites keep one stable seam.
"""
import json
import os
import sys

import scripts.group_runner as group_runner
import scripts.loop_batch as loop_batch
import scripts.run_manifest as run_manifest
import scripts.safe_write as safe_write
import scripts.tolerant_json as tolerant_json
from . import coverage
from . import runio

_PROMPT_INDEX_MAX = 16 * 1024 * 1024


def _driver_plan_entries(review_root, manifest):
    """The declared review cells as a matrix domain-cell dispatch plan
    (#5.0-16). Computed DETERMINISTICALLY from groups.json (each discovered
    group) x its effective domains -- the SAME two sources review_execute
    dispatches from (_discovered_groups x _effective_domains) -- with the EXACT
    out_file spelling _cell_entry uses, so synth.integrity.reconcile_findings_files
    sees no missing/unexpected on a clean run. `enforced` mirrors _cell_entry so
    plan_mod.derive_tool_policy_mode reports the run's real posture rather than
    defaulting to "advisory". No `files`/`role`/`model` -- this is a
    declaration of which out_files must exist, not a scope grant or a cost row;
    the dispatch entries carry scope (F4 `files`, plan 5 `scope`) and this
    deliberately does not (R-P5-6)."""
    enforced = loop_batch.expected_enforced(review_root, manifest.get("host", "claude"))
    entries = []
    for group, _files in coverage._discovered_groups(review_root):
        for domain in coverage._effective_domains(review_root, group):
            entries.append({
                "group": group, "domain": domain, "enforced": enforced,
                "out_file": os.path.abspath(
                    runio._pano(review_root, "findings-%s-%s.json" % (group, domain)))})
    return entries


def _snapshot_review_out_files(review_root, manifest):
    """Snapshot a sha256 per declared review cell at the review->verify boundary
    (#5.0-16 H3), so synthesize's verify_out_file_hashes (content-substitution
    detection) is live on the driver path. Runs after review_done (every cell
    written) and before any verify-phase agent can touch a findings file, so a
    later substitution -- e.g. by a rogue advisor on the unenforced generic host
    -- is caught. Idempotent AND one-way: if the snapshot already exists it is
    NOT rewritten, nor re-taken once DELETED -- either masks a substitution
    (SEC-377944137; `run_manifest.claim_artifact`)."""
    path = runio._pano(review_root, "out-file-hashes.json")
    if os.path.isfile(path):
        return path
    entries = _driver_plan_entries(review_root, manifest)
    if not entries:
        return None
    written = run_manifest.claim_artifact(   # None: owed and gone -- never re-taken
        review_root, manifest, run_manifest.OUT_FILE_SNAPSHOT, path,
        lambda: group_runner.snapshot_out_files(entries, out_path=os.path.abspath(path)),
        cells=len(entries),
        stamp_fields=lambda result: {"sha256": result[1]})
    return path if written and written[0] else None


def write_prompt_index(path, written):
    """`_prompts/index.json`, {entry id: its prompt file's name} (#3233): an id holding a `:` is
    stored under a hash, so nothing else finds `Orchestration:Core`'s prompt by name. For an
    operator: no run reads it back and no agent is granted it, so a lost or planted one costs a
    lookup. Once per pass and merged, because each checkpoint writes its own prompts."""
    if not written:
        return
    try:
        try:
            raw = safe_write.read_regular_bytes(path, _PROMPT_INDEX_MAX)
            found = json.loads(tolerant_json.depth_checked(raw.decode("utf-8")))
        except (OSError, ValueError):
            found = None             # absent, or not ours: this pass's names are still true
        kept = ({k: v for k, v in found.items() if isinstance(v, str)}
                if isinstance(found, dict) else {})
        runio._write_json(path, dict(kept, **written))
    except (OSError, ValueError) as exc:
        print("driver: could not write the prompt index (%s); the prompts still stand" % exc,
              file=sys.stderr, flush=True)
