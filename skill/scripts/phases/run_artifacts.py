"""The driver plan, review-output snapshot and prompt index artifacts.

These helpers moved whole from :mod:`scripts.phases.requests` when that module
reached the 700-line ceiling.  ``requests`` re-exports both private names so
the review, verify, synthesize, and test call sites keep one stable seam.
The --reset sweep (``_RESET_GLOBS``, ``_clear_run_artifacts``) moved whole from driver.py.
"""
import glob as _glob
import json
import os
import shutil
import sys

import scripts.group_runner as group_runner
import scripts.loop_batch as loop_batch
import scripts.plan_contract as plan_contract
import scripts.run_manifest as run_manifest
import scripts.safe_write as safe_write
import scripts.tolerant_json as tolerant_json
from . import coverage
from . import runio

_PROMPT_INDEX_MAX = 16 * 1024 * 1024


def _driver_plan_entries(review_root, manifest, targeted_by_group=None):
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
            entry = {
                "group": group, "domain": domain, "enforced": enforced,
                "out_file": os.path.abspath(
                    runio._pano(review_root, "findings-%s-%s.json" % (group, domain)))}
            targets = ((targeted_by_group or {}).get(group, ())
                       if domain == "SEC" else ())
            if targets:
                entry["targeted_review"] = list(targets)
            entries.append(entry)
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


_RESET_GLOBS = ("groups.json", "coverage-*.json", "scout-*.json", "tools-ran.json",
                "validate.json",
                "report.json", "dispatch-request.json",
                # #1809: the trailing `*` sweeps a `tree-baseline.txt.tmp` orphaned by a SIGKILL
                # between the staging open and the replace -- --reset is the corrupt-baseline remedy.
                "tree-baseline.txt*",
                "verify-queue.json", "findings-*.json",
                # #5.0-07: stale delta artifacts must not survive a --reset and silently delta-scope
                # (or content-check) the next run. #5.0-16: the driver's own dispatch plan clears
                # too, so a --reset run re-declares cells from fresh coverage.
                "diff-hunks.json", "out-file-hashes.json",
                "dispatch-plan-driver.json",
                # #1637 P08: the readiness verdict and the per-cell
                # scanner-context tally are both run-scoped facts -- a --reset
                # must not resume on the previous run's answer to either.
                "readiness.json", "panel-tools-context.json",
                # #1638 P13: the per-group test-inventory verdict is derived
                # from THIS run's assignment, so a --reset that re-discovers
                # must not resume on the previous run's answer either.
                "panel-test-inventory.json",
                # #1513: the per-cell retry budget is run-scoped -- a --reset
                # must not start with a cell already exhausted.
                # #1809: its three siblings are run-scoped for the same
                # reason, and an unreadable one now names --reset as the
                # remedy, so the legacy flat sweep has to actually clear them
                # (`scout-*.json` already covers the scout counter, and
                # discovery-attempts.json's own docstring already claimed it).
                "cell-attempts.json", "verify-attempts.json",
                "discovery-attempts.json")


def _clear_run_artifacts(review_root):
    """--reset: clear the current run's working folder (findings / verdicts /
    coverage / scouts / dispatch / ...) so a fresh run starts, while KEEPING the
    durable top-level tag-named report — reset reclaims the scratch, not the
    deliverable (§5.1). NEVER touches the committed root config — since #1681
    the matrix lives outside `.panopticon/` entirely — or another run's
    folder/report. MUST run BEFORE the manifest is removed, so the tag still
    resolves; with no/corrupt manifest it degrades to the legacy flat sweep.
    Both callers run after first contact (#3271), which vetted `.panopticon/`
    and every manifest in it."""
    base = os.path.join(os.path.abspath(review_root), plan_contract.ARTIFACT_DIR)
    manifest = run_manifest.load_manifest(review_root)
    tag = run_manifest.run_tag(manifest) if manifest else None

    # Collect and vet EVERY destination before the first removal. A linked
    # `runs` parent must never redirect the active folder or `latest` unlink.
    run_dir = os.path.join(base, "runs", tag) if tag else None
    latest = os.path.join(base, "runs", "latest")
    paths = []
    # Migration safety: sweep any legacy FLAT run artifacts a pre-5.1 run may have left at top-level.
    # The report.json SYMLINK points at the durable tag-named report and is kept; only a STALE FLAT
    # report.json (a real file -- pre-5.1 or a corrupt/orphaned state) is swept, preserving the I1
    # no-resume-on-stale-data invariant. The tag-named reports themselves are never in _RESET_GLOBS.
    for pat in _RESET_GLOBS:
        for path in _glob.glob(os.path.join(base, pat)):
            if os.path.basename(path) == "report.json" and os.path.islink(path):
                continue
            paths.append(path)
    dirs = [os.path.join(base, sub) for sub in ("tools", "verdicts")]
    candidates = [run_dir, latest] + paths + dirs if run_dir else paths + dirs
    for path in candidates:
        runio._confine_link_parent(path)

    def remove_dir(path):
        if os.path.islink(path):
            os.unlink(path)  # remove only the final link, never its referent
        elif os.path.isdir(path):
            shutil.rmtree(path)

    if run_dir:
        remove_dir(run_dir)
        if os.path.lexists(latest):
            os.unlink(latest)
    for path in paths:
        if os.path.isdir(path) and not os.path.islink(path):   # #2095: the tree's, never ours
            print("driver: --reset left %s alone: a directory is never a run artifact of ours"
                  % path, file=sys.stderr, flush=True)
            continue
        os.remove(path)
    for path in dirs:
        remove_dir(path)
