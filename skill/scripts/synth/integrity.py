"""Findings-file integrity: planned vs ingested files, labels, the unenforced
ack, and `INTEGRITY_KEYS` -- the one table naming which of those facts sinks
certification and what the summary says when one does."""
import hashlib
import json
import os
import sys

import scripts.group_runner as group_runner
import scripts.findings_contract as findings_contract
import scripts.integrity_messages as integrity_messages
import scripts.tools.base as tool_base

# Module-attribute access only (spec §3 rule 1): the package's cycle through
# this module is `integrity -> plan -> tool_axis -> integrity`, with
# `render -> integrity` alongside it, and every edge is safe precisely because
# none of them touches a sibling at import time -- only at call time.
from . import artifacts as artifacts_mod
from . import plan as plan_mod
from . import findings as findings_mod


# Shared with the flat HTML renderer so both human surfaces use one table.
# These documented aliases preserve the package API used by render/tool_axis.
IntegrityKey = integrity_messages.IntegrityKey
INTEGRITY_KEYS = integrity_messages.INTEGRITY_KEYS


def evidence_text(key, value):
    """Terminal-safe evidence for a shared integrity sentence's `%s` slot.

    The raw formatter lives beside the shared sentence table. Neutralization
    stays at this terminal producer boundary; HTML applies its own escaping.
    """
    return tool_base.inert_text(integrity_messages.raw_evidence_text(key, value))


def duplicate_out_files(plan):
    """out_file values assigned to more than one reviewer entry in the merged
    plan (#936). A collision means two reviewers share a write target and one
    silently overwrites the other — a coverage risk that
    reconcile_findings_files' set-keyed view structurally cannot see."""
    if not isinstance(plan, list):
        return []
    seen: set[str] = set()
    dupes: set[str] = set()
    for e in plan:
        if isinstance(e, dict) and isinstance(e.get("out_file"), str) and e.get("out_file"):
            of = os.path.normpath(e["out_file"])
            (dupes if of in seen else seen).add(of)
    return sorted(dupes)

def _expected_from_filename(path):
    """(group, domain) declared by a reviewer findings filename, or None when
    the name is not a reviewer findings file or its trailing token is not a
    known OCRDb domain. Takes a path or a bare name -- `cell_of` basenames it.

    `findings_contract.cell_of` owns the parse (ARC-3899903550, #1765); this is
    the tuple the callers below unpack. #run10: the check keyed on the 4.x
    `-panel_review` / `-lens_sweep-<lens>` suffix until those roles were retired
    (#1441). The only findings filename the pipeline can produce is
    phases.review._cell_entry's `findings-<group>-<domain>.json`, which never
    matched -- so every caller below silently returned "nothing wrong" on every
    5.x run.
    """
    cell = findings_contract.cell_of(path)
    return (cell[0], cell[1]) if cell else None

def mislabeled_findings_files(paths):
    """Reviewer findings files whose CONTENT contradicts the (group, domain)
    cell their filename declares (#937) — a mis-targeted or overwritten write.

    Flags a file as soon as its `_panopticon` cell stamp, or any finding's
    own `domain`, clearly disagrees with the filename; absent fields are
    never second-guessed. This is the byte-identity follow-up SKILL.md
    step 9 names. Distinct from phases.review._get_valid_cell_data, which guards the
    same stamp at review-phase done-detection for the cells the driver itself
    dispatched: this one screens whatever synthesize was actually handed."""
    bad = []
    for p in paths or []:
        exp = _expected_from_filename(p)
        if not exp:
            continue
        group, domain = exp
        try:
            data = artifacts_mod.read_json(p, tolerant=True, announce=True)
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        meta = data.get("_panopticon")
        if isinstance(meta, dict):
            md, mg = meta.get("domain"), meta.get("group")
            if (md and md != domain) or (mg and mg != group):
                bad.append(p)
    return sorted(set(bad))

def malformed_findings_files(paths):
    """Findings files that violate the shared contract, with what was dropped.

    #1513: a stamped cell whose `findings` list held a non-object was accepted
    everywhere -- the driver called it a completed review, and synthesis turned
    it into `findings: []` with `schema_errors: 0` and certified PASS. Dropped
    entries existed only as a line on stderr, so a report built from garbage was
    byte-indistinguishable from one built from a clean, empty review.

    Returns ``[{"file", "cell", "defects"}]``, sorted by file. Screens whatever
    synthesize was HANDED, which is why it also catches direct synthesis on a
    malformed cell -- fixing only the driver's done-predicate would leave
    `synthesize.py` able to certify invalid input on its own.
    """
    out = []
    for p in paths or []:
        try:
            data = artifacts_mod.read_json(p, tolerant=True)
        except (OSError, ValueError) as e:
            out.append({"file": str(p), "cell": findings_contract.cell_of(p),
                        "defects": [{"index": None,
                                     "reason": artifacts_mod.read_failure_reason(e)}]})
            continue
        defects = findings_contract.payload_defects(data)
        if defects:
            out.append({"file": str(p), "cell": findings_contract.cell_of(p),
                        "defects": defects})
    return sorted(out, key=lambda d: d["file"])


def cross_domain_findings(paths):
    """Findings filed under a domain other than their cell's — REPORTED, never gating.

    #calibration-4 (gotify): #1443 revived this file's integrity check by
    re-pointing it from the dead 4.x `source_role`/`panel` fields to the 5.x
    shape, and while doing so also compared each finding's own `domain` to the
    filename's. Those two comparisons answer different questions. `source_role`
    and `panel` are PROVENANCE -- who wrote this file -- and their faithful 5.x
    analogue is the `_panopticon` stamp, which mislabeled_findings_files still
    checks and still gates on. A finding's `domain` is a CONTENT
    classification: an ARC reviewer that files a TST finding has not
    mis-targeted its write, it has stepped outside its lane.

    Treating the second as an integrity failure sank certification on a run
    whose file integrity was perfect: 0 stamp mismatches across 160 files, and
    3 cross-domain findings in 2 of them -- every one a `TST-X0X`, the
    catalog-gap code, filed by a reviewer that saw a testing gap and had no
    code in its own domain for it. Failing a whole run for that penalises
    exactly the gap-reporting the X0X schema exists to collect.

    So report it instead. Cross-domain filing is worth seeing -- it is a real
    signal about panel discipline and about catalog gaps -- but it is evidence
    about the REVIEW, not about whether the artifacts on disk can be trusted.
    """
    out = []
    for p in paths or []:
        exp = _expected_from_filename(p)
        if not exp:
            continue
        _group, domain = exp
        try:
            data = artifacts_mod.read_json(p, tolerant=True, announce=True)
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        findings = data.get("findings")
        if not isinstance(findings, list):
            continue
        for f in findings:
            if not isinstance(f, dict):
                continue
            f = findings_mod.agent_finding(f, p)
            fd = f.get("domain")
            if not fd or fd == domain:
                continue
            # #1639 P15: this row is copied out of an AGENT payload into a
            # section the schema pins as strings, so it is normalized at the
            # boundary like every other agent input -- the schema pins the
            # CONTROLLER's output, and a reviewer that wrote `"code": 7` must
            # not be able to end a completed run in `error`. A non-string
            # domain names no cell, so the row goes; a non-string code is a
            # lossless str() (the row's point is the DOMAIN mismatch).
            if not isinstance(fd, str):
                print("integrity: %s: dropped a cross-domain row whose finding "
                      "domain is not a string" % p, file=sys.stderr)
                continue
            code = f.get("ocrdb_code") or f.get("code")
            if code is not None and not isinstance(code, str):
                code = str(code)
            out.append({"file": p, "cell_domain": domain,
                        "finding_domain": fd, "code": code})
    return sorted(out, key=lambda r: (r["file"], str(r["finding_domain"]), str(r["code"])))

def reconcile_findings_files(plan, ingested_paths):
    """(#146) Reconcile the findings files synthesize ingested against the
    dispatch plan's declared reviewer out_files. Returns (unexpected, missing)
    as sorted lists of the ORIGINAL path strings. Skipped (empty, empty) when
    no plan is present — an ordinary non-fan-out run, not tampering.
    """
    if not isinstance(plan, list) or not plan:
        return [], []
    # realpath, not abspath (#947 FIXME-1): macOS temp worktrees live under
    # /var/folders/... which is a SYMLINK to /private/var/... -- a cwd inside
    # the worktree yields /private/var paths while the plan recorded /var
    # ones, and abspath comparison flagged every file on a clean run.
    planned = {os.path.realpath(e["out_file"]): e["out_file"] for e in plan
               if isinstance(e, dict) and isinstance(e.get("out_file"), str)
               and e.get("out_file")}
    ingested = {os.path.realpath(p): p for p in ingested_paths or []}
    unexpected = sorted(ingested[a] for a in ingested if a not in planned)
    missing = sorted(planned[a] for a in planned if a not in ingested)
    return unexpected, missing

def _plan_hash(plan):
    """The one implementation of the review plan's content hash, with no twin
    to keep in sync: the `dispatch.plan_content_hash` this once mirrored
    (#493 R2) went with the 4.x DispatchPlan builder and no longer exists.

    Every `plan_sha256` in the tree is this function's output. `phases/requests.py`
    and `phases/setup_ack.py` stamp it, `run_manifest.record_artifact_stamp`'s
    docstring names it as the canonical hash the artifact stamp carries, and the
    two checks in this module -- the #493 R2 ack-staleness test and the
    substituted-plan test below -- re-derive it from the plans on disk."""
    return hashlib.sha256(
        json.dumps(plan, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

def read_unenforced_ack(path=os.path.join(".panopticon", "unenforced-ack.json")):
    """Return the full ack dict when dispatch recorded --allow-unenforced, {} otherwise.

    The return value is truthy when acknowledged and falsy (empty dict) when not.
    Extra fields written by dispatch (e.g. ``write_guard_covers_bash``, ``note``)
    are included so callers can surface them in ``meta.integrity`` (#680).
    Unreadable/malformed => {} (tolerant)."""
    try:
        data = artifacts_mod.read_json(path, announce=True)
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict) or not data.get("acknowledged"):
        return {}
    return data


def _owes_a_snapshot(run_dir):
    """True when this run's driver plan declares at least one review cell.

    That plan is what `_snapshot_review_out_files` hashes, so its presence is
    exactly the condition under which a snapshot must exist. A missing or empty
    plan means no cells were declared and nothing could have been snapshotted.
    Unreadable is treated as NOT owing: a corrupt plan is already reported by
    the plan loader, and inferring a second failure from it would double-count
    one fault.
    """
    try:
        entries = artifacts_mod.read_json(
            os.path.join(run_dir, plan_mod.DRIVER_DISPATCH_PLAN), announce=True)
    except (OSError, ValueError):
        return False
    return isinstance(entries, list) and any(isinstance(e, dict) for e in entries)


def load_verify_queue(run_dir):
    """(queue, invalid_reason) for <run_dir>/verify-queue.json: the parsed
    queue when it is a dict with an `entries` list, else None plus the reason
    meta.integrity.invalid_verify_queue reports; (None, None) with no file.

    Lives here, beside the section it feeds, rather than in `plan`: it exists
    only to produce `invalid_verify_queue`, and `plan` needed the ten lines back
    (#1644 put it at its 700-line ceiling). Behaviour is unchanged.
    """
    path = os.path.join(run_dir, "verify-queue.json")
    if not os.path.lexists(path):
        return None, None
    try:
        loaded = artifacts_mod.read_json(path)
    except (OSError, ValueError) as exc:
        return None, "cannot read verify queue: %s" % exc
    if isinstance(loaded, dict) and isinstance(loaded.get("entries"), list):
        return loaded, None
    return None, "verify queue has no entries list"


def _discovery_disclosures(discovery):
    """Discovery's two DEGRADATION disclosures out of the run folder's
    `groups.json` `discovery` block, as `(git_failure, files_truncated)`
    (#2271).

    `(None, None)` for an absent or unusable block -- NOT MEASURED, which is
    what a direct `synthesize.py` call over hand-collected findings publishes
    and what a run folder written before the block existed (#1576) carries. A
    measured `0` truncation is a different fact and survives as `0`:
    `discovery._discovery_block` publishes it on every scan precisely so a
    reader comparing two runs can see that this one reviewed the whole tree
    rather than a prefix of it.

    isinstance-guarded, because `groups.json` is written inside the reviewed
    tree and a hostile target can pre-commit one. `repair.repair_groups_json`
    pins the five fields of that file which already reached the artifact; these
    two are pinned here, at the boundary that publishes them, for the same
    reason. A bool is not an integer for this purpose -- `jsonschema` rejects
    `True` where `integer` is pinned, so an unrepaired one would fail the
    artifact it rode into.
    """
    block = discovery if isinstance(discovery, dict) else {}
    failure, truncated = block.get("git_failure"), block.get("files_truncated")
    # An empty reason is the no-failure case `None` already means, and a
    # negative count is not a measurement this pipeline can produce
    # (`_cap_discovered` writes `max(0, ...)`): both publish None (#2271 review).
    return ((failure or None) if isinstance(failure, str) else None,
            truncated if isinstance(truncated, int)
            and not isinstance(truncated, bool) and truncated >= 0 else None)


def integrity_section(plan_lists, files, run_dir, plans_seen, invalid_plans,
                      invalid_verify_queue, plan_owed=False, plan_sha256=None,
                      discovery=None):
    """`meta.integrity` as main() assembled it (WS-0 S3): planned-vs-ingested
    findings files, out_file collisions, mislabeled / cross-domain files, the
    unenforced ack (+ its #493 staleness check), the #493 R4 content-hash
    check, the plan-loader's own counts, and discovery's two degradation
    disclosures. `plan_lists` is the per-file list
    load_dispatch_plans_detailed returned; `plans_seen` / `invalid_plans`
    / `invalid_verify_queue` are that loader's and load_verify_queue's
    disclosures, carried through so "no plan found" and "reconciled, nothing
    wrong" read apart.

    `plan_owed` / `plan_sha256` are the driver's statement that this run WROTE a
    dispatch plan, and the content hash its manifest stamped for it
    (SEC-377944137, #1832) -- see `dispatch_plan_missing` /
    `dispatch_plan_mismatched` below. Both are threaded from
    `phases/synthesize.py` rather than read here so this package stays free of
    `scripts.run_manifest`, and both default to "nothing claimed" because a
    direct `synthesize.py` call over hand-collected findings has no driver to
    ask.

    `discovery` is the run's `groups.json` `discovery` block (#2271), threaded
    through `plan.PlanInputs.load` on the same seam as those two and defaulting
    to None for the same reason -- see `_discovery_disclosures` for what it
    publishes and why each field is guarded."""
    plan = [e for pl in plan_lists for e in pl]
    unexpected, missing = reconcile_findings_files(plan, files)
    ack = read_unenforced_ack(os.path.join(run_dir, "unenforced-ack.json"))
    # #493 R2: an ack with no run binding over-reports risk forever -- a
    # stale ack from an earlier --allow-unenforced run would mark a fully
    # enforced run acknowledged. The ack now carries plan_sha256 (canonical
    # hash of the plan content it acknowledged); treat a non-matching ack as
    # STALE: report false + a loud note. A legacy ack without the field stays
    # trusted (pre-#493 artifacts).
    ack_stale = False
    if ack and ack.get("plan_sha256") is not None and plan_lists:
        hashes = {_plan_hash(pl) for pl in plan_lists}
        if ack["plan_sha256"] not in hashes:
            ack_stale = True
            print("synthesize: unenforced-ack.json does not hash-match any "
                  "on-disk dispatch plan -- STALE ack from a previous run; "
                  "reporting unenforced_acknowledged: false", file=sys.stderr)
    # #493 R4: after-the-fact content check -- when the orchestrator recorded
    # out-file hashes at fan-out end, verify the ingested bytes still match.
    #
    # #1511 (Codex BR-01): read the snapshot from THIS run's folder, explicitly.
    # The driver writes it per-run (`runs/<tag>/out-file-hashes.json`) while the
    # verifier defaulted to top-level `.panopticon/`, found nothing, and reported
    # a run that never had a snapshot -- so the guard was inactive on every
    # ordinary driver run, and run-11 shipped CERTIFIED with
    # content_hashes_checked null. run_dir is the same context every other run
    # artifact resolves against (ack, plans, tool manifest); naming the path here
    # also means a stale top-level snapshot can neither substitute for the
    # active run's nor manufacture a mismatch in it.
    snapshot_path = os.path.join(run_dir, "out-file-hashes.json")
    content_checked, content_mismatched, content_snapshot_unreadable = \
        group_runner.verify_out_file_hashes(files, hashes_path=snapshot_path)
    # #1208: absence used to read as a benign "not measured", which made deleting
    # the baseline the cheapest way to erase evidence of a substitution. A run
    # whose driver plan DECLARES cells owed a snapshot, so absence there is a
    # deleted baseline, not an ordinary non-fan-out run. A run that owes nothing
    # (no driver plan, or one declaring nothing) keeps the benign reading.
    content_snapshot_missing = (not os.path.isfile(snapshot_path)
                                and _owes_a_snapshot(run_dir))
    if content_snapshot_missing:
        print("synthesize: this run's dispatch plan declares review cells, so a "
              "fan-out out-file-hashes.json snapshot is OWED -- none is present at "
              "%s. Treating as a deleted baseline (fail-closed), not an unmeasured "
              "run; integrity is NOT certified." % snapshot_path, file=sys.stderr)
    if content_mismatched:
        print("synthesize: %d findings file(s) changed AFTER the fan-out "
              "snapshot (content substitution?): %s"
              % (len(content_mismatched), ", ".join(content_mismatched)),
              file=sys.stderr)
    if content_snapshot_unreadable:
        # #run7 #1208: a present-but-corrupt out-file-hashes.json is a tamper
        # signal, not a missing snapshot -- fail closed rather than silently pass.
        print("synthesize: the fan-out out-file-hashes.json snapshot EXISTS but is "
              "unreadable/corrupt -- treating as tamper (fail-closed), not a missing "
              "snapshot; integrity is NOT certified.", file=sys.stderr)
    # SEC-377944137 (#1832): #1208's reasoning applied to the file one level up.
    # Every check keyed on the driver plan reads its ABSENCE as owing nothing --
    # `_owes_a_snapshot` above returns False, `reconcile_findings_files` returns
    # ([], []) by design, `duplicate_out_files([])` is [], and
    # `empty_dispatch_plans` counts empty LISTS, of which there are none when
    # there are no plan FILES. So one more `rm` after the snapshot turned a
    # DETECTED substitution back into a clean run, and `plans_seen` -- the one
    # key that noticed -- was not read by `integrity_ok`.
    #
    # The anchor is the run manifest, not the plan: a plan cannot attest to its
    # own existence. `plan_owed` is the driver's record that it wrote one (the
    # manifest's recorded review-or-later dispatch request, #1727), so with no
    # plan on disk the file was deleted. A run that never had a driver says
    # nothing and keeps the benign reading, which is the back-compat property
    # every other key here has.
    #
    # `plans_seen` counts dispatch-plan FILES of any name, not this one (see
    # plan.load_dispatch_plans_detailed) -- so a stray `dispatch-plan-decoy.json`
    # dropped beside a deleted driver plan zeroes this key. That still fails
    # closed, through `invalid_dispatch_plans` ("unrecognized dispatch-plan
    # file"), which is the belt this key leans on: a future relaxation of that
    # loader has to keep it, or key this on DRIVER_DISPATCH_PLAN directly.
    dispatch_plan_missing = bool(plan_owed) and plans_seen == 0
    if dispatch_plan_missing:
        print("synthesize: this run's driver dispatched review cells, so a %s "
              "is OWED -- no dispatch plan file is present in %s. Treating as "
              "deleted evidence (fail-closed), not an unmeasured run; integrity "
              "is NOT certified."
              % (plan_mod.DRIVER_DISPATCH_PLAN, run_dir), file=sys.stderr)
    # Replacing the plan is the same erasure as deleting it, and cheaper: a
    # narrower plan declares fewer cells, so reconcile has less to miss and the
    # snapshot obligation shrinks. The stamp carries the canonical content hash
    # of the entries the driver wrote (`_plan_hash`, the same comparison the
    # #493 R2 ack staleness check makes), so a plan that parses but is not this
    # run's reads as tamper. An UNREADABLE plan is not counted here: the loader
    # already reports it as `invalid_dispatch_plans`, and inferring a second
    # failure from one fault would double-count it.
    dispatch_plan_mismatched = bool(
        plan_sha256 and plan_lists
        and all(_plan_hash(pl) != plan_sha256 for pl in plan_lists))
    if dispatch_plan_mismatched:
        print("synthesize: the dispatch plan on disk is NOT the one this run "
              "wrote -- its content does not hash to the %s stamped in the run "
              "manifest. Treating as substituted evidence (fail-closed); "
              "integrity is NOT certified." % plan_sha256[:12], file=sys.stderr)
    malformed = malformed_findings_files(files)
    if malformed:
        print("synthesize: %d findings file(s) violate the findings contract "
              "(dropped source evidence): %s"
              % (len(malformed), ", ".join(d["file"] for d in malformed)),
              file=sys.stderr)
    discovery_git_failure, discovery_files_truncated = \
        _discovery_disclosures(discovery)
    integrity = {"unexpected_findings_files": unexpected,
                 "missing_planned_files": missing,
                 "malformed_findings_files": malformed,
                 "duplicate_out_files": duplicate_out_files(plan),
                 "mislabeled_findings_files": mislabeled_findings_files(files),
                 "cross_domain_findings": cross_domain_findings(files),
                 "unenforced_acknowledged": bool(ack) and not ack_stale,
                 "ack_stale": ack_stale,
                 "content_hashes_checked": content_checked,
                 "content_mismatched_files": content_mismatched,
                 "content_snapshot_unreadable": content_snapshot_unreadable,
                 "content_snapshot_missing": content_snapshot_missing,
                 "empty_dispatch_plans": sum(1 for pl in plan_lists if not pl),
                 "invalid_dispatch_plans": invalid_plans,
                 "invalid_verify_queue": invalid_verify_queue,
                 "plans_seen": plans_seen,
                 "dispatch_plan_missing": dispatch_plan_missing,
                 "dispatch_plan_mismatched": dispatch_plan_mismatched,
                 # #2271: published on every report like every other key here,
                 # `None` where this run measured nothing.
                 "discovery_git_failure": discovery_git_failure,
                 "discovery_files_truncated": discovery_files_truncated}
    if ack:
        # Surface the Bash-coverage disclosure fields written by dispatch so
        # they appear in meta.integrity in the final report (#680).
        # Default to False so consumers never see None for this field.
        integrity["write_guard_covers_bash"] = ack.get("write_guard_covers_bash", False)
    return integrity
