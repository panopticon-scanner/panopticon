"""Dispatch plans, coverage cells, out-of-scope and the tool axis."""
from dataclasses import dataclass, field
import glob
import json
import os
import sys

import scripts.evidence as evidence_mod
import scripts.group_runner as group_runner
import scripts.ingest_tools as ingest_tools
import scripts.plan_contract as plan_contract
import scripts.score_gate as score_gate
from scripts.tools import EXECUTES_TARGET_BUILD
from . import coverage_io as coverage_io
from . import findings as findings_mod
from . import integrity as integrity_mod
from . import repair as repair_mod
from . import validate_schema as validate_schema_mod


@dataclass(frozen=True)
class PlanInputs:
    """What the run folder says was planned and what happened to it (WS-0 S2):
    group definitions, fan-out accounting, scout requests, lane discipline,
    per-group coverage cells, the integrity dict main() assembled, and resume
    stats. Every default is the "not measured" value the omitted build_report
    keyword carried."""
    groups_meta: list = field(default_factory=list)
    fan_out: dict | None = None
    scout_requested: list | None = None
    scout_profiles_seen: int = 0
    out_of_scope: dict | None = None
    coverages: list | None = None
    integrity: dict | None = None
    resume: dict | None = None
    # #1638 P13: {unit: "complete"|"empty"|"split"} -- whether each cell's
    # reviewers could believe their own test inventory. {} / None when this
    # run did not measure it (a direct synthesize.py call over hand-collected
    # findings had no driver to write the tally).
    test_inventory: dict | None = None

    @classmethod
    def load(cls, run_dir, files, verdicts_dir, groups_meta, plans, queue, verdicts):
        """main()'s plan stage (WS-0 S3), in its original order: lane
        discipline (#441), fan-out accounting, resume stats, the integrity
        section, scout requests, coverage files. `plans` is the
        load_dispatch_plans_detailed triple and `queue` the load_verify_queue
        pair -- both read once by main() because ToolAxis.load / FindingSet.load
        need a piece of each first (#146/C1: never load the plans twice).
        `verdicts` is the FindingSet's dict, threaded through resume_stats so
        the verdicts dir is read once."""
        plan_lists, plans_seen, invalid_plans = plans
        queue_obj, invalid_verify_queue = queue
        plan = [e for pl in plan_lists for e in pl]
        out_of_scope = out_of_scope_findings(files, plan)
        if out_of_scope and out_of_scope["count"]:
            print("synthesize: %d finding(s) cite files OUTSIDE their group's "
                  "assigned file list (#441) -- reviewers left their lane; see "
                  "meta.coverage.out_of_scope" % out_of_scope["count"],
                  file=sys.stderr)
        fan_out = group_runner.fan_out_coverage(plan) if plan else None
        resume = group_runner.resume_stats(plan, queue_obj, verdicts_dir, _verdicts=verdicts)
        integrity = integrity_mod.integrity_section(
            plan_lists, files, run_dir, plans_seen, invalid_plans, invalid_verify_queue)
        scout_requested, scout_profiles_seen = load_scout_requests(run_dir)
        # 5.0 (matrix Sec5.1): auto-discover <run_dir>/coverage-<group>.json the
        # same way groups.json/scout-*.json are -- fed to audit_floor_cells in
        # reconcile along with the ingested paths.
        coverages = coverage_io.load_coverage_files(run_dir)
        return cls(groups_meta=groups_meta, fan_out=fan_out,
                   scout_requested=sorted(scout_requested),
                   scout_profiles_seen=scout_profiles_seen, out_of_scope=out_of_scope,
                   coverages=coverages, integrity=integrity, resume=resume,
                   test_inventory=load_test_inventory(run_dir))


@dataclass(frozen=True)
class ToolAxis:
    """The tool layer's own accounting (WS-0 S2). `tools_ran` None means
    --tools-dir was not supplied, and build_executing_tools is inferred from
    the findings; an empty set asserts "no build-executing tool ran" (the
    inversion #450 was about). `manifest` is the runner's deterministic
    tools-manifest (#1031); `ingested_paths` the findings-file list main()
    ingested (reconcile_findings_files' own term), which audit_floor_cells
    reads for the cells present."""
    policy_mode: str | None = None
    tools_ran: set | None = None
    dispositions: dict | None = None
    manifest: dict | None = None
    ingested_paths: list | None = None
    # #1644: why an EXISTING manifest could not be read, or None. Absent and
    # corrupt are different facts and only one of them is an integrity failure.
    manifest_invalid: str | None = None

    @classmethod
    def load(cls, args, run_dir, plan_lists, dispositions, tools_ran):
        """The tool axis from the run folder (WS-0 S3): the runner's
        tools-manifest with its two FATAL (#17) checks, the policy mode the
        dispatch plans declare, and the ingest results `ingest_tool_findings`
        produced. #1031: a present manifest makes reconcile gate on its
        `missing`, not the scout's advisory list; an ABSENT one falls back to
        the 4.x scout-derived gate.

        #1644: a manifest that EXISTS and cannot be read is neither. Corruption
        used to be folded into absence -- `manifest = None`, silently -- and
        absence selects the permissive path, so a scanner the runner selected
        and never produced dropped out of `tools_absent` entirely. The reason is
        recorded here and reconcile refuses to invent the required set from it.
        This is the read failing, not a field being malformed: a manifest that
        parses to an object with rubbish IN it is repaired at the boundary by
        `synth/repair.py` (#1645/#1646), where a bad row costs a warning and the
        row, never the run.
        """
        manifest, manifest_invalid = None, None
        tm_path = os.path.join(run_dir, "tools-manifest.json")
        if os.path.isfile(tm_path):
            try:
                with open(tm_path, encoding="utf-8") as fh:
                    tm = json.load(fh)
            except (OSError, ValueError) as exc:
                manifest_invalid = "tools-manifest.json is unreadable: %s" % exc
            else:
                if isinstance(tm, dict):
                    manifest = tm
                else:
                    manifest_invalid = ("tools-manifest.json is not a JSON object "
                                        "(%s)" % type(tm).__name__)
            if manifest_invalid:
                print("synthesize: %s -- the runner's selected/missing set is "
                      "unknown, so tool coverage is NOT certified (the scout's "
                      "advisory list is not a substitute for it)."
                      % manifest_invalid, file=sys.stderr)
        if manifest is not None:
            # #17: never certify against a foreign/stale manifest. A 5.1 manifest
            # carries schema_version; its run_id (when the runner stamps it) must
            # match this run. Either mismatch is a loud error, not a silent fallback.
            if "schema_version" not in manifest:
                sys.exit("FATAL (#17): tools-manifest at %s lacks schema_version — it "
                         "looks like a pre-5.1 flat manifest from another run; refusing "
                         "to certify against it. Re-run the tools phase." % tm_path)
            mrid = manifest.get("run_id")
            if args.run_id and mrid and mrid != args.run_id:
                sys.exit("FATAL (#17): tools-manifest run_id %r != this run %r (at %s) — "
                         "refusing to certify against another run's manifest."
                         % (mrid, args.run_id, tm_path))
        return cls(policy_mode=derive_tool_policy_mode(plans=plan_lists),
                   tools_ran=tools_ran, dispositions=dispositions, manifest=manifest,
                   ingested_paths=args.files, manifest_invalid=manifest_invalid)


@dataclass(frozen=True)
class Reconciled:
    """reconcile()'s result: the `meta.coverage` and `meta.integrity` sections
    plus the plan-derived facts certification needs."""
    coverage: dict
    integrity: dict
    integrity_ok: bool
    panels_incomplete: set
    tools_absent: list
    cell_audit: dict
    groups_meta: list
    # #1646: what the adapters refused to hand their scanners, off the runner's
    # manifest and repaired at that read. Beside `coverage` rather than inside
    # it: `meta.coverage` accounts for which ADAPTERS produced output, and this
    # says one of them produced a PARTIAL answer. `{}` on a run with no
    # manifest -- nothing measured, which is not "nothing was dropped".
    tools_sanitized: dict = field(default_factory=dict)
    # #1645: what egress each scanner was given, off the same manifest and
    # repaired at the same read. Beside `coverage` for the same reason as
    # `tools_sanitized`: coverage says which adapters PRODUCED output, and this
    # says what one of them could reach while doing it.
    tools_network: dict = field(default_factory=dict)
    # #1644: why this run's tools-manifest could not be read, or None. Carried
    # beside `integrity` (which also publishes it) the way `integrity_ok` is:
    # certification takes it as an input, and must not have to read a section.
    tools_manifest_invalid: str | None = None


# One source for the per-group dispatch-plan filename glob (#681): synthesize
# reconciles findings against, and derives coverage from, every plan file the
# fan-out wrote. Both call sites join it against their own base dir.
DISPATCH_PLAN_GLOB = "dispatch-plan*.json"

# #5.0-16: the resumable driver emits ONE dedicated plan under this name. It
# matches DISPATCH_PLAN_GLOB (so reconcile/coverage/snapshot see its out_files)
# but declares matrix (group, domain) cells -- findings-<group>-<domain>.json --
# not the 4.x panel-review shape. It is the only dispatch plan the pipeline
# writes, and plan_contract.driver_plan_issues is the only contract left to
# validate it against; any OTHER dispatch-plan*.json is rejected as stray.
DRIVER_DISPATCH_PLAN = "dispatch-plan-driver.json"

def engaged_matrix_cells(findings):
    """Matrix (group, domain) cells scoring >= F_p — the cells a primary advisor
    engages. Called BEFORE verdicts are derived, so the score uses the unverified
    evidence factor, the same as phases.verify.verify_execute's own engagement decision.

    `findings` here is the DEDUPED/aggregated list (prepare_for_queue has
    already run), whereas phases.verify.verify_execute/verify_done score
    should_engage_primary on the raw per-cell list (see
    phases.review._load_cell_findings) -- dedup only removes findings, never adds
    them, so the cells this returns are a subset of what the driver engaged,
    never a superset. Safe: verify_done gates synthesize, so every
    driver-engaged cell already has a verdict bundle on disk by the time this
    runs; the discrepancy only shows up as a possible undercount in
    meta.coverage.verify_matrix.engaged when exact-duplicate findings collapse."""
    cells = {}
    for f in findings:
        grp, dom = f.get("_group"), f.get("domain")
        if grp is None or dom is None:
            continue
        cells.setdefault((grp, dom), []).append(f)
    return {key for key, cf in cells.items() if score_gate.should_engage_primary(cf)}

def _finding_owed_verification(finding, engaged):
    """Was this finding owed an advisor verdict? A matrix finding is owed only when
    its cell is engaged (>= F_p); a below-gate cell is skipped by design and its
    unverified findings must NOT force INCONCLUSIVE. A non-matrix (4.x) finding is
    always owed — unchanged behavior."""
    grp, dom = finding.get("_group"), finding.get("domain")
    if grp is not None and dom is not None:
        return (grp, dom) in engaged
    return True

def out_of_scope_findings(findings_paths, plan):
    """#441: count agent findings whose location.file falls outside the FILE
    LIST of the group their findings-file belongs to (per the dispatch plan).

    Reviewers are prompted to stay inside their assignment, but that fence is
    prompt-advisory -- this is the report-side disclosure. Only findings files
    whose name matches GROUP_RE and whose group has a plan entry are checked;
    tool findings and unplanned groups are out of this check's reach.
    Returns {"checked": N, "count": N, "examples": [...]} or None when no
    plan/group could be checked.
    """
    group_files = {}
    for e in plan or []:
        if isinstance(e, dict) and isinstance(e.get("files"), list):
            group_files.setdefault(e.get("group"), set()).update(
                str(f).replace("\\", "/") for f in e["files"])
    if not group_files:
        return None
    checked = count = 0
    examples = []
    for path in findings_paths or []:
        m = findings_mod.GROUP_RE.match(os.path.basename(str(path)))
        if not m or m.group(1) not in group_files:
            continue
        allowed = group_files[m.group(1)]
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            continue
        for f in (data.get("findings") or [] if isinstance(data, dict) else []):
            loc = (f.get("location") or {}) if isinstance(f, dict) else {}
            fpath = evidence_mod.norm_path(loc.get("file"))
            if not fpath:
                continue
            checked += 1
            if fpath not in allowed:
                count += 1
                if len(examples) < 10:
                    examples.append({"group": m.group(1), "file": fpath})
    return {"checked": checked, "count": count, "examples": examples}

def load_dispatch_plans_detailed(panopticon_dir=".panopticon"):
    """Return (valid plans, files seen, invalid plan diagnostics).

    #run10: dropped `groups_path`/`root`. Both existed only to feed the 4.x
    panel plan's groups.json cross-validation (assignment_issues/output_issues),
    retired with the roles it keyed on."""
    plans = []
    invalid = []
    paths = sorted(glob.glob(os.path.join(panopticon_dir, DISPATCH_PLAN_GLOB)))
    for path in paths:
        try:
            with open(path, encoding="utf-8") as fh:
                plan = json.load(fh)
        except (OSError, ValueError) as exc:
            invalid.append({"file": path, "reason": "unreadable: %s" % exc})
            continue
        # #5.0-16: route by filename. dispatch-plan-driver.json carries the
        # matrix domain-cell shape, validated by driver_plan_issues; a malformed
        # one lands in `invalid` (=> invalid_dispatch_plans => INCONCLUSIVE).
        #
        # #run10: every OTHER dispatch-plan*.json used to be validated as a 4.x
        # per-group panel plan. That contract was keyed on the retired
        # panel_review/lens_sweep roles, so it rejected every plan the pipeline
        # can write and accepted only plans nothing can emit -- retired with
        # them. The branch's OTHER job was to fail closed on a stray
        # dispatch-plan-*.json dropped into the artifacts dir, and that is kept
        # explicitly: an unrecognized plan file is still INCONCLUSIVE, never
        # silently ignored.
        if os.path.basename(path) == DRIVER_DISPATCH_PLAN:
            issues = plan_contract.driver_plan_issues(plan)
        else:
            issues = ["unrecognized dispatch-plan file (expected %s)"
                      % DRIVER_DISPATCH_PLAN]
        if issues:
            invalid.append({"file": path, "reason": "; ".join(issues)})
            continue
        plans.append(plan)
    return plans, len(paths), invalid

def load_dispatch_plans(panopticon_dir=".panopticon"):
    """Load every per-group dispatch plan file as a list of per-file plan
    lists. Tolerant: unreadable/malformed plan files are skipped."""
    plans = []
    for path in sorted(glob.glob(os.path.join(panopticon_dir, DISPATCH_PLAN_GLOB))):
        try:
            with open(path, encoding="utf-8") as fh:
                plan = json.load(fh)
        except (OSError, ValueError):
            continue
        if isinstance(plan, list):
            plans.append(plan)
    return plans

def derive_tool_policy_mode(panopticon_dir=".panopticon", plans=None):
    """Derive the run's tool-policy posture from dispatch plan files.

    unknown: no usable plan file was found — posture undetermined (distinct
    from advisory, which is a plan we DID read that enforced nothing).
    enforced: every entry across every plan is enforced; mixed: some are;
    advisory: a plan exists but none are. Pass `plans` (per-file plan lists,
    as returned by load_dispatch_plans) to skip re-reading the files a caller
    already loaded.
    """
    if plans is None:
        plans = load_dispatch_plans(panopticon_dir)
    if not plans:
        return "unknown"
    flags = [bool(e.get("enforced")) for plan in plans
             for e in plan if isinstance(e, dict)]
    if flags and all(flags):
        return "enforced"
    if any(flags):
        return "mixed"
    return "advisory"

def tools_ran_from_dispositions(dispositions):
    """Adapters whose run is worth COVERAGE CREDIT (status ok or empty).

    A 'failed' adapter (0-byte / unparseable / no registered adapter) is
    excluded, so build_executing_tools can never name an adapter that ran
    empty. This is the repair of #450's residual weakness and the core of #456.

    #1335: 'noscan' is excluded too. An adapter that scanned zero files ran
    without covering anything, and naming it in `tools_ran` is the report
    asserting coverage it does not have. Use `tools_produced_from_dispositions`
    for the different question of which adapters actually cost a dispatch.
    """
    return {name for name, d in dispositions.items()
            if d.get("status") in ("ok", "empty")}


def tools_produced_from_dispositions(dispositions):
    """Adapters that ran and produced a parseable document -- 'noscan' included.

    #1335 split this from `tools_ran_from_dispositions`, which had been asked
    two questions at once. A no-op semgrep provided no coverage but did consume
    a dispatch, so the cost ledger must still count it; crediting coverage and
    counting spend are not the same set.
    """
    return {name for name, d in dispositions.items()
            if d.get("status") in ("ok", "empty", "noscan")}


def reconcile(plan, tools, resolved):
    """The plan-reconciliation cluster (WS-0 S2): meta.coverage and
    meta.integrity from the dispatch plan, the tool layer and the resolved
    findings (verdict stats, tool axis, ocrdb coverage, delta counts)."""
    planned = (plan.fan_out or {}).get("planned") or {} if isinstance(plan.fan_out, dict) else {}
    executed = (plan.fan_out or {}).get("executed") or {} if isinstance(plan.fan_out, dict) else {}
    panels_incomplete = {p for p, n in planned.items() if executed.get(p, 0) < n}
    tools_ran = tools.tools_ran
    produced = set(tools_ran if tools_ran is not None else resolved.tool_names)
    # #1031: certify on the runner's DETERMINISTIC adapter set when its manifest
    # is present -- `missing` (applicable known adapters that didn't produce) is
    # the only real tool-coverage loss, so it drives the gate (`tools_absent`).
    # The scout's advisory list is demoted: a request the runner can't satisfy
    # (no adapter, or inapplicable to the target) is disclosed as non-gating
    # `requested_unavailable`, never sinking coverage_certified. With no manifest
    # (e.g. --no-tools, or a pre-manifest run) the 4.x scout-derived gate stands.
    # #1646: repaired AT THE READ, like every other manifest field this function
    # takes -- the file is target-writable and this block reaches the artifact.
    sanitized = (repair_mod.repair_tools_sanitized(
        tools.manifest.get("sanitized")) if isinstance(tools.manifest, dict) else {})
    # #1645: same read, same repair -- the block is target-writable and reaches
    # the artifact and the HTML.
    network = (repair_mod.repair_tools_network(
        tools.manifest.get("network")) if isinstance(tools.manifest, dict) else {})
    if tools.manifest_invalid:
        # #1644: corruption is not absence, and the scout-derived fallback below
        # is only honest when nothing WAS corrupted. With the manifest
        # unreadable the runner's selected set is unknown, so `tools_absent`
        # cannot be computed at all -- the scout's advisory list answers a
        # different question, and every selected-but-unproduced scanner silently
        # drops out of it. Claim nothing here; certification is what fails
        # (certify's `tools_manifest_invalid`), not the gate.
        tools_absent, tool_divergence = [], {}
    elif isinstance(tools.manifest, dict):
        selected = set(validate_schema_mod.string_list(tools.manifest.get("selected")))
        produced_m = set(validate_schema_mod.string_list(tools.manifest.get("produced")))
        missing = tools.manifest.get("missing")
        missing_list = sorted(validate_schema_mod.string_list(missing)
                              if isinstance(missing, list) else selected - produced_m)
        tools_absent = list(missing_list)
        tool_divergence = {t: "requested_absent" for t in missing_list}
        # #1512 (Codex BR-02): the manifest records what the RUNNER wrote, which
        # is a fact about bytes, not about coverage. A selected scanner whose
        # output could not be parsed is `failed` in the dispositions and already
        # excluded from tools_ran -- but coverage was derived from the manifest
        # alone, so it certified a scanner that delivered nothing readable.
        # Required set stays the manifest's selection; it is reconciled here
        # against what ingestion could actually USE:
        #     tools_absent = missing  U  (selected - usable)
        # Guarded on tools_ran, which is None exactly when no ingest ran
        # (--no-tools, or no --tools-dir). With no dispositions to judge
        # usability by, inferring "unusable" from their absence would fail every
        # selected adapter on a run that never ingested.
        if tools.tools_ran is not None:
            lost = ingest_tools.lost_required_coverage(tools.manifest,
                                                       tools.dispositions or {})
            tools_absent = sorted(set(tools_absent) | set(lost))
            tool_divergence.update(
                {t: "produced_unusable" if info["kind"] == "unusable"
                 else "requested_absent"
                 for t, info in lost.items()})
        unavailable = sorted(set(plan.scout_requested or []) - selected - produced_m)
        tool_divergence.update({t: "requested_unavailable" for t in unavailable})
    else:
        tools_absent = sorted(set(plan.scout_requested or []) - produced)
        tool_divergence = {t: "requested_absent" for t in tools_absent}
    # #1335: an adapter that ran but scanned nothing is disclosed, never gated.
    # It is absent from `tools_ran` (no coverage credit) which would otherwise
    # sink it into `tools_absent` on the scout-derived path above -- but a
    # no-surface target is not a coverage loss an operator can act on, so
    # `produced_noscan` is non-gating by construction: it appears only in the
    # divergence map, and `tools_absent` is what reaches certify().
    noscan = sorted(name for name, d in (tools.dispositions or {}).items()
                    if isinstance(d, dict) and d.get("status") == "noscan")
    if noscan:
        tools_absent = [t for t in tools_absent if t not in noscan]
        tool_divergence.update({t: "produced_noscan" for t in noscan})
    divergence = {
        "panels": {p: {"planned": planned[p], "executed": executed.get(p, 0)}
                   for p in sorted(panels_incomplete)},
        "tools": tool_divergence,
    }
    integrity = plan.integrity if isinstance(plan.integrity, dict) else None
    integrity = integrity or {"unexpected_findings_files": [],
                              "missing_planned_files": [],
                              "duplicate_out_files": [],
                              "mislabeled_findings_files": [],
                              "cross_domain_findings": [],
                              "empty_dispatch_plans": 0,
                              "invalid_dispatch_plans": [],
                              "invalid_verify_queue": None,
                              "unenforced_acknowledged": False,
                              "plans_seen": 0}
    # #1644: recorded beside the other "this artifact exists and cannot be
    # trusted" reasons, and always present (None on a clean read AND on a run
    # with no manifest at all), exactly like `invalid_verify_queue`.
    integrity = dict(integrity)
    integrity["tools_manifest_invalid"] = tools.manifest_invalid
    scope_ok = not ((plan.out_of_scope or {}).get("count")
                    if isinstance(plan.out_of_scope, dict) else False)
    integrity_ok = scope_ok and not (integrity.get("unexpected_findings_files")
                                     or integrity.get("duplicate_out_files")
                                     or integrity.get("mislabeled_findings_files")
                                     or integrity.get("content_mismatched_files")
                                     or integrity.get("content_snapshot_unreadable")
                                     or integrity.get("content_snapshot_missing")
                                     or integrity.get("malformed_findings_files")
                                     or integrity.get("empty_dispatch_plans")
                                     or integrity.get("invalid_dispatch_plans")
                                     or integrity.get("invalid_verify_queue"))
    # 5.0 (matrix Sec5.1): certifiable coverage over the review matrix's FLOOR
    # cells, alongside the requested-absent-TOOL check above. `coverages` is
    # the raw list of coverage-<group>.json dicts the caller read (main()
    # auto-discovers them, same convention as groups.json/scout-*.json);
    # `ingested_paths` is the findings-file path list the caller ingested.
    # Both default to empty/None for callers that predate P4 cells, so
    # cell_audit is a no-op {"missing_floor": []} for them.
    # #1513: presence is filename-derived, which is right for "was synthesize
    # HANDED this cell" but wrong for "did this cell complete". A cell whose file
    # violates the findings contract was written and is therefore present, yet it
    # is not completed work -- so net it out before the floor audit and let it
    # surface as missing_floor, the channel that already means "a floor cell did
    # not produce a review".
    present = coverage_io.present_cells(tools.ingested_paths)
    for entry in (integrity.get("malformed_findings_files") or []):
        cell = entry.get("cell") if isinstance(entry, dict) else None
        if cell and cell[0] in present:
            present[cell[0]].discard(cell[1])
    cell_audit = coverage_io.audit_floor_cells(plan.coverages or [], present)
    coverage = {
        "adapters": tools.dispositions or {},
        "tools_ran": (sorted(tools_ran) if tools_ran is not None
                      else sorted(resolved.tool_names)),
        "build_executing_tools": sorted(
            (set(tools_ran) if tools_ran is not None else resolved.tool_names)
            & EXECUTES_TARGET_BUILD),
        "tool_policy_mode": tools.policy_mode or "unknown",
        "tool_axis": resolved.tool_axis,
        # #471: with scout_requested, lets consumers tell "no scouts
        # ran" (0) apart from "scouts ran and requested no tools"
        # (N>0 with scout_requested []).
        "scout_profiles_seen": plan.scout_profiles_seen,
        "scout_requested": sorted(plan.scout_requested or []),
        "out_of_scope": plan.out_of_scope,
        "doc_policy": resolved.doc_policy,
        "verdicts": resolved.verdict_stats,
        "ocrdb": resolved.ocrdb_coverage,   # None when no bundle vendored (= 4.x)
        # P5 verify-matrix accounting: engaged (>= F_p) cell count and the
        # engaged cells left unverified -- the same set that forces gate
        # INCONCLUSIVE via the gate-aware `unanswered` count.
        "verify_matrix": resolved.verify_matrix,
        "fan_out": plan.fan_out,
        "divergence": divergence,
        # 5.0 (matrix Sec5.1): per-floor-cell certifiable-coverage
        # disclosure -- {"missing_floor": [[group, domain], ...]}. A
        # non-empty list is what forces the gate to INCONCLUSIVE.
        "cells": cell_audit,
        # #1638 P13: which review units were shown a test inventory their
        # reviewers could believe. An empty/split entry is why a `TST`
        # no-coverage claim here may be about the MATRIX, not the target.
        # Driver-computed; no agent files a finding for it.
        "test_inventory": dict(plan.test_inventory or {}),
        "resume": plan.resume,
        "delta": resolved.delta_meta,
    }
    return Reconciled(coverage=coverage, integrity=integrity, integrity_ok=integrity_ok,
                      panels_incomplete=panels_incomplete, tools_absent=tools_absent,
                      cell_audit=cell_audit, groups_meta=plan.groups_meta,
                      tools_sanitized=sanitized, tools_network=network,
                      tools_manifest_invalid=tools.manifest_invalid)


def load_groups_json(path):
    """The run's groups.json as a dict, or {} when there is no file at `path`,
    it cannot be read, or it is not a JSON object -- tolerant by design (never
    abort a run); the two failure modes are announced on stderr.

    The file is target-writable, and five of its fields are type-pinned by the
    time they reach the artifact, so the dict is normalized HERE rather than by
    the caller (#1639 P15 fix round 3, R2-6): repairing at the read is what
    makes a second caller safe by construction. It lived at the caller for one
    round only because this module was two lines under its ceiling.
    """
    if not (path and os.path.isfile(path)):
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            gj = json.load(fh)
    except (OSError, ValueError) as e:
        print("synthesize: could not read %s (%s); ignoring" % (path, e), file=sys.stderr)
        return {}
    if not isinstance(gj, dict):
        print("synthesize: %s is not a JSON object; ignoring" % path, file=sys.stderr)
        return {}
    return repair_mod.repair_groups_json(gj)


def load_verify_queue(run_dir):
    """(queue, invalid_reason) for <run_dir>/verify-queue.json: the parsed
    queue when it is a dict with an `entries` list, else None plus the reason
    meta.integrity.invalid_verify_queue reports; (None, None) with no file."""
    path = os.path.join(run_dir, "verify-queue.json")
    if not os.path.isfile(path):
        return None, None
    try:
        with open(path, encoding="utf-8") as fh:
            loaded = json.load(fh)
    except (OSError, ValueError) as exc:
        return None, "cannot read verify queue: %s" % exc
    if isinstance(loaded, dict) and isinstance(loaded.get("entries"), list):
        return loaded, None
    return None, "verify queue has no entries list"


PANEL_TOOLS_CONTEXT = "panel-tools-context.json"


def load_panel_tools_context(run_dir):
    """`{"with": n, "without": m}` over <run_dir>/panel-tools-context.json.

    #1637 P08 ruling 5. The driver's review phase stamps every dispatch entry
    with whether tool output was on disk as its prompt was rendered, and
    merges the per-cell answers into that file as each batch goes out. This
    counts them, so the report can say how many panels actually saw scanner
    evidence -- run-13's 85 panels reviewed with none, and the report had no
    field in which to say so.

    Fail-closed to two zeroes on anything unreadable, and on the file being
    absent: this lives under `.panopticon`, which a hostile target can
    pre-commit, and "nothing measured" must read as a measurable zero rather
    than as a traceback or an invented figure. A run that dispatched no panel
    at all reports the same two zeroes, correctly.
    """
    counts = {"with": 0, "without": 0}
    try:
        with open(os.path.join(run_dir, PANEL_TOOLS_CONTEXT), encoding="utf-8") as fh:
            body = json.load(fh)
    except (OSError, ValueError):
        return counts
    cells = body.get("cells") if isinstance(body, dict) else None
    if not isinstance(cells, dict):
        return counts
    for saw_tools in cells.values():
        counts["with" if saw_tools is True else "without"] += 1
    return counts


TEST_INVENTORY = "panel-test-inventory.json"

INVENTORY_STATES = ("complete", "empty", "split")


def load_test_inventory(run_dir):
    """`{unit: state}` over <run_dir>/panel-test-inventory.json (#1638 P13).

    The review phase records, per REVIEW UNIT (the groups.yml entry a chunked
    `<name>_N` was split out of, so the key names a group the operator can
    find), whether that unit's prompts were built from a `complete`, `empty`
    or `split` inventory; this reads it back so `meta.coverage.test_inventory`
    can say which `TST` coverage claims rest on one nobody could trust.

    Fail-closed to `{}` on an absent or unreadable file, and any state outside
    `INVENTORY_STATES` is DROPPED rather than carried: this lives under
    `.panopticon`, which a hostile target can pre-commit, and an invented
    state in the artifact is worse than a missing group.
    """
    out = {}
    try:
        with open(os.path.join(run_dir, TEST_INVENTORY), encoding="utf-8") as fh:
            body = json.load(fh)
    except (OSError, ValueError):
        return out
    groups = body.get("groups") if isinstance(body, dict) else None
    if not isinstance(groups, dict):
        return out
    for name, state in groups.items():
        if isinstance(name, str) and state in INVENTORY_STATES:
            out[name] = state
    return out


def load_scout_requests(run_dir):
    """(tools requested, profiles seen) across <run_dir>/scout-*.json. #471: a
    scout can return tools:[] -- a silent decline of the tool layer -- so the
    profile count is recorded separately and the decline is announced."""
    requested = set()
    profiles_seen = 0
    for sp in glob.glob(os.path.join(run_dir, "scout-*.json")):
        try:
            with open(sp, encoding="utf-8") as fh:
                sd = evidence_mod.load_json_tolerant(fh.read())
        except (OSError, ValueError):  # tolerant by design: never abort a run
            continue
        if not isinstance(sd, dict):
            continue
        profiles_seen += 1
        tools = sd.get("tools")
        if isinstance(tools, list):
            requested.update(t for t in tools if isinstance(t, str))
    if profiles_seen and not requested:
        print("synthesize: %d scout profile(s) requested NO tools (tools:[]) "
              "-- the tool layer ran on default triggers only, not scout "
              "guidance" % profiles_seen, file=sys.stderr)
    return requested, profiles_seen


def ingest_tool_findings(args):
    """The --tools-dir ingest (WS-0 S3): (raw tool findings, per-adapter
    dispositions, tools_ran). tools_ran is None when --tools-dir wasn't
    supplied -- reconcile then infers build_executing_tools from the findings;
    an empty set would ASSERT "no build-executing tool ran" from an absence of
    evidence (the inversion #450 was about). A "failed" disposition (empty /
    unparseable / no-adapter) is excluded from tools_ran, so
    build_executing_tools can no longer name an adapter that ran empty."""
    if not args.tools_dir:
        default_tools = os.path.join(".panopticon", "tools")
        if os.path.isdir(default_tools) and os.listdir(default_tools):
            print("synthesize: %s appears un-ingested — pass --tools-dir %s to "
                  "include tool findings in this report"
                  % (default_tools, default_tools), file=sys.stderr)
    if not (args.tools_dir and os.path.isdir(args.tools_dir)):
        return [], {}, None
    tool_findings, dispositions = ingest_tools.ingest_dir_detailed(
        args.tools_dir, None, exclude_globs=args.tools_exclude,
        include_fixtures=args.include_fixtures)
    return tool_findings, dispositions, tools_ran_from_dispositions(dispositions)
