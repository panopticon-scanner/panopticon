"""Dispatch plans, coverage cells, out-of-scope and the tool axis."""
from dataclasses import dataclass, field
import glob
import json
import os

import scripts.evidence as evidence_mod
import scripts.groups_schema as groups_schema
import scripts.plan_contract as plan_contract
import scripts.score_gate as score_gate
from scripts.tools import EXECUTES_TARGET_BUILD
from . import findings as findings_mod


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
    evidence factor, the same as driver.verify_execute's own engagement decision.

    `findings` here is the DEDUPED/aggregated list (prepare_for_queue has
    already run), whereas driver.verify_execute/verify_done score
    should_engage_primary on the raw per-cell list (see
    driver._load_cell_findings) -- dedup only removes findings, never adds
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

def audit_floor_cells(coverages, present):
    """Certifiable-coverage check (matrix Sec5.1): every FLOOR (domain, group)
    cell must have produced a findings file. `coverages` = the per-group
    coverage dicts (as written to .panopticon/coverage-<group>.json by
    driver.coverage_execute: {"group", "floor", "effective", ...}); `present`
    = {group: set(domains with a findings file)}. A missing floor cell is the
    INCONCLUSIVE story -- scout-WIDENED (non-floor) domains are never audited
    here, matching the matrix's floor-is-the-contract semantics. A floor domain
    listed in the cell's `excluded` (e.g. a universal global-floor domain a group
    opted out of, #5.0-11) does NOT run and is netted out first -- it is not a
    missing floor cell. Pure; never raises.
    """
    missing = []
    for cov in coverages:
        group = cov.get("group")
        have = present.get(group, set())
        excluded = set(cov.get("excluded") or [])
        for dom in cov.get("floor") or []:
            # #5.0-11: a floor domain explicitly excluded (e.g. a universal
            # global-floor domain a group opted out of) does not run, so it is
            # not a missing floor cell — net exclude before auditing.
            if dom in excluded:
                continue
            if dom not in have:
                missing.append([group, dom])
    return {"missing_floor": sorted(missing)}

def present_cells(paths):
    """{group: set(domains)} from findings-<group>-<domain>.json names among
    the ingested paths (P4 review cells; feeds audit_floor_cells).

    Filename-only, deliberately: presence means synthesize was HANDED a
    findings file for that (group, domain) cell, independent of whether the
    reviewer found anything in it -- an empty findings-Auth-SEC.json still
    proves the SEC floor cell for group Auth ran. Domain codes
    (groups_schema.DOMAINS) are hyphen-free, so the domain is the LAST
    hyphen-delimited token before `.json`; this can never collide with the
    legacy panel-suffixed shape (findings-<group>-<panel>[-panel_review|
    -lens_sweep-<lens>].json, see GROUP_RE) because panel tokens are lowercase
    words and domain codes are upper-case 2-3 letter codes -- disjoint
    alphabets by construction (groups_schema.DOMAINS vs. PANEL_ORDER).
    """
    out = {}
    for p in paths or []:
        base = os.path.basename(str(p))
        if not (base.startswith("findings-") and base.endswith(".json")):
            continue
        stem = base[len("findings-"):-len(".json")]
        group, sep, domain = stem.rpartition("-")
        if sep and group and domain in groups_schema.DOMAINS:
            out.setdefault(group, set()).add(domain)
    return out

def load_coverage_files(panopticon_dir=".panopticon"):
    """Load every .panopticon/coverage-<group>.json cell-coverage artifact
    (driver.coverage_execute's output) for audit_floor_cells. Tolerant:
    unreadable/malformed/non-dict files are skipped, never raise -- these are
    the same run artifacts groups.json/scout-*.json are read as elsewhere."""
    out = []
    for path in sorted(glob.glob(os.path.join(panopticon_dir, "coverage-*.json"))):
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            out.append(data)
    return out

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
    """Adapters that produced a parseable document (status ok or empty).

    A 'failed' adapter (0-byte / unparseable / no registered adapter) is
    excluded, so build_executing_tools can never name an adapter that ran
    empty. This is the repair of #450's residual weakness and the core of #456.
    """
    return {name for name, d in dispositions.items()
            if d.get("status") in ("ok", "empty")}


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
    if isinstance(tools.manifest, dict):
        selected = set(tools.manifest.get("selected") or [])
        produced_m = set(tools.manifest.get("produced") or [])
        missing = tools.manifest.get("missing")
        tools_absent = sorted(missing if isinstance(missing, list)
                              else selected - produced_m)
        unavailable = sorted(set(plan.scout_requested or []) - selected - produced_m)
        tool_divergence = {t: "requested_absent" for t in tools_absent}
        tool_divergence.update({t: "requested_unavailable" for t in unavailable})
    else:
        tools_absent = sorted(set(plan.scout_requested or []) - produced)
        tool_divergence = {t: "requested_absent" for t in tools_absent}
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
    scope_ok = not ((plan.out_of_scope or {}).get("count")
                    if isinstance(plan.out_of_scope, dict) else False)
    integrity_ok = scope_ok and not (integrity.get("unexpected_findings_files")
                                     or integrity.get("duplicate_out_files")
                                     or integrity.get("mislabeled_findings_files")
                                     or integrity.get("content_mismatched_files")
                                     or integrity.get("content_snapshot_unreadable")
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
    cell_audit = audit_floor_cells(plan.coverages or [], present_cells(tools.ingested_paths))
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
        "resume": plan.resume,
        "delta": resolved.delta_meta,
    }
    return Reconciled(coverage=coverage, integrity=integrity, integrity_ok=integrity_ok,
                      panels_incomplete=panels_incomplete, tools_absent=tools_absent,
                      cell_audit=cell_audit, groups_meta=plan.groups_meta)
