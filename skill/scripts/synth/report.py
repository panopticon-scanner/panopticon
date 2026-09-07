"""build_report: assemble and validate the CodeReviewReport."""
import sys

import scripts.citations as citations
try:
    from scripts._version import __version__
except ModuleNotFoundError:  # imported flat, with skill/scripts itself on sys.path
    from _version import __version__
from scripts.citations import load_cwe_catalog
import scripts.evidence as evidence_mod
import scripts.ocrdb as ocrdb
from scripts.tools import EXECUTES_TARGET_BUILD
from . import findings as findings_mod
from . import codes as codes_mod
from . import delta as delta_mod
from . import grading as grading_mod
from . import plan as plan_mod
from . import cost as cost_mod


# Format version of the report DOCUMENT itself (the meta/summary/groups/findings
# envelope), stamped top-level like every sibling artifact (findings-envelope,
# x0x-report, tool-manifest, dispatch-request ...). Distinct from meta.version
# (the panopticon release) and meta.ocrdb_version (the code bundle): the report
# envelope evolves on its own clock -- 5.1 added meta.cost/meta.integrity/
# summary.health/summary.delta with no change to the finding shape. Bump this
# only on a report-envelope format change. Absent (legacy pre-5.1 reports) reads
# as version 0. #run7 DAT-F2A: gives the cross-run readers (reconcile.load_report,
# the html compare view, per-run-folder A/B) a discriminator before per-run
# folders make cross-version report reads routine.
REPORT_SCHEMA_VERSION = 1

def _role_from_discovered_by(discovered_by):
    """Map a provenance discovered_by value to a model role."""
    if not discovered_by:
        return None
    discovered_by = str(discovered_by)
    if discovered_by.startswith("agent:"):
        return discovered_by.split(":", 1)[1]
    return discovered_by

def _collect_models_used(findings):
    """Collect unique model/version/role triples from agent findings.

    Tool findings (model is null) are skipped. Agent findings contribute their
    provenance model/version plus a role derived from discovered_by. Advisor
    confirmations contribute the confirming model with role 'advisor'.
    """
    seen = set()
    out = []
    for f in findings:
        prov = f.get("provenance") or {}
        model = prov.get("model")
        version = prov.get("model_version")
        # Skip tool and other entries without a model identifier.
        if not model:
            continue
        role = _role_from_discovered_by(prov.get("discovered_by"))
        # Dedup by (model, role): agents self-report model_version
        # inconsistently (F-CAL-3), which produced duplicate entries.
        key = (model, role)
        if key in seen:
            continue
        seen.add(key)
        entry = {"model": model, "role": role}
        if version:
            entry["version"] = version
        out.append(entry)
        confirmed_by_model = prov.get("confirmed_by_model")
        if confirmed_by_model:
            advisor_key = (confirmed_by_model, None, "advisor")
            if advisor_key not in seen:
                seen.add(advisor_key)
                out.append({"model": confirmed_by_model, "role": "advisor"})
    return out

def build_report(findings, groups_meta, target, fail_on, timestamp, review_type="repo",
                 security_mode="standard", verdicts=None, gate_unverified=False,
                 max_verify=None, verdicts_supplied=False, tool_policy_mode=None,
                 tools_ran=None, tool_dispositions=None, fan_out=None,
                 scout_requested=None, scout_profiles_seen=0, out_of_scope=None,
                 doc_policy=None, resume=None, integrity=None,
                 diff_hunks=None, diff_context=5, gate_scope="on-diff",
                 catalog=None, verdict_unloadable=None,
                 verdict_run_id=None, coverages=None, ingested_paths=None,
                 verdict_bundles=None, driver_cost=None, tool_manifest=None,
                 run_usage=None):
    """Build a CodeReviewReport under the two-axis severity x evidence model.

    Severity is never mutated here. Verdicts (from evidence.load_verdicts) are
    applied to queued findings; every finding gets an evidence object; grades
    and the gate are computed from gate-eligible findings only (all non-rejected
    when gate_unverified is set). `verdicts_supplied` records whether --verdicts-dir
    was passed at all (distinct from whether it yielded any verdicts) so the
    aggregate "no verdict" note still fires for an existing-but-empty dir.
    `tools_ran` is the set of adapter names that produced output this run;
    when omitted, `build_executing_tools` falls back to inferring from findings.
    `coverages` (5.0) is the list of .panopticon/coverage-<group>.json dicts
    (see load_coverage_files); `ingested_paths` is the same findings-file path
    list the caller ingested (main() passes args.files, matching
    reconcile_findings_files' "ingested" terminology) -- both feed
    audit_floor_cells below.
    """
    findings, integration_findings = findings_mod.prepare_for_queue(findings)
    if catalog is None:
        catalog = load_cwe_catalog()
    ocrdb_bundle = ocrdb.load_bundle()
    ocrdb_coverage = codes_mod.validate_finding_codes(findings, ocrdb_bundle)
    queue, cut = evidence_mod.build_verify_queue(findings, max_verify)
    # Identity must be read BEFORE any verdict is applied. For a SARIF-sourced
    # tool finding the adapters park the rule id in
    # provenance.confirmation_reasoning (tools/sarif_utils.tool_provenance sets
    # no tool_evidence), evidence.tool_rule_id falls back to it, and
    # finding_fingerprint uses it as the identity discriminator -- while
    # evidence.apply_verdict overwrites that same field with the advisor's
    # prose. Recomputing afterwards would export a hash of the reasoning text,
    # so the "stable cross-run identity" would change whenever an advisor
    # re-worded itself. Harmless for findings that are never verdicted
    # (including those cut by --max-verify): nothing between here and the
    # assignment site mutates an identity field on them.
    pre_verdict_fps = {id(f): evidence_mod.finding_fingerprint(f) for f in findings}
    verdicts = verdicts or {}
    matched = {}
    matched_n = 0
    unanswered = 0
    by_fid = verdict_bundles or {}
    # Computed on PRE-verdict evidence (nothing below has applied a verdict yet)
    # and on this DEDUPED `findings` list, so it is a subset of (never
    # identical to) driver.verify_execute's own engagement decision, which
    # scores the raw per-cell list -- see engaged_matrix_cells's docstring.
    engaged_cells = plan_mod.engaged_matrix_cells(findings)
    # #1475: verdict files that EXIST for a cell but cannot be bound to it (the
    # finding_id echo names a different finding, or none at all). Collected
    # separately because they are the opposite failure from `unanswered`: an
    # advisor ran and answered, and the answer was mislabelled.
    verdict_misrouted = []
    for entry in queue:
        v = evidence_mod.match_verdict(entry, verdicts, run_id=verdict_run_id,
                                       misrouted=verdict_misrouted)
        if v is None and by_fid:
            v = evidence_mod.match_verdict_by_id(entry["finding"], by_fid,
                                                 run_id=verdict_run_id)
        if v is not None:
            evidence_mod.apply_verdict(entry["finding"], v)
            matched_n += 1
        elif verdicts_supplied and plan_mod._finding_owed_verification(entry["finding"], engaged_cells):
            unanswered += 1
        matched[id(entry["finding"])] = v
    # P5 verify-matrix disclosure: engaged cells (>= F_p) that received no
    # verdict -- the same cells that just drove `unanswered` above. A cell
    # counts as verified once ANY of its findings matched a verdict.
    verified_cells = set()
    for f in findings:
        if matched.get(id(f)) is not None:
            grp, dom = f.get("_group"), f.get("domain")
            if grp is not None and dom is not None:
                verified_cells.add((grp, dom))
    verify_matrix_cov = {
        "engaged": len(engaged_cells),
        "unverified_engaged": sorted(list(k) for k in engaged_cells
                                     if k not in verified_cells)}
    if ocrdb_coverage is not None:
        ocrdb_coverage.update(codes_mod.apply_verdict_quality(findings, matched, ocrdb_bundle))
    if unanswered:
        print("synthesize: %d queued findings had no verdict; left unverified"
              % unanswered, file=sys.stderr)
    if verdict_misrouted:
        print("synthesize: %d verdict(s) could not be bound to the cell they were "
              "dispatched for (an advisor answered, mislabelled): %s"
              % (len(verdict_misrouted),
                 ", ".join("%s (%s)" % (m["queue_id"], m["reason"])
                           for m in verdict_misrouted[:5])),
              file=sys.stderr)
    unknown = set(verdicts) - {e["queue_id"] for e in queue}
    if unknown:
        print("synthesize: verdict file(s) for unknown queue_id(s): %s"
              % ", ".join(sorted(unknown)), file=sys.stderr)
    # Verdict files that existed but could not be parsed/validated (#938). Their
    # findings are already counted as unanswered above (no verdict matched); the
    # count here records that a verdict was LOST to corruption, not that one was
    # never generated -- otherwise a malformed advisor return vanishes silently.
    verdict_unloadable = verdict_unloadable or []
    if verdict_unloadable:
        print("synthesize: %d verdict file(s) were un-loadable (corrupt) and "
              "their findings left unverified: %s"
              % (len(verdict_unloadable),
                 ", ".join(u.get("file", "?") for u in verdict_unloadable)),
              file=sys.stderr)
    # A run whose verdicts all failed to match now produces gate PASS / grade A
    # / risk LOW -- the safest-looking output there is -- because only verified
    # findings gate. Stderr is not what CI consumes, so the drop counts belong
    # in the artifact: supplied - matched - unknown is the number of verdicts
    # that named a queued finding but failed match_verdict's finding_id echo.
    # Includes bundle verdicts (by_fid) alongside queue_id-keyed `verdicts` --
    # under the P5 bundle flow `verdicts` is often empty while by_fid carries
    # the actual answers, and matched_n already counts bundle matches, so
    # leaving bundle verdicts out of "supplied" made the invariant go negative.
    _bundle_supplied = sum(len(vs) for vs in by_fid.values())
    _finding_ids = {f.get("id") for f in findings if f.get("id")}
    _bundle_unknown = sum(len(vs) for fid, vs in by_fid.items() if fid not in _finding_ids)
    verdict_stats = {
        "queued": len(queue),
        "cut": cut,
        "supplied": len(verdicts) + _bundle_supplied,
        "matched": matched_n,
        "unknown": len(unknown) + _bundle_unknown,
        # Verdict files present on disk but un-loadable (corrupt/invalid). A
        # non-zero count means verification evidence was lost, distinct from a
        # finding that never had a verdict generated (#938).
        "unloadable": len(verdict_unloadable),
        # #1475: a verdict file existed for the cell but its finding_id echo
        # named a different finding (or none). These are ALSO counted in
        # `unanswered` -- the finding genuinely has no valid verdict -- but the
        # cause is the opposite of a missing dispatch, and the report has to be
        # able to tell an operator which one happened.
        "misrouted": len(verdict_misrouted),
        # Measured only when --verdicts-dir was passed at all. Emitting 0 for a
        # run with no verify phase would read as "nothing went unanswered",
        # which is the opposite of the truth; null means "not measured", the
        # same convention as tool_axis.rejection_rate.
        "unanswered": unanswered if verdicts_supplied else None,
    }
    # Re-validate citations after advisor merges (idempotent; preserves epss).
    citations.enrich_citations(findings, catalog, epss_enabled=False)
    for f in findings:
        f["evidence"] = evidence_mod.derive_evidence(f, matched.get(id(f)))
        # KNOWN DIVERGENCE from queue_id (unchanged behavior, recorded): on a
        # fingerprint collision the queue assigns `fp` and `fp-1`, but both
        # findings export the bare `fp` here -- so a colliding pair does not
        # round-trip from exported identity back to its queue entry. See the
        # matching note in evidence.build_verify_queue.
        f["fingerprint"] = pre_verdict_fps[id(f)]
        f.pop("citation_quality", None)

    tool_like = [f for f in findings
                 if evidence_mod.is_tool_sourced(f) or f.get("reinforced")]

    def _tool_count(status):
        return sum(1 for f in tool_like if f["evidence"]["status"] == status)

    confirmed = _tool_count("tool_confirmed")
    rejected_n = _tool_count("rejected")
    decided = confirmed + rejected_n
    tool_axis = {
        "queued": len(tool_like),
        "confirmed": confirmed,
        "rejected": rejected_n,
        "needs_more_info": _tool_count("needs_more_info"),
        "unanswered": _tool_count("tool_reported"),
        # Share of DECIDED tool claims an advisor refuted — the tool-side
        # mirror of the 27% agentic rejection rate. None when nothing was
        # decided, so an unverified run reports "unmeasured", not "0%".
        "rejection_rate": round(rejected_n / decided, 3) if decided else None,
    }

    rejected = [f for f in findings if f["evidence"]["status"] == "rejected"]
    active = [f for f in findings if f["evidence"]["status"] != "rejected"]
    delta_mode = bool(diff_hunks and diff_hunks.get("base"))
    if delta_mode:
        delta_mod.classify_findings(active, diff_hunks.get("hunks") or {}, diff_context)
    on_diff_active = [f for f in active if (f.get("delta") or {}).get("on_diff")]
    pre_existing_active = [f for f in active
                           if delta_mode and not (f.get("delta") or {}).get("on_diff")]
    gate_source = active
    if delta_mode and gate_scope == "on-diff":
        gate_source = on_diff_active
    gate_eligible = (gate_source if gate_unverified else
                     [f for f in gate_source
                      if f["evidence"]["status"] in evidence_mod.GATE_ELIGIBLE_DEFAULT])

    by_panel = {p: [] for p in findings_mod.VALID_PANELS}
    for f in gate_eligible:
        by_panel.get(f["panel"], by_panel["code"]).append(f)

    known_groups = {g["name"] for g in groups_meta}
    eligible_ids = {id(x) for x in gate_eligible}
    group_objs = []
    for g in groups_meta:
        gfiles = set(g["files"])
        gfind = [f for f in active
                 if (f.get("_group") == g["name"])
                 or (f.get("_group") not in known_groups
                     and (f.get("location") or {}).get("file") in gfiles)]
        geligible = [f for f in gfind if id(f) in eligible_ids]
        gp = {p: [x for x in geligible if x["panel"] == p] for p in by_panel}
        group_objs.append({
            "name": g["name"],
            "files": g["files"],
            "panel_grades": {p: grading_mod.grade(gp[p]) for p in by_panel},
            "key_findings": [f.get("title", "") for f in gfind
                             if f["severity"] in ("CRITICAL", "HIGH")][:5],
        })
    group_objs = grading_mod._roll_up_to_parent(group_objs, groups_meta, by_panel)

    # The headline grade now comes from the health index, not the max-severity
    # rollup -- see health_grade(). Computed here (rather than inline in the
    # summary) because certify() needs it, and the same dict is reused below so
    # the grade and the reported health can never disagree.
    health = grading_mod.health_stats(grading_mod.nonblank_loc(target, groups_meta), gate_eligible)
    overall = grading_mod.health_grade(health["score"])
    for f in findings:
        f.pop("_group", None)
        f.pop("_repo_root", None)
    tool_names = {evidence_mod.tool_name(f) for f in findings
                  if evidence_mod.is_tool_sourced(f)}
    planned = (fan_out or {}).get("planned") or {} if isinstance(fan_out, dict) else {}
    executed = (fan_out or {}).get("executed") or {} if isinstance(fan_out, dict) else {}
    panels_incomplete = {p for p, n in planned.items() if executed.get(p, 0) < n}
    produced = set(tools_ran if tools_ran is not None else tool_names)
    # #1031: certify on the runner's DETERMINISTIC adapter set when its manifest
    # is present -- `missing` (applicable known adapters that didn't produce) is
    # the only real tool-coverage loss, so it drives the gate (`tools_absent`).
    # The scout's advisory list is demoted: a request the runner can't satisfy
    # (no adapter, or inapplicable to the target) is disclosed as non-gating
    # `requested_unavailable`, never sinking coverage_certified. With no manifest
    # (e.g. --no-tools, or a pre-manifest run) the 4.x scout-derived gate stands.
    if isinstance(tool_manifest, dict):
        selected = set(tool_manifest.get("selected") or [])
        produced_m = set(tool_manifest.get("produced") or [])
        missing = tool_manifest.get("missing")
        tools_absent = sorted(missing if isinstance(missing, list)
                              else selected - produced_m)
        unavailable = sorted(set(scout_requested or []) - selected - produced_m)
        tool_divergence = {t: "requested_absent" for t in tools_absent}
        tool_divergence.update({t: "requested_unavailable" for t in unavailable})
    else:
        tools_absent = sorted(set(scout_requested or []) - produced)
        tool_divergence = {t: "requested_absent" for t in tools_absent}
    divergence = {
        "panels": {p: {"planned": planned[p], "executed": executed.get(p, 0)}
                   for p in sorted(panels_incomplete)},
        "tools": tool_divergence,
    }
    integrity = integrity if isinstance(integrity, dict) else None
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
    scope_ok = not ((out_of_scope or {}).get("count")
                    if isinstance(out_of_scope, dict) else False)
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
    # Both default to empty/None for callers that predate P4 cells (every
    # existing build_report call site), so cell_audit is a no-op {"missing_
    # floor": []} for them -- byte-identical to pre-5.0 behavior.
    cell_audit = plan_mod.audit_floor_cells(coverages or [], plan_mod.present_cells(ingested_paths))
    cert = grading_mod.certify(overall, gate_eligible, fail_on, panels_incomplete, tools_absent,
                   integrity_ok=integrity_ok,
                   verdicts_unloadable=len(verdict_unloadable),
                   verdicts_unanswered=(unanswered if verdicts_supplied else 0),
                   missing_floor=len(cell_audit["missing_floor"]))
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "meta": {
            "target": target,
            "review_type": review_type,
            "timestamp": timestamp,
            "version": __version__,
            "ocrdb_version": ocrdb.BUNDLE_VERSION if ocrdb_bundle is not None else None,
            "security_mode": security_mode,
            "models_used": _collect_models_used(findings),
            "coverage": {
                "adapters": tool_dispositions or {},
                "tools_ran": (sorted(tools_ran) if tools_ran is not None
                              else sorted(tool_names)),
                "build_executing_tools": sorted(
                    (set(tools_ran) if tools_ran is not None else tool_names)
                    & EXECUTES_TARGET_BUILD),
                "tool_policy_mode": tool_policy_mode or "unknown",
                "tool_axis": tool_axis,
                # #471: with scout_requested, lets consumers tell "no scouts
                # ran" (0) apart from "scouts ran and requested no tools"
                # (N>0 with scout_requested []).
                "scout_profiles_seen": scout_profiles_seen,
                "scout_requested": sorted(scout_requested or []),
                "out_of_scope": out_of_scope,
                "doc_policy": doc_policy,
                "verdicts": verdict_stats,
                "ocrdb": ocrdb_coverage,   # None when no bundle vendored (= 4.x)
                # P5 verify-matrix accounting: engaged (>= F_p) cell count and the
                # engaged cells left unverified -- the same set that forces gate
                # INCONCLUSIVE via the gate-aware `unanswered` count above.
                "verify_matrix": verify_matrix_cov,
                "fan_out": fan_out,
                "divergence": divergence,
                # 5.0 (matrix Sec5.1): per-floor-cell certifiable-coverage
                # disclosure -- {"missing_floor": [[group, domain], ...]}. A
                # non-empty list is what forced the gate to INCONCLUSIVE above.
                "cells": cell_audit,
                "resume": resume,
                "delta": ({"base": diff_hunks.get("base"),
                           "base_source": diff_hunks.get("base_source"),
                           "base_commit": diff_hunks.get("base_commit"),
                           "delta_start": diff_hunks.get("delta_start"),
                           "delta_end": diff_hunks.get("delta_end"),
                           "includes_uncommitted": diff_hunks.get("includes_uncommitted"),
                           "files_changed": diff_hunks.get("files_changed"),
                           "diff_context": diff_context,
                           "on_diff_total": len(on_diff_active),
                           "pre_existing_total": len(pre_existing_active)}
                          if delta_mode else None),
            },
            "integrity": integrity,
            # meta.cost: the run's dispatch ledger, derived from the artifacts
            # already ingested (scout profiles, dispatch plans, verify queue /
            # driver verdict bundles) — never hand-assembled. On the 5.0 driver
            # path `driver_cost` carries the per-class counts so review cells +
            # verify rounds + the tool scan are all represented (#1030); it is
            # None only when there is no driver plan to read. `tokens` stays
            # null until a host exposes per-dispatch usage.
            "cost": {
                "dispatches": cost_mod.cost_dispatches(
                    scout_profiles_seen, verdict_stats["queued"], driver_cost),
                # #run10 D4: host-reported usage when the host wrote usage.json
                # (see load_run_usage); still null when it did not -- never an
                # estimate derived from the counts above.
                "tokens": run_usage,
            },
        },
        "summary": {
            "overall_grade": cert["overall_grade"],
            "provisional_grade": cert["provisional_grade"],
            "coverage_certified": cert["coverage_certified"],
            "coverage_note": cert["coverage_note"],
            "risk_level": grading_mod.risk_level(gate_eligible),
            "top_issues": [f.get("title", "") for f in
                           sorted(active, key=findings_mod._issue_sort)[:3]],
            "gate": cert["gate"],
            "gate_policy": ("include_unverified" if gate_unverified
                            else "confirmed_only"),
            # #1059: `stats` and `evidence_stats` count DIFFERENT populations --
            # `stats` the ACTIVE (non-rejected == findings[]) set, `evidence_stats`
            # ALL findings (active + discarded == findings[] + discarded_claims[]).
            # Their totals differ by len(rejected); the population tags + counts
            # block below make that explicit and reconcilable (the run-5 self-scan
            # surfaced two unlabeled HIGH counts in one summary).
            "stats": grading_mod.severity_stats(active),
            "stats_population": "active",
            # Which severities the --fail-on threshold puts in play, and which of
            # them the FAIL is actually made of. Computed off `gate_eligible`,
            # NOT off `stats` above -- see gate_severity_roles().
            "gate_severities": grading_mod.gate_severity_roles(gate_eligible, fail_on),
            # #1146: size-aware health ratio alongside the letter; denominator is
            # the gate-eligible set, numerator the reviewed scope's non-blank LoC.
            "health": health,
            "evidence_stats": findings_mod.evidence_stats(findings),
            "evidence_stats_population": "all",
            "counts": {
                "active": len(active),
                "discarded": len(rejected),
                "total": len(findings),
            },
            "delta": ({"on_diff": grading_mod.severity_stats(on_diff_active),
                       "pre_existing": grading_mod.severity_stats(pre_existing_active)}
                      if delta_mode else None),
        },
        "groups": group_objs,
        "findings": active,
        "discarded_claims": rejected,
        "cross_panel": {"integration_findings": integration_findings},
    }

def attach_schema_status(report, errors):
    """Record schema-validation results in the artifact itself.

    Validation stays advisory — a run never aborts — but the count is no longer
    stderr-only, so a downstream consumer (issue tracker, CI) can see that a
    report failed its own schema.
    """
    report.setdefault("meta", {})["schema_errors"] = len(errors)
    return report

def validate_report(report):
    """Validate report structure and content, returning error and warning lists."""
    errors, warnings = [], []
    for key in ("meta", "summary", "groups", "findings", "cross_panel"):
        if key not in report:
            errors.append("missing top-level key: %s" % key)
    for i, f in enumerate(report.get("findings", [])):
        if not findings_mod.ID_RE.match(f.get("id", "")):
            errors.append("finding[%d] bad id: %r" % (i, f.get("id")))
        if not f.get("title"):
            errors.append("finding[%d] missing title" % i)
        if not f.get("category"):
            errors.append("finding[%d] missing category" % i)
        if f.get("severity") not in findings_mod.SEVERITIES:
            errors.append("finding[%d] bad severity: %r" % (i, f.get("severity")))
        if f.get("confidence") not in findings_mod.CONFIDENCES:
            errors.append("finding[%d] bad confidence: %r" % (i, f.get("confidence")))
        if f.get("panel") not in findings_mod.VALID_PANELS:
            errors.append("finding[%d] bad panel: %r" % (i, f.get("panel")))
        ev = f.get("evidence") or {}
        if ev.get("status") not in evidence_mod.EVIDENCE_STATUSES:
            errors.append("finding[%d] bad evidence.status: %r" % (i, ev.get("status")))
        loc = f.get("location") or {}
        if not loc.get("file") or loc.get("line_start") is None:
            warnings.append("finding[%d] missing location.file/line_start" % i)
        agent_sourced = not evidence_mod.is_tool_sourced(f)
        if agent_sourced and f.get("panel") in ("security", "redteam") and f.get("severity") in ("CRITICAL", "HIGH"):
            if not f.get("cvss"):
                errors.append("finding[%d] %s %s missing cvss" % (i, f["panel"], f["severity"]))
            if not f.get("exploit_scenario"):
                errors.append("finding[%d] %s %s missing exploit_scenario" % (i, f["panel"], f["severity"]))
    id_counts = {}
    for f in report.get("findings", []):
        fid = f.get("id")
        if fid:
            id_counts[fid] = id_counts.get(fid, 0) + 1
    for fid, count in id_counts.items():
        if count > 1:
            errors.append("duplicate finding id: %s" % fid)
    return errors, warnings
