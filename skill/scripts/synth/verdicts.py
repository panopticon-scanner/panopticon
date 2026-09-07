"""The verify round: emit its queue, then resolve findings against the advisor
verdicts and the delta context."""
from dataclasses import dataclass
import copy
import os
import sys

import scripts.citations as citations
from scripts.citations import load_cwe_catalog
import scripts.evidence as evidence_mod
import scripts.ocrdb as ocrdb
from . import findings as findings_mod
from . import codes as codes_mod
from . import delta as delta_mod
from . import plan as plan_mod


def emit_verify_queue(findings, run_dir, max_verify):
    """--emit-verify-queue (WS-0 S3): write <run_dir>/verify-queue.json from the
    prepared findings and return True (main exits 0 so the orchestrator runs
    the verify phase). With nothing to queue, remove a STALE queue file and
    return False: main goes on to emit the final report."""
    prepared, _ = findings_mod.prepare_for_queue(copy.deepcopy(findings))
    queue, cut = evidence_mod.build_verify_queue(prepared, max_verify)
    qpath = os.path.join(run_dir, "verify-queue.json")
    if queue:
        evidence_mod.write_verify_queue(queue, cut, qpath)
        print("verify queue: %d entries (%d cut by --max-verify) -> %s"
              % (len(queue), cut, qpath))
        return True
    # Nothing to verify this run. Post-P2 EVERY finding queues -- tool
    # findings included -- so an empty queue means this run produced no
    # findings at all, not "only findings that never queued". A queue file
    # left by a PREVIOUS run would otherwise mislead step 7's re-run: the
    # orchestrator branches on the file's existence, so a stale one would
    # send it to the verify phase with stale/absent entries.
    if os.path.isfile(qpath):
        try:
            os.remove(qpath)
        except OSError as e:
            print("synthesize: could not remove stale %s: %s" % (qpath, e),
                  file=sys.stderr)
    print("verify queue empty; emitting final report", file=sys.stderr)
    return False


@dataclass(frozen=True)
class Resolved:
    """resolve_findings()'s result: every finding with its evidence object and
    fingerprint, partitioned for the sections downstream (WS-0 S2).

    `findings` is the deduped list (integration findings split off into
    `integration_findings`); `active`/`rejected` partition it by evidence
    status; `gate_eligible` is the subset grades and the gate are computed
    from; the on-diff/pre-existing lists are empty outside delta mode.
    `verdict_stats`, `verify_matrix`, `tool_axis`, `ocrdb_coverage` and
    `delta_meta` are the meta.coverage sections this stage owns; `tool_names`
    is the adapter set inferred from the findings (the fallback when the tool
    layer reported none); `unanswered_gate` the gate-aware unanswered count
    certify() consumes."""
    findings: list
    active: list
    rejected: list
    gate_eligible: list
    on_diff_active: list
    pre_existing_active: list
    integration_findings: list
    ocrdb_bundle: dict | None
    ocrdb_coverage: dict | None
    verdict_stats: dict
    verify_matrix: dict
    tool_axis: dict
    tool_names: set
    delta_mode: bool
    delta_meta: dict | None
    doc_policy: dict | None
    verdict_unloadable: list
    unanswered_gate: int


def resolve_findings(fs, delta, run):
    """The verdict-matching cluster (WS-0 S2): dedupe, queue, bind advisor
    verdicts, derive every finding's evidence object and fingerprint, then
    partition for the gate under the two-axis severity x evidence model.

    Severity is never mutated here. Verdicts (from evidence.load_verdicts) are
    applied to queued findings; every finding gets an evidence object.
    `fs.verdicts_supplied` records whether --verdicts-dir was passed at all
    (distinct from whether it yielded any verdicts) so the aggregate "no
    verdict" note still fires for an existing-but-empty dir.
    """
    findings, integration_findings = findings_mod.prepare_for_queue(fs.findings)
    catalog = fs.catalog if fs.catalog is not None else load_cwe_catalog()
    ocrdb_bundle = ocrdb.load_bundle()
    ocrdb_coverage = codes_mod.validate_finding_codes(findings, ocrdb_bundle)
    queue, cut = evidence_mod.build_verify_queue(findings, run.max_verify)
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
    verdicts = fs.verdicts or {}
    matched = {}
    matched_n = 0
    unanswered = 0
    by_fid = fs.verdict_bundles or {}
    # Computed on PRE-verdict evidence (nothing below has applied a verdict yet)
    # and on this DEDUPED `findings` list, so it is a subset of (never
    # identical to) phases.verify.verify_execute's own engagement decision, which
    # scores the raw per-cell list -- see engaged_matrix_cells's docstring.
    engaged_cells = plan_mod.engaged_matrix_cells(findings)
    # #1475: verdict files that EXIST for a cell but cannot be bound to it (the
    # finding_id echo names a different finding, or none at all). Collected
    # separately because they are the opposite failure from `unanswered`: an
    # advisor ran and answered, and the answer was mislabelled.
    verdict_misrouted = []
    for entry in queue:
        v = evidence_mod.match_verdict(entry, verdicts, run_id=fs.verdict_run_id,
                                       misrouted=verdict_misrouted)
        if v is None and by_fid:
            v = evidence_mod.match_verdict_by_id(entry["finding"], by_fid,
                                                 run_id=fs.verdict_run_id)
        if v is not None:
            evidence_mod.apply_verdict(entry["finding"], v)
            matched_n += 1
        elif fs.verdicts_supplied and plan_mod._finding_owed_verification(entry["finding"], engaged_cells):
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
    verdict_unloadable = fs.verdict_unloadable or []
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
        "unanswered": unanswered if fs.verdicts_supplied else None,
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
    delta_mode = delta.active
    if delta_mode:
        delta_mod.classify_findings(active, delta.diff_hunks.get("hunks") or {}, delta.diff_context)
    on_diff_active = [f for f in active if (f.get("delta") or {}).get("on_diff")]
    pre_existing_active = [f for f in active
                           if delta_mode and not (f.get("delta") or {}).get("on_diff")]
    gate_source = active
    if delta_mode and run.gate_scope == "on-diff":
        gate_source = on_diff_active
    gate_eligible = (gate_source if run.gate_unverified else
                     [f for f in gate_source
                      if f["evidence"]["status"] in evidence_mod.GATE_ELIGIBLE_DEFAULT])

    tool_names = {evidence_mod.tool_name(f) for f in findings
                  if evidence_mod.is_tool_sourced(f)}
    delta_meta = ({"base": delta.diff_hunks.get("base"),
                   "base_source": delta.diff_hunks.get("base_source"),
                   "base_commit": delta.diff_hunks.get("base_commit"),
                   "delta_start": delta.diff_hunks.get("delta_start"),
                   "delta_end": delta.diff_hunks.get("delta_end"),
                   "includes_uncommitted": delta.diff_hunks.get("includes_uncommitted"),
                   "files_changed": delta.diff_hunks.get("files_changed"),
                   "diff_context": delta.diff_context,
                   "on_diff_total": len(on_diff_active),
                   "pre_existing_total": len(pre_existing_active)}
                  if delta_mode else None)
    return Resolved(findings=findings, active=active, rejected=rejected,
                    gate_eligible=gate_eligible, on_diff_active=on_diff_active,
                    pre_existing_active=pre_existing_active,
                    integration_findings=integration_findings,
                    ocrdb_bundle=ocrdb_bundle, ocrdb_coverage=ocrdb_coverage,
                    verdict_stats=verdict_stats, verify_matrix=verify_matrix_cov,
                    tool_axis=tool_axis, tool_names=tool_names,
                    delta_mode=delta_mode, delta_meta=delta_meta,
                    doc_policy=fs.doc_policy, verdict_unloadable=verdict_unloadable,
                    # Gate-aware unanswered count: measured only when
                    # --verdicts-dir was passed at all (see verdict_stats).
                    unanswered_gate=unanswered if fs.verdicts_supplied else 0)
