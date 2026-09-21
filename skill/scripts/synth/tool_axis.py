"""The tool axis: the runner's tools-manifest, and the reconciliation that
turns it plus the dispatch plan into `meta.coverage` / `meta.integrity`.

Split out of `synth/plan.py` when that module reached the 700-line ceiling
(#1701). The two halves of the old module answer different questions and are
now separate: `plan.py` is the DISPATCH-plan side (group definitions, fan-out
accounting, coverage cells, out-of-scope, the run-folder loaders), this is the
TOOL side (the manifest and its two FATAL checks, the per-adapter dispositions,
what coverage was and was not certified). They meet in `reconcile`, which takes
a `plan.PlanInputs` and a `ToolAxis` and returns the `Reconciled` sections the
report is assembled from.

A mutual pair with `plan.py` -- this module reads `derive_tool_policy_mode`
(the posture the dispatch plans declare) and `plan.py` reads
`tools_ran_from_dispositions` -- which is safe for the reason `phases/`'s three
pairs are: layout rule 1 means every reference is a module attribute read at
CALL time, never a name bound from a half-initialized sibling at import time.
"""
from dataclasses import dataclass, field
import json
import os
import sys

import scripts.ingest_tools as ingest_tools
from scripts.tools import EXECUTES_TARGET_BUILD
from . import coverage_io as coverage_io
from . import plan as plan_mod
from . import repair as repair_mod
from . import validate_schema as validate_schema_mod


class ToolManifestError(ValueError):
    """A stale or foreign tool manifest cannot be used for synthesis."""


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
    suppressed: dict | None = None   # #1578: {segment: count} dropped as vendored
    # #1701: the vendored drops this run's GATE must still count -- non-empty
    # only under `--security redteam`. Carried beside `suppressed` rather than
    # inside it because they answer different questions: that one is what the
    # report DISCLOSES, this is what certification COUNTS. Never merged into
    # the report's findings body; `reconcile` hands it to `grade_report`.
    gated_suppressed: list | None = None
    # #1740 fix round 2: `{globs, count}` -- the operator/committed exclusion
    # POLICY this ingest ran under. Not a suppression: these findings were
    # never candidates for any gate in any mode, which is exactly why the
    # policy that removed them has to be published beside the two tallies that
    # are.
    excluded: dict | None = None

    @classmethod
    def load(cls, args, run_dir, plan_lists, dispositions, tools_ran, suppressed=None,
             gated_suppressed=None, excluded=None):
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
        # `lexists`, not `isfile` (fix round 2 L1): `isfile` asks "is a REGULAR
        # file", so a directory, a dangling symlink or a link to /dev/null at
        # this target-writable path answered "no manifest" and took the
        # permissive scout-derived branch -- the carve-out F1 closed for regular
        # files, reachable again by leaving something that is not one. `lexists`
        # asks the question this branch means ("is there anything here"), and
        # the open() below fails these with an OSError the reason names.
        if os.path.lexists(tm_path):
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
        if manifest is not None:
            # #17: never certify against a foreign/stale manifest. A 5.1 manifest
            # carries schema_version; its run_id (when the runner stamps it) must
            # match this run. Either mismatch is a loud error, not a silent fallback.
            if "schema_version" not in manifest:
                raise ToolManifestError("FATAL (#17): tools-manifest at %s lacks schema_version — it "
                         "looks like a pre-5.1 flat manifest from another run; refusing "
                         "to certify against it. Re-run the tools phase." % tm_path)
            mrid = manifest.get("run_id")
            if args.run_id and mrid and mrid != args.run_id:
                raise ToolManifestError("FATAL (#17): tools-manifest run_id %r != this run %r (at %s) — "
                         "refusing to certify against another run's manifest."
                         % (mrid, args.run_id, tm_path))
            # #1692: `selected` is the whole of what this manifest is FOR --
            # reconcile derives `tools_absent` from it, and certification from
            # that. A manifest with no `selected` key at all read as "the runner
            # selected nothing", so `{"schema_version": 1}` -- a shape needing no
            # corruption, only omission, in a target-writable file -- certified a
            # run on which zero scanners ran: nothing missing, every scout request
            # demoted to non-gating `requested_unavailable`, gate PASS, rc 0. A
            # manifest the runner writes always carries the key, even when it
            # selected nothing, so its absence is the READ failing, which is
            # #1644's case and gets #1644's treatment.
            #
            # A non-list `selected` is the same failure with a louder symptom:
            # `ingest_tools.lost_required_coverage` iterates it, so
            # `"selected": "semgrep"` published six one-letter tool names into
            # `divergence.tools`. Nothing here repairs the value -- a selection
            # nobody can read has no honest repair, and inventing one would be
            # certifying against a set the runner never wrote.
            if not isinstance(manifest.get("selected"), list):
                manifest_invalid = ("tools-manifest.json declares no `selected` "
                                    "list (%s)" % type(manifest.get("selected")).__name__)
                manifest = None
        if manifest_invalid:
            print("synthesize: %s -- the runner's selected/missing set is "
                  "unknown, so tool coverage is NOT certified (the scout's "
                  "advisory list is not a substitute for it)."
                  % manifest_invalid, file=sys.stderr)
        return cls(policy_mode=plan_mod.derive_tool_policy_mode(plans=plan_lists),
                   tools_ran=tools_ran, dispositions=dispositions, manifest=manifest,
                   ingested_paths=args.files, manifest_invalid=manifest_invalid,
                   suppressed=suppressed,                     # #1578
                   gated_suppressed=list(gated_suppressed or []),   # #1701
                   excluded=excluded)                          # #1740 round 2


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
    # #1701: the name-based drops this run's gate counts anyway (redteam
    # only; `[]` in every other mode). Beside `coverage` like the two blocks
    # above and for the same reason: `meta.coverage` is what the report SAYS,
    # and this is a population certification consumes but never publishes.
    gated_suppressed: list = field(default_factory=list)


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
        # drops out of it. Claim nothing here: the reason is recorded in
        # `meta.integrity` below, and `integrity_ok` is false, so the gate goes
        # INCONCLUSIVE with every other integrity failure (fix round 1 F1).
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
    # #1701 fix round 1 (F1/F2): the gate-counted set comes off `resolved`, not
    # off the ToolAxis -- `resolve_findings` applies the delta / `gate_scope`
    # filter to it, so the ToolAxis holds CANDIDATES and this holds what the
    # gate actually counts. Counting it here is what keeps the two published
    # tallies consistent with each other and with the gate.
    gated = list(resolved.gated_suppressed or [])
    gated_counts = repair_mod.repair_tools_suppressed(
        ingest_tools.suppressed_counts(gated))
    suppressed_total = repair_mod.repair_tools_suppressed(tools.suppressed)
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
                                     or integrity.get("invalid_verify_queue")
                                     # Fix round 1 F1: an unreadable manifest
                                     # is an integrity failure like the rest of
                                     # this list, so it forces INCONCLUSIVE.
                                     # Exempting it made corrupting one byte of
                                     # a target-writable file the cheapest way
                                     # to turn an INCONCLUSIVE gate into PASS.
                                     or integrity.get("tools_manifest_invalid"))
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
        # #1578 (SEC-G2B), widened by #1740: the name-based drops, per
        # segment (vendored / virtualenv-by-name / fixture-corpus); schema has the
        # why. #1701 fix round 1 (F2): ONE tally, split in two. `gated` is what
        # this run's gate counted anyway; this key is the remainder -- what the
        # exclusion kept out of the gate as well as out of the body, which is
        # what "suppressed" now means. The two sum, per segment, to the ingest's
        # own count -- the number stderr and `security_gate` print, which
        # `ingest_tools.suppressed_counts` exists to keep from diverging.
        # Repaired FIRST, then split: the tally is derived from `location.file`
        # values a scanner read out of the reviewed tree, so the arithmetic must
        # never run on a value the boundary has not pinned (a `"lots"` row cost
        # a TypeError mid-synthesis in fix round 1 before this order was fixed).
        # Clamped at 0 for the same reason: a hostile tally that under-counts
        # its own segment must not publish a negative measurement.
        "tools_suppressed": {
            segment: max(0, total - gated_counts.get(segment, 0))
            for segment, total in suppressed_total.items()},
        # #1701 fix round 1 (F2): the other half. Without it the artifact holds
        # no number at all for a redteam FAIL whose findings list is empty --
        # the mode that changed the gate was the mode that stopped disclosing,
        # and the report contradicted its own run's stderr and CI gate line.
        "tools_suppressed_gated": gated_counts,
        # #1740 fix round 2: the exclusion POLICY, repaired at the read like
        # its two siblings -- `exclude_paths:` is target-authored, so a glob
        # reaching a published artifact is a target-carried input.
        "tools_excluded": repair_mod.repair_tools_excluded(tools.excluded),
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
                      tools_manifest_invalid=tools.manifest_invalid,
                      gated_suppressed=gated)
