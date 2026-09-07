#!/usr/bin/env python3
"""Merge panopticon finding files into a validated CodeReviewReport with
grades and a CI gate verdict. Stdlib-only.
"""
import argparse
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import scripts.citations as citations
import scripts.evidence as evidence_mod
import scripts.group_runner as group_runner
import scripts.html_report as html_report
import scripts.ingest_tools as ingest_tools
import scripts.ocrdb as ocrdb
import scripts.plan_contract as plan_contract
import scripts.x0x_report as x0x_report
import scripts.synth.findings as findings_mod
import scripts.synth.delta as delta_mod
import scripts.synth.plan as plan_mod
import scripts.synth.integrity as integrity_mod
import scripts.synth.cost as cost_mod
import scripts.synth.report as report_mod
import scripts.synth.render as render_mod


def main(argv=None):
    """Main entry point: load findings, enrich citations, build and validate report."""
    ap = argparse.ArgumentParser(description="panopticon synthesizer")
    ap.add_argument("--target", default="unknown")
    ap.add_argument("--groups", metavar="PATH")
    ap.add_argument("--security", choices=["standard", "redteam"], default=None,
                    help="Override security mode from groups.json")
    ap.add_argument("--fail-on", metavar="SEV", type=str.lower,
                    choices=["critical", "high", "medium", "low"])
    ap.add_argument("--severity", metavar="LEVEL", type=str.lower,
                    choices=["all", "medium", "high", "critical"], default="all",
                    help="Minimum severity to include in the report (all, medium, high, critical)")
    ap.add_argument("--changes", "-c", action="store_true",
                    help="Alias for a changes/diff review type")
    ap.add_argument("--out", default=None)
    ap.add_argument("--run-id", default=None,
                    help="driver run-manifest run_id -> X0X generated_by.run_id")
    ap.add_argument("--run-dir", default=None,
                    help="directory holding THIS run's artifacts (tools-manifest, "
                         "scout-*, coverage-*, dispatch plans, verify-queue, "
                         "unenforced-ack). Defaults to dirname(--groups); flat "
                         ".panopticon only for legacy non-run-folder invocations.")
    ap.add_argument("--html-out", metavar="PATH", default=None,
                    help="Write HTML report to PATH")
    ap.add_argument("--compare", metavar="JSON", nargs=2, default=None,
                    help="Compare two JSON reports and emit HTML")
    ap.add_argument("--epss", action="store_true")
    ap.add_argument("--tools-dir", metavar="DIR")
    ap.add_argument("--tools-exclude", metavar="GLOB", action="append", default=None,
                    help="Drop tool findings whose location.file matches GLOB "
                         "(repeatable; e.g. 'tests/fixtures/*')")
    ap.add_argument("--doc-paths", metavar="GLOB", action="append", default=None,
                    help="Doc-tree globs for the #487 severity policy "
                         "(default: docs/*, specs/*, plans/* trees); "
                         "standard mode soft-downgrades non-secret code "
                         "findings under them to INFO, disclosed in meta")
    ap.add_argument("--include-fixtures", action="store_true",
                    help="Keep tool findings located under test-fixture corpora "
                         "(testdata/, __fixtures__/, tests/fixtures/). Default "
                         "prunes them for parity with the standard-mode agentic "
                         "review prune (#434); pass this for redteam self-scans.")
    ap.add_argument("--emit-verify-queue", action="store_true",
                    help="Pass 1: write .panopticon/verify-queue.json and skip the "
                         "report when agentic findings need verification")
    ap.add_argument("--verdicts-dir", metavar="DIR", default=None,
                    help="Pass 2: ingest advisor verdict files from DIR")
    ap.add_argument("--gate-unverified", action="store_true",
                    help="Let corroborated/needs_more_info/unverified findings "
                         "drive grades and the gate")
    ap.add_argument("--max-verify", type=int, default=None, metavar="N",
                    help="Cap the verify queue at the top-priority N entries "
                         "(pass the same value to both passes)")
    ap.add_argument("--diff-hunks", metavar="PATH", default=None,
                    help="Path to the orchestrator's diff-hunks.json (#449); "
                         "stamps each finding with finding.delta")
    ap.add_argument("--diff-context", type=int, default=5, metavar="N",
                    help="Lines of tolerance for on-diff classification (default 5)")
    ap.add_argument("--gate-scope", choices=["on-diff", "all"], default="on-diff",
                    help="Scope the gate/grade to on-diff findings, or all (default on-diff)")
    ap.add_argument("files", nargs="*")
    args = ap.parse_args(argv)

    if args.compare:
        a_path, b_path = args.compare
        report_a = render_mod._read_json_report(a_path)
        if report_a is None:
            return 2
        report_b = render_mod._read_json_report(b_path)
        if report_b is None:
            return 2
        html_out = args.html_out or (render_mod._derive_html_path(args.out) if args.out else None)
        if not html_out:
            print("ERROR: --compare requires --html-out or --out", file=sys.stderr)
            return 2
        html_report.write_html(report_b, html_out, compare_report=report_a)
        print("Compare HTML: %s" % html_out)
        return 0

    try:
        plan_contract.artifact_root(os.getcwd())
    except ValueError as exc:
        print("synthesize: %s" % exc, file=sys.stderr)
        return 2

    groups_meta = []
    review_type = "changes" if args.changes else "repo"
    security_mode = args.security
    # Default to the discovery output so the report carries group definitions:
    # groups[].files drives the HTML heatmap and grouped findings, and an empty
    # groups[] is why those fell back to path segments. An explicit --groups
    # still wins; auto-discovery only fills the common case where the
    # orchestrator's synthesize call omitted the flag.
    groups_path = args.groups
    if groups_path is None:
        default_groups = os.path.join(".panopticon", "groups.json")
        if os.path.isfile(default_groups):
            groups_path = default_groups
    if groups_path and os.path.isfile(groups_path):
        try:
            with open(groups_path, encoding="utf-8") as fh:
                gj = json.load(fh)
            if isinstance(gj, dict):
                groups_meta = gj.get("groups", [])
                # An explicit --changes wins: a discovered groups.json mode must
                # not flip an explicitly-requested changes review back to repo.
                if not args.changes:
                    review_type = findings_mod.MODE_TO_REVIEW_TYPE.get(gj.get("mode"), review_type)
                if security_mode is None:
                    security_mode = gj.get("security_mode", "standard")
            else:
                print("synthesize: %s is not a JSON object; ignoring" % groups_path,
                      file=sys.stderr)
        except (OSError, ValueError) as e:  # tolerant by design: never abort a run
            print("synthesize: could not read %s (%s); ignoring" % (groups_path, e),
                  file=sys.stderr)
    if security_mode is None:
        security_mode = "standard"

    # #17/#16: run-scoped artifacts (tools-manifest, scout-*, coverage-*, dispatch
    # plans, verify-queue, unenforced-ack) live in the run directory next to
    # groups.json — NOT flat .panopticon under 5.1 per-run folders. Reading them
    # flat certified tool coverage against a PREVIOUS run's manifest (#17) and
    # zeroed the scout coverage (#16). Resolve every run artifact under run_dir.
    run_dir = args.run_dir or (os.path.dirname(groups_path) if groups_path else "") \
        or ".panopticon"
    if args.run_id and run_dir == ".panopticon":
        # #17 fail-open guard: a 5.1 run (--run-id set) that fell back to flat
        # .panopticon has no run folder, so it would read a PRIOR run's stale
        # artifacts. Make the drift LOUD — never silent. (The schema_version
        # assertion at the manifest read still FATALs on a stale pre-5.1 manifest,
        # so certification cannot silently certify against one either.)
        print("WARNING (#17): --run-id set but no run directory resolved "
              "(--run-dir/--groups); falling back to flat .panopticon, which under "
              "5.1 holds no run artifacts. Pass --groups <run-folder>/groups.json.",
              file=sys.stderr)

    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out = args.out or os.path.join(".panopticon", "report-%s.json" % ts.replace(":", ""))

    if not args.tools_dir:
        default_tools = os.path.join(".panopticon", "tools")
        if os.path.isdir(default_tools) and os.listdir(default_tools):
            print("synthesize: %s appears un-ingested — pass --tools-dir %s to "
                  "include tool findings in this report"
                  % (default_tools, default_tools), file=sys.stderr)
    findings = findings_mod.load_findings(args.files)
    tool_dispositions = {}
    # None when --tools-dir wasn't supplied: build_report treats None as
    # "not measured -> infer build_executing_tools from findings"; an empty set
    # would ASSERT "no build-executing tool ran" from an absence of evidence
    # (the inversion #450 was about).
    tools_ran = None
    if args.tools_dir and os.path.isdir(args.tools_dir):
        tool_findings, tool_dispositions = ingest_tools.ingest_dir_detailed(
            args.tools_dir, None, exclude_globs=args.tools_exclude,
            include_fixtures=args.include_fixtures)
        for tf in tool_findings:
            findings.append(findings_mod.normalize_finding(tf))
        # A "failed" disposition (empty / unparseable / no-adapter) is excluded,
        # so build_executing_tools can no longer name an adapter that ran empty.
        tools_ran = plan_mod.tools_ran_from_dispositions(tool_dispositions)
    # #1031: the runner's deterministic adapter manifest (run_tools --manifest:
    # selected/produced/missing/excluded_scope). Present -> build_report gates on
    # `missing`, not the scout's advisory list. Tolerant read: a corrupt/absent
    # manifest just falls back to the 4.x scout-derived gate.
    tool_manifest = None
    _tm_path = os.path.join(run_dir, "tools-manifest.json")
    if os.path.isfile(_tm_path):
        try:
            with open(_tm_path, encoding="utf-8") as fh:
                _tm = json.load(fh)
            tool_manifest = _tm if isinstance(_tm, dict) else None
        except (OSError, ValueError):
            tool_manifest = None
    if tool_manifest is not None:
        # #17: never certify against a foreign/stale manifest. A 5.1 manifest
        # carries schema_version; its run_id (when the runner stamps it) must
        # match this run. Either mismatch is a loud error, not a silent fallback.
        if "schema_version" not in tool_manifest:
            sys.exit("FATAL (#17): tools-manifest at %s lacks schema_version — it "
                     "looks like a pre-5.1 flat manifest from another run; refusing "
                     "to certify against it. Re-run the tools phase." % _tm_path)
        _mrid = tool_manifest.get("run_id")
        if args.run_id and _mrid and _mrid != args.run_id:
            sys.exit("FATAL (#17): tools-manifest run_id %r != this run %r (at %s) — "
                     "refusing to certify against another run's manifest."
                     % (_mrid, args.run_id, _tm_path))
    catalog = citations.load_cwe_catalog()
    citations.enrich_citations(findings, catalog, epss_enabled=args.epss,
                               cache_path=os.path.join(".panopticon", "epss-cache.json"))
    doc_policy = findings_mod.apply_doc_severity_policy(findings, security_mode,
                                           doc_globs=args.doc_paths)
    if doc_policy and doc_policy["downgraded"]:
        print("synthesize: %d code finding(s) under doc trees soft-downgraded "
              "to INFO (#487; secrets exempt, redteam bypasses) -- see "
              "meta.coverage.doc_policy" % doc_policy["downgraded"],
              file=sys.stderr)
    if args.severity and args.severity != "all":
        threshold = findings_mod.SEV_ORDER.index(args.severity.upper())
        findings = [f for f in findings if findings_mod._sev_rank(f) <= threshold]

    if args.emit_verify_queue:
        import copy
        prepared, _ = findings_mod.prepare_for_queue(copy.deepcopy(findings))
        queue, cut = evidence_mod.build_verify_queue(prepared, args.max_verify)
        qpath = os.path.join(run_dir, "verify-queue.json")
        if queue:
            evidence_mod.write_verify_queue(queue, cut, qpath)
            print("verify queue: %d entries (%d cut by --max-verify) -> %s"
                  % (len(queue), cut, qpath))
            return 0
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

    verdicts, verdict_unloadable = evidence_mod.load_verdicts_detailed(args.verdicts_dir)
    verdict_bundles, bundle_unloadable = evidence_mod.load_verdict_bundles(args.verdicts_dir)
    # Both loaders scan the same verdicts_dir and independently attempt to parse
    # every *.json in it, so a single unparseable file is reported by both --
    # dedupe on filename or a genuinely-corrupt file double-counts in
    # meta.coverage.verdicts.unloadable (#938 follow-on).
    verdict_unloadable = verdict_unloadable or []
    _already_unloadable = {u.get("file") for u in verdict_unloadable}
    verdict_unloadable = verdict_unloadable + [
        u for u in bundle_unloadable if u.get("file") not in _already_unloadable]
    # Union of every per-group dispatch-plan-*.json on disk -- loaded ONCE and
    # shared with derive_tool_policy_mode, so the two cannot drift apart again
    # (#146/C1). The real fan-out workflow writes one plan file PER GROUP
    # (dispatch-plan-<group>.json); a lone dispatch-plan.json is just the
    # one-group case of that same naming convention, not a different shape.
    # plans_seen distinguishes "no plan found -> reconcile skipped" from
    # "reconciled, nothing wrong" -- an empty unexpected/missing pair means
    # nothing on its own (see meta.integrity below).
    _plan_lists, plans_seen, invalid_plans = plan_mod.load_dispatch_plans_detailed(
        panopticon_dir=run_dir)
    _plan = [e for plan in _plan_lists for e in plan]
    out_of_scope = plan_mod.out_of_scope_findings(args.files, _plan)
    if out_of_scope and out_of_scope["count"]:
        print("synthesize: %d finding(s) cite files OUTSIDE their group's "
              "assigned file list (#441) -- reviewers left their lane; see "
              "meta.coverage.out_of_scope" % out_of_scope["count"],
              file=sys.stderr)
    tool_policy_mode = plan_mod.derive_tool_policy_mode(plans=_plan_lists)
    fan_out = group_runner.fan_out_coverage(_plan) if _plan else None
    _queue = None
    invalid_verify_queue = None
    queue_path = os.path.join(run_dir, "verify-queue.json")
    if os.path.isfile(queue_path):
        try:
            with open(queue_path, encoding="utf-8") as fh:
                loaded_q = json.load(fh)
            if (isinstance(loaded_q, dict)
                    and isinstance(loaded_q.get("entries"), list)):
                _queue = loaded_q
            else:
                invalid_verify_queue = "verify queue has no entries list"
        except (OSError, ValueError) as exc:
            invalid_verify_queue = "cannot read verify queue: %s" % exc
    resume = group_runner.resume_stats(_plan, _queue, args.verdicts_dir,
                                       _verdicts=verdicts)
    unexpected, missing = integrity_mod.reconcile_findings_files(_plan, args.files)
    _ack = integrity_mod.read_unenforced_ack(os.path.join(run_dir, "unenforced-ack.json"))
    # #493 R2: an ack with no run binding over-reports risk forever -- a
    # stale ack from an earlier --allow-unenforced run would mark a fully
    # enforced run acknowledged. The ack now carries plan_sha256 (canonical
    # hash of the plan content it acknowledged); treat a non-matching ack as
    # STALE: report false + a loud note. A legacy ack without the field stays
    # trusted (pre-#493 artifacts).
    ack_stale = False
    if _ack and _ack.get("plan_sha256") is not None and _plan_lists:
        _hashes = {integrity_mod._plan_hash(pl) for pl in _plan_lists}
        if _ack["plan_sha256"] not in _hashes:
            ack_stale = True
            print("synthesize: unenforced-ack.json does not hash-match any "
                  "on-disk dispatch plan -- STALE ack from a previous run; "
                  "reporting unenforced_acknowledged: false", file=sys.stderr)
    # #493 R4: after-the-fact content check -- when the orchestrator recorded
    # out-file hashes at fan-out end, verify the ingested bytes still match.
    content_checked, content_mismatched, content_snapshot_unreadable = \
        group_runner.verify_out_file_hashes(args.files)
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
    integrity = {"unexpected_findings_files": unexpected,
                 "missing_planned_files": missing,
                 "duplicate_out_files": integrity_mod.duplicate_out_files(_plan),
                 "mislabeled_findings_files": integrity_mod.mislabeled_findings_files(args.files),
                 "cross_domain_findings": integrity_mod.cross_domain_findings(args.files),
                 "unenforced_acknowledged": bool(_ack) and not ack_stale,
                 "ack_stale": ack_stale,
                 "content_hashes_checked": content_checked,
                 "content_mismatched_files": content_mismatched,
                 "content_snapshot_unreadable": content_snapshot_unreadable,
                 "empty_dispatch_plans": sum(1 for plan in _plan_lists if not plan),
                 "invalid_dispatch_plans": invalid_plans,
                 "invalid_verify_queue": invalid_verify_queue,
                 "plans_seen": plans_seen}
    if _ack:
        # Surface the Bash-coverage disclosure fields written by dispatch so
        # they appear in meta.integrity in the final report (#680).
        # Default to False so consumers never see None for this field.
        integrity["write_guard_covers_bash"] = _ack.get("write_guard_covers_bash", False)
    scout_requested = set()
    scout_profiles_seen = 0
    for sp in glob.glob(os.path.join(run_dir, "scout-*.json")):
        try:
            with open(sp, encoding="utf-8") as fh:
                sd = evidence_mod.load_json_tolerant(fh.read())
        except (OSError, ValueError):  # tolerant by design: never abort a run
            continue
        if not isinstance(sd, dict):
            continue
        scout_profiles_seen += 1
        tools = sd.get("tools")
        if isinstance(tools, list):
            scout_requested.update(t for t in tools if isinstance(t, str))
    if scout_profiles_seen and not scout_requested:
        # #471: a scout can return tools:[] -- a silent decline of the tool
        # layer. Disclose it; the artifact records scout_profiles_seen so
        # "no scouts ran" and "scouts ran, requested nothing" read apart.
        print("synthesize: %d scout profile(s) requested NO tools (tools:[]) "
              "-- the tool layer ran on default triggers only, not scout "
              "guidance" % scout_profiles_seen, file=sys.stderr)

    # 5.0 (matrix Sec5.1): auto-discover .panopticon/coverage-<group>.json the
    # same way groups.json/scout-*.json are auto-discovered above -- fed to
    # audit_floor_cells in build_report along with args.files (the "ingested
    # paths", reconcile_findings_files' own term for this same list).
    coverages = plan_mod.load_coverage_files(run_dir)

    # meta.cost (#1030): on the 5.0 driver path, count every dispatch class from
    # its own on-disk artifact -- review cells, verify rounds, and the tool scan.
    # driver_cost is None off the driver path (no dispatch-plan-driver.json), and
    # cost_dispatches then emits the scout + queued-advisor rows only.
    # #21: resolve the plan + verdicts under `run_dir`
    # like every other run artifact. The 5.1 per-run-folder migration threaded
    # run_dir through the scout/coverage/manifest reads above but MISSED this one
    # (the plan lives at run_dir/dispatch-plan-driver.json, not flat .panopticon),
    # leaving a now-false "cwd-relative" comment -- so driver_cost was silently
    # None on EVERY 5.1 run and cost_dispatches fell back to the empty 4.x shape,
    # falsifying meta.cost (run-7: reported scout=24/advisor=581 vs ~298 real
    # dispatches).
    driver_cost = cost_mod.driver_cost_counts(
        run_dir, args.verdicts_dir, tools_ran)

    diff_hunks = delta_mod.load_diff_hunks(args.diff_hunks) if args.diff_hunks else None
    if args.diff_hunks and not args.fail_on:
        # #957: a delta review is gate-first by intent, but the gate only arms
        # when --fail-on is passed. Without this notice a forgotten flag
        # yields a green-looking report whose gate silently reads OFF.
        print("synthesize: DELTA REVIEW WITH Gate: OFF -- no --fail-on was "
              "passed, so nothing can gate this change; pass --fail-on "
              "{critical,high,medium,low} to arm the gate", file=sys.stderr)

    # #1034/#1: a corrupt/malformed OCRDb bundle must exit with a code CI can
    # tell apart from a gate FAIL (1) or INCONCLUSIVE (2). Validate it up front
    # (build_report loads it again internally) and return 3 loudly, rather than
    # letting the ValueError escape as a traceback that Python exits 1 on.
    try:
        ocrdb.load_bundle()
    except ValueError as exc:
        print("synthesize: OCRDb bundle unreadable: %s" % exc, file=sys.stderr)
        return 3

    report = report_mod.build_report(report_mod.ReportInputs(
        run=report_mod.RunConfig(
            target=args.target,
            fail_on=args.fail_on,
            timestamp=ts,
            review_type=review_type,
            security_mode=security_mode,
            gate_unverified=args.gate_unverified,
            max_verify=args.max_verify,
            gate_scope=args.gate_scope,
        ),
        findings=findings_mod.FindingSet(
            findings=findings,
            verdicts=verdicts,
            verdicts_supplied=args.verdicts_dir is not None,
            verdict_unloadable=verdict_unloadable,
            verdict_run_id=(_queue or {}).get("run_id"),
            verdict_bundles=verdict_bundles,
            catalog=catalog,
            doc_policy=doc_policy,
        ),
        delta=delta_mod.DeltaContext(diff_hunks=diff_hunks, diff_context=args.diff_context),
        plan=plan_mod.PlanInputs(
            groups_meta=groups_meta,
            fan_out=fan_out,
            scout_requested=sorted(scout_requested),
            scout_profiles_seen=scout_profiles_seen,
            out_of_scope=out_of_scope,
            coverages=coverages,
            integrity=integrity,
            resume=resume,
        ),
        tools=plan_mod.ToolAxis(
            policy_mode=tool_policy_mode,
            tools_ran=tools_ran,
            dispositions=tool_dispositions,
            manifest=tool_manifest,
            ingested_paths=args.files,
        ),
        cost=cost_mod.CostInputs(
            driver_cost=driver_cost,
            run_usage=cost_mod.load_run_usage(run_dir),
        ),
    ))
    render_mod.redact_report_secrets(report)   # #run7 SEC-B2C: before any shareable artifact
    errors, warnings = report_mod.validate_report(report)
    report_mod.attach_schema_status(report, errors)
    for w in warnings:
        print("WARN: %s" % w, file=sys.stderr)
    for e in errors:
        print("SCHEMA: %s" % e, file=sys.stderr)

    paths = render_mod.write_report(report, out)
    # §5.1: emit the X0X catalog-gap report — the <DOM>-X0X / ZZZ-X0X findings as
    # candidate records for OCRDb's new-code adjudication pool (ingested
    # downstream), a sibling of the JSON report. Always emitted; empty candidates
    # = an honest "no catalog gaps this run".
    x0x = x0x_report.build_report(report.get("findings") or [],
                                  report.get("meta") or {}, args.run_id)
    x0x_stem = out[:-len(".json")] if out.endswith(".json") else out
    x0x_path = x0x_stem + "-x0x.json"
    x0x_tmp = x0x_path + ".tmp"
    with open(x0x_tmp, "w", encoding="utf-8") as fh:
        json.dump(x0x, fh, indent=2, sort_keys=True)
    os.replace(x0x_tmp, x0x_path)
    print("X0X artifact: %s (%d candidates)" % (x0x_path, len(x0x["candidates"])))
    html_out = args.html_out
    if html_out is None and args.out:
        html_out = render_mod._derive_html_path(paths[0])
    if html_out:
        html_report.write_html(report, html_out)
        print("HTML artifact: %s" % html_out)
    print(render_mod.render_summary(report))
    print("\nJSON artifact: %s" % ", ".join(paths))
    gate = report["summary"]["gate"]
    return 1 if gate == "FAIL" else 2 if gate == "INCONCLUSIVE" else 0


if __name__ == "__main__":
    sys.exit(main())
