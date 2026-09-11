#!/usr/bin/env python3
"""Merge panopticon finding files into a validated CodeReviewReport with
grades and a CI gate verdict. Stdlib-only.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import scripts.html_report as html_report
import scripts.ocrdb as ocrdb
import scripts.plan_contract as plan_contract
import scripts.x0x_report as x0x_report
import scripts.synth.findings as findings_mod
import scripts.synth.delta as delta_mod
import scripts.synth.plan as plan_mod
import scripts.synth.cost as cost_mod
import scripts.synth.report as report_mod
import scripts.synth.render as render_mod
import scripts.synth.verdicts as verdicts_mod


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
    gj = plan_mod.load_groups_json(groups_path)
    groups_meta = gj.get("groups", [])

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

    # WS-0 S3: each ReportInputs struct loads itself from the run folder; main()
    # only threads the three reads two loaders share -- the dispatch plans
    # (ToolAxis.policy_mode + PlanInputs; loaded ONCE so the two cannot drift
    # apart again, #146/C1), the verify queue (FindingSet.verdict_run_id +
    # PlanInputs.resume) and the ingested tool findings (FindingSet + ToolAxis).
    # WS-0 S3 fix #1: FindingSet.prepare() runs BEFORE the --emit-verify-queue
    # branch, and the verify-queue read / FindingSet.load()'s verdicts read run
    # AFTER it -- matching the old main()'s order. emit_verify_queue can DELETE
    # a stale verify-queue.json left by a previous run, so reading the queue or
    # loading verdicts before that branch runs would let stale state leak into
    # verdict_run_id, resume and invalid_verify_queue on the "nothing to queue
    # this run" path.
    # 5.1 surface 2. dirname(--groups) IS the per-run folder (the same
    # resolution used for --run-dir above), and host-capabilities.json is a
    # non-top-level artifact, so it sits beside groups.json. The artifact is
    # a file on disk and therefore untrusted: absent, truncated or corrupt
    # JSON all fall back to {} -- "nobody looked" -- rather than raising a
    # traceback mid-synthesis or fabricating a posture.
    _hc_path = os.path.join(os.path.dirname(os.path.abspath(args.groups or ".")),
                            "host-capabilities.json")
    try:
        with open(_hc_path, encoding="utf-8") as fh:
            host_capabilities = json.load(fh)
    except (OSError, ValueError):
        host_capabilities = {}          # absent or corrupt -> "nobody looked"
    if not isinstance(host_capabilities, dict):
        host_capabilities = {}

    run = report_mod.RunConfig.from_args(args, gj, ts, host_capabilities=host_capabilities)
    plans = plan_mod.load_dispatch_plans_detailed(panopticon_dir=run_dir)
    tool_findings, dispositions, tools_ran = plan_mod.ingest_tool_findings(args)
    tools = plan_mod.ToolAxis.load(args, run_dir, plans[0], dispositions, tools_ran)
    prepared = findings_mod.FindingSet.prepare(args, tool_findings, run.security_mode)
    if args.emit_verify_queue and verdicts_mod.emit_verify_queue(
            prepared[0], run_dir, args.max_verify):
        return 0
    queue = plan_mod.load_verify_queue(run_dir)
    fs = findings_mod.FindingSet.load(args, tool_findings, run.security_mode,
                                      verdict_run_id=(queue[0] or {}).get("run_id"),
                                      prepared=prepared)
    plan = plan_mod.PlanInputs.load(run_dir, args.files, args.verdicts_dir, groups_meta,
                                    plans, queue, fs.verdicts)
    # #1335: SPEND, not coverage -- a no-op scanner still cost a dispatch.
    cost = cost_mod.CostInputs.load(
        run_dir, args.verdicts_dir,
        plan_mod.tools_produced_from_dispositions(dispositions))
    delta = delta_mod.DeltaContext.from_args(args)

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
        run=run, findings=fs, delta=delta, plan=plan, tools=tools, cost=cost))
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
