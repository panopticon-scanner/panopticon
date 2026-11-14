#!/usr/bin/env python3
"""Merge panopticon finding files into a validated CodeReviewReport with
grades and a CI gate verdict.

No third-party import at THIS level, but the run is not dependency-free: the
normal completion path validates the report -- before the write, and again as
re-read from disk -- and the sibling X0X artifact against their published
schemas, and `synth/validate_schema.py` does that with `jsonschema` and fails
CLOSED when the import does not resolve. See SKILL.md, Dependencies.
"""
import argparse
import json
import os
import sys

if __name__ == "__main__":  # run by path: puts skill/ on sys.path (#3505)
    import runpy
    runpy.run_path(os.path.join(os.path.dirname(os.path.realpath(__file__)), "_bootstrap.py"))

import scripts.config_schema as config_schema
import scripts.executable as executable
import scripts.first_contact as first_contact
import scripts.html_report as html_report
import scripts.ingest_tools as ingest_tools
import scripts.ocrdb as ocrdb
import scripts.plan_contract as plan_contract
import scripts.redact as redact
import scripts.safe_write as safe_write
import scripts.x0x_report as x0x_report
import scripts.synth.findings as findings_mod
import scripts.synth.delta as delta_mod
import scripts.synth.plan as plan_mod
import scripts.synth.tool_axis as tool_axis_mod
import scripts.synth.integrity as integrity_mod
import scripts.synth.cost as cost_mod
import scripts.synth.report as report_mod
import scripts.synth.render as render_mod
import scripts.synth.validate_schema as validate_schema_mod
import scripts.synth.verdicts as verdicts_mod


def build_parser():
    """The CLI, as a named function -- `driver.py` has had one since 5.0.

    Extracted so a test can bind the driver's emitted argv to THIS parser
    (#1637 P08 fix round 2): `tests/synth/helpers._cli_args` builds a Namespace
    directly, which is right for the loaders it feeds and means no test had
    ever put a driver-authored flag through argparse. Renaming an option here
    alone therefore stayed green while the real child exited 2.
    """
    ap = argparse.ArgumentParser(description="panopticon synthesizer")
    ap.add_argument("--target", default="unknown")
    ap.add_argument("--root", metavar="PATH", default=None,
                    help="Filesystem root for LOC grading (defaults to an existing "
                         "--target, else the --tools-dir repository ancestor)")
    ap.add_argument("--groups", metavar="PATH")
    ap.add_argument("--security", choices=["standard", "redteam"], default=None,
                    help="Override security mode from groups.json")
    ap.add_argument("--fail-on", metavar="SEV", type=str.lower,
                    choices=["critical", "high", "medium", "low"])
    ap.add_argument("--severity", metavar="LEVEL", type=str.lower,
                    choices=["all", "medium", "high", "critical"], default="all",
                    help="Minimum severity to include in the report (all, medium, high, critical)")
    scope = ap.add_mutually_exclusive_group()
    scope.add_argument("--repo", action="store_true",
                       help="Explicitly declare a repository-wide review type")
    scope.add_argument("--changes", "-c", action="store_true",
                       help="Explicitly declare a changes/diff review type")
    ap.add_argument("--out", default=None)
    ap.add_argument("--run-id", default=None,
                    help="driver run-manifest run_id -> X0X generated_by.run_id")
    ap.add_argument("--run-dir", default=None,
                    help="directory holding THIS run's artifacts (tools-manifest, "
                         "scout-*, coverage-*, dispatch plans, verify-queue, "
                         "unenforced-ack). Defaults to dirname(--groups); flat "
                         "%s only for legacy non-run-folder invocations." % plan_contract.ARTIFACT_DIR)
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
    ap.add_argument("--prior-run", default=None, metavar="HOST:RUN_ID",
                    help="this run started over an earlier run of another host "
                         "in %s/ (#3271); disclosed as meta.prior_run" % plan_contract.ARTIFACT_DIR)
    ap.add_argument("--target-commit", default=None, metavar="SHA",
                    help="the scanned tree's HEAD off the driver's run manifest (#3560); "
                         "copied to meta.target_commit, absent when not given")
    ap.add_argument("--target-dirty", default=None, choices=("true", "false"),
                    help="whether the scanned tree had uncommitted changes, off the run "
                         "manifest (#3560); copied to meta.target_dirty, absent when not given")
    ap.add_argument("--model-strict", default=None, choices=("true", "false"),
                    help="whether the run's model fallbacks were off, off the run manifest "
                         "(#3582); copied to meta.model_strict, absent when not given")
    ap.add_argument("--tools-skipped", action="store_true",
                    help="no scanner ran this run (--no-tools), so no output in "
                         "--tools-dir is bound to it: none is ingested, every one "
                         "present is listed as an unbound tool output (#3197)")
    ap.add_argument("--tools-disabled-mid-run", action="store_true",
                    help="this run started with the tool scan enabled and had "
                         "it switched off with --no-tools while in flight "
                         "(#1637 P08); disclosed as meta.tools.disabled_mid_run")
    ap.add_argument("--plan-owed", action="store_true",
                    help="this run's driver WROTE a dispatch plan, per the run "
                         "manifest's own stamp (SEC-377944137, #1832); an absent "
                         "plan file is then deleted evidence, not an unmeasured "
                         "run. Disclosed as meta.integrity.dispatch_plan_missing. "
                         "Omit it when re-synthesizing BY HAND over a run folder "
                         "whose artifacts were deliberately cleared")
    ap.add_argument("--plan-sha256", metavar="HEX", default=None,
                    help="the canonical content hash the manifest stamped for "
                         "that plan (SEC-377944137); a plan file present with "
                         "different content is tamper, not an absence. "
                         "Disclosed as meta.integrity.dispatch_plan_mismatched")
    ap.add_argument("--snapshot-sha256", metavar="HEX", default=None,
                    help="sha256 of the exact out-file-hashes.json bytes this "
                         "run's driver wrote (#2115); a plan-owed run with a "
                         "present snapshot that differs or has no such stamp "
                         "sets meta.integrity.content_snapshot_mismatched")
    ap.add_argument("--git-drivers-suppressed", metavar="JSON", default=None,
                    help="JSON list of {repo, key} pairs: the target's own Git "
                         "driver commands this scan ran with emptied (#2013); "
                         "disclosed as meta.coverage.git_drivers_suppressed")
    ap.add_argument("--emit-verify-queue", action="store_true",
                    help="Pass 1: write %s/verify-queue.json and skip the "
                         "report when agentic findings need verification" % plan_contract.ARTIFACT_DIR)
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
    ap.add_argument("--diff-hunks-run-id", metavar="ID", default=None,
                    help="The run generation --diff-hunks must carry (#2107): a "
                         "foreign or absent run_id rejects the payload, so the "
                         "gate widens instead of scoping to another run's diff. "
                         "Omitted, it defaults to the run_id on the --groups "
                         "inventory this run read -- the other half of the pair")
    ap.add_argument("--diff-context", type=int, default=5, metavar="N",
                    help="Lines of tolerance for on-diff classification (default 5)")
    ap.add_argument("--gate-scope", choices=["on-diff", "all"], default="on-diff",
                    help="Scope the gate/grade to on-diff findings, or all (default on-diff)")
    ap.add_argument("files", nargs="*")
    return ap


def validate_artifacts(report_path, x0x_path=None, x0x_failure_path=None):
    """Validate the artifacts AS WRITTEN against their published schemas.

    #1639 P15 ruling 2 / #3535. `validate_report` now checks in-memory policy
    only; this is the sole published-schema pass. It checks what is on disk,
    which is the only document a consumer will ever read. Two details matter:

    * the report may be SPLIT. `report.json` then carries one chunk of
      `findings` and a `meta.parts` list, so validating the main file alone
      says nothing about the other chunks. The HYDRATED union is validated,
      through the same reader `--compare` hydrates with, so the two can never
      disagree about what "the report" means. A part that cannot be read makes
      the union unknowable, which fails CLOSED -- a run may not claim validity
      it could not establish.
    * `report-x0x.json` and its optional locus-free failure log are sibling
      artifacts with their own schemas. The first is ingested downstream by
      OCRDb's candidate pool; the second records findings that cannot enter its
      occurrence-bearing candidate set.

    Each error names its artifact, because "N schema errors" across two files
    is not actionable without knowing which.
    """
    errors = []
    hydrated = render_mod._read_json_report(report_path)
    name = os.path.basename(report_path)
    if hydrated is None:
        errors.append("%s: schema: the written report could not be re-read as "
                      "one document (see the error above) — validity unknown"
                      % name)
    else:
        errors.extend("%s: %s" % (name, e)
                      for e in validate_schema_mod.schema_errors(hydrated))
    for artifact_path, schema in (
            (x0x_path, validate_schema_mod.X0X_SCHEMA),
            (x0x_failure_path, validate_schema_mod.X0X_FAILURE_SCHEMA)):
        if artifact_path is None:
            continue
        artifact_name = os.path.basename(artifact_path)
        try:
            with open(artifact_path, encoding="utf-8") as fh:
                artifact_doc = json.load(fh)
        except (OSError, ValueError) as exc:
            errors.append("%s: schema: unreadable (%s)" % (artifact_name, exc))
        else:
            errors.extend("%s: %s" % (artifact_name, e) for e in
                          validate_schema_mod.schema_errors(artifact_doc, schema))
    return errors


def _say(text):
    """Print `text` to stdout. #2961: a path the run wrote can hold a byte that is
    not UTF-8 (a lone surrogate here), which a strict stdout cannot encode; spell
    it as stderr does (`backslashreplace`) rather than raise after the writes."""
    try:
        print(text)
    except UnicodeEncodeError:
        encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
        print(text.encode(encoding, "backslashreplace").decode(encoding))


def _artifact_path_refused(exc):
    """Report an artifact-path refusal without aliasing it to gate FAIL."""
    detail = redact.redact_diagnostic(str(exc), 400)
    print("synthesize: artifact path refused: %s" % detail, file=sys.stderr)
    return validate_schema_mod.ARTIFACT_INVALID


def _artifact_write_failed(exc):
    """#3472: the one answer to a writer's failure, exit 4 either way. A
    `UnicodeError` is a `ValueError` too, but it is the TEXT that could not be
    written, not the path: name it so. Everything else (`ArtifactPathError`, a
    raw confinement `ValueError`) is the path refusal, as before."""
    if isinstance(exc, UnicodeError):
        detail = redact.redact_diagnostic(str(exc), 400)
        print("synthesize: artifact not written: its text cannot be encoded: %s" % detail,
              file=sys.stderr)
        return validate_schema_mod.ARTIFACT_INVALID
    return _artifact_path_refused(exc)


def _first_contact(args, read_paths, write_paths):
    """#3273 P1: first contact's `.panopticon/` half (`assess_standalone`).
    True when it halted, with its one line printed."""
    try:
        first_contact.assess_standalone(os.getcwd(), read_paths, write_paths,
                                        root_hints=(args.root, os.environ.get("PWD")))
    except (first_contact.FirstContactHalt, executable.TargetPathEntry) as exc:
        print("synthesize: %s" % exc, file=sys.stderr)
        return True
    return False


def _compare(args):
    """`--compare A B`: render B's HTML with A as the baseline (#3398: out of main)."""
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
    try:
        html_report.write_html(report_b, html_out, compare_report=report_a)
    except (safe_write.ArtifactPathError, ValueError) as exc:
        return _artifact_write_failed(exc)
    _say("Compare HTML: %s" % html_out)
    return 0


def _resolve_analysis_root(args):
    """Pin the one filesystem root ingest and synthesis both use (N6)."""
    if args.root is not None:
        return
    target = args.target
    # The driver always passes a concrete --root. A direct invocation may use
    # --target only when it names a directory; a display-only basename defers
    # to the same `.panopticon` ancestor ingest derives from --tools-dir. Two
    # real but different roots are an error. Only a bare tools directory with
    # no target identity falls back to cwd, which is then passed into ingest too
    # so classification cannot split across two trees.
    target_root = (os.path.abspath(target)
                   if isinstance(target, str) and target != "unknown"
                   and os.path.isdir(target) else None)
    tools_root = (ingest_tools._target_root_for(args.tools_dir)
                  if args.tools_dir else None)
    if (target_root is not None and tools_root is not None
            and os.path.realpath(target_root) != os.path.realpath(tools_root)):
        raise ValueError("--target directory and --tools-dir name different "
                         "analysis roots")
    chosen = target_root or tools_root or os.getcwd()
    args.root = os.path.abspath(chosen)


def main(argv=None):
    """Main entry point: load findings, enrich citations, build and validate report."""
    args = build_parser().parse_args(argv)

    if args.compare:
        return _compare(args)

    try:
        _resolve_analysis_root(args)
    except ValueError as exc:
        print("synthesize: %s" % exc, file=sys.stderr)
        return 2

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
        default_groups = os.path.join(plan_contract.ARTIFACT_DIR, "groups.json")
        if os.path.isfile(default_groups):
            groups_path = default_groups
    # #3273 P1: run artifacts are trusted only from a `.panopticon/` first
    # contact verifies as this machine's -- the driver's child always is, and a
    # direct invocation in a tree that planted one halts here, not at a reader.
    # One this run writes into (the report, pass 1's verify queue) and finds
    # absent or empty is marked ours, so the next pass trusts it (R1). Pass 1
    # writes the report only when it queues nothing: its tree is assessed now
    # and marked then.
    report_writes = [args.out or os.path.join(plan_contract.ARTIFACT_DIR, "report.json"), args.html_out]
    writes = ([args.run_dir or (os.path.dirname(groups_path) if groups_path else "")
               or plan_contract.ARTIFACT_DIR] if args.emit_verify_queue else report_writes)
    reads = (groups_path, args.run_dir, args.tools_dir, args.verdicts_dir, args.diff_hunks)
    if _first_contact(args, reads + (tuple(report_writes) if args.emit_verify_queue else ()),
                      writes):
        return 2
    # #1639 P15 (F6): groups.json is read from the target's own `.panopticon/`,
    # and five of its fields are type-pinned by the time they reach the
    # artifact. `load_groups_json` normalizes them at the read, so its "never
    # abort a run" contract survives the validator for every caller.
    raw_groups: list = []               # #2962: the cell lists unspelled, for one reader
    groups_valid: list[bool] = []
    gj = plan_mod.load_groups_json(
        groups_path, raw_groups=raw_groups, valid_out=groups_valid)
    groups_meta = gj.get("groups", [])

    # #17/#16: run-scoped artifacts (tools-manifest, scout-*, coverage-*, dispatch
    # plans, verify-queue, unenforced-ack) live in the run directory next to
    # groups.json — NOT flat .panopticon under 5.1 per-run folders. Reading them
    # flat certified tool coverage against a PREVIOUS run's manifest (#17) and
    # zeroed the scout coverage (#16). Resolve every run artifact under run_dir.
    run_dir = args.run_dir or (os.path.dirname(groups_path) if groups_path else "") \
        or plan_contract.ARTIFACT_DIR
    if args.run_id and run_dir == plan_contract.ARTIFACT_DIR:
        # #17 fail-open guard: a 5.1 run (--run-id set) that fell back to flat
        # .panopticon has no run folder, so it would read a PRIOR run's stale
        # artifacts. Make the drift LOUD — never silent. (The schema_version
        # assertion at the manifest read still FATALs on a stale pre-5.1 manifest,
        # so certification cannot silently certify against one either.)
        print("WARNING (#17): --run-id set but no run directory resolved "
              "(--run-dir/--groups); falling back to flat %s, which under "
              "5.1 holds no run artifacts. Pass --groups <run-folder>/groups.json."
              % plan_contract.ARTIFACT_DIR,
              file=sys.stderr)

    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out = args.out or os.path.join(plan_contract.ARTIFACT_DIR, "report-%s.json" % ts.replace(":", ""))

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
    host_capabilities = plan_mod.load_host_capabilities(run_dir)

    # #1637 P08 ruling 5: resolved under `run_dir` like every other run
    # artifact, and fail-closed to two zeroes when it is absent -- a direct
    # `synthesize.py` invocation over hand-collected findings files never had
    # a driver to write it.
    try:
        run = report_mod.RunConfig.from_args(
            args, gj, ts, host_capabilities=host_capabilities,
            panel_tools_context=plan_mod.load_panel_tools_context(run_dir),
            tools_disabled_mid_run=getattr(args, "tools_disabled_mid_run", False),
            prior_run=getattr(args, "prior_run", None),
            config=config_schema.load_resolution(run_dir))
    except report_mod.ReviewScopeError as exc:
        print("synthesize: %s" % exc, file=sys.stderr)
        return validate_schema_mod.ARTIFACT_INVALID  # fatal even beside an old report
    plans = plan_mod.load_dispatch_plans_detailed(panopticon_dir=run_dir)
    try:
        manifest_state = tool_axis_mod.ToolAxis.manifest_state(args, run_dir)
    except tool_axis_mod.ToolManifestError as exc:
        print(str(exc), file=sys.stderr)
        return 3              # invalid input, distinct from gate FAIL (1)
    # #1701/#3269 G4: `gated_suppressed` is the source-scope drops the gate still
    # counts under --security redteam; empty otherwise. It rides to certification
    # on the ToolAxis and never joins `tool_findings`, so the report body is the
    # same in both modes.
    unbound_outputs: list[str] = []
    (tool_findings, dispositions, tools_ran, suppressed,
     gated_suppressed, tools_excluded) = plan_mod.ingest_tool_findings(
         args, allowed_outputs=manifest_state[2], unbound_out=unbound_outputs)
    tools = tool_axis_mod.ToolAxis.load(
        args, run_dir, plans[0], dispositions, tools_ran, suppressed,
        gated_suppressed, tools_excluded, manifest_state, unbound_outputs)
    prepared = findings_mod.FindingSet.prepare(args, tool_findings, run.security_mode)
    # #1634: redact the INPUT, not only the output -- and do it HERE, upstream
    # of the --emit-verify-queue branch, so both passes of a run see identical
    # text.
    #
    # Why the placement is load-bearing: evidence.finding_fingerprint keys an
    # agent finding on its TITLE, and build_verify_queue uses that fingerprint
    # as the queue_id -- the filename an advisor's verdict is stored under and
    # the key match_verdict binds on. Redacting after the early return would
    # queue the unredacted title in pass 1 and recompute from the redacted one
    # in pass 2: every queue_id changes, the verdict stops binding, the finding
    # silently drops to `unverified` and coverage_certified flips to False --
    # on precisely the input this fix exists for. (Finding ids are unaffected
    # either way: load_findings derives them before any redaction, in both
    # passes and in the driver's own queue build.) It also masks
    # verify-queue.json, which is fed verbatim into the advisor prompt.
    #
    # Redacting the input is what makes the DERIVED fields safe: build_report
    # copies f["title"] into summary.top_issues and groups[].key_findings, so a
    # credential a reviewer quoted-but-didn't-redact reached those copies (and
    # the HTML, which reads top_issues) before the post-build backstop ever ran
    # -- it rewrote the finding, never the copies. discarded_claims are
    # partitioned out of this same list inside build_report, so one pass covers
    # them too. The post-build call stays: redaction is idempotent, and it is
    # still the backstop for text produced AFTER this point (an advisor's
    # reasoning is merged into finding.evidence during build_report).
    prepared = (redact.redact_tree(prepared[0]),) + tuple(prepared[1:])
    if args.emit_verify_queue and verdicts_mod.emit_verify_queue(
            prepared[0], run_dir, args.max_verify):
        return 0
    if args.emit_verify_queue and _first_contact(args, (), report_writes):
        return 2
    queue = integrity_mod.load_verify_queue(run_dir)
    fs = findings_mod.FindingSet.load(args, tool_findings, run.security_mode,
                                      verdict_run_id=(queue[0] or {}).get("run_id"),
                                      prepared=prepared)
    plan = plan_mod.PlanInputs.load(run_dir, args.files, args.verdicts_dir, groups_meta,
                                    plans, queue, fs.verdicts,
                                    git_drivers_suppressed=getattr(
                                        args, "git_drivers_suppressed", None),
                                    plan_owed=getattr(args, "plan_owed", False),
                                    plan_sha256=getattr(args, "plan_sha256", None),
                                    snapshot_sha256=getattr(
                                        args, "snapshot_sha256", None),
                                    # #2271: discovery's own disclosures. It
                                    # recorded them here and printed them on a
                                    # stderr the driver buffers and discards on
                                    # a SUCCESSFUL run, so the report is the
                                    # only human surface they can reach.
                                    discovery=gj.get("discovery"),
                                    # #1757: and the exclusion this run did NOT
                                    # apply -- the coverage section is where the
                                    # owner ruling says it has to be disclosed.
                                    sec_carve_out=gj.get(
                                        "exclude_paths_sec_carve_out"),
                                    groups_valid=groups_valid == [True],
                                    # #2962: #2964's check reads the names
                                    # unspelled; every other reader keeps `gj`.
                                    raw_groups=raw_groups)
    # #1335: SPEND, not coverage -- a no-op scanner still cost a dispatch.
    cost = cost_mod.CostInputs.load(
        run_dir, args.verdicts_dir,
        tool_axis_mod.tools_produced_from_dispositions(dispositions))
    # #2107 review round 1: `gj` is the inventory this run actually read, and
    # its `run_id` is the generation the hunk map must share. Passed as the
    # DEFAULT expectation so the hand-run path -- `--groups` auto-discovered
    # above, `--diff-hunks` supplied by the operator, no driver in sight -- is
    # bound too; `--diff-hunks-run-id` overrides, and an unstamped inventory
    # expects nothing.
    delta = delta_mod.DeltaContext.from_args(args, gj.get("run_id"))

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
    # #run7 SEC-B2C / #1634: the whole-tree backstop, before any shareable
    # artifact. The inputs were already masked above; this catches text
    # produced since (advisor reasoning merged into finding.evidence) and
    # anything a future producer derives, at any depth in the report.
    render_mod.redact_report_secrets(report)
    policy_errors, warnings = report_mod.validate_report(report)
    # Policy remains advisory for the exit code, but its errors have always
    # been part of the published count. Seed them before the first write; the
    # artifact pass below adds any written-schema errors (#3535 review r1).
    report_mod.attach_schema_status(report, policy_errors)
    for w in warnings:
        print("WARN: %s" % w, file=sys.stderr)
    for e in policy_errors:
        print("REPORT policy: %s" % e, file=sys.stderr)

    try:
        paths = render_mod.write_report(report, out)
    except (safe_write.ArtifactPathError, ValueError) as exc:
        return _artifact_write_failed(exc)
    # §5.1: emit the X0X catalog-gap report — the <DOM>-X0X / ZZZ-X0X findings as
    # candidate records for OCRDb's new-code adjudication pool (ingested
    # downstream), a sibling of the JSON report. Empty candidates are an honest
    # "no catalog gaps this run". A fallback finding without location.file has
    # no schema-valid occurrence, so leave it out of the candidate set and put
    # a deterministic record in a separate failure log. The finding itself
    # remains in report.json and the HTML.
    x0x_stem = out[:-len(".json")] if out.endswith(".json") else out
    x0x_path = x0x_stem + "-x0x.json"
    failure_path = x0x_report.failure_log_path(x0x_path)
    x0x, failure_log = x0x_report.build_emission(
        report.get("findings") or [], report.get("meta") or {}, args.run_id)
    targets = [
        (x0x_path, x0x_path + ".tmp",
         json.dumps(x0x, indent=2, sort_keys=True)),
    ]
    try:
        if failure_log is None:
            safe_write.remove_artifact(failure_path)
        else:
            targets.append(
                (failure_path, failure_path + ".tmp",
                 json.dumps(failure_log, indent=2, sort_keys=True)))
        safe_write.publish_texts(targets)
    except (safe_write.ArtifactPathError, ValueError) as exc:
        return _artifact_write_failed(exc)
    _say("X0X artifact: %s (%d candidates)"
         % (x0x_path, len(x0x["candidates"])))
    if failure_log is not None:
        discarded = len(failure_log["discarded_findings"])
        print("synthesize: warning: discarded %d locus-free catalog-gap "
              "finding(s) from X0X; failure log: %s"
              % (discarded, failure_path), file=sys.stderr)
    failure_validation_path = failure_path if failure_log is not None else None
    artifact_errors = validate_artifacts(
        paths[0], x0x_path, failure_validation_path)
    report_mod.attach_schema_status(report, policy_errors + artifact_errors)
    if artifact_errors:
        # The field itself is schema-valid, so publishing the combined count
        # cannot create a new schema defect; the original error remains the
        # terminal result even if a raced/unreadable file becomes writable.
        try:
            paths = render_mod.write_report(report, out)
        except (safe_write.ArtifactPathError, ValueError) as exc:
            return _artifact_write_failed(exc)
    html_out = args.html_out
    if html_out is None and args.out:
        html_out = render_mod._derive_html_path(paths[0])
    if html_out:
        try:
            html_report.write_html(report, html_out)
        except (safe_write.ArtifactPathError, ValueError) as exc:
            return _artifact_write_failed(exc)
        _say("HTML artifact: %s" % html_out)
    print(render_mod.render_summary(report))
    _say("\nJSON artifact: %s" % ", ".join(paths))
    # #1639 P15: terminal completion, artifact validity and coverage
    # certification are three different facts, so they get three different
    # channels. The gate's verdicts (1/2) are VALID reports about a coverage
    # question and are answered below; this is the artifact itself failing to
    # be what it claims to be, and it is reported AFTER the summary so the
    # grade/gate text a run always prints is unchanged by it.
    if artifact_errors:
        for e in artifact_errors:
            print("SCHEMA artifact: %s" % e, file=sys.stderr)
        checked_paths = [paths[0], x0x_path]
        if failure_validation_path is not None:
            checked_paths.append(failure_validation_path)
        print("synthesize: artifact invalid: %d schema errors (see %s)"
              % (len(artifact_errors), ", ".join(checked_paths)),
              file=sys.stderr)
        return validate_schema_mod.ARTIFACT_INVALID
    gate = report["summary"]["gate"]
    return 1 if gate == "FAIL" else 2 if gate == "INCONCLUSIVE" else 0


if __name__ == "__main__":
    sys.exit(main())
