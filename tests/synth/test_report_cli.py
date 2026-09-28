"""Report CLI, rendering, input, and run-configuration contracts."""

import contextlib
import io
import os
import json
import tempfile
import unittest
from unittest import mock
import scripts.synthesize as syn
import scripts.synth.findings as findings_mod
import scripts.synth.delta as delta_mod
import scripts.synth.grading as grading_mod
import scripts.synth.plan as plan_mod
import scripts.synth.tool_axis as tool_axis_mod
import scripts.synth.cost as cost_mod
import scripts.synth.report as report_mod
import scripts.synth.verdicts as verdicts_mod
import scripts.synth.render as render_mod
import scripts.hosts as hosts_mod
from tests.synth.helpers import SPLIT_FILE_MAX_BYTES, DEFAULT_TIMESTAMP, _make_finding, _cli_args


class TestCliAndSummary(unittest.TestCase):
    def test_render_summary_contains_grade_and_location(self):
        # gate_unverified=True: this test is about render_summary's formatting
        # (location string, FAIL label), not the default gating policy.
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(
                target="src",
                fail_on="high",
                timestamp=DEFAULT_TIMESTAMP,
                gate_unverified=True,
            ),
            findings=findings_mod.FindingSet(
                findings=[
                    {
                        "id": "CD-001",
                        "title": "SQL injection",
                        "severity": "HIGH",
                        "confidence": "CERTAIN",
                        "panel": "security",
                        "category": "injection",
                        "location": {"file": "a.rb", "line_start": 42},
                        "cvss": {"score": 8.1, "vector": "CVSS:3.1/AV:N"},
                        "exploit_scenario": "...",
                    }
                ],
            ),
            plan=plan_mod.PlanInputs(groups_meta=[{"name": "g1", "files": ["a.rb"]}]),
        ))
        text = render_mod.render_summary(report)
        self.assertIn("a.rb:42", text)
        self.assertIn("FAIL", text)

    def test_render_summary_includes_all_panel_grades(self):
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(
                findings=[
                    {
                        "id": "CD-001",
                        "title": "t",
                        "severity": "LOW",
                        "confidence": "POSSIBLE",
                        "panel": "architecture",
                        "category": "structure",
                        "location": {"file": "a.py", "line_start": 1},
                    }
                ],
            ),
            plan=plan_mod.PlanInputs(groups_meta=[{"name": "g1", "files": ["a.py"]}]),
        ))
        text = render_mod.render_summary(report)
        for panel in ["code", "test", "security", "architecture", "database", "redteam"]:
            self.assertIn("%s " % panel, text)

    def test_main_returns_1_on_gate_fail(self):
        with tempfile.TemporaryDirectory() as d:
            fpath = os.path.join(d, "findings-g1-security.json")
            with open(fpath, "w") as fh:
                # tool-sourced: tool_confirmed is gate-eligible by default, so
                # this exercises the CLI FAIL path without needing a verdict.
                # SEC-102: a findings-*.json file is agent-authored, so a
                # self-claimed `source` is stripped at load; --gate-unverified
                # is what exercises the CLI FAIL path now.
                json.dump(
                    {
                        "findings": [
                            {
                                "id": "SE-001",
                                "title": "x",
                                "severity": "CRITICAL",
                                "confidence": "CERTAIN",
                                "panel": "security",
                                "category": "injection",
                                "location": {"file": "a.rb", "line_start": 1},
                                "cvss": {"score": 9.0, "vector": "CVSS:3.1/x"},
                                "exploit_scenario": "y",
                            }
                        ]
                    },
                    fh,
                )
            out = os.path.join(d, "report.json")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = syn.main(
                    [
                        "--target",
                        "src",
                        "--fail-on",
                        "high",
                        "--gate-unverified",
                        "--out",
                        out,
                        fpath,
                    ]
                )
            self.assertEqual(rc, 1)
            self.assertTrue(os.path.isfile(out))

    def test_write_report_split_preserves_findings_without_mutating_input(self):
        findings = [
            {
                "id": "CD-%03d" % i,
                "title": "t" * 40,
                "severity": "LOW",
                "confidence": "POSSIBLE",
                "panel": "code",
                "category": "structure",
                "location": {"file": "a.py", "line_start": i},
            }
            for i in range(1, 400)
        ]
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=findings),
        ))
        n_before = len(report["findings"])
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "report.json")
            paths = render_mod.write_report(report, out, max_bytes=SPLIT_FILE_MAX_BYTES)
            self.assertGreaterEqual(len(paths), 2)
            with open(paths[0]) as _fh:
                main_doc = json.load(_fh)
            self.assertIn("parts", main_doc["meta"])
            part_findings_count = 0
            for p in paths[1:]:
                with open(p) as fh:
                    part_findings_count += len(json.load(fh)["findings"])
            self.assertEqual(len(main_doc["findings"]) + part_findings_count, n_before)
            self.assertEqual(len(report["findings"]), n_before)  # caller not mutated

    def test_write_report_atomic_cleans_up_on_error(self):
        findings = [
            {
                "id": "CD-%03d" % i,
                "title": "t" * 40,
                "severity": "LOW",
                "confidence": "POSSIBLE",
                "panel": "code",
                "category": "structure",
                "location": {"file": "a.py", "line_start": i},
            }
            for i in range(1, 400)
        ]
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=findings),
        ))
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "report.json")
            # If os.replace fails partway, no incomplete files should be left behind
            with mock.patch("os.replace", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    render_mod.write_report(report, out, max_bytes=SPLIT_FILE_MAX_BYTES)
            self.assertFalse(os.path.exists(out))
            # No stray .tmp files left in dir
            self.assertEqual(os.listdir(d), [])

    def test_main_returns_0_when_gate_not_fail(self):
        with tempfile.TemporaryDirectory() as d:
            fpath = os.path.join(d, "findings-g1-code.json")
            with open(fpath, "w") as fh:
                json.dump(
                    {
                        "findings": [
                            {
                                "id": "CD-001",
                                "title": "x",
                                "severity": "MEDIUM",
                                "confidence": "POSSIBLE",
                                "panel": "code",
                                "category": "structure",
                                "location": {"file": "a.py", "line_start": 1},
                            }
                        ]
                    },
                    fh,
                )
            out = os.path.join(d, "report.json")

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = syn.main(["--target", "src", "--out", out, fpath])
            self.assertEqual(rc, 0)


class ReportInputsTest(unittest.TestCase):
    """WS-0 S2: the grouped build_report input structs. Their defaults must
    mean exactly what the omitted keyword meant on the 33-argument signature,
    and the four-stage orchestrator must not depend on which of them a caller
    spelled out."""

    def _run(self):
        return report_mod.RunConfig(target="t", fail_on="high", timestamp=DEFAULT_TIMESTAMP)

    def test_omitted_structs_equal_their_explicit_defaults(self):
        f = _make_finding(severity="HIGH")
        terse = report_mod.build_report(report_mod.ReportInputs(
            run=self._run(), findings=findings_mod.FindingSet(findings=[dict(f)])))
        explicit = report_mod.build_report(report_mod.ReportInputs(
            run=self._run(),
            findings=findings_mod.FindingSet(findings=[dict(f)]),
            delta=delta_mod.DeltaContext(),
            plan=plan_mod.PlanInputs(),
            tools=tool_axis_mod.ToolAxis(),
            cost=cost_mod.CostInputs(),
        ))
        self.assertEqual(terse, explicit)
        # the "not measured" values the defaults stand for
        cov = terse["meta"]["coverage"]
        self.assertEqual(cov["tool_policy_mode"], "unknown")
        self.assertEqual(cov["scout_profiles_seen"], 0)
        self.assertIsNone(cov["delta"])
        self.assertIsNone(cov["resume"])
        self.assertIsNone(terse["meta"]["cost"]["tokens"])
        self.assertEqual(terse["meta"]["integrity"]["plans_seen"], 0)
        self.assertEqual(terse["groups"], [])

    def test_structs_are_frozen(self):
        import dataclasses
        run = self._run()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            run.target = "u"
        fs = findings_mod.FindingSet(findings=[])
        with self.assertRaises(dataclasses.FrozenInstanceError):
            fs.verdicts = {}

    def test_delta_context_active_needs_a_base(self):
        self.assertFalse(delta_mod.DeltaContext().active)
        self.assertFalse(delta_mod.DeltaContext(diff_hunks={"hunks": {}}).active)
        self.assertTrue(delta_mod.DeltaContext(diff_hunks={"base": "main", "hunks": {}}).active)

    def test_legacy_positional_signature_is_gone(self):
        with self.assertRaises(TypeError):
            report_mod.build_report([], [], "t", "high", DEFAULT_TIMESTAMP)

    def test_stages_compose_to_the_report(self):
        # build_report is resolve -> reconcile -> grade -> cost -> assemble;
        # running the stages by hand must give the same envelope.
        f = _make_finding(severity="HIGH")
        inp = report_mod.ReportInputs(
            run=self._run(), findings=findings_mod.FindingSet(findings=[dict(f)]),
            plan=plan_mod.PlanInputs(groups_meta=[{"name": "g1", "files": ["a.py"]}]))
        whole = report_mod.build_report(inp)
        inp = report_mod.ReportInputs(
            run=self._run(), findings=findings_mod.FindingSet(findings=[dict(f)]),
            plan=plan_mod.PlanInputs(groups_meta=[{"name": "g1", "files": ["a.py"]}]))
        resolved = verdicts_mod.resolve_findings(inp.findings, inp.delta, inp.run,
                                                 gated_suppressed=inp.tools.gated_suppressed)
        reconciled = tool_axis_mod.reconcile(inp.plan, inp.tools, resolved,
                                             run=inp.run)
        graded = grading_mod.grade_report(inp.run, resolved, reconciled, delta=inp.delta)
        cost = cost_mod.cost_section(inp.cost, 0, resolved.verdict_stats["queued"])
        by_hand = report_mod.assemble(inp.run, resolved, reconciled, graded, cost)
        self.assertEqual(whole, by_hand)
        self.assertEqual(list(whole), ["schema_version", "meta", "summary", "groups",
                                       "findings", "discarded_claims", "cross_panel"])

    def test_stages_compose_with_a_gate_counted_suppressed_finding(self):
        # Re-review of item 25c R1: `build_report` hands the gated-suppressed
        # set to `resolve_findings`, and the by-hand recipe above stayed green
        # only because its ToolAxis is empty. One gated finding must give the
        # same envelope both ways -- FAIL from `build_report`, FAIL by hand.
        #
        # CRITICAL, not HIGH, since the #1578 owner ruling of 2026-09-22
        # (policy C): a suppressed HIGH with no secret evidence no longer
        # gates, so a HIGH here would empty the gated set and leave this test
        # comparing two identical PASSes. The `assertEqual(..., "FAIL")` below
        # is what keeps it from going vacuous again.
        gated = dict(_make_finding(severity="CRITICAL"))
        gated["location"] = dict(gated.get("location") or {}, file="app/vendor/x.js")
        def inputs():
            return report_mod.ReportInputs(
                run=self._run(), findings=findings_mod.FindingSet(findings=[]),
                plan=plan_mod.PlanInputs(groups_meta=[{"name": "g1", "files": ["a.py"]}]),
                tools=tool_axis_mod.ToolAxis(gated_suppressed=[gated]))
        whole = report_mod.build_report(inputs())
        inp = inputs()
        resolved = verdicts_mod.resolve_findings(inp.findings, inp.delta, inp.run,
                                                 gated_suppressed=inp.tools.gated_suppressed)
        reconciled = tool_axis_mod.reconcile(inp.plan, inp.tools, resolved,
                                             run=inp.run)
        graded = grading_mod.grade_report(inp.run, resolved, reconciled, delta=inp.delta)
        cost = cost_mod.cost_section(inp.cost, 0, resolved.verdict_stats["queued"])
        by_hand = report_mod.assemble(inp.run, resolved, reconciled, graded, cost)
        self.assertEqual(whole["summary"]["gate"], "FAIL")
        self.assertEqual(whole["summary"]["gate"], by_hand["summary"]["gate"])
        self.assertEqual(whole, by_hand)


class RunConfigLoaderTest(unittest.TestCase):
    """WS-0 S3: RunConfig.from_args resolves the CLI against groups.json."""

    def test_explicit_changes_beats_a_discovered_repo_mode(self):
        run = report_mod.RunConfig.from_args(
            _cli_args(changes=True), {"mode": "repo"}, DEFAULT_TIMESTAMP)
        self.assertEqual(run.review_type, "changes")

    def test_discovered_mode_maps_to_review_type(self):
        run = report_mod.RunConfig.from_args(_cli_args(), {"mode": "files"}, DEFAULT_TIMESTAMP)
        self.assertEqual(run.review_type, "changes")
        run = report_mod.RunConfig.from_args(_cli_args(), {"mode": "bogus"}, DEFAULT_TIMESTAMP)
        self.assertEqual(run.review_type, "repo")
        run = report_mod.RunConfig.from_args(_cli_args(), {}, DEFAULT_TIMESTAMP)
        self.assertEqual(run.review_type, "repo")

    def test_explicit_security_beats_the_file(self):
        run = report_mod.RunConfig.from_args(
            _cli_args(security="redteam"), {"security_mode": "standard"}, DEFAULT_TIMESTAMP)
        self.assertEqual(run.security_mode, "redteam")

    def test_security_defaults_to_standard_even_when_the_file_says_null(self):
        run = report_mod.RunConfig.from_args(
            _cli_args(), {"security_mode": None}, DEFAULT_TIMESTAMP)
        self.assertEqual(run.security_mode, "standard")
        run = report_mod.RunConfig.from_args(_cli_args(), {}, DEFAULT_TIMESTAMP)
        self.assertEqual(run.security_mode, "standard")

    def test_flags_are_carried_verbatim(self):
        run = report_mod.RunConfig.from_args(
            _cli_args(target="t", fail_on="high", gate_unverified=True, max_verify=7,
                      gate_scope="all"), {}, DEFAULT_TIMESTAMP)
        self.assertEqual((run.target, run.fail_on, run.timestamp, run.gate_unverified,
                          run.max_verify, run.gate_scope),
                         ("t", "high", DEFAULT_TIMESTAMP, True, 7, "all"))

    def test_host_capabilities_defaults_to_empty_dict_when_omitted(self):
        # A caller that predates 5.1 surface 2 (or a code path that just
        # never read the artifact) must not have to know this parameter
        # exists -- omitting it reads as "nobody looked", same as {}.
        run = report_mod.RunConfig.from_args(_cli_args(), {}, DEFAULT_TIMESTAMP)
        self.assertEqual(run.host_capabilities, {})

    def test_host_capabilities_threads_through_verbatim(self):
        env = {"schema_version": 1, "host": "claude", "probed_at": "T",
              "capabilities": {hosts_mod.ARTIFACT_WRITE_GUARD:
                               {"state": hosts_mod.PROVEN, "by": "b", "detail": "d"}}}
        run = report_mod.RunConfig.from_args(_cli_args(), {}, DEFAULT_TIMESTAMP,
                                             host_capabilities=env)
        self.assertEqual(run.host_capabilities, env)
