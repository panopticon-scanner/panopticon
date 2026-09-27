"""Health letter grade boundaries and report contracts."""

import unittest
import scripts.synth.findings as findings_mod
import scripts.synth.grading as grading_mod
import scripts.synth.plan as plan_mod
import scripts.synth.report as report_mod
import scripts.evidence as evidence_mod
from tests.synth.helpers import _target_with_files, _agentic


class TestHealthLetterGrade(unittest.TestCase):
    """The letter grade, banded over the 0-100 health index.

    Replaces the max-severity rollup, which saturated: one HIGH anywhere was a D
    regardless of codebase size, so ten of the eleven measured runs graded D and
    the eleventh graded F.
    """

    def test_every_band_boundary(self):
        for score, letter in ((100, "S"), (99.99, "A"), (90, "A"), (89.99, "B"),
                              (80, "B"), (79.99, "C"), (70, "C"), (69.99, "D"),
                              (60, "D"), (59.99, "F"), (26, "F"), (25.99, "X"),
                              (0, "X")):
            with self.subTest(score=score):
                self.assertEqual(grading_mod.health_grade(score), letter)

    def test_s_is_reachable_only_at_exactly_100(self):
        # S must mean "no gate-eligible weighted defect at all", not "rounded up
        # from 99.995" -- otherwise it is just a second A.
        self.assertEqual(grading_mod.health_grade(100), "S")
        self.assertEqual(grading_mod.health_grade(99.99), "A")

    def test_unmeasurable_health_has_no_grade(self):
        # None, not X. A run whose paths do not resolve read no code; grading it
        # the floor letter would report a catastrophe it never measured.
        self.assertIsNone(grading_mod.health_grade(None))

    def test_grades_are_monotonic_in_health(self):
        order = ["S", "A", "B", "C", "D", "F", "X"]
        seen = [grading_mod.health_grade(v) for v in range(100, -1, -1)]
        ranks = [order.index(g) for g in seen]
        self.assertEqual(ranks, sorted(ranks), "a lower health scored a better letter")

    def test_the_six_calibration_targets_grade_c_d_f(self):
        # Real measured (total_loc, weighted_defect). Recorded because the bands
        # are a prior, not a fit: no measured codebase has ever reached B, so
        # this is the evidence a future recut would be argued against.
        expected = {"fzf": "F", "gotify": "F", "ripgrep": "F",
                    "express": "D", "btcpayserver": "D", "solidus": "C"}
        measured = {"fzf": (51789, 93341), "gotify": (31277, 52305),
                    "ripgrep": (68932, 72954), "express": (21911, 14512),
                    "btcpayserver": (321482, 183694), "solidus": (251596, 105547)}
        got = {n: grading_mod.health_grade(grading_mod.health_score(*v)) for n, v in measured.items()}
        self.assertEqual(got, expected)

    def test_grade_no_longer_saturates_on_one_high(self):
        # THE regression the change exists to prevent. Two codebases, same single
        # confirmed HIGH, three orders of magnitude apart in size. The old
        # max-severity rollup graded both D; they must now differ.
        def graded(lines):
            groups = [{"name": "g1", "files": ["a.py"]}]
            finding = _agentic(sev="HIGH",
                               location={"file": "a.py", "line_start": 1, "line_end": 4})
            verdicts = {evidence_mod.finding_fingerprint(finding): {
                "finding_id": "AG-001", "verdict": "CONFIRMED", "reasoning": "v"}}
            with _target_with_files(groups, lines=lines) as tgt:
                r = report_mod.build_report(report_mod.ReportInputs(
                    run=report_mod.RunConfig(
                        target=tgt,
                        fail_on="high",
                        timestamp="2026-01-01T00:00:00Z",
                    ),
                    findings=findings_mod.FindingSet(findings=[finding], verdicts=verdicts),
                    plan=plan_mod.PlanInputs(groups_meta=groups),
                ))
            return r["summary"]["overall_grade"]

        small, large = graded(50), graded(50000)
        self.assertNotEqual(small, large)
        # 25 (HIGH) x 4 lines = 100 weighted defect either way.
        self.assertEqual(large, "A")   # ... against 50,000 clean lines -> 99.8
        self.assertEqual(small, "F")   # ... against 50 -> 33.33
        # Not S: S needs ZERO gate-eligible weighted defect, so a confirmed
        # finding of any severity can never reach it however large the codebase.

    def test_a_clean_tree_grades_s_end_to_end(self):
        groups = [{"name": "g1", "files": ["a.py"]}]
        with _target_with_files(groups) as tgt:
            r = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(
                    target=tgt,
                    fail_on="high",
                    timestamp="2026-01-01T00:00:00Z",
                ),
                findings=findings_mod.FindingSet(findings=[]),
                plan=plan_mod.PlanInputs(groups_meta=groups),
            ))
        self.assertEqual(r["summary"]["overall_grade"], "S")
        self.assertEqual(r["summary"]["health"]["score"], 100.0)

    def test_grade_and_health_can_never_disagree(self):
        # They are computed from one shared dict; this pins that they stay so.
        groups = [{"name": "g1", "files": ["a.py"]}]
        finding = _agentic(sev="MEDIUM",
                           location={"file": "a.py", "line_start": 1, "line_end": 20})
        verdicts = {evidence_mod.finding_fingerprint(finding): {
            "finding_id": "AG-001", "verdict": "CONFIRMED", "reasoning": "v"}}
        with _target_with_files(groups, lines=200) as tgt:
            r = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(
                    target=tgt,
                    fail_on="high",
                    timestamp="2026-01-01T00:00:00Z",
                ),
                findings=findings_mod.FindingSet(findings=[finding], verdicts=verdicts),
                plan=plan_mod.PlanInputs(groups_meta=groups),
            ))
        s = r["summary"]
        self.assertEqual(s["overall_grade"], grading_mod.health_grade(s["health"]["score"]))
