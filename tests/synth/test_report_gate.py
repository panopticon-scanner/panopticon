"""Unloadable verdict gate contracts."""

import contextlib
import io
import unittest
import scripts.synth.findings as findings_mod
import scripts.synth.grading as grading_mod
import scripts.synth.report as report_mod


class TestUnloadableVerdictsGate(unittest.TestCase):
    """#979: an un-loadable verdict is missing verify coverage — a PASS with
    verdicts lost must read INCONCLUSIVE, not certified-clean."""

    def _crit(self):
        return [{"severity": "CRITICAL", "evidence": {"status": "advisor_confirmed"}}]

    def test_unloadable_forces_inconclusive_on_pass(self):
        r = grading_mod.certify("A", [], "high", set(), [], verdicts_unloadable=1)
        self.assertEqual(r["gate"], "INCONCLUSIVE")
        self.assertFalse(r["coverage_certified"])

    def test_zero_unloadable_leaves_pass(self):
        r = grading_mod.certify("A", [], "high", set(), [], verdicts_unloadable=0)
        self.assertEqual(r["gate"], "PASS")
        self.assertTrue(r["coverage_certified"])

    def test_unanswered_supplied_verdict_forces_inconclusive(self):
        r = grading_mod.certify("A", [], "high", set(), [], verdicts_unanswered=1)
        self.assertEqual(r["gate"], "INCONCLUSIVE")
        self.assertFalse(r["coverage_certified"])

    def test_unloadable_never_masks_fail(self):
        r = grading_mod.certify("F", self._crit(), "high", set(), [], verdicts_unloadable=2)
        self.assertEqual(r["gate"], "FAIL")

    def test_build_report_wires_unloadable_into_gate(self):
        f = {
            "id": "A-1",
            "title": "claim",
            "severity": "HIGH",
            "confidence": "POSSIBLE",
            "panel": "code",
            "category": "logic",
            "description": "d",
            "location": {"file": "a.py", "line_start": 1},
        }
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            clean = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(
                    target="t",
                    fail_on="high",
                    timestamp="2026-08-05T00:00:00Z",
                ),
                findings=findings_mod.FindingSet(
                    findings=[dict(f)],
                    verdicts={},
                    verdicts_supplied=True,
                ),
            ))
            lossy = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(
                    target="t",
                    fail_on="high",
                    timestamp="2026-08-05T00:00:00Z",
                ),
                findings=findings_mod.FindingSet(
                    findings=[dict(f)],
                    verdicts={},
                    verdicts_supplied=True,
                    verdict_unloadable=[{"file": "x.json", "reason": "unparseable"}],
                ),
            ))
        self.assertEqual(clean["summary"]["gate"], "INCONCLUSIVE")
        self.assertEqual(lossy["summary"]["gate"], "INCONCLUSIVE")
