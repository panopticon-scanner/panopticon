"""Delta classification, coverage, and gate contracts."""

import unittest
import scripts.synth.findings as findings_mod
import scripts.synth.delta as delta_mod
import scripts.synth.plan as plan_mod
import scripts.synth.report as report_mod


class TestDeltaClassify(unittest.TestCase):
    def test_build_report_stamps_delta_when_hunks_present(self):
        findings = [
            {
                "id": "A-1",
                "title": "on",
                "severity": "HIGH",
                "confidence": "POSSIBLE",
                "panel": "code",
                "category": "x",
                "location": {"file": "a.py", "line_start": 11},
            },
            {
                "id": "A-2",
                "title": "off",
                "severity": "HIGH",
                "confidence": "POSSIBLE",
                "panel": "code",
                "category": "x",
                "location": {"file": "a.py", "line_start": 90},
            },
        ]
        hunks = {
            "base": "main",
            "base_source": "explicit",
            "diff_context": 5,
            "files_changed": 1,
            "hunks": {"a.py": [(10, 12)]},
        }
        rep = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp="2026-01-01T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=findings),
            delta=delta_mod.DeltaContext(diff_hunks=hunks, diff_context=5),
            plan=plan_mod.PlanInputs(groups_meta=[{"name": "g1", "files": ["a.py"]}]),
        ))
        by = {f["id"]: f["delta"]["on_diff"] for f in rep["findings"]}
        self.assertTrue(by["A-1"])
        self.assertFalse(by["A-2"])

    def test_build_report_no_delta_key_when_diff_hunks_omitted(self):
        """Backward compatibility: no diff_hunks kwarg -> no delta stamping at all
        (not even a False/None placeholder) — existing non-delta callers unaffected."""
        findings = [
            {
                "id": "A-1",
                "title": "x",
                "severity": "HIGH",
                "confidence": "POSSIBLE",
                "panel": "code",
                "category": "x",
                "location": {"file": "a.py", "line_start": 11},
            },
        ]
        rep = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp="2026-01-01T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=findings),
            plan=plan_mod.PlanInputs(groups_meta=[{"name": "g1", "files": ["a.py"]}]),
        ))
        self.assertNotIn("delta", rep["findings"][0])

    def test_build_report_no_delta_when_base_unresolved(self):
        """diff_hunks present but base is None (unresolved) -> delta_mode is False,
        so findings are left unstamped. (Orchestrator Task 5 now fails loudly
        before this artifact shape can occur in practice.)"""
        findings = [
            {
                "id": "A-1",
                "title": "x",
                "severity": "HIGH",
                "confidence": "POSSIBLE",
                "panel": "code",
                "category": "x",
                "location": {"file": "a.py", "line_start": 11},
            },
        ]
        hunks = {
            "base": None,
            "base_source": "unresolved",
            "diff_context": 5,
            "files_changed": 0,
            "hunks": {},
        }
        rep = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp="2026-01-01T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=findings),
            delta=delta_mod.DeltaContext(diff_hunks=hunks, diff_context=5),
            plan=plan_mod.PlanInputs(groups_meta=[{"name": "g1", "files": ["a.py"]}]),
        ))
        self.assertNotIn("delta", rep["findings"][0])


class TestDeltaGate(unittest.TestCase):
    """#449 Task 8 (rework): on-diff gate/grade scoping, summary.delta,
    coverage.delta with three commit anchors. An unresolvable base is now a
    loud orchestrator failure (Task 5) that never reaches synthesize, so
    delta_mode alone drives these blocks -- no delta_unresolved path."""

    def _findings(self):
        return [
            {
                "id": "A-1",
                "title": "on-high",
                "severity": "HIGH",
                "confidence": "POSSIBLE",
                "panel": "code",
                "category": "x",
                "location": {"file": "a.py", "line_start": 11},
            },
            {
                "id": "A-2",
                "title": "pre-high",
                "severity": "HIGH",
                "confidence": "POSSIBLE",
                "panel": "code",
                "category": "x",
                "location": {"file": "a.py", "line_start": 90},
            },
        ]

    def test_gate_scopes_to_on_diff(self):
        hunks = {
            "base": "main",
            "base_source": "explicit",
            "diff_context": 5,
            "files_changed": 1,
            "hunks": {"a.py": [(10, 12)]},
        }
        rep = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(
                target="t",
                fail_on="high",
                timestamp="2026-01-01T00:00:00Z",
                gate_unverified=True,
                gate_scope="on-diff",
            ),
            findings=findings_mod.FindingSet(findings=self._findings()),
            delta=delta_mod.DeltaContext(diff_hunks=hunks, diff_context=5),
            plan=plan_mod.PlanInputs(groups_meta=[{"name": "g1", "files": ["a.py"]}]),
        ))
        # only the on-diff HIGH gates
        self.assertEqual(rep["summary"]["delta"]["on_diff"].get("high"), 1)
        self.assertEqual(rep["summary"]["delta"]["pre_existing"].get("high"), 1)
        self.assertEqual(rep["meta"]["coverage"]["delta"]["base"], "main")

    def test_gate_scope_all_gates_everything(self):
        hunks = {
            "base": "main",
            "base_source": "explicit",
            "diff_context": 5,
            "files_changed": 1,
            "hunks": {"a.py": [(10, 12)]},
        }
        rep = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(
                target="t",
                fail_on="high",
                timestamp="2026-01-01T00:00:00Z",
                gate_unverified=True,
                gate_scope="all",
            ),
            findings=findings_mod.FindingSet(findings=self._findings()),
            delta=delta_mod.DeltaContext(diff_hunks=hunks, diff_context=5),
            plan=plan_mod.PlanInputs(groups_meta=[{"name": "g1", "files": ["a.py"]}]),
        ))
        self.assertEqual(rep["summary"]["gate"], "FAIL")  # both HIGHs count

    def test_coverage_delta_carries_three_anchors(self):
        hunks = {
            "base": "main",
            "base_source": "fallback",
            "diff_context": 5,
            "base_commit": "b0",
            "delta_start": "d0",
            "delta_end": "d1",
            "includes_uncommitted": False,
            "files_changed": 1,
            "hunks": {"a.py": [(10, 12)]},
        }
        rep = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(
                target="t",
                fail_on="high",
                timestamp="2026-01-01T00:00:00Z",
                gate_unverified=True,
            ),
            findings=findings_mod.FindingSet(findings=self._findings()),
            delta=delta_mod.DeltaContext(diff_hunks=hunks, diff_context=5),
            plan=plan_mod.PlanInputs(groups_meta=[{"name": "g1", "files": ["a.py"]}]),
        ))
        d = rep["meta"]["coverage"]["delta"]
        self.assertEqual((d["base_commit"], d["delta_start"], d["delta_end"]), ("b0", "d0", "d1"))
        self.assertIs(d["includes_uncommitted"], False)

    def test_base_less_artifact_is_non_delta_not_inconclusive(self):
        # No delta_unresolved path anymore: a base-less artifact (which the
        # orchestrator no longer produces) is treated as a plain review.
        hunks = {
            "base": None,
            "base_source": "unresolved",
            "diff_context": 5,
            "files_changed": 0,
            "hunks": {},
        }
        rep = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(
                target="t",
                fail_on="high",
                timestamp="2026-01-01T00:00:00Z",
                gate_unverified=True,
            ),
            findings=findings_mod.FindingSet(findings=self._findings()),
            delta=delta_mod.DeltaContext(diff_hunks=hunks, diff_context=5),
            plan=plan_mod.PlanInputs(groups_meta=[{"name": "g1", "files": ["a.py"]}]),
        ))
        self.assertNotEqual(rep["summary"]["gate"], "INCONCLUSIVE")
        self.assertIsNone(rep["summary"]["delta"])
        self.assertIsNone(rep["meta"]["coverage"]["delta"])
