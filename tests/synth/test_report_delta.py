"""Delta classification, coverage, and gate contracts."""

import contextlib
import io
import json
import os
import tempfile
import unittest
import scripts.synth.findings as findings_mod
import scripts.synth.delta as delta_mod
import scripts.synth.plan as plan_mod
import scripts.synth.report as report_mod
from tests.synth.helpers import _cli_args


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

    def test_a_zero_hunk_active_delta_is_disclosed_not_silent(self):
        """ARC-2340795244 (#1783): a based artifact with an EMPTY hunk map keeps
        the delta ACTIVE while matching no finding, so every finding classifies
        off-diff and `--gate-scope on-diff` has an empty gate source -- a green
        gate over a change with findings. #1783 disclosed it and left the policy
        open (refuse to certify vs fall back to the wider scope).

        OWNER RULING 2026-09-27 (#2178): refuse to certify. This run reads
        INCONCLUSIVE, and `coverage_note` names the zero-hunk map so the operator
        is not left to infer it from the gate word. Falling back to the wider
        scope was REJECTED -- a benign empty `--changes` run would then go red on
        pre-existing findings it did not introduce."""
        with tempfile.TemporaryDirectory() as d:
            hp = os.path.join(d, "diff-hunks.json")
            with open(hp, "w", encoding="utf-8") as fh:
                json.dump({"base": "main", "base_source": "explicit",
                           "diff_context": 5, "files_changed": 0, "hunks": {}}, fh)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                delta = delta_mod.DeltaContext.from_args(
                    _cli_args(diff_hunks=hp, fail_on="high", gate_scope="on-diff"))
            rep = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(
                    target="t",
                    fail_on="high",
                    timestamp="2026-01-01T00:00:00Z",
                    gate_unverified=True,
                    gate_scope="on-diff",
                ),
                findings=findings_mod.FindingSet(findings=self._findings()),
                delta=delta,
                plan=plan_mod.PlanInputs(groups_meta=[{"name": "g1", "files": ["a.py"]}]),
            ))
        # Two active HIGHs, and the gate has nothing to fail on because none of
        # them is on-diff -- so the gate refuses to certify instead of passing.
        self.assertTrue(delta.active)
        self.assertEqual(rep["summary"]["counts"]["active"], 2)
        self.assertEqual(rep["summary"]["delta"]["on_diff"].get("high"), 0)
        self.assertEqual(rep["summary"]["delta"]["pre_existing"].get("high"), 2)
        self.assertEqual(rep["summary"]["gate"], "INCONCLUSIVE")
        self.assertIs(rep["summary"]["coverage_certified"], False)
        note = rep["summary"]["coverage_note"]
        self.assertIn("zero-hunk delta gate", note)
        self.assertIn("2 active finding(s)", note)
        self.assertIn("regenerate the diff-hunks artifact", note)
        # The disclosure: the report says the delta was scoped to nothing...
        cov = rep["meta"]["coverage"]["delta"]
        self.assertEqual(cov["hunks_ranges"], 0)
        self.assertEqual(cov["hunks_files"], 0)
        self.assertEqual(cov["ranges_dropped"], 0)
        self.assertIsNone(cov["payload_malformed"])
        self.assertEqual(cov["on_diff_total"], 0)
        # ...and the operator was told at load time.
        self.assertIn("DELTA REVIEW WITH ZERO HUNKS", err.getvalue())


class TestTheZeroHunkGateRuling(unittest.TestCase):
    """#2178 (owner ruling 2026-09-27), end to end through `build_report`: the
    zero-hunk refusal fires only where the ruling says it does. Its three
    neighbours -- an empty change with nothing to report, a run that ASKED for
    the wider scope, and a map with real ranges -- keep the gate they had."""

    def _findings(self, n):
        return [{"id": "A-%d" % i, "title": "t%d" % i, "severity": "HIGH",
                 "confidence": "POSSIBLE", "panel": "code", "category": "x",
                 "location": {"file": "a.py", "line_start": 90}}
                for i in range(1, n + 1)]

    def _report(self, hunks, findings, gate_scope="on-diff"):
        with tempfile.TemporaryDirectory() as d:
            hp = os.path.join(d, "diff-hunks.json")
            with open(hp, "w", encoding="utf-8") as fh:
                json.dump({"base": "main", "base_source": "explicit",
                           "diff_context": 5, "files_changed": len(hunks),
                           "hunks": hunks}, fh)
            with contextlib.redirect_stderr(io.StringIO()):
                delta = delta_mod.DeltaContext.from_args(
                    _cli_args(diff_hunks=hp, fail_on="high", gate_scope=gate_scope))
            return report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(
                    target="t", fail_on="high", timestamp="2026-01-01T00:00:00Z",
                    gate_unverified=True, gate_scope=gate_scope),
                findings=findings_mod.FindingSet(findings=findings),
                delta=delta,
                plan=plan_mod.PlanInputs(groups_meta=[{"name": "g1", "files": ["a.py"]}]),
            ))

    def test_an_empty_change_with_no_findings_still_passes(self):
        # The owner's carve-out: a legitimately empty diff is not a defect, and
        # a clean run must not be punished for having nothing to gate.
        rep = self._report({}, [])
        self.assertEqual(rep["summary"]["gate"], "PASS")
        self.assertIs(rep["summary"]["coverage_certified"], True)
        self.assertIsNone(rep["summary"]["coverage_note"])
        self.assertEqual(rep["meta"]["coverage"]["delta"]["hunks_ranges"], 0)

    def test_the_wider_scope_keeps_the_gate_the_findings_earned(self):
        # `--gate-scope all` gates on every active finding, so nothing was
        # scoped away by the empty map: the FAIL is real and uncaveated. This is
        # the scope the ruling REFUSED to fall back to automatically -- asking
        # for it is the operator's call, not the report's.
        rep = self._report({}, self._findings(2), gate_scope="all")
        self.assertEqual(rep["summary"]["gate"], "FAIL")
        self.assertIs(rep["summary"]["coverage_certified"], True)
        self.assertIsNone(rep["summary"]["coverage_note"])

    def test_a_populated_map_is_untouched(self):
        # Both findings sit at `line_start` 90, outside the (10, 12) hunk, so
        # the on-diff gate has nothing to fail on -- and that is a MEASURED empty
        # scope, which passes exactly as it did before this ruling.
        rep = self._report({"a.py": [[10, 12]]}, self._findings(2))
        self.assertEqual(rep["summary"]["gate"], "PASS")
        self.assertIs(rep["summary"]["coverage_certified"], True)
        self.assertIsNone(rep["summary"]["coverage_note"])

    def test_a_rejected_payload_names_that_cause_in_the_note(self):
        with tempfile.TemporaryDirectory() as d:
            hp = os.path.join(d, "diff-hunks.json")
            with open(hp, "w", encoding="utf-8") as fh:
                json.dump({"base": "main", "base_source": "explicit",
                           "diff_context": 5, "files_changed": 0, "hunks": 7}, fh)
            with contextlib.redirect_stderr(io.StringIO()):
                delta = delta_mod.DeltaContext.from_args(
                    _cli_args(diff_hunks=hp, fail_on="high", gate_scope="on-diff"))
            rep = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(
                    target="t", fail_on="high", timestamp="2026-01-01T00:00:00Z",
                    gate_unverified=True, gate_scope="on-diff"),
                findings=findings_mod.FindingSet(findings=self._findings(1)),
                delta=delta,
                plan=plan_mod.PlanInputs(groups_meta=[{"name": "g1", "files": ["a.py"]}]),
            ))
        self.assertEqual(rep["summary"]["gate"], "INCONCLUSIVE")
        self.assertIn("because the payload was rejected",
                      rep["summary"]["coverage_note"])
        self.assertEqual(rep["meta"]["coverage"]["delta"]["payload_malformed"],
                         delta_mod.MALFORMED_HUNKS_NOT_OBJECT)
