"""Delta classification, coverage, and gate contracts."""

import contextlib
import dataclasses
import io
import json
import os
import tempfile
import unittest
import scripts.synth.findings as findings_mod
import scripts.synth.delta as delta_mod
import scripts.synth.plan as plan_mod
import scripts.synth.report as report_mod
import scripts.evidence as evidence_mod
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
        # #2222: the note counts the GATE-ELIGIBLE population, which this run
        # (`--gate-unverified`, two HIGHs, `--fail-on high`) makes both of them.
        self.assertIn("2 gate-eligible finding(s)", note)
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
    the wider scope, and a map with real ranges -- keep the gate they had. #2222
    (owner ruling 2026-09-28) adds the fourth and fifth: a run whose active
    findings are ones this gate would never have judged keeps its PASS too."""

    def _findings(self, n, sev="HIGH"):
        # Off-diff lines (the (10, 12) hunk this class also uses reaches 17 at
        # `diff_context` 5), one per finding: two claims at the SAME locus dedupe
        # into one, and a count these tests assert must mean what it says.
        return [{"id": "A-%d" % i, "title": "t%d" % i, "severity": sev,
                 "confidence": "POSSIBLE", "panel": "code", "category": "x",
                 "location": {"file": "a.py", "line_start": 90 + i}}
                for i in range(1, n + 1)]

    def _report(self, hunks, findings, gate_scope="on-diff",
                gate_unverified=True, verdicts=None):
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
                    gate_unverified=gate_unverified, gate_scope=gate_scope),
                findings=findings_mod.FindingSet(findings=findings,
                                                 verdicts=verdicts or {}),
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
        # Both findings sit past line 90 -- at 91 and 92 -- outside the (10, 12)
        # hunk, which reaches 17 at `diff_context` 5, so the on-diff gate has
        # nothing to fail on -- and that is a MEASURED empty scope, which passes
        # exactly as it did before this ruling.
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

    # #2222 (owner ruling 2026-09-28), NARROWING #2178: the refusal is a
    # statement about what the empty map hid FROM THE GATE, so the population it
    # counts is the active set the gate would actually have judged -- the
    # evidence policy, then the `--fail-on` floor. A finding the gate would have
    # ignored at any scope was never scoped away by the empty map, so a run
    # carrying only those keeps the PASS it earned.

    def test_findings_below_the_fail_on_floor_keep_the_pass(self):
        """Two active INFO findings under `--fail-on high`: the floor admits
        neither, so nothing the gate would have judged was scoped away and the
        run is not INCONCLUSIVE. Before #2222 the count was `len(active)` and
        this same run refused to certify over findings that cannot gate."""
        rep = self._report({}, self._findings(2, sev="INFO"))
        self.assertEqual(rep["summary"]["counts"]["active"], 2)
        self.assertEqual(rep["summary"]["gate"], "PASS")
        self.assertIs(rep["summary"]["coverage_certified"], True)
        self.assertIsNone(rep["summary"]["coverage_note"])

    def test_unverified_findings_keep_the_pass_under_the_default_policy(self):
        """The evidence half of the same ruling: two active HIGHs with no
        verdict are `unverified`, which the default `confirmed_only` policy
        keeps out of the gate at every scope."""
        rep = self._report({}, self._findings(2), gate_unverified=False)
        self.assertEqual(rep["summary"]["gate_policy"], "confirmed_only")
        self.assertEqual(rep["summary"]["counts"]["active"], 2)
        self.assertEqual(rep["summary"]["gate"], "PASS")
        self.assertIs(rep["summary"]["coverage_certified"], True)
        self.assertIsNone(rep["summary"]["coverage_note"])

    def test_one_confirmed_high_over_an_empty_map_is_still_inconclusive(self):
        """#2222 narrows the population; it does not retire the refusal. A
        CONFIRMED HIGH under `--fail-on high` is exactly what this gate would
        have judged, and the zero-range map is what kept it out of the on-diff
        source set -- so the run still refuses to certify, and the note counts
        the ONE gate-eligible finding, not the three active ones."""
        findings = [
            {"id": "A-1", "title": "confirmed high", "severity": "HIGH",
             "confidence": "POSSIBLE", "panel": "code", "category": "x",
             "location": {"file": "a.py", "line_start": 90}},
            {"id": "A-2", "title": "unverified high", "severity": "HIGH",
             "confidence": "POSSIBLE", "panel": "code", "category": "x",
             "location": {"file": "a.py", "line_start": 95}},
            {"id": "A-3", "title": "unverified info", "severity": "INFO",
             "confidence": "POSSIBLE", "panel": "code", "category": "x",
             "location": {"file": "a.py", "line_start": 99}},
        ]
        verdicts = {evidence_mod.finding_fingerprint(findings[0]): {
            "finding_id": "A-1", "verdict": "CONFIRMED", "reasoning": "v"}}
        rep = self._report({}, findings, gate_unverified=False, verdicts=verdicts)
        self.assertEqual(rep["summary"]["counts"]["active"], 3)
        self.assertEqual(rep["summary"]["gate"], "INCONCLUSIVE")
        self.assertIs(rep["summary"]["coverage_certified"], False)
        note = rep["summary"]["coverage_note"]
        self.assertIn("zero-hunk delta gate", note)
        self.assertIn("1 gate-eligible finding(s)", note)


class TestTheBrokenArtifactGateRuling(unittest.TestCase):
    """#2405 (owner ruling 2026-10-01), end to end through `build_report`: a map
    with a real range, one path the loader emptied because every range under it
    was malformed, and one finding this gate would have judged. The zero-hunk
    rule is silent -- the map HAS a range -- and the run still refuses to
    certify, because the artifact that chose the gate's scope is provably
    damaged. The twin is the carve-out: the same shape arriving `[]` is a
    legitimate deletion-only change and keeps the PASS it earned."""

    # The zero-hunk class's builders, by reference: one fixture for both rulings,
    # so the two cases differ only in the artifact they are handed.
    _findings = TestTheZeroHunkGateRuling._findings
    _report = TestTheZeroHunkGateRuling._report

    def test_a_path_emptied_by_dropped_ranges_is_inconclusive(self):
        rep = self._report({"a.py": [[10, 12]], "c.py": ["nope"]},
                           self._findings(1))
        self.assertEqual(rep["summary"]["gate"], "INCONCLUSIVE")
        self.assertIs(rep["summary"]["coverage_certified"], False)
        note = rep["summary"]["coverage_note"]
        self.assertIn("broken-artifact delta gate", note)
        self.assertIn("paths_emptied_by_drops", note)
        self.assertIn("1 gate-eligible finding(s)", note)
        cov = rep["meta"]["coverage"]["delta"]
        self.assertEqual((cov["hunks_ranges"], cov["paths_without_ranges"],
                          cov["paths_emptied_by_drops"]), (1, 1, 1))

    def test_a_legitimately_rangeless_path_keeps_the_pass(self):
        rep = self._report({"a.py": [[10, 12]], "c.py": []}, self._findings(1))
        self.assertEqual(rep["summary"]["gate"], "PASS")
        self.assertIs(rep["summary"]["coverage_certified"], True)
        self.assertIsNone(rep["summary"]["coverage_note"])
        cov = rep["meta"]["coverage"]["delta"]
        self.assertEqual((cov["paths_without_ranges"],
                          cov["paths_emptied_by_drops"]), (1, 0))


class TestARejectedArtifactIsDisclosedInTheReport(unittest.TestCase):
    """#2169, end to end through the report builder: a run rejected the
    diff-hunks artifact, said so on stderr, and published a report in which the
    fact did not appear. The sibling `meta.coverage.delta_artifact` is the fix,
    and its schema node in `report-schema.json` says why it has the shape it
    has and what it deliberately does NOT change about `meta.coverage.delta`."""

    def _findings(self):
        return [{"id": "A-1", "title": "t", "severity": "HIGH",
                 "confidence": "POSSIBLE", "panel": "code", "category": "x",
                 "location": {"file": "a.py", "line_start": 11}}]

    def _coverage(self, raw=None, payload=None, with_flag=True, findings=None,
                  group_files=("a.py",)):
        """`meta.coverage` for a run handed this artifact, or none at all."""
        with tempfile.TemporaryDirectory() as d:
            hp = os.path.join(d, "diff-hunks.json")
            if raw is not None or payload is not None:
                with open(hp, "w", encoding="utf-8") as fh:
                    fh.write(raw if raw is not None else json.dumps(payload))
            with contextlib.redirect_stderr(io.StringIO()):
                delta = delta_mod.DeltaContext.from_args(_cli_args(
                    diff_hunks=hp if with_flag else None, fail_on="high"))
            rep = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(
                    target="t", fail_on="high", timestamp="2026-01-01T00:00:00Z",
                    gate_unverified=True),
                findings=findings_mod.FindingSet(
                    findings=self._findings() if findings is None else findings),
                delta=delta,
                plan=plan_mod.PlanInputs(
                    groups_meta=[{"name": "g1", "files": list(group_files)}]),
            ))
            return rep["meta"]["coverage"]

    def test_an_unreadable_artifact_is_named_in_the_report(self):
        cov = self._coverage(raw="{not json")
        self.assertIsNone(cov["delta"])            # still not a delta review
        self.assertEqual(cov["delta_artifact"],
                         {"payload_malformed": delta_mod.MALFORMED_UNREADABLE,
                          "ranges_dropped": 0, "paths_dropped": 0,
                          "paths_without_ranges": 0,
                          "paths_emptied_by_drops": 0, "keys_repaired": []})

    def test_a_non_object_artifact_is_named_in_the_report(self):
        cov = self._coverage(payload=["not", "an", "object"])
        self.assertIsNone(cov["delta"])
        self.assertEqual(cov["delta_artifact"],
                         {"payload_malformed": delta_mod.MALFORMED_NOT_OBJECT,
                          "ranges_dropped": 0, "paths_dropped": 0,
                          "paths_without_ranges": 0,
                          "paths_emptied_by_drops": 0, "keys_repaired": []})

    def test_no_diff_hunks_flag_leaves_both_keys_null(self):
        # The distinction the whole change is about: nothing was read, so there
        # is nothing to report about a read -- and `delta_artifact` is PRESENT
        # and null rather than absent, so its absence can never be mistaken for
        # a producer that failed to run.
        cov = self._coverage(with_flag=False)
        self.assertIsNone(cov["delta"])
        self.assertIn("delta_artifact", cov)
        self.assertIsNone(cov["delta_artifact"])

    def test_an_active_delta_carries_both_blocks(self):
        cov = self._coverage(payload={"base": "main", "base_source": "explicit",
                                      "diff_context": 5, "files_changed": 1,
                                      "hunks": {"a.py": [[10, 12]]}})
        self.assertIsNotNone(cov["delta"])
        self.assertEqual(cov["delta"]["paths_dropped"], 0)
        self.assertEqual(cov["delta_artifact"],
                         {"payload_malformed": None,
                          "ranges_dropped": 0, "paths_dropped": 0,
                          "paths_without_ranges": 0,
                          "paths_emptied_by_drops": 0, "keys_repaired": []})

    def test_the_two_blocks_agree_about_the_losses(self):
        # One loader record behind both, so the active block and the sibling
        # cannot disagree about what reading the artifact cost.
        cov = self._coverage(payload={"base": "main", "base_source": "explicit",
                                      "diff_context": 5, "files_changed": 2,
                                      "hunks": {"a.py": [[10, 12], [3]],
                                                "b.py": 7}})
        self.assertEqual(cov["delta"]["ranges_dropped"],
                         cov["delta_artifact"]["ranges_dropped"])
        self.assertEqual(cov["delta"]["paths_dropped"],
                         cov["delta_artifact"]["paths_dropped"])
        self.assertEqual((cov["delta"]["ranges_dropped"],
                          cov["delta"]["paths_dropped"]), (1, 1))

    def test_a_named_path_with_no_range_is_published_in_both_blocks(self):
        # #2381: the map NAMES c.py and gives it no range, so `diff_map.classify`
        # fails open and the finding there is counted on-diff -- `on_diff_total: 2`
        # below is that fail-open, and before this counter nothing in the report
        # said the second of the two was admitted on the artifact's word rather
        # than on a measured range. Nothing was dropped (both loss counters are 0)
        # and the whole-map disclosures stay silent (`hunks_ranges` is 1), so this
        # key is the only place the shape appears.
        cov = self._coverage(
            payload={"base": "main", "base_source": "explicit", "diff_context": 5,
                     "files_changed": 2,
                     "hunks": {"a.py": [[10, 12]], "c.py": []}},
            group_files=("a.py", "c.py"),
            findings=self._findings() + [
                {"id": "A-2", "title": "in the rangeless file", "severity": "HIGH",
                 "confidence": "POSSIBLE", "panel": "code", "category": "x",
                 "location": {"file": "c.py", "line_start": 99}}])
        self.assertEqual(cov["delta"]["paths_without_ranges"], 1)
        self.assertEqual(cov["delta_artifact"]["paths_without_ranges"], 1)
        self.assertEqual((cov["delta"]["ranges_dropped"],
                          cov["delta"]["paths_dropped"]), (0, 0))
        self.assertEqual((cov["delta"]["hunks_files"],
                          cov["delta"]["hunks_ranges"]), (2, 1))
        self.assertEqual(cov["delta"]["on_diff_total"], 2)
        self.assertEqual(cov["delta"]["pre_existing_total"], 0)
        # #2386: c.py arrived `[]`, the legitimate half of the shape.
        self.assertEqual(cov["delta"]["paths_emptied_by_drops"], 0)
        self.assertEqual(cov["delta_artifact"]["paths_emptied_by_drops"], 0)

    def test_the_broken_half_of_the_rangeless_shape_is_published_too(self):
        # #2386: c.py's only range was malformed, so the loader emptied its list
        # -- a BROKEN artifact wearing the same shape as the deletion-only change
        # above. Both blocks carry the subset, so a consumer reading the report
        # (not the stderr line) can tell the two apart for the first time.
        cov = self._coverage(
            payload={"base": "main", "base_source": "explicit", "diff_context": 5,
                     "files_changed": 2,
                     "hunks": {"a.py": [[10, 12]], "c.py": ["nope"]}},
            group_files=("a.py", "c.py"))
        self.assertEqual(cov["delta"]["paths_without_ranges"], 1)
        self.assertEqual(cov["delta"]["paths_emptied_by_drops"], 1)
        self.assertEqual(cov["delta_artifact"]["paths_emptied_by_drops"], 1)
        self.assertEqual(cov["delta"]["ranges_dropped"], 1)
        self.assertEqual(cov["delta"]["paths_dropped"], 0)

    def test_every_hunks_load_field_is_published_in_both_blocks(self):
        # #2381 review, N6: schema parity binds the schema to the report and the
        # cases above bind each counter to both blocks, but nothing bound the
        # dataclass to its two publishers -- a field added to `HunksLoad` and
        # forgotten in `artifact_facts` or `_delta_meta` stayed green, which is
        # the class of omission #2169 and #2381 both were.
        renamed = {"files": "hunks_files", "ranges": "hunks_ranges"}
        # #2382: ONE field is published in the sibling only, and deliberately.
        # `keys_repaired` exists to disclose a repair that can null `base`, and a
        # nulled base leaves `delta` itself null -- so a key there could not carry
        # it in the case it was added for. Exempted by name, so the guard still
        # fails for the next field added to `HunksLoad` and forgotten.
        artifact_only = {"keys_repaired"}
        fields = {f.name for f in dataclasses.fields(delta_mod.HunksLoad)}
        self.assertTrue(set(renamed) <= fields)
        self.assertTrue(artifact_only <= fields)
        cov = self._coverage(payload={"base": "main", "base_source": "explicit",
                                      "diff_context": 5, "files_changed": 1,
                                      "hunks": {"a.py": [[10, 12]]}})
        # the sibling publishes what the READ cost, so the two map sizes stay out
        self.assertEqual(set(cov["delta_artifact"]), fields - set(renamed))
        self.assertLessEqual({renamed.get(f, f) for f in fields - artifact_only},
                             set(cov["delta"]))
