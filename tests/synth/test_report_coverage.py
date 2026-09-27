"""Coverage, inventory, resume, and summary contracts."""

import os
import json
import tempfile
import unittest
import scripts.synthesize as syn
import scripts.dispatch as dispatch_mod
import scripts.synth.findings as findings_mod
import scripts.synth.codes as codes_mod
import scripts.synth.plan as plan_mod
import scripts.synth.tool_axis as tool_axis_mod
import scripts.synth.report as report_mod
import scripts.synth.render as render_mod
import scripts.evidence as evidence_mod
import scripts.ocrdb as ocrdb
from tests._test_helpers import SKILL_ROOT
from tests.synth.helpers import DEFAULT_TIMESTAMP, _chdir, _target_with_files, _agentic


class TestMetaCoverage(unittest.TestCase):
    def _tool(self, fid="T-1"):
        return {
            "id": fid,
            "source": "tool:bandit",
            "severity": "HIGH",
            "panel": "security",
            "category": "secrets",
            "title": "x",
            "confidence": "LIKELY",
            "description": "d",
            "location": {"file": "a.py", "line_start": 1},
            "provenance": {"confirmation_reasoning": "B105"},
        }

    def test_coverage_block_holds_the_moved_fields(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-05T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[self._tool()]),
            tools=tool_axis_mod.ToolAxis(
                policy_mode="enforced",
                tools_ran={"bandit"},
                dispositions={"bandit": {"status": "ok", "findings": 1}},
            ),
        ))
        cov = r["meta"]["coverage"]
        self.assertEqual(cov["adapters"]["bandit"]["status"], "ok")
        self.assertEqual(cov["tools_ran"], ["bandit"])
        self.assertEqual(cov["tool_policy_mode"], "enforced")
        self.assertIn("tool_axis", cov)
        self.assertIn("verdicts", cov)

    def test_moved_fields_are_gone_from_top_level_meta(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-05T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[self._tool()]),
        ))
        m = r["meta"]
        for k in ("tool_axis", "verdicts", "tool_policy_mode", "build_executing_tools"):
            self.assertNotIn(k, m)

    def test_coverage_present_on_a_findings_only_run(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-05T00:00:00Z"),
            findings=findings_mod.FindingSet(
                findings=[
                    {
                        "id": "A",
                        "severity": "LOW",
                        "panel": "code",
                        "category": "logic",
                        "title": "t",
                        "confidence": "POSSIBLE",
                        "description": "d",
                        "location": {"file": "a.py", "line_start": 1},
                    }
                ],
            ),
        ))
        self.assertIn("coverage", r["meta"])
        self.assertEqual(r["meta"]["coverage"]["tool_policy_mode"], "unknown")
        self.assertEqual(r["meta"]["coverage"]["adapters"], {})


class TestCoverageEndToEnd(unittest.TestCase):
    def test_full_coverage_block_is_honest(self):
        tool = {
            "id": "T-1",
            "source": "tool:bandit",
            "severity": "HIGH",
            "panel": "security",
            "category": "secrets",
            "title": "x",
            "confidence": "LIKELY",
            "description": "d",
            "location": {"file": "a.py", "line_start": 1},
            "provenance": {"confirmation_reasoning": "B105"},
        }
        agent = {
            "id": "A-1",
            "severity": "LOW",
            "panel": "code",
            "category": "logic",
            "title": "t",
            "confidence": "POSSIBLE",
            "description": "d",
            "location": {"file": "b.py", "line_start": 2},
        }
        disp = {
            "bandit": {"status": "ok", "findings": 1},
            "semgrep": {"status": "failed", "findings": 0, "reason": "empty output file"},
        }
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(
                target="t",
                fail_on="high",
                timestamp="2026-08-05T00:00:00Z",
                max_verify=1,
            ),
            findings=findings_mod.FindingSet(findings=[tool, agent]),
            tools=tool_axis_mod.ToolAxis(
                policy_mode="enforced",
                tools_ran={"bandit"},
                dispositions=disp,
            ),
        ))
        cov = r["meta"]["coverage"]
        # semgrep failed -> not in tools_ran / build_executing_tools
        self.assertNotIn("semgrep", cov["tools_ran"])
        self.assertEqual(cov["adapters"]["semgrep"]["status"], "failed")
        # the cut is disclosed
        self.assertEqual(cov["verdicts"]["cut"], 1)
        self.assertEqual(cov["tool_policy_mode"], "enforced")


class TestFanOutCoverageMeta(unittest.TestCase):
    def _f(self):
        return {
            "id": "A",
            "severity": "LOW",
            "panel": "code",
            "category": "x",
            "title": "t",
            "confidence": "POSSIBLE",
            "description": "d",
            "location": {"file": "a.py", "line_start": 1},
        }

    def test_fan_out_present_under_coverage(self):
        fo = {
            "planned": {"code": 2},
            "executed": {"code": 1},
            "groups_complete": ["g1"],
            "groups_partial": ["g2"],
        }
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-07T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[self._f()]),
            plan=plan_mod.PlanInputs(fan_out=fo),
        ))
        self.assertEqual(r["meta"]["coverage"]["fan_out"], fo)

    def test_fan_out_null_when_absent(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-07T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[self._f()]),
        ))
        self.assertIsNone(r["meta"]["coverage"]["fan_out"])


class TestCoverageDivergence(unittest.TestCase):
    GROUPS = [{"name": "g1", "files": ["a.py"]}]
    TS = "2026-01-01T00:00:00Z"

    def test_inconclusive_on_incomplete_high_value_panel(self):
        fan_out = {
            "planned": {"security": 21, "code": 10},
            "executed": {"security": 3, "code": 10},
            "groups_complete": [],
            "groups_partial": ["g1"],
        }
        # Real files on disk: the letter is health-derived, and a fixture with
        # no readable LoC has no letter to make provisional.
        with _target_with_files(self.GROUPS) as tgt:
            r = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(target=tgt, fail_on="high", timestamp=self.TS),
                findings=findings_mod.FindingSet(findings=[]),
                plan=plan_mod.PlanInputs(groups_meta=self.GROUPS, fan_out=fan_out),
            ))
        self.assertEqual(r["summary"]["gate"], "INCONCLUSIVE")
        self.assertIsNone(r["summary"]["overall_grade"])
        # No findings -> no weighted defect -> health 100 -> S, held provisional
        # because a high-value panel did not complete.
        self.assertEqual(r["summary"]["provisional_grade"], "S")
        self.assertEqual(
            r["meta"]["coverage"]["divergence"]["panels"]["security"],
            {"planned": 21, "executed": 3},
        )
        self.assertNotIn("code", r["meta"]["coverage"]["divergence"]["panels"])

    def test_partial_eslint_facts_reach_report_and_qualify_summary(self):
        from scripts.ingest_tools import ingest_dir_detailed
        with tempfile.TemporaryDirectory() as directory:
            with open(os.path.join(directory, "eslint-security.json"), "w") as fh:
                json.dump([{"filePath": "/src/bad.js", "fatalErrorCount": 1, "messages": []}], fh)
            findings, dispositions = ingest_dir_detailed(directory, "g1")
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=findings),
            plan=plan_mod.PlanInputs(groups_meta=self.GROUPS, scout_requested=["eslint-security"]),
            tools=tool_axis_mod.ToolAxis(
                tools_ran=tool_axis_mod.tools_ran_from_dispositions(dispositions),
                dispositions=dispositions),
        ))
        self.assertEqual(r["meta"]["coverage"]["tools_file_partial"]["eslint-security"]["unparsed_files"], 1)
        self.assertFalse(r["summary"]["coverage_certified"])
        self.assertIn("partial scanner file coverage", r["summary"]["coverage_note"])
        self.assertEqual(r["summary"]["gate"], "PASS")

    def test_tool_noscan_is_disclosed_without_sinking_the_gate(self):
        # #1335: a semgrep that scanned 0 files gets no coverage credit (it is
        # absent from tools_ran), but it is NOT a coverage loss the operator can
        # fix -- on a no-surface repo there was nothing for it to scan. So it is
        # disclosed as `produced_noscan` and must never reach tools_absent,
        # which is what turns the gate INCONCLUSIVE.
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(groups_meta=self.GROUPS,
                                     scout_requested=["trivy", "semgrep"]),
            tools=tool_axis_mod.ToolAxis(
                tools_ran=["trivy"],
                dispositions={"trivy": {"status": "ok", "findings": 2},
                              "semgrep": {"status": "noscan", "findings": 0}}),
        ))
        self.assertEqual(r["meta"]["coverage"]["divergence"]["tools"],
                         {"semgrep": "produced_noscan"})
        self.assertNotIn("semgrep", r["meta"]["coverage"]["tools_ran"])
        self.assertNotEqual(r["summary"]["gate"], "INCONCLUSIVE")

    def test_tool_requested_absent_is_disclosed_and_inconclusive(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(groups_meta=self.GROUPS, scout_requested=["trivy", "semgrep"]),
            tools=tool_axis_mod.ToolAxis(tools_ran=["trivy"]),
        ))
        self.assertEqual(
            r["meta"]["coverage"]["divergence"]["tools"], {"semgrep": "requested_absent"}
        )
        self.assertEqual(r["summary"]["gate"], "INCONCLUSIVE")

    def test_backward_compat_no_fanout_no_scout(self):
        with _target_with_files(self.GROUPS) as tgt:
            r = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(target=tgt, fail_on="high", timestamp=self.TS),
                findings=findings_mod.FindingSet(findings=[]),
                plan=plan_mod.PlanInputs(groups_meta=self.GROUPS),
            ))
        # Clean tree, fully covered: no weighted defect at all -> health 100 -> S.
        self.assertEqual(r["summary"]["overall_grade"], "S")
        self.assertEqual(r["summary"]["gate"], "PASS")
        self.assertTrue(r["summary"]["coverage_certified"])
        self.assertIsNone(r["summary"]["provisional_grade"])
        self.assertEqual(r["meta"]["coverage"]["divergence"], {"panels": {}, "tools": {}})

    def test_present_empty_dispatch_plan_is_inconclusive(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(
                groups_meta=self.GROUPS,
                integrity={"plans_seen": 1, "empty_dispatch_plans": 1},
            ),
        ))
        self.assertEqual(r["summary"]["gate"], "INCONCLUSIVE")
        self.assertFalse(r["summary"]["coverage_certified"])


class TestFloorCellCoverageWiring(unittest.TestCase):
    """5.0 (matrix Sec5.1): build_report's own wiring of audit_floor_cells --
    not just the pure function (TestFloorCellAudit in test_plan.py). Mirrors
    TestCoverageDivergence's tools_absent-level coverage for the same
    INCONCLUSIVE-forcing mechanism."""

    GROUPS = [{"name": "g1", "files": ["a.py"]}]
    TS = "2026-01-01T00:00:00Z"

    def test_missing_floor_cell_forces_inconclusive_and_is_disclosed(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(
                groups_meta=self.GROUPS,
                coverages=[{"group": "g1", "floor": ["SEC"], "effective": ["SEC"]}],
            ),
            tools=tool_axis_mod.ToolAxis(ingested_paths=[]),
        ))
        self.assertEqual(r["meta"]["coverage"]["cells"]["missing_floor"], [["g1", "SEC"]])
        self.assertEqual(r["summary"]["gate"], "INCONCLUSIVE")
        self.assertFalse(r["summary"]["coverage_certified"])

    def test_present_floor_cell_stays_certified(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(
                groups_meta=self.GROUPS,
                coverages=[{"group": "g1", "floor": ["SEC"], "effective": ["SEC"]}],
            ),
            tools=tool_axis_mod.ToolAxis(
                ingested_paths=[os.path.join(".panopticon", "findings-g1-SEC.json")],
            ),
        ))
        self.assertEqual(r["meta"]["coverage"]["cells"]["missing_floor"], [])
        self.assertEqual(r["summary"]["gate"], "PASS")
        self.assertTrue(r["summary"]["coverage_certified"])

    def test_measured_pairs_filter_invalid_plan_values_and_keep_chunk_identity(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(coverages=[
                {"group": "g_1", "effective": ["SEC", "COD", "SEC", 2, [], "bad"]},
                {"group": "g_2", "effective": ["QAL"]},
                {"group": [], "effective": ["SEC"]},
                {"group": "bad", "effective": "SEC"}, None]),
            tools=tool_axis_mod.ToolAxis(ingested_paths=[
                "findings-g_2-QAL.json", "findings-g_1-SEC.json", "findings-g_1-SEC.json",
                "findings-g_1-security.json", "semgrep.json"])))
        cells = r["meta"]["coverage"]["cells"]
        self.assertEqual(cells["reviewed"], [["g_1", "SEC"], ["g_2", "QAL"]])
        self.assertEqual(cells["planned_pairs"], [["g_1", "COD"], ["g_1", "SEC"], ["g_2", "QAL"]])
        self.assertEqual(cells["missing_floor"], [])

    def test_measured_empty_and_unknown_plan_are_distinct(self):
        for coverages in (None, []):
            r = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
                findings=findings_mod.FindingSet(findings=[]),
                plan=plan_mod.PlanInputs(coverages=coverages),
                tools=tool_axis_mod.ToolAxis(ingested_paths=[])))
            cells = r["meta"]["coverage"]["cells"]
            self.assertEqual(cells["reviewed"], [])
            self.assertEqual("planned_pairs" in cells, coverages is not None)

    def test_backward_compat_no_coverages_no_regression(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(groups_meta=self.GROUPS),
        ))
        self.assertEqual(r["meta"]["coverage"]["cells"], {"missing_floor": []})
        self.assertEqual(r["summary"]["gate"], "PASS")


class TestResumeDisclosure(unittest.TestCase):
    G = [{"name": "g1", "files": ["a.py"]}]
    TS = "2026-01-01T00:00:00Z"

    def test_build_report_emits_resume(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(
                groups_meta=self.G,
                resume={
                    "fan_out": {"total": 74, "done": 33, "pending": 41},
                    "verify": {"total": 52, "done": 12, "pending": 40},
                },
            ),
        ))
        self.assertEqual(r["meta"]["coverage"]["resume"]["fan_out"]["done"], 33)
        self.assertEqual(r["meta"]["coverage"]["resume"]["verify"]["pending"], 40)

    def test_build_report_resume_defaults_none(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(groups_meta=self.G),
        ))
        self.assertIsNone(r["meta"]["coverage"]["resume"])

    def test_main_tolerates_non_list_verify_queue_entries(self):
        # A verify-queue.json with a truthy non-list `entries` (e.g. an int)
        # is a valid JSON dict -- it passes main()'s isinstance(dict) load
        # guard -- and used to raise a TypeError deep inside
        # group_runner.resume_stats, aborting the whole run with no report
        # artifact. A malformed queue must never abort a run.
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            os.makedirs(os.path.join(d, ".panopticon"), exist_ok=True)
            with open(os.path.join(d, ".panopticon", "verify-queue.json"), "w") as fh:
                json.dump({"entries": 42}, fh)
            with open(os.path.join(d, ".panopticon", "groups.json"), "w") as fh:
                json.dump({"mode": "repo", "groups": self.G}, fh)
            fpath = os.path.join(d, "findings-g1-code.json")
            with open(fpath, "w") as fh:
                json.dump(
                    {
                        "findings": [
                            {
                                "id": "CD-001",
                                "title": "x",
                                "severity": "LOW",
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
            rc = syn.main(["--out", out, fpath])
            self.assertIsInstance(rc, int)
            self.assertTrue(os.path.exists(out))
            with open(out) as fh:
                report = json.load(fh)
            self.assertEqual(report["meta"]["coverage"]["resume"]["verify"]["total"], 0)
            self.assertEqual(report["summary"]["gate"], "OFF")
            self.assertFalse(report["summary"]["coverage_certified"])
            self.assertIn("entries list", report["meta"]["integrity"]["invalid_verify_queue"])


class TestRenderSummaryCoverage(unittest.TestCase):
    def test_inconclusive_summary_names_divergence(self):
        fan_out = {
            "planned": {"security": 21},
            "executed": {"security": 3},
            "groups_complete": [],
            "groups_partial": ["g1"],
        }
        groups = [{"name": "g1", "files": ["a.py"]}]
        # Real files: the summary line prints a PROVISIONAL letter, and there is
        # no letter to hold provisional without readable LoC.
        with _target_with_files(groups) as tgt:
            r = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(
                    target=tgt,
                    fail_on="high",
                    timestamp="2026-01-01T00:00:00Z",
                ),
                findings=findings_mod.FindingSet(findings=[]),
                plan=plan_mod.PlanInputs(groups_meta=groups, fan_out=fan_out),
            ))
        text = render_mod.render_summary(r)
        self.assertIn("INCONCLUSIVE", text)
        self.assertIn("NOT CERTIFIED", text)
        self.assertIn("security", text)
        self.assertIn("provisional", text.lower())


class TestRenderSummaryResume(unittest.TestCase):
    G = [{"name": "g1", "files": ["a.py"]}]
    TS = "2026-01-01T00:00:00Z"

    def test_resume_line_shown_when_pending(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(
                groups_meta=self.G,
                resume={
                    "fan_out": {"total": 74, "done": 33, "pending": 41},
                    "verify": {"total": 52, "done": 12, "pending": 40},
                },
            ),
        ))
        text = render_mod.render_summary(r)
        self.assertIn("Resume:", text)
        self.assertIn("33/74", text)
        self.assertIn("12/52", text)

    def test_no_resume_line_when_complete(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(
                groups_meta=self.G,
                resume={
                    "fan_out": {"total": 74, "done": 74, "pending": 0},
                    "verify": {"total": 52, "done": 52, "pending": 0},
                },
            ),
        ))
        self.assertNotIn("Resume:", render_mod.render_summary(r))

    def test_no_resume_line_when_resume_absent(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(groups_meta=self.G),
        ))  # resume=None
        self.assertNotIn("Resume:", render_mod.render_summary(r))


class TestTestInventoryCoverage(unittest.TestCase):
    """#1638 P13: an operator reading run-13's report saw a TST panel claim a
    module had no automated coverage. Nothing in the report said the claim had
    been derived from an EMPTY inventory rather than from the tree, so nothing
    in the report distinguished a real coverage gap from a matrix defect.
    `meta.coverage.test_inventory` is that distinction, counted per group off
    the tally the review phase persists as it renders each prompt.
    """

    def _coverage(self, inventory):
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on="high",
                                     timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(test_inventory=inventory)))
        return report["meta"]["coverage"]

    def test_the_states_reach_the_report_per_group(self):
        self.assertEqual({"Code": "split", "Other": "complete"},
                         self._coverage({"Code": "split",
                                         "Other": "complete"})["test_inventory"])

    def test_a_run_that_measured_nothing_reports_an_empty_map(self):
        # Stated on every report, `{}` included: an absent key would make
        # "nobody measured" and "every group is fine" the same document.
        self.assertEqual({}, self._coverage(None)["test_inventory"])

    def test_the_tally_is_loaded_from_the_run_folder(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "panel-test-inventory.json"), "w",
                      encoding="utf-8") as fh:
                json.dump({"schema_version": 1,
                           "groups": {"A": "complete", "B": "empty"}}, fh)
            self.assertEqual({"A": "complete", "B": "empty"},
                             plan_mod.load_test_inventory(d))

    def test_an_absent_or_corrupt_tally_reads_as_nothing_measured(self):
        # Fail-closed like its sibling: `.panopticon` is a directory a hostile
        # target can pre-commit, and a state this run did not measure must not
        # be invented from one it did not write.
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual({}, plan_mod.load_test_inventory(d))
            with open(os.path.join(d, "panel-test-inventory.json"), "w",
                      encoding="utf-8") as fh:
                fh.write("{ not json")
            self.assertEqual({}, plan_mod.load_test_inventory(d))

    def test_an_unknown_state_is_dropped_rather_than_carried(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "panel-test-inventory.json"), "w",
                      encoding="utf-8") as fh:
                json.dump({"groups": {"A": "complete", "B": "sideways",
                                      "C": {"nested": 1}}}, fh)
            self.assertEqual({"A": "complete"}, plan_mod.load_test_inventory(d))

    def test_the_schema_declares_the_field(self):
        with open(os.path.join(SKILL_ROOT, "reference",
                               "report-schema.json"), encoding="utf-8") as fh:
            schema = json.load(fh)
        block = schema["properties"]["meta"]["properties"]["coverage"]
        self.assertIn("test_inventory", block["properties"])


class TestTheInventoryStateFilesNothingAndGatesNothing(unittest.TestCase):
    """#1638 P13 ruling 4, as amended by fix round 1 (F1).

    The inventory state is DRIVER-computed and published twice already -- on
    the dispatch entry and in `meta.coverage.test_inventory`. No agent files a
    finding for it, so the invariant is stronger than "the diagnostic is
    weightless": an empty/split matrix must change nothing in the report
    except `meta.coverage.test_inventory` itself. In particular it must emit
    no `-X0X` code, because an X0X from a non-TST cell is rewritten to that
    cell's domain, counts as a cross-domain finding, and clusters into
    `report-x0x.json` as a target-specific OCRDb candidate nobody can adjudicate.
    """

    GROUPS = [{"name": "g1", "files": ["a.py"]}]
    FLAGGED = {"g1": "empty", "g2": "split"}

    def _report(self, inventory):
        real = _agentic(sev="HIGH", location={"file": "a.py", "line_start": 5,
                                              "line_end": 8})
        verdicts = {evidence_mod.finding_fingerprint(real): {
            "finding_id": real["id"], "verdict": "CONFIRMED", "reasoning": "v"}}
        with _target_with_files(self.GROUPS, lines=200) as tgt:
            return report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(target=tgt, fail_on="high",
                                         timestamp=DEFAULT_TIMESTAMP),
                findings=findings_mod.FindingSet(findings=[real],
                                                 verdicts=verdicts),
                plan=plan_mod.PlanInputs(groups_meta=self.GROUPS,
                                         test_inventory=inventory)))

    def test_a_flagged_matrix_changes_nothing_but_the_disclosure(self):
        clean = self._report({"g1": "complete"})
        flagged = self._report(self.FLAGGED)
        self.assertNotEqual(clean["meta"]["coverage"]["test_inventory"],
                            flagged["meta"]["coverage"]["test_inventory"])
        self.assertEqual(clean["summary"], flagged["summary"])
        self.assertEqual(clean["findings"], flagged["findings"])
        self.assertEqual(clean["discarded_claims"], flagged["discarded_claims"])

    def test_a_flagged_matrix_manufactures_no_x0x_candidate(self):
        report = self._report(self.FLAGGED)
        codes = [f.get("code") for f in report["findings"]
                 + report["discarded_claims"]]
        self.assertEqual([], [c for c in codes if c and str(c).endswith("-X0X")])
        ocrdb_cov = report["meta"]["coverage"]["ocrdb"]
        self.assertEqual(0, ocrdb_cov["invalid_codes"])
        self.assertEqual({}, ocrdb_cov["fallbacks"])
        self.assertEqual(0, ocrdb_cov["code_domain_mismatch"])

    def test_the_x0x_assertion_has_teeth(self):
        # Guards the guard. The assertion above is over a fixture with no
        # agent findings, so it would hold vacuously. This is the shape fix
        # round 1 removed -- a `TST-X0X` filed from a SEC cell -- proving the
        # counters it reads actually move when it happens: the code is
        # rewritten to the CELL's domain, the mismatch is counted, and the
        # candidate pool gains a fallback under a domain that never saw it.
        bogus = _agentic(fid="AG-X0X", sev="INFO", panel="security",
                         domain="SEC", code="TST-X0X",
                         title="Test inventory for g1 is empty or incomplete")
        cov = codes_mod.validate_finding_codes([bogus], ocrdb.load_bundle())
        self.assertEqual("SEC-X0X", bogus["code"])
        self.assertEqual(1, cov["invalid_codes"])
        self.assertEqual(1, cov["code_domain_mismatch"])
        self.assertEqual({"SEC": 1}, cov["fallbacks"])

    def test_the_prompt_asks_for_no_such_finding(self):
        # The end of the chain the two assertions above measure: nothing files
        # it because the template no longer names a code or a title for it.
        _meta, body = dispatch_mod.load_template("domain-panel.md")
        self.assertNotIn("TST-X0X", body)
        self.assertNotIn("Test inventory for {group} is empty or incomplete",
                         body)
