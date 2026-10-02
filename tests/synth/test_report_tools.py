"""Tool execution, scanner context, and disclosure contracts."""

import contextlib
import io
import os
import json
import tempfile
import unittest
import scripts.synth.validate_schema as validate_schema_mod
import scripts.synth.corroborate as corroborate_mod
import scripts.synth.findings as findings_mod
import scripts.synth.plan as plan_mod
import scripts.synth.repair as repair_mod
import scripts.synth.tool_axis as tool_axis_mod
import scripts.synth.report as report_mod
import scripts.evidence as evidence_mod
from tests.synth.helpers import DEFAULT_TIMESTAMP, _make_finding, _agentic


class TestBuildExecutingTools(unittest.TestCase):

    def test_meta_records_build_executing_tool(self):
        f = _make_finding(source="tool:roslyn-secguard")
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-03T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[f]),
        ))
        self.assertEqual(report["meta"]["coverage"]["build_executing_tools"], ["roslyn-secguard"])

    def test_meta_empty_without_executing_tools(self):
        f = _make_finding(source="tool:bandit")
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-03T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[f]),
        ))
        self.assertEqual(report["meta"]["coverage"]["build_executing_tools"], [])


class TestToolAxisMeta(unittest.TestCase):
    def _tool(self, fid="T-1", **over):
        f = {
            "id": fid,
            "source": "tool:bandit",
            "severity": "HIGH",
            "panel": "security",
            "category": "secrets",
            "title": "hardcoded password",
            "confidence": "LIKELY",
            "description": "d",
            "location": {"file": "a.py", "line_start": 1},
            "provenance": {"confirmation_reasoning": "B105"},
        }
        f.update(over)
        return f

    def test_tool_axis_counts_unverified_as_unanswered(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-05T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[self._tool()]),
        ))
        axis = r["meta"]["coverage"]["tool_axis"]
        self.assertEqual(axis["queued"], 1)
        self.assertEqual(axis["unanswered"], 1)
        self.assertEqual(axis["confirmed"], 0)
        self.assertIsNone(axis["rejection_rate"])

    def test_tool_axis_rejection_rate_when_verdicts_exist(self):
        a, b = self._tool("T-1"), self._tool("T-2", location={"file": "b.py", "line_start": 2})
        prepared, _ = corroborate_mod.prepare_for_queue([a, b])
        queue, _c = evidence_mod.build_verify_queue(prepared)
        verdicts = {}
        for i, e in enumerate(queue):
            verdicts[e["queue_id"]] = {
                "verdict": "REJECTED" if i == 0 else "CONFIRMED",
                "finding_id": e["finding"]["id"],
                "reasoning": "r",
            }
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-05T00:00:00Z"),
            findings=findings_mod.FindingSet(
                findings=[a, b],
                verdicts=verdicts,
                verdicts_supplied=True,
            ),
        ))
        axis = r["meta"]["coverage"]["tool_axis"]
        self.assertEqual((axis["confirmed"], axis["rejected"]), (1, 1))
        self.assertEqual(axis["rejection_rate"], 0.5)

    def test_tool_axis_counts_needs_more_info_and_excludes_it_from_decided(self):
        a, b = self._tool("T-1"), self._tool("T-2", location={"file": "b.py", "line_start": 2})
        prepared, _ = corroborate_mod.prepare_for_queue([a, b])
        queue, _c = evidence_mod.build_verify_queue(prepared)
        verdicts = {
            queue[0]["queue_id"]: {
                "verdict": "NEEDS_MORE_INFO",
                "finding_id": queue[0]["finding"]["id"],
                "reasoning": "r",
            }
        }
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-05T00:00:00Z"),
            findings=findings_mod.FindingSet(
                findings=[a, b],
                verdicts=verdicts,
                verdicts_supplied=True,
            ),
        ))
        axis = r["meta"]["coverage"]["tool_axis"]
        self.assertEqual(axis["needs_more_info"], 1)
        self.assertEqual(axis["unanswered"], 1)
        # needs_more_info is neither confirmed nor rejected, so it must not
        # count toward "decided" -- otherwise the rejection rate would be
        # diluted by claims that were never actually resolved either way.
        self.assertIsNone(axis["rejection_rate"])

    def test_tool_axis_counts_reinforced_non_tool_sourced_finding(self):
        # A reinforced (tool+agent same-locus merge) survivor can carry a
        # non-"tool:"-prefixed source, yet build_report's tool_like filter is
        # is_tool_sourced(f) OR f.get("reinforced") -- not is_tool_sourced
        # alone -- so it must still land in the tool axis.
        f = _agentic(reinforced=True)
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-05T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[f]),
        ))
        axis = r["meta"]["coverage"]["tool_axis"]
        self.assertEqual(axis["queued"], 1)

    def test_build_executing_tools_reports_a_run_with_zero_findings(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-05T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[]),
            tools=tool_axis_mod.ToolAxis(tools_ran={"roslyn-secguard", "bandit"}),
        ))
        self.assertEqual(r["meta"]["coverage"]["build_executing_tools"], ["roslyn-secguard"])

    def test_build_executing_tools_falls_back_without_tools_ran(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-05T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[self._tool(source="tool:roslyn-secguard")]),
        ))
        self.assertEqual(r["meta"]["coverage"]["build_executing_tools"], ["roslyn-secguard"])


class TestToolCoverageCertification(unittest.TestCase):
    """#1031: tool-coverage certification keys on the runner's DETERMINISTIC
    adapter manifest (selected/produced/missing), not the scout's advisory tool
    list. A scout naming a tool the runner can't run -> disclosed, never gates."""

    TS = "2026-08-17T00:00:00Z"

    def _div_tools(self, r):
        return r["meta"]["coverage"]["divergence"]["tools"]

    def test_scout_noise_disclosed_not_gating(self):
        # scout named tools with no adapter / inapplicable to the target; every
        # SELECTED adapter produced -> certified, noise only disclosed.
        tm = {
            "selected": ["eslint-security", "semgrep"],
            "produced": ["eslint-security", "semgrep"],
            "missing": [],
            "excluded_scope": [],
        }
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(scout_requested=["bcryptjs", "pip-audit", "eslint"]),
            tools=tool_axis_mod.ToolAxis(manifest=tm),
        ))
        self.assertEqual(
            self._div_tools(r),
            {
                "bcryptjs": "requested_unavailable",
                "pip-audit": "requested_unavailable",
                "eslint": "requested_unavailable",
            },
        )
        self.assertTrue(r["summary"]["coverage_certified"])

    def test_produced_but_unusable_adapter_gates(self):
        # #1512 / Codex BR-02: bandit was selected and wrote bytes, so the
        # manifest calls it produced with nothing missing -- but ingestion could
        # not parse those bytes. Deriving coverage from the manifest alone
        # certified a scanner that never delivered a finding it could read.
        tm = {"selected": ["bandit", "gitleaks"],
              "produced": ["bandit", "gitleaks"], "missing": [], "excluded_scope": []}
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(scout_requested=[]),
            tools=tool_axis_mod.ToolAxis(
                manifest=tm, tools_ran={"gitleaks"},
                dispositions={"bandit": {"status": "failed", "findings": 0,
                                         "reason": "unparseable: x"},
                              "gitleaks": {"status": "ok", "findings": 1}}),
        ))
        self.assertEqual(self._div_tools(r), {"bandit": "produced_unusable"})
        self.assertFalse(r["summary"]["coverage_certified"])
        self.assertEqual(r["summary"]["gate"], "INCONCLUSIVE")
        # the reason stays legible in the artifact, not just the label
        self.assertIn("unparseable",
                      r["meta"]["coverage"]["adapters"]["bandit"]["reason"])

    def test_unusable_gates_while_noscan_beside_it_does_not(self):
        # The two #1512 / #1335 verdicts must not collapse into each other: one
        # is lost coverage an operator can act on, the other is a no-surface
        # disclosure. Same run, same manifest, different outcomes.
        tm = {"selected": ["bandit", "semgrep"],
              "produced": ["bandit", "semgrep"], "missing": [], "excluded_scope": []}
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(scout_requested=[]),
            tools=tool_axis_mod.ToolAxis(
                manifest=tm, tools_ran=set(),
                dispositions={"bandit": {"status": "failed", "findings": 0,
                                         "reason": "unparseable: x"},
                              "semgrep": {"status": "noscan", "findings": 0}}),
        ))
        self.assertEqual(self._div_tools(r),
                         {"bandit": "produced_unusable", "semgrep": "produced_noscan"})
        self.assertFalse(r["summary"]["coverage_certified"])

    def test_a_manifest_without_ingestion_keeps_the_1031_behaviour(self):
        # --no-tools / no --tools-dir: there are no dispositions to judge
        # usability with. Inferring "unusable" from their absence would fail
        # every selected adapter on a run that never ingested.
        tm = {"selected": ["bandit"], "produced": ["bandit"], "missing": [],
              "excluded_scope": []}
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(scout_requested=[]),
            tools=tool_axis_mod.ToolAxis(manifest=tm),
        ))
        self.assertEqual(self._div_tools(r), {})
        self.assertTrue(r["summary"]["coverage_certified"])

    def test_real_missing_adapter_gates(self):
        # a SELECTED adapter that didn't produce is a real coverage loss ->
        # requested_absent -> not certified, even if the scout never named it.
        tm = {
            "selected": ["eslint-security", "npm-audit"],
            "produced": ["eslint-security"],
            "missing": ["npm-audit"],
            "excluded_scope": [],
        }
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(scout_requested=[]),
            tools=tool_axis_mod.ToolAxis(manifest=tm),
        ))
        self.assertEqual(self._div_tools(r), {"npm-audit": "requested_absent"})
        self.assertFalse(r["summary"]["coverage_certified"])

    def test_scout_wanted_a_real_missing_adapter_still_gates(self):
        # the scout named a selected-but-unproduced adapter: it's a real gap.
        tm = {
            "selected": ["npm-audit"],
            "produced": [],
            "missing": ["npm-audit"],
            "excluded_scope": [],
        }
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(scout_requested=["npm-audit", "bcryptjs"]),
            tools=tool_axis_mod.ToolAxis(manifest=tm),
        ))
        self.assertEqual(
            self._div_tools(r),
            {"npm-audit": "requested_absent", "bcryptjs": "requested_unavailable"},
        )
        self.assertFalse(r["summary"]["coverage_certified"])

    def test_manifest_absent_uses_legacy_scout_gate(self):
        # no manifest -> unchanged 4.x behavior (scout_requested - produced).
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(scout_requested=["eslint"]),
            tools=tool_axis_mod.ToolAxis(tools_ran=[]),
        ))
        self.assertEqual(self._div_tools(r), {"eslint": "requested_absent"})
        self.assertFalse(r["summary"]["coverage_certified"])


class TestToolCleanupCoverage(unittest.TestCase):
    def _report(self, cleanup=None):
        manifest = {"selected": ["semgrep"], "produced": [],
                    "missing": ["semgrep"], "excluded_scope": []}
        if cleanup is not None:
            manifest["cleanup_failures"] = cleanup
        return report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high",
                                     timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=[]),
            tools=tool_axis_mod.ToolAxis(manifest=manifest),
        ))

    def test_cleanup_failure_reaches_coverage_without_changing_timeout_gate(self):
        row = {"semgrep": {
            "kind": "kill_failed",
            "detail": "docker kill exited 125 — daemon unavailable",
        }}
        report = self._report(row)
        self.assertEqual(
            report["meta"]["coverage"]["tools_cleanup_failures"], row)
        self.assertEqual(report["summary"]["gate"], "INCONCLUSIVE")
        self.assertEqual(
            report["meta"]["coverage"]["divergence"]["tools"],
            {"semgrep": "requested_absent"},
        )

    def test_legacy_manifest_adds_no_cleanup_claim(self):
        report = self._report()
        self.assertNotIn("tools_cleanup_failures", report["meta"]["coverage"])


class TestPanelsWithScannerContext(unittest.TestCase):
    """#1637 P08 ruling 5: run-13 dispatched 85 panels after the tool scan had
    silently skipped, and the report never said so. `meta.tools
    .panels_with_scanner_context` is that fact, counted off the per-cell tally
    the review phase persists as it renders each prompt."""

    def _report(self, tally):
        return report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on="high",
                                     timestamp=DEFAULT_TIMESTAMP,
                                     panel_tools_context=tally),
            findings=findings_mod.FindingSet(findings=[])))

    def test_meta_tools_reports_the_split(self):
        meta = self._report({"with": 3, "without": 82})["meta"]
        self.assertEqual(meta["tools"]["panels_with_scanner_context"],
                         {"with": 3, "without": 82})

    def test_a_run_that_dispatched_no_panel_reports_zeroes(self):
        meta = self._report({})["meta"]
        self.assertEqual(meta["tools"]["panels_with_scanner_context"],
                         {"with": 0, "without": 0})

    def test_the_tally_is_loaded_from_the_run_folder(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "panel-tools-context.json"), "w",
                      encoding="utf-8") as fh:
                json.dump({"schema_version": 1,
                           "cells": {"A/SEC": True, "A/DAT": False,
                                     "B/SEC": False}}, fh)
            self.assertEqual(plan_mod.load_panel_tools_context(d),
                             {"with": 1, "without": 2})

    def test_an_absent_or_corrupt_tally_reads_as_nothing_measured(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(plan_mod.load_panel_tools_context(d),
                             {"with": 0, "without": 0})
            with open(os.path.join(d, "panel-tools-context.json"), "w",
                      encoding="utf-8") as fh:
                fh.write("{ not json")
            self.assertEqual(plan_mod.load_panel_tools_context(d),
                             {"with": 0, "without": 0})

    def test_the_schema_declares_the_field(self):
        with open(os.path.join(validate_schema_mod.REFERENCE_DIR,
                               validate_schema_mod.REPORT_SCHEMA), encoding="utf-8") as fh:
            schema = json.load(fh)
        block = schema["properties"]["meta"]["properties"]["tools"]
        self.assertIn("panels_with_scanner_context", block["properties"])


class TestUnplaceableToolFindings(unittest.TestCase):
    @staticmethod
    def _finding(fid, source, file_name, tool_evidence):
        return _make_finding(
            id=fid, source=source,
            location={"file": file_name, "line_start": 1},
            tool_evidence=tool_evidence)

    @staticmethod
    def _report(findings, **finding_set):
        return report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on="high",
                                     timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(
                findings=findings, **finding_set)))

    def test_meta_tools_counts_each_active_unplaceable_adapter(self):
        findings = [
            self._finding("SB-001", "tool:spotbugs", "a.java",
                          {"rule_id": "SB-A", "path_resolution": "unresolved"}),
            self._finding("SB-002", "tool:spotbugs", "b.java",
                          {"rule_id": "SB-B", "path_resolution": "unresolved"}),
            self._finding("SG-001", "tool:semgrep", "c.py",
                          {"rule_id": "SG-A", "path_resolution": "unresolved"}),
            self._finding("SB-003", "tool:spotbugs", "d.java",
                          {"rule_id": "SB-C"}),
            self._finding("AG-001", "agent:panel_review", "e.py",
                          {"path_resolution": "unresolved"}),
            self._finding("SB-004", "tool:spotbugs", "f.java", "malformed"),
        ]
        self.assertEqual(
            self._report(findings)["meta"]["tools"]["unplaceable"],
            {"spotbugs": 2, "semgrep": 1})

    def test_a_rejected_finding_is_not_counted(self):
        finding = self._finding(
            "SB-001", "tool:spotbugs", "a.java",
            {"rule_id": "SB-A", "path_resolution": "unresolved"})
        prepared, _ = corroborate_mod.prepare_for_queue([finding])
        queue, _ = evidence_mod.build_verify_queue(prepared)
        (entry,) = queue
        verdicts = {entry["queue_id"]: {
            "verdict": "REJECTED", "finding_id": finding["id"],
            "reasoning": "the bytecode belongs to another source tree"}}
        report = self._report([finding], verdicts=verdicts,
                              verdicts_supplied=True)
        self.assertEqual(report["meta"]["tools"]["unplaceable"], {})
        self.assertEqual(len(report["discarded_claims"]), 1)

    def test_the_schema_declares_the_count_map(self):
        with open(os.path.join(validate_schema_mod.REFERENCE_DIR,
                               validate_schema_mod.REPORT_SCHEMA), encoding="utf-8") as fh:
            schema = json.load(fh)
        block = schema["properties"]["meta"]["properties"]["tools"]["properties"]
        self.assertEqual(block["unplaceable"]["type"], "object")
        self.assertEqual(block["unplaceable"]["additionalProperties"]["type"],
                         "integer")
        self.assertTrue(block["unplaceable"]["description"])


class TestSanitizedRequirementLinesReachTheReport(unittest.TestCase):
    """#1646 ruling 3: pip-audit is handed a GENERATED requirements list, so the
    dependency audit can be PARTIAL. The manifest records what was dropped; the
    report has to carry it, or an operator reads "pip-audit: produced" and
    believes every declared dependency was checked."""

    _BLOCK = {"pip-audit": {"source": "requirements.txt", "kept": 2,
                            "dropped": [{"line": "-e .", "reason": "editable"},
                                        {"line": "./v/p", "reason": "local path"}],
                            "hashes_stripped": False}}

    def _meta(self, manifest):
        return report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on="high",
                                     timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=[]),
            tools=tool_axis_mod.ToolAxis(manifest=manifest)))["meta"]

    def test_meta_tools_carries_the_manifest_block(self):
        meta = self._meta({"schema_version": 1, "selected": [], "produced": [],
                           "sanitized": self._BLOCK})
        self.assertEqual(meta["tools"]["sanitized"], self._BLOCK)

    def test_a_run_with_no_manifest_says_nothing_rather_than_nothing_dropped(self):
        self.assertEqual(self._meta(None)["tools"]["sanitized"], {})

    def test_a_hostile_manifest_block_is_repaired_not_carried(self):
        with contextlib.redirect_stderr(io.StringIO()):
            meta = self._meta({"schema_version": 1, "selected": [], "produced": [],
                               "sanitized": {"pip-audit": {"kept": "lots"},
                                             "npm-audit": "nope"}})
        self.assertEqual(meta["tools"]["sanitized"], {"pip-audit": {}})

    def test_the_schema_declares_the_field(self):
        with open(os.path.join(validate_schema_mod.REFERENCE_DIR,
                               validate_schema_mod.REPORT_SCHEMA), encoding="utf-8") as fh:
            schema = json.load(fh)
        block = schema["properties"]["meta"]["properties"]["tools"]
        self.assertIn("sanitized", block["properties"])
        row = block["properties"]["sanitized"]["additionalProperties"]
        self.assertEqual(sorted(row["properties"]),
                         ["dropped", "dropped_truncated", "hashes_stripped",
                          "kept", "source", "truncated"])
        # N8: every reason the sanitizer can emit is named in the description,
        # `include` and `archive name` included -- both reach the manifest.
        reason = row["properties"]["dropped"]["items"]["properties"]["reason"]
        for token in ("editable", "local path", "archive name", "vcs url",
                      "direct url", "option line", "include",
                      "include outside target", "nested include",
                      "include unreadable", "unparseable"):
            self.assertIn(token, reason["description"], token)


class TestAMidRunToolsDowngradeIsDisclosed(unittest.TestCase):
    """#1637 P08 F2: `--no-tools` rescues a run whose scanner environment
    moved, instead of `--reset` discarding every paid scout. It is a real
    downgrade of what this run's reviewers were shown, so the report says so
    rather than reading like a run that simply never had tools."""

    def _meta(self, **kw):
        return report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on="high",
                                     timestamp=DEFAULT_TIMESTAMP, **kw),
            findings=findings_mod.FindingSet(findings=[])))["meta"]

    def test_the_flag_reaches_meta_tools(self):
        self.assertIs(self._meta(tools_disabled_mid_run=True)
                      ["tools"]["disabled_mid_run"], True)

    def test_an_ordinary_run_says_so_explicitly(self):
        self.assertIs(self._meta()["tools"]["disabled_mid_run"], False)

    def test_the_schema_declares_it(self):
        with open(os.path.join(validate_schema_mod.REFERENCE_DIR,
                               validate_schema_mod.REPORT_SCHEMA), encoding="utf-8") as fh:
            schema = json.load(fh)
        block = schema["properties"]["meta"]["properties"]["tools"]
        self.assertIn("disabled_mid_run", block["properties"])


class TestSuppressedToolFindingsCoverage(unittest.TestCase):
    """#1578: `meta.coverage.tools_suppressed` -- what the vendored-path
    exclusion dropped, per segment.

    The exclusion earns its keep (592 of solidus's 623 eslint-security messages
    were bundled jQuery under `vendor/`), and it stays. What does not stay is
    the provenance-free, disclosure-free form of it: a directory NAME dropped
    a finding from the report with nothing but an aggregate stderr line to
    say so, so a real vendored library and an evasion were indistinguishable.
    """

    # #1839: one manifest row per reserved scan-skip class -- a virtualenv the
    # RUNNER was told to skip, which produced no finding for the tally above to
    # count and no other artifact that says the tree left the scan.
    _SKIPPED = {"excluded_dirs": [
        {"path": ".venv", "reason": "pyvenv.cfg", "skipped": True},
        {"path": "venv", "reason": "name", "skipped": True},
        {"path": "src", "reason": "pyvenv.cfg-without-shape", "skipped": False}]}

    def _coverage(self, suppressed, manifest=None):
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on="high",
                                     timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=[]),
            tools=tool_axis_mod.ToolAxis(suppressed=suppressed,
                                         manifest=manifest)))
        return report["meta"]["coverage"]

    def test_the_directories_the_scan_skipped_join_the_tally(self):
        # #1839: both reserved classes, counted as DIRECTORIES beside the
        # finding counts, because a scan that never entered the tree produced no
        # finding to count -- and a key that names a CLASS is the signal that
        # its number is directories.
        self.assertEqual(
            {"vendor": 1, "virtualenv-by-marker": 1, "virtualenv-by-name": 1},
            self._coverage({"vendor": 1}, self._SKIPPED)["tools_suppressed"])

    def test_the_scan_side_rows_cross_the_same_bound_as_their_siblings(self):
        # Review round 1 N2: this tally's comment said the scan-side counts were
        # "repaired like their siblings" while the merge happened AFTER the
        # repair -- so they crossed no boundary at all, and a tally already at
        # `ROWS_MAX` published one row more than the bound this key documents.
        rows = {"pyvenv.cfg:v%03d" % n: 1 for n in range(repair_mod.ROWS_MAX)}
        with contextlib.redirect_stderr(io.StringIO()):
            cov = self._coverage(rows, self._SKIPPED)
        self.assertEqual(len(cov["tools_suppressed"]), repair_mod.ROWS_MAX)

    def test_the_counts_reach_the_report_per_segment(self):
        self.assertEqual({"vendor": 592, "node_modules": 3},
                         self._coverage({"vendor": 592,
                                         "node_modules": 3})["tools_suppressed"])

    def test_a_run_that_suppressed_nothing_reports_an_empty_map(self):
        # Stated on every report, `{}` included -- the same rule the sibling
        # disclosures follow: an absent key makes "nothing was dropped" and
        # "nobody counted" the same document.
        self.assertEqual({}, self._coverage(None)["tools_suppressed"])

    def test_a_malformed_tally_is_repaired_at_the_boundary(self):
        # The counts are derived from `location.file` values a scanner read out
        # of the reviewed tree, so the key is repaired rather than trusted; a
        # bad row must never cost the run an `artifact invalid` exit.
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual({"vendor": 1},
                             self._coverage({"vendor": 1,
                                             "node_modules": "lots"})["tools_suppressed"])

    def test_the_gate_is_unchanged_by_the_disclosure(self):
        # Report-side suppression STAYS -- this key discloses it, it does not
        # re-gate it. The redteam no-loss rule lives in `security_gate`, which
        # is the gate that blocks a merge.
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on="high",
                                     timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=[]),
            tools=tool_axis_mod.ToolAxis(suppressed={"vendor": 9})))
        self.assertEqual(report["summary"]["gate"], "PASS")
