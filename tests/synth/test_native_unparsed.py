"""#3611 report/certification behavior for native Semgrep parser gaps."""
import json
import os
import tempfile
import unittest

from scripts import native_unparsed
from scripts import html_report
from scripts.synth import findings as findings_mod
from scripts.synth import coverage_io
from scripts.synth import plan
from scripts.synth import report
from scripts.synth import render
from scripts.synth import tool_axis


class NativeUnparsedReportTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def _write(self, rel, body="x\n"):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path) or self.root, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)

    def _facts(self, paths):
        rows = [{"file": path, "reason": "syntax_error", "syntax_errors": 1,
                 "rules": [], "rules_omitted": 0, "rule_scope": "all_applicable"}
                for path in paths]
        facts = {
            "status": "partial", "parsed_files": 0, "unparsed_files": len(paths),
            "unavailable_files": 0, "files": rows, "files_omitted": 0,
            "capabilities_unavailable": [], "rule_timeouts": 0,
            "syntax_errors": len(paths), "syntax_error_files": len(paths),
            "size_skipped": 0, "size_limit": 1_000_000, "size_listing": "listed",
            "unlocated_records": 0,
        }
        facts.update(native_unparsed.producer_facts(self.root, paths))
        return facts

    def _cell(self, group, targets=None):
        path = os.path.join(self.root, "findings-%s-SEC.json" % group)
        payload = {"schema_version": 1, "findings": [], "_panopticon": {
            "run_id": "R", "role": "domain_panel", "group": group, "domain": "SEC"}}
        if targets is not None:
            payload["targeted_review"] = targets
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        return path

    def _report(self, paths, *, group="Web", group_files=None, attestation=None,
                plan_targets=None, include_cell=True, facts=None):
        groups = [{"name": group, "files": list(
            paths if group_files is None else group_files)}]
        entry = {"group": group, "domain": "SEC",
                 "out_file": os.path.join(self.root, "findings-%s-SEC.json" % group)}
        if plan_targets is not None:
            entry["targeted_review"] = plan_targets
        cell = self._cell(group, attestation) if include_cell else None
        dispositions = {"semgrep": {"status": "empty", "findings": 0,
                                      "file_coverage": facts or self._facts(paths)}}
        return report.build_report(report.ReportInputs(
            run=report.RunConfig(target=self.root, root=self.root, fail_on="high",
                                 timestamp="2026-11-13T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan.PlanInputs(groups_meta=groups, dispatch_entries=[entry]),
            tools=tool_axis.ToolAxis(
                tools_ran={"semgrep"}, dispositions=dispositions,
                ingested_paths=[cell] if cell else [])))

    def test_one_native_file_certifies_after_exact_sec_review(self):
        self._write("src/broken.js")
        result = self._report(
            ["src/broken.js"], attestation=["src/broken.js"],
            plan_targets=["src/broken.js"])
        self.assertTrue(result["summary"]["coverage_certified"])
        targeted = result["meta"]["coverage"]["targeted_review"]
        self.assertEqual(targeted["files"][0]["covered_by"], [["Web", "SEC"]])
        self.assertIn("src/broken.js", result["summary"]["coverage_note"])
        self.assertIn("src/broken.js", render.render_summary(result))
        self.assertIn("Web/SEC", render.render_summary(result))
        html = html_report.render(result)
        self.assertIn("Targeted manual security review", html)
        self.assertIn("Web/SEC", html)

    def test_failed_or_malformed_sec_cell_decertifies_and_names_file(self):
        self._write("src/broken.js")
        for include_cell, attestation in ((False, None), (True, None),
                                          (True, ["src/other.js"])):
            with self.subTest(include_cell=include_cell, attestation=attestation):
                result = self._report(
                    ["src/broken.js"], include_cell=include_cell,
                    attestation=attestation, plan_targets=["src/broken.js"])
                self.assertFalse(result["summary"]["coverage_certified"])
                self.assertEqual(result["summary"]["gate"], "INCONCLUSIVE")
                self.assertIn("src/broken.js", result["summary"]["coverage_note"])

    def test_out_of_delta_native_gap_is_warning_only(self):
        self._write("src/changed.py")
        self._write("scripts/deploy.sh", "#!/bin/sh\nexit 0\n")
        result = self._report(
            ["scripts/deploy.sh"], group_files=["src/changed.py"],
            attestation=None, plan_targets=None,
        )
        self.assertTrue(result["summary"]["coverage_certified"])
        targeted = result["meta"]["coverage"]["targeted_review"]
        self.assertEqual(targeted["native_unparsed"], 0)
        self.assertEqual(targeted["out_of_scope"]["files"], [
            {"file": "scripts/deploy.sh", "language": "Shell"}
        ])
        self.assertIn("scripts/deploy.sh", result["summary"]["coverage_note"])
        self.assertIn("outside this run's reviewed universe", render.render_summary(result))

    def test_pruned_fixture_native_gap_is_warning_only(self):
        self._write("src/app.js")
        self._write("testdata/broken.js")
        result = self._report(
            ["testdata/broken.js"], group_files=["src/app.js"],
            attestation=None, plan_targets=None,
        )
        self.assertTrue(result["summary"]["coverage_certified"])
        targeted = result["meta"]["coverage"]["targeted_review"]
        self.assertEqual(targeted["out_of_scope"]["count"], 1)
        self.assertFalse(targeted["over_cap"])

    def test_missing_or_rejected_groups_inventory_sinks_native_membership(self):
        self._write("src/broken.js")
        dispositions = {"semgrep": {
            "status": "empty", "findings": 0,
            "file_coverage": self._facts(["src/broken.js"]),
        }}
        result = report.build_report(report.ReportInputs(
            run=report.RunConfig(target=self.root, root=self.root, fail_on="high",
                                 timestamp="2026-11-13T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan.PlanInputs(groups_meta=[], groups_valid=False),
            tools=tool_axis.ToolAxis(
                tools_ran={"semgrep"}, dispositions=dispositions,
                ingested_paths=[]),
        ))
        self.assertFalse(result["summary"]["coverage_certified"])
        self.assertIn("reviewed-universe membership is unknown",
                      result["summary"]["coverage_note"])
        targeted = result["meta"]["coverage"]["targeted_review"]
        self.assertEqual(targeted["out_of_scope"]["count"], 0)

    def test_valid_empty_groups_inventory_keeps_native_rows_warning_only(self):
        self._write("src/broken.js")
        dispositions = {"semgrep": {
            "status": "empty", "findings": 0,
            "file_coverage": self._facts(["src/broken.js"]),
        }}
        result = report.build_report(report.ReportInputs(
            run=report.RunConfig(target=self.root, root=self.root, fail_on="high",
                                 timestamp="2026-11-13T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan.PlanInputs(groups_meta=[]),
            tools=tool_axis.ToolAxis(
                tools_ran={"semgrep"}, dispositions=dispositions,
                ingested_paths=[]),
        ))
        self.assertTrue(result["summary"]["coverage_certified"])
        self.assertEqual(
            result["meta"]["coverage"]["targeted_review"]["out_of_scope"]["count"],
            1,
        )

    def test_in_scope_uncovered_gap_still_sinks(self):
        self._write("src/broken.js")
        result = self._report(
            ["src/broken.js"], include_cell=False,
            plan_targets=["src/broken.js"],
        )
        self.assertFalse(result["summary"]["coverage_certified"])
        self.assertIn("not covered", result["summary"]["coverage_note"])

    def test_broken_markdown_is_warning_only(self):
        self._write("README.md")
        result = self._report(["README.md"], group="Docs")
        self.assertTrue(result["summary"]["coverage_certified"])
        self.assertNotIn("targeted_review", result["meta"]["coverage"])
        self.assertIn("README.md", result["summary"]["coverage_note"])

    def test_extensionless_bash_file_is_targeted_as_shell(self):
        self._write("bin/launch", "#!/usr/bin/env bash\necho ready\n")
        result = self._report(
            ["bin/launch"], attestation=["bin/launch"], plan_targets=["bin/launch"])
        targeted = result["meta"]["coverage"]["targeted_review"]
        self.assertEqual(targeted["files"][0]["language"], "Shell")
        self.assertTrue(result["summary"]["coverage_certified"])

    def test_twenty_one_native_files_sink_without_reviewer_dispatch(self):
        paths = ["src/f%02d.js" % i for i in range(21)]
        for path in paths:
            self._write(path)
        result = self._report(paths, attestation=None, plan_targets=None)
        targeted = result["meta"]["coverage"]["targeted_review"]
        self.assertEqual((targeted["native_unparsed"], targeted["cap"],
                          targeted["over_cap"]), (21, 20, True))
        self.assertTrue(all(not row["dispatched_to"] for row in targeted["files"]))
        self.assertFalse(result["summary"]["coverage_certified"])
        self.assertIn("21 > 20", result["summary"]["coverage_note"])

    def test_twenty_native_files_certify_when_one_sec_cell_attests_every_path(self):
        paths = ["src/f%02d.js" % i for i in range(20)]
        for path in paths:
            self._write(path)
        result = self._report(paths, attestation=paths, plan_targets=paths)
        targeted = result["meta"]["coverage"]["targeted_review"]
        self.assertEqual((targeted["native_unparsed"], targeted["cap"],
                          targeted["over_cap"]), (20, 20, False))
        self.assertTrue(all(row["covered_by"] == [["Web", "SEC"]]
                            for row in targeted["files"]))
        self.assertTrue(result["summary"]["coverage_certified"])

    def test_consumer_rejects_forged_native_classification(self):
        self._write("src/broken.js")
        facts = self._facts(["src/broken.js"])
        facts["native_syntax"][0]["language"] = "Python"
        result = self._report(["src/broken.js"], facts=facts)
        self.assertFalse(result["summary"]["coverage_certified"])
        self.assertIn("classification facts are missing or invalid",
                      result["summary"]["coverage_note"])

    def test_malformed_findings_file_cannot_attest_with_a_correct_echo(self):
        path = self._cell("Web", ["src/broken.js"])
        with open(path, encoding="utf-8") as fh:
            payload = json.load(fh)
        payload["findings"] = "not a findings list"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        self.assertEqual(coverage_io.targeted_review_attestations([path]), {})

    def test_findings_stamp_must_name_the_filename_cell(self):
        path = self._cell("Web", ["src/broken.js"])
        with open(path, encoding="utf-8") as fh:
            payload = json.load(fh)
        payload["_panopticon"]["group"] = "Other"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        self.assertEqual(coverage_io.targeted_review_attestations([path]), {})

    def test_renderers_ignore_non_integer_omitted_counts(self):
        value = {
            "files": [{"file": "src/broken.js", "language": "JavaScript",
                       "covered_by": [["Web", "SEC"]]}],
            "files_omitted": "many",
            "out_of_scope": {
                "files": [{"file": "testdata/broken.js", "language": "JavaScript"}],
                "files_omitted": "also many",
            },
        }
        line = render._targeted_review_line(value)
        self.assertIn("src/broken.js", line)
        self.assertIn("testdata/broken.js", line)
        self.assertNotIn("more omitted", line)
        html = html_report._render_targeted_review(
            {"coverage": {"targeted_review": value}})
        self.assertIn("src/broken.js", html)
        self.assertIn("testdata/broken.js", html)
        self.assertNotIn("more omitted", html)

    def test_html_escapes_out_of_scope_file_names(self):
        value = {
            "files": [], "files_omitted": 0,
            "out_of_scope": {
                "files": [{"file": "<b>x.js", "language": "JavaScript"}],
                "files_omitted": 0,
            },
        }
        html = html_report._render_targeted_review(
            {"coverage": {"targeted_review": value}})
        self.assertIn("&lt;b&gt;x.js", html)
        self.assertNotIn("<code><b>x.js", html)
