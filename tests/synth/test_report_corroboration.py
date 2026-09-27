"""Cross-panel corroboration and report integration contracts."""

import os
import json
import unittest
import scripts.synth.corroborate as corroborate_mod
import scripts.synth.findings as findings_mod
import scripts.synth.report as report_mod
import scripts.synth.render as render_mod
from tests._test_helpers import SKILL_ROOT
from tests.synth.helpers import DEFAULT_TIMESTAMP


class TestCrossPanelCorroboration(unittest.TestCase):
    """Cross-LENS agreement: the same real issue seen through different panels
    carries DIFFERENT categories by nature (security 'input-validation' vs test
    'test-coverage' vs code 'error-handling'), so it never matches dedupe's
    (file, line, category) key. A separate corroboration pass surfaces that N
    distinct panels independently flagged the same locus, WITHOUT collapsing the
    distinct-lens findings into one."""

    def _f(
        self, fid, panel, category, line, sev="HIGH", conf="POSSIBLE", file="app/resolver.py", **kw
    ):
        base = {
            "id": fid,
            "title": fid,
            "severity": sev,
            "confidence": conf,
            "panel": panel,
            "category": category,
            "location": {"file": file, "line_start": line},
        }
        base.update(kw)
        return base

    def test_different_panels_same_locus_corroborate(self):
        # SEC-701 (security, input-validation) + TST-701 (test, test-coverage)
        # at the SAME file:line, DIFFERENT categories -> corroboration.
        findings = [
            self._f(
                "SEC-701",
                "security",
                "input-validation",
                42,
                cvss={"score": 8.1, "vector": "v"},
                exploit_scenario="e",
            ),
            self._f("TST-701", "test", "test-coverage", 42),
        ]
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=findings),
        ))
        integ = report["cross_panel"]["integration_findings"]
        self.assertEqual(len(integ), 1)
        entry = integ[0]
        self.assertEqual(entry["location"]["file"], "app/resolver.py")
        self.assertEqual(entry["location"]["line_start"], 42)
        self.assertEqual(sorted(entry["panels"]), ["security", "test"])
        self.assertEqual(sorted(entry["finding_ids"]), ["SEC-701", "TST-701"])
        # both distinct-lens findings survive (NOT collapsed into one)
        self.assertEqual(len(report["findings"]), 2)
        self.assertTrue(all(f.get("corroborated") for f in report["findings"]))

    def test_three_lens_agreement(self):
        # security + test + code all converge on one locus, different categories.
        findings = [
            self._f(
                "SE-1",
                "security",
                "input-validation",
                151,
                cvss={"score": 9, "vector": "v"},
                exploit_scenario="e",
            ),
            self._f("TS-1", "test", "test-coverage", 151),
            self._f("CD-1", "code", "error-handling", 151),
        ]
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=findings),
        ))
        integ = report["cross_panel"]["integration_findings"]
        self.assertEqual(len(integ), 1)
        self.assertEqual(sorted(integ[0]["panels"]), ["code", "security", "test"])
        self.assertEqual(len(report["findings"]), 3)  # none collapsed

    def test_negative_different_files_do_not_corroborate(self):
        # Two findings, different panels, but at genuinely different loci
        # (different files) -> NO false corroboration.
        findings = [
            self._f(
                "SE-1",
                "security",
                "input-validation",
                42,
                file="a.py",
                cvss={"score": 8, "vector": "v"},
                exploit_scenario="e",
            ),
            self._f("TS-1", "test", "test-coverage", 42, file="b.py"),
        ]
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=findings),
        ))
        self.assertEqual(report["cross_panel"]["integration_findings"], [])
        self.assertFalse(any(f.get("corroborated") for f in report["findings"]))

    def test_negative_far_apart_lines_do_not_corroborate(self):
        # Same file, different panels, but lines beyond the proximity window
        # -> genuinely different issues, not corroboration.
        findings = [
            self._f(
                "SE-1",
                "security",
                "input-validation",
                10,
                cvss={"score": 8, "vector": "v"},
                exploit_scenario="e",
            ),
            self._f("TS-1", "test", "test-coverage", 90),
        ]
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=findings),
        ))
        self.assertEqual(report["cross_panel"]["integration_findings"], [])

    def test_negative_same_panel_not_cross_panel(self):
        # Two SAME-panel findings at one line are within-lens, not cross-panel
        # corroboration (only ONE distinct panel present at the locus).
        findings = [
            self._f("CD-1", "code", "structure", 5),
            self._f("CD-2", "code", "naming", 5),
        ]
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=findings),
        ))
        self.assertEqual(report["cross_panel"]["integration_findings"], [])
        self.assertFalse(any(f.get("corroborated") for f in report["findings"]))

    def test_proximity_window_adjacent_lines(self):
        # Panels citing adjacent lines (function def at 150, vulnerable call at
        # 151) within CORROBORATION_LINE_WINDOW still corroborate.
        self.assertGreaterEqual(corroborate_mod.CORROBORATION_LINE_WINDOW, 1)
        findings = [
            self._f(
                "SE-1",
                "security",
                "input-validation",
                150,
                cvss={"score": 8, "vector": "v"},
                exploit_scenario="e",
            ),
            self._f("CD-1", "code", "error-handling", 151),
        ]
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=findings),
        ))
        self.assertEqual(len(report["cross_panel"]["integration_findings"]), 1)

    def test_confidence_not_mutated_by_corroboration(self):
        # Amended spec: confidence is never mutated by the pipeline — it is
        # purely the reviewer's self-assessment. Corroboration still annotates
        # `corroborated`/`corroborated_by` but must leave confidence as-is.
        fs = [
            self._f("SE-1", "security", "input-validation", 7, conf="POSSIBLE"),
            self._f("CD-1", "code", "error-handling", 7, conf="CERTAIN"),
        ]
        integ = corroborate_mod.cross_panel_corroboration(fs)
        self.assertEqual(len(integ), 1)
        by_id = {f["id"]: f for f in fs}
        self.assertEqual(by_id["SE-1"]["confidence"], "POSSIBLE")
        self.assertEqual(by_id["CD-1"]["confidence"], "CERTAIN")
        self.assertTrue(by_id["SE-1"]["corroborated"])
        self.assertTrue(by_id["CD-1"]["corroborated"])

    def test_integration_entry_records_max_severity(self):
        integ = corroborate_mod.cross_panel_corroboration(
            [
                self._f("SE-1", "security", "input-validation", 3, sev="CRITICAL"),
                self._f("CD-1", "code", "error-handling", 3, sev="LOW"),
            ]
        )
        self.assertEqual(integ[0]["severity"], "CRITICAL")

    def test_does_not_break_tool_agent_reinforce(self):
        # A tool+agent pair (dedupe collapses -> 1 security finding) plus an
        # independent test finding at the same locus -> the reinforced survivor
        # AND the test finding corroborate cross-panel.
        findings = [
            {
                "id": "SG-1",
                "severity": "HIGH",
                "confidence": "CERTAIN",
                "panel": "security",
                "category": "sqli",
                "source": "tool:semgrep",
                "location": {"file": "db.py", "line_start": 10},
                "citations": {"cwe": [{"id": "CWE-89", "verified": True}]},
            },
            {
                "id": "SE-1",
                "severity": "HIGH",
                "confidence": "LIKELY",
                "panel": "security",
                "category": "sqli",
                "location": {"file": "db.py", "line_start": 10},
                "cvss": {"score": 8, "vector": "v"},
                "exploit_scenario": "e",
            },
            {
                "id": "TS-1",
                "severity": "MEDIUM",
                "confidence": "POSSIBLE",
                "panel": "test",
                "category": "test-coverage",
                "location": {"file": "db.py", "line_start": 10},
            },
        ]
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=findings),
        ))
        secs = [f for f in report["findings"] if f["panel"] == "security"]
        self.assertEqual(len(secs), 1)  # tool+agent still collapsed
        self.assertTrue(secs[0].get("reinforced"))  # reinforce preserved
        self.assertEqual(len(report["cross_panel"]["integration_findings"]), 1)

    def test_summary_renders_corroboration_section(self):
        findings = [
            self._f(
                "SE-1",
                "security",
                "input-validation",
                42,
                cvss={"score": 8, "vector": "v"},
                exploit_scenario="e",
            ),
            self._f("TS-1", "test", "test-coverage", 42),
        ]
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=findings),
        ))
        text = render_mod.render_summary(report)
        self.assertIn("Cross-panel", text)
        self.assertIn("app/resolver.py:42", text)

    def test_schema_defines_integration_finding_items(self):
        ref = os.path.join(SKILL_ROOT, "reference", "report-schema.json")
        with open(ref, encoding="utf-8") as fh:
            schema = json.load(fh)
        items = schema["properties"]["cross_panel"]["properties"]["integration_findings"]["items"]
        self.assertEqual(items["type"], "object")
        self.assertIn("panels", items["properties"])
        self.assertIn("finding_ids", items["properties"])
        # the finding-level corroboration annotations are documented too
        fprops = schema["properties"]["findings"]["items"]["properties"]
        self.assertIn("corroborated", fprops)
        self.assertIn("corroborated_by", fprops)
