import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "scripts"))
import file_issues


FINDING = {
    "fingerprint": "deadbeefcafe0001",
    "id": "SEC-007",
    "location": {"file": "skill/scripts/run_tools.py", "line_start": 42},
    "severity": "HIGH",
    "evidence": {"status": "advisor_confirmed"},
    "confidence": "LIKELY",
    "description": "example",
}


class TestBodyProvenance(unittest.TestCase):
    def test_defaults_preserve_run2_footer(self):
        """body_for() with no run overrides must still describe run 2, so the
        one existing caller (reconcile_apply's recovery test) and any bare call
        keep working."""
        body = file_issues.body_for(FINDING)
        self.assertIn("self-scan run 2, 2026-08-04", body)
        self.assertIn(file_issues.RUN_STATE_DOC, body)
        self.assertIn(
            "https://github.com/panopticon-scanner/panopticon/blob/main/"
            "docs/superpowers/2026-08-04-self-scan-report.json", body)

    def test_run_overrides_thread_into_footer(self):
        body = file_issues.body_for(
            FINDING,
            report="docs/superpowers/2026-08-08-self-scan-report.json",
            report_url="https://example.test/run3.json",
            run_label="run 3",
            run_date="2026-08-08",
            run_state_doc="docs/superpowers/2026-08-08-self-scan-run-state.md")
        self.assertIn("self-scan run 3, 2026-08-08", body)
        self.assertIn("https://example.test/run3.json", body)
        self.assertIn("docs/superpowers/2026-08-08-self-scan-run-state.md", body)
        self.assertNotIn("run 2, 2026-08-04", body)

    def test_provenance_anchor_lines_are_stable(self):
        """The Fingerprint / Finding id / Location lines are the cross-run
        identity that reconcile recovery parses; parameterizing the report
        provenance must never disturb them."""
        body = file_issues.body_for(FINDING, run_label="run 3", run_date="2026-08-08")
        self.assertIn("**Fingerprint:** `deadbeefcafe0001`", body)
        self.assertIn("**Finding id in report:** `SEC-007`", body)
        self.assertIn("**Location:** `skill/scripts/run_tools.py:42`", body)


if __name__ == "__main__":
    unittest.main()
