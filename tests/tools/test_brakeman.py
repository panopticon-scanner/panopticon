import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
import scripts.tools.brakeman as br

BRAKEMAN_SAMPLE = json.dumps({
    "warnings": [
        {
            "warning_type": "SQL Injection",
            "message": "Possible SQL injection",
            "file": "app/controllers/users_controller.rb",
            "line": 12,
            "link": "https://brakemanscanner.org/docs/warning_types/sql_injection/",
            "confidence": "High",
            "code": "User.where(\"id = #{params[:id]}\")",
        }
    ]
}).encode()


class TestBrakemanAdapter(unittest.TestCase):
    def test_parse_produces_finding(self):
        findings = br.BrakemanAdapter().parse(BRAKEMAN_SAMPLE, "g1")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["source"], "tool:brakeman")
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(f["confidence"], "CERTAIN")
        self.assertEqual(f["location"]["file"], "app/controllers/users_controller.rb")
        self.assertEqual(f["location"]["line_start"], 12)
        self.assertIn("CWE-89", f["citations"]["cwe"])

    def test_is_applicable_when_rails_files_present(self):
        with mock.patch("os.path.exists", side_effect=lambda p: p.endswith("Gemfile")):
            self.assertTrue(br.BrakemanAdapter().is_applicable("/tmp/fake"))

    def test_is_applicable_false_without_rails_files(self):
        with mock.patch("os.path.exists", return_value=False):
            with mock.patch("os.path.isdir", return_value=False):
                self.assertFalse(br.BrakemanAdapter().is_applicable("/tmp/fake"))

    def test_parse_includes_provenance(self):
        findings = br.BrakemanAdapter().parse(BRAKEMAN_SAMPLE, "g1")
        self.assertTrue(findings)
        self.assertEqual(findings[0]["provenance"]["discovered_by"], "tool:brakeman")
        self.assertEqual(findings[0]["provenance"]["confirmation_status"], "TOOL")

    def test_invoke_runs_brakeman_json(self):
        adapter = br.BrakemanAdapter()
        fake_run = mock.Mock(return_value=mock.Mock(stdout=b"{}", returncode=0))
        with mock.patch("scripts.tools.brakeman.subprocess.run", fake_run):
            stdout, rc = adapter.invoke("/tmp/fake")
        self.assertEqual(rc, 0)
        fake_run.assert_called_once_with(
            ["brakeman", "--format", "json", "--quiet", "--run-all-checks", "/tmp/fake"],
            capture_output=True, timeout=300,
        )
