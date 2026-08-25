import contextlib
import io
import json
import unittest
from unittest import mock

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

    def test_confidence_and_cwe_mappings(self):
        adapter = br.BrakemanAdapter()
        test_cases = [
            ("Cross-Site Scripting", "Medium", "LIKELY", "CWE-79"),
            ("Command Injection", "Low", "POSSIBLE", "CWE-78"),
            ("Redirect", "High", "CERTAIN", "CWE-601"),
            ("Dangerous Eval", "High", "CERTAIN", "CWE-94"),
            ("Cross-Site Request Forgery", "Medium", "LIKELY", "CWE-352"),
        ]
        for wt, conf, expected_conf, expected_cwe in test_cases:
            payload = json.dumps({
                "warnings": [{
                    "warning_type": wt,
                    "message": f"Test {wt}",
                    "file": "app/models/user.rb",
                    "line": 10,
                    "confidence": conf,
                    "code": "eval(x)",
                }]
            }).encode()
            findings = adapter.parse(payload, "g1")
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["confidence"], expected_conf)
            self.assertIn(expected_cwe, findings[0]["citations"]["cwe"])

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

    def test_parse_empty_findings(self):
        findings = br.BrakemanAdapter().parse(b"{}", "g1")
        self.assertEqual(findings, [])
        findings = br.BrakemanAdapter().parse(b'{"warnings": []}', "g1")
        self.assertEqual(findings, [])

    def test_invoke_runs_brakeman_json(self):
        adapter = br.BrakemanAdapter()
        fake_run = mock.Mock(return_value=mock.Mock(stdout=b"{}", returncode=0))
        with mock.patch("scripts.tools.base.subprocess.run", fake_run):
            stdout, rc = adapter.invoke("/tmp/fake")
        self.assertEqual(rc, 0)
        fake_run.assert_called_once_with(
            ["brakeman", "--format", "json", "--quiet", "--run-all-checks", "/tmp/fake"],
            capture_output=True, timeout=300,
        )

    def test_invoke_remaps_rc_2_and_3_to_success(self):
        adapter = br.BrakemanAdapter()
        for rc_in in (2, 3):
            fake_run = mock.Mock(return_value=mock.Mock(stdout=b"{}", returncode=rc_in))
            with mock.patch("scripts.tools.base.subprocess.run", fake_run):
                stdout, rc = adapter.invoke("/tmp/fake")
            self.assertEqual(rc, 0, f"rc={rc_in} should be remapped to 0")

    def test_invoke_leaves_rc_4_as_failure(self):
        adapter = br.BrakemanAdapter()
        fake_run = mock.Mock(return_value=mock.Mock(stdout=b"{}", stderr=b"", returncode=4))
        with mock.patch("scripts.tools.base.subprocess.run", fake_run):
            stdout, rc = adapter.invoke("/tmp/fake")
        self.assertEqual(rc, 4)

    def test_new_warning_type_uses_mapped_severity(self):
        # COD-C3B run-7: newly mapped warning types must not silently fall back.
        adapter = br.BrakemanAdapter()
        for wt, expected_sev in (
            ("Path Traversal", "HIGH"),
            ("Weak Hash", "MEDIUM"),
            ("Timing Attack", "LOW"),
            ("Command Injection", "HIGH"),
        ):
            payload = json.dumps({
                "warnings": [{
                    "warning_type": wt,
                    "message": f"Test {wt}",
                    "file": "app/controllers/x.rb",
                    "line": 7,
                    "confidence": "Medium",
                }]
            }).encode()
            findings = adapter.parse(payload, "g1")
            self.assertEqual(findings[0]["severity"], expected_sev, wt)

    def test_unmapped_warning_type_emits_stderr_and_defaults_medium(self):
        adapter = br.BrakemanAdapter()
        payload = json.dumps({
            "warnings": [{
                "warning_type": "Future Mystery Warning",
                "message": "Something new",
                "file": "app/models/y.rb",
                "line": 3,
                "confidence": "High",
            }]
        }).encode()
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            findings = adapter.parse(payload, "g1")
        self.assertEqual(findings[0]["severity"], "MEDIUM")
        self.assertIn("unmapped warning_type 'Future Mystery Warning'", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
