import json
import unittest
from unittest import mock

import scripts.tools.dependency_check as dc

DC_SAMPLE = json.dumps({
    "dependencies": [
        {
            "fileName": "spring-core-5.2.0.RELEASE.jar",
            "vulnerabilities": [
                {
                    "name": "CVE-2022-22965",
                    "severity": "HIGH",
                    "cwes": ["CWE-94"],
                    "description": "Spring Framework RCE",
                }
            ],
        }
    ]
}).encode()


class TestDependencyCheckAdapter(unittest.TestCase):
    def test_parse_produces_finding(self):
        findings = dc.DependencyCheckAdapter().parse(DC_SAMPLE, "g1")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["source"], "tool:dependency-check")
        self.assertEqual(f["citations"]["cve"], ["CVE-2022-22965"])
        self.assertEqual(f["citations"]["cwe"], ["CWE-94"])
        self.assertEqual(f["tool_evidence"]["package_name"], "spring-core-5.2.0.RELEASE.jar")

    def test_parse_includes_provenance(self):
        findings = dc.DependencyCheckAdapter().parse(DC_SAMPLE, "g1")
        self.assertTrue(findings)
        self.assertEqual(findings[0]["provenance"]["discovered_by"], "tool:dependency-check")
        self.assertEqual(findings[0]["provenance"]["confirmation_status"], "TOOL")

    def test_normalize_cwe_handles_multiple_formats(self):
        adapter = dc.DependencyCheckAdapter()
        self.assertEqual(adapter._normalize_cwe(94), "CWE-94")
        self.assertEqual(adapter._normalize_cwe("CWE-94"), "CWE-94")
        self.assertEqual(adapter._normalize_cwe("94"), "CWE-94")
        self.assertIsNone(adapter._normalize_cwe("invalid"))

    def test_parse_empty_findings(self):
        findings = dc.DependencyCheckAdapter().parse(b"{}", "g1")
        self.assertEqual(findings, [])
        findings = dc.DependencyCheckAdapter().parse(b'{"dependencies": []}', "g1")
        self.assertEqual(findings, [])

    def test_invoke_uses_noupdate_and_odc_data(self):
        adapter = dc.DependencyCheckAdapter()
        fake_run = mock.Mock(return_value=(b"{}", 0))
        def mock_exists(path):
            return path.endswith("dependency-check-report.json")
        with mock.patch("scripts.tools.dependency_check.run_tool", fake_run):
            with mock.patch("scripts.tools.dependency_check.os.path.exists", side_effect=mock_exists):
                with mock.patch("builtins.open", mock.mock_open(read_data=b"{}")):
                    with mock.patch("shutil.rmtree"):
                        stdout, rc = adapter.invoke("/tmp/fake")
        # Verify the command includes --noupdate and --data /opt/odc-data
        called_cmd = fake_run.call_args[0][0]
        self.assertIn("--noupdate", called_cmd)
        self.assertIn("--data", called_cmd)
        data_idx = called_cmd.index("--data")
        self.assertEqual(called_cmd[data_idx + 1], "/opt/odc-data")

    def test_invoke_fails_closed_when_report_missing(self):
        adapter = dc.DependencyCheckAdapter()
        fake_run = mock.Mock(return_value=(b"", 0))
        with mock.patch("scripts.tools.dependency_check.run_tool", fake_run):
            with mock.patch("scripts.tools.dependency_check.os.path.exists", return_value=False):
                with mock.patch("shutil.rmtree"):
                    stdout, rc = adapter.invoke("/tmp/fake")
        self.assertEqual(stdout, b"")
        self.assertNotEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()

