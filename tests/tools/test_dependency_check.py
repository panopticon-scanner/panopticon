import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, "skill"))
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
