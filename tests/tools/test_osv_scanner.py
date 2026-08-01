import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
import scripts.tools.osv_scanner as osv

OSV_SAMPLE = json.dumps({
    "results": [
        {
            "package": {"name": "django", "version": "3.2", "ecosystem": "PyPI"},
            "vulnerabilities": [
                {
                    "id": "GHSA-XXXX-XXXX",
                    "aliases": ["CVE-2022-1234"],
                    "severity": "HIGH",
                    "summary": "SQL injection in Django"
                }
            ]
        }
    ]
}).encode()


MARKERS = [
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "pyproject.toml", "Pipfile.lock",
    "go.mod", "go.sum",
    "Cargo.lock", "Cargo.toml",
    "pom.xml", "build.gradle", "gradle.lockfile",
]


class TestOsvScannerAdapter(unittest.TestCase):
    def test_parse_produces_finding(self):
        findings = osv.OsvScannerAdapter().parse(OSV_SAMPLE, "g1")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["source"], "tool:osv-scanner")
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(f["citations"]["cve"], ["CVE-2022-1234"])
        self.assertEqual(f["tool_evidence"]["package_name"], "django")

    def test_parse_uppercases_cve_and_filters_aliases(self):
        sample = json.dumps({
            "results": [
                {
                    "package": {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"},
                    "vulnerabilities": [
                        {
                            "id": "GHSA-1234-5678",
                            "aliases": ["cve-2021-23337", "GHSA-ABCD-1234"],
                            "severity": "moderate",
                            "summary": "Prototype pollution"
                        }
                    ]
                }
            ]
        }).encode()
        findings = osv.OsvScannerAdapter().parse(sample, "g1")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["citations"]["cve"], ["CVE-2021-23337"])

    def test_is_applicable_detects_each_marker(self):
        adapter = osv.OsvScannerAdapter()
        for marker in MARKERS:
            with tempfile.TemporaryDirectory() as d:
                open(os.path.join(d, marker), "w").close()
                self.assertTrue(adapter.is_applicable(d), f"failed for {marker}")

    def test_is_applicable_false_when_no_marker(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertFalse(osv.OsvScannerAdapter().is_applicable(d))

    def test_invoke_runs_osv_scanner_json(self):
        adapter = osv.OsvScannerAdapter()
        fake_run = mock.Mock(return_value=mock.Mock(stdout=b"{}", returncode=0))
        with mock.patch("scripts.tools.osv_scanner.subprocess.run", fake_run):
            stdout, rc = adapter.invoke("/tmp/fake")
        self.assertEqual(stdout, b"{}")
        self.assertEqual(rc, 0)
        fake_run.assert_called_once_with(
            ["osv-scanner", "--format", "json", "--recursive", "/tmp/fake"],
            capture_output=True,
            timeout=300,
        )

    def test_parse_omits_none_tool_evidence_fields(self):
        sample = json.dumps({
            "results": [
                {
                    "package": {"name": "django"},
                    "vulnerabilities": [
                        {
                            "id": "GHSA-XXXX-XXXX",
                            "aliases": ["CVE-2022-1234"],
                            "severity": "HIGH",
                            "summary": "SQL injection in Django"
                        }
                    ]
                }
            ]
        }).encode()
        findings = osv.OsvScannerAdapter().parse(sample, "g1")
        self.assertEqual(len(findings), 1)
        evidence = findings[0]["tool_evidence"]
        self.assertNotIn("ecosystem", evidence)
        self.assertNotIn("vulnerable_versions", evidence)
        self.assertEqual(evidence["package_name"], "django")


if __name__ == "__main__":
    unittest.main()
