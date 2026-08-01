import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
import scripts.tools.npm_audit as na

NPM_AUDIT_SAMPLE = json.dumps({
    "advisories": {
        "1234": {
            "id": 1234,
            "title": "Prototype Pollution in lodash",
            "module_name": "lodash",
            "overview": "Versions of lodash before 4.17.21 are vulnerable.",
            "severity": "high",
            "cves": ["CVE-2021-23337"],
            "findings": [{"version": "4.17.20", "paths": ["lodash"]}],
            "vulnerable_versions": "<4.17.21",
            "patched_versions": ">=4.17.21",
            "url": "https://npmjs.com/advisories/1234",
        }
    }
}).encode()


class TestNpmAuditAdapter(unittest.TestCase):
    def test_parse_produces_finding(self):
        findings = na.NpmAuditAdapter().parse(NPM_AUDIT_SAMPLE, "g1")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["source"], "tool:npm-audit")
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(f["citations"]["cve"], ["CVE-2021-23337"])
        self.assertEqual(f["tool_evidence"]["package_name"], "lodash")

    def test_parse_uppercases_cve(self):
        sample = json.dumps({
            "advisories": {
                "1234": {
                    "id": 1234,
                    "title": "Prototype Pollution in lodash",
                    "module_name": "lodash",
                    "overview": "...",
                    "severity": "moderate",
                    "cves": ["cve-2021-23337"],
                    "vulnerable_versions": "<4.17.21",
                    "patched_versions": ">=4.17.21",
                }
            }
        }).encode()
        findings = na.NpmAuditAdapter().parse(sample, "g1")
        self.assertEqual(findings[0]["citations"]["cve"], ["CVE-2021-23337"])

    def test_parse_omits_non_cve_aliases(self):
        sample = json.dumps({
            "advisories": {
                "1234": {
                    "id": 1234,
                    "title": "Prototype Pollution in lodash",
                    "module_name": "lodash",
                    "overview": "...",
                    "severity": "low",
                    "cves": ["CVE-2021-23337", "GHSA-1234"],
                    "vulnerable_versions": "<4.17.21",
                    "patched_versions": ">=4.17.21",
                }
            }
        }).encode()
        findings = na.NpmAuditAdapter().parse(sample, "g1")
        self.assertEqual(findings[0]["citations"]["cve"], ["CVE-2021-23337"])

    def test_is_applicable_when_package_lock_present(self):
        with mock.patch("os.path.isfile", side_effect=lambda p: p.endswith("package-lock.json")):
            self.assertTrue(na.NpmAuditAdapter().is_applicable("/tmp/fake"))

    def test_is_applicable_when_shrinkwrap_present(self):
        with mock.patch("os.path.isfile", side_effect=lambda p: p.endswith("npm-shrinkwrap.json")):
            self.assertTrue(na.NpmAuditAdapter().is_applicable("/tmp/fake"))

    def test_is_applicable_false_when_no_lockfile(self):
        with mock.patch("os.path.isfile", return_value=False):
            self.assertFalse(na.NpmAuditAdapter().is_applicable("/tmp/fake"))

    def test_invoke_runs_npm_audit_json(self):
        adapter = na.NpmAuditAdapter()
        fake_run = mock.Mock(return_value=mock.Mock(stdout=b"{}", returncode=0))
        with mock.patch("scripts.tools.npm_audit.subprocess.run", fake_run):
            stdout, rc = adapter.invoke("/tmp/fake")
        self.assertEqual(stdout, b"{}")
        self.assertEqual(rc, 0)
        fake_run.assert_called_once_with(
            ["npm", "audit", "--json", "--prefix", "/tmp/fake"],
            capture_output=True,
            timeout=300,
        )

    def test_parse_v2_produces_finding(self):
        sample = json.dumps({
            "auditReportVersion": 2,
            "vulnerabilities": {
                "lodash": {
                    "name": "lodash",
                    "severity": "high",
                    "range": "<4.17.21",
                    "via": [{
                        "source": 1234,
                        "name": "lodash",
                        "dependency": "lodash",
                        "title": "Prototype Pollution in lodash",
                        "url": "https://npmjs.com/advisories/1234",
                        "severity": "high",
                        "range": "<4.17.21",
                        "cves": ["CVE-2021-23337"],
                    }],
                    "fixAvailable": {"name": "lodash", "version": "4.17.21"},
                }
            }
        }).encode()
        findings = na.NpmAuditAdapter().parse(sample, "g1")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["source"], "tool:npm-audit")
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(f["citations"]["cve"], ["CVE-2021-23337"])
        self.assertEqual(f["tool_evidence"]["package_name"], "lodash")
        self.assertEqual(f["tool_evidence"]["fixed_version"], "4.17.21")

    def test_parse_v2_skips_string_via_entries(self):
        sample = json.dumps({
            "auditReportVersion": 2,
            "vulnerabilities": {
                "lodash": {
                    "name": "lodash",
                    "severity": "high",
                    "range": "<4.17.21",
                    "via": ["another-package"],
                    "fixAvailable": False,
                }
            }
        }).encode()
        findings = na.NpmAuditAdapter().parse(sample, "g1")
        self.assertEqual(len(findings), 0)

    def test_parse_v2_uses_vuln_severity_when_via_lacks_it(self):
        sample = json.dumps({
            "auditReportVersion": 2,
            "vulnerabilities": {
                "lodash": {
                    "name": "lodash",
                    "severity": "moderate",
                    "range": "<4.17.21",
                    "via": [{
                        "source": 1234,
                        "title": "Prototype Pollution in lodash",
                        "cves": [],
                    }],
                    "fixAvailable": True,
                }
            }
        }).encode()
        findings = na.NpmAuditAdapter().parse(sample, "g1")
        self.assertEqual(findings[0]["severity"], "MEDIUM")


if __name__ == "__main__":
    unittest.main()
