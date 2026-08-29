import json
import unittest
from unittest import mock

from _test_helpers import FakePopen, first
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
        self.assertEqual(len(findings), 1)
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
        self.assertEqual(len(findings), 1)
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

    def test_parse_includes_provenance(self):
        findings = na.NpmAuditAdapter().parse(NPM_AUDIT_SAMPLE, "g1")
        self.assertTrue(findings)
        self.assertEqual(first(findings)["provenance"]["discovered_by"], "tool:npm-audit")
        self.assertEqual(first(findings)["provenance"]["confirmation_status"], "TOOL")

    def test_invoke_runs_npm_audit_json(self):
        adapter = na.NpmAuditAdapter()
        fake_run = FakePopen(stdout=b"{}", stderr=b"", returncode=0)
        with mock.patch("scripts.tools.base.subprocess.Popen",
                        return_value=fake_run) as popen_mock:
            stdout, rc = adapter.invoke("/tmp/fake")
        self.assertEqual(stdout, b"{}")
        self.assertEqual(rc, 0)
        popen_mock.assert_called_once_with(
            ["npm", "audit", "--json", "--prefix", "/tmp/fake"],
            stdout=mock.ANY,
            stderr=mock.ANY,
        )

    def test_invoke_reports_nonzero_exit(self):
        import contextlib, io
        adapter = na.NpmAuditAdapter()
        fake_run = FakePopen(stdout=b"audit output", stderr=b"npm audit failed",
                             returncode=2)
        buf = io.StringIO()
        with mock.patch("scripts.tools.base.subprocess.Popen", return_value=fake_run), \
             contextlib.redirect_stderr(buf):
            stdout, rc = adapter.invoke("/tmp/fake")
        self.assertEqual(stdout, b"audit output")
        self.assertEqual(rc, 2)
        self.assertIn("tool npm exited 2", buf.getvalue())
        self.assertIn("npm audit failed", buf.getvalue())

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
        self.assertEqual(first(findings)["severity"], "MEDIUM")

    def test_parse_omits_none_tool_evidence_fields_v1(self):
        sample = json.dumps({
            "advisories": {
                "1234": {
                    "id": 1234,
                    "title": "Prototype Pollution in lodash",
                    "module_name": "lodash",
                    "overview": "...",
                    "severity": "high",
                    "cves": ["CVE-2021-23337"],
                    "vulnerable_versions": "<4.17.21",
                }
            }
        }).encode()
        findings = na.NpmAuditAdapter().parse(sample, "g1")
        self.assertEqual(len(findings), 1)
        evidence = findings[0]["tool_evidence"]
        self.assertNotIn("fixed_version", evidence)
        self.assertEqual(evidence["rule_id"], "1234")

    def test_parse_omits_none_tool_evidence_fields_v2(self):
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
                    "fixAvailable": False,
                }
            }
        }).encode()
        findings = na.NpmAuditAdapter().parse(sample, "g1")
        self.assertEqual(len(findings), 1)
        evidence = findings[0]["tool_evidence"]
        self.assertNotIn("fixed_version", evidence)
        self.assertEqual(evidence["rule_id"], "1234")

    def test_parse_empty_findings(self):
        findings = na.NpmAuditAdapter().parse(b"{}", "g1")
        self.assertEqual(findings, [])
        findings = na.NpmAuditAdapter().parse(b'{"advisories": {}}', "g1")
        self.assertEqual(findings, [])
        findings = na.NpmAuditAdapter().parse(b'{"vulnerabilities": {}}', "g1")
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
