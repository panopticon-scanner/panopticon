import unittest
from unittest import mock

import scripts.tools.bundler_audit as ba

BUNDLE_AUDIT_SAMPLE = b"""
Name: actionpack
Version: 5.2.4.3
CVE: CVE-2020-8164
GHSA: GHSA-8727-m6gj-c7p7
Criticality: High
URL: https://groups.google.com/forum/#!topic/rubyonrails-security/f6ioZMBKU80
Title: Possible Strong Parameters Bypass
Solution: upgrade to ~> 5.2.4.3, >= 6.0.3.1

Name: nokogiri
Version: 1.10.9
CVE: CVE-2020-7595
GHSA: GHSA-755c-xvpm-fw4r
Criticality: Medium
URL: https://github.com/sparklemotion/nokogiri/issues/1996
Title: libxml2 infinite loop in xz_decomp
Solution: upgrade to >= 1.10.8
"""


class TestBundlerAuditAdapter(unittest.TestCase):
    def test_parse_produces_findings(self):
        findings = ba.BundlerAuditAdapter().parse(BUNDLE_AUDIT_SAMPLE, "g1")
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["tool_evidence"]["package_name"], "actionpack")
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertEqual(findings[0]["citations"]["cve"], ["CVE-2020-8164"])
        self.assertEqual(findings[1]["tool_evidence"]["package_name"], "nokogiri")
        self.assertEqual(findings[1]["severity"], "MEDIUM")
        self.assertEqual(findings[1]["citations"]["cve"], ["CVE-2020-7595"])

    def test_is_applicable_when_gemfile_lock_present(self):
        with mock.patch("os.path.exists", side_effect=lambda p: p.endswith("Gemfile.lock")):
            self.assertTrue(ba.BundlerAuditAdapter().is_applicable("/tmp/fake"))

    def test_parse_includes_provenance(self):
        findings = ba.BundlerAuditAdapter().parse(BUNDLE_AUDIT_SAMPLE, "g1")
        self.assertTrue(findings)
        self.assertEqual(findings[0]["provenance"]["discovered_by"], "tool:bundler-audit")
        self.assertEqual(findings[0]["provenance"]["confirmation_status"], "TOOL")

    def test_parse_empty_findings(self):
        findings = ba.BundlerAuditAdapter().parse(b"", "g1")
        self.assertEqual(findings, [])
        findings = ba.BundlerAuditAdapter().parse(b"No vulnerabilities found\n", "g1")
        self.assertEqual(findings, [])

    def test_invoke_runs_bundle_audit(self):
        fake_run = mock.Mock(return_value=mock.Mock(stdout=b"", returncode=0))
        with mock.patch("scripts.tools.base.subprocess.run", fake_run):
            stdout, rc = ba.BundlerAuditAdapter().invoke("/tmp/fake")
        self.assertEqual(rc, 0)
        fake_run.assert_called_once_with(
            ["bundle-audit", "check", "--no-update"],
            capture_output=True, timeout=300, cwd="/tmp/fake",
        )


if __name__ == "__main__":
    unittest.main()

