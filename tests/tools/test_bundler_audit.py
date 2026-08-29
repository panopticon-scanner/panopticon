import io
import sys
import unittest
from unittest import mock

from _test_helpers import FakePopen, first
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

BUNDLE_AUDIT_JSON_SAMPLE = b"""
{
  "version": "0.9.3",
  "created_at": "2026-08-25 04:03:41 +0000",
  "results": [
    {
      "type": "unpatched_gem",
      "gem": {
        "name": "actionview",
        "version": "8.0.4"
      },
      "advisory": {
        "path": "/root/.local/share/ruby-advisory-db/gems/actionview/CVE-2026-33168.yml",
        "id": "CVE-2026-33168",
        "url": "https://github.com/rails/rails/security/advisories/GHSA-v55j-83pf-r9cq",
        "title": "Rails has a possible XSS vulnerability in its Action View tag helpers",
        "date": "2026-03-23",
        "description": "Possible XSS in Action View tag helpers.",
        "cvss_v2": null,
        "cvss_v3": null,
        "cve": "2026-33168",
        "osvdb": null,
        "ghsa": "v55j-83pf-r9cq",
        "unaffected_versions": [],
        "patched_versions": ["~> 7.2.3, >= 7.2.3.1", "~> 8.0.4, >= 8.0.4.1", ">= 8.1.2.1"],
        "criticality": null
      }
    },
    {
      "type": "unpatched_gem",
      "gem": {
        "name": "activestorage",
        "version": "8.0.4"
      },
      "advisory": {
        "path": "/root/.local/share/ruby-advisory-db/gems/activestorage/CVE-2026-33173.yml",
        "id": "CVE-2026-33173",
        "url": "https://github.com/rails/rails/security/advisories/GHSA-qcfx-2mfw-w4cg",
        "title": "Rails Active Storage has possible content type bypass via metadata in direct uploads",
        "date": "2026-03-23",
        "description": "Content type bypass in Active Storage.",
        "cvss_v2": null,
        "cvss_v3": null,
        "cve": "2026-33173",
        "osvdb": null,
        "ghsa": "qcfx-2mfw-w4cg",
        "unaffected_versions": [],
        "patched_versions": ["~> 7.2.3, >= 7.2.3.1", "~> 8.0.4, >= 8.0.4.1", ">= 8.1.2.1"],
        "criticality": "Medium"
      }
    }
  ]
}
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

    def test_is_applicable_when_gemfile_lock_absent(self):
        with mock.patch("os.path.exists", return_value=False):
            self.assertFalse(ba.BundlerAuditAdapter().is_applicable("/tmp/fake"))

    def test_parse_includes_provenance(self):
        findings = ba.BundlerAuditAdapter().parse(BUNDLE_AUDIT_SAMPLE, "g1")
        self.assertTrue(findings)
        self.assertEqual(first(findings)["provenance"]["discovered_by"], "tool:bundler-audit")
        self.assertEqual(first(findings)["provenance"]["confirmation_status"], "TOOL")

    def test_parse_empty_findings(self):
        findings = ba.BundlerAuditAdapter().parse(b"", "g1")
        self.assertEqual(findings, [])
        findings = ba.BundlerAuditAdapter().parse(b"No vulnerabilities found\n", "g1")
        self.assertEqual(findings, [])

    def test_invoke_runs_bundle_audit(self):
        fake_run = FakePopen(stdout=b"", stderr=b"", returncode=0)
        with mock.patch("scripts.tools.base.subprocess.Popen",
                        return_value=fake_run) as popen_mock:
            stdout, rc = ba.BundlerAuditAdapter().invoke("/tmp/fake")
        self.assertEqual(rc, 0)
        popen_mock.assert_called_once_with(
            ["bundle-audit", "check", "--format", "json", "--no-update"],
            stdout=mock.ANY, stderr=mock.ANY, cwd="/tmp/fake",
        )

    def test_invoke_falls_back_to_text_when_json_unsupported(self):
        """Older bundler-audit (< 0.8.0) rejects --format json."""
        calls = []

        def fake_run_tool(cmd, **kwargs):
            calls.append(cmd)
            if "--format" in cmd:
                return (b"", b"Unknown switches '--format'", 1)
            return (BUNDLE_AUDIT_SAMPLE, 0)

        with mock.patch("scripts.tools.bundler_audit.run_tool",
                        side_effect=fake_run_tool):
            raw, rc = ba.BundlerAuditAdapter().invoke("/tmp/fake")

        self.assertEqual(rc, 0)
        self.assertEqual(raw, BUNDLE_AUDIT_SAMPLE)
        self.assertEqual(calls, [
            ["bundle-audit", "check", "--format", "json", "--no-update"],
            ["bundle-audit", "check", "--no-update"],
        ])
        # Fallback output is still shape-guarded by parse().
        findings = ba.BundlerAuditAdapter().parse(raw, "g1")
        self.assertEqual(len(findings), 2)

    def test_parse_json_produces_findings(self):
        findings = ba.BundlerAuditAdapter().parse(BUNDLE_AUDIT_JSON_SAMPLE, "g1")
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["tool_evidence"]["package_name"], "actionview")
        self.assertEqual(findings[0]["severity"], "INFO")
        self.assertEqual(findings[0]["citations"]["cve"], ["CVE-2026-33168"])
        self.assertEqual(
            findings[0]["title"],
            "actionview 8.0.4: Rails has a possible XSS vulnerability in its Action View tag helpers",
        )
        self.assertEqual(findings[1]["tool_evidence"]["package_name"], "activestorage")
        self.assertEqual(findings[1]["severity"], "MEDIUM")
        self.assertEqual(findings[1]["citations"]["cve"], ["CVE-2026-33173"])
        self.assertTrue(first(findings)["remediation"].startswith("Upgrade to a fixed version:"))

    def test_parse_json_empty_results_returns_empty_list(self):
        findings = ba.BundlerAuditAdapter().parse(b'{"results": []}', "g1")
        self.assertEqual(findings, [])

    def test_parse_incomplete_block_returns_no_findings(self):
        # The regex requires all mandatory fields; a truncated block must not
        # produce a partial/malformed finding (#1196).
        text = b"Name: actionpack\nVersion: 5.2.4.3\n"
        findings = ba.BundlerAuditAdapter().parse(text, "g1")
        self.assertEqual(findings, [])

    def test_parse_block_without_cve_has_empty_citations(self):
        # A CVE value that does not start with 'CVE-' yields an empty citations
        # list, which make_finding omits entirely (#1196).
        text = b"""
Name: actionpack
Version: 5.2.4.3
CVE: RESERVED
GHSA: GHSA-8727-m6gj-c7p7
Criticality: High
URL: https://example.com
Title: Possible Strong Parameters Bypass
Solution: upgrade
"""
        findings = ba.BundlerAuditAdapter().parse(text, "g1")
        self.assertEqual(len(findings), 1)
        self.assertNotIn("citations", findings[0])
        self.assertEqual(findings[0]["tool_evidence"]["rule_id"], "RESERVED")

    def test_parse_unknown_criticality_normalizes_to_info(self):
        text = b"""
Name: actionpack
Version: 5.2.4.3
CVE: CVE-2020-8164
Criticality: BANANA
URL: https://example.com
Title: Possible Strong Parameters Bypass
Solution: upgrade
"""
        findings = ba.BundlerAuditAdapter().parse(text, "g1")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "INFO")

    def test_parse_text_guard_warns_on_unparsed_output(self):
        # Non-empty text that does not match the legacy block regex should
        # trigger the shape guard so format changes are not silently ignored
        # (ARC-A2B run-7).
        text = b"Vulnerability report generated by bundle-audit\n"
        captured = io.StringIO()
        old_stderr = sys.stderr
        try:
            sys.stderr = captured
            findings = ba.BundlerAuditAdapter().parse(text, "g1")
        finally:
            sys.stderr = old_stderr
        self.assertEqual(findings, [])
        self.assertIn("no advisories parsed", captured.getvalue())


if __name__ == "__main__":
    unittest.main()

