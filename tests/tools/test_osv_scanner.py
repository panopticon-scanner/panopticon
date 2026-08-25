import json
import os
import tempfile
import unittest
from unittest import mock

import scripts.tools.osv_scanner as osv
import scripts.tools.base as base

# Golden trimmed from a REAL `osv-scanner --format json --recursive` run
# (2026-08-03, osv-scanner in the panopticon-tools image). The real shape nests
# results[].packages[].{package, vulnerabilities, groups}; severity is the
# numeric CVSS in groups[].max_severity; source.path carries the /src mount
# prefix. Do NOT replace this with a hand-invented shape — a fictional fixture
# previously masked a parser that dropped 100% of real findings.
OSV_REAL_SAMPLE = json.dumps({
    "results": [
        {
            "source": {"path": "/src/tests/fixtures/vulnerable-python/requirements.txt",
                       "type": "lockfile"},
            "packages": [
                {
                    "package": {"name": "requests", "version": "2.19.1",
                                "ecosystem": "PyPI"},
                    "dependency_groups": [],
                    "vulnerabilities": [
                        {
                            "id": "GHSA-9hjg-9r4m-mvj7",
                            "aliases": ["cve-2024-47081", "PYSEC-2026-1872"],
                            "severity": [{"type": "CVSS_V3",
                                          "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"}],
                            "summary": "Requests leaks .netrc credentials",
                            "details": "long details text",
                        },
                        {
                            "id": "GHSA-x84v-xcm2-53pg",
                            "aliases": ["CVE-2018-18074"],
                            "severity": [{"type": "CVSS_V3",
                                          "score": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
                            "summary": "Requests sends Authorization header cross-origin",
                        },
                    ],
                    "groups": [
                        {"ids": ["GHSA-9hjg-9r4m-mvj7", "PYSEC-2026-1872"],
                         "aliases": ["CVE-2024-47081"],
                         "max_severity": "5.3"},
                        {"ids": ["GHSA-x84v-xcm2-53pg"],
                         "aliases": ["CVE-2018-18074"],
                         "max_severity": "9.8"},
                    ],
                }
            ],
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
    def test_parse_real_shape_produces_findings(self):
        findings = osv.OsvScannerAdapter().parse(OSV_REAL_SAMPLE, "g1")
        self.assertEqual(len(findings), 2)
        f = findings[0]
        self.assertEqual(f["source"], "tool:osv-scanner")
        self.assertEqual(f["tool_evidence"]["package_name"], "requests")
        self.assertEqual(f["location"]["file"],
                         "tests/fixtures/vulnerable-python/requirements.txt")

    def test_severity_from_groups_max_severity_cvss(self):
        findings = osv.OsvScannerAdapter().parse(OSV_REAL_SAMPLE, "g1")
        by_id = {f["tool_evidence"]["rule_id"]: f for f in findings}
        self.assertEqual(by_id["GHSA-9hjg-9r4m-mvj7"]["severity"], "MEDIUM")  # 5.3
        self.assertEqual(by_id["GHSA-x84v-xcm2-53pg"]["severity"], "CRITICAL")  # 9.8

    def test_severity_from_vulnerability_cvss_v3_list(self):
        # ARC-D2B / COD-C3B run-7: when groups[].max_severity is absent, OSV's
        # vulnerabilities[].severity list of CVSS_V3 vector dicts must be parsed.
        sample = json.dumps({
            "results": [{
                "source": {"path": "/src/package-lock.json"},
                "packages": [{
                    "package": {"name": "dep", "version": "1.0.0", "ecosystem": "npm"},
                    "groups": [],
                    "vulnerabilities": [{
                        "id": "GHSA-LIST-ONLY",
                        "aliases": ["CVE-2024-0001"],
                        "severity": [{"type": "CVSS_V3",
                                      "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                        "summary": "Remote code execution",
                    }],
                }],
            }]
        }).encode()
        findings = osv.OsvScannerAdapter().parse(sample, "g1")
        self.assertEqual(len(findings), 1)
        self.assertNotEqual(findings[0]["severity"], "INFO")
        self.assertEqual(findings[0]["severity"], "CRITICAL")

    def test_cvss_bucket_boundaries(self):
        self.assertEqual(base.cvss_bucket(9.0), "CRITICAL")
        self.assertEqual(base.cvss_bucket(7.0), "HIGH")
        self.assertEqual(base.cvss_bucket(6.9), "MEDIUM")
        self.assertEqual(base.cvss_bucket(4.0), "MEDIUM")
        self.assertEqual(base.cvss_bucket(3.9), "LOW")

    def test_parse_uppercases_cve_and_filters_aliases(self):
        findings = osv.OsvScannerAdapter().parse(OSV_REAL_SAMPLE, "g1")
        by_id = {f["tool_evidence"]["rule_id"]: f for f in findings}
        self.assertEqual(by_id["GHSA-9hjg-9r4m-mvj7"]["citations"]["cve"],
                         ["CVE-2024-47081"])

    def test_source_path_mount_prefix_stripped(self):
        findings = osv.OsvScannerAdapter().parse(OSV_REAL_SAMPLE, "g1")
        for f in findings:
            self.assertFalse(f["location"]["file"].startswith("/src"),
                             f["location"]["file"])

    def test_is_applicable_detects_each_marker(self):
        adapter = osv.OsvScannerAdapter()
        for marker in MARKERS:
            with tempfile.TemporaryDirectory() as d:
                open(os.path.join(d, marker), "w").close()
                self.assertTrue(adapter.is_applicable(d), f"failed for {marker}")

    def test_is_applicable_false_when_no_marker(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertFalse(osv.OsvScannerAdapter().is_applicable(d))

    def test_parse_includes_provenance(self):
        findings = osv.OsvScannerAdapter().parse(OSV_REAL_SAMPLE, "g1")
        self.assertTrue(findings)
        self.assertEqual(findings[0]["provenance"]["discovered_by"], "tool:osv-scanner")
        self.assertEqual(findings[0]["provenance"]["confirmation_status"], "TOOL")

    def test_invoke_runs_osv_scanner_json(self):
        adapter = osv.OsvScannerAdapter()
        fake_run = mock.Mock(return_value=mock.Mock(stdout=b"{}", returncode=0))
        with mock.patch("scripts.tools.base.subprocess.run", fake_run):
            stdout, rc = adapter.invoke("/tmp/fake")
        self.assertEqual(stdout, b"{}")
        self.assertEqual(rc, 0)
        fake_run.assert_called_once_with(
            ["osv-scanner", "--format", "json", "--experimental-offline", "--recursive", "/tmp/fake"],
            capture_output=True,
            timeout=300,
        )

    def test_invoke_reports_nonzero_exit(self):
        import contextlib, io
        adapter = osv.OsvScannerAdapter()
        fake_run = mock.Mock(return_value=mock.Mock(
            stdout=b"scan output", stderr=b"no lockfiles found", returncode=2))
        buf = io.StringIO()
        with mock.patch("scripts.tools.base.subprocess.run", fake_run), \
             contextlib.redirect_stderr(buf):
            stdout, rc = adapter.invoke("/tmp/fake")
        self.assertEqual(stdout, b"scan output")
        self.assertEqual(rc, 2)
        self.assertIn("tool osv-scanner exited 2", buf.getvalue())
        self.assertIn("no lockfiles found", buf.getvalue())

    def test_parse_tolerates_malformed_entries(self):
        sample = json.dumps({
            "results": [
                {"source": {"path": "/src/x.lock"},
                 "packages": [None, {"package": {"name": "p"},
                                     "vulnerabilities": [None]}]},
                {"packages": []},
            ]
        }).encode()
        findings = osv.OsvScannerAdapter().parse(sample, "g1")
        self.assertEqual(findings, [])

    def test_parse_empty_results(self):
        findings = osv.OsvScannerAdapter().parse(b'{"results": []}', "g1")
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
