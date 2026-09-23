import json
import os
import tempfile
import unittest
from unittest import mock

from _test_helpers import FakePopen, first, only
import scripts.tools.osv_scanner as osv
import scripts.tools.base as base
from .conftest import assert_scratch_cwd, scratch_cwd_recorder

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
    @staticmethod
    def _severity_sample(vulnerabilities, groups=None):
        return json.dumps({"results": [{
            "source": {"path": "/src/requirements.txt"},
            "packages": [{"package": {"name": "dep", "version": "1", "ecosystem": "PyPI"},
                          "vulnerabilities": vulnerabilities, "groups": groups or []}],
        }]}).encode()

    def test_database_labels_preserved_for_unscored_advisories(self):
        labels = {"CRITICAL": "CRITICAL", "high": "HIGH", "MoDeRaTe": "MEDIUM",
                  "LOW": "LOW", "unknown": "LOW", "very CRITICAL": "LOW"}
        vulnerabilities = [{"id": key, "database_specific": {"severity": key}}
                           for key in labels]
        vulnerabilities += [{"id": "malformed", "database_specific": "critical"},
                            {"id": "bad-label", "database_specific": {"severity": ["CRITICAL"]}}]
        findings = osv.OsvScannerAdapter().parse(self._severity_sample(vulnerabilities), "g1")
        by_id = {f["tool_evidence"]["rule_id"]: f for f in findings}
        self.assertEqual({key: by_id[key]["severity"] for key in labels}, labels)
        self.assertEqual(by_id["malformed"]["severity"], "LOW")
        self.assertEqual(by_id["bad-label"]["severity"], "LOW")
        self.assertEqual(len(findings), len(vulnerabilities))

    def test_v4_without_calculator_uses_database_label(self):
        vuln = {"id": "V4", "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/..."}],
                "database_specific": {"severity": "CRITICAL"}}
        findings = osv.OsvScannerAdapter().parse(self._severity_sample([vuln]), "g1")
        finding = first(findings)
        self.assertEqual(finding["severity"], "CRITICAL")
        self.assertEqual(finding["tool_evidence"]["rule_id"], "V4")
        self.assertNotIn("cvss_max_severity", finding["tool_evidence"])

    def test_cvss_v3_vector_precedes_conflicting_database_label(self):
        vuln = {"id": "V3", "severity": [{"type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                "database_specific": {"severity": "LOW"}}
        finding = first(osv.OsvScannerAdapter().parse(self._severity_sample([vuln]), "g1"))
        self.assertEqual(finding["severity"], "CRITICAL")

    def test_valid_group_score_wins_and_duplicate_group_membership_uses_maximum(self):
        vuln = {"id": "SCORE", "database_specific": {"severity": "LOW"}}
        groups = [{"ids": ["SCORE"], "max_severity": "5.3"},
                  {"ids": ["SCORE"], "max_severity": "9.8"},
                  {"ids": ["SCORE"], "max_severity": "4.0"}]
        finding = first(osv.OsvScannerAdapter().parse(self._severity_sample([vuln], groups), "g1"))
        self.assertEqual(finding["severity"], "CRITICAL")
        self.assertEqual(finding["tool_evidence"]["cvss_max_severity"], 9.8)

    def test_invalid_group_scores_fall_through_and_zero_is_valid_low(self):
        # OSV group score 0 remains a valid LOW score; SARIF security-severity
        # 0 has no grade and falls through to its other metadata.
        bad_scores = [float("nan"), float("inf"), float("-inf"), True,
                      -1, 10.1, "nan", "Infinity", {}, []]
        vulnerabilities = [{"id": str(i), "database_specific": {"severity": "HIGH"}}
                           for i in range(len(bad_scores))]
        vulnerabilities.append({"id": "zero", "database_specific": {"severity": "CRITICAL"}})
        groups = [{"ids": [str(i)], "max_severity": score}
                  for i, score in enumerate(bad_scores)]
        groups.append({"ids": ["zero"], "max_severity": 0})
        findings = osv.OsvScannerAdapter().parse(self._severity_sample(vulnerabilities, groups), "g1")
        by_id = {f["tool_evidence"]["rule_id"]: f for f in findings}
        self.assertEqual([by_id[str(i)]["severity"] for i in range(len(bad_scores))],
                         ["HIGH"] * len(bad_scores))
        self.assertEqual(by_id["zero"]["severity"], "LOW")
        self.assertEqual(by_id["zero"]["tool_evidence"]["cvss_max_severity"], 0.0)

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
        self.assertIn("GHSA-9hjg-9r4m-mvj7", by_id)
        self.assertIn("GHSA-x84v-xcm2-53pg", by_id)
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
        self.assertIn("GHSA-9hjg-9r4m-mvj7", by_id)
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
        self.assertEqual(first(findings)["provenance"]["discovered_by"], "tool:osv-scanner")
        self.assertEqual(first(findings)["provenance"]["confirmation_status"], "TOOL")

    def test_invoke_runs_osv_scanner_json(self):
        adapter = osv.OsvScannerAdapter()
        calls = []
        with mock.patch("scripts.tools.base.subprocess.Popen",
                        side_effect=scratch_cwd_recorder(calls)):
            stdout, rc = adapter.invoke("/tmp/fake")
        self.assertEqual(stdout, b"{}")
        self.assertEqual(rc, 0)
        launch = only(calls, "osv-scanner launch")
        self.assertEqual(
            launch["argv"],
            ["osv-scanner", "--format", "json", "--experimental-offline",
             "--recursive", "/tmp/fake"])
        # #1877: the scan root is named on argv, so the cwd is a scratch.
        assert_scratch_cwd(self, launch, "/tmp/fake")

    def test_invoke_reports_nonzero_exit(self):
        import contextlib, io
        adapter = osv.OsvScannerAdapter()
        fake_run = FakePopen(stdout=b"scan output", stderr=b"no lockfiles found",
                             returncode=2)
        buf = io.StringIO()
        with mock.patch("scripts.tools.base.subprocess.Popen", return_value=fake_run), \
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
