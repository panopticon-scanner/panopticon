import json
import os
from _test_helpers import first
import tempfile
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
        self.assertEqual(first(findings)["provenance"]["discovered_by"], "tool:dependency-check")
        self.assertEqual(first(findings)["provenance"]["confirmation_status"], "TOOL")

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

    def test_invoke_fails_closed_on_oversize_report(self):
        # #run8 OPS-D1A: an oversize on-disk report (read_capped_report -> None)
        # must fail closed to (b"", nonzero) instead of being slurped whole.
        adapter = dc.DependencyCheckAdapter()
        fake_run = mock.Mock(return_value=(b"", 0))
        with mock.patch("scripts.tools.dependency_check.run_tool", fake_run), \
             mock.patch("scripts.tools.dependency_check.os.path.exists", return_value=True), \
             mock.patch("scripts.tools.dependency_check.read_capped_report", return_value=None), \
             mock.patch("shutil.rmtree"):
            stdout, rc = adapter.invoke("/tmp/fake")
        self.assertEqual(stdout, b"")
        self.assertNotEqual(rc, 0)

    def test_invoke_returns_report_with_nonzero_exit(self):
        adapter = dc.DependencyCheckAdapter()
        fake_run = mock.Mock(return_value=(b"", 7))
        with mock.patch("scripts.tools.dependency_check.run_tool", fake_run):
            with mock.patch("scripts.tools.dependency_check.os.path.exists", return_value=True):
                with mock.patch("builtins.open", mock.mock_open(read_data=b"{\"report\": true}")):
                    with mock.patch("shutil.rmtree"):
                        stdout, rc = adapter.invoke("/tmp/fake")
        self.assertEqual(stdout, b"{\"report\": true}")
        self.assertEqual(rc, 7)


class TestDependencyCheckIsApplicable(unittest.TestCase):
    def test_applicable_when_pom_xml_present(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "pom.xml"), "w").close()
            self.assertTrue(dc.DependencyCheckAdapter().is_applicable(d))

    def test_applicable_when_build_gradle_present(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "build.gradle"), "w").close()
            self.assertTrue(dc.DependencyCheckAdapter().is_applicable(d))

    def test_applicable_when_build_gradle_kts_present(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "build.gradle.kts"), "w").close()
            self.assertTrue(dc.DependencyCheckAdapter().is_applicable(d))

    def test_not_applicable_without_java_build_files(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "package.json"), "w").close()
            self.assertFalse(dc.DependencyCheckAdapter().is_applicable(d))

    def test_not_applicable_when_target_missing(self):
        self.assertFalse(dc.DependencyCheckAdapter().is_applicable("/nonexistent/path"))


class TestOfflineAnalyzers(unittest.TestCase):
    """Every analyzer that calls home must be disabled: scans have no network.

    #calibration-6. OSS Index / Node Audit / RetireJS were disabled in #1461
    because each logged [ERROR] and forced exit 14. The Central Analyzer is
    worse: offline it does not fail, it HANGS, until the adapter's 900s timeout
    kills the invocation and the run gets NO report at all. Measured on
    WebGoat's jars: without --disableCentral exit 124 and 9 error lines; with
    it, exit 0 and none.
    """

    def _argv(self):
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            return b"{}", 0

        with mock.patch.object(dc, "run_tool", side_effect=fake_run):
            dc.DependencyCheckAdapter().invoke("/tmp/x")
        return captured["cmd"]

    def test_every_call_home_analyzer_is_disabled(self):
        argv = self._argv()
        for flag in ("--disableOssIndex", "--disableNodeAudit",
                     "--disableRetireJS", "--disableCentral"):
            self.assertIn(flag, argv,
                          "%s reaches the network; scans run --network none" % flag)

    def test_offline_data_source_is_still_used(self):
        # Disabling the network analyzers must not disable the SCAN: offline
        # vulnerability data comes from the baked NVD set, so --data and
        # --noupdate have to survive.
        argv = self._argv()
        self.assertIn("--noupdate", argv)
        self.assertIn("--data", argv)
        self.assertIn("/opt/odc-data", argv)



if __name__ == "__main__":
    unittest.main()

