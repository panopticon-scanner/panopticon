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


def _tree(d, *paths):
    """Create empty files at `paths` (relative), making parent dirs."""
    for rel in paths:
        full = os.path.join(d, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        open(full, "w").close()


class TestDependencyCheckIsApplicable(unittest.TestCase):
    """#1474: a build file proves the LANGUAGE; artifacts prove there is
    something to scan. dependency-check reads jars, not build manifests."""

    def test_applicable_when_pom_xml_and_a_real_jar_present(self):
        with tempfile.TemporaryDirectory() as d:
            _tree(d, "pom.xml", "target/app-1.0.jar")
            self.assertTrue(dc.DependencyCheckAdapter().is_applicable(d))

    def test_applicable_when_build_gradle_and_a_real_jar_present(self):
        with tempfile.TemporaryDirectory() as d:
            _tree(d, "build.gradle", "build/libs/app.jar")
            self.assertTrue(dc.DependencyCheckAdapter().is_applicable(d))

    def test_applicable_when_build_gradle_kts_and_a_real_jar_present(self):
        with tempfile.TemporaryDirectory() as d:
            _tree(d, "build.gradle.kts", "libs/dep.jar")
            self.assertTrue(dc.DependencyCheckAdapter().is_applicable(d))

    def test_war_and_ear_also_count_as_artifacts(self):
        for artifact in ("build/app.war", "build/app.ear"):
            with self.subTest(artifact=artifact):
                with tempfile.TemporaryDirectory() as d:
                    _tree(d, "pom.xml", artifact)
                    self.assertTrue(dc.DependencyCheckAdapter().is_applicable(d))

    # --- the bug this exists to prevent -------------------------------------

    def test_bare_clone_with_only_the_gradle_wrapper_is_NOT_applicable(self):
        # THE #1474 case, measured on antennapod: selected, ran 97 seconds,
        # scanned exactly one jar -- the wrapper -- returned zero findings, and
        # certified the run. gradle-wrapper.jar is committed by convention, so
        # it is present in EVERY bare Gradle clone and proves nothing.
        with tempfile.TemporaryDirectory() as d:
            _tree(d, "build.gradle", "gradle/wrapper/gradle-wrapper.jar",
                  "src/main/java/App.java")
            self.assertFalse(dc.DependencyCheckAdapter().is_applicable(d))

    def test_maven_wrapper_jar_is_excluded_for_the_same_reason(self):
        with tempfile.TemporaryDirectory() as d:
            _tree(d, "pom.xml", ".mvn/wrapper/maven-wrapper.jar")
            self.assertFalse(dc.DependencyCheckAdapter().is_applicable(d))

    def test_a_wrapper_alongside_a_real_jar_is_still_applicable(self):
        # The wrapper is ignored, not disqualifying.
        with tempfile.TemporaryDirectory() as d:
            _tree(d, "build.gradle", "gradle/wrapper/gradle-wrapper.jar",
                  "build/libs/app.jar")
            self.assertTrue(dc.DependencyCheckAdapter().is_applicable(d))

    def test_build_file_with_no_artifacts_at_all_is_not_applicable(self):
        with tempfile.TemporaryDirectory() as d:
            _tree(d, "pom.xml", "src/main/java/App.java")
            self.assertFalse(dc.DependencyCheckAdapter().is_applicable(d))

    # --- unchanged preconditions --------------------------------------------

    def test_not_applicable_without_java_build_files(self):
        # A jar alone is not a JVM project to scan -- both halves are required.
        with tempfile.TemporaryDirectory() as d:
            _tree(d, "package.json", "vendor/some.jar")
            self.assertFalse(dc.DependencyCheckAdapter().is_applicable(d))

    def test_not_applicable_when_target_missing(self):
        self.assertFalse(dc.DependencyCheckAdapter().is_applicable("/nonexistent/path"))

    def test_run_artifact_dirs_are_not_searched_for_artifacts(self):
        # A jar inside .git/.panopticon/.worktrees is not the project's, so it
        # must not resurrect the false-clean scan through the back door.
        for junk in (".git/x.jar", ".panopticon/x.jar", ".worktrees/t/x.jar",
                     "node_modules/x.jar"):
            with self.subTest(junk=junk):
                with tempfile.TemporaryDirectory() as d:
                    _tree(d, "pom.xml", junk)
                    self.assertFalse(dc.DependencyCheckAdapter().is_applicable(d))


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

