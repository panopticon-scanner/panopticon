import contextlib
import contextvars
import io
import json
import os
from tests._test_helpers import first, only
import tempfile
import unittest
from unittest import mock

import pytest

import scripts.tools.base as base
import scripts.tools.dependency_check as dc


@pytest.fixture(autouse=True)
def _reset_dependency_check_context_vars():
    """Reset the two ContextVars `location.file` is resolved from (#2225).

    Module-wide and autouse on purpose: the `invoke` tests below run in the MAIN
    execution context, so the manifest one of them records is still set when the
    NEXT test runs -- which silently shadows both of the other two routes (the
    ingest replay through `target_root_cv`, and the bytes-only default). Found
    by exactly that: two of this file's tests passed alone and failed in file
    order. `target_root_cv` is ingest_tools' process-wide state for the same
    reason, so it is reset here too. Pytest-only, like pip_audit's: the
    `unittest.main()` footer at the bottom of this file does not carry fixtures,
    which is this repo's posture for every test file that has both.
    """
    tokens = [(var, var.set(None))
              for var in (dc._manifest_path_cv, base.target_root_cv)]
    try:
        yield
    finally:
        for var, token in reversed(tokens):
            var.reset(token)


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

# One dependency that DOES carry `includedBy` -- the golden's three do not, and
# these references are Maven coordinates (GAV), not paths in any repository.
DC_INCLUDED_BY_SAMPLE = json.dumps({
    "dependencies": [
        {
            "fileName": "commons-fileupload-1.4.jar",
            "includedBy": [
                {"reference": "org.owasp.webgoat:webgoat-container:2023.4"},
                {"reference": "org.owasp.webgoat:webgoat-lessons:2023.4"},
            ],
            "vulnerabilities": [
                {
                    "name": "CVE-2023-24998",
                    "severity": "HIGH",
                    "cwes": ["CWE-770"],
                    "description": "Apache Commons FileUpload DoS",
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



class TestReportWriteIsBounded(unittest.TestCase):
    """#1576 (run-13 OPS-3272189615): dependency-check wrote its JSON report
    into an unquota'd temp directory and the 50 MiB cap was applied only after
    it had finished.

    The 900-second timeout bounds how LONG the scanner runs, not how much it
    writes, so a target crafted to emit a huge dependency/CVE report could
    exhaust the work volume -- taking every concurrent scan with it -- before
    read_capped_report so much as opened the file.
    """

    def _invoke(self, fake_run):
        with mock.patch.object(dc, "run_tool", side_effect=fake_run), \
                mock.patch("shutil.rmtree"):
            return dc.DependencyCheckAdapter().invoke("/tmp/x")

    def test_the_scanner_is_watched_while_it_writes(self):
        seen = {}

        def fake_run(cmd, **kw):
            seen.update(kw)
            seen["out"] = cmd[cmd.index("--out") + 1]
            return b"{}", 0

        with mock.patch.object(dc, "run_tool", side_effect=fake_run), \
                mock.patch.object(dc.os.path, "exists", return_value=False), \
                mock.patch("shutil.rmtree"):
            dc.DependencyCheckAdapter().invoke("/tmp/x")
        # The watched path is the report directory it told the scanner to use.
        self.assertEqual(seen["watch_path"], seen["out"])
        # dependency-check.sh is a wrapper; the kill has to reach the JVM.
        self.assertTrue(seen["start_new_session"])

    def test_an_overrun_is_a_disclosed_tool_failure_not_a_clean_scan(self):
        def fake_run(cmd, **kw):
            raise base.OutputCapExceeded(kw["watch_path"], 50, 100)

        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            stdout, rc = self._invoke(fake_run)
        self.assertEqual(stdout, b"")
        self.assertNotIn(rc, (0, 1))       # outside ok_codes -> recorded missing
        self.assertIn("write-time output cap", err.getvalue())


class TestLocationIsTheBuildManifest(unittest.TestCase):
    """#2225 (ARC-1020240040), the owner's MANIFEST PROXY ruling.

    dependency-check analyses ARTIFACTS -- jars under the build output -- so
    what it reports a CVE against is `angus-activation-2.0.1.jar`, a name that
    exists nowhere in the reviewed repository. `location.file` is what PLACES a
    finding (the delta/`--pr` gate matches it against `diff-hunks.json`, the
    tool-verify advisor's read grant resolves it, grading attributes findings to
    groups by it, every exclude glob matches it), so a jar basename placed
    nothing. The build manifest this scan audited is the repo file that stands in
    for the jar -- the shape every sibling dependency adapter already emits.

    Three routes, one per real caller, all of them repo-relative:
      `invoke` -> `_manifest_path_cv`  in-process (capture_goldens)
      `target_root_cv`                 the ingest replay, `invoke` elsewhere
      `DEFAULT_MANIFEST`               bytes and no tree at all (the goldens)
    """

    GOLDEN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "goldens", "tool-raw", "dependency-check.raw")

    def _golden(self):
        with open(self.GOLDEN, "rb") as fh:
            return fh.read()

    def _files(self, findings):
        self.assertTrue(findings, "the payload holds findings to locate")
        return {f["location"]["file"] for f in findings}

    def _invoked(self, target):
        """`invoke` on `target` in its own execution context, scanner stubbed.

        A COPIED context rather than a reset: what `invoke` records cannot then
        escape to the next test, and the `parse` run in the same context reads
        exactly the value this invocation wrote (test_pip_audit.py's shape).
        """
        adapter = dc.DependencyCheckAdapter()
        context = contextvars.copy_context()
        with mock.patch.object(dc, "run_tool", return_value=(b"{}", 0)):
            context.run(adapter.invoke, target)
        return adapter, context

    # --- route 1: the manifest `invoke` audited ------------------------------

    def test_a_gradle_only_target_locates_its_findings_at_build_gradle(self):
        with tempfile.TemporaryDirectory() as d:
            _tree(d, "build.gradle", "build/libs/app.jar")
            adapter, context = self._invoked(d)
            findings = context.run(adapter.parse, self._golden(), "g1")
        self.assertEqual({"build.gradle"}, self._files(findings))

    def test_maven_wins_over_gradle_when_both_manifests_are_present(self):
        # The order is BUILD_MANIFESTS', which is `is_applicable`'s marker order:
        # one tuple, so the file a scan is LOCATED at cannot disagree with the
        # file that selected the scanner.
        with tempfile.TemporaryDirectory() as d:
            _tree(d, "pom.xml", "build.gradle", "target/app.jar")
            adapter, context = self._invoked(d)
            findings = context.run(adapter.parse, self._golden(), "g1")
        self.assertEqual({"pom.xml"}, self._files(findings))
        self.assertEqual(("pom.xml", "build.gradle", "build.gradle.kts"),
                         tuple(dc.BUILD_MANIFESTS))

    # --- route 2: the ingest replay -----------------------------------------

    def test_the_ingest_replay_resolves_the_manifest_from_the_target_root(self):
        # The route a REAL scan takes (#1649): `invoke` ran in the tools
        # container, so the ContextVar it set is gone by parse time and
        # `ingest_tools` names the tree instead, around its own `parse`.
        with tempfile.TemporaryDirectory() as d:
            _tree(d, "build.gradle.kts", "build/libs/app.jar")
            token = base.target_root_cv.set(d)
            try:
                findings = dc.DependencyCheckAdapter().parse(self._golden(), "g1")
            finally:
                base.target_root_cv.reset(token)
        self.assertEqual({"build.gradle.kts"}, self._files(findings))

    # --- route 3: bytes, and no tree at all ---------------------------------

    def test_bytes_with_no_tree_fall_back_to_the_default_manifest(self):
        # Goldens and any caller that hands over bytes: Maven's manifest is the
        # documented last resort, never an absolute path or a jar name.
        findings = dc.DependencyCheckAdapter().parse(self._golden(), "g1")
        self.assertEqual({"pom.xml"}, self._files(findings))
        self.assertEqual("pom.xml", dc.DEFAULT_MANIFEST)

    # --- what the jar is still good for -------------------------------------

    def test_the_jar_name_stays_in_the_title_the_impact_and_the_evidence(self):
        # The ruling moved the LOCATION, not the identification: the jar is the
        # only thing that names the vulnerable artifact, so it stays where a
        # reader and a fingerprint look for it.
        f = only(dc.DependencyCheckAdapter().parse(DC_SAMPLE, "g1"))
        jar = "spring-core-5.2.0.RELEASE.jar"
        self.assertIn(jar, f["title"])
        self.assertIn(jar, f["impact"])
        self.assertEqual(jar, f["tool_evidence"]["package_name"])
        self.assertEqual("pom.xml", f["location"]["file"])

    def test_included_by_is_evidence_and_never_a_location(self):
        # `includedBy` names what pulled the jar in, as a GAV/pURL coordinate --
        # never a repository path, so it is surfaced beside the finding and can
        # never become `location.file`.
        f = only(dc.DependencyCheckAdapter().parse(DC_INCLUDED_BY_SAMPLE, "g1"))
        self.assertEqual(["org.owasp.webgoat:webgoat-container:2023.4",
                          "org.owasp.webgoat:webgoat-lessons:2023.4"],
                         f["tool_evidence"]["included_by"])
        self.assertEqual("pom.xml", f["location"]["file"])

    def test_included_by_is_omitted_when_the_tool_reports_none(self):
        # An empty list would read as "nothing pulled this in" rather than "the
        # tool did not say"; the golden's three dependencies carry no `includedBy`.
        f = only(dc.DependencyCheckAdapter().parse(DC_SAMPLE, "g1"))
        self.assertNotIn("included_by", f["tool_evidence"])
        golden = dc.DependencyCheckAdapter().parse(self._golden(), "g1")
        self.assertTrue(golden)
        for finding in golden:
            self.assertNotIn("included_by", finding["tool_evidence"])

    def test_a_hostile_included_by_reference_arrives_inert_and_bounded(self):
        # Fix round 1, finding 1. `make_finding` neutralizes `rule_id`,
        # `location.file` and the prose; a per-adapter evidence key it has never
        # heard of has to neutralize its own, or a scanner-authored reference
        # reaches `render_summary` and an operator's terminal live. The 5000
        # characters are the other half: the string is target-controlled and
        # unbounded inside the 50 MiB ingest cap.
        hostile = ("pkg\x1b[2J\x00\x7f " + "A" * 5000)
        payload = json.dumps({
            "dependencies": [
                {
                    "fileName": "commons-fileupload-1.4.jar",
                    "includedBy": [{"reference": hostile}],
                    "vulnerabilities": [{"name": "CVE-2023-24998",
                                         "severity": "HIGH"}],
                }
            ]
        }).encode()
        f = only(dc.DependencyCheckAdapter().parse(payload, "g1"))
        refs = f["tool_evidence"]["included_by"]
        self.assertEqual(1, len(refs))
        ref = refs[0]
        for live in ("\x1b", "\x00", "\x7f", " "):
            self.assertNotIn(live, ref,
                             "a live %r reached tool_evidence.included_by" % live)
        # Escaped, not deleted -- the ESC is the evidence that someone tried.
        self.assertIn(r"\x1b[2J", ref)
        self.assertLessEqual(len(ref), base.INERT_TEXT_MAX + len(base.INERT_CUT),
                             "included_by is unbounded target text")
        self.assertTrue(ref.endswith(base.INERT_CUT),
                        "a cut reference must say that it was cut")

    def test_a_long_included_by_list_is_bounded_with_a_marker(self):
        # Fix round 1, finding 4. Each reference is bounded on its own; the
        # LENGTH of the list is the target's to choose, so it is bounded too, and
        # the marker wears `INERT_CUT` so a shortened list cannot read as whole.
        payload = json.dumps({
            "dependencies": [
                {
                    "fileName": "commons-fileupload-1.4.jar",
                    "includedBy": [{"reference": "org.example:dep-%02d:1.0" % n}
                                   for n in range(20)],
                    "vulnerabilities": [{"name": "CVE-2023-24998",
                                         "severity": "HIGH"}],
                }
            ]
        }).encode()
        f = only(dc.DependencyCheckAdapter().parse(payload, "g1"))
        refs = f["tool_evidence"]["included_by"]
        self.assertEqual(dc.INCLUDED_BY_MAX + 1, len(refs))
        self.assertEqual(["org.example:dep-%02d:1.0" % n
                          for n in range(dc.INCLUDED_BY_MAX)],
                         refs[:dc.INCLUDED_BY_MAX])
        self.assertEqual("4 more" + base.INERT_CUT, refs[dc.INCLUDED_BY_MAX])

    def test_a_reference_that_is_not_a_string_is_dropped_not_coerced(self):
        # Fix round 1, finding 1 (the controller's expression stringified the
        # value; `inert_text(None)` is the literal "None"). A missing or
        # non-string reference must leave NOTHING, never a forged coordinate --
        # the contract test's `..._keeps_a_null_rule_id` rule, one field over.
        payload = json.dumps({
            "dependencies": [
                {
                    "fileName": "commons-fileupload-1.4.jar",
                    "includedBy": [{}, {"reference": None}, {"reference": "   "},
                                   {"reference": "org.example:real:1.0"}],
                    "vulnerabilities": [{"name": "CVE-2023-24998",
                                         "severity": "HIGH"}],
                }
            ]
        }).encode()
        f = only(dc.DependencyCheckAdapter().parse(payload, "g1"))
        self.assertEqual(["org.example:real:1.0"], f["tool_evidence"]["included_by"])

    # --- the ContextVar is per-invocation, not adapter state -----------------

    def test_the_recorded_manifest_is_per_invocation_not_shared_state(self):
        # pip-audit's own regression one module over (`_manifest_path` lived on
        # the singleton adapter): BOTH targets are audited before EITHER report
        # is parsed, so a value stored per adapter collapses the two onto one
        # manifest. Different manifests on purpose -- two targets with the same
        # one would record the same string and hide exactly that.
        adapter = dc.DependencyCheckAdapter()
        with tempfile.TemporaryDirectory() as maven, \
                tempfile.TemporaryDirectory() as gradle:
            _tree(maven, "pom.xml")
            _tree(gradle, "build.gradle")
            ctx_maven = contextvars.copy_context()
            ctx_gradle = contextvars.copy_context()
            with mock.patch.object(dc, "run_tool", return_value=(b"{}", 0)):
                ctx_maven.run(adapter.invoke, maven)
                ctx_gradle.run(adapter.invoke, gradle)
            raw = self._golden()
            self.assertEqual({"pom.xml"},
                             self._files(ctx_maven.run(adapter.parse, raw, "g1")))
            self.assertEqual({"build.gradle"},
                             self._files(ctx_gradle.run(adapter.parse, raw, "g2")))
        # And nothing escaped into THIS context, so the next test starts clean.
        self.assertIsNone(dc._manifest_path_cv.get())


if __name__ == "__main__":
    unittest.main()

