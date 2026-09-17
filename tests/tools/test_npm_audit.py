import contextvars
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

import pytest

from _test_helpers import FakePopen, first, only
import scripts.ingest_tools as ingest_tools
import scripts.tools.npm_audit as na
import scripts.tools.base as base


@pytest.fixture(autouse=True)
def _reset_npm_audit_manifest_path_cv():
    """Reset the per-invocation manifest path ContextVar around each test.

    `invoke` records the manifest it chose, and the two invoke() tests below
    call it on a bare path outside any copied context -- so without this reset
    their answer would be the ambient one every later parse() reads.
    """
    token = na._manifest_path_cv.set(None)
    try:
        yield
    finally:
        na._manifest_path_cv.reset(token)

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

    # ---- #1649: located at the manifest the adapter actually audited --------
    #
    # `is_applicable` accepts a shrinkwrap OR a lockfile, and `_finding_from`
    # hard-coded `package-lock.json` on both report-version branches, so every
    # finding on a shrinkwrap-only project pointed at a file that is not in the
    # tree. `location.file` drives source navigation, the advisor's backup
    # scope grant (P16) and path-based downstream matching, so a nonexistent
    # path degrades verification, not just the display.

    def _target(self, *names):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        for name in names:
            with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
                fh.write("{}")
        return d

    def _audit(self, target, sample=None):
        """invoke() then parse(), the order the adapter really runs in, inside
        ONE copied execution context -- so whatever invoke records about this
        target cannot leak into another test's parse."""
        adapter = na.NpmAuditAdapter()

        def run():
            with mock.patch.object(na, "run_tool",
                                   return_value=(sample or NPM_AUDIT_SAMPLE, 0)):
                raw, _rc = adapter.invoke(target)
            return adapter.parse(raw, "g1")

        return only(contextvars.copy_context().run(run))["location"]["file"]

    def test_a_shrinkwrap_only_project_locates_findings_at_the_shrinkwrap(self):
        self.assertEqual("npm-shrinkwrap.json",
                         self._audit(self._target("npm-shrinkwrap.json")))

    def test_a_lockfile_project_still_locates_findings_at_the_lockfile(self):
        self.assertEqual("package-lock.json",
                         self._audit(self._target("package-lock.json")))

    def test_the_shrinkwrap_wins_when_both_are_present(self):
        # npm itself reads npm-shrinkwrap.json in preference to package-lock.json.
        self.assertEqual("npm-shrinkwrap.json",
                         self._audit(self._target("npm-shrinkwrap.json",
                                                  "package-lock.json")))

    def test_a_target_with_neither_lockfile_falls_back_to_package_json(self):
        self.assertEqual("package.json", self._audit(self._target("package.json")))

    def test_the_v2_report_branch_is_located_the_same_way(self):
        # Both report-version branches went through _finding_from's hard-coded
        # path; fixing one and not the other would be invisible.
        sample = json.dumps({
            "auditReportVersion": 2,
            "vulnerabilities": {
                "lodash": {
                    "name": "lodash", "severity": "high", "range": "<4.17.21",
                    "via": [{"source": 1234, "title": "Prototype Pollution",
                             "cves": ["CVE-2021-23337"]}],
                    "fixAvailable": False,
                }
            }
        }).encode()
        self.assertEqual("npm-shrinkwrap.json",
                         self._audit(self._target("npm-shrinkwrap.json"), sample))

    # ---- the route a real scan actually takes --------------------------------
    #
    # `invoke` and `parse` NEVER run in the same process: run_tools dispatches
    # each adapter as `docker run ... _run_adapter.py <tool>`, which calls only
    # `invoke` and writes the raw bytes out, and the host's `ingest_tools`
    # later calls only `parse`. Anything the adapter learned at invoke time is
    # gone by then -- which is why the location is resolved a second time on
    # the ingest side, from the target root ingest already holds.

    def _ingested(self, target, sample=None):
        """That sequence: invoke inside a context that is THROWN AWAY (stands
        in for the container process), then the host's real ingest over the
        bytes that came back."""
        tools_dir = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tools_dir, ignore_errors=True))
        adapter = na.NpmAuditAdapter()
        with mock.patch.object(na, "run_tool",
                               return_value=(sample or NPM_AUDIT_SAMPLE, 0)):
            raw, _rc = contextvars.copy_context().run(adapter.invoke, target)
        with open(os.path.join(tools_dir, "npm-audit.json"), "wb") as fh:
            fh.write(raw)
        findings, _dispositions = ingest_tools.ingest_dir_detailed(
            tools_dir, "g1", target_root=target)
        return only(findings)["location"]["file"]

    def test_a_host_side_ingest_locates_the_finding_at_the_audited_manifest(self):
        self.assertEqual("npm-shrinkwrap.json",
                         self._ingested(self._target("npm-shrinkwrap.json")))

    def test_a_host_side_ingest_still_locates_a_lockfile_project_at_its_lockfile(self):
        self.assertEqual("package-lock.json",
                         self._ingested(self._target("package-lock.json")))

    def test_the_target_root_is_unset_again_after_the_parse_even_when_it_raises(self):
        # The ContextVar is scoped to ONE parse: a later parse for another
        # target must not inherit this root, and a raising parse must not leak
        # it. Named here so the reset is not pinned only by test ordering.
        target = self._target("npm-shrinkwrap.json")
        tools_dir = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tools_dir, ignore_errors=True))
        with open(os.path.join(tools_dir, "npm-audit.json"), "wb") as fh:
            fh.write(NPM_AUDIT_SAMPLE)
        with mock.patch.object(na.NpmAuditAdapter, "parse",
                               side_effect=RuntimeError("boom")):
            _findings, dispositions = ingest_tools.ingest_dir_detailed(
                tools_dir, "g1", target_root=target)
        self.assertEqual("failed", only(list(dispositions.values()))["status"])
        self.assertIsNone(base.target_root_cv.get())
        ingest_tools.ingest_dir_detailed(tools_dir, "g1", target_root=target)
        self.assertIsNone(base.target_root_cv.get())

    def test_the_located_file_really_is_in_the_target(self):
        # The whole point of #1649: `location.file` drives source navigation,
        # the advisor's backup scope grant and path-based matching, so a path
        # that is not in the tree degrades verification.
        target = self._target("npm-shrinkwrap.json")
        self.assertTrue(os.path.isfile(os.path.join(target, self._ingested(target))))

    def test_only_a_parse_that_names_no_tree_falls_back_to_a_lockfile_name(self):
        # NOT the production shape, and not an answer to rely on: ingest always
        # names the target root, and the in-process route (capture_goldens)
        # names it through invoke. This is the last resort for a caller that
        # hands over bytes and no tree at all (#1649).
        findings = na.NpmAuditAdapter().parse(NPM_AUDIT_SAMPLE, "g1")
        self.assertEqual(na.DEFAULT_MANIFEST, only(findings)["location"]["file"])

    def test_the_manifest_is_per_invocation_not_singleton_state(self):
        # ADAPTERS holds ONE shared adapter object, so instance state would let
        # a second invoke overwrite the first invocation's answer before its
        # output was parsed. Invoke both targets before parsing either.
        adapter = na.NpmAuditAdapter()
        shrink = self._target("npm-shrinkwrap.json")
        lock = self._target("package-lock.json")
        with mock.patch.object(na, "run_tool", return_value=(NPM_AUDIT_SAMPLE, 0)):
            ctx1, ctx2 = contextvars.copy_context(), contextvars.copy_context()
            raw1, _ = ctx1.run(adapter.invoke, shrink)
            raw2, _ = ctx2.run(adapter.invoke, lock)
            findings1 = ctx1.run(adapter.parse, raw1, "g1")
            findings2 = ctx2.run(adapter.parse, raw2, "g2")
        self.assertEqual("npm-shrinkwrap.json", first(findings1)["location"]["file"])
        self.assertEqual("package-lock.json", first(findings2)["location"]["file"])

    def test_parse_empty_findings(self):
        findings = na.NpmAuditAdapter().parse(b"{}", "g1")
        self.assertEqual(findings, [])
        findings = na.NpmAuditAdapter().parse(b'{"advisories": {}}', "g1")
        self.assertEqual(findings, [])
        findings = na.NpmAuditAdapter().parse(b'{"vulnerabilities": {}}', "g1")
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
