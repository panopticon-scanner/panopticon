import contextlib
import contextvars
import io
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

import pytest

from _test_helpers import FakePopen, first
import scripts.tools.pip_audit as pa


@pytest.fixture(autouse=True)
def _reset_pip_audit_manifest_path_cv():
    """Reset the per-invocation manifest path ContextVar around each test."""
    token = pa._manifest_path_cv.set(None)
    try:
        yield
    finally:
        pa._manifest_path_cv.reset(token)

PIP_AUDIT_SAMPLE = json.dumps({
    "dependencies": [
        {
            "name": "requests",
            "version": "2.25.1",
            "vulns": [
                {
                    "id": "PYSEC-2023-1",
                    "fix_versions": ["2.31.0"],
                    "description": "Unintended leak of proxy credentials",
                    "aliases": ["CVE-2023-32681"],
                }
            ]
        }
    ]
}).encode()


class TestPipAuditAdapter(unittest.TestCase):
    def test_parse_produces_finding(self):
        adapter = pa.PipAuditAdapter()
        findings = adapter.parse(PIP_AUDIT_SAMPLE, "g1")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["source"], "tool:pip-audit")
        self.assertEqual(f["severity"], "MEDIUM")
        self.assertEqual(f["citations"]["cve"], ["CVE-2023-32681"])
        self.assertEqual(f["tool_evidence"]["package_name"], "requests")
        self.assertEqual(f["tool_evidence"]["fixed_version"], "2.31.0")

    def test_parse_survives_empty_fix_versions_list(self):
        # pip-audit emits "fix_versions": [] when no fixed release exists; the
        # .get default only covers a MISSING key, so [..][0] used to IndexError
        # and ingest marked the whole pip-audit document failed (PR #945 scan,
        # finding CORR-001).
        sample = json.dumps({
            "dependencies": [
                {"name": "leftpad", "version": "0.1", "vulns": [
                    {"id": "PYSEC-2024-9", "fix_versions": [],
                     "description": "d", "aliases": []}]}
            ]
        }).encode()
        findings = pa.PipAuditAdapter().parse(sample, "g1")
        self.assertEqual(len(findings), 1)
        self.assertNotIn("fixed_version", findings[0]["tool_evidence"])

    def test_parse_uses_actual_manifest_path(self):
        adapter = pa.PipAuditAdapter()
        token = pa._manifest_path_cv.set("/tmp/fake/pyproject.toml")
        try:
            findings = adapter.parse(PIP_AUDIT_SAMPLE, "g1")
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["location"]["file"], "/tmp/fake/pyproject.toml")
        finally:
            pa._manifest_path_cv.reset(token)

    def test_parse_defaults_location_file_when_no_manifest(self):
        adapter = pa.PipAuditAdapter()
        findings = adapter.parse(PIP_AUDIT_SAMPLE, "g1")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["location"]["file"], "requirements.txt")

    def test_manifest_path_is_per_invocation_not_singleton_state(self):
        # Regression: _manifest_path used to be stored on the singleton
        # instance, so a second invoke could overwrite the value before the
        # first invoke's output was parsed. To catch that, invoke both targets
        # before parsing either result. Each target's invoke/parse pair runs in
        # its own copied execution context so the ContextVar set by invoke is
        # still the right one when parse is finally called.
        adapter = pa.PipAuditAdapter()

        def fake_find_requirement(target: str) -> str:
            return os.path.join(target, "requirements.txt")

        with mock.patch.object(adapter, "_find_requirement", side_effect=fake_find_requirement):
            with mock.patch.object(pa, "run_tool", return_value=(PIP_AUDIT_SAMPLE, 0)):
                ctx1 = contextvars.copy_context()
                ctx2 = contextvars.copy_context()
                raw1, _ = ctx1.run(adapter.invoke, "/tmp/fake1")
                raw2, _ = ctx2.run(adapter.invoke, "/tmp/fake2")
                findings1 = ctx1.run(adapter.parse, raw1, "g1")
                findings2 = ctx2.run(adapter.parse, raw2, "g2")

        self.assertEqual(first(findings1)["location"]["file"], "/tmp/fake1/requirements.txt")
        self.assertEqual(first(findings2)["location"]["file"], "/tmp/fake2/requirements.txt")

    def test_parse_omits_none_tool_evidence_fields(self):
        sample = json.dumps({
            "dependencies": [
                {
                    "name": "requests",
                    "version": "2.25.1",
                    "vulns": [
                        {
                            "id": "PYSEC-2023-1",
                            "description": "Missing fixed version",
                        }
                    ]
                }
            ]
        }).encode()
        findings = pa.PipAuditAdapter().parse(sample, "g1")
        self.assertEqual(len(findings), 1)
        evidence = findings[0]["tool_evidence"]
        self.assertNotIn("fixed_version", evidence)
        self.assertEqual(evidence["package_name"], "requests")

    def test_is_applicable_when_requirements_present(self):
        with mock.patch("os.path.exists", side_effect=lambda p: p.endswith("requirements.txt")):
            self.assertTrue(pa.PipAuditAdapter().is_applicable("/tmp/fake"))

    def test_is_applicable_when_requirements_dev_present(self):
        with mock.patch("scripts.tools.pip_audit.glob.glob", return_value=["/tmp/fake/requirements-dev.txt"]):
            with mock.patch("os.path.exists", return_value=False):
                self.assertTrue(pa.PipAuditAdapter().is_applicable("/tmp/fake"))

    def test_is_applicable_when_pyproject_present(self):
        with mock.patch("os.path.exists", side_effect=lambda p: p.endswith("pyproject.toml")):
            with mock.patch("scripts.tools.pip_audit.glob.glob", return_value=[]):
                self.assertTrue(pa.PipAuditAdapter().is_applicable("/tmp/fake"))

    def test_is_applicable_false_for_setup_py(self):
        with mock.patch("os.path.exists", side_effect=lambda p: p.endswith("setup.py")):
            with mock.patch("scripts.tools.pip_audit.glob.glob", return_value=[]):
                self.assertFalse(pa.PipAuditAdapter().is_applicable("/tmp/fake"))

    def test_is_applicable_false_for_setup_cfg(self):
        with mock.patch("os.path.exists", side_effect=lambda p: p.endswith("setup.cfg")):
            with mock.patch("scripts.tools.pip_audit.glob.glob", return_value=[]):
                self.assertFalse(pa.PipAuditAdapter().is_applicable("/tmp/fake"))

    def test_is_applicable_false_when_no_manifest(self):
        with mock.patch("os.path.exists", return_value=False):
            with mock.patch("scripts.tools.pip_audit.glob.glob", return_value=[]):
                self.assertFalse(pa.PipAuditAdapter().is_applicable("/tmp/fake"))

    def test_find_requirement_prefers_canonical_over_dev_sibling(self):
        # #707: requirements-dev.txt sorts before requirements.txt ('-' < '.'),
        # so the old lexicographic-first pick silently audited the dev manifest
        # and skipped the primary one. The canonical file must always win.
        with tempfile.TemporaryDirectory() as d:
            for name in ("requirements.txt", "requirements-dev.txt",
                         "requirements-test.txt"):
                open(os.path.join(d, name), "w").close()
            self.assertEqual(pa.PipAuditAdapter()._find_requirement(d),
                             os.path.join(d, "requirements.txt"))

    def test_find_requirement_falls_back_to_glob_without_canonical(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "requirements-dev.txt"), "w").close()
            self.assertEqual(pa.PipAuditAdapter()._find_requirement(d),
                             os.path.join(d, "requirements-dev.txt"))

    def test_find_requirement_none_when_absent(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(pa.PipAuditAdapter()._find_requirement(d))

    def test_parse_includes_provenance(self):
        findings = pa.PipAuditAdapter().parse(PIP_AUDIT_SAMPLE, "g1")
        self.assertTrue(findings)
        self.assertEqual(first(findings)["provenance"]["discovered_by"], "tool:pip-audit")
        self.assertEqual(first(findings)["provenance"]["confirmation_status"], "TOOL")

    def test_invoke_uses_requirements_txt_when_present(self):
        adapter = pa.PipAuditAdapter()
        fake_run = FakePopen(stdout=b"[]", stderr=b"", returncode=0)
        with mock.patch("scripts.tools.base.subprocess.Popen",
                        return_value=fake_run) as popen_mock:
            with mock.patch("scripts.tools.pip_audit.glob.glob", return_value=["/tmp/fake/requirements.txt"]):
                stdout, rc = adapter.invoke("/tmp/fake")
        self.assertEqual(stdout, b"[]")
        self.assertEqual(rc, 0)
        popen_mock.assert_called_once_with(
            ["pip-audit", "--format=json", "--desc=on", "--progress-spinner=off", "--requirement", "/tmp/fake/requirements.txt"],
            stdout=mock.ANY,
            stderr=mock.ANY,
        )

    def test_invoke_falls_back_to_pyproject_toml(self):
        adapter = pa.PipAuditAdapter()
        fake_run = FakePopen(stdout=b"[]", stderr=b"", returncode=0)
        with mock.patch("scripts.tools.base.subprocess.Popen",
                        return_value=fake_run) as popen_mock:
            with mock.patch("scripts.tools.pip_audit.glob.glob", return_value=[]):
                with mock.patch("scripts.tools.pip_audit._deps_from_pyproject",
                               return_value=["requests==2.25.1"]):
                    stdout, rc = adapter.invoke("/tmp/fake")
        self.assertEqual(stdout, b"[]")
        self.assertEqual(rc, 0)
        # Verify that --requirement is used with a temp file, not a positional arg
        call_args = popen_mock.call_args[0][0]
        self.assertIn("--requirement", call_args)
        self.assertNotIn("/tmp/fake", call_args)


PYPROJECT_STATIC = b"""
[project]
name = "x"
dependencies = ["requests==2.25.1", "urllib3>=1.26"]
[project.optional-dependencies]
dev = ["pytest"]
"""

PYPROJECT_DYNAMIC = b"""
[project]
name = "x"
dynamic = ["dependencies"]
"""


class TestStaticPyproject(unittest.TestCase):
    def _target(self, content):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        with open(os.path.join(d, "pyproject.toml"), "wb") as fh:
            fh.write(content)
        return d

    def test_static_deps_extracted(self):
        deps = pa._deps_from_pyproject(self._target(PYPROJECT_STATIC))
        self.assertEqual(deps,
                         ["requests==2.25.1", "urllib3>=1.26", "pytest"])

    def test_dynamic_deps_return_none(self):
        self.assertIsNone(
            pa._deps_from_pyproject(self._target(PYPROJECT_DYNAMIC)))

    def test_invoke_uses_requirement_file_not_positional(self):
        target = self._target(PYPROJECT_STATIC)
        captured = {}
        def fake_run_tool(cmd, timeout=0):
            captured["cmd"] = list(cmd)
            # Guard the index so a command-shape change fails with a clear
            # message, not an opaque ValueError/IndexError (#587).
            self.assertIn("--requirement", cmd)
            req_idx = cmd.index("--requirement")
            self.assertLess(req_idx + 1, len(cmd),
                            "--requirement is the last argument with no value")
            with open(cmd[req_idx + 1]) as fh:
                captured["reqs"] = fh.read()
            return b"{}", 0
        with mock.patch.object(pa, "run_tool", fake_run_tool):
            pa.PipAuditAdapter().invoke(target)
        self.assertNotIn(target, captured["cmd"])
        self.assertIn("requests==2.25.1", captured["reqs"])

    def test_invoke_reports_nonzero_exit(self):
        import contextlib, io
        adapter = pa.PipAuditAdapter()
        fake_run = FakePopen(stdout=b"audit output", stderr=b"pip-audit failed",
                             returncode=2)
        buf = io.StringIO()
        with mock.patch("scripts.tools.base.subprocess.Popen", return_value=fake_run), \
             mock.patch("scripts.tools.pip_audit.glob.glob", return_value=["/tmp/fake/requirements.txt"]), \
             contextlib.redirect_stderr(buf):
            stdout, rc = adapter.invoke("/tmp/fake")
        self.assertEqual(stdout, b"audit output")
        self.assertEqual(rc, 2)
        self.assertIn("tool pip-audit exited 2", buf.getvalue())
        self.assertIn("pip-audit failed", buf.getvalue())

    def test_invoke_dynamic_pyproject_returns_empty_without_running(self):
        target = self._target(PYPROJECT_DYNAMIC)
        buf = io.StringIO()
        with mock.patch.object(pa, "run_tool") as rt_mock, \
             contextlib.redirect_stderr(buf):
            raw, rc = pa.PipAuditAdapter().invoke(target)
        rt_mock.assert_not_called()
        self.assertEqual((json.loads(raw), rc),
                         ({"dependencies": [], "fixes": []}, 0))
        self.assertIn("no static [project.dependencies]", buf.getvalue())

    def test_non_utf8_pyproject_returns_none(self):
        deps = pa._deps_from_pyproject(
            self._target(b'\xff\xfe[project]\nname = "x"\n'))
        self.assertIsNone(deps)


if __name__ == "__main__":
    unittest.main()
