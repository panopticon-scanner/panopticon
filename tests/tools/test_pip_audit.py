import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
import scripts.tools.pip_audit as pa

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

    def test_parse_uses_actual_manifest_path(self):
        adapter = pa.PipAuditAdapter()
        adapter._manifest_path = "/tmp/fake/pyproject.toml"
        findings = adapter.parse(PIP_AUDIT_SAMPLE, "g1")
        self.assertEqual(findings[0]["location"]["file"], "/tmp/fake/pyproject.toml")

    def test_parse_defaults_location_file_when_no_manifest(self):
        adapter = pa.PipAuditAdapter()
        findings = adapter.parse(PIP_AUDIT_SAMPLE, "g1")
        self.assertEqual(findings[0]["location"]["file"], "requirements.txt")

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

    def test_invoke_uses_requirements_txt_when_present(self):
        adapter = pa.PipAuditAdapter()
        fake_run = mock.Mock(return_value=mock.Mock(stdout=b"[]", returncode=0))
        with mock.patch("scripts.tools.pip_audit.subprocess.run", fake_run):
            with mock.patch("scripts.tools.pip_audit.glob.glob", return_value=["/tmp/fake/requirements.txt"]):
                stdout, rc = adapter.invoke("/tmp/fake")
        self.assertEqual(stdout, b"[]")
        self.assertEqual(rc, 0)
        fake_run.assert_called_once_with(
            ["pip-audit", "--format=json", "--desc", "--requirement", "/tmp/fake/requirements.txt"],
            capture_output=True,
            timeout=300,
        )

    def test_invoke_falls_back_to_pyproject_toml(self):
        adapter = pa.PipAuditAdapter()
        fake_run = mock.Mock(return_value=mock.Mock(stdout=b"[]", returncode=0))
        with mock.patch("scripts.tools.pip_audit.subprocess.run", fake_run):
            with mock.patch("scripts.tools.pip_audit.glob.glob", return_value=[]):
                stdout, rc = adapter.invoke("/tmp/fake")
        self.assertEqual(stdout, b"[]")
        self.assertEqual(rc, 0)
        fake_run.assert_called_once_with(
            ["pip-audit", "--format=json", "--desc", "/tmp/fake"],
            capture_output=True,
            timeout=300,
        )


if __name__ == "__main__":
    unittest.main()
