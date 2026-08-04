import contextlib
import io
import unittest
import sys, os
from unittest import mock
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, "skill"))
import scripts.tools.base as base


class TestBase(unittest.TestCase):
    def test_normalize_severity_maps_common_values(self):
        self.assertEqual(base.normalize_severity("critical"), "CRITICAL")
        self.assertEqual(base.normalize_severity("high"), "HIGH")
        self.assertEqual(base.normalize_severity("moderate"), "MEDIUM")
        self.assertEqual(base.normalize_severity("low"), "LOW")
        self.assertEqual(base.normalize_severity("info"), "INFO")
        self.assertEqual(base.normalize_severity("unknown"), "INFO")

    def test_new_finding_id_increments(self):
        self.assertEqual(base.new_finding_id("PA", 1), "PA-001")
        self.assertEqual(base.new_finding_id("PA", 12), "PA-012")

    def test_omit_none_removes_none_values(self):
        self.assertEqual(base.omit_none({"a": 1, "b": None, "c": ""}), {"a": 1, "c": ""})

    def test_omit_none_returns_empty_dict_when_all_none(self):
        self.assertEqual(base.omit_none({"a": None, "b": None}), {})

    def test_omit_none_preserves_zero_and_false(self):
        self.assertEqual(base.omit_none({"a": 0, "b": False, "c": None}), {"a": 0, "b": False})

    def test_attach_tool_provenance_adds_tool_status(self):
        finding = {"id": "TEST-001"}
        base.attach_tool_provenance(finding, "demo", reasoning="rule-123")
        self.assertEqual(finding["provenance"]["discovered_by"], "tool:demo")
        self.assertEqual(finding["provenance"]["confirmation_status"], "TOOL")
        self.assertEqual(finding["provenance"]["confirmation_reasoning"], "rule-123")


if __name__ == "__main__":
    unittest.main()


class TestRunTool(unittest.TestCase):
    """F-CAL-1: adapter failures must not be undiagnosable — run_tool logs a
    capped stderr excerpt whenever the tool exits outside (0, 1)."""

    def test_returns_stdout_and_rc(self):
        with mock.patch("scripts.tools.base.subprocess.run",
                        return_value=mock.Mock(stdout=b"{}", stderr=b"", returncode=0)):
            out, rc = base.run_tool(["tool", "--x"], timeout=5)
        self.assertEqual((out, rc), (b"{}", 0))

    def test_error_exit_logs_stderr_excerpt(self):
        err = io.StringIO()
        with mock.patch("scripts.tools.base.subprocess.run",
                        return_value=mock.Mock(stdout=b"", stderr=b"boom: bad flag",
                                               returncode=2)), \
             contextlib.redirect_stderr(err):
            out, rc = base.run_tool(["tool"], timeout=5)
        self.assertEqual(rc, 2)
        self.assertIn("boom: bad flag", err.getvalue())
        self.assertIn("tool", err.getvalue())

    def test_stderr_excerpt_is_capped(self):
        err = io.StringIO()
        with mock.patch("scripts.tools.base.subprocess.run",
                        return_value=mock.Mock(stdout=b"", stderr=b"x" * 5000,
                                               returncode=3)), \
             contextlib.redirect_stderr(err):
            base.run_tool(["tool"], timeout=5)
        self.assertLess(len(err.getvalue()), 1500)

    def test_findings_exit_one_does_not_log(self):
        err = io.StringIO()
        with mock.patch("scripts.tools.base.subprocess.run",
                        return_value=mock.Mock(stdout=b"[]", stderr=b"warnings",
                                               returncode=1)), \
             contextlib.redirect_stderr(err):
            out, rc = base.run_tool(["tool"], timeout=5)
        self.assertEqual(rc, 1)
        self.assertEqual(err.getvalue(), "")

    def test_passes_through_cwd_and_env(self):
        rec = mock.Mock(return_value=mock.Mock(stdout=b"", stderr=b"", returncode=0))
        with mock.patch("scripts.tools.base.subprocess.run", rec):
            base.run_tool(["t"], timeout=7, cwd="/x", env={"A": "1"})
        rec.assert_called_once_with(["t"], capture_output=True, timeout=7,
                                    cwd="/x", env={"A": "1"})
