import contextlib
import io
import unittest
from unittest import mock
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

    def test_strip_ansi_removes_csi_sequences(self):
        self.assertEqual(base.strip_ansi(b"\x1b[32mhi\x1b[0m"), b"hi")
        self.assertEqual(base.strip_ansi(b"\x1b[?25l\x1b[2Kx"), b"x")

    def test_strip_ansi_leaves_plain_bytes_unchanged(self):
        self.assertEqual(base.strip_ansi(b'{"a": 1}'), b'{"a": 1}')

    def test_parse_json_bytes_plain_json(self):
        self.assertEqual(base.parse_json_bytes(b'{"a": 1}'), {"a": 1})
        self.assertEqual(base.parse_json_bytes(b'[1, 2]'), [1, 2])

    def test_parse_json_bytes_strips_ansi_progress_preamble(self):
        # pip-audit-style ANSI spinner + progress text before the JSON payload
        raw = (b"\x1b[?25l\x1b[32m-\x1b[0m Collecting inputs\r\x1b[2K"
               b'{"dependencies": [], "fixes": []}\n')
        self.assertEqual(base.parse_json_bytes(raw),
                         {"dependencies": [], "fixes": []})

    def test_parse_json_bytes_raises_on_non_json(self):
        with self.assertRaises(ValueError):
            base.parse_json_bytes(b"not json at all")


if __name__ == "__main__":
    unittest.main()
