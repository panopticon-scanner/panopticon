import contextlib
import io
import os
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

from _test_helpers import FakePopen
import scripts.tools.base as base


class _ImmediateTimer:
    """threading.Timer stand-in that fires its callback synchronously when
    start() is called. Lets timeout paths be exercised without real delays."""

    def __init__(self, interval, function, args=None, kwargs=None):
        self.function = function
        self.args = args or ()
        self.kwargs = kwargs or {}

    def start(self):
        self.function(*self.args, **self.kwargs)

    def cancel(self):
        pass

    @property
    def daemon(self):
        return False

    @daemon.setter
    def daemon(self, value):
        pass


class TestBase(unittest.TestCase):
    def test_run_tool_rejects_unsafe_args_or_env(self):
        with self.assertRaises(Exception):
            base.run_tool(["tool", ";", "rm", "-rf", "/"], env={"LD_PRELOAD": "malicious.so"})

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
    capped stderr excerpt whenever the tool exits outside (0, 1).

    OPS-D1A: stdout capture is bounded so adversarial/large output cannot
    exhaust orchestrator memory.
    """

    def test_returns_stdout_and_rc(self):
        fake = FakePopen(stdout=b"{}", stderr=b"", returncode=0)
        with mock.patch("scripts.tools.base.subprocess.Popen", return_value=fake):
            out, rc = base.run_tool(["tool", "--x"], timeout=5)
        self.assertEqual((out, rc), (b"{}", 0))

    def test_error_exit_logs_stderr_excerpt(self):
        err = io.StringIO()
        fake = FakePopen(stdout=b"", stderr=b"boom: bad flag", returncode=2)
        with mock.patch("scripts.tools.base.subprocess.Popen", return_value=fake), \
             contextlib.redirect_stderr(err):
            out, rc = base.run_tool(["tool"], timeout=5)
        self.assertEqual(rc, 2)
        self.assertIn("boom: bad flag", err.getvalue())
        self.assertIn("tool", err.getvalue())

    def test_stderr_excerpt_is_capped(self):
        err = io.StringIO()
        fake = FakePopen(stdout=b"", stderr=b"x" * 5000, returncode=3)
        with mock.patch("scripts.tools.base.subprocess.Popen", return_value=fake), \
             contextlib.redirect_stderr(err):
            base.run_tool(["tool"], timeout=5)
        self.assertLess(len(err.getvalue()), 1500)

    def test_stderr_capture_buffer_is_bounded(self):
        # run-8 COD-A2A: a tool flooding stderr must not accumulate unbounded in
        # memory — the drain buffer is capped like stdout. Feed many chunks so the
        # cap engages mid-stream (a real pipe read returns <=64KB per call).
        chunk = b"e" * (64 * 1024)
        n = (base.MAX_TOOL_STDERR_BYTES // len(chunk)) + 40
        fake = FakePopen(stdout=b"{}", stderr=[chunk] * n, returncode=0)
        with mock.patch("scripts.tools.base.subprocess.Popen", return_value=fake):
            out, err, rc = base.run_tool(["tool"], timeout=5, capture_stderr=True)
        self.assertEqual((out, rc), (b"{}", 0))
        self.assertLessEqual(len(err), base.MAX_TOOL_STDERR_BYTES + len(chunk))
        self.assertLess(len(err), n * len(chunk))

    def test_findings_exit_one_does_not_log(self):
        err = io.StringIO()
        fake = FakePopen(stdout=b"[]", stderr=b"warnings", returncode=1)
        with mock.patch("scripts.tools.base.subprocess.Popen", return_value=fake), \
             contextlib.redirect_stderr(err):
            out, rc = base.run_tool(["tool"], timeout=5)
        self.assertEqual(rc, 1)
        self.assertEqual(err.getvalue(), "")

    def test_passes_through_cwd_and_env(self):
        rec = mock.Mock(side_effect=lambda *a, **kw: FakePopen(*a, **kw))
        with mock.patch("scripts.tools.base.subprocess.Popen", rec):
            base.run_tool(["t"], timeout=7, cwd="/x", env={"A": "1"})
        rec.assert_called_once_with(["t"], stdout=base.subprocess.PIPE,
                                    stderr=base.subprocess.PIPE,
                                    cwd="/x", env={"A": "1"})

    def test_timeout_expired_propagates(self):
        fake = FakePopen(stdout=b"x", stderr=b"", returncode=0)
        with mock.patch("scripts.tools.base.subprocess.Popen", return_value=fake), \
             mock.patch("scripts.tools.base.threading.Timer", _ImmediateTimer):
            with self.assertRaises(base.subprocess.TimeoutExpired):
                base.run_tool(["t"], timeout=5)

    def test_output_exceeds_cap_truncates_with_marker_and_nonzero_rc(self):
        err = io.StringIO()
        with mock.patch.object(base, "MAX_TOOL_OUTPUT_BYTES", 1024):
            chunks = [b"x" * 512, b"x" * 512, b"x" * 512]
            fake = FakePopen(stdout=chunks, stderr=b"", returncode=0)
            with mock.patch("scripts.tools.base.subprocess.Popen", return_value=fake), \
                 contextlib.redirect_stderr(err):
                out, rc = base.run_tool(["tool"], timeout=5)
        marker = (
            b"\n\n[TRUNCATED by panopticon: output exceeded 1024 byte limit; "
            b"only the first 1024 bytes were retained]\n"
        )
        self.assertTrue(out.startswith(b"x" * 1024))
        self.assertTrue(out.endswith(marker))
        self.assertEqual(len(out), 1024 + len(marker))
        self.assertNotEqual(rc, 0)
        self.assertIn("exceeded 1024 byte limit", err.getvalue())

    def test_concurrent_stdout_stderr_no_deadlock(self):
        # A child that fills the stderr pipe before writing stdout would
        # deadlock if run_tool read stdout to EOF before touching stderr.
        script = textwrap.dedent("""
            import sys
            sys.stderr.write('e' * 200000)
            sys.stderr.flush()
            sys.stdout.write('done')
            sys.stdout.flush()
        """)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py",
                                          delete=False) as fh:
            fh.write(script)
            path = fh.name
        try:
            out, rc = base.run_tool([sys.executable, path], timeout=10)
            self.assertEqual(rc, 0)
            self.assertIn(b"done", out)
        finally:
            os.unlink(path)

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
