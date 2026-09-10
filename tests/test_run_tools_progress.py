"""#1317: a tool scan that says nothing is indistinguishable from one that hung.

`run_tools` can sit inside a single `docker run` for the better part of an hour.
Until this, it emitted nothing while it did, so from a GitHub Actions run page a
healthy scan and a wedged one produced the same artifact -- an absence -- and the
only way to tell them apart was to wait out the timeout.

The half of this that needs pinning is not the formatting. It is that the two
call sites DISAGREE ON PURPOSE: CI passes `--progress`, and the driver must not,
because `phases/tools.py` builds its tool-scan failure note out of the child's
first 300 stderr characters and progress lines would crowd the real error out of
that window. Both halves are asserted below against the real workflow file and
the real command the driver builds, so "tidying up" the inconsistency fails.
"""
import os
import tempfile
import threading
import time
import unittest
from unittest import mock

import yaml

from conftest import REPO_ROOT
from run_tools_test_helpers import _FakeResult
import scripts.run_tools as run_tools
from scripts.progress import PREFIX, NullProgress, StderrProgress, make_progress

# A legacy-SARIF tool and an adapter, so both dispatch paths are covered.
LEGACY = "semgrep"
ADAPTER = "brakeman"


class _Sink:
    """A thread-safe stand-in for stderr: the heartbeat writes from its own
    thread while the test reads, and a bare StringIO makes that a race."""

    def __init__(self):
        self._lock = threading.Lock()
        self._parts = []

    def write(self, text):
        with self._lock:
            self._parts.append(text)

    def flush(self):
        pass

    def text(self):
        with self._lock:
            return "".join(self._parts)

    def lines(self):
        return [line for line in self.text().splitlines() if line.strip()]


def _runner(payload=b'{"runs": []}'):
    """A runner returning a CompletedProcess-alike, which _capture_run accepts
    without ever reaching Docker."""
    def run(cmd, stdout=None, stderr=None, timeout=None):
        return _FakeResult(0, payload)
    return run


class _RunTools(unittest.TestCase):
    def scan(self, tools, progress=None, payload=b'{"runs": []}'):
        with tempfile.TemporaryDirectory() as target, \
                tempfile.TemporaryDirectory() as out_dir:
            written = run_tools.run_tools(target, tools, out_dir,
                                          runner=_runner(payload),
                                          progress=progress)
            return target, written


class TestSilentByDefault(_RunTools):
    def test_no_progress_argument_emits_nothing(self):
        sink = _Sink()
        with mock.patch("sys.stderr", sink):
            self.scan([LEGACY, ADAPTER])
        self.assertNotIn(PREFIX, sink.text(),
                         "run_tools must be byte-identical on stderr unless a "
                         "caller opts in; the driver depends on that")

    def test_the_default_is_a_working_no_op_not_a_none(self):
        # If the default were None, every call site would need its own guard
        # and the one that got forgotten would raise mid-scan.
        _, written = self.scan([LEGACY])
        self.assertEqual(1, len(written))


class TestTheLinesSayWhatHappened(_RunTools):
    def _scan_with_progress(self, tools, payload=b'{"runs": []}'):
        sink = _Sink()
        progress = StderrProgress(stream=sink, heartbeat=0)
        _, written = self.scan(tools, progress=progress, payload=payload)
        return sink.lines(), written

    def test_a_header_a_line_per_tool_and_a_footer(self):
        lines, _ = self._scan_with_progress([LEGACY, ADAPTER])
        self.assertTrue(lines[0].startswith("%s scanning " % PREFIX), lines[0])
        self.assertIn("with 2 tools", lines[0])
        self.assertIn("[1/2] %s started" % LEGACY, lines[1])
        self.assertIn("[2/2] %s started" % ADAPTER, lines[3])
        self.assertIn("2/2 tools produced output", lines[-1])

    def test_each_tool_reports_its_own_outcome(self):
        lines, _ = self._scan_with_progress([LEGACY])
        done = [line for line in lines if " ok in " in line]
        self.assertEqual(1, len(done), lines)
        self.assertIn("[1/1] %s ok in " % LEGACY, done[0])

    def test_a_tool_that_produced_nothing_is_named_not_omitted(self):
        # The whole point. A selected tool that emits nothing is the #1051
        # fail-closed case; a progress log that simply skipped it would be the
        # vacuous-green shape this feature exists to break.
        lines, written = self._scan_with_progress([LEGACY], payload=b"")
        self.assertEqual([], written)
        self.assertTrue(any("NO OUTPUT" in line for line in lines), lines)
        self.assertIn("0/1 tools produced output", lines[-1])

    def test_the_footer_counts_what_was_produced_not_what_was_selected(self):
        lines, _ = self._scan_with_progress([LEGACY, ADAPTER], payload=b"")
        self.assertIn("0/2 tools produced output", lines[-1])


class TestItGoesToStderr(unittest.TestCase):
    def test_stdout_is_left_alone_because_it_carries_the_result(self):
        # run_tools.main prints the produced artifact paths on stdout; a caller
        # reading them must not have to filter progress out of the stream.
        err, out = _Sink(), _Sink()
        with mock.patch("sys.stderr", err), mock.patch("sys.stdout", out):
            progress = make_progress(True)
            progress.header("/tmp/target", 1)
        self.assertIn(PREFIX, err.text())
        self.assertEqual("", out.text())


class TestHeartbeat(unittest.TestCase):
    def _wait_for(self, sink, needle, timeout=5.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if needle in sink.text():
                return True
            time.sleep(0.01)
        return False

    def test_a_long_running_tool_still_says_something(self):
        sink = _Sink()
        progress = StderrProgress(stream=sink, heartbeat=0.01)
        with progress.tool("semgrep", 1, 1) as step:
            found = self._wait_for(sink, "still running")
            step.finish("/dev/null")
        self.assertTrue(found, sink.text())

    def test_the_heartbeat_stops_when_the_tool_does(self):
        sink = _Sink()
        progress = StderrProgress(stream=sink, heartbeat=0.01)
        with progress.tool("semgrep", 1, 1) as step:
            self._wait_for(sink, "still running")
            step.finish(None)
        settled = len(sink.lines())
        time.sleep(0.1)          # several heartbeat intervals
        self.assertEqual(settled, len(sink.lines()),
                         "the heartbeat thread outlived its step")

    def test_a_zero_interval_disables_it_entirely(self):
        sink = _Sink()
        progress = StderrProgress(stream=sink, heartbeat=0)
        with progress.tool("semgrep", 1, 1) as step:
            time.sleep(0.05)
            step.finish(None)
        self.assertNotIn("still running", sink.text())


class TestProgressNeverFailsAScan(unittest.TestCase):
    def test_a_broken_stream_is_swallowed(self):
        class _Closed:
            def write(self, text):
                raise ValueError("I/O operation on closed file")

            def flush(self):
                raise ValueError("I/O operation on closed file")

        progress = StderrProgress(stream=_Closed(), heartbeat=0)
        progress.header("/tmp/t", 1)          # must not raise
        with progress.tool("semgrep", 1, 1) as step:
            step.finish(None)
        progress.footer(0, 1)


class TestNullProgress(unittest.TestCase):
    def test_every_method_a_caller_uses_exists_and_does_nothing(self):
        null = NullProgress()
        self.assertFalse(null.enabled)
        null.header("/tmp/t", 3)
        null.note("anything")
        with null.tool("semgrep", 1, 3) as step:
            self.assertIsNone(step.finish(None))
            self.assertEqual("x", step.finish("x"))
        null.footer(0, 3)

    def test_make_progress_picks_by_the_flag(self):
        self.assertIsInstance(make_progress(False), NullProgress)
        self.assertIsInstance(make_progress(True), StderrProgress)


class TestTheFlagIsWiredToTheRunner(unittest.TestCase):
    """Assert on the object run_tools actually receives, not on a parsed flag:
    an argument that parses and reaches nothing is the failure mode."""

    def _progress_handed_to_the_runner(self, argv):
        captured = {}

        def fake_run_tools(*args, **kwargs):
            captured["progress"] = kwargs.get("progress")
            return []

        with mock.patch.object(run_tools, "docker_available", return_value=True), \
                mock.patch.object(run_tools, "run_tools", fake_run_tools), \
                mock.patch.object(run_tools, "select_adapters", return_value={}), \
                mock.patch.object(run_tools, "detect_languages", return_value=[]):
            with tempfile.TemporaryDirectory() as target:
                run_tools.main(["--target", target,
                                "--out", os.path.join(target, "out")] + argv)
        return captured["progress"]

    def test_the_flag_turns_on_stderr_progress(self):
        self.assertIsInstance(
            self._progress_handed_to_the_runner(["--progress"]), StderrProgress)

    def test_without_it_the_runner_gets_the_null_object(self):
        self.assertIsInstance(
            self._progress_handed_to_the_runner([]), NullProgress)


class TestTheTwoCallSitesDisagreeOnPurpose(unittest.TestCase):
    """The durable half. Either half of this asymmetry is one edit from being
    "fixed" into the bug it exists to prevent."""

    def test_ci_asks_for_progress(self):
        path = os.path.join(REPO_ROOT, ".github", "workflows", "security.yml")
        with open(path, encoding="utf-8") as fh:
            workflow = yaml.safe_load(fh.read())
        steps = workflow["jobs"]["scan"]["steps"]
        scan = [s for s in steps if "run_tools.py" in (s.get("run") or "")]
        self.assertEqual(1, len(scan),
                         "expected exactly one step invoking run_tools.py; the "
                         "assertion below would otherwise pass over nothing")
        self.assertIn("--progress", scan[0]["run"],
                      "the CI scan step is the one place a long silent tools "
                      "phase is actually watched")

    def test_the_driver_does_not(self):
        from scripts.phases import runio, tools as tools_phase

        captured = {}

        def fake_child(cmd, review_root, phase, timeout=None):
            captured["cmd"] = list(cmd)
            return _FakeResult(0, "", "")

        with tempfile.TemporaryDirectory() as review_root:
            with mock.patch.object(runio, "_run_child", fake_child):
                tools_phase.tools_execute(
                    review_root, {"run_id": "r1", "flags": {"tools": True}})

        cmd = captured["cmd"]
        self.assertTrue(any("run_tools.py" in str(part) for part in cmd),
                        "guard the guard: this is not the tools command (%s)" % cmd)
        self.assertNotIn(
            "--progress", cmd,
            "phases/tools.py builds its failure note from the child's first 300 "
            "stderr characters (tools.py: `raw_err = (proc.stderr or '')"
            ".strip()[:300]`). Progress lines would push the real error out of "
            "that window, so the driver deliberately does not ask for them.")

    def test_the_reason_is_still_true(self):
        # If that 300-char note ever stops being built from the child's stderr,
        # the asymmetry above becomes cargo cult and should be revisited rather
        # than kept out of habit.
        path = os.path.join(REPO_ROOT, "skill", "scripts", "phases", "tools.py")
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
        self.assertIn("proc.stderr", source)
        self.assertIn("[:300]", source)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
