"""Tests for scripts.phases.child: the driver's phase children.

Split out of tests/phases/test_runio.py with the module itself. It lives HERE
rather than under tests/phases/ because `.panopticon/groups.yml` claims
`skill/scripts/phases/child.py` under `Orchestration:Core` -- `Phases` is full
at 48/48 -- and a cell's test inventory is built from the claiming group's
`tests:` axis, so the tests have to sit where that group can claim them (#1638
P13).
"""
import io
import os
import shutil
import signal
import sys
import tempfile
import time
import unittest
from unittest import mock

import scripts.phases.child as child
import scripts.phases.runio as runio


class _ChildCase(unittest.TestCase):
    """A real child, never a shell builtin by name.

    Every child here is `sys.executable -c ...` -- an absolute interpreter path
    and a program on the command line -- so the case runs identically under the
    PATH shim (which stubs every host binary and must log nothing) and under an
    empty PATH, where a lookup by name would fail and prove nothing about the
    code under test.
    """

    def setUp(self):
        self.root = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def _child(self, code, phase="discovery", timeout=60):
        return child._run_child([sys.executable, "-c", code], self.root, phase,
                                timeout=timeout)


class _FakeProc:
    """A Popen stand-in with both pipes already at EOF, for the one assertion
    that is about the TIMEOUT ARGUMENT rather than about a real child."""
    returncode = 0

    def __init__(self, seen):
        self._seen = seen
        self.stdout = io.StringIO("")
        self.stderr = io.StringIO("")

    def wait(self, timeout=None):
        self._seen["timeout"] = timeout
        return 0


class TestRunChildTimeout(_ChildCase):
    """#1094: the discovery/tools/synthesize spawn point is time-bounded, and a
    phase timeout is a clean DriverError (status:error), not an unbounded hang."""

    def test_passes_phase_timeout(self):
        seen = {}
        with mock.patch.object(child.subprocess, "Popen",
                               return_value=_FakeProc(seen)), \
             mock.patch.object(child, "_child_env", return_value={}):
            child._run_child([sys.executable, "discovery.py"], self.root, "discovery")
        self.assertEqual(seen.get("timeout"), child._CHILD_TIMEOUTS["discovery"])

    def test_timeout_becomes_driver_error(self):
        with self.assertRaises(runio.DriverError) as ctx:
            self._child("import time\ntime.sleep(60)\n", phase="tools", timeout=1)
        self.assertIn("timed out", str(ctx.exception))

    def test_a_spawn_failure_is_a_driver_error(self):
        with self.assertRaises(runio.DriverError) as ctx:
            child._run_child([os.path.join(self.root, "nope")], self.root,
                             "discovery", timeout=10)
        self.assertIn("could not spawn", str(ctx.exception))


class TestRunChildCapture(_ChildCase):
    """#1576 (OPS-D1A): `_run_child` used `capture_output=True`, which routes
    both streams through `Popen.communicate()` and buffers each ENTIRELY in the
    driver before returning. Nothing bounded the SIZE -- only the wall clock,
    and the tools phase allows 7200s of it. A scanner harness, or `discovery.py`
    over a pathological tree, emits output proportional to file/match count, and
    every byte of it was a Python string in the controller until the child
    exited.

    The bound keeps the HEAD, which is what a diagnostic needs (`tools_execute`
    reads the first 300 characters of stderr for its note), marks what it
    dropped, and drains the rest. Draining matters as much as capping: a child
    whose pipe fills blocks on write for ever, which is the hang the timeout
    exists to bound.
    """

    def test_a_child_that_floods_stdout_is_capped(self):
        proc = self._child(
            "import sys\n"
            "for _ in range(50):\n"
            "    sys.stdout.write('x' * (1024 * 1024))\n")
        self.assertEqual(proc.returncode, 0)
        self.assertLess(len(proc.stdout), child.CAPTURE_BYTES_MAX + 200)
        self.assertIn("[cut", proc.stdout)

    def test_a_child_that_floods_stderr_is_capped(self):
        proc = self._child(
            "import sys\n"
            "for _ in range(50):\n"
            "    sys.stderr.write('e' * (1024 * 1024))\n")
        self.assertLess(len(proc.stderr), child.CAPTURE_BYTES_MAX + 200)
        self.assertIn("[cut", proc.stderr)

    def test_the_line_ceiling_bites_before_the_byte_ceiling(self):
        n = child.CAPTURE_LINES_MAX + 5000
        proc = self._child("import sys\n"
                           "for i in range(%d):\n"
                           "    sys.stdout.write('%%d\\n' %% i)\n" % n)
        head = proc.stdout.split("\n\u2026 [cut")[0]
        self.assertEqual(head.count("\n"), child.CAPTURE_LINES_MAX)
        self.assertIn("[cut", proc.stdout)

    def test_an_ordinary_child_is_unchanged(self):
        proc = self._child("import sys\n"
                           "sys.stdout.write('out\\n')\n"
                           "sys.stderr.write('err\\n')\n"
                           "sys.exit(3)\n")
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(proc.stdout, "out\n")
        self.assertEqual(proc.stderr, "err\n")
        self.assertNotIn("[cut", proc.stdout)

    def test_the_head_is_kept_not_the_tail(self):
        proc = self._child(
            "import sys\n"
            "sys.stdout.write('FIRST\\n')\n"
            "for _ in range(3):\n"
            "    sys.stdout.write('x' * (1024 * 1024))\n"
            "sys.stdout.write('LAST\\n')\n")
        self.assertTrue(proc.stdout.startswith("FIRST\n"))
        self.assertNotIn("LAST", proc.stdout)

    def test_one_enormous_line_is_still_bounded(self):
        # The byte ceiling has to hold on a stream with no newline in it at
        # all. `readline(_CAPTURE_CHUNK)` is bounded BY that chunk as well as by
        # the newline, so this arrives in 64 KiB slices; an unbounded
        # `readline()` would have held the whole 8 MiB looking for a newline
        # that is not there.
        proc = self._child("import sys\n"
                           "sys.stdout.write('y' * 8 * 1024 * 1024)\n")
        self.assertLess(len(proc.stdout), child.CAPTURE_BYTES_MAX + 200)
        self.assertIn("[cut", proc.stdout)


class TestATimeoutReachesTheWholeProcessTree(_ChildCase):
    """#1575 (OPS-A1A): the timeout did not BIND.

    `_run_child` started the child in the driver's own process group and, on
    timeout, killed the direct PID only. A phase child that forked a worker --
    `run_tools.py` launching a scanner, a scanner launching its own workers --
    left that worker alive, holding the stdout pipe it inherited; the reader
    never saw EOF, and the descendant went on running after the driver had
    reported the phase timed out. That is the opposite failure from "no
    timeout": a nominal deadline that bounds one process out of a tree.

    `start_new_session=True` makes the child its own group leader, so one
    `killpg` reaches everything it spawned.
    """

    def _orphan_maker(self, pidfile):
        return (
            "import subprocess, sys, time\n"
            "p = subprocess.Popen([sys.executable, '-c',"
            " 'import time; time.sleep(60)'])\n"
            "open(%r, 'w').write(str(p.pid))\n"
            "time.sleep(60)\n" % pidfile)

    @staticmethod
    def _alive(pid):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:      # pragma: no cover - alive, not ours
            return True
        return True

    def test_the_grandchild_does_not_outlive_the_timeout(self):
        pidfile = os.path.join(self.root, "grandchild.pid")
        with self.assertRaises(runio.DriverError):
            self._child(self._orphan_maker(pidfile), timeout=2)
        pid = int(open(pidfile, encoding="utf-8").read())
        self.addCleanup(self._reap, pid)
        for _ in range(100):                      # bounded poll, never a sleep(n)
            if not self._alive(pid):
                break
            time.sleep(0.05)
        self.assertFalse(self._alive(pid),
                         "the timeout killed the child and left its worker running")

    def _reap(self, pid):
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass

    def test_the_child_leads_its_own_session(self):
        # The property the kill depends on, asserted directly: the child's
        # process-group id is its own pid, not the driver's group.
        seen = {}
        real_popen = child.subprocess.Popen

        def spy(cmd, **kw):
            seen.update(kw)
            return real_popen(cmd, **kw)

        with mock.patch.object(child.subprocess, "Popen", side_effect=spy):
            self._child("import sys\nsys.stdout.write('ok')\n")
        self.assertIs(seen.get("start_new_session"), True)

    def test_an_ordinary_timeout_is_still_a_driver_error(self):
        with self.assertRaises(runio.DriverError) as ctx:
            self._child("import time\ntime.sleep(30)\n", timeout=1)
        self.assertIn("timed out", str(ctx.exception))

    def test_kill_group_tolerates_a_process_that_is_already_gone(self):
        proc = child.subprocess.Popen([sys.executable, "-c", "pass"],
                                      start_new_session=True)
        proc.wait()
        child._kill_group(proc, grace=0.1)     # must not raise


class TestTheHeadSurvivesAReaderThatIsCutOff(_ChildCase):
    """Item 24 R1-2: the head was published only at EOF, so a reader joined out
    at `_READER_JOIN_GRACE` yielded NOTHING.

    Measured: a child writes a diagnostic line, spawns a worker that inherits
    its stdout/stderr, and exits non-zero. `proc.wait()` returns at once, but
    the worker holds the write ends, so no EOF ever arrives -- and the reader
    was blocked inside `stream.read(_CAPTURE_CHUNK)`, which returns only when
    the full chunk or EOF is available. Both readers were joined out in turn,
    `into[name]` had never been assigned, and `_run_child` returned
    `stdout == stderr == ""` ten seconds later. `phases/tools.py` then recorded
    "tool scan crashed" with the reason it had been handed deleted.

    The reason a child gives for dying is the single most valuable thing it
    produces. It has to survive a reader that never reaches EOF.
    """

    def _worker_holder(self, pidfile):
        return ("import subprocess, sys\n"
                "sys.stdout.write('DIAGNOSTIC: adapter exploded\\n')\n"
                "sys.stderr.write('Traceback: the reason\\n')\n"
                "sys.stdout.flush(); sys.stderr.flush()\n"
                "p = subprocess.Popen([sys.executable, '-c',"
                " 'import time; time.sleep(30)'])\n"
                "open(%r, 'w').write(str(p.pid))\n"
                "sys.exit(4)\n" % pidfile)

    def _reap(self, pidfile):
        try:
            pid = int(open(pidfile, encoding="utf-8").read())
        except (OSError, ValueError):       # pragma: no cover - never written
            return
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass

    def test_the_diagnostic_survives_and_the_join_is_bounded(self):
        pidfile = os.path.join(self.root, "worker.pid")
        self.addCleanup(self._reap, pidfile)
        started = time.monotonic()
        proc = self._child(self._worker_holder(pidfile), timeout=60)
        elapsed = time.monotonic() - started
        self.assertEqual(proc.returncode, 4)
        self.assertIn("DIAGNOSTIC: adapter exploded", proc.stdout)
        self.assertIn("Traceback: the reason", proc.stderr)
        # Both readers are cut off, and the two joins share ONE deadline --
        # otherwise the bound is per-reader and the driver stalls for twice it.
        self.assertLess(elapsed, child._READER_JOIN_GRACE + 4,
                        "the join grace is per-reader, not shared")

    def test_a_cut_off_head_says_so(self):
        # A head that stops early must never read as a complete one -- the same
        # rule the `[cut N characters]` marker exists for.
        pidfile = os.path.join(self.root, "worker.pid")
        self.addCleanup(self._reap, pidfile)
        proc = self._child(self._worker_holder(pidfile), timeout=60)
        self.assertIn("… [", proc.stdout)
        self.assertNotIn("… [", self._child(
            "import sys\nsys.stdout.write('done\\n')\n").stdout)
