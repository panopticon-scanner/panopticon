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
import sys
import tempfile
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
        # The byte ceiling has to hold on a stream with no newline in it at all;
        # a line-based reader would have held the whole thing to find one.
        proc = self._child("import sys\n"
                           "sys.stdout.write('y' * 8 * 1024 * 1024)\n")
        self.assertLess(len(proc.stdout), child.CAPTURE_BYTES_MAX + 200)
        self.assertIn("[cut", proc.stdout)
