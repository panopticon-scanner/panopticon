"""Tests for scripts.phases.child: the driver's phase children.

Split out of tests/phases/test_runio.py with the module itself. It lives HERE
rather than under tests/phases/ because `.panopticon/groups.yml` claims
`skill/scripts/phases/child.py` under `Orchestration:Core` -- `Phases` is full
at 48/48 -- and a cell's test inventory is built from the claiming group's
`tests:` axis, so the tests have to sit where that group can claim them (#1638
P13).
"""
import subprocess
import unittest
from unittest import mock

import scripts.phases.child as child
import scripts.phases.runio as runio


class TestRunChildTimeout(unittest.TestCase):
    """#1094: the discovery/tools/synthesize spawn point is time-bounded, and a
    phase timeout is a clean DriverError (status:error), not an unbounded hang."""

    def test_passes_phase_timeout(self):
        seen = {}
        def fake_run(cmd, **kw):
            seen.update(kw)
            return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        with mock.patch("subprocess.run", side_effect=fake_run), \
             mock.patch("scripts.phases.child._child_env", return_value={}):
            child._run_child(["python", "discovery.py"], "/tmp", "discovery")
        self.assertEqual(seen.get("timeout"), child._CHILD_TIMEOUTS["discovery"])

    def test_timeout_becomes_driver_error(self):
        def fake_run(cmd, **kw):
            raise subprocess.TimeoutExpired(cmd, kw.get("timeout"))
        with mock.patch("subprocess.run", side_effect=fake_run), \
             mock.patch("scripts.phases.child._child_env", return_value={}):
            with self.assertRaises(runio.DriverError):
                child._run_child(["python", "tools.py"], "/tmp", "tools")
