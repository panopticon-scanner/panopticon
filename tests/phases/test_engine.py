"""Tests for scripts.phases.engine: the phase state machine and its status line.
"""
import io
import json
import unittest

import scripts.phases.engine as engine

from tests.phases.helpers import _fake_phase


class TestRunEngine(unittest.TestCase):
    def test_advances_deterministic_to_complete(self):
        a, _ = _fake_phase("a")
        b, _ = _fake_phase("b")
        c, _ = _fake_phase("c")
        status = engine.run_engine("/root", {}, [a, b, c])
        self.assertEqual(status["status"], "complete")
        # A finished run must SAY to disarm the write-guard: it is fail-closed
        # while registered, so one left armed denies every later Write/Edit in
        # the session, the operator's included.
        self.assertIn("uninstall", status["teardown"])
        self.assertEqual(status["advanced"], ["a", "b", "c"])

    def test_stops_at_first_checkpoint(self):
        a, _ = _fake_phase("a")
        b, _ = _fake_phase("b", done_after=99, result_kind="checkpoint",
                           checkpoint="scout")
        c, _ = _fake_phase("c")
        status = engine.run_engine("/root", {}, [a, b, c])
        self.assertEqual(status["status"], "checkpoint")
        self.assertEqual(status["phase"], "b")
        self.assertEqual(status["checkpoint"], "scout")
        self.assertEqual(status["group"], "G")
        self.assertEqual(status["advanced"], ["a"])   # c never reached

    def test_skips_done_phases_on_resume(self):
        a, sa = _fake_phase("a", done_after=0)   # already done
        b, sb = _fake_phase("b", done_after=0)   # already done
        c, _ = _fake_phase("c")
        status = engine.run_engine("/root", {}, [a, b, c])
        self.assertEqual(status["status"], "complete")
        self.assertEqual(status["advanced"], ["c"])
        self.assertEqual(sa["executes"], 0)      # not re-executed
        self.assertEqual(sb["executes"], 0)

    def test_mixed_phase_reselected_until_done(self):
        # one phase that needs 3 executes (advances one "unit" each) then done
        m, state = _fake_phase("coverage", done_after=3)
        status = engine.run_engine("/root", {}, [m])
        self.assertEqual(status["status"], "complete")
        self.assertEqual(state["executes"], 3)
        self.assertEqual(status["advanced"], ["coverage"])   # deduped

    def test_progress_guard_raises_on_no_progress(self):
        stuck, _ = _fake_phase("stuck", done_after=99)   # never satisfied
        with self.assertRaises(RuntimeError):
            engine.run_engine("/root", {}, [stuck], max_steps=5)

class TestEmitStatus(unittest.TestCase):
    def test_error_status_returns_exit_1(self):
        buf = io.StringIO()
        rc = engine.emit_status({"status": "error", "message": "boom"}, stream=buf)
        self.assertEqual(rc, 1)
        self.assertIn("boom", buf.getvalue())

    def test_checkpoint_and_complete_return_exit_0(self):
        self.assertEqual(engine.emit_status({"status": "checkpoint"},
                                            stream=io.StringIO()), 0)
        self.assertEqual(engine.emit_status({"status": "complete"},
                                            stream=io.StringIO()), 0)

    def test_emits_valid_json(self):
        buf = io.StringIO()
        engine.emit_status({"status": "complete", "phase": None}, stream=buf)
        self.assertEqual(json.loads(buf.getvalue())["status"], "complete")
