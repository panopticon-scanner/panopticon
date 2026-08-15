import io
import json
import os
import tempfile
import unittest

import scripts.driver as driver


def _fake_phase(name, *, done_after=1, result_kind="advanced", checkpoint=None):
    """A fake phase backed by an execute counter (stands in for disk state).
    done() flips True once execute has run `done_after` times."""
    state = {"executes": 0}

    def done(root, manifest):
        return state["executes"] >= done_after

    def execute(root, manifest):
        state["executes"] += 1
        if result_kind == "checkpoint":
            return driver.PhaseResult(kind="checkpoint", checkpoint=checkpoint,
                                      group="G", dispatch_request="/abs/req.json",
                                      message="stop")
        return driver.PhaseResult(kind="advanced")

    return driver.Phase(name=name, kind="deterministic", done=done,
                        execute=execute), state


class TestRunEngine(unittest.TestCase):
    def test_advances_deterministic_to_complete(self):
        a, _ = _fake_phase("a")
        b, _ = _fake_phase("b")
        c, _ = _fake_phase("c")
        status = driver.run_engine("/root", {}, [a, b, c])
        self.assertEqual(status["status"], "complete")
        self.assertEqual(status["advanced"], ["a", "b", "c"])

    def test_stops_at_first_checkpoint(self):
        a, _ = _fake_phase("a")
        b, _ = _fake_phase("b", done_after=99, result_kind="checkpoint",
                           checkpoint="scout")
        c, _ = _fake_phase("c")
        status = driver.run_engine("/root", {}, [a, b, c])
        self.assertEqual(status["status"], "checkpoint")
        self.assertEqual(status["phase"], "b")
        self.assertEqual(status["checkpoint"], "scout")
        self.assertEqual(status["group"], "G")
        self.assertEqual(status["advanced"], ["a"])   # c never reached

    def test_skips_done_phases_on_resume(self):
        a, sa = _fake_phase("a", done_after=0)   # already done
        b, sb = _fake_phase("b", done_after=0)   # already done
        c, _ = _fake_phase("c")
        status = driver.run_engine("/root", {}, [a, b, c])
        self.assertEqual(status["status"], "complete")
        self.assertEqual(status["advanced"], ["c"])
        self.assertEqual(sa["executes"], 0)      # not re-executed
        self.assertEqual(sb["executes"], 0)

    def test_mixed_phase_reselected_until_done(self):
        # one phase that needs 3 executes (advances one "unit" each) then done
        m, state = _fake_phase("coverage", done_after=3)
        status = driver.run_engine("/root", {}, [m])
        self.assertEqual(status["status"], "complete")
        self.assertEqual(state["executes"], 3)
        self.assertEqual(status["advanced"], ["coverage"])   # deduped

    def test_progress_guard_raises_on_no_progress(self):
        stuck, _ = _fake_phase("stuck", done_after=99)   # never satisfied
        with self.assertRaises(RuntimeError):
            driver.run_engine("/root", {}, [stuck], max_steps=5)


class TestEmitStatus(unittest.TestCase):
    def test_error_status_returns_exit_1(self):
        buf = io.StringIO()
        rc = driver.emit_status({"status": "error", "message": "boom"}, stream=buf)
        self.assertEqual(rc, 1)
        self.assertIn("boom", buf.getvalue())

    def test_checkpoint_and_complete_return_exit_0(self):
        self.assertEqual(driver.emit_status({"status": "checkpoint"},
                                            stream=io.StringIO()), 0)
        self.assertEqual(driver.emit_status({"status": "complete"},
                                            stream=io.StringIO()), 0)

    def test_emits_valid_json(self):
        buf = io.StringIO()
        driver.emit_status({"status": "complete", "phase": None}, stream=buf)
        self.assertEqual(json.loads(buf.getvalue())["status"], "complete")


class TestWriteDispatchRequest(unittest.TestCase):
    def test_writes_host_agnostic_request(self):
        with tempfile.TemporaryDirectory() as root:
            entries = [{"id": "e1", "agent": "panopticon-scout", "enforced": True,
                        "model": None, "prompt": "…", "out_file": "/abs/scout-Auth.json"}]
            path = driver.write_dispatch_request(root, "RID", "scout", "Auth", entries)
            self.assertTrue(path.endswith(".panopticon/dispatch-request.json"))
            self.assertEqual(path, os.path.abspath(path))
            with open(path) as fh:
                req = json.load(fh)
            self.assertEqual(req["checkpoint"], "scout")
            self.assertEqual(req["run_id"], "RID")
            self.assertEqual(req["group"], "Auth")
            self.assertEqual(req["entries"][0]["out_file"], "/abs/scout-Auth.json")
            # host-agnostic: no per-host delivery block
            self.assertNotIn("delivery", req["entries"][0])

    def test_unknown_checkpoint_kind_raises(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(ValueError):
                driver.write_dispatch_request(root, "RID", "bogus", "Auth", [])


if __name__ == "__main__":
    unittest.main()
