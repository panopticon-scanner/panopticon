"""#3350: drain-and-pause -- SIGUSR1 stops a headless loop launching, lets the running
entries finish and exits `paused`, resumable without `--reset`."""
import contextlib
import glob
import io
import os
import signal
import threading
import unittest
from unittest import mock

import scripts.loop_batch as loop_batch
import scripts.loop_setup as loop_setup
import scripts.orchestrate as orchestrate
import scripts.phases.runio as runio
import scripts.runners.base as base
from tests._test_helpers import all_proven_artifact as _all_proven_artifact
from tests._test_helpers import docker_probe_runner
from tests.orchestrate_helpers import FakeRunner, LoopCase


def setUpModule():
    global _patches
    _patches = [mock.patch("scripts.host_probes.run_probes",
                           side_effect=lambda host, target, **kw: _all_proven_artifact(host)),
                mock.patch("scripts.phases.readiness_checks.DOCKER_RUNNER", docker_probe_runner())]
    for p in _patches:
        p.start()


def tearDownModule():
    for p in _patches:
        p.stop()


FLOOR = ("SEC", "ACC", "ARC", "TST")


class PausesDuringFirstReview(FakeRunner):
    """Sets the pause the way the SIGUSR1 handler does, while the FIRST review entry is still
    running -- the moment a worker would otherwise turn over and launch the next one."""

    def __init__(self, pause):
        super().__init__()
        self.pause = pause

    def run_entry(self, entry, env):
        if entry["id"].startswith("review-") and not self.pause.is_set():
            self.pause.event.set()
        return super().run_entry(entry, env)


class _PauseLoop(LoopCase):

    def _loop(self, d, floor, runner, pause, *extra, seed=True):
        args = self._args(d, "--concurrency", "1", *extra)
        err = io.StringIO()
        with mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=lambda rr: seed and self._seed_coverage(rr, floor)), \
                mock.patch("scripts.runners.base.runner_for", return_value=runner), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            status = orchestrate.loop(args, pause=pause)
        return status, err.getvalue()

    def _attempts(self, d):
        return runio._load_json(runio._pano(d, "cell-attempts.json")) or {}

    def _run_dir(self, d):
        return glob.glob(os.path.join(d, ".panopticon", "runs", "*-*"))[0]



class TestDrainAndPause(_PauseLoop):

    def test_a_pause_mid_batch_finishes_the_running_entry_and_launches_no_more(self):
        d, floor = self._repo(floor=FLOOR)
        pause = loop_setup.PauseRequest()
        runner = PausesDuringFirstReview(pause)
        status, err = self._loop(d, floor, runner, pause)
        self.assertEqual("paused", status["status"], status)
        reviews = [e for e in runner.launched if e.startswith("review-")]
        # The strict gate: width 1, and the worker that finished entry 1 never starts entry 2.
        self.assertEqual(1, len(reviews), runner.launched)
        self.assertIn("paused on request (SIGUSR1): 1 running entry finished and was kept; 3 "
                      "never launched", status["message"])
        self.assertIn("no `--reset`", status["message"])
        self.assertIn("stopped launching after a pause request; 3 of 4 entries not launched", err)
        # ...recorded as usual: its findings file, its ledger row, no batch record left behind.
        run_dir = self._run_dir(d)
        self.assertEqual(1, len(glob.glob(os.path.join(run_dir, "findings-*.json"))))
        with open(os.path.join(run_dir, base.LEDGER_FILE)) as fh:
            self.assertEqual(1, sum('"phase": "review"' in line for line in fh))
        self.assertEqual([], glob.glob(os.path.join(run_dir, "batch-*.json")))
        # ...and only the launched cell keeps its attempt.
        charged = {k: v for k, v in self._attempts(d).items() if v}
        self.assertEqual(1, len(charged), charged)

    def test_the_paused_run_resumes_without_reset_and_reruns_only_what_never_launched(self):
        d, floor = self._repo(floor=FLOOR)
        pause = loop_setup.PauseRequest()
        first = PausesDuringFirstReview(pause)
        self.assertEqual("paused", self._loop(d, floor, first, pause)[0]["status"])
        healthy = FakeRunner()
        status, _err = self._loop(d, floor, healthy, loop_setup.PauseRequest(), seed=False)
        self.assertEqual("complete", status["status"], status)
        reviews = sorted(e for e in healthy.launched if e.startswith("review-"))
        expected = sorted(set("review-app-%s" % x for x in FLOOR) - set(first.launched))
        self.assertEqual(expected, reviews)

    def test_a_pause_between_batches_opens_no_batch_and_gives_every_attempt_back(self):
        d, floor = self._repo(floor=FLOOR)
        pause = loop_setup.PauseRequest()
        pause.event.set()
        runner = FakeRunner()
        with mock.patch.object(orchestrate.Guards, "arm") as arm, \
                mock.patch.object(orchestrate.batch_mod.Batch, "open") as opened:
            status, _err = self._loop(d, floor, runner, pause)
        arm.assert_not_called()
        opened.assert_not_called()
        self.assertEqual("paused", status["status"], status)
        self.assertIn("0 running entries finished and were kept; 4 never launched",
                      status["message"])
        self.assertEqual([], runner.launched)
        self.assertEqual([], glob.glob(os.path.join(self._run_dir(d), "batch-*.json")))
        self.assertEqual({}, {k: v for k, v in self._attempts(d).items() if v})

    def test_an_interrupt_after_a_pause_request_still_rolls_back(self):
        # The handler only sets an event: Ctrl-C keeps its immediate path, pause or no pause.
        d, floor = self._repo(floor=FLOOR)
        pause = loop_setup.PauseRequest()
        runner = PausesDuringFirstReview(pause)
        with mock.patch.object(loop_batch, "record_entry", side_effect=KeyboardInterrupt):
            status, _err = self._loop(d, floor, runner, pause)
        self.assertEqual("error", status["status"], status)
        self.assertNotIn("paused on request", status["message"])

    def test_a_run_that_completes_first_says_the_pause_was_moot(self):
        d, _floor = self._repo(floor=FLOOR)
        pause = loop_setup.PauseRequest()
        pause.event.set()
        with mock.patch.object(orchestrate, "_loop", return_value={"status": "complete"}), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual("complete", orchestrate.loop(self._args(d), pause=pause)["status"])
        self.assertIn("a pause was requested, but the run completed first", err.getvalue())

    def test_session_mode_installs_no_handler(self):
        d, floor = self._repo(floor=FLOOR)
        pause = loop_setup.PauseRequest()
        with mock.patch.object(pause, "install") as install:
            self._loop(d, floor, FakeRunner(), pause, "--mode", "session",
                       "--session-dir", self._session_root(d))
        install.assert_not_called()


class SendsARealSigusr1(FakeRunner):
    """Delivers a REAL SIGUSR1 to this process while the first review entry runs. The default
    action of SIGUSR1 is to end the process, so this only passes when the loop installed its
    handler. It then waits for the handler (it runs on the main thread) before returning, so
    the worker's next dequeue sees the request -- the property the gate is for."""

    def __init__(self, pause):
        super().__init__()
        self.pause = pause

    def run_entry(self, entry, env):
        if entry["id"].startswith("review-") and not self.pause.is_set():
            os.kill(os.getpid(), signal.SIGUSR1)
            if not self.pause.event.wait(10):
                raise AssertionError("SIGUSR1 delivered but the loop's handler never ran")
        return super().run_entry(entry, env)


@unittest.skipUnless(hasattr(signal, "SIGUSR1"), "no SIGUSR1 on this platform")
class TestARealSignalEndToEnd(_PauseLoop):
    """Review round 1: the install itself is under test. An uninstalled handler is not a
    weaker pause -- SIGUSR1's default action kills the driver with no rollback."""

    def test_a_real_sigusr1_drains_and_pauses_a_headless_loop(self):
        self.assertIs(signal.SIG_DFL, signal.getsignal(signal.SIGUSR1))
        self.addCleanup(signal.signal, signal.SIGUSR1, signal.SIG_DFL)
        d, floor = self._repo(floor=FLOOR)
        pause = loop_setup.PauseRequest()
        runner = SendsARealSigusr1(pause)
        status, err = self._loop(d, floor, runner, pause)
        self.assertEqual("paused", status["status"], status)
        self.assertIn("pause requested; finishing the running entries", err)
        reviews = [e for e in runner.launched if e.startswith("review-")]
        self.assertEqual(1, len(reviews), runner.launched)       # the queued ones never launched
        run_dir = self._run_dir(d)
        self.assertEqual(1, len(glob.glob(os.path.join(run_dir, "findings-*.json"))))  # kept
        self.assertIs(signal.SIG_DFL, signal.getsignal(signal.SIGUSR1))                # restored


@unittest.skipUnless(hasattr(signal, "SIGUSR1"), "no SIGUSR1 on this platform")
class TestPauseRequestSignal(unittest.TestCase):

    def setUp(self):
        self.assertIs(signal.SIG_DFL, signal.getsignal(signal.SIGUSR1))
        self.addCleanup(signal.signal, signal.SIGUSR1, signal.SIG_DFL)

    def test_sigusr1_sets_the_request_and_restore_puts_the_default_back(self):
        pause, out = loop_setup.PauseRequest(), io.StringIO()
        self.assertTrue(pause.install(out))
        self.assertIn("`kill -USR1 %d` drains and pauses" % os.getpid(), out.getvalue())
        with contextlib.redirect_stderr(io.StringIO()) as err:
            os.kill(os.getpid(), signal.SIGUSR1)
            os.kill(os.getpid(), signal.SIGUSR1)
        self.assertTrue(pause.is_set())
        self.assertIn("pause requested", err.getvalue())
        self.assertIn("already draining; Ctrl-C stops now", err.getvalue())
        pause.restore()
        self.assertIs(signal.SIG_DFL, signal.getsignal(signal.SIGUSR1))

    def test_a_handler_that_is_already_there_is_left_alone(self):
        def theirs(signum, frame):
            return None

        signal.signal(signal.SIGUSR1, theirs)
        pause, out = loop_setup.PauseRequest(), io.StringIO()
        self.assertFalse(pause.install(out))
        self.assertIn("pause unavailable (SIGUSR1 already has a handler)", out.getvalue())
        self.assertIs(theirs, signal.getsignal(signal.SIGUSR1))
        pause.restore()
        self.assertIs(theirs, signal.getsignal(signal.SIGUSR1))

    def test_off_the_main_thread_it_installs_nothing(self):
        pause, out, result = loop_setup.PauseRequest(), io.StringIO(), []
        worker = threading.Thread(target=lambda: result.append(pause.install(out)))
        worker.start()
        worker.join()
        self.assertEqual([False], result)
        self.assertIn("pause unavailable (not on the main thread)", out.getvalue())
        self.assertIs(signal.SIG_DFL, signal.getsignal(signal.SIGUSR1))

    def test_a_platform_without_sigusr1_says_so(self):
        pause, out = loop_setup.PauseRequest(), io.StringIO()
        pause._signal = None
        self.assertFalse(pause.install(out))
        self.assertIn("pause unavailable (this platform has no SIGUSR1)", out.getvalue())


class TestIterBatchHold(unittest.TestCase):
    """#3350 at the seam: `hold` is asked after a worker dequeues and BEFORE `run_entry`."""

    class Counting(base.HostRunner):
        host = "claude"; mode = "headless"; default_concurrency = 1

        def __init__(self, hold=None):
            super().__init__("claude")
            self.calls, self.hold = [], hold

        def run_entry(self, entry, env):
            self.calls.append(entry["id"])
            if self.hold is not None:
                self.hold.set()      # the request lands while this entry is running
            return base.RunResult(entry_id=entry["id"], ok=True, text="ok")

    ENTRIES = [{"id": "e%d" % n} for n in range(5)]

    def test_a_hold_set_mid_entry_stops_the_worker_turnover(self):
        hold = threading.Event()
        runner = self.Counting(hold)
        got = list(runner.iter_batch(self.ENTRIES, 1, lambda e: {}, hold=hold))
        self.assertEqual(1, len(runner.calls), runner.calls)
        self.assertEqual(["e0"], [entry["id"] for entry, _r, _t in got])

    def test_a_hold_set_before_the_batch_launches_and_yields_nothing(self):
        hold = threading.Event()
        hold.set()
        runner = self.Counting()
        self.assertEqual([], list(runner.iter_batch(self.ENTRIES, 2, lambda e: {}, hold=hold)))
        self.assertEqual([], runner.calls)

    def test_a_stop_after_a_hold_drains_without_yielding_the_held(self):
        # A held worker returns no result; the second pass a `stop` starts must skip it too.
        class CountingHold:
            def __init__(self):
                self.flag, self.asked = False, 0
                self.lock, self.all_asked = threading.Lock(), threading.Event()

            def set(self):
                self.flag = True

            def is_set(self):
                with self.lock:
                    self.asked += 1
                    if self.asked >= 3:          # e0 (not yet held), then e1 and e2 (held)
                        self.all_asked.set()
                    return self.flag

        hold = CountingHold()
        runner = self.Counting(hold)
        got = list(runner.iter_batch(self.ENTRIES[:3], 1, lambda e: {}, hold=hold,
                                     stop=lambda: hold.all_asked.wait(10)))
        self.assertTrue(hold.all_asked.is_set())
        self.assertNotIn(None, got)
        self.assertEqual(["e0"], [entry["id"] for entry, _r, _t in got])

    def test_without_a_hold_every_entry_runs(self):
        runner = self.Counting()
        self.assertEqual(5, len(list(runner.iter_batch(self.ENTRIES, 2, lambda e: {}))))


if __name__ == "__main__":
    unittest.main()
