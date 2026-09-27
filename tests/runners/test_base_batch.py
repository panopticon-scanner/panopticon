import contextlib
import importlib
import io
import os
import signal
import subprocess
import threading
import time
import unittest
from unittest import mock

import scripts.runners.base as base


class FakeRunner(base.HostRunner):
    host = "fake"; mode = "headless"; default_concurrency = 3
    def __init__(self):
        self.calls = []
    def run_entry(self, entry, env):
        self.calls.append((entry["id"], dict(env)))
        if entry["id"] == "boom":
            raise RuntimeError("launch failed")
        return base.RunResult(entry_id=entry["id"], ok=True, text="{}", usage={},
                              cost_usd=0.0, model=None, session_id=None, denials=[], error=None)


class TestRunBatch(unittest.TestCase):
    def test_results_come_back_in_entry_order_and_an_exception_is_a_failed_result(self):
        r = FakeRunner()
        entries = [{"id": "a"}, {"id": "boom"}, {"id": "c"}]
        out = r.run_batch(entries, 2, env_for=lambda e: {"E": e["id"]})
        self.assertEqual([x.entry_id for x in out], ["a", "boom", "c"])
        self.assertTrue(out[0].ok and out[2].ok)
        self.assertFalse(out[1].ok)
        self.assertIn("launch failed", out[1].error)
        self.assertEqual(sorted(c[0] for c in r.calls), ["a", "boom", "c"])
        self.assertEqual(next(c[1] for c in r.calls if c[0] == "a"), {"E": "a"})

    def test_run_entry_is_abstract(self):
        with self.assertRaises(NotImplementedError):
            base.HostRunner().run_entry({"id": "x"}, {})


class TestIterBatch(unittest.TestCase):
    """P07 (#1636): the loop has to be handed each entry the MOMENT it
    finishes, not when its slowest peer does. `run_batch` joined every future
    before returning anything, so a 42-minute 85-panel batch persisted and
    ledgered nothing until the last entry came back -- and an interruption
    before that lost every completed reply and its usage. `iter_batch` is that
    seam: completion order, with the timing measured around `run_entry`
    itself, which is also where the ledger's duration_ms now comes from (it
    was hard-coded None at the one call site)."""

    def _gated(self):
        """A runner whose "slow" entry blocks until `released` is set, and
        which announces on `entered` that it is really inside `run_entry` --
        the consumer needs that to time anything, because `iter_batch` is a
        generator and its pool does not exist until the first `next()`."""
        released, entered = threading.Event(), threading.Event()

        class Gated(base.HostRunner):
            host = "fake"; mode = "headless"; default_concurrency = 2

            def run_entry(self, entry, env):
                if entry["id"] == "slow":
                    entered.set()
                    released.wait(10)
                return base.RunResult(entry_id=entry["id"], ok=True, text="", usage={},
                                      cost_usd=None, model=None, session_id=None,
                                      denials=[], error=None)

        return Gated(), released, entered

    def test_a_finished_entry_is_yielded_while_its_peer_is_still_running(self):
        r, released, _entered = self._gated()
        entries = [{"id": "slow"}, {"id": "fast"}]
        stream = r.iter_batch(entries, 2, env_for=lambda e: {})
        self.addCleanup(released.set)
        self.addCleanup(stream.close)
        entry, result, timing = next(stream)
        # entry order says "slow" first; completion order says otherwise, and
        # completion order is the one the loop persists in.
        self.assertEqual("fast", entry["id"])
        self.assertEqual("fast", result.entry_id)
        self.assertFalse(released.is_set(), "the slow entry is still inside run_entry")
        self.assertEqual({"started_at", "finished_at", "duration_ms"}, set(timing))
        self.assertIsInstance(timing["duration_ms"], int)
        self.assertGreaterEqual(timing["duration_ms"], 0)
        # same fixed-width UTC format the ledger's own `ts` uses, so the two
        # sort together and finished never precedes started
        for stamp in (timing["started_at"], timing["finished_at"]):
            self.assertRegex(stamp, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        self.assertLessEqual(timing["started_at"], timing["finished_at"])
        released.set()
        self.assertEqual(["slow"], [e["id"] for e, _r, _t in stream])

    def test_the_slow_entrys_timing_covers_the_time_it_blocked(self):
        # The 50 ms window opens only once the worker is provably inside
        # `run_entry`: a bare `threading.Timer` starts counting before the
        # generator has even built its pool, so any stall longer than the
        # window (a loaded CI runner, a CPU-quota'd container) would release
        # the entry before it blocked and collapse duration_ms to 0.
        r, released, entered = self._gated()
        stream = r.iter_batch([{"id": "slow"}, {"id": "fast"}], 2, lambda e: {})
        self.addCleanup(released.set)
        self.addCleanup(stream.close)
        first = next(stream)                       # "fast"; the pool now exists
        self.assertTrue(entered.wait(10), "the slow entry never entered run_entry")
        time.sleep(0.05)
        released.set()
        timings = {e["id"]: t for e, _r, t in [first] + list(stream)}
        self.assertGreaterEqual(timings["slow"]["duration_ms"], 40)
        self.assertLess(timings["fast"]["duration_ms"], timings["slow"]["duration_ms"])

    def test_run_batch_drains_iter_batch_and_keeps_entry_order(self):
        r, released, _entered = self._gated()
        released.set()
        out = r.run_batch([{"id": "slow"}, {"id": "fast"}], 2, env_for=lambda e: {})
        self.assertEqual(["slow", "fast"], [x.entry_id for x in out])

    def test_a_family_inherits_it_without_overriding_anything(self):
        # docs/FAMILY-PR-GUARDRAILS.md §3: `run_entry` is the only method a
        # family implements; the pool -- both shapes of it -- is inherited.
        # This is what made dropping the `results is None` branch safe, and it
        # matters more now: headless calls `iter_batch`, so a family that
        # overrode `run_batch` -- the documented seam until this PR -- would
        # have its override silently ignored rather than failing loudly.
        #
        # Discovered from the package directory, the way
        # tests/test_layout.py::_package_dirs does, so the NEXT family is
        # enrolled by existing rather than by being listed here.
        #
        # `base.py` is the seam itself, `batch.py` (#1662) the loop's
        # rollback manifest, `children.py` (#1575) the seam's own launcher and
        # child registry mixed into HostRunner, `outage.py` (#1623) its
        # host-outage verdict, `schema.py` (#1732) the output-schema argv
        # rules split out of `base.py`, `resume.py` (#1732) the resume command
        # split out of `outage.py`, and `kimi_home.py` the sandboxed
        # `$KIMI_CODE_HOME` the kimi family's children run under: none is a
        # family, none launches a HOST, and none has a Runner. A shared module
        # added to this package costs one line here, which is the visible
        # decision it should be -- the alternative, skipping any module that
        # happens to have no `Runner`, would silently excuse the family that
        # forgot one.
        pkg_dir = os.path.dirname(os.path.abspath(base.__file__))
        names = sorted(f[:-3] for f in os.listdir(pkg_dir)
                       if f.endswith(".py")
                       and f not in ("__init__.py", "base.py", "batch.py",
                                     "children.py", "outage.py", "resume.py",
                                     "schema.py", "kimi_home.py"))
        self.assertIn("claude", names)                  # the directory really was read
        for name in names:
            mod = importlib.import_module("scripts.runners.%s" % name)
            runner = getattr(mod, "Runner", None) or getattr(mod, "SessionRunner", None)
            self.assertIsNotNone(runner, name)
            self.assertNotIn("iter_batch", vars(runner), name)
            if name != "session":       # the one documented override: it launches nothing
                self.assertNotIn("run_batch", vars(runner), name)


class TestTheCooperativeStop(unittest.TestCase):
    """#1721: a host outage that begins mid-batch had to drain the WHOLE
    checkpoint before the loop could ask whether the host was down -- 78 review
    cells at one launch each, every one of them charged at dispatch. `stop` is
    the seam that lets the consumer say "no more": what is still QUEUED is
    cancelled, what is already IN FLIGHT is drained and yielded exactly as
    usual, and no child is terminated (that is the interrupt path -- an
    in-flight launch during an outage fails fast on its own)."""

    def _runner(self, seen):
        """A runner whose first two entries are fast, and whose entry `ei`
        (i >= 2) does not come back until the consumer has handled `i` results.

        That chain is what makes the launch bound a FACT rather than a race.
        Two workers answering instantly outrun a consumer that does real work
        per result, so a fixture that merely released everything at the moment
        `stop` fires leaves a window in which both workers pull another entry
        before the cancel lands. Here the pool is pinned to the consumer's own
        progress: at the moment `stop` returns true the consumer has handled 2,
        so `e2` may be free but `e3` (which waits for 3) cannot be, and at most
        one further entry can start. The chain always makes progress -- `ei`
        waits on results that arrive from entries launched before it -- so it
        cannot deadlock, and every wait is deadlined.
        """
        launched, terminated = [], []

        def await_consumer(n):
            deadline = time.monotonic() + 10
            while len(seen) < n:
                if time.monotonic() > deadline:
                    raise AssertionError("the consumer never handled %d results" % n)
                time.sleep(0.002)

        class Stopping(base.HostRunner):
            host = "fake"; mode = "headless"; default_concurrency = 2

            def run_entry(self, entry, env):
                launched.append(entry["id"])
                index = int(entry["id"][1:])
                if index >= 2:
                    await_consumer(index)
                return base.RunResult(entry_id=entry["id"], ok=True, text="", usage={},
                                      cost_usd=None, model=None, session_id=None,
                                      denials=[], error=None)

            def terminate_children(self, grace=None):
                terminated.append(grace)
                return []

        return Stopping(), launched, terminated

    def _drain(self, runner, seen, entries, **kw):
        with contextlib.closing(runner.iter_batch(entries, 2, lambda e: {}, **kw)) as stream:
            for entry, _result, _timing in stream:
                seen.append(entry["id"])

    def test_a_stop_that_says_yes_cancels_what_is_still_queued(self):
        seen, calls = [], []
        runner, launched, terminated = self._runner(seen)

        def stop():
            calls.append(len(seen))
            return len(seen) >= 2

        self._drain(runner, seen, [{"id": "e%d" % i} for i in range(8)], stop=stop)
        self.assertLess(len(launched), 8, launched)
        # 2 handled + the pool: `e2`/`e3` were already running and at most one
        # worker can turn over between the second result and the cancel
        self.assertLessEqual(len(launched), 5, launched)
        # every entry that really launched came back to the consumer -- the
        # in-flight ones included -- and nothing cancelled was yielded
        self.assertEqual(sorted(launched), sorted(seen))
        self.assertEqual([], terminated, "an outage is not the interrupt path")
        # asked once per yield at most, and never before the first result
        self.assertLessEqual(len(calls), len(seen))
        self.assertTrue(calls and calls[0] >= 1)

    def test_a_stop_that_raises_is_not_the_interrupt_path(self):
        # A consumer's predicate is not a Ctrl-C. Unwrapped it fell into the
        # `except BaseException` arm, which terminates this batch's children --
        # the one thing the stop path promises never to do -- and re-raised
        # into the loop. It means "carry on".
        seen = []
        runner, launched, terminated = self._runner(seen)

        def stop():
            raise RuntimeError("the tally blew up")

        self._drain(runner, seen, [{"id": "e%d" % i} for i in range(8)], stop=stop)
        self.assertEqual(8, len(launched), launched)
        self.assertEqual(sorted(seen), sorted(launched))
        self.assertEqual([], terminated, "a raising stop terminated the children")

    def test_no_stop_at_all_launches_the_whole_batch(self):
        seen = []
        runner, launched, terminated = self._runner(seen)
        self._drain(runner, seen, [{"id": "e%d" % i} for i in range(8)])
        self.assertEqual(8, len(launched), launched)
        self.assertEqual(sorted(seen), sorted(launched))
        self.assertEqual([], terminated)

    def test_a_stop_that_stays_false_launches_the_whole_batch(self):
        seen = []
        runner, launched, _terminated = self._runner(seen)
        self._drain(runner, seen, [{"id": "e%d" % i} for i in range(8)],
                    stop=lambda: False)
        self.assertEqual(8, len(launched), launched)
        self.assertEqual(sorted(seen), sorted(launched))


class FakeChild:
    """A `subprocess.Popen`-shaped handle for `terminate_children` (#1662):
    `terminate` then, for one that will not die, `kill`. No real process: the
    suite never launches a host binary, and this path is about what the runner
    SENDS, not about what a child does with it."""

    def __init__(self, stubborn=False):
        self.stubborn = stubborn
        self.sent = []

    def terminate(self):
        self.sent.append("TERM")

    def kill(self):
        self.sent.append("KILL")

    def wait(self, timeout=None):
        if self.stubborn:
            raise subprocess.TimeoutExpired(["child"], timeout or 0)
        return 0


class TestAnInterruptStopsTheBatch(unittest.TestCase):
    """#1662: Ctrl-C means complete stoppage. `shutdown(wait=True)` queued its
    stop sentinel BEHIND every work item, so every entry the batch had queued
    -- running or not yet started -- was still launched and allowed to finish,
    none of them persisted, and the interrupt did not return until the last
    child exited. On a wide batch of slow entries that is minutes of work paid
    for and thrown away."""

    def _stoppable(self, terminate_releases=True):
        """A runner whose entries (bar the first) block until the interrupt
        path terminates them -- which is what a SIGTERM does to a real child:
        the worker holding it stops blocking and returns."""
        released, started, terminated = threading.Event(), [], []

        class Stoppable(base.HostRunner):
            host = "fake"; mode = "headless"; default_concurrency = 2
            INTERRUPT_GRACE = 0.25

            def run_entry(self, entry, env):
                started.append(entry["id"])
                if entry["id"] != "e0":
                    released.wait(10)
                return base.RunResult(entry_id=entry["id"], ok=True, text="", usage={},
                                      cost_usd=None, model=None, session_id=None,
                                      denials=[], error=None)

            def terminate_children(self, grace=None):
                terminated.append(grace)
                if terminate_releases:
                    released.set()

        self.addCleanup(released.set)
        return Stoppable(), started, terminated

    def _interrupt_after_the_first_completion(self, runner, entries, width=2):
        stream = runner.iter_batch(entries, width, lambda e: {})
        began = time.monotonic()
        with self.assertRaises(KeyboardInterrupt):
            with contextlib.closing(stream):
                for _entry, _result, _timing in stream:
                    raise KeyboardInterrupt          # the operator's Ctrl-C
        return time.monotonic() - began

    def test_the_entries_still_queued_are_never_launched(self):
        # Six entries, concurrency two, interrupted after the first
        # completion. A worker that finishes an entry takes the next queued
        # item straight away and nothing the consumer does can beat it, so up
        # to `width` entries can still launch after the interrupt -- here only
        # `e0` completes, so exactly one slot turns over and `e1` plus at most
        # `e2` run. e3..e5 were queued and must never launch; the test above
        # pins the general bound. On the base every one of the six ran.
        r, started, _terminated = self._stoppable()
        entries = [{"id": "e%d" % i} for i in range(6)]
        self._interrupt_after_the_first_completion(r, entries)
        self.assertIn("e0", started)
        self.assertEqual([], [x for x in ("e3", "e4", "e5") if x in started],
                         "queued entries launched after the interrupt: %r" % started)
        self.assertLessEqual(len(started), 3, started)

    def test_the_launches_after_the_interrupt_are_bounded_by_the_pool_width(self):
        # "One worker slot turns over" is only true when ONE entry completes.
        # Every worker that finishes an entry pulls the next queued item
        # before the consumer's interrupt can reach the generator, so the real
        # bound is the POOL, not a single slot: with four fast entries at
        # width four, four workers each start one more -- eight launches out
        # of twenty, and never a ninth. The test above is what pins the
        # cancellation itself; this one pins how much can still get out, which
        # is the number the seam's docstring now quotes. On the base, whose
        # `shutdown(wait=True)` queued its sentinel behind every work item, all
        # twenty ran.
        released, started = threading.Event(), []
        self.addCleanup(released.set)

        class Wide(base.HostRunner):
            host = "fake"; INTERRUPT_GRACE = 0.25

            def run_entry(self, entry, env):
                started.append(entry["id"])
                if int(entry["id"][1:]) >= 4:          # only the first four are fast
                    released.wait(10)
                return base.RunResult(entry_id=entry["id"], ok=True, text="", usage={},
                                      cost_usd=None, model=None, session_id=None,
                                      denials=[], error=None)

        self._interrupt_after_the_first_completion(
            Wide(), [{"id": "e%d" % i} for i in range(20)], width=4)
        self.assertLessEqual(len(started), 8, started)     # 2 x width, exactly
        self.assertEqual([], [x for x in started if int(x[1:]) >= 8], started)

    def test_the_in_flight_entry_is_terminated_rather_than_awaited(self):
        r, _started, terminated = self._stoppable()
        self._interrupt_after_the_first_completion(
            r, [{"id": "e%d" % i} for i in range(6)])
        self.assertEqual(1, len(terminated), "terminate_children was not called once")

    def test_a_child_that_ignores_the_terminate_is_not_waited_out(self):
        # The grace is a BOUND, not a promise: a runner whose terminate does
        # not end the child still returns from the interrupt, instead of
        # blocking for the entry's full 10s.
        r, _started, terminated = self._stoppable(terminate_releases=False)
        elapsed = self._interrupt_after_the_first_completion(
            r, [{"id": "e%d" % i} for i in range(6)])
        self.assertEqual(1, len(terminated))
        self.assertLess(elapsed, 5, "the interrupt waited the blocked entry out")

    def test_a_terminate_that_raises_does_not_replace_the_interrupt(self):
        # A family's teardown must never become the exception the operator
        # sees instead of their own Ctrl-C.
        released = threading.Event()
        self.addCleanup(released.set)

        class Angry(base.HostRunner):
            host = "angry"; INTERRUPT_GRACE = 0.05

            def run_entry(self, entry, env):
                if entry["id"] != "e0":
                    released.wait(10)
                return base.RunResult(entry_id=entry["id"], ok=True, text="", usage={},
                                      cost_usd=None, model=None, session_id=None,
                                      denials=[], error=None)

            def terminate_children(self, grace=None):
                raise RuntimeError("teardown exploded")

        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self._interrupt_after_the_first_completion(
                Angry(), [{"id": "e%d" % i} for i in range(4)])
        self.assertIn("teardown exploded", err.getvalue())
        self.assertIn("angry", err.getvalue())

    def test_terminate_children_sends_sigterm_then_sigkill(self):
        r = base.HostRunner()
        quick, stubborn = FakeChild(), FakeChild(stubborn=True)
        r.register_child(quick)
        r.register_child(stubborn)
        self.assertEqual([quick, stubborn], r.terminate_children(grace=0))
        self.assertEqual(["TERM"], quick.sent)
        self.assertEqual(["TERM", "KILL"], stubborn.sent)
        # ...and the registry is emptied, so a second call is a no-op rather
        # than a second SIGKILL at a pid the OS has since reused.
        self.assertEqual([], r.terminate_children(grace=0))

    def test_a_runner_that_registered_nothing_terminates_nothing(self):
        self.assertEqual([], base.HostRunner().terminate_children(grace=0))

    def test_the_interrupt_path_installs_no_signal_handler(self):
        # The rollback must CALL THROUGH a family's handler, never replace it:
        # runners/kimi.py chains a SIGTERM secret-stripper onto whatever was
        # there, and an interrupt path that installed its own would unlink it.
        before = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
        r, _started, _terminated = self._stoppable()
        self._interrupt_after_the_first_completion(
            r, [{"id": "e%d" % i} for i in range(4)])
        self.assertEqual(before, {s: signal.getsignal(s)
                                  for s in (signal.SIGINT, signal.SIGTERM)})


class TestTheOneConcurrencyCeiling(unittest.TestCase):
    """#1576 (OPS-2112448973): the headless runner accepted unbounded process
    concurrency. `--concurrency` is a `_positive_int` with no upper bound, and
    `default_concurrency` is whatever a family declares, so `driver loop
    --concurrency 500` opened a 500-wide pool of host CLIs -- each one a real
    process tree, each one charged.

    ONE ceiling, applied in ONE place: `batch_width`. The flag keeps accepting
    any positive int (a clamp in the parser AND here would be two ceilings
    that can disagree), and every caller that needs the number -- `iter_batch`
    for its pool, `orchestrate.loop` for its outage tally -- asks this method
    rather than re-deriving the expression.
    """

    def test_the_ceiling_is_the_largest_shipped_family_default(self):
        # A flat number, not a cpu count: these children are network-bound
        # CLIs, and a 2-core CI runner running 8 of them is the shape the
        # suite already assumes.
        self.assertEqual(8, base.MAX_CONCURRENCY)

    def test_every_shipped_family_fits_under_it(self):
        pkg_dir = os.path.dirname(os.path.abspath(base.__file__))
        names = sorted(f[:-3] for f in os.listdir(pkg_dir)
                       if f.endswith(".py")
                       and f not in ("__init__.py", "base.py", "batch.py",
                                     "children.py", "outage.py", "resume.py",
                                     "schema.py", "kimi_home.py"))
        for name in names:
            mod = importlib.import_module("scripts.runners.%s" % name)
            runner = getattr(mod, "Runner", None) or getattr(mod, "SessionRunner")
            with self.subTest(family=name):
                self.assertLessEqual(
                    runner.default_concurrency, base.MAX_CONCURRENCY,
                    "%s ships a default above the ceiling, so its ordinary run "
                    "would print a clamp warning on every batch" % name)

    def test_an_absent_or_zero_request_falls_back_to_the_family_default(self):
        runner = FakeRunner()                       # default_concurrency = 3
        for asked in (None, 0):
            with self.subTest(asked=asked):
                self.assertEqual(3, runner.batch_width(asked))

    def test_a_request_under_the_ceiling_is_what_was_asked_for(self):
        self.assertEqual(2, FakeRunner().batch_width(2))

    def test_a_request_over_the_ceiling_is_clamped_and_says_so_once(self):
        runner, err = FakeRunner(), io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(base.MAX_CONCURRENCY, runner.batch_width(500))
            self.assertEqual(base.MAX_CONCURRENCY, runner.batch_width(500))
        # ONE line, not one per caller: `iter_batch` and `orchestrate.loop`
        # both ask for the same width on every batch.
        self.assertEqual(["concurrency 500 clamped to the ceiling 8"],
                         err.getvalue().splitlines())

    def test_a_clamp_at_a_different_width_is_still_reported(self):
        runner, err = FakeRunner(), io.StringIO()
        with contextlib.redirect_stderr(err):
            runner.batch_width(500)
            runner.batch_width(64)
        self.assertEqual(2, len(err.getvalue().splitlines()))

    def test_a_width_under_the_ceiling_prints_nothing(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            FakeRunner().batch_width(base.MAX_CONCURRENCY)
        self.assertEqual("", err.getvalue())

    def test_a_negative_request_is_still_a_pool_of_one(self):
        # `max(1, ...)` was already there and stays: a ThreadPoolExecutor
        # refuses max_workers <= 0, so a bad number must degrade, not crash.
        self.assertEqual(1, FakeRunner().batch_width(-5))

    def test_the_pool_itself_is_bounded_by_the_ceiling(self):
        # The guarantee, not the arithmetic: `iter_batch` asks for 500 and
        # never has more than the ceiling in flight.
        runner, peak, live, lock = FakeRunner(), [0], [0], threading.Lock()

        def one(entry, env):
            with lock:
                live[0] += 1
                peak[0] = max(peak[0], live[0])
            time.sleep(0.02)
            with lock:
                live[0] -= 1
            return base.RunResult(entry_id=entry["id"], ok=True, text="", usage={},
                                  cost_usd=None, model=None, session_id=None,
                                  denials=[], error=None)

        entries = [{"id": "e%d" % i} for i in range(40)]
        err = io.StringIO()
        with contextlib.redirect_stderr(err), mock.patch.object(runner, "run_entry", one):
            list(runner.iter_batch(entries, 500, lambda e: {}))
        self.assertLessEqual(peak[0], base.MAX_CONCURRENCY)
        self.assertGreater(peak[0], 1, "the pool never ran anything in parallel")
