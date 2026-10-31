"""#3232: what `driver loop` says on stderr, and that it says it on stderr ONLY: stdout's status
and every JSON artifact are the same with the wrapper as without it."""
import contextlib
import io
import json
import os
import re
import subprocess
import sys
import threading
import unittest
from unittest import mock

import scripts.driver as driver
import scripts.loop_progress as lp
import scripts.phases.child as child
import scripts.phases.engine as engine
import scripts.phases.runio as runio
import tests.test_phases_child as child_tests
from tests.orchestrate_helpers import FakeRunner, _HeadlessLoopCase

STAMP = r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ "


def _stream():
    real = io.StringIO()
    return lp._Stamped(real), real


class _Installed(unittest.TestCase):
    """`loop_progress` as the `loop` verb installs it, around a fresh stderr."""

    def setUp(self):
        super().setUp()
        self.real = io.StringIO()
        self.stream = lp._Stamped(self.real)
        redirect = contextlib.redirect_stderr(self.stream)
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)
        for name, value in (("_active", lp._Run(self.stream)), ("HEARTBEAT_SECONDS", 0.05)):
            patcher = mock.patch.object(lp, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def lines(self):
        return re.sub(r"(?m)^" + STAMP, "", self.real.getvalue()).splitlines()


class EveryLineIsStampedTest(unittest.TestCase):
    def test_a_line_carries_a_utc_stamp_and_a_blank_one_does_not(self):
        stream, real = _stream()
        stream.write("driver loop: x done\n\n")
        first, blank = real.getvalue().split("\n")[:2]
        self.assertRegex(first, "^" + STAMP + "driver loop: x done$")
        self.assertEqual("", blank)

    def test_print_arrives_as_one_line(self):
        stream, real = _stream()
        print("a", "b", file=stream)
        self.assertRegex(real.getvalue(), "^" + STAMP + "a b\n$")

    def test_threads_never_tear_a_line(self):
        stream, real = _stream()

        def emit(n):
            for _ in range(200):
                print("thread-%d-%s" % (n, "x" * 40), file=stream)
        workers = [threading.Thread(target=emit, args=(n,)) for n in range(6)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()
        lines = real.getvalue().splitlines()
        self.assertEqual(1200, len(lines))
        for line in lines:
            self.assertRegex(line, "^" + STAMP + r"thread-\d-x{40}$")

    def test_two_threads_mid_print_keep_their_own_lines(self):
        # `print` is two writes: text, then newline. Forced into the worst order.
        stream, real = _stream()

        def in_thread(call):
            worker = threading.Thread(target=call)
            worker.start()
            worker.join()
        stream.write("from main")
        in_thread(lambda: stream.write("from worker\n"))
        stream.write("\n")
        self.assertEqual(["from worker", "from main"],
                         [re.sub("^" + STAMP, "", x) for x in real.getvalue().splitlines()])

    def test_another_threads_partial_line_survives_the_wrapper_coming_down(self):
        real = io.StringIO()

        def body():
            worker = threading.Thread(target=lambda: sys.stderr.write("worker's partial"))
            worker.start()
            worker.join()
        with contextlib.redirect_stderr(real):
            lp.stamped_call(True, body)
        self.assertIn("worker's partial", real.getvalue())

    def test_what_subprocess_and_friends_ask_of_a_stream_passes_through(self):
        stream, real = _stream()
        real.fileno = lambda: 77
        real.isatty = lambda: True
        self.assertEqual((77, True), (stream.fileno(), stream.isatty()))


class PrintOnceNeverSwallowsSomethingNewTest(unittest.TestCase):
    def _out(self, stream, real):
        return re.sub(r"(?m)^" + STAMP, "", real.getvalue()).splitlines()

    def test_each_listed_class_prints_a_repeat_once(self):
        for line in ("driver: host capabilities: 5 of 5 proven, unchanged since T",
                     "driver: target ships .claude/skills/x; closed by y (z)",
                     "semgrep: partial file coverage: 1 rule timeout(s) on 2 file(s)",
                     "ingest: excluded 3 finding(s) (test-fixture corpus: 3)"):
            with self.subTest(line):
                stream, real = _stream()
                for _ in range(3):
                    print(line, file=stream)
                self.assertEqual([line], self._out(stream, real))

    def test_a_changed_line_of_a_listed_class_always_prints(self):
        stream, real = _stream()
        lines = ["driver: host capabilities: 5 of 5 proven, unchanged since T",
                 "driver: host capabilities: 4 of 5 proven",
                 "ingest: excluded 3 finding(s) (a)", "ingest: excluded 4 finding(s) (a)"]
        for line in lines:
            print(line, file=stream)
        self.assertEqual(lines, self._out(stream, real))

    def test_an_unlisted_repeat_prints_every_time(self):
        for line in ("driver loop: review-a done (1 ms, 1/2)", "driver run: refused: x",
                     "ERROR: boom", "synthesize: artifact path refused: x",
                     "  driver: host capabilities: indented is not the class",
                     "driver:   a capability detail line"):
            with self.subTest(line):
                stream, real = _stream()
                print(line, file=stream)
                print(line, file=stream)
                self.assertEqual([line, line], self._out(stream, real))

    def test_a_phase_transition_resets_the_phase_classes_only(self):
        stream, real = _stream()
        host, ingest = "driver: host capabilities: same", "ingest: excluded 1 finding(s) (a)"
        print(host, file=stream)
        print(ingest, file=stream)
        stream.new_phase()
        print(host, file=stream)
        print(ingest, file=stream)
        self.assertEqual([host, ingest, host], self._out(stream, real))


class TheWrapperCannotLoseOutputTest(unittest.TestCase):
    def test_a_partial_line_goes_out_on_flush_and_the_rest_continues_it(self):
        stream, real = _stream()
        stream.write("half")
        stream.flush()
        self.assertRegex(real.getvalue(), "^" + STAMP + "half$")
        stream.write(" and half\nnext\n")
        lines = real.getvalue().splitlines()
        self.assertRegex(lines[0], "^" + STAMP + "half and half$")
        self.assertRegex(lines[1], "^" + STAMP + "next$")

    def test_a_crash_mid_line_keeps_the_line_and_takes_the_wrapper_down(self):
        real = io.StringIO()

        def crash():
            sys.stderr.write("Traceback (most recent call last) with no newline yet")
            raise RuntimeError("boom")
        with contextlib.redirect_stderr(real), self.assertRaisesRegex(RuntimeError, "boom"):
            lp.stamped_call(True, crash)
            self.fail("not reached")
        self.assertIn("Traceback (most recent call last) with no newline yet", real.getvalue())
        self.assertIsNone(lp._active)

    def test_it_is_removed_on_every_way_out(self):
        real = io.StringIO()
        with contextlib.redirect_stderr(real):
            self.assertEqual(7, lp.stamped_call(True, lambda: 7))
            self.assertIs(real, sys.stderr)
            with self.assertRaises(KeyboardInterrupt):
                lp.stamped_call(True, mock.Mock(side_effect=KeyboardInterrupt))
            self.assertIs(real, sys.stderr)
        self.assertIsNone(lp._active)

    def test_a_fault_in_its_own_bookkeeping_sends_the_line_raw(self):
        stream, real = _stream()
        with mock.patch.object(lp, "_stamp", side_effect=ValueError("clock")):
            print("kept", file=stream)
        self.assertEqual("kept\n", real.getvalue())

    def test_a_wrapped_write_that_raises_once_is_retried_raw(self):
        real = mock.Mock()
        real.write.side_effect = [OSError("EAGAIN"), None]
        lp._Stamped(real).write("kept\n")
        self.assertEqual("kept\n", real.write.call_args_list[-1].args[0])

    def test_a_stream_that_stays_broken_raises_as_plain_stderr_would(self):
        real = mock.Mock()
        real.write.side_effect = BrokenPipeError("gone")
        with self.assertRaises(BrokenPipeError):
            lp._Stamped(real).write("x\n")

    def test_write_returns_what_a_stream_returns(self):
        self.assertEqual(3, _stream()[0].write("ab\n"))


class NothingHappensUntilInstalledTest(unittest.TestCase):
    def test_every_entry_is_a_no_op(self):
        err = io.StringIO()
        proc = mock.Mock()
        proc.wait.return_value = 0
        with contextlib.redirect_stderr(err):
            self.assertEqual(5, lp.stamped_call(False, lambda: 5))
            self.assertIs(err, sys.stderr)
            lp.phase("review")
            lp.relay_summary("text")
            self.assertEqual(0, lp.wait(proc, 123, "tools"))
        self.assertEqual("", err.getvalue())
        proc.wait.assert_called_once_with(timeout=123)

    def test_only_the_loop_verb_installs_it(self):
        seen = []
        with mock.patch("scripts.orchestrate.main_verb",
                        side_effect=lambda _a: seen.append(sys.stderr) or 0), \
                mock.patch.object(driver.model_resolver, "validate_env_overrides"), \
                mock.patch.object(driver, "parse_cli") as parse:
            for verb in ("loop", "persist"):
                parse.return_value = mock.Mock(verb=verb)
                self.assertEqual(0, driver.main([verb]))
        self.assertIsInstance(seen[0], lp._Stamped)
        self.assertNotIsInstance(seen[1], lp._Stamped)


class PhaseLinesTest(_Installed):
    def _phase(self, name, done):
        return engine.Phase(name, "deterministic", done, mock.Mock(side_effect=[
            engine.PhaseResult(kind="checkpoint", checkpoint="x"),
            engine.PhaseResult(kind="advanced"), engine.PhaseResult(kind="advanced")]))

    def test_a_phase_prints_once_however_often_it_is_reselected(self):
        lp.phase("review")
        lp.phase("review")
        lp.phase("verify")
        lp.phase("verify")
        lp.phase(None)
        lines = self.lines()
        self.assertEqual("driver: phase review started", lines[0])
        self.assertRegex(lines[1], r"^driver: phase review finished \(\d+ s\)$")
        self.assertEqual("driver: phase verify started", lines[2])
        self.assertRegex(lines[3], r"^driver: phase verify finished \(\d+ s\)$")
        self.assertEqual(4, len(lines))

    def test_a_transition_lets_host_capabilities_print_again(self):
        line = "driver: host capabilities: same"
        lp.phase("review")
        print(line, file=sys.stderr)
        print(line, file=sys.stderr)
        lp.phase("verify")
        print(line, file=sys.stderr)
        self.assertEqual(2, self.lines().count(line))

    def test_the_engine_says_which_phase_it_is_in(self):
        marks = iter((False, True))
        phase = engine.Phase("review", "deterministic", lambda *_a: next(marks),
                             lambda *_a: engine.PhaseResult(kind="advanced"))
        status = engine.run_engine("root", {}, [phase])
        self.assertEqual("complete", status["status"])
        self.assertEqual("driver: phase review started", self.lines()[0])
        self.assertRegex(self.lines()[1], r"^driver: phase review finished")


class HeartbeatTest(_Installed):
    def test_it_beats_while_the_child_runs_and_the_result_is_unchanged(self):
        proc = mock.Mock()
        proc.wait.side_effect = [subprocess.TimeoutExpired("c", 0.05),
                                 subprocess.TimeoutExpired("c", 0.05), 0]
        self.assertEqual(0, lp.wait(proc, 60, "tools"))
        self.assertEqual(2, len(self.lines()))
        self.assertRegex(self.lines()[0], r"^driver: tools still running \(\d+ s\)$")

    def test_each_slice_is_bounded_by_what_is_left(self):
        proc = mock.Mock()
        proc.wait.return_value = 0
        with mock.patch.object(lp, "HEARTBEAT_SECONDS", 60):
            lp.wait(proc, 5, "tools")
        self.assertEqual(5, round(proc.wait.call_args.kwargs["timeout"]))

    def test_the_timeout_still_arrives_on_time_and_silently_at_the_end(self):
        proc = mock.Mock()
        proc.wait.side_effect = [subprocess.TimeoutExpired("c", 0)] * 3   # a loop runs out, not hangs
        with self.assertRaises(subprocess.TimeoutExpired):
            lp.wait(proc, 0, "tools")
        self.assertEqual(1, proc.wait.call_count)
        self.assertEqual([], self.lines())

    def test_ctrl_c_during_a_slice_ends_the_childs_group(self):
        proc = mock.Mock(stdout=io.StringIO(""), stderr=io.StringIO(""))
        proc.wait.side_effect = [subprocess.TimeoutExpired("c", 0.05), KeyboardInterrupt]
        with mock.patch.object(child.subprocess, "Popen", return_value=proc), \
                mock.patch.object(child, "_child_env", return_value={}), \
                mock.patch.object(child.procgroup, "kill_group") as kill, \
                self.assertRaises(KeyboardInterrupt):
            child._run_child([sys.executable, "x.py"], "/tmp", "tools", timeout=60)
        kill.assert_called_once_with(proc)
        self.assertEqual(2, proc.wait.call_count)

    def test_a_real_child_beats_and_its_output_is_still_captured(self):
        program = "import sys, time\ntime.sleep(0.4)\nprint('out')\nprint('err', file=sys.stderr)\n"
        done = child._run_child([sys.executable, "-c", program], os.getcwd(), "tools", timeout=60)
        self.assertEqual((0, "out\n", "err\n"), (done.returncode, done.stdout, done.stderr))
        self.assertTrue([x for x in self.lines() if x.startswith("driver: tools still running")])


class _UnderTheSlices(_Installed):
    """The existing child tests, with the wait in slices: nothing else may differ."""


class TimeoutTreeUnderSlices(_UnderTheSlices, child_tests.TestATimeoutReachesTheWholeProcessTree):
    pass


class InterruptTreeUnderSlices(_UnderTheSlices, child_tests.TestAnInterruptReachesTheWholeProcessTree):
    pass


class TimeoutErrorUnderSlices(_UnderTheSlices, child_tests._ChildCase):
    def test_timeout_becomes_driver_error(self):
        with self.assertRaises(runio.DriverError) as ctx:
            self._child("import time\ntime.sleep(60)\n", phase="tools", timeout=1)
        self.assertIn("timed out", str(ctx.exception))


class RelayedSummaryTest(_Installed):
    def test_an_escape_sequence_cannot_reach_the_terminal(self):
        lp.relay_summary("**Grade:** A \x1b[2J\x1b]0;owned\x07 title\u202e\r")
        text = self.real.getvalue()
        for byte in ("\x1b", "\x07", "\u202e", "\r"):
            self.assertNotIn(byte, text)
        self.assertIn("\\x1b[2J", text)

    def test_a_forged_line_cannot_pass_as_a_driver_line(self):
        lp.relay_summary("title\ndriver: phase verify finished (1 s)\n2026-01-01T00:00:00Z driver: x")
        self.assertEqual(["summary: title", "summary: driver: phase verify finished (1 s)",
                          "summary: 2026-01-01T00:00:00Z driver: x"], self.lines())

    def test_a_separator_splitlines_honours_cannot_forge_one_either(self):
        lp.relay_summary("title\x0bdriver: forged\u2028driver: forged too")
        for line in self.lines():
            self.assertTrue(line.startswith(lp.SUMMARY_PREFIX), line)

    def test_a_huge_summary_is_bounded_and_says_so(self):
        lp.relay_summary("\n".join("line %d" % n for n in range(lp.SUMMARY_LINES_MAX + 7)))
        self.assertEqual(lp.SUMMARY_LINES_MAX + 1, len(self.lines()))
        self.assertIn("7 more line(s)", self.lines()[-1])

    def test_nothing_to_relay_prints_nothing(self):
        lp.relay_summary("")
        self.assertEqual("", self.real.getvalue())


class IngestWordingTest(unittest.TestCase):
    def test_each_mechanism_says_what_it_is(self):
        from scripts import ingest_tools
        self.assertEqual(["test-fixture corpus: 28"],
                         ingest_tools._suppression_reasons({ingest_tools.FIXTURE_SEGMENT: 28}))
        self.assertEqual(["vendored dependencies (vendor: 2)"],
                         ingest_tools._suppression_reasons({"vendor": 2}))


# What legitimately differs between two runs of one fake loop: the temp root, and the clock.
_VOLATILE = re.compile(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|\+00:00)?|[0-9a-f]{8,}|\btmp\w{8}\b')
_VOLATILE_KEYS = {"duration_ms", "wall_seconds", "elapsed_ms", "elapsed_seconds", "pid", "owner_pid",
                  "request_sha256", "sha256", "report_sha256"}


def _normal(value, root):
    if isinstance(value, dict):
        return {_VOLATILE.sub("<time>", k.replace(root, "<root>")):
                "<volatile>" if k in _VOLATILE_KEYS else _normal(v, root) for k, v in value.items()}
    if isinstance(value, list):
        return [_normal(v, root) for v in value]
    if isinstance(value, str):
        return _VOLATILE.sub("<time>", value.replace(root, "<root>"))
    return value


class StderrOnlyTest(_HeadlessLoopCase):
    """A whole fake-runner loop, the real engine and the real synthesize child under it."""

    def _loop(self, wrapped):
        d, floor = self._repo()
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
            status = lp.stamped_call(wrapped, self._run, d, floor, FakeRunner())
            engine.emit_status(status)
        return d, out.getvalue(), err.getvalue()

    @staticmethod
    def _artifacts(root):
        found = {}
        for folder, _dirs, names in os.walk(os.path.join(root, ".panopticon")):
            for name in names:
                if name.endswith(".json"):
                    path = os.path.join(folder, name)
                    if os.path.islink(path):
                        continue
                    rel = _VOLATILE.sub("<time>", os.path.relpath(path, root))
                    with open(path, encoding="utf-8") as fh:
                        try:
                            found[rel] = _normal(json.load(fh), root)
                        except ValueError:
                            found[rel] = None
        return found

    def test_stdout_and_every_json_artifact_are_the_same_with_and_without_it(self):
        plain_root, plain_out, plain_err = self._loop(False)
        root, out, err = self._loop(True)
        self.assertEqual(_VOLATILE.sub("<time>", plain_out.replace(plain_root, "<root>")),
                         _VOLATILE.sub("<time>", out.replace(root, "<root>")))
        plain, wrapped = self._artifacts(plain_root), self._artifacts(root)
        self.assertEqual(sorted(plain), sorted(wrapped))
        for rel in plain:
            with self.subTest(rel):
                self.assertEqual(plain[rel], wrapped[rel])
        self.assertNotRegex(plain_err, "(?m)^" + STAMP)     # and off, it is what it was

    def test_what_a_whole_run_says_on_stderr(self):
        _root, _out, err = self._loop(True)
        lines = [x for x in err.splitlines() if x]
        for line in lines:
            self.assertRegex(line, "^" + STAMP)
        bare = [re.sub("^" + STAMP, "", x) for x in lines]
        started = [x for x in bare if re.fullmatch(r"driver: phase \S+ started", x)]
        finished = [x for x in bare if re.match(r"driver: phase \S+ finished", x)]
        self.assertEqual(len(started), len(finished))
        self.assertIn("driver: phase synthesize started", started)
        summary = [x for x in bare if x.startswith(lp.SUMMARY_PREFIX)]
        self.assertTrue([x for x in summary if "**Grade:**" in x], err)
        self.assertLess(bare.index("driver: phase synthesize started"),
                        bare.index(next(x for x in summary if "**Grade:**" in x)))


if __name__ == "__main__":
    unittest.main()
