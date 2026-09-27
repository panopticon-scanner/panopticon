"""Loop usage, completion, and runner width tests."""
import ast
import contextlib
import dataclasses
import io
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock


import scripts.driver as driver
import scripts.ledger as ledger_mod
import scripts.loop_batch as loop_batch
import scripts.orchestrate as orchestrate
import scripts.phases.runio as runio
import scripts.read_guard_hook as read_guard_hook
import scripts.runners.base as base
import scripts.write_guard_hook as write_guard_hook
from tests._test_helpers import (all_proven_artifact as _all_proven_artifact, write_guard_not_proven as _write_guard_not_proven)
from tests._test_helpers import docker_probe_runner
from scripts import hosts


from tests.orchestrate_helpers import (FakeRunner, LoopCase, _HeadlessLoopCase)

def setUpModule():
    global _patch, _readiness_docker_patch
    _patch = mock.patch("scripts.host_probes.run_probes",
                        side_effect=lambda host, target, **kw: _all_proven_artifact(host))
    _patch.start()
    # #1637 P08: the `readiness` phase leads PHASES and fails closed on a
    # missing tools image, so every loop below would stop there instead of at
    # the checkpoint it is about. A fake runner, never a real daemon.
    _readiness_docker_patch = mock.patch(
        "scripts.phases.readiness_checks.DOCKER_RUNNER", docker_probe_runner())
    _readiness_docker_patch.start()


def tearDownModule():
    _patch.stop()
    _readiness_docker_patch.stop()


class TestHeadlessLoop(_HeadlessLoopCase):
    def test_driver_run_alone_writes_no_batch_manifest(self):
        # `driver run` is the non-loop path: it stops AT a checkpoint and
        # writes nothing between checkpoints, so an interrupt there has
        # nothing to roll back and no manifest is ever opened for it.
        d, floor = self._repo(floor=("SEC", "ACC"))
        args = self._args(d)
        args.mode = "headless"
        with contextlib.redirect_stdout(io.StringIO()):
            driver.run(args)
            self._seed_coverage(d, floor)
            status = driver.run(args)
        self.assertEqual("checkpoint", status["status"], status)
        run_dir = orchestrate.persist.run_dir(d)
        self.assertEqual([], self._manifests(run_dir))

    def test_the_ledger_row_records_when_the_entry_ran(self):
        # `duration_ms` was passed as a literal None at the one call site, so
        # every row in every run carried a null. The row GAINS three fields
        # and loses none -- usage_document() reads `phase`/`usage` and
        # total_cost() reads `cost_usd`, all still there. D10 ruling 1 adds a
        # fourth, `rejected_file`: null on a row whose reply the loop could
        # use, and the path to the kept reply on one it could not.
        d, floor = self._repo()
        runner = FakeRunner()
        self._run(d, floor, runner)
        rows = ledger_mod.Ledger(runner.run_dir).lines()
        self.assertEqual(len(runner.launched), len(rows))
        for row in rows:
            self.assertEqual(
                {"ts", "entry_id", "checkpoint", "phase", "mode", "host", "model", "ok",
                 "usage", "cost_usd", "duration_ms", "session_id", "denials", "error",
                 "started_at", "finished_at", "rejected_file"}, set(row))
            self.assertIsNone(row["rejected_file"])       # a clean run keeps nothing
            self.assertIsInstance(row["duration_ms"], int)
            self.assertGreaterEqual(row["duration_ms"], 0)
            self.assertLessEqual(row["started_at"], row["finished_at"])
            # #1685: `ts` IS the entry's finish, so the ordering below holds by
            # construction instead of by two clock reads landing in the same
            # second (it was flaky on CI when they did not).
            self.assertEqual(row["finished_at"], row["ts"])
            self.assertLessEqual(row["started_at"], row["ts"])

    def test_the_review_root_is_resolved_once_for_the_whole_loop(self):
        # #1616 item 6: once per `driver loop` INVOCATION, counted at the
        # bottom (`runio.resolve_review_root`) rather than at the seam, because
        # the loop calls `driver.run` once per ITERATION and that was the
        # dominant term -- fix round 1, F3, measured 5 on this very run (1 in
        # `loop`, 4 in `driver.run`). On a `--pr` run each one is a
        # `gh pr view` plus a worktree acquisition.
        d, floor = self._repo()
        real, calls = runio.resolve_review_root, []

        def _spy(*a, **kw):
            calls.append((a, kw))
            return real(*a, **kw)

        with mock.patch.object(runio, "resolve_review_root", side_effect=_spy):
            status = self._run(d, floor, FakeRunner())
        self.assertEqual(status["status"], "complete", status)
        self.assertEqual(len(calls), 1,
                         "the loop resolved the review root %d times" % len(calls))

    def test_the_rows_duration_is_the_one_its_own_worker_measured(self):
        # #1616 item 1 -- "ledger duration_ms is always null" -- is already
        # closed, by #1636's P07 timing: `iter_batch` measures around
        # `run_entry` IN THE WORKER and hands the loop a
        # {started_at, finished_at, duration_ms} per entry, which
        # `Ledger.record` defaults `duration_ms` from. What was missing was a
        # test that says so. The assertions beside this one (an int >= 0) hold
        # just as well for a hard-coded zero or for one batch-wide figure
        # copied onto every row, so this one pins the fact the item is about:
        # each row carries the time THAT entry took. The clock is scoped to
        # base.iter_batch's measurement seam; each worker thread owns its own
        # pair of observations, independent of scheduling order.
        d, floor = self._repo(floor=("SEC", "ACC"))
        durations = {"review-app-SEC": 375, "review-app-ACC": 125}
        worker = threading.local()

        def measured_clock():
            if not getattr(worker, "measuring", False):
                worker.measuring = True
                worker.entry_id = None
                return 100.0
            entry_id = worker.entry_id
            if entry_id not in durations:
                raise AssertionError("worker clock ended without an entry")
            worker.measuring = False
            return 100.0 + durations[entry_id] / 1000

        class MeasuredCell(FakeRunner):
            def run_entry(self, entry, env):
                worker.entry_id = entry["id"]
                return super().run_entry(entry, env)

        runner = MeasuredCell()
        clock = mock.Mock(wraps=time, monotonic=measured_clock)
        with mock.patch.object(base, "time", clock):
            self._run(d, floor, runner)
        rows = {r["entry_id"]: r for r in ledger_mod.Ledger(runner.run_dir).lines()}
        self.assertEqual(set(durations), rows.keys())
        self.assertEqual(durations, {eid: row["duration_ms"] for eid, row in rows.items()})

    def test_every_completed_entry_prints_one_progress_line(self):
        # The ledger item's "progress visible without inspecting processes":
        # the run-13 operator's only workaround was an external read-only
        # process monitor.
        d, floor = self._repo()
        runner = FakeRunner()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self._run(d, floor, runner)
        lines = [x for x in err.getvalue().splitlines() if " done (" in x]
        self.assertEqual(len(runner.launched), len(lines))
        self.assertRegex(lines[0], r"^driver loop: review-app-SEC done \(\d+ ms, 1/1\)$")

    def test_usage_json_is_written_atomically(self):
        # F6: the only per-entry artifact write the loop makes that a reader
        # can catch mid-flight. `persist.write_reply` already does this for the
        # reply beside it; `write_usage` is the one caller that asks for it.
        d, floor = self._repo()
        runner = FakeRunner()
        with mock.patch.object(orchestrate.runio, "_write_json",
                               wraps=orchestrate.runio._write_json) as wj:
            self._run(d, floor, runner)
        usage_calls = [c for c in wj.call_args_list if c.args[0].endswith("usage.json")]
        self.assertTrue(usage_calls)
        for call in usage_calls:
            self.assertTrue(call.kwargs.get("atomic"), call)
        self.assertEqual([], [f for f in os.listdir(runner.run_dir) if f.endswith(".tmp")])

    def test_the_ledger_row_takes_its_duration_from_the_timing_it_was_given(self):
        # F5: `duration_ms` and `timing["duration_ms"]` were the same fact
        # spelled twice at the only call site, so a future caller could make a
        # row contradict itself. The parameter now defaults FROM the timing.
        d, floor = self._repo()
        ledger = ledger_mod.Ledger(d)
        result = base.RunResult(entry_id="e", ok=True, text="", usage={}, cost_usd=None,
                                model=None, session_id=None, denials=[], error=None)
        timing = {"started_at": "2026-01-01T00:00:00Z",
                  "finished_at": "2026-01-01T00:00:02Z", "duration_ms": 2000}
        ledger.record({"id": "e"}, "review", result, "headless", "claude", timing=timing)
        ledger.record({"id": "e"}, "review", result, "headless", "claude", 7, timing=timing)
        ledger.record({"id": "e"}, "review", result, "headless", "claude")
        rows = ledger.lines()
        self.assertEqual(2000, rows[0]["duration_ms"])      # defaulted from timing
        self.assertEqual(7, rows[1]["duration_ms"])         # an explicit value still wins
        self.assertIsNone(rows[2]["duration_ms"])           # neither given
        self.assertIsNone(rows[2]["started_at"])

    def test_a_failed_usage_write_does_not_abandon_the_rest_of_the_batch(self):
        # F1: usage.json is a PROGRESS write -- `_finish` rewrites it from the
        # same ledger -- and it now runs once per ENTRY instead of once per
        # batch. Unguarded, one transient failure aborted everything after it:
        # the entries still in flight were drained (launched, paid for) and
        # then discarded with no reply and no ledger row, which is precisely
        # the loss P07 exists to stop. `_finish`'s own call has always been
        # wrapped for the same reason.
        d, floor = self._repo(floor=("SEC", "ACC", "ARC", "TST"))
        runner = FakeRunner()
        calls, real = [], loop_batch.write_usage

        def flaky(review_root, ledger, namespace=None):
            calls.append(1)
            if len(calls) == 2:                       # mid-batch, entries still running
                raise OSError(28, "No space left on device")
            return real(review_root, ledger, namespace)

        err = io.StringIO()
        with contextlib.redirect_stderr(err), \
             mock.patch.object(loop_batch, "write_usage", side_effect=flaky):
            status = self._run(d, floor, runner)
        self.assertEqual(status["status"], "complete", status)
        rows = [row["entry_id"] for row in ledger_mod.Ledger(runner.run_dir).lines()]
        # nothing was launched and then thrown away
        self.assertEqual(sorted(runner.launched), sorted(rows))
        self.assertIn("usage.json not updated", err.getvalue())

    def test_usage_is_rewritten_after_every_entry_not_once_per_batch(self):
        d, floor = self._repo(floor=("SEC", "ACC"))
        runner = FakeRunner()
        with mock.patch.object(loop_batch, "write_usage",
                               wraps=loop_batch.write_usage) as wu:
            status = self._run(d, floor, runner)
        self.assertEqual(status["status"], "complete", status)
        # one per launch, plus _finish's terminal write
        self.assertEqual(len(runner.launched) + 1, wu.call_count)

    def test_engine_refusals_surface_unchanged(self):
        d, floor = self._repo()
        runner = FakeRunner()
        self._run(d, floor, runner)
        status = self._run(d, floor, FakeRunner())        # already complete, no --reset
        self.assertEqual(status["status"], "error")
        self.assertIn("--reset", status["message"])

    def test_a_reset_loop_resets_once_and_then_resumes_the_run_it_minted(self):
        # Found by the Claude family PR's second real `driver loop --reset`:
        # `args.reset` reached driver.run on EVERY iteration, so each one
        # cleared the run folder and re-minted the manifest, and the loop
        # re-launched its first checkpoint's entries until --max-iterations
        # (the same three scouts ten times, 30 identical ledger rows). The
        # first call consumes the flag; the loop then resumes its own run.
        d, floor = self._repo()
        self._run(d, floor, FakeRunner())                   # a complete run on disk
        runner = FakeRunner()
        status = self._run(d, floor, runner, "--reset", "--max-iterations", "4")
        self.assertEqual(status["status"], "complete", status)
        self.assertEqual(sorted(runner.launched), ["review-app-SEC", "verify-app-SEC-primary"])

    def test_an_unexpected_exception_disarms_and_reports_without_raising(self):
        # `loop` never raises: any bug in the loop body (not just Ctrl-C) must
        # still land the run in a reported error with both guards torn down --
        # never a traceback with the guards left armed over the rest of the
        # session (review round 1, item 3).
        #
        # The injected fault used to be `write_usage`, which is now
        # best-effort in-batch (F1) and no longer ends a run; `ledger.record`
        # is the same blast radius -- inside the per-entry body, after the
        # launch -- and is still fatal, which is what this test is about.
        d, floor = self._repo()
        runner = FakeRunner()
        with mock.patch.object(ledger_mod.Ledger, "record", side_effect=RuntimeError("boom")):
            status = self._run(d, floor, runner)
        self.assertEqual(status["status"], "error")
        self.assertIn("RuntimeError", status["message"])
        self.assertIn("boom", status["message"])
        settings = os.path.join(runner.run_dir, base.SETTINGS_FILE)
        self.assertFalse(write_guard_hook.is_armed(settings, os.path.join(runner.run_dir, "write-allowlist.json"))[0])
        self.assertFalse(read_guard_hook.is_armed(settings, os.path.join(runner.run_dir, "read-scope.json"))[0])

    def test_a_failed_return_persist_result_never_reaches_write_reply(self):
        # review round 1, item 4: `if result.ok and delivery == "return_json"`
        # must stay an AND -- a failed launch's RunResult (empty text, ok=False)
        # must never be handed to persist.write_reply, and the retry that
        # eventually succeeds must be the ONLY thing that produces the file.
        d, floor = self._repo()
        runner = FakeRunner(); runner.fail_once.add("review-app-SEC")

        seen = []
        orig_write_reply = orchestrate.persist.write_reply   # captured BEFORE patching

        def _tracking_write_reply(entry, text):
            seen.append((entry["id"], os.path.exists(entry["out_file"])))
            return orig_write_reply(entry, text)

        with mock.patch("scripts.host_probes.run_probes",
                        side_effect=_write_guard_not_proven), \
             mock.patch("scripts.phases.persist.write_reply",
                        side_effect=_tracking_write_reply):
            status = self._run(d, floor, runner, "--allow-unenforced")
        self.assertEqual(status["status"], "complete", status)
        self.assertEqual(runner.launched.count("review-app-SEC"), 2)   # failed once, then a real retry
        review_calls = [c for c in seen if c[0] == "review-app-SEC"]
        self.assertEqual(len(review_calls), 1)          # write_reply only for the ok result
        self.assertFalse(review_calls[0][1])             # the out_file did not exist before that call

    def test_the_runners_teardown_runs_on_every_terminal_status(self):
        # C1 (kimi family PR review): the kimi runner's per-run KIMI_CODE_HOME
        # lives OUTSIDE the reviewed tree -- it carries the operator's
        # credential surface -- so the loop, which owns the only terminal path,
        # has to tell the runner when the run is over and how it ended.
        for expect in ("complete", "error"):
            with self.subTest(status=expect):
                d, floor = self._repo()
                runner = FakeRunner()
                runner.torn_down = []
                runner.teardown = runner.torn_down.append
                if expect == "error":
                    runner.run_entry = lambda entry, env: base.RunResult.failed(entry["id"], "always")
                    status = self._run(d, floor, runner, "--max-iterations", "2")
                else:
                    status = self._run(d, floor, runner)
                self.assertEqual(status["status"], expect, status)
                self.assertEqual(runner.torn_down, [expect])

    def test_a_teardown_failure_never_masks_the_runs_status(self):
        d, floor = self._repo()
        runner = FakeRunner()

        def boom(status=None):
            raise OSError("could not remove the run home")
        runner.teardown = boom
        with contextlib.redirect_stderr(io.StringIO()) as err:
            status = self._run(d, floor, runner)
        self.assertEqual(status["status"], "complete", status)
        self.assertIn("teardown failed", err.getvalue())

    def test_a_failure_preparing_the_run_folder_is_an_error_not_a_traceback(self):
        # M8 (final review): `loop` never raises (review round 1, item 3), but
        # the pre-loop setup -- resolving the run folder, `runner.prepare`,
        # constructing Guards -- sat OUTSIDE the try that makes that true. A
        # read-only run folder or an unwritable settings path escaped as a
        # traceback instead of a reported `error` status.
        d, floor = self._repo()
        runner = FakeRunner()

        def boom(run_dir, review_root):
            raise OSError("read-only file system")
        runner.prepare = boom
        status = self._run(d, floor, runner)
        self.assertEqual(status["status"], "error", status)
        self.assertIn("OSError", status["message"])
        self.assertIn("read-only file system", status["message"])

    def test_finish_writes_usage_on_error_even_when_a_mid_batch_exception_skipped_it(self):
        # review round 2: an exception firing between `ledger.record` and the
        # loop's own in-batch `write_usage` call (the round-1 catch-all's
        # blind spot) must not leave usage.json stale -- `_finish` must
        # attempt write_usage on EVERY terminal status (complete AND error),
        # not just complete, so the ledger line that already landed is always
        # reflected.
        #
        # F1 made the in-batch `write_usage` best-effort, so it can no longer
        # be the fault that ends the run. The row-then-raise below is the
        # docstring's case exactly: the ledger line has landed and the
        # exception fires before this batch's own usage write.
        d, floor = self._repo()
        runner = FakeRunner()
        real_record = ledger_mod.Ledger.record

        def _record_then_boom(self, *args, **kwargs):
            real_record(self, *args, **kwargs)
            raise RuntimeError("boom")

        with mock.patch.object(ledger_mod.Ledger, "record", _record_then_boom):
            status = self._run(d, floor, runner)
        self.assertEqual(status["status"], "error")
        self.assertIn("RuntimeError", status["message"])
        self.assertIn("boom", status["message"])
        usage_path = os.path.join(runner.run_dir, "usage.json")
        self.assertTrue(os.path.exists(usage_path))
        usage = runio._load_json(usage_path)
        with open(os.path.join(runner.run_dir, "dispatch-ledger.jsonl"), encoding="utf-8") as fh:
            lines = [json.loads(x) for x in fh if x.strip()]
        self.assertEqual(usage["total"], sum(sum(row["usage"].values()) for row in lines))



class TestFinishTreatsPausedAsTerminal(unittest.TestCase):
    """M1: `paused` is a TERMINAL status, so `_finish` owes it the same
    teardown `error` gets -- and both branches were reachable only through a
    loop path where `guards.disarm(pending)` had already run, so a mutation to
    either went unnoticed by the whole suite."""

    class Guards:
        def __init__(self):
            self.armed_entries = [{"id": "review-app-SEC"}]
            self.disarmed = []

        def disarm(self, entries=None):
            self.disarmed.append(entries)

    def _finish(self, status, guards=None, ledger=None, writes=None):
        # #1616 item 6: `_finish` is handed the review root `loop` already
        # resolved, so there is no `_resolve_target` call left here to patch.
        writes = [] if writes is None else writes
        with mock.patch.object(loop_batch, "write_usage",
                               side_effect=lambda *a, **k: writes.append(a)):
            return orchestrate._finish({"status": status, "message": "m"}, "/repo",
                                       guards, ledger, None, "headless", None)

    def test_paused_disarms_exactly_what_this_invocation_armed(self):
        guards = self.Guards()
        self._finish("paused", guards=guards)
        self.assertEqual([guards.armed_entries], guards.disarmed)

    def test_paused_writes_the_terminal_usage_document(self):
        writes = []
        self._finish("paused", ledger=object(), writes=writes)
        self.assertEqual(1, len(writes), "usage.json was not rewritten on the paused path")


class TestTheRealUsageProbeAcrossLoopIterations(LoopCase):
    """#1626 I1, the loop-level test the review asked for: no OTHER test in
    this suite lets the real `probe_usage_source` see the run it is probing.

    `usage-source` is the only probe whose subject the loop WRITES -- it reads
    back `runs/<tag>/dispatch-ledger.jsonl` after every batch. Every other
    probe measures something static (registration files, a sandbox round
    trip, a directory's writability). This module patches `host_probes.
    run_probes` out for every other test, so the interaction between "a probe
    that reads the run's own output" and "any state change refuses the run"
    was never exercised: a CLI release whose envelope stops reporting tokens
    completes batch 1, refutes on invocation 2, and from then on refuses
    every re-invocation, with `--reset` -- which discards the paid-for
    batches -- as the only exit.
    """

    class LedgerGoesQuiet(FakeRunner):
        """Successful launches that report NO usage, which is what the probe
        reads back off the ledger the loop writes.

        It also has to answer the probe's own `<cli> --help` interrogation,
        so it carries the three attributes `_headless_usage_source` reads off
        a runner: `CLI`, `ENVELOPE_FLAGS` and a `subprocess.run`-compatible
        `runner`. The loop patches `runners.base.runner_for` to return this
        object, and the probe resolves its runner through that same function,
        so one fake answers both.
        """

        CLI = "claude"
        ENVELOPE_FLAGS = ("-p", "--output-format")

        def __init__(self, host="claude"):
            super().__init__(host)
            self.help_calls = []
            self.runner = self._fake_help

        def _fake_help(self, cmd, **kwargs):
            self.help_calls.append(list(cmd))
            return subprocess.CompletedProcess(
                cmd, 0, stdout="usage: claude [options]\n  -p, --print\n"
                               "  --output-format <format>\n", stderr="")

        def run_entry(self, entry, env):
            return dataclasses.replace(super().run_entry(entry, env), usage={})

    def test_a_usage_ledger_that_goes_quiet_mid_run_does_not_abort_the_loop(self):
        # The module-level `run_probes` patch is stopped for this test ALONE:
        # the point is to run the real probe against the real ledger.
        _patch.stop()
        self.addCleanup(_patch.start)
        d, floor = self._repo()
        # _repo seeds an all-proven artifact for the tests that patch the
        # probes out; here the real probes must establish the baseline
        # themselves, or invocation 1 would refuse against that fixture.
        os.remove(runio._pano(d, runio.HOST_CAPABILITIES))
        bin_dir = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(bin_dir, ignore_errors=True))
        cli = os.path.join(bin_dir, "claude")
        with open(cli, "w", encoding="utf-8") as fh:
            fh.write("#!/bin/sh\nexit 0\n")     # found by shutil.which, never run
        os.chmod(cli, 0o755)

        runner = self.LedgerGoesQuiet()
        args = self._args(d, "--allow-unenforced",
                          "--session-dir", self._session_root(d))
        # PREPENDED, not replacing: the loop shells out to `git` for the
        # clean-tree baseline, and a PATH holding only `bin_dir` would fail
        # that probe for a reason this test is not about. `shutil.which`
        # searches in order, so the stub still wins -- and it is never
        # executed anyway (every launch goes through the injected runner).
        with mock.patch.dict(os.environ,
                             {"PATH": bin_dir + os.pathsep + os.environ.get("PATH", "")}), \
                mock.patch.object(orchestrate, "_after_first_run",
                                  side_effect=lambda root: self._seed_coverage(root, floor)), \
                mock.patch("scripts.runners.base.runner_for", return_value=runner), \
                contextlib.redirect_stdout(io.StringIO()):
            status = orchestrate.loop(args)

        self.assertEqual("complete", status["status"], status)
        # The probe really ran, against the real CLI-interrogation path.
        self.assertIn([cli, "--help"], runner.help_calls)
        # ...and it really did change its mind: the ledger the loop wrote
        # carries successful launches with no usage figure in them.
        evidence = runio.host_evidence(d)
        self.assertEqual(hosts.REFUTED, evidence[hosts.USAGE_LEDGER]["state"])
        self.assertIn("not one envelope carried a usage figure",
                      evidence[hosts.USAGE_LEDGER]["detail"])


class TestTheLoopAsksTheRunnerForItsWidth(unittest.TestCase):
    """#1576: the loop's outage tally and `iter_batch`'s pool have to be the
    SAME number, and they were two copies of one expression --
    `max(1, int(concurrency or runner.default_concurrency))`, written out in
    both places. One of them then grew a ceiling and the other did not, which
    is how a clamp becomes a clamp on one of two pools.

    Read off the AST rather than the text: the comment above the call site
    names `default_concurrency` in prose, and a grep-based guard would either
    flag the prose or be defeated by a line break in the expression.
    """

    def _tree(self):
        path = os.path.join(os.path.dirname(os.path.abspath(orchestrate.__file__)),
                            "orchestrate.py")
        with open(path, encoding="utf-8") as fh:
            return path, ast.parse(fh.read(), path)

    def test_the_loop_calls_batch_width(self):
        path, tree = self._tree()
        calls = {ast.unparse(node.func) for node in ast.walk(tree)
                 if isinstance(node, ast.Call)}
        self.assertIn("runner.batch_width", calls, path)

    def test_the_loop_never_reads_default_concurrency_itself(self):
        path, tree = self._tree()
        offenders = ["%s:%d: %s" % (path, node.lineno, ast.unparse(node))
                     for node in ast.walk(tree)
                     if isinstance(node, ast.Attribute)
                     and node.attr == "default_concurrency"]
        self.assertEqual(
            [], offenders,
            "the loop re-derives the pool width instead of asking "
            "`runner.batch_width(...)`, so the ceiling binds one pool and not "
            "the other:\n  %s" % "\n  ".join(offenders))

    def test_the_flag_itself_still_takes_any_positive_int(self):
        # The clamp is ONE place. A second bound in the parser would be a
        # second ceiling, and a `--concurrency 500` that argparse rejects can
        # never be clamped-and-reported by the runner that owns the number.
        parser = driver.build_parser()
        args = parser.parse_args(["loop", ".", "--concurrency", "500"])
        self.assertEqual(500, args.concurrency)
        with self.assertRaises(SystemExit):
            parser.parse_args(["loop", ".", "--concurrency", "0"])

