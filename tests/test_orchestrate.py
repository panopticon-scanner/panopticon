"""driver loop (spec 4.3): the engine driven by a process, with a fake runner."""
import contextlib
import io
import json
import os
from unittest import mock


import scripts.driver as driver
import scripts.orchestrate as orchestrate
import scripts.phases.runio as runio
import scripts.read_guard_hook as read_guard_hook
import scripts.runners.base as base
import scripts.write_guard_hook as write_guard_hook
from tests._test_helpers import (all_proven_artifact as _all_proven_artifact, write_guard_not_proven as _write_guard_not_proven)
from tests._test_helpers import docker_probe_runner


from tests.orchestrate_helpers import (ACreditedLedger, FakeRunner, FifteenCentRows,
    PoisonedLedger, _HeadlessLoopCase)

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
    def test_the_loop_hands_the_runner_its_namespace_before_preparing(self):
        # A runner cannot decide what to arm without knowing WHICH namespace
        # it is preparing for: the Codex runner's enforced-only refusal has to
        # stand down for `--setup`, whose only entry needs no registered
        # shell. Both facts were handed over one line AFTER prepare().
        class Recording(FakeRunner):
            seen = "unset"

            def prepare(self, run_dir, review_root):
                Recording.seen = (self.namespace, self.dispatch_request)
                super().prepare(run_dir, review_root)

        d, floor = self._repo()
        self._run(d, floor, Recording())
        namespace, request = Recording.seen
        self.assertIsNone(namespace)                     # a review run
        self.assertIsNotNone(request)                    # ...but both were handed over
        self.assertTrue(request.endswith("dispatch-request.json"), request)

    def test_max_turns_warns_when_the_runner_cannot_honour_it(self):
        # M-9: orchestrate sets `runner.max_turns` unconditionally and the
        # Codex runner never reads it -- accepted, then silently ignored.
        class NoTurnLimit(FakeRunner):
            HONOURS_MAX_TURNS = False

        d, floor = self._repo()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            status = self._run(d, floor, NoTurnLimit("codex"), "--allow-unenforced",
                               "--host", "codex", "--max-turns", "3")
        self.assertEqual(status["status"], "complete", status)
        self.assertIn("--max-turns has no effect on host 'codex'", err.getvalue())
        self.assertIn("--entry-timeout", err.getvalue())

    def test_max_turns_is_silent_on_a_runner_that_honours_it(self):
        d, floor = self._repo()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self._run(d, floor, FakeRunner(), "--max-turns", "3")
        self.assertNotIn("--max-turns has no effect", err.getvalue())

    def test_max_budget_warns_on_a_host_that_reports_no_dollars(self):
        # I-3: parse_envelope refuses to fabricate a cost, so cost_usd is
        # always None on Codex, the ledger total stays 0 and the budget branch
        # never trips. The flag was accepted without a word.
        d, floor = self._repo()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            # --allow-unenforced: codex claims no artifact_write_guard, so the
            # shared §7.3 gate refuses the plan without it (I-9).
            status = self._run(d, floor, FakeRunner("codex"), "--allow-unenforced",
                               "--host", "codex", "--max-budget-usd", "5")
        self.assertEqual(status["status"], "complete", status)
        self.assertIn("--max-budget-usd has no effect on host 'codex' "
                      "(no usage ledger)", err.getvalue())
        self.assertIn("--max-iterations", err.getvalue())
        self.assertIn("--entry-timeout", err.getvalue())

    def test_max_budget_is_silent_on_a_host_that_keeps_a_usage_ledger(self):
        d, floor = self._repo()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self._run(d, floor, FakeRunner(), "--max-budget-usd", "5")
        self.assertNotIn("no usage ledger", err.getvalue())

    def test_the_loop_reaches_complete_through_review_and_verify(self):
        d, floor = self._repo()
        runner = FakeRunner()
        status = self._run(d, floor, runner)
        self.assertEqual(status["status"], "complete", status)
        self.assertEqual(sorted(runner.launched), ["review-app-SEC", "verify-app-SEC-primary"])
        report = runio._load_json(runio._pano(d, "report.json"))
        self.assertNotEqual(report["summary"]["gate"], "INCONCLUSIVE")

    def test_guards_are_armed_around_every_launch_and_disarmed_after(self):
        d, floor = self._repo()
        runner = FakeRunner()
        self._run(d, floor, runner)
        self.assertTrue(runner.armed_at_launch)
        for w, r in runner.armed_at_launch:
            self.assertTrue(w and r)
        settings = os.path.join(runner.run_dir, base.SETTINGS_FILE)
        self.assertFalse(write_guard_hook.is_armed(settings, os.path.join(runner.run_dir, "write-allowlist.json"))[0])
        self.assertFalse(read_guard_hook.is_armed(settings, os.path.join(runner.run_dir, "read-scope.json"))[0])
        # M12: the run folder's allowlist and scope FILES are gone too, not
        # merely the hook entry -- `Guards.disarm` has to hand `uninstall` the
        # RUN-FOLDER paths for that, and dropping either one resolves the
        # cwd-relative default instead, leaving the real file behind.
        for name in (base.ALLOWLIST_FILE, base.SCOPE_FILE):
            self.assertFalse(os.path.exists(os.path.join(runner.run_dir, name)), name)
        # the target's own settings file was never created (D3)
        self.assertFalse(os.path.exists(os.path.join(d, ".claude", "settings.local.json")))

    def test_reset_is_consumed_by_the_first_run_not_re_applied_each_iteration(self):
        # 2026-09-13, found by the kimi family PR's first full `loop --reset`:
        # the loop hands the SAME args to every driver.run call, and with
        # args.reset left set each iteration re-ran the wipe+re-mint -- the
        # second call deleted the run folder the runner had just prepared
        # (kimi-home/config.toml there; claude's host-settings.json is the
        # same shape in the same place), and the manifest re-minted a new
        # tag every call while the ledger/runner/guards kept writing to the
        # first. One reset per loop, consumed by the first driver.run.
        d, floor = self._repo()
        runner = FakeRunner()
        minted = []

        def seed_and_record(review_root):
            minted.append(driver.run_manifest.load_manifest(review_root)["run_id"])
            return self._seed_coverage(review_root, floor)

        args = self._args(d, "--reset")
        with mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=seed_and_record), \
             mock.patch("scripts.runners.base.runner_for", return_value=runner), \
             contextlib.redirect_stdout(io.StringIO()):
            status = orchestrate.loop(args)
        self.assertEqual(status["status"], "complete", status)
        final = driver.run_manifest.load_manifest(d)["run_id"]
        self.assertEqual(minted[0], final)

    def test_every_launch_carries_the_three_bindings(self):
        d, floor = self._repo()
        runner = FakeRunner()
        self._run(d, floor, runner)
        env = runner.seen_env["review-app-SEC"]
        self.assertEqual(env[base.ENV_ENTRY_ID], "review-app-SEC")
        self.assertEqual(env[base.ENV_WRITE_ALLOWLIST], os.path.join(runner.run_dir, "write-allowlist.json"))
        self.assertEqual(env[base.ENV_READ_SCOPE], os.path.join(runner.run_dir, "read-scope.json"))

    def test_return_persist_entries_are_persisted_through_persist(self):
        d, floor = self._repo()
        runner = FakeRunner()

        # R-P6 Task 5 ruling 2: drive the not-proven write-guard posture
        # through the run_probes patch, not write_host_evidence -- driver.run
        # re-probes on every invocation via the module-patched run_probes and
        # overwrites the evidence artifact, so a write_host_evidence call here
        # would be silently undone the moment the first driver.run() executes.
        with mock.patch("scripts.host_probes.run_probes",
                        side_effect=_write_guard_not_proven), \
             mock.patch("scripts.phases.persist.write_reply",
                        wraps=orchestrate.persist.write_reply) as wr:
            status = self._run(d, floor, runner, "--allow-unenforced")
        self.assertEqual(status["status"], "complete", status)
        persisted = sorted(c.args[0]["id"] for c in wr.call_args_list)
        self.assertEqual(persisted, ["review-app-SEC", "verify-app-SEC-primary"])

    def test_a_dropped_entry_is_re_emitted_exactly_once(self):
        d, floor = self._repo()
        runner = FakeRunner(); runner.drop_once.add("review-app-SEC")
        status = self._run(d, floor, runner)
        self.assertEqual(status["status"], "complete")
        self.assertEqual(runner.launched.count("review-app-SEC"), 2)

    def test_the_ledger_has_one_line_per_launch_and_usage_sums_it(self):
        d, floor = self._repo()
        runner = FakeRunner(); runner.fail_once.add("verify-app-SEC-primary")
        self._run(d, floor, runner)
        with open(os.path.join(runner.run_dir, "dispatch-ledger.jsonl"), encoding="utf-8") as fh:
            lines = [json.loads(x) for x in fh if x.strip()]
        self.assertEqual(len(lines), len(runner.launched))
        self.assertEqual({row["phase"] for row in lines}, {"review", "verify"})
        self.assertEqual(sum(1 for row in lines if not row["ok"]), 1)
        usage = runio._load_json(os.path.join(runner.run_dir, "usage.json"))
        # M2: EVERY line, not just the ok ones. A launch that failed still
        # spent the tokens its envelope reported, and a usage document that
        # silently drops them under-reports what the run cost -- the one thing
        # an honest ledger must not do.
        self.assertEqual(usage["total"], sum(sum(row["usage"].values()) for row in lines))
        self.assertTrue(any(not row["ok"] and sum(row["usage"].values()) for row in lines))
        self.assertEqual(set(usage["by_phase"]), {"scout", "review", "verify", "unattributed"})
        report = runio._load_json(runio._pano(d, "report.json"))
        self.assertEqual(report["meta"]["cost"]["tokens"]["total"], usage["total"])   # R-P6-4

    def test_max_iterations_trips_to_error_naming_the_stuck_entries(self):
        d, floor = self._repo()
        runner = FakeRunner()
        runner.run_entry = lambda entry, env: base.RunResult.failed(entry["id"], "always")
        # 2, not 3: review's own MAX_CELL_ATTEMPTS retry budget is also 3, and
        # colliding with it would let the ENGINE reach `complete` on its own
        # (cell exhaustion counts as done) before this cap gets a chance to
        # fire -- a plan error, not a reason to change --max-iterations'
        # semantics (it must permit exactly N iterations, tripping on the
        # (N+1)th).
        status = self._run(d, floor, runner, "--max-iterations", "2")
        self.assertEqual(status["status"], "error")
        self.assertIn("review-app-SEC", status["message"])
        # #2379: the pending ids are request-sourced text on their way to an
        # operator's terminal, so the message renders each through `%r` -- the
        # register `loop_batch.misroute_refusal` already uses for the same
        # value. The engine cannot mint an id with control bytes today
        # (`_GROUP_NAME_RE` forbids them in the group half), so this asserts
        # the register rather than a hostile id.
        self.assertIn("'review-app-SEC'", status["message"])
        self.assertIn("2", status["message"])

    def test_max_budget_stops_new_launches_and_exits_error_with_the_ledger(self):
        d, floor = self._repo()
        runner = FakeRunner()
        status = self._run(d, floor, runner, "--max-budget-usd", "0.005")
        self.assertEqual(status["status"], "error")
        self.assertIn("dispatch-ledger.jsonl", status["message"])
        self.assertEqual(runner.launched, ["review-app-SEC"])      # one launch crossed the budget

    def test_a_non_finite_ledger_cost_stops_the_loop_instead_of_failing_open(self):
        # #1648, the sharp half: Python's JSON decoder ACCEPTS `NaN`, one such
        # cost poisons the sum, and `NaN >= budget` is False -- so the control
        # whose whole job is to stop spending kept launching paid entries. The
        # gate now fails CLOSED on a ledger line it cannot read.
        d, floor = self._repo()
        runner = PoisonedLedger()
        status = self._run(d, floor, runner, "--max-budget-usd", "1")
        self.assertEqual(status["status"], "error", status)
        self.assertIn("ledger corrupt at line 1", status["message"])
        self.assertIn("refusing to spend past an unreadable cost", status["message"])
        self.assertIn("delete or repair that line, or re-run with `--reset`",
                      status["message"])               # fix round 1, N1: say what to do
        self.assertEqual(runner.launched, [])            # nothing further was paid for
        # ...and the terminal teardown still ran over that same ledger: the
        # tokens half of `_finish`'s final write_usage must not fall over the
        # row the money half just refused the run for.
        self.assertNotIn("usage.json not written", status["message"])
        self.assertEqual(1, runio._load_json(
            os.path.join(runner.run_dir, "usage.json"))["corrupt_rows"])

    def test_a_negative_ledger_cost_is_not_spendable_credit(self):
        # Fix round 1, M1. A `-1000` cost summed as a credit puts the total a
        # thousand dollars below any budget, so the gate never fires again --
        # the #1648 fail-open reached by arithmetic rather than by NaN.
        d, floor = self._repo()
        runner = ACreditedLedger()
        status = self._run(d, floor, runner, "--max-budget-usd", "0.45")
        self.assertEqual(status["status"], "error", status)
        self.assertIn("non-negative", status["message"])
        self.assertEqual(runner.launched, [])

    def test_the_budget_boundary_is_exact_where_float_missed_it(self):
        # #1648, the mundane half. Three ledgered $0.15 rows against a $0.45
        # budget: as floats they sum to 0.44999999999999996, so the old gate
        # said the budget had NOT been reached and launched the next entry; the
        # exact sum is 0.45 and reaches it. The float fact is asserted rather
        # than assumed, and both ways of summing it -- `sum()` is compensated
        # from CPython 3.12, `+=` never is, and this suite runs on 3.11 too.
        running = 0.0
        for value in [0.15] * 3:
            running += value
        self.assertLess(sum([0.15] * 3), 0.45)
        self.assertLess(running, 0.45)
        d, floor = self._repo()
        runner = FifteenCentRows()
        status = self._run(d, floor, runner, "--max-budget-usd", "0.45")
        self.assertEqual(status["status"], "error", status)
        self.assertIn("--max-budget-usd 0.45 reached", status["message"])
        self.assertIn("dispatch-ledger.jsonl", status["message"])
        self.assertEqual(runner.launched, [])

    def test_an_interrupt_disarms_and_reports(self):
        d, floor = self._repo()
        runner = FakeRunner()
        def interrupt(entry, env):
            raise KeyboardInterrupt
        runner.run_entry = interrupt
        status = self._run(d, floor, runner)
        self.assertEqual(status["status"], "error")
        self.assertIn("interrupted", status["message"])
        settings = os.path.join(runner.run_dir, base.SETTINGS_FILE)
        self.assertFalse(write_guard_hook.is_armed(settings, os.path.join(runner.run_dir, "write-allowlist.json"))[0])

    def test_a_finished_entry_is_persisted_and_ledgered_before_its_peer_returns(self):
        d, floor = self._repo(floor=("SEC", "ACC"))
        runner = FakeRunner()
        seen = self._gate_on_peer(runner, "review-app-ACC", "review-app-SEC")
        status = self._return_persist(d, floor, runner)
        self.assertEqual(status["status"], "complete", status)
        # ...and usage.json is live during the batch, not only after it
        self.assertEqual({"reply": True, "ledger": True, "usage": True}, seen)
