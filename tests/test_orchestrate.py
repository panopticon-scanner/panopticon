"""driver loop (spec 4.3): the engine driven by a process, with a fake runner."""
import contextlib
import io
import json
import os
import tempfile
import tomllib

import pytest
from unittest import mock


import scripts.codex_host as codex_host
import scripts.driver as driver
import scripts.codex_read_tools as codex_read_tools
import scripts.dispatch as dispatch
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
        self.assertEqual(env[base.ENV_READ_SCOPE],
                         os.path.join(runner.run_dir, "read-scope", "review-app-SEC.json"))

    def test_six_hundred_tool_advisors_each_get_a_bounded_reader_binding(self):
        # #3219: the shared scope is deliberately over the broker's 1 MiB
        # binding cap, at the same 600-entry scale as the whole-repo failure.
        # Every launch must instead name its own small one-entry document.
        with tempfile.TemporaryDirectory() as temporary:
            root = os.path.realpath(temporary)
            run_dir = os.path.join(root, ".panopticon", "runs", "scale")
            os.makedirs(os.path.join(run_dir, "verdicts"))
            long_dir = os.path.join(root, "source", "x" * 150)
            entries = []
            for number in range(600):
                queue_id = "%016x" % number
                entries.append({
                    "id": "verify-tool-" + queue_id,
                    "agent": "panopticon-advisor",
                    "model": "fixture-model",
                    "out_file": os.path.join(run_dir, "verdicts", queue_id + ".json"),
                    "scope": {"files": [os.path.join(
                        long_dir, "%03d-%02d.py" % (number, item)) for item in range(10)],
                        "dirs": [], "reads": []},
                })
            guards = orchestrate.Guards("headless", run_dir=run_dir)
            registration_dir = os.path.join(root, "codex-agents")
            dispatch.emit_host_agents("codex", registration_dir)
            runtime_dir = os.path.join(root, "codex-runtime")

            def catalog():
                return [{"slug": "fixture-model"}]

            try:
                guards.arm(entries)
                self.assertGreater(os.path.getsize(guards.scope_path),
                                   codex_read_tools.MAX_FILE_BYTES)
                bindings = []
                for entry in entries:
                    env = guards.env_for(entry)
                    binding = env[base.ENV_READ_SCOPE]
                    bindings.append(binding)
                    self.assertLess(os.path.getsize(binding),
                                    codex_read_tools.MAX_FILE_BYTES)
                    reader = codex_read_tools.load_reader(env, cwd=root)
                    self.assertIn(os.path.realpath(entry["scope"]["files"][0]),
                                  reader.scope["files"])
                    argv = codex_host.command(
                        entry, env, root, runtime_dir,
                        registration_dir=registration_dir, catalog=catalog)
                    try:
                        config = tomllib.loads("\n".join(
                            argv[index + 1] for index, arg in enumerate(argv)
                            if arg == "-c"))
                        broker_env = config["mcp_servers"]["panopticon_scope"]["env"]
                        self.assertEqual(binding, broker_env[base.ENV_READ_SCOPE])
                    finally:
                        codex_host.cleanup_command(argv)
                self.assertEqual(600, len(set(bindings)))
            finally:
                guards.disarm(entries)
            self.assertFalse(os.path.exists(guards.entry_scopes.directory))

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


class TestHeadlessGuardSettingsAreBuiltFresh:
    """The headless settings file is the run folder's own, so arming builds it
    from the two guards' entries alone, never merged from what is on disk --
    in setup's flat folder and a review's `runs/<tag>/` alike."""

    PRIOR = {"hooks": {"PreToolUse": [{"matcher": "Read", "hooks": [
                 {"type": "command", "command": "true"}]}],
                       "SessionStart": [{"hooks": [{"type": "command", "command": "true"}]}]},
             "env": {"EXTRA": "1"}, "permissions": {"allow": ["Bash"]}, "model": "x"}

    def _guards(self, root, namespace):
        import scripts.phases.persist as persist
        run_dir = persist.run_dir(root, namespace)
        os.makedirs(os.path.join(run_dir, "out"), exist_ok=True)
        return orchestrate.Guards("headless", run_dir=run_dir), run_dir

    def _entry(self, run_dir, n=1):
        return {"id": "e%d" % n, "agent": "panopticon-advisor", "model": "m",
                "out_file": os.path.join(run_dir, "out", "e%d.json" % n),
                "scope": {"files": [], "dirs": [], "reads": []}}

    def _commands(self, doc):
        return [h["command"] for e in doc["hooks"]["PreToolUse"] for h in e["hooks"]]

    @pytest.mark.parametrize("namespace", ["setup", None])
    def test_only_the_guards_own_entries_are_in_the_armed_file(self, tmp_path, namespace):
        root = os.path.realpath(str(tmp_path))
        if namespace is None:
            runio._write_json(runio._pano(root, "run-manifest.json"),
                              {"schema_version": 1, "run_id": "0123456789abcdef", "host": "claude",
                               "review_root": root, "created": "2026-10-24T00:00:00Z",
                               "security_mode": "standard", "scope": {"mode": "repo"}})
        guards, run_dir = self._guards(root, namespace)
        assert (run_dir == os.path.join(root, ".panopticon")) == (namespace == "setup")
        runio._write_json(guards.settings_path, self.PRIOR)
        guards.arm([self._entry(run_dir)])
        with open(guards.settings_path, encoding="utf-8") as fh:
            doc = json.load(fh)
        assert list(doc) == ["hooks"] and list(doc["hooks"]) == ["PreToolUse"]
        entries = doc["hooks"]["PreToolUse"]
        assert len(entries) == 2
        assert all(write_guard_hook._is_our_entry(e) or read_guard_hook._is_our_entry(e)
                   for e in entries)
        assert any(write_guard_hook._is_our_entry(e) for e in entries)
        assert any(read_guard_hook._is_our_entry(e) for e in entries)

    def test_a_re_arm_keeps_both_guards_and_adds_nothing(self, tmp_path):
        root = os.path.realpath(str(tmp_path))
        guards, run_dir = self._guards(root, "setup")
        guards.arm([self._entry(run_dir, 1)])
        with open(guards.settings_path, encoding="utf-8") as fh:
            first = json.load(fh)
        seen = []
        real = write_guard_hook.install

        def install(*a, **k):   # the file as the second fan-out finds it
            with open(guards.settings_path, encoding="utf-8") as fh:
                seen.append(self._commands(json.load(fh)))
            return real(*a, **k)

        with mock.patch.object(write_guard_hook, "install", side_effect=install):
            guards.arm([self._entry(run_dir, 2)])
        assert seen == [self._commands(first)]       # never a state with a guard missing
        with open(guards.settings_path, encoding="utf-8") as fh:
            assert len(json.load(fh)["hooks"]["PreToolUse"]) == 2

    def _near_entries(self):
        """Entries that name a guard's script without being the entry its
        installer writes: a second hook beside it, or a longer command."""
        guard = os.path.abspath(write_guard_hook.__file__)
        return [{"matcher": "*", "hooks": [{"type": "command", "command": "true " + guard},
                                            {"type": "command", "command": "true extra"}]},
                {"matcher": "*", "hooks": [{"type": "command", "command": "true; " + guard}]}]

    def test_only_the_exact_installer_entries_are_carried(self, tmp_path):
        root = os.path.realpath(str(tmp_path))
        guards, run_dir = self._guards(root, "setup")
        near = self._near_entries()
        assert all(write_guard_hook._is_our_entry(e) for e in near)
        runio._write_json(guards.settings_path, {"hooks": {"PreToolUse": near}})
        base.own_settings(guards.settings_path)
        with open(guards.settings_path, encoding="utf-8") as fh:
            assert json.load(fh) == {}

    def test_nothing_else_survives_an_arm_whose_second_install_fails(self, tmp_path):
        root = os.path.realpath(str(tmp_path))
        guards, run_dir = self._guards(root, "setup")
        runio._write_json(guards.settings_path,
                          dict(self.PRIOR, hooks={"PreToolUse": self._near_entries()}))
        with mock.patch.object(read_guard_hook, "install", side_effect=RuntimeError("x")):
            with pytest.raises(RuntimeError):
                guards.arm([self._entry(run_dir)])
        with open(guards.settings_path, encoding="utf-8") as fh:
            doc = json.load(fh)
        assert list(doc) == ["hooks"]
        assert [write_guard_hook._is_our_entry(e) for e in doc["hooks"]["PreToolUse"]] == [True]
        assert doc["hooks"]["PreToolUse"] == [write_guard_hook._hook_entry(guards.allowlist_path)]

    def test_an_unreadable_file_is_replaced_not_refused(self, tmp_path):
        root = os.path.realpath(str(tmp_path))
        guards, run_dir = self._guards(root, "setup")
        with open(guards.settings_path, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        guards.arm([self._entry(run_dir)])
        with open(guards.settings_path, encoding="utf-8") as fh:
            assert list(json.load(fh)) == ["hooks"]

    def test_a_session_s_settings_are_still_merged(self, tmp_path):
        # The session file is the operator's own; its keys stay.
        root = os.path.realpath(str(tmp_path))
        settings = os.path.join(root, ".claude", "settings.local.json")
        os.makedirs(os.path.dirname(settings))
        runio._write_json(settings, {"permissions": {"allow": ["Read"]}})
        guards = orchestrate.Guards("session", session_root=root)
        guards.arm([self._entry(os.path.join(root, ".panopticon"))])
        with open(settings, encoding="utf-8") as fh:
            assert json.load(fh)["permissions"] == {"allow": ["Read"]}
