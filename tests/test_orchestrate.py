"""driver loop (spec 4.3): the engine driven by a process, with a fake runner."""
import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

import scripts.driver as driver
import scripts.orchestrate as orchestrate
import scripts.phases.review as review
import scripts.phases.runio as runio
import scripts.read_guard_hook as read_guard_hook
import scripts.runners.base as base
import scripts.write_guard_hook as write_guard_hook
from conftest import write_host_evidence
from scripts import hosts

_ALL_PROVEN = {c: hosts.PROVEN for c in hosts.CAPABILITIES}
RUN_ID = None   # the manifest mints one; the fake reads it off the entry


def _all_proven_artifact(host="claude"):
    return {"schema_version": 1, "host": host, "probed_at": "2026-09-10T00:00:00Z",
            "capabilities": {c: {"state": hosts.PROVEN, "by": "fixture", "detail": "fixture"}
                             for c in hosts.CAPABILITIES}}


def _write_guard_not_proven(host, target, **kw):
    """host_probes.run_probes stand-in: every capability PROVEN except
    artifact_write_guard, left UNKNOWN -- drives the not-proven write-guard
    posture through the probe (Task 5 ruling 2), never through
    write_host_evidence: driver.run re-probes on every invocation via this
    same patched function and overwrites the evidence artifact, so a
    write_host_evidence call would be silently undone the moment the first
    driver.run() executes."""
    body = _all_proven_artifact(host)
    body["capabilities"][hosts.ARTIFACT_WRITE_GUARD] = {
        "state": hosts.UNKNOWN, "by": None,
        "detail": "fixture: write guard deliberately not proven"}
    return body


def setUpModule():
    global _patch
    _patch = mock.patch("scripts.host_probes.run_probes",
                        side_effect=lambda host, target, **kw: _all_proven_artifact(host))
    _patch.start()


def tearDownModule():
    _patch.stop()


class FakeRunner(base.HostRunner):
    """Answers entries like a well-behaved agent: self-writes findings/verdicts
    under the write guard (a real agent's Write would be mediated; here the
    fake writes directly, and the test asserts the guard WAS armed around it),
    returns JSON text for return-persist entries, and can be told to drop or
    fail an entry once."""
    host = "claude"; mode = "headless"; default_concurrency = 4

    def __init__(self, host="claude"):
        super().__init__(host)
        self.launched = []
        self.drop_once = set()
        self.fail_once = set()
        self.seen_env = {}
        self.armed_at_launch = []

    def prepare(self, run_dir, review_root):
        self.run_dir, self.review_root = run_dir, review_root
        self.settings_path = os.path.join(run_dir, base.SETTINGS_FILE)

    def run_entry(self, entry, env):
        eid = entry["id"]
        self.launched.append(eid)
        self.seen_env[eid] = dict(env)
        self.armed_at_launch.append((
            write_guard_hook.is_armed(self.settings_path, os.path.join(self.run_dir, "write-allowlist.json"))[0],
            read_guard_hook.is_armed(self.settings_path, os.path.join(self.run_dir, "read-scope.json"))[0]))
        if eid in self.drop_once:
            self.drop_once.discard(eid)
            return base.RunResult.failed(eid, "concurrency cap")
        if eid in self.fail_once:
            self.fail_once.discard(eid)
            # M2: a failed entry still BURNED tokens -- `claude -p` reports
            # usage on an is_error envelope exactly as it does on success --
            # so the fake reports them too, and the usage assertions below can
            # tell a document that counts them from one that drops them.
            return base.RunResult(entry_id=eid, ok=False, text="",
                                  usage={"input_tokens": 70, "output_tokens": 3,
                                         "cache_read_input_tokens": 0,
                                         "cache_creation_input_tokens": 0},
                                  cost_usd=0.004, model="claude-sonnet-5",
                                  session_id="s-" + eid, denials=[], error="is_error")
        run_id = entry.get("run_id")
        if eid.startswith("review-"):
            body = {"findings": [{"title": "issue", "severity": "HIGH", "domain": entry["domain"],
                                  "code": entry["domain"] + "-A1A", "category": "authz",
                                  "location": {"file": "src/app.py", "line_start": 1}}],
                    "_panopticon": {"run_id": run_id, "role": "domain_panel",
                                    "domain": entry["domain"], "group": entry["group"]}}
        elif eid.startswith("verify-"):
            cell = review._load_cell_findings(self.review_root, {"run_id": run_id},
                                              entry["group"], entry["domain"])
            body = {"verdicts": [{"finding_id": cell[0]["id"], "verdict": "CONFIRMED",
                                  "reasoning": "verified"}],
                    "_panopticon": {"run_id": run_id, "role": "domain_advisor",
                                    "domain": entry["domain"], "group": entry["group"],
                                    "stage": entry.get("stage", "primary")}}
        else:
            raise AssertionError("unexpected entry %s" % eid)
        if entry.get("delivery") == "return_json":
            text = "```json\n" + json.dumps(body) + "\n```"
        else:
            runio._write_json(entry["out_file"], body)
            text = "written"
        return base.RunResult(entry_id=eid, ok=True, text=text,
                              usage={"input_tokens": 100, "output_tokens": 10,
                                     "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0},
                              cost_usd=0.01, model="claude-sonnet-5", session_id="s-" + eid,
                              denials=[], error=None)


class LoopCase(unittest.TestCase):
    def _repo(self, floor=("SEC",)):
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        os.makedirs(os.path.join(d, "src"))
        with open(os.path.join(d, "src", "app.py"), "w") as fh:
            fh.write("def f():\n    return 1\n")
        os.makedirs(os.path.join(d, ".panopticon"))
        write_host_evidence(d, _ALL_PROVEN)
        runio._write_json(runio._pano(d, "groups.json"),
                          {"groups": [{"name": "app", "files": ["src/app.py"]}]})
        with open(runio._pano(d, "groups.yml"), "w") as fh:
            fh.write("groups:\n  app:\n    match: ['src/**']\n")
        return d, list(floor)

    def _args(self, d, *extra):
        return driver.build_parser().parse_args(
            ["loop", d, "--no-tools", "--fail-on", "high", *extra])

    def _session_root(self, d):
        # session mode arms the SESSION root's settings file (spec 5.1); the
        # tests point it at a sandbox via --session-dir so the real file is
        # never touched, and pre-create the file install() requires (#1493).
        s = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(s, ignore_errors=True))
        os.makedirs(os.path.join(s, ".claude"))
        with open(os.path.join(s, ".claude", "settings.local.json"), "w") as fh:
            fh.write("{}")
        return s

    def _seed_coverage(self, d, floor):
        # discovery/coverage would dispatch a scout; seed coverage so the first
        # checkpoint is review (the scout path is covered by TestScoutRoundTrip).
        # Returns True: this seam mutated review_root, so `loop` must re-derive
        # `status` with a second driver.run call to see the review checkpoint
        # (production's `_after_first_run` always returns False -- see its
        # docstring for why an unconditional second call would be a bug).
        manifest = driver.run_manifest.load_manifest(d)
        runio._write_json(runio._pano(d, "coverage-app.json"),
                          {"group": "app", "floor": floor, "effective": floor,
                           "run_id": manifest["run_id"]})
        return True


class TestHeadlessLoop(LoopCase):
    def _run(self, d, floor, runner, *extra):
        args = self._args(d, *extra)
        # first driver.run mints the manifest; seed coverage right after (the
        # loop's first iteration will then see the review checkpoint)
        with mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=lambda review_root: self._seed_coverage(review_root, floor)), \
             mock.patch("scripts.runners.base.runner_for", return_value=runner), \
             contextlib.redirect_stdout(io.StringIO()):
            return orchestrate.loop(args)

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
        self.assertIn("2", status["message"])

    def test_max_budget_stops_new_launches_and_exits_error_with_the_ledger(self):
        d, floor = self._repo()
        runner = FakeRunner()
        status = self._run(d, floor, runner, "--max-budget-usd", "0.005")
        self.assertEqual(status["status"], "error")
        self.assertIn("dispatch-ledger.jsonl", status["message"])
        self.assertEqual(runner.launched, ["review-app-SEC"])      # one launch crossed the budget

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
        d, floor = self._repo()
        runner = FakeRunner()
        with mock.patch.object(orchestrate, "write_usage", side_effect=RuntimeError("boom")):
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
        d, floor = self._repo()
        runner = FakeRunner()
        calls = {"n": 0}
        orig_write_usage = orchestrate.write_usage

        def _fail_first_call(review_root, ledger, namespace=None):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("boom")
            return orig_write_usage(review_root, ledger, namespace)

        with mock.patch.object(orchestrate, "write_usage", side_effect=_fail_first_call):
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


class TestNoRedundantReDeriveOnReview(LoopCase):
    """review round 1, item 2 (plan-mandated bug): `_after_first_run`'s seam
    must gate the second `driver.run` call -- an UNCONDITIONAL one burns a
    cell's cell-attempts.json retry budget on every resume that lands on the
    `review` checkpoint, with zero launches in between."""

    def test_a_review_checkpoint_reached_by_first_run_burns_no_attempt_without_a_launch(self):
        d, floor = self._repo()
        args = self._args(d)
        # Simulate a resume: an earlier process already minted the manifest
        # and got coverage established (e.g. a prior `driver loop` that
        # crashed after coverage but before any review launch), so THIS new
        # orchestrate.loop() call's very first driver.run() lands directly on
        # the review checkpoint. `_after_first_run` is left UNPATCHED here
        # (the production no-op) -- if `loop` still re-derived unconditionally,
        # it would call review_execute a second time with no launch at all,
        # inflating cell-attempts.json.
        driver.run(args)                        # mints the manifest, dispatches the scout
        self._seed_coverage(d, floor)
        runner = FakeRunner(); runner.fail_once.add("review-app-SEC")
        with mock.patch("scripts.runners.base.runner_for", return_value=runner), \
             contextlib.redirect_stdout(io.StringIO()):
            status = orchestrate.loop(args)
        self.assertEqual(status["status"], "complete", status)
        attempts = runio._load_json(runio._pano(d, "cell-attempts.json"))
        review_launches = runner.launched.count("review-app-SEC")
        self.assertEqual(review_launches, 2)     # failed once, then a real retry
        self.assertEqual(attempts["app/SEC"], review_launches)


class TestLoopParser(unittest.TestCase):
    """review round 1, item 6: `--max-per-group` (shared with `setup`, for
    symmetry with `--max-groups`) parses on the `loop` verb."""

    def test_max_per_group_and_max_groups_are_both_accepted(self):
        args = driver.build_parser().parse_args(
            ["loop", ".", "--max-per-group", "10", "--max-groups", "5"])
        self.assertEqual(args.max_per_group, 10)
        self.assertEqual(args.max_groups, 5)


class TestScoutRoundTrip(LoopCase):
    def test_the_scout_checkpoint_is_return_persisted_and_advances(self):
        d, _ = self._repo()
        class ScoutRunner(FakeRunner):
            def run_entry(self, entry, env):
                self.launched.append(entry["id"])
                if entry["id"].startswith("scout-"):
                    return base.RunResult(entry_id=entry["id"], ok=True,
                                          text=json.dumps({"domains": ["QAL"], "files": [], "tools": []}),
                                          usage={}, cost_usd=0.0, model=None, session_id=None,
                                          denials=[], error=None)
                return super().run_entry(entry, env)
        runner = ScoutRunner()
        args = self._args(d)
        with mock.patch("scripts.runners.base.runner_for", return_value=runner), \
             contextlib.redirect_stdout(io.StringIO()):
            status = orchestrate.loop(args)
        self.assertEqual(status["status"], "complete", status)
        self.assertEqual(runner.launched[0], "scout-app")
        self.assertTrue(os.path.isfile(runio._pano(d, "scout-app.json")))


class TestPendingFilter(unittest.TestCase):
    """Direct unit coverage for `_pending`'s persist.is_done filter (Task 6
    ruling 2's mutation gate: `_pending` returning `entries` unfiltered must
    make a test fail).

    This CANNOT be observed through TestSessionMode's re-entry test: every
    phase's own `execute()` already rebuilds dispatch-request.json with only
    not-yet-done entries on EVERY call (review_execute filters `_cell_done`
    cells before writing, and the request is a single shared path per run --
    verify's rewrite replaces review's entirely), so by the time `loop()`
    reads the request, a just-persisted entry is already absent from it --
    there is nothing left for `_pending` to drop. Confirmed empirically:
    mutating `_pending` to `return entries` left every existing test green.
    Only a direct call, handed a done and a pending entry in the SAME list,
    actually exercises the filter -- so this is the "strengthen the test ...
    until it does" fallback ruling 2 names, done as a dedicated unit test
    rather than inside the integration test (see the Task 6 report)."""

    def test_pending_drops_a_done_entry_and_keeps_a_pending_one(self):
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        done_out = os.path.join(d, "scout-done.json")
        runio._write_json(done_out, {"domains": [], "files": [], "tools": []})
        pending_out = os.path.join(d, "scout-pending.json")   # never written
        done_entry = {"id": "scout-done", "out_file": done_out}
        pending_entry = {"id": "scout-pending", "out_file": pending_out}
        self.assertTrue(orchestrate.persist.is_done(done_entry))
        self.assertFalse(orchestrate.persist.is_done(pending_entry))
        result = orchestrate._pending([done_entry, pending_entry])
        self.assertEqual([e["id"] for e in result], ["scout-pending"])


class TestVerifyBundleCompletenessGatesResume(LoopCase):
    """I3 (final review), the loop half: `_pending` must keep re-launching a
    verify cell the ENGINE still considers pending.

    `persist.is_done` accepted a verdict bundle on shape + stamp alone, while
    the engine's predicate (`verify._verify_cell_done`) also requires every
    dispatched claim to come back adjudicated. A short bundle therefore read
    as done HERE and pending THERE: `_pending` returned [], `run_batch([])`
    launched nothing, and each `driver.run` charged one of the cell's three
    re-dispatch attempts for a round trip that re-ran no advisor. The retry
    budget was spent without a single retry."""

    def test_a_short_verdict_bundle_keeps_the_cell_pending_and_re_launched(self):
        d, floor = self._repo()

        class ShortVerifyRunner(FakeRunner):
            """Self-writes a bundle that adjudicates NONE of the cell's claims
            -- the A2 (run-9) failure, where an advisor re-coded findings and
            returned fewer verdicts than it was handed."""

            def run_entry(self, entry, env):
                if not entry["id"].startswith("verify-"):
                    return super().run_entry(entry, env)
                self.launched.append(entry["id"])
                runio._write_json(entry["out_file"], {
                    "verdicts": [],
                    "_panopticon": {"run_id": entry.get("run_id"),
                                    "role": "domain_advisor",
                                    "domain": entry["domain"], "group": entry["group"],
                                    "stage": entry.get("stage", "primary")}})
                return base.RunResult(entry_id=entry["id"], ok=True, text="written",
                                      usage={}, cost_usd=0.0, model=None,
                                      session_id=None, denials=[], error=None)

        runner = ShortVerifyRunner()
        pending_seen = []
        real_pending = orchestrate._pending

        def _record(entries):
            out = real_pending(entries)
            pending_seen.append([e.get("id") for e in out])
            return out

        args = self._args(d)
        with mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=lambda rr: self._seed_coverage(rr, floor)), \
             mock.patch.object(orchestrate, "_pending", side_effect=_record), \
             mock.patch("scripts.runners.base.runner_for", return_value=runner), \
             contextlib.redirect_stdout(io.StringIO()):
            status = orchestrate.loop(args)
        # The bounded A2 budget still terminates the run -- but only after the
        # advisor was actually re-dispatched, which is the whole point of it.
        self.assertEqual(status["status"], "complete", status)
        self.assertGreaterEqual(runner.launched.count("verify-app-SEC-primary"), 2)
        # The defect was an empty pending set on EVERY iteration after the
        # first short bundle: the cell's whole re-dispatch budget spent on
        # round trips that launched nothing. The one empty set that remains is
        # the handoff at the cap -- `verify_execute` bumps to
        # `_MAX_VERIFY_ATTEMPTS` and writes the request in the SAME call, then
        # disowns the cell on the next one, so the loop is right to decline an
        # entry the engine has already given up on.
        self.assertTrue(pending_seen)
        self.assertEqual(pending_seen[-1], [])
        self.assertNotIn([], pending_seen[:-1])


class TestPerEntryFailureCap(LoopCase):
    """Fix round 2: the loop caps CONSECUTIVE failed launches per ENTRY.

    `--max-iterations` bounds the RUN. It does not bound the thing that
    actually goes wrong, which is one entry that cannot advance while the rest
    of the run is fine. Two failure kinds count the same here because from the
    run's point of view they ARE the same -- the runner failed the launch, or
    the launch came back and persist refused the reply -- and neither becomes
    likelier on the fortieth attempt.

    This is what bounds the return-persist path, which the I3 completeness fix
    left uncapped: a refused bundle never reaches disk, so
    `verify._verify_bundle_labeled` stays false, so the phase's own A2 attempt
    budget never bumps. Measured before this cap: 11 launches of one advisor
    at `--max-iterations 12`.
    """

    def _run_loop(self, d, floor, runner, *extra, probes=None):
        args = self._args(d, *extra)
        with contextlib.ExitStack() as es:
            if probes is not None:
                es.enter_context(mock.patch("scripts.host_probes.run_probes",
                                            side_effect=probes))
            es.enter_context(mock.patch.object(
                orchestrate, "_after_first_run",
                side_effect=lambda rr: self._seed_coverage(rr, floor)))
            es.enter_context(mock.patch("scripts.runners.base.runner_for",
                                        return_value=runner))
            es.enter_context(contextlib.redirect_stdout(io.StringIO()))
            es.enter_context(contextlib.redirect_stderr(io.StringIO()))
            return orchestrate.loop(args)

    def test_a_chronically_refused_reply_stops_at_the_cap(self):
        d, floor = self._repo()

        class ShortReturnRunner(FakeRunner):
            """Return-persist advisor that adjudicates none of its claims, every
            time -- the A2 (run-9) re-coding failure, on a host with no proven
            write guard."""

            def run_entry(self, entry, env):
                if not entry["id"].startswith("verify-"):
                    return super().run_entry(entry, env)
                self.launched.append(entry["id"])
                body = {"verdicts": [],
                        "_panopticon": {"run_id": entry.get("run_id"),
                                        "role": "domain_advisor",
                                        "domain": entry["domain"], "group": entry["group"],
                                        "stage": entry.get("stage", "primary")}}
                return base.RunResult(
                    entry_id=entry["id"], ok=True,
                    text="```json\n" + json.dumps(body) + "\n```",
                    usage={"input_tokens": 11, "output_tokens": 2,
                           "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0},
                    cost_usd=0.002, model="claude-sonnet-5", session_id="s",
                    denials=[], error=None)

        runner = ShortReturnRunner()
        status = self._run_loop(d, floor, runner, "--allow-unenforced",
                                probes=_write_guard_not_proven)
        self.assertEqual(status["status"], "error", status)
        self.assertEqual(runner.launched.count("verify-app-SEC-primary"),
                         orchestrate.MAX_ENTRY_FAILURES)
        self.assertIn("verify-app-SEC-primary", status["message"])
        self.assertIn("3 consecutive launches", status["message"])
        self.assertIn("persist refused", status["message"])
        rows = [r for r in orchestrate.Ledger(runner.run_dir).lines()
                if r["entry_id"] == "verify-app-SEC-primary"]
        self.assertEqual(len(rows), orchestrate.MAX_ENTRY_FAILURES)
        for row in rows:
            # the runner said ok; the RUN did not advance, and the ledger says so
            self.assertFalse(row["ok"], row)
            self.assertTrue(row["error"].startswith("persist refused"), row["error"])
            self.assertEqual(sum(row["usage"].values()), 13)   # M2: tokens still counted
            self.assertEqual(row["cost_usd"], 0.002)

    def test_a_clean_launch_resets_the_entrys_streak(self):
        d, floor = self._repo()

        class FlakyVerifyRunner(FakeRunner):
            """Fails twice, self-writes a SHORT bundle (a clean launch that does
            not finish the cell), fails twice more, then writes the real one.
            Five launches -- the sixth is never dispatched, because the A2
            attempt budget the short bundle started bumping runs out first and
            the cell is declared done (exhausted) on the iteration that would
            have launched it. Never three consecutive failures either way, so
            the run must reach `complete`; without the reset the third failure
            lands on launch 4 and the cap trips at four."""

            def run_entry(self, entry, env):
                if not entry["id"].startswith("verify-"):
                    return super().run_entry(entry, env)
                self.launched.append(entry["id"])
                n = self.launched.count(entry["id"])
                if n in (1, 2, 4, 5):
                    return base.RunResult.failed(entry["id"], "flaky")
                cell = review._load_cell_findings(
                    self.review_root, {"run_id": entry["run_id"]},
                    entry["group"], entry["domain"])
                runio._write_json(entry["out_file"], {
                    "verdicts": [] if n == 3 else [
                        {"finding_id": cell[0]["id"], "verdict": "CONFIRMED",
                         "reasoning": "v"}],
                    "_panopticon": {"run_id": entry["run_id"], "role": "domain_advisor",
                                    "domain": entry["domain"], "group": entry["group"],
                                    "stage": entry.get("stage", "primary")}})
                return base.RunResult(entry_id=entry["id"], ok=True, text="written",
                                      usage={}, cost_usd=0.0, model=None,
                                      session_id=None, denials=[], error=None)

        runner = FlakyVerifyRunner()
        status = self._run_loop(d, floor, runner)
        self.assertEqual(status["status"], "complete", status)
        self.assertEqual(runner.launched.count("verify-app-SEC-primary"), 5)

    def test_repeated_runner_failures_stop_at_the_same_cap(self):
        d, floor = self._repo()

        class AlwaysFailsVerify(FakeRunner):
            def run_entry(self, entry, env):
                if not entry["id"].startswith("verify-"):
                    return super().run_entry(entry, env)
                self.launched.append(entry["id"])
                return base.RunResult.failed(entry["id"], "always")

        runner = AlwaysFailsVerify()
        status = self._run_loop(d, floor, runner)
        self.assertEqual(status["status"], "error", status)
        self.assertEqual(runner.launched.count("verify-app-SEC-primary"),
                         orchestrate.MAX_ENTRY_FAILURES)
        self.assertIn("verify-app-SEC-primary", status["message"])
        self.assertIn("3 consecutive launches", status["message"])
        self.assertIn("last: always", status["message"])
