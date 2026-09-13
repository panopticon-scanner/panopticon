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
            return base.RunResult.failed(eid, "is_error")
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
        # the target's own settings file was never created (D3)
        self.assertFalse(os.path.exists(os.path.join(d, ".claude", "settings.local.json")))

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
        ok_lines = [row for row in lines if row["ok"]]
        self.assertEqual(usage["total"], sum(sum(row["usage"].values()) for row in ok_lines))
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

        def _fail_first_call(review_root, ledger):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("boom")
            return orig_write_usage(review_root, ledger)

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
        ok_lines = [row for row in lines if row["ok"]]
        self.assertEqual(usage["total"], sum(sum(row["usage"].values()) for row in ok_lines))


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


class TestSessionMode(LoopCase):
    def _loop(self, d, *extra):
        args = self._args(d, "--mode", "session", *extra)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            status = orchestrate.loop(args)
        return status, out.getvalue()

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

    def _armed_read_ids(self, s):
        # read_guard_hook.is_armed() answers (armed, COUNT), not the id set
        # (#1493 guard_state has the same shape) -- reach into the private
        # scope file directly, exactly as tests/test_read_guard_hook.py does
        # (e.g. `set(rg._read_scope_file(self.scope_path))`), to assert WHICH
        # ids are armed rather than merely how many.
        _settings, scope_path, _ = read_guard_hook._resolve(None, None, s)
        return set(read_guard_hook._read_scope_file(scope_path))

    def test_the_loop_exits_dispatch_with_the_pending_ids_and_leaves_guards_armed(self):
        d, floor = self._repo(); s = self._session_root(d)
        with mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=lambda rr: self._seed_coverage(rr, floor)):
            status, out = self._loop(d, "--session-dir", s)
        self.assertEqual(status["status"], "dispatch", status)
        self.assertEqual(status["pending"], ["review-app-SEC"])
        printed = [json.loads(line) for line in out.splitlines() if line.startswith("{")]
        self.assertTrue(any(p.get("status") == "dispatch" and p.get("pending") == ["review-app-SEC"]
                            for p in printed))
        self.assertTrue(write_guard_hook.is_armed(session_root=s)[0])
        self.assertTrue(read_guard_hook.is_armed(session_root=s)[0])
        self.assertIn("review-app-SEC", self._armed_read_ids(s))

    def test_re_entry_with_nothing_done_re_emits_the_same_set(self):
        d, floor = self._repo(); s = self._session_root(d)
        with mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=lambda rr: self._seed_coverage(rr, floor)):
            s1, _ = self._loop(d, "--session-dir", s)
        s2, _ = self._loop(d, "--session-dir", s)
        self.assertEqual((s1["status"], s1["pending"]), (s2["status"], s2["pending"]))
        # nothing advanced, so the id must still be armed after the re-entry
        # disarms-then-rearms it (R-P6-6) -- never left armed-over-nothing.
        self.assertIn("review-app-SEC", self._armed_read_ids(s))

    def test_re_entry_after_persisting_every_entry_advances_and_disarms_the_done_ones(self):
        d, floor = self._repo(); s = self._session_root(d)
        # Ruling 1: drive the not-proven write-guard posture (so the review
        # cell is return-persist, not self-write) through the run_probes
        # patch -- never write_host_evidence, which driver.run's own re-probe
        # on every invocation would silently undo.
        with mock.patch("scripts.host_probes.run_probes", side_effect=_write_guard_not_proven), \
             mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=lambda rr: self._seed_coverage(rr, floor)):
            s1, _ = self._loop(d, "--session-dir", s, "--allow-unenforced")
        self.assertEqual(s1["status"], "dispatch")
        self.assertEqual(s1["pending"], ["review-app-SEC"])
        self.assertIn("review-app-SEC", self._armed_read_ids(s))
        req = orchestrate.requests.load_dispatch_request(d)
        entry = next(e for e in req["entries"] if e["id"] == "review-app-SEC")
        body = {"findings": [{"title": "issue", "severity": "HIGH", "domain": "SEC", "code": "SEC-A1A",
                              "category": "authz", "location": {"file": "src/app.py", "line_start": 1}}],
                "_panopticon": {"run_id": entry["run_id"], "role": "domain_panel",
                                "domain": "SEC", "group": "app"}}
        reply = os.path.join(d, "reply.txt")
        with open(reply, "w", encoding="utf-8") as fh:
            fh.write("```json\n" + json.dumps(body) + "\n```")
        with contextlib.redirect_stdout(io.StringIO()):
            rc = driver.main(["persist", "review-app-SEC", "--file", reply, d])
        self.assertEqual(rc, 0)
        with mock.patch("scripts.host_probes.run_probes", side_effect=_write_guard_not_proven):
            s2, _ = self._loop(d, "--session-dir", s, "--allow-unenforced")
        self.assertEqual(s2["status"], "dispatch")
        self.assertEqual(s2["checkpoint"], "verify")                    # advanced past review
        # the persisted entry must not be re-listed as pending, and must be
        # disarmed -- the mutation gate this test exists to catch (Task 6
        # ruling 2): a `_pending` that stopped filtering by persist.is_done
        # would re-list "review-app-SEC" here and never disarm it.
        self.assertNotIn("review-app-SEC", s2["pending"])
        self.assertNotIn("review-app-SEC", self._armed_read_ids(s))
        self.assertIn("verify-app-SEC-primary", s2["pending"])
        self.assertIn("verify-app-SEC-primary", self._armed_read_ids(s))

    def test_complete_disarms_both_guards_unconditionally(self):
        d, floor = self._repo(); s = self._session_root(d)
        with mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=lambda rr: self._seed_coverage(rr, floor)):
            self._loop(d, "--session-dir", s)
        # drive review + verify to done by self-writing exactly as a session would
        runner = FakeRunner(); runner.prepare(os.path.dirname(runio._pano(d, "x")), d)
        for _ in range(3):
            req = orchestrate.requests.load_dispatch_request(d) or {}
            for e in req.get("entries") or []:
                if not orchestrate.persist.is_done(e):
                    runner.run_entry(e, {})
            status, _ = self._loop(d, "--session-dir", s)
            if status["status"] == "complete":
                break
        self.assertEqual(status["status"], "complete", status)
        self.assertFalse(write_guard_hook.is_armed(session_root=s)[0])
        self.assertFalse(read_guard_hook.is_armed(session_root=s)[0])

    def test_headless_on_a_host_without_a_runner_is_an_error_naming_session_mode(self):
        d, _ = self._repo()
        args = self._args(d, "--host", "gemini")
        with contextlib.redirect_stdout(io.StringIO()):
            status = orchestrate.loop(args)
        self.assertEqual(status["status"], "error")
        self.assertIn("--mode session", status["message"])


class TestSetupOnRails(LoopCase):
    def test_setup_scan_is_run_through_the_runner_and_the_loop_stops_at_the_draft(self):
        d, _ = self._repo()

        class SetupRunner(FakeRunner):
            def run_entry(self, entry, env):
                self.launched.append(entry["id"])
                assert entry["id"] == "setup-scan"
                # setup_proposal.validate_proposal requires `groups` to be a
                # LIST of {"capability", "match", ...} mappings (the brief's
                # snippet nested them under a name key instead, which
                # validate_proposal rejects with "'groups' must be a
                # non-empty list" -- deviation, see the task report).
                proposal = {"groups": [{"capability": "custom:App", "match": ["src/**"], "tests": [],
                                        "profile": {"purpose": "app", "surfaces": [], "entry_points": [],
                                                    "trust_boundaries": []}}]}
                return base.RunResult(entry_id="setup-scan", ok=True, text=json.dumps(proposal),
                                      usage={}, cost_usd=0.0, model=None, session_id=None, denials=[], error=None)
        runner = SetupRunner()
        args = driver.build_parser().parse_args(["loop", d, "--setup"])
        with mock.patch("scripts.runners.base.runner_for", return_value=runner), \
             contextlib.redirect_stdout(io.StringIO()):
            status = orchestrate.loop(args)
        self.assertEqual(status["status"], "complete", status)
        self.assertEqual(runner.launched, ["setup-scan"])
        self.assertIn("setup-report.md", status["message"])
        self.assertIn("groups.yml.draft", status["message"])
        self.assertTrue(os.path.isfile(runio._pano(d, "setup-proposal.json")))
