"""driver loop (spec 4.3): the engine driven by a process, with a fake runner."""
import ast
import contextlib
import copy
import dataclasses
import hashlib
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

import pytest

import scripts.driver as driver
import scripts.ledger as ledger_mod
import scripts.loop_batch as loop_batch
import scripts.orchestrate as orchestrate
import scripts.phases.review as review
import scripts.runners.batch as batch_mod
import scripts.phases.runio as runio
import scripts.read_guard_hook as read_guard_hook
import scripts.runners.base as base
import scripts.runners.claude as claude_runner
import scripts.runners.kimi as kimi_runner
import scripts.runners.outage as outage
import scripts.probes.shape as shape_probe
import scripts.write_guard_hook as write_guard_hook
from _test_helpers import dead_pid
from conftest import docker_probe_runner, write_host_evidence
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


class SeededLedger(FakeRunner):
    """A runner that leaves ledger lines on disk before the loop's first budget
    check -- `prepare` is the last thing the loop does before it constructs the
    Ledger and enters the while loop, so this is the seam for a ledger the
    process did not write itself (a resumed run, or a host that reported a
    cost this repo would now refuse to store)."""

    LINES = ()

    def prepare(self, run_dir, review_root):
        super().prepare(run_dir, review_root)
        os.makedirs(run_dir, exist_ok=True)
        with open(os.path.join(run_dir, base.LEDGER_FILE), "w", encoding="utf-8") as fh:
            fh.write("".join(x + "\n" for x in self.LINES))


class PoisonedLedger(SeededLedger):
    # Written by hand, exactly as `json.dumps` with its defaults emits it.
    LINES = ('{"cost_usd": NaN, "entry_id": "review-app-SEC", "error": null, '
             '"ok": true, "phase": "review", "usage": {}}',)


class ACreditedLedger(SeededLedger):
    # Fix round 1, M1: one negative cost, which a plain sum treats as a credit.
    LINES = ('{"cost_usd": -1000, "entry_id": "e0", "error": null, '
             '"ok": true, "phase": "review", "usage": {}}',)


class FifteenCentRows(SeededLedger):
    LINES = tuple('{"cost_usd": 0.15, "entry_id": "e%d", "error": null, '
                  '"ok": true, "phase": "review", "usage": {}}' % i for i in range(3))


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
        # #1681: `panopticon.yml` is a committed ROOT file now, so it is an
        # ordinary repo file discovery sees. Excluded here so this fixture keeps
        # its one-group/one-file shape (the loop's entry ids are pinned).
        matrix = ("groups:\n  app:\n    match: ['src/**']\n"
                  "exclude_paths: ['panopticon.yml']\n")
        with open(os.path.join(d, "panopticon.yml"), "w") as fh:
            fh.write("version: 1\n" + matrix)
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

    def _run_loop(self, d, floor, runner, *extra, probes=None, seed=True):
        """One whole `driver loop` against `runner`, with the engine's own
        phases real. `seed=False` is the RESUME shape: coverage is already on
        disk, so the second driver.run the seam exists for would only re-charge
        the review checkpoint's per-cell attempt marker (see
        `_after_first_run`)."""
        args = self._args(d, *extra)
        with contextlib.ExitStack() as es:
            if probes is not None:
                es.enter_context(mock.patch("scripts.host_probes.run_probes",
                                            side_effect=probes))
            es.enter_context(mock.patch.object(
                orchestrate, "_after_first_run",
                side_effect=lambda rr: seed and self._seed_coverage(rr, floor)))
            es.enter_context(mock.patch("scripts.runners.base.runner_for",
                                        return_value=runner))
            es.enter_context(contextlib.redirect_stdout(io.StringIO()))
            es.enter_context(contextlib.redirect_stderr(io.StringIO()))
            return orchestrate.loop(args)

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
    # #1912 (review round 1, finding 1): the two hardware ids the owner-stamp
    # cases STATE rather than read off whatever machine the suite is running on.
    # `uuid.getnode()` answers differently per host and falls back to a random
    # multicast value where it finds no hardware address -- and every owner
    # verdict asserted below has to be the same verdict on every machine.
    MACHINE = "acde48001122"            # "this machine", because the test says so
    OTHER_MACHINE = "00deadbeef00"      # ...and somebody else's

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

    # ---- P07 (#1636): each entry lands the moment it finishes ----------------
    #
    # Codex's run-13 evidence: 42 minutes into an 85-panel batch, zero
    # persisted outputs and a ledger holding only the 12 scouts, because the
    # loop persisted and ledgered nothing until the WHOLE batch returned. An
    # interruption there loses every completed reply and its usage, and the
    # resume repeats paid work.

    def _return_persist(self, d, floor, runner, *extra):
        """`self._run` in the posture where review/verify replies come back as
        JSON for the LOOP to persist (artifact_write_guard not proven, so
        `requests.delivery` says return_json). A persisted out_file is then
        evidence about the loop, not about the fake agent's own Write."""
        with mock.patch("scripts.host_probes.run_probes",
                        side_effect=_write_guard_not_proven):
            return self._run(d, floor, runner, "--allow-unenforced", *extra)

    def _peer_artifacts(self, runner, peer_id, timeout=10):
        """What is on disk for `peer_id`, polled from INSIDE another entry's
        run_entry -- so the answer describes what the loop had persisted while
        this batch was still running, which is the whole of P07."""
        req = orchestrate.requests.load_dispatch_request(runner.review_root) or {}
        peer = next(e for e in req.get("entries") or [] if e.get("id") == peer_id)
        usage_path = os.path.join(runner.run_dir, "usage.json")
        seen = {"reply": False, "ledger": False, "usage": False}
        deadline = time.monotonic() + timeout
        while True:
            seen["reply"] = os.path.exists(peer["out_file"])
            seen["ledger"] = any(row.get("entry_id") == peer_id
                                 for row in ledger_mod.Ledger(runner.run_dir).lines())
            seen["usage"] = bool((runio._load_json(usage_path) or {}).get("total"))
            if all(seen.values()) or time.monotonic() >= deadline:
                return seen
            time.sleep(0.02)

    def _gate_on_peer(self, runner, blocked_id, peer_id, then=None):
        """Make `blocked_id` sit inside run_entry until `peer_id`'s reply,
        ledger row and usage total exist; return what it saw."""
        seen, inner = {}, runner.run_entry

        def gated(entry, env):
            if entry["id"] == blocked_id and not seen:
                seen.update(self._peer_artifacts(runner, peer_id))
                if then is not None:
                    then()
            return inner(entry, env)

        runner.run_entry = gated
        return seen

    def test_a_finished_entry_is_persisted_and_ledgered_before_its_peer_returns(self):
        d, floor = self._repo(floor=("SEC", "ACC"))
        runner = FakeRunner()
        seen = self._gate_on_peer(runner, "review-app-ACC", "review-app-SEC")
        status = self._return_persist(d, floor, runner)
        self.assertEqual(status["status"], "complete", status)
        # ...and usage.json is live during the batch, not only after it
        self.assertEqual({"reply": True, "ledger": True, "usage": True}, seen)

    # ---- #1662: a Ctrl-C stops, cancels, and rolls back to the checkpoint ----
    #
    # P07's per-entry persistence still stands for a crash or a compaction --
    # it is what keeps a batch's completed work while the batch is running.
    # What the owner ruled is that a Ctrl-C is not a crash: it means complete
    # stoppage, and the interrupted PHASE is re-run from scratch rather than
    # recovered from disk. Whole-run rollback stays `--reset`.

    def _manifests(self, run_dir):
        return sorted(f for f in os.listdir(run_dir)
                      if f.startswith(batch_mod.MANIFEST_PREFIX) and f.endswith(".json"))

    def _interrupt_mid_batch(self, d, floor, runner):
        """Interrupt the review batch the moment its first entry has landed."""
        def interrupt():
            raise KeyboardInterrupt

        seen = self._gate_on_peer(runner, "review-app-ACC", "review-app-SEC",
                                  then=interrupt)
        return self._return_persist(d, floor, runner), seen

    def test_an_interrupt_rolls_the_batch_back_to_its_checkpoint(self):
        # One entry done, one still running when the Ctrl-C lands. While the
        # batch was live the finished entry really was on disk (P07, `seen`) --
        # and the interrupt then takes it back, because the phase re-runs from
        # its checkpoint rather than resuming half-done.
        d, floor = self._repo(floor=("SEC", "ACC"))
        runner = FakeRunner()
        status, seen = self._interrupt_mid_batch(d, floor, runner)
        self.assertEqual(status["status"], "error", status)
        self.assertEqual({"reply": True, "ledger": True, "usage": True}, seen)
        # "handled", not "completed": `done` counts every entry the loop got
        # back, a failed launch included -- it is ledgered as the failure it
        # was rather than persisted (F2), and the rollback takes back what it
        # did write either way.
        self.assertIn("interrupted: 1 of 2 entries had been handled and have been "
                      "rolled back", status["message"])
        self.assertIn("the phase will re-run from its checkpoint on the next "
                      "`driver loop`", status["message"])
        self.assertIn("use `--reset` to discard the whole run", status["message"])

        # the reply the loop had persisted is gone, and the entry is pending again
        req = orchestrate.requests.load_dispatch_request(d) or {}
        entries = {e["id"]: e for e in req.get("entries") or []}
        for eid in ("review-app-SEC", "review-app-ACC"):
            self.assertFalse(os.path.exists(entries[eid]["out_file"]), eid)
            self.assertFalse(orchestrate.persist.is_done(entries[eid]), eid)
        # the manifest that listed what to take back is gone with it
        self.assertEqual([], self._manifests(runner.run_dir))
        settings = os.path.join(runner.run_dir, base.SETTINGS_FILE)
        self.assertFalse(write_guard_hook.is_armed(
            settings, os.path.join(runner.run_dir, "write-allowlist.json"))[0])

    def test_an_interrupt_with_a_tampered_batch_list_preserves_its_files(self):
        d, floor = self._repo(floor=("SEC", "ACC"))
        runner = FakeRunner()
        outside = os.path.join(d, ".panopticon", "keep-outside.json")
        with open(outside, "w", encoding="utf-8") as fh:
            fh.write("keep")
        opened, original_open = [], batch_mod.Batch.open

        def capture(batch_self):
            opened.append(batch_self)
            return original_open(batch_self)

        def tamper_and_interrupt():
            opened[0].entries[0]["artifacts"].append(outside)
            raise KeyboardInterrupt

        seen = self._gate_on_peer(runner, "review-app-ACC", "review-app-SEC",
                                  then=tamper_and_interrupt)
        with mock.patch.object(batch_mod.Batch, "open", capture):
            status = self._return_persist(d, floor, runner)
        self.assertEqual("error", status["status"], status)
        self.assertTrue(seen["reply"])
        self.assertIn("rollback incomplete", status["message"])
        self.assertIn("batch artifact escapes the run folder", status["message"])
        req = orchestrate.requests.load_dispatch_request(d) or {}
        completed = next(e["out_file"] for e in req["entries"]
                         if e["id"] == "review-app-SEC")
        self.assertTrue(os.path.isfile(completed))
        self.assertEqual(["batch-1.json"], self._manifests(runner.run_dir))
        with open(outside, encoding="utf-8") as fh:
            self.assertEqual("keep", fh.read())

    def test_failed_recovery_flag_defers_bookkeeping_until_the_next_resume(self):
        d, floor = self._repo(floor=("SEC", "ACC"))
        runner = FakeRunner()
        outside = os.path.join(d, ".panopticon", "keep-outside.json")
        with open(outside, "w", encoding="utf-8") as fh:
            fh.write("keep")
        prior = {"app/SEC": 1, "app/ACC": 1}
        original_seed = self._seed_coverage

        def seed_prior_attempts(review_root, domains):
            result = original_seed(review_root, domains)
            runio._write_json(runio._pano(review_root, review._ATTEMPTS_FILE), prior)
            return result

        opened, original_open = [], batch_mod.Batch.open

        def capture(batch_self):
            opened.append(batch_self)
            return original_open(batch_self)

        def tamper_and_interrupt():
            opened[0].entries[0]["artifacts"].append(outside)
            raise KeyboardInterrupt

        seen = self._gate_on_peer(runner, "review-app-ACC", "review-app-SEC",
                                  then=tamper_and_interrupt)
        with mock.patch.object(self, "_seed_coverage", side_effect=seed_prior_attempts), \
             mock.patch.object(batch_mod.Batch, "open", capture):
            interrupted = self._return_persist(d, floor, runner)
        self.assertEqual("error", interrupted["status"], interrupted)
        self.assertTrue(seen["reply"])
        self.assertIn("rollback incomplete", interrupted["message"])
        manifest = os.path.join(runner.run_dir, "batch-1.json")
        self.assertTrue(os.path.isfile(manifest))
        self.assertNotIn("recovering", runio._load_json(manifest))
        req = orchestrate.requests.load_dispatch_request(d) or {}
        completed = next(e["out_file"] for e in req["entries"]
                         if e["id"] == "review-app-SEC")
        self.assertTrue(os.path.isfile(completed))
        self.assertEqual({"app/SEC": 2, "app/ACC": 2},
                         runio._load_json(runio._pano(d, review._ATTEMPTS_FILE)))
        before = ledger_mod.Ledger(runner.run_dir).lines()
        self.assertFalse(any(row.get("status") in (ledger_mod.ROLLED_BACK,
                                                    ledger_mod.CANCELLED) for row in before))
        with open(outside, encoding="utf-8") as fh:
            self.assertEqual("keep", fh.read())

        self._stamp_crash_owner(runner.run_dir, pid=dead_pid())
        stale_doc = runio._load_json(manifest)
        refused_doc = copy.deepcopy(stale_doc)
        refused_doc["entries"][0]["artifacts"].append(outside)
        runio._write_json(manifest, refused_doc)
        refused_runner = FakeRunner()
        with mock.patch("scripts.runners.base.runner_for", return_value=refused_runner), \
             contextlib.redirect_stderr(io.StringIO()), \
             contextlib.redirect_stdout(io.StringIO()):
            refused = orchestrate.loop(self._args(d, "--allow-unenforced"))
        self.assertEqual("error", refused["status"], refused)
        self.assertIn("escapes the run folder", refused["message"])
        self.assertEqual([], refused_runner.launched)
        self.assertTrue(os.path.isfile(manifest))
        self.assertTrue(os.path.isfile(completed))
        self.assertEqual({"app/SEC": 2, "app/ACC": 2},
                         runio._load_json(runio._pano(d, review._ATTEMPTS_FILE)))
        self.assertEqual(before, ledger_mod.Ledger(runner.run_dir).lines())

        runio._write_json(manifest, stale_doc)
        resumed = FakeRunner()
        with mock.patch("scripts.runners.base.runner_for", return_value=resumed), \
             mock.patch.object(orchestrate, "_first_run",
                               return_value=orchestrate._status("error", "stopped after recovery")), \
             contextlib.redirect_stderr(io.StringIO()), \
             contextlib.redirect_stdout(io.StringIO()):
            status = orchestrate.loop(self._args(d, "--allow-unenforced"))
        self.assertEqual("error", status["status"], status)
        self.assertEqual([], resumed.launched)
        self.assertEqual([], self._manifests(runner.run_dir))
        self.assertFalse(os.path.lexists(completed))
        self.assertEqual(prior, runio._load_json(runio._pano(d, review._ATTEMPTS_FILE)))
        after = ledger_mod.Ledger(runner.run_dir).lines()
        self.assertEqual(before, after[:len(before)])
        rolled = [row for row in after if row.get("status") in (ledger_mod.ROLLED_BACK,
                                                                 ledger_mod.CANCELLED)]
        self.assertEqual(2, len(rolled), rolled)
        with open(outside, encoding="utf-8") as fh:
            self.assertEqual("keep", fh.read())

    # `_dead_pid` was copied verbatim into tests/runners/test_batch.py; it is
    # `_test_helpers.dead_pid` now, imported by both (review round 1, finding 12).

    def _stamp_crash_owner(self, run_dir, **fields):
        """Rewrite every leftover crash record's owner stamp (#1698).

        The suite models a crash IN THIS PROCESS, so the record it leaves
        names a pid that is very much alive -- which is exactly what recovery
        now refuses to touch. A test about a CRASHED loop has to say the
        process is gone, and a reaped child's pid is the honest way to say it.
        """
        for name in self._manifests(run_dir):
            path = os.path.join(run_dir, name)
            doc = runio._load_json(path)
            doc.update(fields)
            runio._write_json(path, doc)

    def _crash_record(self, run_dir):
        return runio._load_json(os.path.join(run_dir, self._manifests(run_dir)[0]))

    def _untouched(self, d, run_dir):
        """Everything a refused recovery must leave exactly as it found it."""
        doc = self._crash_record(run_dir)
        return (sorted(self._manifests(run_dir)),
                [p for row in doc["entries"] for p in row["artifacts"] if os.path.exists(p)],
                ledger_mod.Ledger(run_dir).lines(),
                runio._load_json(runio._pano(d, review._ATTEMPTS_FILE)))

    def _leave_crashed_batch(self, d, floor):
        runner = FakeRunner()
        # Model a process that never reached its interrupt rollback. The
        # finished peer's artifact, real paid row and batch record survive.
        with mock.patch.object(loop_batch, "rolled_back",
                               return_value="simulated process loss"):
            self._interrupt_mid_batch(d, floor, runner)
        # ...and that process is GONE: the record it left names a dead pid.
        self._stamp_crash_owner(runner.run_dir, pid=dead_pid())
        return runner

    def test_resume_rolls_back_a_crashed_batch_before_reading_done_artifacts(self):
        d, floor = self._repo(floor=("SEC", "ACC"))
        crashed = self._leave_crashed_batch(d, floor)
        run_dir = crashed.run_dir
        self.assertTrue(self._manifests(run_dir))
        before = ledger_mod.Ledger(run_dir).lines()
        attempts = runio._load_json(runio._pano(d, review._ATTEMPTS_FILE))
        self.assertTrue(all(n >= 1 for n in attempts.values()))
        resumed = FakeRunner()
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()), \
                mock.patch("scripts.host_probes.run_probes", side_effect=_write_guard_not_proven), \
                mock.patch("scripts.runners.base.runner_for", return_value=resumed):
            status = orchestrate.loop(self._args(d, "--allow-unenforced"))
        self.assertEqual(status["status"], "complete", status)
        self.assertIn("review-app-SEC", resumed.launched)
        self.assertIn("review-app-ACC", resumed.launched)
        self.assertIn("recovered stale batch", err.getvalue())
        self.assertEqual(self._manifests(run_dir), [])
        after = ledger_mod.Ledger(run_dir).lines()
        self.assertEqual(after[:len(before)], before)
        self.assertTrue(any(r.get("status") == ledger_mod.ROLLED_BACK for r in after))
        self.assertEqual(runio._load_json(runio._pano(d, review._ATTEMPTS_FILE)), attempts)

    def test_recovery_accepts_hashed_rejection_name_and_refuses_unrelated_one(self):
        d, floor = self._repo(floor=("SEC", "ACC"))
        crashed = self._leave_crashed_batch(d, floor)
        manifest = os.path.join(crashed.run_dir, self._manifests(crashed.run_dir)[0])
        doc = runio._load_json(manifest)
        req = orchestrate.requests.previous_request(d)
        old_id = doc["entries"][0]["id"]
        new_id = "review-app:unsafe-SEC"
        doc["entries"][0]["id"] = new_id
        next(e for e in req["entries"] if e["id"] == old_id)["id"] = new_id
        component = orchestrate.requests.entry_file_component(new_id)
        retained = os.path.join(crashed.run_dir, "rejected", component + "-1.json")
        runio._write_json(retained, {"entry_id": new_id, "attempt": 1})
        wrong = os.path.join(crashed.run_dir, "rejected", "unrelated-1.json")
        runio._write_json(wrong, {"entry_id": "unrelated", "attempt": 1})
        doc["entries"][0]["artifacts"].append(wrong)
        runio._write_json(manifest, doc)
        with self.assertRaisesRegex(ValueError, "unexpected retained-reply artifact"):
            loop_batch.recover_stale(d, req, "claude", "headless")
        self.assertTrue(os.path.exists(retained))
        doc["entries"][0]["artifacts"][-1] = retained
        runio._write_json(manifest, doc)
        runio._write_json(retained, {"entry_id": "unrelated", "attempt": 1})
        with self.assertRaisesRegex(ValueError, "unexpected retained-reply artifact"):
            loop_batch.recover_stale(d, req, "claude", "headless")
        self.assertTrue(os.path.exists(retained))
        runio._write_json(retained, {"entry_id": new_id, "attempt": 1})
        with contextlib.redirect_stderr(io.StringIO()):
            loop_batch.recover_stale(d, req, "claude", "headless")
        self.assertFalse(os.path.exists(retained))
        self.assertFalse(os.path.exists(manifest))

    def test_an_outside_path_in_a_crash_record_refuses_before_any_deletion(self):
        d, floor = self._repo(floor=("SEC", "ACC"))
        crashed = self._leave_crashed_batch(d, floor)
        path = os.path.join(crashed.run_dir, self._manifests(crashed.run_dir)[0])
        doc = runio._load_json(path)
        victim = os.path.join(d, "keep.txt")
        with open(victim, "w") as fh:
            fh.write("keep")
        doc["entries"][0]["artifacts"].append(victim)
        runio._write_json(path, doc)
        existing = [p for row in doc["entries"] for p in row["artifacts"] if os.path.exists(p)]
        resumed = FakeRunner()
        status = self._return_persist(d, floor, resumed)
        self.assertEqual(status["status"], "error", status)
        self.assertIn("escapes the run folder", status["message"])
        self.assertEqual(resumed.launched, [])
        self.assertTrue(all(os.path.exists(p) for p in existing))
        self.assertTrue(os.path.exists(path))

    def test_a_linked_retained_reply_parent_in_a_crash_record_preserves_every_artifact(self):
        d, floor = self._repo(floor=("SEC", "ACC"))
        crashed = self._leave_crashed_batch(d, floor)
        run_dir = crashed.run_dir
        manifest = os.path.join(run_dir, self._manifests(run_dir)[0])
        doc = runio._load_json(manifest)
        rejected = os.path.join(run_dir, orchestrate.persist.REJECTED_DIR)
        os.makedirs(rejected, exist_ok=True)
        alias = os.path.join(run_dir, "linked-replies")
        os.symlink(rejected, alias)
        retained = os.path.join(rejected, "review-app-SEC-1.json")
        with open(retained, "w", encoding="utf-8") as fh:
            fh.write("keep")
        doc["entries"][0]["artifacts"].append(os.path.join(alias, os.path.basename(retained)))
        runio._write_json(manifest, doc)
        before = self._untouched(d, run_dir)
        resumed = FakeRunner()
        status = self._return_persist(d, floor, resumed)
        self.assertEqual("error", status["status"], status)
        self.assertIn("symlink", status["message"])
        self.assertEqual([], resumed.launched)
        self.assertEqual(before, self._untouched(d, run_dir))
        with open(retained, encoding="utf-8") as fh:
            self.assertEqual("keep", fh.read())

    # #1698: a manifest on disk is a CRASHED batch only if the process that
    # opened it is gone. A second `driver loop` on the same run folder used to
    # read the first's LIVE record as a crash: it deleted the artifacts that
    # loop was still producing, cancelled its entries, refunded its attempts
    # and unlinked its manifest, so the first loop's own Ctrl-C then found
    # nothing to roll back. `opened_at` cannot tell the two apart (a batch may
    # legitimately run for hours), so the record names its process and
    # recovery asks the operating system.

    def test_a_live_owner_refuses_the_resume_and_touches_nothing(self):
        d, floor = self._repo(floor=("SEC", "ACC"))
        crashed = self._leave_crashed_batch(d, floor)
        # the record says the loop that wrote it is still running, here
        self._stamp_crash_owner(crashed.run_dir, pid=os.getpid())
        before = self._untouched(d, crashed.run_dir)
        self.assertTrue(before[1], "the crashed batch left no artifact to protect")
        resumed = FakeRunner()
        status = self._return_persist(d, floor, resumed)
        self.assertEqual(status["status"], "error", status)
        self.assertIn("still running here", status["message"])
        self.assertIn(str(os.getpid()), status["message"])
        self.assertNotIn("--reset", status["message"])    # never, at a live loop
        self.assertEqual(resumed.launched, [])
        self.assertEqual(self._untouched(d, crashed.run_dir), before)

    def test_a_record_from_another_machine_refuses_rather_than_guesses(self):
        # A pid number from over there names some unrelated local process
        # here, so nothing may be concluded from it either way. #1912: BOTH
        # ids have to be somebody else's -- a record carrying this machine's
        # hardware id under another hostname is this machine's own.
        d, floor = self._repo(floor=("SEC", "ACC"))
        crashed = self._leave_crashed_batch(d, floor)
        self._stamp_crash_owner(crashed.run_dir, host="some-other-box",
                                machine=self.OTHER_MACHINE)
        before = self._untouched(d, crashed.run_dir)
        resumed = FakeRunner()
        status = self._return_persist(d, floor, resumed)
        self.assertEqual(status["status"], "error", status)
        self.assertIn("some-other-box", status["message"])
        self.assertIn("not this machine", status["message"])
        self.assertIn("--reset", status["message"])
        self.assertEqual(resumed.launched, [])
        self.assertEqual(self._untouched(d, crashed.run_dir), before)

    def test_the_same_machine_under_a_new_hostname_is_recovered_not_refused(self):
        # #1912 hazard 1, end to end: macOS renames the laptop between the
        # crash and the resume (`mac.office` -> `mac.local`), and the run used
        # to be unresumable -- `--reset`, the whole run of paid cells, was the
        # only remedy the refusal could name for a record this machine had
        # written itself. The hardware id did not move, so the resume still
        # recognises its own record and the dead pid decides as it always did.
        #
        # BOTH ids are stated, never read off the machine running the suite
        # (review round 1, finding 1): where `uuid.getnode()` falls back to its
        # random multicast value `machine_id()` is None and `document()` omits
        # the field, so a test that leaned on the real one asserted None ==
        # None and then failed three lines later as an opaque status mismatch.
        d, floor = self._repo(floor=("SEC", "ACC"))
        crashed = self._leave_crashed_batch(d, floor)
        self._stamp_crash_owner(crashed.run_dir, host="mac.office.example",
                                machine=self.MACHINE)
        self.assertEqual(self.MACHINE,
                         self._crash_record(crashed.run_dir).get("machine"),
                         "the record must carry the hardware id this test states")
        resumed = FakeRunner()
        err = io.StringIO()
        with contextlib.redirect_stderr(err), \
                mock.patch.object(batch_mod, "machine_id",
                                  return_value=self.MACHINE):
            status = self._return_persist(d, floor, resumed)
        self.assertEqual(status["status"], "complete", status)
        self.assertIn("recovered stale batch", err.getvalue())
        self.assertEqual(self._manifests(crashed.run_dir), [])

    def test_a_record_with_no_owner_stamp_fails_closed(self):
        # The record lives INSIDE the reviewed tree. An absent owner is either
        # a manifest from before the field existed or one the target wrote;
        # neither is evidence that a crash happened.
        d, floor = self._repo(floor=("SEC", "ACC"))
        crashed = self._leave_crashed_batch(d, floor)
        path = os.path.join(crashed.run_dir, self._manifests(crashed.run_dir)[0])
        doc = runio._load_json(path)
        doc.pop("pid"), doc.pop("host")
        runio._write_json(path, doc)
        before = self._untouched(d, crashed.run_dir)
        resumed = FakeRunner()
        status = self._return_persist(d, floor, resumed)
        self.assertEqual(status["status"], "error", status)
        self.assertIn("no owner stamp", status["message"])
        self.assertEqual(resumed.launched, [])
        self.assertEqual(self._untouched(d, crashed.run_dir), before)

    # ---- #1912 hazard 2: discard ONE record, not the run ----
    #
    # A `foreign`/`unstamped` verdict used to cost the whole run: `--reset` was
    # the only escape from it, and `--reset` throws away every paid cell.
    # `--discard-batch <N>` is the narrow remedy -- the operator states that
    # THAT record's owner is gone, the loop rolls exactly that batch back the
    # way it rolls back a dead owner's, and the run continues. It also bounds
    # hazard 1's residual: a mis-classification now costs one record.

    def _foreign(self, run_dir):
        """Make every leftover record read as another machine's: both ids."""
        self._stamp_crash_owner(run_dir, host="some-other-box",
                                machine=self.OTHER_MACHINE)

    def _accepted(self, run_dir):
        return runio._load_json(os.path.join(run_dir, batch_mod.DISCARDED_BATCHES))

    def _second_record(self, run_dir):
        """Split the crash record in two, one entry each.

        Two records may not claim the same entry (recovery refuses that), so a
        second record has to be carved out of the first. Both then validate
        against the same bound request, which is what makes this a test about
        the FLAG's scope rather than about validation.
        """
        first = os.path.join(run_dir, self._manifests(run_dir)[0])
        doc = runio._load_json(first)
        self.assertEqual(2, len(doc["entries"]), "the fixture lost an entry")
        second = dict(doc, batch=2, entries=[doc["entries"][1]])
        runio._write_json(batch_mod.manifest_path(run_dir, 2), second)
        runio._write_json(first, dict(doc, entries=[doc["entries"][0]]))
        return sorted(self._manifests(run_dir))

    def test_discard_batch_rolls_back_that_record_and_keeps_the_run(self):
        d, floor = self._repo(floor=("SEC", "ACC"))
        crashed = self._leave_crashed_batch(d, floor)
        run_dir = crashed.run_dir
        self._foreign(run_dir)
        owner = self._crash_record(run_dir)
        artifacts = [p for row in owner["entries"] for p in row["artifacts"]]
        self.assertTrue([p for p in artifacts if os.path.exists(p)],
                        "the crashed batch left no artifact to roll back")
        before = ledger_mod.Ledger(run_dir).lines()
        attempts = runio._load_json(runio._pano(d, review._ATTEMPTS_FILE))
        resumed = FakeRunner()
        err = io.StringIO()
        # the RESUME shape (as the dead-owner case above): coverage is already
        # on disk, so no second driver.run re-charges the review checkpoint's
        # per-cell attempt marker and the refund below is the only movement
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()), \
                mock.patch("scripts.host_probes.run_probes", side_effect=_write_guard_not_proven), \
                mock.patch("scripts.runners.base.runner_for", return_value=resumed):
            status = orchestrate.loop(self._args(d, "--allow-unenforced",
                                                 "--discard-batch", "1"))
        self.assertEqual(status["status"], "complete", status)
        self.assertIn("discarded batch 1", err.getvalue())
        # the record and its artifacts are gone, the entries were ledgered as
        # rolled back, and their attempts were given back -- the same rollback
        # a dead owner gets, no more and no less
        self.assertEqual([], self._manifests(run_dir))
        after = ledger_mod.Ledger(run_dir).lines()
        self.assertEqual(after[:len(before)], before)
        self.assertTrue(any(r.get("status") == ledger_mod.ROLLED_BACK for r in after))
        self.assertEqual(runio._load_json(runio._pano(d, review._ATTEMPTS_FILE)),
                         attempts)
        # ...and the run went on to finish, which is the whole point
        self.assertIn("review-app-SEC", resumed.launched)
        self.assertIn("review-app-ACC", resumed.launched)

    def test_the_discarded_records_artifacts_are_deleted(self):
        # At the RECOVERY itself rather than after the resume: the whole point
        # of the flag is that the run goes on, and going on re-dispatches those
        # entries and writes the same out_files again.
        d, floor = self._repo(floor=("SEC", "ACC"))
        crashed = self._leave_crashed_batch(d, floor)
        self._foreign(crashed.run_dir)
        doc = self._crash_record(crashed.run_dir)
        landed = [p for row in doc["entries"] for p in row["artifacts"]
                  if os.path.exists(p)]
        self.assertTrue(landed, "the crashed batch left no artifact to delete")
        req = orchestrate.requests.previous_request(d)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            loop_batch.recover_stale(d, req, "claude", "headless", discard=1)
        self.assertEqual([], [p for p in landed if os.path.exists(p)])
        self.assertEqual([], self._manifests(crashed.run_dir))
        self.assertIn("discarded batch 1", err.getvalue())
        self.assertEqual([1], [row["batch"]
                               for row in self._accepted(crashed.run_dir)])

    def test_the_operators_acceptance_is_written_down(self):
        d, floor = self._repo(floor=("SEC", "ACC"))
        crashed = self._leave_crashed_batch(d, floor)
        run_dir = crashed.run_dir
        self._foreign(run_dir)
        stamp = self._crash_record(run_dir)
        with contextlib.redirect_stderr(io.StringIO()):
            status = self._return_persist(d, floor, FakeRunner(),
                                          "--discard-batch", "1")
        self.assertEqual(status["status"], "complete", status)
        accepted = self._accepted(run_dir)
        self.assertEqual(1, len(accepted), accepted)
        self.assertEqual(1, accepted[0]["batch"])
        # the stamp AS FOUND, so the record that was thrown away can still be
        # read back: whose pid, on whose machine, and what the loop made of it
        self.assertEqual({"pid": stamp["pid"], "host": "some-other-box",
                          "machine": self.OTHER_MACHINE,
                          "state": batch_mod.OWNER_FOREIGN},
                         accepted[0]["owner"])
        self.assertRegex(accepted[0]["accepted_at"],
                         r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        # ...and the run manifest carries the count, beside the run's other
        # recorded acceptances
        manifest = driver.run_manifest.load_manifest(d)
        self.assertEqual([1], [row["batch"] for row in manifest["discarded_batches"]])

    def test_discard_batch_refuses_a_live_owner_and_touches_nothing(self):
        # A live verdict is demonstrably a loop running HERE: no flag may help,
        # and the refusal keeps naming only the pid.
        d, floor = self._repo(floor=("SEC", "ACC"))
        crashed = self._leave_crashed_batch(d, floor)
        self._stamp_crash_owner(crashed.run_dir, pid=os.getpid())
        before = self._untouched(d, crashed.run_dir)
        resumed = FakeRunner()
        status = self._return_persist(d, floor, resumed, "--discard-batch", "1")
        self.assertEqual(status["status"], "error", status)
        self.assertIn("still running here", status["message"])
        self.assertNotIn("--discard-batch", status["message"])
        self.assertEqual([], resumed.launched)
        self.assertEqual(self._untouched(d, crashed.run_dir), before)
        self.assertFalse(os.path.exists(
            os.path.join(crashed.run_dir, batch_mod.DISCARDED_BATCHES)))

    def test_discard_batch_on_a_record_that_is_not_there_errors_loudly(self):
        d, floor = self._repo(floor=("SEC", "ACC"))
        crashed = self._leave_crashed_batch(d, floor)
        self._foreign(crashed.run_dir)
        before = self._untouched(d, crashed.run_dir)
        resumed = FakeRunner()
        status = self._return_persist(d, floor, resumed, "--discard-batch", "7")
        self.assertEqual(status["status"], "error", status)
        # named, so the operator can see WHICH folder was looked in
        self.assertIn(batch_mod.manifest_path(crashed.run_dir, 7),
                      status["message"])
        # ...and prefixed ONCE: every refusal out of `recover_stale` is raised,
        # and `orchestrate.loop`'s one catch adds the lead (review round 1,
        # finding 2 -- both discard constants carried a second one).
        self.assertEqual(1, status["message"].count("driver loop: "),
                         status["message"])
        self.assertEqual([], resumed.launched)
        self.assertEqual(self._untouched(d, crashed.run_dir), before)

    def test_discard_batch_before_this_tree_has_a_run_of_its_own_errors(self):
        # The reachable first-invocation mistake: `--discard-batch` typed on a
        # tree with no run manifest yet. Recovery runs BEFORE the first
        # `driver.run` mints one, so the flag would otherwise pass straight
        # through the one branch that reads no records at all.
        d, floor = self._repo(floor=("SEC", "ACC"))
        self.assertIsNone(driver.run_manifest.load_manifest(d))
        resumed = FakeRunner()
        status = self._return_persist(d, floor, resumed, "--discard-batch", "1")
        self.assertEqual(status["status"], "error", status)
        self.assertIn("no run manifest of its own", status["message"])
        self.assertIn(driver.run_manifest.manifest_path(d), status["message"])
        self.assertEqual(1, status["message"].count("driver loop: "),
                         status["message"])
        self.assertEqual([], resumed.launched)

    def test_discard_batch_names_one_record_and_not_the_others(self):
        # The flag is one record's acceptance, never a blanket one: a SECOND
        # foreign record still refuses, and nothing is rolled back or written
        # down on the way to that refusal.
        d, floor = self._repo(floor=("SEC", "ACC"))
        crashed = self._leave_crashed_batch(d, floor)
        run_dir = crashed.run_dir
        records = self._second_record(run_dir)
        self.assertEqual(["batch-1.json", "batch-2.json"], records)
        self._foreign(run_dir)
        before = self._untouched(d, run_dir)
        resumed = FakeRunner()
        status = self._return_persist(d, floor, resumed, "--discard-batch", "1")
        self.assertEqual(status["status"], "error", status)
        self.assertIn("batch-2.json", status["message"])
        self.assertIn("not this machine", status["message"])
        self.assertEqual([], resumed.launched)
        self.assertEqual(self._untouched(d, run_dir), before)
        self.assertFalse(os.path.exists(
            os.path.join(run_dir, batch_mod.DISCARDED_BATCHES)))

    def test_a_dead_owner_needs_no_acceptance_and_records_none(self):
        # `--discard-batch` on a record that recovers on its own is not an
        # error, but nothing was accepted: the flag records an operator's
        # RULING, and there was none to record.
        d, floor = self._repo(floor=("SEC", "ACC"))
        crashed = self._leave_crashed_batch(d, floor)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            status = self._return_persist(d, floor, FakeRunner(),
                                          "--discard-batch", "1")
        self.assertEqual(status["status"], "complete", status)
        self.assertIn("recovered stale batch", err.getvalue())
        self.assertNotIn("discarded batch", err.getvalue())
        self.assertFalse(os.path.exists(
            os.path.join(crashed.run_dir, batch_mod.DISCARDED_BATCHES)))
        self.assertIsNone(
            driver.run_manifest.load_manifest(d).get("discarded_batches"))

    def test_the_two_recoverable_refusals_name_the_narrow_remedy_first(self):
        # Read off the constants: an operator meeting either refusal is offered
        # the one-record remedy BEFORE the one that throws the run away.
        for refusal in (loop_batch.BATCH_OWNER_ELSEWHERE,
                        loop_batch.BATCH_OWNER_UNSTAMPED):
            with self.subTest(refusal=refusal[:40]):
                self.assertLess(refusal.index("--discard-batch"),
                                refusal.index("--reset"), refusal)
                self.assertIn("no other", refusal)
        self.assertNotIn("--discard-batch", loop_batch.BATCH_OWNER_LIVE)
        self.assertNotIn("--reset", loop_batch.BATCH_OWNER_LIVE)

    def _obstruct(self, d, entry_id):
        """Make `entry_id`'s artifact un-removable: a non-empty directory
        where the reply file was. `os.remove` raises, which is what a
        rollback with PROBLEMS looks like."""
        req = orchestrate.requests.load_dispatch_request(d) or {}
        out = next(e for e in req["entries"] if e["id"] == entry_id)["out_file"]
        os.remove(out)
        os.makedirs(out)
        with open(os.path.join(out, "keep.txt"), "w") as fh:
            fh.write("keep")
        return out

    def test_a_rollback_that_could_not_finish_is_flagged_and_never_re_ledgered(self):
        # #1698: `roll_back` keeps the manifest when it has problems, so the
        # Ctrl-C path could leave a record carrying NO `recovering` flag after
        # the rollback rows were written and the markers refunded. The next
        # loop then recovered it from scratch: a second ROLLED_BACK/CANCELLED
        # row per entry and a second decrement of the same attempt counter.
        d, floor = self._repo(floor=("SEC", "ACC"))
        runner = FakeRunner()
        obstructed = []

        def obstruct_then_interrupt():
            obstructed.append(self._obstruct(d, "review-app-SEC"))
            raise KeyboardInterrupt

        self._gate_on_peer(runner, "review-app-ACC", "review-app-SEC",
                           then=obstruct_then_interrupt)
        status = self._return_persist(d, floor, runner)
        self.assertEqual(status["status"], "error", status)
        self.assertIn("rollback incomplete", status["message"])
        # the record survived the rollback it could not finish -- FLAGGED, so
        # that what was already ledgered is never ledgered again
        run_dir = runner.run_dir
        self.assertEqual(self._manifests(run_dir), ["batch-1.json"])
        self.assertIs(self._crash_record(run_dir).get("recovering"), True)
        rows = ledger_mod.Ledger(run_dir).lines()
        rolled = [r for r in rows if r.get("status") in (ledger_mod.ROLLED_BACK,
                                                         ledger_mod.CANCELLED)]
        self.assertEqual(len(rolled), 2, rolled)
        attempts = runio._load_json(runio._pano(d, review._ATTEMPTS_FILE))
        # the operator clears the obstruction; a LATER loop finishes the job
        shutil.rmtree(obstructed[0])
        self._stamp_crash_owner(run_dir, pid=dead_pid())
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            orchestrate.loop_batch.recover_stale(
                d, orchestrate.requests.previous_request(d), "claude", "headless")
        self.assertIn("finished the interrupted recovery", err.getvalue())
        self.assertEqual(self._manifests(run_dir), [])
        self.assertEqual(ledger_mod.Ledger(run_dir).lines(), rows)
        self.assertEqual(runio._load_json(runio._pano(d, review._ATTEMPTS_FILE)), attempts)

    def test_open_never_overwrites_an_existing_batch_record(self):
        with tempfile.TemporaryDirectory() as root:
            batch = batch_mod.Batch(root, 1, "review", [])
            batch.open()
            with open(batch.path, "rb") as fh:
                before = fh.read()
            with self.assertRaises(FileExistsError):
                batch_mod.Batch(root, 1, "scout", []).open()
            with open(batch.path, "rb") as fh:
                self.assertEqual(fh.read(), before)

    def test_a_leftover_batch_record_refuses_before_the_guards_are_armed(self):
        # #1698: `--setup --reset` left `batch-<n>.json` behind and skipped
        # recovery, so `Batch.open`'s O_EXCL raised FileExistsError out of
        # `loop` -- a traceback, AFTER `guards.arm(pending)`, with the write
        # guard still armed. It is a refusal now, and it lands before a single
        # grant is installed.
        d, floor = self._repo(floor=("SEC",))
        runner = FakeRunner()

        def seed_and_plant(review_root):
            seeded = self._seed_coverage(review_root, floor)
            run_dir = orchestrate.persist.run_dir(review_root)
            with open(batch_mod.manifest_path(run_dir, 1), "w") as fh:
                fh.write("{}")
            return seeded

        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()), \
                mock.patch("scripts.host_probes.run_probes", side_effect=_write_guard_not_proven), \
                mock.patch.object(orchestrate, "_after_first_run", side_effect=seed_and_plant), \
                mock.patch("scripts.runners.base.runner_for", return_value=runner):
            status = orchestrate.loop(self._args(d, "--allow-unenforced"))
        self.assertEqual(status["status"], "error", status)
        self.assertIn("batch-1.json", status["message"])
        self.assertIn("already exists", status["message"])
        self.assertNotIn("FileExistsError", status["message"])
        self.assertEqual(runner.launched, [])
        settings = os.path.join(runner.run_dir, base.SETTINGS_FILE)
        self.assertFalse(write_guard_hook.is_armed(
            settings, os.path.join(runner.run_dir, "write-allowlist.json"))[0])

    def test_a_record_that_lands_between_the_check_and_the_open_refuses_too(self):
        # The race the check above cannot close: O_EXCL is the backstop, and
        # what it raises must still reach the operator as the same sentence
        # rather than as a Python type name.
        d, floor = self._repo(floor=("SEC",))
        runner = FakeRunner()
        with mock.patch.object(batch_mod.Batch, "open",
                               side_effect=FileExistsError(17, "File exists")):
            status = self._return_persist(d, floor, runner)
        self.assertEqual(status["status"], "error", status)
        self.assertIn("batch-1.json", status["message"])
        self.assertIn("already exists", status["message"])
        self.assertNotIn("FileExistsError", status["message"])
        # armed for this batch, and taken back down on the way out
        settings = os.path.join(runner.run_dir, base.SETTINGS_FILE)
        self.assertFalse(write_guard_hook.is_armed(
            settings, os.path.join(runner.run_dir, "write-allowlist.json"))[0])

    def test_an_interrupted_recovery_never_refunds_the_attempt_twice(self):
        d, floor = self._repo(floor=("SEC", "ACC"))
        crashed = self._leave_crashed_batch(d, floor)
        req = orchestrate.requests.previous_request(d)
        with mock.patch.object(batch_mod.Batch, "close", return_value=["simulated interruption"]):
            with self.assertRaises(OSError):
                orchestrate.loop_batch.recover_stale(d, req, "claude", "headless")
        attempts = runio._load_json(runio._pano(d, review._ATTEMPTS_FILE))
        rows = ledger_mod.Ledger(crashed.run_dir).lines()
        # #1698: flagging the record took it over, so it now names THIS
        # process. The next loop is a later one, and that one died too.
        self._stamp_crash_owner(crashed.run_dir, pid=dead_pid())
        with contextlib.redirect_stderr(io.StringIO()):
            orchestrate.loop_batch.recover_stale(d, req, "claude", "headless")
        # it FINISHED the file removals and nothing else: the rows and the
        # refund the interrupted recovery had already written stand alone.
        self.assertEqual(self._manifests(crashed.run_dir), [])
        self.assertEqual(runio._load_json(runio._pano(d, review._ATTEMPTS_FILE)), attempts)
        self.assertEqual(ledger_mod.Ledger(crashed.run_dir).lines(), rows)

    def test_the_interrupt_ledgers_what_it_cut_and_keeps_what_was_spent(self):
        # Spend is a fact and is never rolled back: the completed entry's row
        # stands, with its real cost. The entry that never completed gets a
        # `cancelled` row so the run's history says what was cut.
        d, floor = self._repo(floor=("SEC", "ACC"))
        runner = FakeRunner()
        self._interrupt_mid_batch(d, floor, runner)
        rows = ledger_mod.Ledger(runner.run_dir).lines()
        self.assertEqual([("review-app-SEC", None),          # the real, paid launch
                          ("review-app-SEC", ledger_mod.ROLLED_BACK),
                          ("review-app-ACC", ledger_mod.CANCELLED)],
                         [(row["entry_id"], row.get("status")) for row in rows])
        paid, marker, cut = rows
        # the paid row is untouched: its shape and its spend are what they were
        self.assertEqual(0.01, paid["cost_usd"])
        self.assertNotIn("rolled_back", paid)
        # ...and the marker beside it says the artifact that spend bought is gone
        for row in (marker, cut):
            self.assertIs(True, row["rolled_back"])
            self.assertIsNone(row["cost_usd"])
            self.assertFalse(row["ok"])
        # ...and usage.json still counts the tokens that were really spent
        usage = runio._load_json(os.path.join(runner.run_dir, "usage.json"))
        self.assertEqual(110, usage["total"])
        self.assertEqual(0, usage["corrupt_rows"])

    def test_the_rollback_returns_the_cells_retry_budget(self):
        # `cell-attempts.json` is charged at DISPATCH time, to bound a cell
        # that never completes. An operator's Ctrl-C is not the host failing,
        # so charging it would silently drop the cell from the review after
        # three interrupts.
        d, floor = self._repo(floor=("SEC", "ACC"))
        runner = FakeRunner()
        self._interrupt_mid_batch(d, floor, runner)
        self.assertEqual({}, {k: v for k, v in review._cell_attempts(d).items() if v})

    def test_a_prior_phases_artifacts_survive_the_rollback(self):
        # Ruling: phases completed BEFORE the interrupted one are untouched.
        d, floor = self._repo(floor=("SEC", "ACC"))
        runner = FakeRunner()
        def snapshot():
            # resolved lazily: `_pano` is per-run, and the run tag does not
            # exist until the first driver.run has minted the manifest
            with open(runio._pano(d, "coverage-app.json"), "rb") as fh:
                return fh.read()

        before = {}

        def interrupt():
            # read from INSIDE the batch, so the comparison is against what
            # the completed `coverage` phase had on disk while the review
            # batch this Ctrl-C rolls back was still running
            before["bytes"] = snapshot()
            raise KeyboardInterrupt

        self._gate_on_peer(runner, "review-app-ACC", "review-app-SEC", then=interrupt)
        status = self._return_persist(d, floor, runner)
        self.assertEqual(status["status"], "error", status)
        self.assertEqual(before["bytes"], snapshot())

    def test_the_next_loop_re_dispatches_the_rolled_back_entries(self):
        d, floor = self._repo(floor=("SEC", "ACC"))
        self._interrupt_mid_batch(d, floor, FakeRunner())
        resumed = FakeRunner()
        status = self._return_persist(d, floor, resumed)
        self.assertEqual(status["status"], "complete", status)
        self.assertEqual({"review-app-SEC", "review-app-ACC"},
                         {eid for eid in resumed.launched if eid.startswith("review-")})

    def test_a_batch_that_completes_normally_leaves_no_manifest(self):
        d, floor = self._repo(floor=("SEC", "ACC"))
        runner = FakeRunner()
        status = self._return_persist(d, floor, runner)
        self.assertEqual(status["status"], "complete", status)
        self.assertEqual([], self._manifests(runner.run_dir))

    def test_an_interrupt_before_any_batch_rolls_nothing_back(self):
        # A Ctrl-C can land before the loop ever opens a batch -- while the
        # runner is preparing, or inside a deterministic phase between
        # checkpoints. There is nothing to take back then, and the message
        # must not claim "0 of 0 entries were completed and have been rolled
        # back", which reads like a rollback that found nothing.
        d, floor = self._repo()
        runner = FakeRunner()

        def prepare(run_dir, review_root):
            raise KeyboardInterrupt

        runner.prepare = prepare
        status = self._run(d, floor, runner)
        self.assertEqual("error", status["status"], status)
        self.assertEqual(loop_batch.INTERRUPTED_IDLE, status["message"])
        self.assertIn("no batch was in flight", status["message"])
        self.assertIn("`--reset`", status["message"])

    def _rejected(self, runner):
        folder = os.path.join(runner.run_dir, orchestrate.persist.REJECTED_DIR)
        return sorted(os.listdir(folder)) if os.path.isdir(folder) else []

    def test_a_rejected_reply_from_the_interrupted_batch_is_rolled_back_too(self):
        # D10 ruling 5 keeps what a failed launch printed, and ruling 2 reads
        # it back into the next attempt's prompt -- but a rolled-back phase
        # re-runs from scratch, so a record of an attempt that is being taken
        # back must not steer the one that replaces it. It is not knowable at
        # the manifest's open (retain_rejected names the file only once it has
        # written it), so the batch gains it mid-flight.
        d, floor = self._repo(floor=("SEC", "ACC"))
        runner = FakeRunner()
        runner.fail_once.add("review-app-SEC")     # a launch failure, with output
        inner, during = runner.run_entry, {}

        def gated(entry, env):
            if entry["id"] == "review-app-SEC":
                result = inner(entry, env)
                result.text = "half a reply"
                return result
            if entry["id"] == "review-app-ACC" and not during:
                deadline = time.monotonic() + 10
                while not self._rejected(runner) and time.monotonic() < deadline:
                    time.sleep(0.02)
                during["kept"] = self._rejected(runner)
                raise KeyboardInterrupt
            return inner(entry, env)

        runner.run_entry = gated
        status = self._return_persist(d, floor, runner)
        self.assertEqual("error", status["status"], status)
        self.assertEqual(1, len(during["kept"]), during)   # it really was kept...
        self.assertEqual([], self._rejected(runner))       # ...and taken back

    def _guards_armed(self, runner):
        settings = os.path.join(runner.run_dir, base.SETTINGS_FILE)
        return (write_guard_hook.is_armed(
                    settings, os.path.join(runner.run_dir, "write-allowlist.json"))[0],
                read_guard_hook.is_armed(
                    settings, os.path.join(runner.run_dir, "read-scope.json"))[0])

    def _interrupt_the_rollback(self, where):
        """Patch `where` so the SECOND Ctrl-C lands inside the rollback itself
        -- the operator holding the key down, or hitting it again because the
        first one did not seem to do anything."""
        if where == "ledger":
            real = ledger_mod.Ledger.record

            def record(self, *args, **kwargs):
                if kwargs.get("status"):        # only the interrupt's own rows
                    raise KeyboardInterrupt
                return real(self, *args, **kwargs)

            return mock.patch.object(ledger_mod.Ledger, "record", record)
        if where == "artifacts":
            return mock.patch.object(batch_mod.Batch, "roll_back",
                                     side_effect=KeyboardInterrupt)
        return mock.patch.object(orchestrate.persist, "rollback_markers",
                                 side_effect=KeyboardInterrupt)

    def test_a_second_interrupt_during_the_rollback_still_tears_down(self):
        # `loop` never raises (review round 1, item 3) -- and a KeyboardInterrupt
        # is a BaseException, so an `except Exception` around the rollback does
        # not hold it. Escaping here skips `_finish` entirely: the guards stay
        # armed over the whole session and the kimi run home keeps its
        # config.toml and credential links.
        for where in ("ledger", "artifacts", "markers"):
            with self.subTest(where=where):
                d, floor = self._repo(floor=("SEC", "ACC"))
                runner = FakeRunner()
                runner.torn_down = []
                runner.teardown = runner.torn_down.append
                with self._interrupt_the_rollback(where):
                    status, _seen = self._interrupt_mid_batch(d, floor, runner)
                self.assertEqual("error", status["status"], status)
                self.assertIn("interrupted:", status["message"])
                self.assertIn("rollback incomplete", status["message"])
                self.assertIn("KeyboardInterrupt", status["message"])
                self.assertEqual(["error"], runner.torn_down)
                self.assertEqual((False, False), self._guards_armed(runner))

    def test_an_interrupt_inside_the_teardown_is_reported_not_raised(self):
        # A THIRD Ctrl-C, landing inside the runner's own teardown: `loop`
        # never raises, so it must come back as a status the operator can read
        # ("teardown interrupted") with the guards already down -- not as a
        # traceback out of driver.main with no JSON status at all.
        d, floor = self._repo(floor=("SEC", "ACC"))
        runner = FakeRunner()

        def teardown(status):
            raise KeyboardInterrupt

        runner.teardown = teardown
        status, _seen = self._interrupt_mid_batch(d, floor, runner)
        self.assertEqual("error", status["status"], status)
        self.assertIn("interrupted:", status["message"])
        self.assertIn("teardown interrupted: KeyboardInterrupt", status["message"])
        self.assertEqual((False, False), self._guards_armed(runner))

    def test_a_straggler_write_is_denied_inside_the_rollback_window(self):
        # The rollback deletes the batch's artifacts. If the write guard is
        # still armed while it does, a child that outlived the termination can
        # re-create the file it was just handed back -- and the resume then
        # reads that cell as done and never re-dispatches it, which is the one
        # outcome the whole rollback exists to prevent. Disarming first closes
        # the window: the guard is fail-closed the moment its allowlist is
        # unlinked, so the straggler's own Write is denied.
        d, floor = self._repo(floor=("SEC", "ACC"))
        runner = FakeRunner()
        seen, real = {}, batch_mod.Batch.roll_back

        def rolling(batch_self):
            req = orchestrate.requests.load_dispatch_request(d) or {}
            entry = next(e for e in req["entries"] if e["id"] == "review-app-ACC")
            seen["verdict"] = write_guard_hook.adjudicate(
                {"tool_name": "Write", "tool_input": {"file_path": entry["out_file"]}},
                os.path.join(runner.run_dir, "write-allowlist.json"),
                env={base.ENV_ENTRY_ID: "review-app-ACC"})
            return real(batch_self)

        with mock.patch.object(batch_mod.Batch, "roll_back", rolling):
            status, _s = self._interrupt_mid_batch(d, floor, runner)
        self.assertEqual("error", status["status"], status)
        allowed, reason = seen["verdict"]
        self.assertFalse(allowed, "the guard was still armed during the rollback")
        self.assertTrue(reason, "a denial must say why")

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


class TestTheClaudeRunnerCannotBeReachedByAccident(LoopCase):
    """#1616 item 8, fix round 1 (F1): the guard has to bite on the accident it
    was written for, which is a `driver loop` test that forgets to patch
    `runner_for` -- claude is the default host, so that test builds the real
    family runner and dispatches through `iter_batch`.

    `iter_batch`'s worker converts any `Exception` from `run_entry` into a
    failed RunResult, by contract ("a runner crash is a failed entry, never a
    crashed loop"), so a refusal raised as one is swallowed and the run still
    reports `complete` -- the loop goes green on three launches that reached
    the real runner. The refusal is therefore a BaseException (pytest's own
    `Failed`), which that `except Exception` cannot hold, and it escapes
    `orchestrate.loop` too (it catches `KeyboardInterrupt` and `Exception`).
    """

    def test_a_loop_that_forgets_to_patch_runner_for_fails_the_test(self):
        d, floor = self._repo()
        with mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=lambda rr: self._seed_coverage(rr, floor)), \
             contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(pytest.fail.Exception) as cm:
                orchestrate.loop(self._args(d))
        self.assertIn("runner_for", str(cm.exception))      # names the way out


class TestExhaustedReviewCellsAreNamedOnComplete(LoopCase):
    """#1616 item 2: a review cell that spends `MAX_CELL_ATTEMPTS` without
    ever returning an acceptable findings file leaves the phase DONE --
    `review_done` counts exhaustion as done so the run advances rather than
    wedging -- and the run therefore ends `complete`, reading exactly like a
    clean one. The terminal status has to be able to tell them apart."""

    class NeverAcceptable(FakeRunner):
        """Self-writes a findings file the contract rejects, every time: the
        cell never completes, and no LAUNCH ever fails, so the per-entry cap
        never trips and only the per-cell retry budget bounds the run."""

        def run_entry(self, entry, env):
            if not entry["id"].startswith("review-"):
                return super().run_entry(entry, env)
            self.launched.append(entry["id"])
            runio._write_json(entry["out_file"], {"findings": [None]})
            return base.RunResult(entry_id=entry["id"], ok=True, text="written",
                                  usage={}, cost_usd=0.0, model=None,
                                  session_id=None, denials=[], error=None)

    def test_a_cell_that_spends_its_retry_budget_is_named_in_the_terminal_status(self):
        d, floor = self._repo()
        status = self._run_loop(d, floor, self.NeverAcceptable())
        self.assertEqual(status["status"], "complete", status)
        self.assertTrue(review._cell_exhausted(d, "app", "SEC"))
        self.assertEqual(status["cells_exhausted"], 1, status)
        self.assertIn("cells_exhausted: 1", status["message"])
        self.assertIn("app/SEC", status["message"])

    def test_a_clean_run_says_nothing_about_exhausted_cells(self):
        # The other half: the key is absent, not zero, so a clean run's
        # terminal status is byte-for-byte the one every host already parses.
        d, floor = self._repo()
        status = self._run_loop(d, floor, FakeRunner())
        self.assertEqual(status["status"], "complete", status)
        self.assertNotIn("cells_exhausted", status)
        self.assertEqual(status["message"], "all phases complete")


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

    # #1912: `--discard-batch <N>` -- one record's acceptance.

    def test_discard_batch_takes_a_positive_batch_number(self):
        args = driver.parse_cli(["loop", ".", "--discard-batch", "3"])
        self.assertEqual(3, args.discard_batch)
        self.assertIsNone(driver.parse_cli(["loop", "."]).discard_batch)

    def test_discard_batch_refuses_a_number_that_is_not_a_batch(self):
        for value in ("0", "-1", "two", "1.5", ""):
            with self.subTest(value=value):
                with self.assertRaises(SystemExit), \
                        contextlib.redirect_stderr(io.StringIO()):
                    driver.parse_cli(["loop", ".", "--discard-batch", value])

    def test_discard_batch_and_reset_together_are_refused(self):
        # Contradictory: one keeps the run and throws away a record, the other
        # throws the run away. Accepting both would make `--reset` win silently
        # (it skips recovery entirely), which is the opposite of what the
        # operator asked for with the narrower flag.
        err = io.StringIO()
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(err):
            driver.parse_cli(["loop", ".", "--discard-batch", "1", "--reset"])
        self.assertIn("--discard-batch", err.getvalue())
        self.assertIn("--reset", err.getvalue())

    def test_the_flag_is_the_loops_alone(self):
        # `driver run` keeps no batch record -- the loop writes them -- so the
        # flag would name a file that verb never reads.
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            driver.parse_cli(["run", ".", "--discard-batch", "1"])


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
        result = loop_batch._pending([done_entry, pending_entry])
        self.assertEqual([e["id"] for e in result], ["scout-pending"])


class TestAHostWideOutage(LoopCase):
    """#1623: a host-wide outage is not the entry's failure.

    The Kimi evidence run: 243 of 247 launches came back with ONE 403, the
    loop charged every one of them to whichever entry was holding it, and
    three iterations therefore spent every pending cell's attempt budget. The
    run then ended `complete` -- with an empty review axis and a report that
    looked like a review had happened.
    """

    FLOOR = ("SEC", "ACC", "ARC", "TST")

    class Outage(FakeRunner):
        """Every launch comes back with the host's own auth refusal, in the
        shape a family composes for a non-zero exit."""

        ERROR = "claude -p exited 1: API Error: 403 Forbidden"
        HOST_ERROR = "API Error: 403 Forbidden"

        def run_entry(self, entry, env):
            self.launched.append(entry["id"])
            return base.RunResult.failed(entry["id"], self.ERROR,
                                         host_error=self.HOST_ERROR)

    def test_a_batch_that_is_all_host_failures_pauses_instead_of_charging_the_cells(self):
        d, floor = self._repo(floor=self.FLOOR)
        runner = self.Outage()
        status = self._run_loop(d, floor, runner)
        self.assertEqual("paused", status["status"], status)
        # ONE iteration, one launch per cell: the run stops at the outage
        # instead of spending two more iterations proving the host is still out.
        self.assertEqual(sorted(["review-app-%s" % x for x in self.FLOOR]),
                         sorted(runner.launched))
        # ...and nothing downstream ran, so there is no report claiming a review
        self.assertFalse(os.path.exists(runio._pano(d, "report.json")))

    def test_the_pause_names_the_host_the_class_the_count_and_the_way_back(self):
        d, floor = self._repo(floor=self.FLOOR)
        status = self._run_loop(d, floor, self.Outage())
        message = status["message"]
        self.assertIn("claude", message)                      # the host
        self.assertIn(outage.HOST_FAILURE, message)             # the failure class
        self.assertIn("4", message)                           # how many launches it took down
        self.assertIn("403 Forbidden", message)               # what the host actually said
        self.assertIn("driver loop", message)                 # the exact resume command
        self.assertIn("--host claude", message)

    def test_a_paused_run_still_ledgers_every_failed_launch(self):
        # Nothing is rolled back -- nothing was written -- so the evidence of
        # the outage stays exactly where the operator will look for it.
        d, floor = self._repo(floor=self.FLOOR)
        runner = self.Outage()
        self._run_loop(d, floor, runner)
        rows = ledger_mod.Ledger(runner.run_dir).lines()
        self.assertEqual(4, len(rows))
        for row in rows:
            self.assertFalse(row["ok"], row)
            self.assertIn("403", row["error"])

    def test_the_paused_run_resumes_and_re_dispatches_every_cell(self):
        d, floor = self._repo(floor=self.FLOOR)
        self.assertEqual("paused", self._run_loop(d, floor, self.Outage())["status"])
        healthy = FakeRunner()
        status = self._run_loop(d, floor, healthy, seed=False)
        self.assertEqual("complete", status["status"], status)
        self.assertEqual(sorted(["review-app-%s" % x for x in self.FLOOR]),
                         sorted(x for x in healthy.launched if x.startswith("review-")))
        report = runio._load_json(runio._pano(d, "report.json"))
        self.assertNotEqual("INCONCLUSIVE", report["summary"]["gate"])

    def test_claudes_subscription_limit_line_pauses_the_run(self):
        # #1729, tool-confirmed on run 14: three episodes, 225 wasted
        # launches. The envelope carries NO `error` object -- only the CLI's
        # own `result` string -- so this goes through the REAL claude runner's
        # `parse_envelope` rather than a `host_error=` shortcut, the same way
        # `test_an_agents_own_opening_words_do_not_stop_the_run` does for N1.
        d, floor = self._repo(floor=self.FLOOR)
        line = "You've hit your session limit · resets 10:10am (America/Chicago)"

        class SessionLimit(FakeRunner):
            def run_entry(self, entry, env):
                self.launched.append(entry["id"])
                return claude_runner.Runner("claude").parse_envelope(
                    entry["id"], json.dumps({"type": "result", "subtype": "success",
                                             "is_error": True, "result": line,
                                             "session_id": "x", "total_cost_usd": 0,
                                             "usage": {}}), 1)

        runner = SessionLimit()
        status = self._run_loop(d, floor, runner)
        message = status["message"]
        self.assertEqual("paused", status["status"], status)
        self.assertIn(outage.HOST_FAILURE, message)
        self.assertIn("resets 10:10am", message)
        self.assertIn("driver loop", message)
        self.assertIn("--host claude", message)
        # no cell charged: a healthy re-run dispatches every cell again.
        # (coordinator review, Nit 6: `_load_json(...) or {}` would make this
        # vacuously true if the file were never written at all, so the file's
        # existence and shape are asserted first.)
        attempts_path = runio._pano(d, "cell-attempts.json")
        self.assertTrue(os.path.exists(attempts_path), "no cell-attempts.json was written")
        attempts = runio._load_json(attempts_path)
        self.assertIsInstance(attempts, dict)
        for domain in self.FLOOR:
            self.assertIn("app/%s" % domain, attempts, attempts)
        self.assertEqual([], [k for k, v in attempts.items() if v],
                         "a session-limit pause charged the cells: %s" % attempts)
        healthy = FakeRunner()
        again = self._run_loop(d, floor, healthy, seed=False)
        self.assertEqual("complete", again["status"], again)
        self.assertEqual(sorted(["review-app-%s" % x for x in self.FLOOR]),
                         sorted(x for x in healthy.launched if x.startswith("review-")))

    def test_a_failure_that_only_MENTIONS_a_quota_is_still_the_entrys_own(self):
        # #1623 C1. A batch of one, whose failure text names a file under
        # src/billing/: read off the composed message it stopped the whole run
        # on the first launch, and `MAX_ENTRY_FAILURES` -- the cap that is the
        # loop's only bound on an entry that cannot advance -- was silently off
        # for it. The host said nothing here, so the cap must still bite.
        d, floor = self._repo()

        class QuotaPath(FakeRunner):
            def run_entry(self, entry, env):
                if not entry["id"].startswith("verify-"):
                    return super().run_entry(entry, env)
                self.launched.append(entry["id"])
                return base.RunResult.failed(
                    entry["id"],
                    "kimi -p exited 1: no such file or directory: src/billing/quota.py")

        runner = QuotaPath()
        status = self._run_loop(d, floor, runner)
        self.assertEqual("error", status["status"], status)
        self.assertIn("3 consecutive launches", status["message"])
        self.assertEqual(orchestrate.MAX_ENTRY_FAILURES,
                         runner.launched.count("verify-app-SEC-primary"))

    def test_a_paused_run_gives_the_cells_their_attempt_back(self):
        # M2. The pause gave back the per-entry streak but not the review
        # checkpoint's per-cell attempt marker, which `review_execute` charges
        # at DISPATCH -- so three paused runs during one outage exhausted
        # MAX_CELL_ATTEMPTS and the fourth dropped the cells. That is #1623's
        # own symptom, at three operator re-runs instead of three iterations.
        d, floor = self._repo(floor=self.FLOOR)
        self.assertEqual("paused", self._run_loop(d, floor, self.Outage())["status"])
        for _ in range(2):
            self.assertEqual("paused",
                             self._run_loop(d, floor, self.Outage(), seed=False)["status"])
        attempts = runio._load_json(runio._pano(d, "cell-attempts.json")) or {}
        self.assertEqual([], [k for k, v in attempts.items() if v],
                         "a host-paused batch charged the cells: %s" % attempts)
        # ...and the fourth run still has every cell to dispatch
        healthy = FakeRunner()
        status = self._run_loop(d, floor, healthy, seed=False)
        self.assertEqual("complete", status["status"], status)
        self.assertEqual(sorted(["review-app-%s" % x for x in self.FLOOR]),
                         sorted(x for x in healthy.launched if x.startswith("review-")))

    def test_the_pause_claims_only_what_is_true_of_the_batch(self):
        # m1. The pause fires when every FAILURE is host-class, which a batch
        # with successful entries in it can be -- over persisted findings, real
        # ledger rows and a rewritten usage.json. "nothing was written" was
        # false there.
        d, floor = self._repo(floor=("SEC", "ACC"))

        class HalfOut(self.Outage):
            def run_entry(self, entry, env):
                if entry["id"].endswith("-SEC"):
                    return FakeRunner.run_entry(self, entry, env)
                return super().run_entry(entry, env)

        status = self._run_loop(d, floor, HalfOut())
        self.assertEqual("paused", status["status"], status)
        landed = runio._pano(d, "findings-app-SEC.json")
        self.assertTrue(os.path.exists(landed), "the successful cell was persisted")
        self.assertNotIn("nothing was written", status["message"])

    def test_the_resume_command_carries_every_flag_the_run_was_given(self):
        # m2. A copy-pasted resume that silently dropped the operator's bounds
        # would run unbounded, and the message calls itself the way back "with
        # the same flags".
        d, floor = self._repo(floor=self.FLOOR)
        status = self._run_loop(d, floor, self.Outage(), "--security", "redteam",
                                "--concurrency", "2", "--max-iterations", "7",
                                "--max-budget-usd", "5", "--entry-timeout", "60",
                                "--max-turns", "9", "--allow-unenforced")
        for token in ("--host claude", "--mode headless", "--security redteam",
                      "--fail-on high", "--no-tools", "--allow-unenforced",
                      "--concurrency 2", "--max-iterations 7", "--max-budget-usd 5",
                      "--entry-timeout 60", "--max-turns 9", d):
            self.assertIn(token, status["message"])
        # ...and never `--reset`, which would discard the run it is resuming
        self.assertNotIn("--reset", status["message"])

    def test_the_pause_and_the_cap_redact_what_the_host_said(self):
        # M3. The one message whose whole purpose is to surface an AUTH
        # failure is the one most likely to carry a credential.
        d, floor = self._repo()

        class Leaks(FakeRunner):
            SECRET = ("Incorrect API key provided: sk-ant-api03-7f3c9d2e1a8b4c6d5e0f; "
                      "db url postgres://svc:hunter2@db.internal/x")

            def run_entry(self, entry, env):
                if not entry["id"].startswith("verify-"):
                    return super().run_entry(entry, env)
                self.launched.append(entry["id"])
                return base.RunResult.failed(entry["id"], "claude -p exited 1: " + self.SECRET,
                                             host_error=self.host_error())

            def host_error(self):
                return "API Error: 401 " + self.SECRET

        paused = self._run_loop(d, floor, Leaks())
        self.assertEqual("paused", paused["status"], paused)

        class LeaksButEntryClass(Leaks):
            def host_error(self):
                return None                    # the entry's own failure: the cap path

        d2, floor2 = self._repo()
        capped = self._run_loop(d2, floor2, LeaksButEntryClass())
        self.assertEqual("error", capped["status"], capped)
        self.assertIn("3 consecutive launches", capped["message"])
        for status in (paused, capped):
            self.assertNotIn("sk-ant-api03-7f3c9d2e1a8b4c6d5e0f", status["message"])
            self.assertNotIn("hunter2", status["message"])
            self.assertIn("REDACTED", status["message"])

    def test_an_agents_own_opening_words_do_not_stop_the_run(self):
        # N1 at the loop, through the REAL claude envelope path: one verify
        # cell whose reply opens with a finding about authentication. The
        # provider said nothing, so the cap -- the only bound a verify entry
        # has -- must still bite.
        d, floor = self._repo()

        class ClaudeOpener(FakeRunner):
            OPENER = "Authentication error handling is missing in src/login.py"

            def run_entry(self, entry, env):
                if not entry["id"].startswith("verify-"):
                    return super().run_entry(entry, env)
                self.launched.append(entry["id"])
                return claude_runner.Runner("claude").parse_envelope(
                    entry["id"], json.dumps({"type": "result", "is_error": True,
                                             "result": self.OPENER, "usage": {},
                                             "session_id": "s"}), 0)

        runner = ClaudeOpener()
        status = self._run_loop(d, floor, runner)
        self.assertEqual("error", status["status"], status)
        self.assertIn("3 consecutive launches", status["message"])
        self.assertEqual(orchestrate.MAX_ENTRY_FAILURES,
                         runner.launched.count("verify-app-SEC-primary"))

    def test_a_local_permission_error_is_not_a_provider_outage(self):
        # N2, through the REAL kimi stderr path: a file this machine cannot
        # open is not the host refusing us. Told to wait for the provider and
        # re-run, the operator reproduces it for ever and the run can never
        # complete.
        d, floor = self._repo()

        class Eacces(FakeRunner):
            STDERR = ("Error: EACCES: permission denied, open "
                      "'/tmp/panopticon-kimi-abc/config.toml'")

            def run_entry(self, entry, env):
                if not entry["id"].startswith("verify-"):
                    return super().run_entry(entry, env)
                self.launched.append(entry["id"])
                return kimi_runner.Runner("kimi").parse_envelope(
                    entry["id"], "", 1, stderr=self.STDERR)

        runner = Eacces()
        status = self._run_loop(d, floor, runner)
        self.assertEqual("error", status["status"], status)
        self.assertIn("3 consecutive launches", status["message"])

    def test_a_mixed_batch_blames_the_entry_and_never_the_host(self):
        # The discriminator. Two verify cells in one batch: SEC gets the
        # host's 403 every time, ACC gets a failure of its own. Before #1623
        # both streaks ran up together and the cap tripped on SEC, the entry
        # that had done nothing wrong.
        #
        # #1721 changed the VERDICT this batch reaches, not the blame. ACC's
        # own failure no longer cancels the outage SEC's 403 opened -- that
        # cancellation is the defect -- so the batch ends inside a trailing run
        # and pauses on the first iteration, instead of spending three of them
        # proving the host is still out. SEC is still never charged, never
        # capped and never named; `test_an_entry_the_host_failed_never_reaches
        # _the_cap` in tests/runners/test_outage.py pins the charge directly.
        d, floor = self._repo(floor=("SEC", "ACC"))

        class MixedVerify(FakeRunner):
            def run_entry(self, entry, env):
                if not entry["id"].startswith("verify-"):
                    return super().run_entry(entry, env)
                self.launched.append(entry["id"])
                if "-SEC-" in entry["id"]:
                    return base.RunResult.failed(
                        entry["id"], "claude -p exited 1: API Error: 403 Forbidden",
                        host_error="API Error: 403 Forbidden")
                return base.RunResult.failed(entry["id"], "always")

        runner = MixedVerify()
        status = self._run_loop(d, floor, runner)
        self.assertEqual("paused", status["status"], status)
        self.assertIn(outage.HOST_FAILURE, status["message"])
        self.assertIn("403 Forbidden", status["message"])       # the host's own words
        self.assertNotIn("consecutive launches", status["message"])
        self.assertNotIn("verify-app-SEC-primary", status["message"])
        self.assertEqual(1, runner.launched.count("verify-app-SEC-primary"),
                         runner.launched)
        # ...and the cell the host took down kept its turn: a healthy re-run
        # dispatches it again rather than finding it capped
        healthy = FakeRunner()
        self.assertEqual("complete", self._run_loop(d, floor, healthy, seed=False)["status"])
        self.assertIn("verify-app-SEC-primary", healthy.launched)


class TestAMidBatchHostOutage(LoopCase):
    """#1721: an outage that begins PART-WAY through a batch.

    Tool-confirmed on the 2026-09-18 kimi run. `settle` runs only once
    `iter_batch` has drained the whole queue, so a quota 403 that began at
    entry 12 of 78 cost 66 more launches -- each charged at dispatch -- before
    the loop could ask whether the host was down. And the verdict was
    all-or-nothing: the one cell that had refused on its own turned the whole
    outage into "not an outage", so nothing paused, nothing was given back and
    every cell was charged.
    """

    # Ten cells, not eight: the launch bound is the POOL, not the checkpoint,
    # so widening the batch must not widen it. Two or three cells left
    # unlaunched out of ten says "constant"; eight cells with one left over
    # would read as "proportional".
    FLOOR = ("SEC", "COD", "ARC", "TST", "QAL", "AGT", "DAT", "OPS", "ACC", "LNG")
    HOST_ERROR = ("provider.auth_error: 403 You've reached your weekly (7-day) "
                  "usage limit")
    REFUSAL = "kimi -p exited 1: All files read and cross-checked"
    WIDTH = 2

    class Gated(FakeRunner):
        """Behaviour keyed on the cell's index in the batch's pending list --
        which is its LAUNCH order, the pool being FIFO -- not on a counter, so
        no thread interleaving can change which cell does what. And from index
        two on, a launch does not come back until the LOOP has ledgered every
        result before it: two workers answering instantly outrun a consumer
        that persists and ledgers each reply, and "what the short-circuit
        stopped" would be a race rather than a fact. The chain always makes
        progress (a launch waits only on results from launches before it) and
        every wait is deadlined.

        One worker turnover is NOT pinned and cannot be: the loop persists,
        ledgers and counts a result before it asks `stop`, so a worker freed by
        that result's own ledger line can start one more entry in between. That
        is a real property of the loop, not the fixture's, which is why the
        bound below carries it as an explicit `+ 1` rather than being flaky.
        """

        def __init__(self, floor, host_error, refusal=None):
            super().__init__()
            self.order = ["review-app-%s" % d for d in floor]
            self.failure, self.refusal = host_error, refusal

        def _index(self, entry):
            eid = entry["id"]
            return self.order.index(eid) if eid in self.order else None

        def _host_failure(self, eid):
            return base.RunResult.failed(eid, "kimi -p exited 1: " + self.failure,
                                         host_error=self.failure)

        def _await_ledger(self, lines):
            path = os.path.join(self.run_dir, base.LEDGER_FILE)
            for _ in range(2000):
                try:
                    with open(path) as fh:
                        if sum(1 for line in fh if line.strip()) >= lines:
                            return
                except OSError:
                    pass
                time.sleep(0.005)
            raise AssertionError("the loop never ledgered %d results" % lines)

    class Outage(Gated):
        """The kimi run's shape: the first two cells answer, the third refuses
        on ITS own account (#1719's masked 403 classifies entry-class), and
        every launch after that is the quota 403."""

        def run_entry(self, entry, env):
            i = self._index(entry)
            if i is None or i < 2:
                return super().run_entry(entry, env)
            eid = entry["id"]
            self.launched.append(eid)
            if i == 2:
                return base.RunResult.failed(eid, self.refusal)
            self._await_ledger(i)
            return self._host_failure(eid)

    class Recovers(Gated):
        """The same 403, and then the host comes back. Cells 2 and 3 fail
        host-class on their FIRST launch -- two in a row, which trips the stop
        at width two -- and the launch already in flight when it trips (cell 4,
        a later `seq`) answers cleanly, which closes the trailing run. So the
        batch settles to "not an outage" even though the stop had already
        cancelled everything still queued."""

        def run_entry(self, entry, env):
            i = self._index(entry)
            if i is None or i < 2:
                return super().run_entry(entry, env)
            eid = entry["id"]
            first = eid not in self.launched
            if first:
                self._await_ledger(i)
            if first and i < 4:
                self.launched.append(eid)
                return self._host_failure(eid)
            return super().run_entry(entry, env)

    def _outage(self):
        return self.Outage(self.FLOOR, self.HOST_ERROR, self.REFUSAL)

    def _recovers(self):
        return self.Recovers(self.FLOOR, self.HOST_ERROR)

    def _run(self, d, floor, runner, *extra):
        """`LoopCase._run_loop` with this run's stderr kept: the short-circuit
        announces itself there, and the redirect inside `_run_loop` throws it
        away."""
        err = io.StringIO()
        with contextlib.ExitStack() as es:
            es.enter_context(mock.patch.object(
                orchestrate, "_after_first_run",
                side_effect=lambda rr: self._seed_coverage(rr, floor)))
            es.enter_context(mock.patch("scripts.runners.base.runner_for", return_value=runner))
            es.enter_context(contextlib.redirect_stdout(io.StringIO()))
            es.enter_context(contextlib.redirect_stderr(err))
            status = orchestrate.loop(self._args(d, "--concurrency", str(self.WIDTH), *extra))
        return status, err.getvalue()

    def _reviews(self, runner):
        return [x for x in runner.launched if x.startswith("review-")]

    def _first_batch(self, runner):
        """The review cells the FIRST checkpoint launched: `launched` in order
        up to the first repeat, since no cell is launched twice in one batch
        and the next iteration re-dispatches the ones that failed."""
        out = []
        for eid in self._reviews(runner):
            if eid in out:
                break
            out.append(eid)
        return out

    def test_the_outage_stops_the_batch_instead_of_draining_it(self):
        d, floor = self._repo(floor=self.FLOOR)
        runner = self._outage()
        status, err = self._run(d, floor, runner)
        self.assertEqual("paused", status["status"], status)
        reviews = self._reviews(runner)
        self.assertLess(len(reviews), len(self.FLOOR), reviews)
        # 2 answered + 1 refused + the corroboration the stop waits for
        # (max(2, width)) + the pool that was already running (width) + the one
        # worker that can turn over while the loop is still persisting,
        # ledgering and counting the result that trips the stop, since the
        # decision point is after that work. A CONSTANT either way: the batch
        # is ten cells and the bound is still eight, so what an outage costs is
        # the pool, not the checkpoint.
        self.assertLessEqual(len(reviews), 3 + max(2, self.WIDTH) + self.WIDTH + 1, reviews)
        unlaunched = len(self.FLOOR) - len(reviews)
        self.assertGreaterEqual(unlaunched, 2, reviews)
        self.assertIn("%d of %d entries not launched" % (unlaunched, len(self.FLOOR)), err)
        self.assertIn("driver loop: stopped launching after %d host-class failure(s)"
                      % max(2, self.WIDTH), err)
        self.assertIn("%d of its entries were never launched" % unlaunched, status["message"])

    def test_only_the_cell_that_failed_on_its_own_account_is_charged(self):
        d, floor = self._repo(floor=self.FLOOR)
        runner = self._outage()
        status, _err = self._run(d, floor, runner)
        self.assertEqual("paused", status["status"], status)
        reviews = self._reviews(runner)
        attempts = runio._load_json(runio._pano(d, "cell-attempts.json")) or {}
        # the cell that refused on its OWN account keeps the charge it spent
        self.assertEqual(1, attempts.get("app/%s" % self.FLOOR[2]), attempts)
        # every cell the host took down, and every cell that never launched at
        # all, gets its attempt back -- neither was ever given a turn
        for domain in self.FLOOR[3:]:
            self.assertEqual(0, attempts.get("app/%s" % domain), (domain, attempts))
            self.assertFalse(os.path.exists(runio._pano(d, "findings-app-%s.json" % domain)),
                             domain)
        # ...and the two the host never touched are simply done
        for domain in self.FLOOR[:2]:
            self.assertTrue(os.path.exists(runio._pano(d, "findings-app-%s.json" % domain)),
                            domain)
        self.assertEqual(sorted(reviews), sorted(set(reviews)), "a cell was launched twice")

    def test_a_healthy_re_run_picks_up_exactly_the_cells_that_are_not_done(self):
        d, floor = self._repo(floor=self.FLOOR)
        status, _err = self._run(d, floor, self._outage())
        self.assertEqual("paused", status["status"], status)
        healthy = FakeRunner()
        again = self._run_loop(d, floor, healthy, "--concurrency", str(self.WIDTH), seed=False)
        self.assertEqual("complete", again["status"], again)
        self.assertEqual(sorted("review-app-%s" % x for x in self.FLOOR[2:]),
                         sorted(x for x in healthy.launched if x.startswith("review-")))

    def test_a_stop_that_does_not_end_in_a_pause_still_gives_the_markers_back(self):
        # The stop and the settle verdict are DIFFERENT predicates, and the
        # give-back used to hang off the pause. Two 403s trip the stop at width
        # two; the launch already in flight has a later seq and answers
        # cleanly, so the run closes and `settle` returns None -- and the cells
        # the stop had already CANCELLED kept the attempt `review_execute`
        # charged them at dispatch, for a launch that never happened. Three
        # such batches and those cells are dropped from the review.
        d, floor = self._repo(floor=self.FLOOR)
        runner = self._recovers()
        seen = {}
        real = orchestrate.persist.rollback_markers

        def spy(review_root, checkpoint, entries):
            cleared = real(review_root, checkpoint, entries)
            seen.setdefault("calls", []).append(sorted(cleared))
            # read the document back THROUGH the give-back, which is the only
            # moment "those cells are at zero" is observable
            seen["attempts"] = dict(runio._load_json(
                runio._pano(d, "cell-attempts.json")) or {})
            return cleared

        with mock.patch.object(orchestrate.persist, "rollback_markers", side_effect=spy):
            status, err = self._run(d, floor, runner)
        self.assertEqual("complete", status["status"], status)   # not an outage after all
        first = self._first_batch(runner)
        never = [x for x in self.FLOOR if "review-app-%s" % x not in first]
        self.assertTrue(never, first)
        # the give-back ran exactly once, off the stop rather than off the pause
        self.assertEqual(1, len(seen.get("calls") or []), seen)
        host_failed = [self.FLOOR[2], self.FLOOR[3]]
        self.assertEqual(sorted("app/%s" % x for x in never + host_failed),
                         seen["calls"][0])
        for domain in never + host_failed:
            self.assertEqual(0, seen["attempts"].get("app/%s" % domain),
                             (domain, seen["attempts"]))
        # ...and the next iteration re-dispatches them, so each is charged for
        # the one launch it really got rather than for two
        for domain in never:
            self.assertIn("review-app-%s" % domain, self._reviews(runner)[len(first):])
        attempts = runio._load_json(runio._pano(d, "cell-attempts.json")) or {}
        self.assertEqual([], [k for k, v in attempts.items() if v != 1], attempts)
        self.assertNotIn("paused", err)
        # the stderr line reports what the STOP saw, which a later success has
        # since reset -- and it does not call this an outage, because the
        # settle verdict is the only thing entitled to that word
        self.assertIn("driver loop: stopped launching after %d host-class failure(s); "
                      "%d of %d entries not launched"
                      % (max(2, self.WIDTH), len(never), len(self.FLOOR)), err)
        self.assertNotIn("outage", err)

    def test_a_403_a_later_launch_answers_after_is_not_an_outage(self):
        # The other half of the trailing-run rule: a 403 whose successor came
        # back clean says the host is up, so the batch is not paused -- and the
        # 403 still costs its cell no consecutive-failure streak, so the loop's
        # next iteration re-dispatches it and the run completes.
        d, floor = self._repo(floor=("SEC", "ACC"))

        class BackUp(FakeRunner):
            def run_entry(self, entry, env):
                if entry["id"] == "review-app-SEC" and "review-app-SEC" not in self.launched:
                    self.launched.append(entry["id"])
                    return base.RunResult.failed(entry["id"],
                                                 "kimi -p exited 1: 403 Forbidden",
                                                 host_error="403 Forbidden")
                return super().run_entry(entry, env)

        runner = BackUp()
        status = self._run_loop(d, floor, runner, "--concurrency", "1")
        self.assertEqual("complete", status["status"], status)
        self.assertEqual(2, runner.launched.count("review-app-SEC"))


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


class TestRefusedRepliesAreRetained(LoopCase):
    """D10 ruling 1, loop side: the reply the loop refuses is kept.

    Before this the refusal printed a reason to stderr and dropped the text on
    the floor -- so run-13's eight failed attempts left nothing to look at and
    nothing for the retry to quote.

    The refusal used here is a CONTRADICTING stamp, deliberately: a reply that
    merely OMITS `_panopticon` -- run-13's actual failure, 7 times out of 8 --
    is no longer refused at all (ruling 4 fills it from the entry). What is
    left to refuse is a reply making a different claim than the entry, and that
    one is never overwritten.
    """

    class RefusingRunner(FakeRunner):
        """A return-persist reviewer that stamps its findings for a cell it was
        not dispatched for, and leaks a token-shaped literal while it is at
        it."""

        SECRET = "ghp_" + "B" * 36

        def __init__(self, host="claude"):
            super().__init__(host)
            self.prompts, self.priors = [], []

        def run_entry(self, entry, env):
            if not entry["id"].startswith("review-"):
                return super().run_entry(entry, env)
            self.launched.append(entry["id"])
            self.prompts.append(entry["prompt"])
            self.priors.append(entry.get("prior_rejection"))
            body = {"findings": [{"title": "issue at " + self.SECRET, "severity": "HIGH",
                                  "domain": entry["domain"], "code": entry["domain"] + "-A1A",
                                  "category": "authz",
                                  "location": {"file": "src/app.py", "line_start": 1}}],
                    "_panopticon": {"run_id": entry.get("run_id"), "role": "domain_panel",
                                    "domain": entry["domain"], "group": "a-different-group"}}
            return base.RunResult(
                entry_id=entry["id"], ok=True, text=json.dumps(body),
                usage={"input_tokens": 5, "output_tokens": 1, "cache_read_input_tokens": 0,
                       "cache_creation_input_tokens": 0},
                cost_usd=0.001, model="claude-sonnet-5", session_id="s", denials=[], error=None)

    def _run_loop(self, d, floor, runner):
        args = self._args(d, "--allow-unenforced")
        with mock.patch("scripts.host_probes.run_probes", side_effect=_write_guard_not_proven), \
             mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=lambda rr: self._seed_coverage(rr, floor)), \
             mock.patch("scripts.runners.base.runner_for", return_value=runner), \
             contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            return orchestrate.loop(args)

    def test_every_refusal_writes_its_own_record_and_the_ledger_row_names_it(self):
        d, floor = self._repo()
        runner = self.RefusingRunner()
        # `complete`, not `error`: the REVIEW phase's own per-cell attempt
        # budget gives up on the cell before the loop's per-entry cap sees it
        # pending a fourth time (TestPerEntryFailureCap covers the cap itself,
        # on the verify round, where the phase has no such budget). Either way
        # the reply was refused three times, and this is about what survives.
        status = self._run_loop(d, floor, runner)
        self.assertEqual(status["status"], "complete", status)
        self.assertEqual(runner.launched, ["review-app-SEC"] * 3)
        rejected = os.path.join(runner.run_dir, "rejected")
        self.assertEqual(sorted(os.listdir(rejected)),
                         ["review-app-SEC-%d.json" % n
                          for n in range(1, orchestrate.MAX_ENTRY_FAILURES + 1)])
        rows = [r for r in ledger_mod.Ledger(runner.run_dir).lines()
                if r["entry_id"] == "review-app-SEC"]
        self.assertEqual([r["rejected_file"] for r in rows],
                         [os.path.join(rejected, "review-app-SEC-%d.json" % n)
                          for n in range(1, orchestrate.MAX_ENTRY_FAILURES + 1)])
        with open(os.path.join(rejected, "review-app-SEC-1.json"), encoding="utf-8") as fh:
            record = json.load(fh)
        self.assertIn("_panopticon.group is 'a-different-group'", record["reason"])
        self.assertIn("[REDACTED_TOKEN]", record["reply"])
        self.assertNotIn(self.RefusingRunner.SECRET, record["reply"])

    def test_the_next_launch_of_a_refused_entry_is_told_why(self):
        # D10 ruling 2, end to end: the retry goes out through the ordinary
        # `driver.run` -> `write_dispatch_request` path, so the only way the
        # agent hears about the refusal is the prompt the loop hands it.
        d, floor = self._repo()
        runner = self.RefusingRunner()
        self._run_loop(d, floor, runner)
        self.assertEqual(3, len(runner.prompts))
        self.assertNotIn("refused", runner.prompts[0])
        self.assertIsNone(runner.priors[0])
        self.assertIn("_panopticon.group is 'a-different-group'", runner.prompts[1])
        self.assertIn("attempt 1", runner.prompts[1])
        self.assertEqual(1, runner.priors[1]["attempt"])
        self.assertEqual(2, runner.priors[2]["attempt"])

    def test_a_clean_run_writes_no_records_at_all(self):
        d, floor = self._repo()
        runner = FakeRunner()
        status = self._run_loop(d, floor, runner)
        self.assertEqual(status["status"], "complete", status)
        self.assertFalse(os.path.exists(os.path.join(runner.run_dir, "rejected")))



class TestATimedOutEntryKeepsItsEvidence(LoopCase):
    """D10 ruling 5, loop side: a failed launch that printed something keeps
    it, and the ledger row names both the tokens and the file."""

    PARTIAL = '{"findings": [{"title": "half a finding, key ghp_' + "D" * 36 + '"'

    class TimesOutOnce(FakeRunner):
        def __init__(self, host="claude"):
            super().__init__(host)
            self.priors = []

        def run_entry(self, entry, env):
            if entry["id"] in self.fail_once:
                self.fail_once.discard(entry["id"])
                self.launched.append(entry["id"])
                return base.RunResult.failed(
                    entry["id"], "claude -p timed out after 1800s",
                    usage={"input_tokens": 7000, "output_tokens": 0,
                           "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0},
                    text=TestATimedOutEntryKeepsItsEvidence.PARTIAL)
            return super().run_entry(entry, env)

    def test_the_partial_output_is_retained_and_the_tokens_are_counted(self):
        d, floor = self._repo()
        runner = self.TimesOutOnce()
        runner.fail_once.add("review-app-SEC")
        args = self._args(d)
        with mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=lambda rr: self._seed_coverage(rr, floor)), \
             mock.patch("scripts.runners.base.runner_for", return_value=runner), \
             contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            status = orchestrate.loop(args)
        self.assertEqual(status["status"], "complete", status)
        kept = os.path.join(runner.run_dir, "rejected", "review-app-SEC-1.json")
        with open(kept, encoding="utf-8") as fh:
            record = json.load(fh)
        self.assertIn("timed out after", record["reason"])
        self.assertIn("[REDACTED_TOKEN]", record["reply"])
        self.assertTrue(record["reply"].startswith('{"findings"'), record["reply"])
        row = next(r for r in ledger_mod.Ledger(runner.run_dir).lines()
                   if r["entry_id"] == "review-app-SEC" and not r["ok"])
        self.assertEqual(kept, row["rejected_file"])
        self.assertEqual(7000, sum(row["usage"].values()))
        usage = runio._load_json(os.path.join(runner.run_dir, "usage.json"))
        self.assertGreaterEqual(usage["by_phase"]["review"], 7000)

    def test_a_self_writing_entry_is_not_told_its_reply_was_refused(self):
        # D10 F4: this cell SELF-WRITES (the write guard is proven here), so a
        # timeout is not a format refusal and there is no reply to "return
        # again". The partial output is still kept; the prompt must not gain a
        # word.
        d, floor = self._repo()
        runner = self.TimesOutOnce()
        runner.fail_once.add("review-app-SEC")
        prompts = []

        class Recording(self.TimesOutOnce):
            def run_entry(self, entry, env):
                prompts.append(entry["prompt"])
                self.priors.append(entry.get("prior_rejection"))
                return super().run_entry(entry, env)

        runner = Recording()
        runner.fail_once.add("review-app-SEC")
        args = self._args(d)
        with mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=lambda rr: self._seed_coverage(rr, floor)), \
             mock.patch("scripts.runners.base.runner_for", return_value=runner), \
             contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            status = orchestrate.loop(args)
        self.assertEqual(status["status"], "complete", status)
        review = [p for p in prompts if "SEC` domain reviewer" in p]
        self.assertEqual(2, len(review))                   # timed out, then ran
        self.assertEqual(review[0], review[1])             # byte-identical
        self.assertNotIn("refused", review[1])
        self.assertEqual([None, None], runner.priors[:2])
        # ...and the partial output was still kept (ruling 5 is untouched)
        self.assertTrue(os.path.exists(os.path.join(
            runner.run_dir, "rejected", "review-app-SEC-1.json")))

    def test_a_failure_that_printed_nothing_keeps_nothing(self):
        d, floor = self._repo()
        runner = FakeRunner()
        runner.drop_once.add("review-app-SEC")          # RunResult.failed, no text
        args = self._args(d)
        with mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=lambda rr: self._seed_coverage(rr, floor)), \
             mock.patch("scripts.runners.base.runner_for", return_value=runner), \
             contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            orchestrate.loop(args)
        self.assertFalse(os.path.exists(os.path.join(runner.run_dir, "rejected")))
        row = next(r for r in ledger_mod.Ledger(runner.run_dir).lines() if not r["ok"])
        self.assertIsNone(row["rejected_file"])


def _refuted_artifact(host="claude"):
    """host_probes.run_probes stand-in whose tool policy is REFUTED -- the
    `--allow-unenforced` posture, where the phases legitimately emit
    `enforced: False` and the loop must let the run through unchanged."""
    body = _all_proven_artifact(host)
    body["capabilities"][hosts.TOOL_POLICY_ENFORCED] = {
        "state": hosts.REFUTED, "by": "fixture",
        "detail": "fixture: tool policy deliberately refuted"}
    return body


class TestTheRequestsEnforcedFlagIsDerived(LoopCase):
    """#1720: `enforced` travels in `.panopticon/dispatch-request.json`, inside
    the reviewed tree, and every family read it as the launch's posture. The
    loop re-derives it from THIS run's own capability evidence and refuses the
    whole request when the two disagree -- before the batch opens, so nothing
    launches and nothing is charged. It is a request-integrity refusal, not a
    cell failure."""

    def _tampered(self, **fields):
        """Flip a field on every entry between the phase that wrote the
        request and the loop that reads it -- the on-disk hop the reviewed
        tree could tamper with.

        Patched at `load_bound_request` (#1727 moved the loop's read there) and
        deliberately AFTER its integrity check: these two controls are
        independent. The hash answers "is this the file we wrote"; this one
        answers "does what it says match this run's own evidence", and it has
        to keep holding for a tamper the hash cannot see."""
        real = orchestrate.requests.load_bound_request

        def fake(review_root, namespace=None, expected_sha256=None):
            req, refusal = real(review_root, namespace, expected_sha256)
            for entry in (req or {}).get("entries") or []:
                entry.update(fields)
            return req, refusal

        return mock.patch.object(orchestrate.requests, "load_bound_request", fake)

    def test_a_proven_run_refuses_a_request_that_claims_an_unenforced_launch(self):
        d, floor = self._repo()
        runner = FakeRunner()
        with self._tampered(enforced=False, agent=None):
            status = self._run_loop(d, floor, runner)
        self.assertEqual("error", status["status"], status)
        self.assertIn("review-app-SEC", status["message"])
        self.assertIn("claims unenforced launch", status["message"])
        self.assertIn("posture is enforced", status["message"])
        self.assertIn("--reset", status["message"])
        self.assertEqual([], runner.launched)          # nothing launched...
        run_dir = orchestrate.persist.run_dir(d, None)
        self.assertFalse(os.path.exists(os.path.join(run_dir, base.LEDGER_FILE)))
        # ...and no cell was charged a second attempt: the one on disk is the
        # one review_execute booked when it WROTE the request. Asserted as the
        # whole document -- `sorted(set(values)) or [1]` read as green for a
        # missing or empty file, which is every way this could go wrong.
        attempts = runio._load_json(runio._pano(d, "cell-attempts.json"))
        self.assertEqual({"app/SEC": 1}, attempts)

    def test_a_proven_run_refuses_a_request_that_claims_an_enforced_launch_on_a_refuted_host(self):
        d, floor = self._repo()
        runner = FakeRunner()
        with self._tampered(enforced=True):
            status = self._run_loop(d, floor, runner, "--allow-unenforced",
                                    probes=lambda host, target, **kw: _refuted_artifact(host))
        self.assertEqual("error", status["status"], status)
        self.assertIn("claims enforced launch", status["message"])
        self.assertIn("posture is unenforced", status["message"])
        self.assertEqual([], runner.launched)

    def test_an_allow_unenforced_run_launches_bare_exactly_as_before(self):
        d, floor = self._repo()
        runner = FakeRunner()
        status = self._run_loop(d, floor, runner, "--allow-unenforced",
                                probes=lambda host, target, **kw: _refuted_artifact(host))
        self.assertEqual("complete", status["status"], status)
        self.assertEqual(["review-app-SEC", "verify-app-SEC-primary"],
                         sorted(runner.launched))

    def test_an_untampered_proven_run_is_unaffected(self):
        d, floor = self._repo()
        runner = FakeRunner()
        status = self._run_loop(d, floor, runner)
        self.assertEqual("complete", status["status"], status)
        self.assertEqual(["review-app-SEC", "verify-app-SEC-primary"],
                         sorted(runner.launched))


class TestExpectedEnforced(unittest.TestCase):
    """`loop_batch.expected_enforced` on its own: the two postures that are
    NOT read off the capability evidence at all."""

    def _root(self, states):
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        os.makedirs(os.path.join(d, ".panopticon"))
        write_host_evidence(d, states)
        return d

    def test_the_setup_namespace_reads_the_same_posture_as_a_run(self):
        # #1737 flips the old "the setup namespace is never enforced"
        # short-circuit. `setup_scan` IS in dispatch.ROLE_FILES now, so a host
        # that has registered its shells enforces this dispatch like any other
        # -- and a machine that has not registered anything reads REFUTED here
        # and goes down the ack-gated unenforced path instead of skipping the
        # question entirely.
        d = self._root(_ALL_PROVEN)
        self.assertTrue(loop_batch.expected_enforced(d, "claude", None))
        self.assertTrue(loop_batch.expected_enforced(d, "claude", "setup"))
        self.assertEqual([], loop_batch.refuse_disagreeing(
            [{"id": "setup-scan", "agent": "panopticon-setup-scan", "enforced": True}],
            loop_batch.expected_enforced(d, "claude", "setup")))

    def test_an_unregistered_machine_is_unenforced_in_the_setup_namespace(self):
        d = self._root({hosts.TOOL_POLICY_ENFORCED: hosts.REFUTED})
        self.assertFalse(loop_batch.expected_enforced(d, "claude", "setup"))

    def test_the_setup_namespace_reads_setups_own_evidence_artifact(self):
        # #1507's class of accident, one file over: `runio.host_evidence`
        # resolves host-capabilities.json through the RUN manifest's tag, so on
        # a tree that already holds a review run it would answer with THAT
        # run's posture. `driver loop --setup` writes and reads the flat one.
        d = self._root(_ALL_PROVEN)                 # flat: setup's own
        runio._write_json(
            driver.run_manifest.manifest_path(d),
            {"schema_version": 1, "run_id": "r1", "host": "claude",
             "created": "2026-09-21T00:00:00Z", "review_root": os.path.abspath(d)})
        # ...and a DIFFERENT posture in the review run's own folder.
        write_host_evidence(d, {hosts.TOOL_POLICY_ENFORCED: hosts.REFUTED})
        self.assertFalse(loop_batch.expected_enforced(d, "claude", None))
        self.assertTrue(loop_batch.expected_enforced(d, "claude", "setup"))

    def test_the_scan_checkpoint_dispatches_the_setup_scan_shell(self):
        # #1727's routing table: `scan` used to accept NO name at all. It
        # dispatches exactly one shell now, so a setup entry naming a scout
        # shell -- a reviewer's charter in a round that only classifies -- is
        # refused, and the entry's own shell is accepted.
        #
        # `out_file` is what makes these ENTRIES: since #1886 the acceptance
        # role is read off the controller-bound output path, so a fixture
        # without one describes nothing the phases build and fails closed on
        # the missing family rather than on the shell under test.
        out_file = "/repo/.panopticon/setup-proposal.json"
        self.assertEqual(("setup_scan",), loop_batch.checkpoint_roles("scan"))
        self.assertEqual([], loop_batch.refuse_misrouted(
            [{"id": "setup-scan", "out_file": out_file,
              "agent": "panopticon-setup-scan", "enforced": True}],
            "scan"))
        self.assertEqual(["setup-scan"], loop_batch.refuse_misrouted(
            [{"id": "setup-scan", "out_file": out_file,
              "agent": "panopticon-scout", "enforced": True}],
            "scan"))
        self.assertIn("panopticon-setup-scan",
                      loop_batch.misroute_refusal(["setup-scan"], "scan"))

    def test_the_unenforced_fallback_host_is_never_enforced(self):
        d = self._root(_ALL_PROVEN)
        self.assertFalse(loop_batch.expected_enforced(d, "generic", None))

    def test_each_posture_state_maps_to_one_answer(self):
        # PROVEN is the only state that enforces. UNKNOWN gates exactly as
        # REFUTED (spec 5.1) -- "we did not measure" grants nothing.
        for state, expected in ((hosts.PROVEN, True), (hosts.REFUTED, False),
                                (hosts.UNKNOWN, False)):
            d = self._root({hosts.TOOL_POLICY_ENFORCED: state})
            self.assertIs(expected, loop_batch.expected_enforced(d, "claude", None), state)

    def test_refuse_disagreeing_names_only_the_entries_that_disagree(self):
        pending = [{"id": "a", "enforced": True}, {"id": "b", "enforced": False},
                   {"id": "c"}, {"id": "d", "enforced": 1}]
        self.assertEqual(["b", "c"], loop_batch.refuse_disagreeing(pending, True))
        self.assertEqual(["a", "d"], loop_batch.refuse_disagreeing(pending, False))


class TestEnforcedIsDerivedInOnePlace(unittest.TestCase):
    """#1720 drift guard. The loop re-derives `enforced` to CHECK the dispatch
    request; the phases derive it to WRITE that request. A second copy of the
    expression is exactly the drift that would make a run refuse itself -- or
    quietly stop refusing -- so every site calls `loop_batch.expected_enforced`
    and none of them spells `hosts.posture(...)[...] == hosts.PROVEN` again.

    AST, not text: the expression is written across two source lines at some
    of these sites, and a grep for it returns a false zero (the `git grep \\b`
    trap, one shape over)."""

    PHASES = os.path.join(os.path.dirname(orchestrate.__file__), "phases")
    # The builders that STAMP `enforced` onto dispatch entries, plus the
    # driver plan that declares it for the same cells. #1737 added `setup.py`:
    # its one entry used to hardcode False, which is the same second copy of
    # the expression by another name.
    SITES = ("coverage.py", "review.py", "verify.py", "verify_tools.py",
             "requests.py", "setup.py")

    def _tree(self, name):
        path = os.path.join(self.PHASES, name)
        with open(path, encoding="utf-8") as fh:
            return path, ast.parse(fh.read(), path)

    def test_every_site_calls_the_loops_derivation(self):
        for name in self.SITES:
            path, tree = self._tree(name)
            calls = {ast.unparse(node.func) for node in ast.walk(tree)
                     if isinstance(node, ast.Call)}
            self.assertIn("loop_batch.expected_enforced", calls, path)

    def test_no_phase_module_keeps_its_own_copy_of_the_expression(self):
        offenders = []
        for name in sorted(os.listdir(self.PHASES)):
            if not name.endswith(".py"):
                continue
            path, tree = self._tree(name)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Compare):
                    continue
                if not isinstance(node.left, ast.Subscript):
                    continue
                inner = node.left.value
                # THIS capability only: the other `hosts.posture(...)[cap]`
                # comparisons in phases/ (artifact_write_guard in
                # requests.delivery, usage_ledger in synthesize) are different
                # decisions with no second owner, and #1720 did not touch them.
                if (isinstance(inner, ast.Call)
                        and ast.unparse(inner.func) == "hosts.posture"
                        and ast.unparse(node.left.slice) == "hosts.TOOL_POLICY_ENFORCED"):
                    offenders.append("%s:%d: %s"
                                     % (path, node.lineno, ast.unparse(node)))
        self.assertEqual([], offenders,
                         "a phase re-derives the enforcement posture instead of "
                         "calling loop_batch.expected_enforced; two copies is the "
                         "drift #1720 closed:\n" + "\n".join(offenders))


class TestTheRequestHashTravelsOnTheStatus(LoopCase):
    """#1727: the phase that WRITES the dispatch request is the only code that
    has seen its bytes before the reviewed tree could touch them. The hash it
    computed travels to the loop in process, on the checkpoint status."""

    def test_the_checkpoint_status_carries_the_hash_of_the_request_it_wrote(self):
        d, _floor = self._repo()
        with contextlib.redirect_stderr(io.StringIO()):
            status = driver.run(self._args(d))
        self.assertEqual(status["status"], "checkpoint", status)
        self.assertEqual(status["checkpoint"], "scout")
        with open(status["dispatch_request"], "rb") as fh:
            self.assertEqual(hashlib.sha256(fh.read()).hexdigest(),
                             status["request_sha256"])
        self.assertEqual(driver.run_manifest.load_manifest(d)["dispatch_request"],
                         {"checkpoint": "scout", "sha256": status["request_sha256"],
                          "at": driver.run_manifest.load_manifest(d)
                          ["dispatch_request"]["at"]})

    def test_every_checkpoint_phase_result_carries_one(self):
        # The anti-drift pin for all six writers (coverage, review, verify x2,
        # verify_tools, setup) and for the seventh somebody adds: a checkpoint
        # that names a dispatch_request and no request_sha256 would reach the
        # loop with nothing to compare, and `load_bound_request` would fall
        # back to the manifest alone -- silently weaker, and nothing would say so.
        phases_dir = os.path.join(os.path.dirname(orchestrate.__file__), "phases")
        missing = []
        for name in sorted(os.listdir(phases_dir)):
            if not name.endswith(".py"):
                continue
            path = os.path.join(phases_dir, name)
            with open(path, encoding="utf-8") as fh:
                tree = ast.parse(fh.read(), path)
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "PhaseResult"):
                    continue
                kw = {k.arg: k.value for k in node.keywords}
                kind = kw.get("kind")
                if not (isinstance(kind, ast.Constant) and kind.value == "checkpoint"):
                    continue
                if "request_sha256" not in kw:
                    missing.append("%s:%d" % (name, node.lineno))
        self.assertEqual(missing, [],
                         "checkpoint PhaseResult with no request_sha256:\n"
                         + "\n".join(missing))


def _append_a_byte(path):
    """The minimal on-disk tamper: the document still parses and still says
    everything it said, so only the HASH can tell it apart from what the
    driver wrote."""
    with open(path, "ab") as fh:
        fh.write(b" ")


class TestTheLoopRefusesARequestItCannotProveItWrote(LoopCase):
    """#1727: `.panopticon/dispatch-request.json` is written into the reviewed
    tree, and between the phase that writes it and the loop that reads it back
    the target owns that file. The loop checks the bytes against the hash the
    phase handed it in memory and the hash the run manifest recorded, and
    refuses before it arms, launches or spends anything."""

    def _tamper_after_every_run(self, mutate=_append_a_byte):
        real = orchestrate._run

        def fake(args, namespace, resolved=None):
            status = real(args, namespace, resolved)
            path = orchestrate.requests.request_path(args.target, namespace)
            if os.path.isfile(path):
                mutate(path)
            return status

        return mock.patch.object(orchestrate, "_run", fake)

    def _loop_capturing(self, d, floor, runner, *extra, seed=True):
        args = self._args(d, *extra)
        err = io.StringIO()
        with mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=lambda rr: seed and self._seed_coverage(rr, floor)), \
             mock.patch("scripts.runners.base.runner_for", return_value=runner), \
             contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(err):
            return orchestrate.loop(args), err.getvalue()

    def test_a_request_altered_after_the_phase_wrote_it_ends_the_run(self):
        d, floor = self._repo()
        runner = FakeRunner()
        armed = []
        with self._tamper_after_every_run(), \
             mock.patch.object(orchestrate.Guards, "arm",
                               side_effect=lambda *a: armed.append(a[-1])):
            status, _err = self._loop_capturing(d, floor, runner)
        self.assertEqual("error", status["status"], status)
        self.assertIn("does not match the request this run wrote", status["message"])
        self.assertIn("re-run `driver run`/`driver loop`", status["message"])
        self.assertEqual([], runner.launched)      # nothing launched...
        self.assertEqual([], armed)                # ...and nothing was ever armed
        run_dir = orchestrate.persist.run_dir(d, None)
        self.assertFalse(os.path.exists(os.path.join(run_dir, base.LEDGER_FILE)))

    def test_a_forged_record_is_caught_by_the_hash_the_phase_returned(self):
        # The manifest is inside the reviewed tree as well -- better defended
        # (no dispatched agent may write it, and `_foreign_manifest` discards
        # a planted one), not out of reach. So assume it WAS reached: the loop
        # still holds the hash the PHASE computed, in memory, and that is the
        # value no on-disk edit can reconcile.
        d, floor = self._repo()
        runner = FakeRunner()

        def tamper(path):
            _append_a_byte(path)
            with open(path, "rb") as fh:
                forged = hashlib.sha256(fh.read()).hexdigest()
            manifest = driver.run_manifest.load_manifest(d)
            manifest["dispatch_request"]["sha256"] = forged
            driver.run_manifest._rewrite(d, manifest)

        with self._tamper_after_every_run(tamper):
            status, _err = self._loop_capturing(d, floor, runner)
        self.assertEqual("error", status["status"], status)
        self.assertIn("recorded dispatch request hash was altered", status["message"])
        self.assertEqual([], runner.launched)

    def test_a_resume_after_a_tampered_file_regenerates_it_and_completes(self):
        # Nothing to repair by hand: the request is ROLLING, so the next
        # invocation's own phase overwrites both the file and the record.
        d, floor = self._repo()
        with contextlib.redirect_stderr(io.StringIO()):
            first = driver.run(self._args(d))
        self.assertEqual("checkpoint", first["status"], first)
        _append_a_byte(first["dispatch_request"])
        status, err = self._loop_capturing(d, floor, FakeRunner())
        self.assertEqual("complete", status["status"], status)
        # ...and the previous, tampered request was refused as a source of
        # disarm targets rather than acted on (R-P6-6 reads it before the
        # regeneration, by design).
        self.assertIn("ignoring the previous dispatch request", err)
        self.assertIn("does not match the request this run wrote", err)

    def test_a_clean_previous_request_is_still_read_for_the_disarm(self):
        # The negative control for the line above: an untouched re-entry must
        # print nothing and must still hand `loop_batch.disarm_previous` its entries.
        d, floor = self._repo()
        with contextlib.redirect_stderr(io.StringIO()):
            driver.run(self._args(d))
        status, err = self._loop_capturing(d, floor, FakeRunner())
        self.assertEqual("complete", status["status"], status)
        self.assertNotIn("ignoring the previous dispatch request", err)


class TestTheEntrysShellIsBoundToItsCheckpoint(LoopCase):
    """#1727 second half. `agent` is a registered-shell NAME, and #1720 made
    sure it is one of the four -- but any of the four passed for any
    checkpoint, so a `verify` entry could name `panopticon-domain-panel` and
    get a reviewer's WRITE-granting charter in a round that only adjudicates.
    The loop owns the routing table and refuses a misrouted entry before it
    arms anything."""

    def _misrouted(self, agent):
        real = orchestrate.requests.load_bound_request

        def fake(review_root, namespace=None, expected_sha256=None):
            req, refusal = real(review_root, namespace, expected_sha256)
            for entry in (req or {}).get("entries") or []:
                entry["agent"] = agent
            return req, refusal

        return mock.patch.object(orchestrate.requests, "load_bound_request", fake)

    def test_checkpoint_roles_has_a_row_for_every_checkpoint_kind(self):
        self.assertEqual(sorted(loop_batch.CHECKPOINT_ROLES),
                         sorted(runio.CHECKPOINT_KINDS))

    def test_every_role_named_is_a_dispatch_role(self):
        import scripts.dispatch as dispatch
        for kind, roles in loop_batch.CHECKPOINT_ROLES.items():
            for role in roles:
                self.assertIn(role, dispatch.ROLE_FILES, (kind, role))

    def test_no_role_can_be_added_to_one_side_of_the_routing_tables_only(self):
        # #1886's `OUTPUT_ROLES` and `dispatch.ROLE_FILES` are two halves of
        # ONE statement: the second says which shells exist, the first says
        # which output family may carry each. #1737 registered `setup_scan`
        # in the second and not the first, and every enforced setup entry was
        # refused -- `role_of` resolved to a family with no row, so `expected`
        # came out None and no name could match it. The failure mode is
        # SILENT (an entry that is simply never accepted, on a path that only
        # runs once the shells are emitted), so the two sides are pinned
        # against each other rather than left to the next reader.
        import scripts.dispatch as dispatch
        import scripts.phases.persist as persist
        self.assertEqual(sorted(dispatch.ROLE_FILES),
                         sorted(set(loop_batch.OUTPUT_ROLES.values())))
        # One family per role would be wrong in the other direction too:
        # `verify` has two roles with different charters and one file family
        # each, so a value used twice means two families share a shell.
        self.assertEqual(len(loop_batch.OUTPUT_ROLES),
                         len(set(loop_batch.OUTPUT_ROLES.values())))
        # ...and every KEY is an out_file family `persist.role_of` can really
        # return -- read out of its AST rather than restated here, since a
        # duplicated list is the thing that drifts. A key it never produces is
        # a row nothing reaches; a family it produces with no row fails closed.
        with open(persist.__file__, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), "persist.py")
        fn = next(node for node in ast.walk(tree)
                  if isinstance(node, ast.FunctionDef) and node.name == "role_of")
        families = set()
        for node in ast.walk(fn):
            if not isinstance(node, ast.Return):
                continue
            # The returned expression only -- walking the whole Return would
            # also collect the `startswith` argument in its ternary's test.
            returned = ([node.value.body, node.value.orelse]
                        if isinstance(node.value, ast.IfExp) else [node.value])
            families |= {n.value for n in returned
                         if isinstance(n, ast.Constant) and isinstance(n.value, str)}
        self.assertEqual(sorted(loop_batch.OUTPUT_ROLES), sorted(families))

    def test_the_table_matches_the_shells_the_phases_actually_assign(self):
        # Read out of the phase modules rather than trusted: each builder
        # spells its shell as `dispatch.registered_agent_name("<role>.md")`,
        # and the table has to name the role that file maps to. A builder
        # retargeted without this row moving would dispatch a shell the loop
        # then refuses -- or, worse, the row would quietly widen.
        import scripts.dispatch as dispatch
        by_file = {f: role for role, f in dispatch.ROLE_FILES.items()}
        phase_checkpoint = {"coverage.py": "scout", "review.py": "review",
                            "verify.py": "verify", "verify_tools.py": "verify",
                            "setup.py": "scan"}
        phases_dir = os.path.join(os.path.dirname(orchestrate.__file__), "phases")
        seen = {kind: set() for kind in runio.CHECKPOINT_KINDS}
        for name, kind in phase_checkpoint.items():
            with open(os.path.join(phases_dir, name), encoding="utf-8") as fh:
                tree = ast.parse(fh.read(), name)
            for node in ast.walk(tree):
                if (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "registered_agent_name"
                        and node.args and isinstance(node.args[0], ast.Constant)):
                    seen[kind].add(by_file[node.args[0].value])
        for kind in runio.CHECKPOINT_KINDS:
            self.assertEqual(seen[kind], set(loop_batch.CHECKPOINT_ROLES[kind]), kind)

    def test_an_unhashable_checkpoint_is_a_refusal_not_a_caught_crash(self):
        # `checkpoint` is read off the same target-writable file as `agent`, so
        # it arrives as whatever JSON says -- and `CHECKPOINT_ROLES.get([])`
        # raises `TypeError: unhashable type`. `loop` catches everything, so
        # that became an `error` naming a Python type instead of the routing
        # refusal it is. Reachable only through a forged record plus a planted
        # file; a named refusal either way.
        for checkpoint in ([], {}, ["verify"], {"a": "verify"}, 7, None):
            with self.subTest(checkpoint=checkpoint):
                self.assertEqual((), loop_batch.checkpoint_roles(checkpoint))
                self.assertEqual(
                    ["e"], loop_batch.refuse_misrouted(
                        [{"id": "e", "enforced": True, "agent": "panopticon-advisor"}],
                        checkpoint))
                message = loop_batch.misroute_refusal(["e"], checkpoint)
                self.assertIn("does not dispatch", message)
                self.assertIn("no enforcement shell", message)
                self.assertNotIn("TypeError", message)

    def test_a_misrouted_shell_ends_the_run_before_anything_is_armed(self):
        d, floor = self._repo()
        runner = FakeRunner()
        armed = []
        with self._misrouted("panopticon-domain-advisor"), \
             mock.patch.object(orchestrate.Guards, "arm",
                               side_effect=lambda *a: armed.append(a[-1])), \
             contextlib.redirect_stderr(io.StringIO()):
            status = self._run_loop(d, floor, runner)
        self.assertEqual("error", status["status"], status)
        self.assertIn("review-app-SEC", status["message"])
        self.assertIn("does not dispatch", status["message"])
        self.assertIn("panopticon-domain-panel", status["message"])
        self.assertEqual([], runner.launched)
        self.assertEqual([], armed)

    def test_an_unenforced_entry_that_names_a_shell_is_misrouted_too(self):
        # The mirror of #1720's `enforced` check: an unenforced entry carries
        # `agent: None` by construction, so a name on one is a claim the run
        # never made.
        d, floor = self._repo()
        runner = FakeRunner("generic")
        with self._misrouted("panopticon-domain-panel"), \
             contextlib.redirect_stderr(io.StringIO()):
            status = self._run_loop(d, floor, runner, "--host", "generic",
                                    "--allow-unenforced")
        self.assertEqual("error", status["status"], status)
        self.assertIn("does not dispatch", status["message"])
        self.assertEqual([], runner.launched)

    def test_the_loop_hands_the_runner_the_checkpoints_roles(self):
        seen = []

        class Recording(FakeRunner):
            def run_entry(self, entry, env):
                seen.append((entry["id"], self.roles))
                return super().run_entry(entry, env)

        d, floor = self._repo()
        with contextlib.redirect_stderr(io.StringIO()):
            status = self._run_loop(d, floor, Recording())
        self.assertEqual("complete", status["status"], status)
        self.assertIn(("review-app-SEC", ("domain_panel",)), seen)
        self.assertIn(("verify-app-SEC-primary", ("advisor", "domain_advisor")), seen)

    def test_verify_shells_are_bound_to_each_entries_output_family(self):
        outputs = (("/run/verdicts/abc123.json", "panopticon-advisor"),
                   ("/run/verdicts/verdicts-app-SEC-primary.json", "panopticon-domain-advisor"))
        for path, expected in outputs:
            for shell in ("panopticon-advisor", "panopticon-domain-advisor"):
                with self.subTest(path=path, shell=shell):
                    entry = {"id": "verify-e", "out_file": path,
                             "enforced": True, "agent": shell}
                    self.assertEqual([] if shell == expected else ["verify-e"],
                                     loop_batch.refuse_misrouted([entry], "verify"))

    def test_unknown_output_role_fails_closed(self):
        entry = {"id": "e", "out_file": "/run/rejected/verdicts-app-SEC.json",
                 "enforced": True, "agent": "panopticon-domain-advisor"}
        self.assertEqual(["e"], loop_batch.refuse_misrouted([entry], "verify"))

    def test_a_role_with_no_registered_shell_is_a_refusal_not_a_key_error(self):
        # `_allowed_shells` skips a role `ROLE_FILES` does not hold; the
        # acceptance side has to agree, or the two disagree exactly where a
        # half-added role lands -- and a KeyError out of `refuse_misrouted` is
        # `loop`'s catch-all reporting a Python type instead of the routing
        # refusal it is (the same shape as the unhashable checkpoint above).
        # The drift guard forbids this pair in production; the code must still
        # fail closed if it ever holds.
        entry = {"id": "setup-scan", "out_file": "/repo/.panopticon/setup-proposal.json",
                 "enforced": True, "agent": "panopticon-setup-scan"}
        with mock.patch.dict(loop_batch.OUTPUT_ROLES, {"setup-scan": "unregistered"}), \
             mock.patch.dict(loop_batch.CHECKPOINT_ROLES, {"scan": ("unregistered",)}):
            self.assertEqual(["setup-scan"], loop_batch.refuse_misrouted([entry], "scan"))
            self.assertIn("no enforcement shell",
                          loop_batch.misroute_refusal(["setup-scan"], "scan", [entry]))

    def test_the_refusal_names_the_shell_the_entry_should_have_carried(self):
        # The operator gets the checkpoint's whole list either way, and on
        # `verify` that list holds both advisor shells -- so it does not say
        # WHICH one this entry's output family was owed. The refusal is the
        # only place that answer surfaces, and reading it off the same
        # `expected_shell` the refusal was made with is what keeps the message
        # from becoming a second opinion.
        entry = {"id": "verify-e", "out_file": "/run/verdicts/abc123.json",
                 "enforced": True, "agent": "panopticon-domain-advisor"}
        self.assertEqual(["verify-e"], loop_batch.refuse_misrouted([entry], "verify"))
        message = loop_batch.misroute_refusal(["verify-e"], "verify", [entry])
        self.assertIn("its output role expects panopticon-advisor;", message)
        self.assertIn("panopticon-domain-advisor", message)   # the checkpoint's list

    def test_the_refusal_says_when_the_output_family_is_owed_no_shell(self):
        # The fail-closed half: a family no rule knows (a retained record) is
        # owed nothing, and claiming it "expects" some shell would name a
        # remedy that is not one.
        entry = {"id": "e", "out_file": "/run/rejected/verdicts-app-SEC.json",
                 "enforced": True, "agent": "panopticon-domain-advisor"}
        message = loop_batch.misroute_refusal(["e"], "verify", [entry])
        self.assertIn("its output role expects no shell this checkpoint dispatches",
                      message)

    def test_the_refusal_claims_nothing_about_an_entry_it_was_not_given(self):
        # `pending` is optional, and the clause is DROPPED rather than guessed
        # when the caller passes none: an "expects ..." sentence derived from
        # no entry is a statement about a request nobody read.
        message = loop_batch.misroute_refusal(["e"], "verify")
        self.assertNotIn("its output role expects", message)
        self.assertIn("does not dispatch", message)

    def test_swapping_advisor_shells_stops_the_loop_before_verify_launches(self):
        root, floor = self._repo()
        runner = FakeRunner()
        real = orchestrate.requests.load_bound_request

        def swap(review_root, namespace=None, expected_sha256=None):
            request, refusal = real(review_root, namespace, expected_sha256)
            if (request or {}).get("checkpoint") == "verify":
                for entry in request["entries"]:
                    entry["agent"] = "panopticon-advisor"
            return request, refusal

        with mock.patch.object(orchestrate.requests, "load_bound_request", swap), \
                contextlib.redirect_stderr(io.StringIO()):
            status = self._run_loop(root, floor, runner)
        self.assertEqual("error", status["status"], status)
        self.assertIn("output role", status["message"])
        self.assertTrue(runner.launched)
        self.assertFalse(any(entry_id.startswith("verify-") for entry_id in runner.launched))


class TestNoDriverReaderTakesTheUnboundRead(unittest.TestCase):
    """#1727 drift guard. `requests.load_dispatch_request` proves NOTHING about
    who wrote the file it parses; `load_bound_request` is the read every driver
    reader takes. Three call sites moved across in this change (the loop's own,
    the re-entry read, `persist.find_entry`) and a fourth followed
    (`readiness._existing_run_row`), so the unbound name now has zero callers
    under `skill/scripts/` -- and the way this control comes undone is somebody
    reaching for the shorter name in a new reader, which no test would notice.

    The function itself stays: it is the documented UNBOUND accessor, used by
    tests and by anything inspecting a request document rather than trusting
    it. Kept honest by this pin rather than by its docstring.

    AST, not grep: a call written across two source lines returns a false zero
    from `git grep` (the `\\b` trap, one shape over).
    """

    SCRIPTS = os.path.dirname(orchestrate.__file__)

    def _modules(self):
        for folder, _dirs, files in os.walk(self.SCRIPTS):
            for name in sorted(files):
                if name.endswith(".py"):
                    yield os.path.join(folder, name)

    def test_nothing_under_skill_scripts_calls_the_unbound_read(self):
        offenders = []
        for path in self._modules():
            with open(path, encoding="utf-8") as fh:
                tree = ast.parse(fh.read(), path)
            for node in ast.walk(tree):
                if (isinstance(node, ast.Call)
                        and ast.unparse(node.func).endswith("load_dispatch_request")):
                    offenders.append("%s:%d" % (os.path.relpath(path, self.SCRIPTS),
                                                node.lineno))
        self.assertEqual(offenders, [],
                         "a driver reader took the UNBOUND dispatch-request read; use "
                         "requests.load_bound_request:\n" + "\n".join(offenders))

    def test_the_bound_reader_does_not_delegate_to_it_either(self):
        # It reads the file as BYTES and hashes them; routing through the
        # unbound reader would hash one read and parse another.
        source = os.path.join(self.SCRIPTS, "phases", "requests.py")
        with open(source, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), source)
        bound = next(n for n in ast.walk(tree)
                     if isinstance(n, ast.FunctionDef) and n.name == "load_bound_request")
        self.assertEqual([], [ast.unparse(n.func) for n in ast.walk(bound)
                              if isinstance(n, ast.Call)
                              and ast.unparse(n.func).endswith("load_dispatch_request")])


class TestAUniformInstantFailure(LoopCase):
    """#1732 part 2: the whole batch refused before any entry did any work.

    Run 14's tool-verify checkpoint launched 103 entries and every one exited
    non-zero in ~120 ms with `claude -p printed no JSON envelope (exit 1)`,
    because `--json-schema` had been handed the schema's PATH where the CLI
    wants its TEXT. Nothing in the loop could tell that from 103 entries each
    failing on its own account, so the driver launched all 103 three times --
    309 launches, ~35 minutes -- to reach the per-entry cap on a defect its
    first two results had already proved.
    """

    FLOOR = ("SEC", "COD", "ARC", "TST", "QAL", "AGT", "DAT", "OPS", "ACC", "LNG")
    MESSAGE = "claude -p printed no JSON envelope (exit 1)"
    WIDTH = 2

    class Refused(FakeRunner):
        """Every launch fails instantly with the SAME message.

        Gated exactly as `TestAMidBatchHostOutage.Gated` is, and for the same
        reason: from index two on, a launch does not come back until the LOOP
        has ledgered every result before it, so "what the short-circuit
        stopped" is a fact rather than a thread race. One worker turnover is
        still not pinnable (the loop persists, ledgers and counts a result
        before it asks `stop`), which is the explicit `+ 1` in the bound.
        """

        def __init__(self, floor, message, per_entry=False):
            super().__init__()
            self.order = ["review-app-%s" % d for d in floor]
            self.message, self.per_entry = message, per_entry

        def _await_ledger(self, lines):
            path = os.path.join(self.run_dir, base.LEDGER_FILE)
            for _ in range(2000):
                try:
                    with open(path) as fh:
                        if sum(1 for line in fh if line.strip()) >= lines:
                            return
                except OSError:
                    pass
                time.sleep(0.005)
            raise AssertionError("the loop never ledgered %d results" % lines)

        def _result(self, eid):
            return base.RunResult.failed(
                eid, self.message + (": " + eid if self.per_entry else ""))

        def run_entry(self, entry, env):
            eid = entry["id"]
            index = self.order.index(eid) if eid in self.order else None
            if index is not None and index >= 2:
                self._await_ledger(index)
            self.launched.append(eid)
            return self._result(eid)

    class HostRefused(Refused):
        """The same instant, identical batch -- but host-class. The existing
        outage path must still own it (regression pin)."""

        def _result(self, eid):
            return base.RunResult.failed(eid, self.message,
                                         host_error="provider.auth_error: 403 Forbidden")

    def _run(self, d, floor, runner, *extra):
        err = io.StringIO()
        with contextlib.ExitStack() as es:
            es.enter_context(mock.patch.object(
                orchestrate, "_after_first_run",
                side_effect=lambda rr: self._seed_coverage(rr, floor)))
            es.enter_context(mock.patch("scripts.runners.base.runner_for", return_value=runner))
            es.enter_context(contextlib.redirect_stdout(io.StringIO()))
            es.enter_context(contextlib.redirect_stderr(err))
            status = orchestrate.loop(self._args(d, "--concurrency", str(self.WIDTH), *extra))
        return status, err.getvalue()

    def _reviews(self, runner):
        return [x for x in runner.launched if x.startswith("review-")]

    def test_the_batch_stops_instead_of_burning_every_entrys_budget(self):
        d, floor = self._repo(floor=self.FLOOR)
        runner = self.Refused(self.FLOOR, self.MESSAGE)
        status, err = self._run(d, floor, runner)
        self.assertEqual("paused", status["status"], status)
        reviews = self._reviews(runner)
        self.assertLess(len(reviews), len(self.FLOOR), reviews)
        # the corroboration the stop waits for (max(2, width)) + the pool that
        # was already running (width) + the one worker that can turn over while
        # the loop is still persisting the result that trips the stop
        self.assertLessEqual(len(reviews), max(2, self.WIDTH) + self.WIDTH + 1, reviews)
        self.assertIn("the first %d launches of this batch all failed in under %d ms"
                      % (max(2, self.WIDTH), outage.UNIFORM_FAST_MS), status["message"])
        self.assertIn(self.MESSAGE, status["message"])
        self.assertIn("driver loop: stopped launching after %d identical instant failure(s)"
                      % max(2, self.WIDTH), err)
        self.assertNotIn("host-class failure(s)", err)

    def test_it_charges_nobody_so_a_healthy_re_run_dispatches_every_cell(self):
        d, floor = self._repo(floor=self.FLOOR)
        status, _err = self._run(d, floor, self.Refused(self.FLOOR, self.MESSAGE))
        self.assertEqual("paused", status["status"], status)
        attempts = runio._load_json(runio._pano(d, "cell-attempts.json")) or {}
        self.assertEqual([], [k for k, v in attempts.items() if v], attempts)
        healthy = FakeRunner()
        again = self._run_loop(d, floor, healthy, "--concurrency", str(self.WIDTH), seed=False)
        self.assertEqual("complete", again["status"], again)
        self.assertEqual(sorted("review-app-%s" % x for x in self.FLOOR),
                         sorted(x for x in healthy.launched if x.startswith("review-")))

    def test_the_message_is_composed_once_not_per_entry(self):
        # Run 14 printed its identical failure once per entry per checkpoint,
        # three checkpoints deep, which is how a defect two results had
        # already proved stayed unreadable.
        d, floor = self._repo(floor=self.FLOOR)
        status, err = self._run(d, floor, self.Refused(self.FLOOR, self.MESSAGE))
        self.assertEqual(1, (err + status["message"]).count(
            "the first %d launches of this batch" % max(2, self.WIDTH)))

    def test_different_messages_charge_exactly_as_before(self):
        # Ten cells each failing for their OWN reason is not one launch being
        # refused, and the rules that already bound it are untouched: every
        # cell is charged for every launch it really got, and the review
        # phase's own three-dispatch retry budget is what ends the run --
        # `complete`, with those cells named as exhausted. No pause, no
        # give-back, no uniform line.
        d, floor = self._repo(floor=self.FLOOR)
        runner = self.Refused(self.FLOOR, self.MESSAGE, per_entry=True)
        status, err = self._run(d, floor, runner)
        self.assertEqual("complete", status["status"], status)
        self.assertEqual(len(self.FLOOR), status["cells_exhausted"])
        self.assertNotIn("identical instant failure", err)
        self.assertNotIn("paused", err)
        attempts = runio._load_json(runio._pano(d, "cell-attempts.json")) or {}
        self.assertEqual(sorted("app/%s" % x for x in self.FLOOR), sorted(attempts))
        self.assertEqual([], [k for k, v in attempts.items() if v != 3], attempts)

    def test_an_instant_identical_batch_that_is_host_class_is_still_an_outage(self):
        d, floor = self._repo(floor=self.FLOOR)
        runner = self.HostRefused(self.FLOOR, self.MESSAGE)
        status, err = self._run(d, floor, runner)
        self.assertEqual("paused", status["status"], status)
        self.assertIn(outage.HOST_OUTAGE_CLAUSE, status["message"])
        self.assertNotIn("identical instant failure", err)
        self.assertIn("host-class failure(s)", err)


class TestABudgetCapMidBatch(LoopCase):
    """#1760 (AGT-4265600920): the cap is re-read after every entry lands, not
    once per checkpoint.

    `--max-budget-usd` was compared with the ledger exactly once per `while`
    iteration, at the top and ahead of `guards.arm` -- and a checkpoint is ONE
    batch, so a whole review round (every pending cell, all of it charged)
    launched before the cap was looked at a second time. The guide meanwhile
    promises it "stops launching once the ledger's cumulative reported cost
    crosses it". Ten cells at `FakeRunner`'s $0.01 apiece against a $0.03 cap
    is the shape: the third result reaches it, and what launches after that
    must be the pool, not the checkpoint.
    """

    FLOOR = ("SEC", "COD", "ARC", "TST", "QAL", "AGT", "DAT", "OPS", "ACC", "LNG")
    WIDTH = 2
    BUDGET = "0.03"          # three of FakeRunner's $0.01 entries, exactly
    # Written by hand, exactly as `json.dumps` with its defaults emits it: the
    # decoder ACCEPTS the bare `NaN` token, which is how an unreadable cost
    # reaches a budget comparison (#1648). `money.ledger_text` never writes one.
    POISON = ('{"cost_usd": NaN, "entry_id": "review-app-SEC", "error": null, '
              '"ok": true, "phase": "review", "usage": {}}')

    class Paid(TestAMidBatchHostOutage.Gated):
        """Every cell answers and is charged `FakeRunner`'s $0.01.

        Subclassed off `TestAMidBatchHostOutage.Gated` rather than gated a
        third time by hand: from index two on, a launch does not come back
        until the LOOP has ledgered every result before it, so "what the
        short-circuit stopped" is a fact rather than a thread race -- two
        workers answering instantly outrun a consumer that persists, ledgers
        and counts each reply. The one worker turnover the loop allows between
        a result's ledger line and the `stop` question after it is the explicit
        `+ 1` in the bound below.

        `poison` is an unreadable cost appended from INSIDE the batch, while it
        is in flight: the pre-loop seam is `SeededLedger`'s, already covered.
        """

        def __init__(self, floor, poison=None):
            super().__init__(floor, None)
            self.poison = poison

        def run_entry(self, entry, env):
            index = self._index(entry)
            if index is not None and index >= 2:
                self._await_ledger(index)
            result = super().run_entry(entry, env)
            if self.poison and entry["id"] == self.order[0]:
                with open(os.path.join(self.run_dir, base.LEDGER_FILE), "a",
                          encoding="utf-8") as fh:
                    fh.write(self.poison + "\n")
            return result

    def _run(self, d, floor, runner, *extra):
        """`LoopCase._run_loop` with this run's stderr kept and the cap set --
        the same seam `TestAMidBatchHostOutage._run` uses, because the stop
        announces itself there and `_run_loop`'s own redirect throws it away."""
        err = io.StringIO()
        with contextlib.ExitStack() as es:
            es.enter_context(mock.patch.object(
                orchestrate, "_after_first_run",
                side_effect=lambda rr: self._seed_coverage(rr, floor)))
            es.enter_context(mock.patch("scripts.runners.base.runner_for", return_value=runner))
            es.enter_context(contextlib.redirect_stdout(io.StringIO()))
            es.enter_context(contextlib.redirect_stderr(err))
            status = orchestrate.loop(self._args(
                d, "--concurrency", str(self.WIDTH),
                "--max-budget-usd", self.BUDGET, *extra))
        return status, err.getvalue()

    def _reviews(self, runner):
        return [x for x in runner.launched if x.startswith("review-")]

    def test_the_cap_stops_the_batch_instead_of_launching_the_checkpoint(self):
        d, floor = self._repo(floor=self.FLOOR)
        runner = self.Paid(self.FLOOR)
        status, err = self._run(d, floor, runner)
        reviews = self._reviews(runner)
        self.assertEqual(sorted(reviews), sorted(set(reviews)), "a cell was launched twice")
        self.assertLess(len(reviews), len(self.FLOOR), reviews)
        # the three $0.01 results that reach $0.03 + the pool that was already
        # running (width) + the one worker that can turn over while the loop is
        # still persisting, ledgering and counting the result that trips it
        self.assertLessEqual(len(reviews), 3 + self.WIDTH + 1, reviews)
        unlaunched = len(self.FLOOR) - len(reviews)
        self.assertGreaterEqual(unlaunched, 2, reviews)
        # the stop's own line says which of the three rules fired, and a cap is
        # not a failure: "0 host-class failure(s)" would send the operator to
        # wait out a host that is perfectly healthy
        self.assertIn("driver loop: stopped launching after the --max-budget-usd cap; "
                      "%d of %d entries not launched" % (unlaunched, len(self.FLOOR)), err)
        self.assertNotIn("host-class failure(s)", err)
        self.assertNotIn("identical instant failure", err)
        # ...and the run still ends on the gate that always ended it, one
        # iteration later, once the batch has drained
        self.assertEqual("error", status["status"], status)
        self.assertIn("--max-budget-usd %s reached" % self.BUDGET, status["message"])
        self.assertIn("dispatch-ledger.jsonl", status["message"])

    def test_a_cost_it_cannot_read_stops_launching_rather_than_carrying_on(self):
        # `iter_batch` reads a `stop` that RAISES as "carry on", so the
        # `LedgerCorrupt` the top-of-iteration gate turns into an `error`
        # status has to answer True here instead of escaping: a predicate that
        # raised would be swallowed and the rest of the checkpoint launched and
        # paid for -- #1648's fail-open again, one level down.
        d, floor = self._repo(floor=self.FLOOR)
        runner = self.Paid(self.FLOOR, poison=self.POISON)
        status, err = self._run(d, floor, runner)
        reviews = self._reviews(runner)
        self.assertLess(len(reviews), len(self.FLOOR), reviews)
        # No tight upper bound here, unlike the case above: the unreadable row
        # is itself a ledger LINE, and the fixture's gate counts lines, so it
        # is one looser for as long as that row is on disk.
        self.assertGreaterEqual(len(self.FLOOR) - len(reviews), 2, reviews)
        self.assertIn("stopped launching after the --max-budget-usd cap", err)
        self.assertEqual("error", status["status"], status)
        self.assertIn("ledger corrupt at line", status["message"])
        self.assertIn("refusing to spend past an unreadable cost", status["message"])


class TestTheOutputSchemaShapeProof(LoopCase):
    """#1732 part 1, where it belongs: inside the loop, under the guards.

    `probe_cli_flags` reads `<cli> --help` and answers whether the flag is
    ADVERTISED. Run 14 proved a name is not a contract: the CLI advertised
    `--json-schema`, the driver handed it the schema's PATH where it wants the
    TEXT, and 309 launches went to that gap. The other half is one real launch
    — and it happens HERE, after `Guards.arm(pending)`, so it is confined by
    this batch's own read scope and write allowlist and the settings file its
    argv names has been written. At posture time it would have been an
    unconfined turn naming a file that did not exist yet.
    """

    FLOOR = ("SEC", "COD")
    ADVERTISED = {hosts.OUTPUT_SCHEMA: {"flag": "--json-schema", "advertised": True,
                                        "detail": "`claude --help` advertises it"}}
    POSTURE = dict(_ALL_PROVEN, **{hosts.ARTIFACT_WRITE_GUARD: hosts.UNKNOWN})

    def _repo(self, floor=FLOOR, cli_flags=None):
        d, floor = super()._repo(floor=floor)
        # What the `--help` READ found. Driven through `run_probes` for the
        # whole loop, because `driver.run` re-probes on every iteration and
        # would otherwise overwrite a seeded answer with whatever this
        # machine's PATH holds -- a different measurement, tested in
        # tests/probes/test_common.py, and not the subject here.
        # DEEP copies, both here and in `_posture`: `prove_output_schema_shape`
        # writes its verdict INTO the fact it read, so a fixture that handed
        # out the class constant itself would carry one test's verdict into
        # every later test in this class.
        self.flags = copy.deepcopy(self.ADVERTISED if cli_flags is None else cli_flags)
        write_host_evidence(d, self.POSTURE, cli_flags=copy.deepcopy(self.flags))
        return d, floor

    def _posture(self, *_a, **_k):
        """A posture whose write guard is NOT proven, which is what makes a
        review cell `return_json` (`requests.delivery`: a template that grants
        Write, on a host that cannot prove it mediates one, returns its
        findings instead of self-writing). That is the shape run 14 failed in
        -- its 103 tool advisors return their verdicts -- and the only shape
        in which an entry carries `output_schema` at all."""
        return {"schema_version": 1, "host": "claude", "probed_at": "2026-09-20T00:00:00Z",
                "capabilities": {c: {"state": self.POSTURE[c], "by": "fixture",
                                     "detail": "fixture"}
                                 for c in hosts.CAPABILITIES},
                hosts.CLI_FLAGS: copy.deepcopy(self.flags)}

    class Schemed(FakeRunner):
        """A family whose CLI takes the flag, and whose probe launch answers
        however the test says. Every launch records the entry it saw, so what
        reached the argv is a fact rather than an inference."""

        OUTPUT_SCHEMA_FLAG = ("--json-schema",)

        def __init__(self, verdict="ok", host="claude"):
            super().__init__(host)
            self.verdict = verdict
            self.seen = []
            self.bounds = []
            # The two per-launch bounds a real family carries: the loop only
            # SETS them when the operator passed a flag, so a fake that did
            # not declare them could not show that the probe's own bounds are
            # put back.
            self.max_turns, self.entry_timeout = 60, 1800
            self.runner = lambda *a, **k: None      # the injected launcher seam

        def run_entry(self, entry, env):
            self.seen.append(dict(entry))
            self.bounds.append((self.max_turns, self.entry_timeout))
            if entry["id"] != shape_probe.PROBE_ENTRY_ID:
                return super().run_entry(entry, env)
            self.runner(["claude", "-p"])           # the CLI really started
            if self.verdict == "ok":
                return base.RunResult(entry_id=entry["id"], ok=True, text='{"ok": true}',
                                      usage={}, cost_usd=None, model=None,
                                      session_id=None, denials=[], error=None)
            if self.verdict == "refuse":
                return base.RunResult.failed(
                    entry["id"], "claude -p printed no JSON envelope (exit 1)",
                    stderr="--json-schema is not valid JSON")
            raise base.LaunchRefused("the suite must never launch the real claude")

        def probe_launches(self):
            return [e for e in self.seen if e["id"] == shape_probe.PROBE_ENTRY_ID]

        def cells(self):
            return [e for e in self.seen if e["id"] != shape_probe.PROBE_ENTRY_ID]

    def _run(self, d, floor, runner, *extra, seed=True):
        err = io.StringIO()
        with contextlib.ExitStack() as es:
            es.enter_context(mock.patch.object(
                orchestrate, "_after_first_run",
                side_effect=lambda rr: seed and self._seed_coverage(rr, floor)))
            es.enter_context(mock.patch("scripts.runners.base.runner_for", return_value=runner))
            es.enter_context(mock.patch("scripts.host_probes.run_probes",
                                        side_effect=self._posture))
            es.enter_context(contextlib.redirect_stdout(io.StringIO()))
            es.enter_context(contextlib.redirect_stderr(err))
            return orchestrate.loop(self._args(d, "--allow-unenforced", *extra)), err.getvalue()

    def _fact(self, d):
        return runio._load_json(
            runio._pano(d, runio.HOST_CAPABILITIES))[hosts.CLI_FLAGS][hosts.OUTPUT_SCHEMA]

    def test_the_proof_launches_once_and_records_its_verdict(self):
        d, floor = self._repo()
        runner = self.Schemed()
        status, _err = self._run(d, floor, runner)
        self.assertEqual("complete", status["status"], status)
        self.assertEqual(1, len(runner.probe_launches()))
        self.assertEqual(hosts.SHAPE_PROVEN, self._fact(d)[hosts.SHAPE])

    def test_the_probe_is_launched_under_the_armed_guards(self):
        # The whole reason it moved here. `armed_at_launch` is written by the
        # fake from the guard files themselves, so this is the real arming
        # state at the moment of the probe's launch, not a claim about it.
        d, floor = self._repo()
        runner = self.Schemed()
        self._run(d, floor, runner)
        self.assertEqual((True, True), runner.armed_at_launch[0])
        # ...and its own entry is NOT one of the armed grants, so the out_file
        # it names could not be written even if it tried
        probe = runner.probe_launches()[0]
        self.assertNotIn(probe["id"], [e["id"] for e in runner.cells()])
        self.assertFalse(os.path.exists(probe["out_file"]))

    def test_the_probe_clones_a_real_cells_binding_and_its_own_bounds(self):
        d, floor = self._repo()
        runner = self.Schemed()
        self._run(d, floor, runner)
        probe, cell = runner.probe_launches()[0], runner.cells()[0]
        self.assertEqual(cell["agent"], probe["agent"])
        self.assertEqual(cell["enforced"], probe["enforced"])
        self.assertEqual(cell["model"], probe["model"])
        self.assertEqual(shape_probe.PROBE_ENTRY_ID, probe["id"])
        # one turn for the probe, and the batch's own bound put back after it
        self.assertEqual((shape_probe.PROBE_MAX_TURNS, shape_probe.PROBE_ENTRY_TIMEOUT),
                         runner.bounds[0])
        self.assertNotEqual(shape_probe.PROBE_MAX_TURNS, runner.bounds[1][0])

    def test_a_refutation_strips_the_flag_off_this_very_batch(self):
        # The point of proving it before the first `iter_batch` rather than
        # after: the cells this batch is about to launch must not carry an
        # argv the CLI has just refused.
        d, floor = self._repo()
        runner = self.Schemed(verdict="refuse")
        status, err = self._run(d, floor, runner)
        self.assertEqual("complete", status["status"], status)
        self.assertEqual(hosts.SHAPE_REFUTED, self._fact(d)[hosts.SHAPE])
        self.assertEqual([], [c for c in runner.cells() if c.get("output_schema")],
                         "a cell launched with the flag the CLI had just refused")
        self.assertIn("REFUSED it on one probe launch", err)
        self.assertEqual(1, err.count("REFUSED it on one probe launch"))

    def test_a_refuted_run_writes_no_schema_into_later_requests(self):
        d, floor = self._repo()
        runner = self.Schemed(verdict="refuse")
        self._run(d, floor, runner)
        # every later checkpoint regenerated its request through
        # `_materialize_prompts`, which consults the recorded shape
        self.assertEqual([], [c for c in runner.cells() if c.get("output_schema")])
        self.assertEqual(1, len(runner.probe_launches()), "it probed more than once")

    def test_a_proven_run_keeps_stamping(self):
        d, floor = self._repo()
        runner = self.Schemed()
        self._run(d, floor, runner)
        self.assertTrue([c for c in runner.cells() if c.get("output_schema")],
                        "a proven shape stopped the driver stamping")

    def test_it_never_probes_twice_not_even_across_a_resume(self):
        d, floor = self._repo()
        first = self.Schemed()
        self._run(d, floor, first)
        self.assertEqual(1, len(first.probe_launches()))
        again = self.Schemed()
        self._run(d, floor, again, seed=False)
        self.assertEqual([], again.probe_launches(), "a resume re-spent the probe launch")

    def test_a_flag_that_is_not_advertised_is_never_probed(self):
        d, floor = self._repo(cli_flags={hosts.OUTPUT_SCHEMA: {
            "flag": "--json-schema", "advertised": False, "detail": "does not advertise"}})
        runner = self.Schemed()
        self._run(d, floor, runner)
        self.assertEqual([], runner.probe_launches())
        self.assertNotIn(hosts.SHAPE, self._fact(d))

    def test_a_host_that_was_never_interrogated_is_never_probed(self):
        d, floor = self._repo(cli_flags={})
        runner = self.Schemed()
        self._run(d, floor, runner)
        self.assertEqual([], runner.probe_launches())
        self.assertEqual({}, runio._load_json(
            runio._pano(d, runio.HOST_CAPABILITIES))[hosts.CLI_FLAGS])

    def test_a_family_with_no_flag_is_never_probed(self):
        d, floor = self._repo()
        runner = FakeRunner()                       # OUTPUT_SCHEMA_FLAG is ()
        self._run(d, floor, runner)
        self.assertNotIn(hosts.SHAPE, self._fact(d))

    def test_a_batch_with_no_schema_carrying_entry_is_never_probed(self):
        # A checkpoint of self-writing cells has no binding to clone and no
        # flag to measure; it waits for one that does.
        d, floor = self._repo()
        runner = self.Schemed()
        real = orchestrate.loop_batch.prove_output_schema_shape
        seen = []

        def spy(run_dir, host, runner_, pending, env_for):
            for entry in pending:
                entry.pop("output_schema", None)     # self-writing batch
            seen.append(len(pending))
            return real(run_dir, host, runner_, pending, env_for)

        with mock.patch.object(orchestrate.loop_batch, "prove_output_schema_shape", spy):
            self._run(d, floor, runner)
        self.assertTrue(seen)
        self.assertEqual([], runner.probe_launches())
        self.assertNotIn(hosts.SHAPE, self._fact(d))

    def test_a_structural_launch_refusal_is_unmeasured_not_an_exception(self):
        # tests/conftest.py swaps every family's DEFAULT_RUNNER for a
        # LaunchRefused. Reaching it must cost one `unmeasured` verdict, never
        # a run that ends `error`.
        d, floor = self._repo()
        runner = self.Schemed(verdict="refused-launch")
        status, _err = self._run(d, floor, runner)
        self.assertEqual("complete", status["status"], status)
        self.assertEqual(hosts.SHAPE_UNMEASURED, self._fact(d)[hosts.SHAPE])
        self.assertTrue([c for c in runner.cells() if c.get("output_schema")],
                        "an unmeasured shape must change no stamping")

    def test_session_mode_never_probes(self):
        d, floor = self._repo()
        runner = self.Schemed()
        with mock.patch.object(orchestrate.loop_batch, "prove_output_schema_shape") as probe:
            self._run(d, floor, runner, "--mode", "session",
                      "--session-dir", self._session_root(d))
        self.assertEqual(0, probe.call_count)


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
