"""driver loop (spec 4.3): the engine driven by a process, with a fake runner."""
import contextlib
import dataclasses
import io
import json
import os
import shutil
import subprocess
import tempfile
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
import scripts.write_guard_hook as write_guard_hook
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
        self.assertEqual(orchestrate.INTERRUPTED_IDLE, status["message"])
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
        # each row carries the time THAT entry took. Two cells in one batch,
        # one of them made slow -- concurrent, so a batch-wide measurement
        # would give them the same number.
        d, floor = self._repo(floor=("SEC", "ACC"))

        class OneSlowCell(FakeRunner):
            def run_entry(self, entry, env):
                if entry["id"] == "review-app-SEC":
                    time.sleep(0.05)
                return super().run_entry(entry, env)

        runner = OneSlowCell()
        self._run(d, floor, runner)
        rows = {r["entry_id"]: r for r in ledger_mod.Ledger(runner.run_dir).lines()}
        self.assertIn("review-app-ACC", rows)
        # Fix round 1, N1: both bounds are CONCRETE. Comparing the two rows
        # instead raced the sleep -- on a contended runner (this suite launches
        # at the pool's full width) ACC's own work can exceed 50 ms and invert
        # the pair, while the fact under test is only that each row carries its
        # own entry's time.
        self.assertGreaterEqual(rows["review-app-SEC"]["duration_ms"], 40)
        self.assertLess(rows["review-app-ACC"]["duration_ms"], 40)

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

    # Ten cells, not eight: the launch bound is the POOL (3 + max(2, width) +
    # width = 7), so widening the batch must not widen it. Seven launched and
    # three never launched says "constant", where eight cells and one left over
    # would read as "proportional".
    FLOOR = ("SEC", "COD", "ARC", "TST", "QAL", "AGT", "DAT", "OPS", "ACC", "LNG")
    HOST_ERROR = ("provider.auth_error: 403 You've reached your weekly (7-day) "
                  "usage limit")
    REFUSAL = "kimi -p exited 1: All files read and cross-checked"
    WIDTH = 2

    class Outage(FakeRunner):
        """The kimi run's shape: the first two cells answer, the third refuses
        on ITS own account (#1719's masked 403 classifies entry-class), and
        every launch after that is the quota 403.

        Behaviour is keyed on the cell's index in the batch's pending list --
        which is its launch order, the pool being FIFO -- not on a counter, so
        no thread interleaving can change which cell does what. And from that
        index on, a launch does not come back until the LOOP has ledgered every
        result before it: two workers answering instantly outrun a consumer
        that persists and ledgers each reply, and "what the short-circuit
        stopped" would be a race rather than a fact.
        """

        def __init__(self, floor, host_error, refusal):
            super().__init__()
            self.order = ["review-app-%s" % d for d in floor]
            self.failure, self.refusal = host_error, refusal

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

        def run_entry(self, entry, env):
            eid = entry["id"]
            i = self.order.index(eid) if eid in self.order else None
            if i is None or i < 2:
                return super().run_entry(entry, env)
            self.launched.append(eid)
            if i == 2:
                return base.RunResult.failed(eid, self.refusal)
            self._await_ledger(i)
            return base.RunResult.failed(eid, "kimi -p exited 1: " + self.failure,
                                         host_error=self.failure)

    def _outage(self):
        return self.Outage(self.FLOOR, self.HOST_ERROR, self.REFUSAL)

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

    def test_the_outage_stops_the_batch_instead_of_draining_it(self):
        d, floor = self._repo(floor=self.FLOOR)
        runner = self._outage()
        status, err = self._run(d, floor, runner)
        self.assertEqual("paused", status["status"], status)
        reviews = self._reviews(runner)
        self.assertLess(len(reviews), len(self.FLOOR), reviews)
        # 2 answered + 1 refused + the corroboration the stop waits for
        # (max(2, width)) + the pool that was already running (width). A
        # CONSTANT: the batch is ten cells and the bound is still seven, so
        # what the outage costs is the pool, not the checkpoint.
        self.assertLessEqual(len(reviews), 3 + max(2, self.WIDTH) + self.WIDTH, reviews)
        unlaunched = len(self.FLOOR) - len(reviews)
        self.assertGreaterEqual(unlaunched, 3, reviews)
        self.assertIn("%d of %d entries not launched" % (unlaunched, len(self.FLOOR)), err)
        self.assertIn("host outage detected after", err)
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
