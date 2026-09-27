"""Host outage handling during loop dispatch."""
import contextlib
import io
import json
import os
from unittest import mock


import scripts.ledger as ledger_mod
import scripts.orchestrate as orchestrate
import scripts.phases.runio as runio
import scripts.runners.base as base
import scripts.runners.claude as claude_runner
import scripts.runners.kimi as kimi_runner
import scripts.runners.outage as outage
from tests._test_helpers import (all_proven_artifact as _all_proven_artifact)
from tests._test_helpers import docker_probe_runner


from tests.orchestrate_helpers import (_MidBatchGated, FakeRunner, LoopCase)

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

    Gated = _MidBatchGated

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

