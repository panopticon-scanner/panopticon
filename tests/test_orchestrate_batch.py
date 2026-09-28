"""Loop batch discard and rollback tests."""
import contextlib
import io
import os
import shutil
import tempfile
import time
from unittest import mock


import scripts.driver as driver
import scripts.ledger as ledger_mod
import scripts.loop_batch as loop_batch
import scripts.orchestrate as orchestrate
import scripts.phases.review as review
import scripts.runners.batch as batch_mod
import scripts.phases.runio as runio
import scripts.runners.base as base
import scripts.write_guard_hook as write_guard_hook
from tests._test_helpers import (all_proven_artifact as _all_proven_artifact, dead_pid,
                           write_guard_not_proven as _write_guard_not_proven)
from tests._test_helpers import docker_probe_runner


from tests.orchestrate_helpers import (FakeRunner, _HeadlessLoopCase)

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

    def test_an_interrupt_during_first_run_ends_with_the_interrupted_status(self):
        # #2200: `_first_run` used to be called BEFORE the try, so a Ctrl-C
        # during a fresh run's first `driver.run` (readiness, discovery, the
        # coverage scouts) escaped `loop` as a traceback instead of the
        # `interrupted:` status every later Ctrl-C produces.
        d, _ = self._repo()
        runner = FakeRunner()
        runner.torn_down = []
        runner.teardown = runner.torn_down.append
        with mock.patch.object(orchestrate, "_first_run", side_effect=KeyboardInterrupt), \
                mock.patch("scripts.runners.base.runner_for", return_value=runner), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            status = orchestrate.loop(self._args(d))
        self.assertEqual("error", status["status"], status)
        self.assertEqual(loop_batch.INTERRUPTED_IDLE, status["message"])
        # `_finish` still ran for this invocation: the runner was torn down
        # for the terminal status, exactly as a mid-batch interrupt tears it
        # down (the assertion the pre-existing rollback tests use).
        self.assertEqual(["error"], runner.torn_down)

    def test_an_interrupt_on_the_resume_seam_ends_with_the_interrupted_status(self):
        # #2200: the same escape existed on the OTHER call before the try --
        # the resume seam's `_run`, taken when `_after_first_run` says the
        # first `driver.run` landed on a checkpoint coverage had already
        # reached (see its own docstring for why that seam exists at all).
        d, _ = self._repo()
        runner = FakeRunner()
        runner.torn_down = []
        runner.teardown = runner.torn_down.append
        with mock.patch.object(orchestrate, "_first_run",
                               return_value={"status": "checkpoint"}), \
                mock.patch.object(orchestrate, "_after_first_run", return_value=True), \
                mock.patch.object(orchestrate, "_run", side_effect=KeyboardInterrupt), \
                mock.patch("scripts.runners.base.runner_for", return_value=runner), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            status = orchestrate.loop(self._args(d))
        self.assertEqual("error", status["status"], status)
        self.assertEqual(loop_batch.INTERRUPTED_IDLE, status["message"])
        self.assertEqual(["error"], runner.torn_down)

    def test_an_exception_from_first_run_ends_with_the_error_status(self):
        # #2200: the same call site, for the loop's OTHER promise -- `loop`
        # never raises (review round 1, item 3). An Exception used to escape
        # as a traceback too, where every other failure in `loop` becomes an
        # `error` status.
        d, _ = self._repo()
        runner = FakeRunner()
        runner.torn_down = []
        runner.teardown = runner.torn_down.append
        with mock.patch.object(orchestrate, "_first_run", side_effect=RuntimeError("boom")), \
                mock.patch("scripts.runners.base.runner_for", return_value=runner), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            status = orchestrate.loop(self._args(d))
        self.assertEqual("error", status["status"], status)
        self.assertEqual("driver loop: RuntimeError: boom", status["message"])
        self.assertEqual(["error"], runner.torn_down)

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


