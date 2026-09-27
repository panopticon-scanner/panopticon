"""Loop interruption and recovery tests."""
import contextlib
import copy
import io
import os
from unittest import mock


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


