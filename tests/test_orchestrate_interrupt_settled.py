"""#3349: a graceful Ctrl-C/SIGTERM keeps every entry that had SETTLED -- its
real ledger row appended by this process in this batch -- exactly as a clean
batch close leaves it, and rolls back only the unfinished rest.

The authority is `Ledger.settled`, held in the controller's memory; the batch
record on disk never decides what an interrupt keeps."""
import contextlib
import io
import os
import signal
import sys
import threading
import time
from unittest import mock


import scripts.ledger as ledger_mod
import scripts.loop_batch as loop_batch
import scripts.orchestrate as orchestrate
import scripts.phases.review as review
import scripts.phases.runio as runio
import scripts.procgroup as procgroup
import scripts.runners.base as base
import scripts.runners.batch as batch_mod
import scripts.runners.outage as outage
from tests._test_helpers import all_proven_artifact as _all_proven_artifact, dead_pid
from tests._test_helpers import docker_probe_runner
from tests.orchestrate_helpers import FakeRunner, _HeadlessLoopCase

SEC, ACC = "review-app-SEC", "review-app-ACC"

# A runner child that forks a worker, records both pids, and outsleeps every
# deadline here: what the interrupt has to reap (tests/test_procgroup.py).
_TREE = ("import os, subprocess, sys, time\n"
         "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
         "open(sys.argv[1], 'w').write('%d %d' % (os.getpid(), p.pid))\n"
         "time.sleep(60)\n")


def setUpModule():
    global _patch, _readiness_docker_patch
    _patch = mock.patch("scripts.host_probes.run_probes",
                        side_effect=lambda host, target, **kw: _all_proven_artifact(host))
    _patch.start()
    _readiness_docker_patch = mock.patch(
        "scripts.phases.readiness_checks.DOCKER_RUNNER", docker_probe_runner())
    _readiness_docker_patch.start()


def tearDownModule():
    _patch.stop()
    _readiness_docker_patch.stop()


def _alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:          # pragma: no cover - alive, not ours
        return True
    return True


class TestSettledEntriesSurviveTheInterrupt(_HeadlessLoopCase):

    def _entries(self, d):
        req = orchestrate.requests.load_dispatch_request(d) or {}
        return {e["id"]: e for e in req.get("entries") or []}

    def _rows(self, runner):
        return [(r["entry_id"], r.get("status")) for r in ledger_mod.Ledger(runner.run_dir).lines()]

    def _charged(self, d):
        return {k: v for k, v in review._cell_attempts(d).items() if v}

    def _wait_for_row(self, runner, eid, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if any(r.get("entry_id") == eid for r in ledger_mod.Ledger(runner.run_dir).lines()):
                return True
            time.sleep(0.02)
        return False

    def _on_record(self, after):
        """Patch the ledger's writer so the interrupt lands inside it, on a real row:
        `after` False raises BEFORE the append, True right after it. Returns the
        patch and the ids it fired for."""
        real, fired = ledger_mod.Ledger.record, []

        def record(ledger, entry, *args, **kwargs):
            if kwargs.get("status") or fired:
                return real(ledger, entry, *args, **kwargs)
            if after:
                real(ledger, entry, *args, **kwargs)
            fired.append(entry["id"])
            raise KeyboardInterrupt

        return mock.patch.object(ledger_mod.Ledger, "record", record), fired

    def test_a_settled_refusal_keeps_its_evidence_row_and_charge_and_is_retried(self):
        # A reply the loop REFUSED is still a launch that came back: its row is
        # the failure it was, and its redacted reply is the next prompt's input
        # (D10 ruling 2). Settled, the interrupt keeps all of it.
        d, floor = self._repo(floor=("SEC", "ACC"))
        runner, inner = FakeRunner(), None
        inner = runner.run_entry

        def gated(entry, env):
            if entry["id"] == SEC:
                return base.RunResult(entry_id=SEC, ok=True, text="not a reply", usage={},
                                      cost_usd=0.01, model="m", session_id="s", denials=[],
                                      error=None)
            if entry["id"] == ACC:
                self.assertTrue(self._wait_for_row(runner, SEC))
                raise KeyboardInterrupt
            return inner(entry, env)

        runner.run_entry = gated
        status = self._return_persist(d, floor, runner)
        self.assertIn("1 of 2 entries had settled and were kept", status["message"])
        self.assertEqual([(SEC, None), (ACC, ledger_mod.CANCELLED)], self._rows(runner))
        self.assertEqual(1, len(self._rejected(runner)))
        self.assertEqual({"app/SEC": 1}, self._charged(d))
        self.assertFalse(orchestrate.persist.is_done(self._entries(d)[SEC]))
        resumed = FakeRunner()
        self.assertEqual("complete", self._return_persist(d, floor, resumed)["status"])
        self.assertEqual({SEC, ACC}, {e for e in resumed.launched if e.startswith("review-")})

    def test_an_interrupt_before_the_row_is_appended_settles_nothing(self):
        # The reply is on disk but its row is not: NOT settled. The issue's
        # predicate is the conjunction, so the reply goes, the entry is cut and
        # its attempt comes back -- whatever an `out_file exists` test would say.
        d, floor = self._repo(floor=("SEC", "ACC"))
        runner = FakeRunner()
        patch, fired = self._on_record(after=False)
        with patch:
            status = self._return_persist(d, floor, runner)
        self.assertEqual(1, len(fired))
        self.assertIn("0 of 2 entries had settled and were kept; 2 unfinished",
                      status["message"])
        self.assertEqual({(SEC, ledger_mod.CANCELLED), (ACC, ledger_mod.CANCELLED)},
                         set(self._rows(runner)))
        for eid, entry in self._entries(d).items():
            self.assertFalse(os.path.exists(entry["out_file"]), eid)
        self.assertEqual({}, self._charged(d))
        self.assertEqual([], self._manifests(runner.run_dir))

    def test_an_interrupt_after_the_row_is_appended_keeps_the_entry(self):
        # The row is on disk but the loop never got to note the id in `handled`:
        # settled all the same, because the ledger's own record is the authority.
        d, floor = self._repo(floor=("SEC", "ACC"))
        runner = FakeRunner()
        patch, fired = self._on_record(after=True)
        with patch:
            status = self._return_persist(d, floor, runner)
        (kept,) = fired
        cut = ({SEC, ACC} - {kept}).pop()
        self.assertIn("1 of 2 entries had settled and were kept; 1 unfinished",
                      status["message"])
        self.assertEqual([(kept, None), (cut, ledger_mod.CANCELLED)], self._rows(runner))
        entries = self._entries(d)
        self.assertTrue(orchestrate.persist.is_done(entries[kept]))
        self.assertFalse(os.path.exists(entries[cut]["out_file"]))
        self.assertEqual({"app/" + kept.rsplit("-", 1)[1]: 1}, self._charged(d))

    def test_the_record_on_disk_never_decides_what_the_interrupt_takes_back(self):
        # The reviewed tree owns the record's bytes. Rewritten mid-batch to drop
        # the in-flight entry, it must not spare that entry's partial artifact.
        d, floor = self._repo(floor=("SEC", "ACC"))
        runner = FakeRunner()

        def tamper_and_interrupt():
            out = self._entries(d)[ACC]["out_file"]
            with open(out, "w", encoding="utf-8") as fh:
                fh.write('{"findings": [')                 # a self-writer's half reply
            path = os.path.join(runner.run_dir, "batch-1.json")
            doc = runio._load_json(path)
            doc["entries"] = [row for row in doc["entries"] if row["id"] != ACC]
            runio._write_json(path, doc)
            raise KeyboardInterrupt

        self._gate_on_peer(runner, ACC, SEC, then=tamper_and_interrupt)
        status = self._return_persist(d, floor, runner)
        self.assertNotIn("rollback incomplete", status["message"])
        entries = self._entries(d)
        self.assertFalse(os.path.exists(entries[ACC]["out_file"]))
        self.assertTrue(orchestrate.persist.is_done(entries[SEC]))
        self.assertEqual([(SEC, None), (ACC, ledger_mod.CANCELLED)], self._rows(runner))

    def test_a_second_ctrl_c_after_the_narrowing_is_finished_from_the_narrowed_record(self):
        # The second interrupt lands inside the artifact removal, after the record
        # was narrowed and flagged. The next loop finishes from THAT record: only
        # the unfinished entry's artifact goes, and nothing is ledgered or
        # refunded twice.
        d, floor = self._repo(floor=("SEC", "ACC"))
        runner = FakeRunner()

        def half_write_and_interrupt():
            with open(self._entries(d)[ACC]["out_file"], "w", encoding="utf-8") as fh:
                fh.write('{"findings": [')
            raise KeyboardInterrupt

        self._gate_on_peer(runner, ACC, SEC, then=half_write_and_interrupt)
        with self._interrupt_the_rollback("artifacts"):
            status = self._return_persist(d, floor, runner)
        self.assertIn("rollback incomplete", status["message"])
        record = self._crash_record(runner.run_dir)
        self.assertIs(True, record.get("recovering"))
        self.assertEqual([ACC], [row["id"] for row in record["entries"]])
        rows, charged = self._rows(runner), self._charged(d)
        self.assertEqual([(SEC, None), (ACC, ledger_mod.CANCELLED)], rows)
        self._stamp_crash_owner(runner.run_dir, pid=dead_pid())
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            loop_batch.recover_stale(d, orchestrate.requests.previous_request(d),
                                     "claude", "headless")
        self.assertIn("finished the interrupted recovery", err.getvalue())
        entries = self._entries(d)
        self.assertFalse(os.path.exists(entries[ACC]["out_file"]))
        self.assertTrue(orchestrate.persist.is_done(entries[SEC]))
        self.assertEqual(rows, self._rows(runner))
        self.assertEqual(charged, self._charged(d))
        self.assertEqual([], self._manifests(runner.run_dir))

    def test_an_interrupt_with_nothing_unfinished_leaves_no_record(self):
        # Every entry had landed when the Ctrl-C came: there is nothing to take
        # back, so no flagged record is left for the next loop to trip over.
        d, floor = self._repo(floor=("SEC", "ACC"))
        runner = FakeRunner()
        real, seen = ledger_mod.Ledger.record, []

        def record(ledger, entry, *args, **kwargs):
            real(ledger, entry, *args, **kwargs)
            if not kwargs.get("status"):
                seen.append(entry["id"])
                if len(seen) == 2:
                    raise KeyboardInterrupt

        with mock.patch.object(ledger_mod.Ledger, "record", record):
            status = self._return_persist(d, floor, runner)
        self.assertIn("2 of 2 entries had settled and were kept; 0 unfinished",
                      status["message"])
        self.assertNotIn("rollback incomplete", status["message"])
        self.assertEqual([], self._manifests(runner.run_dir))
        self.assertNotIn(ledger_mod.CANCELLED, [s for _e, s in self._rows(runner)])
        self.assertEqual({"app/SEC": 1, "app/ACC": 1}, self._charged(d))

    def _attempts_after_first_give_back(self, d, floor, runner, interrupt):
        """`cell-attempts.json` as the batch's FIRST refund left it: the clean
        close's `give_back`, or the interrupt's own refund."""
        real, snapshot = orchestrate.persist.rollback_markers, []

        def markers(review_root, checkpoint, entries):
            real(review_root, checkpoint, entries)
            if not snapshot:
                snapshot.append(self._charged(d))

        runner.fail_once.add(SEC)
        inner = runner.run_entry

        def host_down(entry, env):
            result = inner(entry, env)
            if entry["id"] == SEC and not result.ok:
                result.failure_class = outage.HOST_FAILURE    # a 429, a quota storm
            return result

        runner.run_entry = host_down
        real_record, landed = ledger_mod.Ledger.record, []

        def record(ledger, entry, *args, **kwargs):
            real_record(ledger, entry, *args, **kwargs)
            if not kwargs.get("status"):
                landed.append(entry["id"])
                if interrupt and len(landed) == 2:
                    raise KeyboardInterrupt

        with mock.patch.object(orchestrate.persist, "rollback_markers", markers), \
                mock.patch.object(ledger_mod.Ledger, "record", record):
            self._return_persist(d, floor, runner, "--max-iterations", "3")
        return snapshot[0]

    def test_a_settled_host_class_failure_is_refunded_as_the_clean_close_refunds_it(self):
        # R2: a seat outage is not the cell's fault on either path, and the
        # interrupt must not spend the retry budget a clean close gives back.
        d, floor = self._repo(floor=("SEC", "ACC"))
        clean = self._attempts_after_first_give_back(d, floor, FakeRunner(), interrupt=False)
        d2, _ = self._repo(floor=("SEC", "ACC"))
        interrupted = self._attempts_after_first_give_back(d2, floor, FakeRunner(),
                                                           interrupt=True)
        self.assertEqual({"app/ACC": 1}, clean)
        self.assertEqual(clean, interrupted)

    def test_sigterm_takes_the_same_path_and_reaps_the_in_flight_child(self):
        # The issue's item 3, end to end: a SIGTERM to the driver, raised as the
        # interrupt by `sigterm_as_interrupt`, while ACC's real child process
        # group is running. The group is reaped, SEC stays, ACC is cut.
        previous = signal.signal(signal.SIGTERM, signal.SIG_DFL)
        self.addCleanup(signal.signal, signal.SIGTERM, previous)
        d, floor = self._repo(floor=("SEC", "ACC"))
        runner, pidfile = FakeRunner(), os.path.join(d, "tree.pid")
        inner, pids = runner.run_entry, []

        def child_then_term():
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and not pids:
                try:
                    with open(pidfile, encoding="utf-8") as fh:
                        pids.extend(int(p) for p in fh.read().split())
                except (OSError, ValueError):
                    time.sleep(0.02)
            os.kill(os.getpid(), signal.SIGTERM)

        def gated(entry, env):
            if entry["id"] == ACC:
                self.assertTrue(self._wait_for_row(runner, SEC))
                threading.Thread(target=child_then_term, daemon=True).start()
                return runner.launch([sys.executable, "-c", _TREE, pidfile], cwd=d, timeout=60)
            return inner(entry, env)

        runner.run_entry = gated
        status = procgroup.sigterm_as_interrupt(lambda: self._return_persist(d, floor, runner))
        self.assertEqual("error", status["status"], status)
        self.assertIn("1 of 2 entries had settled and were kept", status["message"])
        self.assertEqual(2, len(pids))
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and any(_alive(p) for p in pids):
            time.sleep(0.05)
        self.assertFalse([p for p in pids if _alive(p)], "the in-flight child group outlived it")
        self.assertEqual([(SEC, None), (ACC, ledger_mod.CANCELLED)], self._rows(runner))
        self.assertTrue(orchestrate.persist.is_done(self._entries(d)[SEC]))
        self.assertEqual({"app/SEC": 1}, self._charged(d))


class TestTheBatchNarrows(_HeadlessLoopCase):

    def _batch(self):
        run_dir = os.path.realpath(self._tmp())
        entries = [{"id": eid, "artifacts": [os.path.join(run_dir, eid + ".json")]}
                   for eid in ("a", "b", "c")]
        return batch_mod.Batch(run_dir, 1, "review", entries).open()

    def _tmp(self):
        import shutil
        import tempfile
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        return d

    def test_narrow_keeps_only_the_named_entries_and_flags_in_one_write(self):
        batch = self._batch()
        writes = []
        real = batch_mod.guard_rules.atomic_write_json
        with mock.patch.object(batch_mod.guard_rules, "atomic_write_json",
                               side_effect=lambda *a, **k: (writes.append(a[1]), real(*a, **k))):
            batch.narrow(["b"])
        self.assertEqual(1, len(writes))
        self.assertEqual((["b"], True), ([row["id"] for row in writes[0]["entries"]],
                                         writes[0]["recovering"]))
        doc = runio._load_json(batch.path)
        self.assertEqual(["b"], [row["id"] for row in doc["entries"]])
        self.assertIs(True, doc["recovering"])

    def test_narrow_refuses_an_id_the_batch_never_held(self):
        batch = self._batch()
        with self.assertRaisesRegex(ValueError, "not this batch's entries: z"):
            batch.narrow(["a", "z"])
        self.assertNotIn("recovering", runio._load_json(batch.path))


class TestTheLedgersSettlementRecord(_HeadlessLoopCase):

    def _ledger(self):
        import shutil
        import tempfile
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        return ledger_mod.Ledger(d)

    def _record(self, ledger, eid, ok=True, **kwargs):
        result = (base.RunResult(entry_id=eid, ok=True, text="", usage={}, cost_usd=0.01,
                                 model="m", session_id="s", denials=[], error=None)
                  if ok else base.RunResult.failed(eid, "boom"))
        ledger.record({"id": eid}, "review", result, "headless", "claude", **kwargs)
        return result

    def test_only_real_rows_since_the_mark_are_settled(self):
        ledger = self._ledger()
        self._record(ledger, "before")                  # no batch open: nothing settles
        self.assertIsNone(ledger.settled)
        ledger.mark_batch()
        ok = self._record(ledger, "a")
        self._record(ledger, "b", status=ledger_mod.CANCELLED, rolled_back=True)
        self.assertEqual({"a": (ok, None)}, ledger.settled)
        ledger.mark_batch()                             # the next batch starts clean
        self.assertEqual({}, ledger.settled)

    def test_a_row_that_never_reached_disk_is_not_settled(self):
        ledger = self._ledger()
        ledger.mark_batch()
        with mock.patch.object(ledger_mod.runio, "_open_a_nofollow", side_effect=OSError("full")):
            with self.assertRaises(OSError):
                self._record(ledger, "a")
        self.assertEqual({}, ledger.settled)

    def test_the_interrupt_and_the_tally_classify_a_landed_entry_alike(self):
        host = base.RunResult.failed("h", "429", failure_class=outage.HOST_FAILURE)
        self.assertEqual(outage.HOST_FAILURE, outage.landed_class(host))
        self.assertEqual(outage.ENTRY_FAILURE, outage.landed_class(host, "persist refused"))
        self.assertIsNone(outage.landed_class(self._record(self._ledger(), "a")))
