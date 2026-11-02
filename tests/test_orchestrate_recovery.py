"""Loop interruption and recovery tests."""
import contextlib
import copy
import hashlib
import io
import json
import os
import signal
import threading
import time
from unittest import mock


import scripts.ledger as ledger_mod
import scripts.loop_batch as loop_batch
import scripts.batch_settlement as batch_settlement
import scripts.orchestrate as orchestrate
import scripts.phases.review as review
import scripts.runners.batch as batch_mod
import scripts.phases.runio as runio
import scripts.runners.base as base
import scripts.runners.outage as outage
import scripts.runners.settlement as settlement_mod
import scripts.run_manifest as run_manifest
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


def _unfinished(batch):
    """The interrupted batch's in-flight entry's row (#3349): the one the rollback still owns."""
    return next(row for row in batch.entries if row["id"] == "review-app-ACC")


class TestHeadlessLoop(_HeadlessLoopCase):
    def _sigkill_real_loop_after_first_receipt(self, d, floor):
        """Fork a real loop process; kill it while its peer worker is live."""
        pid = os.fork()
        if pid == 0:  # pragma: no branch - the parent asserts the child's bytes
            runner, inner = FakeRunner(), None
            inner = runner.run_entry

            def one_finishes_one_waits(entry, env):
                if entry["id"] == "review-app-ACC":
                    while True:
                        threading.Event().wait(1)
                return inner(entry, env)

            runner.run_entry = one_finishes_one_waits
            try:
                self._return_persist(d, floor, runner)
            finally:
                os._exit(0)

        reaped = False

        def reap():
            nonlocal reaped
            if reaped:
                return
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
            reaped = True

        self.addCleanup(reap)
        deadline, run_dir = time.monotonic() + 15, None
        while time.monotonic() < deadline:
            manifest = run_manifest.load_manifest(d)
            if manifest:
                run_dir = orchestrate.persist.run_dir(d)
                path = os.path.join(run_dir, "batch-1.json")
                doc = runio._load_json(path)
                if (isinstance(doc, dict)
                        and any(row.get("id") == "review-app-SEC" and row.get("settlement")
                                for row in doc.get("entries") or [])):
                    break
            threading.Event().wait(0.02)
        else:
            self.fail("real loop did not publish a settlement receipt before SIGKILL")
        os.kill(pid, signal.SIGKILL)
        waited, status = os.waitpid(pid, 0)
        reaped = True
        self.assertEqual(pid, waited)
        self.assertTrue(os.WIFSIGNALED(status))
        self.assertEqual(signal.SIGKILL, os.WTERMSIG(status))
        return run_dir

    def test_real_sigkill_mid_batch_keeps_only_the_receipted_entry(self):
        d, floor = self._repo(floor=("SEC", "ACC"))
        run_dir = self._sigkill_real_loop_after_first_receipt(d, floor)
        record = self._crash_record(run_dir)
        self.assertEqual({"review-app-SEC"},
                         {row["id"] for row in record["entries"] if row.get("settlement")})
        req = orchestrate.requests.previous_request(d)
        entries = {entry["id"]: entry for entry in req["entries"]}
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            loop_batch.recover_stale(d, req, "claude", "headless")
        self.assertIn("kept 1 entries; rolled back 1", err.getvalue())
        self.assertTrue(orchestrate.persist.is_done(entries["review-app-SEC"]))
        self.assertFalse(os.path.lexists(entries["review-app-ACC"]["out_file"]))
        rows = [(row["entry_id"], row.get("status"))
                for row in ledger_mod.Ledger(run_dir).lines()]
        self.assertEqual([("review-app-SEC", None),
                          ("review-app-ACC", ledger_mod.CANCELLED)], rows)
        self.assertEqual({"app/SEC": 1},
                         {key: value for key, value in review._cell_attempts(d).items()
                          if value})

    def test_real_sigkill_mid_recovery_replays_no_rows_or_refunds(self):
        d, floor = self._repo(floor=("SEC", "ACC"))
        run_dir = self._sigkill_real_loop_after_first_receipt(d, floor)
        req = orchestrate.requests.previous_request(d)
        marker = os.path.join(d, "recovery-reached-close")
        pid = os.fork()
        if pid == 0:  # pragma: no branch - parent inspects durable effects
            def block_at_close(_batch):
                with open(marker, "w", encoding="utf-8") as fh:
                    fh.write("ready")
                while True:
                    threading.Event().wait(1)

            with mock.patch.object(batch_mod.Batch, "close", block_at_close):
                loop_batch.recover_stale(d, req, "claude", "headless")
            os._exit(0)

        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not os.path.isfile(marker):
            threading.Event().wait(0.02)
        if not os.path.isfile(marker):
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            self.fail("real recovery did not reach its final close")
        os.kill(pid, signal.SIGKILL)
        waited, status = os.waitpid(pid, 0)
        self.assertEqual(pid, waited)
        self.assertEqual(signal.SIGKILL, os.WTERMSIG(status))

        record = self._crash_record(run_dir)
        self.assertIs(True, record.get("recovering"))
        self.assertEqual(["review-app-ACC"], [row["id"] for row in record["entries"]])
        rows_before = ledger_mod.Ledger(run_dir).lines()
        attempts_before = review._cell_attempts(d)
        with contextlib.redirect_stderr(io.StringIO()):
            loop_batch.recover_stale(d, req, "claude", "headless")
        self.assertEqual([], self._manifests(run_dir))
        self.assertEqual(rows_before, ledger_mod.Ledger(run_dir).lines())
        self.assertEqual(attempts_before, review._cell_attempts(d))
        entries = {entry["id"]: entry for entry in req["entries"]}
        self.assertTrue(orchestrate.persist.is_done(entries["review-app-SEC"]))

    def test_real_sigkill_between_row_and_receipt_rolls_back_conservatively(self):
        d, floor = self._repo(floor=("SEC",))
        marker = os.path.join(d, "row-before-receipt")
        pid = os.fork()
        if pid == 0:  # pragma: no branch - the parent kills this exact window
            def block_receipt(_batch, _entry_id, **_kwargs):
                with open(marker, "w", encoding="utf-8") as fh:
                    fh.write("ready")
                while True:
                    threading.Event().wait(1)

            with mock.patch.object(batch_mod.Batch, "settle", block_receipt):
                self._return_persist(d, floor, FakeRunner())
            os._exit(0)

        deadline, run_dir = time.monotonic() + 10, None
        while time.monotonic() < deadline and not os.path.isfile(marker):
            manifest = run_manifest.load_manifest(d)
            if manifest:
                run_dir = orchestrate.persist.run_dir(d)
            threading.Event().wait(0.02)
        if not os.path.isfile(marker):
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            self.fail("real loop did not reach the row-before-receipt window")
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        record = self._crash_record(run_dir)
        self.assertNotIn("settlement", record["entries"][0])
        self.assertTrue(any(row.get("entry_id") == "review-app-SEC"
                            for row in ledger_mod.Ledger(run_dir).lines()))
        req = orchestrate.requests.previous_request(d)
        out_file = req["entries"][0]["out_file"]
        self.assertTrue(os.path.isfile(out_file))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            loop_batch.recover_stale(d, req, "claude", "headless")
        self.assertIn("kept 0 entries; rolled back 1", err.getvalue())
        self.assertIn("no receipt 1", err.getvalue())
        self.assertFalse(os.path.lexists(out_file))
        self.assertTrue(any(row.get("entry_id") == "review-app-SEC"
                            and row.get("status") == ledger_mod.ROLLED_BACK
                            for row in ledger_mod.Ledger(run_dir).lines()))

    def _sigkill_real_loop_after_all_settled(self, d, floor):
        marker = os.path.join(d, "all-settled-before-close")
        pid = os.fork()
        if pid == 0:  # pragma: no branch - killed at the clean-close seam
            def block_close(_batch):
                with open(marker, "w", encoding="utf-8") as fh:
                    fh.write("ready")
                while True:
                    threading.Event().wait(1)

            with mock.patch.object(batch_mod.Batch, "close", block_close):
                self._return_persist(d, floor, FakeRunner())
            os._exit(0)
        reaped = False

        def reap():
            nonlocal reaped
            if reaped:
                return
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
            reaped = True

        self.addCleanup(reap)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not os.path.isfile(marker):
            threading.Event().wait(0.02)
        if not os.path.isfile(marker):
            reap()
            self.fail("all-settled loop did not reach close")
        os.kill(pid, signal.SIGKILL)
        waited, status = os.waitpid(pid, 0)
        reaped = True
        self.assertEqual(pid, waited)
        self.assertEqual(signal.SIGKILL, os.WTERMSIG(status))
        return orchestrate.persist.run_dir(d)

    def test_an_all_settled_crash_record_closes_without_rollback_rows(self):
        d, floor = self._repo(floor=("SEC",))
        run_dir = self._sigkill_real_loop_after_all_settled(d, floor)
        req = orchestrate.requests.previous_request(d)
        out_file = req["entries"][0]["out_file"]
        before = ledger_mod.Ledger(run_dir).lines()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            loop_batch.recover_stale(d, req, "claude", "headless")
        self.assertIn("kept 1 entries; rolled back 0", err.getvalue())
        self.assertTrue(os.path.isfile(out_file))
        self.assertEqual(before, ledger_mod.Ledger(run_dir).lines())
        self.assertEqual([], self._manifests(run_dir))

    def test_an_empty_flagged_all_settled_record_finishes_on_the_next_recovery(self):
        d, floor = self._repo(floor=("SEC",))
        run_dir = self._sigkill_real_loop_after_all_settled(d, floor)
        req = orchestrate.requests.previous_request(d)
        out_file = req["entries"][0]["out_file"]
        before = ledger_mod.Ledger(run_dir).lines()

        with mock.patch.object(batch_mod.Batch, "roll_back",
                               side_effect=KeyboardInterrupt("second crash")), \
             self.assertRaisesRegex(KeyboardInterrupt, "second crash"):
            loop_batch.recover_stale(d, req, "claude", "headless")
        record = self._crash_record(run_dir)
        self.assertIs(True, record.get("recovering"))
        self.assertEqual([], record["entries"])
        self.assertTrue(os.path.isfile(out_file))
        self.assertEqual(before, ledger_mod.Ledger(run_dir).lines())

        # The prior recovery owned the atomic narrow write. Model its process
        # loss before asking a new recovery to finish the flagged empty record.
        self._stamp_crash_owner(run_dir, pid=dead_pid())
        with contextlib.redirect_stderr(io.StringIO()):
            loop_batch.recover_stale(d, req, "claude", "headless")
        self.assertEqual([], self._manifests(run_dir))
        self.assertTrue(os.path.isfile(out_file))
        self.assertEqual(before, ledger_mod.Ledger(run_dir).lines())

    def test_a_crashed_record_carries_a_signed_row_and_artifact_receipt(self):
        """#3351 RED: the settled peer is recoverable after process loss."""
        d, floor = self._repo(floor=("SEC", "ACC"))
        crashed = self._leave_crashed_batch(d, floor)
        record = self._crash_record(crashed.run_dir)
        settled = next(row for row in record["entries"]
                       if row["id"] == "review-app-SEC")
        receipt = settled["settlement"]
        self.assertEqual(1, receipt["version"])
        self.assertEqual("panopticon-batch-settlement-1", receipt["domain"])
        self.assertEqual("review-app-SEC", receipt["entry_id"])
        self.assertEqual(record["nonce"], receipt["nonce"])
        self.assertEqual(1, len(receipt["artifacts"]))
        artifact = receipt["artifacts"][0]
        with open(artifact["path"], "rb") as fh:
            self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), artifact["sha256"])
        self.assertNotIn("settlement", next(row for row in record["entries"]
                                             if row["id"] == "review-app-ACC"))

    def test_edited_truncated_deleted_or_swapped_artifact_is_never_settled(self):
        """#3351: the HMAC proves bytes and schema, not merely a paid row."""
        for mutation in ("edited", "truncated", "deleted", "swapped"):
            with self.subTest(mutation=mutation):
                d, floor = self._repo(floor=("SEC", "ACC"))
                crashed = self._leave_crashed_batch(d, floor)
                req = orchestrate.requests.previous_request(d)
                entries = {entry["id"]: entry for entry in req["entries"]}
                sec = entries["review-app-SEC"]["out_file"]
                if mutation == "edited":
                    with open(sec, "a", encoding="utf-8") as fh:
                        fh.write("\n")                 # still schema-valid, different bytes
                elif mutation == "truncated":
                    with open(sec, "w", encoding="utf-8") as fh:
                        fh.write('{"findings": [')
                elif mutation == "deleted":
                    os.remove(sec)
                else:
                    with open(sec, encoding="utf-8") as fh:
                        other = json.load(fh)
                    other["_panopticon"]["domain"] = "ACC"
                    other["findings"][0]["domain"] = "ACC"
                    other["findings"][0]["code"] = "ACC-A1A"
                    acc = entries["review-app-ACC"]["out_file"]
                    runio._write_json(acc, other)
                    self.assertTrue(orchestrate.persist.is_done(entries["review-app-ACC"]))
                    os.replace(acc, sec)                # another entry's valid artifact

                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    loop_batch.recover_stale(d, req, "claude", "headless")
                self.assertFalse(os.path.lexists(sec))
                self.assertIn("kept 0 entries; rolled back 2", err.getvalue())
                self.assertIn("no receipt 1", err.getvalue())
                self.assertIn("artifact mismatch 1", err.getvalue())
                rows = ledger_mod.Ledger(crashed.run_dir).lines()
                self.assertTrue(any(row.get("entry_id") == "review-app-SEC"
                                    and row.get("status") == ledger_mod.ROLLED_BACK
                                    for row in rows), rows)

    def test_missing_or_edited_receipt_and_edited_ledger_row_roll_back(self):
        for mutation, reason in (("missing", "no receipt 2"),
                                 ("receipt", "ledger mismatch 1"),
                                 ("ledger", "ledger mismatch 1")):
            with self.subTest(mutation=mutation):
                d, floor = self._repo(floor=("SEC", "ACC"))
                crashed = self._leave_crashed_batch(d, floor)
                path = os.path.join(crashed.run_dir, "batch-1.json")
                doc = runio._load_json(path)
                settled = next(row for row in doc["entries"]
                               if row["id"] == "review-app-SEC")
                if mutation == "missing":
                    settled.pop("settlement")
                    runio._write_json(path, doc)
                elif mutation == "receipt":
                    settled["settlement"]["version"] = 2
                    runio._write_json(path, doc)
                else:
                    span = settled["settlement"]["ledger"]
                    with open(os.path.join(crashed.run_dir, base.LEDGER_FILE), "r+b") as fh:
                        fh.seek(span["start"])
                        raw = fh.read(span["end"] - span["start"])
                        self.assertIn(b"0.01", raw)
                        fh.seek(span["start"])
                        fh.write(raw.replace(b"0.01", b"0.02", 1))
                req = orchestrate.requests.previous_request(d)
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    loop_batch.recover_stale(d, req, "claude", "headless")
                self.assertIn("kept 0 entries; rolled back 2", err.getvalue())
                self.assertIn(reason, err.getvalue())
                self.assertFalse(os.path.exists(
                    next(entry["out_file"] for entry in req["entries"]
                         if entry["id"] == "review-app-SEC")))

    def test_a_repeated_entry_uses_this_batchs_exact_row_not_the_prior_attempt(self):
        class PriorAttempt(FakeRunner):
            def prepare(inner, run_dir, review_root):
                super().prepare(run_dir, review_root)
                if getattr(inner, "seeded", False):
                    return
                inner.seeded = True
                prior = base.RunResult.failed("review-app-SEC", "prior attempt")
                ledger_mod.Ledger(run_dir).record(
                    {"id": "review-app-SEC"}, "review", prior,
                    "headless", "claude")

        d, floor = self._repo(floor=("SEC", "ACC"))
        runner = PriorAttempt()
        with mock.patch.object(loop_batch, "rolled_back",
                               return_value="simulated process loss"):
            self._interrupt_mid_batch(d, floor, runner)
        self._stamp_crash_owner(runner.run_dir, pid=dead_pid())
        record = self._crash_record(runner.run_dir)
        receipt = next(row["settlement"] for row in record["entries"]
                       if row["id"] == "review-app-SEC")
        with open(os.path.join(runner.run_dir, base.LEDGER_FILE), "rb") as fh:
            raw = fh.read()
        self.assertGreater(receipt["ledger"]["start"], raw.find(b"review-app-SEC"))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            loop_batch.recover_stale(
                d, orchestrate.requests.previous_request(d), "claude", "headless")
        self.assertIn("kept 1 entries", err.getvalue())
        statuses = [(row["entry_id"], row.get("status"))
                    for row in ledger_mod.Ledger(runner.run_dir).lines()]
        self.assertEqual([("review-app-SEC", None), ("review-app-SEC", None),
                          ("review-app-ACC", ledger_mod.CANCELLED)], statuses)

    def test_a_receipt_write_failure_does_not_abort_or_change_the_clean_result(self):
        d, floor = self._repo(floor=("SEC",))
        runner, err = FakeRunner(), io.StringIO()
        with mock.patch.object(batch_mod.Batch, "settle", side_effect=OSError("full")), \
             contextlib.redirect_stderr(err):
            status = self._return_persist(d, floor, runner)
        self.assertEqual("complete", status["status"], status)
        self.assertIn("settlement receipt not recorded (OSError)", err.getvalue())
        self.assertEqual([], self._manifests(runner.run_dir))
        review_entry = next(entry for entry in orchestrate.requests.previous_request(d)["entries"]
                            if entry["id"].startswith("verify-"))
        # The clean run reached verify, its ordinary outputs are accepted, and
        # the ledger row shape did not grow a crash-only field.
        self.assertTrue(orchestrate.persist.is_done(review_entry))
        rows = ledger_mod.Ledger(runner.run_dir).lines()
        self.assertTrue(rows)
        self.assertFalse(any("settlement" in row for row in rows))

    def test_clean_run_outputs_match_the_pre_receipt_path(self):
        """#3351: receipts are transient batch state, not a clean-run output."""
        snapshots = []
        for receipts in (False, True):
            d, floor = self._repo(floor=("SEC",))
            runner = FakeRunner()
            patch = (contextlib.nullcontext() if receipts else
                     mock.patch.object(batch_mod.Batch, "settle", return_value=None))
            with patch:
                status = self._return_persist(d, floor, runner)
            self.assertEqual("complete", status["status"], status)
            self.assertEqual([], self._manifests(runner.run_dir))

            def stable(value):
                if isinstance(value, dict):
                    return {key: stable(item) for key, item in value.items()
                            if key not in ("run_id", "ts", "started_at", "finished_at",
                                           "duration_ms")}
                if isinstance(value, list):
                    return [stable(item) for item in value]
                return value

            outputs = {}
            for root, _dirs, files in os.walk(runner.run_dir):
                for name in files:
                    if not (name.startswith("findings-") or name.startswith("verdicts-")):
                        continue
                    path = os.path.join(root, name)
                    outputs[os.path.relpath(path, runner.run_dir)] = stable(
                        runio._load_json(path))
            snapshots.append({
                "launched": runner.launched,
                "outputs": outputs,
                "ledger": stable(ledger_mod.Ledger(runner.run_dir).lines()),
                "usage": stable(runio._load_json(
                    os.path.join(runner.run_dir, "usage.json"))),
                "attempts": review._cell_attempts(d),
            })
        self.assertEqual(snapshots[0], snapshots[1])

    def test_a_receipted_host_failure_is_kept_but_its_attempt_is_refunded(self):
        d, floor = self._repo(floor=("SEC", "ACC"))
        runner, inner = FakeRunner(), None
        runner.fail_once.add("review-app-SEC")
        inner = runner.run_entry

        def host_then_crash(entry, env):
            if entry["id"] == "review-app-ACC":
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if any(row.get("entry_id") == "review-app-SEC"
                           for row in ledger_mod.Ledger(runner.run_dir).lines()):
                        raise KeyboardInterrupt
                    threading.Event().wait(0.01)
                raise AssertionError("host-failure row did not land")
            result = inner(entry, env)
            result.failure_class = outage.HOST_FAILURE
            return result

        runner.run_entry = host_then_crash
        with mock.patch.object(loop_batch, "rolled_back",
                               return_value="simulated process loss"):
            self._return_persist(d, floor, runner)
        self._stamp_crash_owner(runner.run_dir, pid=dead_pid())
        receipt = next(row["settlement"] for row in self._crash_record(runner.run_dir)["entries"]
                       if row["id"] == "review-app-SEC")
        self.assertEqual([], receipt["artifacts"])
        self.assertIs(True, receipt["refund_attempt"])
        with contextlib.redirect_stderr(io.StringIO()):
            loop_batch.recover_stale(
                d, orchestrate.requests.previous_request(d), "claude", "headless")
        self.assertEqual({}, {key: value for key, value in review._cell_attempts(d).items()
                              if value})
        rows = ledger_mod.Ledger(runner.run_dir).lines()
        self.assertFalse(any(row.get("entry_id") == "review-app-SEC"
                             and row.get("status") for row in rows))
        self.assertTrue(any(row.get("entry_id") == "review-app-ACC"
                            and row.get("status") == ledger_mod.CANCELLED for row in rows))

    def test_a_receipted_retained_refusal_survives_recovery(self):
        d, floor = self._repo(floor=("SEC", "ACC"))
        runner, inner = FakeRunner(), None
        inner = runner.run_entry

        def refusal_then_crash(entry, env):
            if entry["id"] == "review-app-SEC":
                return base.RunResult(entry_id=entry["id"], ok=True,
                                      text="not a JSON reply", usage={}, cost_usd=0.01,
                                      model="m", session_id="s", denials=[], error=None)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if any(row.get("entry_id") == "review-app-SEC"
                       for row in ledger_mod.Ledger(runner.run_dir).lines()):
                    raise KeyboardInterrupt
                threading.Event().wait(0.01)
            return inner(entry, env)

        runner.run_entry = refusal_then_crash
        with mock.patch.object(loop_batch, "rolled_back",
                               return_value="simulated process loss"):
            self._return_persist(d, floor, runner)
        self._stamp_crash_owner(runner.run_dir, pid=dead_pid())
        receipt = next(row["settlement"] for row in self._crash_record(runner.run_dir)["entries"]
                       if row["id"] == "review-app-SEC")
        self.assertEqual(1, len(receipt["artifacts"]))
        retained = receipt["artifacts"][0]["path"]
        self.assertIn(os.sep + orchestrate.persist.REJECTED_DIR + os.sep, retained)
        with contextlib.redirect_stderr(io.StringIO()):
            loop_batch.recover_stale(
                d, orchestrate.requests.previous_request(d), "claude", "headless")
        self.assertTrue(os.path.isfile(retained))
        self.assertFalse(any(row.get("entry_id") == "review-app-SEC"
                             and row.get("status") for row
                             in ledger_mod.Ledger(runner.run_dir).lines()))

    def test_a_retained_artifact_must_have_the_complete_refusal_schema(self):
        d, _floor = self._repo(floor=("SEC",))
        run_dir = os.path.join(d, ".panopticon", "runs", "receipt-schema")
        retained = os.path.join(run_dir, orchestrate.persist.REJECTED_DIR,
                                "review-app-SEC-1.json")
        primary = os.path.join(run_dir, "findings-app-SEC.json")
        record = {"schema_version": 1, "entry_id": "review-app-SEC",
                  "attempt": 1, "kind": orchestrate.persist.REFUSAL,
                  "run_id": "run-1", "reason": "invalid envelope",
                  "recorded_at": "2026-11-02T00:00:00Z", "reply": "not JSON"}
        runio._write_json(retained, record)
        batch = mock.Mock()
        batch.entry_artifacts.return_value = [primary, retained]
        entry = {"id": "review-app-SEC", "out_file": primary}
        self.assertEqual([retained], [proof["path"] for proof in
                                     batch_settlement.artifact_proofs(
                                         entry, batch, "run-1")])

        mutations = (
            lambda row: row.pop("reply"),
            lambda row: row.update(entry_id="review-app-ACC"),
            lambda row: row.update(reason=[]),
            lambda row: row.update(truncated="yes"),
            lambda row: row.update(attacker_field=True),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                changed = copy.deepcopy(record)
                mutate(changed)
                runio._write_json(retained, changed)
                self.assertIsNone(batch_settlement.artifact_proofs(
                    entry, batch, "run-1"))

    def test_a_signed_matching_digest_does_not_bypass_artifact_shape(self):
        d, _floor = self._repo(floor=("SEC",))
        run_dir = os.path.join(d, ".panopticon", "runs", "receipt-shape")
        primary = os.path.join(run_dir, "findings-app-SEC.json")
        os.makedirs(run_dir, exist_ok=True)
        with open(primary, "wb") as fh:
            fh.write(b'{"findings": [')
        with open(primary, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        entry = {"id": "review-app-SEC", "out_file": primary,
                 "group": "app", "domain": "SEC"}
        self.assertFalse(batch_settlement.persist.is_done(entry))
        batch = mock.Mock()
        batch.entry_artifacts.return_value = [primary]
        with mock.patch.object(settlement_mod.run_stamp, "key", return_value=b"k" * 32):
            receipt = settlement_mod.issue(
                context={"run_id": "run-1", "review_root": os.path.abspath(d),
                         "namespace": "", "request_sha256": "a" * 64},
                batch=1, nonce="b" * 32, checkpoint="review",
                entry_id=entry["id"],
                ledger={"version": 1, "start": 0, "end": 1,
                        "sha256": "c" * 64},
                artifacts=[{"path": primary, "sha256": digest}],
                refund_attempt=False)
        self.assertFalse(batch_settlement._receipt_artifacts_match(
            entry, batch, receipt, "run-1"))

    def test_artifact_digest_refuses_nonregular_symlink_and_hard_links(self):
        d, _floor = self._repo(floor=("SEC",))
        root = os.path.join(d, ".panopticon", "runs", "receipt-links")
        os.makedirs(root, exist_ok=True)
        regular = os.path.join(root, "regular.json")
        with open(regular, "wb") as fh:
            fh.write(b"proof")
        self.assertEqual(hashlib.sha256(b"proof").hexdigest(),
                         batch_settlement._regular_sha256(regular))

        symlink = os.path.join(root, "symlink.json")
        os.symlink(regular, symlink)
        fifo = os.path.join(root, "fifo")
        os.mkfifo(fifo)
        hard_link = os.path.join(root, "hard-link.json")
        os.link(regular, hard_link)
        for kind, path in (("symlink", symlink), ("nonregular", fifo),
                           ("hard-link", hard_link)):
            with self.subTest(kind=kind), self.assertRaises(OSError):
                batch_settlement._regular_sha256(path)

    def test_an_interrupt_keeps_the_settled_entry_and_rolls_back_the_rest(self):
        # One entry done, one still running when the Ctrl-C lands. The finished
        # entry had crossed the settlement boundary -- reply persisted, real row
        # ledgered, usage rewritten (P07, `seen`) -- so #3349 keeps it exactly as
        # a clean close would; only the entry still in flight is rolled back.
        d, floor = self._repo(floor=("SEC", "ACC"))
        runner = FakeRunner()
        status, seen = self._interrupt_mid_batch(d, floor, runner)
        self.assertEqual(status["status"], "error", status)
        self.assertEqual({"reply": True, "ledger": True, "usage": True}, seen)
        self.assertIn("interrupted: 1 of 2 entries had settled and were kept; 1 unfinished "
                      "entries were rolled back to the checkpoint", status["message"])
        self.assertIn("re-run `driver loop` (without `--reset`) to resume them",
                      status["message"])
        self.assertIn("use `--reset` to discard the whole run", status["message"])
        self.assertNotIn("rollback incomplete", status["message"])

        # the settled reply stands and is done; the cut entry is pending again
        req = orchestrate.requests.load_dispatch_request(d) or {}
        entries = {e["id"]: e for e in req.get("entries") or []}
        self.assertTrue(os.path.isfile(entries["review-app-SEC"]["out_file"]))
        self.assertTrue(orchestrate.persist.is_done(entries["review-app-SEC"]))
        self.assertFalse(os.path.exists(entries["review-app-ACC"]["out_file"]))
        self.assertFalse(orchestrate.persist.is_done(entries["review-app-ACC"]))
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
            # #3349: the UNFINISHED entry's list -- a settled entry's leaves the record
            _unfinished(opened[0])["artifacts"].append(outside)
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
            _unfinished(opened[0])["artifacts"].append(outside)
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
        # #3351: the failed graceful flag left an UNFLAGGED crash record, but
        # SEC's signed receipt still proves its row and artifact on resume.
        self.assertTrue(os.path.isfile(completed))
        self.assertEqual({"app/SEC": 2, "app/ACC": 1},
                         runio._load_json(runio._pano(d, review._ATTEMPTS_FILE)))
        after = ledger_mod.Ledger(runner.run_dir).lines()
        self.assertEqual(before, after[:len(before)])
        rolled = [row for row in after if row.get("status") in (ledger_mod.ROLLED_BACK,
                                                                 ledger_mod.CANCELLED)]
        self.assertEqual([("review-app-ACC", ledger_mod.CANCELLED)],
                         [(row["entry_id"], row["status"]) for row in rolled])
        with open(outside, encoding="utf-8") as fh:
            self.assertEqual("keep", fh.read())

    def test_resume_keeps_a_receipted_entry_and_rolls_back_only_the_unfinished_peer(self):
        """#3351: crash recovery now agrees with #3349's settlement boundary."""
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
        self.assertNotIn("review-app-SEC", resumed.launched)
        self.assertIn("review-app-ACC", resumed.launched)
        self.assertIn("recovered stale batch", err.getvalue())
        self.assertIn("kept 1 entr", err.getvalue())
        self.assertIn("rolled back 1", err.getvalue())
        self.assertIn("no receipt 1", err.getvalue())
        self.assertEqual(self._manifests(run_dir), [])
        after = ledger_mod.Ledger(run_dir).lines()
        self.assertEqual(after[:len(before)], before)
        self.assertFalse(any(r.get("entry_id") == "review-app-SEC" and r.get("status")
                             in (ledger_mod.ROLLED_BACK, ledger_mod.CANCELLED)
                             for r in after))
        self.assertTrue(any(r.get("entry_id") == "review-app-ACC"
                            and r.get("status") == ledger_mod.CANCELLED for r in after))
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


