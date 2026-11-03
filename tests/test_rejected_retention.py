"""#1664: retention for `<run_dir>/rejected/`."""
import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

import scripts.batch_settlement as batch_settlement
import scripts.driver as driver
import scripts.phases.persist as persist
import scripts.phases.requests as requests
import scripts.phases.runio as runio
import scripts.rejected_retention as retention
import scripts.runners.batch as batch_mod

RUN = "run-1"


class _Folder(unittest.TestCase):
    def setUp(self):
        parent = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, parent, True)
        self.run = os.path.join(parent, ".panopticon", "runs", "t")
        self.rejected = os.path.join(self.run, persist.REJECTED_DIR)
        os.makedirs(self.rejected)

    def record(self, entry_id, attempt, *, run_id=RUN, at="2026-11-03T00:00:00Z", reply="r"):
        path = os.path.join(self.rejected, "%s-%d.json" % (
            requests.entry_file_component(entry_id), attempt))
        runio._write_json(path, {
            "schema_version": 1, "entry_id": entry_id, "attempt": attempt,
            "kind": persist.REFUSAL, "run_id": run_id, "reason": "bad envelope",
            "recorded_at": at, "reply": reply})
        return path

    def survivors(self):
        return sorted(name for name in os.listdir(self.rejected) if name != retention.TOMBSTONE)

    def tombstones(self):
        path = os.path.join(self.rejected, retention.TOMBSTONE)
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh]

    def prune(self, run_id=RUN):
        with contextlib.redirect_stderr(io.StringIO()):
            return retention.prune(self.run, run_id)


class TestTheRule(_Folder):
    def test_keeps_the_last_three_per_entry_and_numbering_continues(self):
        for attempt in range(1, 6):
            self.record("review-app-SEC", attempt)
        self.record("review-app-ACC", 1)
        removed = self.prune()
        self.assertEqual(["review-app-ACC-1.json", "review-app-SEC-3.json",
                          "review-app-SEC-4.json", "review-app-SEC-5.json"], self.survivors())
        self.assertEqual(2, len(removed))
        rows = self.tombstones()
        self.assertEqual([(1, "per_entry"), (2, "per_entry")],
                         sorted((row["attempt"], row["rule"]) for row in rows))
        self.assertTrue(all(row["run_id"] == RUN for row in rows))
        self.assertEqual(6, persist._next_attempt(self.rejected, "review-app-SEC"))

    def test_the_ceiling_evicts_oldest_first_but_never_an_entrys_newest(self):
        self.record("a", 1, at="2026-11-03T00:00:01Z")
        self.record("b", 1, at="2026-11-03T00:00:02Z")
        self.record("a", 2, at="2026-11-03T00:00:03Z")
        self.record("b", 2, at="2026-11-03T00:00:04Z")
        with mock.patch.object(retention, "RUN_CEILING", 1):
            self.prune()
        self.assertEqual(["a-2.json", "b-2.json"], self.survivors())
        self.assertEqual([("a", 1, "ceiling"), ("b", 1, "ceiling")],
                         [(r["entry_id"], r["attempt"], r["rule"]) for r in self.tombstones()])

    def test_the_ceiling_stops_once_the_folder_fits(self):
        old = self.record("a", 1, at="2026-11-03T00:00:01Z")
        self.record("b", 1, at="2026-11-03T00:00:02Z")
        self.record("a", 2, at="2026-11-03T00:00:03Z")
        self.record("b", 2, at="2026-11-03T00:00:04Z")
        total = sum(os.path.getsize(os.path.join(self.rejected, n)) for n in self.survivors())
        with mock.patch.object(retention, "RUN_CEILING", total - 1):
            self.prune()
        self.assertFalse(os.path.exists(old))
        self.assertEqual(["a-2.json", "b-1.json", "b-2.json"], self.survivors())


class TestOnlyThisRunsRecords(_Folder):
    def test_foreign_and_planted_files_neither_count_nor_go(self):
        for attempt in range(1, 6):
            self.record("other", attempt, run_id="run-0")
        self.record("mine", 1)
        planted = os.path.join(self.rejected, "mine-0.json")
        with open(planted, "w", encoding="utf-8") as fh:
            fh.write("x" * (retention.RECORD_MAX + 1))
        misnamed = os.path.join(self.rejected, "renamed.json")
        os.replace(self.record("mine", 2), misnamed)
        before = self.survivors()
        with mock.patch.object(retention, "RUN_CEILING", 1):
            self.assertEqual([], self.prune())
        self.assertEqual(before, self.survivors())

    def test_a_planted_giant_does_not_force_eviction(self):
        self.record("mine", 1, at="2026-11-03T00:00:01Z")
        self.record("mine", 2, at="2026-11-03T00:00:02Z")
        with open(os.path.join(self.rejected, "mine-9.json"), "w", encoding="utf-8") as fh:
            json.dump({"entry_id": "mine", "pad": "x" * 4096}, fh)
        mine = sum(os.path.getsize(os.path.join(self.rejected, "mine-%d.json" % n)) for n in (1, 2))
        with mock.patch.object(retention, "RUN_CEILING", mine):
            self.assertEqual([], self.prune())

    def test_an_oversized_record_is_not_read_counted_or_evicted(self):
        # Bigger than any record this build writes, so it is the target's however well-formed.
        big = self.record("big", 1, reply="x" * retention.RECORD_MAX)
        self.record("big", 2)
        with mock.patch.object(retention, "RUN_CEILING", 1):
            self.assertEqual([], self.prune())
        self.assertTrue(os.path.exists(big))

    def test_no_run_id_prunes_nothing(self):
        for attempt in range(1, 6):
            self.record("e", attempt, run_id=None)
        self.assertEqual([], self.prune(run_id=None))
        self.assertEqual(5, len(self.survivors()))


class TestBatchManifestsProtect(_Folder):
    def _open_batch(self, entry_id, *paths):
        out = os.path.join(self.run, "findings-%s.json" % entry_id)
        batch = batch_mod.Batch(self.run, 7, "review", [{"id": entry_id, "out_file": out}]).open()
        for path in paths:
            batch.add_artifact(entry_id, path)
        return batch, {"id": entry_id, "out_file": out}

    def test_an_open_batchs_record_survives_and_its_receipt_still_matches(self):
        listed = self.record("e", 1)
        for attempt in range(2, 6):
            self.record("e", attempt)
        batch, entry = self._open_batch("e", listed)
        receipt = {"artifacts": batch_settlement.artifact_proofs(entry, batch, RUN)}
        self.prune()
        self.assertTrue(os.path.exists(listed))
        self.assertEqual(["e-1.json", "e-3.json", "e-4.json", "e-5.json"], self.survivors())
        self.assertTrue(batch_settlement._receipt_artifacts_match(entry, batch, receipt, RUN))

    def test_an_unreadable_manifest_prunes_nothing(self):
        for attempt in range(1, 6):
            self.record("e", attempt)
        with open(batch_mod.manifest_path(self.run, 4), "w", encoding="utf-8") as fh:
            fh.write("{not json")
        self.assertEqual([], self.prune())
        self.assertEqual(5, len(self.survivors()))


class TestResolve(_Folder):
    def test_present_pruned_and_missing(self):
        paths = [self.record("e", attempt) for attempt in range(1, 5)]
        self.assertEqual(("present", paths[0]), retention.resolve(self.run, paths[0], RUN))
        self.prune()
        self.assertEqual(("pruned", "per_entry"), retention.resolve(self.run, paths[0], RUN))
        self.assertEqual(("missing", None), retention.resolve(self.run, paths[0], "run-2"))
        self.assertEqual(("missing", None), retention.resolve(
            self.run, os.path.join(self.rejected, "e-99.json"), RUN))
        self.assertEqual(("missing", None), retention.resolve(self.run, None, RUN))

    def test_a_planted_tombstone_row_with_a_foreign_run_id_stays_missing(self):
        gone = os.path.join(self.rejected, "e-1.json")
        with open(os.path.join(self.rejected, retention.TOMBSTONE), "w", encoding="utf-8") as fh:
            fh.write("garbage\n")
            fh.write(json.dumps({"run_id": "run-0", "path": gone, "rule": "per_entry"}) + "\n")
            fh.write(json.dumps({"run_id": RUN, "path": gone + "x", "rule": "per_entry"}) + "\n")
            fh.write(json.dumps({"run_id": RUN, "path": gone, "rule": "anything"}) + "\n")
        self.assertEqual(("missing", None), retention.resolve(self.run, gone, RUN))


class TestDriverPersistApplies(unittest.TestCase):
    def test_refused_replies_are_pruned_to_the_last_three(self):
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        os.makedirs(os.path.join(d, ".panopticon", "runs", "t"))
        driver.run_manifest.write_manifest(d, {
            "schema_version": 1, "run_id": "0123456789abcdef", "host": "claude",
            "security_mode": "standard", "created": "2026-09-20T00:00:00Z",
            "review_root": d, "target": d})
        out = os.path.join(d, ".panopticon", "runs", "t", "scout-app.json")
        requests.write_dispatch_request(
            d, "RID", "scout", None, [{"id": "scout-app", "out_file": out, "delivery": "return_json"}])
        reply = os.path.join(d, "reply.txt")
        with open(reply, "w", encoding="utf-8") as fh:
            fh.write("not an envelope")
        with contextlib.redirect_stderr(io.StringIO()):
            for _ in range(5):
                self.assertEqual(1, driver.main(["persist", "scout-app", "--file", reply, d]))
        folder = os.path.join(persist.run_dir(d), persist.REJECTED_DIR)
        self.assertEqual(["pruned.jsonl", "scout-app-3.json", "scout-app-4.json",
                          "scout-app-5.json"], sorted(os.listdir(folder)))


if __name__ == "__main__":
    unittest.main()
