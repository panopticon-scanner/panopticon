import json
import os
import shutil
import tempfile
import unittest

import scripts.runners.batch as batch_mod


class TestTheBatchManifest(unittest.TestCase):
    """#1662: focused contracts for the manifest written before a batch's
    first launch and used to roll back its artifacts after Ctrl-C."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)

    def _artifact(self, name, body="{}"):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
        return path

    def _batch(self, *names):
        entries = [{"id": n, "out_file": self._artifact(n + ".json")} for n in names]
        return batch_mod.Batch(self.dir, 3, "review", entries).open(), entries

    def test_the_manifest_lists_the_entry_ids_and_the_files_they_will_write(self):
        batch, entries = self._batch("review-app-SEC", "review-app-ACC")
        self.assertEqual(batch.path,
                         os.path.join(self.dir, "batch-3.json"))
        with open(batch.path, encoding="utf-8") as fh:
            doc = json.load(fh)
        self.assertEqual(1, doc["schema_version"])
        self.assertEqual((3, "review"), (doc["batch"], doc["checkpoint"]))
        self.assertRegex(doc["opened_at"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        self.assertEqual(["review-app-SEC", "review-app-ACC"],
                         [row["id"] for row in doc["entries"]])
        self.assertEqual([[e["out_file"]] for e in entries],
                         [row["artifacts"] for row in doc["entries"]])

    def test_roll_back_deletes_what_it_lists_and_nothing_else(self):
        # The "never a glob" rule: a prior phase's output sits in the same
        # folder, and on a redteam target so does whatever the tree planted
        # with a matching name.
        batch, entries = self._batch("review-app-SEC")
        bystander = self._artifact("coverage-app.json")
        removed, problems = batch.roll_back()
        self.assertEqual(([entries[0]["out_file"]], []), (removed, problems))
        self.assertFalse(os.path.exists(entries[0]["out_file"]))
        self.assertTrue(os.path.isfile(bystander))
        self.assertFalse(os.path.exists(batch.path), "the manifest goes with it")

    def test_an_artifact_that_was_never_written_is_not_a_problem(self):
        # Most of a cancelled batch never got that far.
        batch, entries = self._batch("review-app-SEC")
        os.remove(entries[0]["out_file"])
        self.assertEqual(([], []), batch.roll_back())

    def test_a_record_the_batch_wrote_later_is_rolled_back_too(self):
        # `persist.retain_rejected` names the file only once it has written
        # it, so the manifest gains it mid-batch rather than at open.
        batch, entries = self._batch("review-app-SEC")
        kept = self._artifact("rejected-review-app-SEC-1.json")
        batch.add_artifact("review-app-SEC", kept)
        batch.add_artifact("review-app-SEC", kept)          # idempotent
        with open(batch.path, encoding="utf-8") as fh:
            self.assertEqual([entries[0]["out_file"], kept],
                             json.load(fh)["entries"][0]["artifacts"])
        removed, _problems = batch.roll_back()
        self.assertEqual({entries[0]["out_file"], kept}, set(removed))

    def test_a_record_for_an_entry_not_in_the_batch_is_ignored(self):
        batch, _entries = self._batch("review-app-SEC")
        batch.add_artifact("review-app-ACC", self._artifact("stray.json"))
        batch.add_artifact("review-app-SEC", None)
        self.assertEqual(1, len(batch.artifacts()))

    def test_an_artifact_planted_as_a_symlink_loses_the_link_not_the_target(self):
        batch, entries = self._batch("review-app-SEC")
        target = self._artifact("elsewhere.json", "precious")
        os.remove(entries[0]["out_file"])
        os.symlink(target, entries[0]["out_file"])
        batch.roll_back()
        self.assertFalse(os.path.lexists(entries[0]["out_file"]))
        self.assertTrue(os.path.isfile(target))

    def test_a_path_that_cannot_be_removed_is_reported_not_raised(self):
        # The loop is already on its way out with an interrupt to explain; a
        # rollback that could not finish is something the operator is TOLD,
        # not something that replaces the interrupt's own message.
        batch, entries = self._batch("review-app-SEC")
        os.remove(entries[0]["out_file"])
        os.makedirs(os.path.join(entries[0]["out_file"], "child"))
        removed, problems = batch.roll_back()
        self.assertEqual([], removed)
        self.assertEqual(1, len(problems))
        self.assertIn(entries[0]["out_file"], problems[0])

    def test_close_removes_the_manifest_and_a_second_close_is_quiet(self):
        batch, _entries = self._batch("review-app-SEC")
        self.assertEqual([], batch.close())
        self.assertFalse(os.path.exists(batch.path))
        self.assertEqual([], batch.close())

    def test_an_empty_batch_lists_nothing(self):
        batch = batch_mod.Batch(self.dir, 1, "scout", []).open()
        self.assertEqual(([], []), (batch.entry_ids(), batch.artifacts()))
        self.assertEqual(([], []), batch.roll_back())

    def test_registration_refuses_paths_outside_the_run_before_manifest_creation(self):
        sibling = self.dir + "-sibling"
        os.mkdir(sibling)
        self.addCleanup(shutil.rmtree, sibling, True)
        outside = os.path.join(sibling, "keep.json")
        with open(outside, "w", encoding="utf-8") as fh:
            fh.write("keep")
        paths = (outside, os.path.join(self.dir, "..", os.path.basename(sibling), "keep.json"))
        for path in paths:
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "escapes the run folder"):
                batch_mod.Batch(self.dir, 3, "review", [{"id": "e", "out_file": path}]).open()
            self.assertFalse(os.path.lexists(batch_mod.manifest_path(self.dir, 3)))
        with open(outside, encoding="utf-8") as fh:
            self.assertEqual("keep", fh.read())

    def test_registration_refuses_a_linked_parent_even_when_it_points_inside(self):
        real = os.path.join(self.dir, "real")
        os.mkdir(real)
        link = os.path.join(self.dir, "linked")
        os.symlink(real, link)
        for destination in (real, self.dir + "-outside"):
            with self.subTest(destination=destination):
                os.unlink(link)
                os.symlink(destination, link)
                with self.assertRaisesRegex(ValueError, "symlink"):
                    batch_mod.Batch(self.dir, 3, "review", [
                        {"id": "e", "out_file": os.path.join(link, "keep.json")}]).open()
                self.assertFalse(os.path.lexists(batch_mod.manifest_path(self.dir, 3)))

    def test_add_artifact_refuses_outside_and_linked_parent_without_changing_record(self):
        batch, _entries = self._batch("review-app-SEC")
        with open(batch.path, "rb") as fh:
            before = fh.read()
        outside = os.path.join(os.path.dirname(self.dir), "outside.json")
        link = os.path.join(self.dir, "linked")
        os.symlink(self.dir, link)
        for path in (outside, os.path.join(link, "keep.json"), None):
            if path is None:
                with self.assertRaises(ValueError):
                    batch.add_artifact("review-app-SEC", 42)
            else:
                with self.assertRaises(ValueError):
                    batch.add_artifact("review-app-SEC", path)
            with open(batch.path, "rb") as fh:
                self.assertEqual(before, fh.read())
            self.assertEqual(1, len(batch.artifacts()))

    def test_rollback_validates_all_artifacts_before_deleting_any(self):
        batch, entries = self._batch("review-app-SEC")
        outside = os.path.join(os.path.dirname(self.dir), "keep-outside.json")
        with open(outside, "w", encoding="utf-8") as fh:
            fh.write("keep")
        self.addCleanup(lambda: os.path.exists(outside) and os.remove(outside))
        batch.entries[0]["artifacts"].append(outside)
        removed, problems = batch.roll_back()
        self.assertEqual([], removed)
        self.assertTrue(problems)
        self.assertIn("unsafe batch artifact", problems[0])
        self.assertTrue(os.path.isfile(entries[0]["out_file"]))
        self.assertTrue(os.path.isfile(batch.path))
        with open(outside, encoding="utf-8") as fh:
            self.assertEqual("keep", fh.read())

    def test_rollback_refuses_a_parent_replaced_with_a_link(self):
        parent = os.path.join(self.dir, "owned")
        other = os.path.join(self.dir, "other")
        os.mkdir(parent)
        os.mkdir(other)
        owned = os.path.join(parent, "keep.json")
        with open(owned, "w", encoding="utf-8") as fh:
            fh.write("original")
        batch = batch_mod.Batch(self.dir, 3, "review", [{"id": "e", "out_file": owned}]).open()
        os.rename(parent, parent + "-moved")
        with open(os.path.join(other, "keep.json"), "w", encoding="utf-8") as fh:
            fh.write("keep")
        os.symlink(other, parent)
        removed, problems = batch.roll_back()
        self.assertEqual([], removed)
        self.assertTrue(problems)
        self.assertTrue(os.path.isfile(batch.path))
        with open(os.path.join(other, "keep.json"), encoding="utf-8") as fh:
            self.assertEqual("keep", fh.read())

    def test_rollback_refuses_a_parent_replaced_with_another_directory(self):
        parent = os.path.join(self.dir, "owned")
        os.mkdir(parent)
        owned = os.path.join(parent, "keep.json")
        with open(owned, "w", encoding="utf-8") as fh:
            fh.write("original")
        batch = batch_mod.Batch(self.dir, 3, "review", [{"id": "e", "out_file": owned}]).open()
        os.rename(parent, parent + "-moved")
        os.mkdir(parent)
        with open(owned, "w", encoding="utf-8") as fh:
            fh.write("keep")
        removed, problems = batch.roll_back()
        self.assertEqual([], removed)
        self.assertTrue(problems)
        self.assertTrue(os.path.isfile(batch.path))
        with open(owned, encoding="utf-8") as fh:
            self.assertEqual("keep", fh.read())

    def test_rollback_refuses_malformed_recovered_artifacts(self):
        for bad in (42, "bad\0path", {"path": "bad"}):
            with self.subTest(bad=bad):
                batch, entries = self._batch("review-app-SEC")
                batch.entries[0]["artifacts"].append(bad)
                removed, problems = batch.roll_back()
                self.assertEqual([], removed)
                self.assertTrue(problems)
                self.assertTrue(os.path.isfile(entries[0]["out_file"]))
                self.assertTrue(os.path.isfile(batch.path))
                batch.entries[0]["artifacts"].pop()
                self.assertEqual([], batch.close())

    def test_system_alias_above_the_run_folder_is_accepted(self):
        if not os.path.islink("/tmp") or not self.dir.startswith("/private/tmp/"):
            self.skipTest("no /tmp to /private/tmp alias")
        aliased = os.path.join("/tmp", os.path.relpath(self.dir, "/private/tmp"))
        batch = batch_mod.Batch(aliased, 3, "review", [
            {"id": "e", "out_file": os.path.join(aliased, "owned.json")}]).open()
        with open(os.path.join(self.dir, "owned.json"), "w", encoding="utf-8") as fh:
            fh.write("owned")
        removed, problems = batch.roll_back()
        self.assertEqual(([os.path.join(aliased, "owned.json")], []), (removed, problems))
        self.assertFalse(os.path.lexists(os.path.join(self.dir, "owned.json")))

    def test_replaced_run_directory_refuses_close_and_manifest_rewrite(self):
        batch, _entries = self._batch("review-app-SEC")
        moved = self.dir + "-moved"
        self.addCleanup(shutil.rmtree, moved, True)
        os.rename(self.dir, moved)
        os.mkdir(self.dir)
        planted = batch_mod.manifest_path(self.dir, 3)
        with open(planted, "w", encoding="utf-8") as fh:
            fh.write("keep")
        self.assertTrue(batch.close())
        with self.assertRaises(ValueError):
            batch.begin_recovery()
        with open(planted, encoding="utf-8") as fh:
            self.assertEqual("keep", fh.read())
        self.assertTrue(os.path.isfile(batch_mod.manifest_path(moved, 3)))
