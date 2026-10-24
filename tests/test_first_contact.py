"""First contact (#3271, the #3173 audit's G2): one readiness assessment at run
start that halts, with a fixed reason, on a tracked or pre-planted
`.panopticon/`, a symlink under it, or a file hard-linked outside the target --
in git trees and in non-git (tarball) trees alike. And the run stamp that
decides "ours" without trusting anything in the tree."""
import contextlib
import io
import json
import os
import re
import shutil
import stat
import tempfile
import threading
import unittest
from unittest import mock

import scripts.driver as driver
import scripts.loop_batch as loop_batch
import scripts.orchestrate as orchestrate
import scripts.phases.requests as requests
import scripts.phases.runio as runio
import scripts.first_contact as first_contact
import scripts.phases.setup as setup
import scripts.run_manifest as run_manifest
import scripts.run_stamp as run_stamp
import scripts.safe_write as safe_write
from tests._test_helpers import adopt_panopticon, hard_link_or_skip
from tests.tools.git_repo import make_git_repo, plant_fsmonitor_command

# The fixed reasons, verbatim: an operator reads these, and a remedy that
# drifts is a remedy that stops working.
H1 = (".panopticon/ is tracked in the target's git index; panopticon never commits its "
      "artifact directory -- remove it from the index (git rm -r --cached .panopticon) or "
      "review a clean clone")
H2 = (".panopticon/ was not created by a panopticon run on this machine (its run stamp does "
      "not verify); move it aside (mv .panopticon .panopticon.old) or pass --reset, and re-run")
H3 = (".panopticon/%s is a symlink, and the artifact directory holds none but the run's own "
      "links; remove it and re-run")
H4 = ("%s is hard-linked outside the target (st_nlink=%d, %d in-tree names); review a copy "
      "without hard links (a plain cp)")
H5 = "the target cannot be assessed at first contact: %s: %s"


class TestTheReasonsAreFixed(unittest.TestCase):
    def test_each_reason_is_the_ruled_sentence(self):
        self.assertEqual((H1, H2, H3, H4, H5), (first_contact.H1, first_contact.H2, first_contact.H3,
                                                first_contact.H4, first_contact.H5))


class _Trees(unittest.TestCase):
    def _dir(self):
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        return d

    def _tree(self, git):
        """A target to review: a git checkout, or a plain extracted tarball."""
        if git:
            return make_git_repo(test_case=self, files={"src/a.py": "x = 1\n"})
        d = self._dir()
        os.makedirs(os.path.join(d, "src"))
        with open(os.path.join(d, "src", "a.py"), "w", encoding="utf-8") as fh:
            fh.write("x = 1\n")
        return d

    def _run(self, root, *extra):
        with contextlib.redirect_stderr(io.StringIO()):
            return driver.run(driver.build_parser().parse_args(["run", root, "--no-tools", *extra]),
                              phases=())

    def _halts(self, root, reason, *extra):
        status = self._run(root, *extra)
        self.assertEqual(("error", reason), (status["status"], status.get("message")))
        self.assertNotIn("\n", status["message"])
        return status


class TestATrackedPanopticonHalts(_Trees):
    def test_a_committed_artifact_directory_halts_and_reset_does_not_lift_it(self):
        root = make_git_repo(test_case=self, files={"src/a.py": "x = 1\n",
                                                    ".panopticon/groups.json": "{}\n"})
        self._halts(root, H1)
        self._halts(root, H1, "--reset")
        with open(os.path.join(root, ".panopticon", "groups.json"), encoding="utf-8") as fh:
            self.assertEqual("{}\n", fh.read())          # a tracked file is never touched


class TestAPrePlantedPanopticonHalts(_Trees):
    def _plant_manifest(self, root):
        """The G2 tree: a `run-manifest.json` naming this very review root, as a
        tarball extracted at a predictable path can ship, with its own flags."""
        pano = os.path.join(root, ".panopticon")
        os.makedirs(pano)
        with open(os.path.join(pano, "run-manifest.json"), "w", encoding="utf-8") as fh:
            json.dump({"schema_version": 1, "run_id": "planted", "host": "claude",
                       "review_root": root, "target": root, "flags": {"tools": False},
                       "created": "2026-10-24T00:00:00Z", "security_mode": "standard",
                       "scope": {"mode": "repo", "target": None}}, fh)

    def test_a_planted_manifest_halts_in_a_tarball_and_a_git_tree(self):
        for git in (False, True):
            with self.subTest(git=git):
                root = self._tree(git)
                self._plant_manifest(root)
                self._halts(root, H2)
                with open(os.path.join(root, ".panopticon", "run-manifest.json"),
                          encoding="utf-8") as fh:
                    self.assertEqual("planted", json.load(fh)["run_id"])   # never adopted

    def test_a_mark_copied_from_another_checkout_does_not_verify(self):
        elsewhere, root = self._tree(False), self._tree(False)
        self.assertNotEqual("error", self._run(elsewhere)["status"])     # a run of ours there
        os.makedirs(os.path.join(root, ".panopticon"))
        shutil.copy(os.path.join(elsewhere, ".panopticon", "owner.json"),
                    os.path.join(root, ".panopticon", "owner.json"))
        self._halts(root, H2)

    def test_a_mark_for_this_tree_with_a_forged_stamp_does_not_verify(self):
        root = self._tree(False)
        os.makedirs(os.path.join(root, ".panopticon"))
        with open(os.path.join(root, ".panopticon", "owner.json"), "w", encoding="utf-8") as fh:
            json.dump({"run_id": "planted", "review_root": root, "stamp": "0" * 64}, fh)
        self._halts(root, H2)

    def test_reset_moves_it_aside_intact_and_the_run_starts_fresh(self):
        root = self._tree(False)
        self._plant_manifest(root)
        status = self._run(root, "--reset")
        self.assertNotEqual("error", status["status"], status)
        (aside,) = [n for n in os.listdir(root) if n.startswith(".panopticon.unverified-")]
        with open(os.path.join(root, aside, "run-manifest.json"), encoding="utf-8") as fh:
            self.assertEqual("planted", json.load(fh)["run_id"])      # moved, not destroyed
        manifest = run_manifest.load_manifest(root)
        self.assertNotEqual("planted", manifest["run_id"])
        self.assertTrue(run_stamp.verifies(first_contact._load(
            os.path.join(root, ".panopticon", "owner.json"))))

    def test_a_tarball_re_extracted_over_a_scanned_checkout_halts(self):
        # Review C1: `owner.json` proves the DIRECTORY is ours, not the files in
        # it. v2 of the tarball ships `.panopticon/run-manifest.json` (and no
        # mark) over a tree a run of ours already scanned.
        for manifest in ("run-manifest.json", "setup-manifest.json"):
            with self.subTest(manifest=manifest):
                root = self._tree(False)
                self.assertNotEqual("error", self._run(root)["status"])
                pano = os.path.join(root, ".panopticon")
                with open(os.path.join(pano, manifest), "w", encoding="utf-8") as fh:
                    json.dump({"schema_version": 1, "run_id": "evil", "host": "claude",
                               "review_root": root, "target": root, "flags": {"tools": False},
                               "first_contact": {"files": 1}}, fh)
                walks = []
                real = first_contact._outside_links
                with mock.patch.object(first_contact, "_outside_links",
                                       side_effect=lambda *a, **k: walks.append(1) or real(*a, **k)):
                    self._halts(root, H2)
                    self.assertEqual([], walks)
                    self.assertNotEqual("error", self._run(root, "--reset")["status"])
                    self.assertEqual([1], walks)            # the walk is not skipped
                self.assertNotEqual("evil", run_manifest.load_manifest(root)["run_id"])

    def test_a_manifest_of_an_earlier_mark_does_not_resume_under_a_new_one(self):
        # Every manifest is signed over the mark it was written under, so even a
        # real one of ours, from a `.panopticon/` since moved aside, does not
        # pass as this directory's.
        root = self._tree(False)
        self.assertNotEqual("error", self._run(root)["status"])
        path = os.path.join(root, ".panopticon", "run-manifest.json")
        with open(path, encoding="utf-8") as fh:
            earlier = fh.read()
        os.rename(os.path.join(root, ".panopticon"), os.path.join(root, ".panopticon.old"))
        self.assertNotEqual("error", self._run(root)["status"])          # a new mark
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(earlier)
        self._halts(root, H2)

    def _owned(self):
        root = self._tree(False)
        self.assertNotEqual("error", self._run(root)["status"])
        pano = os.path.join(root, ".panopticon")
        with open(os.path.join(pano, "owner.json"), encoding="utf-8") as fh:
            owner = json.load(fh)
        with open(os.path.join(pano, "run-manifest.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
        return root, pano, owner, manifest

    def _rewrite(self, pano, manifest):
        with open(os.path.join(pano, "run-manifest.json"), "w", encoding="utf-8") as fh:
            json.dump(manifest, fh)

    def test_a_manifest_must_carry_its_own_stamp_not_just_the_mark_s_id(self):
        root, pano, owner, manifest = self._owned()
        self._rewrite(pano, dict(manifest, run_id="other", stamp="0" * 64))
        self._halts(root, H2)

    def test_the_mark_s_id_is_under_the_manifest_s_stamp(self):
        # A real manifest of an earlier mark, its `owner` field rewritten to
        # this mark's id: the stamp was made over the old one.
        root, pano, _, earlier = self._owned()
        os.rename(pano, pano + ".old")
        self.assertNotEqual("error", self._run(root)["status"])          # a new mark
        with open(os.path.join(pano, "owner.json"), encoding="utf-8") as fh:
            now = json.load(fh)["run_id"]
        self.assertNotEqual(now, earlier["owner"])
        self._rewrite(pano, dict(earlier, owner=now))
        self._halts(root, H2)

    def test_a_manifest_stamped_for_another_tree_does_not_verify_here(self):
        root, pano, owner, manifest = self._owned()
        self._rewrite(pano, first_contact.bind(root, dict(manifest, review_root="/elsewhere")))
        with self.assertRaisesRegex(first_contact.FirstContactHalt, "^%s$" % re.escape(H2)):
            first_contact.assess_artifacts(root)

    def test_driver_setup_halts_on_the_same_tree(self):
        root = self._tree(True)
        self._plant_manifest(root)
        status = setup.run_setup_flow(driver.build_parser().parse_args(["setup", root]))
        self.assertEqual(("error", H2), (status["status"], status["message"]))

    def test_a_run_of_ours_resumes_and_an_empty_directory_is_ours(self):
        root = self._tree(True)
        os.makedirs(os.path.join(root, ".panopticon"))
        for _ in range(2):
            self.assertNotEqual("error", self._run(root)["status"])
        self.assertTrue(run_stamp.verifies(first_contact._load(
            os.path.join(root, ".panopticon", "owner.json"))))


# The ruled cap, as a literal: the pins below must fail on behaviour, not on a
# missing name, wherever the cap is not enforced.
_CAP = 1 << 20


class TestAManifestNoReaderCanTrustHalts(_Trees):
    """#3271 F0: a manifest that is THERE but cannot be read whole is trusted by
    no reader, so it halts H2 rather than passing as "no manifest" -- and every
    reader shares one cap, so the document verified is the one resumed."""

    def _owned(self):
        root = self._tree(False)
        self.assertNotEqual("error", self._run(root)["status"])
        pano = os.path.join(root, ".panopticon")
        with open(os.path.join(pano, "run-manifest.json"), encoding="utf-8") as fh:
            return root, pano, json.load(fh)

    def _plant(self, pano, name, data):
        path = os.path.join(pano, name)
        with contextlib.suppress(FileNotFoundError):
            os.remove(path)
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def _assess_halts_h2(self, root):
        with self.assertRaisesRegex(first_contact.FirstContactHalt, "^%s$" % re.escape(H2)):
            first_contact.assess_artifacts(root)

    def _padded(self, manifest, size):
        body = json.dumps(manifest).encode("utf-8")
        return body[:-1] + b" " * (size - len(body)) + b"}"

    def test_an_unbound_manifest_padded_past_the_cap_halts(self):
        root, pano, manifest = self._owned()
        planted = dict(manifest, run_id="planted", stamp="0" * 64)
        for name in ("run-manifest.json", "setup-manifest.json"):
            with self.subTest(name=name):
                self._plant(pano, name, self._padded(planted, _CAP + 1))
                self._assess_halts_h2(root)
                os.remove(os.path.join(pano, name))
        self._plant(pano, "run-manifest.json",
                    self._padded(planted, _CAP + 1))
        self._halts(root, H2)

    def test_our_own_manifest_past_the_cap_is_refused_by_every_reader(self):
        # The cap is the CONSUMER's too: `load_manifest` refuses what first
        # contact cannot verify, rather than parsing past it.
        root, pano, manifest = self._owned()
        self._plant(pano, "run-manifest.json",
                    self._padded(manifest, _CAP + 1))
        self.assertIsNone(run_manifest.load_manifest(root))
        self._assess_halts_h2(root)

    def test_exactly_the_cap_is_read_and_resumes(self):
        root, pano, manifest = self._owned()
        self._plant(pano, "run-manifest.json", self._padded(manifest, _CAP))
        self.assertEqual(manifest, run_manifest.load_manifest(root))
        self.assertEqual(manifest, first_contact.assess_artifacts(root)["run-manifest.json"])

    def test_a_fifo_manifest_halts_without_blocking_any_reader(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("no FIFOs on this platform")
        root, pano, _ = self._owned()
        for name in ("run-manifest.json", "setup-manifest.json"):
            with self.subTest(name=name):
                path = os.path.join(pano, name)
                with contextlib.suppress(FileNotFoundError):
                    os.remove(path)
                os.mkfifo(path)
                outcome = []

                def readers():
                    outcome.append((run_manifest.load_manifest(root), setup.load_setup_manifest(root)))
                    try:
                        first_contact.assess_artifacts(root)
                    except first_contact.FirstContactHalt as exc:
                        outcome.append(str(exc))

                worker = threading.Thread(target=readers, daemon=True)
                worker.start()
                worker.join(10)
                if worker.is_alive():
                    with contextlib.suppress(OSError):   # unblock the reader we leaked
                        os.close(os.open(path, os.O_WRONLY | os.O_NONBLOCK))
                self.assertEqual([(None, None), H2], outcome)
                os.remove(path)

    def test_a_document_too_deep_to_trust_halts_and_never_overflows(self):
        root, pano, _ = self._owned()
        for depth in (65, 200_000):
            with self.subTest(depth=depth):
                self._plant(pano, "run-manifest.json", b"[" * depth + b"]" * depth)
                self._assess_halts_h2(root)
                self.assertIsNone(run_manifest.load_manifest(root))

    def test_a_present_manifest_that_is_not_an_object_halts(self):
        root, pano, _ = self._owned()
        for name in ("run-manifest.json", "setup-manifest.json"):
            for data in (b"[]", b"null", b"7", b"\xff\xfe{}", b"{", b""):
                with self.subTest(name=name, data=data):
                    self._plant(pano, name, data)
                    self._assess_halts_h2(root)
                    self.assertEqual((None, None), (run_manifest.load_manifest(root),
                                                    setup.load_setup_manifest(root)))
                    os.remove(os.path.join(pano, name))

    def test_only_an_absent_manifest_is_no_manifest(self):
        root, pano, _ = self._owned()
        os.remove(os.path.join(pano, "run-manifest.json"))
        self.assertIsNone(first_contact.assess_artifacts(root)["run-manifest.json"])

    def test_bind_over_an_unreadable_mark_binds_to_no_owner(self):
        # bind() runs after first contact verified the mark; a mark that went
        # bad in between binds the manifest to nothing, which no later first
        # contact verifies -- never a crash on the sentinel.
        root, pano, manifest = self._owned()
        self._plant(pano, "owner.json", b"[]")
        self.assertIsNone(first_contact.bind(root, dict(manifest))["owner"])

    def test_the_cap_is_the_ruled_one(self):
        self.assertEqual(_CAP, safe_write.MANIFEST_MAX_BYTES)

    def test_every_manifest_reader_takes_the_one_cap(self):
        # One number, read at call time: lower it, and the checker and every
        # consumer refuse the same document together.
        root, pano, manifest = self._owned()
        self._plant(pano, "setup-manifest.json", json.dumps(first_contact.bind(root, dict(manifest))).encode())
        self.assertIsNotNone(setup.load_setup_manifest(root))
        with mock.patch.object(safe_write, "MANIFEST_MAX_BYTES", 16):
            self.assertIsNone(run_manifest.load_manifest(root))
            self.assertIsNone(setup.load_setup_manifest(root))
            self.assertIs(first_contact.UNREADABLE,
                          first_contact._load(os.path.join(pano, "run-manifest.json")))
            self._assess_halts_h2(root)


class TestASymlinkUnderPanopticonHalts(_Trees):
    def test_a_planted_link_halts_in_a_tarball_and_a_git_tree(self):
        for git in (False, True):
            with self.subTest(git=git):
                root, outside = self._tree(git), self._dir()
                self.assertNotEqual("error", self._run(root)["status"])      # a run of ours
                shutil.rmtree(os.path.join(root, ".panopticon", "runs"))
                os.symlink(outside, os.path.join(root, ".panopticon", "runs"))
                self._halts(root, H3 % "runs")
                self.assertEqual([], os.listdir(outside))

    def test_a_link_where_a_reset_clears_halts_too(self):
        # #3271 B2's contract change: the active run folder, tools/ and
        # verdicts/ as a planted link are H3 like any other stray link.
        root = self._tree(False)
        self.assertNotEqual("error", self._run(root)["status"])
        pano = os.path.join(root, ".panopticon")
        tag = run_manifest.run_tag(run_manifest.load_manifest(root))
        with contextlib.suppress(FileNotFoundError):      # it would follow runs/<tag> out
            os.unlink(os.path.join(pano, "runs", "latest"))
        for rel in ("runs/" + tag, "tools", "verdicts"):
            with self.subTest(rel=rel):
                outside = self._dir()
                path = os.path.join(pano, rel)
                if os.path.isdir(path):
                    shutil.rmtree(path)
                os.symlink(outside, path)
                self._halts(root, H3 % rel)
                self.assertEqual([], os.listdir(outside))
                os.unlink(path)

    def test_the_artifact_directory_as_a_plain_file_halts(self):
        root = self._tree(False)
        with open(os.path.join(root, ".panopticon"), "w", encoding="utf-8") as fh:
            fh.write("not a directory")
        self._halts(root, H5 % (".panopticon", "not a directory"))

    def test_the_artifact_directory_itself_as_a_link_halts(self):
        root, outside = self._tree(False), self._dir()
        os.symlink(outside, os.path.join(root, ".panopticon"))
        self._halts(root, H3 % "")
        self.assertEqual([], os.listdir(outside))

    def test_the_run_s_own_links_pass_and_a_lookalike_does_not(self):
        root = self._tree(False)
        adopt_panopticon(root)
        pano = os.path.join(root, ".panopticon")
        os.makedirs(os.path.join(pano, "runs", "tag-1"))
        os.symlink("tag-1", os.path.join(pano, "runs", "latest"))
        os.symlink("tag-1-report.json", os.path.join(pano, "report.json"))
        self.assertEqual([], first_contact._stray_links(pano))
        os.symlink(os.path.join(pano, "runs", "tag-1"), os.path.join(pano, "runs", "abs"))
        os.symlink("../../src", os.path.join(pano, "report.json.html"))      # escapes
        os.symlink("runs/tag-1", os.path.join(pano, "groups.json"))          # not a name of ours
        self.assertEqual(["groups.json", "report.json.html", "runs/abs"],
                         first_contact._stray_links(pano))
        self._halts(root, H3 % "groups.json" + first_contact.MORE % 2)
        for name in ("groups.json", "report.json.html", "runs/abs"):
            os.unlink(os.path.join(pano, name))
        os.unlink(os.path.join(pano, "runs", "latest"))
        os.symlink(os.path.join(pano, "runs", "tag-1"), os.path.join(pano, "runs", "latest"))
        self.assertEqual(["runs/latest"], first_contact._stray_links(pano))   # absolute: not ours


class TestDriverLoopMakesFirstContactFirst(_Trees):
    """#3271 B2: `driver loop` and `driver loop --setup` make first contact
    before they resolve a host off the manifest, read the outgoing request, or
    recover a crash record -- every one of which first contact vouches for."""

    def _loop(self, root, *extra, resolved=None):
        args = driver.build_parser().parse_args(["loop", root, "--no-tools", *extra])
        with contextlib.ExitStack() as stack:
            spies = [stack.enter_context(mock.patch.object(owner, name))
                     for owner, name in ((runio, "resolve_host"), (requests, "previous_request"),
                                         (loop_batch, "recover_stale"))]
            if resolved is not None:
                stack.enter_context(mock.patch.object(runio, "resolve_review_root",
                                                      return_value=resolved))
            stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            status = orchestrate.loop(args)
        for spy in spies:
            spy.assert_not_called()
        return status

    def _planted_outside(self):
        """A `.panopticon/`'s worth of planted records, outside the tree."""
        outside = self._dir()
        os.makedirs(os.path.join(outside, "runs", "t", "rejected"))
        for rel, body in (("run-manifest.json", {"run_id": "planted", "host": "claude"}),
                          ("runs/t/batch-1.json", {"entries": [{"id": "e"}]}),
                          ("runs/t/rejected/e-1.json", {"entry_id": "e"})):
            with open(os.path.join(outside, rel), "w", encoding="utf-8") as fh:
                json.dump(body, fh)
        return outside, sorted(os.walk(outside))

    def test_a_linked_artifact_directory_halts_both_loops_and_nothing_it_names_moves(self):
        for extra in ((), ("--setup",)):
            with self.subTest(setup=bool(extra)):
                root = self._tree(True)
                outside, before = self._planted_outside()
                os.symlink(outside, os.path.join(root, ".panopticon"))
                status = self._loop(root, *extra)
                self.assertEqual(("error", H3 % ""), (status["status"], status["message"]))
                self.assertEqual(before, sorted(os.walk(outside)))

    def test_a_planted_manifest_halts_both_loops_before_the_host_is_read(self):
        for extra in ((), ("--setup",)):
            with self.subTest(setup=bool(extra)):
                root = self._tree(False)
                adopt_panopticon(root)
                with open(os.path.join(root, ".panopticon", "run-manifest.json"), "w",
                          encoding="utf-8") as fh:
                    json.dump({"run_id": "planted", "host": "claude", "review_root": root}, fh)
                status = self._loop(root, *extra)
                self.assertEqual(("error", H2), (status["status"], status["message"]))

    def test_reset_moves_a_planted_directory_aside_and_the_loop_goes_on(self):
        root = self._tree(False)
        adopt_panopticon(root)
        with open(os.path.join(root, ".panopticon", "run-manifest.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"run_id": "planted"}, fh)
        args = driver.build_parser().parse_args(["loop", root, "--no-tools", "--reset"])
        with mock.patch.object(runio, "resolve_host", side_effect=RuntimeError("reached")), \
                contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, "^reached$"):
                orchestrate.loop(args)
        self.assertEqual([True], [n.startswith(".panopticon.unverified-") for n in os.listdir(root)
                                  if n.startswith(".panopticon.")])

    def test_under_pr_the_operator_s_checkout_is_assessed_and_the_worktree_released(self):
        checkout, worktree = self._tree(False), self._tree(False)
        adopt_panopticon(checkout)
        with open(os.path.join(checkout, ".panopticon", "run-manifest.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"run_id": "planted"}, fh)
        with mock.patch("scripts.diff_map.release_worktree") as release:
            status = self._loop(checkout, "--pr", "7", resolved=(worktree, "/wt/7", "main"))
        self.assertEqual(("error", H2), (status["status"], status["message"]))
        release.assert_called_once_with("/wt/7", repo=checkout)
        self.assertFalse(os.path.lexists(os.path.join(worktree, ".panopticon")))


class TestTheTrackedProbeIsTheTrustedGit(_Trees):
    def test_the_target_s_fsmonitor_never_runs(self):
        root = make_git_repo(test_case=self, files={"src/a.py": "x = 1\n"})
        marker = plant_fsmonitor_command(root)
        first_contact.assess_artifacts(root)
        self.assertFalse(os.path.exists(marker))

    def test_no_trusted_git_halts_on_one_line_naming_no_stderr(self):
        root = self._tree(True)
        with mock.patch.object(first_contact.safe_git, "probe",
                               side_effect=FileNotFoundError("git: /tmp/evil said hi")):
            status = self._run(root)
        self.assertEqual(("error", H5 % ("git ls-files", "FileNotFoundError")),
                         (status["status"], status["message"]))


class TestAnOutOfTreeHardLinkHalts(_Trees):
    def test_a_file_linked_outside_halts_in_a_tarball_and_a_git_tree(self):
        for git in (False, True):
            with self.subTest(git=git):
                root, outside = self._tree(git), self._dir()
                secret = os.path.join(outside, "secret")
                with open(secret, "w", encoding="utf-8") as fh:
                    fh.write("x")
                hard_link_or_skip(secret, os.path.join(root, "src", "looks-innocent.txt"))
                self._halts(root, H4 % ("src/looks-innocent.txt", 2, 1))

    def test_the_count_is_in_tree_names_not_a_bare_nlink(self):
        root, outside = self._tree(False), self._dir()
        pair = os.path.join(root, "src", "a.py")
        hard_link_or_skip(pair, os.path.join(root, "src", "b.py"))          # 2 links, 2 names
        self.assertEqual(([], 3), first_contact._outside_links(root)[:1] + (3,))
        hard_link_or_skip(pair, os.path.join(outside, "c.py"))               # 3 links, 2 names
        self.assertEqual([("src/a.py", 3, 2)], first_contact._outside_links(root)[0])

    def _linked_git_dir(self, root, where):
        outside = self._dir()
        # exist_ok: a real repo's own objects land in `ab/` one time in ~256 per object.
        os.makedirs(os.path.join(root, where, "objects", "ab"), exist_ok=True)
        blob = os.path.join(outside, "blob")
        with open(blob, "w", encoding="utf-8") as fh:
            fh.write("z")
        hard_link_or_skip(blob, os.path.join(root, where, "objects", "ab", "cdef"))
        return where + "/objects/ab/cdef"

    def test_only_the_work_tree_s_own_git_objects_are_not_counted(self):
        # Ruling A1: `git clone /local/path` hard-links .git/objects by default.
        root = self._tree(True)
        self._linked_git_dir(root, ".git")
        self.assertNotEqual("error", self._run(root)["status"])

    def test_a_shipped_git_directory_is_target_content(self):
        # Review C2: a nested `vendor/.git/`, or a `.git/` in a tree that is no
        # git work tree (a tarball), is the target's -- it hides nothing.
        for git, where in ((True, "vendor/.git"), (False, ".git")):
            with self.subTest(where=where, git=git):
                root = self._tree(git)
                rel = self._linked_git_dir(root, where)
                self._halts(root, H4 % (rel, 2, 1))

    def test_a_symlink_or_fifo_is_not_a_hard_link(self):
        root, outside = self._tree(False), self._dir()
        target = os.path.join(outside, "t")
        with open(target, "w", encoding="utf-8") as fh:
            fh.write("t")
        hard_link_or_skip(target, os.path.join(outside, "t2"))
        os.symlink(target, os.path.join(root, "src", "link"))
        fifo = os.path.join(outside, "fifo")
        os.mkfifo(fifo)
        hard_link_or_skip(fifo, os.path.join(root, "src", "fifo"))
        self.assertEqual([], first_contact._outside_links(root)[0])

    def test_more_than_one_is_counted_in_the_one_line(self):
        root, outside = self._tree(False), self._dir()
        for name in ("a", "b", "c"):
            path = os.path.join(outside, name)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(name)
            hard_link_or_skip(path, os.path.join(root, "src", name))
        self._halts(root, H4 % ("src/a", 2, 1) + first_contact.MORE % 2)

    def test_the_walk_runs_once_per_run_not_once_per_invocation(self):
        root = self._tree(True)
        calls = []
        real = first_contact._outside_links

        def counted(review_root, **kw):
            calls.append(review_root)
            return real(review_root, **kw)

        with mock.patch.object(first_contact, "_outside_links", side_effect=counted):
            for _ in range(3):
                self.assertNotEqual("error", self._run(root)["status"])
            self.assertEqual(1, len(calls))
            self._run(root, "--reset")
        self.assertEqual(2, len(calls))
        self.assertIsInstance(run_manifest.load_manifest(root)["first_contact"]["files"], int)

    def test_a_directory_the_walk_cannot_read_fails_closed(self):
        if os.geteuid() == 0:
            self.skipTest("root reads every directory")
        root = self._tree(False)
        sealed = os.path.join(root, "src", "sealed")
        os.makedirs(sealed)
        os.chmod(sealed, 0)
        self.addCleanup(os.chmod, sealed, 0o700)
        status = self._run(root)
        self.assertEqual("error", status["status"])
        self.assertTrue(status["message"].startswith(
            "the target cannot be assessed at first contact: "), status["message"])


    def test_an_entry_the_walk_cannot_lstat_fails_closed(self):
        # A directory that can be LISTED but not searched (r--): its names are
        # known and none of them can be measured.
        if os.geteuid() == 0:
            self.skipTest("root reads every directory")
        root = self._tree(False)
        sealed = os.path.join(root, "src", "listed")
        os.makedirs(sealed)
        with open(os.path.join(sealed, "f.py"), "w", encoding="utf-8") as fh:
            fh.write("x")
        os.chmod(sealed, 0o400)
        self.addCleanup(os.chmod, sealed, 0o700)
        with self.assertRaisesRegex(first_contact.FirstContactHalt,
                                    "^the target cannot be assessed at first contact: "
                                    "src/listed/f.py: "):
            first_contact.assess(root, "run-manifest.json")


class TestDriverSetupWalksEveryInvocation(_Trees):
    """#3271 B1 (ruling G-b): `driver setup`'s scan holds the one directory
    grant over the whole tree, so it runs the H4 walk on every invocation --
    a resume included -- where `driver run` walks once per run."""

    def _setup(self, root):
        with contextlib.redirect_stderr(io.StringIO()):
            return setup.run_setup_flow(driver.build_parser().parse_args(["setup", root]))

    def _plant_outside(self, root):
        outside = os.path.join(self._dir(), "secret")
        with open(outside, "w", encoding="utf-8") as fh:
            fh.write("s")
        hard_link_or_skip(outside, os.path.join(root, "src", "later.py"))

    def test_driver_setup_halts_on_an_out_of_tree_link(self):
        root = self._tree(True)
        self._plant_outside(root)
        status = self._setup(root)
        self.assertEqual(("error", H4 % ("src/later.py", 2, 1)),
                         (status["status"], status["message"]))

    def test_a_link_that_appears_between_two_setup_invocations_halts_the_second(self):
        root = self._tree(True)
        first = self._setup(root)
        self.assertFalse(str(first.get("message")).endswith("in-tree names); review a copy "
                                                            "without hard links (a plain cp)"))
        manifest = setup.load_setup_manifest(root)
        self.assertIsInstance(manifest.get("first_contact"), dict)      # a resume follows
        self._plant_outside(root)
        status = self._setup(root)
        self.assertEqual(("error", H4 % ("src/later.py", 2, 1)),
                         (status["status"], status["message"]))
        self.assertEqual(manifest["run_id"], setup.load_setup_manifest(root)["run_id"])

    def test_a_resumed_setup_walks_but_records_nothing_new(self):
        # The walk is every time; the record is still the manifest's, once.
        root = self._tree(True)
        self._setup(root)
        walks = []
        real = first_contact._outside_links
        with mock.patch.object(first_contact, "_outside_links",
                               side_effect=lambda *a, **k: walks.append(1) or real(*a, **k)):
            self.assertIsNone(first_contact.assess(root, setup.SETUP_MANIFEST, walk_every_time=True))
        self.assertEqual([1], walks)

    def test_driver_run_still_walks_once_per_run(self):
        root = self._tree(True)
        self.assertNotEqual("error", self._run(root)["status"])
        self._plant_outside(root)
        self.assertNotEqual("error", self._run(root)["status"])          # a resume


class TestWhatTheWalkDoesNotCountNoGrantReads(_Trees):
    """#3271 B1 (ruling G-a): a work tree's own `.git/` is not counted by H4
    (ruling A1), so setup's directory grant never covers it -- including the
    complete `.git/` a tarball can ship, which passes for a work tree's."""

    def test_a_link_under_a_shipped_git_store_does_not_halt_and_cannot_be_read(self):
        import scripts.read_guard_hook as read_guard_hook
        import scripts.kimi_guard_hook as kimi_guard_hook
        from scripts import codex_read_tools
        root = self._tree(True)                    # `git ls-files` succeeds: a work tree
        outside = os.path.join(self._dir(), "secret")
        with open(outside, "w", encoding="utf-8") as fh:
            fh.write("SEALED-CONTENT")
        store = os.path.join(root, ".git", "objects", "zz", "planted")
        os.makedirs(os.path.dirname(store))
        hard_link_or_skip(outside, store)
        self.assertEqual([], first_contact._outside_links(root, git=True)[0])     # A1: not counted
        entry = setup._setup_scan_entry(root, "PROMPT", "claude")
        scope = read_guard_hook.scope_from_plan([entry])[entry["id"]]
        for tool, key in (("Read", "file_path"), ("Grep", "path")):
            with self.subTest(reader="claude", tool=tool):
                self.assertFalse(read_guard_hook.decide(tool, {key: store, "pattern": "p"}, scope)[0])
            with self.subTest(reader="kimi", tool=tool):
                self.assertFalse(kimi_guard_hook._decide_read(tool, {"path": store, "pattern": "p"},
                                                              scope, root)[0])
        reader = codex_read_tools.Reader(entry["scope"], root)
        result = reader.call("read_file", {"path": store})
        self.assertTrue(result["isError"])
        self.assertNotIn("SEALED-CONTENT", json.dumps(result))

class TestAnotherHostsPriorRunIsDisclosed(_Trees):
    def test_starting_over_a_stamped_run_of_another_host_says_so(self):
        root = self._tree(True)
        self.assertNotEqual("error", self._run(root, "--host", "claude")["status"])
        prior = run_manifest.load_manifest(root)["run_id"][:8]
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            status = driver.run(driver.build_parser().parse_args(
                ["run", root, "--no-tools", "--reset", "--host", "codex", "--allow-unenforced"]),
                phases=())
        self.assertNotEqual("error", status["status"], status)
        line = "this run started over an earlier claude run (%s) in .panopticon/" % prior
        self.assertIn("driver: " + line, err.getvalue())
        self.assertEqual({"host": "claude", "run_id": prior},
                         run_manifest.load_manifest(root)["first_contact"]["prior_run"])

    def test_the_pr_mode_checkout_is_assessed_too(self):
        operator, worktree = self._tree(True), self._tree(True)
        os.makedirs(os.path.join(operator, ".panopticon"))
        with open(os.path.join(operator, ".panopticon", "x.json"), "w", encoding="utf-8") as fh:
            fh.write("{}")
        with self.assertRaisesRegex(first_contact.FirstContactHalt, "^%s$" % H2.replace("(", r"\(")
                                    .replace(")", r"\)").replace(".", r"\.")):
            first_contact.assess(worktree, "run-manifest.json", other_roots=(operator,))


class TestTheRunStamp(unittest.TestCase):
    def setUp(self):
        state = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, state, ignore_errors=True)
        self.state = os.path.join(state, "panopticon")
        patcher = mock.patch.dict(os.environ, {"PANOPTICON_STATE_DIR": self.state})
        patcher.start()
        self.addCleanup(patcher.stop)
        run_stamp._KEY_CACHE.clear()
        self.addCleanup(run_stamp._KEY_CACHE.clear)

    def _record(self, root="/srv/target"):
        record = {"run_id": "0123456789abcdef", "review_root": root}
        record["stamp"] = run_stamp.sign(record)
        return record

    def test_the_key_is_private_and_made_once(self):
        record = self._record()
        key = os.path.join(self.state, run_stamp.KEY_NAME)
        self.assertEqual(0o700, stat.S_IMODE(os.stat(self.state).st_mode))
        self.assertEqual(0o600, stat.S_IMODE(os.stat(key).st_mode))
        self.assertEqual(run_stamp.KEY_BYTES, os.path.getsize(key))
        self.assertTrue(run_stamp.verifies(record))
        self.assertEqual([run_stamp.KEY_NAME], os.listdir(self.state))   # no temp left behind

    def test_a_forged_stamp_and_a_moved_record_do_not_verify(self):
        record = self._record()
        self.assertFalse(run_stamp.verifies(dict(record, stamp="0" * 64)))
        self.assertFalse(run_stamp.verifies(dict(record, review_root="/srv/other")))
        self.assertFalse(run_stamp.verifies(dict(record, run_id="fedcba9876543210")))
        for bad in (None, [], {"stamp": 1}, dict(record, stamp=None)):
            self.assertFalse(run_stamp.verifies(bad))

    def test_another_machine_s_key_does_not_verify(self):
        record = self._record()
        other = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, other, ignore_errors=True)
        with mock.patch.dict(os.environ, {"PANOPTICON_STATE_DIR": other}):
            run_stamp._KEY_CACHE.clear()
            self.assertFalse(run_stamp.verifies(record))

    def test_racing_first_runs_agree_on_one_key(self):
        os.makedirs(self.state, mode=0o700)
        path = os.path.join(self.state, run_stamp.KEY_NAME)
        barrier, seen, errors = threading.Barrier(8), [], []

        def first_run():
            barrier.wait()
            try:
                run_stamp._create(self.state, path)
                seen.append(run_stamp._read(path))
            except Exception as exc:     # noqa: BLE001 - a loser must not raise
                errors.append(exc)

        threads = [threading.Thread(target=first_run) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(([], 8, 1), (errors, len(seen), len(set(seen))))
        self.assertEqual([run_stamp.KEY_NAME], os.listdir(self.state))

    def test_a_loose_state_directory_is_tightened(self):
        os.makedirs(self.state, mode=0o755)
        os.chmod(self.state, 0o755)
        run_stamp.key()
        self.assertEqual(0o700, stat.S_IMODE(os.stat(self.state).st_mode))

    def test_a_key_nobody_can_trust_halts_the_run(self):
        os.makedirs(self.state, mode=0o700)
        path = os.path.join(self.state, run_stamp.KEY_NAME)
        decoy = os.path.join(self.state, "decoy")
        with open(decoy, "wb") as fh:
            fh.write(b"k" * run_stamp.KEY_BYTES)
        os.chmod(decoy, 0o600)
        cases = (("a symlink", lambda: os.symlink(decoy, path)),
                 ("readable by group or other", lambda: (shutil.copy(decoy, path), os.chmod(path, 0o644))),
                 ("not a 32-byte key", lambda: (open(path, "wb").write(b"k" * 31), os.chmod(path, 0o600))))
        for why, make in cases:
            with self.subTest(why=why):
                if os.path.lexists(path):
                    os.unlink(path)
                make()
                run_stamp._KEY_CACHE.clear()
                with self.assertRaisesRegex(run_stamp.KeyUnavailable, why):
                    run_stamp.key()
                with self.assertRaisesRegex(first_contact.FirstContactHalt,
                                            "^the target cannot be assessed at first contact: "
                                            "run stamp: .*%s" % why):
                    first_contact.assess_artifacts(self.state)


if __name__ == "__main__":
    unittest.main()
