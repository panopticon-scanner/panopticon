"""Tests for scripts.phases.validate: the tree baseline, the delta and worktree
finalization.
"""
import contextlib
import io
import json
import os
import shlex
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

import scripts.phases.runio as runio
import scripts.phases.validate as validate_phase

import scripts.diff_map as diff_map
import scripts.run_manifest as run_manifest

from tests.tools.git_repo import make_git_repo


class TestValidatePhase(unittest.TestCase):
    def _git_repo(self):
        return make_git_repo(
            test_case=self,
            files={"a.py": None},
            panopticon=True,
            branch=None,
            user_email="t@t",
            user_name="t",
        )

    def _assert_delta_refuses_validation(self, repo, expected, runner=subprocess.run):
        baseline = runio._pano(repo, "tree-baseline.txt")
        with open(baseline, "rb") as fh:
            before = fh.read()
        delta = validate_phase._tree_delta(repo, runner)
        self.assertTrue(delta)
        self.assertIn(expected, " ".join(delta))
        manifest = {"run_id": "R", "worktree": None}
        with self.assertRaises(runio.DriverError):
            validate_phase.validate_execute(repo, manifest, runner=runner)
        with open(baseline, "rb") as fh:
            self.assertEqual(fh.read(), before)
        marker = runio._pano(repo, "validate.json")
        with open(marker, encoding="utf-8") as fh:
            validation = json.load(fh)
        self.assertFalse(validation["tree_clean"])
        self.assertIn(expected, " ".join(validation["unexpected_changes"]))
        self.assertFalse(validate_phase.validate_done(repo, manifest))

    def _marker_command(self, root):
        marker = os.path.join(root, ".panopticon", "probe-marker")
        return marker, "printf hit > %s; cat" % shlex.quote(marker)

    def test_local_fsmonitor_never_executes_in_baseline_or_delta(self):
        d = self._git_repo()
        marker, command = self._marker_command(d)
        subprocess.run(["git", "-C", d, "config", "core.fsmonitor", command], check=True, timeout=30)
        validate_phase.capture_tree_baseline(d)
        self.assertFalse(os.path.exists(marker))
        self.assertEqual(validate_phase._tree_delta(d, subprocess.run), [])
        self.assertFalse(os.path.exists(marker))

    def _install_clean_filter(self, d):
        marker, command = self._marker_command(d)
        with open(os.path.join(d, "a.py"), "w") as fh:
            fh.write("before\n")
        with open(os.path.join(d, ".gitattributes"), "w") as fh:
            fh.write("a.py filter=fixture\n")
        subprocess.run(["git", "-C", d, "add", "a.py", ".gitattributes"], check=True, timeout=30)
        subprocess.run(["git", "-C", d, "commit", "-qm", "filter fixture"], check=True, timeout=30)
        subprocess.run(["git", "-C", d, "config", "filter.fixture.clean", command], check=True, timeout=30)
        # Same-size content defeats the size-only fast path and requests cleaning.
        with open(os.path.join(d, "a.py"), "w") as fh:
            fh.write("after!\n")
        return marker

    def test_clean_filter_baseline_never_executes_and_is_still_captured(self):
        # #2013 inverts #2006 here: the filter is EMPTIED rather than the tree
        # refused, so the integrity baseline is real instead of the
        # probe-failed sentinel. The marker assertion is unchanged -- that is
        # the invariant; only who pays for it moved.
        d = self._git_repo()
        marker = self._install_clean_filter(d)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            baseline = validate_phase.capture_tree_baseline(d)
        self.assertFalse(os.path.exists(marker))
        # Review M2: assert on the BASELINE FILE. The sentinel is a file-content
        # constant, so comparing it against a stderr buffer was a dead assertion
        # that read like a check.
        with open(baseline) as fh:
            content = fh.read()
        self.assertIn("a.py", content)
        self.assertNotEqual(content, validate_phase._TREE_BASELINE_PROBE_FAILED)
        # The tree did not move between the baseline and the delta.
        self.assertEqual(validate_phase._tree_delta(d, subprocess.run), [])

    def test_clean_filter_delta_never_executes_and_is_still_measured(self):
        # The filter fixture COMMITS a.py and .gitattributes and rewrites a.py,
        # so the tree really did move after the baseline: the delta names the
        # file, where #2006 could only name the refusal.
        d = self._git_repo()
        validate_phase.capture_tree_baseline(d)
        marker = self._install_clean_filter(d)
        delta = validate_phase._tree_delta(d, subprocess.run)
        self.assertFalse(os.path.exists(marker))
        self.assertTrue(delta)
        self.assertIn("a.py", " ".join(delta))

    def _submodule_repo(self):
        d, child = self._git_repo(), self._git_repo()
        subprocess.run(["git", "-C", d, "-c", "protocol.file.allow=always", "submodule",
                        "add", child, "sub"], check=True, capture_output=True, timeout=60)
        subprocess.run(["git", "-C", d, "commit", "-qam", "add submodule"], check=True, timeout=30)
        return d, os.path.join(d, "sub")

    def test_normal_submodule_dirt_remains_visible(self):
        d, sub = self._submodule_repo()
        # Repository preferences must not silently remove this integrity surface.
        subprocess.run(["git", "-C", d, "config", "submodule.sub.ignore", "all"], check=True, timeout=30)
        validate_phase.capture_tree_baseline(d)
        with open(os.path.join(sub, "a.py"), "w") as fh:
            fh.write("dirty submodule\n")
        delta = validate_phase._tree_delta(d, subprocess.run)
        self.assertTrue(any("sub" in entry for entry in delta), delta)

    def test_submodule_filter_never_executes(self):
        d, sub = self._submodule_repo()
        validate_phase.capture_tree_baseline(d)
        os.makedirs(os.path.join(sub, ".panopticon"), exist_ok=True)
        subprocess.run(["git", "-C", sub, "config", "user.name", "T"], check=True, timeout=30)
        subprocess.run(["git", "-C", sub, "config", "user.email", "t@t"], check=True, timeout=30)
        marker = self._install_clean_filter(sub)
        delta = validate_phase._tree_delta(d, subprocess.run)
        self.assertFalse(os.path.exists(marker))
        # #2013: the submodule's dirt is REPORTED with its filter emptied --
        # the `-c` override reaches the child git that runs inside `sub`.
        self.assertIn("sub", " ".join(delta))

    def test_missing_trusted_git_fails_closed(self):
        d = self._git_repo()
        empty = tempfile.mkdtemp()      # a PATH with no git on it (#3270: not the target)
        self.addCleanup(lambda: shutil.rmtree(empty, ignore_errors=True))
        with mock.patch.dict(os.environ, {"PATH": empty}):
            validate_phase.capture_tree_baseline(d)
        self.assertTrue(validate_phase._tree_delta(d, subprocess.run))

    def test_clean_tree_advances(self):
        d = self._git_repo()
        validate_phase.capture_tree_baseline(d)
        m = {"run_id": "R", "worktree": None}
        result = validate_phase.validate_execute(d, m)
        self.assertEqual(result.kind, "advanced")
        self.assertTrue(validate_phase.validate_done(d, m))

    def test_reviewer_side_effect_outside_panopticon_raises(self):
        d = self._git_repo()
        validate_phase.capture_tree_baseline(d)
        open(os.path.join(d, "leaked.py"), "w").close()   # NEW file outside .panopticon
        m = {"run_id": "R", "worktree": None}
        with self.assertRaises(runio.DriverError):
            validate_phase.validate_execute(d, m)
        self.assertFalse(validate_phase.validate_done(d, m))   # dirty tree != validated

    def test_a_clean_marker_does_not_outlive_a_change_to_the_tree(self):
        # #3235: `validate.json` saying clean was trusted on its own. A change after it -- or a
        # marker written over a dirty tree -- re-runs validate, which refuses.
        d = self._git_repo()
        validate_phase.capture_tree_baseline(d)
        m = {"run_id": "R", "worktree": None}
        self.assertEqual("advanced", validate_phase.validate_execute(d, m).kind)
        self.assertTrue(validate_phase.validate_done(d, m))
        with open(os.path.join(d, "a.py"), "a", encoding="utf-8") as fh:
            fh.write("# edited after validate\n")
        self.assertFalse(validate_phase.validate_done(d, m))
        with self.assertRaises(runio.DriverError):
            validate_phase.validate_execute(d, m)

    def test_after_completion_the_stop_does_not_blame_reviewers(self):
        # #3235 ruling: the same stop, worded for the likelier cause once the run has completed.
        d = self._git_repo()
        validate_phase.capture_tree_baseline(d)
        open(os.path.join(d, "edited.py"), "w").close()
        for manifest, words, not_words in (
                ({"run_id": "R", "worktree": None}, "reviewer side effects", "changed since"),
                ({"run_id": "R", "worktree": None, "completed_at": "2026-10-31T00:00:00Z"},
                 "the tree changed since this run validated", "reviewer")):
            with self.subTest(completed="completed_at" in manifest):
                with self.assertRaises(runio.DriverError) as caught:
                    validate_phase.validate_execute(d, manifest)
                self.assertIn(words, str(caught.exception))
                self.assertNotIn(not_words, str(caught.exception))
                self.assertIn("edited.py", str(caught.exception))

    def test_a_planted_clean_marker_over_a_dirty_tree_is_not_done(self):
        d = self._git_repo()
        validate_phase.capture_tree_baseline(d)
        open(os.path.join(d, "leaked.py"), "w").close()
        runio._write_json(runio._pano(d, "validate.json"),
                          {"schema_version": 1, "run_id": "R", "tree_clean": True,
                           "unexpected_changes": []})
        self.assertFalse(validate_phase.validate_done(d, {"run_id": "R", "worktree": None}))

    def test_panopticon_changes_are_ignored(self):
        d = self._git_repo()
        validate_phase.capture_tree_baseline(d)
        open(os.path.join(d, ".panopticon", "report.json"), "w").close()
        result = validate_phase.validate_execute(d, {"run_id": "R", "worktree": None})
        self.assertEqual(result.kind, "advanced")

    def test_validate_does_not_release_pr_worktree(self):
        # Ruling A: validate must NOT release the worktree -- when review_root IS
        # the worktree, releasing here would delete report.json + the manifest and
        # break cursor derivation. Release happens in run() on completion instead.
        d = self._git_repo()
        validate_phase.capture_tree_baseline(d)
        with mock.patch("scripts.diff_map.release_worktree") as rel:
            result = validate_phase.validate_execute(d, {"run_id": "R", "worktree": "/tmp/pr-wt"})
        rel.assert_not_called()
        self.assertEqual(result.kind, "advanced")
        self.assertTrue(validate_phase.validate_done(d, {"run_id": "R", "worktree": "/tmp/pr-wt"}))

    def test_non_git_target_has_no_baseline_and_advances(self):
        with tempfile.TemporaryDirectory() as d:
            d = os.path.realpath(d)
            os.makedirs(os.path.join(d, ".panopticon"))
            self.assertIsNone(validate_phase.capture_tree_baseline(d))
            result = validate_phase.validate_execute(d, {"run_id": "R", "worktree": None})
            self.assertEqual(result.kind, "advanced")

    def test_baseline_probe_failure_fails_closed(self):
        # #run9 OPS-E1A: a git-status PROBE FAILURE at run start (timeout/error) is
        # NOT a non-git target -- it records a sentinel and makes validate fail
        # CLOSED, never silently certify a tree whose baseline it never captured.
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".panopticon"))
            def boom(*_a, **_k):
                raise subprocess.TimeoutExpired(cmd="git", timeout=15)
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                validate_phase.capture_tree_baseline(d, runner=boom)
            self.assertIn("fail closed", buf.getvalue())
            with self.assertRaises(runio.DriverError):        # sentinel -> fail closed
                validate_phase.validate_execute(d, {"run_id": "R", "worktree": None})

    def test_validate_probe_failure_fails_closed(self):
        # A baseline was captured cleanly, but the validate-time git-status probe
        # fails -- the tree cannot be confirmed unchanged, so fail closed, not clean.
        d = self._git_repo()
        validate_phase.capture_tree_baseline(d)
        def boom(*_a, **_k):
            raise OSError("git unavailable")
        with self.assertRaises(runio.DriverError):
            validate_phase.validate_execute(d, {"run_id": "R", "worktree": None}, runner=boom)

    def test_nonzero_verification_status_names_failure_and_refuses_validation(self):
        repo = self._git_repo()
        validate_phase.capture_tree_baseline(repo)

        def failed_status(*args, **kwargs):
            return subprocess.CompletedProcess(args, 7, stdout="", stderr="status failed")

        self._assert_delta_refuses_validation(repo, "verification git-status exited 7",
                                              runner=failed_status)

    def test_unreadable_recorded_entry_names_path_and_refuses_validation(self):
        repo = self._git_repo()
        dirty = os.path.join(repo, "a.py")
        with open(dirty, "w", encoding="utf-8") as fh:
            fh.write("dirty\n")
        validate_phase.capture_tree_baseline(repo)
        original = validate_phase._entry_for

        def unreadable(root, rel, budget):
            if rel == "a.py":
                raise OSError("digest read failed")
            return original(root, rel, budget)

        with mock.patch.object(validate_phase, "_entry_for", side_effect=unreadable):
            self._assert_delta_refuses_validation(repo, "a.py content unreadable")

    def test_verification_digest_budget_exhaustion_refuses_validation(self):
        repo = self._git_repo()
        with open(os.path.join(repo, "a.py"), "w", encoding="utf-8") as fh:
            fh.write("dirty\n")
        validate_phase.capture_tree_baseline(repo)
        with mock.patch.object(validate_phase, "_MAX_BASELINE_FILES", 0):
            self._assert_delta_refuses_validation(repo, "a.py content equality not established")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFOs")
    def test_file_entry_skips_a_fifo_without_opening_it(self):
        """#3269 G10: a target FIFO cannot block the run-start baseline."""
        with tempfile.TemporaryDirectory() as root:
            fifo = os.path.join(root, "target-pipe")
            os.mkfifo(fifo)
            with mock.patch("builtins.open", side_effect=AssertionError("FIFO was read")), \
                    mock.patch.object(validate_phase.os, "open",
                                      side_effect=AssertionError("FIFO was opened")) as opened:
                entry = validate_phase._file_entry(fifo)
        self.assertEqual(entry, {"type": "non-regular"})
        opened.assert_not_called()

    def test_file_entry_does_not_open_a_known_character_device(self):
        """#3269 G10: lstat-classified devices are skipped before open."""
        device = "/target/character-device"
        character = mock.Mock(st_mode=stat.S_IFCHR | 0o600)
        with mock.patch.object(validate_phase.os, "lstat", return_value=character), \
                mock.patch.object(validate_phase.os, "open",
                                  side_effect=AssertionError("device was opened")) as opened:
            entry = validate_phase._file_entry(device)
        self.assertEqual(entry, {"type": "non-regular"})
        opened.assert_not_called()

    def test_file_entry_rechecks_the_open_descriptor_type(self):
        """#3269 G10: a regular-to-FIFO race is opened nonblocking then skipped."""
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "raced")
            open(path, "wb").close()
            regular = mock.Mock(st_mode=stat.S_IFREG | 0o644)
            fifo = mock.Mock(st_mode=stat.S_IFIFO | 0o644)
            with mock.patch.object(validate_phase.os, "lstat", return_value=regular), \
                    mock.patch.object(validate_phase.os, "open", return_value=37) as opened, \
                    mock.patch.object(validate_phase.os, "fstat", return_value=fifo), \
                    mock.patch.object(validate_phase.os, "close") as closed:
                entry = validate_phase._file_entry(path)

        self.assertEqual(entry, {"type": "non-regular"})
        flags = opened.call_args.args[1]
        for name in ("O_NONBLOCK", "O_NOFOLLOW"):
            if hasattr(os, name):
                self.assertTrue(flags & getattr(os, name), name)
        closed.assert_called_once_with(37)

    def test_recorded_nonregular_leaf_becoming_regular_is_a_delta(self):
        """#3269 G10 control: skipping bytes does not drop the integrity entry."""
        repo = self._git_repo()
        rel = "target-pipe"
        status = "?? %s\0" % rel
        with open(runio._pano(repo, "tree-baseline.txt"), "w", encoding="utf-8") as fh:
            json.dump({"schema_version": 2, "status": status,
                       "entries": {rel: {"type": "non-regular"}},
                       "truncated": False}, fh)
        with open(os.path.join(repo, rel), "wb") as fh:
            fh.write(b"now regular")

        def unchanged_status(*args, **_kwargs):
            return subprocess.CompletedProcess(args[0], 0, stdout=status, stderr="")

        self.assertIn(
            "CONTENT target-pipe (non-regular -> file)",
            validate_phase._tree_delta(repo, unchanged_status),
        )

    @unittest.skipUnless(hasattr(os, "symlink"), "requires symlink support")
    def test_retargeting_an_untracked_symlink_is_a_content_delta(self):
        """#3269 G10: the symlink target remains part of baseline identity."""
        repo = self._git_repo()
        rel = "target-link"
        link = os.path.join(repo, rel)
        try:
            os.symlink("first-target", link)
        except (NotImplementedError, OSError) as exc:
            self.skipTest("cannot create symlink: %s" % exc)
        baseline = validate_phase.capture_tree_baseline(repo)
        with open(baseline, encoding="utf-8") as fh:
            snapshot = json.load(fh)
        self.assertEqual(snapshot["entries"][rel],
                         {"type": "symlink", "target": "first-target"})

        os.unlink(link)
        os.symlink("second-target", link)
        self.assertEqual(validate_phase._tree_delta(repo, subprocess.run),
                         ["CONTENT target-link"])

    def test_panopticon_prefix_sibling_is_flagged(self):
        # a repo-root file sharing the '.panopticon' prefix WITHOUT a '/' boundary
        # is a reviewer side effect, not an in-.panopticon artifact -> must raise.
        d = self._git_repo()
        validate_phase.capture_tree_baseline(d)
        open(os.path.join(d, ".panopticon-evil.py"), "w").close()
        with self.assertRaises(runio.DriverError):
            validate_phase.validate_execute(d, {"run_id": "R", "worktree": None})

    def test_rename_out_of_panopticon_is_flagged(self):
        # a rename moving a tracked file OUT of .panopticon/ must be caught on
        # its DESTINATION path.
        d = self._git_repo()
        os.makedirs(os.path.join(d, ".panopticon"), exist_ok=True)
        inside = os.path.join(d, ".panopticon", "x.py")
        open(inside, "w").close()
        subprocess.run(["git", "-C", d, "add", "-A"], check=True, timeout=30)
        subprocess.run(["git", "-C", d, "commit", "-qm", "add pano file"], check=True, timeout=30)
        validate_phase.capture_tree_baseline(d)
        subprocess.run(["git", "-C", d, "mv", ".panopticon/x.py", "leaked.py"], check=True, timeout=30)
        with self.assertRaises(runio.DriverError):
            validate_phase.validate_execute(d, {"run_id": "R", "worktree": None})

    def test_rename_into_panopticon_is_flagged(self):
        # #1033/SEC-1: a rename moving a tracked file INTO .panopticon/ still
        # changed the OUTSIDE tree (its source) -> must be caught on the SOURCE
        # endpoint. The old destination-only check silently missed this.
        d = self._git_repo()
        open(os.path.join(d, "real_src.py"), "w").close()
        subprocess.run(["git", "-C", d, "add", "-A"], check=True, timeout=30)
        subprocess.run(["git", "-C", d, "commit", "-qm", "add real_src"], check=True, timeout=30)
        validate_phase.capture_tree_baseline(d)
        subprocess.run(["git", "-C", d, "mv", "real_src.py", ".panopticon/hidden.py"],
                       check=True, timeout=30)
        with self.assertRaises(runio.DriverError):
            validate_phase.validate_execute(d, {"run_id": "R", "worktree": None})

    def test_nonascii_name_in_panopticon_is_not_flagged(self):
        # #1033/SEC-1: -z emits RAW paths, so a non-ASCII filename inside
        # .panopticon/ is no longer C-quoted ('".panopticon/\\303\\251.py"') and
        # mis-flagged as a leak (the leading quote broke the old prefix check).
        d = self._git_repo()
        # .panopticon must hold TRACKED content, else git collapses an entirely-
        # untracked dir to '.panopticon/' and the individual (quotable) path never
        # appears — which wouldn't exercise the quoting fix at all.
        open(os.path.join(d, ".panopticon", "keep.txt"), "w").close()
        subprocess.run(["git", "-C", d, "add", ".panopticon/keep.txt"], check=True, timeout=30)
        subprocess.run(["git", "-C", d, "commit", "-qm", "track pano"], check=True, timeout=30)
        validate_phase.capture_tree_baseline(d)
        open(os.path.join(d, ".panopticon", "é.py"), "w").close()   # é.py
        result = validate_phase.validate_execute(d, {"run_id": "R", "worktree": None})
        self.assertEqual(result.kind, "advanced")   # in-.panopticon -> ignored

class TestFinalizeWorktree(unittest.TestCase):
    """Ruling A: on a completed --pr run, review_root IS the disposable worktree.
    _finalize_worktree surfaces report.json to the caller's target BEFORE
    releasing the worktree, and no-ops when there is no worktree."""

    def _dir(self):
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        return d

    def test_surfaces_report_then_releases_with_target_repo(self):
        worktree = self._dir()
        target = self._dir()
        manifest = {"run_id": "R", "worktree": worktree, "target": target}
        # §5.1: synthesize writes the durable, top-level, tag-named report.
        tag = run_manifest.run_tag(manifest)
        runio._write_json(
            os.path.join(worktree, ".panopticon", f"{tag}-report.json"),
            {"summary": {"gate": "PASS"}})
        with mock.patch.object(diff_map, "release_worktree") as rel:
            validate_phase._finalize_worktree(worktree, manifest)
        # the durable tag-named report is surfaced to the OWNING checkout...
        self.assertEqual(
            runio._load_json(os.path.join(target, ".panopticon", f"{tag}-report.json")),
            {"summary": {"gate": "PASS"}})
        # ...and the compat report.json symlink there resolves to it (zero-break).
        self.assertEqual(runio._load_json(runio._pano(target, "report.json")),
                         {"summary": {"gate": "PASS"}})
        # released against the owning repo (target), not review_root (==worktree)
        rel.assert_called_once_with(worktree, repo=target)

    def test_no_worktree_is_a_noop(self):
        target = self._dir()
        with mock.patch.object(diff_map, "release_worktree") as rel:
            validate_phase._finalize_worktree(target, {"run_id": "R", "worktree": None})
        rel.assert_not_called()

    def test_failed_report_surface_keeps_worktree_not_silent(self):
        # #run7 OPS-E1A: if the report can't be copied to the caller's tree, the
        # worktree (the only other copy) must NOT be released -- that would be
        # silent, unrecoverable data loss while run() still returns complete.
        worktree, target = self._dir(), self._dir()
        manifest = {"run_id": "R", "worktree": worktree, "target": target}
        tag = run_manifest.run_tag(manifest)
        runio._write_json(
            os.path.join(worktree, ".panopticon", f"{tag}-report.json"),
            {"summary": {"gate": "PASS"}})
        err = io.StringIO()
        with mock.patch.object(diff_map, "release_worktree") as rel, \
             mock.patch.object(validate_phase.safe_write, "read_regular_bytes",
                               side_effect=OSError("disk full")), \
             contextlib.redirect_stderr(err):
            validate_phase._finalize_worktree(worktree, manifest)
        rel.assert_not_called()                        # worktree KEPT, not destroyed
        self.assertIn("KEEPING the worktree", err.getvalue())

    def test_surfaces_all_report_parts_not_just_part2(self):
        # #run7 OPS-E1A: a split report (run-7 produced 4 parts + discarded) must
        # surface EVERY tag-named part, not just part2.
        worktree, target = self._dir(), self._dir()
        manifest = {"run_id": "R", "worktree": worktree, "target": target}
        tag = run_manifest.run_tag(manifest)
        for part in ("report.json", "report_part2.json", "report_part3.json",
                     "report_part4.json", "report-discarded.json"):
            runio._write_json(
                os.path.join(worktree, ".panopticon", f"{tag}-{part}"), {"p": part})
        with mock.patch.object(diff_map, "release_worktree"):
            validate_phase._finalize_worktree(worktree, manifest)
        for part in ("report_part3.json", "report_part4.json", "report-discarded.json"):
            self.assertTrue(
                os.path.isfile(os.path.join(target, ".panopticon", f"{tag}-{part}")),
                "%s not surfaced" % part)


class TestFinalizeIntoAPlantedCallerTree(unittest.TestCase):
    """#3225: in --pr mode first contact vets the WORKTREE, never the caller
    checkout, so the caller's `.panopticon` is whatever the target's default
    branch committed. The surface writes there through a held directory fd:
    a planted root is refused (the worktree is kept), a planted leaf or link
    is swapped rather than written through, and nothing lands outside."""

    def _dir(self):
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        return d

    def _run(self, html=False):
        worktree, target, outside = self._dir(), self._dir(), self._dir()
        manifest = {"run_id": "R", "worktree": worktree, "target": target}
        tag = run_manifest.run_tag(manifest)
        src = os.path.join(worktree, ".panopticon")
        runio._write_json(os.path.join(src, f"{tag}-report.json"), {"gate": "PASS"})
        if html:
            with open(os.path.join(src, f"{tag}-report.json.html"), "w") as fh:
                fh.write("<html>report</html>")
        return worktree, target, outside, manifest, tag

    def _finalize(self, worktree, manifest):
        err = io.StringIO()
        with mock.patch.object(diff_map, "release_worktree") as rel, \
                contextlib.redirect_stderr(err):
            validate_phase._finalize_worktree(worktree, manifest)
        return rel, err.getvalue()

    def _assert_kept(self, rel, err, reason):
        rel.assert_not_called()
        self.assertIn("KEEPING the worktree", err)
        self.assertIn(reason, err)

    def test_a_symlinked_panopticon_is_refused_and_nothing_lands_outside(self):
        worktree, target, outside, manifest, _tag = self._run()
        os.symlink(outside, os.path.join(target, ".panopticon"))
        rel, err = self._finalize(worktree, manifest)
        self._assert_kept(rel, err, "not a symlink")
        self.assertEqual(os.listdir(outside), [])

    def test_a_panopticon_that_is_a_file_is_refused(self):
        worktree, target, _outside, manifest, _tag = self._run()
        open(os.path.join(target, ".panopticon"), "w").close()
        rel, err = self._finalize(worktree, manifest)
        self._assert_kept(rel, err, "not a directory")

    def _swap(self, target, outside):
        real = os.path.join(target, ".panopticon")
        os.rename(real, os.path.join(target, "moved"))
        os.symlink(outside, real)

    def test_a_swap_after_the_check_is_refused_by_the_open(self):
        # The order the review asked for: `.panopticon` passes the check and is
        # THEN swapped for a link. A path-based write follows it (measured:
        # `publish_texts` published into the link's target). The O_NOFOLLOW
        # open refuses the link instead, and the worktree is kept.
        worktree, target, outside, manifest, _tag = self._run()
        os.mkdir(os.path.join(target, ".panopticon"))
        checked = validate_phase.plan_contract.artifact_root

        def check_then_swap(root):
            path = checked(root)
            self._swap(target, outside)
            return path

        with mock.patch.object(validate_phase.plan_contract, "artifact_root",
                               side_effect=check_then_swap):
            rel, err = self._finalize(worktree, manifest)
        self._assert_kept(rel, err, ".panopticon")
        self.assertEqual(os.listdir(outside), [])

    def test_a_swap_after_the_open_cannot_redirect_the_write(self):
        # The later window: the directory is already held when the name is
        # swapped. Every write is relative to the fd, so the reports land in
        # the real directory (wherever it was renamed to), never outside.
        worktree, target, outside, manifest, tag = self._run()
        os.mkdir(os.path.join(target, ".panopticon"))
        opened = validate_phase._open_caller_artifact_dir

        def open_then_swap(root):
            fd = opened(root)
            self._swap(target, outside)
            return fd

        with mock.patch.object(validate_phase, "_open_caller_artifact_dir",
                               side_effect=open_then_swap):
            self._finalize(worktree, manifest)
        self.assertEqual(os.listdir(outside), [])
        self.assertTrue(os.path.isfile(os.path.join(target, "moved", f"{tag}-report.json")))

    def test_a_planted_leaf_link_is_replaced_not_written_through(self):
        worktree, target, outside, manifest, tag = self._run()
        victim = os.path.join(outside, "victim")
        with open(victim, "w") as fh:
            fh.write("untouched")
        os.mkdir(os.path.join(target, ".panopticon"))
        leaf = os.path.join(target, ".panopticon", f"{tag}-report.json")
        os.symlink(victim, leaf)
        rel, _err = self._finalize(worktree, manifest)
        rel.assert_called_once()
        with open(victim) as fh:
            self.assertEqual(fh.read(), "untouched")
        self.assertFalse(os.path.islink(leaf))
        self.assertEqual(runio._load_json(leaf), {"gate": "PASS"})

    def test_a_planted_report_json_link_is_swapped_for_ours(self):
        worktree, target, outside, manifest, tag = self._run(html=True)
        os.mkdir(os.path.join(target, ".panopticon"))
        for link in ("report.json", "report.json.html"):
            os.symlink(os.path.join(outside, link), os.path.join(target, ".panopticon", link))
        self._finalize(worktree, manifest)
        for link, name in (("report.json", f"{tag}-report.json"),
                           ("report.json.html", f"{tag}-report.json.html")):
            self.assertEqual(os.readlink(os.path.join(target, ".panopticon", link)), name)
        self.assertEqual(os.listdir(outside), [])

    def test_a_relink_that_fails_keeps_the_worktree_instead_of_raising(self):
        # A planted DIRECTORY at report.json: the link cannot be swapped onto
        # it. Before #3225 the relink's refusal escaped as a traceback after
        # the copies had landed.
        worktree, target, _outside, manifest, _tag = self._run()
        os.makedirs(os.path.join(target, ".panopticon", "report.json", "x"))
        rel, err = self._finalize(worktree, manifest)
        self._assert_kept(rel, err, "report.json (")

    def test_an_over_cap_source_is_a_failed_surface_never_a_partial_copy(self):
        worktree, target, _outside, manifest, tag = self._run(html=True)
        with mock.patch.object(validate_phase, "MAX_SURFACED_BYTES", 8):
            rel, err = self._finalize(worktree, manifest)
        self._assert_kept(rel, err, "read limit")
        self.assertEqual(os.listdir(os.path.join(target, ".panopticon")), [])

    def test_a_later_sibling_that_fails_publishes_nothing_and_leaves_no_tmp(self):
        # The main report stages; the html after it is over the cap. Nothing
        # may go live -- not even the main report -- and no staging leaf may be
        # left behind (review of #3310: without the early return, the publish
        # loop paired the SHORTER staged list with the names and published a
        # tmp under the wrong final name).
        worktree, target, _outside, manifest, tag = self._run()
        with open(os.path.join(worktree, ".panopticon", f"{tag}-report.json.html"), "w") as fh:
            fh.write("x" * 4096)
        with mock.patch.object(validate_phase, "MAX_SURFACED_BYTES", 1024):
            rel, err = self._finalize(worktree, manifest)
        self._assert_kept(rel, err, f"{tag}-report.json.html")
        self.assertEqual(os.listdir(os.path.join(target, ".panopticon")), [])

    def test_the_main_report_goes_live_last(self):
        worktree, target, _outside, manifest, tag = self._run(html=True)
        runio._write_json(os.path.join(worktree, ".panopticon", f"{tag}-report_part2.json"),
                          {"part": 2})
        published = []
        replace = os.replace

        def spy(src, dst, **kwargs):
            if ".finalize-" in src:
                published.append(dst)
            return replace(src, dst, **kwargs)

        with mock.patch.object(validate_phase.os, "replace", side_effect=spy):
            self._finalize(worktree, manifest)
        self.assertEqual(len(published), 3, published)
        self.assertEqual(published[-1], f"{tag}-report.json")

    def test_no_dir_fd_support_refuses_rather_than_writing_by_path(self):
        worktree, target, _outside, manifest, _tag = self._run()

        def unsupported():
            pass

        with mock.patch.object(validate_phase, "_DIR_FD_CALLS",
                               validate_phase._DIR_FD_CALLS + (unsupported,)):
            rel, err = self._finalize(worktree, manifest)
        self._assert_kept(rel, err, "no dir_fd support for unsupported")
        self.assertFalse(os.path.lexists(os.path.join(target, ".panopticon")))

    def test_the_happy_path_surfaces_byte_identical_reports_and_links(self):
        worktree, target, _outside, manifest, tag = self._run(html=True)
        rel, _err = self._finalize(worktree, manifest)
        rel.assert_called_once_with(worktree, repo=target)
        dst = os.path.join(target, ".panopticon")
        for name in (f"{tag}-report.json", f"{tag}-report.json.html"):
            with open(os.path.join(worktree, ".panopticon", name), "rb") as a, \
                    open(os.path.join(dst, name), "rb") as b:
                self.assertEqual(a.read(), b.read(), name)
        self.assertEqual(os.readlink(os.path.join(dst, "report.json")), f"{tag}-report.json")
        self.assertEqual(sorted(os.listdir(dst)),
                         sorted([f"{tag}-report.json", f"{tag}-report.json.html",
                                 "report.json", "report.json.html"]))


class TestBaselineDiagnosticRedaction(unittest.TestCase):
    def test_failed_git_stderr_is_redacted_before_200_character_cut(self):
        key_type = "PRIVATE KEY"
        for text in ("ordinary failure", "x" * 160 + f"-----BEGIN {key_type}-----\n" + "A" * 2000,
                     "token " + "ghp_" + "B" * 36):
            with self.subTest(text=text[:20]), tempfile.TemporaryDirectory() as root:
                captured = io.StringIO()
                runner = mock.Mock(return_value=mock.Mock(returncode=2, stderr=text))
                with contextlib.redirect_stderr(captured):
                    baseline = validate_phase.capture_tree_baseline(root, runner=runner)
                self.assertIsNotNone(baseline)
                out = captured.getvalue()
                self.assertNotIn("AAAA", out)
                self.assertNotIn("BBBB", out)
                self.assertIn("will fail closed", out)
                if text == "ordinary failure":
                    self.assertIn(text, out)
