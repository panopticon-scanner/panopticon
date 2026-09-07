"""Tests for scripts.phases.validate: the tree baseline, the delta and worktree
finalization.
"""
import contextlib
import io
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import scripts.phases.runio as runio
import scripts.phases.validate as validate_phase

import scripts.diff_map as diff_map
import scripts.run_manifest as run_manifest

from tools.git_repo import make_git_repo


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
        subprocess.run(["git", "-C", d, "add", "-A"], check=True)
        subprocess.run(["git", "-C", d, "commit", "-qm", "add pano file"], check=True)
        validate_phase.capture_tree_baseline(d)
        subprocess.run(["git", "-C", d, "mv", ".panopticon/x.py", "leaked.py"], check=True)
        with self.assertRaises(runio.DriverError):
            validate_phase.validate_execute(d, {"run_id": "R", "worktree": None})

    def test_rename_into_panopticon_is_flagged(self):
        # #1033/SEC-1: a rename moving a tracked file INTO .panopticon/ still
        # changed the OUTSIDE tree (its source) -> must be caught on the SOURCE
        # endpoint. The old destination-only check silently missed this.
        d = self._git_repo()
        open(os.path.join(d, "real_src.py"), "w").close()
        subprocess.run(["git", "-C", d, "add", "-A"], check=True)
        subprocess.run(["git", "-C", d, "commit", "-qm", "add real_src"], check=True)
        validate_phase.capture_tree_baseline(d)
        subprocess.run(["git", "-C", d, "mv", "real_src.py", ".panopticon/hidden.py"],
                       check=True)
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
        subprocess.run(["git", "-C", d, "add", ".panopticon/keep.txt"], check=True)
        subprocess.run(["git", "-C", d, "commit", "-qm", "track pano"], check=True)
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
        import io, contextlib
        worktree, target = self._dir(), self._dir()
        manifest = {"run_id": "R", "worktree": worktree, "target": target}
        tag = run_manifest.run_tag(manifest)
        runio._write_json(
            os.path.join(worktree, ".panopticon", f"{tag}-report.json"),
            {"summary": {"gate": "PASS"}})
        err = io.StringIO()
        with mock.patch.object(diff_map, "release_worktree") as rel, \
             mock.patch("shutil.copyfile",
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
