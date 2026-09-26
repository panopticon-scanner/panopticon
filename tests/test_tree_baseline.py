"""#1514 / Codex BR-04: validate must detect edits to an ALREADY-DIRTY file.

`_tree_delta` set-subtracted `git status --porcelain -z` records, so a file that
was already `M app.py` at run start could be rewritten arbitrarily during the
run and its status record was unchanged -- delta empty, `tree_clean: true`.
Pre-existing edits are the NORMAL starting state for a coding-agent review, so
this was the common path, not a corner.

Mocked status output cannot validate any of this: the whole defect is that the
status text is IDENTICAL before and after. These use real temporary git repos.
"""
import json
import os
import subprocess
import unittest
from unittest import mock

import scripts.phases.validate as validate_phase
import scripts.phases.runio as runio
import scripts.run_manifest as run_manifest

from tools.git_repo import make_git_repo


def _git(repo, *args):
    subprocess.run(["git", "-C", repo, *args], check=True,
                   capture_output=True, timeout=30)


class TreeContentBaselineTest(unittest.TestCase):
    def _repo(self, files=None):
        return make_git_repo(test_case=self, files=files or {"app.py": "value = 1\n"})

    def _status(self, repo):
        out = subprocess.run(["git", "-C", repo, "status", "--porcelain"],
                             capture_output=True, text=True, timeout=30).stdout
        return [ln for ln in out.splitlines() if ".panopticon" not in ln]

    def _write(self, repo, rel, text):
        with open(os.path.join(repo, rel), "w", encoding="utf-8") as fh:
            fh.write(text)

    def test_edit_to_an_already_dirty_file_is_detected(self):
        # The BR-04 probe, verbatim.
        repo = self._repo()
        self._write(repo, "app.py", "value = 2\n")        # dirty BEFORE the run
        before = self._status(repo)
        validate_phase.capture_tree_baseline(repo)
        self._write(repo, "app.py", "value = 999\n")      # reviewer side effect
        # The status text is IDENTICAL across the edit -- that identity IS the
        # defect, so assert it or the test proves nothing. (`.panopticon/` itself
        # appears once the baseline is written; it is outside the guard's scope.)
        self.assertEqual(before, self._status(repo),
                         "fixture must reproduce the identical-status case")
        self.assertTrue(validate_phase._tree_delta(repo, subprocess.run))

    def test_a_reverted_user_edit_is_detected(self):
        # Restoring a file is a side effect too: the record DISAPPEARS from
        # status, and subtraction only ever looked at NEW records.
        repo = self._repo()
        self._write(repo, "app.py", "value = 2\n")
        validate_phase.capture_tree_baseline(repo)
        self._write(repo, "app.py", "value = 1\n")        # back to HEAD content
        self.assertTrue(validate_phase._tree_delta(repo, subprocess.run))

    def test_edit_to_an_already_untracked_file_is_detected(self):
        repo = self._repo()
        self._write(repo, "scratch.txt", "one\n")         # untracked before the run
        validate_phase.capture_tree_baseline(repo)
        self._write(repo, "scratch.txt", "two\n")
        self.assertTrue(validate_phase._tree_delta(repo, subprocess.run))

    def test_deleting_an_already_dirty_file_is_detected(self):
        repo = self._repo()
        self._write(repo, "app.py", "value = 2\n")
        validate_phase.capture_tree_baseline(repo)
        os.remove(os.path.join(repo, "app.py"))
        self.assertTrue(validate_phase._tree_delta(repo, subprocess.run))

    def test_a_mode_change_on_an_already_dirty_file_is_detected(self):
        repo = self._repo()
        self._write(repo, "app.py", "value = 2\n")
        validate_phase.capture_tree_baseline(repo)
        os.chmod(os.path.join(repo, "app.py"), 0o755)
        self.assertTrue(validate_phase._tree_delta(repo, subprocess.run))

    def test_staging_an_already_dirty_file_is_detected(self):
        # `M ` vs ` M` differ as status records, but assert it explicitly: the
        # index half of the state has to stay covered.
        repo = self._repo()
        self._write(repo, "app.py", "value = 2\n")
        validate_phase.capture_tree_baseline(repo)
        _git(repo, "add", "app.py")
        self.assertTrue(validate_phase._tree_delta(repo, subprocess.run))

    def test_a_run_that_changes_nothing_passes_with_a_dirty_baseline(self):
        # The normal case: the user had edits, the review touched nothing.
        repo = self._repo()
        self._write(repo, "app.py", "value = 2\n")
        self._write(repo, "scratch.txt", "keep\n")
        validate_phase.capture_tree_baseline(repo)
        self.assertEqual(validate_phase._tree_delta(repo, subprocess.run), [])

    def test_panopticon_artifact_writes_do_not_false_positive(self):
        repo = self._repo()
        self._write(repo, "app.py", "value = 2\n")
        validate_phase.capture_tree_baseline(repo)
        os.makedirs(os.path.join(repo, ".panopticon"), exist_ok=True)
        self._write(repo, ".panopticon/report.json", '{"x": 1}\n')
        self.assertEqual(validate_phase._tree_delta(repo, subprocess.run), [])

    def test_a_clean_file_modified_during_the_run_is_still_detected(self):
        # The case the old status subtraction DID catch must keep working.
        repo = self._repo({"app.py": "value = 1\n", "other.py": "x = 1\n"})
        validate_phase.capture_tree_baseline(repo)
        self._write(repo, "other.py", "x = 2\n")
        self.assertTrue(validate_phase._tree_delta(repo, subprocess.run))

    def test_an_ignored_file_is_out_of_scope_by_policy(self):
        # Explicit policy (the issue asks for one): `git status` without
        # --ignored does not report ignored paths, so they are not baselined and
        # not audited. Build outputs and caches churn during any real run; a
        # scanner that never writes them is not what this guard proves.
        repo = self._repo()
        self._write(repo, ".gitignore", "build/\n")
        _git(repo, "add", ".gitignore")
        _git(repo, "-c", "commit.gpgsign=false", "commit", "-qm", "ignore build")
        os.makedirs(os.path.join(repo, "build"), exist_ok=True)
        self._write(repo, "build/out.o", "one\n")
        validate_phase.capture_tree_baseline(repo)
        self._write(repo, "build/out.o", "two\n")
        self.assertEqual(validate_phase._tree_delta(repo, subprocess.run), [])

    def test_a_legacy_status_only_baseline_fails_closed(self):
        # Resume across the upgrade: a v1 baseline cannot establish content
        # equality, and saying so is the only honest answer.
        repo = self._repo()
        self._write(repo, "app.py", "value = 2\n")
        path = runio._pano(repo, "tree-baseline.txt")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(" M app.py\0")                      # the old raw-porcelain shape
        delta = validate_phase._tree_delta(repo, subprocess.run)
        self.assertTrue(delta)
        self.assertIn("content equality", delta[0])

    def test_resume_keeps_the_original_run_start_baseline(self):
        repo = self._repo()
        self._write(repo, "app.py", "value = 2\n")
        validate_phase.capture_tree_baseline(repo)
        with open(runio._pano(repo, "tree-baseline.txt"), encoding="utf-8") as fh:
            first = fh.read()
        self._write(repo, "app.py", "value = 999\n")
        validate_phase.capture_tree_baseline(repo)       # resume: must NOT re-capture
        with open(runio._pano(repo, "tree-baseline.txt"), encoding="utf-8") as fh:
            self.assertEqual(fh.read(), first)
        self.assertTrue(validate_phase._tree_delta(repo, subprocess.run))

    def test_a_non_git_target_still_has_no_baseline(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(validate_phase.capture_tree_baseline(d))
            self.assertEqual(validate_phase._tree_delta(d, subprocess.run), [])

    def test_detection_never_repairs_the_tree(self):
        repo = self._repo()
        self._write(repo, "app.py", "value = 2\n")
        validate_phase.capture_tree_baseline(repo)
        self._write(repo, "app.py", "value = 999\n")
        validate_phase._tree_delta(repo, subprocess.run)
        with open(os.path.join(repo, "app.py"), encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "value = 999\n")   # user content untouched


class TargetProvenanceTest(unittest.TestCase):
    """#1492: nothing in the run record established WHICH code a run saw.

    The calibration apparatus compares runs against each other -- the cap series,
    the same-cap overlap result, the per-cell yield curve -- and every one of
    those comparisons assumes the two runs scanned the same tree. Comparing
    fzf's cap-15 and cap-48 runs required inferring tree-identity from the fact
    that their group files union to 155 paths, which is circumstantial: it would
    catch a changed file SET, never a changed file's CONTENTS.
    """

    def test_manifest_records_the_scanned_commit_and_dirtiness(self):
        repo = make_git_repo(test_case=self, files={"app.py": "value = 1\n"})
        m = run_manifest.build_manifest(target=repo, review_root=repo,
                                        host="claude", security_mode="standard")
        head = subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=30).stdout.strip()
        self.assertEqual(m["target_commit"], head)
        self.assertIs(m["target_dirty"], False)

    def test_a_dirty_target_is_recorded_as_dirty(self):
        repo = make_git_repo(test_case=self, files={"app.py": "value = 1\n"})
        with open(os.path.join(repo, "app.py"), "w", encoding="utf-8") as fh:
            fh.write("value = 2\n")
        m = run_manifest.build_manifest(target=repo, review_root=repo,
                                        host="claude", security_mode="standard")
        self.assertIs(m["target_dirty"], True)

    def test_a_non_git_target_records_nulls_not_a_crash(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            m = run_manifest.build_manifest(target=d, review_root=d,
                                            host="claude", security_mode="standard")
        self.assertIsNone(m["target_commit"])
        self.assertIsNone(m["target_dirty"])

    def test_provenance_is_not_an_anti_drift_flag(self):
        # A resumed run must not be refused because the tree moved under it --
        # that is a fact to RECORD, not a knob the user set. Only _FLAG_KEYS
        # drive the drift refusal.
        self.assertNotIn("target_commit", run_manifest._FLAG_KEYS)
        self.assertNotIn("target_dirty", run_manifest._FLAG_KEYS)


def _torn_dump(data, fh, **kwargs):
    """`json.dump` that emits part of the document and then dies -- the torn
    write, without needing a real signal."""
    fh.write(json.dumps(data, **kwargs)[:20])
    raise OSError("no space left on device")


class _TornHandle:
    """A handle whose write lands half its text and then dies."""

    def __init__(self, fh):
        self._fh = fh

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self._fh.close()
        return False

    def write(self, text):
        self._fh.write(text[:len(text) // 2])
        raise OSError("no space left on device")


def _torn_open(path):
    return _TornHandle(open(path, "w", encoding="utf-8"))


class TornBaselineTest(unittest.TestCase):
    """#1809 / DAT-4027033499: the baseline was written truncate-in-place behind
    an exists-means-done guard, so a write torn mid-way was PERMANENT. Every
    resume accepted the partial document (git is deliberately never re-probed),
    the run failed closed at validate forever, and the operator was told the
    baseline "predates content digests (schema v1)" -- a resume across an
    upgrade that never happened, which hides the real remedy (`--reset`).
    """

    def _repo(self):
        return make_git_repo(test_case=self, files={"app.py": "value = 1\n"})

    def _put(self, repo, text):
        """`text` as the baseline on disk, with no complete baseline before it."""
        path = runio._pano(repo, "tree-baseline.txt")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def _tear(self, repo):
        """Capture a complete v2 baseline, then truncate it at half its bytes."""
        path = validate_phase.capture_tree_baseline(repo)
        with open(path, encoding="utf-8") as fh:
            whole = fh.read()
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(whole[:len(whole) // 2])
        return path

    def test_a_torn_v2_baseline_is_diagnosed_as_corrupt_not_as_schema_v1(self):
        repo = self._repo()
        torn = self._tear(repo)
        with open(torn, encoding="utf-8") as fh:
            self.assertTrue(fh.read().startswith("{"))   # a v2 doc, not porcelain
        delta = validate_phase._tree_delta(repo, subprocess.run)
        self.assertTrue(delta)
        self.assertIn("CORRUPT", delta[0])
        self.assertIn("--reset", delta[0])
        self.assertNotIn("schema v1", delta[0])

    def test_a_torn_baseline_is_still_never_re_probed_on_resume(self):
        # The early return is load-bearing: re-probing `git status` here would
        # baseline the reviewer's OWN writes as clean. The write was the bug.
        repo = self._repo()
        path = self._tear(repo)

        def runner(*_a, **_k):
            raise AssertionError("git must not be re-probed on resume")

        self.assertEqual(validate_phase.capture_tree_baseline(repo, runner=runner), path)

    def test_a_genuine_v1_baseline_still_reads_as_schema_v1(self):
        repo = self._repo()
        path = runio._pano(repo, "tree-baseline.txt")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(" M app.py\0")                      # raw porcelain: no leading '{'
        delta = validate_phase._tree_delta(repo, subprocess.run)
        self.assertTrue(delta)
        self.assertIn("schema v1", delta[0])
        self.assertNotIn("CORRUPT", delta[0])

    def test_a_torn_capture_write_leaves_no_baseline_and_no_tmp(self):
        repo = self._repo()
        path = runio._pano(repo, "tree-baseline.txt")
        with mock.patch.object(json, "dump", _torn_dump), self.assertRaises(OSError):
            validate_phase.capture_tree_baseline(repo)
        self.assertFalse(os.path.exists(path),
                         "a partial baseline is what every later resume accepts")
        self.assertFalse(os.path.exists(path + ".tmp"), "staging file left behind")

    def test_a_torn_sentinel_write_keeps_the_previous_baseline_byte_identical(self):
        repo = self._repo()
        path = validate_phase.capture_tree_baseline(repo)
        with open(path, "rb") as fh:
            before = fh.read()
        with mock.patch.object(runio, "_open_w_nofollow", _torn_open), \
                self.assertRaises(OSError):
            validate_phase._write_probe_failed_baseline(path)
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(), before, "a failed write clobbered the baseline")
        self.assertFalse(os.path.exists(path + ".tmp"), "staging file left behind")

    def test_an_empty_baseline_is_diagnosed_as_empty_not_as_schema_v1(self):
        # The pre-fix writer's MOST likely torn shape: `O_TRUNC` succeeded and
        # the process died before the first buffer flushed. Telling that operator
        # the baseline "predates content digests" points at an upgrade that never
        # happened. Empty is genuinely ambiguous (a v1 baseline of a clean tree
        # WAS empty), so the message says so -- and still names the remedy.
        repo = self._repo()
        self._put(repo, "")
        delta = validate_phase._tree_delta(repo, subprocess.run)
        self.assertTrue(delta)
        self.assertIn("EMPTY", delta[0])
        self.assertIn("--reset", delta[0])
        self.assertNotIn("predates", delta[0])

    def test_a_whitespace_only_baseline_is_diagnosed_as_empty(self):
        repo = self._repo()
        self._put(repo, "   \n\t ")
        delta = validate_phase._tree_delta(repo, subprocess.run)
        self.assertIn("EMPTY", delta[0])
        self.assertIn("--reset", delta[0])

    def test_valid_json_that_is_not_an_object_is_corrupt(self):
        # "Parses to the wrong shape" is the other half of the classifier: a
        # porcelain record always opens with an XY status pair, so JSON that
        # parses to a list/number/null/string is never a v1 baseline.
        for raw in ("[1, 2]", "5", "null", '"hello"'):
            with self.subTest(raw=raw):
                repo = self._repo()
                self._put(repo, raw)
                delta = validate_phase._tree_delta(repo, subprocess.run)
                self.assertTrue(delta)
                self.assertIn("CORRUPT", delta[0])
                self.assertNotIn("predates", delta[0])

    def test_a_deeply_nested_baseline_fails_closed_instead_of_raising(self):
        # `json.loads` raises RecursionError -- a RuntimeError, so outside
        # `except ValueError` -- and driver.run catches (DriverError, ValueError)
        # only, so this ended the invocation with a traceback and no status JSON.
        repo = self._repo()
        self._put(repo, "[" * 200000)
        self.assertTrue(validate_phase._tree_delta(repo, subprocess.run))

    def test_the_run_recovers_from_a_torn_capture_write(self):
        # The end-to-end point of the fix: a torn write is no longer permanent,
        # so the next resume re-probes git and validate can certify again.
        repo = self._repo()
        with mock.patch.object(json, "dump", _torn_dump), self.assertRaises(OSError):
            validate_phase.capture_tree_baseline(repo)
        validate_phase.capture_tree_baseline(repo)
        self.assertEqual(validate_phase._tree_delta(repo, subprocess.run), [])

    def test_a_refused_write_never_deletes_a_file_outside_the_tree(self):
        # #1574's `_relink` shape: `.panopticon/runs` force-committed as a
        # symlink makes `<elsewhere>/<tag>/tree-baseline.txt.tmp` our staging
        # NAME -- but it was never our file, and a refusal must not delete it.
        # Cleanup belongs to what this call opened, not to whatever sits there.
        import tempfile
        repo = self._repo()
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(outside.cleanup)
        manifest = {"schema_version": 1, "run_id": "0123456789abcdef",
                    "host": "claude", "security_mode": "standard",
                    "created": "2026-09-20T00:00:00Z", "review_root": repo,
                    "target": repo}
        run_manifest.write_manifest(repo, manifest)
        tag = run_manifest.run_tag(manifest)
        os.symlink(outside.name, os.path.join(repo, ".panopticon", "runs"))
        os.makedirs(os.path.join(outside.name, tag))
        keep = os.path.join(outside.name, tag, "tree-baseline.txt.tmp")
        with open(keep, "w", encoding="utf-8") as fh:
            fh.write("NOT OURS")
        self.assertEqual(runio._pano(repo, "tree-baseline.txt"),
                         os.path.join(repo, ".panopticon", "runs", tag,
                                      "tree-baseline.txt"))   # the plant redirects us
        with self.assertRaises(ValueError):
            validate_phase.capture_tree_baseline(repo)
        self.assertTrue(os.path.exists(keep), "a refusal deleted a file outside the tree")
        with open(keep, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "NOT OURS")

    def test_a_completed_capture_leaves_no_staging_file(self):
        path = validate_phase.capture_tree_baseline(self._repo())
        self.assertFalse(os.path.exists(path + ".tmp"))


if __name__ == "__main__":
    unittest.main()
