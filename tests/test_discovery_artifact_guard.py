"""Artifact-output symlink-escape and scope-guard tests."""
import os
import contextlib
import io
import tempfile
import unittest
from unittest import mock

from discovery_test_helpers import orchestrator, touch, init_repo, git_cmd


class TestArtifactOutputGuard(unittest.TestCase):
    """Symlink-escape guards on the --out artifact root, migrated out of
    test_orchestrator.py::TestSetup (the rest of that class -- --setup
    scaffolding/readiness -- is covered by test_setup_flow.py and
    test_driver.py::TestDriverSetup)."""

    def test_artifact_output_rejects_symlinked_panopticon(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as outside:
            os.symlink(outside, os.path.join(d, ".panopticon"))
            with self.assertRaisesRegex(ValueError, "not a symlink"):
                orchestrator._validate_artifact_output(
                    d, os.path.join(d, ".panopticon", "groups.json"))

    def test_main_rejects_symlinked_artifact_root(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as outside:
            os.symlink(outside, os.path.join(d, ".panopticon"))
            self.assertEqual(orchestrator.main(["--repo", d, "--repo-scan"]), 2)
            self.assertEqual(orchestrator.main(["--repo", d, "--repo-scan", "--out", os.path.join(d, ".panopticon", "out.json")]), 2)

    def test_scope_changed_non_git_repo_refuses_base_resolution(self):
        with tempfile.TemporaryDirectory() as d:
            touch(d, "src/app.py")
            # Base resolution refuses a non-git repo before collection begins.
            self.assertEqual(orchestrator.main(["--repo", d, "--repo-scan", "--scope-changed"]), 2)

    def test_scope_changed_collection_failure_refuses_artifact(self):
        with tempfile.TemporaryDirectory() as d:
            touch(d, "src/app.py")
            init_repo(d)
            git_cmd(d, "add", ".")
            git_cmd(d, "commit", "-q", "-m", "init")
            out = os.path.join(d, ".panopticon", "changed.json")
            stderr = io.StringIO()
            with mock.patch.object(orchestrator, "collect_changed_files", return_value=None) as collect, \
                    contextlib.redirect_stderr(stderr):
                rc = orchestrator.main(["--repo", d, "--repo-scan", "--scope-changed",
                                        "--base", "HEAD", "--out", out])
            self.assertTrue(collect.called)
            self.assertEqual(rc, 2)
            self.assertEqual(stderr.getvalue(),
                             "could not determine changed files; is %s a git repo?\n" % d)
            self.assertFalse(os.path.exists(out))

    def test_scope_files_fails_with_bad_base(self):
        with tempfile.TemporaryDirectory() as d:
            touch(d, "src/app.py")
            init_repo(d)
            git_cmd(d, "add", ".")
            git_cmd(d, "commit", "-q", "-m", "init")
            # bad base -> resolve_base_or_die returns None -> return 2
            self.assertEqual(orchestrator.main(["--repo", d, "--repo-scan", "--scope-files", "src/app.py", "--base", "nope"]), 2)
