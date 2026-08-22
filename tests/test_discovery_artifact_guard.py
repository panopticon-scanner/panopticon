"""Artifact-output symlink-escape and scope-guard tests."""
import os
import tempfile
import unittest

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

    def test_scope_changed_fails_when_not_git_repo(self):
        with tempfile.TemporaryDirectory() as d:
            touch(d, "src/app.py")
            # d is not a git repo, so collect_changed_files returns None
            self.assertEqual(orchestrator.main(["--repo", d, "--repo-scan", "--scope-changed"]), 2)

    def test_scope_files_fails_with_bad_base(self):
        with tempfile.TemporaryDirectory() as d:
            touch(d, "src/app.py")
            init_repo(d)
            git_cmd(d, "add", ".")
            git_cmd(d, "commit", "-q", "-m", "init")
            # bad base -> resolve_base_or_die returns None -> return 2
            self.assertEqual(orchestrator.main(["--repo", d, "--repo-scan", "--scope-files", "src/app.py", "--base", "nope"]), 2)
