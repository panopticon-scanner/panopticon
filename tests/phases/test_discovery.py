"""Tests for scripts.phases.discovery: the repo-profiling phase.
"""
import json
import os
import tempfile
import unittest
from unittest import mock

import scripts.phases.runio as runio
import scripts.phases.discovery as discovery


class TestDiscoveryPhase(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        os.makedirs(os.path.join(self.root, ".panopticon"))
        self.addCleanup(self._t.cleanup)
        self.manifest = {"run_id": "R", "security_mode": "standard"}

    def _write_groups_yml(self, body):
        with open(runio._pano(self.root, "groups.yml"), "w") as fh:
            fh.write(body)

    def test_missing_groups_yml_raises(self):
        with self.assertRaises(runio.DriverError):
            discovery.discovery_execute(self.root, self.manifest)

    def test_discovery_subprocesses_discovery_and_marks_done(self):
        self._write_groups_yml("groups:\n  Auth:\n    match: ['src/auth/**']\n")

        def fake_run(cmd, **kw):   # tolerant: driver passes cwd/env/capture_output
            out = cmd[cmd.index("--out") + 1]
            with open(out, "w") as fh:
                json.dump({"groups": [{"name": "Auth", "files": ["src/auth/a.py"]}]}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("subprocess.run", side_effect=fake_run):
            result = discovery.discovery_execute(self.root, self.manifest)
        self.assertEqual(result.kind, "advanced")
        self.assertTrue(discovery.discovery_done(self.root, self.manifest))

    def test_discovery_raises_when_no_groups_json_produced(self):
        self._write_groups_yml("groups:\n  Auth:\n    match: ['src/auth/**']\n")
        with mock.patch("subprocess.run",
                        return_value=mock.Mock(returncode=1, stdout="", stderr="boom")):
            with self.assertRaises(runio.DriverError):
                discovery.discovery_execute(self.root, self.manifest)

    def test_discovery_threads_scope_group_to_repo_scan(self):
        self._write_groups_yml("groups:\n  Auth:\n    match: ['src/auth/**']\n")
        manifest = dict(self.manifest, scope={"mode": "group", "target": "Auth"})

        def fake_run(cmd, **kw):
            out = cmd[cmd.index("--out") + 1]
            with open(out, "w") as fh:
                json.dump({"groups": [{"name": "Auth", "files": ["src/auth/a.py"]}]}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("subprocess.run", side_effect=fake_run) as run:
            result = discovery.discovery_execute(self.root, manifest)
        self.assertEqual(result.kind, "advanced")
        cmd = run.call_args.args[0]
        self.assertIn("--scope-group", cmd)
        self.assertIn("Auth", cmd)

    def test_discovery_repo_scope_appends_no_scope_arg(self):
        self._write_groups_yml("groups:\n  Auth:\n    match: ['src/auth/**']\n")
        manifest = dict(self.manifest, scope={"mode": "repo"})

        def fake_run(cmd, **kw):
            out = cmd[cmd.index("--out") + 1]
            with open(out, "w") as fh:
                json.dump({"groups": [{"name": "Auth", "files": ["src/auth/a.py"]}]}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("subprocess.run", side_effect=fake_run) as run:
            discovery.discovery_execute(self.root, manifest)
        cmd = run.call_args.args[0]
        self.assertNotIn("--scope-file", cmd)
        self.assertNotIn("--scope-dir", cmd)
        self.assertNotIn("--scope-group", cmd)

    def test_discovery_threads_changed_scope_with_base_and_diff_context(self):
        self._write_groups_yml("groups:\n  Auth:\n    match: ['src/auth/**']\n")
        manifest = dict(self.manifest, scope={"mode": "changed", "target": None},
                        base="main", flags={"diff_context": 5})

        def fake_run(cmd, **kw):
            out = cmd[cmd.index("--out") + 1]
            with open(out, "w") as fh:
                json.dump({"groups": [{"name": "Auth", "files": ["src/auth/a.py"]}]}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("subprocess.run", side_effect=fake_run) as run:
            result = discovery.discovery_execute(self.root, manifest)
        self.assertEqual(result.kind, "advanced")
        cmd = run.call_args.args[0]
        self.assertIn("--scope-changed", cmd)
        self.assertIn("--base", cmd)
        self.assertEqual(cmd[cmd.index("--base") + 1], "main")
        self.assertIn("--diff-context", cmd)
        self.assertEqual(cmd[cmd.index("--diff-context") + 1], "5")
        self.assertNotIn("--scope-file", cmd)
        self.assertNotIn("--scope-dir", cmd)
        self.assertNotIn("--scope-group", cmd)
        self.assertNotIn("--scope-files", cmd)

    def test_discovery_threads_files_scope_with_target_list(self):
        self._write_groups_yml("groups:\n  Auth:\n    match: ['src/auth/**']\n")
        manifest = dict(self.manifest,
                        scope={"mode": "files", "target": ["a.py", "b.py"]})

        def fake_run(cmd, **kw):
            out = cmd[cmd.index("--out") + 1]
            with open(out, "w") as fh:
                json.dump({"groups": [{"name": "Auth", "files": ["src/auth/a.py"]}]}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("subprocess.run", side_effect=fake_run) as run:
            result = discovery.discovery_execute(self.root, manifest)
        self.assertEqual(result.kind, "advanced")
        cmd = run.call_args.args[0]
        self.assertIn("--scope-files", cmd)
        i = cmd.index("--scope-files")
        self.assertEqual(cmd[i + 1:i + 3], ["a.py", "b.py"])
        self.assertNotIn("--base", cmd)
        self.assertNotIn("--diff-context", cmd)

    def test_discovery_threads_pr_base_when_present(self):
        # Finding B: a --pr manifest carries the gh-detected base in `pr_base`
        # (not `base`) so discovery.py resolves it with origin/<base> preference.
        self._write_groups_yml("groups:\n  Auth:\n    match: ['src/auth/**']\n")
        manifest = dict(self.manifest, scope={"mode": "changed", "target": None},
                        base=None, pr_base="main")

        def fake_run(cmd, **kw):
            out = cmd[cmd.index("--out") + 1]
            with open(out, "w") as fh:
                json.dump({"groups": [{"name": "Auth", "files": ["src/auth/a.py"]}]}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("subprocess.run", side_effect=fake_run) as run:
            result = discovery.discovery_execute(self.root, manifest)
        self.assertEqual(result.kind, "advanced")
        cmd = run.call_args.args[0]
        self.assertIn("--scope-changed", cmd)
        self.assertIn("--pr-base", cmd)
        self.assertEqual(cmd[cmd.index("--pr-base") + 1], "main")
        self.assertNotIn("--base", cmd)   # base is None -> not threaded

    def test_discovery_omits_pr_base_when_absent(self):
        # A -c/--files manifest (no PR) carries no pr_base -> discovery.py gets
        # no --pr-base and its byte-identical behavior is preserved.
        self._write_groups_yml("groups:\n  Auth:\n    match: ['src/auth/**']\n")
        manifest = dict(self.manifest, scope={"mode": "changed", "target": None},
                        base="main")

        def fake_run(cmd, **kw):
            out = cmd[cmd.index("--out") + 1]
            with open(out, "w") as fh:
                json.dump({"groups": [{"name": "Auth", "files": ["src/auth/a.py"]}]}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("subprocess.run", side_effect=fake_run) as run:
            discovery.discovery_execute(self.root, manifest)
        cmd = run.call_args.args[0]
        self.assertNotIn("--pr-base", cmd)
        self.assertIn("--base", cmd)
