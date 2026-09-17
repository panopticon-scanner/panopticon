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


class TestGroupsArtifactShape(unittest.TestCase):
    """#1643: `discovery_done` was `_json_parses`, so `{}` completed the phase.

    Coverage then derived zero groups, every later `all(...)` over an empty
    collection was true by definition, and the driver walked to a report having
    dispatched no review cell -- the failure shape that does not error, it
    succeeds emptily.
    """
    MANIFEST = {"run_id": "R", "security_mode": "standard"}
    REAL = {"run_id": "R", "security_mode": "standard", "mode": "repo",
            "groups": [{"name": "Auth", "files": ["src/auth/a.py"],
                        "chunk_of": "Auth", "panels": ["SEC"]}]}

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        os.makedirs(os.path.join(self.root, ".panopticon"))
        self.addCleanup(self._t.cleanup)

    def _write(self, doc):
        with open(runio._pano(self.root, "groups.json"), "w") as fh:
            json.dump(doc, fh)

    def test_the_real_producer_output_is_done(self):
        self._write(self.REAL)
        self.assertEqual(discovery.groups_artifact_errors(self.REAL, self.MANIFEST), [])
        self.assertTrue(discovery.discovery_done(self.root, self.MANIFEST))

    def test_an_empty_object_is_not_done(self):
        self._write({})
        self.assertFalse(discovery.discovery_done(self.root, self.MANIFEST))
        self.assertTrue(discovery.groups_artifact_errors({}, self.MANIFEST))

    def test_no_groups_is_not_done_on_a_whole_repo_scan(self):
        doc = dict(self.REAL, groups=[])
        self._write(doc)
        self.assertFalse(discovery.discovery_done(self.root, self.MANIFEST))

    def test_no_groups_IS_done_when_the_scope_selected_nothing(self):
        # A `-c` run whose delta matches no file is a real, deliberate empty
        # scope: discovery.py builds it from `git diff`, and zero groups is the
        # honest answer rather than a corrupt artifact.
        doc = dict(self.REAL, groups=[])
        self._write(doc)
        manifest = dict(self.MANIFEST, scope={"mode": "changed", "target": None})
        self.assertEqual(discovery.groups_artifact_errors(doc, manifest), [])
        self.assertTrue(discovery.discovery_done(self.root, manifest))

    def test_a_record_without_files_is_not_done(self):
        doc = dict(self.REAL, groups=[{"name": "Auth"}])
        self._write(doc)
        self.assertFalse(discovery.discovery_done(self.root, self.MANIFEST))

    def test_a_record_without_a_name_is_not_done(self):
        doc = dict(self.REAL, groups=[{"name": "", "files": ["a.py"]}])
        self._write(doc)
        self.assertFalse(discovery.discovery_done(self.root, self.MANIFEST))

    def test_a_foreign_runs_artifact_is_not_done(self):
        self._write(dict(self.REAL, run_id="SOMEONE-ELSE"))
        self.assertFalse(discovery.discovery_done(self.root, self.MANIFEST))

    def test_a_groups_value_that_is_not_a_list_is_not_done(self):
        self._write(dict(self.REAL, groups={"Auth": ["a.py"]}))
        self.assertFalse(discovery.discovery_done(self.root, self.MANIFEST))


class TestMalformedProducerOutput(unittest.TestCase):
    """#1643: the child writes an artifact that parses but says nothing.

    One re-run is free (a truncated write is worth retrying); the SECOND
    identical malformed round ends the run `error` rather than letting the
    engine spin or the phase pass emptily.
    """

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        os.makedirs(os.path.join(self.root, ".panopticon"))
        self.addCleanup(self._t.cleanup)
        with open(runio._pano(self.root, "groups.yml"), "w") as fh:
            fh.write("groups:\n  Auth:\n    match: ['src/auth/**']\n")
        self.manifest = {"run_id": "R", "security_mode": "standard"}

    @staticmethod
    def _writes(doc):
        def fake_run(cmd, **kw):
            with open(cmd[cmd.index("--out") + 1], "w") as fh:
                json.dump(doc, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")
        return fake_run

    def test_the_first_malformed_round_retries_and_the_second_errors(self):
        with mock.patch("subprocess.run", side_effect=self._writes({})):
            first = discovery.discovery_execute(self.root, self.manifest)
            self.assertEqual(first.kind, "advanced")
            self.assertFalse(discovery.discovery_done(self.root, self.manifest))
            with self.assertRaises(runio.DriverError) as cm:
                discovery.discovery_execute(self.root, self.manifest)
        self.assertIn("discovery produced no usable groups", str(cm.exception))
        self.assertEqual(runio._error_status(str(cm.exception))["status"], "error")

    def test_a_good_round_after_a_malformed_one_is_accepted(self):
        with mock.patch("subprocess.run", side_effect=self._writes({})):
            discovery.discovery_execute(self.root, self.manifest)
        good = {"groups": [{"name": "Auth", "files": ["src/auth/a.py"]}]}
        with mock.patch("subprocess.run", side_effect=self._writes(good)):
            result = discovery.discovery_execute(self.root, self.manifest)
        self.assertEqual(result.kind, "advanced")
        self.assertTrue(discovery.discovery_done(self.root, self.manifest))
