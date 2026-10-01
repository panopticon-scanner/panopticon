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

    def _write_config(self, body):
        with open(os.path.join(self.root, "panopticon.yml"), "w") as fh:
            fh.write("version: 1\n")
            fh.write(body)

    def test_missing_config_raises(self):
        with self.assertRaises(runio.DriverError):
            discovery.discovery_execute(self.root, self.manifest)

    def test_discovery_subprocesses_discovery_and_marks_done(self):
        self._write_config("groups:\n  Auth:\n    match: ['src/auth/**']\n")

        def fake_run(cmd, **kw):   # tolerant: driver passes cwd/env/capture_output
            out = cmd[cmd.index("--out") + 1]
            with open(out, "w") as fh:
                json.dump({"groups": [{"name": "Auth", "files": ["src/auth/a.py"]}]}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("scripts.phases.child._run_child", side_effect=fake_run):
            result = discovery.discovery_execute(self.root, self.manifest)
        self.assertEqual(result.kind, "advanced")
        self.assertTrue(discovery.discovery_done(self.root, self.manifest))

    def test_discovery_raises_when_no_groups_json_produced(self):
        self._write_config("groups:\n  Auth:\n    match: ['src/auth/**']\n")
        with mock.patch("scripts.phases.child._run_child",
                        return_value=mock.Mock(returncode=1, stdout="", stderr="boom")):
            with self.assertRaises(runio.DriverError):
                discovery.discovery_execute(self.root, self.manifest)

    def test_missing_groups_redacts_complete_key_before_limiting_error(self):
        self._write_config("groups:\n  Auth:\n    match: ['src/auth/**']\n")
        key_type = "PRIVATE KEY"
        key = (f"-----BEGIN {key_type}-----\n" + "A" * 80
               + f"\n-----END {key_type}-----")
        stderr = "x" * 360 + key + " trailing diagnostic"
        with mock.patch("scripts.phases.child._run_child",
                        return_value=mock.Mock(returncode=1, stdout="", stderr=stderr)):
            with self.assertRaises(runio.DriverError) as caught:
                discovery.discovery_execute(self.root, self.manifest)
        error = str(caught.exception)
        self.assertIn("[REDACTED_PRIVATE_KEY]", error)
        self.assertNotIn("-----BEGIN PRIVATE", error)
        self.assertNotIn("A" * 20, error)
        status = runio._error_status(error)
        self.assertEqual(status["status"], "error")
        self.assertNotIn("-----BEGIN PRIVATE", str(status))

    def test_missing_groups_redacts_dangling_key(self):
        self._write_config("groups:\n  Auth:\n    match: ['src/auth/**']\n")
        key_type = "PRIVATE KEY"
        key = (f"-----BEGIN {key_type}-----\n" + "A" * 2000)
        stderr = "x" * 360 + key + " trailing diagnostic"
        with mock.patch("scripts.phases.child._run_child",
                        return_value=mock.Mock(returncode=1, stdout="", stderr=stderr)):
            with self.assertRaises(runio.DriverError) as caught:
                discovery.discovery_execute(self.root, self.manifest)
        error = str(caught.exception)
        self.assertIn("[REDACTED_PRIVATE_KEY]", error)
        self.assertNotIn("-----BEGIN PRIVATE", error)
        self.assertNotIn("A" * 20, error)
        status = runio._error_status(error)
        self.assertEqual(status["status"], "error")
        self.assertNotIn("-----BEGIN PRIVATE", str(status))

    def test_discovery_threads_scope_group_to_repo_scan(self):
        self._write_config("groups:\n  Auth:\n    match: ['src/auth/**']\n")
        manifest = dict(self.manifest, scope={"mode": "group", "target": "Auth"})

        def fake_run(cmd, **kw):
            out = cmd[cmd.index("--out") + 1]
            with open(out, "w") as fh:
                json.dump({"groups": [{"name": "Auth", "files": ["src/auth/a.py"]}]}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("scripts.phases.child._run_child", side_effect=fake_run) as run:
            result = discovery.discovery_execute(self.root, manifest)
        self.assertEqual(result.kind, "advanced")
        cmd = run.call_args.args[0]
        self.assertIn("--scope-group", cmd)
        self.assertIn("Auth", cmd)

    def test_discovery_repo_scope_appends_no_scope_arg(self):
        self._write_config("groups:\n  Auth:\n    match: ['src/auth/**']\n")
        manifest = dict(self.manifest, scope={"mode": "repo"})

        def fake_run(cmd, **kw):
            out = cmd[cmd.index("--out") + 1]
            with open(out, "w") as fh:
                json.dump({"groups": [{"name": "Auth", "files": ["src/auth/a.py"]}]}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("scripts.phases.child._run_child", side_effect=fake_run) as run:
            discovery.discovery_execute(self.root, manifest)
        cmd = run.call_args.args[0]
        self.assertNotIn("--scope-file", cmd)
        self.assertNotIn("--scope-dir", cmd)
        self.assertNotIn("--scope-group", cmd)

    def test_discovery_threads_changed_scope_with_base_and_diff_context(self):
        self._write_config("groups:\n  Auth:\n    match: ['src/auth/**']\n")
        manifest = dict(self.manifest, scope={"mode": "changed", "target": None},
                        base="main", flags={"diff_context": 5})

        def fake_run(cmd, **kw):
            out = cmd[cmd.index("--out") + 1]
            with open(out, "w") as fh:
                json.dump({"groups": [{"name": "Auth", "files": ["src/auth/a.py"]}]}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("scripts.phases.child._run_child", side_effect=fake_run) as run:
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
        self._write_config("groups:\n  Auth:\n    match: ['src/auth/**']\n")
        manifest = dict(self.manifest,
                        scope={"mode": "files", "target": ["a.py", "b.py"]})

        def fake_run(cmd, **kw):
            out = cmd[cmd.index("--out") + 1]
            with open(out, "w") as fh:
                json.dump({"groups": [{"name": "Auth", "files": ["src/auth/a.py"]}]}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("scripts.phases.child._run_child", side_effect=fake_run) as run:
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
        self._write_config("groups:\n  Auth:\n    match: ['src/auth/**']\n")
        manifest = dict(self.manifest, scope={"mode": "changed", "target": None},
                        base=None, pr_base="main")

        def fake_run(cmd, **kw):
            out = cmd[cmd.index("--out") + 1]
            with open(out, "w") as fh:
                json.dump({"groups": [{"name": "Auth", "files": ["src/auth/a.py"]}]}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("scripts.phases.child._run_child", side_effect=fake_run) as run:
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
        self._write_config("groups:\n  Auth:\n    match: ['src/auth/**']\n")
        manifest = dict(self.manifest, scope={"mode": "changed", "target": None},
                        base="main")

        def fake_run(cmd, **kw):
            out = cmd[cmd.index("--out") + 1]
            with open(out, "w") as fh:
                json.dump({"groups": [{"name": "Auth", "files": ["src/auth/a.py"]}]}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("scripts.phases.child._run_child", side_effect=fake_run) as run:
            discovery.discovery_execute(self.root, manifest)
        cmd = run.call_args.args[0]
        self.assertNotIn("--pr-base", cmd)
        self.assertIn("--base", cmd)

    def test_discovery_threads_pr_worktree_when_the_manifest_has_a_pr(self):
        # #1681: under --pr the review root IS the throwaway worktree, and
        # `diff_map._sync_config` has already overwritten its root config with
        # the operator's copy. `--pr-worktree` is what tells discovery.py to
        # keep that sync out of diff-hunks.json rather than attribute it to the
        # PR -- nothing pinned the flag's emission, so a dropped `if` would
        # have published the operator's own config edit as a reviewable hunk.
        self._write_config("groups:\n  Auth:\n    match: ['src/auth/**']\n")
        manifest = dict(self.manifest, scope={"mode": "changed", "target": None},
                        base=None, pr_base="main", pr=7)

        def fake_run(cmd, **kw):
            out = cmd[cmd.index("--out") + 1]
            with open(out, "w") as fh:
                json.dump({"groups": [{"name": "Auth", "files": ["src/auth/a.py"]}]}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("scripts.phases.child._run_child", side_effect=fake_run) as run:
            result = discovery.discovery_execute(self.root, manifest)
        self.assertEqual(result.kind, "advanced")
        self.assertIn("--pr-worktree", run.call_args.args[0])

    def test_discovery_omits_pr_worktree_without_a_pr(self):
        # The other half: a plain -c/--base run in the operator's OWN checkout
        # carries no `pr`, and excluding the config names there would hide a
        # real reviewable change to them.
        self._write_config("groups:\n  Auth:\n    match: ['src/auth/**']\n")
        manifest = dict(self.manifest, scope={"mode": "changed", "target": None},
                        base="main")

        def fake_run(cmd, **kw):
            out = cmd[cmd.index("--out") + 1]
            with open(out, "w") as fh:
                json.dump({"groups": [{"name": "Auth", "files": ["src/auth/a.py"]}]}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("scripts.phases.child._run_child", side_effect=fake_run) as run:
            discovery.discovery_execute(self.root, manifest)
        self.assertNotIn("--pr-worktree", run.call_args.args[0])


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

    def test_a_group_with_an_EMPTY_file_list_is_not_done(self):
        # Fix round 1 F4: `groups: [{"name": "A", "files": []}]` is the same
        # empty success one level down -- the artifact has a record, the run
        # has no file under review, and every per-group `all(...)` is again
        # true over nothing. Only the scopes that may select nothing are
        # allowed to land here.
        doc = dict(self.REAL, groups=[{"name": "A", "files": []}])
        self._write(doc)
        self.assertFalse(discovery.discovery_done(self.root, self.MANIFEST))
        manifest = dict(self.MANIFEST, scope={"mode": "changed", "target": None})
        self.assertEqual(discovery.groups_artifact_errors(doc, manifest), [])

    def test_one_empty_group_beside_a_real_one_is_fine(self):
        # Discovery legitimately emits an empty leaf beside real ones; the rule
        # is about the WHOLE artifact reviewing nothing, not about each record.
        doc = dict(self.REAL, groups=[{"name": "A", "files": []},
                                      {"name": "B", "files": ["src/b.py"]}])
        self._write(doc)
        self.assertTrue(discovery.discovery_done(self.root, self.MANIFEST))

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
        with open(os.path.join(self.root, "panopticon.yml"), "w") as fh:
            fh.write("version: 1\n")
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
        with mock.patch("scripts.phases.child._run_child", side_effect=self._writes({})):
            first = discovery.discovery_execute(self.root, self.manifest)
            self.assertEqual(first.kind, "advanced")
            self.assertFalse(discovery.discovery_done(self.root, self.manifest))
            with self.assertRaises(runio.DriverError) as cm:
                discovery.discovery_execute(self.root, self.manifest)
        self.assertIn("discovery produced no usable groups", str(cm.exception))
        self.assertEqual(runio._error_status(str(cm.exception))["status"], "error")

    def test_a_child_that_writes_NOTHING_cannot_launder_a_previous_inventory(self):
        """Fix round 1 F2: the stamp is applied to whatever is on disk.

        A previous run's `groups.json` is still in the folder, the child exits
        non-zero without writing, and the driver stamped THIS run's `run_id`
        onto the stale artifact -- which then passed the shape check, reported
        "groups.json written" and read as done. The artifact must be removed
        before the child runs, so "the child produced nothing" cannot be
        answered by someone else's inventory.
        """
        stale = {"run_id": "PREVIOUS", "mode": "repo",
                 "groups": [{"name": "Old", "files": ["gone/a.py"]}]}
        with open(runio._pano(self.root, "groups.json"), "w") as fh:
            json.dump(stale, fh)

        def writes_nothing(cmd, **kw):
            return mock.Mock(returncode=1, stdout="", stderr="boom")

        with mock.patch("scripts.phases.child._run_child", side_effect=writes_nothing):
            with self.assertRaises(runio.DriverError) as cm:
                discovery.discovery_execute(self.root, self.manifest)
        self.assertIn("produced no groups.json", str(cm.exception))
        self.assertFalse(discovery.discovery_done(self.root, self.manifest))

    def test_a_directory_at_the_artifact_path_is_a_clean_driver_error(self):
        """Fix round 2 L2: the F2 removal must not turn a hostile path into a
        traceback. `groups.json` is inside `.panopticon`, which the reviewed
        target can pre-commit; a directory there made `os.remove` raise
        IsADirectoryError out of the phase, where the base code reached a clean
        `DriverError` (and `driver run` a `status: error`) instead."""
        os.mkdir(runio._pano(self.root, "groups.json"))

        def never_runs(cmd, **kw):                    # pragma: no cover
            raise AssertionError("the child must not be launched")

        with mock.patch("scripts.phases.child._run_child", side_effect=never_runs):
            with self.assertRaises(runio.DriverError) as cm:
                discovery.discovery_execute(self.root, self.manifest)
        self.assertIn("cannot clear", str(cm.exception))
        self.assertEqual(runio._error_status(str(cm.exception))["status"], "error")

    def test_a_good_round_after_a_malformed_one_is_accepted(self):
        with mock.patch("scripts.phases.child._run_child", side_effect=self._writes({})):
            discovery.discovery_execute(self.root, self.manifest)
        good = {"groups": [{"name": "Auth", "files": ["src/auth/a.py"]}]}
        with mock.patch("scripts.phases.child._run_child", side_effect=self._writes(good)):
            result = discovery.discovery_execute(self.root, self.manifest)
        self.assertEqual(result.kind, "advanced")
        self.assertTrue(discovery.discovery_done(self.root, self.manifest))


class TestTheDiffHunksGenerationStamp(unittest.TestCase):
    """#2107: the delta half of discovery's output, bound to the groups half.

    One child writes `diff-hunks.json` and then `groups.json`, as two
    INDEPENDENT atomic writes, and only the groups half carried the run
    binding. The #2107 probe traced all eight driver paths and could not
    assemble old-groups + new-hunks -- the pre-child clear, the
    hunks-before-groups write order and the per-run folder each stop it -- but
    the invariant was STRUCTURAL and undeclared: one reordering of
    `discovery.main`, or one "we can reuse the old groups.json" optimisation,
    silently turns it into the mixed pair the probe reached by hand, where the
    review's cells and the gate's scope come from different generations.

    So the sibling gets the SAME stamp, from the same party for the same
    reason, and `phases/synthesize.py` requires it. Stamped here and not in
    `discovery.write_diff_hunks` because the child is a repo profiler with no
    notion of a run -- it also serves `panopticon discovery` by hand.
    """

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        os.makedirs(os.path.join(self.root, ".panopticon"))
        self.addCleanup(self._t.cleanup)
        with open(os.path.join(self.root, "panopticon.yml"), "w") as fh:
            fh.write("version: 1\n")
            fh.write("groups:\n  Auth:\n    match: ['src/auth/**']\n")
        self.manifest = {"run_id": "R", "security_mode": "standard",
                         "scope": {"mode": "changed", "target": None},
                         "base": "main"}

    @property
    def _hunks_path(self):
        return runio._pano(self.root, "diff-hunks.json")

    def _hunks(self):
        return runio._load_json(self._hunks_path)

    def _child(self, groups=True, hunks=None, rc=0):
        """A child that writes the halves it is told to, in the real order:
        `diff-hunks.json` first (`discovery.py:1852-1862`), `groups.json`
        second (`discovery.py:1911-1923`)."""
        def fake_run(cmd, **kw):
            if hunks is not None:
                with open(self._hunks_path, "w") as fh:
                    json.dump(hunks, fh)
            if groups:
                with open(cmd[cmd.index("--out") + 1], "w") as fh:
                    json.dump({"groups": [{"name": "Auth",
                                           "files": ["src/auth/a.py"]}]}, fh)
            return mock.Mock(returncode=rc, stdout="", stderr="boom")
        return fake_run

    PAYLOAD = {"schema_version": 1, "base": "main", "hunks": {"a.py": [[1, 5]]}}

    def test_a_successful_child_leaves_both_halves_stamped_for_this_run(self):
        with mock.patch("scripts.phases.child._run_child",
                        side_effect=self._child(hunks=dict(self.PAYLOAD))):
            result = discovery.discovery_execute(self.root, self.manifest)
        self.assertEqual(result.kind, "advanced")
        self.assertEqual(self._hunks()["run_id"], "R")
        self.assertEqual(runio._load_json(runio._pano(self.root,
                                                      "groups.json"))["run_id"], "R")
        # The stamp is ADDED, not a rewrite: every field the child wrote has to
        # survive, or the gate scopes against a different diff than was measured.
        self.assertEqual(self._hunks()["hunks"], {"a.py": [[1, 5]]})
        self.assertEqual(self._hunks()["base"], "main")
        self.assertEqual(self._hunks()["schema_version"], 1)

    def test_a_stale_generations_stamp_is_replaced_not_kept(self):
        # The child rewrites the artifact from one tree state, so whatever
        # stamp a previous run left is gone with the bytes it was written on.
        with open(self._hunks_path, "w") as fh:
            json.dump(dict(self.PAYLOAD, run_id="PREVIOUS"), fh)
        with mock.patch("scripts.phases.child._run_child",
                        side_effect=self._child(hunks=dict(self.PAYLOAD))):
            discovery.discovery_execute(self.root, self.manifest)
        self.assertEqual(self._hunks()["run_id"], "R")

    def test_an_orphan_hunks_file_with_no_groups_still_raises(self):
        """Probe state Q1-B: `os.replace` dies on the groups write after the
        hunks write committed. The pre-child clear ate the previous
        `groups.json`, so the surviving half-pair is missing the half that IS
        checked, and the phase is terminal -- `synthesize` is the last phase in
        `driver.PHASES` and is never reached with the orphan. Unchanged by this
        issue, and pinned here because the stamp must not become a second,
        softer answer to "did discovery happen"."""
        with mock.patch("scripts.phases.child._run_child",
                        side_effect=self._child(groups=False,
                                                hunks=dict(self.PAYLOAD))):
            with self.assertRaises(runio.DriverError) as cm:
                discovery.discovery_execute(self.root, self.manifest)
        self.assertIn("produced no groups.json", str(cm.exception))
        self.assertFalse(discovery.discovery_done(self.root, self.manifest))
        # The orphan survives on disk, UNSTAMPED: it was never bound to a
        # generation, which is exactly what makes `phases/synthesize.py` refuse
        # it if a later resume were ever to reach that phase with it.
        self.assertTrue(os.path.isfile(self._hunks_path))
        self.assertNotIn("run_id", self._hunks())

    def test_a_non_object_artifact_is_left_for_the_loader_to_reject(self):
        # Rewriting it would replace the operator's broken bytes with
        # different broken bytes, and `synth/delta.py` already rejects a
        # non-object payload on its own terms (`not an object`).
        with mock.patch("scripts.phases.child._run_child",
                        side_effect=self._child(hunks=["not", "an", "object"])):
            discovery.discovery_execute(self.root, self.manifest)
        self.assertEqual(self._hunks(), ["not", "an", "object"])

    def test_an_unreadable_artifact_is_left_alone_too(self):
        def writes_garbage(cmd, **kw):
            with open(self._hunks_path, "w") as fh:
                fh.write("{not json")
            with open(cmd[cmd.index("--out") + 1], "w") as fh:
                json.dump({"groups": [{"name": "Auth",
                                       "files": ["src/auth/a.py"]}]}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch("scripts.phases.child._run_child", side_effect=writes_garbage):
            result = discovery.discovery_execute(self.root, self.manifest)
        self.assertEqual(result.kind, "advanced")
        with open(self._hunks_path, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "{not json")

    def test_a_non_delta_run_has_nothing_to_stamp_and_creates_nothing(self):
        # `discovery.py`'s non-delta branch REMOVES a stale hunks file
        # (#5.0-07), so there is no artifact here -- and the stamp must not
        # conjure one, which would hand synthesize an empty delta to scope by.
        manifest = {"run_id": "R", "security_mode": "standard",
                    "scope": {"mode": "repo"}}
        with mock.patch("scripts.phases.child._run_child", side_effect=self._child()):
            result = discovery.discovery_execute(self.root, manifest)
        self.assertEqual(result.kind, "advanced")
        self.assertFalse(os.path.exists(self._hunks_path))
