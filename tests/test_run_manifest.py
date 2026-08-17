import os
import tempfile
import unittest
from unittest import mock

import scripts.run_manifest as rm


class TestRunManifest(unittest.TestCase):
    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.root = self._d.name
        self.addCleanup(self._d.cleanup)

    def test_write_manifest_does_not_truncate_existing(self):   # #1033
        rm.write_manifest(self.root, {"run_id": "first"})
        with self.assertRaises(FileExistsError):
            rm.write_manifest(self.root, {"run_id": "second"})
        # the refused write must NOT have truncated the original ("x", not "w")
        self.assertEqual(rm.load_manifest(self.root)["run_id"], "first")

    def test_reset_run_propagates_real_removal_error(self):   # #1033
        rm.write_manifest(self.root, {"run_id": "x"})
        with mock.patch("scripts.run_manifest.os.remove",
                        side_effect=PermissionError("denied")):
            with self.assertRaises(PermissionError):
                rm.reset_run(self.root)      # a REAL failure must not be swallowed
        # an absent manifest stays a benign False (FileNotFoundError only)
        with tempfile.TemporaryDirectory() as empty:
            self.assertFalse(rm.reset_run(empty))

    def _params(self, **over):
        p = dict(target=self.root, review_root=self.root, host="claude",
                 security_mode="standard", base=None,
                 flags={"fail_on": "high", "severity": "all", "tools": True})
        p.update(over)
        return p

    def test_build_manifest_shape(self):
        m = rm.build_manifest(**self._params())
        self.assertEqual(m["schema_version"], rm.SCHEMA_VERSION)
        self.assertTrue(m["run_id"])
        self.assertEqual(m["review_root"], os.path.abspath(self.root))
        self.assertEqual(m["host"], "claude")
        self.assertEqual(m["security_mode"], "standard")
        # only the recognized flag keys are retained
        self.assertEqual(set(m["flags"]), set(rm._FLAG_KEYS))
        self.assertEqual(m["flags"]["fail_on"], "high")

    def test_worktree_defaults_none_and_is_stored(self):
        self.assertIsNone(rm.build_manifest(**self._params())["worktree"])
        m = rm.build_manifest(**self._params(), worktree="/tmp/pr-wt")
        self.assertEqual(m["worktree"], "/tmp/pr-wt")

    def test_new_run_id_is_distinct(self):
        self.assertNotEqual(rm.new_run_id(), rm.new_run_id())

    def test_write_once_then_load(self):
        m = rm.build_manifest(**self._params())
        path = rm.write_manifest(self.root, m)
        self.assertTrue(os.path.isfile(path))
        loaded = rm.load_manifest(self.root)
        self.assertEqual(loaded["run_id"], m["run_id"])

    def test_write_refuses_second_write(self):
        rm.write_manifest(self.root, rm.build_manifest(**self._params()))
        with self.assertRaises(FileExistsError):
            rm.write_manifest(self.root, rm.build_manifest(**self._params()))

    def test_load_absent_returns_none(self):
        self.assertIsNone(rm.load_manifest(self.root))

    def test_load_unparseable_returns_none(self):
        os.makedirs(os.path.join(self.root, ".panopticon"), exist_ok=True)
        with open(rm.manifest_path(self.root), "w") as fh:
            fh.write("{ not json")
        self.assertIsNone(rm.load_manifest(self.root))

    def test_no_conflict_when_incoming_none(self):
        # a bare `driver run` re-invocation passes nothing -> always resumes
        m = rm.build_manifest(**self._params())
        self.assertEqual(rm.conflicting_flags(m), [])

    def test_no_conflict_when_matching(self):
        m = rm.build_manifest(**self._params())
        self.assertEqual(
            rm.conflicting_flags(m, security_mode="standard",
                                 flags={"fail_on": "high"}),
            [])

    def test_conflict_on_differing_security_mode(self):
        m = rm.build_manifest(**self._params())
        conflicts = rm.conflicting_flags(m, security_mode="redteam")
        self.assertEqual(len(conflicts), 1)
        self.assertIn("security_mode", conflicts[0])

    def test_conflict_on_differing_flag(self):
        m = rm.build_manifest(**self._params())
        conflicts = rm.conflicting_flags(m, flags={"fail_on": "critical"})
        self.assertTrue(any("fail_on" in c for c in conflicts))

    def test_reset_removes_manifest(self):
        rm.write_manifest(self.root, rm.build_manifest(**self._params()))
        self.assertTrue(rm.reset_run(self.root))
        self.assertIsNone(rm.load_manifest(self.root))
        self.assertFalse(rm.reset_run(self.root))  # idempotent: nothing to remove

    def test_scope_defaults_to_repo(self):
        m = rm.build_manifest(**self._params())
        self.assertEqual(m["scope"], {"mode": "repo", "target": None})

    def test_scope_recorded_and_conflict_detected(self):
        m = rm.build_manifest(**self._params(
            scope={"mode": "group", "target": "Auth"}))
        self.assertEqual(m["scope"], {"mode": "group", "target": "Auth"})
        conflicts = rm.conflicting_flags(
            m, scope={"mode": "group", "target": "Checkout"})
        self.assertTrue(any("scope" in c for c in conflicts))

    def test_pr_defaults_none_and_is_stored(self):
        self.assertIsNone(rm.build_manifest(**self._params())["pr"])
        m = rm.build_manifest(**self._params(), pr=7)
        self.assertEqual(m["pr"], 7)

    def test_scope_changed_and_pr_recorded_and_conflict(self):
        m = rm.build_manifest(target=".", review_root=".", host="claude",
                              security_mode="standard", base="main",
                              scope={"mode": "changed", "target": None}, pr=7)
        self.assertEqual(m["scope"]["mode"], "changed")
        self.assertEqual(m["pr"], 7)
        conflicts = rm.conflicting_flags(m, pr=9)
        self.assertTrue(any("pr" in c for c in conflicts))

    def test_pr_base_defaults_none_and_is_stored(self):
        # Finding B: pr_base is a DERIVED field (like worktree) -- the gh-detected
        # PR base, threaded to orchestrator's --pr-base for origin-preference.
        self.assertIsNone(rm.build_manifest(**self._params())["pr_base"])
        m = rm.build_manifest(**self._params(), pr_base="main")
        self.assertEqual(m["pr_base"], "main")

    def test_pr_base_is_not_an_anti_drift_key(self):
        # A PR's base is fixed by the PR, not a user knob -- pr_base must NOT be a
        # conflicting_flags key (only pr/scope/base gate drift).
        m = rm.build_manifest(**self._params(), pr_base="main")
        self.assertEqual(rm.conflicting_flags(m), [])


if __name__ == "__main__":
    unittest.main()
