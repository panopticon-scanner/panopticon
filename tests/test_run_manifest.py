import contextlib
import io
import json
import os
import re
import tempfile
import unittest
from unittest import mock

import scripts.config_schema as cs
import scripts.run_manifest as rm
from scripts import hosts


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

    def test_tools_downgrade_is_one_way_and_only_for_an_explicit_false(self):
        for original in (True, None):
            with self.subTest(original=original):
                m = rm.build_manifest(**self._params(flags={"tools": original,
                                                          "fail_on": "high"}))
                self.assertTrue(rm.is_tools_downgrade(m, {"tools": False}))
                self.assertEqual(rm.conflicting_flags(m, flags={"tools": False}), [])
                self.assertFalse(rm.is_tools_downgrade(m, None))
                self.assertFalse(rm.is_tools_downgrade(m, {}))
                self.assertFalse(rm.is_tools_downgrade(m, {"tools": None}))
                self.assertEqual(rm.conflicting_flags(m, flags={"tools": original}), [])
                self.assertEqual(rm.conflicting_flags(m, flags={}), [])
                self.assertEqual(rm.conflicting_flags(m, flags={"tools": None}), [])
                conflicts = rm.conflicting_flags(m, flags={"tools": False,
                                                           "fail_on": "critical"})
                self.assertEqual(len(conflicts), 1)
                self.assertIn("flags.fail_on", conflicts[0])
        m = rm.build_manifest(**self._params(flags={"tools": False}))
        self.assertFalse(rm.is_tools_downgrade(m, {"tools": False}))
        self.assertEqual(rm.conflicting_flags(m, flags={"tools": False}), [])
        self.assertFalse(rm.is_tools_downgrade(m, {"tools": True}))
        self.assertEqual(len(rm.conflicting_flags(m, flags={"tools": True})), 1)
        self.assertIn("flags.tools", rm.conflicting_flags(m, flags={"tools": True})[0])

    def test_record_tools_downgrade_persists_change_without_drifting_other_keys(self):
        manifest = rm.build_manifest(**self._params(flags={"tools": True,
                                                       "fail_on": "high",
                                                       "max_verify": 4}))
        manifest["flag_changes"] = [{"flag": "earlier", "at": "before"}]
        rm.write_manifest(self.root, manifest)
        with mock.patch("scripts.run_manifest._now_iso", return_value="2026-09-25T12:00:00Z"):
            rm.record_tools_downgrade(self.root, manifest)
        loaded = rm.load_manifest(self.root)
        self.assertEqual(loaded["flags"]["tools"], False)
        self.assertEqual(loaded["flags"]["fail_on"], "high")
        self.assertEqual(loaded["flags"]["max_verify"], 4)
        self.assertEqual(loaded["run_id"], manifest["run_id"])
        self.assertEqual(loaded["security_mode"], "standard")
        self.assertEqual(loaded["flag_changes"], [
            {"flag": "earlier", "at": "before"},
            {"flag": "tools", "from": True, "to": False,
             "at": "2026-09-25T12:00:00Z"}])
        self.assertTrue(rm.tools_downgraded_mid_run(loaded))

    def test_posture_disclosure_round_trips_and_replaces_old_digest(self):
        manifest = rm.build_manifest(**self._params())
        rm.write_manifest(self.root, manifest)
        rm.record_posture_disclosure(self.root, manifest, "digest-a",
                                     at="2026-09-25T12:00:00Z")
        loaded = rm.load_manifest(self.root)
        self.assertEqual(loaded[rm.POSTURE_DISCLOSED],
                         {"digest": "digest-a", "at": "2026-09-25T12:00:00Z"})
        self.assertEqual(rm.posture_disclosed_at(loaded, "digest-a"),
                         "2026-09-25T12:00:00Z")
        self.assertIsNone(rm.posture_disclosed_at(loaded, "digest-b"))
        rm.record_posture_disclosure(self.root, loaded, "digest-b",
                                     at="2026-09-25T13:00:00Z")
        updated = rm.load_manifest(self.root)
        self.assertEqual(rm.posture_disclosed_at(updated, "digest-b"),
                         "2026-09-25T13:00:00Z")
        self.assertIsNone(rm.posture_disclosed_at(updated, "digest-a"))
        self.assertEqual(updated["flags"], manifest["flags"])

    def test_rewrite_strips_ephemeral_keys_and_atomically_replaces_valid_json(self):
        manifest = rm.build_manifest(**self._params())
        rm.write_manifest(self.root, manifest)
        manifest["session_dir"] = "/private/tmp/session"
        manifest["invocation"] = "one-call"
        manifest["posture_disclosed"] = {"digest": "valid", "at": "now"}
        path = rm.manifest_path(self.root)
        rm._rewrite(self.root, manifest)
        with open(path, encoding="utf-8") as fh:
            disk = json.load(fh)
        self.assertNotIn("session_dir", disk)
        self.assertNotIn("invocation", disk)
        self.assertEqual(disk["posture_disclosed"], manifest["posture_disclosed"])
        self.assertEqual(disk["flags"], manifest["flags"])
        self.assertEqual(disk["run_id"], manifest["run_id"])
        self.assertFalse(os.path.exists(path + ".tmp"))

    def test_rewrite_failures_leave_original_manifest_valid_and_unchanged(self):
        manifest = rm.build_manifest(**self._params())
        rm.write_manifest(self.root, manifest)
        path = rm.manifest_path(self.root)
        with open(path, "rb") as fh:
            original = fh.read()
        for target, failure in (("scripts.run_manifest.json.dump", TypeError("bad json")),
                                ("scripts.run_manifest.os.replace", OSError("rename failed"))):
            with self.subTest(target=target):
                with mock.patch(target, side_effect=failure):
                    with self.assertRaises(type(failure)):
                        rm.record_posture_disclosure(self.root, manifest,
                                                     "new-digest", at="now")
                with open(path, "rb") as fh:
                    self.assertEqual(fh.read(), original)
                with open(path, encoding="utf-8") as fh:
                    self.assertEqual(json.load(fh)["run_id"], manifest["run_id"])

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

    def test_build_manifest_stamps_created(self):   # §5.1 per-run folders
        m = rm.build_manifest(**self._params())
        self.assertRegex(m["created"], r"^\d{4}-\d{2}-\d{2}T")

    def test_run_tag_is_stable_and_formatted(self):   # §5.1
        m = {"host": "claude", "security_mode": "redteam",
             "scope": {"mode": "repo"}, "run_id": "deadbeefcafe0000",
             "created": "2026-08-18T09:30:00Z"}
        self.assertEqual(rm.run_tag(m), "claude-redteam-repo-20260818-deadbeef")
        # deterministic from the write-once manifest -> identical on every resume
        self.assertEqual(rm.run_tag(m), rm.run_tag(dict(m)))

    def test_run_tag_none_for_empty_manifest(self):   # §5.1 (falls back to flat)
        self.assertIsNone(rm.run_tag(None))
        self.assertIsNone(rm.run_tag({}))

    def test_run_tag_is_total_for_json_shapes(self):
        for value in ([], ["repo"], "repo", 12, True, None):
            with self.subTest(top_level=value):
                self.assertIsNone(rm.run_tag(value))
        for scope in ([], ["repo"], "repo", 12, True, None):
            for created in ([], {}, 12, True, "../../x/y", "2026-09-23T00:00:00Z"):
                with self.subTest(scope=scope, created=created):
                    tag = rm.run_tag({"host": "claude", "security_mode": "standard",
                                      "scope": scope, "created": created, "run_id": "abc123"})
                    self.assertRegex(tag, r"^[A-Za-z0-9-]+$")
                    self.assertLessEqual(len(tag), 220)
        long = "a" * 1000
        tag = rm.run_tag({"host": long, "security_mode": long,
                          "scope": {"mode": long}, "created": long,
                          "run_id": long})
        self.assertIsNotNone(re.fullmatch(r"[A-Za-z0-9-]+", tag))
        self.assertLessEqual(len(tag), 220)

    def test_load_manifest_discards_unhashable_host(self):
        rm.write_manifest(self.root, {"host": [], "review_root": self.root})
        self.assertIsNone(rm.load_manifest(self.root))

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

    def test_the_manifest_records_the_config_resolution_beside_the_flags(self):
        settings = cs.resolve_settings(
            {}, cs.parse_settings({"settings": {"max_per_group": 5000,
                                                "allow_unenforced": True}}))
        m = rm.build_manifest(**self._params(), config=settings)
        self.assertEqual(m["config_requested"],
                         {"max_per_group": 5000, "allow_unenforced": True})
        self.assertEqual(m["config_effective"], {"max_per_group": 48})
        self.assertEqual(m["config_clamped"][0]["effective"], 48)
        self.assertEqual(m["config_refused"][0]["key"], "allow_unenforced")
        self.assertTrue(m["config_disclosures"])

    def test_a_hostile_config_still_leaves_the_manifest_strict_json(self):
        # `settings:` is TARGET-authored and lands in the manifest verbatim.
        # A non-finite float would reach json.dump (allow_nan=True by default)
        # as a bare Infinity -- valid to Python, invalid JSON to every other
        # reader of run-manifest.json -- and an unbounded string would be
        # copied into it whole (YAML aliases amplify past the source cap).
        # config_schema bounds both at the parse boundary; this is the end of
        # that pipe, where the damage would actually be written.
        settings = cs.resolve_settings({}, cs.parse_settings(
            {"settings": {"max_verify": float("inf"), "severity": "s" * 10000}}))
        m = rm.build_manifest(**self._params(), config=settings)
        strict = json.loads(json.dumps(m, allow_nan=False, sort_keys=True))
        self.assertEqual(strict["config_requested"]["max_verify"], "inf")
        self.assertEqual(len(strict["config_requested"]["severity"]),
                         cs.MAX_RECORDED_CHARS + 1)
        self.assertLess(len(json.dumps(strict["config_disclosures"])), 2000)

    def test_the_config_blocks_are_not_anti_drift_keys(self):
        for key in ("config_requested", "config_effective", "config_refused",
                    "config_clamped", "config_disclosures"):
            self.assertNotIn(key, rm._FLAG_KEYS)

    def test_a_manifest_built_without_a_config_carries_empty_blocks(self):
        m = rm.build_manifest(**self._params())
        self.assertEqual(m["config_requested"], {})
        self.assertEqual(m["config_refused"], [])


class TestManifestRejectsAnUnknownHost(unittest.TestCase):
    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.root = self._d.name
        self.addCleanup(self._d.cleanup)

    def test_a_host_the_registry_does_not_know_is_refused(self):
        with self.assertRaises(ValueError) as caught:
            rm.validate_host("no-such-host")
        self.assertIn("no-such-host", str(caught.exception))

    def test_every_driver_host_is_accepted(self):
        for name in hosts.driver_hosts():
            with self.subTest(host=name):
                self.assertEqual(name, rm.validate_host(name))

    def test_an_unknown_host_in_a_stored_manifest_does_not_crash_path_resolution(self):
        # run_tag is called on every artifact path resolution, including the
        # --reset recovery path (driver._clear_run_artifacts -> runio._run_tag).
        # It must never raise: a function that computes a path is on every code
        # path, recovery included.
        m = {"host": "evilhost", "run_id": "r1", "created": "2026-09-10"}
        self.assertEqual("evilhost-standard-repo-20260910-r1", rm.run_tag(m))

    def test_a_stored_manifest_with_an_unknown_host_is_discarded_not_trusted(self):
        # Unusable, exactly like a corrupt one: load_manifest returns None so
        # the driver clears artifacts and rebuilds from CLI args, rather than
        # resuming an unenforced run under a plausible directory name.
        path = rm.manifest_path(self.root)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"host": "evilhost", "run_id": "r1",
                       "created": "2026-09-10T00:00:00Z"}, fh)
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertIsNone(rm.load_manifest(self.root))
        self.assertIn("evilhost", err.getvalue())
        self.assertIn("run-manifest.json", err.getvalue())

    def test_a_known_host_in_a_stored_manifest_is_loaded_silently(self):
        rm.write_manifest(self.root, rm.build_manifest(
            target=self.root, review_root=self.root, host="claude",
            security_mode="standard"))
        with contextlib.redirect_stderr(io.StringIO()) as err:
            loaded = rm.load_manifest(self.root)
        self.assertEqual("claude", loaded["host"])
        self.assertEqual("", err.getvalue())

    def test_build_manifest_refuses_an_unknown_host(self):
        # The WRITE path: a new run's host comes from CLI args, so raising here
        # is reachable only by a programming error -- unlike run_tag, which
        # reads whatever is already on disk.
        with self.assertRaises(ValueError):
            rm.build_manifest(target=".", review_root=self.root,
                              host="evilhost", security_mode="standard")


class TestRewriteDoesNotFollowAPlantedTmpSymlink(unittest.TestCase):
    """#1735 (SEC-D1C): `_rewrite` staged at `<manifest>.tmp` with a plain
    `open(tmp, "w")`.

    `.panopticon/` lives INSIDE the reviewed tree and `run-manifest.json.tmp`
    is a FIXED name, so a redteam target can commit it as a symlink to any
    file the invoking user can write: the open followed the link and replaced
    that file's contents with the manifest JSON, and the `os.replace` then
    renamed the LINK itself over `run-manifest.json` (rename does not
    dereference), so every later `load_manifest` read through it. Reachable on
    essentially every run -- `record_posture_disclosure` rewrites on the first
    invocation. `write_manifest` was never exposed: mode "x" is O_EXCL.
    """

    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.root = self._d.name
        self.addCleanup(self._d.cleanup)
        rm.write_manifest(self.root, {"run_id": "r1", "host": "claude"})
        self.tmp = rm.manifest_path(self.root) + ".tmp"

    def _victim(self, where):
        victim = os.path.join(where, "victim.txt")
        with open(victim, "w", encoding="utf-8") as fh:
            fh.write("PRECIOUS")
        return victim

    def test_a_link_out_of_the_tree_is_refused_and_the_victim_untouched(self):
        victim = self._victim(self.root)            # stands in for ~/.ssh/authorized_keys
        os.symlink(victim, self.tmp)                # committed by the reviewed repo
        manifest = rm.load_manifest(self.root)
        with self.assertRaises(ValueError):
            rm.record_posture_disclosure(self.root, manifest, "d1")
        with open(victim, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "PRECIOUS")
        self.assertNotIn(rm.POSTURE_DISCLOSED, rm.load_manifest(self.root))

    def test_a_link_inside_panopticon_is_replaced_not_written_through(self):
        # The confinement above answers a link pointing OUT; O_NOFOLLOW answers
        # the one that stays in, which is the half a whole-path check cannot see.
        victim = self._victim(os.path.dirname(self.tmp))
        os.symlink(victim, self.tmp)
        rm.record_posture_disclosure(self.root, rm.load_manifest(self.root), "d2")
        with open(victim, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "PRECIOUS")
        path = rm.manifest_path(self.root)
        self.assertFalse(os.path.islink(path))      # the link never became the manifest
        self.assertEqual(rm.load_manifest(self.root)[rm.POSTURE_DISCLOSED]["digest"],
                         "d2")
        self.assertFalse(os.path.exists(self.tmp))  # staging file renamed away

    def test_the_other_two_rewriters_stage_the_same_way(self):
        # One `_rewrite`, three callers (#1637 P08 F2, #1596, #1727): the fix
        # is on the shared write, so record it is reached from each of them.
        victim = self._victim(self.root)
        for record in (lambda m: rm.record_tools_downgrade(self.root, m),
                       lambda m: rm.record_dispatch_request(self.root, m,
                                                            "scout", "a" * 64)):
            os.symlink(victim, self.tmp)
            with self.assertRaises(ValueError):
                record(rm.load_manifest(self.root))
            with open(victim, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "PRECIOUS")
            os.unlink(self.tmp)


if __name__ == "__main__":
    unittest.main()
