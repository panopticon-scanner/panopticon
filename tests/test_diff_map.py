# tests/test_diff_map.py
import contextlib, io, os, unittest, subprocess, tempfile, shutil
from unittest import mock

import scripts.diff_map as diff_map
from tools.git_repo import make_git_repo


def _git(d, *a):
    subprocess.run(["git", "-C", d, *a], check=True, capture_output=True)

DIFF = """diff --git a/app/db.py b/app/db.py
index 111..222 100644
--- a/app/db.py
+++ b/app/db.py
@@ -10,0 +11,3 @@ def q():
+a
+b
+c
@@ -40,2 +43,1 @@ def r():
-old1
-old2
+new
diff --git a/gone.py b/gone.py
deleted file mode 100644
--- a/gone.py
+++ /dev/null
@@ -1,2 +0,0 @@
-x
-y
diff --git a/new.py b/new.py
new file mode 100644
--- /dev/null
+++ b/new.py
@@ -0,0 +1,4 @@
+1
+2
+3
+4
"""

class TestParse(unittest.TestCase):
    def test_new_side_ranges_and_deletions(self):
        m = diff_map.parse_unified_diff(DIFF)
        self.assertEqual(m["app/db.py"], [(11, 13), (43, 43)])  # d==0 hunk omitted, single-line count defaults to 1
        self.assertEqual(m["new.py"], [(1, 4)])                 # whole new file
        self.assertNotIn("gone.py", m)                          # deleted -> not a new-side key

    def test_single_line_hunk_without_count(self):
        d = "--- a/x.py\n+++ b/x.py\n@@ -5 +7 @@\n-old\n+new\n"
        self.assertEqual(diff_map.parse_unified_diff(d), {"x.py": [(7, 7)]})

    def test_empty_and_garbage_tolerated(self):
        self.assertEqual(diff_map.parse_unified_diff(""), {})
        self.assertEqual(diff_map.parse_unified_diff("not a diff\nrandom\n"), {})


def _make_repo(test_case):
    return make_git_repo(
        test_case=test_case,
        files={"a.py": "\n".join("line%d" % i for i in range(1, 11)) + "\n"},
        branch="main",
        user_email="t@e.com",
        user_name="T",
        realpath=False,
    )


class TestHunkMap(unittest.TestCase):
    def _repo(self):
        return _make_repo(self)

    def test_committed_and_uncommitted_changes(self):
        d = self._repo()
        _git(d, "checkout", "-q", "-b", "feat")
        p = os.path.join(d, "a.py")
        with open(p, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        lines[2] = "CHANGED3"
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        _git(d, "commit", "-qam", "c")
        # uncommitted new file (untracked) -> whole-file range
        with open(os.path.join(d, "b.py"), "w", encoding="utf-8") as fh:
            fh.write("x\ny\n")
        m = diff_map.hunk_map(d, "main")
        self.assertIn("a.py", m)
        self.assertTrue(any(s <= 3 <= e for (s, e) in m["a.py"]))
        self.assertEqual(m["b.py"], [(1, 2)])
        # #1083: a no-trailing-newline untracked file still counts its last line
        # (the chunked newline count matches `sum(1 for _ in fh)`).
        with open(os.path.join(d, "c.py"), "w", encoding="utf-8") as fh:
            fh.write("x\ny\nz")   # 3 lines, no trailing newline
        m2 = diff_map.hunk_map(d, "main")
        self.assertEqual(m2["c.py"], [(1, 3)])

    def test_unresolvable_base_raises_instead_of_returning_empty(self):
        # #1256: this used to return {}. An empty map scopes the on-diff gate to
        # nothing, so a typo'd or unfetched base would PASS vacuously.
        with self.assertRaises(diff_map.DiffMapError) as caught:
            diff_map.hunk_map(self._repo(), "no-such-ref")
        self.assertIn("does not resolve to a commit", str(caught.exception))

    def _fake_git(self, seen, diff_rc=0, diff_err=""):
        def fake(repo, args, timeout=60):
            r = mock.Mock()
            if args[0] == "merge-base":
                r.returncode, r.stdout, r.stderr = 0, "deadbeef\n", ""
            elif args[0] == "-c":                 # the pinned `git -c ... diff`
                seen["diff"] = args
                r.returncode, r.stdout, r.stderr = diff_rc, "", diff_err
            else:                                  # ls-files --others
                r.returncode, r.stdout, r.stderr = 0, "", ""
            return r
        return fake

    def test_diff_command_failure_raises_not_empty(self):
        # #5.0-08: merge-base OK but the diff itself fails -> DiffMapError, so
        # the run fails loud instead of returning {} and passing the gate vacuously.
        seen = {}
        with mock.patch.object(diff_map, "_run_git",
                               side_effect=self._fake_git(seen, diff_rc=128, diff_err="boom")):
            with self.assertRaises(diff_map.DiffMapError):
                diff_map.hunk_map(".", "main")

    def test_merge_base_infra_failure_raises_not_empty(self):
        # #run7 OPS-E1A: an INFRA failure on merge-base (git missing/timeout) must
        # raise DiffMapError like the diff step, not silently return {} and pass
        # the delta gate vacuously. (A genuinely unresolvable base still -> {}.)
        def raising(repo, args, timeout=60):
            if args[0] == "merge-base":
                raise FileNotFoundError("git not found")
            return mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch.object(diff_map, "_run_git", side_effect=raising):
            with self.assertRaises(diff_map.DiffMapError):
                diff_map.hunk_map(".", "main")

    def test_exclude_drops_named_paths_from_the_map(self):
        # #1681 fix round 1 item 3: the --pr worktree caller (write_diff_hunks)
        # excludes the root config names so the operator's post-acquire
        # overwrite is never attributed to the PR in diff-hunks.json. A plain
        # (non-PR) caller passes none and sees a real change normally.
        d = self._repo()
        _git(d, "checkout", "-q", "-b", "feat")
        with open(os.path.join(d, "panopticon.yml"), "w", encoding="utf-8") as fh:
            fh.write("version: 1\ngroups: {}\n")
        _git(d, "add", "panopticon.yml")
        _git(d, "commit", "-qm", "add root config")
        m = diff_map.hunk_map(d, "main")
        self.assertIn("panopticon.yml", m)
        m2 = diff_map.hunk_map(d, "main", exclude=("panopticon.yml", ".panopticon.yml"))
        self.assertNotIn("panopticon.yml", m2)
        # untracked-others path: same exclusion applies to an uncommitted file
        with open(os.path.join(d, ".panopticon.yml"), "w", encoding="utf-8") as fh:
            fh.write("version: 1\ngroups: {}\n")
        # positive control (fix round 2 item 6): without exclude, the untracked
        # file IS in the map -- proves the assertion below is actually testing
        # the exclusion, not an untracked-others path that never picks it up.
        m3_control = diff_map.hunk_map(d, "main")
        self.assertIn(".panopticon.yml", m3_control)
        m3 = diff_map.hunk_map(d, "main", exclude=("panopticon.yml", ".panopticon.yml"))
        self.assertNotIn(".panopticon.yml", m3)

    def test_diff_flags_are_pinned(self):
        # #5.0-08: pin mnemonicPrefix/quotepath/prefixes so a user's gitconfig
        # can't reshape the `+++ b/<path>` headers parse_unified_diff keys on.
        seen = {}
        with mock.patch.object(diff_map, "_run_git", side_effect=self._fake_git(seen)):
            diff_map.hunk_map(".", "main")
        argv = seen["diff"]
        self.assertIn("diff.mnemonicPrefix=false", argv)
        self.assertIn("core.quotepath=false", argv)
        self.assertIn("--dst-prefix=b/", argv)


class TestClassify(unittest.TestCase):
    HM = {"a.py": [(10, 12)], "empty.py": []}
    def _f(self, path, ls=None, le=None):
        loc = {"file": path}
        if ls is not None: loc["line_start"] = ls
        if le is not None: loc["line_end"] = le
        return {"location": loc}

    def test_inside_hunk_is_on_diff_distance_zero(self):
        d = diff_map.classify(self._f("a.py", 11), self.HM)
        self.assertEqual((d["on_diff"], d["hunk"], d["distance"]), (True, [10, 12], 0))

    def test_within_tolerance_boundary_on_at_5_off_at_6(self):
        self.assertTrue(diff_map.classify(self._f("a.py", 17), self.HM, 5)["on_diff"])   # 17 vs end 12 = 5
        off = diff_map.classify(self._f("a.py", 18), self.HM, 5)                          # = 6
        self.assertFalse(off["on_diff"]); self.assertEqual(off["distance"], 6)

    def test_range_overlap_counts(self):
        self.assertTrue(diff_map.classify(self._f("a.py", 1, 50), self.HM)["on_diff"])

    def test_lineless_on_changed_file_fails_open(self):
        self.assertTrue(diff_map.classify(self._f("empty.py"), self.HM)["on_diff"])

    def test_file_not_in_map_is_pre_existing(self):
        d = diff_map.classify(self._f("other.py", 3), self.HM)
        self.assertEqual((d["on_diff"], d["distance"]), (False, None))

    def test_multiline_off_diff_uses_four_corners(self):
        # finding [1, 3] vs range (10, 12): nearest gap is le=3 to s=10 = 7
        d = diff_map.classify(self._f("a.py", 1, 3), self.HM, 5)
        self.assertFalse(d["on_diff"])
        self.assertEqual(d["distance"], 7)

    def test_dotslash_prefix_still_matches(self):
        # #5.0-06: './a.py' must still match the git-relative key 'a.py'.
        self.assertTrue(diff_map.classify(self._f("./a.py", 11), self.HM)["on_diff"])

    def test_absolute_path_relativizes_against_repo_root(self):
        # #5.0-06: a worktree-absolute location.file (what --pr panels emit)
        # must match the git-relative hunk key once relativized against the root.
        d = diff_map.classify(self._f("/repo/a.py", 11), self.HM, repo_root="/repo")
        self.assertTrue(d["on_diff"])
        # and without a repo_root it (correctly) cannot relativize -> pre-existing,
        # which is exactly the silent-drop the fix closes when repo_root IS passed.
        self.assertFalse(diff_map.classify(self._f("/repo/a.py", 11), self.HM)["on_diff"])

    def test_norm_key(self):
        self.assertEqual(diff_map.norm_key("a\\b.py"), "a/b.py")
        self.assertEqual(diff_map.norm_key("./a.py"), "a.py")
        self.assertEqual(diff_map.norm_key("/repo/sub/a.py", "/repo"), "sub/a.py")
        self.assertEqual(diff_map.norm_key("/outside/a.py", "/repo"), "/outside/a.py")


class TestDiffAnchors(unittest.TestCase):
    def _repo(self):
        return _make_repo(self)

    def test_anchors_resolve_base_fork_and_head(self):
        d = self._repo()
        base_sha = subprocess.run(["git", "-C", d, "rev-parse", "main"],
                                  capture_output=True, text=True, check=True).stdout.strip()
        _git(d, "checkout", "-q", "-b", "feat")
        with open(os.path.join(d, "a.py"), "a") as fh:
            fh.write("line2\n")
        _git(d, "commit", "-qam", "c")
        head_sha = subprocess.run(["git", "-C", d, "rev-parse", "HEAD"],
                                  capture_output=True, text=True, check=True).stdout.strip()
        anchors = diff_map.diff_anchors(d, "main")
        self.assertEqual(anchors["base_commit"], base_sha)
        self.assertEqual(anchors["delta_start"], base_sha)  # merge-base(HEAD, main)
        self.assertEqual(anchors["delta_end"], head_sha)

    def test_anchors_unresolvable_base_returns_none_fields(self):
        d = self._repo()
        anchors = diff_map.diff_anchors(d, "no-such-ref")
        self.assertIsNone(anchors["base_commit"])
        self.assertIsNone(anchors["delta_start"])
        self.assertIsNotNone(anchors["delta_end"])   # HEAD always resolves

    def test_anchors_no_base_returns_none_for_base_and_start(self):
        d = self._repo()
        anchors = diff_map.diff_anchors(d, None)
        self.assertIsNone(anchors["base_commit"])
        self.assertIsNone(anchors["delta_start"])
        self.assertIsNotNone(anchors["delta_end"])


class TestPrWorktree(unittest.TestCase):
    def test_acquire_reads_base_and_adds_worktree(self):
        # `acquire_pr` calls `_sync_config` on BOTH paths (#1681), and that
        # refuses a worktree directory that is not there -- so a fake `git
        # worktree add` has to leave a real directory behind the way git does.
        # Pinned as a temp dir created here and removed after: with a
        # hard-coded `/tmp/wt-pr7` this passed only while a stale one from an
        # earlier run happened to still exist, and failed on a clean machine.
        wt = tempfile.mkdtemp(prefix="panopticon-test-wt-")
        self.addCleanup(shutil.rmtree, wt, ignore_errors=True)
        calls = []
        fetched_ref = []
        def runner(argv, **kw):
            calls.append(argv)
            out = ""
            if argv[:3] == ["gh", "pr", "view"]:
                out = '{"baseRefName": "main"}'
            elif "fetch" in argv:
                fetched_ref.append(argv[-1].split(":", 1)[1])
            elif "rev-parse" in argv:
                out = "deadbeef\n"
            class R: returncode = 0; stdout = out; stderr = ""
            return R()
        with mock.patch.object(diff_map, "_worktree_dir", return_value=wt):
            info = diff_map.acquire_pr(7, repo=".", runner=runner)
        self.assertEqual(info["base"], "main")
        self.assertEqual(info["worktree"], wt)
        worktree = next(a for a in calls if "worktree" in a and "add" in a)
        self.assertEqual(worktree[-1], "deadbeef")
        self.assertNotIn("FETCH_HEAD", " ".join(" ".join(a) for a in calls))
        self.assertTrue(any("--no-write-fetch-head" in a for a in calls))
        self.assertTrue(any("update-ref" in a and fetched_ref[0] in a for a in calls))
        self.assertTrue(any("refs/pull/7/head" in " ".join(a) for a in calls))

    def test_acquire_is_idempotent_deterministic_path(self):
        repo = "."
        wt = diff_map._worktree_dir(repo, 7)
        # Same reason as the test above: the fake `worktree add` creates the
        # directory, so `_sync_config` has a real tree to sync into on the
        # create pass and the reuse pass alike.
        self.addCleanup(shutil.rmtree, wt, ignore_errors=True)
        calls = {"fetch": 0, "wtadd": 0}
        def runner(argv, **kw):
            out = ""
            if argv[:3] == ["gh", "pr", "view"]:
                out = '{"baseRefName": "main"}'
            elif "worktree" in argv and "list" in argv:
                # Real `git worktree list` (no --porcelain) format:
                # "<path>  <sha> [<branch>]" / "(detached HEAD)". Only
                # registered (i.e. after the worktree add) on later calls.
                out = "%s  deadbeef [detached HEAD]\n" % wt if calls["wtadd"] > 0 else ""
            elif "worktree" in argv and "add" in argv:
                calls["wtadd"] += 1
                os.makedirs(wt, exist_ok=True)
            elif "fetch" in argv:
                calls["fetch"] += 1
            elif "rev-parse" in argv:
                out = "deadbeef\n"
            class R: returncode = 0; stdout = out; stderr = ""
            return R()
        a = diff_map.acquire_pr(7, repo=repo, runner=runner)
        b = diff_map.acquire_pr(7, repo=repo, runner=runner)
        self.assertEqual(a["worktree"], b["worktree"])
        self.assertEqual(a["worktree"], wt)
        self.assertEqual(a["base"], "main")
        self.assertEqual(a["head_sha"], "deadbeef")
        self.assertEqual(b["head_sha"], "deadbeef")
        self.assertEqual(calls["wtadd"], 1)   # created once, reused second time
        self.assertEqual(calls["fetch"], 1)   # no re-fetch on reuse

    def test_acquire_raises_loudly_on_gh_failure(self):
        def runner(argv, **kw):
            class R: returncode = 1; stdout = ""; stderr = "gh: no PR 999"
            return R()
        with self.assertRaises(RuntimeError):
            diff_map.acquire_pr(999, repo=".", runner=runner)

    def test_acquire_raises_loudly_on_invalid_gh_json(self):
        def runner(argv, **kw):
            class R: returncode = 0; stdout = "not json"; stderr = ""
            return R()
        with self.assertRaisesRegex(RuntimeError, "invalid JSON"):
            diff_map.acquire_pr(7, repo=".", runner=runner)

    def test_acquire_raises_loudly_on_missing_baseRefName(self):
        def runner(argv, **kw):
            class R: returncode = 0; stdout = '{"number": 7}'; stderr = ""
            return R()
        with self.assertRaisesRegex(RuntimeError, "missing baseRefName"):
            diff_map.acquire_pr(7, repo=".", runner=runner)

    def test_acquire_rejects_symlink_worktree(self):
        def runner(argv, **kw):
            if argv[:3] == ["gh", "pr", "view"]:
                return mock.Mock(returncode=0, stdout='{"baseRefName": "main"}', stderr="")
            return mock.Mock(returncode=0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as d:
            target_dir = os.path.join(d, "target")
            os.makedirs(target_dir)
            symlink_path = os.path.join(d, "symlink_wt")
            os.symlink(target_dir, symlink_path)
            with mock.patch.object(diff_map, "_worktree_dir", return_value=symlink_path):
                with self.assertRaisesRegex(RuntimeError, "insecure symlink detected"):
                    diff_map.acquire_pr(7, repo=".", runner=runner)

    def test_worktree_dir_does_not_resolve_leaf_symlink(self):
        # #run8 COD-X0X: _worktree_dir must NOT realpath its deterministic leaf.
        # If it did, an attacker-planted symlink at the leaf would be silently
        # followed and acquire_pr's islink guard (which inspects the returned
        # path) would only ever see the resolved, non-symlink target.
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(diff_map.tempfile, "gettempdir", return_value=d):
                wt = diff_map._worktree_dir(".", 7)
            self.assertEqual(os.path.dirname(wt), os.path.realpath(d))
            target = os.path.join(d, "attacker")
            os.makedirs(target)
            os.symlink(target, wt)                 # plant symlink AT the leaf
            with mock.patch.object(diff_map.tempfile, "gettempdir", return_value=d):
                wt_again = diff_map._worktree_dir(".", 7)
            # deterministic + unresolved: same leaf path, and it IS seen as a link
            self.assertEqual(wt_again, wt)
            self.assertTrue(os.path.islink(wt_again))

    def test_acquire_rejects_symlink_worktree_via_real_worktree_dir(self):
        # #run8 COD-X0X: exercise the REAL _worktree_dir (not a monkeypatched
        # stub) with an attacker-planted symlink at the deterministic leaf, to
        # prove acquire_pr's islink guard actually fires on the true code path.
        def runner(argv, **kw):
            if argv[:3] == ["gh", "pr", "view"]:
                return mock.Mock(returncode=0, stdout='{"baseRefName": "main"}', stderr="")
            return mock.Mock(returncode=0, stdout="", stderr="")
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(diff_map.tempfile, "gettempdir", return_value=d):
                wt = diff_map._worktree_dir(".", 7)
                target = os.path.join(d, "attacker")
                os.makedirs(target)
                os.symlink(target, wt)             # pre-plant the hostile leaf
                with self.assertRaisesRegex(RuntimeError, "insecure symlink detected"):
                    diff_map.acquire_pr(7, repo=".", runner=runner)

    def test_release_is_tolerant(self):
        def runner(argv, **kw):
            class R: returncode = 1; stdout = ""; stderr = "not a worktree"
            return R()
        diff_map.release_worktree("/tmp/gone", runner=runner)  # must not raise

    def test_acquire_pr_calls_carry_timeout(self):
        # #1081: every git/gh call in acquire_pr is time-bounded.
        # Real temp worktree for the same reason as the two tests above: the
        # create path ends in `_sync_config`, which refuses a missing tree.
        wt = tempfile.mkdtemp(prefix="panopticon-test-wt-")
        self.addCleanup(shutil.rmtree, wt, ignore_errors=True)
        seen = []
        def runner(argv, **kw):
            seen.append(kw.get("timeout"))
            out = ""
            if argv[:3] == ["gh", "pr", "view"]:
                out = '{"baseRefName": "main"}'
            elif "rev-parse" in argv:
                out = "deadbeef\n"
            class R: returncode = 0; stdout = out; stderr = ""
            return R()
        with mock.patch.object(diff_map, "_worktree_dir", return_value=wt):
            diff_map.acquire_pr(7, repo=".", runner=runner)
        self.assertTrue(seen)
        self.assertTrue(all(t == diff_map._PR_TIMEOUT for t in seen), seen)

    def test_acquire_pr_timeout_raises_runtimeerror(self):
        def runner(argv, **kw):
            raise subprocess.TimeoutExpired(argv, kw.get("timeout"))
        with self.assertRaises(RuntimeError):
            diff_map.acquire_pr(7, repo=".", runner=runner)   # bounded, loud

    def test_worktree_list_timeout_raises_runtimeerror(self):
        # #run7 QAL-C2D: a stalled `git worktree list` must raise RuntimeError
        # (which driver.run's #5.0-14 handler catches), not leak a raw
        # TimeoutExpired as an uncaught traceback.
        def runner(argv, **kw):
            if argv[:2] == ["gh", "pr"]:
                return mock.Mock(returncode=0, stdout='{"baseRefName": "main"}',
                                 stderr="")
            if "worktree" in argv and "list" in argv:
                raise subprocess.TimeoutExpired(argv, kw.get("timeout"))
            return mock.Mock(returncode=0, stdout="", stderr="")
        with self.assertRaises(RuntimeError):
            diff_map.acquire_pr(7, repo=".", runner=runner)

    def test_release_passes_timeout_and_tolerates_hang(self):
        # #1082: release_worktree bounds the git call and a hung teardown is tolerated.
        seen = []
        def runner(argv, **kw):
            seen.append(kw.get("timeout"))
            raise subprocess.TimeoutExpired(argv, kw.get("timeout"))
        diff_map.release_worktree("/tmp/x", runner=runner)   # must not raise
        self.assertEqual(seen, [diff_map._PR_TIMEOUT])

    def test_acquire_pr_prints_sync_notes_with_the_pr_prefix(self):
        # minor 7: acquire_pr's own print (not _sync_config's return value) must
        # carry the "panopticon --pr: " prefix for whatever _sync_config reports.
        with tempfile.TemporaryDirectory() as d:
            repo = os.path.join(d, "repo"); os.makedirs(repo)
            with open(os.path.join(repo, "panopticon.yml"), "w", encoding="utf-8") as fh:
                fh.write("version: 1\ngroups: {}\n")
            wt = os.path.join(d, "wt"); os.makedirs(wt)
            with open(os.path.join(wt, "panopticon.yml"), "w", encoding="utf-8") as fh:
                fh.write("version: 1\ngroups:\n  Evil:\n    match: ['**']\n")

            def runner(argv, **kw):
                out = ""
                if argv[:3] == ["gh", "pr", "view"]:
                    out = '{"baseRefName": "main"}'
                elif "rev-parse" in argv:
                    out = "deadbeef\n"
                class R: returncode = 0; stdout = out; stderr = ""
                return R()

            buf = io.StringIO()
            with mock.patch.object(diff_map, "_worktree_dir", return_value=wt):
                with contextlib.redirect_stderr(buf):
                    diff_map.acquire_pr(7, repo=repo, runner=runner)
            self.assertIn("panopticon --pr: ", buf.getvalue())
            self.assertIn("overwrote", buf.getvalue())


class TestDiffMapFailures(unittest.TestCase):
    def test_hunk_map_fallback_parser_and_failures(self):
        # coverage gap filler
        import scripts.diff_map as dm   # #run7 TST-G2A: one module identity (matches line 5)
        res = dm.diff_anchors(".", "nonexistent-branch-12345")
        self.assertIsNone(res.get("base_commit"))

        with self.assertRaises(dm.DiffMapError):   # #1256: fails closed
            dm.hunk_map(".", "nonexistent-base")

    def test_hunk_map_skips_untracked_symlink_outside_repo(self):
        # #1260: untracked-file line count must not follow symlinks outside repo.
        with tempfile.TemporaryDirectory() as outside_dir:
            outside = os.path.join(outside_dir, "outside_target.txt")
            with open(outside, "w", encoding="utf-8") as fh:
                fh.write("1\n2\n3\n4\n5\n")
            with tempfile.TemporaryDirectory() as d:
                _git(d, "init", "-q")
                _git(d, "config", "user.name", "T")
                _git(d, "config", "user.email", "t@example.com")
                with open(os.path.join(d, "committed.txt"), "w", encoding="utf-8") as fh:
                    fh.write("line\n")
                _git(d, "add", "committed.txt")
                _git(d, "commit", "-qm", "init")
                with open(os.path.join(d, "safe.txt"), "w", encoding="utf-8") as fh:
                    fh.write("a\nb\nc\n")
                os.symlink(outside, os.path.join(d, "link.txt"))
                hm = diff_map.hunk_map(d, "HEAD")
                self.assertIn("safe.txt", hm)
                self.assertEqual(hm["safe.txt"], [(1, 3)])
                self.assertNotIn("link.txt", hm)
                self.assertNotIn("outside_target.txt", hm)

    def test_hunk_map_raises_on_ls_files_failure(self):
        # #1257: a failed `git ls-files` must not silently drop untracked files.
        with tempfile.TemporaryDirectory() as d:
            _git(d, "init", "-q")
            _git(d, "config", "user.name", "T")
            _git(d, "config", "user.email", "t@example.com")
            with open(os.path.join(d, "committed.txt"), "w", encoding="utf-8") as fh:
                fh.write("line\n")
            _git(d, "add", "committed.txt")
            _git(d, "commit", "-qm", "init")

            def fake_run_git(repo, args, timeout=60):
                if args[:2] == ["merge-base", "HEAD"]:
                    class R: returncode = 0; stdout = "HEAD\n"; stderr = ""
                    return R()
                if len(args) > 4 and args[4] == "diff":
                    class R: returncode = 0; stdout = ""; stderr = ""
                    return R()
                if args[:2] == ["ls-files", "--others"]:
                    class R: returncode = 1; stdout = ""; stderr = "mock ls-files failure"
                    return R()
                return subprocess.run([shutil.which("git") or "git", "-C", repo, *args],
                                      capture_output=True, text=True, timeout=timeout)

            with mock.patch.object(diff_map, "_run_git", side_effect=fake_run_git):
                with self.assertRaisesRegex(RuntimeError, "git ls-files failed"):
                    diff_map.hunk_map(d, "HEAD")


class TestSyncConfig(unittest.TestCase):
    """#run8 SEC-D1C / #1681: _sync_config OVERWRITES whatever the PR shipped
    under either root config name with the operator's own file, and must not
    follow a symlinked destination out of the worktree (CWE-59)."""

    def _repo_with_config(self, d, name="panopticon.yml"):
        repo = os.path.join(d, "repo")
        os.makedirs(repo)
        with open(os.path.join(repo, name), "w", encoding="utf-8") as fh:
            fh.write("version: 1\ngroups: {}\n")
        return repo

    def test_copies_into_worktree_normally(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo_with_config(d)
            wt = os.path.join(d, "wt"); os.makedirs(wt)
            self.assertEqual(diff_map._sync_config(repo, wt), [])
            with open(os.path.join(wt, "panopticon.yml"), encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "version: 1\ngroups: {}\n")

    def test_noop_when_operator_has_no_config(self):
        # #1681 fix round 2 item 5 (R18): still holds after the restructure --
        # a BARE worktree (nothing for the unconditional removal loop to find)
        # plus no operator config yields [] and writes nothing.
        with tempfile.TemporaryDirectory() as d:
            repo = os.path.join(d, "repo"); os.makedirs(repo)
            wt = os.path.join(d, "wt"); os.makedirs(wt)
            self.assertEqual(diff_map._sync_config(repo, wt), [])
            self.assertFalse(os.path.exists(os.path.join(wt, "panopticon.yml")))

    def test_no_operator_config_but_pr_ships_one_is_still_removed(self):
        # #1681 fix round 2 item 5 (controller ruling R18): even with NO
        # operator config anywhere, a PR-shipped file at either name must
        # never govern its own review -- the removal loop runs regardless,
        # and the caller is told why nothing was copied back.
        with tempfile.TemporaryDirectory() as d:
            repo = os.path.join(d, "repo"); os.makedirs(repo)
            wt = os.path.join(d, "wt"); os.makedirs(wt)
            with open(os.path.join(wt, "panopticon.yml"), "w", encoding="utf-8") as fh:
                fh.write("version: 1\ngroups:\n  Evil:\n    match: ['**']\n")
            notes = diff_map._sync_config(repo, wt)
            self.assertFalse(os.path.exists(os.path.join(wt, "panopticon.yml")))
            self.assertTrue(any("removed the PR's panopticon.yml" in n for n in notes), notes)
            self.assertTrue(any("no operator config" in n for n in notes), notes)

    def test_operator_file_overwrites_a_pr_shipped_one_and_says_so(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo_with_config(d)
            wt = os.path.join(d, "wt"); os.makedirs(wt)
            with open(os.path.join(wt, "panopticon.yml"), "w") as fh:
                fh.write("version: 1\ngroups:\n  Evil:\n    match: ['**']\n")
            notes = diff_map._sync_config(repo, wt)
            with open(os.path.join(wt, "panopticon.yml"), encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "version: 1\ngroups: {}\n")
            self.assertTrue(any("overwrote" in n and "panopticon.yml" in n for n in notes))

    def test_both_names_in_the_worktree_are_removed_before_the_copy(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo_with_config(d, name=".panopticon.yml")
            wt = os.path.join(d, "wt"); os.makedirs(wt)
            with open(os.path.join(wt, "panopticon.yml"), "w", encoding="utf-8") as fh:
                fh.write("version: 1\ngroups:\n  Evil:\n    match: ['**']\n")
            notes = diff_map._sync_config(repo, wt)
            self.assertFalse(os.path.exists(os.path.join(wt, "panopticon.yml")))
            with open(os.path.join(wt, ".panopticon.yml"), encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "version: 1\ngroups: {}\n")
            self.assertTrue(any("removed" in n for n in notes))

    def test_a_symlink_at_either_name_in_the_worktree_is_unlinked_not_followed(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo_with_config(d)
            wt = os.path.join(d, "wt"); os.makedirs(wt)
            outside = os.path.join(d, "outside.yml")
            with open(outside, "w", encoding="utf-8") as fh:
                fh.write("i must not be read or written through the link\n")
            os.symlink(outside, os.path.join(wt, "panopticon.yml"))
            os.symlink(outside, os.path.join(wt, ".panopticon.yml"))
            diff_map._sync_config(repo, wt)
            self.assertFalse(os.path.islink(os.path.join(wt, "panopticon.yml")))
            with open(os.path.join(wt, "panopticon.yml"), encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "version: 1\ngroups: {}\n")
            # minor 6: the OTHER name's symlink was unlinked too, not just the
            # one that got recreated -- it must not still be lying around.
            self.assertFalse(os.path.lexists(os.path.join(wt, ".panopticon.yml")))
            # the link was unlinked, never followed: the file it pointed at is untouched
            with open(outside, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "i must not be read or written through the link\n")

    def test_rejects_a_worktree_root_that_is_a_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo_with_config(d)
            escape = os.path.join(d, "escape"); os.makedirs(escape)
            wt = os.path.join(d, "wt"); os.symlink(escape, wt)
            with self.assertRaisesRegex(RuntimeError, "symlinked worktree"):
                diff_map._sync_config(repo, wt)
            self.assertFalse(os.path.exists(os.path.join(escape, "panopticon.yml")))

    def test_rejects_a_missing_worktree_with_its_own_message(self):
        # minor 5: a MISSING worktree is not a SYMLINKED one -- the two used to
        # share one message, which would call a plain typo'd/never-created
        # path "symlinked".
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo_with_config(d)
            wt = os.path.join(d, "does-not-exist")
            with self.assertRaisesRegex(RuntimeError, "missing worktree"):
                diff_map._sync_config(repo, wt)

    def test_resuming_a_previous_sync_refreshes_rather_than_removes(self):
        # #1681 fix round 1 item 1: the reuse/resume acquire_pr call site finds
        # the operator's file ALREADY in the worktree from a prior sync in the
        # same run. Re-syncing must not claim it "removed the PR's" file --
        # the PR never shipped it; a previous _sync_config call wrote it.
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo_with_config(d)
            wt = os.path.join(d, "wt"); os.makedirs(wt)
            first = diff_map._sync_config(repo, wt)
            self.assertEqual(first, [])   # empty worktree: plain copy, nothing to report
            second = diff_map._sync_config(repo, wt)
            self.assertTrue(any("refreshed" in n for n in second), second)
            self.assertFalse(any("removed the PR's" in n for n in second), second)
            with open(os.path.join(wt, "panopticon.yml"), encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "version: 1\ngroups: {}\n")

    def test_a_size_mismatched_file_is_removed_without_being_read(self):
        # #1681 fix round 2 item 1: the size from the already-done `lstat`
        # must rule a byte-compare out before anything is opened at all -- a
        # large PR-planted file at the config name is never read just to
        # prove it differs from the (small) operator copy.
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo_with_config(d)
            wt = os.path.join(d, "wt"); os.makedirs(wt)
            big = os.path.join(wt, "panopticon.yml")
            with open(big, "wb") as fh:
                fh.write(b"x" * (3 * 1024 * 1024))
            real_open = os.open
            def guarded_open(path, flags=os.O_RDONLY, *a, **kw):
                # READS only: since fix round 3 M1 the operator's copy is
                # written through `os.open` too, and that write is the point of
                # the call -- what must never happen is OPENING the blob to
                # compare bytes with it.
                if (os.path.abspath(path) == os.path.abspath(big)
                        and flags & os.O_ACCMODE == os.O_RDONLY):
                    raise AssertionError("must not read a size-mismatched file")
                return real_open(path, flags, *a, **kw)
            with mock.patch("os.open", side_effect=guarded_open):
                notes = diff_map._sync_config(repo, wt)
            # the 3MB blob is gone -- `big` IS the destination name, so the
            # operator's copy legitimately lands there afterward; what proves
            # the size guard worked is that it is now the SMALL operator
            # content, not the original blob (and the guard above proves it
            # got there without ever being read for a byte-compare).
            with open(big, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "version: 1\ngroups: {}\n")
            self.assertTrue(any("removed the PR's panopticon.yml" in n for n in notes), notes)

    def test_refresh_only_applies_to_the_operators_own_name(self):
        # #1681 fix round 2 item 2: a BYTE-IDENTICAL file under the OTHER
        # (non-canonical) name is still removed, never "refreshed" -- that
        # fast path only ever applies to the destination matching the
        # operator's own file, so the worktree never ends up with both names
        # present (which would raise its own "both present" disclosure the
        # next time something reads config from the worktree).
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo_with_config(d)   # operator's file is "panopticon.yml"
            wt = os.path.join(d, "wt"); os.makedirs(wt)
            with open(os.path.join(wt, ".panopticon.yml"), "w", encoding="utf-8") as fh:
                fh.write("version: 1\ngroups: {}\n")   # byte-identical, WRONG name
            notes = diff_map._sync_config(repo, wt)
            self.assertFalse(os.path.exists(os.path.join(wt, ".panopticon.yml")))
            self.assertTrue(any("removed the PR's .panopticon.yml" in n for n in notes), notes)
            self.assertFalse(any("refreshed" in n for n in notes), notes)
            with open(os.path.join(wt, "panopticon.yml"), encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "version: 1\ngroups: {}\n")

    def test_a_link_planted_after_the_removal_is_not_written_through(self):
        # M1: the destination was `os.unlink(dst)` and then
        # `shutil.copy2(src, dst)` -- two opens of one name in a directory
        # holding attacker-controlled PR content. copy2 FOLLOWS whatever is at
        # the path when it opens it, so a link planted in that window carried
        # the operator's config onto its target. The write is an exclusive
        # O_NOFOLLOW create now: a path that came back is refused, loudly.
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo_with_config(d)
            wt = os.path.join(d, "wt"); os.makedirs(wt)
            dst = os.path.join(wt, "panopticon.yml")
            with open(dst, "w", encoding="utf-8") as fh:
                fh.write("version: 1\ngroups:\n  Evil:\n    match: ['**']\n")
            outside = os.path.join(d, "outside.yml")
            with open(outside, "w", encoding="utf-8") as fh:
                fh.write("i must not be written through the link\n")
            real_unlink = os.unlink

            def racing_unlink(path, *a, **kw):
                real_unlink(path, *a, **kw)
                if os.path.abspath(path) == os.path.abspath(dst):
                    os.symlink(outside, dst)        # planted inside the window

            with mock.patch("os.unlink", side_effect=racing_unlink):
                with self.assertRaisesRegex(RuntimeError, "reappeared"):
                    diff_map._sync_config(repo, wt)
            self.assertTrue(os.path.islink(dst))
            with open(outside, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "i must not be written through the link\n")

    def test_an_over_cap_operator_config_is_disclosed_and_not_copied(self):
        # M3: this read the operator's file unbounded while every other reader
        # takes MAX_CONFIG_BYTES + 1 and refuses the extra byte. Same cap, same
        # refusal -- copying a file `read_document` will refuse would hand the
        # review a config nothing downstream can read.
        cap = diff_map.repo_config.MAX_CONFIG_BYTES
        with tempfile.TemporaryDirectory() as d:
            repo = os.path.join(d, "repo"); os.makedirs(repo)
            with open(os.path.join(repo, "panopticon.yml"), "w", encoding="utf-8") as fh:
                fh.write("version: 1\n#" + "x" * cap + "\n")
            wt = os.path.join(d, "wt"); os.makedirs(wt)
            with open(os.path.join(wt, "panopticon.yml"), "w", encoding="utf-8") as fh:
                fh.write("version: 1\ngroups:\n  Evil:\n    match: ['**']\n")
            notes = diff_map._sync_config(repo, wt)
            self.assertTrue(any("exceeds" in n for n in notes), notes)
            # refused == absent for the removal loop (R18): the PR's own file
            # still must not govern its own review.
            self.assertFalse(os.path.exists(os.path.join(wt, "panopticon.yml")))
            self.assertTrue(any("no operator config" in n for n in notes), notes)

    def test_an_unchanged_destination_is_not_rewritten(self):
        # M2: the docstring said a byte-identical destination was "left
        # alone" while the code fell through to an unconditional copy2 that
        # rewrote it. The skip is real now -- proved by the file's identity
        # (inode + mtime) surviving the second sync.
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo_with_config(d)
            wt = os.path.join(d, "wt"); os.makedirs(wt)
            dst = os.path.join(wt, "panopticon.yml")
            diff_map._sync_config(repo, wt)
            before = os.stat(dst)
            notes = diff_map._sync_config(repo, wt)
            after = os.stat(dst)
            self.assertTrue(any("refreshed" in n for n in notes), notes)
            # ctime, not mtime: copy2 restores the SOURCE's mtime, so only the
            # inode-change stamp tells a rewrite from a genuine skip.
            self.assertEqual((before.st_ino, before.st_ctime_ns),
                             (after.st_ino, after.st_ctime_ns))
            with open(dst, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "version: 1\ngroups: {}\n")

    def test_both_names_present_in_the_operators_repo_discloses_on_success_too(self):
        # #1681 fix round 2 item 4: `res.disclosures` used to reach the caller
        # only on the no-config branch -- the "both present" note is exactly
        # as real on a successful sync and must not go missing there.
        with tempfile.TemporaryDirectory() as d:
            repo = os.path.join(d, "repo"); os.makedirs(repo)
            with open(os.path.join(repo, "panopticon.yml"), "w", encoding="utf-8") as fh:
                fh.write("version: 1\ngroups: {}\n")
            with open(os.path.join(repo, ".panopticon.yml"), "w", encoding="utf-8") as fh:
                fh.write("version: 1\ngroups: {}\n")
            wt = os.path.join(d, "wt"); os.makedirs(wt)
            notes = diff_map._sync_config(repo, wt)
            self.assertTrue(any("both" in n and "present" in n for n in notes), notes)
            with open(os.path.join(wt, "panopticon.yml"), encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "version: 1\ngroups: {}\n")

    def test_operator_side_symlinked_config_still_removes_the_prs_file(self):
        # #1681 fix round 1 item 2 + fix round 2 item 5 (controller ruling
        # R18, which closes the re-review's O1 and supersedes this test's
        # original round-1 assertion that the worktree was left "untouched"):
        # repo_config.resolve refuses an OPERATOR-side symlinked config and
        # discloses why -- that disclosure must still reach the caller -- but
        # a REFUSED operator config is exactly like NO operator config for
        # the removal loop: the PR's own file must never govern its own
        # review, so it is removed regardless of whether the operator has a
        # usable config.
        with tempfile.TemporaryDirectory() as d:
            repo = os.path.join(d, "repo"); os.makedirs(repo)
            elsewhere = os.path.join(d, "elsewhere.yml")
            with open(elsewhere, "w", encoding="utf-8") as fh:
                fh.write("version: 1\ngroups: {}\n")
            os.symlink(elsewhere, os.path.join(repo, "panopticon.yml"))
            wt = os.path.join(d, "wt"); os.makedirs(wt)
            with open(os.path.join(wt, "panopticon.yml"), "w", encoding="utf-8") as fh:
                fh.write("version: 1\ngroups:\n  Evil:\n    match: ['**']\n")
            notes = diff_map._sync_config(repo, wt)
            self.assertTrue(any("symlink" in n for n in notes), notes)
            self.assertTrue(any("removed the PR's panopticon.yml" in n for n in notes), notes)
            self.assertFalse(os.path.exists(os.path.join(wt, "panopticon.yml")))

