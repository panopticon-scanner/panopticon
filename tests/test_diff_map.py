# tests/test_diff_map.py
import os, sys, unittest, subprocess, tempfile
from unittest import mock
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "skill", "scripts"))
import diff_map


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


class TestHunkMap(unittest.TestCase):
    def _repo(self):
        d = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, d, ignore_errors=True)
        subprocess.run(["git", "init", "-q", d], check=True)
        _git(d, "config", "user.email", "t@e.com")
        _git(d, "config", "user.name", "T")
        with open(os.path.join(d, "a.py"), "w") as fh:
            fh.write("\n".join("line%d" % i for i in range(1, 11)) + "\n")
        _git(d, "add", ".")
        _git(d, "commit", "-qm", "init")
        _git(d, "branch", "-M", "main")
        return d

    def test_committed_and_uncommitted_changes(self):
        d = self._repo()
        _git(d, "checkout", "-q", "-b", "feat")
        # committed change to line 3
        p = os.path.join(d, "a.py")
        lines = open(p).read().splitlines()
        lines[2] = "CHANGED3"
        open(p, "w").write("\n".join(lines) + "\n")
        _git(d, "commit", "-qam", "c")
        # uncommitted new file (untracked) -> whole-file range
        open(os.path.join(d, "b.py"), "w").write("x\ny\n")
        m = diff_map.hunk_map(d, "main")
        self.assertIn("a.py", m)
        self.assertTrue(any(s <= 3 <= e for (s, e) in m["a.py"]))
        self.assertEqual(m["b.py"], [(1, 2)])

    def test_missing_base_returns_empty(self):
        self.assertEqual(diff_map.hunk_map(self._repo(), "no-such-ref"), {})

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
        d = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, d, ignore_errors=True)
        subprocess.run(["git", "init", "-q", d], check=True)
        _git(d, "config", "user.email", "t@e.com")
        _git(d, "config", "user.name", "T")
        with open(os.path.join(d, "a.py"), "w") as fh:
            fh.write("line1\n")
        _git(d, "add", ".")
        _git(d, "commit", "-qm", "init")
        _git(d, "branch", "-M", "main")
        return d

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
        with mock.patch.object(diff_map, "_worktree_dir", return_value="/tmp/wt-pr7"):
            info = diff_map.acquire_pr(7, repo=".", runner=runner)
        self.assertEqual(info["base"], "main")
        self.assertEqual(info["worktree"], "/tmp/wt-pr7")
        worktree = next(a for a in calls if "worktree" in a and "add" in a)
        self.assertEqual(worktree[-1], "deadbeef")
        self.assertNotIn("FETCH_HEAD", " ".join(" ".join(a) for a in calls))
        self.assertTrue(any("--no-write-fetch-head" in a for a in calls))
        self.assertTrue(any("update-ref" in a and fetched_ref[0] in a for a in calls))
        self.assertTrue(any("refs/pull/7/head" in " ".join(a) for a in calls))

    def test_acquire_is_idempotent_deterministic_path(self):
        repo = "."
        wt = diff_map._worktree_dir(repo, 7)
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

    def test_release_is_tolerant(self):
        def runner(argv, **kw):
            class R: returncode = 1; stdout = ""; stderr = "not a worktree"
            return R()
        diff_map.release_worktree("/tmp/gone", runner=runner)  # must not raise
