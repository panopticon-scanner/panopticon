# tests/test_diff_map.py
import os, sys, unittest, subprocess, tempfile
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
