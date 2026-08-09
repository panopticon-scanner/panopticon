# tests/test_diff_map.py
import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "skill", "scripts"))
import diff_map

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
