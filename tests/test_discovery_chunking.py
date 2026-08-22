"""Chunking, depth, and panel-priority tests."""
import unittest

from discovery_test_helpers import orchestrator


class TestChunkFiles(unittest.TestCase):
    def test_never_exceeds_max_per(self):
        files = ["a/f%02d.py" % i for i in range(37)]
        chunks = orchestrator.chunk_files(files, max_per=15)
        self.assertTrue(all(len(c) <= 15 for c in chunks))
        self.assertEqual(sum(len(c) for c in chunks), 37)

    def test_merges_small_directories(self):
        files = ["a/one.py", "b/two.py", "c/three.py"]
        chunks = orchestrator.chunk_files(files, max_per=15)
        self.assertEqual(chunks, [["a/one.py", "b/two.py", "c/three.py"]])

    def test_empty_input(self):
        self.assertEqual(orchestrator.chunk_files([], max_per=15), [])

    def test_chunk_files_rejects_nonpositive_max(self):
        with self.assertRaises(ValueError) as cm:
            orchestrator.chunk_files(["a/b.py"], max_per=0)
        self.assertIn("max_per must be >= 1", str(cm.exception))
        with self.assertRaises(ValueError) as cm:
            orchestrator.chunk_files(["a/b.py"], max_per=-1)
        self.assertIn("max_per must be >= 1", str(cm.exception))


class TestDepth(unittest.TestCase):
    def test_clean_group_is_shallow(self):
        depth = orchestrator._compute_depth(["docs/style.md"], ["code"], "standard")
        self.assertEqual(depth, "shallow")

    def test_security_panel_is_standard(self):
        result = orchestrator.build_result(".", "repo", ".", None, ["app/views.py"], [], 15, security_mode="standard")
        self.assertEqual(result["groups"][0]["depth"], "standard")

    def test_redteam_is_deep(self):
        result = orchestrator.build_result(".", "repo", ".", None, ["app/auth.py"], [], 15, security_mode="redteam")
        self.assertEqual(result["groups"][0]["depth"], "deep")


class TestPanelPriority(unittest.TestCase):
    def test_compute_group_panels_emits_priority_order(self):
        # Whatever panels are present, they must appear in PANEL_PRIORITY order.
        files = ["app.py", "models.py", "schema.sql", "infra/main.tf", "tests/test_app.py"]
        panels = orchestrator.compute_group_panels(files, "standard")
        assert panels == [p for p in orchestrator.PANEL_PRIORITY if p in panels]
        # security must precede code; code must precede test
        assert panels.index("security") < panels.index("code")
        assert panels.index("code") < panels.index("test")

    def test_compute_group_panels_redteam_mode_ordered(self):
        panels = orchestrator.compute_group_panels(["app.py", "tests/test_app.py"], "redteam")
        if "redteam" not in panels or "security" in panels: raise AssertionError()
        if panels != [p for p in orchestrator.PANEL_PRIORITY if p in panels]: raise AssertionError()

    def test_panels_in_priority_order_puts_unknown_last(self):
        assert orchestrator.panels_in_priority_order(
            ["test", "zzz", "security"]) == ["security", "test", "zzz"]
