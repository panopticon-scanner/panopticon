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


class TestChunkBalance(unittest.TestCase):
    """#1499: chunks pack to an even target, not greedily to max_per.

    Greedy packing of 97 files at max_per=48 gives 48/48/1, and that 1-file
    trailing chunk is a full review cell in the measured 0.20-findings/cell
    bucket -- the Commons floor's waste, re-introduced one level down.
    """

    def test_no_starved_trailing_chunk(self):
        files = ["src/f%03d.py" % i for i in range(97)]
        chunks = orchestrator.chunk_files(files, max_per=48)
        self.assertEqual(len(chunks), 3)                    # count unchanged
        self.assertTrue(all(len(c) <= 48 for c in chunks))  # cap still holds
        sizes = [len(c) for c in chunks]
        self.assertLessEqual(max(sizes) - min(sizes), 2)    # balanced: 33/33/31
        self.assertEqual(sum(len(c) for c in chunks), 97)   # nothing dropped

    def test_chunk_count_matches_greedy(self):
        # Balancing must never ADD a cell: ceil(n/max_per) either way.
        import math
        for n in (1, 47, 48, 49, 96, 97, 200):
            files = ["src/f%03d.py" % i for i in range(n)]
            chunks = orchestrator.chunk_files(files, max_per=48)
            self.assertEqual(len(chunks), max(1, math.ceil(n / 48)), n)
            self.assertTrue(all(len(c) <= 48 for c in chunks), n)
