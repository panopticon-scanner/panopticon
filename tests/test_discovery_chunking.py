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


class TestChunkCountIsExact(unittest.TestCase):
    """#1503: the #1499 even-target packing promised `ceil(n/max_per)` chunks
    and no starved tail. Both were false off the single-directory happy path,
    because directory blocks were packed FIRST-FIT in sorted-name order and a
    block that did not fit closed the current chunk. So the SAME 50 files
    chunked into 2 or 3 depending only on the directory NAMES, and a 97-file
    three-directory shape re-created the starved 4-file tail #1499 removed.
    Each phantom chunk is a full domain fan-out.
    """

    def _files(self, spec):
        return sorted("%s/f%03d.py" % (d, i) for d, n in spec for i in range(n))

    def test_directory_names_do_not_change_the_chunk_count(self):
        early = self._files([("a", 2), ("b", 25), ("c", 23)])
        late = self._files([("b", 25), ("c", 23), ("z", 2)])
        self.assertEqual([len(c) for c in orchestrator.chunk_files(early, max_per=48)],
                         [25, 25])
        self.assertEqual([len(c) for c in orchestrator.chunk_files(late, max_per=48)],
                         [25, 25])

    def test_no_sub_floor_trailing_chunk_across_directories(self):
        # 97 files as 30/30/37: the old packer emitted [30, 30, 33, 4].
        files = self._files([("a", 30), ("b", 30), ("c", 37)])
        chunks = orchestrator.chunk_files(files, max_per=48)
        self.assertEqual(len(chunks), 3)
        self.assertGreaterEqual(min(len(c) for c in chunks),
                                orchestrator.COMMONS_MIN_FILES)

    def test_the_guarantees_hold_over_many_directory_shapes(self):
        import math
        shapes = [
            [("a", 2), ("b", 25), ("c", 23)],
            [("a", 30), ("b", 30), ("c", 37)],
            [("a", 1), ("b", 1), ("c", 1)],
            [("a", 48), ("b", 48)],
            [("a", 49)],
            [("a", 100), ("b", 3), ("c", 3), ("d", 3)],
            [("a", 7), ("b", 11), ("c", 13), ("d", 17), ("e", 19), ("f", 23)],
            [("deep/nest/a", 60), ("deep/nest/b", 60), ("z", 1)],
        ]
        for max_per in (7, 15, 48):
            for shape in shapes:
                files = self._files(shape)
                with self.subTest(max_per=max_per, shape=shape):
                    chunks = orchestrator.chunk_files(files, max_per=max_per)
                    sizes = [len(c) for c in chunks]
                    # exactly the promised count, never one more
                    self.assertEqual(len(chunks),
                                     math.ceil(len(files) / max_per))
                    # the cap still holds, and no chunk is starved relative to
                    # its siblings: sizes differ by at most one
                    self.assertLessEqual(max(sizes), max_per)
                    self.assertLessEqual(max(sizes) - min(sizes), 1)
                    # every file exactly once
                    flat = [f for c in chunks for f in c]
                    self.assertEqual(sorted(flat), files)
                    self.assertEqual(len(flat), len(set(flat)))

    def test_a_directory_stays_together_when_it_fits(self):
        # Cohesion is still the point: 25 + 23 + 2 packs as b | c+a, not by
        # slicing b across the boundary.
        files = self._files([("a", 2), ("b", 25), ("c", 23)])
        chunks = orchestrator.chunk_files(files, max_per=48)
        dirs = [{f.split("/")[0] for f in c} for c in chunks]
        self.assertIn({"b"}, dirs)
