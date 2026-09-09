"""#1521 (OPS-D1A): the verify advisor prompt embedded a whole cell uncapped.

`_render_findings` serialized every finding a domain-panel returned, with no
truncation anywhere between the panel's output and the embedding step -- while
the sibling tool-hits channel a few hundred lines away is capped at 40. Under
redteam the target is adversarial by definition and can be engineered to make a
reviewer flood findings.

The fix must NOT be to drop claims. `_verify_cell_done` requires every finding
in the cell to have a verdict, so a silently truncated prompt would burn the
whole re-dispatch budget and then declare a real gap. Oversized cells are
CHUNKED across several advisor dispatches instead, and the per-claim free text
-- the dominant size term -- is bounded.
"""
import json
import os
import tempfile
import unittest

import scripts.phases.runio as runio
import scripts.phases.verify as verify


def _finding(i, description="d"):
    return {"id": "SEC-%03d" % i, "code": "SEC-A1A", "severity": "HIGH",
            "title": "finding %d" % i, "category": "general",
            "location": {"file": "src/app.py", "line_start": i + 1},
            "description": description}


class TestChunking(unittest.TestCase):
    def test_a_small_cell_is_one_chunk(self):
        cell = [_finding(i) for i in range(3)]
        self.assertEqual(verify._cell_chunks(cell), [cell])

    def test_an_oversized_cell_splits_at_the_cap(self):
        cap = verify._CELL_CLAIMS_CAP
        cell = [_finding(i) for i in range(cap * 2 + 1)]
        chunks = verify._cell_chunks(cell)
        self.assertEqual(len(chunks), 3)
        self.assertEqual([len(c) for c in chunks], [cap, cap, 1])

    def test_chunking_loses_no_claim(self):
        cell = [_finding(i) for i in range(verify._CELL_CLAIMS_CAP * 3 + 7)]
        flat = [f for chunk in verify._cell_chunks(cell) for f in chunk]
        self.assertEqual([f["id"] for f in flat], [f["id"] for f in cell])

    def test_an_empty_cell_is_a_single_empty_chunk(self):
        self.assertEqual(verify._cell_chunks([]), [[]])


class TestClaimTextIsBounded(unittest.TestCase):
    def test_a_huge_description_is_truncated_visibly(self):
        cell = [_finding(0, description="x" * (verify._CLAIM_DESC_CAP * 4))]
        rendered = json.loads(verify._render_findings("/repo", cell))
        description = rendered[0]["description"]
        self.assertLess(len(description), verify._CLAIM_DESC_CAP * 2)
        self.assertIn("truncated", description)

    def test_an_ordinary_description_is_untouched(self):
        cell = [_finding(0, description="a normal finding description")]
        rendered = json.loads(verify._render_findings("/repo", cell))
        self.assertEqual(rendered[0]["description"],
                         "a normal finding description")

    def test_truncation_never_touches_the_adjudicable_fields(self):
        # The advisor still needs the id to echo, and the locus to go read.
        cell = [_finding(7, description="y" * (verify._CLAIM_DESC_CAP * 4))]
        rendered = json.loads(verify._render_findings("/repo", cell))[0]
        self.assertEqual(rendered["id"], "SEC-007")
        self.assertEqual(rendered["severity"], "HIGH")
        self.assertEqual(rendered["title"], "finding 7")
        self.assertEqual(rendered["location"]["line_start"], 8)


class TestPartPaths(unittest.TestCase):
    def test_part_zero_keeps_the_established_filename(self):
        # Existing runs, tests and the backup reader all key on this name.
        self.assertEqual(verify._verify_out_file("/r", "G", "SEC", "primary"),
                         verify._verify_out_file("/r", "G", "SEC", "primary", 0))
        self.assertTrue(verify._verify_out_file("/r", "G", "SEC", "primary")
                        .endswith("verdicts-G-SEC.json"))

    def test_later_parts_get_their_own_file(self):
        first = verify._verify_out_file("/r", "G", "SEC", "primary", 0)
        second = verify._verify_out_file("/r", "G", "SEC", "primary", 1)
        self.assertNotEqual(first, second)
        self.assertIn("part1", os.path.basename(second))

    def test_the_backup_stage_still_separates_from_primary(self):
        self.assertNotEqual(
            verify._verify_out_file("/r", "G", "SEC", "primary", 1),
            verify._verify_out_file("/r", "G", "SEC", "backup", 1))


class TestVerdictsMergeAcrossParts(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        os.makedirs(runio._pano(self.root, "verdicts"))
        self.addCleanup(self._t.cleanup)
        self.manifest = {"run_id": "R", "host": "claude"}

    def _write_part(self, part, ids):
        path = verify._verify_out_file(self.root, "G", "SEC", "primary", part)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"_panopticon": {"run_id": "R", "group": "G",
                                       "domain": "SEC", "stage": "primary"},
                       "verdicts": [{"finding_id": i, "verdict": "confirmed"}
                                    for i in ids]}, fh)

    def test_a_cell_is_done_only_when_every_part_answered(self):
        cell = [_finding(i) for i in range(verify._CELL_CLAIMS_CAP + 3)]
        self._write_part(0, [f["id"] for f in cell[:verify._CELL_CLAIMS_CAP]])
        self.assertFalse(verify._cell_parts_complete(
            self.root, self.manifest, "G", "SEC", "primary", cell))
        self._write_part(1, [f["id"] for f in cell[verify._CELL_CLAIMS_CAP:]])
        self.assertTrue(verify._cell_parts_complete(
            self.root, self.manifest, "G", "SEC", "primary", cell))

    def test_merged_verdicts_span_every_part(self):
        cell = [_finding(i) for i in range(verify._CELL_CLAIMS_CAP + 2)]
        self._write_part(0, [f["id"] for f in cell[:verify._CELL_CLAIMS_CAP]])
        self._write_part(1, [f["id"] for f in cell[verify._CELL_CLAIMS_CAP:]])
        merged = verify._cell_verdicts(self.root, "G", "SEC", "primary",
                                       parts=2)
        self.assertEqual(len(merged), len(cell))

    def test_a_single_part_cell_reads_exactly_as_before(self):
        cell = [_finding(i) for i in range(3)]
        self._write_part(0, [f["id"] for f in cell])
        self.assertTrue(verify._cell_parts_complete(
            self.root, self.manifest, "G", "SEC", "primary", cell))


if __name__ == "__main__":
    unittest.main()
