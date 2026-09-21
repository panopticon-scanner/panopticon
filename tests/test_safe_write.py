"""`scripts.safe_write`: the ONE no-follow `.panopticon` artifact open (#1735).

The primitive lived in `phases/runio`, which `run_manifest` may not import --
`phases/*` imports `run_manifest`, so the arrow only goes one way (layout rule
3) -- and neither may `synth/*`. A leaf module with no panopticon imports of
its own is reachable from all three, so the guard is written once and every
`.panopticon`-resident writer can have it.

runio keeps its private spellings as aliases of these functions: ~15 call
sites and the suite's one `mock.patch` target say `runio._open_w_nofollow`,
and a SECOND implementation behind that name is exactly the drift layout rule
4 exists to prevent -- so the identity is pinned here.
"""
import os
import tempfile
import unittest

import scripts.safe_write as safe_write
from scripts.phases import runio


class TestOneImplementation(unittest.TestCase):
    """runio's names ARE these functions -- not copies of them."""

    def test_runio_aliases_are_this_modules_functions(self):
        self.assertIs(runio._open_w_nofollow, safe_write.open_w_nofollow)
        self.assertIs(runio._open_a_nofollow, safe_write.open_a_nofollow)
        self.assertIs(runio._confine_artifact_path,
                      safe_write.confine_artifact_path)


class TestNoFollowOpen(unittest.TestCase):
    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.root = self._d.name
        self.addCleanup(self._d.cleanup)
        self.pano = os.path.join(self.root, ".panopticon")
        os.makedirs(self.pano)

    def _victim(self):
        victim = os.path.join(self.root, "victim.txt")
        with open(victim, "w", encoding="utf-8") as fh:
            fh.write("PRECIOUS")
        return victim

    def test_a_planted_symlink_out_of_the_tree_is_refused(self):
        # The plantable attack: the link points at a file the invoking user can
        # write. The whole-path confinement answers it FIRST -- loudly, and
        # before any byte moves -- so the O_NOFOLLOW fallback below is only ever
        # reached by a link that stays inside `.panopticon`.
        victim = self._victim()
        artifact = os.path.join(self.pano, "artifact.json")
        os.symlink(victim, artifact)
        with self.assertRaises(ValueError):
            safe_write.open_w_nofollow(artifact)
        with open(victim, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "PRECIOUS")

    def test_a_planted_symlink_is_replaced_not_written_through(self):
        victim = self._victim()
        artifact = os.path.join(self.root, "artifact.json")   # no .panopticon segment
        os.symlink(victim, artifact)
        with safe_write.open_w_nofollow(artifact) as fh:
            fh.write("{}")
        with open(victim, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "PRECIOUS")
        self.assertFalse(os.path.islink(artifact))
        self.assertTrue(os.path.isfile(artifact))

    def test_append_does_not_follow_a_planted_symlink(self):
        victim = self._victim()
        artifact = os.path.join(self.root, "ledger.jsonl")    # no .panopticon segment
        os.symlink(victim, artifact)
        with safe_write.open_a_nofollow(artifact) as fh:
            fh.write("line\n")
        with open(victim, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "PRECIOUS")
        self.assertFalse(os.path.islink(artifact))

    def test_confine_rejects_a_symlinked_intermediate_component(self):
        outside = os.path.join(self.root, "outside")
        os.makedirs(outside)
        os.symlink(outside, os.path.join(self.pano, "runs"))
        with self.assertRaises(ValueError):
            safe_write.confine_artifact_path(
                os.path.join(self.pano, "runs", "tag", "report.json"))
        # a path with no `.panopticon` segment is not an artifact path
        safe_write.confine_artifact_path(os.path.join(self.root, "elsewhere.json"))


if __name__ == "__main__":
    unittest.main()
