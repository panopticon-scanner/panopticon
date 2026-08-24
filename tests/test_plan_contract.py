"""#run7 TST-A2B: direct coverage for plan_contract.artifact_root's fail-closed
branches. Previously only the symlink branch was exercised indirectly via
test_driver.py::TestArtifactConfinement; the "exists but not a directory" branch
(a security-relevant guard) had none."""
import os
import tempfile
import unittest

import scripts.plan_contract as pc


class TestArtifactRoot(unittest.TestCase):
    def test_accepts_real_directory(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".panopticon"))
            self.assertEqual(pc.artifact_root(d),
                             os.path.join(os.path.abspath(d), ".panopticon"))

    def test_rejects_panopticon_that_is_a_plain_file(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, ".panopticon"), "w").close()   # a file, not a dir
            with self.assertRaises(ValueError) as cm:
                pc.artifact_root(d)
            self.assertIn("not a directory", str(cm.exception))

    def test_rejects_symlinked_panopticon(self):
        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, "real")
            os.makedirs(target)
            os.symlink(target, os.path.join(d, ".panopticon"))
            with self.assertRaises(ValueError) as cm:
                pc.artifact_root(d)
            self.assertIn("symlink", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
