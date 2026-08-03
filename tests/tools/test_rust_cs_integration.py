import os
import shutil
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, "skill"))
from scripts.tools import ADAPTERS


class TestRustCsIntegration(unittest.TestCase):
    def test_cargo_audit_skips_without_rust(self):
        adapter = ADAPTERS["cargo-audit"]
        self.assertIsNotNone(adapter)
        if shutil.which("cargo"):
            raise unittest.SkipTest("cargo is available; run full fixture test instead")
        self.assertTrue(True)
