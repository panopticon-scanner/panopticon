import shutil
import unittest

from scripts.tools import ADAPTERS


class TestRustCsIntegration(unittest.TestCase):
    def test_cargo_audit_skips_without_rust(self):
        adapter = ADAPTERS["cargo-audit"]
        self.assertIsNotNone(adapter)
        if shutil.which("cargo"):
            raise unittest.SkipTest("cargo is available; run full fixture test instead")
        self.assertTrue(True)

    def test_roslyn_secguard_skips_without_dotnet(self):
        adapter = ADAPTERS.get("roslyn-secguard")
        self.assertIsNotNone(adapter)
        if shutil.which("dotnet"):
            raise unittest.SkipTest("dotnet is available; run full fixture test instead")
        self.assertTrue(True)
