import shutil
import tempfile
import unittest

from scripts.tools import ADAPTERS


class TestRustCsIntegration(unittest.TestCase):
    def test_cargo_audit_skips_without_rust(self):
        adapter = ADAPTERS["cargo-audit"]
        self.assertIsNotNone(adapter)
        if shutil.which("cargo"):
            raise unittest.SkipTest("cargo is available; run full fixture test instead")

        with tempfile.TemporaryDirectory() as empty_target:
            self.assertFalse(adapter.is_applicable(empty_target))

    def test_roslyn_secguard_skips_without_dotnet(self):
        adapter = ADAPTERS.get("roslyn-secguard")
        self.assertIsNotNone(adapter)
        if shutil.which("dotnet"):
            raise unittest.SkipTest("dotnet is available; run full fixture test instead")

        with tempfile.TemporaryDirectory() as empty_target:
            self.assertFalse(adapter.is_applicable(empty_target))


if __name__ == "__main__":
    unittest.main()

