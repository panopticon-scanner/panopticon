import shutil
import tempfile
import unittest

from scripts.tools import ADAPTERS


class TestRustCsIntegration(unittest.TestCase):
    def _assert_not_applicable_without_toolchain(self, adapter_name, tool_cmd):
        adapter = ADAPTERS.get(adapter_name) or ADAPTERS[adapter_name]
        self.assertIsNotNone(adapter)
        if shutil.which(tool_cmd):
            raise unittest.SkipTest(
                f"{tool_cmd} is available; run full fixture test instead")

        with tempfile.TemporaryDirectory() as empty_target:
            self.assertFalse(adapter.is_applicable(empty_target))

    def test_cargo_audit_skips_without_rust(self):
        self._assert_not_applicable_without_toolchain("cargo-audit", "cargo")

    def test_roslyn_secguard_skips_without_dotnet(self):
        self._assert_not_applicable_without_toolchain("roslyn-secguard", "dotnet")


if __name__ == "__main__":
    unittest.main()

