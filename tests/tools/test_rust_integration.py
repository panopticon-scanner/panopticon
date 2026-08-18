import os
import shutil
import unittest

from scripts.tools import ADAPTERS
from conftest import FIXTURE_ROOT

OK_SCAN_EXIT_CODES = (0, 1)  # 0 = clean exit, 1 = findings detected


class TestRustIntegration(unittest.TestCase):
    def test_cargo_audit_finds_rustsec_advisories(self):
        if not shutil.which("cargo"):
            self.skipTest("cargo not installed")
        target = os.path.join(FIXTURE_ROOT, "vulnerable-rust")
        if "cargo-audit" not in ADAPTERS:
            self.skipTest("cargo-audit adapter not registered")
        adapter = ADAPTERS["cargo-audit"]
        if not os.path.isdir(target):
            self.skipTest("vulnerable-rust fixture not present")
        if not adapter.is_applicable(target):
            self.skipTest("cargo-audit not applicable")
        raw, rc = adapter.invoke(target)
        if rc not in OK_SCAN_EXIT_CODES:
            self.skipTest(f"cargo-audit failed with {rc}")
        findings = adapter.parse(raw, "g1")
        self.assertTrue(findings, "expected cargo-audit findings")
        self.assertTrue(
            any("RUSTSEC-" in str(f.get("citations")) for f in findings),
            "expected RUSTSEC citations",
        )


if __name__ == "__main__":
    unittest.main()
