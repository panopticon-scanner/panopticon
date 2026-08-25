import shutil
import subprocess
import unittest

from _test_helpers import assert_adapter_finds
from .conftest import OK_SCAN_EXIT_CODES


class TestRustIntegration(unittest.TestCase):
    def test_cargo_audit_finds_rustsec_advisories(self):
        if not shutil.which("cargo"):
            self.skipTest("cargo not installed")
        proc = subprocess.run(["cargo", "audit", "--version"],
                              capture_output=True, text=True, timeout=30)
        if proc.returncode != 0:
            self.skipTest("cargo-audit subcommand not installed")
        findings = assert_adapter_finds(
            self, "cargo-audit", "vulnerable-rust", ok_codes=OK_SCAN_EXIT_CODES
        )
        self.assertTrue(
            any(
                any(r.startswith("RUSTSEC-")
                    for r in (f.get("citations") or {}).get("rustsec", []))
                for f in findings
            ),
            "expected RUSTSEC citations",
        )


if __name__ == "__main__":
    unittest.main()
