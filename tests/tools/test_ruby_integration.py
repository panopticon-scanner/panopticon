import unittest

from _test_helpers import assert_adapter_finds
from .conftest import OK_SCAN_EXIT_CODES


class TestRubyIntegration(unittest.TestCase):
    # Fixture-not-vendored is the "am I in the fixtures image?" gate (skip);
    # past it, a non-applicable fixture or a tool crash is a real failure, not
    # a skip that would leave coverage silently empty (#583).
    def test_brakeman_finds_railsgoat_issues(self):
        findings = assert_adapter_finds(self, "brakeman", "railsgoat",
                                        ok_codes=OK_SCAN_EXIT_CODES)
        self.assertTrue(findings, "expected brakeman findings against railsgoat")

    def test_bundler_audit_finds_railsgoat_vulns(self):
        findings = assert_adapter_finds(self, "bundler-audit", "railsgoat",
                                        ok_codes=OK_SCAN_EXIT_CODES)
        self.assertTrue(findings, "expected bundler-audit findings against railsgoat")


if __name__ == "__main__":
    unittest.main()
