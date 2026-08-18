import os
import unittest

from scripts.tools import ADAPTERS
from conftest import FIXTURE_ROOT

OK_SCAN_EXIT_CODES = (0, 1)  # 0 = clean exit, 1 = findings detected


class TestRubyIntegration(unittest.TestCase):
    def _target(self, name: str) -> str:
        return os.path.join(FIXTURE_ROOT, name)

    # Fixture-not-vendored is the "am I in the fixtures image?" gate (skip);
    # past it, a non-applicable fixture or a tool crash is a real failure, not
    # a skip that would leave coverage silently empty (#583).
    def test_brakeman_finds_railsgoat_issues(self):
        target = self._target("railsgoat")
        adapter = ADAPTERS["brakeman"]
        if not os.path.isdir(target):
            self.skipTest("railsgoat fixture not vendored (run inside the fixtures image)")
        self.assertTrue(adapter.is_applicable(target),
                        "brakeman should apply to the railsgoat Rails project")
        raw, rc = adapter.invoke(target)
        self.assertIn(rc, OK_SCAN_EXIT_CODES, f"brakeman errored (rc {rc}) on railsgoat")
        findings = adapter.parse(raw, "g1")
        self.assertTrue(findings, "expected brakeman findings against railsgoat")

    def test_bundler_audit_finds_railsgoat_vulns(self):
        target = self._target("railsgoat")
        adapter = ADAPTERS["bundler-audit"]
        if not os.path.isdir(target):
            self.skipTest("railsgoat fixture not vendored (run inside the fixtures image)")
        self.assertTrue(adapter.is_applicable(target),
                        "bundler-audit should apply to the railsgoat Rails project")
        raw, rc = adapter.invoke(target)
        self.assertIn(rc, OK_SCAN_EXIT_CODES, f"bundler-audit errored (rc {rc}) on railsgoat")
        findings = adapter.parse(raw, "g1")
        self.assertTrue(findings, "expected bundler-audit findings")


if __name__ == "__main__":
    unittest.main()
