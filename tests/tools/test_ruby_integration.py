import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
from scripts.tools import ADAPTERS

FIXTURE_ROOT = os.environ.get(
    "FIXTURE_ROOT", os.path.join(os.path.dirname(__file__), "..", "fixtures")
)


class TestRubyIntegration(unittest.TestCase):
    def _target(self, name: str) -> str:
        return os.path.join(FIXTURE_ROOT, name)

    def test_brakeman_finds_railsgoat_issues(self):
        target = self._target("railsgoat")
        adapter = ADAPTERS["brakeman"]
        if not os.path.isdir(target):
            self.skipTest("railsgoat fixture not vendored")
        if not adapter.is_applicable(target):
            self.skipTest("brakeman not applicable")
        raw, rc = adapter.invoke(target)
        if rc not in (0, 1):
            self.skipTest(f"brakeman failed with {rc}")
        findings = adapter.parse(raw, "g1")
        self.assertTrue(findings, "expected brakeman findings against railsgoat")

    def test_bundler_audit_finds_railsgoat_vulns(self):
        target = self._target("railsgoat")
        adapter = ADAPTERS["bundler-audit"]
        if not os.path.isdir(target):
            self.skipTest("railsgoat fixture not vendored")
        if not adapter.is_applicable(target):
            self.skipTest("bundler-audit not applicable")
        raw, rc = adapter.invoke(target)
        if rc not in (0, 1):
            self.skipTest(f"bundler-audit failed with {rc}")
        findings = adapter.parse(raw, "g1")
        self.assertTrue(findings, "expected bundler-audit findings")


if __name__ == "__main__":
    unittest.main()
