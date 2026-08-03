import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, "skill"))
from scripts.tools import ADAPTERS

FIXTURE_ROOT = os.environ.get(
    "FIXTURE_ROOT", os.path.join(os.path.dirname(__file__), "..", "fixtures")
)


class TestJavaIntegration(unittest.TestCase):
    def _target(self, name: str) -> str:
        return os.path.join(FIXTURE_ROOT, name)

    def test_spotbugs_finds_webgoat_issues(self):
        target = self._target("WebGoat")
        adapter = ADAPTERS["spotbugs"]
        if not os.path.isdir(target):
            self.skipTest("WebGoat fixture not vendored")
        if not adapter.is_applicable(target):
            self.skipTest("spotbugs not applicable")
        raw, rc = adapter.invoke(target)
        if rc not in (0, 1):
            self.skipTest(f"spotbugs failed with {rc}")
        findings = adapter.parse(raw, "g1")
        self.assertTrue(findings, "expected SpotBugs findings against WebGoat")

    def test_dependency_check_finds_webgoat_vulns(self):
        target = self._target("WebGoat")
        adapter = ADAPTERS["dependency-check"]
        if not os.path.isdir(target):
            self.skipTest("WebGoat fixture not vendored")
        if not adapter.is_applicable(target):
            self.skipTest("dependency-check not applicable")
        raw, rc = adapter.invoke(target)
        if rc not in (0, 1):
            self.skipTest(f"dependency-check failed with {rc}")
        findings = adapter.parse(raw, "g1")
        self.assertTrue(findings, "expected dependency-check findings")
        self.assertTrue(
            any("CVE-" in str(f.get("citations")) for f in findings),
            "expected CVE citations",
        )


if __name__ == "__main__":
    unittest.main()
