import os
import unittest

from scripts.tools import ADAPTERS

FIXTURE_ROOT = os.environ.get(
    "FIXTURE_ROOT", os.path.join(os.path.dirname(__file__), "..", "fixtures")
)


class TestJavaIntegration(unittest.TestCase):
    def _target(self, name: str) -> str:
        return os.path.join(FIXTURE_ROOT, name)

    # Fixture-not-vendored is the "am I in the fixtures image?" gate (skip);
    # past it, a non-applicable fixture or a tool crash is a real failure, not
    # a skip that would leave coverage silently empty (#582).
    def test_spotbugs_finds_webgoat_issues(self):
        target = self._target("WebGoat")
        adapter = ADAPTERS["spotbugs"]
        if not os.path.isdir(target):
            self.skipTest("WebGoat fixture not vendored (run inside the fixtures image)")
        self.assertTrue(adapter.is_applicable(target),
                        "spotbugs should apply to the WebGoat Java project")
        raw, rc = adapter.invoke(target)
        self.assertIn(rc, (0, 1), f"spotbugs errored (rc {rc}) on WebGoat")
        findings = adapter.parse(raw, "g1")
        self.assertTrue(findings, "expected SpotBugs findings against WebGoat")

    def test_dependency_check_finds_webgoat_vulns(self):
        target = self._target("WebGoat")
        adapter = ADAPTERS["dependency-check"]
        if not os.path.isdir(target):
            self.skipTest("WebGoat fixture not vendored (run inside the fixtures image)")
        self.assertTrue(adapter.is_applicable(target),
                        "dependency-check should apply to the WebGoat Java project")
        raw, rc = adapter.invoke(target)
        self.assertIn(rc, (0, 1), f"dependency-check errored (rc {rc}) on WebGoat")
        findings = adapter.parse(raw, "g1")
        self.assertTrue(findings, "expected dependency-check findings")
        self.assertTrue(
            any("CVE-" in str(f.get("citations")) for f in findings),
            "expected CVE citations",
        )


if __name__ == "__main__":
    unittest.main()
