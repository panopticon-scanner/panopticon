import os
import unittest

from scripts.tools import ADAPTERS
from tests.tools.conftest import FIXTURE_ROOT


# Guard against a surprising FIXTURE_ROOT value before any test relies on it.
assert FIXTURE_ROOT.rstrip(os.sep).endswith(os.path.join("tests", "fixtures"))


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
        self.assertGreaterEqual(len(findings), 1)
        self.assertTrue(
            any(
                f.get("source") == "tool:spotbugs"
                and f.get("category") == "jvm_security"
                for f in findings
            ),
            "expected a SpotBugs/FindSecBugs finding with the expected shape",
        )

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
        self.assertGreaterEqual(len(findings), 1)
        self.assertTrue(
            any(
                f.get("source") == "tool:dependency-check"
                and any(c.startswith("CVE-") for c in (f.get("citations") or {}).get("cve", []))
                for f in findings
            ),
            "expected dependency-check findings with CVE citations",
        )


if __name__ == "__main__":
    unittest.main()
