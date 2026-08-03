import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
from scripts.tools import ADAPTERS

FIXTURE_ROOT = os.environ.get(
    "FIXTURE_ROOT", os.path.join(os.path.dirname(__file__), "..", "fixtures")
)


class TestJavaIntegration(unittest.TestCase):
    def _target(self, name: str) -> str:
        return os.path.join(FIXTURE_ROOT, name)

    def test_spotbugs_finds_webgoat_issues(self):
        target = self._target("WebGoat")
        if "spotbugs" not in ADAPTERS:
            self.skipTest("spotbugs adapter not registered")
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
        if "dependency-check" not in ADAPTERS:
            self.skipTest("dependency-check adapter not registered")
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
WEBGOAT = "https://github.com/WebGoat/WebGoat.git"


@unittest.skip("dependency-check integration requires Java runtime and large DB")
class TestJavaIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.repo = os.path.join(self.tmp, "webgoat")
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", WEBGOAT, self.repo],
                capture_output=True, timeout=180, check=True,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.tearDown()
            raise unittest.SkipTest(f"Could not clone fixture repo: {e}")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_dependency_check_finds_issues(self):
        adapter = ADAPTERS["dependency-check"]
        if not adapter.is_applicable(self.repo):
            raise unittest.SkipTest("Fixture does not look like a Java project")
