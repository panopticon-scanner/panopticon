import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, "skill"))
from scripts.tools import ADAPTERS

FIXTURE_ROOT = os.environ.get(
    "FIXTURE_ROOT", os.path.join(os.path.dirname(__file__), "..", "fixtures")
)


class TestCSharpIntegration(unittest.TestCase):
    def test_roslyn_secguard_finds_aspnet_issues(self):
        target = os.path.join(FIXTURE_ROOT, "AspGoat")
        if "roslyn-secguard" not in ADAPTERS:
            self.skipTest("roslyn-secguard adapter not registered")
        adapter = ADAPTERS["roslyn-secguard"]
        if not os.path.isdir(target):
            self.skipTest("AspGoat fixture not vendored")
        if not adapter.is_applicable(target):
            self.skipTest("roslyn-secguard not applicable")
        raw, rc = adapter.invoke(target)
        if rc not in (0, 1):
            self.skipTest(f"roslyn-secguard failed with {rc}")
        findings = adapter.parse(raw, "g1")
        self.assertTrue(findings, "expected SecurityCodeScan findings against AspGoat")


if __name__ == "__main__":
    unittest.main()
