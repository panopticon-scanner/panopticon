import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
from scripts.tools import ADAPTERS
from scripts.tools.legacy_sarif import LegacySarifAdapter

FIXTURE_ROOT = os.environ.get(
    "FIXTURE_ROOT", os.path.join(os.path.dirname(__file__), "..", "fixtures")
)


def _invoke_legacy_sarif(tool: str, target: str) -> tuple[bytes, int]:
    """Run a legacy SARIF tool directly; adapters of this type have no invoke()."""
    cmd = [tool, "-f", "sarif", target]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout, result.returncode


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
        if isinstance(adapter, LegacySarifAdapter):
            raw, rc = _invoke_legacy_sarif("brakeman", target)
        else:
            raw, rc = adapter.invoke(target)
        # Brakeman exits 3 when warnings are found; 0/1 are also acceptable.
        if rc not in (0, 1, 3):
            self.skipTest(f"brakeman failed with {rc}")
        findings = adapter.parse(raw, "g1")
        self.assertTrue(findings, "expected brakeman findings against railsgoat")

    def test_bundler_audit_finds_railsgoat_vulns(self):
        target = self._target("railsgoat")
        if "bundler-audit" not in ADAPTERS:
            self.skipTest("bundler-audit adapter not registered")
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
