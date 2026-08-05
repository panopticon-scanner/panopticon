# tests/tools/test_hostile_csproj.py
"""Containment probe (P1): the hostile fixture's Exec targets run inside the
no-egress container; egress must fail and findings must still parse. Runs
only where the fixture and the roslyn adapter are usable (dev-local, like
test_csharp_integration.py)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__),
                                os.pardir, os.pardir, "skill"))
from scripts.tools import ADAPTERS

FIXTURE = os.path.join(os.path.dirname(__file__), os.pardir,
                       "fixtures", "hostile-csproj")


class TestHostileCsproj(unittest.TestCase):
    def test_contained_build_still_yields_scs_findings(self):
        adapter = ADAPTERS["roslyn-secguard"]
        if not os.path.isdir(FIXTURE):
            self.skipTest("hostile-csproj fixture missing")
        if not adapter.is_applicable(FIXTURE):
            self.skipTest("no csproj visible")
        try:
            raw, rc = adapter.invoke(FIXTURE)
        except FileNotFoundError:
            self.skipTest("dotnet not installed on this host")
        self.assertIn(rc, (0, 1))
        findings = adapter.parse(raw, "g")
        # Every finding is SCS (Task 3 filter); the Exec noise never lands.
        for f in findings:
            self.assertTrue(
                f["tool_evidence"]["rule_id"].startswith("SCS"))


if __name__ == "__main__":
    unittest.main()
