# tests/tools/test_hostile_csproj.py
"""Containment probe (P1): the hostile fixture's Exec targets run inside the
no-egress container; egress must fail and findings must still parse.

Opt-in only: set PANOPTICON_CONTAINMENT_PROBE=1 to run it. This test
actually executes evil.csproj's hostile MSBuild target (a live curl attempt
and a marker-file write) via `dotnet build`, invoked through plain
subprocess with no sandboxing of its own. It must only be run inside the
no-egress panopticon-tools container, never on a bare host or CI runner —
bare hosts/runners (e.g. ubuntu-latest, which ships the .NET SDK
preinstalled) have no `--network none` to contain the egress attempt, so
running this test there would perform the real curl. On bare hosts this
test always skips unless the env var is set explicitly."""
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
        if os.environ.get("PANOPTICON_CONTAINMENT_PROBE") != "1":
            self.skipTest(
                "containment probe is opt-in: it executes hostile build logic and "
                "must only run inside the no-egress panopticon-tools container "
                "(set PANOPTICON_CONTAINMENT_PROBE=1)")
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
