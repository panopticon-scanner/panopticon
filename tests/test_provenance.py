import unittest

import scripts.provenance as pv


class TestProvenance(unittest.TestCase):
    def test_tool_provenance(self):
        p = pv.tool_provenance("brakeman", reasoning="rule SCS0002")
        self.assertEqual(p["discovered_by"], "tool:brakeman")
        self.assertEqual(p["confirmed_by"], "tool:brakeman")
        self.assertEqual(p["confirmation_status"], "TOOL")
        self.assertIsNone(p["model"])

    def test_agent_provenance_unconfirmed(self):
        p = pv.agent_provenance("lens_sweep", "kimi-k2.7-coding", "2026-08-03")
        self.assertEqual(p["discovered_by"], "agent:lens_sweep")
        self.assertEqual(p["confirmation_status"], "UNVERIFIED")
        self.assertEqual(p["model"], "kimi-k2.7-coding")

    def test_merge_provenance_expansion(self):
        base = pv.agent_provenance("lens_sweep", "kimi-k2.7-coding", "v1")
        expansion = pv.agent_provenance("panel_review", "kimi-k3", "v2")
        merged = pv.merge_provenance(base, expansion)
        self.assertEqual(merged["discovered_by"], "agent:lens_sweep")
        self.assertEqual(merged["expanded_by"], "agent:panel_review")
        self.assertEqual(merged["model"], "kimi-k3")
