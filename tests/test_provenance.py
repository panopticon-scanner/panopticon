import unittest

import scripts.provenance as pv


class TestProvenance(unittest.TestCase):
    def test_tool_provenance(self):
        p = pv.tool_provenance("brakeman", reasoning="rule SCS0002")
        self.assertEqual(p, {
            "discovered_by": "tool:brakeman",
            "expanded_by": None,
            "confirmed_by": "tool:brakeman",
            "model": None,
            "model_version": None,
            "confirmation_status": "TOOL",
            "confirmation_reasoning": "rule SCS0002",
        })

    def test_default_reasoning_names_the_adapter(self):
        self.assertEqual(pv.tool_provenance("semgrep"), {
            "discovered_by": "tool:semgrep",
            "expanded_by": None,
            "confirmed_by": "tool:semgrep",
            "model": None,
            "model_version": None,
            "confirmation_status": "TOOL",
            "confirmation_reasoning": "Reported by static-analysis tool semgrep",
        })
