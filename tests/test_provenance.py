import unittest

import scripts.provenance as pv


class TestProvenance(unittest.TestCase):
    def test_tool_provenance(self):
        p = pv.tool_provenance("brakeman", reasoning="rule SCS0002")
        self.assertEqual(p["discovered_by"], "tool:brakeman")
        self.assertEqual(p["confirmed_by"], "tool:brakeman")
        self.assertEqual(p["confirmation_status"], "TOOL")
        self.assertIsNone(p["model"])
