import os, unittest, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "skill"))
import scripts.write_guard_hook as wg


class TestDecide(unittest.TestCase):
    def setUp(self):
        self.allow = {os.path.abspath(".panopticon/findings-g1-code-panel_review.json")}

    def test_write_to_allowed_out_file_is_permitted(self):
        ok, _ = wg.decide("Write",
                          ".panopticon/findings-g1-code-panel_review.json", self.allow)
        self.assertTrue(ok)

    def test_write_outside_allowlist_is_blocked(self):
        ok, reason = wg.decide("Write", "skill/scripts/synthesize.py", self.allow)
        self.assertFalse(ok)
        self.assertIn("outside", reason.lower())

    def test_write_to_sibling_findings_not_in_plan_is_blocked(self):
        ok, _ = wg.decide("Edit",
                          ".panopticon/findings-g9-code-panel_review.json", self.allow)
        self.assertFalse(ok)

    def test_non_write_tool_is_permitted(self):
        ok, _ = wg.decide("Read", "/etc/passwd", self.allow)
        self.assertTrue(ok)


class TestAllowlistFromPlan(unittest.TestCase):
    def test_collects_out_files_absolute(self):
        plan = [{"out_file": ".panopticon/a.json"}, {"out_file": ".panopticon/b.json"}]
        al = wg.allowlist_from_plan(plan)
        self.assertEqual(al, {os.path.abspath(".panopticon/a.json"),
                              os.path.abspath(".panopticon/b.json")})
