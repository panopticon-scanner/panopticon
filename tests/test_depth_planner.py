import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "scripts"))
import depth_planner as dp


class TestDepthPlanner(unittest.TestCase):
    def _profile(self, depth="standard"):
        return {
            "group": "g1",
            "panels": ["code", "security"],
            "depth": depth,
            "lenses": {
                "code": [
                    {"name": "structure", "spawn": True, "priority": 1, "depth_threshold": "shallow"},
                    {"name": "correctness", "spawn": True, "priority": 2, "depth_threshold": "standard"},
                    {"name": "style", "spawn": True, "priority": 3, "depth_threshold": "shallow"},
                ],
                "security": [
                    {"name": "known_vulns", "spawn": True, "priority": 1, "depth_threshold": "standard"},
                    {"name": "injection", "spawn": True, "priority": 2, "depth_threshold": "standard"},
                    {"name": "novel", "spawn": True, "priority": 3, "depth_threshold": "deep"},
                    {"name": "extra", "spawn": True, "priority": 4, "depth_threshold": "deep"},
                ]
            }
        }

    def test_shallow_spawns_zero_or_one(self):
        planned = dp.plan_lenses(self._profile("shallow"), "code")
        self.assertLessEqual(len(planned), 1)
        self.assertIn("structure", planned)

    def test_standard_spawns_up_to_two(self):
        planned = dp.plan_lenses(self._profile("standard"), "code")
        self.assertLessEqual(len(planned), 2)
        self.assertIn("structure", planned)
        self.assertIn("correctness", planned)

    def test_deep_spawns_up_to_three(self):
        planned = dp.plan_lenses(self._profile("deep"), "security")
        self.assertLessEqual(len(planned), 3)
        self.assertIn("known_vulns", planned)
        self.assertIn("injection", planned)
        self.assertIn("novel", planned)
        self.assertNotIn("extra", planned)

    def test_unspawnable_lenses_excluded(self):
        profile = self._profile("deep")
        profile["lenses"]["code"][0]["spawn"] = False
        self.assertEqual(dp.plan_lenses(profile, "code"), ["correctness", "style"])

    def test_panel_not_in_profile_returns_empty(self):
        self.assertEqual(dp.plan_lenses(self._profile("deep"), "architecture"), [])
