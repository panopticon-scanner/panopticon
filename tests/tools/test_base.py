import unittest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
import scripts.tools.base as base


class TestBase(unittest.TestCase):
    def test_normalize_severity_maps_common_values(self):
        self.assertEqual(base.normalize_severity("critical"), "CRITICAL")
        self.assertEqual(base.normalize_severity("high"), "HIGH")
        self.assertEqual(base.normalize_severity("moderate"), "MEDIUM")
        self.assertEqual(base.normalize_severity("low"), "LOW")
        self.assertEqual(base.normalize_severity("info"), "INFO")
        self.assertEqual(base.normalize_severity("unknown"), "INFO")

    def test_new_finding_id_increments(self):
        self.assertEqual(base.new_finding_id("PA", 1), "PA-001")
        self.assertEqual(base.new_finding_id("PA", 12), "PA-012")

    def test_omit_none_removes_none_values(self):
        self.assertEqual(base.omit_none({"a": 1, "b": None, "c": ""}), {"a": 1, "c": ""})

    def test_omit_none_returns_empty_dict_when_all_none(self):
        self.assertEqual(base.omit_none({"a": None, "b": None}), {})

    def test_omit_none_preserves_zero_and_false(self):
        self.assertEqual(base.omit_none({"a": 0, "b": False, "c": None}), {"a": 0, "b": False})


if __name__ == "__main__":
    unittest.main()
