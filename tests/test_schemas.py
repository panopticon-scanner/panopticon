import json
import os
import unittest

REF = os.path.join(os.path.dirname(__file__), os.pardir, "reference")


class TestSchemas(unittest.TestCase):
    def _load(self, name):
        with open(os.path.join(REF, name), encoding="utf-8") as fh:
            return json.load(fh)

    def test_report_schema_shape(self):
        schema = self._load("report-schema.json")
        self.assertEqual(schema["title"], "CodeReviewReport")
        gate = schema["properties"]["summary"]["properties"]["gate"]
        self.assertEqual(set(gate["enum"]), {"PASS", "FAIL", "OFF"})

    def test_scope_profile_required_fields(self):
        schema = self._load("scope-profile-schema.json")
        for field in ("group", "languages", "surfaces", "risk", "suggested_lenses"):
            self.assertIn(field, schema["required"])

    def test_scope_profile_has_tools_field(self):
        schema = self._load("scope-profile-schema.json")
        self.assertIn("tools", schema["properties"])
        self.assertIn("has_deps", schema["properties"])
