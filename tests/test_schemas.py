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
        for field in ("group", "languages", "surfaces", "risk", "lenses", "panels"):
            self.assertIn(field, schema["required"])
        self.assertNotIn("suggested_lenses", schema["required"])

    def test_scope_profile_has_tools_field(self):
        schema = self._load("scope-profile-schema.json")
        self.assertIn("tools", schema["properties"])
        self.assertIn("has_deps", schema["properties"])

    def test_report_schema_has_security_mode(self):
        schema = self._load("report-schema.json")
        prop = schema["properties"]["meta"]["properties"]["security_mode"]
        self.assertEqual(set(prop["enum"]), {"standard", "redteam"})

    def test_report_schema_requires_security_mode(self):
        schema = self._load("report-schema.json")
        self.assertIn("security_mode", schema["properties"]["meta"]["required"])

    def test_scope_profile_panels_include_new_panels(self):
        schema = self._load("scope-profile-schema.json")
        panels = schema["properties"]["panels"]["items"]["enum"]
        for panel in ["architecture", "database", "redteam"]:
            self.assertIn(panel, panels)


class TestToolEvidenceSchema(unittest.TestCase):
    def _load(self, name):
        with open(os.path.join(REF, name), encoding="utf-8") as fh:
            return json.load(fh)

    def test_tool_evidence_in_finding_schema(self):
        schema = self._load("report-schema.json")
        props = schema["properties"]["findings"]["items"]["properties"]
        self.assertIn("tool_evidence", props)
        self.assertEqual(props["tool_evidence"]["type"], "object")

    def test_tool_evidence_optional(self):
        schema = self._load("report-schema.json")
        required = schema["properties"]["findings"]["items"]["required"]
        self.assertNotIn("tool_evidence", required)

    def test_tool_evidence_expected_fields(self):
        schema = self._load("report-schema.json")
        evidence_props = schema["properties"]["findings"]["items"]["properties"]["tool_evidence"]["properties"]
        expected = {
            "rule_id", "advisory_url", "package_name", "vulnerable_versions",
            "fixed_version", "cvss_score", "ecosystem"
        }
        self.assertTrue(expected.issubset(set(evidence_props.keys())))
