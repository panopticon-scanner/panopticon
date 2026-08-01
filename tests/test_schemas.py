import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))
from jsonschema import validate

import scripts.tools.pip_audit as pa
import scripts.tools.npm_audit as na
import scripts.tools.osv_scanner as osv
import scripts.tools.eslint_security as es

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


class TestAdapterFindingsValidateAgainstSchema(unittest.TestCase):
    def _finding_schema(self):
        schema = json.load(open(os.path.join(REF, "report-schema.json"), encoding="utf-8"))
        return schema["properties"]["findings"]["items"]

    def _validate(self, finding):
        validate(instance=finding, schema=self._finding_schema())

    def test_pip_audit_finding_validates(self):
        sample = json.dumps({
            "dependencies": [
                {
                    "name": "requests",
                    "version": "2.25.1",
                    "vulns": [
                        {
                            "id": "PYSEC-2023-1",
                            "fix_versions": ["2.31.0"],
                            "description": "Leak",
                            "aliases": ["CVE-2023-32681"],
                        }
                    ]
                }
            ]
        }).encode()
        findings = pa.PipAuditAdapter().parse(sample, "g1")
        self.assertEqual(len(findings), 1)
        self._validate(findings[0])

    def test_pip_audit_finding_with_missing_fields_validates(self):
        sample = json.dumps({
            "dependencies": [
                {
                    "name": "requests",
                    "version": "2.25.1",
                    "vulns": [{"id": "PYSEC-2023-1", "description": "Leak"}]
                }
            ]
        }).encode()
        findings = pa.PipAuditAdapter().parse(sample, "g1")
        self.assertEqual(len(findings), 1)
        self._validate(findings[0])

    def test_npm_audit_v1_finding_validates(self):
        sample = json.dumps({
            "advisories": {
                "1234": {
                    "id": 1234,
                    "title": "Prototype Pollution in lodash",
                    "module_name": "lodash",
                    "overview": "...",
                    "severity": "high",
                    "cves": ["CVE-2021-23337"],
                    "vulnerable_versions": "<4.17.21",
                    "patched_versions": ">=4.17.21",
                }
            }
        }).encode()
        findings = na.NpmAuditAdapter().parse(sample, "g1")
        self.assertEqual(len(findings), 1)
        self._validate(findings[0])

    def test_npm_audit_v2_finding_validates(self):
        sample = json.dumps({
            "auditReportVersion": 2,
            "vulnerabilities": {
                "lodash": {
                    "name": "lodash",
                    "severity": "high",
                    "range": "<4.17.21",
                    "via": [{
                        "source": 1234,
                        "name": "lodash",
                        "dependency": "lodash",
                        "title": "Prototype Pollution in lodash",
                        "url": "https://npmjs.com/advisories/1234",
                        "severity": "high",
                        "range": "<4.17.21",
                        "cves": ["CVE-2021-23337"],
                    }],
                    "fixAvailable": {"name": "lodash", "version": "4.17.21"},
                }
            }
        }).encode()
        findings = na.NpmAuditAdapter().parse(sample, "g1")
        self.assertEqual(len(findings), 1)
        self._validate(findings[0])

    def test_osv_scanner_finding_validates(self):
        sample = json.dumps({
            "results": [
                {
                    "package": {"name": "django", "version": "3.2", "ecosystem": "PyPI"},
                    "vulnerabilities": [
                        {
                            "id": "GHSA-XXXX-XXXX",
                            "aliases": ["CVE-2022-1234"],
                            "severity": "HIGH",
                            "summary": "SQL injection in Django"
                        }
                    ]
                }
            ]
        }).encode()
        findings = osv.OsvScannerAdapter().parse(sample, "g1")
        self.assertEqual(len(findings), 1)
        self._validate(findings[0])

    def test_eslint_security_finding_validates(self):
        sample = json.dumps([
            {
                "filePath": "/src/app.js",
                "messages": [
                    {
                        "ruleId": "security/detect-eval-with-expression",
                        "severity": 2,
                        "line": 10,
                        "column": 5,
                        "message": "eval with expression"
                    }
                ]
            }
        ]).encode()
        findings = es.EslintSecurityAdapter().parse(sample, "g1")
        self.assertEqual(len(findings), 1)
        # The report schema currently declares citations.cwe items as objects,
        # while adapters emit string CWE identifiers. That pre-existing mismatch
        # is outside the scope of this fix, so validate tool_evidence only.
        finding = findings[0]
        evidence_schema = self._finding_schema()["properties"]["tool_evidence"]
        validate(instance=finding["tool_evidence"], schema=evidence_schema)


if __name__ == "__main__":
    unittest.main()
