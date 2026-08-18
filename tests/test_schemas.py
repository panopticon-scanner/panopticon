import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "skill"))
from jsonschema import validate

import scripts.tools.pip_audit as pa
import scripts.tools.npm_audit as na
import scripts.tools.osv_scanner as osv
import scripts.tools.eslint_security as es

REF = os.path.join(os.path.dirname(__file__), os.pardir, "skill", "reference")


class TestSchemas(unittest.TestCase):
    def _load(self, name):
        with open(os.path.join(REF, name), encoding="utf-8") as fh:
            return json.load(fh)

    def test_report_schema_shape(self):
        schema = self._load("report-schema.json")
        self.assertEqual(schema["title"], "CodeReviewReport")
        gate = schema["properties"]["summary"]["properties"]["gate"]
        self.assertEqual(set(gate["enum"]), {"PASS", "FAIL", "OFF", "INCONCLUSIVE"})

    def test_scope_profile_required_fields(self):
        schema = self._load("scope-profile-schema.json")
        for field in ("group", "languages", "surfaces", "risk", "lenses", "domains"):
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

    def test_scope_profile_domains_enum_is_the_ten(self):
        schema = self._load("scope-profile-schema.json")
        domains = set(schema["properties"]["domains"]["items"]["enum"])
        self.assertEqual(domains,
                         {"SEC","COD","ARC","TST","QAL","AGT","DAT","OPS","ACC","LNG"})

    def test_findings_envelope_schema(self):
        schema = self._load("findings-envelope-schema.json")
        self.assertEqual(schema["title"], "PanopticonFindingsEnvelope")
        self.assertEqual(schema["required"], ["findings"])
        self.assertFalse(schema["additionalProperties"])

    def test_report_schema_source_role_includes_matrix_roles(self):
        # #5.0-05: the 5.0 matrix reviewers emit source_role domain_panel /
        # domain_advisor; the shipped report schema must accept them.
        schema = self._load("report-schema.json")
        src = schema["properties"]["findings"]["items"]["properties"]["source_role"]
        self.assertLessEqual({"domain_panel", "domain_advisor"}, set(src["enum"]))

    def test_findings_envelope_accepts_matrix_finding_and_panopticon(self):
        # #5.0-05: a conformant matrix cell (domain_panel source_role + the
        # REQUIRED _panopticon block) must validate against the shipped envelope.
        schema = self._load("findings-envelope-schema.json")
        finding = {
            "id": "SEC-001", "severity": "HIGH", "panel": "security",
            "category": "injection",
            "location": {"file": "src/app.py", "line_start": 10},
            "title": "t", "description": "d", "impact": "i", "remediation": "r",
            "references": [], "source_role": "domain_panel", "depth": "standard",
            "provenance": {}, "citations": {},
        }
        envelope = {"findings": [finding],
                    "_panopticon": {"run_id": "R", "domain": "SEC", "group": "g"}}
        validate(instance=envelope, schema=schema)  # must not raise


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
        with open(os.path.join(REF, "report-schema.json"), encoding="utf-8") as fh:
            schema = json.load(fh)
        return schema["properties"]["findings"]["items"]

    def _add_evidence_if_missing(self, finding):
        if "evidence" not in finding:
            finding["evidence"] = {
                "status": "tool_confirmed",
                "verified_by": None,
                "reasoning": None,
                "citation_quality": "none"
            }
        return finding

    def _validate(self, finding):
        finding = self._add_evidence_if_missing(finding)
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
                    "source": {"path": "/src/package-lock.json", "type": "lockfile"},
                    "packages": [
                        {
                            "package": {"name": "django-pkg", "version": "4.17.20", "ecosystem": "npm"},
                            "vulnerabilities": [
                                {
                                    "id": "GHSA-35jh-r3h4-6jhm",
                                    "aliases": ["CVE-2021-23337"],
                                    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                                    "summary": "Command Injection in django-pkg",
                                }
                            ],
                            "groups": [
                                {"ids": ["GHSA-35jh-r3h4-6jhm"], "aliases": ["CVE-2021-23337"], "max_severity": "7.2"}
                            ],
                        }
                    ],
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
        self._validate(findings[0])

    def test_string_cwe_validates(self):
        finding = self._valid_finding()
        finding["citations"] = {"cwe": ["CWE-89"]}
        self._validate(finding)

    def test_object_cwe_validates(self):
        finding = self._valid_finding()
        finding["citations"] = {"cwe": [{"id": "CWE-89", "name": "SQL Injection"}]}
        self._validate(finding)

    def _valid_finding(self):
        return {
            "id": "XX-001",
            "title": "x",
            "severity": "HIGH",
            "confidence": "CERTAIN",
            "panel": "security",
            "category": "x",
            "source_role": "lens_sweep",
            "depth": "standard",
            "location": {"file": "app.py", "line_start": 1},
            "evidence": {
                "status": "unverified",
                "verified_by": None,
                "reasoning": None,
                "citation_quality": "none"
            },
        }


def test_multi_model_fields_in_schemas():
    with open(os.path.join(REF, "scope-profile-schema.json"), encoding="utf-8") as fh:
        scope = json.load(fh)
    assert "depth" in scope["properties"]
    assert "files" in scope["properties"]
    lens_items = scope["properties"]["lenses"]["additionalProperties"]["items"]
    assert "priority" in lens_items["properties"]
    assert "depth_threshold" in lens_items["properties"]

    with open(os.path.join(REF, "report-schema.json"), encoding="utf-8") as fh:
        report = json.load(fh)
    finding_props = report["properties"]["findings"]["items"]["properties"]
    assert "source_role" in finding_props
    assert "evidence" in finding_props
    assert "depth" in finding_props


if __name__ == "__main__":
    unittest.main()
