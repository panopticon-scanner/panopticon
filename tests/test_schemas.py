import json
import os
import tempfile
import unittest

try:
    from jsonschema import validate, ValidationError
except ImportError:
    validate = None
    ValidationError = Exception

import scripts.tools.pip_audit as pa
import scripts.tools.npm_audit as na
import scripts.tools.osv_scanner as osv
import scripts.tools.eslint_security as es

if validate is None:
    raise unittest.SkipTest("jsonschema not installed")

REF = os.path.join(os.path.dirname(__file__), os.pardir, "skill", "reference")


def _load(name):
    with open(os.path.join(REF, name), encoding="utf-8") as fh:
        return json.load(fh)


class TestSchemas(unittest.TestCase):
    def test_report_schema_shape(self):
        schema = _load("report-schema.json")
        self.assertEqual(schema["title"], "CodeReviewReport")
        gate = schema["properties"]["summary"]["properties"]["gate"]
        self.assertEqual(set(gate["enum"]), {"PASS", "FAIL", "OFF", "INCONCLUSIVE"})

    def test_scope_profile_requires_only_what_the_pipeline_routes(self):
        # #run10 D3: the contract is what 5.x CONSUMES. `domains` is the only
        # field that changes what gets reviewed; `group` is its identity. The old
        # required set (languages/surfaces/risk/lenses) compelled every scout to
        # manufacture output no consumer read -- lenses/depth existed for
        # the retired 4.x planner's lens_sweep/panel_review entries, and
        # applicable_global_floor deliberately ignores scout surfaces (#1193).
        schema = _load("scope-profile-schema.json")
        self.assertEqual(sorted(schema["required"]), ["domains", "group"])
        for dropped in ("languages", "surfaces", "risk", "lenses", "depth",
                        "has_tests", "size", "facet_scope"):
            self.assertNotIn(dropped, schema["properties"], dropped)
            self.assertNotIn(dropped, schema["required"], dropped)

    def test_scope_profile_has_tools_field(self):
        schema = _load("scope-profile-schema.json")
        self.assertIn("tools", schema["properties"])
        self.assertIn("has_deps", schema["properties"])

    def test_report_schema_has_security_mode(self):
        schema = _load("report-schema.json")
        prop = schema["properties"]["meta"]["properties"]["security_mode"]
        self.assertEqual(set(prop["enum"]), {"standard", "redteam"})

    def test_report_schema_requires_security_mode(self):
        schema = _load("report-schema.json")
        self.assertIn("security_mode", schema["properties"]["meta"]["required"])

    def test_scope_profile_domains_enum_is_the_ten(self):
        schema = _load("scope-profile-schema.json")
        domains = set(schema["properties"]["domains"]["items"]["enum"])
        self.assertEqual(domains,
                         {"SEC","COD","ARC","TST","QAL","AGT","DAT","OPS","ACC","LNG"})

    def test_findings_envelope_schema(self):
        schema = _load("findings-envelope-schema.json")
        self.assertEqual(schema["title"], "PanopticonFindingsEnvelope")
        self.assertEqual(schema["required"], ["findings", "_panopticon"])
        self.assertFalse(schema["additionalProperties"])
        # oneOf is used to allow both legacy and domain-role findings
        items = schema["properties"]["findings"]["items"]
        self.assertIn("oneOf", items)
        refs = {ref["$ref"] for ref in items["oneOf"]}
        self.assertEqual(
            refs,
            {"#/definitions/legacyPanelFinding", "#/definitions/domainRoleFinding"},
        )

    def test_report_schema_source_role_includes_matrix_roles(self):
        # #5.0-05: the 5.0 matrix reviewers emit source_role domain_panel /
        # domain_advisor; the shipped report schema must accept them.
        schema = _load("report-schema.json")
        src = schema["properties"]["findings"]["items"]["properties"]["source_role"]
        self.assertLessEqual({"domain_panel", "domain_advisor"}, set(src["enum"]))

    def test_findings_envelope_accepts_legacy_panel_review(self):
        # Legacy panel_review / lens_sweep envelope still validates.
        schema = _load("findings-envelope-schema.json")
        finding = {
            "id": "SEC-001", "severity": "HIGH", "panel": "security",
            "category": "injection",
            "location": {"file": "src/app.py", "line_start": 10},
            "title": "t", "description": "d", "impact": "i", "remediation": "r",
            "references": [], "source_role": "panel_review", "depth": "standard",
            "provenance": {}, "citations": {},
        }
        envelope = {"findings": [finding],
                    "_panopticon": {"run_id": "R", "role": "panel_review"},
                    "schema_version": 1}
        validate(instance=envelope, schema=schema)  # must not raise

    def test_findings_envelope_accepts_domain_panel(self):
        # #5.0-05 / #1099: a conformant matrix cell (domain_panel source_role +
        # the REQUIRED _panopticon block) must validate against the shipped envelope.
        schema = _load("findings-envelope-schema.json")
        finding = {
            "domain": "SEC", "code": "SEC-INJ-001", "severity": "HIGH",
            "category": "injection",
            "location": {"file": "src/app.py", "line_start": 10, "line_end": 12},
            "title": "SQL injection", "description": "d",
            "source_role": "domain_panel",
            "citations": {},
        }
        envelope = {
            "findings": [finding],
            "_panopticon": {"run_id": "R", "role": "domain_panel",
                            "domain": "SEC", "group": "g1"},
            "schema_version": 1,
        }
        validate(instance=envelope, schema=schema)  # must not raise

    def test_findings_envelope_rejects_domain_panel_without_required(self):
        # #1099: domain_panel findings must carry domain/code/source_role.
        schema = _load("findings-envelope-schema.json")
        bad = {
            "findings": [{"severity": "HIGH", "title": "t",
                          "description": "d",
                          "location": {"file": "src/app.py", "line_start": 10}}],
            "_panopticon": {"run_id": "R", "role": "domain_panel",
                            "domain": "SEC", "group": "g1"},
            "schema_version": 1,
        }
        with self.assertRaises(ValidationError):
            validate(instance=bad, schema=schema)

    def test_findings_envelope_rejects_missing_panopticon_block(self):
        # #1099: the _panopticon block is REQUIRED by the envelope schema.
        schema = _load("findings-envelope-schema.json")
        bad = {
            "findings": [{"severity": "HIGH", "title": "t",
                          "description": "d",
                          "location": {"file": "src/app.py", "line_start": 10}}],
            "schema_version": 1,
        }
        with self.assertRaises(ValidationError):
            validate(instance=bad, schema=schema)

    def test_findings_envelope_accepts_domain_advisor(self):
        schema = _load("findings-envelope-schema.json")
        finding = {
            "domain": "SEC", "code": "SEC-ADV-001", "severity": "MEDIUM",
            "location": {"file": "src/app.py", "line_start": 10},
            "title": "t", "description": "d",
            "source_role": "domain_advisor",
        }
        envelope = {
            "findings": [finding],
            "_panopticon": {"run_id": "R", "role": "domain_advisor",
                            "domain": "SEC", "group": "g1"},
            "schema_version": 1,
        }
        validate(instance=envelope, schema=schema)  # must not raise

    def test_advisor_verdict_schema_accepts_schema_version(self):
        schema = _load("advisor-verdict-schema.json")
        verdict = {
            "finding_id": "SEC-001",
            "verdict": "CONFIRMED",
            "confidence": "CERTAIN",
            "reasoning": "Confirmed via trace",
            "explored": ["src/app.py"],
            "references": [],
            "citations": {},
            "schema_version": 1,
        }
        validate(instance=verdict, schema=schema)  # must not raise

    def test_report_schema_location_requires_positive_line_numbers(self):
        schema = _load("report-schema.json")
        loc_props = schema["properties"]["findings"]["items"]["properties"]["location"]["properties"]
        self.assertEqual(loc_props["line_start"].get("minimum"), 1)
        self.assertEqual(loc_props["line_end"].get("minimum"), 1)


class TestToolEvidenceSchema(unittest.TestCase):
    def test_tool_evidence_in_finding_schema(self):
        schema = _load("report-schema.json")
        props = schema["properties"]["findings"]["items"]["properties"]
        self.assertIn("tool_evidence", props)
        self.assertEqual(props["tool_evidence"]["type"], "object")

    def test_tool_evidence_optional(self):
        schema = _load("report-schema.json")
        required = schema["properties"]["findings"]["items"]["required"]
        self.assertNotIn("tool_evidence", required)

    def test_tool_evidence_expected_fields(self):
        schema = _load("report-schema.json")
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


class TestMultiModelFields(unittest.TestCase):
    def test_multi_model_fields_in_schemas(self):
        with open(os.path.join(REF, "scope-profile-schema.json"), encoding="utf-8") as fh:
            scope = json.load(fh)
        # #run10 D3: depth/lenses were removed from the ScopeProfile -- nothing in
        # 5.x read them (see test_scope_profile_requires_only_what_the_pipeline_
        # routes). `files` remains as review provenance.
        self.assertIn("files", scope["properties"])
        self.assertNotIn("depth", scope["properties"])
        self.assertNotIn("lenses", scope["properties"])

        with open(os.path.join(REF, "report-schema.json"), encoding="utf-8") as fh:
            report = json.load(fh)
        finding_props = report["properties"]["findings"]["items"]["properties"]
        self.assertIn("source_role", finding_props)
        self.assertIn("evidence", finding_props)
        self.assertIn("depth", finding_props)


class TestEslintSecurityAdapter(unittest.TestCase):
    def test_is_applicable_walks_tree_exactly_once_without_package_json(self):
        # QAL-D1A: applicable_files() and is_applicable() used to duplicate the
        # JS/TS tree walk. When no package.json fast-path applies, is_applicable()
        # must traverse the tree exactly once.
        from unittest import mock
        adapter = es.EslintSecurityAdapter()
        walk_calls = []

        def fake_walk(path):
            walk_calls.append(path)
            return []

        with tempfile.TemporaryDirectory() as d:
            with mock.patch("os.walk", fake_walk):
                self.assertFalse(adapter.is_applicable(d))
        self.assertEqual(len(walk_calls), 1)


if __name__ == "__main__":
    unittest.main()
