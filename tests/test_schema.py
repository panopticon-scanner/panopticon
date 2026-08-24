import json
import os
import unittest


from scripts.synthesize import build_report
from scripts._version import __version__

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "..", "skill", "reference", "report-schema.json")

try:
    import jsonschema
except ImportError:  # pragma: no cover
    jsonschema = None


def test_jsonschema_is_installed():
    # #run7 TST-F1B: jsonschema is a declared test/dev dependency; assert it is
    # importable so the @skipIf(jsonschema is None) guards below can never
    # SILENTLY zero out schema-conformance coverage in a conformant run.
    import importlib.util
    assert importlib.util.find_spec("jsonschema") is not None, \
        "jsonschema (a declared test dependency) is not installed"


def _minimal_report():
    return {
        "meta": {
            "target": "test-target",
            "review_type": "repo",
            "timestamp": "2026-08-03T11:47:43Z",
            "version": "4.0.0",
            "security_mode": "standard",
            "models_used": [{"model": "test-model", "role": "lens_sweep"}],
            "coverage": {
                "adapters": {},
                "tools_ran": [],
                "build_executing_tools": [],
                "tool_policy_mode": "unknown",
                "tool_axis": {
                    "queued": 0,
                    "confirmed": 0,
                    "rejected": 0,
                    "needs_more_info": 0,
                    "unanswered": 0,
                    "rejection_rate": None,
                },
                "verdicts": {
                    "queued": 0,
                    "cut": 0,
                    "supplied": 0,
                    "matched": 0,
                    "unknown": 0,
                    "unanswered": None,
                },
                "fan_out": None,
            },
        },
        "summary": {
            "overall_grade": "A",
            "risk_level": "LOW",
            "top_issues": [],
            "gate": "OFF",
            "gate_policy": "confirmed_only",
            "evidence_stats": {
                "tool_reported": 0,
                "tool_confirmed": 0,
                "advisor_confirmed": 0,
                "corroborated": 0,
                "needs_more_info": 0,
                "unverified": 1,
                "rejected": 0,
            },
            "stats": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        },
        "groups": [],
        "findings": [
            {
                "id": "TS-001",
                "title": "Test finding",
                "severity": "INFO",
                "confidence": "NOTE",
                "panel": "security",
                "category": "test",
                "location": {"file": "app.py", "line_start": 1},
                "citation_quality": "none",
                "evidence": {
                    "status": "unverified",
                    "verified_by": None,
                    "reasoning": None,
                    "citation_quality": "none",
                },
                "provenance": {
                    "discovered_by": "agent:test",
                    "expanded_by": None,
                    "confirmed_by": None,
                    "model": "test-model",
                    "model_version": None,
                    "confirmation_status": "UNVERIFIED",
                    "confirmation_reasoning": None,
                },
            }
        ],
        "discarded_claims": [],
        "cross_panel": {"integration_findings": []},
    }


class TestReportSchema(unittest.TestCase):
    def test_schema_is_valid_json(self):
        with open(SCHEMA_PATH, encoding="utf-8") as fh:
            schema = json.load(fh)
        self.assertEqual(schema["title"], "CodeReviewReport")

    @unittest.skipIf(jsonschema is None, "jsonschema not installed")
    def test_minimal_report_validates_against_schema(self):
        with open(SCHEMA_PATH, encoding="utf-8") as fh:
            schema = json.load(fh)
        report = _minimal_report()
        jsonschema.validate(report, schema)
        self.assertIn("discarded_claims", report)
        self.assertIn("models_used", report["meta"])
        finding = report["findings"][0]
        self.assertIn("provenance", finding)
        self.assertIn("citation_quality", finding)
        self.assertEqual(finding["provenance"]["confirmation_status"], "UNVERIFIED")

    def test_report_schema_version_stamped_and_optional(self):
        # #run7 DAT-F2A: build_report stamps a report-ENVELOPE format version
        # (distinct from meta.version / meta.ocrdb_version) so cross-run readers
        # (reconcile.load_report, the html compare view, per-run-folder A/B) can
        # discriminate formats. It is OPTIONAL in the schema: a legacy pre-5.1
        # report (no stamp) must still validate, since the reconciler reads
        # historical reports across runs.
        import scripts.synthesize as syn
        with open(SCHEMA_PATH, encoding="utf-8") as fh:
            schema = json.load(fh)
        self.assertIsInstance(syn.REPORT_SCHEMA_VERSION, int)
        built = build_report([], [{"name": "g1", "files": ["a.py"]}],
                             "t", "high", "2026-01-01T00:00:00Z")
        self.assertEqual(built["schema_version"], syn.REPORT_SCHEMA_VERSION)
        jsonschema.validate(built, schema)                       # stamped -> valid
        legacy = _minimal_report()
        legacy.pop("schema_version", None)                       # pre-5.1 shape
        jsonschema.validate(legacy, schema)                      # absent -> still valid

    def test_minimal_report_has_required_top_level_keys(self):
        report = _minimal_report()
        for key in ("meta", "summary", "groups", "findings", "cross_panel"):
            self.assertIn(key, report)
        self.assertNotIn("recommendations", report)
        self.assertIn("models_used", report["meta"])
        self.assertNotIn("discarded_claims_count", report["summary"])
        self.assertNotIn("unverified_findings_count", report["summary"])

    def test_schema_requires_evidence_on_findings(self):
        with open(SCHEMA_PATH, encoding="utf-8") as fh:
            schema = json.load(fh)
        finding_props = schema["properties"]["findings"]["items"]
        self.assertIn("evidence", finding_props["properties"])
        self.assertIn("evidence", finding_props["required"])
        statuses = finding_props["properties"]["evidence"]["properties"]["status"]["enum"]
        self.assertEqual(set(statuses),
                         {"tool_reported", "tool_confirmed", "advisor_confirmed",
                          "corroborated", "needs_more_info", "unverified", "rejected"})

    @unittest.skipIf(jsonschema is None, "jsonschema not installed")
    def test_actual_build_report_output_validates_against_schema(self):
        """Test that actual build_report output validates against the schema."""
        with open(SCHEMA_PATH, encoding="utf-8") as fh:
            schema = json.load(fh)

        # Build a minimal report using build_report
        findings = [
            {
                "id": "TS-001",
                "title": "Test finding",
                "severity": "INFO",
                "confidence": "NOTE",
                "panel": "security",
                "category": "test",
                "location": {"file": "app.py", "line_start": 1},
                "citation_quality": "none",
                "evidence": {
                    "status": "unverified",
                    "verified_by": None,
                    "reasoning": None,
                    "citation_quality": "none",
                },
                "provenance": {
                    "discovered_by": "agent:test",
                    "expanded_by": None,
                    "confirmed_by": None,
                    "model": "test-model",
                    "model_version": None,
                    "confirmation_status": "UNVERIFIED",
                    "confirmation_reasoning": None,
                },
            }
        ]

        groups_meta = []
        target = "test-target"

        # Call build_report with minimal inputs
        report = build_report(
            findings=findings,
            groups_meta=groups_meta,
            target=target,
            fail_on="critical",
            timestamp="2026-08-03T11:47:43Z",
            review_type="repo",
            security_mode="standard"
        )

        # Validate against schema
        jsonschema.validate(report, schema)

        # Verify key structure
        self.assertIn("version", report["meta"])
        self.assertEqual(report["meta"]["version"], __version__)
        self.assertIn("evidence", report["findings"][0])
        self.assertNotIn("recommendations", report)

    @unittest.skipIf(jsonschema is None, "jsonschema not installed")
    def test_inconclusive_report_validates_against_schema(self):
        with open(SCHEMA_PATH, encoding="utf-8") as fh:
            schema = json.load(fh)
        report = build_report(
            [], [{"name": "g1", "files": ["a.py"]}], "t", "high",
            "2026-08-09T00:00:00Z",
            fan_out={"planned": {"security": 1}, "executed": {},
                     "groups_complete": [], "groups_partial": ["g1"]})
        self.assertEqual(report["summary"]["gate"], "INCONCLUSIVE")
        self.assertIsNone(report["summary"]["overall_grade"])
        jsonschema.validate(report, schema)

    def test_schema_declares_tool_policy_mode(self):
        with open(SCHEMA_PATH, encoding="utf-8") as fh:
            schema = json.load(fh)
        coverage_props = schema["properties"]["meta"]["properties"]["coverage"]["properties"]
        self.assertEqual(coverage_props["tool_policy_mode"]["enum"],
                         ["enforced", "advisory", "mixed", "unknown"])

    def test_schema_declares_fan_out(self):
        with open(SCHEMA_PATH, encoding="utf-8") as fh:
            schema = json.load(fh)
        cov = schema["properties"]["meta"]["properties"]["coverage"]["properties"]
        self.assertIn("fan_out", cov)


if __name__ == "__main__":
    unittest.main()
