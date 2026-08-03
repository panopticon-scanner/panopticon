import json
import os
import unittest

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "..", "reference", "report-schema.json")

try:
    import jsonschema
except ImportError:  # pragma: no cover
    jsonschema = None


def _minimal_report():
    return {
        "meta": {
            "target": "test-target",
            "review_type": "repo",
            "timestamp": "2026-08-03T11:47:43Z",
            "version": "3.0.0",
            "security_mode": "standard",
            "models_used": [{"model": "test-model", "role": "lens_sweep"}],
        },
        "summary": {
            "overall_grade": "A",
            "risk_level": "LOW",
            "top_issues": [],
            "effort_to_remediate": "MEDIUM",
            "gate": "OFF",
            "stats": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "discarded_claims_count": 0,
            "unverified_findings_count": 0,
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
        "recommendations": {"immediate": [], "short_term": [], "long_term": []},
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

    def test_minimal_report_has_required_top_level_keys(self):
        report = _minimal_report()
        for key in ("meta", "summary", "groups", "findings", "discarded_claims",
                    "cross_panel", "recommendations"):
            self.assertIn(key, report)
        self.assertIn("models_used", report["meta"])
        self.assertIn("discarded_claims_count", report["summary"])
        self.assertIn("unverified_findings_count", report["summary"])


if __name__ == "__main__":
    unittest.main()
