import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "scripts"))
import synthesize as synth


class TestAdvisorTriggers(unittest.TestCase):
    def test_uncited_high_finding_is_flagged(self):
        f = {
            "id": "SEC-001",
            "title": "Bad thing",
            "severity": "HIGH",
            "confidence": "POSSIBLE",
            "panel": "security",
            "category": "injection",
            "location": {"file": "app.py", "line_start": 10},
            "references": [],
            "source_role": "panel_review",
        }
        flagged = synth.flag_for_advisor([f], depth="standard")
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0]["id"], "SEC-001")

    def test_cited_high_finding_not_flagged(self):
        f = {
            "id": "SEC-002",
            "title": "Bad thing",
            "severity": "HIGH",
            "confidence": "LIKELY",
            "panel": "security",
            "category": "injection",
            "location": {"file": "app.py", "line_start": 10},
            "references": ["https://cwe.mitre.org/data/definitions/89.html", "https://docs.sqlalchemy.org/"],
            "source_role": "panel_review",
        }
        flagged = synth.flag_for_advisor([f], depth="standard")
        self.assertEqual(len(flagged), 0)

    def test_low_severity_uncited_not_flagged(self):
        f = {
            "id": "COD-001",
            "title": "Style issue",
            "severity": "LOW",
            "confidence": "POSSIBLE",
            "panel": "code",
            "category": "style",
            "location": {"file": "app.py", "line_start": 10},
            "references": [],
            "source_role": "panel_review",
        }
        flagged = synth.flag_for_advisor([f], depth="standard")
        self.assertEqual(len(flagged), 0)
