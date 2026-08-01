import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))
import scripts.html_report as hr


def _minimal_report(findings=None):
    if findings is None:
        findings = [
            {
                "id": "SEC-001",
                "title": "SQL injection",
                "severity": "HIGH",
                "confidence": "CERTAIN",
                "panel": "security",
                "category": "injection",
                "location": {"file": "app.py", "line_start": 10},
                "description": "User input used directly in query.",
                "impact": "Data exfiltration.",
                "remediation": "Use parameterized queries.",
                "references": [],
            }
        ]
    return {
        "meta": {
            "target": "tapestry",
            "review_type": "repo",
            "timestamp": "2026-08-01T12:00:00Z",
            "version": "3.0.0",
            "security_mode": "standard",
        },
        "summary": {
            "overall_grade": "A",
            "risk_level": "LOW",
            "top_issues": ["SQL injection"],
            "effort_to_remediate": "MEDIUM",
            "gate": "PASS",
            "stats": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
        },
        "groups": [
            {
                "name": "App",
                "files": ["app.py"],
                "panel_grades": {"code": "A", "test": "A", "security": "B"},
                "panel_summaries": {},
                "key_findings": ["SQL injection"],
            }
        ],
        "findings": findings,
        "cross_panel": {"integration_findings": []},
        "recommendations": {"immediate": [], "short_term": [], "long_term": []},
    }


class TestHtmlReport(unittest.TestCase):
    def test_escape_escapes_html(self):
        self.assertEqual(hr._escape("<script>alert('x')</script>"),
                         "&lt;script&gt;alert(&#x27;x&#x27;)&lt;/script&gt;")

    def test_html_doc_is_complete(self):
        doc = hr._html_doc("Test Report", "<p>hello</p>")
        self.assertTrue(doc.startswith("<!DOCTYPE html>"))
        self.assertIn("<title>Test Report</title>", doc)
        self.assertIn("<p>hello</p>", doc)
        self.assertIn(hr._CSS, doc)
        self.assertIn(hr._JS, doc)

    def test_dashboard_renders_summary(self):
        report = _minimal_report()
        out = hr.render(report)
        self.assertIn("Grade: A", out)
        self.assertIn("Risk: LOW", out)
        self.assertIn("Gate: PASS", out)
        self.assertIn("CRITICAL 0", out)
        self.assertIn("HIGH 1", out)

    def test_dashboard_renders_group_grades(self):
        report = _minimal_report()
        out = hr.render(report)
        self.assertIn("App", out)
        self.assertIn("code", out)
        self.assertIn("security", out)

    def test_dashboard_renders_top_issues(self):
        report = _minimal_report()
        out = hr.render(report)
        self.assertIn("Top issues", out)
        self.assertIn("SQL injection", out)

    def test_findings_section_has_tabs(self):
        report = _minimal_report()
        out = hr.render(report)
        self.assertIn('data-tab="ALL"', out)
        self.assertIn('data-tab="HIGH"', out)
        self.assertIn('data-tab="CRITICAL"', out)

    def test_finding_card_renders_details(self):
        report = _minimal_report()
        out = hr.render(report)
        self.assertIn("SEC-001", out)
        self.assertIn("SQL injection", out)
        self.assertIn("app.py:10", out)
        self.assertIn("User input used directly in query.", out)
        self.assertIn("Use parameterized queries.", out)

    def test_heatmap_renders_files(self):
        report = _minimal_report()
        out = hr.render(report)
        self.assertIn("File heatmap", out)
        self.assertIn("app.py", out)

    def test_fingerprint_ignores_line_number(self):
        a = {"panel": "security", "category": "injection", "location": {"file": "app.py", "line_start": 10},
             "title": "SQLi", "description": "bad"}
        b = dict(a)
        b["location"] = {"file": "app.py", "line_start": 20}
        self.assertEqual(hr._fingerprint(a), hr._fingerprint(b))

    def test_compare_shows_new_and_resolved(self):
        base = _minimal_report(findings=[
            {"id": "SEC-001", "title": "SQL injection", "severity": "HIGH", "confidence": "CERTAIN",
             "panel": "security", "category": "injection", "location": {"file": "app.py", "line_start": 10},
             "description": "x", "impact": "", "remediation": "", "references": []},
        ])
        head = _minimal_report(findings=[
            {"id": "SEC-002", "title": "XSS", "severity": "HIGH", "confidence": "CERTAIN",
             "panel": "security", "category": "xss", "location": {"file": "app.py", "line_start": 15},
             "description": "y", "impact": "", "remediation": "", "references": []},
        ])
        out = hr.render(head, compare_report=base)
        self.assertIn("new", out)
        self.assertIn("resolved", out)
        self.assertIn("XSS", out)
        self.assertIn("SQL injection", out)

    def test_compare_duplicate_fingerprints(self):
        finding = {
            "id": "SEC-001", "title": "SQL injection", "severity": "HIGH", "confidence": "CERTAIN",
            "panel": "security", "category": "injection", "location": {"file": "app.py", "line_start": 10},
            "description": "dup", "impact": "", "remediation": "", "references": [],
        }
        base = _minimal_report(findings=[finding, dict(finding)])
        head = _minimal_report(findings=[finding])
        out = hr.render(head, compare_report=base)
        self.assertIn("resolved", out)
        self.assertIn("unchanged", out)
        self.assertIn("SQL injection", out)
        # One paired (unchanged) and one unmatched base finding (resolved).
        self.assertIn("resolved</div><div class='delta-value'>1</div>", out)
        self.assertIn("new</div><div class='delta-value'>0</div>", out)
        self.assertIn("unchanged</div><div class='delta-value'>1</div>", out)

    def test_compare_severity_changed(self):
        base = _minimal_report(findings=[
            {"id": "SEC-001", "title": "SQL injection", "severity": "HIGH", "confidence": "CERTAIN",
             "panel": "security", "category": "injection", "location": {"file": "app.py", "line_start": 10},
             "description": "x", "impact": "", "remediation": "", "references": []},
        ])
        head = _minimal_report(findings=[
            {"id": "SEC-001", "title": "SQL injection", "severity": "MEDIUM", "confidence": "CERTAIN",
             "panel": "security", "category": "injection", "location": {"file": "app.py", "line_start": 10},
             "description": "x", "impact": "", "remediation": "", "references": []},
        ])
        out = hr.render(head, compare_report=base)
        self.assertIn("severity changed", out)
        self.assertIn("severity changed</div><div class='delta-value'>1</div>", out)

    def test_compare_unchanged(self):
        finding = {
            "id": "SEC-001", "title": "SQL injection", "severity": "HIGH", "confidence": "CERTAIN",
            "panel": "security", "category": "injection", "location": {"file": "app.py", "line_start": 10},
            "description": "x", "impact": "", "remediation": "", "references": [],
        }
        base = _minimal_report(findings=[finding])
        head = _minimal_report(findings=[dict(finding)])
        out = hr.render(head, compare_report=base)
        self.assertIn("unchanged", out)
        self.assertIn("unchanged</div><div class='delta-value'>1</div>", out)
        self.assertIn("severity changed</div><div class='delta-value'>0</div>", out)
