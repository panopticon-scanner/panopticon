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

    def test_title_escaped_once(self):
        report = _minimal_report()
        report["meta"]["target"] = "<script>"
        out = hr.render(report)
        self.assertIn("<title>Panopticon — &lt;script&gt;</title>", out)
        self.assertNotIn("&amp;lt;", out)

    def test_dashboard_renders_summary(self):
        report = _minimal_report()
        out = hr.render(report)
        self.assertIn("Grade: A", out)
        self.assertIn("Risk: LOW", out)
        self.assertIn("Gate: PASS", out)
        self.assertIn("<div class='stat-label'>CRITICAL</div>", out)
        self.assertIn("<div class='stat-value'>0</div>", out)
        self.assertIn("<div class='stat-label'>HIGH</div>", out)
        self.assertIn("<div class='stat-value'>1</div>", out)

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

    def test_findings_has_expand_all_button(self):
        report = _minimal_report()
        out = hr.render(report)
        self.assertIn("data-expand-all", out)
        self.assertIn("Expand all", out)

    def test_finding_card_renders_details(self):
        report = _minimal_report()
        out = hr.render(report)
        self.assertIn("SEC-001", out)
        self.assertIn("SQL injection", out)
        self.assertIn("app.py:10", out)
        self.assertIn("User input used directly in query.", out)
        self.assertIn("Use parameterized queries.", out)

    def test_finding_card_renders_citations(self):
        finding = {
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
            "citations": {
                "cwe": [{"id": "CWE-89"}],
                "owasp": ["A03:2021"],
                "ssvc": {"decision": "Act"},
                "cve": ["CVE-2023-1234"],
                "epss": [{"score": 0.1234}, {"score": 0.5678}],
            },
        }
        report = _minimal_report(findings=[finding])
        out = hr.render(report)
        self.assertIn("CWE-89", out)
        self.assertIn("A03:2021", out)
        self.assertIn("SSVC:Act", out)
        self.assertIn("CVE-2023-1234", out)
        self.assertIn("EPSS:0.57", out)

    def test_heatmap_renders_files(self):
        report = _minimal_report()
        out = hr.render(report)
        self.assertIn("File heatmap", out)
        self.assertIn("app.py", out)

    def test_heatmap_ordered_by_count_and_severity(self):
        findings = [
            {"id": "A", "title": "a", "severity": "LOW", "location": {"file": "z.py"}},
            {"id": "B", "title": "b", "severity": "HIGH", "location": {"file": "z.py"}},
            {"id": "C", "title": "c", "severity": "CRITICAL", "location": {"file": "a.py"}},
        ]
        data = hr._heatmap_data(findings)
        paths = [p for p, _ in data]
        self.assertEqual(paths, ["z.py", "a.py"])

    def test_heatmap_tie_breaker_by_worst_severity(self):
        findings = [
            {"id": "A", "title": "a", "severity": "HIGH", "location": {"file": "b.py"}},
            {"id": "B", "title": "b", "severity": "HIGH", "location": {"file": "b.py"}},
            {"id": "C", "title": "c", "severity": "CRITICAL", "location": {"file": "a.py"}},
            {"id": "D", "title": "d", "severity": "CRITICAL", "location": {"file": "a.py"}},
        ]
        data = hr._heatmap_data(findings)
        paths = [p for p, _ in data]
        self.assertEqual(paths, ["a.py", "b.py"])

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

    def test_compare_has_filter_buttons(self):
        base = _minimal_report(findings=[])
        head = _minimal_report(findings=[
            {"id": "SEC-002", "title": "XSS", "severity": "HIGH", "confidence": "CERTAIN",
             "panel": "security", "category": "xss", "location": {"file": "app.py", "line_start": 15},
             "description": "y", "impact": "", "remediation": "", "references": []},
        ])
        out = hr.render(head, compare_report=base)
        self.assertIn("data-compare-filter", out)
        self.assertIn("Show all", out)
        self.assertIn("Only deltas", out)

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

    def test_dynamic_badge_colors(self):
        report = _minimal_report()
        report["summary"]["gate"] = "FAIL"
        report["summary"]["risk_level"] = "CRITICAL"
        out = hr.render(report)
        self.assertIn("badge gate-fail", out)
        self.assertIn("badge sev-critical", out)
        self.assertNotIn("badge gate-pass", out)

    def test_severity_class_sanitizes_input(self):
        self.assertEqual(hr._severity_class("HIGH"), "sev-high")
        self.assertEqual(hr._severity_class("HIGH extra"), "sev-highextra")
        self.assertEqual(hr._severity_class("CRITICAL<script>"), "sev-criticalscript")
        self.assertEqual(hr._severity_class(""), "sev-")


class TestChartAggregations(unittest.TestCase):
    def test_severity_counts_empty(self):
        self.assertEqual(hr._severity_counts([]),
                         {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0})

    def test_severity_counts_groups(self):
        findings = [
            {"severity": "HIGH"}, {"severity": "HIGH"},
            {"severity": "MEDIUM"}, {"severity": "INFO"},
        ]
        self.assertEqual(hr._severity_counts(findings),
                         {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 1, "LOW": 0, "INFO": 1})

    def test_panel_counts_defaults_to_code(self):
        self.assertEqual(hr._panel_counts([]),
                         {"code": 0, "test": 0, "security": 0,
                          "architecture": 0, "database": 0, "redteam": 0})

    def test_panel_counts_groups(self):
        findings = [
            {"panel": "security"}, {"panel": "security"}, {"panel": "test"},
        ]
        self.assertEqual(hr._panel_counts(findings),
                         {"code": 0, "test": 1, "security": 2,
                          "architecture": 0, "database": 0, "redteam": 0})

    def test_top_category_counts_limit_and_other(self):
        findings = [
            {"category": "injection"}, {"category": "injection"},
            {"category": "xss"}, {"category": "xss"},
            {"category": "auth"}, {"category": "config"},
        ]
        result = hr._top_category_counts(findings, limit=2)
        self.assertEqual(result, [("injection", 2), ("xss", 2), ("Other", 2)])

    def test_top_category_counts_no_other_when_within_limit(self):
        findings = [{"category": "a"}, {"category": "b"}]
        self.assertEqual(hr._top_category_counts(findings, limit=3),
                         [("a", 1), ("b", 1)])


class TestDashboardCharts(unittest.TestCase):
    def test_dashboard_renders_severity_chart(self):
        report = _minimal_report()
        out = hr.render(report)
        self.assertIn("Findings by severity", out)
        self.assertIn("chart-bar sev-high", out)
        self.assertIn(">HIGH<", out)
        self.assertIn("chart-value", out)

    def test_dashboard_renders_panel_chart(self):
        report = _minimal_report()
        out = hr.render(report)
        self.assertIn("Findings by panel", out)
        self.assertIn("chart-bar panel-security", out)

    def test_dashboard_renders_category_chart(self):
        report = _minimal_report()
        out = hr.render(report)
        self.assertIn("Top finding categories", out)
        self.assertIn("injection", out)

    def test_charts_handle_empty_findings(self):
        report = _minimal_report(findings=[])
        out = hr.render(report)
        self.assertIn("Findings by severity", out)
        self.assertIn("Findings by panel", out)
        self.assertIn("Top finding categories", out)
        self.assertNotIn("chart-bar sev-high", out)
