import os
import tempfile
import unittest

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
                "evidence": {
                    "status": "advisor_confirmed",
                    "verified_by": "agent:advisor",
                    "reasoning": "verified",
                    "citation_quality": "partial",
                },
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
            "gate": "PASS",
            "gate_policy": "confirmed_only",
            "evidence_stats": {"unverified": 1},
            "stats": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
        },
        "groups": [
            {
                "name": "App",
                "files": ["app.py"],
                "panel_grades": {"code": "A", "test": "A", "security": "B"},
                "key_findings": ["SQL injection"],
            }
        ],
        "findings": findings,
        "cross_panel": {"integration_findings": []},
    }


class TestHtmlReport(unittest.TestCase):
    def test_escape_escapes_html(self):
        self.assertEqual(
            hr._escape("<script>alert('x')</script>"),
            "&lt;script&gt;alert(&#x27;x&#x27;)&lt;/script&gt;",
        )

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

    def test_render_card_tolerates_malformed_cvss_and_epss(self):
        # Agent-supplied cvss/epss with the wrong type must not crash the card
        # renderer (run-4 self-scan C12: type confusion). A string cvss is
        # skipped; a mixed epss list still uses its valid dict element.
        finding = {
            "id": "X-1",
            "title": "t",
            "severity": "HIGH",
            "confidence": "POSSIBLE",
            "panel": "security",
            "category": "general",
            "references": [],
            "location": {"file": "a.py", "line_start": 1},
            "description": "d",
            "cvss": "9.8",  # string, not a dict
            "citations": {"epss": ["not-a-dict", {"score": 0.4}]},
        }
        out = hr._render_card(finding)  # must not raise
        self.assertIn("X-1", out)
        self.assertNotIn("<dt>CVSS</dt>", out)
        self.assertIn("EPSS:0.40", out)

    def test_citation_quality_cannot_inject_markup(self):
        report = _minimal_report()
        payload = "none'><img src=x onerror=alert(1)><span class='"
        report["findings"][0]["evidence"]["citation_quality"] = payload
        out = hr.render(report)
        self.assertNotIn("<img src=x onerror=alert(1)>", out)
        self.assertIn("cit-quality cit-unknown", out)
        self.assertIn("&lt;img", out)

    def test_compare_stats_cannot_inject_markup(self):
        base = _minimal_report(findings=[])
        base["summary"]["stats"]["high"] = "<img src=x onerror=alert(1)>"
        out = hr.render(_minimal_report(findings=[]), compare_report=base)
        self.assertNotIn("<img src=x onerror=alert(1)>", out)
        self.assertIn("&lt;img", out)

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

    def test_heatmap_renders_group_grid(self):
        report = _minimal_report()
        out = hr.render(report)
        self.assertIn("Group heatmap", out)
        self.assertIn("App", out)  # the group name is the row label
        self.assertIn("heat-cell", out)  # a group x panel cell rendered
        self.assertIn("heat-total", out)

    def test_heatmap_grid_buckets_by_group_and_panel(self):
        report = _minimal_report()  # one HIGH security finding on app.py, group "App"
        panels, rows = hr._heatmap_grid(report)
        self.assertIn("security", panels)
        names = [n for n, _ in rows]
        self.assertIn("App", names)
        app = dict(rows)["App"]
        self.assertEqual(app["total"], 1)
        self.assertEqual(app["cells"]["security"]["count"], 1)
        self.assertEqual(app["cells"]["security"]["worst"], "HIGH")

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
        a = {
            "panel": "security",
            "category": "injection",
            "location": {"file": "app.py", "line_start": 10},
            "title": "SQLi",
            "description": "bad",
        }
        b = dict(a)
        b["location"] = {"file": "app.py", "line_start": 20}
        self.assertEqual(hr._fingerprint(a), hr._fingerprint(b))

    def test_fingerprint_normalizes_backslash_path(self):
        # #run7 QAL-D1C: the same file spelled with "\" in one report and "/" in
        # the other must fingerprint identically (was a dead os.sep no-op on
        # POSIX -> new+resolved instead of unchanged). evidence.norm_path folds
        # backslashes for every other pipeline key; the compare view now agrees.
        win = {"panel": "security", "category": "injection",
               "location": {"file": "src\\app\\pay.py", "line_start": 1},
               "title": "SQLi", "description": "bad"}
        nix = dict(win)
        nix["location"] = {"file": "src/app/pay.py", "line_start": 1}
        self.assertEqual(hr._fingerprint(win), hr._fingerprint(nix))

    def test_compare_shows_new_and_resolved(self):
        base = _minimal_report(
            findings=[
                {
                    "id": "SEC-001",
                    "title": "SQL injection",
                    "severity": "HIGH",
                    "confidence": "CERTAIN",
                    "panel": "security",
                    "category": "injection",
                    "location": {"file": "app.py", "line_start": 10},
                    "description": "x",
                    "impact": "",
                    "remediation": "",
                    "references": [],
                },
            ]
        )
        head = _minimal_report(
            findings=[
                {
                    "id": "SEC-002",
                    "title": "XSS",
                    "severity": "HIGH",
                    "confidence": "CERTAIN",
                    "panel": "security",
                    "category": "xss",
                    "location": {"file": "app.py", "line_start": 15},
                    "description": "y",
                    "impact": "",
                    "remediation": "",
                    "references": [],
                },
            ]
        )
        out = hr.render(head, compare_report=base)
        self.assertIn("class='delta-card delta-new'", out)
        self.assertIn("class='delta-card delta-resolved'", out)
        self.assertIn("data-delta='new'", out)
        self.assertIn("data-delta='resolved'", out)
        self.assertIn("XSS", out)
        self.assertIn("SQL injection", out)

    def test_compare_has_filter_buttons(self):
        base = _minimal_report(findings=[])
        head = _minimal_report(
            findings=[
                {
                    "id": "SEC-002",
                    "title": "XSS",
                    "severity": "HIGH",
                    "confidence": "CERTAIN",
                    "panel": "security",
                    "category": "xss",
                    "location": {"file": "app.py", "line_start": 15},
                    "description": "y",
                    "impact": "",
                    "remediation": "",
                    "references": [],
                },
            ]
        )
        out = hr.render(head, compare_report=base)
        self.assertIn("data-compare-filter", out)
        self.assertIn("Show all", out)
        self.assertIn("Only deltas", out)

    def test_compare_duplicate_fingerprints(self):
        finding = {
            "id": "SEC-001",
            "title": "SQL injection",
            "severity": "HIGH",
            "confidence": "CERTAIN",
            "panel": "security",
            "category": "injection",
            "location": {"file": "app.py", "line_start": 10},
            "description": "dup",
            "impact": "",
            "remediation": "",
            "references": [],
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
        base = _minimal_report(
            findings=[
                {
                    "id": "SEC-001",
                    "title": "SQL injection",
                    "severity": "HIGH",
                    "confidence": "CERTAIN",
                    "panel": "security",
                    "category": "injection",
                    "location": {"file": "app.py", "line_start": 10},
                    "description": "x",
                    "impact": "",
                    "remediation": "",
                    "references": [],
                },
            ]
        )
        head = _minimal_report(
            findings=[
                {
                    "id": "SEC-001",
                    "title": "SQL injection",
                    "severity": "MEDIUM",
                    "confidence": "CERTAIN",
                    "panel": "security",
                    "category": "injection",
                    "location": {"file": "app.py", "line_start": 10},
                    "description": "x",
                    "impact": "",
                    "remediation": "",
                    "references": [],
                },
            ]
        )
        out = hr.render(head, compare_report=base)
        self.assertIn("severity changed", out)
        self.assertIn("severity changed</div><div class='delta-value'>1</div>", out)

    def test_compare_unchanged(self):
        finding = {
            "id": "SEC-001",
            "title": "SQL injection",
            "severity": "HIGH",
            "confidence": "CERTAIN",
            "panel": "security",
            "category": "injection",
            "location": {"file": "app.py", "line_start": 10},
            "description": "x",
            "impact": "",
            "remediation": "",
            "references": [],
        }
        base = _minimal_report(findings=[finding])
        head = _minimal_report(findings=[dict(finding)])
        out = hr.render(head, compare_report=base)
        self.assertIn("unchanged", out)
        self.assertIn("unchanged</div><div class='delta-value'>1</div>", out)
        self.assertIn("severity changed</div><div class='delta-value'>0</div>", out)

    def _compare_finding(self, level, variant="base", issue="sqli"):
        """Build a finding of the requested complexity for compare scenarios."""
        base = {
            "id": f"SEC-{variant}-{level}-{issue}",
            "title": "SQL injection" if issue == "sqli" else "XSS",
            "severity": "HIGH",
            "confidence": "CERTAIN",
            "panel": "security",
            "category": "injection" if issue == "sqli" else "xss",
            "location": {"file": "app.py", "line_start": 10},
            "description": "User input used directly in query.",
            "impact": "",
            "remediation": "",
            "references": [],
        }
        if level in ("medium", "complex"):
            base.update(
                {
                    "impact": "Data exfiltration or unauthorized access.",
                    "remediation": "Use parameterized queries.",
                    "references": ["https://cwe.mitre.org/data/definitions/89.html"],
                }
            )
        if level == "complex":
            base.update(
                {
                    "description": (
                        "User input used directly in query. The tainted value flows from "
                        "the request handler into the database call without validation."
                    ),
                    "references": [
                        "https://cwe.mitre.org/data/definitions/89.html",
                        "https://owasp.org/Top10/A03_2021-Injection/",
                    ],
                    "citations": {
                        "cwe": [{"id": "CWE-89"}],
                        "owasp": ["A03:2021"],
                    },
                }
            )
        return base

    def _assert_delta_counts(self, out, new=0, resolved=0, unchanged=0, severity_changed=0):
        self.assertIn(f"new</div><div class='delta-value'>{new}</div>", out)
        self.assertIn(f"resolved</div><div class='delta-value'>{resolved}</div>", out)
        self.assertIn(f"unchanged</div><div class='delta-value'>{unchanged}</div>", out)
        self.assertIn(
            f"severity changed</div><div class='delta-value'>{severity_changed}</div>", out
        )

    def test_compare_scenario_matrix(self):
        """Exercise compare hashing across complexity levels and change scenarios.

        Scenarios:
        a) nothing changed -> unchanged
        b) something else in the file changed -> new + resolved
        c) vulnerable code changed but not fixed -> resolved + new (fingerprint changed)
        d) fix correctly applied -> resolved
        """
        for level in ("simple", "medium", "complex"):
            with self.subTest(level=level, scenario="unchanged"):
                f = self._compare_finding(level)
                base = _minimal_report(findings=[f])
                head = _minimal_report(findings=[dict(f)])
                out = hr.render(head, compare_report=base)
                self._assert_delta_counts(out, new=0, resolved=0, unchanged=1, severity_changed=0)
                self.assertIn("unchanged", out)

            with self.subTest(level=level, scenario="new_issue_elsewhere"):
                base = _minimal_report(findings=[self._compare_finding(level, issue="sqli")])
                head = _minimal_report(findings=[self._compare_finding(level, issue="xss")])
                out = hr.render(head, compare_report=base)
                self._assert_delta_counts(out, new=1, resolved=1, unchanged=0, severity_changed=0)
                self.assertIn("new", out)
                self.assertIn("resolved", out)

            with self.subTest(level=level, scenario="changed_not_fixed"):
                f_base = self._compare_finding(level)
                f_head = dict(f_base)
                # Modify the description so the SHA fingerprint changes, simulating a
                # code edit that leaves the vulnerability in place.
                f_head["description"] = f_base["description"] + " Still vulnerable after edit."
                base = _minimal_report(findings=[f_base])
                head = _minimal_report(findings=[f_head])
                out = hr.render(head, compare_report=base)
                self._assert_delta_counts(out, new=1, resolved=1, unchanged=0, severity_changed=0)
                self.assertIn("new", out)
                self.assertIn("resolved", out)

            with self.subTest(level=level, scenario="fixed"):
                base = _minimal_report(findings=[self._compare_finding(level)])
                head = _minimal_report(findings=[])
                out = hr.render(head, compare_report=base)
                self._assert_delta_counts(out, new=0, resolved=1, unchanged=0, severity_changed=0)
                self.assertIn("resolved", out)

    def test_finding_card_renders_provenance(self):
        finding = {
            "id": "SEC-001",
            "title": "SQL injection",
            "severity": "HIGH",
            "confidence": "CERTAIN",
            "panel": "security",
            "category": "injection",
            "location": {"file": "app.py", "line_start": 10},
            "description": "x",
            "impact": "",
            "remediation": "",
            "references": [],
            "provenance": {
                "discovered_by": "tool:brakeman",
                "confirmation_status": "TOOL",
                "model": None,
                "model_version": None,
            },
            "evidence": {
                "status": "advisor_confirmed",
                "verified_by": "tool:brakeman",
                "reasoning": "verified",
                "citation_quality": "partial",
            },
        }
        report = _minimal_report(findings=[finding])
        out = hr.render(report)
        self.assertIn("tool:brakeman", out)
        self.assertIn("partial", out)

    def test_unverified_findings_render_separately(self):
        finding = {
            "id": "SEC-002",
            "title": "Unverified",
            "severity": "INFO",
            "confidence": "NOTE",
            "panel": "security",
            "category": "general",
            "location": {"file": "app.py", "line_start": 11},
            "description": "x",
            "impact": "",
            "remediation": "",
            "references": [],
            "provenance": {
                "discovered_by": "agent:lens_sweep",
                "confirmation_status": "NEEDS_MORE_INFO",
                "model": "kimi-k2.7-coding",
                "model_version": "v1",
            },
            "evidence": {
                "status": "needs_more_info",
                "verified_by": "agent:lens_sweep",
                "reasoning": "need more info",
                "citation_quality": "none",
            },
        }
        report = _minimal_report(findings=[finding])
        out = hr.render(report)
        self.assertIn("Unverified findings", out)
        self.assertIn("agent:lens_sweep", out)

    def test_tool_reported_renders_as_unverified_not_in_main_findings(self):
        # P2/#446 regression: an unverified tool claim (e.g. the Bandit B105
        # false positive) must land in the collapsed "Unverified findings"
        # section, not the primary tabbed Findings section that reads as
        # reviewed/trustworthy.
        finding = {
            "id": "SEC-003",
            "title": "possible hardcoded password",
            "severity": "HIGH",
            "confidence": "CERTAIN",
            "panel": "security",
            "category": "secrets",
            "location": {"file": "app.py", "line_start": 12},
            "description": "x",
            "impact": "",
            "remediation": "",
            "references": [],
            "provenance": {
                "discovered_by": "tool:bandit",
                "confirmation_status": "TOOL",
                "model": None,
                "model_version": None,
            },
            "evidence": {
                "status": "tool_reported",
                "verified_by": "tool:bandit",
                "reasoning": "Reported by static-analysis tool",
                "citation_quality": "none",
            },
        }
        report = _minimal_report(findings=[finding])
        out = hr.render(report)
        self.assertIn("Unverified findings <span class='count'>(1)</span>", out)
        self.assertIn("ALL <span class='count'>0</span>", out)

    def test_provenance_needs_more_info_class_is_hyphenated(self):
        finding = {
            "id": "SEC-002",
            "title": "Unverified",
            "severity": "INFO",
            "confidence": "NOTE",
            "panel": "security",
            "category": "general",
            "location": {"file": "app.py", "line_start": 11},
            "description": "x",
            "impact": "",
            "remediation": "",
            "references": [],
            "provenance": {
                "discovered_by": "agent:lens_sweep",
                "confirmation_status": "NEEDS_MORE_INFO",
                "model": "kimi-k2.7-coding",
                "model_version": "v1",
            },
            "evidence": {
                "status": "needs_more_info",
                "verified_by": "agent:lens_sweep",
                "reasoning": "need more info",
                "citation_quality": "none",
            },
        }
        report = _minimal_report(findings=[finding])
        out = hr.render(report)
        self.assertIn("prov-needs-more-info", out)
        self.assertNotIn("prov-needs_more_info", out)

    def test_dynamic_badge_colors(self):
        report = _minimal_report()
        report["summary"]["gate"] = "FAIL"
        report["summary"]["risk_level"] = "CRITICAL"
        out = hr.render(report)
        self.assertIn("badge gate-fail", out)
        self.assertIn("badge sev-critical", out)
        self.assertNotIn("badge gate-pass", out)

    def test_header_shows_coverage_line(self):
        report = _minimal_report()
        report["summary"]["evidence_stats"] = {
            "advisor_confirmed": 2,
            "tool_confirmed": 1,
            "unverified": 5,
            "tool_reported": 3,
        }
        report["summary"]["gate_policy"] = "confirmed_only"
        report["meta"]["coverage"] = {"verdicts": {"queued": 3, "cut": 4}}
        html = hr.render(report)
        self.assertIn("Coverage:", html)
        self.assertIn("3 verified", html)  # advisor_confirmed + tool_confirmed
        self.assertIn("5 unverified", html)
        self.assertIn("4 cut", html)
        self.assertIn("gate: strict", html)  # confirmed_only -> "strict"

    def test_severity_class_sanitizes_input(self):
        self.assertEqual(hr._severity_class("HIGH"), "sev-high")
        self.assertEqual(hr._severity_class("HIGH extra"), "sev-highextra")
        self.assertEqual(hr._severity_class("CRITICAL<script>"), "sev-criticalscript")
        self.assertEqual(hr._severity_class(""), "sev-")


class TestChartAggregations(unittest.TestCase):
    def test_severity_counts_empty(self):
        self.assertEqual(
            hr._severity_counts([]), {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        )

    def test_severity_counts_groups(self):
        findings = [
            {"severity": "HIGH"},
            {"severity": "HIGH"},
            {"severity": "MEDIUM"},
            {"severity": "INFO"},
        ]
        self.assertEqual(
            hr._severity_counts(findings),
            {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 1, "LOW": 0, "INFO": 1},
        )

    def test_panel_counts_defaults_to_code(self):
        self.assertEqual(
            hr._panel_counts([]),
            {"code": 0, "test": 0, "security": 0, "architecture": 0, "database": 0, "redteam": 0},
        )

    def test_panel_counts_groups(self):
        findings = [
            {"panel": "security"},
            {"panel": "security"},
            {"panel": "test"},
        ]
        self.assertEqual(
            hr._panel_counts(findings),
            {"code": 0, "test": 1, "security": 2, "architecture": 0, "database": 0, "redteam": 0},
        )

    def test_top_category_counts_limit_and_other(self):
        findings = [
            {"category": "injection"},
            {"category": "injection"},
            {"category": "xss"},
            {"category": "xss"},
            {"category": "auth"},
            {"category": "config"},
        ]
        result = hr._top_category_counts(findings, limit=2)
        self.assertEqual(result, [("injection", 2), ("xss", 2), ("Other", 2)])

    def test_top_category_counts_no_other_when_within_limit(self):
        findings = [{"category": "a"}, {"category": "b"}]
        self.assertEqual(hr._top_category_counts(findings, limit=3), [("a", 1), ("b", 1)])


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
        self.assertIn("<span class='chart-value'>1</span>", out)

    def test_category_chart_shows_other_bucket(self):
        findings = [
            {"category": cat, "severity": "HIGH"}
            for cat in [
                "injection",
                "injection",
                "xss",
                "xss",
                "auth",
                "config",
                "crypto",
                "logging",
                "headers",
                "csrf",
                "ssrf",
            ]
        ]
        report = _minimal_report(findings=findings)
        out = hr.render(report)
        self.assertIn("Top finding categories", out)
        self.assertIn("injection", out)
        self.assertIn("xss", out)
        self.assertIn(">Other<", out)
        self.assertIn("<span class='chart-value'>1</span>", out)

    def test_charts_handle_empty_findings(self):
        report = _minimal_report(findings=[])
        out = hr.render(report)
        self.assertIn("Findings by severity", out)
        self.assertIn("Findings by panel", out)
        self.assertIn("Top finding categories", out)
        self.assertIn(">HIGH<", out)
        self.assertTrue("chart-bar sev-high" in out and "width: 0.0%" in out)

    def test_rejected_badge_has_distinct_style(self):
        finding = {
            "id": "SEC-003",
            "title": "Discarded",
            "severity": "INFO",
            "confidence": "NOTE",
            "panel": "security",
            "category": "general",
            "location": {"file": "app.py", "line_start": 12},
            "description": "x",
            "impact": "",
            "remediation": "",
            "references": [],
            "provenance": {
                "discovered_by": "agent:lens_sweep",
                "confirmation_status": "REJECTED",
                "model": "kimi-k2.7-coding",
                "model_version": "v1",
            },
        }
        report = _minimal_report(findings=[finding])
        report["discarded_claims"] = [finding]
        out = hr.render(report)
        self.assertIn("prov-rejected", out)


class TestEvidencePartition(unittest.TestCase):
    def test_unverified_section_keys_on_evidence(self):
        report = _minimal_report()
        report["findings"][0]["evidence"] = {
            "status": "needs_more_info",
            "verified_by": "agent:advisor",
            "reasoning": "need config",
            "citation_quality": "none",
        }
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.html")
            hr.write_html(report, path)
            with open(path, encoding="utf-8") as fh:
                html = fh.read()
        self.assertIn("Unverified findings", html)


class TestCoverageHonesty(unittest.TestCase):
    """#490: the HTML must not launder an uncertified/INCONCLUSIVE run."""

    def _report(self, **summary):
        base = {
            "overall_grade": "B",
            "risk_level": "MEDIUM",
            "gate": "PASS",
            "coverage_certified": True,
        }
        base.update(summary)
        return {
            "meta": {"target": "t", "coverage": {}},
            "summary": base,
            "findings": [],
            "groups": [],
        }

    def test_inconclusive_gate_gets_distinct_style(self):
        out = hr.render(self._report(gate="INCONCLUSIVE", coverage_certified=False))
        self.assertIn("gate-inconclusive", out)  # not the benign gate-off slate

    def test_uncertified_run_shows_banner_and_provisional_grade(self):
        out = hr.render(
            self._report(
                gate="INCONCLUSIVE",
                coverage_certified=False,
                coverage_note="tool layer incomplete: semgrep absent",
            )
        )
        self.assertIn("NOT CERTIFIED", out)
        self.assertIn("tool layer incomplete: semgrep absent", out)
        self.assertIn("(provisional)", out)

    def test_grade_none_never_renders_literal_none(self):
        out = hr.render(self._report(overall_grade=None, coverage_certified=False))
        self.assertNotIn("Grade: None", out)
        self.assertIn("Grade: -", out)

    def test_certified_pass_run_unchanged(self):
        out = hr.render(self._report())
        self.assertNotIn("NOT CERTIFIED", out)
        self.assertNotIn("(provisional)", out)
        self.assertIn("gate-pass", out)
