import dataclasses
import html
import os
import tempfile
import unittest
from html.parser import HTMLParser
from unittest import mock

import scripts.host_disclosure as host_disclosure
import scripts.hosts as hosts
import scripts.html_report as hr


class _FragmentParser(HTMLParser):
    """Keep the generated fragment's element tree for semantic assertions."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = {"tag": "root", "attrs": {}, "children": [], "text": ""}
        self.stack = [self.root]

    def handle_starttag(self, tag, attrs):
        node = {"tag": tag, "attrs": dict(attrs), "children": [], "text": ""}
        self.stack[-1]["children"].append(node)
        if tag not in {"br", "hr", "img", "input", "meta", "link"}:
            self.stack.append(node)

    def handle_endtag(self, tag):
        if len(self.stack) > 1 and self.stack[-1]["tag"] == tag:
            self.stack.pop()

    def handle_data(self, data):
        self.stack[-1]["text"] += data


def _nodes(node, tag):
    return ([node] if node["tag"] == tag else []) + [
        match for child in node["children"] for match in _nodes(child, tag)
    ]


def _text(node):
    return node["text"] + "".join(_text(child) for child in node["children"])


def _parse(fragment):
    parser = _FragmentParser()
    parser.feed(fragment)
    return parser.root


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
    def test_gate_mode_is_explicit_in_normal_and_compared_reports(self):
        report = _minimal_report()
        report["meta"].update(security_mode="redteam", gate_security_mode="standard")
        for output in (hr._render_header(report), hr._render_compare_summary("Current", report)):
            self.assertIn("Gate: PASS (standard)", output)
        report["meta"]["gate_security_mode"] = "<script>"
        self.assertNotIn("(<script>)", hr._render_header(report))
        self.assertIn("(&lt;script&gt;)", hr._render_header(report))

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

    def test_dashboard_renders_group_panel_counts_in_the_heatmap(self):
        report = _minimal_report()
        report["groups"].append({"name": "Other <group>", "files": ["other.py"]})
        report["findings"].extend([
            {"id": "C1", "panel": "code", "severity": "LOW",
             "location": {"file": "other.py"}},
            {"id": "C2", "panel": "code", "severity": "LOW",
             "location": {"file": "other.py"}},
        ])
        out = hr.render(report)
        root = _parse(out)
        dashboards = [node for node in _nodes(root, "section")
                      if node["attrs"].get("class") == "dashboard"]
        self.assertEqual(len(dashboards), 1)
        tables = [node for node in _nodes(dashboards[0], "table")
                  if node["attrs"].get("class") == "heatmap-table"]
        self.assertEqual(len(tables), 1)
        rows = [[_text(cell).strip() for cell in row["children"]]
                for row in _nodes(tables[0], "tr")]
        self.assertEqual(rows, [["Group", "code", "security", "Total"],
                                ["Other <group>", "2", "—", "2"],
                                ["App", "—", "1", "1"]])
        self.assertIn("Other &lt;group&gt;", out)
        self.assertNotIn("<group>", out)

    def test_dashboard_renders_top_issues(self):
        report = _minimal_report()
        out = hr.render(report)
        self.assertIn("Top issues", out)
        self.assertIn("SQL injection", out)

    def test_findings_severity_buttons_control_one_visible_result_set(self):
        report = _minimal_report()
        root = _parse(hr._render_findings(report))
        groups = [n for n in _nodes(root, "div") if n["attrs"].get("role") == "group"]
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["attrs"].get("aria-label"), "Filter findings by severity")
        buttons = _nodes(groups[0], "button")
        self.assertEqual([b["attrs"].get("data-severity-filter") for b in buttons],
                         ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
        self.assertTrue(all(b["attrs"].get("type") == "button" for b in buttons))
        self.assertEqual([b["attrs"].get("aria-pressed") for b in buttons],
                         ["true", "false", "false", "false", "false", "false"])
        self.assertEqual([_text(b).strip() for b in buttons],
                         ["ALL 1", "CRITICAL 0", "HIGH 1", "MEDIUM 0", "LOW 0", "INFO 0"])
        result_sets = [n for n in _nodes(root, "div") if "data-severity-results" in n["attrs"]]
        self.assertEqual(len(result_sets), len(buttons))
        self.assertEqual([b["attrs"].get("aria-controls") for b in buttons],
                         [p["attrs"].get("id") for p in result_sets])
        self.assertEqual(len({p["attrs"].get("id") for p in result_sets}), len(buttons))
        self.assertEqual(["hidden" in p["attrs"] for p in result_sets],
                         [False, True, True, True, True, True])
        self.assertNotIn("role=\"tablist\"", hr._render_findings(report))
        self.assertNotIn("aria-selected", hr._render_findings(report))

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

    def test_render_skips_each_invalid_epss_score_and_keeps_valid_maximum(self):
        invalid_rows = [
            {"score": None},
            {"score": "0.9"},
            {"score": "<script>alert(1)</script>"},
            {"score": {"bad": 1}},
            {"score": [0.9]},
            {"score": True},
            {"score": False},
            {},
            {"score": -0.1},
            {"score": 1.1},
            {"score": float("nan")},
            {"score": float("inf")},
            {"score": float("-inf")},
            {"score": 10**1000},
        ]
        for invalid_row in invalid_rows:
            with self.subTest(invalid_row=invalid_row):
                report = _minimal_report()
                report["findings"][0]["citations"] = {
                    "cwe": [{"id": "CWE-89"}],
                    "epss": [{"score": 0.4}, invalid_row, {"score": 0.8}],
                }
                out = hr.render(report)
                self.assertIn("SEC-001", out)
                self.assertIn("SQL injection", out)
                self.assertIn("CWE-89", out)
                self.assertIn("EPSS:0.80", out)
                self.assertNotIn("EPSS:0.90", out)
                self.assertNotIn("<script>alert(1)</script>", out)

    def test_render_omits_epss_chip_when_all_scores_invalid(self):
        report = _minimal_report()
        report["findings"][0]["citations"] = {
            "cwe": [{"id": "<CWE-89>"}],
            "epss": [{"score": None}, {"score": "0.9"}, {}, {"score": True}],
        }
        out = hr.render(report)
        self.assertIn("</html>", out)
        self.assertIn("SEC-001", out)
        self.assertIn("SQL injection", out)
        self.assertIn("&lt;CWE-89&gt;", out)
        self.assertNotIn("<CWE-89>", out)
        self.assertNotIn("EPSS:", out)

    def test_render_epss_accepts_zero_and_one(self):
        for score, expected in ((0, "0.00"), (1, "1.00")):
            with self.subTest(score=score):
                report = _minimal_report()
                report["findings"][0]["citations"] = {
                    "epss": [{"score": score}],
                }
                out = hr.render(report)
                self.assertIn(f"EPSS:{expected}", out)

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
        root = _parse(hr.render(_minimal_report()))
        tables = [node for node in _nodes(root, "table")
                  if node["attrs"].get("class") == "heatmap-table"]
        self.assertEqual(len(tables), 1)
        self.assertEqual([[_text(cell).strip() for cell in row["children"]]
                          for row in _nodes(tables[0], "tr")],
                         [["Group", "security", "Total"], ["App", "1", "1"]])

    def test_heatmap_table_names_rows_columns_and_unknown_cells(self):
        report = _minimal_report()
        report["groups"] = [
            {"name": "Quiet <group>", "files": ["quiet.py"]},
            {"name": "App & API", "files": ["app.py"]},
        ]
        report["findings"].append({
            "id": "CODE-1", "title": "lint", "severity": "LOW", "panel": "code",
            "location": {"file": "app.py"},
        })
        root = _parse(hr._render_heatmap(report))
        tables = _nodes(root, "table")
        self.assertEqual(len(tables), 1)
        self.assertEqual(_text(_nodes(tables[0], "caption")[0]).strip(), "Group heatmap")
        headers = _nodes(tables[0], "th")
        self.assertEqual([_text(h).strip() for h in headers if h["attrs"].get("scope") == "col"],
                         ["Group", "code", "security", "Total"])
        self.assertEqual([_text(h).strip() for h in headers if h["attrs"].get("scope") == "row"],
                         ["App & API", "Quiet <group>"])
        rows = _nodes(_nodes(tables[0], "tbody")[0], "tr")
        self.assertEqual([[_text(cell).strip() for cell in row["children"]] for row in rows],
                         [["App & API", "1", "1", "2"], ["Quiet <group>", "—", "—", "0"]])
        self.assertIn("&lt;group&gt;", hr._render_heatmap(report))
        self.assertNotIn("<group>", hr._render_heatmap(report))

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

    def test_archived_generic_group_uses_common_directory_as_display_label(self):
        report = _minimal_report(findings=[
            {"id": "A", "severity": "LOW", "panel": "code",
             "location": {"file": "./src/api/handler.py"}},
        ])
        report["groups"] = [
            {"name": "._1", "files": ["src/api/handler.py", "src/api/routes.py"]},
            {"name": "123", "files": []},
            {"name": "Billing", "files": ["billing/main.py"]},
        ]
        self.assertEqual(hr._group_display_labels(report), {"._1": "src/api", "123": "123"})
        root = _parse(hr._render_heatmap(report))
        rows = _nodes(_nodes(root, "tbody")[0], "tr")
        self.assertEqual([[_text(cell).strip() for cell in row["children"]] for row in rows],
                         [["src/api", "1", "1"], ["123", "—", "0"],
                          ["Billing", "—", "0"]])

    def test_partial_group_inventory_leaves_unmapped_files_ungrouped(self):
        report = _minimal_report(findings=[
            {"id": "A", "panel": "code", "location": {"file": "./src/api/a.py"}},
            {"id": "B", "panel": "code", "location": {"file": "src/other/b.py"}},
        ])
        report["groups"] = [{"name": "API", "files": ["src/api/a.py"]}]
        panels, rows = hr._heatmap_grid(report)
        self.assertEqual(panels, ["code"])
        self.assertEqual([(name, row["total"]) for name, row in rows],
                         [("API", 1), ("Ungrouped", 1)])
        root = _parse(hr._render_heatmap(report))
        self.assertEqual([_text(n).strip() for n in _nodes(root, "th")
                          if n["attrs"].get("scope") == "row"], ["API", "Ungrouped"])

    def test_missing_group_inventory_uses_path_module_fallbacks(self):
        report = _minimal_report(findings=[
            {"id": "A", "panel": "code", "location": {"file": "./src/api/a.py"}},
            {"id": "B", "panel": "code", "location": {"file": "docs/readme.md"}},
            {"id": "C", "panel": "code", "location": {"file": "root.py"}},
        ])
        report.pop("groups")
        panels, rows = hr._heatmap_grid(report)
        self.assertEqual(panels, ["code"])
        self.assertEqual([(name, row["total"]) for name, row in rows],
                         [("(root)", 1), ("docs", 1), ("src/api", 1)])
        root = _parse(hr._render_heatmap(report))
        self.assertEqual([_text(n).strip() for n in _nodes(root, "th")
                          if n["attrs"].get("scope") == "row"],
                         ["(root)", "docs", "src/api"])

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

    # --- health in the header (#calibration) -----------------------------
    # The letter grade is a worst-severity rollup, so it saturates: all six
    # calibration targets graded D or F off the same ceiling while health ranged
    # 35.68-70.45. Health is the field that discriminated, so it belongs in the
    # header -- and it needs an explainer, because a bare number does not say
    # which direction is good or what the top of the scale is.

    def test_health_badge_in_header(self):
        report = _minimal_report()
        report["summary"]["health"] = {"score": 48.58, "total_loc": 68932,
                                       "weighted_defect": 72954}
        out = hr.render(report)
        self.assertIn("badge health", out)
        # "/ 100" is not decoration: the predecessor score was unbounded, so a
        # bare number gave a reader no way to tell good from bad.
        self.assertIn("Health: 48.58 / 100", out)
        # it sits with the other header badges, not somewhere further down
        badges = out.split("<div class='badges'>")[1].split("</div>")[0]
        self.assertIn("badge health", badges)

    def test_health_explainer_states_the_good_direction_and_the_ceiling(self):
        report = _minimal_report()
        report["summary"]["health"] = {"score": 48.58, "total_loc": 68932,
                                       "weighted_defect": 72954}
        out = hr.render(report)
        self.assertIn("health-pop", out)
        self.assertIn("Higher is better", out)      # the whole point of the popup
        self.assertIn("100 means no", out)          # ... and where the top is
        self.assertIn("never affects the gate", out)  # #1057: health never gates
        for weight in ("125", "25", "5", "1"):        # the severity weights
            self.assertIn("&times;%s" % weight, out)

    def test_health_explainer_is_keyboard_reachable(self):
        # A hover-only affordance is unusable by keyboard; the popover must also
        # open on focus, and the control must be a real focusable element.
        report = _minimal_report()
        report["summary"]["health"] = {"score": 50.0, "total_loc": 10,
                                       "weighted_defect": 10}
        out = hr.render(report)
        self.assertIn(":focus-within", out)
        self.assertIn("<button type='button' class='health-q'", out)
        self.assertIn("aria-label=", out)

    def test_a_perfect_score_still_renders(self):
        # A clean repo scores 100, which is truthy-adjacent but must not be
        # confused with the None case below -- it is the BEST outcome, and the
        # one the old formula silently dropped.
        report = _minimal_report()
        report["summary"]["health"] = {"score": 100.0, "total_loc": 4200,
                                       "weighted_defect": 0}
        out = hr.render(report)
        self.assertIn("Health: 100.0 / 100", out)

    def test_no_health_badge_when_score_is_absent(self):
        # A score of None now means nothing was reviewed at all (both inputs 0),
        # so render nothing rather than a misleading "0" or "-".
        for health in (None, {"score": None, "total_loc": 0, "weighted_defect": 0}):
            report = _minimal_report()
            report["summary"]["health"] = health
            out = hr.render(report)
            self.assertNotIn("badge health", out)
            # the CSS rule `.health-pop` is always in the stylesheet; assert the
            # ELEMENT is not emitted, not that the token never appears
            self.assertNotIn("<span class='health-pop'", out)
            self.assertNotIn("health-help'>", out)

    # --- the gate's reach, marked on the severity cards --------------------
    # A bare distribution does not say which levels can break a build; that
    # depends on --fail-on, which lives elsewhere in the report. These cards
    # carry it.

    def _report_with_roles(self, fail_on, in_play, contributing):
        report = _minimal_report()
        report["summary"]["stats"] = {"critical": 0, "high": 101, "medium": 296,
                                      "low": 315, "info": 105}
        report["summary"]["gate_severities"] = {
            "fail_on": fail_on, "in_play": in_play, "contributing": contributing}
        return hr.render(report)

    def test_contributing_level_is_shaded_darker_than_merely_in_play(self):
        out = self._report_with_roles("HIGH", ["CRITICAL", "HIGH"], ["HIGH"])
        self.assertIn("gate-fails", out)      # HIGH: carries the failure
        self.assertIn("gate-in-play", out)    # CRITICAL: in play, count 0
        # and the two classes must resolve to different backgrounds
        self.assertIn(".stat-card.gate-fails", out)
        self.assertIn(".stat-card.gate-in-play", out)

    def test_gate_marks_are_not_colour_only(self):
        # A red wash is invisible to a colourblind reader and to a printout, and
        # this is the field that says whether a build breaks.
        out = self._report_with_roles("HIGH", ["CRITICAL", "HIGH"], ["HIGH"])
        self.assertIn("fails gate", out)
        self.assertIn("in play, none found", out)

    def test_the_legend_names_the_threshold(self):
        out = self._report_with_roles("MEDIUM", ["CRITICAL", "HIGH", "MEDIUM"],
                                      ["HIGH", "MEDIUM"])
        self.assertIn("--fail-on MEDIUM", out)
        self.assertIn("gate-legend", out)

    def test_no_fail_on_leaves_every_card_unmarked(self):
        out = self._report_with_roles(None, [], [])
        self.assertNotIn("gate-fails'", out)       # the class is in the CSS ...
        self.assertNotIn("gate-in-play'", out)     # ... but on no card
        self.assertNotIn("<div class='gate-legend'", out)
        self.assertNotIn("fails gate", out)

    def test_a_level_with_findings_but_none_confirmed_is_in_play_not_failing(self):
        # 101 active HIGHs, none gate-eligible: alarming count, untouched gate.
        out = self._report_with_roles("HIGH", ["CRITICAL", "HIGH"], [])
        self.assertIn("in play, none confirmed", out)
        self.assertNotIn("fails gate", out)

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

    def test_an_unreadable_tools_manifest_is_named_in_the_html(self):
        # #1644: the gate is what the findings say (PASS here), so the banner
        # is the ONLY place a reader of the HTML meets the fact that tool
        # coverage could not be computed. It must carry the reason, not just
        # the word.
        out = hr.render(self._report(
            gate="PASS", coverage_certified=False,
            coverage_note=("tools manifest unreadable — tool coverage could not "
                           "be computed: tools-manifest.json is unreadable: x")))
        self.assertIn("NOT CERTIFIED", out)
        self.assertIn("tools manifest unreadable", out)
        self.assertIn("tools-manifest.json is unreadable", out)

    def test_grade_none_never_renders_literal_none(self):
        out = hr.render(self._report(overall_grade=None, coverage_certified=False))
        self.assertNotIn("Grade: None", out)
        self.assertIn("Grade: -", out)

    def test_certified_pass_run_unchanged(self):
        out = hr.render(self._report())
        self.assertNotIn("NOT CERTIFIED", out)
        self.assertNotIn("(provisional)", out)
        self.assertIn("gate-pass", out)


_NO_KEY = object()

_HOSTILE_TREE_CAPS = {
    hosts.TOOL_POLICY_ENFORCED: {
        "state": hosts.REFUTED, "by": "shadow-shell-scan",
        "detail": "the reviewed tree ships .claude/agents/panopticon-scout.md"},
    hosts.ARTIFACT_WRITE_GUARD: {
        "state": hosts.PROVEN, "by": "write-guard-armed",
        "detail": "round-trip denied"},
    hosts.USAGE_LEDGER: {
        "state": hosts.UNKNOWN, "by": None,
        "detail": "no transcript directory"},
    hosts.READ_SCOPE_CONFINED: {
        "state": hosts.UNKNOWN, "by": None,
        "detail": "claude proves this since plan 5; other hosts do not claim it"},
    hosts.MODEL_BINDING: {
        "state": hosts.UNKNOWN, "by": None,
        "detail": "model=None until F4 binds them"},
}


class TestHostCapabilityDisclosure(unittest.TestCase):
    """Spec 5.1 surface 3, in the artifact a person actually opens.

    `render_summary`'s "**Host capabilities:**" line is printed to the
    synthesize child's STDOUT; `driver run` runs that child with
    capture_output=True and reads `proc.stdout` only on the report-absent error
    path. So on the canonical driver path surface 3 lived entirely in a
    captured-and-discarded pipe, and report.json.html -- the thing an operator
    opens -- said nothing about the posture at all.

    Asserted against host_disclosure's own output, never against restated
    prose: this module must compose no sentence of its own. Read through
    html.unescape because `_escape` is doing its job on the quotes in
    `on host 'claude'`.
    """

    def _report(self, host_capabilities=_NO_KEY):
        meta = {"target": "t", "coverage": {}}
        if host_capabilities is not _NO_KEY:
            meta["host_capabilities"] = host_capabilities
        return {"meta": meta,
                "summary": {"overall_grade": "B", "risk_level": "MEDIUM",
                            "gate": "PASS", "coverage_certified": True},
                "findings": [], "groups": []}

    def _rendered(self, host_capabilities=_NO_KEY):
        return html.unescape(hr.render(self._report(host_capabilities)))

    def test_a_mixed_posture_renders_the_headline_and_every_gap(self):
        # MIXED on purpose (plan Global Constraints): one proven, one refuted,
        # three unknown, on five different capabilities. An all-proven or
        # all-unknown fixture passes a renderer that hard-codes one of them.
        envelope = {"host": "claude", "capabilities": _HOSTILE_TREE_CAPS}
        out = self._rendered(envelope)
        self.assertIn(host_disclosure.headline(envelope), out)
        gaps = host_disclosure.lines(envelope)
        self.assertEqual(4, len(gaps))          # the proven one earns no line
        for gap in gaps:
            with self.subTest(gap=gap):
                self.assertIn(gap, out)

    def test_every_gap_carries_its_remedy(self):
        envelope = {"host": "claude", "capabilities": _HOSTILE_TREE_CAPS}
        out = self._rendered(envelope)
        for capability in hosts.unproven(
                hosts.posture("claude", _HOSTILE_TREE_CAPS)):
            with self.subTest(capability=capability):
                # VERBATIM, and five distinct strings -- a block that rendered
                # one remedy for every capability fails here.
                self.assertIn(host_disclosure.remedy(capability, "claude"), out)

    def test_a_proven_capability_is_not_warned_about(self):
        out = self._rendered({"host": "claude", "capabilities": _HOSTILE_TREE_CAPS})
        self.assertNotIn(hosts.ARTIFACT_WRITE_GUARD, out)

    def test_an_all_proven_report_says_so_rather_than_rendering_nothing(self):
        # 5.1's inverse: the absence of a warning must mean "measured and
        # proven", which only holds if the proven case is stated. The
        # synthetic fixture pins the shape; claude proves this capability
        # since plan 5, other hosts do not claim it -- patch claude's claims
        # rather than assert something the registry cannot produce.
        claiming = dataclasses.replace(hosts.HOSTS["claude"],
                                       claims=frozenset(hosts.CAPABILITIES))
        caps = {c: {"state": hosts.PROVEN, "by": "fixture", "detail": "proven"}
                for c in hosts.CAPABILITIES}
        with mock.patch.dict(hosts.HOSTS, {"claude": claiming}):
            out = self._rendered({"host": "claude", "capabilities": caps})
        self.assertIn(host_disclosure.ALL_PROVEN, out)

    def test_a_report_with_no_posture_says_nobody_looked(self):
        out = self._rendered()
        self.assertIn(host_disclosure.NO_EVIDENCE, out)
        self.assertNotIn(host_disclosure.ALL_PROVEN, out)

    def test_a_malformed_posture_fails_closed_and_never_raises(self):
        # A foreign report.json fed to --compare, or a truncated artifact that
        # reached meta. Every one of these must read as "nobody looked".
        for bad in (None, "garbage", [1, 2], 5, {},
                    {"host": "claude", "capabilities": "not-a-mapping"},
                    {"host": 123, "capabilities": {}}):
            with self.subTest(bad=bad):
                out = self._rendered(bad)
                self.assertIn(host_disclosure.NO_EVIDENCE, out)
                self.assertNotIn(host_disclosure.ALL_PROVEN, out)

    def test_a_hostile_detail_is_escaped_rather_than_injected(self):
        # `detail` quotes the REVIEWED tree -- paths and filenames a hostile
        # target chooses. It reaches this page through host-capabilities.json,
        # a file on disk, so it is untrusted input to the renderer.
        caps = {hosts.TOOL_POLICY_ENFORCED: {
            "state": hosts.REFUTED, "by": "shadow-shell-scan",
            "detail": "<script>alert(1)</script>"}}
        raw = hr.render(self._report({"host": "claude", "capabilities": caps}))
        self.assertNotIn("<script>alert(1)</script>", raw)
        self.assertIn("&lt;script&gt;", raw)


class TestComparePostureIsPerReport(unittest.TestCase):
    """`--compare` renders TWO reports side by side, and their postures can
    differ -- which is exactly the cross-run diff `meta.host_capabilities` was
    specified to enable (spec 5.1: "so a consumer can diff posture across runs
    without re-deriving it"). A compare view that showed one posture, or none,
    would answer the question it exists to raise.

    The main report's own surface-3 block is `_render_header`'s, and `render()`
    branches away from `_render_header` entirely on the compare path -- so the
    posture reaches the compare view only if `_render_compare_summary` renders
    it itself. Each panel must carry ITS OWN report's posture, not the other's
    and not one of them twice.
    """

    @staticmethod
    def _report(host_capabilities=_NO_KEY):
        meta = {"target": "t", "coverage": {}}
        if host_capabilities is not _NO_KEY:
            meta["host_capabilities"] = host_capabilities
        return {"meta": meta,
                "summary": {"overall_grade": "B", "risk_level": "MEDIUM",
                            "gate": "PASS", "coverage_certified": True},
                "findings": [], "groups": []}

    @staticmethod
    def _envelope(**states):
        caps = {cap: {"state": state, "by": by, "detail": detail}
                for cap, (state, by, detail) in states.items()}
        return {"host": "claude", "capabilities": caps}

    def _rendered(self, base_caps, head_caps):
        return html.unescape(hr.render(self._report(head_caps),
                                       compare_report=self._report(base_caps)))

    def test_each_panel_carries_its_own_report_posture(self):
        # Deliberately DIFFERENT postures, mixed on both sides and differing on
        # a capability that appears in both. Two identical fixtures would pass
        # against a renderer that read one report twice -- the single most
        # likely way to get this wrong.
        base = self._envelope(**{
            hosts.TOOL_POLICY_ENFORCED: (hosts.REFUTED, "shadow-shell-scan",
                                         "base tree ships panopticon-scout.md"),
            hosts.ARTIFACT_WRITE_GUARD: (hosts.PROVEN, "write-guard-armed",
                                         "round-trip denied")})
        head = self._envelope(**{
            hosts.TOOL_POLICY_ENFORCED: (hosts.PROVEN, "shadow-shell-scan",
                                         "no shadowing shells found"),
            hosts.ARTIFACT_WRITE_GUARD: (hosts.REFUTED, "write-guard-armed",
                                         "head tree left the guard unarmed")})
        out = self._rendered(base, head)

        self.assertNotEqual(host_disclosure.headline(base),
                            host_disclosure.headline(head),
                            "fixture is not exercising a posture DIFFERENCE")
        for label, envelope in (("base", base), ("head", head)):
            with self.subTest(panel=label):
                self.assertIn(host_disclosure.headline(envelope), out)
                for gap in host_disclosure.lines(envelope):
                    self.assertIn(gap, out)

    def test_a_posture_absent_from_one_side_reads_as_nobody_looked(self):
        # The asymmetric case is the real one: comparing a run from this
        # version against an older report.json that predates the artifact. The
        # side with no posture must say NO EVIDENCE, not inherit the other's.
        head = self._envelope(**{
            hosts.TOOL_POLICY_ENFORCED: (hosts.REFUTED, "shadow-shell-scan",
                                         "ships panopticon-scout.md")})
        out = self._rendered(_NO_KEY, head)
        self.assertIn(host_disclosure.NO_EVIDENCE, out)
        self.assertIn(host_disclosure.headline(head), out)

    def test_a_hostile_detail_is_escaped_on_the_compare_path_too(self):
        # `detail` quotes the REVIEWED tree, and --compare is the documented
        # way a FOREIGN report.json reaches this renderer -- so the compare
        # path is the likelier hostile-input route of the two, not the safer.
        caps = {hosts.TOOL_POLICY_ENFORCED: {
            "state": hosts.REFUTED, "by": "shadow-shell-scan",
            "detail": "<script>alert(1)</script>"}}
        raw = hr.render(self._report({"host": "claude", "capabilities": caps}),
                        compare_report=self._report(
                            {"host": "claude", "capabilities": caps}))
        self.assertNotIn("<script>alert(1)</script>", raw)
        self.assertIn("&lt;script&gt;", raw)


class TestScannerContextLine(unittest.TestCase):
    """#1637 P08 ruling 5: the same fact the JSON carries, next to the tool
    coverage line, so a person meets it without opening the report."""

    def test_the_header_names_how_many_panels_saw_scanner_evidence(self):
        report = _minimal_report()
        report["meta"]["tools"] = {
            "panels_with_scanner_context": {"with": 3, "without": 82}}
        html_out = hr.render(report)
        self.assertIn("Scanner context:", html_out)
        self.assertIn("3 of 85 panels", html_out)

    def test_a_report_with_no_such_block_renders_no_line(self):
        self.assertNotIn("Scanner context:", hr.render(_minimal_report()))


class TestPartialDependencyAuditLine(unittest.TestCase):
    """#1646 ruling 3: pip-audit now audits a GENERATED requirements list, so
    the dependency audit can be partial. A person reading the report must meet
    that beside the tool coverage -- "pip-audit: produced" otherwise reads as
    "every declared dependency was checked"."""

    def _report(self, sanitized):
        report = _minimal_report()
        report["meta"]["tools"] = {"sanitized": sanitized}
        return report

    def test_the_header_names_the_tool_and_the_count(self):
        html_out = hr.render(self._report({"pip-audit": {
            "source": "requirements.txt", "kept": 2,
            "dropped": [{"line": "-e .", "reason": "editable"},
                        {"line": "./v/p", "reason": "local path"},
                        {"line": "git+https://x/y", "reason": "vcs url"}]}}))
        self.assertIn("Scanner context:", html_out)
        self.assertIn("pip-audit: 3 requirement lines not audited "
                      "(editable/local/VCS)", html_out)

    def test_the_count_is_the_true_total_not_the_listed_rows(self):
        # #1646 fix round 1 C2(c): `dropped` is capped at 200 rows and the
        # remainder counted. Printing len(dropped) would understate a partial
        # audit by exactly the amount the cap hid.
        html_out = hr.render(self._report({"pip-audit": {
            "source": "requirements.txt", "kept": 0,
            "dropped": [{"line": "-e .", "reason": "editable"}],
            "dropped_truncated": 299}}))
        self.assertIn("pip-audit: 300 requirement lines not audited", html_out)

    def test_a_malformed_remainder_does_not_inflate_the_count(self):
        html_out = hr.render(self._report({"pip-audit": {
            "dropped": [{"line": "-e .", "reason": "editable"}],
            "dropped_truncated": "lots"}}))
        self.assertIn("pip-audit: 1 requirement lines not audited", html_out)

    def test_a_fully_audited_run_says_nothing(self):
        html_out = hr.render(self._report({"pip-audit": {
            "source": "requirements.txt", "kept": 5, "dropped": []}}))
        self.assertNotIn("requirement lines not audited", html_out)

    def test_a_report_that_never_measured_this_says_nothing(self):
        self.assertNotIn("requirement lines not audited",
                         hr.render(_minimal_report()))

    def test_a_malformed_block_renders_no_line_rather_than_a_traceback(self):
        for bad in ("nope", {"pip-audit": "nope"}, {"pip-audit": {"dropped": 7}}):
            with self.subTest(value=repr(bad)):
                self.assertNotIn("requirement lines not audited",
                                 hr.render(self._report(bad)))


class TestAMidRunToolsDowngradeIsVisible(unittest.TestCase):
    """#1637 P08 F2: a person reading the report must meet the downgrade
    without opening JSON -- it changed what every panel after it was shown."""

    def test_the_header_says_the_scan_was_disabled_mid_run(self):
        report = _minimal_report()
        report["meta"]["tools"] = {
            "panels_with_scanner_context": {"with": 1, "without": 4},
            "disabled_mid_run": True}
        html_out = hr.render(report)
        self.assertIn("disabled mid-run", html_out)
        self.assertIn("1 of 5 panels", html_out)

    def test_an_ordinary_run_says_nothing_about_it(self):
        report = _minimal_report()
        report["meta"]["tools"] = {
            "panels_with_scanner_context": {"with": 1, "without": 4},
            "disabled_mid_run": False}
        self.assertNotIn("disabled mid-run", hr.render(report))


class TestSuppressedGitDriversLine(unittest.TestCase):
    """#2013: the target's own Git driver commands were EMPTIED for this scan.

    The scan proceeded where #2006 refused it, so the operator reading the
    report has to be told that the tree was read with the repository's own
    clean/diff drivers off -- a git-lfs target's pointer files were compared as
    pointer files, not as the content the filter would have produced. Beside
    the coverage line with the other "what this run did not see" facts.

    Keys only: a driver's value is a command line the target authored.
    """

    def _report(self, rows):
        report = _minimal_report()
        report["meta"].setdefault("coverage", {})["git_drivers_suppressed"] = rows
        return report

    def test_the_line_counts_and_names_the_keys(self):
        out = hr.render(self._report([{"repo": ".", "key": "filter.lfs.clean"},
                                      {"repo": "sub", "key": "diff.external"}]))
        self.assertIn("Target git drivers suppressed: 2", out)
        self.assertIn("filter.lfs.clean", out)
        self.assertIn("diff.external", out)
        # The line states the measured EFFECT, not only the fact (review I1).
        self.assertIn("compare as modified", out)

    def test_the_count_and_the_names_agree_when_one_key_is_in_two_repos(self):
        # Review M1: the count was rows and the names were deduped KEYS, so the
        # same key in root and submodule rendered as "2 (filter.lfs.clean)" --
        # a count a reader cannot reconcile with what they are shown, and no way
        # to tell which repository configured it.
        out = hr.render(self._report([{"repo": ".", "key": "filter.lfs.clean"},
                                      {"repo": "sub", "key": "filter.lfs.clean"}]))
        self.assertIn("Target git drivers suppressed: 2", out)
        self.assertIn("sub: filter.lfs.clean", out)

    def test_a_clean_target_renders_no_line(self):
        self.assertNotIn("git drivers suppressed",
                         hr.render(self._report([])))

    def test_a_report_that_measured_nothing_renders_no_line(self):
        # Absent (a pre-#2013 report, or one fed to --compare) is not the same
        # claim as "the target configured none".
        self.assertNotIn("git drivers suppressed",
                         hr.render(_minimal_report()))

    def test_a_hostile_key_is_escaped(self):
        # A git subsection is whatever the target wrote into its own config.
        out = hr.render(self._report(
            [{"repo": ".", "key": "filter.<script>alert(1)</script>.clean"}]))
        self.assertNotIn("<script>alert(1)</script>", out)
        self.assertIn("&lt;script&gt;", out)


class TestTestInventoryLine(unittest.TestCase):
    """#1638 P13: the groups whose test inventory was empty or split, printed
    next to coverage, so an operator meets the MATRIX defect before they meet
    the TST finding it induced. Run-13's report showed a confident-looking
    "no automated coverage" claim and no way to tell it apart from a real one.
    """

    def _report(self, inventory):
        report = _minimal_report()
        report["meta"].setdefault("coverage", {})["test_inventory"] = inventory
        return report

    def test_the_header_names_the_groups_whose_inventory_is_unusable(self):
        out = hr.render(self._report({"Code": "split", "Hosts": "empty",
                                      "Other": "complete"}))
        self.assertIn("Test inventory:", out)
        self.assertIn("Code", out)
        self.assertIn("Hosts", out)
        self.assertIn("split", out)
        self.assertIn("empty", out)

    def test_an_all_complete_matrix_renders_no_line(self):
        self.assertNotIn("Test inventory:",
                         hr.render(self._report({"Other": "complete"})))

    def test_a_report_that_measured_nothing_renders_no_line(self):
        # Absent (a pre-#1638 report, or one fed to --compare) is not the same
        # claim as "every group is fine", and must not be rendered as one.
        self.assertNotIn("Test inventory:", hr.render(_minimal_report()))

    def test_a_hostile_group_name_is_escaped(self):
        # Group names come from a committed groups.yml in the REVIEWED tree.
        out = hr.render(self._report({"<script>alert(1)</script>": "empty"}))
        self.assertNotIn("<script>alert(1)</script>", out)
        self.assertIn("&lt;script&gt;", out)


class TestBackupScopeLimited(unittest.TestCase):
    """#1638 P16 ruling 3: the report's advisor classification stays honest --
    the reader is told which files the backup could not see, rather than being
    shown a NEEDS_MORE_INFO that was really a scope failure."""

    def _finding(self, **over):
        f = {"id": "SEC-001", "title": "redaction runs last", "severity": "HIGH",
             "confidence": "CERTAIN", "panel": "security", "category": "general",
             "location": {"file": "synth/render.py", "line_start": 12},
             "description": "d", "references": [],
             "backup_confirmed": False,
             "evidence": {"status": "backup_scope_limited",
                          "verified_by": "agent:advisor",
                          "reasoning": "primary traced the call order",
                          "citation_quality": "full",
                          "missing_evidence": ["synth/grading.py",
                                               "synthesize.py"]}}
        f.update(over)
        return f

    def test_card_names_the_files_the_backup_could_not_see(self):
        out = hr._render_card(self._finding())
        self.assertIn("Backup could not see", out)
        self.assertIn("synth/grading.py", out)
        self.assertIn("synthesize.py", out)

    def test_no_line_when_nothing_was_missing(self):
        f = self._finding()
        f["evidence"] = {"status": "advisor_confirmed", "citation_quality": "full"}
        self.assertNotIn("Backup could not see", hr._render_card(f))

    def test_missing_evidence_cannot_inject_markup(self):
        f = self._finding()
        f["evidence"]["missing_evidence"] = [
            "a.py'><img src=x onerror=alert(1)><span class='"]
        out = hr._render_card(f)
        self.assertNotIn("<img src=x", out)
        self.assertIn("&lt;img", out)

    def test_a_scope_limited_finding_is_not_counted_as_verified(self):
        # Fix round 1, F2: it keeps gate-eligibility and factor 1.5 (the base's
        # primary-only treatment), but the coverage line does NOT call it
        # verified -- it gets its own segment, so the count is disclosed rather
        # than folded into a number that means "a second opinion agreed".
        report = _minimal_report([self._finding()])
        report["summary"]["evidence_stats"] = {"backup_scope_limited": 1,
                                               "advisor_confirmed": 0,
                                               "tool_confirmed": 0}
        out = hr.render(report)
        self.assertIn("0 verified", out)
        self.assertIn("1 backup-scope-limited", out)

    def test_the_coverage_line_omits_the_segment_when_there_are_none(self):
        report = _minimal_report([self._finding()])
        report["summary"]["evidence_stats"] = {"advisor_confirmed": 1,
                                               "tool_confirmed": 0}
        out = hr.render(report)
        self.assertIn("1 verified", out)
        self.assertNotIn("backup-scope-limited", out)


class TestEgressPostureLine(unittest.TestCase):
    """#1645 ruling 3: an operator meets the online adapters' egress beside the
    tool coverage, where they meet the rest of the tool axis."""

    def _report(self, network):
        report = _minimal_report()
        report["meta"]["tools"] = {"network": network}
        return report

    def test_an_online_adapter_names_what_it_could_reach(self):
        html_out = hr.render(self._report(
            {"semgrep": "none",
             "pip-audit": "proxied:files.pythonhosted.org,pypi.org"}))
        self.assertIn("Scanner context:", html_out)
        self.assertIn("pip-audit reached only files.pythonhosted.org, pypi.org",
                      html_out)

    def test_a_refused_adapter_says_it_did_not_run(self):
        html_out = hr.render(self._report(
            {"pip-audit": "excluded:online egress unavailable"}))
        self.assertIn("pip-audit did not run: online egress unavailable",
                      html_out)

    def test_an_all_offline_run_says_nothing(self):
        # Every scanner on `--network none` is the ordinary case; a line for it
        # would bury the two that are not.
        html_out = hr.render(self._report({"semgrep": "none", "trivy": "none"}))
        self.assertNotIn("reached only", html_out)

    def test_a_report_that_never_measured_this_says_nothing(self):
        self.assertNotIn("reached only", hr.render(_minimal_report()))

    def test_a_malformed_block_renders_no_line_rather_than_a_traceback(self):
        for bad in ("nope", 7, {"pip-audit": 7}, {"pip-audit": ["proxied:x"]}):
            with self.subTest(value=repr(bad)):
                self.assertNotIn("reached only", hr.render(self._report(bad)))

    def test_a_posture_string_cannot_inject_markup(self):
        html_out = hr.render(self._report(
            {"<script>alert(1)</script>": "proxied:<b>x</b>"}))
        self.assertNotIn("<script>alert(1)</script>", html_out)
        self.assertNotIn("proxied:<b>", html_out)


class TestSuppressedToolFindingsInHtml(unittest.TestCase):
    """#1578: the same disclosure in the HTML, beside the coverage line where
    the other "what this run did not see" facts live."""

    def _report(self, suppressed):
        report = _minimal_report()
        report["meta"].setdefault("coverage", {})["tools_suppressed"] = suppressed
        return report

    def test_the_segments_and_counts_are_rendered(self):
        out = hr.render(self._report({"vendor": 592}))
        self.assertIn("vendor", out)
        self.assertIn("592", out)
        self.assertIn("suppressed", out)

    def test_a_run_that_suppressed_nothing_renders_no_line(self):
        self.assertNotIn("suppressed by directory name", hr.render(self._report({})))

    def test_a_malformed_block_renders_no_line_rather_than_a_traceback(self):
        for bad in ("nope", 7, ["vendor"], {"vendor": "lots"}):
            with self.subTest(value=repr(bad)):
                self.assertNotIn("suppressed by directory name",
                                 hr.render(self._report(bad)))

    def test_a_segment_name_cannot_inject_markup(self):
        out = hr.render(self._report({"<script>alert(1)</script>": 1}))
        self.assertNotIn("<script>alert(1)</script>", out)


    def test_the_venv_tally_rows_say_what_they_rest_on(self):
        # #1839: two of these keys NAME A CLASS and count virtualenv DIRECTORIES
        # the scan never entered (review round 1 I4 added the name-only half);
        # the `pyvenv.cfg:<dir>` shape counts findings dropped on a marker the
        # target wrote. Neither is the directory-NAME drop this block is about.
        for key in (hr.MARKER_VENV_SEGMENT, hr.NAME_VENV_SEGMENT,
                    hr.MARKER_VENV_PREFIX + "app/venv"):
            with self.subTest(key=key):
                out = hr.render(self._report({"vendor": 2, key: 1}))
                self.assertIn("name a CLASS", out)
                self.assertIn("DIRECTORIES the scan was told to skip", out)
        self.assertNotIn("name a CLASS", hr.render(self._report({"vendor": 2})))

    def test_a_target_authored_tally_key_is_escaped_and_capped(self):
        # Review round 1 I3: the `<dir>` half of the key is a path out of the
        # reviewed tree, and `html.escape` leaves control characters alone -- so
        # the same `ascii()` idiom as the policy globs above, and a cap, because
        # there is one row per virtualenv.
        rows = {"pyvenv.cfg:v%02d" % i: 1 for i in range(15)}
        rows["pyvenv.cfg:hostile\x1b[2J\n<script>alert(1)</script>"] = 3
        out = hr.render(self._report(rows))
        block = out.split("Tool findings suppressed by directory name:", 1)[1]
        block = block.split("</div>", 1)[0]
        self.assertNotIn("\x1b", block)
        self.assertNotIn("\n", block)
        self.assertNotIn("<script>", block)
        self.assertIn(r"pyvenv.cfg:&#x27;hostile\x1b[2J\n", block)
        self.assertIn("and 6 more", block)


class TestGatedSuppressedToolFindingsInHtml(unittest.TestCase):
    def _report(self, gated):
        report = _minimal_report(findings=[])
        if gated is not None:
            report["meta"].setdefault("coverage", {})["tools_suppressed_gated"] = gated
        return report

    def test_nonzero_gated_count_explains_empty_findings_and_escapes_segment(self):
        out = hr.render(self._report({"<script>alert(1)</script>": 3}))
        marker = "Tool findings suppressed by directory name but GATED: "
        self.assertIn(marker, out)
        block = out.split(marker, 1)[1].split("</div>", 1)[0]
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;: 3", block)
        self.assertIn("A gate verdict here may rest on findings this report does not list", block)
        self.assertNotIn("<script>alert(1)</script>", block)

    def test_absent_zero_and_malformed_gated_blocks_make_no_claim(self):
        for gated in (None, {}, {"vendor": 0}, "bad", 7, {"vendor": "three"},
                      {"vendor": True}):
            with self.subTest(gated=gated):
                self.assertNotIn("but GATED", hr.render(self._report(gated)))


class TestExcludedToolFindingsInHtml(unittest.TestCase):
    def _report(self, excluded=_NO_KEY):
        report = _minimal_report()
        coverage = report["meta"].setdefault("coverage", {})
        coverage["tools_suppressed"] = {"vendor": 2}
        if excluded is not _NO_KEY:
            coverage["tools_excluded"] = excluded
        return report

    def test_header_names_count_and_every_glob_beside_suppression(self):
        out = hr.render(self._report(
            {"count": 3, "globs": ["vendor/**", "tests/fixtures/**"]}))
        self.assertIn("Tool findings excluded by policy: 3", out)
        self.assertIn("vendor/**", out)
        self.assertIn("tests/fixtures/**", out)
        self.assertIn("Tool findings suppressed by directory name: vendor: 2", out)

    def test_measured_zero_is_visible_with_and_without_globs(self):
        for globs in (["vendor/**"], []):
            with self.subTest(globs=globs):
                out = hr.render(self._report({"count": 0, "globs": globs}))
                self.assertIn("Tool findings excluded by policy: 0", out)
                self.assertEqual("vendor/**" in out, bool(globs))

    def test_legacy_missing_and_malformed_optional_block_are_safe(self):
        for excluded in (_NO_KEY, None, "bad", {"count": "many", "globs": []},
                         {"count": 1, "globs": "bad"}):
            with self.subTest(excluded=excluded):
                out = hr.render(self._report(excluded))
                self.assertNotIn("Tool findings excluded by policy", out)
                self.assertIn("Tool findings suppressed by directory name", out)

    def test_hostile_glob_is_escaped_and_stays_on_one_html_line(self):
        glob = '<script>" & `x`\n## Forged section'
        out = hr.render(self._report({"count": 1, "globs": [glob]}))
        disclosure = out.split("Tool findings excluded by policy: 1", 1)[1].split(
            "</div>", 1)[0]
        self.assertNotIn("<script>", disclosure)
        self.assertNotIn("\n## Forged section", disclosure)
        self.assertIn("&lt;script&gt;", disclosure)
        self.assertIn("&quot;", disclosure)
        self.assertIn("&amp;", disclosure)
        self.assertIn(r'\n## Forged section', disclosure)

    def test_compare_panels_disclose_their_own_distinct_policies(self):
        base = self._report({"count": 8, "globs": ["base/**"]})
        head = self._report({"count": 0, "globs": ["head/**"]})
        base_panel = hr._render_compare_summary("Base", base)
        head_panel = hr._render_compare_summary("Head", head)
        self.assertIn("Tool findings excluded by policy: 8", base_panel)
        self.assertIn("base/**", base_panel)
        self.assertNotIn("head/**", base_panel)
        self.assertIn("Tool findings excluded by policy: 0", head_panel)
        self.assertIn("head/**", head_panel)
        self.assertNotIn("base/**", head_panel)
        out = hr.render(head, compare_report=base)
        self.assertEqual(out.count("Tool findings excluded by policy:"), 2)


class TestMeasuredHeatmap(unittest.TestCase):
    def _rows(self, report):
        table = _parse(hr._render_heatmap(report))
        return {_text(_nodes(row, "th")[0]): _nodes(row, "td")
                for row in _nodes(_nodes(table, "tbody")[0], "tr")}

    def test_reviewed_empty_never_dispatched_and_tool_counts(self):
        report = _minimal_report()
        report["groups"].append({"name": "Quiet", "files": ["quiet.py"]})
        report["meta"]["coverage"] = {"cells": {
            "reviewed": [["Quiet", "SEC"]],
            "planned_pairs": [["Quiet", "SEC"], ["App", "COD"]]}}
        rows = self._rows(report)
        self.assertEqual([_text(c) for c in rows["Quiet"]], ["—", "0", "0"])
        self.assertEqual(rows["Quiet"][0]["attrs"]["title"], "Not reviewed")
        self.assertEqual(rows["Quiet"][1]["attrs"]["aria-label"],
                         "0 findings; reviewed domains: SEC")
        self.assertEqual([_text(c) for c in rows["App"]], ["—", "1", "1"])
        self.assertIn("missing domains: COD", rows["App"][0]["attrs"]["title"])

    def test_collapsed_panel_requires_every_planned_domain_and_exact_chunk(self):
        report = _minimal_report(findings=[])
        report["groups"] = [{"name": "App_1", "files": ["a.py"]},
                            {"name": "App_2", "files": ["b.py"]}]
        cells = {"reviewed": [["App_1", "COD"]],
                 "planned_pairs": [["App_1", "COD"], ["App_1", "QAL"], ["App_2", "COD"]]}
        report["meta"]["coverage"] = {"cells": cells}
        rows = self._rows(report)
        self.assertEqual(_text(rows["App_1"][0]), "—")
        self.assertEqual(rows["App_1"][0]["attrs"]["title"],
                         "Not reviewed; reviewed domains: COD; missing domains: QAL")
        self.assertEqual(_text(rows["App_2"][0]), "—")
        cells["reviewed"].append(["App_1", "QAL"])
        rows = self._rows(report)
        self.assertEqual(_text(rows["App_1"][0]), "0")
        self.assertEqual(rows["App_1"][0]["attrs"]["title"],
                         "0 findings; reviewed domains: COD, QAL")
        self.assertEqual(_text(rows["App_2"][0]), "—")

    def test_missing_measurements_mean_unknown_even_with_planned_counts(self):
        for cells in ({}, {"reviewed": []}, {"planned_pairs": [["Quiet", "SEC"]]}):
            report = _minimal_report()
            report["groups"].append({"name": "Quiet", "files": ["quiet.py"]})
            report["meta"]["coverage"] = {"cells": cells, "fan_out": {
                "planned": {"security": 2}, "executed": {"security": 2}}}
            cell = self._rows(report)["Quiet"][0]
            self.assertEqual(_text(cell), "—")
            self.assertEqual(cell["attrs"]["title"], "Coverage unknown")
            self.assertEqual(cell["attrs"]["aria-label"], "Coverage unknown")

    def test_assembled_report_schema_and_html_share_measured_cells(self):
        import scripts.synth.findings as findings_mod
        import scripts.synth.plan as plan_mod
        import scripts.synth.report as report_mod
        import scripts.synth.tool_axis as tool_axis_mod
        import scripts.synth.validate_schema as schema_mod
        from tests.synth.helpers import DEFAULT_TIMESTAMP, _make_finding

        finding = _make_finding(id="SEC-001", panel="security",
                                location={"file": "two.py", "line_start": 3})
        finding["source"] = "tool:semgrep"
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=[finding]),
            plan=plan_mod.PlanInputs(
                groups_meta=[{"name": "Unit_1", "files": ["one.py"]},
                             {"name": "Unit_2", "files": ["two.py"]}],
                coverages=[{"group": g, "effective": ["COD", "SEC"], "floor": ["COD"]}
                           for g in ("Unit_1", "Unit_2")],
                integrity={"malformed_findings_files": [{
                    "file": "findings-Unit_1-COD.json", "cell": ["Unit_1", "COD"],
                    "defects": [{"index": 0, "reason": "not an object"}]}]}),
            tools=tool_axis_mod.ToolAxis(ingested_paths=[
                "findings-Unit_2-COD.json", "findings-Unit_1-SEC.json",
                "findings-Unit_1-COD.json"])))
        self.assertEqual(schema_mod.schema_errors(report), [])
        cells = report["meta"]["coverage"]["cells"]
        self.assertEqual(cells["reviewed"], [["Unit_1", "SEC"], ["Unit_2", "COD"]])
        self.assertEqual(cells["missing_floor"], [["Unit_1", "COD"]])
        self.assertEqual(cells["planned_pairs"], [["Unit_1", "COD"], ["Unit_1", "SEC"],
                                                 ["Unit_2", "COD"], ["Unit_2", "SEC"]])
        rows = self._rows(report)
        self.assertEqual([_text(c) for c in rows["Unit_1"]], ["—", "0", "0"])
        self.assertEqual([_text(c) for c in rows["Unit_2"]], ["0", "1", "1"])
        self.assertNotIn(["Unit_2", "SEC"], cells["reviewed"])
