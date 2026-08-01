#!/usr/bin/env python3
"""Render a CodeReviewReport as a self-contained HTML document."""
import html

_CSS = """
:root {
  --bg: #f8f9fa;
  --fg: #212529;
  --muted: #6c757d;
  --card: #ffffff;
  --border: #dee2e6;
  --critical: #dc3545;
  --high: #fd7e14;
  --medium: #ffc107;
  --low: #0dcaf0;
  --info: #6c757d;
  --pass: #198754;
  --fail: #dc3545;
}
body { font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--fg); margin: 0; padding: 1rem; line-height: 1.5; }
.container { max-width: 1200px; margin: 0 auto; }
.badge { display: inline-block; padding: .25rem .5rem; border-radius: .25rem; font-weight: 600; text-transform: uppercase; font-size: .8rem; }
.sev-critical { background: var(--critical); color: #fff; }
.sev-high { background: var(--high); color: #fff; }
.sev-medium { background: var(--medium); color: #000; }
.sev-low { background: var(--low); color: #000; }
.sev-info { background: var(--info); color: #fff; }
.meta { color: var(--muted); margin-bottom: .5rem; }
.meta span { margin-right: 1rem; }
.badges { margin: 1rem 0; }
.badge.grade { background: #0d6efd; color: #fff; }
.badge.risk { background: var(--high); color: #fff; }
.badge.gate { background: var(--pass); color: #fff; }
.dashboard { background: var(--card); border: 1px solid var(--border); border-radius: .5rem; padding: 1rem; margin: 1rem 0; }
.stats { display: flex; gap: .5rem; margin-bottom: 1rem; }
.stat-card { flex: 1; padding: .75rem; border-radius: .25rem; text-align: center; }
.stat-label { font-size: .75rem; font-weight: 700; text-transform: uppercase; }
.stat-value { font-size: 1.5rem; font-weight: 700; }
.grades { width: 100%; border-collapse: collapse; margin-top: 1rem; }
.grades th, .grades td { border: 1px solid var(--border); padding: .5rem; text-align: center; }
.grades th:first-child { text-align: left; }
.top-issues { margin: 0; padding-left: 1.25rem; }
"""

_JS = """
(function () {
  'use strict';
  window.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('[data-tab]').forEach(function (tab) {
      tab.addEventListener('click', function () {
        var group = tab.closest('[data-tab-group]');
        if (!group) return;
        var target = tab.getAttribute('data-tab');
        group.querySelectorAll('[data-tab]').forEach(function (t) { t.setAttribute('aria-selected', 'false'); });
        tab.setAttribute('aria-selected', 'true');
        group.querySelectorAll('[data-panel]').forEach(function (p) {
          p.hidden = p.getAttribute('data-panel') !== target;
        });
      });
    });
  });
})();
"""


def _escape(value):
    """Escape a string for safe insertion into HTML."""
    return html.escape(str(value))


def _html_doc(title, body):
    """Wrap body content in a self-contained HTML document."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_escape(title)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="container">
{body}
</div>
<script>{_JS}</script>
</body>
</html>"""


_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_PANEL_ORDER = ["code", "test", "security", "architecture", "database", "redteam"]


def _severity_class(severity):
    return f"sev-{str(severity).lower()}"


def _render_header(report):
    meta = report.get("meta", {})
    summary = report.get("summary", {})
    parts = [
        f"<h1>{_escape(meta.get('target', 'unknown'))}</h1>",
        "<div class='meta'>",
        f"<span>{_escape(meta.get('review_type', 'review'))}</span>",
        f"<span>{_escape(meta.get('timestamp', ''))}</span>",
        f"<span>{_escape(meta.get('security_mode', 'standard'))}</span>",
        "</div>",
        "<div class='badges'>",
        f"<span class='badge grade'>Grade: {_escape(summary.get('overall_grade', '-'))}</span>",
        f"<span class='badge risk'>Risk: {_escape(summary.get('risk_level', '-'))}</span>",
        f"<span class='badge gate'>Gate: {_escape(summary.get('gate', 'OFF'))}</span>",
        "</div>",
    ]
    return "\n".join(parts)


def _render_dashboard(report):
    summary = report.get("summary", {})
    stats = summary.get("stats", {})
    stat_cards = "\n".join(
        f"<div class='stat-card {_severity_class(sev)}'>"
        f"<div class='stat-label stat-value'>{sev} {stats.get(sev.lower(), 0)}</div></div>"
        for sev in _SEV_ORDER
    )

    rows = []
    for g in report.get("groups", []):
        grades = g.get("panel_grades", {})
        cells = " ".join(
            f"<td>{_escape(grades.get(p, '-'))}</td>" for p in _PANEL_ORDER
        )
        rows.append(f"<tr><th>{_escape(g.get('name', ''))}</th>{cells}</tr>")
    header = " ".join(f"<th>{p}</th>" for p in _PANEL_ORDER)
    grades_table = (
        f"<table class='grades'><thead><tr><th>Group</th>{header}</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )

    top = summary.get("top_issues", [])[:3]
    top_list = "\n".join(f"<li>{_escape(t)}</li>" for t in top) or "<li>None</li>"

    return f"""
<section class="dashboard">
<h2>Dashboard</h2>
<div class="stats">{stat_cards}</div>
{grades_table}
<h3>Top issues</h3>
<ul class="top-issues">{top_list}</ul>
</section>
"""


def render(report, compare_report=None):
    """Render a CodeReviewReport (optionally with a second report for compare)."""
    body = _render_header(report) + _render_dashboard(report)
    title = f"Panopticon — {_escape(report.get('meta', {}).get('target', 'report'))}"
    return _html_doc(title, body)
