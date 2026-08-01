#!/usr/bin/env python3
"""Render a CodeReviewReport as a self-contained HTML document."""
import hashlib
import html
import os

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
.badge.grade { background: #0d6efd; color: #fff; }
.badge.gate-pass { background: var(--pass); color: #fff; }
.badge.gate-fail { background: var(--fail); color: #fff; }
.badge.gate-off { background: var(--info); color: #fff; }
.meta { color: var(--muted); margin-bottom: .5rem; }
.meta span { margin-right: 1rem; }
.badges { margin: 1rem 0; }
.dashboard { background: var(--card); border: 1px solid var(--border); border-radius: .5rem; padding: 1rem; margin: 1rem 0; }
.stats { display: flex; gap: .5rem; margin-bottom: 1rem; }
.stat-card { flex: 1; padding: .75rem; border-radius: .25rem; text-align: center; }
.stat-label { font-size: .75rem; font-weight: 700; text-transform: uppercase; }
.stat-value { font-size: 1.5rem; font-weight: 700; }
.grades { width: 100%; border-collapse: collapse; margin-top: 1rem; }
.grades th, .grades td { border: 1px solid var(--border); padding: .5rem; text-align: center; }
.grades th:first-child { text-align: left; }
.top-issues { margin: 0; padding-left: 1.25rem; }
.findings { margin-top: 1rem; }
.findings-controls { margin-bottom: .5rem; }
.findings-controls button { margin-right: .25rem; }
.tabs { display: flex; gap: .25rem; border-bottom: 1px solid var(--border); margin-bottom: .5rem; }
.tab { background: var(--card); border: 1px solid var(--border); border-bottom: none; padding: .5rem 1rem; cursor: pointer; border-radius: .25rem .25rem 0 0; }
.tab[aria-selected="true"] { background: var(--bg); font-weight: 700; }
.finding-card { background: var(--card); border: 1px solid var(--border); border-radius: .25rem; margin-bottom: .5rem; }
.finding-card summary { padding: .75rem; cursor: pointer; display: flex; align-items: center; gap: .5rem; flex-wrap: wrap; }
.finding-card .title { flex: 1; font-weight: 600; }
.finding-card .where { color: var(--muted); font-family: monospace; }
.finding-card .meta { color: var(--muted); font-size: .85rem; }
.finding-body { padding: .75rem; border-top: 1px solid var(--border); }
.finding-body dl { margin: 0; }
.finding-body dt { font-weight: 700; margin-top: .75rem; }
.finding-body dd { margin-left: 0; }
.chip { display: inline-block; background: #e9ecef; border-radius: .25rem; padding: .1rem .4rem; font-size: .8rem; margin-right: .25rem; }
.prov-tool { background: #6f42c1; color: #fff; }
.prov-reinforced { background: var(--pass); color: #fff; }
.prov-corroborated { background: #0dcaf0; color: #000; }
.prov-agent { background: var(--muted); color: #fff; }
.heatmap-grid { display: flex; flex-wrap: wrap; gap: .25rem; margin-bottom: 1rem; }
.heatmap-cell { padding: .25rem .5rem; border-radius: .25rem; font-size: .85rem; font-family: monospace; }
.heatmap-cell .count { margin-left: .25rem; font-weight: 700; }
.heatmap-more { padding: .25rem .5rem; color: var(--muted); }
.compare-dashboard { display: flex; gap: .5rem; flex-wrap: wrap; }
.compare-panel { flex: 1; min-width: 250px; background: var(--card); border: 1px solid var(--border); border-radius: .5rem; padding: 1rem; }
.stat-minis { margin-top: .5rem; }
.stat-mini { display: inline-block; padding: .1rem .4rem; border-radius: .25rem; font-size: .75rem; margin-right: .25rem; }
.delta-card { flex: 1; min-width: 120px; background: var(--card); border: 1px solid var(--border); border-radius: .25rem; padding: .75rem; text-align: center; }
.delta-label { font-size: .75rem; text-transform: uppercase; }
.delta-value { font-size: 1.25rem; font-weight: 700; }
.delta-new { border-left: 4px solid var(--high); }
.delta-resolved { border-left: 4px solid var(--pass); }
.delta-unchanged { border-left: 4px solid var(--info); }
.delta-severity-changed { border-left: 4px solid var(--medium); }
.compare-columns { display: flex; gap: 1rem; }
.compare-col { flex: 1; min-width: 0; }
.delta-new-badge { background: var(--high); color: #fff; }
.delta-resolved-badge { background: var(--pass); color: #fff; }
.delta-unchanged-badge { background: var(--info); color: #fff; }
.delta-severity-changed-badge { background: var(--medium); color: #000; }
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

    document.querySelectorAll('[data-expand-all]').forEach(function (btn) {
      var expanded = false;
      var section = btn.closest('.findings');
      btn.textContent = 'Expand all';
      btn.addEventListener('click', function () {
        expanded = !expanded;
        var details = section ? section.querySelectorAll('details.finding-card') : [];
        details.forEach(function (d) { d.open = expanded; });
        btn.textContent = expanded ? 'Collapse all' : 'Expand all';
      });
    });

    document.querySelectorAll('[data-compare-findings]').forEach(function (section) {
      var buttons = section.querySelectorAll('[data-compare-filter]');
      buttons.forEach(function (btn) {
        btn.addEventListener('click', function () {
          var mode = btn.getAttribute('data-compare-filter');
          buttons.forEach(function (b) { b.setAttribute('aria-pressed', 'false'); });
          btn.setAttribute('aria-pressed', 'true');
          section.querySelectorAll('details.finding-card').forEach(function (card) {
            var badge = card.querySelector('.delta-badge');
            var delta = badge ? badge.getAttribute('data-delta') : 'unchanged';
            var isDelta = delta !== 'unchanged';
            card.hidden = (mode === 'deltas' && !isDelta);
          });
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


def _normalize_path(path):
    """Strip leading ./ and normalize separators for stable matching."""
    if not path:
        return ""
    p = str(path).replace(os.sep, "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def _fingerprint(finding):
    """Stable fingerprint that ignores line numbers so moved issues match."""
    loc = finding.get("location") or {}
    parts = [
        finding.get("panel", ""),
        finding.get("category", ""),
        _normalize_path(loc.get("file", "")),
        finding.get("title", ""),
        finding.get("description", ""),
    ]
    payload = "|".join(parts).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


def _match_findings(a_findings, b_findings):
    """Return a list of match dicts with keys fingerprint, a, b, delta.

    Findings are grouped by fingerprint and paired greedily. Paired findings
    are marked 'unchanged' or 'severity changed'; unmatched head findings are
    'new'; unmatched base findings are 'resolved'.
    """
    a_by_fp = {}
    for f in a_findings:
        a_by_fp.setdefault(_fingerprint(f), []).append(f)
    b_by_fp = {}
    for f in b_findings:
        b_by_fp.setdefault(_fingerprint(f), []).append(f)

    all_fps = sorted(set(a_by_fp) | set(b_by_fp))
    matches = []
    for fp in all_fps:
        a_list = a_by_fp.get(fp, [])
        b_list = b_by_fp.get(fp, [])
        paired = list(zip(a_list, b_list))
        for af, bf in paired:
            delta = "unchanged"
            if af.get("severity") != bf.get("severity"):
                delta = "severity changed"
            matches.append({"fingerprint": fp, "a": af, "b": bf, "delta": delta})
        for af in a_list[len(paired):]:
            matches.append({"fingerprint": fp, "a": af, "b": None, "delta": "resolved"})
        for bf in b_list[len(paired):]:
            matches.append({"fingerprint": fp, "a": None, "b": bf, "delta": "new"})
    return matches


def _severity_class(severity):
    """Map a severity to a CSS class, stripping non-alphanumeric characters."""
    clean = "".join(c for c in str(severity) if c.isalnum()).lower()
    return f"sev-{clean}"


def _gate_class(gate):
    """Map a gate verdict to a CSS class using the severity palette."""
    return {"PASS": "gate-pass", "FAIL": "gate-fail"}.get(str(gate).upper(), "gate-off")


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
        f"<span class='badge {_severity_class(summary.get('risk_level', 'INFO'))}'>"
        f"Risk: {_escape(summary.get('risk_level', '-'))}</span>",
        f"<span class='badge {_gate_class(summary.get('gate', 'OFF'))}'>"
        f"Gate: {_escape(summary.get('gate', 'OFF'))}</span>",
        "</div>",
    ]
    return "\n".join(parts)


def _render_compare_summary(label, report):
    summary = report.get("summary", {})
    stats = summary.get("stats", {})
    stat_cards = " ".join(
        f"<span class='stat-mini {_severity_class(sev)}'>{sev} {stats.get(sev.lower(), 0)}</span>"
        for sev in _SEV_ORDER
    )
    return f"""
<div class="compare-panel">
<h3>{_escape(label)}</h3>
<div class="badges">
<span class="badge grade">{_escape(summary.get('overall_grade', '-'))}</span>
<span class="badge {_severity_class(summary.get('risk_level', 'INFO'))}">Risk: {_escape(summary.get('risk_level', '-'))}</span>
<span class="badge {_gate_class(summary.get('gate', 'OFF'))}">Gate: {_escape(summary.get('gate', 'OFF'))}</span>
</div>
<div class="stat-minis">{stat_cards}</div>
</div>
"""


def _render_compare_dashboard(matches):
    counts = {"new": 0, "resolved": 0, "unchanged": 0, "severity changed": 0}
    for m in matches:
        counts[m["delta"]] = counts.get(m["delta"], 0) + 1
    delta_cards = " ".join(
        f"<div class='delta-card {k.replace(' ', '-')}'><div class='delta-label'>{k}</div>"
        f"<div class='delta-value'>{v}</div></div>"
        for k, v in counts.items()
    )
    return f"""
<section class="dashboard compare-dashboard">
<h2>Compare</h2>
{delta_cards}
</section>
"""


def _render_compare_findings(matches):
    left = []
    right = []
    for m in matches:
        if m["a"]:
            left.append(_render_card(m["a"], delta=m["delta"]))
        if m["b"]:
            right.append(_render_card(m["b"], delta=m["delta"]))
    return f"""
<section class="findings compare-findings" data-compare-findings>
<h2>Findings</h2>
<div class="findings-controls">
<button type="button" class="toggle-all" data-expand-all>Expand all</button>
<button type="button" data-compare-filter="all" aria-pressed="true">Show all</button>
<button type="button" data-compare-filter="deltas" aria-pressed="false">Only deltas</button>
</div>
<div class="compare-columns">
<div class="compare-col"><h3>Base</h3>{''.join(left)}</div>
<div class="compare-col"><h3>Head</h3>{''.join(right)}</div>
</div>
</section>
"""


def _render_dashboard(report):
    summary = report.get("summary", {})
    stats = summary.get("stats", {})
    stat_cards = "\n".join(
        f"<div class='stat-card {_severity_class(sev)}'>"
        f"<div class='stat-label'>{sev}</div>"
        f"<div class='stat-value'>{stats.get(sev.lower(), 0)}</div></div>"
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
{_render_heatmap(report.get('findings', []))}
{grades_table}
<h3>Top issues</h3>
<ul class="top-issues">{top_list}</ul>
</section>
"""


def _render_card(finding, delta=None):
    loc = finding.get("location") or {}
    where = f"{_escape(loc.get('file', '?'))}:{_escape(loc.get('line_start', '?'))}"
    sev = finding.get("severity", "INFO")
    panel = finding.get("panel", "code")
    category = finding.get("category", "general")
    confidence = finding.get("confidence", "NOTE")
    provenance = "tool" if str(finding.get("source", "")).startswith("tool:") else (
        "reinforced" if finding.get("reinforced") else (
            "corroborated" if finding.get("corroborated") else "agent"
        )
    )
    delta_badge = ""
    if delta:
        delta_badge = (
            f"<span class='badge delta-badge delta-{_escape(delta.replace(' ', '-'))}-badge' "
            f"data-delta='{_escape(delta)}'>{_escape(delta)}</span>"
        )

    details = []
    for label, key in [("Description", "description"), ("Impact", "impact"), ("Remediation", "remediation")]:
        value = finding.get(key)
        if value:
            details.append(f"<dt>{label}</dt><dd>{_escape(value)}</dd>")

    refs = finding.get("references") or []
    if refs:
        links = "\n".join(f"<li><a href='{_escape(r)}'>{_escape(r)}</a></li>" for r in refs)
        details.append(f"<dt>References</dt><dd><ul>{links}</ul></dd>")

    cvss = finding.get("cvss")
    if cvss:
        details.append(f"<dt>CVSS</dt><dd>{_escape(cvss.get('score', ''))} {_escape(cvss.get('vector', ''))}</dd>")
    if finding.get("exploit_scenario"):
        details.append(f"<dt>Exploit scenario</dt><dd>{_escape(finding['exploit_scenario'])}</dd>")

    citations = finding.get("citations") or {}
    chips = []
    for cwe in citations.get("cwe") or []:
        cid = cwe.get("id") if isinstance(cwe, dict) else cwe
        chips.append(f"<span class='chip'>{_escape(cid)}</span>")
    for owasp in citations.get("owasp") or []:
        chips.append(f"<span class='chip'>{_escape(owasp)}</span>")
    ssvc = citations.get("ssvc")
    if isinstance(ssvc, dict) and ssvc.get("decision"):
        chips.append(f"<span class='chip'>SSVC:{_escape(ssvc['decision'])}</span>")
    for cve in citations.get("cve") or []:
        chips.append(f"<span class='chip'>{_escape(cve)}</span>")
    epss_list = citations.get("epss")
    if isinstance(epss_list, list) and epss_list:
        max_score = max(e.get("score", 0.0) for e in epss_list)
        chips.append(f"<span class='chip'>EPSS:{max_score:.2f}</span>")
    if chips:
        details.append(f"<dt>Citations</dt><dd>{' '.join(chips)}</dd>")

    body = f"<dl>{''.join(details)}</dl>" if details else ""

    return f"""
<details class="finding-card">
<summary>
<span class="badge {_severity_class(sev)}">{_escape(sev)}</span>
<strong>{_escape(finding.get('id', '???'))}</strong>
<span class="title">{_escape(finding.get('title', ''))}</span>
<span class="where">{where}</span>
<span class="meta">{_escape(panel)} / {_escape(category)} / {_escape(confidence)}</span>
<span class="badge prov-{provenance}">{_escape(provenance)}</span>
{delta_badge}
</summary>
<div class="finding-body">{body}</div>
</details>
"""


_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _heatmap_data(findings):
    files = {}
    for f in findings:
        loc = f.get("location") or {}
        path = loc.get("file")
        if not path:
            continue
        entry = files.setdefault(
            path, {"counts": {s: 0 for s in _SEV_ORDER}, "worst": "INFO"}
        )
        sev = f.get("severity", "INFO")
        entry["counts"][sev] = entry["counts"].get(sev, 0) + 1
        if _SEV_RANK.get(sev, 99) < _SEV_RANK.get(entry["worst"], 99):
            entry["worst"] = sev
    return sorted(
        files.items(),
        key=lambda item: (
            -sum(item[1]["counts"].values()),
            _SEV_RANK.get(item[1]["worst"], 99),
            item[0],
        ),
    )


def _render_heatmap(findings):
    data = _heatmap_data(findings)
    cells = []
    for path, info in data[:50]:
        total = sum(info["counts"].values())
        tooltip = f"{total} finding(s) in {path}"
        cells.append(
            f"<div class='heatmap-cell {_severity_class(info['worst'])}' "
            f"title='{_escape(tooltip)}'>"
            f"{_escape(path)} <span class='count'>{total}</span></div>"
        )
    more = "<div class='heatmap-more'>...</div>" if len(data) > 50 else ""
    return f"""
<section class="heatmap">
<h3>File heatmap</h3>
<div class="heatmap-grid">{''.join(cells)}{more}</div>
</section>
"""


def _render_findings(findings):
    by_sev = {sev: [] for sev in _SEV_ORDER}
    by_sev["ALL"] = []
    for f in findings:
        by_sev["ALL"].append(f)
        sev = f.get("severity", "INFO")
        if sev in by_sev:
            by_sev[sev].append(f)

    tabs = []
    panels = []
    for sev in ["ALL"] + _SEV_ORDER:
        count = len(by_sev[sev])
        tabs.append(
            f'<button class="tab" data-tab="{sev}" aria-selected="{str(sev == "ALL").lower()}">'
            f"{sev} <span class='count'>{count}</span></button>"
        )
        cards = "\n".join(_render_card(f) for f in by_sev[sev])
        hidden = "" if sev == "ALL" else "hidden"
        panels.append(f'<div class="tab-panel" data-panel="{sev}" {hidden}>{cards}</div>')

    return f"""
<section class="findings" data-tab-group="findings">
<h2>Findings</h2>
<div class="findings-controls">
<button type="button" class="toggle-all" data-expand-all>Expand all</button>
</div>
<div class="tabs" role="tablist">{"".join(tabs)}</div>
{"".join(panels)}
</section>
"""


def write_html(report, path, compare_report=None):
    """Write a rendered HTML report to disk."""
    os.makedirs(os.path.dirname(os.path.abspath(path)) if os.path.dirname(path) else ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render(report, compare_report=compare_report))


def render(report, compare_report=None):
    """Render a CodeReviewReport (optionally with a second report for compare)."""
    if compare_report:
        matches = _match_findings(compare_report.get("findings", []), report.get("findings", []))
        body = (
            _render_compare_summary("Base", compare_report) +
            _render_compare_summary("Head", report) +
            _render_compare_dashboard(matches) +
            _render_compare_findings(matches)
        )
        title = f"Panopticon Compare — {report.get('meta', {}).get('target', 'report')}"
    else:
        body = _render_header(report) + _render_dashboard(report) + _render_findings(report.get("findings", []))
        title = f"Panopticon — {report.get('meta', {}).get('target', 'report')}"
    return _html_doc(title, body)
