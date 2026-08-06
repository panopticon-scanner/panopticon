#!/usr/bin/env python3
"""Render a CodeReviewReport as a self-contained HTML document."""
import hashlib
import html
import os
import re

_CSS = """
:root {
  --bg: #131418; --card: #1b1d22; --panel: #17181d; --chip: #23262d;
  --border: #262a32; --border2: #3a404b;
  --ink: #e9eaec; --ink2: #c6c9cf; --muted: #9aa1ac; --faint: #878f9c;
  --accent: #d3d7dd; --accent-border: #6e7683; --link: #9db1c4;
  /* severity text/tint colors (theme-dependent) */
  --sev-critical: #e5786b; --sev-high: #e59a8c; --sev-medium: #e8c05a;
  --sev-low: #86b1e0; --sev-info: #a9bcc9;
  /* panel bar colors (theme-dependent) */
  --panel-code: #6892c4; --panel-test: #4aac7a; --panel-security: #e59a8c;
  --panel-architecture: #8da0af; --panel-database: #e8c05a; --panel-redteam: #e5786b;
  --panel-unknown: #8da0af;
  --ui: 'Space Grotesk', system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
  --mono: 'Space Mono', ui-monospace, SFMono-Regular, Menlo, monospace;
}
[data-theme="light"] {
  --bg: #f7f7f5; --card: #fbfbf9; --panel: #f1f1ee; --chip: #eaeae6;
  --border: #e2e2dd; --border2: #c9c9c2;
  --ink: #1b1d22; --ink2: #33363c; --muted: #5c636d; --faint: #666d78;
  --accent: #3c4650; --accent-border: #9aa1ac; --link: #46617a;
  --sev-critical: #7d2f2a; --sev-high: #a04b42; --sev-medium: #7e5c18;
  --sev-low: #35619b; --sev-info: #4e6375;
  --panel-code: #265089; --panel-test: #1f6f48; --panel-security: #a04b42;
  --panel-architecture: #4e6375; --panel-database: #7e5c18; --panel-redteam: #7d2f2a;
  --panel-unknown: #4e6375;
}
* { box-sizing: border-box; }
body { font-family: var(--ui); background: var(--bg); color: var(--ink); margin: 0; padding: 0; line-height: 1.5; transition: background .25s; }
.container { max-width: 900px; margin: 0 auto; padding: 32px; position: relative; }
a { color: var(--link); }
h1 { font-size: 32px; font-weight: 600; letter-spacing: -.015em; margin: .2rem 0 .4rem; }
h2 { font-size: 18px; font-weight: 600; }
/* Solid severity badges are theme-independent (AA-audited). */
.badge { display: inline-block; padding: .2rem .5rem; border-radius: 3px; font-weight: 700; text-transform: uppercase; font-size: .68rem; letter-spacing: .07em; font-family: var(--mono); }
.sev-critical { background: #7d2f2a; color: #faf8f2; }
.sev-high { background: #a04b42; color: #faf8f2; }
.sev-medium { background: #b98d28; color: #131418; }
.sev-low { background: #3d6da8; color: #faf8f2; }
.sev-info { background: #4e6375; color: #faf8f2; }
.badge.grade { background: transparent; color: var(--accent); border: 1px solid var(--accent-border); }
.badge.gate-pass { background: #1f6f48; color: #faf8f2; }
.badge.gate-fail { background: #7d2f2a; color: #faf8f2; }
.badge.gate-off { background: #4e6375; color: #faf8f2; }
.panel-code { background: var(--panel-code); }
.panel-test { background: var(--panel-test); }
.panel-security { background: var(--panel-security); }
.panel-architecture { background: var(--panel-architecture); }
.panel-database { background: var(--panel-database); }
.panel-redteam { background: var(--panel-redteam); }
.panel-unknown { background: var(--panel-unknown); }
.chart { background: var(--panel); border: 1px solid var(--border); border-radius: 4px; padding: 1rem; margin: 1rem 0; }
.chart h3 { margin-top: 0; margin-bottom: .75rem; font-size: 13px; color: var(--muted); text-transform: uppercase; letter-spacing: .06em; }
.chart-rows { display: flex; flex-direction: column; gap: .4rem; }
.chart-row { display: flex; align-items: center; gap: .5rem; }
.chart-label { min-width: 6.5rem; font-family: var(--mono); font-size: 10px; color: var(--faint); text-align: right; }
.chart-bar-wrap { flex: 1; background: var(--border); border-radius: 2px; height: 12px; overflow: hidden; }
.chart-bar { height: 100%; border-radius: 2px; transition: width .3s ease; min-width: 0; }
.chart-value { min-width: 2rem; text-align: right; font-family: var(--mono); font-weight: 700; font-size: 11px; }
.meta { color: var(--faint); font-family: var(--mono); font-size: 11px; margin-bottom: .5rem; }
.meta span { margin-right: 1rem; }
.badges { margin: 1rem 0; display: flex; gap: .4rem; flex-wrap: wrap; }
.coverage { color: var(--faint); font-family: var(--mono); font-size: 11px; margin: -.4rem 0 1.4rem; }
.dashboard { background: var(--panel); border: 1px solid var(--border); border-radius: 4px; padding: 1rem; margin: 1rem 0; }
.stats { display: flex; gap: 1px; margin-bottom: 1rem; background: var(--border); border: 1px solid var(--border); border-radius: 4px; overflow: hidden; }
.stat-card { flex: 1; padding: .6rem; text-align: center; background: var(--panel); }
.stat-label { font-family: var(--mono); font-size: 9px; font-weight: 700; letter-spacing: .1em; text-transform: uppercase; color: var(--faint); }
.stat-value { font-family: var(--mono); font-size: 22px; font-weight: 700; }
.grades { width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: 13px; }
.grades th, .grades td { border: 1px solid var(--border); padding: .4rem .5rem; text-align: center; }
.grades th { color: var(--muted); font-weight: 600; }
.grades th:first-child { text-align: left; }
.top-issues { margin: 0; padding-left: 1.25rem; color: var(--ink2); }
.findings { margin-top: 1.6rem; }
.findings-controls { margin-bottom: .5rem; display: flex; gap: .4rem; justify-content: flex-end; }
button, .tab { font-family: var(--ui); }
.findings-controls button, .tab { background: transparent; color: var(--muted); border: 1px solid var(--border2); border-radius: 4px; padding: .3rem .7rem; font-size: 12px; cursor: pointer; }
.findings-controls button:hover, .tab:hover, summary:hover { border-color: var(--accent-border); color: var(--accent); }
.tabs { display: flex; gap: .3rem; margin-bottom: .75rem; flex-wrap: wrap; }
.tab { font-family: var(--mono); font-size: 11px; }
.tab[aria-selected="true"] { background: var(--ink); color: var(--bg); border-color: var(--ink); font-weight: 700; }
.finding-card { background: var(--card); border: 1px solid var(--border); border-radius: 4px; margin-bottom: .5rem; }
.finding-card summary { padding: 11px 16px; cursor: pointer; display: flex; align-items: baseline; gap: 12px; flex-wrap: wrap; }
.finding-card summary::-webkit-details-marker { display: none; }
.finding-card .title { flex: 1; font-weight: 600; font-size: 14px; color: var(--ink); }
.finding-card .where { color: var(--muted); font-family: var(--mono); font-size: 11px; }
.finding-card .meta { color: var(--faint); font-size: 11px; }
.finding-body { padding: 16px; border-top: 1px solid var(--border); }
.finding-body dl { margin: 0; max-width: 78ch; }
.finding-body dt { font-size: 10px; font-weight: 700; letter-spacing: .09em; text-transform: uppercase; color: var(--muted); margin-top: .9rem; }
.finding-body dd { margin-left: 0; color: var(--ink2); line-height: 1.6; }
.chip { display: inline-block; background: var(--chip); color: var(--ink2); border-radius: 3px; padding: .12rem .45rem; font-family: var(--mono); font-size: 11px; margin-right: .3rem; }
.prov-status, .prov-source, .prov-model, .cit-quality { display: inline-block; border-radius: 3px; padding: .12rem .45rem; font-family: var(--mono); font-size: 10px; margin-right: .3rem; font-weight: 700; text-transform: uppercase; }
.prov-status { background: #1f6f48; color: #faf8f2; }
.prov-status.prov-needs-more-info { background: #b98d28; color: #131418; }
.prov-status.prov-unverified { background: #4e6375; color: #faf8f2; }
.prov-status.prov-rejected { background: #7d2f2a; color: #faf8f2; }
.prov-source, .prov-model { background: var(--chip); color: var(--ink2); }
.cit-quality { background: transparent; border: 1px solid var(--border2); color: var(--muted); }
.cit-full { background: #1f6f48; color: #faf8f2; border-color: transparent; }
.cit-partial { background: #b98d28; color: #131418; border-color: transparent; }
.cit-minimal { background: #3d6da8; color: #faf8f2; border-color: transparent; }
.cit-none { background: #4e6375; color: #faf8f2; border-color: transparent; }
.unverified-findings { margin-top: 1rem; }
.unverified-findings > details { background: var(--panel); border: 1px solid var(--border); border-radius: 4px; padding: 1rem; }
.unverified-findings summary { cursor: pointer; font-weight: 600; }
.heatmap-grid { display: flex; flex-wrap: wrap; gap: 2px; margin-bottom: 1rem; }
.heatmap-cell { padding: .25rem .5rem; border-radius: 2px; font-family: var(--mono); font-size: 11px; background: var(--chip); }
.heatmap-cell .count { margin-left: .25rem; font-weight: 700; }
.heatmap-more { padding: .25rem .5rem; color: var(--faint); font-family: var(--mono); font-size: 11px; }
.compare-dashboard { display: flex; gap: .5rem; flex-wrap: wrap; }
.compare-panel { flex: 1; min-width: 250px; background: var(--card); border: 1px solid var(--border); border-radius: 4px; padding: 1rem; }
.stat-minis { margin-top: .5rem; }
.stat-mini { display: inline-block; padding: .12rem .45rem; border-radius: 3px; font-family: var(--mono); font-size: 10px; font-weight: 700; margin-right: .3rem; }
.delta-card { flex: 1; min-width: 120px; background: var(--card); border: 1px solid var(--border); border-radius: 4px; padding: .75rem; text-align: center; }
.delta-label { font-family: var(--mono); font-size: 10px; text-transform: uppercase; color: var(--faint); letter-spacing: .08em; }
.delta-value { font-family: var(--mono); font-size: 26px; font-weight: 700; }
.delta-new { border-top: 3px solid #a04b42; }
.delta-resolved { border-top: 3px solid #1f6f48; }
.delta-unchanged { border-top: 3px solid var(--border2); }
.delta-severity-changed { border-top: 3px solid #b98d28; }
.compare-columns { display: flex; gap: 1rem; }
.compare-col { flex: 1; min-width: 0; }
.delta-new-badge { background: #a04b42; color: #faf8f2; }
.delta-resolved-badge { background: #1f6f48; color: #faf8f2; }
.delta-unchanged-badge { background: transparent; color: var(--muted); border: 1px solid var(--border2); }
.delta-severity-changed-badge { background: #b98d28; color: #131418; }
.theme-toggle { position: absolute; top: 32px; right: 32px; font-family: var(--mono); font-size: 10px; text-transform: uppercase; letter-spacing: .08em; background: transparent; color: var(--muted); border: 1px solid var(--border2); border-radius: 4px; padding: .3rem .6rem; cursor: pointer; }
.theme-toggle:hover { border-color: var(--accent-border); color: var(--accent); }
button:focus-visible, summary:focus-visible, a:focus-visible { outline: 2px solid var(--accent-border); outline-offset: 2px; }
"""

_JS = """
(function () {
  'use strict';
  var THEME_KEY = 'panopticon-theme';
  function applyTheme(t) {
    if (t === 'light') { document.documentElement.setAttribute('data-theme', 'light'); }
    else { document.documentElement.removeAttribute('data-theme'); }
  }
  try { applyTheme(localStorage.getItem(THEME_KEY)); } catch (e) {}
  window.addEventListener('DOMContentLoaded', function () {
    var themeToggle = document.querySelector('[data-theme-toggle]');
    if (themeToggle) {
      var syncLabel = function () {
        var light = document.documentElement.getAttribute('data-theme') === 'light';
        themeToggle.textContent = light ? 'Dark mode' : 'Light mode';
      };
      syncLabel();
      themeToggle.addEventListener('click', function () {
        var light = document.documentElement.getAttribute('data-theme') === 'light';
        var next = light ? 'dark' : 'light';
        applyTheme(next);
        try { localStorage.setItem(THEME_KEY, next); } catch (e) {}
        syncLabel();
      });
    }

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
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=Space+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>{_CSS}</style>
</head>
<body>
<div class="container">
<button class="theme-toggle" type="button" data-theme-toggle>Light mode</button>
{body}
</div>
<script>{_JS}</script>
</body>
</html>"""


_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_PANEL_ORDER = ["code", "test", "security", "architecture", "database", "redteam"]


def _severity_counts(findings):
    """Return finding counts keyed by severity in display order."""
    counts = {sev: 0 for sev in _SEV_ORDER}
    for f in findings:
        sev = f.get("severity", "INFO")
        if sev in counts:
            counts[sev] += 1
    return counts


def _panel_counts(findings):
    """Return finding counts keyed by panel in display order."""
    counts = {panel: 0 for panel in _PANEL_ORDER}
    for f in findings:
        panel = f.get("panel", "code")
        if panel in counts:
            counts[panel] += 1
        else:
            counts["code"] += 1
    return counts


def _top_category_counts(findings, limit=8):
    """Return the top `limit` categories by count, plus an 'Other' bucket."""
    counts = {}
    for f in findings:
        cat = f.get("category") or "unknown"
        counts[cat] = counts.get(cat, 0) + 1
    sorted_cats = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    top = sorted_cats[:limit]
    other_count = sum(c for _, c in sorted_cats[limit:])
    if other_count:
        top.append(("Other", other_count))
    return top


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


def _panel_class(panel):
    """Map a panel name to a CSS class, stripping non-alphanumeric chars."""
    clean = "".join(c for c in str(panel) if c.isalnum()).lower()
    return f"panel-{clean}"


def _render_provenance(provenance):
    if not isinstance(provenance, dict):
        return ""
    status = str(provenance.get("confirmation_status", "UNVERIFIED"))
    # SEC-101: agent-authored value; restrict the class token to a safe
    # charset instead of interpolating it raw into the HTML attribute.
    status_class = re.sub(r"[^a-z0-9-]", "-", status.lower()) or "unknown"
    source = provenance.get("discovered_by", "unknown")
    model = provenance.get("model")
    parts = [f"<span class='prov-status prov-{status_class}'>{_escape(status)}</span>",
             f"<span class='prov-source'>{_escape(source)}</span>"]
    if model:
        parts.append(f"<span class='prov-model'>{_escape(model)}</span>")
    return " ".join(parts)


def _render_citation_quality(quality):
    quality = str(quality).lower() if quality else "none"
    return f"<span class='cit-quality cit-{quality}'>{_escape(quality)}</span>"


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
    ev = summary.get("evidence_stats") or {}
    verified = int(ev.get("advisor_confirmed", 0)) + int(ev.get("tool_confirmed", 0))
    unverified = int(ev.get("unverified", 0))
    tool_reported = int(ev.get("tool_reported", 0))
    cut = int(((meta.get("coverage") or {}).get("verdicts") or {}).get("cut", 0))
    policy = "unverified" if summary.get("gate_policy") == "include_unverified" else "strict"
    coverage_parts = ["%d verified" % verified, "%d unverified" % unverified,
                       "%d tool-reported" % tool_reported]
    if cut:
        coverage_parts.append("%d cut" % cut)
    parts.append(
        "<div class='coverage'>Coverage: %s &mdash; gate: %s</div>"
        % (" &middot; ".join(coverage_parts), policy)
    )
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
        f"<div class='delta-card delta-{k.replace(' ', '-')}'><div class='delta-label'>{_escape(k)}</div>"
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


def _render_bar_chart(rows, color_class_fn, title):
    """Render a horizontal bar chart from (label, count) rows."""
    row_html = []
    if rows:
        max_count = max(count for _, count in rows)
        if max_count == 0:
            max_count = 1
        for label, count in rows:
            pct = (count / max_count) * 100
            row_html.append(
                f"<div class='chart-row'>"
                f"<span class='chart-label'>{_escape(label)}</span>"
                f"<div class='chart-bar-wrap'>"
                f"<div class='chart-bar {color_class_fn(label)}' style='width: {pct:.1f}%'></div>"
                f"</div>"
                f"<span class='chart-value'>{count}</span>"
                f"</div>"
            )
    return f"""
<section class="chart">
<h3>{_escape(title)}</h3>
<div class="chart-rows">{''.join(row_html)}</div>
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

    findings = report.get("findings", [])
    severity_rows = list(_severity_counts(findings).items())
    panel_rows = list(_panel_counts(findings).items())
    category_rows = _top_category_counts(findings)

    charts = "\n".join([
        _render_bar_chart(severity_rows, _severity_class, "Findings by severity"),
        _render_bar_chart(panel_rows, _panel_class, "Findings by panel"),
        _render_bar_chart(category_rows, lambda _: "sev-info", "Top finding categories"),
    ])

    return f"""
<section class="dashboard">
<h2>Dashboard</h2>
<div class="stats">{stat_cards}</div>
{charts}
{_render_heatmap(findings)}
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
    provenance_html = _render_provenance(finding.get("provenance"))
    quality_html = _render_citation_quality(
        (finding.get("evidence") or {}).get("citation_quality"))
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
        links = "\n".join(
            f"<li><a href='{_escape(r)}' rel='noreferrer noopener'>{_escape(r)}</a></li>" if str(r).lower().startswith(("http://", "https://")) else f"<li>{_escape(r)}</li>"
            for r in refs
        )
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
{provenance_html}
{quality_html}
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
    unverified_statuses = ("tool_reported", "needs_more_info", "unverified")
    verified = [f for f in findings
                if (f.get("evidence") or {}).get("status") not in unverified_statuses]
    unverified = [f for f in findings
                  if (f.get("evidence") or {}).get("status") in unverified_statuses]

    by_sev = {sev: [] for sev in _SEV_ORDER}
    by_sev["ALL"] = []
    for f in verified:
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

    unverified_section = ""
    if unverified:
        unverified_cards = "\n".join(_render_card(f) for f in unverified)
        unverified_section = f"""
<section class="findings unverified-findings">
<details>
<summary>Unverified findings <span class='count'>({len(unverified)})</span></summary>
{unverified_cards}
</details>
</section>
"""

    return f"""
<section class="findings" data-tab-group="findings">
<h2>Findings</h2>
<div class="findings-controls">
<button type="button" class="toggle-all" data-expand-all>Expand all</button>
</div>
<div class="tabs" role="tablist">{"".join(tabs)}</div>
{"".join(panels)}
</section>
{unverified_section}
"""


def _render_discarded_claims(discarded):
    if not discarded:
        return ""
    cards = "\n".join(_render_card(f) for f in discarded)
    return f"""
<section class="findings discarded-claims">
<details>
<summary>Discarded claims <span class='count'>({len(discarded)})</span></summary>
{cards}
</details>
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
        body = (
            _render_header(report)
            + _render_dashboard(report)
            + _render_findings(report.get("findings", []))
            + _render_discarded_claims(report.get("discarded_claims", []))
        )
        title = f"Panopticon — {report.get('meta', {}).get('target', 'report')}"
    return _html_doc(title, body)
