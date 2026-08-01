# HTML Report Renderer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a self-contained HTML report renderer for the final `CodeReviewReport` JSON, with a dashboard, severity-tabbed finding cards, file heatmap, and side-by-side compare mode.

**Architecture:** A new stdlib-only module `scripts/html_report.py` contains the inline CSS/JS template and renderer functions. `scripts/synthesize.py` gains `--html-out` and `--compare` flags. A new test file `tests/test_html_report.py` covers rendering, compare matching, and escaping.

**Tech Stack:** Python 3.11+ stdlib only (`html`, `hashlib`, `json`, `datetime`). Vanilla HTML/CSS/JS in the generated report.

## Global Constraints

- **Vanilla HTML/CSS/JS only** — no frameworks, no CDNs, no external dependencies.
- **Self-contained artifact** — one `.html` file with all CSS and JS inlined.
- **Derived from JSON** — the renderer consumes the finalized `CodeReviewReport`, not raw panel/lens outputs.
- **Zero new Python dependencies** — the renderer is stdlib-only, like `synthesize.py`.
- **Accessible and offline-friendly** — semantic HTML, keyboard-friendly tabs/cards, works when opened from disk.
- Target line length 100, ruff rules `E`, `F`, `W` with ignores `E401`, `E501`, `E701`, `E702`.

---

### Task 1: Create `scripts/html_report.py` shell with CSS/JS and escaping

**Files:**
- Create: `scripts/html_report.py`
- Test: `tests/test_html_report.py`

**Interfaces:**
- Consumes: nothing yet.
- Produces: `_escape(value)`, `_CSS`, `_JS`, `_html_doc(title, body)` helpers.

- [ ] **Step 1: Write the failing test**

Create `tests/test_html_report.py`:

```python
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))
import scripts.html_report as hr


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_html_report.py -v`

Expected: `ImportError` or `AttributeError` because `scripts/html_report.py` does not exist.

- [ ] **Step 3: Write minimal implementation**

Create `scripts/html_report.py`:

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_html_report.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/html_report.py tests/test_html_report.py
git commit -m "feat(html): add html_report shell with escaping and inline css/js"
```

---

### Task 2: Add dashboard rendering (header, grade badges, stats, group grades, top issues)

**Files:**
- Modify: `scripts/html_report.py`
- Test: `tests/test_html_report.py`

**Interfaces:**
- Consumes: `CodeReviewReport` dict (top-level keys `meta`, `summary`, `groups`, `findings`).
- Produces: `_render_header(report)`, `_render_dashboard(report)`, `_render(report)`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_html_report.py`:

```python
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
```

Add helper at the top of `tests/test_html_report.py` after imports:

```python
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
```

Run: `pytest tests/test_html_report.py -v`

Expected: FAIL (`AttributeError: module 'scripts.html_report' has no attribute 'render'`).

- [ ] **Step 2: Add dashboard functions to `scripts/html_report.py`**

Add after `_html_doc`:

```python
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
        f"<span class='badge grade'>{_escape(summary.get('overall_grade', '-'))}</span>",
        f"<span class='badge risk'>{_escape(summary.get('risk_level', '-'))}</span>",
        f"<span class='badge gate'>{_escape(summary.get('gate', 'OFF'))}</span>",
        "</div>",
    ]
    return "\n".join(parts)


def _render_dashboard(report):
    summary = report.get("summary", {})
    stats = summary.get("stats", {})
    stat_cards = "\n".join(
        f"<div class='stat-card {_severity_class(sev)}'><div class='stat-label'>{sev}</div>"
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
```

Also add CSS to `_CSS` for these new classes:

```css
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
```

- [ ] **Step 3: Run tests**

Run: `pytest tests/test_html_report.py -v`

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add scripts/html_report.py tests/test_html_report.py
git commit -m "feat(html): add dashboard rendering with grades, stats, and top issues"
```

---

### Task 3: Add findings cards with severity tabs

**Files:**
- Modify: `scripts/html_report.py`
- Test: `tests/test_html_report.py`

**Interfaces:**
- Consumes: `report["findings"]` list.
- Produces: `_render_findings(findings)`, `_render_card(finding)`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_html_report.py`:

```python
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
```

Run: `pytest tests/test_html_report.py::TestHtmlReport::test_findings_section_has_tabs -v`

Expected: FAIL.

- [ ] **Step 2: Add findings rendering functions**

Add to `scripts/html_report.py` before `render`:

```python
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
        delta_badge = f"<span class='badge delta-{_escape(delta)}'>{_escape(delta)}</span>"

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
            f"<button class='tab' data-tab='{sev}' aria-selected='{str(sev == 'ALL').lower()}'>"
            f"{sev} <span class='count'>{count}</span></button>"
        )
        cards = "\n".join(_render_card(f) for f in by_sev[sev])
        hidden = "" if sev == "ALL" else "hidden"
        panels.append(f"<div class='tab-panel' data-panel='{sev}' {hidden}>{cards}</div>")

    return f"""
<section class="findings" data-tab-group="findings">
<h2>Findings</h2>
<div class="tabs" role="tablist">{"".join(tabs)}</div>
{"".join(panels)}
</section>
"""
```

Update `render` to include findings:

```python
def render(report, compare_report=None):
    """Render a CodeReviewReport (optionally with a second report for compare)."""
    body = _render_header(report) + _render_dashboard(report) + _render_findings(report.get("findings", []))
    title = f"Panopticon — {_escape(report.get('meta', {}).get('target', 'report'))}"
    return _html_doc(title, body)
```

Add CSS:

```css
.findings { margin-top: 1rem; }
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
```

- [ ] **Step 3: Run tests**

Run: `pytest tests/test_html_report.py -v`

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add scripts/html_report.py tests/test_html_report.py
git commit -m "feat(html): add severity tabs and collapsible finding cards"
```

---

### Task 4: Add file heatmap

**Files:**
- Modify: `scripts/html_report.py`
- Test: `tests/test_html_report.py`

**Interfaces:**
- Consumes: `report["findings"]` list.
- Produces: `_render_heatmap(findings)`.

- [ ] **Step 1: Write the failing test**

Append:

```python
    def test_heatmap_renders_files(self):
        report = _minimal_report()
        out = hr.render(report)
        self.assertIn("File heatmap", out)
        self.assertIn("app.py", out)
```

Run test, expect FAIL.

- [ ] **Step 2: Add heatmap function**

Add before `_render_findings`:

```python
_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _heatmap_data(findings):
    files = {}
    for f in findings:
        loc = f.get("location") or {}
        path = loc.get("file")
        if not path:
            continue
        entry = files.setdefault(path, {"counts": {s: 0 for s in _SEV_ORDER}, "worst": "INFO"})
        sev = f.get("severity", "INFO")
        entry["counts"][sev] = entry["counts"].get(sev, 0) + 1
        if _SEV_RANK.get(sev, 99) < _SEV_RANK.get(entry["worst"], 99):
            entry["worst"] = sev
    return sorted(files.items())


def _render_heatmap(findings):
    data = _heatmap_data(findings)
    cells = []
    for path, info in data[:50]:
        total = sum(info["counts"].values())
        tooltip = f"{total} finding(s) in {path}"
        cells.append(
            f"<div class='heatmap-cell {_severity_class(info['worst'])}' title='{_escape(tooltip)}'>"
            f"{_escape(path)} <span class='count'>{total}</span></div>"
        )
    more = "<div class='heatmap-more'>...</div>" if len(data) > 50 else ""
    return f"""
<section class="heatmap">
<h3>File heatmap</h3>
<div class="heatmap-grid">{''.join(cells)}{more}</div>
</section>
"""
```

Call it inside `_render_dashboard` after stats:

```python
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
```

Add CSS:

```css
.heatmap-grid { display: flex; flex-wrap: wrap; gap: .25rem; margin-bottom: 1rem; }
.heatmap-cell { padding: .25rem .5rem; border-radius: .25rem; font-size: .85rem; font-family: monospace; }
.heatmap-cell .count { margin-left: .25rem; font-weight: 700; }
.heatmap-more { padding: .25rem .5rem; color: var(--muted); }
```

- [ ] **Step 3: Run tests**

Run: `pytest tests/test_html_report.py -v`

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add scripts/html_report.py tests/test_html_report.py
git commit -m "feat(html): add file-level severity heatmap"
```

---

### Task 5: Add compare mode with stable fingerprint matching

**Files:**
- Modify: `scripts/html_report.py`
- Test: `tests/test_html_report.py`

**Interfaces:**
- Consumes: two `CodeReviewReport` dicts.
- Produces: `_fingerprint(finding)`, `_match_findings(a, b)`, `_render_compare(report_a, report_b)`.

- [ ] **Step 1: Write the failing test**

Append:

```python
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
```

Run tests, expect FAIL.

- [ ] **Step 2: Implement compare functions**

Add to `scripts/html_report.py` after imports:

```python
import hashlib
import os
```

Add after `_html_doc`:

```python
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
    """Return dict fingerprint -> {'a': finding|None, 'b': finding|None, 'delta': str}."""
    a_by_fp = {_fingerprint(f): f for f in a_findings}
    b_by_fp = {_fingerprint(f): f for f in b_findings}
    all_fps = sorted(set(a_by_fp) | set(b_by_fp))
    matches = []
    for fp in all_fps:
        af = a_by_fp.get(fp)
        bf = b_by_fp.get(fp)
        if af and bf:
            delta = "unchanged"
            if af.get("severity") != bf.get("severity"):
                delta = "severity changed"
        elif bf:
            delta = "new"
        else:
            delta = "resolved"
        matches.append({"fingerprint": fp, "a": af, "b": bf, "delta": delta})
    return matches
```

Add `_render_compare_header`, `_render_compare_dashboard`, and `_render_compare_findings`:

```python
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
<span class="badge gate">{_escape(summary.get('gate', 'OFF'))}</span>
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
<section class="findings compare-findings">
<h2>Findings</h2>
<div class="compare-columns">
<div class="compare-col"><h3>Base</h3>{''.join(left)}</div>
<div class="compare-col"><h3>Head</h3>{''.join(right)}</div>
</div>
</section>
"""
```

Update `render`:

```python
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
        title = f"Panopticon Compare — {_escape(report.get('meta', {}).get('target', 'report'))}"
    else:
        body = _render_header(report) + _render_dashboard(report) + _render_findings(report.get("findings", []))
        title = f"Panopticon — {_escape(report.get('meta', {}).get('target', 'report'))}"
    return _html_doc(title, body)
```

Add CSS:

```css
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
```

Add classes to `_render_card` delta badge:

Change the `delta_badge` line to:

```python
        delta_badge = f"<span class='badge delta-{_escape(delta.replace(' ', '-'))}-badge'>{_escape(delta)}</span>"
```

- [ ] **Step 3: Run tests**

Run: `pytest tests/test_html_report.py -v`

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add scripts/html_report.py tests/test_html_report.py
git commit -m "feat(html): add side-by-side compare mode with stable fingerprints"
```

---

### Task 6: Wire `--html-out` and `--compare` into `synthesize.py`

**Files:**
- Modify: `scripts/synthesize.py`
- Test: `tests/test_synthesize.py` (add CLI tests)

**Interfaces:**
- Consumes: CLI args and `scripts/html_report.write_html`.
- Produces: HTML artifact written to disk.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_synthesize.py`:

```python
class TestHtmlOut(unittest.TestCase):
    def test_html_out_writes_file(self):
        with tempfile.TemporaryDirectory() as d:
            out_json = os.path.join(d, "report.json")
            out_html = os.path.join(d, "report.html")
            finding = os.path.join(d, "findings-x-code.json")
            with open(finding, "w") as fh:
                json.dump({"findings": [{"id": "CODE-001", "title": "x", "severity": "LOW",
                                          "panel": "code", "category": "style",
                                          "location": {"file": "a.py", "line_start": 1}}]}, fh)
            rc = syn.main(["--target", "test", "--out", out_json, "--html-out", out_html, finding])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(out_html))
            with open(out_html) as fh:
                self.assertIn("<!DOCTYPE html>", fh.read())

    def test_compare_mode_writes_html(self):
        with tempfile.TemporaryDirectory() as d:
            a = os.path.join(d, "a.json")
            b = os.path.join(d, "b.json")
            out = os.path.join(d, "compare.html")
            for path, findings in [(a, []), (b, [{"id": "CODE-001", "title": "x", "severity": "LOW",
                                                   "panel": "code", "category": "style",
                                                   "location": {"file": "a.py", "line_start": 1}}])]:
                with open(path, "w") as fh:
                    json.dump({
                        "meta": {"target": "t", "review_type": "repo", "timestamp": "2026-08-01",
                                 "version": "3.0.0", "security_mode": "standard"},
                        "summary": {"overall_grade": "A", "risk_level": "LOW", "top_issues": [],
                                    "effort_to_remediate": "LOW", "gate": "PASS",
                                    "stats": {"critical": 0, "high": 0, "medium": 0, "low": len(findings), "info": 0}},
                        "groups": [], "findings": findings,
                        "cross_panel": {"integration_findings": []},
                        "recommendations": {"immediate": [], "short_term": [], "long_term": []},
                    }, fh)
            rc = syn.main(["--compare", a, b, "--html-out", out])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(out))
            with open(out) as fh:
                content = fh.read()
                self.assertIn("new", content)
```

Run: `pytest tests/test_synthesize.py::TestHtmlOut -v`

Expected: FAIL.

- [ ] **Step 2: Add CLI flags and HTML wiring**

Add import near top of `scripts/synthesize.py`:

```python
import scripts.html_report as html_report
```

In `main`, update argparse:

```python
    ap.add_argument("--html-out", metavar="PATH", default=None,
                    help="Write HTML report to PATH")
    ap.add_argument("--compare", metavar="JSON", nargs=2, default=None,
                    help="Compare two JSON reports and emit HTML")
```

Add helper `_derive_html_path(json_path)`:

```python
def _derive_html_path(json_path):
    if json_path.endswith(".json"):
        return json_path + ".html"
    return os.path.join(json_path, "report.html")
```

In `main`, before the existing logic, handle compare mode:

```python
    if args.compare:
        a_path, b_path = args.compare
        with open(a_path, encoding="utf-8") as fh:
            report_a = json.load(fh)
        with open(b_path, encoding="utf-8") as fh:
            report_b = json.load(fh)
        html_out = args.html_out or _derive_html_path(args.out) if args.out else None
        if not html_out:
            ap.error("--compare requires --html-out or --out")
        html_report.write_html(report_b, html_out, compare_report=report_a)
        print("Compare HTML: %s" % html_out)
        return 0
```

After `paths = write_report(report, out)`:

```python
    html_out = args.html_out
    if html_out is None and args.out:
        html_out = _derive_html_path(paths[0])
    if html_out:
        html_report.write_html(report, html_out)
        print("HTML artifact: %s" % html_out)
```

Add `write_html` to `scripts/html_report.py`:

```python
def write_html(report, path, compare_report=None):
    """Write a rendered HTML report to disk."""
    os.makedirs(os.path.dirname(os.path.abspath(path)) if os.path.dirname(path) else ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render(report, compare_report=compare_report))
```

- [ ] **Step 3: Run tests**

Run: `pytest tests/test_synthesize.py::TestHtmlOut -v`

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add scripts/synthesize.py tests/test_synthesize.py scripts/html_report.py
git commit -m "feat(html): wire --html-out and --compare into synthesize.py"
```

---

### Task 7: Full verification

**Files:**
- All of the above.

- [ ] **Step 1: Run the full test suite**

Run: `pytest -q`

Expected: all tests pass.

- [ ] **Step 2: Run lint**

Run: `ruff check .`

Expected: clean.

- [ ] **Step 3: Generate a sample HTML report**

Run:

```bash
python scripts/synthesize.py --target psyberone/panopticon \
  --out .panopticon/sample-report.json \
  --html-out .panopticon/sample-report.html \
  tests/fixtures/*-findings.json 2>/dev/null || true
```

If no fixture findings files exist, create a tiny manual JSON:

```bash
mkdir -p .panopticon
cat > .panopticon/demo-findings.json <<'EOF'
{"findings": [{"id": "CODE-001", "title": "Demo issue", "severity": "HIGH", "confidence": "CERTAIN",
  "panel": "code", "category": "structure", "location": {"file": "demo.py", "line_start": 5},
  "description": "A demo finding for layout verification.", "impact": "Low", "remediation": "Fix it."}]}
EOF
python scripts/synthesize.py --target demo --out .panopticon/demo.json --html-out .panopticon/demo.html .panopticon/demo-findings.json
```

Open `.panopticon/demo.html` in a browser and verify the dashboard, tabs, cards, and heatmap render.

- [ ] **Step 4: Generate a sample compare report**

```bash
python scripts/synthesize.py --compare .panopticon/demo.json .panopticon/demo.json \
  --html-out .panopticon/demo-compare.html
```

Verify both columns render and deltas are labeled `unchanged`.

- [ ] **Step 5: Commit any sample artifacts?**

Do **not** commit sample artifacts. Add `.panopticon/` to `.gitignore` if it is not already ignored, then:

```bash
git status
```

Only source/test files should be modified/added.

- [ ] **Step 6: Final commit**

```bash
git add docs/superpowers/plans/2026-08-01-html-report.md  # if not already committed
git commit -m "feat(html): complete self-contained HTML report renderer"
```

---

## Spec Coverage Checklist

| Spec requirement | Task(s) |
|---|---|
| `--html-out PATH` in `synthesize.py` | Task 6 |
| Auto-derive HTML path from JSON output | Task 6 |
| `--compare A.json B.json` | Task 6 |
| Dashboard: grade, risk, gate badges | Task 2 |
| Severity stat cards | Task 2 |
| Panel grades table | Task 2 |
| File heatmap | Task 4 |
| Top issues | Task 2 |
| Severity tabs (`ALL` + 5 levels) | Task 3 |
| Collapsible finding cards | Task 3 |
| Card details: description, impact, remediation, references, citations, CVSS | Task 3 |
| Provenance chips | Task 3 |
| Compare: side-by-side dashboards | Task 5 |
| Compare: delta summary cards | Task 5 |
| Compare: two-column finding list | Task 5 |
| Stable SHA fingerprint ignoring line numbers | Task 5 |
| Self-contained single HTML file | Tasks 1–5 |
| Vanilla HTML/CSS/JS | Tasks 1–5 |
| HTML escaping for safety | Tasks 1, 3 |
| Tests for rendering, compare, escaping | Tasks 1–6 |

## Placeholder Scan

No `TBD`, `TODO`, or vague steps remain. Every task includes exact file paths, function signatures, code blocks, test commands, and expected outcomes.
