# HTML Report Dashboard Charts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add CSS-only dashboard charts to `scripts/html_report.py` so the single-report view surfaces severity distribution, panel breakdown, and top-category breakdown at a glance.

**Architecture:** Extend the existing self-contained renderer with pure-Python aggregation functions and `div`-based bar charts. Charts are rendered with inline percentage widths, styled by the existing CSS block, and inserted into the current dashboard layout without changing the public `render()` / `write_html()` API.

**Tech Stack:** Python 3.11+ stdlib only; vanilla HTML/CSS/JS (no charting libraries).

## Global Constraints

- Python 3.11+, stdlib only.
- Target line length 100, ruff rules `E`, `F`, `W` with ignores `E401`, `E501`, `E701`, `E702`.
- No breaking changes to the `CodeReviewReport` schema or the `write_html` / `render` public API.
- Self-contained HTML output (no external assets).
- Keep all existing report features intact: file heatmap, group grades table, top issues, severity-tabbed findings list, collapsible cards, A/B compare mode.

---

### Task 1: Add aggregation functions

**Files:**
- Modify: `scripts/html_report.py`
- Test: `tests/test_html_report.py`

**Interfaces:**
- Consumes: `findings` list from a `CodeReviewReport`.
- Produces: `_severity_counts(findings)`, `_panel_counts(findings)`, `_top_category_counts(findings, limit=8)`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_html_report.py`:

```python
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
```

Run: `pytest tests/test_html_report.py::TestChartAggregations -v`
Expected: FAIL (functions not defined).

- [ ] **Step 2: Implement the aggregation functions**

Add to `scripts/html_report.py` after `_PANEL_ORDER`:

```python
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
```

- [ ] **Step 3: Run tests**

Run: `pytest tests/test_html_report.py::TestChartAggregations -v`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add scripts/html_report.py tests/test_html_report.py
git commit -m "feat(html): add dashboard chart aggregation functions"
```

---

### Task 2: Add chart CSS, render functions, and dashboard integration

**Files:**
- Modify: `scripts/html_report.py`
- Test: `tests/test_html_report.py`

**Interfaces:**
- Consumes: aggregation functions from Task 1.
- Produces: `_render_bar_chart(rows, color_class_fn, title)`, `_render_dashboard` includes charts.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_html_report.py`:

```python
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
        self.assertNotIn("sev-high", out)
```

Run: `pytest tests/test_html_report.py::TestDashboardCharts -v`
Expected: FAIL.

- [ ] **Step 2: Add panel color helper and chart CSS**

Add after `_gate_class`:

```python
def _panel_class(panel):
    """Map a panel name to a CSS class, stripping non-alphanumeric chars."""
    clean = "".join(c for c in str(panel) if c.isalnum()).lower()
    return f"panel-{clean}"
```

Add panel color variables and chart CSS to `_CSS` (after the existing `:root` block or merged into it):

```css
:root {
  --panel-code: #0d6efd;
  --panel-test: #20c997;
  --panel-security: #dc3545;
  --panel-architecture: #6f42c1;
  --panel-database: #fd7e14;
  --panel-redteam: #d63384;
  --panel-unknown: #6c757d;
}
.panel-code { background: var(--panel-code); }
.panel-test { background: var(--panel-test); }
.panel-security { background: var(--panel-security); }
.panel-architecture { background: var(--panel-architecture); }
.panel-database { background: var(--panel-database); }
.panel-redteam { background: var(--panel-redteam); }
.panel-unknown { background: var(--panel-unknown); }
.chart { background: var(--card); border: 1px solid var(--border); border-radius: .5rem; padding: 1rem; margin: 1rem 0; }
.chart h3 { margin-top: 0; margin-bottom: .75rem; }
.chart-rows { display: flex; flex-direction: column; gap: .5rem; }
.chart-row { display: flex; align-items: center; gap: .5rem; }
.chart-label { min-width: 6.5rem; font-weight: 600; text-align: right; }
.chart-bar-wrap { flex: 1; background: #e9ecef; border-radius: .25rem; height: 1.25rem; overflow: hidden; }
.chart-bar { height: 100%; border-radius: .25rem; transition: width .3s ease; min-width: 2px; }
.chart-value { min-width: 2rem; text-align: right; font-weight: 600; }
```

- [ ] **Step 3: Implement chart rendering and integrate into dashboard**

Add after `_render_dashboard` helpers:

```python
def _render_bar_chart(rows, color_class_fn, title):
    """Render a horizontal bar chart from (label, count) rows."""
    if not rows:
        return ""
    max_count = max(count for _, count in rows)
    if max_count == 0:
        max_count = 1
    row_html = []
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
```

Modify `_render_dashboard` to include charts after the stats cards and before the heatmap. Replace the existing return body with:

```python
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
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_html_report.py -v`
Expected: PASS.

Run: `ruff check scripts/html_report.py tests/test_html_report.py`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add scripts/html_report.py tests/test_html_report.py
git commit -m "feat(html): add CSS-only dashboard charts"
```

---

### Task 3: Full verification and push

**Files:**
- All of the above.

- [ ] **Step 1: Run the full test suite**

Run: `python3 -m pytest -q`
Expected: all tests pass.

- [ ] **Step 2: Run lint**

Run: `ruff check .`
Expected: clean.

- [ ] **Step 3: Render a sample report and inspect**

Run:

```bash
python3 -c "
import json, scripts.html_report as hr
report = json.load(open('tests/fixtures/sample-report.json')) if __import__('os').path.exists('tests/fixtures/sample-report.json') else {'meta': {'target': 'demo'}, 'summary': {'overall_grade': 'B', 'risk_level': 'MEDIUM', 'top_issues': [], 'effort_to_remediate': 'MEDIUM', 'gate': 'OFF', 'stats': {'critical': 1, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}}, 'groups': [], 'findings': [{'id': 'SEC-001', 'title': 'SQLi', 'severity': 'HIGH', 'confidence': 'CERTAIN', 'panel': 'security', 'category': 'injection', 'location': {'file': 'app.py', 'line_start': 10}, 'description': 'x', 'impact': '', 'remediation': '', 'references': []}], 'cross_panel': {'integration_findings': []}, 'recommendations': {'immediate': [], 'short_term': [], 'long_term': []}}
hr.write_html(report, '/tmp/panopticon-report.html')
print('wrote /tmp/panopticon-report.html')
"
```

Expected: file written; open it locally if possible and confirm charts render.

- [ ] **Step 4: Commit and push**

```bash
git status
# only source/test/docs files modified
git push -u origin feat/html-report-charts
```

---

## Spec Coverage Checklist

| Spec requirement | Task(s) |
|---|---|
| Severity distribution chart | Task 2 |
| Panel breakdown chart | Task 2 |
| Top-category breakdown chart | Task 2 |
| CSS-only, no external libraries | Task 2 |
| Integration into dashboard | Task 2 |
| Tests for charts | Tasks 1, 2 |
| No breaking API changes | Tasks 1, 2 |
| Full verification | Task 3 |

## Placeholder Scan

No `TBD`, `TODO`, or vague steps remain. Each task includes exact file paths, function signatures, code blocks, test commands, and expected outcomes.
