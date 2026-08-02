# HTML Report Dashboard Charts Design

## Goal

Make the existing `scripts/html_report.py` report feel more professional and scannable by adding CSS-only dashboard charts that surface the big picture at a glance: severity distribution, panel breakdown, and top-category breakdown.

## Scope

In scope for this first pass:
- Add three CSS-only bar charts to the single-report dashboard:
  1. **Severity distribution** — counts of findings per severity (CRITICAL, HIGH, MEDIUM, LOW, INFO).
  2. **Panel breakdown** — counts of findings per review panel (code, test, security, architecture, database, redteam).
  3. **Top-category breakdown** — counts for the top N finding categories (default 8), plus an "Other" bucket.
- Keep all existing report features intact: file heatmap, group grades table, top issues, severity-tabbed findings list, collapsible cards, A/B compare mode.
- Stay as close to vanilla HTML/CSS as possible: charts are rendered with `div`-based bars and percentage widths; no external charting libraries, no canvas, no SVG.
- Extend `tests/test_html_report.py` to assert chart presence and values.

Out of scope for this first pass:
- Charts in A/B compare mode (existing delta cards and side-by-side lists remain).
- Search, filter, or sort controls for findings.
- Dark mode, print styles, or responsive redesign.
- Trend/historical sparklines.

## Architecture

The change is confined to `scripts/html_report.py` and its tests.

```
CodeReviewReport JSON
        │
        ▼
Aggregate functions (_chart_data_*)
        │
        ▼
Render functions (_render_*_chart) emit plain HTML divs
        │
        ▼
_dashboard() includes the new charts above the existing heatmap
```

### Aggregation functions

- `_severity_counts(findings)` → `{CRITICAL: n, HIGH: n, MEDIUM: n, LOW: n, INFO: n}`
- `_panel_counts(findings, panel_order)` → `{panel: n, ...}`
- `_top_category_counts(findings, limit=8)` → `[(category, count), ...]` plus an "Other" tuple if needed.

All functions tolerate missing/empty input and return zeroed dicts/lists.

### Chart rendering

Each chart is a horizontal bar chart:

```html
<div class="chart">
  <div class="chart-row">
    <span class="chart-label">HIGH</span>
    <div class="chart-bar-wrap">
      <div class="chart-bar sev-high" style="width: 45%"></div>
    </div>
    <span class="chart-value">9</span>
  </div>
  ...
</div>
```

Widths are computed as `count / max_count * 100`. If all counts are zero, every bar is 0% width and the chart still renders.

### CSS additions

Add the following to the existing `_CSS` block:

- `.chart` container with a light background, border, and padding.
- `.chart-row` as a flex row: label, bar wrap, value.
- `.chart-bar-wrap` as the track (fixed height, subtle background).
- `.chart-bar` with a transition and severity/panel color classes.
- `.chart-label` and `.chart-value` with fixed or minimum widths for alignment.

Reuse existing severity color variables (`--critical`, `--high`, etc.) and add panel-specific colors using the existing palette where possible.

### Integration

`_render_dashboard(report)` will insert the three charts between the stats cards and the existing file heatmap:

```
Dashboard
├── Stats cards (existing)
├── Severity chart (new)
├── Panel chart (new)
├── Top-category chart (new)
├── File heatmap (existing)
├── Grades table (existing)
└── Top issues (existing)
```

## Data model

The charts consume the existing `findings` array in the `CodeReviewReport` schema. Each finding is expected to have:

- `severity`: one of CRITICAL, HIGH, MEDIUM, LOW, INFO.
- `panel`: one of code, test, security, architecture, database, redteam.
- `category`: free-form string.

Missing fields default to INFO / code / "unknown" respectively.

## Testing

Extend `tests/test_html_report.py` with:

- `test_dashboard_renders_severity_chart`: asserts the chart container and bar widths/values are present.
- `test_dashboard_renders_panel_chart`: asserts panel labels and counts appear.
- `test_dashboard_renders_category_chart`: asserts top categories and an "Other" bucket when appropriate.
- `test_charts_handle_empty_findings`: asserts charts render without error when `findings` is empty.

All tests remain stdlib-only and match the existing style.

## Global constraints

- Python 3.11+, stdlib only.
- Line length 100, ruff rules `E`, `F`, `W` with ignores `E401`, `E501`, `E701`, `E702`.
- No breaking changes to the `CodeReviewReport` schema or the `write_html` / `render` public API.
- Self-contained HTML output (no external assets).
