# Panopticon HTML Report Renderer — Design

> **Goal:** Convert the final `CodeReviewReport` JSON into a professional, self-contained HTML report with a dashboard, file heatmap, severity-tabbed finding cards, and a side-by-side compare mode for two result sets.

## Context

Panopticon currently emits a machine-readable `CodeReviewReport` JSON and a terminal markdown summary. The JSON is rich (grades, stats, per-group panel grades, findings with citations, cross-panel integration findings), but it is hard to consume at a glance and impossible to share with stakeholders who do not want to read raw JSON. This design adds an HTML renderer that is derived from the JSON artifact, not from intermediate findings, so it stays stable as the internal pipeline evolves.

## Constraints

- **Vanilla HTML/CSS/JS only** — no frameworks, no CDNs, no external dependencies.
- **Self-contained artifact** — one `.html` file with all CSS and JS inlined.
- **Derived from JSON** — the renderer consumes the finalized `CodeReviewReport`, not raw panel/lens outputs.
- **Zero new Python dependencies** — the renderer is stdlib-only, like `synthesize.py`.
- **Accessible and offline-friendly** — semantic HTML, keyboard-friendly tabs/cards, works when opened from disk.

## Architecture

### New module: `scripts/html_report.py`

Contains:

- `_CSS`: inline stylesheet string using CSS custom properties for severity colors.
- `_JS`: inline script string for tab switching, card expand/collapse, and compare-mode filtering.
- `_fingerprint(finding)`: compute a stable SHA-256 hash for cross-run matching.
- `render(report: dict, compare_report: dict | None = None) -> str`: produce the full HTML document.
- `write_html(report, path, compare_report=None)`: convenience wrapper.

### CLI integration in `synthesize.py`

Add two flags:

- `--html-out PATH` — write the HTML report to `PATH`.
  - If omitted and `--out` ends in `.json`, derive `<out>.html`.
  - If `--out` is a directory, write `report.html` inside it.
- `--compare A.json B.json` — read two existing JSON reports and emit a compare HTML to `--html-out`.
  - In compare mode synthesis is skipped; the renderer receives both reports.

Example usage:

```bash
# Normal review emits JSON + HTML
python scripts/synthesize.py --target . --groups groups.json findings/*.json \
  --out .panopticon/report.json --html-out .panopticon/report.html

# Compare two saved reports
python scripts/synthesize.py --compare .panopticon/report-main.json .panopticon/report-branch.json \
  --html-out .panopticon/compare.html
```

## Report Layout

### 1. Header

- Target name, review type, timestamp, security mode.
- Big badges: overall grade (`A`–`F`), risk level (`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`), gate (`PASS`/`FAIL`/`OFF`).

### 2. Dashboard

- **Severity stat cards**: count of findings per severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
- **Panel grades table**: rows are groups, columns are panels (`code`, `test`, `security`, `architecture`, `database`, `redteam`), cells show letter grades.
- **File heatmap**: a compact grid of files colored by the worst severity found in each file. Hover/focus reveals the file path and total finding count.
- **Top 3 issues**: a short list of the highest-severity, highest-confidence findings.

### 3. Findings Section

- **Severity tabs**: `ALL`, `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`. Each tab shows a count badge.
- **Collapsible cards** (`<details>`/`<summary>`) for each finding:
  - Header: severity chip, finding ID, title, `file:line`, panel, category, confidence.
  - Expanded body:
    - Description
    - Impact
    - Remediation
    - References (links)
    - Citations: CWE, OWASP, SSVC, CVE, EPSS scores
    - CVSS score/vector and exploit scenario (for `security`/`redteam` findings)
    - Provenance chip: `agent`, `tool`, `reinforced`, or `corroborated`

## Compare Mode

When `--compare A.json B.json` is used:

- **A/B dashboards** appear side by side at the top.
- **Delta summary cards** show:
  - New findings (present in B, not A)
  - Resolved findings (present in A, not B)
  - Unchanged findings
  - Severity shifts (same fingerprint, different severity)
- **Two-column finding list** with Report A on the left and Report B on the right.
- Each finding is annotated with a badge: `new`, `resolved`, `unchanged`, or `severity changed`.

### Stable fingerprint for matching

Findings are matched across reports with:

```python
sha256(panel + "|" + category + "|" + normalized_file_path + "|" + title + "|" + description)
```

Line numbers are intentionally excluded so a finding that moves in the file is still recognized as the same issue.

## Technical Details

- **Single file output**: all CSS and JS are embedded in `<style>` and `<script>` tags. No external requests.
- **CSS custom properties** define the severity color palette so a dark theme or brand palette is a single edit.
- **Vanilla JS** handles:
  - Tab activation and ARIA attributes.
  - “Expand all / collapse all” buttons.
  - Compare-mode filter toggles (show all / only deltas).
- **Security**: the renderer HTML-escapes all user-controlled strings (titles, descriptions, file paths) to prevent XSS when opening reports generated from untrusted code.
- **Large reports**: the heatmap shows the top 50 files by finding count with a “show more” link; tabs keep the DOM manageable by default.

## Schema Impact

No schema changes. The renderer consumes the existing `CodeReviewReport` format defined in `reference/report-schema.json`. It uses:

- `meta`, `summary`, `groups`, `findings`, `cross_panel`, `recommendations`
- Optional finding fields (`cvss`, `exploit_scenario`, `citations`, `source`, `reinforced`, `corroborated`) are rendered when present.

## Testing

Add tests under `tests/test_html_report.py`:

- Render a minimal valid `CodeReviewReport` and assert the output contains expected dashboard elements and finding titles.
- Assert the output is a complete HTML document with inline CSS/JS and no external links.
- Test severity tab counts match `summary.stats`.
- Test `--compare` produces delta badges for new and resolved findings using a controlled fingerprint.
- Test HTML escaping for findings containing `<script>` in descriptions.

## Success Criteria

- `synthesize.py --html-out report.html` produces a single self-contained HTML file from any valid `CodeReviewReport`.
- The dashboard gives a clear big-picture view: grade, risk, gate, severity counts, panel grades, and file heatmap.
- Every finding appears as a collapsible card with full details and citations.
- `--compare A.json B.json` produces a side-by-side report that correctly labels new, resolved, unchanged, and severity-shifted findings.
- All renderer code is covered by tests and passes the existing `ruff` lint gate.

## Out of Scope

- Server-side or interactive backends.
- PDF export.
- Theming/UI customization flags beyond the default severity palette.
- Changing the JSON report schema or how findings are assigned IDs.
