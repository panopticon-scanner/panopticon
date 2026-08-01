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
