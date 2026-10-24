"""Shared human rendering for bounded tool-coverage disclosures.

The report's Markdown and HTML views show the same repaired coverage blocks.
This module owns their shared row selection and bounds so neither view drifts.
"""
from collections.abc import Callable
import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scripts import language_detection
else:
    try:
        from scripts import language_detection
    except ModuleNotFoundError:  # standalone html_report import
        import language_detection


ROWS_SHOWN = 5


def rows(value: object) -> list[tuple[str, str, str]]:
    """Valid, sorted `(tool, kind, detail)` rows from a repaired block."""
    if not isinstance(value, dict):
        return []
    kept = []
    for tool, row in sorted(value.items()):
        if (not isinstance(tool, str) or not tool or not isinstance(row, dict)
                or not isinstance(row.get("kind"), str) or not row["kind"]
                or not isinstance(row.get("detail"), str) or not row["detail"]):
            continue
        kept.append((tool, row["kind"], row["detail"]))
    return kept


def markdown_line(value: object, code_span: Callable[[str], str],
                  language_skips: object = None) -> str:
    """The bounded Markdown tool-disclosure lines."""
    lines = []
    skipped = language_detection.display_skip_rows(language_skips)
    if skipped:
        lines.append("**Language-keyed scanners not selected:** " + "; ".join(
            "%s → %s (%s)" % (row["language"], row["tool"], row["reason"])
            for row in skipped))
    found = rows(value)
    if found:
        shown = ["%s (%s): %s" % tuple(
            code_span(json.dumps(field, ensure_ascii=False)) for field in row)
            for row in found[:ROWS_SHOWN]]
        if len(found) > len(shown):
            shown.append("and %d more (see meta.coverage.tools_cleanup_failures)"
                         % (len(found) - len(shown)))
        lines.append("**Tool container cleanup incomplete:** " + "; ".join(shown))
    return "\n".join(lines)


def html_block(meta: object, escape: Callable[[str], str]) -> str:
    """The bounded HTML tool-disclosure blocks."""
    coverage = meta.get("coverage") if isinstance(meta, dict) else None
    parts = []
    skipped = language_detection.display_skip_rows(
        coverage.get("language_detection_skips") if isinstance(coverage, dict) else None)
    if skipped:
        shown_skips = " &middot; ".join(
            "%s &rarr; %s (%s)" % tuple(escape(row[key]) for key in
                                         ("language", "tool", "reason"))
            for row in skipped)
        parts.append("<div class='coverage'>Language-keyed scanners not selected: "
                     "%s</div>" % shown_skips)
    value = (coverage.get("tools_cleanup_failures")
             if isinstance(coverage, dict) else None)
    found = rows(value)
    if found:
        shown = ["<code>%s</code> (<code>%s</code>): <code>%s</code>" % tuple(
            escape(json.dumps(field, ensure_ascii=False)) for field in row)
            for row in found[:ROWS_SHOWN]]
        if len(found) > len(shown):
            shown.append("and %d more (see meta.coverage.tools_cleanup_failures)"
                         % (len(found) - len(shown)))
        parts.append("<div class='coverage'>Tool container cleanup incomplete: "
                     "%s</div>" % " &middot; ".join(shown))
    return "".join(parts)
