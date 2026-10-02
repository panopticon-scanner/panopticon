"""Human disclosures for structured scanner-container cleanup failures.

The report's Markdown and HTML views show the same repaired coverage block.
This module owns their shared row selection, display cap, and JSON quoting so
target-writable tool names or details cannot forge a line or HTML element.
"""
from collections.abc import Callable
import json


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


def markdown_line(value: object, code_span: Callable[[str], str]) -> str:
    """One bounded Markdown coverage line, or empty when no valid row exists."""
    found = rows(value)
    if not found:
        return ""
    shown = ["%s (%s): %s" % tuple(
        code_span(json.dumps(field, ensure_ascii=False)) for field in row)
        for row in found[:ROWS_SHOWN]]
    if len(found) > len(shown):
        shown.append("and %d more (see meta.coverage.tools_cleanup_failures)"
                     % (len(found) - len(shown)))
    return "**Tool container cleanup incomplete:** " + "; ".join(shown)


def html_block(meta: object, escape: Callable[[str], str]) -> str:
    """One bounded HTML coverage block, or empty when no valid row exists."""
    coverage = meta.get("coverage") if isinstance(meta, dict) else None
    value = (coverage.get("tools_cleanup_failures")
             if isinstance(coverage, dict) else None)
    found = rows(value)
    if not found:
        return ""
    shown = ["<code>%s</code> (<code>%s</code>): <code>%s</code>" % tuple(
        escape(json.dumps(field, ensure_ascii=False)) for field in row)
        for row in found[:ROWS_SHOWN]]
    if len(found) > len(shown):
        shown.append("and %d more (see meta.coverage.tools_cleanup_failures)"
                     % (len(found) - len(shown)))
    return ("<div class='coverage'>Tool container cleanup incomplete: %s</div>"
            % " &middot; ".join(shown))
