"""What run-3 says it COMPLETED, per (group, domain) cell, for the cross-run diff (#2084).

`reconcile.build_diff` closes a run-2 finding only when run-3 corroborates the fix. `groups[].files`
is what run-3 PLANNED to review; a floor cell that produced no findings file
(`meta.coverage.cells.missing_floor`) is a review that never happened, and absence of findings
from it is not a fix. This module reads that statement out of a report and answers, per finding,
whether its own cell was lost.

The report is a run artifact Panopticon wrote, but it is read tolerantly: a pair that is not two
strings, or a group with no usable name or file list, contributes nothing rather than raising.
"""
import scripts.evidence as evidence


def _pairs(value):
    """A set of (group, domain) pairs from a `[[group, domain], ...]` list, or None if not a list."""
    if not isinstance(value, list):
        return None
    return {(p[0], p[1]) for p in value
            if isinstance(p, list) and len(p) == 2 and all(isinstance(x, str) and x for x in p)}


def _file_groups(doc):
    """{normalized file: {group names}} from ONE document's `groups[]`, or None if it has none."""
    groups = doc.get("groups")
    if not isinstance(groups, list):
        return None
    out: dict[str, set[str]] = {}
    for group in groups:
        if not isinstance(group, dict) or not isinstance(group.get("name"), str):
            continue
        files = group.get("files")
        for path in files if isinstance(files, list) else ():
            if isinstance(path, str) and path:
                out.setdefault(evidence.norm_path(path), set()).add(group["name"])
    return out


def stated(doc):
    """ONE document's cell statement: {"missing_floor": pairs | None, "file_groups": map | None}."""
    cells = doc
    for key in ("meta", "coverage", "cells"):
        cells = cells.get(key) if isinstance(cells.get(key), dict) else {}
    return {"missing_floor": _pairs(cells.get("missing_floor")), "file_groups": _file_groups(doc)}


def merge(base, part):
    """A part WIDENS what the main document stated, never supplies what it omitted -- the same rule
    `reconcile.load_report` applies to `groups[].files`."""
    out = dict(base)
    if base["missing_floor"] is not None and part["missing_floor"] is not None:
        out["missing_floor"] = base["missing_floor"] | part["missing_floor"]
    if base["file_groups"] is not None and part["file_groups"] is not None:
        merged = {k: set(v) for k, v in base["file_groups"].items()}
        for path, names in part["file_groups"].items():
            merged.setdefault(path, set()).update(names)
        out["file_groups"] = merged
    return out


LOST_FLOOR = ("run3 lost floor cell (%s, %s) for %s's group -- absence of findings from a review "
              "that never happened is not a fix")


def refusal(file_, domain, cells):
    """(reason, "scope") when run-3 lost the floor cell this finding's file and domain fall in,
    else None. An absent cell statement reads as no lost cell -- every report before the 5.0 audit,
    and today's behaviour for it."""
    if not cells or not cells.get("missing_floor") or not cells.get("file_groups"):
        return None
    lost = sorted(g for g in cells["file_groups"].get(file_, ())
                  if (g, domain) in cells["missing_floor"])
    if lost:
        return LOST_FLOOR % (lost[0], domain, file_), "scope"
    return None
