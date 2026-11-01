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


def _names(value):
    """A set of tool names from a list of strings, or None if not a list."""
    if not isinstance(value, list):
        return None
    return {name for name in value if isinstance(name, str) and name}


def stated(doc):
    """ONE document's cell statement. Each key is None when the document does not state it:
    `missing_floor` and `reviewed` ((group, domain) pairs), `file_groups` ({file: {group}}),
    `tools_ran` ({tool})."""
    coverage = doc
    for key in ("meta", "coverage"):
        coverage = coverage.get(key) if isinstance(coverage.get(key), dict) else {}
    cells = coverage.get("cells") if isinstance(coverage.get("cells"), dict) else {}
    return {"missing_floor": _pairs(cells.get("missing_floor")),
            "reviewed": _pairs(cells.get("reviewed")),
            "file_groups": _file_groups(doc), "tools_ran": _names(coverage.get("tools_ran"))}


def merge(base, part):
    """A part WIDENS what the main document stated, never supplies what it omitted -- the same rule
    `reconcile.load_report` applies to `groups[].files`."""
    out = dict(base)
    for key in ("missing_floor", "reviewed", "tools_ran"):
        if base[key] is not None and part[key] is not None:
            out[key] = base[key] | part[key]
    if base["file_groups"] is not None and part["file_groups"] is not None:
        merged = {k: set(v) for k, v in base["file_groups"].items()}
        for path, names in part["file_groups"].items():
            merged.setdefault(path, set()).update(names)
        out["file_groups"] = merged
    return out


LOST_FLOOR = ("run3 lost floor cell (%s, %s) for %s's group -- absence of findings from a review "
              "that never happened is not a fix")


NOT_REVIEWED = ("run3 did not complete a %s review of %s's group -- absence of findings from a "
                "review that never happened is not a fix")
TOOLS_UNSTATED = ("run3 does not state which tools ran -- a %s finding's fix needs %s to have run "
                  "again")
TOOL_NOT_RUN = "run3 did not run %s -- absence of its findings is not a fix"
UNMEASURED = "; run3 did not measure completed cells, so only lost floor cells were checked"


def _lost(file_, domain, cells):
    """#2084: the finding's file is in a group whose floor cell for its domain was lost."""
    if not cells.get("missing_floor") or not cells.get("file_groups"):
        return None
    lost = sorted(g for g in cells["file_groups"].get(file_, ())
                  if (g, domain) in cells["missing_floor"])
    return (LOST_FLOOR % (lost[0], domain, file_), "scope") if lost else None


def _uncompleted(file_, domain, cells):
    """#2087: when run-3 measured its completed cells, an agent finding's (group, domain) must be
    among them for some group holding its file. A finding with no domain matches no cell."""
    if cells.get("reviewed") is None:
        return None
    groups = (cells.get("file_groups") or {}).get(file_, ())
    if any((g, domain) in cells["reviewed"] for g in groups):
        return None
    return NOT_REVIEWED % (domain or "(no domain)", file_), "scope"


def _tool_unrun(tool, cells):
    """#2087: a tool finding's fix is only corroborated by the same tool running again."""
    if cells.get("tools_ran") is None:
        return TOOLS_UNSTATED % (tool, tool), "scope"
    return None if tool in cells["tools_ran"] else (TOOL_NOT_RUN % tool, "scope")


def refusal(file_, domain, tool, cells):
    """(reason, "scope") when run-3's cells cannot corroborate this finding's close, else None.

    `cells` None (a caller that states nothing) refuses nothing. A tool finding (`tool` set) needs
    its tool in `tools_ran`; an agent finding needs its cell not lost and, when run-3 measured
    `reviewed`, completed."""
    if cells is None:
        return None
    if tool:
        return _tool_unrun(tool, cells)
    return _lost(file_, domain, cells) or _uncompleted(file_, domain, cells)


def close_note(tool, cells):
    """The disclosure a close carries when run-3 never measured its completed cells."""
    if cells is None or tool or cells.get("reviewed") is not None:
        return ""
    return UNMEASURED
