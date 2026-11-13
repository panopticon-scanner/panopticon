"""Native-language Semgrep parser gaps and targeted SEC review (#3611).

The Semgrep adapter is the producer: it sees every syntax-error path before
the ordinary disclosure cap and records the native subset.  Review dispatch
and synthesis are independent consumers of the same small, strict fact shape.
"""
from __future__ import annotations

from scripts import native_language


# The bound protects reviewer attention, not a language percentage.  Semgrep's
# Bash parser rejects several ordinary files in real shell-heavy repositories;
# a proportional rule therefore punished exactly the scanner limitation #3611
# is meant to route around.  Twenty or fewer may certify when every file gets
# a completed SEC review; the twenty-first is a scanner-coverage failure.
MAX_TARGETED_REVIEW_FILES = 20

FACT_KEYS = frozenset({
    "native_syntax_files", "native_syntax", "native_syntax_files_omitted",
    "native_syntax_unknown",
})
ROW_KEYS = frozenset({"file", "language"})
_LANGUAGES = frozenset(native_language.EXT_LANG.values())


def _repo_path(value):
    return native_language.repo_path(value)


def _classification(root, rel):
    """``(known, language)``; language is None for a known non-native file."""
    return native_language.classify(root, rel)


def producer_facts(root, syntax_paths):
    """Build the bounded native subset from all located syntax-error paths."""
    rows = []
    unknown = 0
    for path in sorted(set(syntax_paths or ())):
        known, language = _classification(root, path)
        if not known:
            unknown += 1
        elif language is not None:
            rows.append({"file": path, "language": language})
    count = len(rows)
    listed = rows[:MAX_TARGETED_REVIEW_FILES]
    return {
        "native_syntax_files": count,
        "native_syntax": listed,
        "native_syntax_files_omitted": count - len(listed),
        "native_syntax_unknown": unknown,
    }


def fact_shape_valid(facts):
    """Whether the producer fields are complete and internally exact."""
    if not isinstance(facts, dict) or not FACT_KEYS <= set(facts):
        return False
    count = facts.get("native_syntax_files")
    rows = facts.get("native_syntax")
    omitted = facts.get("native_syntax_files_omitted")
    unknown = facts.get("native_syntax_unknown")
    if not (type(count) is int and count >= 0
            and type(omitted) is int and omitted >= 0
            and type(unknown) is int and unknown >= 0
            and isinstance(rows, list)
            and len(rows) <= MAX_TARGETED_REVIEW_FILES
            and count == len(rows) + omitted):
        return False
    expected_listed = min(count, MAX_TARGETED_REVIEW_FILES)
    if len(rows) != expected_listed or omitted != count - expected_listed:
        return False
    names = []
    for row in rows:
        if not (isinstance(row, dict) and set(row) == ROW_KEYS
                and _repo_path(row.get("file"))
                and row.get("language") in _LANGUAGES):
            return False
        names.append(row["file"])
    if names != sorted(names) or len(names) != len(set(names)):
        return False
    total_syntax = facts.get("syntax_error_files")
    if total_syntax is not None and not (
            type(total_syntax) is int and total_syntax >= count + unknown):
        return False
    return True


def read_facts(root, facts):
    """Validate producer facts and reclassify every published path."""
    if not fact_shape_valid(facts):
        return None
    rows = facts["native_syntax"]
    for row in rows:
        known, language = _classification(root, row["file"])
        if not known or language != row["language"]:
            return None
    # When the ordinary file-gap listing is complete and its paths were not
    # presentation-truncated, independently rebuild the producer fields from
    # every disclosed syntax path.  This catches a forged/buggy producer that
    # simply omits a native file while keeping an otherwise plausible count.
    gap_rows = facts.get("files")
    if isinstance(gap_rows, list) and facts.get("files_omitted") == 0:
        syntax_paths = []
        can_rebuild = True
        for gap in gap_rows:
            if not (isinstance(gap, dict)
                    and type(gap.get("syntax_errors", 0)) is int):
                can_rebuild = False
                break
            if gap.get("syntax_errors", 0) <= 0:
                continue
            path = gap.get("file")
            # legacy_sarif bounds displayed paths at 239 characters and adds a
            # cut marker.  Such a spelling has lost identity, so it cannot be
            # used for this optional reconstruction.
            if not isinstance(path, str) or not _repo_path(path) or len(path) >= 239:
                can_rebuild = False
                break
            syntax_paths.append(path)
        if can_rebuild:
            rebuilt = producer_facts(root, syntax_paths)
            if any(facts.get(key) != rebuilt[key] for key in FACT_KEYS):
                return None
    count = facts["native_syntax_files"]
    return {
        "count": count,
        "files": [dict(row) for row in rows],
        "files_omitted": facts["native_syntax_files_omitted"],
        "unknown": facts["native_syntax_unknown"],
        "over_cap": count > MAX_TARGETED_REVIEW_FILES,
    }


def targets_by_group(state, groups):
    """Sorted SEC target paths by every matrix group that covers them."""
    if not isinstance(state, dict) or state.get("over_cap") or state.get("unknown"):
        return {}
    wanted = [row["file"] for row in state.get("files") or ()
              if isinstance(row, dict) and _repo_path(row.get("file"))]
    routed = {}
    for group in groups or ():
        if not (isinstance(group, dict) and isinstance(group.get("name"), str)
                and group["name"] and isinstance(group.get("files"), list)):
            continue
        owned = set(path for path in group["files"] if isinstance(path, str))
        targets = sorted(path for path in wanted if path in owned)
        if targets:
            routed[group["name"]] = targets
    return dict(sorted(routed.items()))


def reconcile(state, groups, plan_entries, attestations):
    """Return ``(report block, certification-gap reason)`` for target review.

    The plan proves what the controller dispatched; the findings envelope's
    exact echo proves what a completed SEC cell says it manually reviewed.
    Neither can substitute for the other.
    """
    if not isinstance(state, dict):
        return None, None
    groups = [group for group in (groups or ()) if isinstance(group, dict)]
    routed = targets_by_group(state, groups)
    sec_cells = {
        (entry.get("group"), "SEC") for entry in (plan_entries or ())
        if isinstance(entry, dict) and entry.get("domain") == "SEC"
        and isinstance(entry.get("group"), str) and entry.get("group")
    }
    expected = {(group, "SEC"): tuple(paths) for group, paths in routed.items()
                if (group, "SEC") in sec_cells}
    declared = {}
    for entry in plan_entries or ():
        if not isinstance(entry, dict) or entry.get("domain") != "SEC":
            continue
        targets = entry.get("targeted_review")
        if isinstance(targets, list) and targets:
            declared[(entry.get("group"), "SEC")] = tuple(targets)
    dispatch_valid = declared == expected

    attested = attestations if isinstance(attestations, dict) else {}
    attestations_valid = all(
        not paths or tuple(paths) == declared.get(cell, ())
        for cell, paths in attested.items()
        if isinstance(cell, tuple) and len(cell) == 2)

    file_groups: dict[str, set[str]] = {}
    for group in groups:
        name, files = group.get("name"), group.get("files")
        if not (isinstance(name, str) and isinstance(files, list)):
            continue
        for path in files:
            if isinstance(path, str):
                file_groups.setdefault(path, set()).add(name)

    files = []
    uncovered = []
    for row in state.get("files") or ():
        path = row["file"]
        possible = sorted((group, "SEC") for group in file_groups.get(path, set())
                          if (group, "SEC") in sec_cells)
        dispatched = [list(cell) for cell in possible
                      if path in declared.get(cell, ())]
        covered = [list(cell) for cell in possible
                   if declared.get(cell) == expected.get(cell)
                   and tuple(attested.get(cell, ())) == expected.get(cell)
                   and path in expected.get(cell, ())]
        files.append({**row, "dispatched_to": dispatched, "covered_by": covered})
        if not state.get("over_cap") and not covered:
            uncovered.append(path)

    block = {
        "native_unparsed": state.get("count", 0),
        "files": files,
        "files_omitted": state.get("files_omitted", 0),
        "classification_unknown": state.get("unknown", 0),
        "cap": MAX_TARGETED_REVIEW_FILES,
        "over_cap": bool(state.get("over_cap")),
        "dispatch_valid": dispatch_valid,
        "attestations_valid": attestations_valid,
    }
    reasons = []
    if state.get("over_cap"):
        reasons.append("native Semgrep parser gaps exceed the targeted-review cap "
                       "(%d > %d)" % (state.get("count", 0),
                                      MAX_TARGETED_REVIEW_FILES))
    if state.get("unknown"):
        reasons.append("%d Semgrep parser-gap file(s) could not be classified "
                       "as native or non-native" % state["unknown"])
    if not dispatch_valid:
        reasons.append("targeted-review dispatch did not match the native parser gaps")
    if not attestations_valid:
        reasons.append("a review cell returned an invalid targeted-review attestation")
    if uncovered:
        reasons.append("native Semgrep parser gap(s) not covered by completed SEC "
                       "review: %s" % ", ".join(uncovered))
    return block, "; ".join(reasons) or None
