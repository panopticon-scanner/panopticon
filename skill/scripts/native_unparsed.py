"""Native-language Semgrep parser gaps and targeted SEC review (#3611).

The Semgrep adapter is the producer: it sees every syntax-error path before
the ordinary disclosure cap and records the native subset.  Review dispatch
and synthesis are independent consumers of the same small, strict fact shape.
"""
from __future__ import annotations

import unicodedata

from scripts import native_language


# The bound protects reviewer attention, not a language percentage.  Semgrep's
# Bash parser rejects several ordinary files in real shell-heavy repositories;
# a proportional rule therefore punished exactly the scanner limitation #3611
# is meant to route around.  Twenty or fewer may certify when every file gets
# a completed SEC review; the twenty-first is a scanner-coverage failure.
MAX_TARGETED_REVIEW_FILES = 20
# The producer cannot know a later run's reviewed universe, so its inventory
# must be wider than the reviewer-attention cap. Reconciliation partitions
# these rows against groups.json first, then applies the 20-file cap only to
# the in-universe side (B1). A capture beyond this defensive record bound fails
# closed as unknown scope membership; ordinary out-of-scope presentation is
# independently capped at 20 below.
MAX_CLASSIFIED_NATIVE_FILES = 1000
MAX_OUT_OF_SCOPE_FILES = 20

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


def _scope_key(path):
    """Filesystem-equivalent spelling key for index/tool path comparison."""
    return unicodedata.normalize("NFC", path.casefold())


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
    listed = rows[:MAX_CLASSIFIED_NATIVE_FILES]
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
            and len(rows) <= MAX_CLASSIFIED_NATIVE_FILES
            and count == len(rows) + omitted):
        return False
    expected_listed = min(count, MAX_CLASSIFIED_NATIVE_FILES)
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
    }


def targets_by_group(state, groups):
    """Sorted SEC target paths by every matrix group that covers them."""
    if (not isinstance(state, dict) or state.get("unknown")
            or state.get("files_omitted")):
        return {}
    file_groups = _file_groups(groups)
    wanted = [row["file"] for row in state.get("files") or ()
              if isinstance(row, dict) and _repo_path(row.get("file"))
              and _groups_for_path(file_groups, row["file"])]
    if len(wanted) > MAX_TARGETED_REVIEW_FILES:
        return {}
    routed: dict[str, list[str]] = {}
    for path in wanted:
        for group in _groups_for_path(file_groups, path):
            routed.setdefault(group, []).append(path)
    return {group: sorted(paths) for group, paths in sorted(routed.items())}


def _file_groups(groups):
    """Exact and casefold+NFC reviewed paths -> their matrix groups."""
    exact: dict[str, set[str]] = {}
    normalized: dict[str, set[str]] = {}
    for group in groups or ():
        if not (isinstance(group, dict) and isinstance(group.get("name"), str)
                and group["name"] and isinstance(group.get("files"), list)):
            continue
        for path in group["files"]:
            if isinstance(path, str):
                exact.setdefault(path, set()).add(group["name"])
                normalized.setdefault(_scope_key(path), set()).add(group["name"])
    return exact, normalized


def _groups_for_path(file_groups, path):
    """Owning groups, preferring an exact spelling over equivalence."""
    if not isinstance(path, str):
        return set()
    exact, normalized = file_groups
    return exact.get(path) or normalized.get(_scope_key(path), set())


def reconcile(state, groups, plan_entries, attestations, groups_known=True):
    """Return ``(report block, certification-gap reason)`` for target review.

    The plan proves what the controller dispatched; the findings envelope's
    exact echo proves what a completed SEC cell says it manually reviewed.
    Neither can substitute for the other.
    """
    if not isinstance(state, dict):
        return None, None
    groups = [group for group in (groups or ()) if isinstance(group, dict)]
    file_groups = _file_groups(groups)
    rows = [row for row in (state.get("files") or ()) if isinstance(row, dict)]
    reviewed_rows = ([row for row in rows
                      if _groups_for_path(file_groups, row.get("file"))]
                     if groups_known else [])
    outside_rows = ([row for row in rows
                     if not _groups_for_path(file_groups, row.get("file"))]
                    if groups_known else [])
    reviewed_count = len(reviewed_rows)
    inventory_omitted = state.get("files_omitted", 0)
    # Omitted rows are already counted immediately below through
    # inventory_omitted, so only the published native rows are added here.
    membership_unknown = len(rows) if not groups_known else 0
    classification_unknown = (state.get("unknown", 0) + inventory_omitted
                              + membership_unknown)
    over_cap = reviewed_count > MAX_TARGETED_REVIEW_FILES
    routed = targets_by_group(state, groups) if groups_known else {}
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

    files = []
    uncovered = []
    for row in reviewed_rows[:MAX_TARGETED_REVIEW_FILES]:
        path = row["file"]
        possible = sorted((group, "SEC")
                          for group in _groups_for_path(file_groups, path)
                          if (group, "SEC") in sec_cells)
        dispatched = [list(cell) for cell in possible
                      if path in declared.get(cell, ())]
        covered = [list(cell) for cell in possible
                   if declared.get(cell) == expected.get(cell)
                   and tuple(attested.get(cell, ())) == expected.get(cell)
                   and path in expected.get(cell, ())]
        files.append({**row, "dispatched_to": dispatched, "covered_by": covered})
        if not over_cap and not classification_unknown and not covered:
            uncovered.append(path)

    outside_listed = [dict(row) for row in outside_rows[:MAX_OUT_OF_SCOPE_FILES]]

    block = {
        "native_unparsed": reviewed_count,
        "files": files,
        "files_omitted": max(0, reviewed_count - len(files)),
        "classification_unknown": classification_unknown,
        "cap": MAX_TARGETED_REVIEW_FILES,
        "over_cap": over_cap,
        "dispatch_valid": dispatch_valid,
        "attestations_valid": attestations_valid,
        "out_of_scope": {
            "count": len(outside_rows),
            "files": outside_listed,
            "files_omitted": max(0, len(outside_rows) - len(outside_listed)),
            "cap": MAX_OUT_OF_SCOPE_FILES,
        },
    }
    reasons = []
    if over_cap:
        reasons.append("native Semgrep parser gaps exceed the targeted-review cap "
                       "(%d > %d)" % (reviewed_count,
                                      MAX_TARGETED_REVIEW_FILES))
    if state.get("unknown"):
        reasons.append("%d Semgrep parser-gap file(s) could not be classified "
                       "as native or non-native" % state["unknown"])
    if inventory_omitted:
        reasons.append("%d native Semgrep parser-gap path(s) were omitted from the "
                       "bounded classification inventory, so reviewed-universe "
                       "membership is unknown" % inventory_omitted)
    if membership_unknown:
        reasons.append("reviewed-universe membership is unknown for %d native "
                       "Semgrep parser-gap file(s) because groups.json is missing "
                       "or invalid" % state.get("count", membership_unknown))
    if not dispatch_valid:
        reasons.append("targeted-review dispatch did not match the native parser gaps")
    if not attestations_valid:
        reasons.append("a review cell returned an invalid targeted-review attestation")
    if uncovered:
        reasons.append("native Semgrep parser gap(s) not covered by completed SEC "
                       "review: %s" % ", ".join(uncovered))
    return block, "; ".join(reasons) or None
