#!/usr/bin/env python3
"""The SEC carve-out for a target-authored `exclude_paths:` (#1757, AGT-1355709320).

Owner ruling 2026-09-25: *a target-authored `exclude_paths` may not remove a file
the objective SEC floor matches from the SEC domain; such an exclusion is
disclosed in the report's coverage section instead of silently applied. Other
domains keep honouring the exclusion.* The floor exists so operator taste cannot
hide the attack surface, and in `--pr` mode the PR cannot touch the config at
all -- so the operator-authored config gets exactly the same treatment.

A review cell is (group x domain) and nothing in the matrix restricts a domain to
a SUBSET of a group's files, so the carve-out has to be a GROUP: the files the
objective SEC floor matches leave the pruned set and form
`groups_schema.SEC_CARVE_OUT_SINK`, whose coverage `phases/coverage.py` pins to
exactly `{"SEC"}` off the `groups_schema.SEC_CARVE_OUT_MARKER` field stamped
here. They deliberately do NOT rejoin their natural groups: every other domain
still honours the exclusion, which is the half of the ruling that leaves
`exclude_paths:` worth having. The TOOL side is untouched -- `--tools-exclude`
and `run_tools --exclude` still get the committed globs as they always have.

Its own module because `discovery.py` is at its line ratchet
(`tests/test_flat_module_ceiling.py`), and because the policy reads better in one
place than spread across three call sites. Stdlib-only. `coverage_model` is
imported inside `sec_surface` rather than at module scope on purpose:
`coverage_model` imports `discovery` and `discovery` imports THIS module, so a
module-level edge here would close that cycle. It is the same lazy shape
`discovery._capability_aliases` keeps for `setup_proposal`, and for the same
reason -- see `coverage_model`'s own docstring, which promises that no
module-level import runs back the other way.
"""
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scripts import groups_schema
else:
    try:
        from scripts import groups_schema
    except ModuleNotFoundError:     # flat: only skill/scripts on sys.path
        import groups_schema


def sec_surface(path):
    """True when the objective SEC floor matches `path` ON ITS OWN.

    One file at a time, because `applicable_sec_floor` answers for a whole group
    and the carve-out is a per-FILE decision: a group-wide answer would carve out
    every excluded file as soon as one of them carried a manifest.
    """
    try:
        from scripts import coverage_model
    except ModuleNotFoundError:     # flat: only skill/scripts on sys.path
        import coverage_model       # type: ignore[no-redef]
    return bool(coverage_model.applicable_sec_floor([path]))


def split(files, exclude_re):
    """Split `files` into `(kept, pruned, carved)` by the committed
    `exclude_paths:` regexes.

    `kept` reached no glob. `pruned` matched one and carries no objective SEC
    surface, so it behaves exactly as every excluded file did before #1757: no
    group, no leftover, no review cell of any domain. `carved` matched one and
    DOES carry that surface, so it goes to `install` instead of being dropped.
    Identity (and no carve-out) when nothing is committed -- the same no-op the
    whole feature has always been on a tree with no `exclude_paths:`.
    """
    if not exclude_re:
        return files, [], []
    kept: list[str] = []
    pruned: list[str] = []
    carved: list[str] = []
    for f in files:
        if not any(rx.match(f) for rx in exclude_re):
            kept.append(f)
        else:
            (carved if sec_surface(f) else pruned).append(f)
    return kept, pruned, carved


def install(result, carved, max_per_group, chunker):
    """Append the SEC-only carve-out group(s) for `carved` to `result`.

    A no-op when nothing was carved, so a run with no `exclude_paths:` -- and a
    run whose globs matched no SEC surface -- emits the group set it always did.
    Chunked by `max_per_group` through the caller's `chunker` (discovery's
    `chunk_files`, which packs by directory) like any other oversize group, and
    `counts["groups"]` is refreshed so the group list and the count cannot
    disagree. No `security_mode`: every other group's panel schedule is computed
    from its files and differs by mode, and this one is the POLICY -- one domain,
    the same in `standard` and `redteam`.

    The group entry is `_group_obj`'s shape with two deliberate differences.
    `panels` is `["SEC"]`: the files are here for one domain, and running
    `compute_group_panels` over them would advertise a code panel this group does
    not get. And it carries the marker field, which is how the coverage phase
    knows to pin this cell narrow rather than widen it off the files' own
    signals. Chunks take the sink name as both `parent` and `chunk_of`, the way
    the residual sink's chunks do: a self-parenting chunk would leak a machine
    name into the report's roll-up.
    """
    if not carved:
        return
    name = groups_schema.SEC_CARVE_OUT_SINK
    chunks = chunker(sorted(carved), max_per_group)
    groups = result.setdefault("groups", [])
    if len(chunks) == 1:
        groups.append(_entry(name, chunks[0], name))
    else:
        groups.extend(_entry("%s_%d" % (name, i + 1), chunk, name)
                      for i, chunk in enumerate(chunks))
    result.setdefault("counts", {})["groups"] = len(groups)


def _entry(name, files, unit):
    """One carve-out group entry: `_group_obj`'s fields, SEC-only panels, marker."""
    return {
        "name": name,
        "files": files,
        "panels": ["SEC"],
        "parent": unit,
        "chunk_of": unit,
        groups_schema.SEC_CARVE_OUT_MARKER: True,
    }


def disclosure(globs, carved):
    """The three facts `groups.json`, the report and the stderr line all state:
    which globs scoped the exclusion, which files it could not take out of SEC,
    and how many. Published whenever `exclude_paths:` is committed, `count: 0`
    included -- globs that carved nothing still scoped the run, and a reader
    comparing two runs has to see that they did.
    """
    return {"globs": list(globs), "files": sorted(carved), "count": len(carved)}

