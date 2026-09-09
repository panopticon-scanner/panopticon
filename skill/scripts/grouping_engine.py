"""Size policy for the 5.2 grouping engine (spec §5.3 steps 3-5; rulings D1, D4).

Pure functions over file lists and the proposal's layer specs. No I/O, no
repo: `discovery` owns which files exist and which group claimed them, this
module owns the arithmetic that decides how a claimed vertical is cut:

- `classify_files` / `count_code_files`: the size arithmetic's file kinds
  (test tree, Commons category, code) -- one classifier for stage 1 and 3.
- `ceiling_for`: how many leaves a repo of this size may have.
- `plan_layers`: a vertical over the cap is split by the layers the setup
  agent proposed (D4: layers REPLACE `chunk_files`); a residual `Core` layer
  carries whatever no layer matched; a layer under the floor merges back.
- `merge_smallest_layer`: the ONE collapse primitive (R2), used by the floor
  and by the ceiling.
- `apply_ceiling`: over the ceiling, collapse the smallest layer anywhere,
  re-evaluate, repeat. Verticals are never auto-merged (D1).
- `layer_bodies`: the groups.yml subgroup bodies for a layered vertical, with
  exactly one CARRIER whose globs are the vertical's `match:` minus every
  other layer's globs, so the vertical's claim stays complete.
- `plan_groups`: stage 3 over the whole repo -- committed groups first, then
  the proposal, scoped tests, the run-time `Tests` sweep, Commons, the size
  policy above -- returning the groups.yml side, the claims and the report.
- `format_report`: the deterministic `setup-report.md` (spec §7.1).

Every function is deterministic given its arguments (sorted iteration, ties
broken by name) -- run-to-run variance must come only from the proposal.
"""
import math
import re

import coverage_model
import discovery
import setup_proposal
import tests_axis

FLOOR = discovery.COMMONS_MIN_FILES     # a layer under this merges back (6)
MIN_CEILING = 4
CORE = "Core"                            # the engine-owned residual layer
_MAX_REPORT_STR = 200


def _clean(text, token=False):
    """Report hygiene (#1120) for strings that come from the repo or the
    proposal rather than from validated names: control characters and
    backticks are stripped and the length is capped; a TOKEN (a path, a raw
    label) carrying whitespace or quotes is repr'd so it cannot read as a
    phrase of the report. Same shape as setup_flow's spine sanitizer, kept
    local because setup_flow imports this module."""
    s = re.sub(r"[\x00-\x1f\x7f-\x9f`]", "", str(text or "")).strip()
    if len(s) > _MAX_REPORT_STR:
        s = s[:_MAX_REPORT_STR] + "..."
    if token and any(c in s for c in " \n\r\t\"'"):
        s = repr(s)
    return s


def ceiling_for(code_files, cap):
    """`max(4, 2 * ceil(code_files / cap))` -- the mean CODE leaf holds roughly
    `cap / 2` files or more (spec §5.3 step 5).

    The ceiling budgets CODE leaves, and only code leaves (#1506). Its
    numerator says so: `count_code_files` subtracts the test tree and the
    Commons files, so the leaves that hold exactly those files -- `Tests` and
    the Commons categories -- are not in the population this number sizes.
    Counting them against it anyway put every repo of <= 96 code files with
    two or more verticals over the ceiling BY CONSTRUCTION (2 verticals +
    Tests + Commons + Docs = 5 > 4), and the report then told the owner to
    merge verticals -- advice the spec forbids the engine to take, on a repo
    whose verticals were exactly the shape the setup brief asks for. They are
    also the leaves the ceiling cannot act on: its only lever is collapsing a
    layer.
    """
    cap = max(1, int(cap or 1))
    return max(MIN_CEILING, 2 * math.ceil(max(0, int(code_files or 0)) / cap))


def classify_files(files):
    """`{path: kind}` for the size arithmetic (spec §5.1), where kind is
    `"tests"` (the Tests seed globs match), `"commons:<Category>"` (the first
    shipped Commons category whose globs match, in catalog order) or `"code"`.
    Classifier-based, so the stage-1 spine and stage 3 agree."""
    commons = [(cat, g.get("match") or []) for cat, g in discovery._commons_catalog().items()]
    seeds = (discovery._tests_catalog().get(discovery.TESTS_GROUP) or {}).get("match") or []
    kinds = {}
    for f in files:
        if discovery.match_patterns(f, seeds):
            kinds[f] = "tests"
            continue
        for cat, globs in commons:
            if discovery.match_patterns(f, globs):
                kinds[f] = "commons:" + cat
                break
        else:
            kinds[f] = "code"
    return kinds


def count_code_files(files):
    """`(code_files, commons, tests)` -- `code_files = total - commons -
    test-tree` over `classify_files`."""
    kinds = classify_files(files)
    n_tests = sum(1 for k in kinds.values() if k == "tests")
    n_commons = sum(1 for k in kinds.values() if k.startswith("commons:"))
    return len(kinds) - n_commons - n_tests, n_commons, n_tests


def _positive(globs):
    return [g for g in globs if isinstance(g, str) and g and not g.startswith("!")]


def plan_layers(vertical_files, layer_specs, cap, all_files, floor=FLOOR):
    """Cut one vertical by its proposed layers.

    vertical_files: the files the vertical claimed (sorted). layer_specs: the
    proposal's `[{"layer", "match", "canonical"}]` in proposal order (from
    `setup_proposal.assemble`). all_files: every reviewable file in the repo,
    for the leakage check. Returns `(layers, notes)`; `layers` is None when
    the vertical stays unlayered (then an over-cap vertical falls back to
    `discovery.chunk_files` at run time and the note says so), else a list of
    `{"layer", "files", "match", "canonical", "carrier", "absorbed"}` with the
    carrier LAST.

    Rules (D4, R2, §5.3 step 3-4): layers only for a vertical over the cap; a
    layer whose globs match a file outside the vertical is dropped; files no
    layer matched form the residual `Core`, which is then the carrier -- else
    the LARGEST proposed layer carries; a layer under `floor` merges into the
    carrier; if that leaves a single layer the vertical is unlayered.
    """
    files = sorted(set(vertical_files))
    notes = []
    if len(files) <= cap:
        if layer_specs:
            notes.append("%d files <= cap %d: proposed layers not needed, dropped"
                         % (len(files), cap))
        return None, notes
    if not layer_specs:
        notes.append("%d files > cap %d and no layers proposed: falls back to "
                     "mechanical chunking (chunk_files)" % (len(files), cap))
        return None, notes
    inside = set(files)
    outside = sorted(set(all_files) - inside)
    layers = []
    unclaimed = list(files)
    for spec in layer_specs:
        name = spec["layer"]
        globs = list(spec.get("match") or [])
        leaked = [f for f in outside if discovery.match_patterns(f, globs)]
        if leaked:
            notes.append("layer %s dropped: its globs match %d file(s) outside the "
                         "vertical (e.g. %s)" % (name, len(leaked), _clean(leaked[0], token=True)))
            continue
        mine = [f for f in unclaimed if discovery.match_patterns(f, globs)]
        taken = set(mine)
        unclaimed = [f for f in unclaimed if f not in taken]
        layers.append({"layer": name, "files": mine, "match": globs,
                       "canonical": bool(spec.get("canonical")),
                       "carrier": False, "absorbed": []})
    if not layers:
        notes.append("every proposed layer was dropped: falls back to mechanical "
                     "chunking (chunk_files)")
        return None, notes
    if unclaimed:
        layers.append({"layer": CORE, "files": unclaimed, "match": [],
                       "canonical": True, "carrier": True, "absorbed": []})
    else:
        largest = max(layers, key=lambda ly: (len(ly["files"]), -layers.index(ly)))
        largest["carrier"] = True
        notes.append("no residual: layer %s (%d files) is the carrier"
                     % (largest["layer"], len(largest["files"])))
    # carrier last, proposal order otherwise -- the order groups.yml will list
    layers.sort(key=lambda ly: ly["carrier"])
    while len(layers) > 1 and min(len(ly["files"]) for ly in layers) < floor:
        layers, note = merge_smallest_layer(layers)
        notes.append(note + " (under floor %d)" % floor)
    if len(layers) == 1:
        notes.append("a single layer remains: vertical stays unlayered and falls "
                     "back to mechanical chunking (chunk_files)")
        return None, notes
    return layers, notes


def merge_smallest_layer(layers):
    """Collapse the smallest layer (R2, the one primitive behind floor and
    ceiling). The smallest non-carrier layer merges into the carrier; if the
    smallest IS the carrier, the largest other layer absorbs it and becomes
    the carrier (its own globs are then replaced by the residual's, see
    `layer_bodies`). Ties break on list order (earlier survives) -- and the
    carrier is listed LAST, so in a tie with the carrier it is the carrier
    that is absorbed. Returns `(new_layers, note)`; a list of one is returned
    unchanged."""
    if len(layers) <= 1:
        return list(layers), "nothing to merge"
    order = {id(ly): i for i, ly in enumerate(layers)}
    smallest = min(layers, key=lambda ly: (len(ly["files"]), -order[id(ly)]))
    if smallest["carrier"]:
        target = max((ly for ly in layers if ly is not smallest),
                     key=lambda ly: (len(ly["files"]), -order[id(ly)]))
    else:
        target = next(ly for ly in layers if ly["carrier"])
    merged = dict(target, files=sorted(set(target["files"]) | set(smallest["files"])),
                  carrier=True, absorbed=list(target["absorbed"]) + [smallest["layer"]]
                  + list(smallest["absorbed"]))
    out = [merged if ly is target else ly for ly in layers if ly is not smallest]
    out.sort(key=lambda ly: ly["carrier"])
    return out, "layer %s (%d files) merged into %s" % (
        smallest["layer"], len(smallest["files"]), target["layer"])


def apply_ceiling(layered, other_leaves, ceiling):
    """Enforce the leaf ceiling (D1, §5.3 step 5).

    layered: `{vertical: layers}` from `plan_layers` (only layered
    verticals); other_leaves: the count of every other leaf (unlayered
    verticals, Tests, Commons categories). While the leaf count exceeds
    `ceiling` and some vertical still has two or more layers, the smallest
    layer ANYWHERE collapses (ties: vertical name, then proposal order). A
    vertical reduced to one layer leaves `layered` and becomes an unlayered
    (chunked) vertical. Verticals are never merged. Returns
    `(layered, notes, over_by)`; `over_by > 0` means "raise max_groups or
    merge verticals in groups.yml" -- coverage is never dropped to fit."""
    layered = {v: list(ls) for v, ls in sorted(layered.items())}
    notes = []

    def leaves():
        return other_leaves + sum(len(ls) for ls in layered.values())

    while leaves() > ceiling:
        candidates = [(len(ly["files"]), v, i)
                      for v, ls in layered.items() if len(ls) > 1
                      for i, ly in enumerate(ls)]
        if not candidates:
            break
        _, vertical, _ = min(candidates)
        before = leaves()
        layered[vertical], note = merge_smallest_layer(layered[vertical])
        notes.append("%s: %s (ceiling %d exceeded: %d leaves)"
                     % (vertical, note, ceiling, before))
        if len(layered[vertical]) == 1:
            layered.pop(vertical)
            other_leaves += 1
            notes.append("%s: a single layer remains, vertical unlayered (falls "
                         "back to mechanical chunking)" % vertical)
    return layered, notes, max(0, leaves() - ceiling)


def layer_bodies(vertical, layers):
    """The groups.yml parent body for a layered vertical: `{"subgroups":
    {layer: {match, tests, panels, exclude}}}` in `layers` order (carrier
    last). Non-carrier layers keep their proposed globs. The carrier's globs
    are the vertical's `match:` plus a negation of every other layer's
    positive glob, so together the subgroups claim exactly what the vertical
    claimed; the vertical's `tests:` ride on the carrier (they are the
    vertical's tests; scoped matching keys on the parent name). Every
    subgroup carries the vertical's `panels` floor."""
    panels = list(vertical.get("panels") or [])
    subs = {}
    for layer in layers:
        if layer["carrier"]:
            negations = ["!" + g for other in layers if not other["carrier"]
                         for g in _positive(other["match"])]
            subs[layer["layer"]] = {"match": list(vertical.get("match") or []) + negations,
                                    "tests": list(vertical.get("tests") or []),
                                    "panels": panels, "exclude": []}
        else:
            subs[layer["layer"]] = {"match": list(layer["match"]), "tests": [],
                                    "panels": panels, "exclude": []}
    return {"subgroups": subs}


# ---------------------------------------------------------------------------
# Stage 3 over the whole repo (spec §5.3 steps 2-5) and the setup report (§7.1)
# ---------------------------------------------------------------------------

def _leaf_view(groups):
    """`{flat id: {"match", "tests"}}` -- what `discovery.assign_scoped` reads."""
    return {n: {"match": list(b.get("match") or []), "tests": list(b.get("tests") or [])}
            for n, b in setup_proposal.flatten_groups(groups).items()}


def _top(flat_id):
    labels = tests_axis.group_labels(flat_id)
    return labels[0] if labels else str(flat_id)


def _domains(panels, files):
    """The leaf's floor domains as the driver will floor them: the declared
    panels plus the file-gated global floor and the objective SEC floor."""
    return sorted(set(panels or [])
                  | coverage_model.applicable_global_floor(files, None)
                  | coverage_model.applicable_sec_floor(files))


def _dir_key(path):
    """Depth-2 directory of a path (`src/auth/x/y.go` -> `src/auth`; a
    top-level file -> `.`) -- how Ungrouped is tallied for the report."""
    parts = path.split("/")[:-1]
    return "/".join(parts[:2]) if parts else "."


def _leaf(name, kind, files, panels, cap):
    files = sorted(files)
    return {"name": name, "kind": kind, "files": len(files),
            "units": max(1, math.ceil(len(files) / cap)) if files else 0,
            "domains": _domains(panels, files)}


def plan_groups(files, committed, assembled, cap, aliases=None, ceiling=None):
    """Stage 3 steps 2-5 (spec §5.3) as one pure function.

    files: every reviewable path (`discovery.discover_repo_files`). committed:
    `discovery._committed_matrix` (leaf or parent bodies). assembled:
    `setup_proposal.assemble` (leaves with `layers`/`profile`). cap:
    `--max-per-group`. aliases: `{canonical: [labels]}` for scoped tests
    (default: the shipped vocabulary). ceiling: override (config/CLI), else
    `ceiling_for(code_files, cap)`.

    Order: committed claims first (scoped tests) -> proposal verticals on the
    leftovers -> the Tests sweep -> Commons -> Ungrouped; then layers for every
    NEW vertical over the cap (D4), the floor, and the ceiling (D1). Returns
    `{"groups", "claims", "report"}`: `groups` is the assembled side for
    `setup_proposal.merge_additive` (a layered vertical is a parent body from
    `layer_bodies`), `claims` maps each proposed name to the previously
    unclaimed files it took, `report` is the §7.1 data (`format_report`
    renders it). No timestamps, sorted everywhere.
    """
    files = sorted(set(files))
    cap = max(1, int(cap or discovery.DEFAULT_MAX_PER_GROUP))
    committed_view = _leaf_view(committed)
    # A proposal against a committed PARENT never lands: merge_additive leaves
    # the owner's subgroup structure alone. Its globs take no part in the
    # run-time catalog below; its claims are side-computed (against the
    # committed leftovers only) so the merge diff can still say whether it was
    # redundant or skipped, and the report can name it.
    parents = sorted(n for n in assembled if (committed.get(n) or {}).get("subgroups"))
    active = {n: b for n, b in assembled.items() if n not in parents}
    active_view = _leaf_view(active)
    full_view = dict(committed_view)
    for n, v in active_view.items():
        if n in full_view:
            full_view[n] = {"match": full_view[n]["match"] + [g for g in v["match"] if g not in full_view[n]["match"]],
                            "tests": full_view[n]["tests"] + [g for g in v["tests"] if g not in full_view[n]["tests"]]}
        else:
            full_view[n] = v
    prefixes = tests_axis.distinguishing_prefixes(full_view)
    c_assigned, leftovers, warnings = discovery.assign_scoped(
        files, committed_view, aliases=aliases, prefixes=prefixes)
    parent_claims = discovery.assign_scoped(
        leftovers, _leaf_view({n: assembled[n] for n in parents}),
        aliases=aliases, prefixes=prefixes)[0]
    a_assigned, leftovers, more = discovery.assign_scoped(
        leftovers, active_view, aliases=aliases, prefixes=prefixes)
    warnings = list(warnings) + list(more)
    claims = {n: list(fs) for n, fs in sorted({**a_assigned, **parent_claims}.items())}
    skipped = [n for n in parents if claims.get(n)]
    # What the merged groups.yml will actually contain: the committed leaves
    # plus the proposals that claimed something (merge_additive drops the
    # rest as redundant). A redundant proposed `Tests` must not suppress the
    # sweep, nor a redundant vertical offer an affinity home or take a name.
    landing_view = {n: v for n, v in full_view.items()
                    if n in committed_view or a_assigned.get(n)}
    suppressed = discovery._tests_suppressed(landing_view)
    if suppressed:
        tests, attached = [], {}
    else:
        tests, attached, leftovers = discovery.sweep_tests(
            leftovers, discovery.vertical_homes(landing_view), landing_view)
    tops = {_top(n) for n in landing_view}
    commons_cat = {n: g for n, g in discovery._commons_catalog().items()
                   if n not in landing_view and n not in tops}
    commons_named, residual = discovery.assign_by_catalog(leftovers, commons_cat)
    commons_named = discovery._fold_tiny_commons(commons_named, landing_view)

    code_files, n_commons, n_tests = count_code_files(files)
    ceiling = int(ceiling) if ceiling else ceiling_for(code_files, cap)
    # The engine's own leaves -- the Tests sweep and the Commons categories
    # left after the fold -- are counted but NOT charged to the ceiling
    # (#1506); see `ceiling_for`. Whatever the ceiling's source, it budgets
    # the same population, so `--max-groups` keeps one meaning.
    engine_leaves = (1 if tests else 0) + len(commons_named)
    layered, layer_report = {}, {}
    new_unlayered = 0
    for name, body in active.items():
        mine = sorted(set(a_assigned.get(name, [])) | set(attached.get(name, [])))
        proposed = body.get("layers") or []
        if not claims.get(name):
            continue                      # merge_additive drops it as redundant
        if name in committed:
            if proposed:
                layer_report[name] = {"kept": [], "notes": [
                    "committed leaf keeps its shape: proposed layers %s dropped, "
                    "globs merged into the leaf" % ", ".join(ly["layer"] for ly in proposed)]}
            continue
        layers, notes = plan_layers(mine, proposed, cap, files)
        if layers:
            layered[name] = layers
        else:
            new_unlayered += 1
        if layers or notes:
            layer_report[name] = {"kept": [], "notes": notes}
    for name in skipped:
        proposed = assembled[name].get("layers") or []
        if proposed:
            layer_report[name] = {"kept": [], "notes": [
                "committed parent left untouched: proposed layers %s dropped"
                % ", ".join(ly["layer"] for ly in proposed)]}
    # a committed leaf is never layered, so its proposal globs (if any) land
    # on the leaf itself; one that claims nothing is not dispatched and does
    # not count against the ceiling
    committed_files = {fid: sorted(set(c_assigned.get(fid, [])) | set(attached.get(fid, []))
                                   | set(a_assigned.get(fid, [])))
                       for fid in committed_view}
    other_code_leaves = sum(1 for fs in committed_files.values() if fs) + new_unlayered
    layered, ceiling_notes, over_by = apply_ceiling(layered, other_code_leaves, ceiling)
    for name, layers in layered.items():
        layer_report[name]["kept"] = [
            {"layer": ly["layer"], "files": len(ly["files"]), "carrier": ly["carrier"],
             "canonical": ly["canonical"], "absorbed": list(ly["absorbed"])} for ly in layers]

    groups = {}
    for name, body in assembled.items():
        vertical = {"match": list(body.get("match") or []),
                    "tests": list(body.get("tests") or []),
                    "panels": list(body.get("panels") or [])}
        groups[name] = layer_bodies(vertical, layered[name]) if name in layered else vertical

    leaves = []
    committed_flat = setup_proposal.flatten_groups(committed)
    for fid, mine in committed_files.items():
        leaves.append(_leaf(fid, "committed", mine, committed_flat[fid].get("panels"), cap))
    for name, body in active.items():
        if not claims.get(name) or name in committed:
            continue
        if name in layered:
            for ly in layered[name]:
                leaves.append(_leaf("%s:%s" % (name, ly["layer"]), "layer", ly["files"],
                                    body.get("panels"), cap))
        else:
            mine = set(a_assigned.get(name, [])) | set(attached.get(name, []))
            leaves.append(_leaf(name, "vertical", mine, body.get("panels"), cap))
    if tests:
        leaves.append(_leaf(discovery.TESTS_GROUP, "tests", tests, [], cap))
    for cat, fs in sorted(commons_named.items()):
        leaves.append(_leaf(cat, "commons", fs, [], cap))
    sizes = [lf["files"] for lf in leaves if lf["files"]]
    by_dir = {}
    for f in residual:
        by_dir[_dir_key(f)] = by_dir.get(_dir_key(f), 0) + 1
    report = {
        "cap": cap, "ceiling": ceiling, "over_ceiling_by": over_by,
        "engine_leaves": engine_leaves,
        "files": {"total": len(files), "code": code_files, "commons": n_commons,
                  "test_tree": n_tests},
        "leaves": leaves,
        "leaf_count": {"total": len(leaves),
                       **{k: sum(1 for lf in leaves if lf["kind"] == k)
                          for k in ("committed", "vertical", "layer", "tests", "commons")}},
        "leaf_sizes": {"min": min(sizes) if sizes else 0,
                       "mean": round(sum(sizes) / len(sizes), 1) if sizes else 0,
                       "max": max(sizes) if sizes else 0},
        "estimated_cells": sum(lf["units"] * len(lf["domains"]) for lf in leaves),
        "layers": {n: layer_report[n] for n in sorted(layer_report)},
        "ceiling_notes": ceiling_notes,
        "tests": {"suppressed": suppressed, "swept": len(tests),
                  "attached": {n: len(fs) for n, fs in sorted(attached.items())}},
        "commons": {n: len(fs) for n, fs in sorted(commons_named.items())},
        "ungrouped": list(residual),
        "ungrouped_by_dir": dict(sorted(by_dir.items())),
        "scoped_tests_warnings": warnings,
        "skipped_committed_parent": skipped,
        "redundant": sorted(n for n in assembled if not claims.get(n)),
    }
    return {"groups": groups, "claims": claims, "report": report}


def _ceiling_line(r):
    """The size section's ceiling line. Says WHICH leaves the ceiling counts,
    so the number can be reconciled against the leaf total printed beside it
    rather than read as a contradiction (#1506)."""
    line = "- cap: %d files per dispatch unit; ceiling: %d code leaves" % (
        r["cap"], r["ceiling"])
    if r.get("engine_leaves"):
        line += (" (+%d engine-owned: Tests and the Commons categories, which the "
                 "ceiling does not budget)" % r["engine_leaves"])
    return line


def format_report(report, disclosure=None):
    """Render `plan_groups(...)["report"]` (+ the `assemble` disclosure) as
    the deterministic `setup-report.md` (spec §7.1). No timestamps."""
    r = report
    lc, f = r["leaf_count"], r["files"]
    out = ["# Setup report", "",
           "## Size", "",
           "- files: %d total = %d code + %d commons + %d test tree"
           % (f["total"], f["code"], f["commons"], f["test_tree"]),
           _ceiling_line(r),
           "- leaves: %d (committed %d, verticals %d, layers %d, Tests %d, Commons %d)"
           % (lc["total"], lc["committed"], lc["vertical"], lc["layer"], lc["tests"], lc["commons"]),
           "- leaf size: min %s / mean %s / max %s"
           % (r["leaf_sizes"]["min"], r["leaf_sizes"]["mean"], r["leaf_sizes"]["max"]),
           "- estimated cells: >= %d (dispatch units x floor domains; the scout only widens)"
           % r["estimated_cells"]]
    if r["over_ceiling_by"]:
        # Reachable only when CODE leaves exceed the ceiling, so both levers
        # named here can actually move the number (#1506).
        out.append("- **over ceiling by %d** -- the ceiling counts code leaves only, "
                   "so raise `max_groups` or merge verticals in groups.yml; nothing "
                   "was dropped to fit" % r["over_ceiling_by"])
    out += ["", "## Leaves", "", "| leaf | kind | files | units | floor |", "|---|---|---|---|---|"]
    out += ["| %s | %s | %d | %d | %s |" % (lf["name"], lf["kind"], lf["files"], lf["units"],
                                            ", ".join(lf["domains"]) or "-")
            for lf in r["leaves"]]
    empty = [lf["name"] for lf in r["leaves"] if lf["kind"] == "committed" and not lf["files"]]
    if empty:
        out += [""] + ["- %s: committed leaf claims 0 files (not dispatched, not counted "
                       "against the ceiling) -- its globs match nothing" % n for n in empty]
    if r["layers"]:
        out += ["", "## Layers", ""]
        for name, info in r["layers"].items():
            if info["kept"]:
                out.append("- %s: %s" % (name, ", ".join(
                    "%s (%d%s%s)" % (ly["layer"], ly["files"], ", carrier" if ly["carrier"] else "",
                                     ", absorbed " + "+".join(ly["absorbed"]) if ly["absorbed"] else "")
                    for ly in info["kept"])))
            else:
                out.append("- %s: unlayered" % name)
            out += ["  - %s" % _clean(n) for n in info["notes"]]
    if r["ceiling_notes"]:
        out += ["", "## Ceiling", ""] + ["- %s" % _clean(n) for n in r["ceiling_notes"]]
    t = r["tests"]
    out += ["", "## Tests", ""]
    if t["suppressed"]:
        out.append("- sweep suppressed: a committed or proposed `Tests` group owns the test tree")
    elif not t["swept"] and not t["attached"]:
        out.append("- nothing to sweep: every test-tree file was credited by a vertical")
    else:
        out.append("- swept %d test-tree file(s) into `Tests` (formed last, mechanical at run time)"
                   % t["swept"] if t["swept"] else
                   "- no `Tests` group: the leftover test-tree files are under the floor")
        out += ["- attached %d to %s by path affinity (under the floor)" % (n, g)
                for g, n in t["attached"].items()]
    out += ["- scoped-tests warning: %s" % _clean(w) for w in r["scoped_tests_warnings"]]
    out += ["", "## Commons", ""]
    out += ["- %s: %d" % (n, c) for n, c in r["commons"].items()] or ["- none"]
    out += ["", "## Ungrouped -- capabilities your catalog is missing (%d files)" % len(r["ungrouped"]), ""]
    if r["ungrouped"]:
        out += ["- %s: %d" % (_clean(d, token=True), n) for d, n in r["ungrouped_by_dir"].items()]
        out.append("")
        out.append("Ungrouped code is reviewed (chunked as `Ungrouped_N`) and yields well; "
                   "a high Ungrouped count is a coverage signal, not waste. Name the "
                   "capability and add a group.")
    else:
        out.append("- none")
    if r["skipped_committed_parent"] or r["redundant"]:
        out += ["", "## Proposal outcome", ""]
        out += ["- %s: committed parent left untouched (edit its subgroups by hand)" % n
                for n in r["skipped_committed_parent"]]
        out += ["- %s: claimed nothing new, dropped as redundant" % n for n in r["redundant"]]
    if disclosure:
        custom = [g for g in disclosure.get("groups", []) if g.get("custom")]
        renamed = [g for g in disclosure.get("groups", []) if g.get("normalized")]
        out += ["", "## Names", ""]
        out += ["- custom: %s (floor %s, %s)" % (g["name"], ", ".join(g["floor"]) or "none",
                                                  g["floor_source"]) for g in custom]
        out += ["- %s -> %s" % (_clean(g["normalized"]["from"], token=True), g["normalized"]["to"])
                for g in renamed]
        out += ["- collision: %s folded into %s" % (_clean(c["capability"], token=True), c["name"])
                for c in disclosure.get("collisions", [])]
        out += ["- warning: %s" % _clean(w) for w in disclosure.get("warnings", [])]
        if out[-1] == "":
            out.append("- none")
    return "\n".join(out) + "\n"
