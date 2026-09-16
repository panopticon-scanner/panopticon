"""The floor-cell audit, and the two run artifacts it reads.

Split out of `synth/plan.py` (#1639 P15 fix round 3, R2-2): that module was at
698 of its 700-line ceiling, and the fix below is a boundary repair, which is
not the kind of change to squeeze in.

`coverage-<group>.json` is written by `phases.coverage.coverage_execute` and
read back from `<run_dir>/`, which on the agentic path is globbed out of the
SCANNED REPOSITORY -- a hostile target can pre-commit one, and the loader's
contract has always been "tolerant: never abort a run". Round 1 made the
published PAIR safe (`meta.coverage.cells.missing_floor` is two strings or it
is dropped); the READ was still raw, so eleven shapes of `group` / `floor` /
`excluded` ended a paid-for run in TypeError before any of that ran -- an
unhashable `group` used as a dict key, a non-iterable `floor`, a list inside
`excluded` used as a set element.

THE PRINCIPLE (see `validate_schema`): the schema pins the CONTROLLER's output,
so target-written content is normalized to the pinned types at the boundary --
here, at the read, with every change announced.
"""
import glob
import json
import os
import sys

import scripts.groups_schema as groups_schema


def _strings(value):
    """The strings in `value`, accepting a lone string as the one-element list
    it was meant to be; [] for anything else."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [x for x in value if isinstance(x, str)]
    return []


def normalized_cell(cell, path=None, warn=None):
    """One coverage record with the three fields the audit reads pinned:
    `group` a string (the key it is looked up by), `floor` and `excluded` lists
    of strings (iterated, and put in a set). Returns a NEW dict -- the rest of
    the record rides along untouched -- and announces every change, because a
    coverage artifact that did not say what it meant is a fact about the run.
    Never raises.
    """
    if not isinstance(cell, dict):
        return {}
    out = dict(cell)
    changed = []
    group = out.get("group")
    if group is not None and not isinstance(group, str):
        out["group"] = str(group) if isinstance(group, (int, float, bool)) else None
        changed.append("group")
    for key in ("floor", "excluded"):
        if key not in out:
            continue
        pinned = _strings(out[key])
        if pinned != out[key]:
            out[key] = pinned
            changed.append(key)
    for key in changed:
        message = ("coverage: %s: %s did not match the type the cell audit "
                   "reads for it; using %r"
                   % (path or "coverage-*.json", key, out.get(key)))
        if warn is not None:
            warn(message)
        else:
            print("synthesize: " + message, file=sys.stderr)
    return out


def load_coverage_files(panopticon_dir=".panopticon"):
    """Load every .panopticon/coverage-<group>.json cell-coverage artifact
    (phases.coverage.coverage_execute's output) for audit_floor_cells. Tolerant:
    unreadable/malformed/non-dict files are skipped, never raise -- these are
    the same run artifacts groups.json/scout-*.json are read as elsewhere, and
    each record is normalized by `normalized_cell` at the read."""
    out = []
    for path in sorted(glob.glob(os.path.join(panopticon_dir, "coverage-*.json"))):
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            out.append(normalized_cell(data, path=os.path.basename(path)))
    return out


def present_cells(paths):
    """{group: set(domains)} from findings-<group>-<domain>.json names among
    the ingested paths (P4 review cells; feeds audit_floor_cells).

    Filename-only, deliberately: presence means synthesize was HANDED a
    findings file for that (group, domain) cell, independent of whether the
    reviewer found anything in it -- an empty findings-Auth-SEC.json still
    proves the SEC floor cell for group Auth ran. Domain codes
    (groups_schema.DOMAINS) are hyphen-free, so the domain is the LAST
    hyphen-delimited token before `.json`; this can never collide with the
    legacy panel-suffixed shape (findings-<group>-<panel>[-panel_review|
    -lens_sweep-<lens>].json, see GROUP_RE) because panel tokens are lowercase
    words and domain codes are upper-case 2-3 letter codes -- disjoint
    alphabets by construction (groups_schema.DOMAINS vs. PANEL_ORDER).
    """
    out = {}
    for p in paths or []:
        base = os.path.basename(str(p))
        if not (base.startswith("findings-") and base.endswith(".json")):
            continue
        stem = base[len("findings-"):-len(".json")]
        group, sep, domain = stem.rpartition("-")
        if sep and group and domain in groups_schema.DOMAINS:
            out.setdefault(group, set()).add(domain)
    return out


def audit_floor_cells(coverages, present):
    """Certifiable-coverage check (matrix Sec5.1): every FLOOR (domain, group)
    cell must have produced a findings file. `coverages` = the per-group
    coverage dicts (as written to .panopticon/coverage-<group>.json by
    phases.coverage.coverage_execute: {"group", "floor", "effective", ...}); `present`
    = {group: set(domains with a findings file)}. A missing floor cell is the
    INCONCLUSIVE story -- scout-WIDENED (non-floor) domains are never audited
    here, matching the matrix's floor-is-the-contract semantics. A floor domain
    listed in the cell's `excluded` (e.g. a universal global-floor domain a group
    opted out of, #5.0-11) does NOT run and is netted out first -- it is not a
    missing floor cell.

    Pure; never raises -- and that is now true of a record this function was
    handed directly rather than through `load_coverage_files` (R2-2): it pins
    the three fields it reads itself, silently, because a caller that did not
    go through the read boundary has already had its warning printed there or
    is a test passing a literal.
    """
    missing = []
    for cov in coverages or []:
        if not isinstance(cov, dict):
            continue
        group = cov.get("group")
        group = group if isinstance(group, str) else None
        have = present.get(group, set()) if isinstance(present, dict) else set()
        excluded = set(_strings(cov.get("excluded")))
        for dom in _strings(cov.get("floor")):
            # #5.0-11: a floor domain explicitly excluded (e.g. a universal
            # global-floor domain a group opted out of) does not run, so it is
            # not a missing floor cell -- net exclude before auditing.
            if dom in excluded:
                continue
            # #1639 P15: the pair is published as two strings, so a cell that
            # named neither is dropped here rather than carried into the
            # artifact and rejected at the exit (it names no real cell anyway,
            # and `sorted` would raise on the mix).
            if dom not in have and group is not None:
                missing.append([group, dom])
    return {"missing_floor": sorted(missing)}
