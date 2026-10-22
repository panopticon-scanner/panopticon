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
import os
import sys

import scripts.findings_contract as findings_contract
from . import artifacts as artifacts_mod
from . import validate_schema as schema_mod

# DAT-2808086775: bound target-writable coverage artifacts before parsing.
# #2080: the writer caps scout_invalid, and skipped records sink certification.
_MAX_COVERAGE_BYTES = 1 << 20


# #1839 (review round 1 I3): how many per-directory rows of the suppression
# tally a rendered line shows before it names the remainder. `meta.coverage` is
# this module's block and two renderers show its rows, so the cap and the
# escaping live here once -- `synth/render.py` is also inside 20 lines of its
# ceiling. The KEY SHAPES stay with the renderers, which mirror them from
# `ingest_tools`; this function is told which prefix is target-authored.
VENV_ROWS_SHOWN = 10


def venv_tally(rows, prefix):
    """`seg: n, ...` for `(segment, count)` rows, with the key shape that embeds
    a TARGET-AUTHORED path escaped and capped (#1839, review round 1 I3).

    `meta.coverage.tools_suppressed` carries one `<prefix><dir>` row per
    marker-confirmed virtualenv, where `<dir>` is a path out of the reviewed
    tree: a newline in it forged a second report line that read like the real
    one, and a monorepo mints dozens of rows. So `ascii()` for that half of the
    key -- non-ASCII too, since a bidi override reorders a line -- and the
    remainder is named rather than dropped silently. Order is the caller's, and
    the class rows are never capped: the JSON keeps every row.
    """
    out, seen, cut = [], 0, 0
    for segment, count in rows:
        if str(segment).startswith(prefix):
            seen += 1
            if seen > VENV_ROWS_SHOWN:
                cut += 1
                continue
            segment = prefix + ascii(str(segment)[len(prefix):])
        out.append("%s: %d" % (segment, count))
    if cut:
        out.append("and %d more (see meta.coverage.tools_suppressed)" % cut)
    return ", ".join(out)


def _strings(value):
    """The strings in `value`, accepting a lone string as the one-element list
    it was meant to be; [] for anything else."""
    if isinstance(value, str):
        return [value]
    return schema_mod.string_list(value)


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


def load_coverage_files(panopticon_dir=".panopticon", *, skipped=None):
    """Load every .panopticon/coverage-<group>.json cell-coverage artifact
    (phases.coverage.coverage_execute's output) for audit_floor_cells. Tolerant:
    unreadable/malformed/non-dict/group-less files are skipped, never raise -- these are
    the same run artifacts groups.json/scout-*.json are read as elsewhere, and
    each record is normalized by `normalized_cell` at the read.

    The shared reader bounds bytes before decoding/parsing, refuses symlinks
    and special files without blocking, and normalizes parser resource errors.
    Append every skipped basename to `skipped` when supplied. PlanInputs.load
    publishes that list as an integrity failure: an empty floor audit cannot
    certify a run whose coverage evidence was dropped (#2080).
    """
    out = []
    for path in sorted(glob.glob(os.path.join(panopticon_dir, "coverage-*.json"))):
        name = os.path.basename(path)
        try:
            data = artifacts_mod.read_json(path, limit=_MAX_COVERAGE_BYTES)
        except (OSError, ValueError) as exc:
            # `str(exc) or type(exc).__name__`, not `exc or ...`: str(MemoryError())
            # is "" while the instance itself is TRUTHY, so the short form renders
            # "could not be read ()" -- a line an operator cannot act on.
            reason = "could not be read (%s)" % (str(exc) or type(exc).__name__)
        else:
            if isinstance(data, dict):
                cell = normalized_cell(data, path=name)
                if isinstance(cell.get("group"), str) and cell["group"]:
                    out.append(cell)
                    continue
                reason = "has no usable group"
            else:
                reason = "is not an object"
        if skipped is not None:
            skipped.append(name)
        print("synthesize: coverage: %s: %s; skipping it" % (name, reason), file=sys.stderr)
    return out


def present_cells(paths):
    """{group: set(domains)} from findings-<group>-<domain>.json names among
    the ingested paths (P4 review cells; feeds audit_floor_cells).

    Filename-only, deliberately: presence means synthesize was HANDED a
    findings file for that (group, domain) cell, independent of whether the
    reviewer found anything in it -- an empty findings-Auth-SEC.json still
    proves the SEC floor cell for group Auth ran.

    `findings_contract.cell_of` parses the name. This function used to
    re-implement that parse, which is how a coverage cell and a defect
    diagnostic came to disagree about which cell a file named
    (ARC-3899903550, #1765).
    """
    out: dict[str, set[str]] = {}
    for p in paths or []:
        cell = findings_contract.cell_of(p)
        if cell:
            out.setdefault(cell[0], set()).add(cell[1])
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


# #3220: led into `summary.coverage_note` by `grading.grade_report`.
REVIEW_MATRIX_MISSING_NOTE = ("no review cell answered: health and grade are unknown, and "
                              "risk_level is only the tool axis's worst finding (null when "
                              "it has none)")


def review_matrix_missing(cell_audit):
    """#3220: the run planned review cells and not one of them answered.

    Read off `cell_audit`'s `planned_pairs` and `reviewed`; `tool_axis`
    publishes `planned_pairs` only beside a measured `reviewed`, so a caller
    that predates them gets False -- today's numbers, never a guess."""
    audit = cell_audit if isinstance(cell_audit, dict) else {}
    planned, reviewed = ({tuple(pair) for pair in audit.get(key) or [] if isinstance(pair, list)}
                         for key in ("planned_pairs", "reviewed"))
    return bool(planned) and not planned & reviewed
