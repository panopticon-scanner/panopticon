"""Grades, gate verdict, certification and the health index."""
import os

from . import findings as findings_mod


def grade(findings):
    """Assign letter grade (A-F) based on highest severity finding."""
    if findings_mod._present(findings, "CRITICAL"):
        return "F"
    if findings_mod._present(findings, "HIGH"):
        return "D"
    if findings_mod._present(findings, "MEDIUM"):
        return "C"
    if findings_mod._present(findings, "LOW"):
        return "B"
    return "A"

def risk_level(findings):
    """Determine overall risk level (CRITICAL/HIGH/MEDIUM/LOW) from findings."""
    for sev in ("CRITICAL", "HIGH", "MEDIUM"):
        if findings_mod._present(findings, sev):
            return sev
    return "LOW"

def gate_verdict(findings, fail_on):
    """Return CI gate verdict (PASS/FAIL/OFF) based on findings and threshold."""
    if not fail_on:
        return "OFF"
    threshold = findings_mod.SEV_ORDER.index(str(fail_on).upper())
    for f in findings:
        if findings_mod._sev_rank(f) <= threshold:
            return "FAIL"
    return "PASS"

def gate_severity_roles(gate_eligible, fail_on):
    """Which severities the `--fail-on` threshold puts IN PLAY, and which of
    those actually carry a gate-eligible finding (i.e. caused the FAIL).

    Three states, matching what gate_verdict() actually reads:

    - not in play  -- below the threshold; nothing at this level can gate.
    - in play      -- at or above the threshold, but no gate-eligible finding
                      here. It WOULD have failed the build; it didn't fire.
    - contributing -- at or above the threshold with >= 1 gate-eligible finding.
                      These are the levels the FAIL is actually made of.

    Derived from `gate_eligible`, NOT from the reported `stats` (which count the
    ACTIVE set). The two differ: an unverified HIGH is active but does not gate.
    Marking off the active counts would paint a level red while the gate passed,
    which is precisely the lie this display exists to prevent.

    With no `--fail-on`, nothing is in play and the display stays unmarked.
    """
    if not fail_on:
        return {"fail_on": None, "in_play": [], "contributing": []}
    name = str(fail_on).upper()
    if name not in findings_mod.SEV_ORDER:
        return {"fail_on": None, "in_play": [], "contributing": []}
    in_play = findings_mod.SEV_ORDER[:findings_mod.SEV_ORDER.index(name) + 1]
    present = {str(f.get("severity", "")).upper() for f in gate_eligible}
    return {"fail_on": name, "in_play": in_play,
            "contributing": [sev for sev in in_play if sev in present]}

def certify(overall_grade, gate_eligible, fail_on, panels_incomplete, tools_absent,
            integrity_ok=True, verdicts_unloadable=0, verdicts_unanswered=0,
            missing_floor=0):
    """Coverage-aware certification. Gate keys on high-value-panel completeness
    (+ requested-absent tools + artifact integrity + verdict loadability +
    missing FLOOR review cells); grade is holistic (provisional on ANY gap).
    Precedence FAIL > INCONCLUSIVE > PASS; OFF preserved. Tolerant: pure,
    never raises.

    A verdict file that survived re-dispatch but is unloadable or fails its
    finding-id echo is lost verify coverage. A PASS with supplied verdict work
    left unanswered is INCONCLUSIVE, so malformed/misrouted advisor output
    cannot silently keep a clean gate.

    `missing_floor` (5.0, matrix Sec5.1) is the count of FLOOR (domain, group)
    cells that produced no findings file at all -- see audit_floor_cells.
    Mirrors `tools_absent`'s treatment exactly: it only feeds
    gate_relevant_gap, not `any_incomplete` (which stays panel-scoped), so a
    missing floor cell forces the gate to INCONCLUSIVE without downgrading the
    holistic overall_grade to provisional -- the same asymmetry a
    requested-absent tool already gets.
    """
    base_gate = gate_verdict(gate_eligible, fail_on)          # PASS / FAIL / OFF
    high_value_incomplete = set(panels_incomplete) & findings_mod.HIGH_VALUE_PANELS
    gate_relevant_gap = (bool(high_value_incomplete) or bool(tools_absent)
                         or not integrity_ok or bool(verdicts_unloadable)
                         or bool(verdicts_unanswered) or bool(missing_floor))
    any_incomplete = bool(panels_incomplete)

    if base_gate == "PASS" and gate_relevant_gap:
        gate = "INCONCLUSIVE"
    else:
        gate = base_gate                                      # FAIL/OFF/PASS unchanged

    if any_incomplete:
        cert_grade, provisional = None, overall_grade
    else:
        cert_grade, provisional = overall_grade, None

    coverage_certified = not (gate_relevant_gap or any_incomplete)

    note = None
    if any_incomplete and not gate_relevant_gap:
        tail = sorted(p for p in panels_incomplete if p not in findings_mod.HIGH_VALUE_PANELS)
        note = ("gate certified; grade provisional — low-value panel(s) incomplete: %s"
                % ", ".join(tail))

    return {"gate": gate, "overall_grade": cert_grade,
            "provisional_grade": provisional,
            "coverage_certified": coverage_certified, "coverage_note": note}

def severity_stats(findings):
    """Count findings by severity level."""
    stats = {s.lower(): 0 for s in findings_mod.SEV_ORDER}
    for f in findings:
        sev = f.get("severity", "INFO").lower()
        if sev in stats:
            stats[sev] += 1
    return stats

# #1146: a secondary "health" ratio reported ALONGSIDE the max-severity letter
# (never replacing it, never touching the gate -- see #1057's adjudication). It
# is non-blank LoC divided by a severity-weighted defect footprint, so HIGHER =
# healthier: more clean code per unit of confirmed, severity-weighted defect.
# Weights escalate x5 per band; INFO is weightless.
HEALTH_WEIGHTS = {"INFO": 0, "LOW": 1, "MEDIUM": 5, "HIGH": 25, "CRITICAL": 125}

def _loc_span(finding):
    """Lines a finding spans: line_end - line_start + 1, floored at 1. Tolerant
    of missing/None/non-int/inverted ranges (any such finding counts as 1)."""
    loc = finding.get("location") or {}
    start = loc.get("line_start")
    if not isinstance(start, int):
        return 1
    end = loc.get("line_end", start)
    if not isinstance(end, int):
        end = start
    return max(1, end - start + 1)

def weighted_defect(findings):
    """Severity-weighted defect footprint: sum over `findings` of
    weight[severity] * _loc_span(finding). INFO (weight 0) contributes nothing."""
    total = 0
    for f in findings:
        weight = HEALTH_WEIGHTS.get(str(f.get("severity", "INFO")).upper(), 0)
        if weight:
            total += weight * _loc_span(f)
    return total

def nonblank_loc(target, groups_meta):
    """Total non-blank lines across the UNIQUE reviewed files (the numerator).
    Each file path is resolved against `target` (a repo root) or cwd; a missing,
    unreadable, or binary file is skipped, never fatal -- the score degrades
    gracefully rather than crashing synthesis."""
    base = target if os.path.isdir(target) else "."
    seen = set()
    total = 0
    for g in groups_meta:
        for rel in g.get("files") or []:
            if rel in seen:
                continue
            seen.add(rel)
            path = rel if os.path.isabs(rel) else os.path.join(base, rel)
            try:
                with open(path, encoding="utf-8", errors="ignore") as fh:
                    total += sum(1 for line in fh if line.strip())
            except (OSError, ValueError):
                continue
    return total

HEALTH_FORMULA = "100 * total_loc / (total_loc + weighted_defect)"

def health_score(total_loc, weighted):
    """Bounded health index: the share of the reviewed codebase NOT under
    severity-weighted defect footprint, as 0-100. Higher = healthier; a repo with
    no gate-eligible weighted defect scores exactly 100. Rounded to 2 decimals.

    Replaces the original `total_loc / weighted_defect` ratio, which was wrong in
    three ways at once. It ran BACKWARDS from the intuition a reader brings to a
    number labelled "health" (the divisor carried the defect); it was unbounded
    above, so there was no value meaning "perfect"; and it divided by
    `weighted_defect`, which is 0 for a CLEAN repo -- so the single best possible
    outcome was the one case that had to return None.

    This form inverts all three. The remaining degenerate case is total_loc == 0
    -- no reviewed file was readable -- which returns None because it is a broken
    MEASUREMENT, not a health of zero. That distinction became load-bearing when
    the letter grade started keying on this score: nonblank_loc() skips missing,
    unreadable and binary files silently, so a run whose paths do not resolve (a
    stale worktree, a moved checkout, a revoked volume permission) would otherwise
    report the floor grade for a codebase it never managed to read.

    Deliberately NOT `100 - weighted/total_loc`, the obvious inversion: that
    reads as a percentage but has no floor (a file-scoped run with wide HIGH
    findings goes negative), and it compresses real spread to nothing. Measured
    on the six calibration targets it puts every one between 98.20 and 99.58 --
    1.38 points to separate codebases whose defect density differs 4.3x, leaving
    gate-F/risk-CRITICAL gotify and the healthiest target 1.25 points apart. The
    saturating form used here spreads the same six across 35.68-70.45, in the
    same order.
    """
    if not total_loc:
        return None
    return round(100.0 * total_loc / (total_loc + weighted), 2)

def health_stats(total_loc, gate_eligible):
    """The `summary.health` block (#1146). `gate_eligible` is the same set the
    letter grade and gate count, so the health ratio inherits their honesty
    contract (unverified/rejected claims never move it)."""
    weighted = weighted_defect(gate_eligible)
    return {
        "score": health_score(total_loc, weighted),
        "total_loc": total_loc,
        "weighted_defect": weighted,
        "weights": {k.lower(): v for k, v in HEALTH_WEIGHTS.items()},
        # Stated so a report is self-describing: the score changed shape once
        # already, and both inputs are emitted, so any reader (or an older
        # report) can be recomputed against whichever formula it names.
        "formula": HEALTH_FORMULA,
        "population": "gate_eligible",
    }

# Owner-set bands over the 0-100 health index (2026-09-02). Ordered best-first
# by LOWER BOUND; a score falls in the first band it reaches.
#
# S and X exist because A-F alone has no room at either end. S is reachable ONLY
# at exactly 100 -- no gate-eligible weighted defect at all -- so it is a real
# distinction rather than a rounding of A. X is the floor band: a weighted defect
# footprint three times the size of the codebase reviewed.
#
# The F band is deliberately the widest (26-59). That is where every measured
# codebase currently sits, and widening it is honest about the fact that we have
# never scanned a healthy control -- see health_grade's note on recalibration.
HEALTH_GRADE_BANDS = ((100, "S"), (90, "A"), (80, "B"), (70, "C"), (60, "D"),
                      (26, "F"))

HEALTH_GRADE_FLOOR = "X"

def health_grade(score):
    """Letter grade from the 0-100 health index, or None when health is None.

    Replaces the max-severity rollup, which SATURATED: one CRITICAL anywhere was
    an F and one HIGH anywhere was a D, regardless of size, so a 320 KLoC service
    with 100 HIGHs and a 30 KLoC utility with one both graded D. Across eleven
    measured runs the old rollup produced ten Ds and one F -- it could not tell
    any two codebases apart, which is why health had to be read instead.

    Severity has NOT stopped mattering; it moved to where it belongs. `--fail-on`
    plus summary.gate_severities is what breaks a build, risk_level still reports
    the worst severity present, and the distribution is displayed with the gate's
    reach marked on it. The grade answers a different question -- how much of the
    codebase is clean -- and now has a metric that can actually answer it.

    CALIBRATION CAVEAT, stated because the bands look more settled than they are:
    all eleven measured runs score 35.68-70.45, so they land C/D/F and nothing has
    ever reached B. We have never scanned a healthy control, so the bands are a
    reasonable prior, not a fitted result. `total_loc` and `weighted_defect` are
    both in every report, so a recut costs nothing and re-grades history exactly.
    """
    if score is None:
        return None
    for lower, letter in HEALTH_GRADE_BANDS:
        if score >= lower:
            return letter
    return HEALTH_GRADE_FLOOR

# Best-first. S/X bracket the A-F rollup used for per-panel grades; the letters
# in between keep their exact previous ordering.
_GRADE_ORDER = ["S", "A", "B", "C", "D", "F", "X"]

def _worst_grade(grades):
    present = [g for g in grades if g in _GRADE_ORDER]
    return max(present, key=_GRADE_ORDER.index) if present else "A"

def _parent_of(g):
    """Resolve a groups_meta entry's parent review-unit.

    Real groups.json (discovery's `_group_obj`, Task 7) always carries an
    explicit ``parent`` (subgroup -> its parent name; leaf -> self). Older/
    hand-built groups_meta (tests, or a pre-5.1 groups.json) may omit the
    key entirely, so fall back to splitting the flat id on its first ``:``
    -- authored group/subgroup names never contain ``:`` (#5.0-02 anti-escape
    holds), so `id.split(":", 1)[0]` is a safe, documented default that
    self-parents any plain (non-subgroup) name.
    """
    return g.get("parent") or g["name"].split(":", 1)[0]

def _roll_up_to_parent(group_objs, groups_meta, by_panel):
    """Group the report's per-flat-id unit objects by parent for presentation.

    A leaf group (flat id == its own parent, i.e. an ordinary un-nested
    groups.yml entry) passes through unchanged -- this is today's shape,
    keeping a flat groups.yml's report byte-identical. A genuine subgroup
    (flat id != parent, e.g. "UI:Admin" under parent "UI") is folded into a
    parent node: the parent's grade is `_worst_grade` over its subgroups'
    grades (per panel), its files are the union of its subgroups' files, and
    it lists its subgroups verbatim -- each keeping its own files/panel_grades/
    key_findings -- so group -> subgroup -> file drill-down stays intact.
    Purely a presentation regrouping: does not touch any finding, and is
    computed after grade()/gate-eligibility, so it cannot affect the overall
    letter/gate.
    """
    parents = [_parent_of(g) for g in groups_meta]
    rolled = []
    nodes_by_parent = {}
    for unit, parent in zip(group_objs, parents):
        if unit["name"] == parent:
            # Leaf / self-parented: unmodified, today's shape.
            rolled.append(unit)
            continue
        node = nodes_by_parent.get(parent)
        if node is None:
            node = {"name": parent, "_subunits": []}
            nodes_by_parent[parent] = node
            rolled.append(node)
        node["_subunits"].append(unit)

    for node in rolled:
        subs = node.pop("_subunits", None)
        if subs is None:
            continue
        files = []
        seen_files = set()
        for u in subs:
            for fpath in u["files"]:
                if fpath not in seen_files:
                    seen_files.add(fpath)
                    files.append(fpath)
        key_findings = []
        for u in subs:
            for kf in u["key_findings"]:
                if kf not in key_findings:
                    key_findings.append(kf)
        node["files"] = files
        node["panel_grades"] = {p: _worst_grade([u["panel_grades"][p] for u in subs])
                                 for p in by_panel}
        node["key_findings"] = key_findings[:5]
        node["subgroups"] = subs
    return rolled

_GATE_ROLE_NOTE = {
    "contributing": "**FAILS THE GATE**",
    "in_play": "in play, nothing confirmed here",
}
