"""Grades, gate verdict, certification and the health index."""
from typing import Any
from dataclasses import dataclass
import os
import stat

from . import findings as findings_mod


@dataclass(frozen=True)
class Graded:
    """grade_report()'s result: the report's `summary` and `groups` sections."""
    summary: dict
    groups: list


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

# #2013 fix round 1 (review I1): the MEASURED effect of emptying a driver, in
# one place, so the note, the HTML line, the stderr line and the schema cannot
# drift into describing different costs. Measured on the canonical git-lfs
# shape: index blob `ptr payload`, worktree `BIG payload`, plain `git status`
# clean, probe `status` ` M big.bin`, and `collect_changed_files`/`hunk_map`
# gaining a file nobody edited.
_SUPPRESSED_DRIVER_EFFECT = ("paths under a suppressed driver compare as "
                             "modified: dirtiness for them is unknown and a "
                             "delta may include them")


def certify(overall_grade, gate_eligible, fail_on, panels_incomplete, tools_absent,
            integrity_ok=True, verdicts_unloadable=0, verdicts_unanswered=0,
            missing_floor=0, tools_manifest_invalid=None, tools_network_excluded=None,
            delta_scope_suppressed_git_drivers=None, tools_file_partial=None):
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

    `tools_manifest_invalid` (#1644) is the REASON an unreadable
    `tools-manifest.json` sank certification, and it is what `coverage_note`
    reports. It is not the channel that moves the gate: the same fact rides in
    `meta.integrity`, so `integrity_ok` is false and the gate goes INCONCLUSIVE
    with every other integrity failure. Fix round 1 reversed an earlier ruling
    here -- exempting it from the gate made corrupting one byte of a
    target-writable file the cheapest way to turn an INCONCLUSIVE run into a
    PASS, on identical findings. It stays in `coverage_certified` too, so a
    caller that passes only the reason still cannot certify.

    `delta_scope_suppressed_git_drivers` (#2013 fix round 1) is the same
    two-channel shape: the keys whose suppression scoped a DELTA run. Emptying
    the target's clean filter makes git compare raw worktree bytes against a
    filtered index blob, so paths nobody touched read as modified -- on a
    delta-scoped run that inflated comparison chose the reviewed file set and
    the gate's scope, which is certification-grade. `reconcile` records it in
    `meta.integrity`, so `integrity_ok` is what moves the gate; this argument is
    what NAMES the caveat in `coverage_note`, and it sinks
    `coverage_certified` on its own so a caller that passes only the reason
    cannot certify either. `None` on a full-repo run, where suppression costs
    provenance and nothing the findings depend on.
    """
    base_gate = gate_verdict(gate_eligible, fail_on)          # PASS / FAIL / OFF
    high_value_incomplete = set(panels_incomplete) & findings_mod.HIGH_VALUE_PANELS
    gate_relevant_gap = (bool(high_value_incomplete) or bool(tools_absent)
                         or not integrity_ok or bool(verdicts_unloadable)
                         or bool(verdicts_unanswered) or bool(missing_floor)
                         or bool(tools_network_excluded))
    any_incomplete = bool(panels_incomplete)

    if base_gate == "PASS" and gate_relevant_gap:
        gate = "INCONCLUSIVE"
    else:
        gate = base_gate                                      # FAIL/OFF/PASS unchanged

    if any_incomplete:
        cert_grade, provisional = None, overall_grade
    else:
        cert_grade, provisional = overall_grade, None

    coverage_certified = not (gate_relevant_gap or any_incomplete
                              or tools_manifest_invalid
                              or delta_scope_suppressed_git_drivers or tools_file_partial)

    note = None
    if tools_manifest_invalid:
        # First: it is the reason the tool axis reports nothing, so a note about
        # what the tool axis found would read as a smaller problem than it is.
        # It is also the only channel that NAMES the file -- `integrity_ok`,
        # which is what moves the gate, is a bare bool.
        note = ("tools manifest unreadable — tool coverage could not be "
                "computed: %s" % tools_manifest_invalid)
    elif any_incomplete and not gate_relevant_gap:
        tail = sorted(p for p in panels_incomplete if p not in findings_mod.HIGH_VALUE_PANELS)
        note = ("gate certified; grade provisional — low-value panel(s) incomplete: %s"
                % ", ".join(tail))
    if tools_network_excluded:
        gap = "safe network unavailable — online scanner coverage missing: %s" % ", ".join(
            sorted(tools_network_excluded))
        note = "%s; %s" % (note, gap) if note else gap
    if delta_scope_suppressed_git_drivers:
        # Composed, never substituted: this run may also have an unreadable
        # manifest or a missing network, and an operator needs every reason.
        gap = ("delta scope inflated by suppressed git drivers — %s: %s"
               % (_SUPPRESSED_DRIVER_EFFECT,
                  ", ".join(sorted(delta_scope_suppressed_git_drivers))))
        note = "%s; %s" % (note, gap) if note else gap

    if tools_file_partial:
        # Valid scanner captures retain their findings and delta eligibility.
        # File gaps qualify coverage, independently of the finding-based gate.
        gap = "partial scanner file coverage: %s" % ", ".join(sorted(tools_file_partial))
        note = "%s; %s" % (note, gap) if note else gap

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

MAX_LOC_FILE_BYTES = 8 * 1024 * 1024
MAX_LOC_TOTAL_BYTES = 64 * 1024 * 1024
MAX_LOC_CANDIDATES = 10_000


def _loc_parts(path, lexical_root, real_root):
    """Return components beneath the supplied root, without following them."""
    normalized = os.path.normpath(path if os.path.isabs(path)
                                  else os.path.join(lexical_root, path))
    for root in (lexical_root, real_root):
        if os.path.commonpath((root, normalized)) == root:
            relative = os.path.relpath(normalized, root)
            return () if relative == "." else tuple(relative.split(os.sep))
    return None


def _read_loc_file(root_fd, parts, remaining):
    """Read one complete regular UTF-8 file, returning LOC and bytes consumed."""
    consumed = 0
    try:
        directory_fd = os.dup(root_fd)
        try:
            directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            for component in parts[:-1]:
                next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
                previous_fd = directory_fd
                directory_fd = next_fd
                os.close(previous_fd)
            flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
            fd = os.open(parts[-1], flags, dir_fd=directory_fd)
            try:
                info = os.fstat(fd)
                allowance = min(MAX_LOC_FILE_BYTES, remaining)
                if not stat.S_ISREG(info.st_mode) or info.st_size > allowance:
                    return 0, 0
                chunks = []
                while consumed < allowance:
                    chunk = os.read(fd, min(64 * 1024, allowance - consumed))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    consumed += len(chunk)
                # A growing file must not contribute a counted prefix. The second
                # stat also handles a file exactly as large as the byte allowance.
                if os.fstat(fd).st_size > consumed:
                    return 0, consumed
                content = b"".join(chunks)
                if b"\x00" in content:
                    return 0, consumed
                try:
                    text = content.decode("utf-8")
                except UnicodeError:
                    return 0, consumed
                return sum(bool(line.strip()) for line in text.splitlines()), consumed
            finally:
                os.close(fd)
        finally:
            os.close(directory_fd)
    except (OSError, ValueError):
        # Reads count against the call budget even when a later read, stat,
        # or descriptor close makes this file unmeasurable.
        return 0, consumed


def nonblank_loc(target, groups_meta):
    """Count unique nonblank lines in regular text files confined to target.

    Skip unsafe or incomplete files. Work is bounded to 8 MiB per file,
    64 MiB read per call, and 10,000 candidate rows per call; files over a
    bound contribute zero, so large repositories may have a smaller measured
    LOC denominator. Symlinks beneath target are never followed.
    """
    try:
        target_path = os.fspath(target)
        if not isinstance(target_path, str) or not target_path:
            return 0
        lexical_root = os.path.abspath(target_path)
        real_root = os.path.realpath(lexical_root)
        root_fd = os.open(real_root, os.O_RDONLY | os.O_DIRECTORY)
    except (OSError, TypeError, ValueError):
        return 0

    if not isinstance(groups_meta, (list, tuple)):
        os.close(root_fd)
        return 0

    seen = set()
    total = 0
    remaining = MAX_LOC_TOTAL_BYTES
    candidates = 0
    try:
        for group in groups_meta:
            if not isinstance(group, dict):
                continue
            files = group.get("files")
            if not isinstance(files, list):
                continue
            for path in files:
                candidates += 1
                if candidates > MAX_LOC_CANDIDATES:
                    return total
                if not isinstance(path, str):
                    continue
                try:
                    parts = _loc_parts(path, lexical_root, real_root)
                except (OSError, ValueError):
                    continue
                if not parts or parts in seen:
                    continue
                seen.add(parts)
                try:
                    count, consumed = _read_loc_file(root_fd, parts, remaining)
                except (OSError, ValueError):
                    continue
                total += count
                remaining -= consumed
                if remaining == 0:
                    return total
    finally:
        os.close(root_fd)
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
    config entry) passes through unchanged -- this is today's shape,
    keeping a flat config's report byte-identical. A genuine subgroup
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
    nodes_by_parent: dict[str, dict[str, Any]] = {}
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


def grade_report(run, resolved, reconciled):
    """The grading cluster (WS-0 S2): per-group panel grades, the health index,
    certification and the gate, from the resolved findings and the reconciled
    plan. Severity is never mutated here; grades and the gate are computed
    from gate-eligible findings only."""
    # #1701: under `--security redteam` a directory-NAME exclusion may keep a
    # tool finding out of the report BODY, but not out of the gate -- a payload
    # parked at `app/vendor/patched_auth.rb` passing a merge gate on the
    # strength of a conventional directory name is the defect the mode exists
    # to refuse. `reconcile` carries the drops here (empty in every other mode)
    # and they join the population `gate_verdict`, `risk_level`,
    # `gate_severity_roles` and `health_stats` read, so they count exactly as
    # un-suppressed findings of the same severity would.
    #
    # Unconditionally, rather than through `evidence.status` like the rest of
    # this set: a suppressed finding is withheld from the report body, so it is
    # never queued for the verify round and can never earn `tool_confirmed`.
    # Gating it on a verdict it is structurally unable to receive would leave
    # #1701 open under a longer explanation. They never enter `resolved.active`,
    # so `stats`, `top_issues`, the per-group objects and `findings[]` are
    # untouched -- the disclosure stays a count.
    gate_eligible = list(resolved.gate_eligible) + list(reconciled.gated_suppressed)
    # Seeded from the ORDERED list, never from `VALID_PANELS` (#1538): every
    # `panel_grades` mapping below and in the roll-up takes its key order from
    # this dict, and a set's order is randomised per process, so two reports
    # built from identical inputs were not byte-identical.
    by_panel: dict[str, list[dict[str, Any]]] = {p: [] for p in findings_mod.PANEL_ORDER}
    for f in gate_eligible:
        by_panel.get(f["panel"], by_panel["code"]).append(f)

    groups_meta = reconciled.groups_meta
    known_groups = {g["name"] for g in groups_meta}
    eligible_ids = {id(x) for x in gate_eligible}
    group_objs = []
    for g in groups_meta:
        gfiles = set(g["files"])
        gfind = [f for f in resolved.active
                 if (f.get("_group") == g["name"])
                 or (f.get("_group") not in known_groups
                     and (f.get("location") or {}).get("file") in gfiles)]
        geligible = [f for f in gfind if id(f) in eligible_ids]
        gp = {p: [x for x in geligible if x["panel"] == p] for p in by_panel}
        group_objs.append({
            "name": g["name"],
            "files": g["files"],
            "panel_grades": {p: grade(gp[p]) for p in by_panel},
            "key_findings": [f.get("title", "") for f in gfind
                             if f["severity"] in ("CRITICAL", "HIGH")][:5],
        })
    group_objs = _roll_up_to_parent(group_objs, groups_meta, by_panel)

    # The headline grade comes from the health index, not the max-severity
    # rollup -- see health_grade(). certify() needs it, and the same dict is
    # reused in the summary so the grade and the reported health can never
    # disagree.
    health = health_stats(nonblank_loc(run.target, groups_meta), gate_eligible)
    overall = health_grade(health["score"])
    cert = certify(overall, gate_eligible, run.fail_on, reconciled.panels_incomplete,
                   reconciled.tools_absent,
                   integrity_ok=reconciled.integrity_ok,
                   verdicts_unloadable=len(resolved.verdict_unloadable),
                   verdicts_unanswered=resolved.unanswered_gate,
                   missing_floor=len(reconciled.cell_audit["missing_floor"]),
                   tools_manifest_invalid=reconciled.tools_manifest_invalid,
                   tools_network_excluded=reconciled.tools_network_excluded,
                   delta_scope_suppressed_git_drivers=(
                       reconciled.delta_scope_suppressed_git_drivers),
                   tools_file_partial=reconciled.coverage.get("tools_file_partial"))
    summary = {
        "overall_grade": cert["overall_grade"],
        "provisional_grade": cert["provisional_grade"],
        "coverage_certified": cert["coverage_certified"],
        "coverage_note": cert["coverage_note"],
        "risk_level": risk_level(gate_eligible),
        "top_issues": [f.get("title", "") for f in
                       sorted(resolved.active, key=findings_mod._issue_sort)[:3]],
        "gate": cert["gate"],
        "gate_policy": ("include_unverified" if run.gate_unverified
                        else "confirmed_only"),
        # #1059: `stats` and `evidence_stats` count DIFFERENT populations --
        # `stats` the ACTIVE (non-rejected == findings[]) set, `evidence_stats`
        # ALL findings (active + discarded == findings[] + discarded_claims[]).
        # Their totals differ by len(rejected); the population tags + counts
        # block below make that explicit and reconcilable (the run-5 self-scan
        # surfaced two unlabeled HIGH counts in one summary).
        "stats": severity_stats(resolved.active),
        "stats_population": "active",
        # Which severities the --fail-on threshold puts in play, and which of
        # them the FAIL is actually made of. Computed off `gate_eligible`,
        # NOT off `stats` above -- see gate_severity_roles().
        "gate_severities": gate_severity_roles(gate_eligible, run.fail_on),
        # #1146: size-aware health ratio alongside the letter; denominator is
        # the gate-eligible set, numerator the reviewed scope's non-blank LoC.
        "health": health,
        "evidence_stats": findings_mod.evidence_stats(resolved.findings),
        "evidence_stats_population": "all",
        "counts": {
            "active": len(resolved.active),
            "discarded": len(resolved.rejected),
            "total": len(resolved.findings),
        },
        "delta": ({"on_diff": severity_stats(resolved.on_diff_active),
                   "pre_existing": severity_stats(resolved.pre_existing_active)}
                  if resolved.delta_mode else None),
    }
    return Graded(summary=summary, groups=group_objs)
