"""Grades, gate verdict, certification and the health index."""
from typing import Any
from dataclasses import dataclass
import os
import re
import stat

import scripts.coverage_model as coverage_model
import scripts.evidence as evidence_mod
import scripts.runners.outage as outage_mod
import scripts.tools_manifest as tools_manifest
from . import backups as backups_mod
from . import coverage_io
from . import health_basis
from . import findings as findings_mod
from . import verdict_scope as verdict_scope_mod


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

# #3672: the rollup letter back to what it stands for. A person is shown the severity;
# the report JSON keeps the letter (`panel_grades`) for one release.
_WORST_SEVERITY = {"F": "CRITICAL", "D": "HIGH", "C": "MEDIUM", "B": "LOW", "A": "none"}


def worst_severity_of(letter):
    """The worst gate-eligible severity a `grade()` letter stands for: CRITICAL, HIGH,
    MEDIUM, LOW, or "none" (nothing at LOW or above). "unknown" for anything `grade`
    does not assign, so a damaged report never reads as clean."""
    return _WORST_SEVERITY.get(letter, "unknown") if isinstance(letter, str) else "unknown"


def risk_level(findings):
    """Determine overall risk level (CRITICAL/HIGH/MEDIUM/LOW) from findings."""
    for sev in ("CRITICAL", "HIGH", "MEDIUM"):
        if findings_mod._present(findings, sev):
            return sev
    return "LOW"

def gate_verdict(findings, fail_on):
    """Return CI gate verdict (PASS/FAIL/OFF) based on findings and threshold.

    The threshold itself is `findings.severity_floor_admits` (#2222)."""
    if not fail_on:
        return "OFF"
    # Resolve the floor BEFORE any verdict: an unknown `--fail-on` raises here
    # whether or not `findings` is empty, so a misconfigured gate never reads
    # PASS on a clean run (#2222 re-review; argparse constrains the flag today).
    findings_mod.severity_floor_rank(fail_on)
    return ("FAIL" if any(findings_mod.severity_floor_admits(f, fail_on)
                          for f in findings) else "PASS")

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

NO_SCA_COVERAGE_NOTE = "no SCA tool produced output on an applicable tree"


def unaudited_notes(dependency_audit):
    """#3648: one fixed sentence per ecosystem the repaired SCA receipt records as
    unaudited, in ecosystem order; [] for a receipt without the record. The words
    only: which of them stop certification is `unaudited_gap`'s."""
    rows = (dependency_audit or {}).get("unaudited") if isinstance(dependency_audit, dict) else None
    if not isinstance(rows, dict):
        return []
    sentences = (tools_manifest.unaudited_sentence(ecosystem, rows[ecosystem])
                 for ecosystem in sorted(rows))
    return [sentence for sentence in sentences if sentence]


def unaudited_gap(dependency_audit):
    """#3700: the ecosystems that stop certification, in ecosystem order: recorded as
    unaudited for a reason in `tools_manifest.UNAUDITED_UNCERTIFIED`, and one the fixed
    sentences can name. [] for a receipt without the record, or one this cannot read
    (the read repairs a malformed record to the whole-tree fallback, which is a gap of
    its own). Owner's ruling, 2026-11-20: an applicable ecosystem whose auditor did not
    run, or needed `--online`, is a tree nobody audited in part."""
    rows = (dependency_audit or {}).get("unaudited") if isinstance(dependency_audit, dict) else None
    if not isinstance(rows, dict):
        return []
    return [ecosystem for ecosystem in sorted(key for key in rows if isinstance(key, str))
            if rows[ecosystem] in tools_manifest.UNAUDITED_UNCERTIFIED
            and tools_manifest.unaudited_sentence(ecosystem, rows[ecosystem])]


# What NOT CERTIFIED says when a gate-relevant gap names no reason of its own.
GATE_GAP_NOTE = "gate-relevant coverage did not complete"
PROVISIONAL_PREFIX = "health provisional: "


_VERIFY_CELL_STAGE = re.compile(r"(?:primary|backup)(?:-part[0-9]+)?$")


def _verify_entry_target(entry_id, cells, tool_queue_ids):
    """Every current verify item ``entry_id`` could name.

    Group names may contain hyphens, so splitting an id cannot recover a cell.
    Match it against the actual engaged ``(group, domain)`` population instead.
    An empty set is a future/malformed/unmapped spelling; more than one target
    is the theoretical collision where an id names both a cell and a tool
    queue entry. Both shapes remain unknown for host-failure attribution, but
    every candidate still proves that item was launched.
    """
    targets: set[tuple[Any, ...]] = set()
    if isinstance(entry_id, str):
        for group, domain in cells:
            prefix = "verify-%s-%s-" % (group, domain)
            if entry_id.startswith(prefix) and _VERIFY_CELL_STAGE.fullmatch(
                    entry_id[len(prefix):]):
                targets.add(("cell", group, domain))
        if entry_id.startswith("verify-tool-"):
            queue_id = entry_id[len("verify-tool-"):]
            if queue_id in tool_queue_ids:
                targets.add(("tool", queue_id))
    return targets


def _verify_shortfall_counts(targets, unknown=0):
    verify_cells = sum(target[0] == "cell" for target in targets)
    tool_advisors = sum(target[0] == "tool" for target in targets)
    counts = []
    if verify_cells:
        counts.append("%d verify cell%s" % (verify_cells, "" if verify_cells == 1 else "s"))
    if tool_advisors:
        counts.append("%d tool-advisor entr%s" % (
            tool_advisors, "y" if tool_advisors == 1 else "ies"))
    if unknown:
        counts.append("%d verify entr%s of unknown shape" % (
            unknown, "y" if unknown == 1 else "ies"))
    return " and ".join(counts)


def verify_host_shortfall(resolved, verify_ledger):
    """The named shortfall left by a host-cut-short verify phase.

    Latest ledger entry ids are joined to the two populations verify actually
    dispatched: engaged matrix cells and queued tool findings. Only an undone
    item with a latest host failure, plus items not launched before that stop,
    is attributed to the host. A verdict retires a cell/tool's older host
    failure; an entry-class or legacy-unknown failure cannot taint a different
    shortfall. Unreadable bounded ledger bytes fail closed with an explicit
    unknown-class reason, while a missing ledger remains ordinary legacy state.
    Because an unknown-shape host row cannot be joined safely, its conservative
    count may overlap a named pending item; the emitted reason says so.
    """
    if verify_ledger is None:
        return None
    raw_unverified = (getattr(resolved, "verify_matrix", None) or {}).get(
        "unverified_engaged") or []
    pending_cells = {
        tuple(cell) for cell in raw_unverified
        if isinstance(cell, (list, tuple)) and len(cell) == 2
    }
    all_cells = {
        tuple(cell) for cell in getattr(resolved, "verify_engaged_cells", ())
        if isinstance(cell, (list, tuple)) and len(cell) == 2
    } | pending_cells
    pending_tools = set(getattr(resolved, "tool_advisor_pending_ids", ()) or ())
    all_tools = set(getattr(resolved, "tool_advisor_queue_ids", ()) or ()) | pending_tools
    pending = ({("cell", group, domain) for group, domain in pending_cells}
               | {("tool", queue_id) for queue_id in pending_tools})
    if not pending:
        return None

    if getattr(verify_ledger, "unreadable", False):
        counts = _verify_shortfall_counts(pending)
        return ("verify phase cut short — failure class unknown (ledger unreadable); "
                "%s left undone; %s" % (counts, outage_mod.RESUME_ADVICE))

    launched_entries = tuple(getattr(verify_ledger, "launched_entries", ()) or ())
    host_entries = tuple(getattr(verify_ledger, "host_failure_entries", ()) or ())
    targets = {
        entry_id: _verify_entry_target(entry_id, all_cells, all_tools)
        for entry_id in set(launched_entries) | set(host_entries)
    }
    launched_targets = {
        target for entry_id, candidates in targets.items()
        if entry_id in launched_entries for target in candidates
    }
    # A host row is attributable only when its identity has exactly one
    # candidate. An ambiguous host row remains unknown and cannot be retired by
    # a verdict for either candidate, while both candidates still count as
    # launched above and therefore cannot inflate the never-launched tail.
    host_targets = {
        next(iter(candidates)) for entry_id, candidates in targets.items()
        if entry_id in host_entries and len(candidates) == 1
    }
    active_host_targets = pending & host_targets
    unknown_host_entries = sum(len(targets.get(entry_id, ())) != 1
                               for entry_id in host_entries)
    if not active_host_targets and not unknown_host_entries:
        return None

    stranded = set(active_host_targets)
    # An id with zero candidates cannot name a pending item. An ambiguous id's
    # full candidate set is already in launched_targets. What remains really
    # was never launched before the active/unknown host failure cut the phase.
    stranded.update(pending - launched_targets)
    counts = _verify_shortfall_counts(stranded, unknown=unknown_host_entries)
    if unknown_host_entries and stranded:
        counts += " (unknown-shape count may overlap named pending work)"
    return ("verify phase cut short by a host-class failure — %s left undone; %s"
            % (counts, outage_mod.RESUME_ADVICE))


def grade_shortfalls(resolved, backups=None, verify_ledger=None):
    """#3667 (owner ruling 2026-11-15): verify work this run left UNDONE, one
    reason per entry. ONE shared rule reads this list: any reason here holds the
    letter back as `provisional_grade`, sinks `coverage_certified`, moves a PASS
    gate to INCONCLUSIVE, and is named in `coverage_note` and beside the letter.
    A new kind of undone verify work (#3753's host-cut-short verify phase) adds
    its reason here and nothing else.

    Unanswered tool advisors: each such finding stays in the report as
    `tool_reported` (unverified, not gate-eligible); the letter must not read as
    though they had been checked. Unanswered verify advisors (the agent claims
    owed a verdict, `unanswered_gate` less the tool ones): when every verify
    launch fails nothing is confirmed, health reads 100 and the letter S stood
    beside an INCONCLUSIVE gate -- the same undone work, the same rule.
    Summoned backup advisors that never answered, or answered unloadably
    (#3676, `meta.coverage.backups`), are the third. Advisor verdicts that were
    not counted, because they named a claim their advisor was not handed or came
    with no record of what it was handed (#3702), are the fourth."""
    reasons = []
    unanswered_tools = getattr(resolved, "unanswered_tools", 0) or 0
    unanswered_claims = max((getattr(resolved, "unanswered_gate", 0) or 0) - unanswered_tools, 0)
    for count, kind in ((unanswered_tools, "tool finding"), (unanswered_claims, "finding")):
        if count:
            reasons.append("%d %s%s unanswered by %s %sadvisor%s" % (
                count, kind, "" if count == 1 else "s", "its" if count == 1 else "their",
                "" if kind == "tool finding" else "verify ", "" if count == 1 else "s"))
    # #3702: verdicts an advisor wrote that were not counted are undone work too:
    # whatever they said, nobody the controller asked has said it.
    host = verify_host_shortfall(resolved, verify_ledger)
    return (reasons + backups_mod.shortfall_reasons(backups)
            + verdict_scope_mod.reasons(getattr(resolved, "verdict_stats", None))
            + ([host] if host else []))


def certify(overall_grade, gate_eligible, fail_on, panels_incomplete, tools_absent,
            integrity_ok=True, verdicts_unloadable=0, verdicts_unanswered=0,
            missing_floor=0, tools_manifest_invalid=None, tools_network_excluded=None,
            tools_file_partial=None,
            dependency_audit_gap=False, custom_profile=None,
            config_notes=None, native_unparsed_gap=None, shortfalls=(),
            dependency_unaudited=(), unaudited_uncertified=False):
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
    `shortfalls` (#3667) is `grade_shortfalls`' list: undone verify work. Any
    entry is gate-relevant, holds the letter back exactly as an incomplete panel
    does, and is named in the note.
    """
    base_gate = gate_verdict(gate_eligible, fail_on)          # PASS / FAIL / OFF
    syntax_disclosures = coverage_model.semgrep_syntax_disclosures(tools_file_partial)
    notification_disclosures = coverage_model.semgrep_notification_disclosures(
        tools_file_partial)
    tools_file_partial, asset_skips = coverage_model.certifying_file_gaps(tools_file_partial)
    high_value_incomplete = set(panels_incomplete) & findings_mod.HIGH_VALUE_PANELS
    gate_relevant_gap = (bool(high_value_incomplete) or bool(tools_absent)
                         or not integrity_ok or bool(verdicts_unloadable)
                         or bool(verdicts_unanswered) or bool(missing_floor)
                         or bool(tools_network_excluded)
                         or dependency_audit_gap or bool(native_unparsed_gap)
                         or bool(shortfalls)
                         # #3700: an applicable ecosystem whose auditor did not run. Its
                         # sentence is in `dependency_unaudited`, which the note carries.
                         or bool(unaudited_uncertified))
    any_incomplete = bool(panels_incomplete)

    if base_gate == "PASS" and gate_relevant_gap:
        gate = "INCONCLUSIVE"
    else:
        gate = base_gate                                      # FAIL/OFF/PASS unchanged

    # #3548: one reason or a list of them (a custom cap, a committed `exclude:` that bit). Each
    # is a sentence, so they join as sentences: the first stays lower-case after the prefix.
    reasons = [r for r in ([custom_profile] if isinstance(custom_profile, str)
                           else custom_profile or ()) if r]
    custom_profile = " ".join(reasons[:1] + [r[:1].upper() + r[1:] for r in reasons[1:]])
    # #1495: a non-default scan profile moves the LETTER only, the way an incomplete panel does.
    # The gate and coverage_certified do not see it: the findings and the coverage are what
    # they are, only the letter is not comparable with the bands.
    if any_incomplete or custom_profile or shortfalls:
        cert_grade, provisional = None, overall_grade
    else:
        cert_grade, provisional = overall_grade, None

    coverage_certified = not (gate_relevant_gap or any_incomplete
                              or tools_manifest_invalid or tools_file_partial)

    note = None
    if tools_manifest_invalid:
        # First: it is the reason the tool axis reports nothing, so a note about
        # what the tool axis found would read as a smaller problem than it is.
        # It is also where the coverage AXIS names the reason -- `integrity_ok`,
        # which is what moves the gate, is a bare bool. Since #1761 the terminal
        # summary names it a second time, as an `**Integrity:**` line off
        # `integrity.INTEGRITY_KEYS`; this note is what the HTML report and
        # `summary.coverage_note` consumers still read.
        note = ("tools manifest unreadable or invalid — tool coverage could not be "
                "computed: %s" % tools_manifest_invalid)
    elif any_incomplete and not gate_relevant_gap:
        tail = sorted(p for p in panels_incomplete if p not in findings_mod.HIGH_VALUE_PANELS)
        note = ("gate certified; health provisional — low-value panel(s) incomplete: %s"
                % ", ".join(tail))
    if custom_profile:
        # #1495 review: the profile reason sits BESIDE any coverage reason, never in its place.
        # A gate-relevant gap with no named reason gets the generic one here, or the profile text
        # would become the whole NOT CERTIFIED reason and blame the gate on the group size.
        lead = note if note is not None or not gate_relevant_gap else GATE_GAP_NOTE
        if note is None and unaudited_uncertified and not dependency_audit_gap:
            # #3700: this gap has a name, so its own sentences lead and the generic one
            # is not said. (The whole-tree gap keeps its #3648 order, below.)
            lead = "; ".join(dependency_unaudited) or GATE_GAP_NOTE
            dependency_unaudited = ()
        reason = (custom_profile if lead and PROVISIONAL_PREFIX.rstrip(": ") in lead
                  else PROVISIONAL_PREFIX + custom_profile)
        note = "; ".join(filter(None, (lead, reason)))
    if shortfalls:
        note = "; ".join(filter(None, (note, *shortfalls)))
    if dependency_audit_gap:
        # #3648: which ecosystem, and why, beside the bare "no SCA output".
        note = "; ".join(filter(None, (note, NO_SCA_COVERAGE_NOTE, *dependency_unaudited)))
    if tools_network_excluded:
        gap = "safe network unavailable — online scanner coverage missing: %s" % ", ".join(
            sorted(tools_network_excluded))
        note = "%s; %s" % (note, gap) if note else gap
    if native_unparsed_gap:
        note = "%s; %s" % (note, native_unparsed_gap) if note else native_unparsed_gap

    if tools_file_partial:
        # Valid scanner captures retain their findings.
        # File gaps qualify coverage, independently of the finding-based gate.
        gap = "partial scanner file coverage: %s" % ", ".join(sorted(tools_file_partial))
        dockerfile_unanalyzed = sum(
            facts["dockerfile_unanalyzed"]
            for facts in tools_file_partial.values()
            if isinstance(facts, dict)
            and type(facts.get("dockerfile_unanalyzed")) is int
            and facts["dockerfile_unanalyzed"] > 0)
        if dockerfile_unanalyzed:
            gap += ("; %d Dockerfile-like file(s) received no Dockerfile rule analysis"
                    % dockerfile_unanalyzed)
        note = "%s; %s" % (note, gap) if note else gap
    for tool, disclosure in sorted(notification_disclosures.items()):
        gap = "%d %s scanner notification(s)" % (disclosure["count"], tool)
        if disclosure["files"]:
            named = []
            for row in disclosure["files"]:
                detail = "%s (%s" % (row["file"], ", ".join(row["ids"]))
                if row["ids_omitted"]:
                    detail += "; %d additional id(s) omitted" % row["ids_omitted"]
                named.append(detail + ")")
            gap += ": %s" % ", ".join(named)
        if disclosure["files_omitted"]:
            gap += "; %d additional file(s) omitted" % disclosure["files_omitted"]
        if disclosure["unlocated"]:
            gap += ("; %d notification(s) without an identifiable file"
                    % disclosure["unlocated"])
        note = "%s; %s" % (note, gap) if note else gap
    for tool, disclosure in sorted(syntax_disclosures.items()):
        gap = "%d file(s) %s could not parse" % (disclosure["count"], tool)
        if disclosure["files"]:
            gap += ": %s" % ", ".join(disclosure["files"])
        if disclosure["files_omitted"]:
            gap += "; %d additional file(s) omitted" % disclosure["files_omitted"]
        note = "%s; %s" % (note, gap) if note else gap
    note = coverage_model.with_asset_skip_note(note, asset_skips)     # #3283: disclosed, not counted
    if not dependency_audit_gap:
        # #3648 (ruling b): an ecosystem no auditor read is named even when another
        # ecosystem's auditor answered. Naming it moves nothing; whether the tree still
        # certifies is `unaudited_uncertified`'s (#3700).
        note = "; ".join(filter(None, (note, *dependency_unaudited))) or None
    # #3548: config disclosures that move nothing (a scout-only exclude, `exclude_paths:`).
    note = "; ".join(filter(None, (note, *(config_notes or ())))) or None

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

# Severity weights for the defect footprint used by the bounded health score. The score drives the
# letter grade when available; severity/evidence policy alone sets the gate. x5 per band; INFO is 0.
HEALTH_WEIGHTS = {"INFO": 0, "LOW": 1, "MEDIUM": 5, "HIGH": 25, "CRITICAL": 125}
# #3230 (owner ruling (a), 2026-10-26): a finding counts at most SPAN_CAP lines, so citing a
# whole file cannot outweigh a run's real defects: one span-weighted 7,458-line MEDIUM swung a
# commit's grade from A to C. 50 is about one function; the A/B/C bands were kept as set.
SPAN_CAP = 50

def _loc_span(finding):
    """Lines a finding spans: line_end - line_start + 1, floored at 1 and capped at
    SPAN_CAP. Missing/None/non-int/inverted ranges count as 1.

    #3732: for a scanner rule's hits collapsed into one finding, the widest hit, not
    the shown one's (the lowest line). Only a scanner finding's own hits count: a claim that absorbed one carries its other
    lines for the reader, and what a reviewer writes there is not read at all."""
    loci = [finding.get("location") or {}]
    if evidence_mod.is_tool_sourced(finding):
        loci += [locus for locus in finding.get("additional_loci") or ()
                 if isinstance(locus, dict)]
    return max(_span(loc) for loc in loci)


def _span(loc):
    start = loc.get("line_start")
    if not isinstance(start, int):
        return 1
    end = loc.get("line_end", start)
    if not isinstance(end, int):
        end = start
    return min(SPAN_CAP, max(1, end - start + 1))

# #3731: (merge group, weight) on each row of a merge group whose weight is not simply the
# sum of its rows' own: the group is counted once, at its heaviest counted finding
# (`verdicts._weigh_the_group`). Private: an agent cannot write a `_` key.
GROUP_WEIGHT = "_group_weight"


def own_weight(finding, severity=None):
    """What one finding weighs by itself: weight[severity] * the lines it spans (span
    capped, #3230). `severity`: the one it will be published at, when the finding
    does not carry it yet. INFO weighs nothing."""
    weight = HEALTH_WEIGHTS.get(str(severity or finding.get("severity", "INFO")).upper(), 0)
    return weight * _loc_span(finding) if weight else 0


def weighted_defect(findings):
    """Severity-weighted defect footprint: the sum over `findings` of each one's own
    weight (`own_weight`), with every merge group among them counted once, at its
    stamped weight (`GROUP_WEIGHT`, #3731)."""
    total, counted = 0, set()
    for f in findings:
        stamp = f.get(GROUP_WEIGHT)
        if not isinstance(stamp, tuple):
            total += own_weight(f)
        elif stamp[0] not in counted:
            counted.add(stamp[0])
            total += stamp[1]
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

HEALTH_FORMULA = ("100 * total_loc / (total_loc + weighted_defect), weighted_defect = "
                  "sum(weight[severity] * min(lines spanned, %d))" % SPAN_CAP)

def health_score(total_loc, weighted):
    """Bounded health index: the share of the reviewed codebase NOT under severity-weighted defect
    footprint, as 0-100. Higher = healthier; a repo with no gate-eligible weighted defect scores
    exactly 100. Rounded to 2 decimals.

    Replaces the original `total_loc / weighted_defect` ratio, which was wrong in three ways at
    once. It ran BACKWARDS from the intuition a reader brings to a number labelled "health" (the
    divisor carried the defect); it was unbounded above, so there was no value meaning "perfect";
    and it divided by `weighted_defect`, which is 0 for a CLEAN repo -- so the single best possible
    outcome was the one case that had to return None.

    This form inverts all three. The remaining degenerate case is total_loc == 0 -- no reviewed
    file was readable -- which returns None because it is a broken MEASUREMENT, not a health of
    zero. That distinction became load-bearing when the letter grade started keying on this score:
    nonblank_loc() skips missing, unreadable and binary files silently, so a run whose paths do not
    resolve (a stale worktree, a moved checkout, a revoked volume permission) would otherwise
    report the floor grade for a codebase it never managed to read.

    Deliberately NOT `100 - weighted/total_loc`, the obvious inversion: that reads as a percentage
    but has no floor (a file-scoped run with wide HIGH findings goes negative), and it compresses
    real spread to nothing. Measured on the six calibration targets it puts every one between 98.20
    and 99.58 -- 1.38 points to separate codebases whose defect density differs 4.3x, leaving
    gate-F/risk-CRITICAL gotify and the healthiest target 1.25 points apart. The saturating form
    used here spreads the same six across 35.68-70.45, in the same order.
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
        "span_cap": SPAN_CAP,
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

# #3652 (owner ruling 2026-11-14; the #3328 bands are not reopened): a severity cap
# layered on the band grade, so "A" never sits beside an open confirmed CRITICAL.
# Worst severity first; a level only ever LOWERS the band letter. Owner ruling
# 2026-11-15: CRITICAL caps at D, HIGH at B.
# ORDER IS LOAD-BEARING: `severity_cap` returns the FIRST severity present, so
# the tuple must run worst severity first with a cap that is never better than
# the next one's (monotone). TestSeverityCapUnits pins both properties.
SEVERITY_GRADE_CAPS = (("CRITICAL", "D"), ("HIGH", "B"))


def severity_cap(gate_eligible):
    """The cap the worst CONFIRMED severity puts on the band grade, or None.

    Confirmed means the default gate's own population (`GATE_ELIGIBLE_DEFAULT`:
    tool- or advisor-confirmed, or a confirmed claim the backup could not check),
    whatever the run's gate policy. An unconfirmed finding never caps -- even
    under `--gate-unverified`, and even a redteam directory-name drop that joins
    the gate (#1701) -- so the cap adds no confirmation variance of its own on top
    of the gate's (#3584)."""
    confirmed = [f for f in gate_eligible
                 if (f.get("evidence") or {}).get("status") in evidence_mod.GATE_ELIGIBLE_DEFAULT]
    for severity, cap in SEVERITY_GRADE_CAPS:
        count = sum(1 for f in confirmed if f.get("severity") == severity)
        if count:
            return {"severity": severity, "count": count, "cap": cap}
    return None


def apply_severity_cap(band_grade, cap):
    """(grade, disclosure): the band letter, lowered to the cap when the cap is worse.

    The disclosure is None when nothing was lowered -- no confirmed CRITICAL/HIGH,
    a band already at or below the cap, or no band letter at all (unmeasured
    health stays unknown rather than inventing one)."""
    if (cap is None or band_grade not in _GRADE_ORDER
            or _GRADE_ORDER.index(band_grade) >= _GRADE_ORDER.index(cap["cap"])):
        return band_grade, None
    return cap["cap"], {
        "band_grade": band_grade, "grade": cap["cap"], "severity": cap["severity"],
        "count": cap["count"],
        "note": "capped from %s by %d confirmed %s" % (band_grade, cap["count"],
                                                      cap["severity"])}

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


def grade_report(run, resolved, reconciled, verify_ledger=None):
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
    root = run.root if run.root is not None else run.target
    health = health_stats(nonblank_loc(root, groups_meta), gate_eligible)
    # #3220: no review cell answered, so the score's zero-defect side measured
    # nothing. Health and grade are unknown; risk keeps only what a finding proves.
    no_review = coverage_io.review_matrix_missing(reconciled.cell_audit)
    if no_review:
        health["score"] = None
    risk = risk_level(gate_eligible)
    if no_review and risk == "LOW" and not findings_mod._present(gate_eligible, "LOW"):
        risk = None
    overall, grade_cap = apply_severity_cap(health_grade(health["score"]),
                                            severity_cap(gate_eligible))
    coverages = getattr(reconciled, "coverages", None)
    shortfalls = grade_shortfalls(resolved, (getattr(reconciled, "coverage", None) or {})
                                  .get("backups"), verify_ledger)
    cert = certify(overall, gate_eligible, run.fail_on, reconciled.panels_incomplete,
                   reconciled.tools_absent,
                   integrity_ok=reconciled.integrity_ok,
                   verdicts_unloadable=len(resolved.verdict_unloadable),
                   verdicts_unanswered=resolved.unanswered_gate,
                   missing_floor=len(reconciled.cell_audit["missing_floor"]),
                   tools_manifest_invalid=reconciled.tools_manifest_invalid,
                   tools_network_excluded=reconciled.tools_network_excluded,
                   tools_file_partial=reconciled.coverage.get("tools_file_partial"),
                   dependency_audit_gap=getattr(reconciled, "dependency_audit_gap", False),
                   native_unparsed_gap=getattr(reconciled, "native_unparsed_gap", None),
                   custom_profile=health_basis.custom_profile_reasons(run, coverages),
                   config_notes=health_basis.config_notes(run, coverages),
                   shortfalls=shortfalls,
                   dependency_unaudited=unaudited_notes(
                       (getattr(reconciled, "coverage", None) or {}).get("dependency_audit")),
                   unaudited_uncertified=bool(unaudited_gap(
                       (getattr(reconciled, "coverage", None) or {}).get("dependency_audit"))))
    summary = {
        "overall_grade": cert["overall_grade"],
        "provisional_grade": cert["provisional_grade"],
        # #3667: why the letter is held back for undone verify work; [] when none is.
        "grade_shortfalls": shortfalls,
        # #3652: the band letter and the cap that lowered it, or None.
        "grade_cap": grade_cap,
        "coverage_certified": cert["coverage_certified"],
        "coverage_note": (cert["coverage_note"] if not no_review else "; ".join(
            filter(None, (coverage_io.REVIEW_MATRIX_MISSING_NOTE, cert["coverage_note"])))),
        "risk_level": risk,
        "top_issues": [f.get("short_title") or f.get("title", "") for f in
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
        # The health score uses gate-eligible defects and the reviewed scope's
        # non-blank LoC; the same score supplies the headline letter above.
        "health": health,
        "evidence_stats": findings_mod.evidence_stats(resolved.findings),
        "evidence_stats_population": "all",
        "counts": {
            "active": len(resolved.active),
            "discarded": len(resolved.rejected),
            "total": len(resolved.findings),
        },
    }
    return Graded(summary=summary, groups=group_objs)
