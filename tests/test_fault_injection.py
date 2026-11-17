"""#3669: the fault-injection matrix. Each case reviews the fixture target end to end while the
fake host fails a planned share of its launches, then checks what the run left behind against
five invariants and against the fault-free control.

`tests/fault_harness.py` is the fixture, the plan, the driver and the report reader.

**The default run is not the full matrix.** It is `default_cases()`: the control, every mode
against every single phase at 100%, every mode against all three verification phases at 100%,
every mode against every phase after the scout at 50% and at 10%, one mode per phase at 50% and
at 10%, and every mode as a transient fault. Set `PANOPTICON_FAULT_MATRIX=full` for the whole
cross (5 modes x 8 targets x 3 rates, plus the transient and control cases); a default run
shows them as skipped, by name, so pytest's summary line counts what a default run left out.

One departure from the design note, approved by the coordinator: the partial-rate cases that
span phases target the four phases AFTER the scout, not all five. A scout that never answers
stops the run at its first checkpoint, so "all phases" at 50% or 10% only repeated the scout
case ten times. "All phases" is still in the full matrix and in the transient cases.

**Known gaps.** `KNOWN_GAPS` lists the checks that do not hold on main today, by the kind of
work left undone and the issue that owns each. A case whose only problems are listed there
is a strict `xfail` naming those issues. A problem no row covers fails the case, and so does
a row whose check holds again: each fix removes its own rows.
"""
import dataclasses
import functools
import glob
import json
import os
import re
import shutil

import pytest

from scripts import evidence
import scripts.loop_progress as loop_progress
import scripts.phases.runio as runio
import scripts.phases.verify as verify
import scripts.run_manifest as run_manifest
import scripts.runners.outage as outage
from tests import fault_harness as fh
from tests.orchestrate_helpers import (FAULT_EMPTY, FAULT_EXIT, FAULT_MALFORMED, FAULT_MODES,
                                       FAULT_OUTAGE, FAULT_TIMEOUT, FakeRunner)

MATRIX_SWITCH = "PANOPTICON_FAULT_MATRIX"
VERIFICATION = (fh.ADVISOR, fh.BACKUP, fh.TOOL)
AFTER_SCOUT = (fh.REVIEW,) + VERIFICATION
TARGETS = tuple((phase,) for phase in fh.PHASES) + (VERIFICATION, AFTER_SCOUT, fh.PHASES)
RATES = (100, 50, 10)


def _name(plan):
    if plan is None:
        return "control"
    target = {VERIFICATION: "verification", AFTER_SCOUT: "after_scout",
              fh.PHASES: "all"}.get(plan.phases, plan.phases[0])
    return "%s-%s-%d%s" % (plan.mode, target, plan.rate, "" if plan.persistent else "-transient")


def full_cases():
    cases = [None]
    cases += [fh.Plan(mode, target, rate)
              for mode in FAULT_MODES for target in TARGETS for rate in RATES]
    cases += [fh.Plan(mode, fh.PHASES, 100, persistent=False) for mode in FAULT_MODES]
    return cases


def default_cases():
    cases = [None]
    cases += [fh.Plan(mode, (phase,), 100) for mode in FAULT_MODES for phase in fh.PHASES]
    cases += [fh.Plan(mode, VERIFICATION, 100) for mode in FAULT_MODES]
    # Partial shares across phases use the phases AFTER the scout: a scout that never
    # answers stops the run at its first checkpoint, so "all" would only repeat that case.
    cases += [fh.Plan(mode, AFTER_SCOUT, rate) for mode in FAULT_MODES for rate in (50, 10)]
    # One mode per phase at each partial rate, rotated so every mode meets a partial share.
    for offset, rate in ((0, 50), (2, 10)):
        cases += [fh.Plan(FAULT_MODES[(index + offset) % len(FAULT_MODES)], (phase,), rate)
                  for index, phase in enumerate(fh.PHASES)]
    cases += [fh.Plan(mode, fh.PHASES, 100, persistent=False) for mode in FAULT_MODES]
    return cases


FULL = os.environ.get(MATRIX_SWITCH) == "full"
SKIP_REASON = "not in the default run: set %s=full" % MATRIX_SWITCH


def _params():
    """Every case of the full matrix, the ones a default run leaves out marked as skipped: so
    pytest's own summary line counts them, and a green default run never reads as the cross."""
    run_by_default = set(default_cases())
    return [pytest.param(plan, id=_name(plan), marks=(
                [] if FULL or plan in run_by_default else [pytest.mark.skip(reason=SKIP_REASON)]))
            for plan in full_cases() if plan is not None]


class Lab:
    """The runs of one test process: each case is driven once, whatever asks about it."""

    def __init__(self):
        self.patches = fh.module_patches()
        for patch in self.patches:
            patch.start()
        self.cleanups = []

    def addCleanup(self, call):                 # `fault_harness.build_target`'s one need
        self.cleanups.append(call)

    def close(self):
        for patch in self.patches:
            patch.stop()
        for call in self.cleanups:
            call()

    @functools.cached_property
    def control(self):
        return fh.drive(self)

    @functools.lru_cache(maxsize=None)
    def outcome(self, plan, split_bytes=None):
        if plan is None:
            return self.control if not split_bytes else fh.drive(self, split_bytes=split_bytes)
        seeded = plan.seeded_for(self.control.launched)
        # An outage never ends by itself: the loop pauses for the operator. So the host heals
        # and the loop is run again, as it would be.
        return fh.drive(self, seeded, recover=fh.is_outage(plan), split_bytes=split_bytes)


@pytest.fixture(scope="module")
def lab():
    made = Lab()
    yield made
    made.close()


def test_the_default_run_is_a_named_subset_of_the_full_matrix():
    full, default = full_cases(), default_cases()
    assert len(set(full)) == len(full) and len(set(default)) == len(default)
    assert set(default) < set(full)
    assert (len(default), len(full)) == (56, 126)
    skipped = [param for param in _params() if param.marks]
    assert len(skipped) == (0 if FULL else len(full) - len(default))
    assert len({param.id for param in _params()}) == len(full) - 1      # every id is distinct


# --- reading a report --------------------------------------------------------------------

def _status(finding):
    return (finding.get("evidence") or {}).get("status")


def _locus(finding):
    location = finding.get("location") or {}
    return location.get("file"), location.get("line_start")


def _is_tool(finding):
    return str(finding.get("source") or "").startswith("tool:")


def tool_claims():
    """Every tool finding the fixture's scanners report: (scanner, rule, package, locus)."""
    claims = [("semgrep", rule, None, (path, line)) for rule, path, line in fh.SEMGREP]
    claims += [("osv-scanner", advisory, package, ("Cargo.lock", 1))
               for package, (_version, advisories) in fh.ADVISORIES.items()
               for advisory in advisories]
    return claims


def _accounts_for(claim, finding):
    """Is `finding` the report's record of tool `claim`: the tool finding itself, or the
    agent finding it was merged into at the same locus."""
    scanner, rule, package, locus = claim
    proof = finding.get("tool_evidence") or {}
    if _is_tool(finding):
        return (finding.get("source") == "tool:" + scanner and proof.get("rule_id") == rule
                and proof.get("package_name") == package)
    by = (finding.get("evidence") or {}).get("verified_by") or []
    return _locus(finding) == locus and "tool+agent" in (by if isinstance(by, list) else [by])


def _persisted_claims(root):
    """(title, cell file) for every agent claim a review cell left on disk."""
    claims = []
    for path in sorted(glob.glob(runio._pano(root, "findings-*.json"))):
        with open(path, encoding="utf-8") as cell:
            try:
                body = json.load(cell)
            except ValueError:
                continue                         # a cut-off cell is no claim at all
        claims += [(f.get("title"), os.path.basename(path))
                   for f in (body.get("findings") or []) if isinstance(f, dict)]
    return claims


def _issue(finding):
    """Which issue a finding is about: its locus, and for an advisory its rule, because a
    lockfile's findings all sit on line 1. A tool finding and the agent claim it was merged
    into are one issue, so neither the title nor the source is part of it."""
    proof = finding.get("tool_evidence") or {}
    return _locus(finding) + ((proof.get("rule_id"),) if proof.get("package_name") else ())


def _gate_eligible(report):
    """The issues the gate counts: confirmed, at or above `--fail-on`."""
    in_play = set((report["summary"].get("gate_severities") or {}).get("in_play") or [])
    return {_issue(f) for f in report["findings"]
            if _status(f) in evidence.GATE_ELIGIBLE_DEFAULT and f.get("severity") in in_play}


def _summary_lines(outcome):
    """The report summary as the operator's terminal showed it."""
    marker = loop_progress.SUMMARY_PREFIX
    return [line.split(marker, 1)[1] for line in outcome.terminal.splitlines()
            if marker in line]


#: What names each kind of work, as a pattern. Loose on purpose: the invariant is that the
#: reader is told what was left undone, not how the sentence is written. But each must be
#: about ITS work: "tool axis" in a note about review cells does not name the tool advisors,
#: and "tool advisor" does not name the domain advisors.
_NAMES = {fh.REVIEW: r"review|panel|fan-out|floor",
          fh.ADVISOR: r"verif|verdict|(?<!tool[- ])(?<!backup )advisor",
          fh.BACKUP: r"backup",
          fh.TOOL: r"tool[- ](advisor|finding|verdict)"}


def _unnamed(text, phases):
    """The phases with undone work whose kind of work `text` does not mention."""
    return [phase for phase in phases if not re.search(_NAMES[phase], (text or "").lower())]


# --- the invariants ----------------------------------------------------------------------
# Each returns what is wrong as (check, phase, sentence), empty when the invariant holds.
# `check` says which part of the invariant it is, so a known gap can be named exactly; `phase`
# is the kind of undone work the problem is about, or None when it is about none. `control`
# is the fault-free run of the same fixture.
LOSS, COUNTS, GATE = "1.loss", "2.counts", "4.gate"
CERTIFIED, LETTER = "3.certified", "3.letter"
# Invariant 5 asks two things of each surface, and they are different defects: whether it
# SAYS the run is not certified at all, and whether it NAMES the work beside that. A known
# gap in the second must never excuse the first (#3678 review).
JSON_SAYS, JSON_COUNTS = "5.json.says", "5.json.counts"
TERMINAL_SAYS, TERMINAL_NAMES = "5.terminal.says", "5.terminal.names"
HTML_SAYS, HTML_NAMES = "5.html.says", "5.html.names"
# #3677: beside naming the kind of work, the HTML names each review cell that went unanswered.
HTML_CELLS = "5.html.cells"

def no_silent_loss(control, outcome):
    """1. Every tool finding ingested, and every agent claim a cell persisted, is in the
    report in some state or among the discarded claims with a reason. A review cell that
    never answered is named."""
    wrong = []
    report = outcome.report
    discarded = report["discarded_claims"]
    for claim in tool_claims():
        if not any(_accounts_for(claim, f) for f in report["findings"] + discarded):
            wrong.append((LOSS, None, "tool finding %s %s is nowhere in the report" % claim[:2]))
    titles = {f.get("title") for f in report["findings"] + discarded}
    for title, cell in _persisted_claims(outcome.root):
        if title not in titles:
            wrong.append((LOSS, None, "agent claim %r (persisted in %s) is nowhere in the "
                          "report" % (title, cell)))
    for finding in discarded:
        if _status(finding) != "rejected" or not (finding.get("evidence") or {}).get("reasoning"):
            wrong.append((LOSS, None, "discarded claim %s carries no rejection reason"
                          % finding.get("id")))
    message = outcome.statuses[-1].get("message") or ""
    for entry in outcome.unanswered_in(fh.REVIEW):
        _review, group, domain = entry.split("-")
        if "%s/%s" % (group, domain) not in message:
            wrong.append((LOSS, fh.REVIEW, "review cell %s/%s never answered and the status "
                          "does not name it" % (group, domain)))
    return wrong


def counts_reconcile(control, outcome):
    """2. The tool axis adds up, its queue is what was ingested, and each scanner's
    findings are all accounted for."""
    wrong = []
    report = outcome.report
    coverage = report["meta"]["coverage"]
    axis = coverage["tool_axis"]
    answered = axis["confirmed"] + axis["rejected"] + axis["needs_more_info"]
    if answered + axis["unanswered"] != axis["queued"]:
        wrong.append((COUNTS, None, "tool_axis does not add up: %r" % (axis,)))
    if axis["queued"] != len(tool_claims()):
        wrong.append((COUNTS, None, "tool_axis.queued is %d; the scanners reported %d"
                      % (axis["queued"], len(tool_claims()))))
    never = len(outcome.unanswered_in(fh.TOOL)) + (
        fh.MERGED_ADVISOR in outcome.unanswered_in(fh.ADVISOR))
    if axis["unanswered"] != never:
        wrong.append((COUNTS, None, "tool_axis.unanswered is %d; %d tool claim(s) had an advisor "
                      "that never answered" % (axis["unanswered"], never)))
    everything = report["findings"] + report["discarded_claims"]
    for scanner in fh.SCANNERS:
        ingested = (coverage["adapters"].get(scanner) or {}).get("findings")
        claims = [c for c in tool_claims() if c[0] == scanner]
        if ingested != len(claims):
            wrong.append((COUNTS, None, "%s: adapters says %r ingested; it reported %d"
                          % (scanner, ingested, len(claims))))
        found = [c for c in claims if any(_accounts_for(c, f) for f in everything)]
        if len(found) != len(claims):
            wrong.append((COUNTS, None, "%s: %d of %d findings are in the report or its discards"
                          % (scanner, len(found), len(claims))))
    stats = report["summary"]["evidence_stats"]
    if stats["tool_reported"] != sum(1 for f in report["findings"]
                                     if _status(f) == "tool_reported"):
        wrong.append((COUNTS, None, "evidence_stats.tool_reported disagrees with the findings"))
    return wrong


def no_false_certification(control, outcome):
    """3. Undone verify, review or tool-advisor work means no certified grade, or a
    disclosed shortfall that names the work. With nothing undone, the run certifies exactly
    as the control does."""
    summary = outcome.report["summary"]
    undone = sorted({fh.phase_of(e) for e in outcome.unanswered})
    if not undone:
        expected = {key: control.report["summary"][key]
                    for key in ("overall_grade", "provisional_grade", "coverage_certified")}
        got = {key: summary[key] for key in expected}
        return [] if got == expected else [
            (CERTIFIED, None, "nothing was left undone, yet certification is %r; the "
             "control's is %r" % (got, expected))]
    if summary["coverage_certified"] is True:
        return [(CERTIFIED, phase, "%s work was left undone and the run is coverage_certified"
                 % phase) for phase in undone]
    if summary["overall_grade"] is None:
        return []
    return [(LETTER, phase, "a letter grade (%s) stands and coverage_note (%r) does not name "
             "the undone %s work" % (summary["overall_grade"], summary.get("coverage_note"),
                                     phase))
            for phase in _unnamed(summary.get("coverage_note"), undone)]


def gate_fails_closed(control, outcome):
    """4. No finding becomes gate-eligible because a host failed, and one that stops being
    eligible that way does not leave a passing gate behind. Undone work is never PASS."""
    wrong = []
    eligible, before = _gate_eligible(outcome.report), _gate_eligible(control.report)
    gate, control_gate = outcome.report["summary"]["gate"], control.report["summary"]["gate"]
    for issue in sorted(eligible - before, key=str):
        wrong.append((GATE, None, "%s is gate-eligible only under the fault"
                      % ":".join(map(str, issue))))
    if not outcome.unanswered:
        if eligible != before or gate != control_gate:
            wrong.append((GATE, None, "nothing was left undone, yet the gate is %s over %d eligible "
                          "finding(s); the control's is %s over %d"
                          % (gate, len(eligible), control_gate, len(before))))
        return wrong
    if gate == "PASS":
        wrong.append((GATE, None, "work was left undone and the gate is PASS"))
    if not eligible and gate != "INCONCLUSIVE":
        wrong.append((GATE, None, "no finding is gate-eligible after the fault and the gate is %s, "
                      "not INCONCLUSIVE" % gate))
    return wrong


def _json_counts(outcome, phase):
    """Does the JSON carry a count of the undone `phase` work, in its own field."""
    coverage = outcome.report["meta"]["coverage"]
    undone = outcome.unanswered_in(phase)
    if phase == fh.REVIEW:
        missing = {tuple(pair) for pair in coverage["cells"]["missing_floor"]}
        return {tuple(e.split("-")[1:]) for e in undone} <= missing
    if phase == fh.TOOL:
        return coverage["tool_axis"]["unanswered"] >= len(undone)
    if phase == fh.ADVISOR:
        return (coverage["verdicts"]["unanswered"] or 0) >= 1
    if phase == fh.BACKUP:
        # #3676: `meta.coverage.backups` counts the summoned backups that never
        # answered (or came back unloadable); #3679 review F3 reads it here.
        backups = coverage.get("backups") or {}
        return (backups.get("unanswered") or 0) + (backups.get("unloadable") or 0) >= 1
    return False


def _not_certified_text(outcome):
    """(terminal, HTML): what each says beside NOT CERTIFIED, or "" where it does not."""
    terminal = " ".join(line for line in _summary_lines(outcome) if "NOT CERTIFIED" in line)
    return terminal, " ".join(re.findall(r"<div class='not-certified'>(.*?)</div>",
                                         outcome.html, re.S))


def shortfall_is_disclosed(control, outcome):
    """5. The terminal, the JSON and the HTML each show the shortfall: each says the run is
    not certified, and says what kind of work was left undone."""
    undone = sorted({fh.phase_of(e) for e in outcome.unanswered})
    terminal, page = _not_certified_text(outcome)
    summary = outcome.report["summary"]
    surfaces = ((TERMINAL_SAYS, TERMINAL_NAMES, "terminal", terminal),
                (HTML_SAYS, HTML_NAMES, "HTML", page))
    if not undone:
        return [(says, None, "%s says NOT CERTIFIED and nothing was left undone" % where)
                for says, _names, where, text in surfaces
                if control.report["summary"]["coverage_certified"] and "NOT CERTIFIED" in text]
    wrong = []
    for phase in undone:
        if summary["coverage_certified"] is not False:
            wrong.append((JSON_SAYS, phase, "JSON: coverage_certified is %r with %s work undone"
                          % (summary["coverage_certified"], phase)))
        if not _json_counts(outcome, phase) and _unnamed(summary.get("coverage_note"), [phase]):
            wrong.append((JSON_COUNTS, phase, "JSON: no field counts the undone %s work and "
                          "coverage_note (%r) does not name it"
                          % (phase, summary.get("coverage_note"))))
        for says, names, where, text in surfaces:
            if "NOT CERTIFIED" not in text:
                wrong.append((says, phase, "%s does not say NOT CERTIFIED with %s work undone"
                              % (where, phase)))
            elif _unnamed(text, [phase]):
                wrong.append((names, phase, "%s does not name the undone %s work beside NOT "
                              "CERTIFIED (it says %r)" % (where, phase, text[:120])))
    unnamed = [cell for cell in _cells(outcome.unanswered_in(fh.REVIEW)) if cell not in page]
    if unnamed and "NOT CERTIFIED" in page:
        wrong.append((HTML_CELLS, fh.REVIEW, "HTML does not name the unanswered review cell(s) "
                      "%s beside NOT CERTIFIED (it says %r)" % (", ".join(unnamed), page[:160])))
    return wrong


def _cells(entries):
    """Review entries as the cells a reader is told about: `review-app-COD` -> `app/COD`."""
    return sorted("/".join(entry.split("-")[1:]) for entry in entries)


INVARIANTS = (no_silent_loss, counts_reconcile, no_false_certification, gate_fails_closed,
              shortfall_is_disclosed)


def problems(control, outcome):
    """Every (check, phase, sentence) that does not hold for `outcome`."""
    return [row for invariant in INVARIANTS for row in invariant(control, outcome)]


def _comparable(outcome):
    """What two runs of the same target must agree on, without run ids, paths or times."""
    report = outcome.report
    coverage = report["meta"]["coverage"]
    summary = {key: value for key, value in report["summary"].items() if key != "health"}
    summary["health_score"] = report["summary"]["health"]["score"]
    return {"findings": sorted((f["id"], _status(f), f["severity"]) for f in report["findings"]),
            "discarded": sorted(f["id"] for f in report["discarded_claims"]),
            "tool_axis": coverage["tool_axis"], "verify_matrix": coverage["verify_matrix"],
            "cells": coverage["cells"], "summary": summary}


def expected_status(plan):
    """How a case ends. A scout that never answers stops the run: the loop's per-entry cap
    is all that bounds it. Every later phase has its own attempt budget, so the run finishes
    and the report carries the gap."""
    if plan is None or not plan.persistent or fh.is_outage(plan):
        return "complete"                        # an outage case has healed by its last status
    return "error" if fh.SCOUT in plan.phases else "complete"


# --- what is known to fail today ---------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class Gap:
    """One check known not to hold for one kind of undone work, and the issue that owns it.
    Each fix removes its own rows: a row whose check holds again fails the case."""
    issue: str
    phase: str
    check: str
    when: object = None       # outcome -> bool: the runs this gap shows in; None means all


KNOWN_GAPS = (
    # #3641 and #3667's rows are closed by #3667's shared `grading.grade_shortfalls` rule:
    # unanswered verify and tool advisors hold the letter back and are named on every surface.
    # #3676's rows are closed by `meta.coverage.backups` and its `grade_shortfalls` reasons.
    # #3677's row is closed: the HTML report names each review cell that returned no answer.
)


def _expected_gaps(outcome):
    undone = {fh.phase_of(e) for e in outcome.unanswered}
    return [gap for gap in KNOWN_GAPS
            if gap.phase in undone and (gap.when is None or gap.when(outcome))]


def triage(found, expected):
    """(problems no expected gap covers, expected gaps with no problem). Both must be empty
    for a case to be a known failure: the first is a new defect, the second a fixed one whose
    row is still in the table."""
    known = {(gap.check, gap.phase) for gap in expected}
    seen = {row[:2] for row in found}
    return ([row for row in found if row[:2] not in known],
            [gap for gap in expected if (gap.check, gap.phase) not in seen])


# --- the tests ---------------------------------------------------------------------------

def test_the_known_gap_table_can_neither_hide_a_problem_nor_outlive_its_fix():
    gap = Gap("#1", fh.TOOL, LETTER)
    listed, other_check, other_phase = ((LETTER, fh.TOOL, "a"), (CERTIFIED, fh.TOOL, "b"),
                                        (LETTER, fh.ADVISOR, "c"))
    assert triage([listed], [gap]) == ([], [])
    assert triage([listed, listed], [gap]) == ([], [])
    # A different check for the same work, the same check for other work, and a problem
    # about no work at all are each new: a known gap excuses only itself.
    assert triage([listed, other_check], [gap]) == ([other_check], [])
    assert triage([listed, other_phase], [gap]) == ([other_phase], [])
    assert triage([(LOSS, None, "d")], [gap]) == ([(LOSS, None, "d")], [gap])
    assert triage([listed], []) == ([listed], [])
    # A row with nothing left to excuse must go.
    assert triage([], [gap]) == ([], [gap])
    assert triage([], []) == ([], [])
    # Every row names a real check and a phase that can leave work undone.
    checks = {LOSS, COUNTS, GATE, CERTIFIED, LETTER, JSON_SAYS, JSON_COUNTS, TERMINAL_SAYS,
              TERMINAL_NAMES, HTML_SAYS, HTML_NAMES, HTML_CELLS}
    for row in KNOWN_GAPS:
        assert row.check in checks and row.phase in fh.PHASES and row.issue.startswith("#")
    assert len({(row.phase, row.check, row.when) for row in KNOWN_GAPS}) == len(KNOWN_GAPS)


def test_the_control_certifies_and_shows_every_state(lab):
    """The 0% run: what every other case is measured against, so it has to be a real review."""
    control = lab.control
    assert [s["status"] for s in control.statuses] == ["complete"]
    assert control.injected == [] and control.unanswered == []
    assert {fh.phase_of(e) for e in control.launched} == set(fh.PHASES)
    summary, coverage = control.report["summary"], control.report["meta"]["coverage"]
    assert summary["coverage_certified"] is True and summary["coverage_note"] is None
    assert summary["overall_grade"] is not None and summary["provisional_grade"] is None
    # The default gate: no `--fail-on` was passed and none is committed (#3673).
    assert summary["gate_severities"]["fail_on"] == "CRITICAL" and summary["gate_disabled"] is None
    assert run_manifest.load_manifest(control.root)["flags"]["fail_on"] is None
    eligible = _gate_eligible(control.report)
    assert summary["gate"] == "FAIL" and eligible
    assert {len(issue) for issue in eligible} == {2, 3}, "agent claims and advisories both gate"
    axis = coverage["tool_axis"]
    assert axis["queued"] == len(tool_claims()) and axis["unanswered"] == 0
    assert min(axis["confirmed"], axis["rejected"], axis["needs_more_info"]) >= 1
    assert {_status(f) for f in control.report["discarded_claims"]} == {"rejected"}
    assert ({_is_tool(f) for f in control.report["discarded_claims"]} == {True, False})
    merged = [f for f in control.report["findings"]
              if not _is_tool(f) and _accounts_for(tool_claims()[0], f)]
    assert len(merged) == 1, "the tool finding merged into an agent finding is the fixture's point"
    assert sorted(coverage["adapters"]) == sorted(fh.SCANNERS)
    assert max(len(advisories) for _v, advisories in fh.ADVISORIES.values()) >= 3
    assert problems(control, control) == []
    assert control.part_files == [], "the control fits one file; the split case is separate"


def test_a_plan_selects_an_exact_and_repeatable_share(lab):
    ids = lab.control.launched
    by_phase = {phase: sorted(e for e in set(ids) if fh.phase_of(e) == phase)
                for phase in fh.PHASES}
    for rate in (10, 50, 100):
        plan = fh.Plan(FAULT_MODES[0], fh.PHASES, rate).seeded_for(ids)
        assert plan == fh.Plan(FAULT_MODES[0], fh.PHASES, rate).seeded_for(ids)
        for phase, entries in by_phase.items():
            chosen = [e for e in entries if plan.selects(e)]
            assert len(chosen) == max(1, round(len(entries) * rate / 100)), (rate, phase)
            assert chosen == plan.selected(entries)
    assert fh.Plan(FAULT_MODES[0], fh.PHASES, 0).selected(ids) == []
    one = fh.Plan(FAULT_MODES[0], (fh.TOOL,), 100)
    assert {fh.phase_of(e) for e in one.selected(ids)} == {fh.TOOL}
    transient = fh.Plan(FAULT_MODES[0], (fh.TOOL,), 100, persistent=False)
    entry = by_phase[fh.TOOL][0]
    assert (transient.mode_for(entry, 1), transient.mode_for(entry, 2)) == (FAULT_MODES[0], None)
    assert (one.mode_for(entry, 1), one.mode_for(entry, 9)) == (FAULT_MODES[0],) * 2
    with pytest.raises(ValueError):
        fh.Plan("melt", (fh.TOOL,), 100)


def test_each_fault_is_the_kind_of_failure_it_claims_to_be():
    """The modes are only worth their names if the loop classifies them as intended."""
    runner = FakeRunner()
    entry = {"id": "scout-app", "delivery": "return_json", "out_file": os.devnull}
    made = {mode: runner._fault(entry, mode) for mode in FAULT_MODES}
    assert outage.classify_failure(made[FAULT_OUTAGE].host_error) == outage.HOST_FAILURE
    for mode in (FAULT_EXIT, FAULT_TIMEOUT):
        assert not made[mode].ok and made[mode].failure_class != outage.HOST_FAILURE
    assert "timed out" in made[FAULT_TIMEOUT].error
    for mode in (FAULT_MALFORMED, FAULT_EMPTY):
        assert made[mode].ok and made[mode].error is None
    assert made[FAULT_EMPTY].text == ""
    with pytest.raises(ValueError):
        json.loads(made[FAULT_MALFORMED].text)
    assert [mode for _entry, mode in runner.injected] == list(FAULT_MODES)


@pytest.mark.parametrize("plan", _params())
def test_a_host_failure_is_never_silent(lab, plan, request):
    control, outcome = lab.control, lab.outcome(plan)
    assert outcome.injected, "the plan failed no launch: the case would pass for nothing"
    assert {mode for _entry, mode in outcome.injected} == {plan.mode}
    assert outcome.status == expected_status(plan), outcome.statuses[-1]

    if fh.is_outage(plan):
        # The loop pauses for as long as the host is down, and publishes nothing meanwhile.
        assert outcome.stalled == ["paused"] * fh.MAX_INVOCATIONS and outcome.recovered
        assert not outcome.stalled_report
    if outcome.status != "complete":
        assert outcome.report is None, "a run that did not complete published a report"
        return
    if not outcome.unanswered:
        # Recovery: a retry that lands, or a healed host, leaves the control's report.
        assert _comparable(outcome) == _comparable(control)

    found = problems(control, outcome)
    expected = _expected_gaps(outcome)
    unexpected, fixed = triage(found, expected)
    assert not unexpected, "no issue covers:\n  " + "\n  ".join(
        "%s: %s" % (check, sentence) for check, _phase, sentence in unexpected)
    assert not fixed, ("these hold again, so remove their rows from KNOWN_GAPS: "
                       + ", ".join("%s (%s, %s)" % (gap.issue, gap.phase, gap.check)
                                   for gap in fixed))
    if expected:
        request.applymarker(pytest.mark.xfail(
            strict=True, reason=", ".join(sorted({gap.issue for gap in expected}))))
        pytest.fail("known: " + "; ".join(sentence for _check, _phase, sentence in found))


# --- a backup that answers part of what it was handed (#3695) -----------------------------

@pytest.fixture(scope="module")
def partial(lab):
    """(whole, short): the three-claim target with its backup answering every claim, and
    with it answering one of the three on every attempt."""
    return (fh.drive(lab, replies=fh.PartialBackup(whole=True)),
            fh.drive(lab, replies=fh.PartialBackup()))


def _backup_charges(outcome):
    with open(runio._pano(outcome.root, verify._VERIFY_ATTEMPTS_FILE), encoding="utf-8") as fh_:
        return json.load(fh_)[verify._verify_key(*fh.PartialBackup.CELL, "backup")]


def _cell_claims(outcome):
    return [f for f in outcome.report["findings"]
            if (f.get("title") or "").startswith("%s/%s defect" % fh.PartialBackup.CELL)]


def test_a_backup_that_answers_one_of_its_three_claims_holds_every_invariant(lab, partial):
    """The partial-backup row. Nothing failed to launch, so no plan is involved: the entry
    answered, and left two of its three claims without a verdict. That is undone backup
    work, and the five invariants are asked of it as of any other."""
    whole, short = partial
    assert (whole.status, short.status) == ("complete", "complete")
    assert whole.unanswered == [] and short.unanswered == [fh.PartialBackup.SHORT]
    assert problems(whole, whole) == []
    assert problems(whole, short) == []
    # Asked again, on the budget a short primary advisor has: every dispatch is charged
    # until the cell has spent its three. #3698: and every charge is a launch. The third
    # used to buy none, because the short bundle on disk read as done once the budget
    # was spent.
    assert _backup_charges(whole) == 1 == whole.launched.count(fh.PartialBackup.SHORT)
    assert _backup_charges(short) == verify._MAX_VERIFY_ATTEMPTS == 3
    assert short.launched.count(fh.PartialBackup.SHORT) == 3


def test_the_two_claims_a_partial_backup_left_are_counted_and_named(partial):
    whole, short = partial
    before, after = (o.report["meta"]["coverage"]["backups"] for o in (whole, short))
    assert before["summoned"] == before["answered"] and before["claims_unanswered"] == 0
    assert before["claims_scoped"] >= fh.PartialBackup.CLAIMS
    assert after == dict(before, answered=before["answered"] - 1, unanswered=1,
                         claims_unanswered=2)
    reasons = ["1 backup advisor unanswered", "2 findings unanswered by their backup advisors"]
    assert whole.report["summary"]["grade_shortfalls"] == []
    assert short.report["summary"]["grade_shortfalls"] == reasons
    # The same three findings either way; the two the backup skipped carry no backup verdict.
    assert [f["title"] for f in _cell_claims(short)] == [f["title"] for f in _cell_claims(whole)]
    assert [f.get("backup_confirmed") for f in _cell_claims(whole)] == [True, True, True]
    assert sorted(str(f.get("backup_confirmed")) for f in _cell_claims(short)) == [
        "None", "None", "True"]
    # Each surface says how many findings, beside how many advisors.
    summary = short.report["summary"]
    assert (summary["overall_grade"], summary["coverage_certified"]) == (None, False)
    assert summary["provisional_grade"] == whole.report["summary"]["overall_grade"]
    terminal, page = _not_certified_text(short)
    for surface in (summary["coverage_note"], terminal, page):
        for reason in reasons:
            assert reason in surface, (reason, surface)


# --- every charged dispatch is a launch (#3698) ---------------------------------------------

def _charges(outcome):
    """{`<group>/<domain>/<stage>`: dispatches charged} off the run's verify record."""
    with open(runio._pano(outcome.root, verify._VERIFY_ATTEMPTS_FILE), encoding="utf-8") as fh_:
        return {key: count for key, count in json.load(fh_).items()
                if key.endswith(("/primary", "/backup"))}


def _launches(outcome):
    """The same keys, counted off what the runner was asked to launch."""
    counts: dict[str, int] = {}
    for entry in outcome.launched:
        if fh.phase_of(entry) in (fh.ADVISOR, fh.BACKUP):
            _verify, group, domain, stage = entry.split("-")[:4]
            counts["%s/%s/%s" % (group, domain, stage)] = counts.get(
                "%s/%s/%s" % (group, domain, stage), 0) + 1
    return counts


def test_a_short_primary_advisor_is_launched_for_each_dispatch_it_is_charged(lab, partial):
    """The short-primary row: the advisor for one cell answers one of its three claims,
    every time. Charged three dispatches and launched three times, and the run ends."""
    short = "verify-%s-%s-primary" % fh.PartialBackup.CELL
    outcome = fh.drive(lab, replies=fh.PartialBackup(short=short))
    assert outcome.status == "complete" and len(outcome.statuses) == 1
    assert outcome.unanswered == [short]
    assert problems(partial[0], outcome) == []
    key = verify._verify_key(*fh.PartialBackup.CELL, "primary")
    assert _charges(outcome)[key] == _launches(outcome)[key] == verify._MAX_VERIFY_ATTEMPTS == 3
    assert _charges(outcome) == _launches(outcome)
    # The two claims with no verdict are the verify advisor's shortfall, named as such.
    assert outcome.report["summary"]["grade_shortfalls"] == [
        "2 findings unanswered by their verify advisors"]
    assert outcome.report["summary"]["coverage_certified"] is False


def test_an_unloadable_bundle_on_disk_is_launched_for_each_dispatch_it_is_charged(lab):
    """The unloadable row: every primary advisor is cut off and leaves the cut-off file,
    every time. With a file on disk the third dispatch launched nothing; with none (an
    exit) it always launched. Both are three and three now."""
    for mode in (FAULT_MALFORMED, FAULT_EXIT):
        outcome = lab.outcome(fh.Plan(mode, (fh.ADVISOR,), 100))
        assert outcome.status == "complete", mode
        charged = {key: count for key, count in _charges(outcome).items()
                   if key.endswith("/primary")}
        assert charged and set(charged.values()) == {verify._MAX_VERIFY_ATTEMPTS}, mode
        assert {key: _launches(outcome)[key] for key in charged} == charged, mode


def test_in_a_run_with_nothing_wrong_every_charge_is_one_launch(lab, partial):
    for outcome in (lab.control, partial[0]):
        assert _charges(outcome) == _launches(outcome)
        assert set(_charges(outcome).values()) == {1}


# --- an advisor that speaks of claims it was not handed (#3702) ---------------------------

_COD, _LIB, _SEC = ("app", "COD"), ("lib", "COD"), ("app", "SEC")
#: name -> (the scene, what one advisor volunteers in it, how many verdicts that is). Each row
#: is run twice: with the advisor silent about the claims it was not handed, and with it
#: speaking. On main every one of these changed a claim's disposition, and the first and the
#: third certified a run with claims no advisor of theirs had answered.
HOSTILE_ROWS = {
    # The issue's case. The primary answers one claim of three, so the backup is handed that
    # one. The backup rejects the two no primary answered: they were discarded.
    "backup-rejects-what-no-primary-answered": (
        dict(triple=_COD, answers={"verify-app-COD-primary": 1}),
        dict(speaker="verify-app-COD-backup", about=_COD, says="REJECTED"), 2),
    # The primary rejected a claim, so the backup was not handed it. The backup confirms it:
    # it came back out of the discarded claims, confirmed twice.
    "backup-confirms-what-its-primary-rejected": (
        dict(), dict(speaker="verify-app-SEC-backup", about=_SEC, says="CONFIRMED",
                     only=fh.REFUTED_CLAIM), 1),
    # Another cell's primary never answers. This cell's primary rejects that cell's claim.
    "primary-rejects-another-cells-unanswered-claim": (
        dict(answers={"verify-lib-COD-primary": 0}),
        dict(speaker="verify-app-COD-primary", about=_LIB, says="REJECTED"), 1),
    # Every advisor answers what it was handed. One primary also rejects another cell's
    # claim, which that cell's own primary confirmed; HIGH, so no backup stands over it. The
    # first verdict file by name used to win: `verdicts-app-COD` before `verdicts-lib-COD`.
    "primary-rejects-what-another-cells-primary-confirmed": (
        dict(severity={_LIB: "HIGH"}),
        dict(speaker="verify-app-COD-primary", about=_LIB, says="REJECTED"), 1),
    # ...and the other way: it confirms a claim another cell's own primary rejected.
    "primary-confirms-what-another-cells-primary-rejected": (
        dict(), dict(speaker="verify-app-COD-primary", about=_SEC, says="CONFIRMED",
                     only=fh.REFUTED_CLAIM), 1),
}
#: The rows whose silent run certifies: the advisor answers all it was handed and adds to it.
CERTIFIED_WHEN_SILENT = {"backup-confirms-what-its-primary-rejected",
                         "primary-rejects-what-another-cells-primary-confirmed",
                         "primary-confirms-what-another-cells-primary-rejected"}


@pytest.fixture(scope="module")
def hostile(lab):
    """{row: (silent, speaking)}, each driven once."""
    return {name: (fh.drive(lab, replies=fh.OutOfScope(**scene)),
                   fh.drive(lab, replies=fh.OutOfScope(**scene, **voice)))
            for name, (scene, voice, _count) in HOSTILE_ROWS.items()}


def _dispositions(outcome):
    """Where every claim ended up and on whose word: (title, id, in the report or discarded,
    evidence status, severity, backup_confirmed, confirmation status)."""
    report = outcome.report
    return sorted(
        (str(f.get("title")), f["id"], where, _status(f), f["severity"],
         str(f.get("backup_confirmed")), str((f.get("provenance") or {}).get("confirmation_status")))
        for where, claims in (("report", report["findings"]),
                              ("discarded", report["discarded_claims"]))
        for f in claims)


def _out_of_scope_reason(count):
    return "%d advisor verdict%s outside %s handed scope" % (
        count, "" if count == 1 else "s", "its" if count == 1 else "their")


@pytest.mark.parametrize("row", sorted(HOSTILE_ROWS))
def test_an_advisor_cannot_speak_for_a_claim_it_was_not_handed(hostile, row):
    _scene, voice, count = HOSTILE_ROWS[row]
    silent, speaking = hostile[row]
    assert (silent.status, speaking.status) == ("complete", "complete")
    # The five invariants hold for the silent run, and 1, 2 and 4 for the speaking one as
    # they stand. 3 and 5 read "no launch failed" as "certifies as the control does", and
    # this row is the case where that is not so: the pins below ask what they would.
    assert problems(silent, silent) == []
    for invariant in (no_silent_loss, counts_reconcile, gate_fails_closed):
        assert invariant(silent, speaking) == []
    before, after = silent.report["summary"], speaking.report["summary"]
    # 1. Every claim is where the silent run left it, on the same advisor's word.
    assert _dispositions(speaking) == _dispositions(silent)
    assert after["gate"] == before["gate"]
    # 2. The run is not certified, whatever the silent run was: the verdicts nobody asked
    #    for are a shortfall of their own, and the only one added.
    assert before["coverage_certified"] is (row in CERTIFIED_WHEN_SILENT)
    assert after["grade_shortfalls"] == before["grade_shortfalls"] + [_out_of_scope_reason(count)]
    assert (after["coverage_certified"], after["overall_grade"]) == (False, None)
    assert after["provisional_grade"] == (before["overall_grade"] or before["provisional_grade"])
    # 3. They are counted, and named on every surface beside NOT CERTIFIED.
    counted = [o.report["meta"]["coverage"]["verdicts"] for o in (silent, speaking)]
    assert [(v["out_of_scope"], v["scope_not_recorded"]) for v in counted] == [(0, 0), (count, 0)]
    terminal, page = _not_certified_text(speaking)
    for surface in (after["coverage_note"], terminal, page):
        assert _out_of_scope_reason(count) in surface, surface
    # 4. The advisor was asked again, on the budget of any advisor that did not answer.
    group, domain, stage = voice["speaker"].split("-")[1:]
    with open(runio._pano(speaking.root, verify._VERIFY_ATTEMPTS_FILE), encoding="utf-8") as fh_:
        charged = json.load(fh_)[verify._verify_key(group, domain, stage)]
    assert charged == verify._MAX_VERIFY_ATTEMPTS == speaking.launched.count(voice["speaker"])
    assert silent.launched.count(voice["speaker"]) == 1


def test_the_hostile_rows_cover_both_stages_both_verdicts_and_a_certified_run(hostile):
    """The table itself: a backup and a primary, a REJECTED and a CONFIRMED, and for each
    stage a row whose silent run certifies, so the count alone is what holds the letter."""
    voices = {name: voice for name, (_scene, voice, _count) in HOSTILE_ROWS.items()}
    stages = {name: fh.phase_of(voice["speaker"]) for name, voice in voices.items()}
    assert set(stages.values()) == {fh.ADVISOR, fh.BACKUP}
    assert {(stages[name], voices[name]["says"]) for name in voices} == {
        (stage, said) for stage in (fh.ADVISOR, fh.BACKUP) for said in ("REJECTED", "CONFIRMED")}
    assert {stages[name] for name in CERTIFIED_WHEN_SILENT} == {fh.ADVISOR, fh.BACKUP}
    for name in CERTIFIED_WHEN_SILENT:
        assert hostile[name][0].report["summary"]["grade_shortfalls"] == []


def test_the_fake_backup_answers_what_it_was_handed_and_no_more(lab):
    """The shared runner's backup used to give a verdict on its whole review cell: on the
    claim the primary rejected too, which no backup is shown. It hid every row above."""
    control = lab.control
    with open(runio._pano(control.root, verify._VERIFY_ATTEMPTS_FILE), encoding="utf-8") as fh_:
        record = json.load(fh_)
    with open(runio._pano(control.root, "verdicts", "verdicts-app-SEC-backup.json"),
              encoding="utf-8") as fh_:
        said = [v["finding_id"] for v in json.load(fh_)["verdicts"]]
    refuted = [f["id"] for f in control.report["discarded_claims"]
               if f.get("title") == fh.REFUTED_CLAIM]
    assert len(refuted) == 1 and refuted[0] not in said
    assert said == record[verify._verify_key("app", "SEC", "backup") + "/claims"]
    assert refuted[0] in record[verify._verify_key("app", "SEC", "primary") + "/claims"]
    assert control.report["meta"]["coverage"]["verdicts"]["out_of_scope"] == 0


# --- a reviewer that copies another cell's claim (#3707) -----------------------------------

#: name -> (what the copying cell's advisors say of the copy, what the owner's say of the
#: claim, the claim's severity). A claim id holds no group, so the copy has the owner's id
#: and the copying cell's advisors are handed it as their own. On main the first two
#: discarded a claim the owner's advisors had confirmed, with no shortfall: through the
#: copier's primary (whose verdict file sorts first; HIGH, so no backup stands over it) and
#: through the copier's backup (a backup won over every primary).
COPIED_ROWS = {
    "primary-rejects-its-copy-of-a-confirmed-claim": ({"primary": "REJECTED"}, "CONFIRMED", "HIGH"),
    "backup-rejects-its-copy-of-a-confirmed-claim": ({"backup": "REJECTED"}, "CONFIRMED",
                                                     "CRITICAL"),
    "primary-confirms-its-copy-of-a-rejected-claim": ({"primary": "CONFIRMED"}, "REJECTED", "HIGH"),
    "backup-confirms-its-copy-of-a-rejected-claim": ({"backup": "CONFIRMED"}, "REJECTED",
                                                     "CRITICAL"),
    "both-cells-confirm": ({}, "CONFIRMED", "CRITICAL"),
    "both-cells-reject": ({"primary": "REJECTED"}, "REJECTED", "CRITICAL"),
}


@pytest.fixture(scope="module")
def copied(lab):
    """({(owner's verdict, severity): the run with no copy}, {row: the run with one}), each
    driven once."""
    silent = {(said, severity): fh.drive(lab, replies=fh.CopiedClaim(
                  copy=False, owner_says=said, severity=severity))
              for said in ("CONFIRMED", "REJECTED") for severity in ("CRITICAL", "HIGH")}
    return silent, {name: fh.drive(lab, replies=fh.CopiedClaim(says=says, owner_says=owner,
                                                               severity=severity))
                    for name, (says, owner, severity) in COPIED_ROWS.items()}


def _the_claim(outcome):
    """Where the copied claim ended up: (in the report or discarded, status, severity)."""
    report = outcome.report
    return [(where, _status(f), f["severity"])
            for where, claims in (("report", report["findings"]),
                                  ("discarded", report["discarded_claims"]))
            for f in claims if f.get("title") == fh.CopiedClaim.CLAIM]


def _verdict_of(outcome):
    summary = outcome.report["summary"]
    return {key: summary[key] for key in ("gate", "coverage_certified", "overall_grade",
                                          "provisional_grade", "grade_shortfalls")}


@pytest.mark.parametrize("row", sorted(COPIED_ROWS))
def test_a_copied_claim_is_decided_by_every_cell_that_holds_it(copied, row):
    says, owner, severity = COPIED_ROWS[row]
    silent, speaking = copied[0][owner, severity], copied[1][row]
    assert (silent.status, speaking.status) == ("complete", "complete")
    assert problems(silent, silent) == []
    counted = [o.report["meta"]["coverage"]["verdicts"] for o in (silent, speaking)]
    assert [v["ids_in_several_cells"] for v in counted] == [0, 1]
    assert [v["out_of_scope"] for v in counted] == [0, 0]       # every verdict was in scope
    copier_says = list(says.values()) or ["CONFIRMED"]
    if owner == "CONFIRMED" or copier_says == ["REJECTED"]:
        # The copy changes nothing: the claim is where the run with no copy left it, with
        # the same gate, certification and letter. That is the owner's confirmation
        # standing against the copier's rejection, and two cells agreeing.
        assert problems(silent, speaking) == []
        assert _the_claim(speaking) == _the_claim(silent)
        assert _dispositions(speaking) == _dispositions(silent)
        assert _verdict_of(speaking) == _verdict_of(silent)
    else:
        # The copier confirms what the owner rejected: no better than the run with no
        # copy. The claim is reported, where that run discarded it, so it is one more
        # gate-eligible finding (which invariant 4 would call a fault's doing).
        for invariant in (no_silent_loss, counts_reconcile):
            assert invariant(silent, speaking) == []
        assert _the_claim(silent) == [("discarded", "rejected", severity)]
        assert _the_claim(speaking) == [("report", "advisor_confirmed", severity)]
        assert speaking.report["summary"]["gate"] == "FAIL"


def test_a_cell_below_the_verify_gate_that_holds_the_claim_is_not_asked_and_does_not_hold_it(lab):
    """Ruling 1. The copying cell rates everything INFO, so it is never dispatched for
    verification. It was never asked about the claim, so it is not one of its holders:
    the owner's rejection stands, and the run certifies as it does with no copy."""
    silent = fh.drive(lab, replies=fh.CopiedClaim(copy=False, owner_says="REJECTED",
                                                  below_gate=True))
    held = fh.drive(lab, replies=fh.CopiedClaim(owner_says="REJECTED", below_gate=True))
    copier = "verify-%s-%s-primary" % fh.CopiedClaim.COPIER
    assert copier not in silent.launched and copier not in held.launched
    with open(runio._pano(held.root, verify._VERIFY_ATTEMPTS_FILE), encoding="utf-8") as fh_:
        assert not [key for key in json.load(fh_)
                    if key.startswith("%s/%s/" % fh.CopiedClaim.COPIER)]
    assert problems(silent, silent) == [] and problems(silent, held) == []
    assert _the_claim(held) == _the_claim(silent) == [("discarded", "rejected", "CRITICAL")]
    assert _verdict_of(held) == _verdict_of(silent)
    assert held.report["summary"]["coverage_certified"] is True
    counted = [o.report["meta"]["coverage"]["verdicts"] for o in (silent, held)]
    assert [v["ids_in_several_cells"] for v in counted] == [0, 1]


def test_the_copied_rows_cover_both_stages_and_both_directions():
    kinds = {(stage, said, owner) for says, owner, _severity in COPIED_ROWS.values()
             for stage, said in says.items()}
    assert kinds >= {("primary", "REJECTED", "CONFIRMED"), ("backup", "REJECTED", "CONFIRMED"),
                     ("primary", "CONFIRMED", "REJECTED"), ("backup", "CONFIRMED", "REJECTED")}


def test_the_copy_reaches_the_copying_cells_advisors_as_their_own_claim(copied):
    """What makes the rows mean something: the controller really did hand the copier's
    advisors the owner's id, at both stages, and they really did answer for it."""
    speaking = copied[1]["backup-rejects-its-copy-of-a-confirmed-claim"]
    with open(runio._pano(speaking.root, verify._VERIFY_ATTEMPTS_FILE), encoding="utf-8") as fh_:
        record = json.load(fh_)
    (claim_id,) = {f["id"] for f in speaking.report["findings"]
                   if f.get("title") == fh.CopiedClaim.CLAIM}
    for cell in (fh.CopiedClaim.COPIER, fh.CopiedClaim.OWNER):
        for stage in ("primary", "backup"):
            assert claim_id in record[verify._verify_key(*cell, stage) + "/claims"], (cell, stage)
    with open(runio._pano(speaking.root, "verdicts", "verdicts-app-COD-backup.json"),
              encoding="utf-8") as fh_:
        said = {v["finding_id"]: v["verdict"] for v in json.load(fh_)["verdicts"]}
    assert said[claim_id] == "REJECTED"


SPLIT_BYTES = 9000


@pytest.mark.parametrize("plan", [None, fh.Plan(FAULT_EXIT, (fh.TOOL,), 100)], ids=_name)
def test_a_report_split_into_parts_is_read_whole(lab, plan):
    """`render.write_report` moves findings past the first chunk into `_partN` files and the
    discarded claims into a sibling. Tool findings come last, so they are what a reader of
    the main file alone would lose. Invariants 1 and 2 are checked across every part."""
    whole, split = lab.outcome(plan), lab.outcome(plan, SPLIT_BYTES)
    parts = [name for name in split.part_files if "_part" in name]
    assert parts and any(name.endswith("-discarded.json") for name in split.part_files)
    with open(runio._pano(split.root, "report.json"), encoding="utf-8") as fh_:
        main = json.load(fh_)
    assert len(main["findings"]) < len(split.report["findings"])
    assert main["discarded_claims"] == [] and split.report["discarded_claims"]
    # Tool findings are appended last, so at least one of them is in a part file.
    assert (sum(1 for f in main["findings"] if _is_tool(f))
            < sum(1 for f in split.report["findings"] if _is_tool(f)))
    assert no_silent_loss(lab.control, split) == []
    assert counts_reconcile(lab.control, split) == []
    assert _comparable(split)["findings"] == _comparable(whole)["findings"]
    assert _comparable(split)["discarded"] == _comparable(whole)["discarded"]


def test_the_reader_holds_the_files_on_disk_against_the_ones_the_report_names(lab, tmp_path):
    """A part the report does not name, or a named part that is gone, is a loss before any
    invariant is asked: the reader refuses to assemble a report from a set that disagrees."""
    split = lab.outcome(None, SPLIT_BYTES)
    source = os.path.realpath(runio._pano(split.root, "report.json"))
    stem = os.path.basename(source)[:-len(".json")]
    for name in [os.path.basename(source)] + split.part_files:
        shutil.copy(os.path.join(os.path.dirname(source), name), tmp_path / name)
    copy = str(tmp_path / os.path.basename(source))
    report, named = fh.read_report_at(copy)
    assert named == split.part_files
    assert _comparable_findings(report) == _comparable_findings(split.report)
    # Other files beside it are not parts of it.
    (tmp_path / (stem + "-report-x0x.json")).write_text("{}")
    (tmp_path / ("other" + stem + "_part2.json")).write_text("{}")
    assert fh.read_report_at(copy)[1] == split.part_files
    stray = tmp_path / ("%s_part%d.json" % (stem, len(split.part_files) + 5))
    stray.write_text(json.dumps({"findings": []}))
    with pytest.raises(AssertionError, match="the report names"):
        fh.read_report_at(copy)
    stray.unlink()
    for name in split.part_files:
        held = (tmp_path / name).read_bytes()
        (tmp_path / name).unlink()
        with pytest.raises(AssertionError, match="the report names"):
            fh.read_report_at(copy)
        (tmp_path / name).write_bytes(held)
    assert fh.read_report_at(copy)[1] == split.part_files
    assert fh.read_report_at(str(tmp_path / "absent.json")) == (None, [])


def _comparable_findings(report):
    return (sorted(f["id"] for f in report["findings"]),
            sorted(f["id"] for f in report["discarded_claims"]))
