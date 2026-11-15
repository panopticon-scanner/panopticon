"""#3669: the fault-injection matrix. Each case reviews the fixture target end to end while the
fake host fails a planned share of its launches, then checks what the run left behind against
five invariants and against the fault-free control.

`tests/fault_harness.py` is the fixture, the plan, the driver and the report reader.

**The default run is not the full matrix.** It is `default_cases()`: the control, every mode
against every single phase at 100%, every mode against all three verification phases at 100%,
every mode against every phase after the scout at 50% and at 10%, one mode per phase at 50% and
at 10%, and every mode as a transient fault. Set `PANOPTICON_FAULT_MATRIX=full` for the whole
cross (5 modes x 8 targets x 3 rates, plus the transient and control cases); a default run
prints how many of those it left out.

One departure from the design note, approved by the coordinator: the partial-rate cases that
span phases target the four phases AFTER the scout, not all five. A scout that never answers
stops the run at its first checkpoint, so "all phases" at 50% or 10% only repeated the scout
case ten times. "All phases" is still in the full matrix and in the transient cases.

**Known gaps.** `KNOWN_GAPS` lists the invariants that do not hold on main today, by the kind
of work left undone and the issue that owns each. A case whose only problems are listed there
is a strict `xfail` naming those issues. A problem no row covers fails the case, and so does
a row whose invariant holds again: each fix removes its own rows.
"""
import dataclasses
import functools
import glob
import json
import os
import re
import sys

import pytest

from scripts import evidence
import scripts.loop_progress as loop_progress
import scripts.phases.runio as runio
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
CASES = full_cases() if FULL else default_cases()
SKIPPED = len(full_cases()) - len(CASES)


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


def test_a_default_run_says_how_much_of_the_matrix_it_left_out():
    """So a green default run is never read as the full cross."""
    if FULL:
        assert SKIPPED == 0
        return
    assert SKIPPED > 0
    print("fault injection: %d of %d cases run by default; %d more with %s=full"
          % (len(CASES), len(CASES) + SKIPPED, SKIPPED, MATRIX_SWITCH), file=sys.stderr)


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


#: Words that name each kind of work. Loose on purpose: the invariant is that the reader is
#: told what was left undone, not how the sentence is written.
_NAMES = {fh.REVIEW: ("review", "cell", "panel", "fan-out"),
          fh.ADVISOR: ("verif", "advisor", "verdict", "unanswered"),
          fh.BACKUP: ("backup",), fh.TOOL: ("tool",)}


def _unnamed(text, phases):
    """The phases with undone work whose kind of work `text` does not mention."""
    text = (text or "").lower()
    return [phase for phase in phases if not any(word in text for word in _NAMES[phase])]


# --- the invariants ----------------------------------------------------------------------
# Each returns what is wrong as (phase, sentence) pairs, empty when the invariant holds. The
# phase is the kind of undone work the problem is about, or None when it is about none.
# `control` is the fault-free run of the same fixture.

def no_silent_loss(control, outcome):
    """1. Every tool finding ingested, and every agent claim a cell persisted, is in the
    report in some state or among the discarded claims with a reason. A review cell that
    never answered is named."""
    wrong = []
    report = outcome.report
    discarded = report["discarded_claims"]
    for claim in tool_claims():
        if not any(_accounts_for(claim, f) for f in report["findings"] + discarded):
            wrong.append((None, "tool finding %s %s is nowhere in the report" % claim[:2]))
    titles = {f.get("title") for f in report["findings"] + discarded}
    for title, cell in _persisted_claims(outcome.root):
        if title not in titles:
            wrong.append((None, "agent claim %r (persisted in %s) is nowhere in the report"
                          % (title, cell)))
    for finding in discarded:
        if _status(finding) != "rejected" or not (finding.get("evidence") or {}).get("reasoning"):
            wrong.append((None, "discarded claim %s carries no rejection reason"
                          % finding.get("id")))
    message = outcome.statuses[-1].get("message") or ""
    for entry in outcome.unanswered_in(fh.REVIEW):
        _review, group, domain = entry.split("-")
        if "%s/%s" % (group, domain) not in message:
            wrong.append((fh.REVIEW, "review cell %s/%s never answered and the status does "
                          "not name it" % (group, domain)))
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
        wrong.append((None, "tool_axis does not add up: %r" % (axis,)))
    if axis["queued"] != len(tool_claims()):
        wrong.append((None, "tool_axis.queued is %d; the scanners reported %d"
                      % (axis["queued"], len(tool_claims()))))
    never = len(outcome.unanswered_in(fh.TOOL)) + (
        fh.MERGED_ADVISOR in outcome.unanswered_in(fh.ADVISOR))
    if axis["unanswered"] != never:
        wrong.append((None, "tool_axis.unanswered is %d; %d tool claim(s) had an advisor "
                      "that never answered" % (axis["unanswered"], never)))
    everything = report["findings"] + report["discarded_claims"]
    for scanner in fh.SCANNERS:
        ingested = (coverage["adapters"].get(scanner) or {}).get("findings")
        claims = [c for c in tool_claims() if c[0] == scanner]
        if ingested != len(claims):
            wrong.append((None, "%s: adapters says %r ingested; it reported %d"
                          % (scanner, ingested, len(claims))))
        found = [c for c in claims if any(_accounts_for(c, f) for f in everything)]
        if len(found) != len(claims):
            wrong.append((None, "%s: %d of %d findings are in the report or its discards"
                          % (scanner, len(found), len(claims))))
    stats = report["summary"]["evidence_stats"]
    if stats["tool_reported"] != sum(1 for f in report["findings"]
                                     if _status(f) == "tool_reported"):
        wrong.append((None, "evidence_stats.tool_reported disagrees with the findings"))
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
            (None, "nothing was left undone, yet certification is %r; the control's is %r"
             % (got, expected))]
    if summary["coverage_certified"] is True:
        return [(phase, "%s work was left undone and the run is coverage_certified" % phase)
                for phase in undone]
    if summary["overall_grade"] is None:
        return []
    return [(phase, "a letter grade (%s) stands and coverage_note (%r) does not name the "
             "undone %s work" % (summary["overall_grade"], summary.get("coverage_note"), phase))
            for phase in _unnamed(summary.get("coverage_note"), undone)]


def gate_fails_closed(control, outcome):
    """4. No finding becomes gate-eligible because a host failed, and one that stops being
    eligible that way does not leave a passing gate behind. Undone work is never PASS."""
    wrong = []
    eligible, before = _gate_eligible(outcome.report), _gate_eligible(control.report)
    gate, control_gate = outcome.report["summary"]["gate"], control.report["summary"]["gate"]
    for issue in sorted(eligible - before, key=str):
        wrong.append((None, "%s is gate-eligible only under the fault"
                      % ":".join(map(str, issue))))
    if not outcome.unanswered:
        if eligible != before or gate != control_gate:
            wrong.append((None, "nothing was left undone, yet the gate is %s over %d eligible "
                          "finding(s); the control's is %s over %d"
                          % (gate, len(eligible), control_gate, len(before))))
        return wrong
    if gate == "PASS":
        wrong.append((None, "work was left undone and the gate is PASS"))
    if not eligible and gate != "INCONCLUSIVE":
        wrong.append((None, "no finding is gate-eligible after the fault and the gate is %s, "
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
    return False                                 # backup: no field counts it


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
    if not undone:
        return [(None, "%s says NOT CERTIFIED and nothing was left undone" % where)
                for where, text in (("terminal", terminal), ("HTML", page))
                if control.report["summary"]["coverage_certified"] and "NOT CERTIFIED" in text]
    wrong = []
    for phase in undone:
        if summary["coverage_certified"] is not False:
            wrong.append((phase, "JSON: coverage_certified is %r with %s work undone"
                          % (summary["coverage_certified"], phase)))
        if not _json_counts(outcome, phase) and _unnamed(summary.get("coverage_note"), [phase]):
            wrong.append((phase, "JSON: no field counts the undone %s work and coverage_note "
                          "(%r) does not name it" % (phase, summary.get("coverage_note"))))
        for where, text in (("terminal", terminal), ("HTML", page)):
            if "NOT CERTIFIED" not in text:
                wrong.append((phase, "%s does not say NOT CERTIFIED with %s work undone"
                              % (where, phase)))
            elif _unnamed(text, [phase]):
                wrong.append((phase, "%s does not name the undone %s work beside NOT CERTIFIED "
                              "(it says %r)" % (where, phase, text[:120])))
    return wrong


INVARIANTS = (no_silent_loss, counts_reconcile, no_false_certification, gate_fails_closed,
              shortfall_is_disclosed)


def problems(control, outcome):
    """Every (invariant name, phase, sentence) that does not hold for `outcome`."""
    return [(check.__name__, phase, sentence) for check in INVARIANTS
            for phase, sentence in check(control, outcome)]


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

def _no_review_gap(outcome):
    """A missing review cell already makes the letter provisional, which hides whether the
    verification shortfall beside it would have."""
    return not outcome.unanswered_in(fh.REVIEW)


def _some_cells_answered(outcome):
    """With every cell gone the report says "no review cell answered" on every surface."""
    return len(outcome.unanswered_in(fh.REVIEW)) < sum(
        1 for e in set(outcome.launched) if fh.phase_of(e) == fh.REVIEW)


@dataclasses.dataclass(frozen=True)
class Gap:
    """One invariant known not to hold for one kind of undone work, and the issue that owns
    it. Each fix removes its own rows: a row whose invariant holds again fails the case."""
    issue: str
    phase: str
    invariant: str
    when: object = None       # outcome -> bool: the runs this gap shows in; None means all


#: #3641: verify advisors that never answer leave a letter standing with no reason given.
#: #3667: the same for tool advisors -- and with every verification phase failing the letter
#:        that stands is S, beside an INCONCLUSIVE gate.
#: #3676: backup advisors that never answer leave the report fully certified, and ones that
#:        write a cut-off file sink certification with no reason; neither is named anywhere.
#: #3677: the HTML report does not name an exhausted review cell; the terminal does.
KNOWN_GAPS = (
    Gap("#3641", fh.ADVISOR, "no_false_certification", _no_review_gap),
    Gap("#3641", fh.ADVISOR, "shortfall_is_disclosed"),
    Gap("#3667", fh.TOOL, "no_false_certification", _no_review_gap),
    Gap("#3667", fh.TOOL, "shortfall_is_disclosed"),
    Gap("#3676", fh.BACKUP, "no_false_certification", _no_review_gap),
    Gap("#3676", fh.BACKUP, "shortfall_is_disclosed"),
    Gap("#3677", fh.REVIEW, "shortfall_is_disclosed", _some_cells_answered),
)


def _expected_gaps(outcome):
    undone = {fh.phase_of(e) for e in outcome.unanswered}
    return [gap for gap in KNOWN_GAPS
            if gap.phase in undone and (gap.when is None or gap.when(outcome))]


# --- the tests ---------------------------------------------------------------------------

def test_the_control_certifies_and_shows_every_state(lab):
    """The 0% run: what every other case is measured against, so it has to be a real review."""
    control = lab.control
    assert [s["status"] for s in control.statuses] == ["complete"]
    assert control.injected == [] and control.unanswered == []
    assert {fh.phase_of(e) for e in control.launched} == set(fh.PHASES)
    summary, coverage = control.report["summary"], control.report["meta"]["coverage"]
    assert summary["coverage_certified"] is True and summary["coverage_note"] is None
    assert summary["overall_grade"] is not None and summary["provisional_grade"] is None
    assert summary["gate"] == "FAIL" and _gate_eligible(control.report)
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


@pytest.mark.parametrize("plan", CASES[1:], ids=_name)
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
    known = {(gap.invariant, gap.phase) for gap in expected}
    unexpected = [row for row in found if (row[0], row[1]) not in known]
    assert not unexpected, "no issue covers:\n  " + "\n  ".join(
        "%s: %s" % (name, sentence) for name, _phase, sentence in unexpected)
    fixed = [gap for gap in expected
             if (gap.invariant, gap.phase) not in {(row[0], row[1]) for row in found}]
    assert not fixed, ("these hold again, so remove their rows from KNOWN_GAPS: "
                       + ", ".join("%s (%s, %s)" % (gap.issue, gap.phase, gap.invariant)
                                   for gap in fixed))
    if expected:
        request.applymarker(pytest.mark.xfail(
            strict=True, reason=", ".join(sorted({gap.issue for gap in expected}))))
        pytest.fail("known: " + "; ".join(sentence for _name, _phase, sentence in found))


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
    assert not any(_is_tool(f) for f in main["findings"]) or len(parts) >= 1
    assert no_silent_loss(lab.control, split) == []
    assert counts_reconcile(lab.control, split) == []
    assert _comparable(split)["findings"] == _comparable(whole)["findings"]
    assert _comparable(split)["discarded"] == _comparable(whole)["discarded"]
