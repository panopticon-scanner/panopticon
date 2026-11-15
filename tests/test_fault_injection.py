"""#3669: the fault-injection matrix. Each case reviews the fixture target end to end while the
fake host fails a planned share of its launches, then checks what the run left behind against
five invariants and against the fault-free control.

`tests/fault_harness.py` is the fixture, the plan, the driver and the report reader.

**The default run is not the full matrix.** It is `default_cases()`: the control, every mode
against every single phase at 100%, every mode against all three verification phases at 100%,
every mode against all phases at 50% and at 10%, one mode per phase at 50% and at 10%, and
every mode as a transient fault. Set `PANOPTICON_FAULT_MATRIX=full` for the whole cross
(5 modes x 7 targets x 3 rates, plus the transient and control cases); a default run prints
how many of those it left out.
"""
import functools
import glob
import json
import os
import shutil
import sys
import tempfile

import pytest

from scripts import evidence
import scripts.loop_progress as loop_progress
import scripts.phases.runio as runio
from tests import fault_harness as fh
from tests.orchestrate_helpers import FAULT_MODES

MATRIX_SWITCH = "PANOPTICON_FAULT_MATRIX"
VERIFICATION = (fh.ADVISOR, fh.BACKUP, fh.TOOL)
TARGETS = tuple((phase,) for phase in fh.PHASES) + (VERIFICATION, fh.PHASES)
RATES = (100, 50, 10)


def _name(plan):
    if plan is None:
        return "control"
    target = {VERIFICATION: "verification", fh.PHASES: "all"}.get(plan.phases, plan.phases[0])
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
    cases += [fh.Plan(mode, fh.PHASES, rate) for mode in FAULT_MODES for rate in (50, 10)]
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


def _gate_eligible(report):
    """Identity of every finding the gate counts: confirmed, at or above `--fail-on`."""
    in_play = set((report["summary"].get("gate_severities") or {}).get("in_play") or [])
    return {(f.get("title"), _locus(f)) for f in report["findings"]
            if _status(f) in evidence.GATE_ELIGIBLE_DEFAULT and f.get("severity") in in_play}


def _summary_lines(outcome):
    """The report summary as the operator's terminal showed it."""
    marker = loop_progress.SUMMARY_PREFIX
    return [line.split(marker, 1)[1] for line in outcome.terminal.splitlines()
            if marker in line]


_NAMES = {fh.REVIEW: ("review", "cell"), fh.ADVISOR: ("verif", "advisor", "unanswered"),
          fh.BACKUP: ("backup",), fh.TOOL: ("tool",)}


def _unnamed(text, phases):
    """The phases with undone work whose kind of work `text` does not mention."""
    text = (text or "").lower()
    return [phase for phase in phases if not any(word in text for word in _NAMES[phase])]


# --- the invariants ----------------------------------------------------------------------
# Each returns the list of what is wrong, empty when the invariant holds. `control` is the
# fault-free run of the same fixture.

def no_silent_loss(control, outcome):
    """1. Every tool finding ingested, and every agent claim a cell persisted, is in the
    report in some state or among the discarded claims with a reason. A review cell that
    never answered is named."""
    wrong = []
    report = outcome.report
    discarded = report["discarded_claims"]
    for claim in tool_claims():
        if not any(_accounts_for(claim, f) for f in report["findings"] + discarded):
            wrong.append("tool finding %s %s is nowhere in the report" % (claim[0], claim[1]))
    titles = {f.get("title") for f in report["findings"] + discarded}
    for title, cell in _persisted_claims(outcome.root):
        if title not in titles:
            wrong.append("agent claim %r (persisted in %s) is nowhere in the report"
                         % (title, cell))
    for finding in discarded:
        if _status(finding) != "rejected" or not (finding.get("evidence") or {}).get("reasoning"):
            wrong.append("discarded claim %s carries no rejection reason" % finding.get("id"))
    message = outcome.statuses[-1].get("message") or ""
    for entry in outcome.unanswered_in(fh.REVIEW):
        _review, group, domain = entry.split("-")
        if "%s/%s" % (group, domain) not in message:
            wrong.append("review cell %s/%s never answered and the status does not name it"
                         % (group, domain))
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
        wrong.append("tool_axis does not add up: %r" % (axis,))
    if axis["queued"] != len(tool_claims()):
        wrong.append("tool_axis.queued is %d; the scanners reported %d"
                     % (axis["queued"], len(tool_claims())))
    never = len(outcome.unanswered_in(fh.TOOL))
    if axis["unanswered"] != never:
        wrong.append("tool_axis.unanswered is %d; %d tool advisor(s) never answered"
                     % (axis["unanswered"], never))
    everything = report["findings"] + report["discarded_claims"]
    for scanner in fh.SCANNERS:
        ingested = (coverage["adapters"].get(scanner) or {}).get("findings")
        claims = [c for c in tool_claims() if c[0] == scanner]
        if ingested != len(claims):
            wrong.append("%s: adapters says %r ingested; it reported %d"
                         % (scanner, ingested, len(claims)))
        found = [c for c in claims if any(_accounts_for(c, f) for f in everything)]
        if len(found) != len(claims):
            wrong.append("%s: %d of %d findings are in the report or its discards"
                         % (scanner, len(found), len(claims)))
    stats = report["summary"]["evidence_stats"]
    if stats["tool_reported"] != sum(1 for f in report["findings"]
                                     if _status(f) == "tool_reported"):
        wrong.append("evidence_stats.tool_reported disagrees with the findings")
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
            "nothing was left undone, yet certification is %r; the control's is %r"
            % (got, expected)]
    if summary["coverage_certified"] is True:
        return ["%s work was left undone and the run is coverage_certified" % ", ".join(undone)]
    if summary["overall_grade"] is None:
        return []
    return ["a letter grade (%s) stands and coverage_note (%r) does not name the undone %s work"
            % (summary["overall_grade"], summary.get("coverage_note"), phase)
            for phase in _unnamed(summary.get("coverage_note"), undone)]


def gate_fails_closed(control, outcome):
    """4. No finding becomes gate-eligible because a host failed, and one that stops being
    eligible that way does not leave a passing gate behind. Undone work is never PASS."""
    wrong = []
    eligible, before = _gate_eligible(outcome.report), _gate_eligible(control.report)
    gate, control_gate = outcome.report["summary"]["gate"], control.report["summary"]["gate"]
    for title, locus in sorted(eligible - before, key=str):
        wrong.append("%r at %s:%s is gate-eligible only under the fault"
                     % (title, locus[0], locus[1]))
    if not outcome.unanswered:
        if eligible != before or gate != control_gate:
            wrong.append("nothing was left undone, yet the gate is %s over %d eligible "
                         "finding(s); the control's is %s over %d"
                         % (gate, len(eligible), control_gate, len(before)))
        return wrong
    if gate == "PASS":
        wrong.append("work was left undone and the gate is PASS")
    if not eligible and gate != "INCONCLUSIVE":
        wrong.append("no finding is gate-eligible after the fault and the gate is %s, "
                     "not INCONCLUSIVE" % gate)
    return wrong


def shortfall_is_disclosed(control, outcome):
    """5. The terminal, the JSON and the HTML each show the shortfall."""
    undone = sorted({fh.phase_of(e) for e in outcome.unanswered})
    terminal = "\n".join(_summary_lines(outcome))
    if not undone:
        return [where + " says NOT CERTIFIED and nothing was left undone"
                for where, text in (("terminal", terminal), ("HTML", outcome.html))
                if control.report["summary"]["coverage_certified"] and "NOT CERTIFIED" in text]
    wrong = []
    summary = outcome.report["summary"]
    surfaces = (("JSON", json.dumps({key: summary.get(key) for key in
                                     ("coverage_certified", "coverage_note")})),
                ("terminal", terminal), ("HTML", outcome.html))
    if summary["coverage_certified"] is not False:
        wrong.append("JSON: coverage_certified is %r" % summary["coverage_certified"])
    for where, text in surfaces[1:]:
        if "NOT CERTIFIED" not in text:
            wrong.append("%s does not say NOT CERTIFIED" % where)
    for where, text in surfaces:
        for phase in _unnamed(text, undone):
            wrong.append("%s does not name the undone %s work" % (where, phase))
    return wrong


INVARIANTS = (no_silent_loss, counts_reconcile, no_false_certification, gate_fails_closed,
              shortfall_is_disclosed)


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


def problems(control, outcome, skip=()):
    return ["%s: %s" % (check.__name__, line) for check in INVARIANTS
            if check.__name__ not in skip for line in check(control, outcome)]


@pytest.mark.parametrize("plan", CASES, ids=_name)
def test_explore(lab, plan):
    """TEMPORARY: print what each case does."""
    import time
    from collections import Counter
    t = time.time()
    o = lab.outcome(plan)
    line = "CASE %-34s %s runs=%s inj=%d unans=%s" % (
        _name(plan), o.status, [s["status"] for s in o.statuses], len(o.injected),
        dict(Counter(fh.phase_of(e) for e in o.unanswered)))
    if o.report is not None:
        sm = o.report["summary"]
        line += " | grade=%s prov=%s cert=%s gate=%s note=%r axis=%s" % (
            sm["overall_grade"], sm["provisional_grade"], sm["coverage_certified"], sm["gate"],
            sm["coverage_note"], o.report["meta"]["coverage"]["tool_axis"])
        same = _comparable(o) == _comparable(lab.control)
        line += " | same_as_control=%s | %s" % (same, problems(lab.control, o))
    else:
        line += " | msg=%r" % (o.statuses[-1].get("message") or "")[:160]
    print(line + " | %.1fs" % (time.time() - t))
