#!/usr/bin/env python3
"""Which evidence statuses the report counts as verified, and which ones it
collapses into its "Unverified findings" section. Stdlib-only.

#1774 (ARC-3073755386): `html_report` derived this twice, differently. The
header counted an INCLUSION of two statuses while the findings tabs split on an
EXCLUSION of three, so five of the ten possible inputs fell on one side of the
word in the header and the other side in the tabs. The exclusion form also
failed OPEN: a status added to `evidence.EVIDENCE_STATUSES` later would have
joined the main list silently.

These are two questions, not one, which is why neither set is the other's
complement:

* `VERIFIED_STATUSES` is the header's WORD. "Verified" means a second opinion
  agreed, so `backup_scope_limited` is deliberately NOT in it -- in that state a
  second opinion could not look, and the coverage line gives it its own segment
  so the count is disclosed rather than folded into a number that would
  overstate it (#1638 P16).
* `UNVERIFIED_STATUSES` is the report's SPLIT: what the collapsed "Unverified
  findings" section holds instead of the main severity tabs.

`MAIN_LIST_STATUSES` is the named remainder -- neither counted nor collapsed.
`corroborated` and `backup_scope_limited` stay in the main list because the
product keeps them prominent: a `backup_scope_limited` finding is a primary
CONFIRMED wearing a disclosure, and gate-eligible. `rejected` is in that tuple
for a different reason -- it never reaches `findings` at all. `synth/report.py`
publishes `resolve_findings`'s `active` list, which is every finding whose
status is not `rejected`, and the rejected half goes to `discarded_claims` and
its own report section, so its entry records where it WOULD land rather than
where it does.

Its own module rather than a block inside `evidence.py`: that module and
`html_report.py` are both pinned at their exact current size by the shrink-only
ratchet in `tests/test_flat_module_ceiling.py` (retired in #3515), whose stated remedy for a module
that needs more room is a new module.
"""

import scripts.evidence as evidence

VERIFIED_STATUSES = ("tool_confirmed", "advisor_confirmed")
UNVERIFIED_STATUSES = ("tool_reported", "needs_more_info", "unverified")
MAIN_LIST_STATUSES = ("corroborated", "rejected", evidence.BACKUP_SCOPE_LIMITED)
# One closed partition, checked at import time like `score_gate.EVIDENCE_FACTOR`
# is: a status added to EVIDENCE_STATUSES with no home here is a loud failure
# rather than a silent promotion into the main list.
if (sorted(VERIFIED_STATUSES + UNVERIFIED_STATUSES + MAIN_LIST_STATUSES)
        != sorted(evidence.EVIDENCE_STATUSES)):
    raise ValueError("evidence_sections does not partition EVIDENCE_STATUSES")


def is_verified(status):
    """True when a second opinion agreed -- the header's word for this status."""
    return status in VERIFIED_STATUSES


def finding_evidence(finding):
    """Return one finding's evidence mapping, or an empty mapping if malformed."""
    value = finding.get("evidence")
    return value if isinstance(value, dict) else {}


def finding_status(finding):
    """Return one finding's status; malformed evidence is an absent status."""
    return finding_evidence(finding).get("status")


def is_unverified(status):
    """True when the report collapses this status into "Unverified findings".

    Fails CLOSED: a status outside `evidence.EVIDENCE_STATUSES` -- an unknown
    one, or a finding carrying no evidence at all -- is collapsed and disclosed
    rather than listed among the findings the run stands behind.
    """
    return (status in UNVERIFIED_STATUSES
            or status not in evidence.EVIDENCE_STATUSES)


def is_unverified_finding(finding):
    """Apply the fail-closed status predicate to one finding."""
    return is_unverified(finding_status(finding))


# #3756: an advisor's REJECTED takes a scanner finding out of the gate and the
# grade. For a scanner HIGH or CRITICAL that is one advisor's word against a
# scanner's, and it was visible as a count on the terminal and a collapsed block on
# the page; a large report's main file holds none of them, because
# `discarded_claims` moves to a sibling file. `synth/report.py` publishes this
# compact list in `meta`, which stays in the main file, and both renderers print
# it. Disclosure only.
REJECTED_SCANNER_SEVERITIES = ("CRITICAL", "HIGH")
REJECTED_SCANNER_ROWS = 50
REJECTED_REASONING_CAP = 600
_CUT = " [cut]"


def rejected_scanner_findings(rejected):
    """`{count, rows}` for `meta.rejected_scanner_findings`, or None when no rejected
    claim is a scanner's at HIGH or above. `rows` is the first
    `REJECTED_SCANNER_ROWS`, most severe first and then in the order given; `count`
    is all of them. Each row is the finding's own id, tool, rule, severity (a
    rejected claim keeps the scanner's), location and hit count, and the advisor's
    reasoning cut to `REJECTED_REASONING_CAP` characters, visibly."""
    chosen = []
    for finding in rejected or ():
        if not isinstance(finding, dict) or not evidence.is_tool_sourced(finding):
            continue
        if (finding.get("severity") not in REJECTED_SCANNER_SEVERITIES
                or finding_status(finding) != "rejected"):
            continue
        chosen.append(finding)
    if not chosen:
        return None
    chosen.sort(key=lambda f: REJECTED_SCANNER_SEVERITIES.index(f["severity"]))
    rows = []
    for finding in chosen[:REJECTED_SCANNER_ROWS]:
        location = evidence.location_of(finding)
        reasoning = finding_evidence(finding).get("reasoning")
        reasoning = reasoning if isinstance(reasoning, str) else ""
        if len(reasoning) > REJECTED_REASONING_CAP:
            reasoning = reasoning[:REJECTED_REASONING_CAP - len(_CUT)] + _CUT
        occurrences = finding.get("occurrences")
        rows.append({
            "id": str(finding.get("id") or ""),
            "tool": evidence.tool_name(finding) or "",
            "rule": str(evidence.tool_rule_id(finding) or ""),
            "severity": finding["severity"],
            "file": str(location.get("file") or ""),
            "line_start": (location.get("line_start")
                           if isinstance(location.get("line_start"), int)
                           and not isinstance(location.get("line_start"), bool) else None),
            "occurrences": (occurrences if isinstance(occurrences, int)
                            and not isinstance(occurrences, bool) and occurrences > 0 else 1),
            "title": str(finding.get("title") or ""),
            "reasoning": reasoning,
        })
    return {"count": len(chosen), "rows": rows}
