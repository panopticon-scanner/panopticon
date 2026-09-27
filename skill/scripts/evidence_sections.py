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
ratchet in `tests/test_flat_module_ceiling.py`, whose stated remedy for a module
that needs more room is a new module.
"""
from typing import TYPE_CHECKING

# PACKAGE first, flat fallback -- the order `score_gate` and `html_report` use
# (tests/test_layout.py pins flat mode for these modules): skill/scripts is on
# sys.path as well as its parent, so a flat-first import would build a SECOND
# `evidence` module object with its own module-level state.
if TYPE_CHECKING:
    import scripts.evidence as evidence
else:
    try:
        import scripts.evidence as evidence
    except ModuleNotFoundError:  # imported flat, with skill/scripts on sys.path
        import evidence

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


def is_unverified(status):
    """True when the report collapses this status into "Unverified findings".

    Fails CLOSED: a status outside `evidence.EVIDENCE_STATUSES` -- an unknown
    one, or a finding carrying no evidence at all -- is collapsed and disclosed
    rather than listed among the findings the run stands behind.
    """
    return (status in UNVERIFIED_STATUSES
            or status not in evidence.EVIDENCE_STATUSES)
