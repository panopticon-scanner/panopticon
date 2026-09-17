"""Deterministic verify-summon score gate for the 5.0 review matrix.

Pure functions over the discrete severity / confidence / evidence.status values
a finding already carries. No I/O, no dispatch. See
docs/superpowers/specs/2026-08-14-panopticon-5.0-domain-panel-matrix-design.md §7.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# PACKAGE first, flat fallback -- the order host_disclosure.py and
# model_resolver.py already use, and the one tests/test_layout.py rule 2
# explains: skill/scripts is on sys.path as well as its parent, so a flat-first
# import builds a SECOND `evidence` module object with its own module-level
# state, and every real run (the driver puts both directories on PYTHONPATH)
# held both at once. Nothing in `evidence` is stateful today; the split would
# be silent when something is (#1679).
try:
    from scripts import evidence
except ImportError:
    import evidence

SEVERITY_WEIGHT = {"CRITICAL": 20, "HIGH": 5, "MEDIUM": 2, "LOW": 0, "INFO": 0}
CONFIDENCE_MULT = {"CERTAIN": 1.0, "LIKELY": 0.9, "POSSIBLE": 0.8, "NOTE": 0.4}
EVIDENCE_FACTOR = {
    "rejected": 0.0,
    "needs_more_info": 0.5,
    "unverified": 1.0,
    "tool_reported": 1.0,
    "corroborated": 1.5,
    "advisor_confirmed": 1.5,
    "tool_confirmed": 1.5,
    # #1638 P16: a primary CONFIRMED whose backup could not reach the evidence.
    # Scored as the confirmation it is -- the backup reported a scope failure,
    # not a doubt, and demoting the score would let the fence decide the gate.
    "backup_scope_limited": 1.5,
}
# Enforce that every canonical evidence status is accounted for in the score gate
if set(EVIDENCE_FACTOR) != set(evidence.EVIDENCE_STATUSES):
    raise ValueError("EVIDENCE_FACTOR keys do not match EVIDENCE_STATUSES")
PRIMARY_FLOOR = 1.5   # F_p — the per-cell advisor engages at/above this
BACKUP_FLOOR = 8.0    # F_b — a category backup sub-advisor is summoned at/above this

_DEFAULT_CONF = CONFIDENCE_MULT["POSSIBLE"]   # unknown confidence → POSSIBLE


def finding_score(finding):
    """severity_weight × confidence_mult × evidence_factor for one finding.

    Unknown/absent values fall to their safe default (severity → INFO=0,
    confidence → POSSIBLE, evidence.status → unverified), matching
    synth.findings.normalize_finding.
    """
    sev = SEVERITY_WEIGHT.get(finding.get("severity"), 0)
    conf = CONFIDENCE_MULT.get(finding.get("confidence"), _DEFAULT_CONF)
    # evidence may be absent (-> treat as {}) or, defensively, a non-dict;
    # a missing/unknown status and a non-dict evidence both resolve to the
    # unverified factor (1.0) via EVIDENCE_FACTOR.get(..., 1.0) below.
    evidence = finding.get("evidence")
    status = evidence.get("status", "unverified") if isinstance(evidence, dict) else "unverified"
    ev = EVIDENCE_FACTOR.get(status, 1.0)
    return round(sev * conf * ev, 6)


def score(findings):
    """Sum of finding_score over the category's findings in a cell."""
    return round(sum(finding_score(f) for f in findings), 6)


def should_engage_primary(findings):
    """Does the primary per-cell advisor verify this cell (vs. skip + disclose)?"""
    return score(findings) >= PRIMARY_FLOOR


def should_summon_backup(findings):
    """Is a category backup sub-advisor summoned for this cluster?"""
    return score(findings) >= BACKUP_FLOOR
