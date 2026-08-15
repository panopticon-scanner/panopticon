"""Deterministic verify-summon score gate for the 5.0 review matrix.

Pure functions over the discrete severity / confidence / evidence.status values
a finding already carries. No I/O, no dispatch. See
docs/superpowers/specs/2026-08-14-panopticon-5.0-domain-panel-matrix-design.md §7.
"""

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
}
PRIMARY_FLOOR = 1.5   # F_p — the per-cell advisor engages at/above this
BACKUP_FLOOR = 8.0    # F_b — a category backup sub-advisor is summoned at/above this

_DEFAULT_CONF = CONFIDENCE_MULT["POSSIBLE"]   # unknown confidence → POSSIBLE


def finding_score(finding):
    """severity_weight × confidence_mult × evidence_factor for one finding.

    Unknown/absent values fall to their safe default (severity → INFO=0,
    confidence → POSSIBLE, evidence.status → unverified), matching
    synthesize.normalize_finding.
    """
    sev = SEVERITY_WEIGHT.get(finding.get("severity"), 0)
    conf = CONFIDENCE_MULT.get(finding.get("confidence"), _DEFAULT_CONF)
    status = (finding.get("evidence") or {}).get("status", "unverified")
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
