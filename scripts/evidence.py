#!/usr/bin/env python3
"""Evidence axis for panopticon findings: status derivation, verify-queue
triage, and advisor verdict ingestion. Stdlib-only.

Two-axis model: severity means "impact if true" and is never mutated here;
evidence.status records how hard the claim has been verified.
"""

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
EVIDENCE_STATUSES = ("tool_confirmed", "advisor_confirmed", "corroborated",
                     "needs_more_info", "unverified", "rejected")
GATE_ELIGIBLE_DEFAULT = frozenset({"tool_confirmed", "advisor_confirmed"})
VERDICT_VALUES = {"CONFIRMED", "REJECTED", "NEEDS_MORE_INFO"}


def is_tool_sourced(finding):
    """Tool-emitted findings carry source='tool:<name>'; everything else is agentic."""
    return str(finding.get("source", "")).startswith("tool:")


def sev_rank(finding):
    """Lower is more severe; unknown severities sort last."""
    try:
        return SEV_ORDER.index(finding.get("severity", "INFO"))
    except ValueError:
        return len(SEV_ORDER)


def derive_evidence(finding, verdict=None):
    """Return the evidence dict for a finding.

    Precedence: tool_confirmed > advisor verdicts (CONFIRMED/REJECTED/
    NEEDS_MORE_INFO) > corroborated > unverified. Never mutates the finding.
    Self-asserted provenance.confirmation_status is deliberately ignored —
    a reviewer cannot confirm its own finding.
    """
    quality = finding.get("citation_quality") or "none"
    prov = finding.get("provenance") or {}
    if is_tool_sourced(finding):
        return {"status": "tool_confirmed",
                "verified_by": finding.get("source"),
                "reasoning": prov.get("confirmation_reasoning")
                or "Reported by static-analysis tool",
                "citation_quality": quality}
    v = str((verdict or {}).get("verdict", "")).upper()
    if v in VERDICT_VALUES:
        status = {"CONFIRMED": "advisor_confirmed",
                  "REJECTED": "rejected"}.get(v, "needs_more_info")
        return {"status": status, "verified_by": "agent:advisor",
                "reasoning": (verdict or {}).get("reasoning"),
                "citation_quality": quality}
    if finding.get("reinforced"):
        return {"status": "corroborated", "verified_by": "tool+agent",
                "reasoning": "Same locus reported independently by a tool and an agent",
                "citation_quality": quality}
    if finding.get("corroborated"):
        panels = list(finding.get("corroborated_by") or [])
        return {"status": "corroborated", "verified_by": panels,
                "reasoning": "Nearby locus independently flagged by panels: %s"
                % ", ".join(panels),
                "citation_quality": quality}
    return {"status": "unverified", "verified_by": None, "reasoning": None,
            "citation_quality": quality}
