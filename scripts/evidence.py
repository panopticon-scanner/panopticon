#!/usr/bin/env python3
"""Evidence axis for panopticon findings: status derivation, verify-queue
triage, and advisor verdict ingestion. Stdlib-only.

Two-axis model: severity means "impact if true" and is never mutated here;
evidence.status records how hard the claim has been verified.
"""

import json
import os

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


def triage_priority(finding):
    """Sort key for the verify queue; lower verifies first.

    Spec order: corroborated CRITICAL/HIGH -> uncorroborated CRITICAL/HIGH ->
    corroborated MEDIUM -> everything else descending by severity.
    """
    sev = str(finding.get("severity", "INFO")).upper()
    corroborated = bool(finding.get("corroborated") or finding.get("reinforced"))
    if sev in ("CRITICAL", "HIGH"):
        return 0 if corroborated else 1
    if sev == "MEDIUM" and corroborated:
        return 2
    try:
        return 3 + SEV_ORDER.index(sev)
    except ValueError:
        return 3 + len(SEV_ORDER)


def build_verify_queue(findings, max_verify=None):
    """Return (entries, cut_count) for ALL agentic findings, priority-sorted.

    Entries hold REFERENCES to the original finding dicts (verdict application
    must mutate the real objects). Self-asserted provenance confirmation is
    ignored — everything non-tool queues. Stable order: (priority, input index),
    so recomputation in pass 2 reproduces pass 1's queue_ids exactly.
    """
    agentic = [(i, f) for i, f in enumerate(findings) if not is_tool_sourced(f)]
    agentic.sort(key=lambda t: (triage_priority(t[1]), t[0]))
    cut = 0
    if max_verify is not None and max_verify >= 0 and len(agentic) > max_verify:
        cut = len(agentic) - max_verify
        agentic = agentic[:max_verify]
    entries = []
    for qi, (_, f) in enumerate(agentic):
        entries.append({"queue_id": "%03d-%s" % (qi, f.get("id", "UNKNOWN")),
                        "priority": triage_priority(f),
                        "finding": f})
    return entries, cut


def write_verify_queue(entries, cut, path):
    """Serialize the queue for the orchestrating agent (pass 1 artifact)."""
    payload = {
        "version": "4.0.0",
        "cut_by_max_verify": cut,
        "entries": [{"queue_id": e["queue_id"], "priority": e["priority"],
                     "finding": {k: v for k, v in e["finding"].items()
                                 if not k.startswith("_")}}
                    for e in entries],
    }
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")
