#!/usr/bin/env python3
"""Evidence axis for panopticon findings: status derivation, verify-queue
triage, and advisor verdict ingestion. Stdlib-only.

Two-axis model: severity means "impact if true" and is never mutated here;
evidence.status records how hard the claim has been verified.
"""

import json
import os
import re
import sys

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

    Precedence: tool_confirmed (incl. reinforced tool+agent merges) > advisor
    verdicts (CONFIRMED/REJECTED/NEEDS_MORE_INFO) > corroborated > unverified.
    Never mutates the finding. Self-asserted provenance.confirmation_status is
    deliberately ignored — a reviewer cannot confirm its own finding.
    """
    quality = finding.get("citation_quality") or "none"
    prov = finding.get("provenance") or {}
    if is_tool_sourced(finding):
        return {"status": "tool_confirmed",
                "verified_by": finding.get("source"),
                "reasoning": prov.get("confirmation_reasoning")
                or "Reported by static-analysis tool",
                "citation_quality": quality}
    if finding.get("reinforced"):
        # A tool+agent same-locus merge is tool-reported by construction, even
        # when the surviving finding's own `source` isn't `tool:*` -> gates the
        # same as a plain tool finding, never demoted to mere `corroborated`.
        return {"status": "tool_confirmed", "verified_by": "tool+agent",
                "reasoning": "Same locus reported independently by a tool and an agent",
                "citation_quality": quality}
    v = str((verdict or {}).get("verdict", "")).upper()
    if v in VERDICT_VALUES:
        status = {"CONFIRMED": "advisor_confirmed",
                  "REJECTED": "rejected"}.get(v, "needs_more_info")
        return {"status": status, "verified_by": "agent:advisor",
                "reasoning": (verdict or {}).get("reasoning"),
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
    ignored — everything non-tool queues, except reinforced (tool+agent
    same-locus merge) findings: they are tool-reported by construction and
    already derive tool_confirmed, so queuing them for advisor verification
    would be pointless and would make tool/verdict collisions possible.
    Stable order: (priority, input index), so recomputation in pass 2
    reproduces pass 1's queue_ids exactly.
    """
    agentic = [(i, f) for i, f in enumerate(findings)
              if not is_tool_sourced(f) and not f.get("reinforced")]
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
        "version": "4.1.0",
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


def merge_citations(best, other):
    """Merge other['citations'] into best['citations'] without overwriting
    keys that already exist in best. (Moved from synthesize._merge_citations.)"""
    oc = other.get("citations")
    if not oc:
        return
    if not best.get("citations"):
        best["citations"] = {}
    bc = best["citations"]
    for key, value in oc.items():
        if not value:
            continue
        if key not in bc or not bc[key]:
            bc[key] = value


def load_json_tolerant(body):
    """Parse JSON from text, stripping markdown code blocks and searching for JSON object."""
    body = body.strip()
    if body.startswith("```"):
        body = re.sub(r"^```[a-zA-Z]*\s*", "", body)
        body = re.sub(r"\s*```\s*$", "", body).strip()
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        m = re.search(r"(\{.*\})", body, re.DOTALL)
        if m:
            return json.loads(m.group(1))
        raise


def load_verdicts(verdicts_dir):
    """Load advisor verdict files keyed by queue_id (filename stem).

    Tolerant by design: unreadable/malformed files and files without a valid
    verdict key are skipped with a stderr note; never raises. Advisors
    routinely wrap their JSON output in a markdown fence (see agents/advisor.md's
    own output example) or add surrounding prose, so parsing goes through
    load_json_tolerant rather than a strict json.load.
    """
    out = {}
    if not verdicts_dir or not os.path.isdir(verdicts_dir):
        return out
    for name in sorted(os.listdir(verdicts_dir)):
        if not name.endswith(".json"):
            continue
        path = os.path.join(verdicts_dir, name)
        try:
            with open(path, encoding="utf-8") as fh:
                data = load_json_tolerant(fh.read())
        except (OSError, ValueError) as e:
            print("evidence: skipping malformed verdict %s: %s" % (name, e),
                  file=sys.stderr)
            continue
        if (not isinstance(data, dict)
                or str(data.get("verdict", "")).upper() not in VERDICT_VALUES):
            print("evidence: skipping verdict %s: missing/invalid verdict key" % name,
                  file=sys.stderr)
            continue
        out[name[:-len(".json")]] = data
    return out


def match_verdict(entry, verdicts):
    """Return the verdict for a queue entry, enforcing the finding_id echo.

    An explicit echo mismatch means the verdict answered a different claim ->
    treated as malformed (None). A missing echo is accepted with a warning.
    """
    v = verdicts.get(entry["queue_id"])
    if v is None:
        return None
    fid = entry["finding"].get("id")
    echoed = v.get("finding_id")
    if echoed is None:
        print("evidence: verdict %s has no finding_id echo; accepting"
              % entry["queue_id"], file=sys.stderr)
        return v
    if str(echoed) != str(fid):
        print("evidence: verdict %s echoes finding_id %r, expected %r; ignoring"
              % (entry["queue_id"], echoed, fid), file=sys.stderr)
        return None
    return v


def apply_verdict(finding, verdict):
    """Merge an advisor verdict into provenance/citations/references.

    Never touches severity or confidence — the two-axis invariant. Citation
    re-validation happens afterwards via citations.enrich_citations.
    """
    prov = finding.setdefault("provenance", {})
    v = str(verdict.get("verdict", "")).upper()
    prov["confirmation_status"] = {"CONFIRMED": "CONFIRMED",
                                   "REJECTED": "REJECTED"}.get(v, "NEEDS_MORE_INFO")
    prov["confirmed_by"] = "agent:advisor"
    prov["confirmation_reasoning"] = verdict.get("reasoning")
    if verdict.get("model"):
        prov["confirmed_by_model"] = verdict["model"]
    merge_citations(finding, {"citations": verdict.get("citations") or {}})
    existing = set(finding.get("references") or [])
    for ref in verdict.get("references") or []:
        if ref not in existing:
            finding.setdefault("references", []).append(ref)
            existing.add(ref)
