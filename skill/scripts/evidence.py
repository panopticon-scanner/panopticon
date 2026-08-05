#!/usr/bin/env python3
"""Evidence axis for panopticon findings: status derivation, verify-queue
triage, and advisor verdict ingestion. Stdlib-only.

Two-axis model: severity means "impact if true" and is never mutated here;
evidence.status records how hard the claim has been verified.
"""

import hashlib
import json
import os
import re
import sys

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
EVIDENCE_STATUSES = ("tool_reported", "tool_confirmed", "advisor_confirmed",
                     "corroborated", "needs_more_info", "unverified",
                     "rejected")
GATE_ELIGIBLE_DEFAULT = frozenset({"tool_confirmed", "advisor_confirmed"})
VERDICT_VALUES = {"CONFIRMED", "REJECTED", "NEEDS_MORE_INFO"}


def is_tool_sourced(finding):
    """Tool-emitted findings carry source='tool:<name>'; everything else is agentic."""
    return str(finding.get("source", "")).startswith("tool:")


def tool_rule_id(finding):
    """The scanner rule a tool finding came from, wherever its adapter put it.

    Two adapter families disagree: the dependency scanners (pip_audit,
    bundler_audit, dependency_check, eslint_security) set
    `tool_evidence.rule_id`, while everything on the SARIF path (bandit,
    semgrep, trivy, ...) sets no tool_evidence at all and carries the rule id
    in `provenance.confirmation_reasoning` via attach_tool_provenance. Reading
    only the first form made every SARIF finding look rule-less, which silently
    disabled both aggregation and rule-based fingerprint identity for them.
    """
    rule = (finding.get("tool_evidence") or {}).get("rule_id")
    if rule:
        return rule
    return (finding.get("provenance") or {}).get("confirmation_reasoning") or None


def finding_fingerprint(finding):
    """Stable cross-run identity for a finding.

    Keys on panel + category + normalized file + the discriminator that is
    actually stable for that source: a tool's rule_id, or an agent finding's
    title. Deliberately EXCLUDES line numbers (issues survive code moves) and
    free-text description (agent prose is re-worded every run). Also the
    verify-queue's queue_id (P2) — the same identity both passes compute.
    """
    loc = finding.get("location") or {}
    fpath = str(loc.get("file") or "").replace("\\", "/")
    # Strip only a `./` prefix. `lstrip("./")` would eat the leading dot of
    # every dotfile path, collapsing `.github/x` onto `github/x`.
    while fpath.startswith("./"):
        fpath = fpath[2:]
    # Gate on tool-sourcing: on an AGENT finding, confirmation_reasoning holds
    # advisor prose, which would be a disastrous identity discriminator.
    rule = tool_rule_id(finding) if is_tool_sourced(finding) else None
    discriminator = str(rule) if rule else str(finding.get("title") or "")
    payload = "|".join([str(finding.get("panel") or ""),
                        str(finding.get("category") or ""),
                        fpath, discriminator]).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


def sev_rank(finding):
    """Lower is more severe; unknown severities sort last."""
    try:
        return SEV_ORDER.index(finding.get("severity", "INFO"))
    except ValueError:
        return len(SEV_ORDER)


def derive_evidence(finding, verdict=None):
    """Return the evidence dict for a finding.

    Precedence (P2, #446): an advisor VERDICT decides first, whatever the
    source — previously tool-sourcing short-circuited ahead of verdicts, so an
    advisor could never refute a scanner. Without a verdict, a tool-sourced or
    reinforced finding is `tool_reported`: reported, not verified, and NOT
    gate-eligible. Never mutates the finding. Self-asserted
    provenance.confirmation_status is deliberately ignored — a reviewer cannot
    confirm its own finding.
    """
    quality = finding.get("citation_quality") or "none"
    prov = finding.get("provenance") or {}
    reinforced = bool(finding.get("reinforced"))
    tool_like = is_tool_sourced(finding) or reinforced
    origin = "tool+agent" if reinforced else finding.get("source")

    v = str((verdict or {}).get("verdict", "")).upper()
    if v in VERDICT_VALUES:
        if v == "REJECTED":
            status = "rejected"
        elif v == "NEEDS_MORE_INFO":
            status = "needs_more_info"
        else:
            status = "tool_confirmed" if tool_like else "advisor_confirmed"
        return {"status": status,
                "verified_by": ([origin, "agent:advisor"] if tool_like
                                else "agent:advisor"),
                "reasoning": (verdict or {}).get("reasoning"),
                "citation_quality": quality}

    if tool_like:
        return {"status": "tool_reported", "verified_by": origin,
                "reasoning": ("Same locus reported independently by a tool and "
                              "an agent" if reinforced
                              else prov.get("confirmation_reasoning")
                              or "Reported by static-analysis tool"),
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


def _queue_tiebreak(f):
    """Last-resort content discriminator for build_verify_queue's sort key.

    finding_fingerprint deliberately excludes line numbers, so two findings
    at different lines in the same file can share one fingerprint; if they
    also share (or both lack) an `id` -- normalize_finding never assigns a
    missing one -- the sort key up to this point ties completely. `sorted`
    is stable, so a total tie falls back to INPUT ORDER: exactly the
    invariant this module exists to remove, and it would decide which
    finding gets the bare fingerprint vs. the `-1` suffix, so a shuffled
    input could hand each finding the other's advisor verdict.

    Deliberately limited to fields BOTH synthesize passes see identically on
    the same finding object: location/severity/source/id survive unchanged
    from the --emit-verify-queue pass to the report-build pass. `_group` is
    NOT safe -- synthesize.build_report strips it (`f.pop("_group", None)`)
    before the second pass would ever see it -- and hashing the whole
    finding dict is NOT safe either, since later pipeline stages add keys
    (`evidence`, `fingerprint`) the emit pass never sees. Either would
    reintroduce pass divergence in a subtler form than the bug this fixes.
    A residual tie after this means the two findings are identical in every
    field that could distinguish them: genuinely fungible claims.
    """
    loc = f.get("location") or {}
    return (str(loc.get("file") or ""), str(loc.get("line_start") or ""),
           str(f.get("severity") or ""), str(f.get("source") or ""))


def build_verify_queue(findings, max_verify=None):
    """Return (entries, cut) for ALL findings, priority-sorted.

    Entries hold REFERENCES to the original finding dicts (verdict application
    must mutate the real objects).

    P2 (#446): tool-sourced and reinforced findings queue too — they are claims
    like any other, and `tool_confirmed` now requires an advisor verdict.
    P2 (#443/#438): the sort key and queue_id are pure functions of finding
    CONTENT — no input index anywhere, including in the collision-suffix
    assignment (see `_queue_tiebreak`) — so both passes of a run compute the
    same ids and a --max-verify cut cannot depend on filename order.
    """
    ordered = sorted(findings, key=lambda f: (triage_priority(f), sev_rank(f),
                                              finding_fingerprint(f),
                                              str(f.get("id") or ""),
                                              _queue_tiebreak(f)))
    cut = 0
    if max_verify is not None and max_verify >= 0 and len(ordered) > max_verify:
        cut = len(ordered) - max_verify
        ordered = ordered[:max_verify]
    entries = []
    seen = {}
    for f in ordered:
        fp = finding_fingerprint(f)
        n = seen.get(fp, 0)
        seen[fp] = n + 1
        qid = fp if n == 0 else "%s-%d" % (fp, n)
        if n:
            # Two findings with one identity usually means dedupe should have
            # merged them; keep them distinct and say so rather than collide.
            print("evidence: fingerprint collision %s (finding %r) -> %s"
                  % (fp, f.get("id"), qid), file=sys.stderr)
        entries.append({"queue_id": qid, "priority": triage_priority(f),
                        "finding": f})
    return entries, cut


def write_verify_queue(entries, cut, path):
    """Serialize the queue for the orchestrating agent (pass 1 artifact)."""
    payload = {
        "version": "4.2.0",
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
