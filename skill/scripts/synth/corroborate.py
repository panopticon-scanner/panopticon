"""Dedupe, cross-panel corroboration and the one pipeline both synthesize
passes share.

Split out of `synth/findings.py` (a pure move) so neither module sits on the
700-line ceiling. `findings` still owns ingestion and normalization; this
module is everything that happens to a normalized list AFTER it is loaded and
BEFORE the report is built -- collapsing same-locus duplicates, reinforcing a
tool+agent pair, and annotating the cross-lens agreement that
`cross_panel.integration_findings` reports.

It reads three names back out of `findings` (`_sev_rank`, `_norm_line`,
`aggregate_tool_findings`), never the other way round: the dependency runs one
way, so neither module needs the other to be fully imported first.
"""
import scripts.evidence as evidence_mod
from . import findings as findings_mod


RELATED_PANELS = {
    "security": {"architecture", "database", "redteam"},
    "redteam": {"security", "architecture", "database"},
    "architecture": {"security", "database", "redteam"},
    "database": {"security", "architecture", "redteam"},
}

def _conf_rank(f):
    order = ["CERTAIN", "LIKELY", "POSSIBLE", "NOTE"]
    try:
        return order.index(f.get("confidence", "NOTE"))
    except ValueError:
        return len(order)

# Alias the shared predicate instead of re-implementing it (#688): a local copy
# had already drifted from being the single source of the tool/agent provenance
# rule. evidence_mod.is_tool_sourced is the one definition.
def _is_tool_sourced(finding):
    return evidence_mod.is_tool_sourced(finding)

def _reinforce_merge(best, other):
    """Pull missing enrichment from other into best. The agent's cvss and
    exploit_scenario are preferred when either finding has them; other text
    fields are filled only if best lacks them; citations are merged rather
    than overwritten."""
    # Prefer agent-authored cvss/exploit_scenario ONLY when best and other are
    # the SAME issue (category match). _reinforce_merge fires for any same-LOCUS
    # tool+agent pair, so without this gate an agent finding about issue X could
    # clobber a tool survivor's authoritative cvss/exploit_scenario for a
    # DIFFERENT issue Y at the same line (run-4 self-scan C20). Missing fields
    # are still filled from `other` by the fall-back loop below.
    same_issue = str(best.get("category")) == str(other.get("category"))
    if not _is_tool_sourced(other) and same_issue:
        for field in ("cvss", "exploit_scenario"):
            if other.get(field):
                best[field] = other[field]
    # Fall back to the other finding for any still-missing enrichment.
    for field in ("cvss", "exploit_scenario", "impact", "remediation", "references"):
        if not best.get(field) and other.get(field):
            best[field] = other[field]
    evidence_mod.merge_citations(best, other)

def dedupe(findings):
    """Cluster findings by (file, line). An exactly-two cluster with one tool- and
    one agent-sourced finding is treated as the same issue seen twice (even across
    categories) -> collapse to one reinforced survivor. Larger clusters keep one
    survivor per category AND per tool rule id — the most severe — never merging
    across categories or across distinct rule ids (dependency scanners emit many
    distinct advisories at one manifest locus; each is a distinct issue); a
    category corroborated by BOTH a tool and an agent within such a cluster is
    still reinforced in place. Same file+line+category+rule findings are
    intentionally deduped to the most severe.
    Findings without a file OR without a concrete integer line pass through
    unmerged (clustering them on file+category alone would drop distinct issues
    that merely omit a line number)."""
    passthrough = []
    by_locus = {}
    order = []
    for f in findings:
        loc = f.get("location") or {}
        fkey = evidence_mod.norm_path(loc.get("file"))
        line = findings_mod._norm_line(loc.get("line_start"))
        if not fkey or not isinstance(line, int):
            passthrough.append(f)
            continue
        key = (fkey, line)
        if key not in by_locus:
            by_locus[key] = []
            order.append(key)
        by_locus[key].append(f)

    result = []
    for key in order:
        group = by_locus[key]
        tool_srcd = [f for f in group if _is_tool_sourced(f)]
        agent_srcd = [f for f in group if not _is_tool_sourced(f)]
        if len(group) == 2 and len(tool_srcd) == 1 and len(agent_srcd) == 1:
            best = min(group, key=lambda f: (findings_mod._sev_rank(f), _conf_rank(f)))
            other = agent_srcd[0] if _is_tool_sourced(best) else tool_srcd[0]
            best["reinforced"] = True
            _reinforce_merge(best, other)
            evidence_mod.record_merged_id(best, other)
            result.append(best)
        else:
            by_cat = {}
            corder = []
            for f in group:
                ck = f.get("category")
                if ck not in by_cat:
                    by_cat[ck] = []
                    corder.append(ck)
                by_cat[ck].append(f)
            for ck in corder:
                members = by_cat[ck]
                cat_has_tool = any(_is_tool_sourced(m) for m in members)
                cat_has_agent = any(not _is_tool_sourced(m) for m in members)
                # Sub-bucket by tool rule id: dependency scanners emit MANY
                # distinct advisories at the same manifest locus (lockfile:1)
                # under one category — collapsing those to one-per-category
                # silently discarded real CVEs (calibration 2026-08-03: 22
                # osv findings -> 3 survivors). Distinct rule_ids are distinct
                # issues; agent findings (no rule_id) share one bucket as before.
                by_rule = {}
                rorder = []
                for m in members:
                    rk = evidence_mod.tool_rule_id(m) if _is_tool_sourced(m) else None
                    if rk not in by_rule:
                        by_rule[rk] = []
                        rorder.append(rk)
                    by_rule[rk].append(m)
                for rk in rorder:
                    sub = by_rule[rk]
                    best = min(sub, key=lambda f: (findings_mod._sev_rank(f), _conf_rank(f)))
                    if cat_has_tool and cat_has_agent:
                        # Category-level tool+agent corroboration still marks
                        # every surviving member of the category reinforced;
                        # enrichment merges stay within the same rule bucket.
                        best["reinforced"] = True
                        # If the surviving member is agent-sourced (rk is None),
                        # merge a representative tool finding so `reinforced`
                        # remains tool-reported by construction (see evidence.py).
                        if rk is None:
                            best_tool = min(
                                [m for m in members if _is_tool_sourced(m)],
                                key=lambda f: (findings_mod._sev_rank(f), _conf_rank(f)),
                            )
                            _reinforce_merge(best, best_tool)
                        for m in sub:
                            if m is not best:
                                _reinforce_merge(best, m)
                    # #1476: alias EVERY collapsed member -- the
                    # corroboration branch above is conditional, the drop is not.
                    for m in sub:
                        if m is not best:
                            evidence_mod.record_merged_id(best, m)
                    result.append(best)
    return result + passthrough

# Cross-panel corroboration groups findings from DIFFERENT panels at a nearby
# locus. Anchor-bounded so a cluster never spans more than this many lines (no
# transitive chaining); 2 catches adjacent-line citations (e.g. a function def
# vs the vulnerable call inside it) while staying tight against false joins.
CORROBORATION_LINE_WINDOW = 2

def _max_severity(findings):
    """Return the most-severe severity label among findings."""
    return min(findings, key=findings_mod._sev_rank).get("severity", "INFO")

def cross_panel_corroboration(findings, window=CORROBORATION_LINE_WINDOW):
    """Surface cross-LENS agreement WITHOUT collapsing the distinct-lens findings.

    Distinct from dedupe (which collapses true same-lens duplicates and handles
    tool+agent reinforce). Cross-panel corroboration keys on (file, line-proximity)
    across DIFFERENT panels — deliberately NOT on category, because the same real
    issue seen through security/test/code lenses carries different categories by
    nature. When >=2 DISTINCT panels flag a nearby locus, each participating
    finding is annotated in place (`corroborated`/`corroborated_by`; confidence is
    left untouched — it is the reviewer's self-assessment, never the pipeline's)
    and a summary entry is returned for cross_panel.integration_findings.
    Requiring >=2 distinct panels is the guard against false corroboration: two
    same-panel findings, or findings at different files or beyond the line
    window, do NOT corroborate.
    """
    candidates = []
    for f in findings:
        loc = f.get("location") or {}
        fkey = evidence_mod.norm_path(loc.get("file"))
        line = findings_mod._norm_line(loc.get("line_start"))
        if fkey and isinstance(line, int):
            candidates.append((fkey, line, f))
    candidates.sort(key=lambda t: (t[0], t[1]))

    def _panels_related(p1, p2):
        if p1 == p2:
            return False
        # Panels outside the explicit map retain the legacy behavior: any two
        # distinct panels corroborate (preserves code/test/security pairings).
        if p1 in RELATED_PANELS and p2 in RELATED_PANELS:
            return p2 in RELATED_PANELS[p1] or p1 in RELATED_PANELS[p2]
        return True

    integration = []
    i, n = 0, len(candidates)
    while i < n:
        fkey, anchor = candidates[i][0], candidates[i][1]
        j = i + 1
        # admit while same file and within `window` lines of the anchor (the
        # cluster's lowest line) — bounds cluster width, so no runaway chaining.
        while j < n and candidates[j][0] == fkey and candidates[j][1] - anchor <= window:
            j += 1
        cluster = candidates[i:j]
        members = [c[2] for c in cluster]
        panels = sorted({m.get("panel") for m in members if m.get("panel")})
        if len(panels) >= 2 and any(_panels_related(p1, p2)
                                    for p1 in panels for p2 in panels):
            for m in members:
                m["corroborated"] = True
                m["corroborated_by"] = list(panels)
            line_starts = [c[1] for c in cluster]
            line_ends = []
            for c in cluster:
                le = findings_mod._norm_line((c[2].get("location") or {}).get("line_end"))
                line_ends.append(le if isinstance(le, int) else c[1])
            ls = min(line_starts)
            categories = sorted({m.get("category") for m in members if m.get("category")})
            ids = [m.get("id") for m in members if m.get("id")]
            integration.append({
                "location": {"file": fkey, "line_start": ls,
                             "line_end": max(line_ends)},
                "panels": panels,
                "categories": categories,
                "finding_ids": ids,
                "severity": _max_severity(members),
                "confidence": "CERTAIN",
                "summary": "%d panels (%s) independently flagged %s:%d" % (
                    len(panels), ", ".join(panels), fkey, ls),
            })
        i = j
    return integration

def prepare_findings(findings):
    """Dedupe + cross-panel corroboration. Extracted so pass 1 (--emit-verify-queue)
    can compute the queue with the same deterministic pipeline as pass 2."""
    findings = dedupe(findings)
    integration = cross_panel_corroboration(findings)
    return findings, integration

def prepare_for_queue(findings):
    """Aggregate, then prepare — the ONE pipeline both passes must share.

    #443: pass 1 (--emit-verify-queue) used to call prepare_findings alone
    while build_report aggregated first, so the two passes fed
    build_verify_queue different lists and every queue position after the
    first tool merge shifted. Both passes call this now; identity is
    content-addressed on top of it (evidence.build_verify_queue).
    """
    return prepare_findings(findings_mod.aggregate_tool_findings(findings))
