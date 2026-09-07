"""Finding ingestion, normalization, dedupe and corroboration."""
from dataclasses import dataclass, field
import fnmatch
import os
import re
import sys

import scripts.evidence as evidence_mod
import scripts.groups_schema as groups_schema
import scripts.ocrdb as ocrdb


# evidence_mod owns the canonical severity and panel scales (#688's aliasing
# rationale: local copies of shared definitions drift).
SEV_ORDER = evidence_mod.SEV_ORDER

SEVERITIES = set(SEV_ORDER)

CONFIDENCES = {"CERTAIN", "LIKELY", "POSSIBLE", "NOTE"}

VERDICT_TO_CONFIDENCE = {"CONFIRMED": "CERTAIN", "PLAUSIBLE": "LIKELY"}

MODE_TO_REVIEW_TYPE = {
    "repo": "repo", "file": "file", "directory": "directory",
    "group": "group", "files": "changes", "changes": "changes",
}

PANEL_ORDER = evidence_mod.PANELS

VALID_PANELS = set(PANEL_ORDER)


@dataclass(frozen=True)
class FindingSet:
    """The findings a report is built from, plus the advisor verdicts that
    resolve them (WS-0 S2). Defaults mean what the omitted build_report
    keyword meant: no verdicts, no catalog (loaded on demand), no doc policy.

    `verdicts_supplied` records whether --verdicts-dir was passed at all
    (distinct from whether it yielded any verdicts) so the aggregate "no
    verdict" note still fires for an existing-but-empty dir."""
    findings: list
    verdicts: dict = field(default_factory=dict)
    verdicts_supplied: bool = False
    verdict_unloadable: list = field(default_factory=list)
    verdict_run_id: str | None = None
    verdict_bundles: dict = field(default_factory=dict)
    catalog: dict | None = None      # CWE catalog; None -> citations.load_cwe_catalog()
    doc_policy: dict | None = None   # apply_doc_severity_policy's disclosure

RELATED_PANELS = {
    "security": {"architecture", "database", "redteam"},
    "redteam": {"security", "architecture", "database"},
    "architecture": {"security", "database", "redteam"},
    "database": {"security", "architecture", "redteam"},
}

SHORT_TITLE_MAX = 100

def normalize_finding(f):
    """Normalize and validate finding fields with sensible defaults."""
    sev = str(f.get("severity", "INFO")).upper()
    f["severity"] = sev if sev in SEVERITIES else "INFO"
    conf = str(f.get("confidence", "")).upper()
    if conf in CONFIDENCES:
        f["confidence"] = conf
    else:
        verdict = str(f.get("verdict", "")).upper()
        f["confidence"] = VERDICT_TO_CONFIDENCE.get(verdict, "POSSIBLE")
    # panel: keep a valid legacy panel; else derive from the finding's domain
    # (matrix cells are domain-scoped); else the historical "code" default.
    panel = f.get("panel")
    if panel not in VALID_PANELS:
        domain = f.get("domain") or ocrdb.domain_of(f.get("code"))
        panel = ocrdb.DOMAIN_TO_PANEL.get(domain, "code")
    f["panel"] = panel
    # code/domain pass through untouched (validated at synthesize; never fabricated here)
    lens = f.get("lens")
    if lens:
        f["lens"] = str(lens)
    else:
        f.pop("lens", None)
    if not isinstance(f.get("location"), dict):
        f["location"] = {}
    loc = f["location"]
    # #5.0-04: bridge the {file, line} shape agents emit (older templates /
    # non-conforming output) into the pipeline's canonical line_start, so id
    # uniqueness, delta classification, and schema validation all work.
    if "line_start" not in loc and loc.get("line") is not None:
        loc["line_start"] = loc.pop("line")
    loc.setdefault("line_end", loc.get("line_start"))
    loc.setdefault("function", None)
    f.setdefault("references", [])
    f.setdefault("impact", "")
    f.setdefault("remediation", "")
    title = f.get("title")
    if not title:
        desc = str(f.get("description", "")).strip()
        title = desc.splitlines()[0].strip() if desc else "(untitled)"
    f["title"] = " ".join(str(title).split())
    # Tool messages can be whole remediation paragraphs (observed: 438 chars);
    # issue titles need a short form with the full text kept in the body.
    if len(f["title"]) > SHORT_TITLE_MAX:
        f["short_title"] = f["title"][:SHORT_TITLE_MAX - 1].rstrip() + "\u2026"
    else:
        f["short_title"] = f["title"]
    if not f.get("category"):
        f["category"] = "general"
    return f

# Fields that confer trust and must NEVER come from an agent-authored payload
# (SEC-102, found by our own self-scan). P2 did NOT weaken this guard; it
# sharpened it. The original rationale is obsolete in all three clauses --
# `source` no longer confers tool_confirmed evidence (that needs an advisor
# verdict now), there is no verify-queue exclusion left to buy, and it no
# longer confers gate eligibility -- but what replaced them is worse:
#
#   `source`: finding_fingerprint keys a TOOL-sourced finding on
#     tool_rule_id(), which falls back to provenance.confirmation_reasoning --
#     free text from the same payload. So a forged `source: "tool:*"` lets the
#     author choose the finding's fingerprint, and with it its queue_id, which
#     advisor verdict it answers to, and the cross-run identity every filed
#     issue is keyed on. That is identity manipulation, not merely a status
#     claim, and it is the one thing a content-addressed pipeline cannot
#     tolerate.
#   `reinforced`: triage_priority ranks a reinforced CRITICAL/HIGH at 0, ahead
#     of every uncorroborated one, so a forged flag jumps the --max-verify cut
#     and starves genuine claims of the advisor budget. It also flips
#     derive_evidence's tool_like branch.
#   `corroborated`/`corroborated_by` (#983): derive_evidence maps a
#     corroborated finding straight to evidence status `corroborated` -- a
#     verification tier reached with no advisor -- and triage_priority ranks a
#     corroborated CRITICAL/HIGH at 0 alongside reinforced. cross_panel_
#     corroboration only ever SETS these on a real >=2-distinct-panel cluster
#     and never resets them to False, so a forged flag on a finding in no such
#     cluster is never cleared: the author self-certifies cross-panel
#     verification and jumps the --max-verify cut.
#   `evidence` (5.0 P5 Slice B, R1): evidence.status is ALWAYS derived by
#     derive_evidence from a real verdict bundle (or its absence), never
#     self-asserted by the panel that authored the finding. score_gate reads
#     evidence.status straight off the finding via EVIDENCE_FACTOR, so a
#     forged `evidence: {"status": "rejected"}` (factor 0.0) zeroes the
#     finding's score and lets it duck should_engage_primary/should_summon_
#     backup entirely -- the matrix's F_p/F_b verification gate itself.
#
# Only ingest_tools (tool output), dedupe's real merge branches, and
# cross_panel_corroboration may set these. `evidence` specifically is set
# only by derive_evidence, downstream of this strip.
AGENT_FORBIDDEN_FIELDS = ("source", "reinforced", "corroborated", "corroborated_by",
                          "evidence")

def load_findings(paths):
    """Load and normalize findings from agent-authored JSON files.

    Agent-settable trust fields are stripped here — see AGENT_FORBIDDEN_FIELDS.
    """
    out = []
    for path in paths:
        if not os.path.isfile(path):
            print("MISSING: %s" % path, file=sys.stderr)
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                data = evidence_mod.load_json_tolerant(fh.read())
        except Exception as e:  # noqa: BLE001 - tolerant by design
            print("PARSE ERROR %s: %s" % (path, e), file=sys.stderr)
            continue
        if not isinstance(data, dict):
            print("not a JSON object: %s" % path, file=sys.stderr)
            continue
        findings = data.get("findings", [])
        if not isinstance(findings, list):
            print("no findings list in %s" % path, file=sys.stderr)
            continue
        m = GROUP_RE.match(os.path.basename(path))
        group = m.group(1) if m else None
        for f in findings:
            if not isinstance(f, dict):
                print("skipping non-object finding in %s" % path, file=sys.stderr)
                continue
            for forbidden in AGENT_FORBIDDEN_FIELDS:
                if forbidden in f:
                    print("synthesize: stripped self-asserted %r from %s in %s"
                          % (forbidden, f.get("id", "?"), path), file=sys.stderr)
                    f.pop(forbidden, None)
            # #run7 COD-X0X: provenance verification sub-fields are agent-self-
            # assertable but render as an authoritative "confirmed" (green) badge
            # in the HTML report -- a reviewer cannot confirm its own finding.
            # Strip them here; apply_verdict re-writes them later from a REAL
            # advisor verdict, so nothing trustworthy is lost.
            prov = f.get("provenance")
            if isinstance(prov, dict):
                for k in ("confirmation_status", "confirmed_by",
                          "confirmation_reasoning"):
                    if k in prov:
                        print("synthesize: stripped self-asserted provenance.%s "
                              "from %s in %s" % (k, f.get("id", "?"), path),
                              file=sys.stderr)
                        prov.pop(k, None)
            nf = normalize_finding(f)
            # #1109: never trust an agent-supplied `id`. A well-formed but crafted
            # or colliding id would otherwise be kept verbatim and could inherit an
            # unrelated CONFIRMED verdict via match_verdict_by_id (a fake finding
            # made gate-eligible with no advisor). Always content-derive it; the
            # driver's _load_cell_findings regenerates identically so the advisor's
            # finding_id echo still binds.
            nf["id"] = evidence_mod.matrix_finding_id(nf)
            if group is not None:
                nf["_group"] = group
            out.append(nf)
    return out

# Alias the shared severity rank instead of re-implementing it — same
# rationale as _is_tool_sourced below.
_sev_rank = evidence_mod.sev_rank

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

def _norm_line(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return v

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
        line = _norm_line(loc.get("line_start"))
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
            best = min(group, key=lambda f: (_sev_rank(f), _conf_rank(f)))
            other = agent_srcd[0] if _is_tool_sourced(best) else tool_srcd[0]
            best["reinforced"] = True
            _reinforce_merge(best, other)
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
                    best = min(sub, key=lambda f: (_sev_rank(f), _conf_rank(f)))
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
                                key=lambda f: (_sev_rank(f), _conf_rank(f)),
                            )
                            _reinforce_merge(best, best_tool)
                        for m in sub:
                            if m is not best:
                                _reinforce_merge(best, m)
                    result.append(best)
    return result + passthrough

# Cross-panel corroboration groups findings from DIFFERENT panels at a nearby
# locus. Anchor-bounded so a cluster never spans more than this many lines (no
# transitive chaining); 2 catches adjacent-line citations (e.g. a function def
# vs the vulnerable call inside it) while staying tight against false joins.
CORROBORATION_LINE_WINDOW = 2

def _max_severity(findings):
    """Return the most-severe severity label among findings."""
    return min(findings, key=_sev_rank).get("severity", "INFO")

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
        line = _norm_line(loc.get("line_start"))
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
                le = _norm_line((c[2].get("location") or {}).get("line_end"))
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

def _present(findings, sev):
    return any(f.get("severity") == sev for f in findings)

HIGH_VALUE_PANELS = {"security", "redteam", "architecture", "database"}

ID_RE = re.compile(r"^[A-Z]{2,8}-\d{3,}$")  # {2,8}: real agents emit e.g. STRUCT-001

# Axis alternation: the 6 legacy PANEL_ORDER names (4.x findings-<group>-<panel>
# [-panel_review|-lens_sweep-<lens>].json) plus the 10 P4 matrix domain codes
# (findings-<group>-<domain>.json, no further suffix -- see present_cells, which
# parses the same P4 shape independently off groups_schema.DOMAINS to avoid
# drift). Keyed off groups_schema.DOMAINS, not a hardcoded literal, so a future
# roster change (P6+) only has to update one place.
_AXES = list(PANEL_ORDER) + sorted(groups_schema.DOMAINS)

GROUP_RE = re.compile(
    r"^findings-(.+)-(?:%s)"
    r"(?:-panel_review|-lens_sweep-[A-Za-z0-9_]+)?\.json$" % "|".join(_AXES))

# #487: committed planning-doc trees (specs, plans, ADRs) are prose, not
# code -- code-oriented findings against them are noise. Path-scoped,
# mode-gated, severity-only soft downgrade with a secrets carve-out.
DOC_PATH_GLOBS = ["docs/*", "specs/*", "*/specs/*", "plans/*", "*/plans/*"]

_SECRET_FINDING_RE = re.compile(
    r"secret|credential|token|password|api[-_ ]?key|private[-_ ]key", re.I)

def apply_doc_severity_policy(findings, security_mode, doc_globs=None):
    """Soft-downgrade code findings under doc-classified paths to INFO (#487).

    Standard mode only -- redteam scans docs for planted content at full
    severity, so the policy is a no-op there (returns None = not applied).
    Secret/credential findings keep their severity (a real credential pasted
    into a plan is the one finding you most want OUT of a doc). Severity is
    never rewritten upward; the downgrade is recorded on the finding
    (doc_policy.downgraded_from) and disclosed in the returned summary, never
    silent. Mutates findings in place.
    """
    if security_mode == "redteam":
        return None
    globs = doc_globs or DOC_PATH_GLOBS
    downgraded = 0
    examples = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        loc = f.get("location") or {}
        path = evidence_mod.norm_path(loc.get("file"))
        if not path or not any(fnmatch.fnmatch(path, g) for g in globs):
            continue
        sev = str(f.get("severity", "")).upper()
        if sev in ("", "INFO"):
            continue
        blob = " ".join([str(f.get("category", "")), str(f.get("title", "")),
                         str(f.get("source", ""))])
        if _SECRET_FINDING_RE.search(blob) or "gitleaks" in blob:
            continue
        f["severity"] = "INFO"
        f["doc_policy"] = {"downgraded_from": sev}
        downgraded += 1
        if len(examples) < 10:
            examples.append({"file": path, "from": sev})
    return {"downgraded": downgraded, "examples": examples}

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
    return prepare_findings(aggregate_tool_findings(findings))

def evidence_stats(findings):
    """Count findings by evidence status."""
    stats = {s: 0 for s in evidence_mod.EVIDENCE_STATUSES}
    for f in findings:
        st = (f.get("evidence") or {}).get("status")
        if st in stats:
            stats[st] += 1
    return stats

def _issue_sort(f):
    """Severity first; among equals, gate-eligible evidence leads."""
    eligible = ((f.get("evidence") or {}).get("status")
                in evidence_mod.GATE_ELIGIBLE_DEFAULT)
    return (_sev_rank(f), 0 if eligible else 1)

def aggregate_tool_findings(findings):
    """Collapse repeated tool hits of one rule in one file into a single finding.

    A scanner rule that fires 18 times in a workflow file is ONE issue with 18
    loci, not 18 issues. Only tool-sourced findings aggregate; agent findings
    are distinct judgements and pass through untouched. The survivor keeps the
    lowest line as its primary locus and records the rest in `additional_loci`
    — except where an agent independently flagged one of the other lines, in
    which case that locus wins. This runs before dedupe, which reinforces on an
    EXACT (file, line) match: moving the tool witness off a line an agent also
    flagged would silently cost that finding its `reinforced` status — the
    tool+agent corroboration in `verified_by`, and the triage_priority 0 that
    puts it at the head of the verify queue. (Pre-P2 it also cost the finding
    automatic `tool_confirmed` evidence; unverified tool claims are
    `tool_reported` now, and only an advisor verdict promotes them.)
    """
    agent_loci = {
        (evidence_mod.norm_path((f.get("location") or {}).get("file")),
         _norm_line((f.get("location") or {}).get("line_start")))
        for f in findings if not evidence_mod.is_tool_sourced(f)}

    def _sort_key(f):
        loc = f.get("location") or {}
        line = _norm_line(loc.get("line_start"))
        corroborated = (evidence_mod.norm_path(loc.get("file")), line) in agent_loci
        return (0 if corroborated else 1, line if isinstance(line, int) else 0)

    out, groups, order = [], {}, []
    for f in findings:
        rule = evidence_mod.tool_rule_id(f)
        if not evidence_mod.is_tool_sourced(f) or not rule:
            out.append(f)
            continue
        key = (f.get("panel"), f.get("category"),
               evidence_mod.norm_path(((f.get("location") or {}).get("file"))),
               str(rule))
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(f)
    for key in order:
        members = sorted(groups[key], key=_sort_key)
        best = members[0]
        if len(members) > 1:
            rest = sorted(members[1:], key=lambda m: _sort_key(m)[1])
            best["additional_loci"] = [
                {"file": (m.get("location") or {}).get("file"),
                 "line_start": (m.get("location") or {}).get("line_start")}
                for m in rest]
        best["occurrences"] = len(members)
        out.append(best)
    return out
