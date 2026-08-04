#!/usr/bin/env python3
"""Merge panopticon finding files into a validated CodeReviewReport with
grades and a CI gate verdict. Stdlib-only.
"""
import argparse
import hashlib
import glob
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import scripts.citations as citations
from scripts.citations import load_cwe_catalog
import scripts.evidence as evidence_mod
import scripts.html_report as html_report
import scripts.ingest_tools as ingest_tools

# Moved to evidence.py (also used by evidence.load_verdicts for advisor
# verdict files, which are just as likely to be fence-wrapped or prose-
# wrapped as panel/lens findings files). Delegation keeps this name importable
# as scripts.synthesize.load_json_tolerant for existing callers/tests.
load_json_tolerant = evidence_mod.load_json_tolerant

SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
CONFIDENCES = {"CERTAIN", "LIKELY", "POSSIBLE", "NOTE"}
VERDICT_TO_CONFIDENCE = {"CONFIRMED": "CERTAIN", "PLAUSIBLE": "LIKELY"}
MODE_TO_REVIEW_TYPE = {
    "repo": "repo", "file": "file", "directory": "directory",
    "group": "group", "files": "changes", "changes": "changes",
}
VALID_PANELS = {"code", "test", "security", "architecture", "database", "redteam"}
PANEL_ORDER = ["code", "test", "security", "architecture", "database", "redteam"]
RELATED_PANELS = {
    "security": {"architecture", "database", "redteam"},
    "redteam": {"security", "architecture", "database"},
    "architecture": {"security", "redteam"},
    "database": {"security", "redteam"},
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
    if f.get("panel") not in VALID_PANELS:
        f["panel"] = "code"
    lens = f.get("lens")
    if lens:
        f["lens"] = str(lens)
    else:
        f.pop("lens", None)
    if not isinstance(f.get("location"), dict):
        f["location"] = {}
    loc = f["location"]
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
# (SEC-102, found by our own self-scan): `source` drives is_tool_sourced() ->
# tool_confirmed evidence + verify-queue exclusion + gate eligibility, and
# `reinforced` short-circuits verification the same way. Only ingest_tools
# (tool output) and dedupe's real merge branches may set them.
AGENT_FORBIDDEN_FIELDS = ("source", "reinforced")


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
                data = load_json_tolerant(fh.read())
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
            nf = normalize_finding(f)
            if group is not None:
                nf["_group"] = group
            out.append(nf)
    return out


def _sev_rank(f):
    try:
        return SEV_ORDER.index(f.get("severity", "INFO"))
    except ValueError:
        return len(SEV_ORDER)


def _conf_rank(f):
    order = ["CERTAIN", "LIKELY", "POSSIBLE", "NOTE"]
    try:
        return order.index(f.get("confidence", "NOTE"))
    except ValueError:
        return len(order)


def _is_tool_sourced(f):
    """Tool-emitted findings carry source='tool:<name>'; agent/panel findings
    carry no source field. Mirrors the provenance convention in validate_report
    and render_summary (anything not 'tool:' is agent-sourced)."""
    return str(f.get("source", "")).startswith("tool:")


def _role_from_discovered_by(discovered_by):
    """Map a provenance discovered_by value to a model role."""
    if not discovered_by:
        return None
    discovered_by = str(discovered_by)
    if discovered_by.startswith("agent:"):
        return discovered_by.split(":", 1)[1]
    return discovered_by


def _collect_models_used(findings):
    """Collect unique model/version/role triples from agent findings.

    Tool findings (model is null) are skipped. Agent findings contribute their
    provenance model/version plus a role derived from discovered_by. Advisor
    confirmations contribute the confirming model with role 'advisor'.
    """
    seen = set()
    out = []
    for f in findings:
        prov = f.get("provenance") or {}
        model = prov.get("model")
        version = prov.get("model_version")
        # Skip tool and other entries without a model identifier.
        if not model:
            continue
        role = _role_from_discovered_by(prov.get("discovered_by"))
        # Dedup by (model, role): agents self-report model_version
        # inconsistently (F-CAL-3), which produced duplicate entries.
        key = (model, role)
        if key in seen:
            continue
        seen.add(key)
        entry = {"model": model, "role": role}
        if version:
            entry["version"] = version
        out.append(entry)
        confirmed_by_model = prov.get("confirmed_by_model")
        if confirmed_by_model:
            advisor_key = (confirmed_by_model, None, "advisor")
            if advisor_key not in seen:
                seen.add(advisor_key)
                out.append({"model": confirmed_by_model, "role": "advisor"})
    return out


def _reinforce_merge(best, other):
    """Pull missing enrichment from other into best. The agent's cvss and
    exploit_scenario are preferred when either finding has them; other text
    fields are filled only if best lacks them; citations are merged rather
    than overwritten."""
    # Prefer agent-authored cvss/exploit_scenario.
    if not _is_tool_sourced(other):
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
        fkey = loc.get("file")
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
                    rk = tool_rule_id(m) if _is_tool_sourced(m) else None
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
        fkey = loc.get("file")
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


def grade(findings):
    """Assign letter grade (A-F) based on highest severity finding."""
    if _present(findings, "CRITICAL"):
        return "F"
    if _present(findings, "HIGH"):
        return "D"
    if _present(findings, "MEDIUM"):
        return "C"
    if _present(findings, "LOW"):
        return "B"
    return "A"


def risk_level(findings):
    """Determine overall risk level (CRITICAL/HIGH/MEDIUM/LOW) from findings."""
    for sev in ("CRITICAL", "HIGH", "MEDIUM"):
        if _present(findings, sev):
            return sev
    return "LOW"


def gate_verdict(findings, fail_on):
    """Return CI gate verdict (PASS/FAIL/OFF) based on findings and threshold."""
    if not fail_on:
        return "OFF"
    threshold = SEV_ORDER.index(str(fail_on).upper())
    for f in findings:
        try:
            if SEV_ORDER.index(f.get("severity", "INFO")) <= threshold:
                return "FAIL"
        except ValueError:
            continue
    return "PASS"


def severity_stats(findings):
    """Count findings by severity level."""
    stats = {s.lower(): 0 for s in SEV_ORDER}
    for f in findings:
        sev = f.get("severity", "INFO").lower()
        if sev in stats:
            stats[sev] += 1
    return stats


ID_RE = re.compile(r"^[A-Z]{2,8}-\d{3,}$")  # {2,8}: real agents emit e.g. STRUCT-001
GROUP_RE = re.compile(
    r"^findings-(.+)-(?:code|test|security|architecture|database|redteam)"
    r"(?:-panel_review|-lens_sweep-[A-Za-z0-9_]+)?\.json$")
_GRADE_ORDER = ["A", "B", "C", "D", "F"]


def _worst_grade(grades):
    present = [g for g in grades if g in _GRADE_ORDER]
    return max(present, key=_GRADE_ORDER.index) if present else "A"


def prepare_findings(findings):
    """Dedupe + cross-panel corroboration. Extracted so pass 1 (--emit-verify-queue)
    can compute the queue with the same deterministic pipeline as pass 2."""
    findings = dedupe(findings)
    integration = cross_panel_corroboration(findings)
    return findings, integration


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


def derive_tool_policy_mode(panopticon_dir=".panopticon"):
    """Derive the run's tool-policy posture from dispatch plan files.

    enforced: every entry across every plan file is enforced; advisory: none
    are (or no plan files exist — nothing was enforced); mixed: some are.
    Tolerant: unreadable/malformed plan files are ignored.
    """
    flags = []
    for path in sorted(glob.glob(os.path.join(panopticon_dir, "dispatch-plan*.json"))):
        try:
            with open(path, encoding="utf-8") as fh:
                plan = json.load(fh)
        except (OSError, ValueError):
            continue
        if isinstance(plan, list):
            flags.extend(bool(e.get("enforced")) for e in plan if isinstance(e, dict))
    if flags and all(flags):
        return "enforced"
    if any(flags):
        return "mixed"
    return "advisory"


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
    """Stable cross-run identity for a finding, for issue round-tripping.

    Keys on panel + category + normalized file + the discriminator that is
    actually stable for that source: a tool's rule_id, or an agent finding's
    title. Deliberately EXCLUDES line numbers (issues survive code moves) and
    free-text description (agent prose is re-worded every run).
    """
    loc = finding.get("location") or {}
    fpath = str(loc.get("file") or "").replace("\\", "/")
    # Strip only a `./` prefix. `lstrip("./")` would eat the leading dot of
    # every dotfile path, collapsing `.github/x` onto `github/x`.
    while fpath.startswith("./"):
        fpath = fpath[2:]
    # Gate on tool-sourcing: on an AGENT finding, confirmation_reasoning holds
    # advisor prose, which would be a disastrous identity discriminator.
    rule = tool_rule_id(finding) if _is_tool_sourced(finding) else None
    discriminator = str(rule) if rule else str(finding.get("title") or "")
    payload = "|".join([str(finding.get("panel") or ""),
                        str(finding.get("category") or ""),
                        fpath, discriminator]).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


def aggregate_tool_findings(findings):
    """Collapse repeated tool hits of one rule in one file into a single finding.

    A scanner rule that fires 18 times in a workflow file is ONE issue with 18
    loci, not 18 issues. Only tool-sourced findings aggregate; agent findings
    are distinct judgements and pass through untouched. The survivor keeps the
    lowest line as its primary locus and records the rest in `additional_loci`
    — except where an agent independently flagged one of the other lines, in
    which case that locus wins. This runs before dedupe, which reinforces on an
    EXACT (file, line) match: moving the tool witness off a line an agent also
    flagged would silently cost that finding its tool_confirmed evidence.
    """
    agent_loci = {
        (str(((f.get("location") or {}).get("file")) or ""),
         _norm_line((f.get("location") or {}).get("line_start")))
        for f in findings if not evidence_mod.is_tool_sourced(f)}

    def _sort_key(f):
        loc = f.get("location") or {}
        line = _norm_line(loc.get("line_start"))
        corroborated = (str(loc.get("file") or ""), line) in agent_loci
        return (0 if corroborated else 1, line if isinstance(line, int) else 0)

    out, groups, order = [], {}, []
    for f in findings:
        rule = tool_rule_id(f)
        if not evidence_mod.is_tool_sourced(f) or not rule:
            out.append(f)
            continue
        key = (f.get("panel"), f.get("category"),
               str(((f.get("location") or {}).get("file")) or ""), str(rule))
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


def build_report(findings, groups_meta, target, fail_on, timestamp, review_type="repo",
                 security_mode="standard", verdicts=None, gate_unverified=False,
                 max_verify=None, verdicts_supplied=False, tool_policy_mode=None):
    """Build a CodeReviewReport under the two-axis severity x evidence model.

    Severity is never mutated here. Verdicts (from evidence.load_verdicts) are
    applied to queued findings; every finding gets an evidence object; grades
    and the gate are computed from gate-eligible findings only (all non-rejected
    when gate_unverified is set). `verdicts_supplied` records whether --verdicts-dir
    was passed at all (distinct from whether it yielded any verdicts) so the
    aggregate "no verdict" note still fires for an existing-but-empty dir.
    """
    findings = aggregate_tool_findings(findings)
    findings, integration_findings = prepare_findings(findings)
    catalog = load_cwe_catalog()
    queue, _cut = evidence_mod.build_verify_queue(findings, max_verify)
    verdicts = verdicts or {}
    matched = {}
    unanswered = 0
    for entry in queue:
        v = evidence_mod.match_verdict(entry, verdicts)
        if v is not None:
            evidence_mod.apply_verdict(entry["finding"], v)
        elif verdicts_supplied:
            unanswered += 1
        matched[id(entry["finding"])] = v
    if unanswered:
        print("synthesize: %d queued findings had no verdict; left unverified"
              % unanswered, file=sys.stderr)
    unknown = set(verdicts) - {e["queue_id"] for e in queue}
    if unknown:
        print("synthesize: verdict file(s) for unknown queue_id(s): %s"
              % ", ".join(sorted(unknown)), file=sys.stderr)
    # Re-validate citations after advisor merges (idempotent; preserves epss).
    citations.enrich_citations(findings, catalog, epss_enabled=False)
    for f in findings:
        f["evidence"] = evidence_mod.derive_evidence(f, matched.get(id(f)))
        f["fingerprint"] = finding_fingerprint(f)
        f.pop("citation_quality", None)

    rejected = [f for f in findings if f["evidence"]["status"] == "rejected"]
    active = [f for f in findings if f["evidence"]["status"] != "rejected"]
    gate_eligible = (active if gate_unverified else
                     [f for f in active
                      if f["evidence"]["status"] in evidence_mod.GATE_ELIGIBLE_DEFAULT])

    by_panel = {p: [] for p in VALID_PANELS}
    for f in gate_eligible:
        by_panel.get(f["panel"], by_panel["code"]).append(f)

    known_groups = {g["name"] for g in groups_meta}
    group_objs = []
    for g in groups_meta:
        gfiles = set(g["files"])
        gfind = [f for f in active
                 if (f.get("_group") == g["name"])
                 or (f.get("_group") not in known_groups
                     and (f.get("location") or {}).get("file") in gfiles)]
        eligible_ids = {id(x) for x in gate_eligible}
        geligible = [f for f in gfind if id(f) in eligible_ids]
        gp = {p: [x for x in geligible if x["panel"] == p] for p in by_panel}
        group_objs.append({
            "name": g["name"],
            "files": g["files"],
            "panel_grades": {p: grade(gp[p]) for p in by_panel},
            "key_findings": [f.get("title", "") for f in gfind
                             if f["severity"] in ("CRITICAL", "HIGH")][:5],
        })

    overall = _worst_grade([grade(by_panel[p]) for p in by_panel])
    for f in findings:
        f.pop("_group", None)
        f.pop("_repo_root", None)
    return {
        "meta": {
            "target": target,
            "review_type": review_type,
            "timestamp": timestamp,
            "version": "4.2.0",
            "security_mode": security_mode,
            "models_used": _collect_models_used(findings),
            **({"tool_policy_mode": tool_policy_mode} if tool_policy_mode else {}),
        },
        "summary": {
            "overall_grade": overall,
            "risk_level": risk_level(gate_eligible),
            "top_issues": [f.get("title", "") for f in
                           sorted(active, key=_issue_sort)[:3]],
            "gate": gate_verdict(gate_eligible, fail_on),
            "gate_policy": ("include_unverified" if gate_unverified
                            else "confirmed_only"),
            "stats": severity_stats(active),
            "evidence_stats": evidence_stats(findings),
        },
        "groups": group_objs,
        "findings": active,
        "discarded_claims": rejected,
        "cross_panel": {"integration_findings": integration_findings},
    }


def attach_schema_status(report, errors):
    """Record schema-validation results in the artifact itself.

    Validation stays advisory — a run never aborts — but the count is no longer
    stderr-only, so a downstream consumer (issue tracker, CI) can see that a
    report failed its own schema.
    """
    report.setdefault("meta", {})["schema_errors"] = len(errors)
    return report


def validate_report(report):
    """Validate report structure and content, returning error and warning lists."""
    errors, warnings = [], []
    for key in ("meta", "summary", "groups", "findings", "cross_panel"):
        if key not in report:
            errors.append("missing top-level key: %s" % key)
    for i, f in enumerate(report.get("findings", [])):
        if not ID_RE.match(f.get("id", "")):
            errors.append("finding[%d] bad id: %r" % (i, f.get("id")))
        if not f.get("title"):
            errors.append("finding[%d] missing title" % i)
        if not f.get("category"):
            errors.append("finding[%d] missing category" % i)
        if f.get("severity") not in SEVERITIES:
            errors.append("finding[%d] bad severity: %r" % (i, f.get("severity")))
        if f.get("confidence") not in CONFIDENCES:
            errors.append("finding[%d] bad confidence: %r" % (i, f.get("confidence")))
        if f.get("panel") not in VALID_PANELS:
            errors.append("finding[%d] bad panel: %r" % (i, f.get("panel")))
        ev = f.get("evidence") or {}
        if ev.get("status") not in evidence_mod.EVIDENCE_STATUSES:
            errors.append("finding[%d] bad evidence.status: %r" % (i, ev.get("status")))
        loc = f.get("location") or {}
        if not loc.get("file") or loc.get("line_start") is None:
            warnings.append("finding[%d] missing location.file/line_start" % i)
        agent_sourced = not str(f.get("source", "")).startswith("tool:")
        if agent_sourced and f.get("panel") in ("security", "redteam") and f.get("severity") in ("CRITICAL", "HIGH"):
            if not f.get("cvss"):
                errors.append("finding[%d] %s %s missing cvss" % (i, f["panel"], f["severity"]))
            if not f.get("exploit_scenario"):
                errors.append("finding[%d] %s %s missing exploit_scenario" % (i, f["panel"], f["severity"]))
    id_counts = {}
    for f in report.get("findings", []):
        fid = f.get("id")
        if fid:
            id_counts[fid] = id_counts.get(fid, 0) + 1
    for fid, count in id_counts.items():
        if count > 1:
            errors.append("duplicate finding id: %s" % fid)
    return errors, warnings


def render_summary(report):
    """Render markdown summary of report with grades, stats, groups, and top findings."""
    s = report["summary"]
    lines = [
        "# panopticon — %s" % report["meta"]["target"],
        "",
        "**Grade:** %s  **Risk:** %s  **Gate:** %s" % (
            s["overall_grade"], s["risk_level"], s["gate"]),
        "",
        "**Findings:** %s" % ", ".join(
            "%s %d" % (k.upper(), v) for k, v in s["stats"].items() if v),
        "",
        "**Evidence:** %s" % ", ".join(
            "%s %d" % (k, v) for k, v in s["evidence_stats"].items() if v),
        "",
        "## Groups",
    ]
    for g in report["groups"]:
        pg = g["panel_grades"]
        grades = " / ".join("%s %s" % (p, pg[p]) for p in PANEL_ORDER)
        lines.append("- **%s** — %s" % (g["name"], grades))
    lines.append("")
    lines.append("## Top findings")
    for f in sorted(report["findings"], key=_issue_sort)[:10]:
        loc = f.get("location") or {}
        where = "%s:%s" % (loc.get("file", "?"), loc.get("line_start", "?"))
        chips = []
        c = f.get("citations") or {}
        for w in (c.get("cwe") or []):
            chips.append(w.get("id", ""))
        chips += (c.get("owasp") or [])
        if c.get("ssvc"):
            chips.append("SSVC:%s" % c["ssvc"].get("decision", ""))
        if c.get("epss"):
            chips.append("EPSS:%.2f" % max(e.get("score", 0.0) for e in c["epss"]))
        ev_status = (f.get("evidence") or {}).get("status", "unverified")
        suffix = (" — " + ", ".join(x for x in chips if x)) if chips else ""
        cor = " ⁂corroborated" if f.get("corroborated") else ""
        lines.append("- `[%s]` **%s** %s (%s) [%s·%s%s]%s" % (
            f["severity"], f.get("title", ""), where, f["confidence"], ev_status,
            f.get("panel", ""), cor, suffix))
    integ = (report.get("cross_panel") or {}).get("integration_findings") or []
    if integ:
        lines.append("")
        lines.append("## Cross-panel corroboration")
        for it in integ:
            loc = it.get("location") or {}
            lines.append("- `[%s]` %s:%s — %s (%s)" % (
                it.get("severity", ""), loc.get("file", "?"),
                loc.get("line_start", "?"), ", ".join(it.get("panels") or []),
                ", ".join(it.get("categories") or [])))
    return "\n".join(lines)


def write_report(report, out_path, max_bytes=800000):
    """Write report to JSON file, splitting into parts if size exceeds max_bytes."""
    blob = json.dumps(report, indent=2)
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    if len(blob.encode("utf-8")) <= max_bytes:
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(blob)
        return [out_path]
    findings = report["findings"]
    half = max(1, len(findings) // 2)
    stem, ext = os.path.splitext(out_path)
    part_path = "%s_part2%s" % (stem, ext)
    main_report = dict(report)
    main_report["meta"] = dict(report["meta"])
    main_report["meta"]["parts"] = [os.path.basename(part_path)]
    main_report["findings"] = findings[:half]
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(main_report, fh, indent=2)
    with open(part_path, "w", encoding="utf-8") as fh:
        json.dump({"findings": findings[half:]}, fh, indent=2)
    return [out_path, part_path]


def _derive_html_path(json_path):
    if json_path.lower().endswith(".json"):
        return json_path + ".html"
    return os.path.join(json_path, "report.html")


def main(argv=None):
    """Main entry point: load findings, enrich citations, build and validate report."""
    ap = argparse.ArgumentParser(description="panopticon synthesizer")
    ap.add_argument("--target", default="unknown")
    ap.add_argument("--groups", metavar="PATH")
    ap.add_argument("--security", choices=["standard", "redteam"], default=None,
                    help="Override security mode from groups.json")
    ap.add_argument("--fail-on", metavar="SEV", type=str.lower,
                    choices=["critical", "high", "medium", "low"])
    ap.add_argument("--severity", metavar="LEVEL", type=str.lower,
                    choices=["all", "medium", "high", "critical"], default="all",
                    help="Minimum severity to include in the report (all, medium, high, critical)")
    ap.add_argument("--changes", "-c", action="store_true",
                    help="Alias for a changes/diff review type")
    ap.add_argument("--out", default=None)
    ap.add_argument("--html-out", metavar="PATH", default=None,
                    help="Write HTML report to PATH")
    ap.add_argument("--compare", metavar="JSON", nargs=2, default=None,
                    help="Compare two JSON reports and emit HTML")
    ap.add_argument("--epss", action="store_true")
    ap.add_argument("--tools-dir", metavar="DIR")
    ap.add_argument("--tools-exclude", metavar="GLOB", action="append", default=None,
                    help="Drop tool findings whose location.file matches GLOB "
                         "(repeatable; e.g. 'tests/fixtures/*')")
    ap.add_argument("--emit-verify-queue", action="store_true",
                    help="Pass 1: write .panopticon/verify-queue.json and skip the "
                         "report when agentic findings need verification")
    ap.add_argument("--verdicts-dir", metavar="DIR", default=None,
                    help="Pass 2: ingest advisor verdict files from DIR")
    ap.add_argument("--gate-unverified", action="store_true",
                    help="Let corroborated/needs_more_info/unverified findings "
                         "drive grades and the gate")
    ap.add_argument("--max-verify", type=int, default=None, metavar="N",
                    help="Cap the verify queue at the top-priority N entries "
                         "(pass the same value to both passes)")
    ap.add_argument("files", nargs="*")
    args = ap.parse_args(argv)

    if args.compare:
        a_path, b_path = args.compare
        try:
            with open(a_path, encoding="utf-8") as fh:
                report_a = json.load(fh)
        except OSError as e:
            print("ERROR: cannot read %s: %s" % (a_path, e), file=sys.stderr)
            return 2
        except ValueError as e:
            print("ERROR: invalid JSON in %s: %s" % (a_path, e), file=sys.stderr)
            return 2
        try:
            with open(b_path, encoding="utf-8") as fh:
                report_b = json.load(fh)
        except OSError as e:
            print("ERROR: cannot read %s: %s" % (b_path, e), file=sys.stderr)
            return 2
        except ValueError as e:
            print("ERROR: invalid JSON in %s: %s" % (b_path, e), file=sys.stderr)
            return 2
        html_out = args.html_out or (_derive_html_path(args.out) if args.out else None)
        if not html_out:
            print("ERROR: --compare requires --html-out or --out", file=sys.stderr)
            return 2
        html_report.write_html(report_b, html_out, compare_report=report_a)
        print("Compare HTML: %s" % html_out)
        return 0

    groups_meta = []
    review_type = "changes" if args.changes else "repo"
    security_mode = args.security
    if args.groups and os.path.isfile(args.groups):
        try:
            with open(args.groups, encoding="utf-8") as fh:
                gj = json.load(fh)
            if isinstance(gj, dict):
                groups_meta = gj.get("groups", [])
                review_type = MODE_TO_REVIEW_TYPE.get(gj.get("mode"), review_type)
                if security_mode is None:
                    security_mode = gj.get("security_mode", "standard")
            else:
                print("synthesize: --groups is not a JSON object; ignoring", file=sys.stderr)
        except (OSError, ValueError) as e:  # tolerant by design: never abort a run
            print("synthesize: could not read --groups (%s); ignoring" % e, file=sys.stderr)
    if security_mode is None:
        security_mode = "standard"

    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out = args.out or os.path.join(".panopticon", "report-%s.json" % ts.replace(":", ""))

    if not args.tools_dir:
        default_tools = os.path.join(".panopticon", "tools")
        if os.path.isdir(default_tools) and os.listdir(default_tools):
            print("synthesize: %s appears un-ingested — pass --tools-dir %s to "
                  "include tool findings in this report"
                  % (default_tools, default_tools), file=sys.stderr)
    findings = load_findings(args.files)
    if args.tools_dir and os.path.isdir(args.tools_dir):
        for tf in ingest_tools.ingest_dir(args.tools_dir, None,
                                          exclude_globs=args.tools_exclude):
            findings.append(normalize_finding(tf))
    catalog = citations.load_cwe_catalog()
    citations.enrich_citations(findings, catalog, epss_enabled=args.epss,
                               cache_path=os.path.join(".panopticon", "epss-cache.json"))
    if args.severity and args.severity != "all":
        threshold = SEV_ORDER.index(args.severity.upper())
        findings = [f for f in findings if _sev_rank(f) <= threshold]

    if args.emit_verify_queue:
        import copy
        prepared, _ = prepare_findings(copy.deepcopy(findings))
        queue, cut = evidence_mod.build_verify_queue(prepared, args.max_verify)
        qpath = os.path.join(".panopticon", "verify-queue.json")
        if queue:
            evidence_mod.write_verify_queue(queue, cut, qpath)
            print("verify queue: %d entries (%d cut by --max-verify) -> %s"
                  % (len(queue), cut, qpath))
            return 0
        # Nothing to verify this run: a queue file left by a PREVIOUS run
        # (with agentic findings) would otherwise mislead step 7's re-run --
        # the orchestrator branches on the file's existence, so a stale one
        # would send it to the verify phase with stale/absent entries.
        if os.path.isfile(qpath):
            try:
                os.remove(qpath)
            except OSError as e:
                print("synthesize: could not remove stale %s: %s" % (qpath, e),
                      file=sys.stderr)
        print("verify queue empty; emitting final report", file=sys.stderr)

    verdicts = evidence_mod.load_verdicts(args.verdicts_dir)
    tool_policy_mode = derive_tool_policy_mode()
    report = build_report(findings, groups_meta, args.target, args.fail_on, ts,
                          review_type, security_mode, verdicts=verdicts,
                          gate_unverified=args.gate_unverified,
                          max_verify=args.max_verify,
                          verdicts_supplied=args.verdicts_dir is not None,
                          tool_policy_mode=tool_policy_mode)
    errors, warnings = validate_report(report)
    attach_schema_status(report, errors)
    for w in warnings:
        print("WARN: %s" % w, file=sys.stderr)
    for e in errors:
        print("SCHEMA: %s" % e, file=sys.stderr)

    paths = write_report(report, out)
    html_out = args.html_out
    if html_out is None and args.out:
        html_out = _derive_html_path(paths[0])
    if html_out:
        html_report.write_html(report, html_out)
        print("HTML artifact: %s" % html_out)
    print(render_summary(report))
    print("\nJSON artifact: %s" % ", ".join(paths))
    return 1 if report["summary"]["gate"] == "FAIL" else 0


if __name__ == "__main__":
    sys.exit(main())
