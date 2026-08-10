#!/usr/bin/env python3
"""Merge panopticon finding files into a validated CodeReviewReport with
grades and a CI gate verdict. Stdlib-only.
"""
import argparse
import fnmatch
import glob
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import scripts.citations as citations
try:
    from scripts._version import __version__
except ModuleNotFoundError:  # imported flat, with skill/scripts itself on sys.path
    from _version import __version__
from scripts.citations import load_cwe_catalog
import scripts.diff_map as diff_map
import scripts.evidence as evidence_mod
import scripts.group_runner as group_runner
import scripts.html_report as html_report
import scripts.ingest_tools as ingest_tools
from scripts.tools import EXECUTES_TARGET_BUILD

# Moved to evidence.py (also used by evidence.load_verdicts for advisor
# verdict files, which are just as likely to be fence-wrapped or prose-
# wrapped as panel/lens findings files). Delegation keeps this name importable
# as scripts.synthesize.load_json_tolerant for existing callers/tests.
load_json_tolerant = evidence_mod.load_json_tolerant
tool_rule_id = evidence_mod.tool_rule_id
finding_fingerprint = evidence_mod.finding_fingerprint

# One source for the per-group dispatch-plan filename glob (#681): synthesize
# reconciles findings against, and derives coverage from, every plan file the
# fan-out wrote. Both call sites join it against their own base dir.
DISPATCH_PLAN_GLOB = "dispatch-plan*.json"

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
#
# Only ingest_tools (tool output) and dedupe's real merge branches may set them.
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
_is_tool_sourced = evidence_mod.is_tool_sourced


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


HIGH_VALUE_PANELS = {"security", "redteam", "architecture", "database"}


def certify(overall_grade, gate_eligible, fail_on, panels_incomplete, tools_absent,
            integrity_ok=True):
    """Coverage-aware certification. Gate keys on high-value-panel completeness
    (+ requested-absent tools + artifact integrity); grade is holistic
    (provisional on ANY gap). Precedence FAIL > INCONCLUSIVE > PASS; OFF
    preserved. Tolerant: pure, never raises.
    """
    base_gate = gate_verdict(gate_eligible, fail_on)          # PASS / FAIL / OFF
    high_value_incomplete = set(panels_incomplete) & HIGH_VALUE_PANELS
    gate_relevant_gap = (bool(high_value_incomplete) or bool(tools_absent)
                         or not integrity_ok)
    any_incomplete = bool(panels_incomplete)

    if base_gate == "PASS" and gate_relevant_gap:
        gate = "INCONCLUSIVE"
    else:
        gate = base_gate                                      # FAIL/OFF/PASS unchanged

    if any_incomplete:
        cert_grade, provisional = None, overall_grade
    else:
        cert_grade, provisional = overall_grade, None

    coverage_certified = not (gate_relevant_gap or any_incomplete)

    note = None
    if any_incomplete and not gate_relevant_gap:
        tail = sorted(p for p in panels_incomplete if p not in HIGH_VALUE_PANELS)
        note = ("gate certified; grade provisional — low-value panel(s) incomplete: %s"
                % ", ".join(tail))

    return {"gate": gate, "overall_grade": cert_grade,
            "provisional_grade": provisional,
            "coverage_certified": coverage_certified, "coverage_note": note}


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
    r"^findings-(.+)-(?:%s)"
    r"(?:-panel_review|-lens_sweep-[A-Za-z0-9_]+)?\.json$" % "|".join(PANEL_ORDER))
def out_of_scope_findings(findings_paths, plan):
    """#441: count agent findings whose location.file falls outside the FILE
    LIST of the group their findings-file belongs to (per the dispatch plan).

    Reviewers are prompted to stay inside their assignment, but that fence is
    prompt-advisory -- this is the report-side disclosure. Only findings files
    whose name matches GROUP_RE and whose group has a plan entry are checked;
    tool findings and unplanned groups are out of this check's reach.
    Returns {"checked": N, "count": N, "examples": [...]} or None when no
    plan/group could be checked.
    """
    group_files = {}
    for e in plan or []:
        if isinstance(e, dict) and isinstance(e.get("files"), list):
            group_files.setdefault(e.get("group"), set()).update(
                str(f).replace("\\", "/") for f in e["files"])
    if not group_files:
        return None
    checked = count = 0
    examples = []
    for path in findings_paths or []:
        m = GROUP_RE.match(os.path.basename(str(path)))
        if not m or m.group(1) not in group_files:
            continue
        allowed = group_files[m.group(1)]
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            continue
        for f in (data.get("findings") or [] if isinstance(data, dict) else []):
            loc = (f.get("location") or {}) if isinstance(f, dict) else {}
            fpath = str(loc.get("file") or "").replace("\\", "/")
            while fpath.startswith("./"):
                fpath = fpath[2:]
            if not fpath:
                continue
            checked += 1
            if fpath not in allowed:
                count += 1
                if len(examples) < 10:
                    examples.append({"group": m.group(1), "file": fpath})
    return {"checked": checked, "count": count, "examples": examples}
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
        path = str(loc.get("file") or "").replace("\\", "/")
        while path.startswith("./"):
            path = path[2:]
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


def load_dispatch_plans(panopticon_dir=".panopticon"):
    """Load every per-group dispatch plan file as a list of per-file plan
    lists. Tolerant: unreadable/malformed plan files are skipped."""
    plans = []
    for path in sorted(glob.glob(os.path.join(panopticon_dir, DISPATCH_PLAN_GLOB))):
        try:
            with open(path, encoding="utf-8") as fh:
                plan = json.load(fh)
        except (OSError, ValueError):
            continue
        if isinstance(plan, list):
            plans.append(plan)
    return plans


def derive_tool_policy_mode(panopticon_dir=".panopticon", plans=None):
    """Derive the run's tool-policy posture from dispatch plan files.

    unknown: no usable plan file was found — posture undetermined (distinct
    from advisory, which is a plan we DID read that enforced nothing).
    enforced: every entry across every plan is enforced; mixed: some are;
    advisory: a plan exists but none are. Pass `plans` (per-file plan lists,
    as returned by load_dispatch_plans) to skip re-reading the files a caller
    already loaded.
    """
    if plans is None:
        plans = load_dispatch_plans(panopticon_dir)
    if not plans:
        return "unknown"
    flags = [bool(e.get("enforced")) for plan in plans
             for e in plan if isinstance(e, dict)]
    if flags and all(flags):
        return "enforced"
    if any(flags):
        return "mixed"
    return "advisory"


def duplicate_out_files(plan):
    """out_file values assigned to more than one reviewer entry in the merged
    plan (#936). A collision means two reviewers share a write target and one
    silently overwrites the other — a coverage risk that
    reconcile_findings_files' set-keyed view structurally cannot see."""
    if not isinstance(plan, list):
        return []
    seen, dupes = set(), set()
    for e in plan:
        if isinstance(e, dict) and isinstance(e.get("out_file"), str) and e.get("out_file"):
            of = os.path.normpath(e["out_file"])
            (dupes if of in seen else seen).add(of)
    return sorted(dupes)


_FINDINGS_NAME_RE = re.compile(
    r"^findings-(?P<rest>.+)-(?P<role>panel_review|lens_sweep)"
    r"(?:-(?P<lens>.+?))?\.json$")


def _expected_from_filename(basename):
    """(panel, role) declared by a reviewer findings filename, or None when the
    name is not a reviewer findings file or its panel token is unrecognizable.
    Panels are a fixed hyphen-free set, so the panel is the last token of the
    `{group}-{panel}` prefix even when the group name contains hyphens."""
    m = _FINDINGS_NAME_RE.match(basename)
    if not m:
        return None
    panel = m.group("rest").split("-")[-1]
    if panel not in VALID_PANELS:
        return None
    return panel, m.group("role")


def mislabeled_findings_files(paths):
    """Reviewer findings files whose CONTENT contradicts the panel/role their
    filename declares (#937) — a mis-targeted or overwritten write. Flags a
    file as soon as any finding carries a source_role or panel that clearly
    disagrees with the filename; absent fields are never second-guessed. This
    is the byte-identity follow-up SKILL.md step 9 names."""
    bad = []
    for p in paths or []:
        exp = _expected_from_filename(os.path.basename(p))
        if not exp:
            continue
        panel, role = exp
        try:
            with open(p, encoding="utf-8") as fh:
                data = load_json_tolerant(fh.read())
        except (OSError, ValueError):
            continue
        findings = (data or {}).get("findings") if isinstance(data, dict) else None
        if not isinstance(findings, list):
            continue
        for f in findings:
            if not isinstance(f, dict):
                continue
            sr, fp = f.get("source_role"), f.get("panel")
            if (sr and sr != role) or (fp and fp != panel):
                bad.append(p)
                break
    return sorted(set(bad))


def reconcile_findings_files(plan, ingested_paths):
    """(#146) Reconcile the findings files synthesize ingested against the
    dispatch plan's declared reviewer out_files. Returns (unexpected, missing)
    as sorted lists of the ORIGINAL path strings. Skipped (empty, empty) when
    no plan is present — an ordinary non-fan-out run, not tampering.
    """
    if not isinstance(plan, list) or not plan:
        return [], []
    # realpath, not abspath (#947 FIXME-1): macOS temp worktrees live under
    # /var/folders/... which is a SYMLINK to /private/var/... -- a cwd inside
    # the worktree yields /private/var paths while the plan recorded /var
    # ones, and abspath comparison flagged every file on a clean run.
    planned = {os.path.realpath(e["out_file"]): e["out_file"] for e in plan
               if isinstance(e, dict) and isinstance(e.get("out_file"), str)
               and e.get("out_file")}
    ingested = {os.path.realpath(p): p for p in ingested_paths or []}
    unexpected = sorted(ingested[a] for a in ingested if a not in planned)
    missing = sorted(planned[a] for a in planned if a not in ingested)
    return unexpected, missing


def _plan_hash(plan):
    """Canonical plan-content hash -- mirror of dispatch.plan_content_hash
    (#493 R2; a shared import is blocked by the two sys.path conventions,
    #742 -- keep the two in sync)."""
    return hashlib.sha256(
        json.dumps(plan, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def read_unenforced_ack(path=os.path.join(".panopticon", "unenforced-ack.json")):
    """Return the full ack dict when dispatch recorded --allow-unenforced, {} otherwise.

    The return value is truthy when acknowledged and falsy (empty dict) when not.
    Extra fields written by dispatch (e.g. ``write_guard_covers_bash``, ``note``)
    are included so callers can surface them in ``meta.integrity`` (#680).
    Unreadable/malformed => {} (tolerant)."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict) or not data.get("acknowledged"):
        return {}
    return data


def tools_ran_from_dispositions(dispositions):
    """Adapters that produced a parseable document (status ok or empty).

    A 'failed' adapter (0-byte / unparseable / no registered adapter) is
    excluded, so build_executing_tools can never name an adapter that ran
    empty. This is the repair of #450's residual weakness and the core of #456.
    """
    return {name for name, d in dispositions.items()
            if d.get("status") in ("ok", "empty")}


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


def load_diff_hunks(path):
    """Load the orchestrator's diff-hunks.json; {} if absent/malformed."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}

    raw = data.get("hunks")
    if not isinstance(raw, dict):
        raw = {}
    hunks = {}
    for p, rs in raw.items():
        if not isinstance(rs, list):
            continue
        cleaned = []
        for r in rs:
            if isinstance(r, (list, tuple)) and len(r) == 2 and isinstance(r[0], int) and isinstance(r[1], int):
                cleaned.append((r[0], r[1]))
        hunks[str(p)] = cleaned
    data["hunks"] = hunks
    return data


def classify_findings(findings, hunks, tolerance):
    """Stamp each finding with delta = {on_diff, hunk, distance}."""
    for f in findings:
        f["delta"] = diff_map.classify(f, hunks, tolerance)


def build_report(findings, groups_meta, target, fail_on, timestamp, review_type="repo",
                 security_mode="standard", verdicts=None, gate_unverified=False,
                 max_verify=None, verdicts_supplied=False, tool_policy_mode=None,
                 tools_ran=None, tool_dispositions=None, fan_out=None,
                 scout_requested=None, scout_profiles_seen=0, out_of_scope=None,
                 doc_policy=None, resume=None, integrity=None,
                 diff_hunks=None, diff_context=5, gate_scope="on-diff",
                 catalog=None, verdict_unloadable=None):
    """Build a CodeReviewReport under the two-axis severity x evidence model.

    Severity is never mutated here. Verdicts (from evidence.load_verdicts) are
    applied to queued findings; every finding gets an evidence object; grades
    and the gate are computed from gate-eligible findings only (all non-rejected
    when gate_unverified is set). `verdicts_supplied` records whether --verdicts-dir
    was passed at all (distinct from whether it yielded any verdicts) so the
    aggregate "no verdict" note still fires for an existing-but-empty dir.
    `tools_ran` is the set of adapter names that produced output this run;
    when omitted, `build_executing_tools` falls back to inferring from findings.
    """
    findings, integration_findings = prepare_for_queue(findings)
    if catalog is None:
        catalog = load_cwe_catalog()
    queue, cut = evidence_mod.build_verify_queue(findings, max_verify)
    # Identity must be read BEFORE any verdict is applied. For a SARIF-sourced
    # tool finding the adapters park the rule id in
    # provenance.confirmation_reasoning (tools/sarif_utils.tool_provenance sets
    # no tool_evidence), evidence.tool_rule_id falls back to it, and
    # finding_fingerprint uses it as the identity discriminator -- while
    # evidence.apply_verdict overwrites that same field with the advisor's
    # prose. Recomputing afterwards would export a hash of the reasoning text,
    # so the "stable cross-run identity" would change whenever an advisor
    # re-worded itself. Harmless for findings that are never verdicted
    # (including those cut by --max-verify): nothing between here and the
    # assignment site mutates an identity field on them.
    pre_verdict_fps = {id(f): finding_fingerprint(f) for f in findings}
    verdicts = verdicts or {}
    matched = {}
    matched_n = 0
    unanswered = 0
    for entry in queue:
        v = evidence_mod.match_verdict(entry, verdicts)
        if v is not None:
            evidence_mod.apply_verdict(entry["finding"], v)
            matched_n += 1
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
    # Verdict files that existed but could not be parsed/validated (#938). Their
    # findings are already counted as unanswered above (no verdict matched); the
    # count here records that a verdict was LOST to corruption, not that one was
    # never generated -- otherwise a malformed advisor return vanishes silently.
    verdict_unloadable = verdict_unloadable or []
    if verdict_unloadable:
        print("synthesize: %d verdict file(s) were un-loadable (corrupt) and "
              "their findings left unverified: %s"
              % (len(verdict_unloadable),
                 ", ".join(u.get("file", "?") for u in verdict_unloadable)),
              file=sys.stderr)
    # A run whose verdicts all failed to match now produces gate PASS / grade A
    # / risk LOW -- the safest-looking output there is -- because only verified
    # findings gate. Stderr is not what CI consumes, so the drop counts belong
    # in the artifact: supplied - matched - unknown is the number of verdicts
    # that named a queued finding but failed match_verdict's finding_id echo.
    verdict_stats = {
        "queued": len(queue),
        "cut": cut,
        "supplied": len(verdicts),
        "matched": matched_n,
        "unknown": len(unknown),
        # Verdict files present on disk but un-loadable (corrupt/invalid). A
        # non-zero count means verification evidence was lost, distinct from a
        # finding that never had a verdict generated (#938).
        "unloadable": len(verdict_unloadable),
        # Measured only when --verdicts-dir was passed at all. Emitting 0 for a
        # run with no verify phase would read as "nothing went unanswered",
        # which is the opposite of the truth; null means "not measured", the
        # same convention as tool_axis.rejection_rate.
        "unanswered": unanswered if verdicts_supplied else None,
    }
    # Re-validate citations after advisor merges (idempotent; preserves epss).
    citations.enrich_citations(findings, catalog, epss_enabled=False)
    for f in findings:
        f["evidence"] = evidence_mod.derive_evidence(f, matched.get(id(f)))
        # KNOWN DIVERGENCE from queue_id (unchanged behavior, recorded): on a
        # fingerprint collision the queue assigns `fp` and `fp-1`, but both
        # findings export the bare `fp` here -- so a colliding pair does not
        # round-trip from exported identity back to its queue entry. See the
        # matching note in evidence.build_verify_queue.
        f["fingerprint"] = pre_verdict_fps[id(f)]
        f.pop("citation_quality", None)

    tool_like = [f for f in findings
                 if evidence_mod.is_tool_sourced(f) or f.get("reinforced")]

    def _tool_count(status):
        return sum(1 for f in tool_like if f["evidence"]["status"] == status)

    confirmed = _tool_count("tool_confirmed")
    rejected_n = _tool_count("rejected")
    decided = confirmed + rejected_n
    tool_axis = {
        "queued": len(tool_like),
        "confirmed": confirmed,
        "rejected": rejected_n,
        "needs_more_info": _tool_count("needs_more_info"),
        "unanswered": _tool_count("tool_reported"),
        # Share of DECIDED tool claims an advisor refuted — the tool-side
        # mirror of the 27% agentic rejection rate. None when nothing was
        # decided, so an unverified run reports "unmeasured", not "0%".
        "rejection_rate": round(rejected_n / decided, 3) if decided else None,
    }

    rejected = [f for f in findings if f["evidence"]["status"] == "rejected"]
    active = [f for f in findings if f["evidence"]["status"] != "rejected"]
    delta_mode = bool(diff_hunks and diff_hunks.get("base"))
    if delta_mode:
        classify_findings(active, diff_hunks.get("hunks") or {}, diff_context)
    on_diff_active = [f for f in active if (f.get("delta") or {}).get("on_diff")]
    pre_existing_active = [f for f in active
                           if delta_mode and not (f.get("delta") or {}).get("on_diff")]
    gate_source = active
    if delta_mode and gate_scope == "on-diff":
        gate_source = on_diff_active
    gate_eligible = (gate_source if gate_unverified else
                     [f for f in gate_source
                      if f["evidence"]["status"] in evidence_mod.GATE_ELIGIBLE_DEFAULT])

    by_panel = {p: [] for p in VALID_PANELS}
    for f in gate_eligible:
        by_panel.get(f["panel"], by_panel["code"]).append(f)

    known_groups = {g["name"] for g in groups_meta}
    eligible_ids = {id(x) for x in gate_eligible}
    group_objs = []
    for g in groups_meta:
        gfiles = set(g["files"])
        gfind = [f for f in active
                 if (f.get("_group") == g["name"])
                 or (f.get("_group") not in known_groups
                     and (f.get("location") or {}).get("file") in gfiles)]
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
    tool_names = {evidence_mod.tool_name(f) for f in findings
                  if evidence_mod.is_tool_sourced(f)}
    planned = (fan_out or {}).get("planned") or {} if isinstance(fan_out, dict) else {}
    executed = (fan_out or {}).get("executed") or {} if isinstance(fan_out, dict) else {}
    panels_incomplete = {p for p, n in planned.items() if executed.get(p, 0) < n}
    produced = set(tools_ran if tools_ran is not None else tool_names)
    tools_absent = sorted(set(scout_requested or []) - produced)
    divergence = {
        "panels": {p: {"planned": planned[p], "executed": executed.get(p, 0)}
                   for p in sorted(panels_incomplete)},
        "tools": {t: "requested_absent" for t in tools_absent},
    }
    integrity = integrity if isinstance(integrity, dict) else None
    integrity = integrity or {"unexpected_findings_files": [],
                              "missing_planned_files": [],
                              "duplicate_out_files": [],
                              "mislabeled_findings_files": [],
                              "unenforced_acknowledged": False,
                              "plans_seen": 0}
    integrity_ok = not (integrity.get("unexpected_findings_files")
                        or integrity.get("duplicate_out_files")
                        or integrity.get("mislabeled_findings_files")
                        or integrity.get("content_mismatched_files"))
    cert = certify(overall, gate_eligible, fail_on, panels_incomplete, tools_absent,
                   integrity_ok=integrity_ok)
    return {
        "meta": {
            "target": target,
            "review_type": review_type,
            "timestamp": timestamp,
            "version": __version__,
            "security_mode": security_mode,
            "models_used": _collect_models_used(findings),
            "coverage": {
                "adapters": tool_dispositions or {},
                "tools_ran": (sorted(tools_ran) if tools_ran is not None
                              else sorted(tool_names)),
                "build_executing_tools": sorted(
                    (set(tools_ran) if tools_ran is not None else tool_names)
                    & EXECUTES_TARGET_BUILD),
                "tool_policy_mode": tool_policy_mode or "unknown",
                "tool_axis": tool_axis,
                # #471: with scout_requested, lets consumers tell "no scouts
                # ran" (0) apart from "scouts ran and requested no tools"
                # (N>0 with scout_requested []).
                "scout_profiles_seen": scout_profiles_seen,
                "scout_requested": sorted(scout_requested or []),
                "out_of_scope": out_of_scope,
                "doc_policy": doc_policy,
                "verdicts": verdict_stats,
                "fan_out": fan_out,
                "divergence": divergence,
                "resume": resume,
                "delta": ({"base": diff_hunks.get("base"),
                           "base_source": diff_hunks.get("base_source"),
                           "base_commit": diff_hunks.get("base_commit"),
                           "delta_start": diff_hunks.get("delta_start"),
                           "delta_end": diff_hunks.get("delta_end"),
                           "includes_uncommitted": diff_hunks.get("includes_uncommitted"),
                           "files_changed": diff_hunks.get("files_changed"),
                           "diff_context": diff_context,
                           "on_diff_total": len(on_diff_active),
                           "pre_existing_total": len(pre_existing_active)}
                          if delta_mode else None),
            },
            "integrity": integrity,
        },
        "summary": {
            "overall_grade": cert["overall_grade"],
            "provisional_grade": cert["provisional_grade"],
            "coverage_certified": cert["coverage_certified"],
            "coverage_note": cert["coverage_note"],
            "risk_level": risk_level(gate_eligible),
            "top_issues": [f.get("title", "") for f in
                           sorted(active, key=_issue_sort)[:3]],
            "gate": cert["gate"],
            "gate_policy": ("include_unverified" if gate_unverified
                            else "confirmed_only"),
            "stats": severity_stats(active),
            "evidence_stats": evidence_stats(findings),
            "delta": ({"on_diff": severity_stats(on_diff_active),
                       "pre_existing": severity_stats(pre_existing_active)}
                      if delta_mode else None),
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
        agent_sourced = not evidence_mod.is_tool_sourced(f)
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
            (s["overall_grade"] or ("%s (provisional)" % s.get("provisional_grade"))),
            s["risk_level"], s["gate"]),
        "",
        "**Findings:** %s" % ", ".join(
            "%s %d" % (k.upper(), v) for k, v in s["stats"].items() if v),
        "",
        "**Evidence:** %s" % ", ".join(
            "%s %d" % (k, v) for k, v in s["evidence_stats"].items() if v),
        "",
        "## Groups",
    ]
    if not s.get("coverage_certified", True):
        div = (report["meta"].get("coverage") or {}).get("divergence") or {}
        parts = []
        panels = div.get("panels") or {}
        if panels:
            parts.append("panels " + ", ".join(
                "%s %d/%d" % (p, v.get("executed", 0), v.get("planned", 0))
                for p, v in sorted(panels.items())))
        tools = div.get("tools") or {}
        if tools:
            parts.append("tools " + ", ".join(sorted(tools)))
        lines.insert(3, "**Coverage:** NOT CERTIFIED — %s" % ("; ".join(parts) or "incomplete"))
    rz = (report["meta"].get("coverage") or {}).get("resume") or {}
    _fo = rz.get("fan_out") or {}
    _vf = rz.get("verify") or {}
    _fo_pending = _fo.get("pending") or 0
    _vf_pending = _vf.get("pending") or 0
    if _fo_pending or _vf_pending:
        total_pending = _fo_pending + _vf_pending
        resume_line = "**Resume:** fan-out %d/%d done, verify %d/%d done (%d pending)" % (
            _fo.get("done", 0), _fo.get("total", 0),
            _vf.get("done", 0), _vf.get("total", 0),
            total_pending)
        insert_idx = 4 if not s.get("coverage_certified", True) else 3
        lines.insert(insert_idx, resume_line)
    integ = report["meta"].get("integrity") or {}
    bad = integ.get("unexpected_findings_files") or []
    if bad:
        lines.insert(3, "**Integrity:** UNEXPECTED FILES — %s (not declared by the "
                        "dispatch plan; run not certified)" % ", ".join(bad))
    dupes = integ.get("duplicate_out_files") or []
    if dupes:
        lines.insert(3, "**Integrity:** DUPLICATE out_file — %s (two reviewers share "
                        "a write target; one overwrote the other; run not certified)"
                        % ", ".join(dupes))
    mislabeled = integ.get("mislabeled_findings_files") or []
    if mislabeled:
        lines.insert(3, "**Integrity:** MISLABELED FILES — %s (content disagrees with "
                        "the filename's panel/role; possible mis-targeted write; run "
                        "not certified)" % ", ".join(mislabeled))
    delta = s.get("delta")
    if delta:
        on = delta.get("on_diff") or {}
        pre = delta.get("pre_existing") or {}
        delta_lines = [
            "**On-diff:** " + (", ".join(
                "%s %d" % (k.upper(), v) for k, v in on.items() if v) or "none"),
            "",
            "**Pre-existing (files you touched, not gating):** " + (", ".join(
                "%s %d" % (k.upper(), v) for k, v in pre.items() if v) or "none"),
        ]
        high_plus = (pre.get("critical", 0) or 0) + (pre.get("high", 0) or 0)
        if high_plus:
            delta_lines.append("")
            delta_lines.append(
                "⚠ %d pre-existing HIGH+ issue(s) in files you touched "
                "— strongly recommend fixing before merge "
                "(not gating this change)." % high_plus)
        delta_lines.append("")
        groups_idx = lines.index("## Groups")
        lines[groups_idx:groups_idx] = delta_lines
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


def _read_json_report(path):
    """Load a JSON report for --compare; None (with a printed error) on failure."""
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except OSError as e:
        print("ERROR: cannot read %s: %s" % (path, e), file=sys.stderr)
    except ValueError as e:
        print("ERROR: invalid JSON in %s: %s" % (path, e), file=sys.stderr)
    return None


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
    ap.add_argument("--doc-paths", metavar="GLOB", action="append", default=None,
                    help="Doc-tree globs for the #487 severity policy "
                         "(default: docs/*, specs/*, plans/* trees); "
                         "standard mode soft-downgrades non-secret code "
                         "findings under them to INFO, disclosed in meta")
    ap.add_argument("--include-fixtures", action="store_true",
                    help="Keep tool findings located under test-fixture corpora "
                         "(testdata/, __fixtures__/, tests/fixtures/). Default "
                         "prunes them for parity with the standard-mode agentic "
                         "review prune (#434); pass this for redteam self-scans.")
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
    ap.add_argument("--diff-hunks", metavar="PATH", default=None,
                    help="Path to the orchestrator's diff-hunks.json (#449); "
                         "stamps each finding with finding.delta")
    ap.add_argument("--diff-context", type=int, default=5, metavar="N",
                    help="Lines of tolerance for on-diff classification (default 5)")
    ap.add_argument("--gate-scope", choices=["on-diff", "all"], default="on-diff",
                    help="Scope the gate/grade to on-diff findings, or all (default on-diff)")
    ap.add_argument("files", nargs="*")
    args = ap.parse_args(argv)

    if args.compare:
        a_path, b_path = args.compare
        report_a = _read_json_report(a_path)
        if report_a is None:
            return 2
        report_b = _read_json_report(b_path)
        if report_b is None:
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
    # Default to the discovery output so the report carries group definitions:
    # groups[].files drives the HTML heatmap and grouped findings, and an empty
    # groups[] is why those fell back to path segments. An explicit --groups
    # still wins; auto-discovery only fills the common case where the
    # orchestrator's synthesize call omitted the flag.
    groups_path = args.groups
    if groups_path is None:
        default_groups = os.path.join(".panopticon", "groups.json")
        if os.path.isfile(default_groups):
            groups_path = default_groups
    if groups_path and os.path.isfile(groups_path):
        try:
            with open(groups_path, encoding="utf-8") as fh:
                gj = json.load(fh)
            if isinstance(gj, dict):
                groups_meta = gj.get("groups", [])
                # An explicit --changes wins: a discovered groups.json mode must
                # not flip an explicitly-requested changes review back to repo.
                if not args.changes:
                    review_type = MODE_TO_REVIEW_TYPE.get(gj.get("mode"), review_type)
                if security_mode is None:
                    security_mode = gj.get("security_mode", "standard")
            else:
                print("synthesize: %s is not a JSON object; ignoring" % groups_path,
                      file=sys.stderr)
        except (OSError, ValueError) as e:  # tolerant by design: never abort a run
            print("synthesize: could not read %s (%s); ignoring" % (groups_path, e),
                  file=sys.stderr)
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
    tool_dispositions = {}
    # None when --tools-dir wasn't supplied: build_report treats None as
    # "not measured -> infer build_executing_tools from findings"; an empty set
    # would ASSERT "no build-executing tool ran" from an absence of evidence
    # (the inversion #450 was about).
    tools_ran = None
    if args.tools_dir and os.path.isdir(args.tools_dir):
        tool_findings, tool_dispositions = ingest_tools.ingest_dir_detailed(
            args.tools_dir, None, exclude_globs=args.tools_exclude,
            include_fixtures=args.include_fixtures)
        for tf in tool_findings:
            findings.append(normalize_finding(tf))
        # A "failed" disposition (empty / unparseable / no-adapter) is excluded,
        # so build_executing_tools can no longer name an adapter that ran empty.
        tools_ran = tools_ran_from_dispositions(tool_dispositions)
    catalog = citations.load_cwe_catalog()
    citations.enrich_citations(findings, catalog, epss_enabled=args.epss,
                               cache_path=os.path.join(".panopticon", "epss-cache.json"))
    doc_policy = apply_doc_severity_policy(findings, security_mode,
                                           doc_globs=args.doc_paths)
    if doc_policy and doc_policy["downgraded"]:
        print("synthesize: %d code finding(s) under doc trees soft-downgraded "
              "to INFO (#487; secrets exempt, redteam bypasses) -- see "
              "meta.coverage.doc_policy" % doc_policy["downgraded"],
              file=sys.stderr)
    if args.severity and args.severity != "all":
        threshold = SEV_ORDER.index(args.severity.upper())
        findings = [f for f in findings if _sev_rank(f) <= threshold]

    if args.emit_verify_queue:
        import copy
        prepared, _ = prepare_for_queue(copy.deepcopy(findings))
        queue, cut = evidence_mod.build_verify_queue(prepared, args.max_verify)
        qpath = os.path.join(".panopticon", "verify-queue.json")
        if queue:
            evidence_mod.write_verify_queue(queue, cut, qpath)
            print("verify queue: %d entries (%d cut by --max-verify) -> %s"
                  % (len(queue), cut, qpath))
            return 0
        # Nothing to verify this run. Post-P2 EVERY finding queues -- tool
        # findings included -- so an empty queue means this run produced no
        # findings at all, not "only findings that never queued". A queue file
        # left by a PREVIOUS run would otherwise mislead step 7's re-run: the
        # orchestrator branches on the file's existence, so a stale one would
        # send it to the verify phase with stale/absent entries.
        if os.path.isfile(qpath):
            try:
                os.remove(qpath)
            except OSError as e:
                print("synthesize: could not remove stale %s: %s" % (qpath, e),
                      file=sys.stderr)
        print("verify queue empty; emitting final report", file=sys.stderr)

    verdicts, verdict_unloadable = evidence_mod.load_verdicts_detailed(args.verdicts_dir)
    # Union of every per-group dispatch-plan-*.json on disk -- loaded ONCE and
    # shared with derive_tool_policy_mode, so the two cannot drift apart again
    # (#146/C1). The real fan-out workflow writes one plan file PER GROUP
    # (dispatch-plan-<group>.json); a lone dispatch-plan.json is just the
    # one-group case of that same naming convention, not a different shape.
    # plans_seen distinguishes "no plan found -> reconcile skipped" from
    # "reconciled, nothing wrong" -- an empty unexpected/missing pair means
    # nothing on its own (see meta.integrity below).
    _plan_lists = load_dispatch_plans()
    plans_seen = len(_plan_lists)
    _plan = [e for plan in _plan_lists for e in plan]
    out_of_scope = out_of_scope_findings(args.files, _plan)
    if out_of_scope and out_of_scope["count"]:
        print("synthesize: %d finding(s) cite files OUTSIDE their group's "
              "assigned file list (#441) -- reviewers left their lane; see "
              "meta.coverage.out_of_scope" % out_of_scope["count"],
              file=sys.stderr)
    tool_policy_mode = derive_tool_policy_mode(plans=_plan_lists)
    fan_out = group_runner.fan_out_coverage(_plan) if _plan else None
    _queue = None
    queue_path = os.path.join(".panopticon", "verify-queue.json")
    if os.path.isfile(queue_path):
        try:
            with open(queue_path, encoding="utf-8") as fh:
                loaded_q = json.load(fh)
            if isinstance(loaded_q, dict):
                _queue = loaded_q
        except (OSError, ValueError):  # tolerant by design
            pass
    resume = group_runner.resume_stats(_plan, _queue, args.verdicts_dir,
                                       _verdicts=verdicts)
    unexpected, missing = reconcile_findings_files(_plan, args.files)
    _ack = read_unenforced_ack()
    # #493 R2: an ack with no run binding over-reports risk forever -- a
    # stale ack from an earlier --allow-unenforced run would mark a fully
    # enforced run acknowledged. The ack now carries plan_sha256 (canonical
    # hash of the plan content it acknowledged); treat a non-matching ack as
    # STALE: report false + a loud note. A legacy ack without the field stays
    # trusted (pre-#493 artifacts).
    ack_stale = False
    if _ack and _ack.get("plan_sha256") is not None and _plan_lists:
        _hashes = {_plan_hash(pl) for pl in _plan_lists}
        if _ack["plan_sha256"] not in _hashes:
            ack_stale = True
            print("synthesize: unenforced-ack.json does not hash-match any "
                  "on-disk dispatch plan -- STALE ack from a previous run; "
                  "reporting unenforced_acknowledged: false", file=sys.stderr)
    # #493 R4: after-the-fact content check -- when the orchestrator recorded
    # out-file hashes at fan-out end, verify the ingested bytes still match.
    content_checked, content_mismatched = group_runner.verify_out_file_hashes(args.files)
    if content_mismatched:
        print("synthesize: %d findings file(s) changed AFTER the fan-out "
              "snapshot (content substitution?): %s"
              % (len(content_mismatched), ", ".join(content_mismatched)),
              file=sys.stderr)
    integrity = {"unexpected_findings_files": unexpected,
                 "missing_planned_files": missing,
                 "duplicate_out_files": duplicate_out_files(_plan),
                 "mislabeled_findings_files": mislabeled_findings_files(args.files),
                 "unenforced_acknowledged": bool(_ack) and not ack_stale,
                 "ack_stale": ack_stale,
                 "content_hashes_checked": content_checked,
                 "content_mismatched_files": content_mismatched,
                 "plans_seen": plans_seen}
    if _ack:
        # Surface the Bash-coverage disclosure fields written by dispatch so
        # they appear in meta.integrity in the final report (#680).
        # Default to False so consumers never see None for this field.
        integrity["write_guard_covers_bash"] = _ack.get("write_guard_covers_bash", False)
    scout_requested = set()
    scout_profiles_seen = 0
    for sp in glob.glob(os.path.join(".panopticon", "scout-*.json")):
        try:
            with open(sp, encoding="utf-8") as fh:
                sd = json.load(fh)
        except (OSError, ValueError):  # tolerant by design: never abort a run
            continue
        if not isinstance(sd, dict):
            continue
        scout_profiles_seen += 1
        tools = sd.get("tools")
        if isinstance(tools, list):
            scout_requested.update(t for t in tools if isinstance(t, str))
    if scout_profiles_seen and not scout_requested:
        # #471: a scout can return tools:[] -- a silent decline of the tool
        # layer. Disclose it; the artifact records scout_profiles_seen so
        # "no scouts ran" and "scouts ran, requested nothing" read apart.
        print("synthesize: %d scout profile(s) requested NO tools (tools:[]) "
              "-- the tool layer ran on default triggers only, not scout "
              "guidance" % scout_profiles_seen, file=sys.stderr)

    diff_hunks = load_diff_hunks(args.diff_hunks) if args.diff_hunks else None
    if args.diff_hunks and not args.fail_on:
        # #957: a delta review is gate-first by intent, but the gate only arms
        # when --fail-on is passed. Without this notice a forgotten flag
        # yields a green-looking report whose gate silently reads OFF.
        print("synthesize: DELTA REVIEW WITH Gate: OFF -- no --fail-on was "
              "passed, so nothing can gate this change; pass --fail-on "
              "{critical,high,medium,low} to arm the gate", file=sys.stderr)

    report = build_report(findings, groups_meta, args.target, args.fail_on, ts,
                          review_type, security_mode, verdicts=verdicts,
                          gate_unverified=args.gate_unverified,
                          max_verify=args.max_verify,
                          verdicts_supplied=args.verdicts_dir is not None,
                          tool_policy_mode=tool_policy_mode,
                          tools_ran=tools_ran,
                          tool_dispositions=tool_dispositions,
                          fan_out=fan_out,
                          scout_requested=sorted(scout_requested),
                          scout_profiles_seen=scout_profiles_seen,
                          out_of_scope=out_of_scope,
                          doc_policy=doc_policy,
                          resume=resume,
                          integrity=integrity,
                          diff_hunks=diff_hunks,
                          diff_context=args.diff_context,
                          gate_scope=args.gate_scope,
                          catalog=catalog,
                          verdict_unloadable=verdict_unloadable)
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
    gate = report["summary"]["gate"]
    return 1 if gate == "FAIL" else 2 if gate == "INCONCLUSIVE" else 0


if __name__ == "__main__":
    sys.exit(main())
