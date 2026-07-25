#!/usr/bin/env python3
"""Merge panopticon finding files into a validated CodeReviewReport with
grades and a CI gate verdict. Stdlib-only.
"""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import citations
import ingest_tools

SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
CONFIDENCES = {"CERTAIN", "LIKELY", "POSSIBLE", "NOTE"}
VERDICT_TO_CONFIDENCE = {"CONFIRMED": "CERTAIN", "PLAUSIBLE": "LIKELY"}
MODE_TO_REVIEW_TYPE = {
    "repo": "repo", "file": "file", "directory": "directory",
    "group": "group", "files": "changes",
}


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
    if f.get("panel") not in ("code", "test", "security"):
        f["panel"] = "code"
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
    if not f.get("category"):
        f["category"] = "general"
    return f


def load_findings(paths):
    """Load and normalize findings from JSON files."""
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


def _norm_line(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return v


def dedupe(findings):
    """Cluster findings by (file, line). An exactly-two cluster with one tool- and
    one agent-sourced finding is treated as the same issue seen twice (even across
    categories) -> collapse to one reinforced survivor. Larger clusters keep one
    survivor per category — the most severe — never merging across categories (so
    distinct issues at a busy line are not silently lost); a category corroborated
    by BOTH a tool and an agent within such a cluster is still reinforced in place.
    Same file+line+category findings are intentionally deduped to the most severe.
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
            best["reinforced"] = True
            best["confidence"] = "CERTAIN"
            if "citations" not in best and tool_srcd[0].get("citations"):
                best["citations"] = tool_srcd[0]["citations"]
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
                best = min(members, key=lambda f: (_sev_rank(f), _conf_rank(f)))
                if (any(_is_tool_sourced(m) for m in members)
                        and any(not _is_tool_sourced(m) for m in members)):
                    best["reinforced"] = True
                    best["confidence"] = "CERTAIN"
                    if "citations" not in best:
                        for m in members:
                            if _is_tool_sourced(m) and m.get("citations"):
                                best["citations"] = m["citations"]
                                break
                result.append(best)
    return result + passthrough


# Cross-panel corroboration groups findings from DIFFERENT panels at a nearby
# locus. Anchor-bounded so a cluster never spans more than this many lines (no
# transitive chaining); 2 catches adjacent-line citations (e.g. a function def
# vs the vulnerable call inside it) while staying tight against false joins.
CORROBORATION_LINE_WINDOW = 2

# ascending confidence ranks (weakest -> strongest) for a monotonic raise
_CONF_ASC = ["NOTE", "POSSIBLE", "LIKELY", "CERTAIN"]


def _bump_confidence(conf):
    """Raise a confidence one rank (capped at CERTAIN); never lowers it."""
    try:
        idx = _CONF_ASC.index(str(conf).upper())
    except ValueError:
        idx = 0
    return _CONF_ASC[min(idx + 1, len(_CONF_ASC) - 1)]


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
    finding is annotated in place (`corroborated`/`corroborated_by`, confidence
    bumped one rank) and a summary entry is returned for cross_panel.
    integration_findings. Requiring >=2 distinct panels is the guard against
    false corroboration: two same-panel findings, or findings at different files
    or beyond the line window, do NOT corroborate.
    """
    candidates = []
    for f in findings:
        loc = f.get("location") or {}
        fkey = loc.get("file")
        line = _norm_line(loc.get("line_start"))
        if fkey and isinstance(line, int):
            candidates.append((fkey, line, f))
    candidates.sort(key=lambda t: (t[0], t[1]))

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
        if len(panels) >= 2:
            for m in members:
                m["corroborated"] = True
                m["corroborated_by"] = list(panels)
                m["confidence"] = _bump_confidence(m.get("confidence"))
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


ID_RE = re.compile(r"^[A-Z]{2,4}-\d{3,}$")
GROUP_RE = re.compile(r"^findings-(.+)-(?:code|test|security)\.json$")
_GRADE_ORDER = ["A", "B", "C", "D", "F"]


def _worst_grade(grades):
    present = [g for g in grades if g in _GRADE_ORDER]
    return max(present, key=_GRADE_ORDER.index) if present else "A"


def build_report(findings, groups_meta, target, fail_on, timestamp, review_type="repo"):
    """Build complete CodeReviewReport with deduplication, grading, and CI gate verdict."""
    findings = dedupe(findings)
    by_panel = {"code": [], "test": [], "security": []}
    for f in findings:
        by_panel.get(f["panel"], by_panel["code"]).append(f)

    known_groups = {g["name"] for g in groups_meta}
    group_objs = []
    for g in groups_meta:
        gfiles = set(g["files"])
        # Attribute a finding to this group if its _group tag matches by name, or
        # (when _group is absent OR names a group that isn't in this run's metadata)
        # its file belongs to the group. The latter fallback keeps a finding from
        # vanishing from per-group grades just because its _group token — derived
        # from the finding filename — doesn't line up with a groups_meta name.
        gfind = [f for f in findings
                 if (f.get("_group") == g["name"])
                 or (f.get("_group") not in known_groups
                     and (f.get("location") or {}).get("file") in gfiles)]
        gp = {p: [x for x in gfind if x["panel"] == p] for p in by_panel}
        group_objs.append({
            "name": g["name"],
            "files": g["files"],
            "panel_grades": {p: grade(gp[p]) for p in by_panel},
            "panel_summaries": {},
            "key_findings": [f.get("title", "") for f in gfind
                             if f["severity"] in ("CRITICAL", "HIGH")][:5],
        })

    overall = _worst_grade([grade(by_panel[p]) for p in by_panel])
    stats = severity_stats(findings)
    # Cross-panel corroboration runs AFTER dedupe on the surviving findings: it
    # annotates them in place and yields the integration summary. It does not
    # touch severity, so grade/gate/stats above are unaffected.
    integration_findings = cross_panel_corroboration(findings)
    for f in findings:
        f.pop("_group", None)
    return {
        "meta": {
            "target": target,
            "review_type": review_type,
            "timestamp": timestamp,
            "version": "2.3.0",
        },
        "summary": {
            "overall_grade": overall,
            "risk_level": risk_level(findings),
            "top_issues": [f.get("title", "") for f in
                           sorted(findings, key=_sev_rank)[:3]],
            "effort_to_remediate": "MEDIUM",
            "gate": gate_verdict(findings, fail_on),
            "stats": stats,
        },
        "groups": group_objs,
        "findings": findings,
        "cross_panel": {"integration_findings": integration_findings},
        "recommendations": {"immediate": [], "short_term": [], "long_term": []},
    }


def validate_report(report):
    """Validate report structure and content, returning error and warning lists."""
    errors, warnings = [], []
    for key in ("meta", "summary", "groups", "findings", "cross_panel", "recommendations"):
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
        if f.get("panel") not in ("code", "test", "security"):
            errors.append("finding[%d] bad panel: %r" % (i, f.get("panel")))
        loc = f.get("location") or {}
        if not loc.get("file") or loc.get("line_start") is None:
            warnings.append("finding[%d] missing location.file/line_start" % i)
        agent_sourced = not str(f.get("source", "")).startswith("tool:")
        if agent_sourced and f.get("panel") == "security" and f.get("severity") in ("CRITICAL", "HIGH"):
            if not f.get("cvss"):
                errors.append("finding[%d] security %s missing cvss" % (i, f["severity"]))
            if not f.get("exploit_scenario"):
                errors.append("finding[%d] security %s missing exploit_scenario" % (i, f["severity"]))
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
        "## Groups",
    ]
    for g in report["groups"]:
        pg = g["panel_grades"]
        lines.append("- **%s** — code %s / test %s / security %s" % (
            g["name"], pg["code"], pg["test"], pg["security"]))
    lines.append("")
    lines.append("## Top findings")
    for f in sorted(report["findings"], key=_sev_rank)[:10]:
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
        prov = "reinforced" if f.get("reinforced") else (
            "tool" if str(f.get("source", "")).startswith("tool:") else "agent")
        suffix = (" — " + ", ".join(x for x in chips if x)) if chips else ""
        cor = " ⁂corroborated" if f.get("corroborated") else ""
        lines.append("- `[%s]` **%s** %s (%s) [%s·%s%s]%s" % (
            f["severity"], f.get("title", ""), where, f["confidence"], prov,
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


def main(argv=None):
    """Main entry point: load findings, enrich citations, build and validate report."""
    ap = argparse.ArgumentParser(description="panopticon synthesizer")
    ap.add_argument("--target", default="unknown")
    ap.add_argument("--groups", metavar="PATH")
    ap.add_argument("--fail-on", metavar="SEV", type=str.lower,
                    choices=["critical", "high", "medium", "low"])
    ap.add_argument("--out", default=None)
    ap.add_argument("--epss", action="store_true")
    ap.add_argument("--tools-dir", metavar="DIR")
    ap.add_argument("files", nargs="*")
    args = ap.parse_args(argv)

    groups_meta = []
    review_type = "repo"
    if args.groups and os.path.isfile(args.groups):
        try:
            with open(args.groups, encoding="utf-8") as fh:
                gj = json.load(fh)
            if isinstance(gj, dict):
                groups_meta = gj.get("groups", [])
                review_type = MODE_TO_REVIEW_TYPE.get(gj.get("mode"), "repo")
            else:
                print("synthesize: --groups is not a JSON object; ignoring", file=sys.stderr)
        except (OSError, ValueError) as e:  # tolerant by design: never abort a run
            print("synthesize: could not read --groups (%s); ignoring" % e, file=sys.stderr)

    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out = args.out or os.path.join(".panopticon", "report-%s.json" % ts.replace(":", ""))

    findings = load_findings(args.files)
    if args.tools_dir and os.path.isdir(args.tools_dir):
        for tf in ingest_tools.ingest_dir(args.tools_dir, None):
            findings.append(normalize_finding(tf))
    catalog = citations.load_cwe_catalog()
    citations.enrich_citations(findings, catalog, epss_enabled=args.epss,
                               cache_path=os.path.join(".panopticon", "epss-cache.json"))
    report = build_report(findings, groups_meta, args.target, args.fail_on, ts, review_type)
    errors, warnings = validate_report(report)
    for w in warnings:
        print("WARN: %s" % w, file=sys.stderr)
    for e in errors:
        print("SCHEMA: %s" % e, file=sys.stderr)

    paths = write_report(report, out)
    print(render_summary(report))
    print("\nJSON artifact: %s" % ", ".join(paths))
    return 1 if report["summary"]["gate"] == "FAIL" else 0


if __name__ == "__main__":
    sys.exit(main())
