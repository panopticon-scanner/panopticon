"""Terminal summary rendering and report writing."""
import json
import os
import sys
import uuid

import scripts.redact as redact
from . import findings as findings_mod
from . import grading as grading_mod


def _grade_text(summary):
    """The grade as displayed: the letter, a provisional letter, or n/a.

    Three-way because the grade now derives from health, which is None when no
    reviewed file was readable. "None (provisional)" -- what the old two-way
    format produced for that case -- reads as a grade rather than as the absence
    of one.
    """
    if summary.get("overall_grade"):
        return summary["overall_grade"]
    if summary.get("provisional_grade"):
        return "%s (provisional)" % summary["provisional_grade"]
    return "n/a (no reviewed lines of code to grade)"

def _render_severity_block(stats, roles, gate_eligible_stats=None):
    """The severity distribution with the gate's reach marked on it.

    A bare distribution does not say which levels can actually fail a build --
    that depends entirely on --fail-on, which lives elsewhere in the report. So
    each level is annotated with its gate role, and the threshold is named.

    Counts stay the ACTIVE population (unchanged, and what `stats` reports); the
    ROLES come from the gate-eligible set. Where a level is in play, has active
    findings, but none of them confirmed, both facts are shown -- that is a level
    that looks alarming and cannot gate, and hiding either half misleads.
    """
    roles = roles or {}
    contributing = set(roles.get("contributing") or [])
    in_play = set(roles.get("in_play") or [])
    fail_on = roles.get("fail_on")
    head = ("**Findings** (`--fail-on %s`)" % fail_on) if fail_on else "**Findings**"
    lines = [head, ""]
    for sev in findings_mod.SEV_ORDER:
        count = stats.get(sev.lower(), 0)
        label = "%s: %d" % (sev, count)
        if sev in contributing:
            lines.append("- **%s** \u2014 %s" % (label, grading_mod._GATE_ROLE_NOTE["contributing"]))
        elif sev in in_play:
            note = ("in play, none found" if not count
                    else grading_mod._GATE_ROLE_NOTE["in_play"])
            lines.append("- **%s** \u2014 %s" % (label, note))
        else:
            lines.append("- %s" % label)
    return lines

def _health_headline(health):
    """The health index as a headline field, or None when unavailable.

    #calibration: promoted onto the top line beside Grade/Risk/Gate. The letter
    grade is a worst-severity rollup, so it saturates -- across six calibration
    targets every one graded D or F off the same severity ceiling, while health
    ranged 35.68 to 70.45. The grade answers "does this gate?"; health answers
    "how much of this codebase is clean?", and only the second told them apart.

    Rendered "N / 100" rather than bare, because the scale is the whole point:
    the predecessor ratio was unbounded, so a reader had no way to know whether
    1.75 was good. Deliberately unbanded even so -- six targets, none of them a
    healthy control, is not a sample to draw healthy/fair/poor thresholds from.
    Health never touches the gate (#1057); this is presentation only.
    """
    if not isinstance(health, dict) or health.get("score") is None:
        return None
    return "**Health:** %s / 100" % health["score"]

def _render_health(health):
    """One-line health summary (#1146): score plus the clean-LoC and
    weighted-defect it reconciles from. n/a only when nothing was reviewed."""
    if not isinstance(health, dict):
        return None
    loc, wd, score = health.get("total_loc", 0), health.get("weighted_defect", 0), health.get("score")
    if score is None:
        # Both inputs zero: no reviewed file was readable. Distinct from a CLEAN
        # repo, which now scores 100 rather than falling into this branch.
        return "**Health:** n/a (no reviewed lines of code to measure against)"
    # The detail line carries the inputs AND the good direction: the headline
    # field above is just the number, and a bare number does not say which way
    # is better. Weights are stated so the footprint can be checked, not trusted.
    return ("**Health:** %s / 100 \u2014 %s clean LoC against %s weighted "
            "defect; HIGHER IS BETTER, 100 = no gate-eligible weighted defect "
            "(weights: CRITICAL x125, HIGH x25, MEDIUM x5, LOW x1, INFO x0, "
            "each x lines spanned). Gate-eligible findings only; never affects "
            "the gate." % (score, "{:,}".format(loc), "{:,}".format(wd)))

def render_summary(report):
    """Render markdown summary of report with grades, stats, groups, and top findings."""
    s = report["summary"]
    health_line = _render_health(s.get("health"))
    lines = [
        "# panopticon — %s" % report["meta"]["target"],
        "",
        "**Grade:** %s  **Risk:** %s  **Gate:** %s%s" % (
            _grade_text(s),
            s["risk_level"], s["gate"],
            ("  " + _health_headline(s.get("health"))) if _health_headline(s.get("health")) else ""),
        "",
    ] + _render_severity_block(s.get("stats") or {}, s.get("gate_severities")) + [
        "",
        "**Evidence:** %s" % ", ".join(
            "%s %d" % (k, v) for k, v in s["evidence_stats"].items() if v),
        "",
    ] + ([health_line, ""] if health_line else []) + [
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
        lines.insert(3, "**Integrity:** MISLABELED FILES — %s (the `_panopticon` cell "
                        "stamp disagrees with the filename; possible mis-targeted "
                        "write; run not certified)" % ", ".join(mislabeled))
    xdom = integ.get("cross_domain_findings") or []
    if xdom:
        # Deliberately not an integrity failure and deliberately not gating:
        # a reviewer filing outside its lane is a fact about the review, not
        # about whether the artifacts on disk can be trusted (#calibration-4).
        by = {}
        for r in xdom:
            if isinstance(r, dict):
                by.setdefault((r.get("cell_domain"), r.get("finding_domain")), 0)
                by[(r.get("cell_domain"), r.get("finding_domain"))] += 1
        pairs = ", ".join("%s→%s ×%d" % (a, b, n) for (a, b), n in sorted(by.items()))
        lines.insert(3, "**Note:** %d cross-domain finding(s) — %s. Reviewers filed "
                        "outside their cell's domain; often a catalog gap (X0X). "
                        "Does NOT affect certification." % (len(xdom), pairs))
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
        grades = " / ".join("%s %s" % (p, pg[p]) for p in findings_mod.PANEL_ORDER)
        lines.append("- **%s** — %s" % (g["name"], grades))
    lines.append("")
    lines.append("## Top findings")
    for f in sorted(report["findings"], key=findings_mod._issue_sort)[:10]:
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

def redact_report_secrets(report):
    """#run7 SEC-B2C: mask unambiguous secret formats (GitHub/OpenAI/AWS/Slack/
    Google tokens, PEM private keys) in every finding and discarded-claim body
    BEFORE the report reaches any shareable artifact -- report.json, the split
    parts, report.json.html, and the X0X candidates all read from this one dict.

    Reviewers are instructed to write [REDACTED], but a credential one of them
    quoted-but-didn't-redact would otherwise flow verbatim into the pipeline's
    final, shareable output surface. Defense-in-depth backstop layered on the
    prompt-level instruction; single-sourced with the driver's tool-output
    redaction via scripts.redact so the two can never drift. Mutates `report`
    in place and returns it. The anchored patterns mask well-formed secrets, not
    prose that merely mentions a token format, so finding text is preserved."""
    report["findings"] = [redact.redact_tree(f)
                          for f in report.get("findings") or []]
    if report.get("discarded_claims"):
        report["discarded_claims"] = [
            redact.redact_tree(f) for f in report["discarded_claims"]]
    return report

def write_report(report, out_path, max_bytes=800000):
    """Write report to JSON file, splitting into parts if size exceeds max_bytes.
    Writes all files atomically using staging temp files (#1124).
    """
    out_dir = os.path.dirname(os.path.abspath(out_path)) or "."
    os.makedirs(out_dir, exist_ok=True)
    stem, ext = os.path.splitext(out_path)

    # #15: discarded_claims carries every rejected claim's full advisor prose and
    # grows with the REJECTED set — precisely when verification works well. Left
    # inline it blew base_bytes past max_bytes and floored chunk_limit to 1000, so
    # every finding became its own part (417 files on run-6). When the report won't
    # fit one file, write discarded to a sibling artifact and keep a pointer+count.
    discarded_sibling = None
    if len(json.dumps(report, indent=2).encode("utf-8")) > max_bytes and report.get("discarded_claims"):
        _disc = report.get("discarded_claims") or []
        report = dict(report)
        report["meta"] = dict(report.get("meta") or {})
        _dpath = "%s-discarded%s" % (stem, ext)
        report["meta"]["discarded_claims_file"] = os.path.basename(_dpath)
        report["meta"]["discarded_claims_count"] = len(_disc)
        report["discarded_claims"] = []
        discarded_sibling = (_dpath, {"discarded_claims": _disc})

    blob = json.dumps(report, indent=2)
    findings = list(report.get("findings") or [])
    if len(blob.encode("utf-8")) <= max_bytes or len(findings) <= 1:
        # #run7 COD-F1A: stage ALL temps first, then os.replace them, committing
        # the pointed-to discarded sibling BEFORE the main report (the pointer).
        # The old per-target write+replace loop committed the main report first,
        # so a failed sibling write left the main report pointing at a
        # discarded_claims_file that never existed (a dangling pointer). This
        # mirrors the chunked branch's write-all-then-replace discipline.
        targets = [(out_path, blob)]
        if discarded_sibling:
            targets.append((discarded_sibling[0], json.dumps(discarded_sibling[1], indent=2)))
        temp_files = []
        try:
            for _fp, _txt in targets:
                tmp = os.path.join(out_dir, ".report-%s.tmp" % uuid.uuid4().hex)
                with open(tmp, "w", encoding="utf-8") as fh:
                    fh.write(_txt)
                temp_files.append((tmp, _fp))
            for tmp, _fp in reversed(temp_files):   # sibling first, main last
                os.replace(tmp, _fp)
        finally:
            for tmp, _ in temp_files:
                if os.path.exists(tmp):
                    try:
                        os.remove(tmp)
                    except OSError:
                        pass
        return [t[0] for t in targets]
    main_report = dict(report)
    main_report["meta"] = dict(report.get("meta") or {})

    empty_doc = dict(report)
    empty_doc["findings"] = []
    base_bytes = len(json.dumps(empty_doc, indent=2).encode("utf-8"))
    if base_bytes >= max_bytes:
        # #15: even with findings removed (discarded_claims already split to a
        # sibling), the base exceeds the budget, so chunk_limit floors to 1000 and
        # findings pack ~1/part. Disclose it LOUDLY rather than silently floor; the
        # per-part sanity check below flags the degenerate output too. In practice
        # this only fires for a genuinely bloated meta or a deliberately tiny
        # max_bytes — the real run-6 cause (inline discarded_claims) is gone.
        print("WARNING (#15): report base is %d bytes >= max_bytes %d — findings "
              "will floor to ~1/part; discarded_claims already split out, so "
              "investigate meta bloat if this is a production report."
              % (base_bytes, max_bytes), file=sys.stderr)
    chunk_limit = max(1000, max_bytes - base_bytes - 500)

    chunks = []
    current_chunk = []
    for f in findings:
        current_chunk.append(f)
        payload = {"findings": current_chunk}
        if len(json.dumps(payload, indent=2).encode("utf-8")) > chunk_limit and len(current_chunk) > 1:
            last = current_chunk.pop()
            chunks.append(current_chunk)
            current_chunk = [last]
    if current_chunk:
        chunks.append(current_chunk)

    if len(chunks) <= 1:
        half = max(1, len(findings) // 2)
        chunks = [findings[:half], findings[half:]]

    if len(findings) >= 20 and len(chunks) * 2 > len(findings):
        # #15: a mean under 2 findings/part on a large report is the chunk-limit
        # pathology signature. The base_bytes guard above catches the extreme case;
        # this warns on the merely-degenerate one.
        print("WARNING (#15): %d findings split into %d parts (~%.1f/part) — "
              "possible chunk-limit pathology." % (len(findings), len(chunks),
              len(findings) / max(1, len(chunks))), file=sys.stderr)

    part_files = []
    part_paths = []
    for idx in range(1, len(chunks)):
        pname = "%s_part%d%s" % (stem, idx + 1, ext)
        part_paths.append(pname)
        part_files.append(os.path.basename(pname))

    main_report["meta"]["parts"] = part_files
    main_report["findings"] = chunks[0]

    all_targets = [(out_path, main_report)]
    for idx in range(1, len(chunks)):
        all_targets.append((part_paths[idx - 1], {"findings": chunks[idx]}))
    if discarded_sibling:
        all_targets.append(discarded_sibling)

    temp_files = []
    try:
        for final_path, content in all_targets:
            parent = os.path.dirname(os.path.abspath(final_path)) or "."
            os.makedirs(parent, exist_ok=True)
            tmp_p = os.path.join(parent, ".part-%s.tmp" % uuid.uuid4().hex)
            with open(tmp_p, "w", encoding="utf-8") as fh:
                json.dump(content, fh, indent=2)
            temp_files.append((tmp_p, final_path))

        # #run7 COD-F1A: commit the main report LAST -- its meta.parts and
        # meta.discarded_claims_file only go live after every part + sibling they
        # point at already exists on disk, so a mid-replace failure can never
        # leave the main report referencing a missing artifact.
        for tmp_p, final_path in reversed(temp_files):
            os.replace(tmp_p, final_path)
    finally:
        for tmp_p, _ in temp_files:
            if os.path.exists(tmp_p):
                try:
                    os.remove(tmp_p)
                except OSError:
                    pass

    return [t[0] for t in all_targets]

def _derive_html_path(json_path):
    if json_path.lower().endswith(".json"):
        return json_path + ".html"
    return os.path.join(json_path, "report.html")

def _read_json_report(path):
    """Load a JSON report for --compare, MERGING meta.parts continuation files.

    #run7 ARC-D1A: a large report is split into `<stem>_partN.json` with the
    part list in meta.parts (write_report); a bare json.load here returned only
    the main file, so --compare silently dropped every part2+ finding and the
    new/resolved/severity-changed counts were wrong with no warning. Merge the
    parts' findings + discarded_claims (reusing reconcile's #1122 path
    confinement) while KEEPING the main report's meta/summary for the compare
    view. A referenced part that can't be read fails LOUD (None), never a silent
    partial compare. None (with a printed error) on any failure."""
    import scripts.reconcile as reconcile
    try:
        with open(path, encoding="utf-8") as fh:
            report = json.load(fh)
    except OSError as e:
        print("ERROR: cannot read %s: %s" % (path, e), file=sys.stderr)
        return None
    except ValueError as e:
        print("ERROR: invalid JSON in %s: %s" % (path, e), file=sys.stderr)
        return None
    meta = report.get("meta") or {}
    parts = meta.get("parts") or []
    # #run9 ARC-D1A: a large report ALSO spills discarded_claims to a
    # `<stem>-discarded.json` sibling with a meta.discarded_claims_file pointer
    # (write_report #15) -- independent of the meta.parts findings-chunking, so it
    # can appear with NO parts. Following only meta.parts silently dropped every
    # rejected claim from --compare. Merge the sibling too, same confinement.
    disc_file = meta.get("discarded_claims_file")
    if parts or disc_file:
        base_dir = os.path.dirname(os.path.abspath(path))
        findings = list(report.get("findings") or [])
        discarded = list(report.get("discarded_claims") or [])
        for part in parts:
            try:
                ppath = reconcile._resolve_part_path(base_dir, part)
                with open(ppath, encoding="utf-8") as fh:
                    pdata = json.load(fh)
            except (OSError, ValueError) as e:
                print("ERROR: --compare report %s references part %r that could not "
                      "be read (%s); the comparison would be incomplete"
                      % (path, part, e), file=sys.stderr)
                return None
            findings.extend(pdata.get("findings") or [])
            discarded.extend(pdata.get("discarded_claims") or [])
        if disc_file:
            try:
                dpath = reconcile._resolve_part_path(base_dir, disc_file)
                with open(dpath, encoding="utf-8") as fh:
                    ddata = json.load(fh)
            except (OSError, ValueError) as e:
                print("ERROR: --compare report %s references discarded_claims_file %r "
                      "that could not be read (%s); the comparison would be incomplete"
                      % (path, disc_file, e), file=sys.stderr)
                return None
            discarded.extend(ddata.get("discarded_claims") or [])
        report["findings"] = findings
        report["discarded_claims"] = discarded
    return report
