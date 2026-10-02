"""Terminal summary rendering and report writing."""
import json
import os
import sys
import uuid

import scripts.host_disclosure as host_disclosure
import scripts.hosts as hosts
import scripts.redact as redact
import scripts.safe_write as safe_write
import scripts.tool_cleanup as tool_cleanup
import scripts.tools.base as tool_base
from . import coverage_io as coverage_io
from . import findings as findings_mod
from . import grading as grading_mod
from . import integrity as integrity_mod


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

    The numeric score appears beside Grade/Risk/Gate. The letter grade is
    derived from the same health score. With no reviewed lines to grade, health
    is unavailable and the displayed grade is n/a. The numeric score preserves
    detail within a grade; incomplete coverage can make the grade provisional.

    Rendered "N / 100" makes the scale explicit. Health and its grade bands
    describe code health; the severity/evidence policy determines the gate.
    This function only formats the already-computed score.
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
    weights = ", ".join("%s x%s" % (severity, grading_mod.HEALTH_WEIGHTS[severity])
                        for severity in findings_mod.SEV_ORDER)
    return ("**Health:** %s / 100 \u2014 %s clean LoC against %s weighted "
            "defect; HIGHER IS BETTER, 100 = no gate-eligible weighted defect "
            "(weights: %s, "
            "each x lines spanned). Gate-eligible findings only; never affects "
            "the gate." % (score, "{:,}".format(loc), "{:,}".format(wd), weights))

def _suppressed_line(suppressed, not_gated=None):
    """#1578: what a directory-NAME exclusion dropped, named per segment.

    #1740: three rules feed it -- a vendored directory, a virtualenv known only
    by its name, and the fixture corpus -- so the wording names the class of
    evidence they share rather than the oldest of the three.

    #1578 owner ruling 2026-09-22 (policy C): `not_gated` is how many of these
    a redteam run's gate SAW and declined, because they are neither CRITICAL
    nor secret-class. Said here rather than on its own line because this is
    already the line for what stayed off the gate -- and because the tail of
    this sentence used to promise that redteam gates all of them, which the
    ruling made untrue.

    Silent when nothing was dropped and on a report that never measured this
    (pre-#1578, or a foreign report on the --compare path) -- "nobody counted"
    must not render as "nothing was dropped". Tolerant of a malformed block for
    the same reason the HTML is: this line is not worth a traceback mid-render.
    """
    rows = _suppressed_rows(suppressed)
    if not rows:
        return ""
    withheld = sum(n for _seg, n in _suppressed_rows(not_gated))
    return ("**Tool findings suppressed:** %s \u2014 dropped from the tool axis "
            "for the DIRECTORY NAME they sit under (a conventional vendored, "
            "virtualenv or fixture-corpus name, with no marker or provenance "
            "behind it); the agentic panel still reviewed those files, and "
            "`--security redteam` gates the CRITICAL and secret-class ones%s%s"
            % (coverage_io.venv_tally(rows, MARKER_VENV_PREFIX),
               (" (%d withheld from this run's gate by that rule, #1578 "
                "policy C)" % withheld) if withheld else "",
               _VENV_TALLY_CLAUSE if any(_is_venv_tally_row(seg)
                                         for seg, _n in rows) else ""))


# #1839: the rows in this tally that do NOT rest on a directory name, spelled
# out because the sentence above would otherwise speak for them and say untrue
# things. The tokens mirror `ingest_tools` rather than import it (a renderer must
# not pull the ingest's adapter registry in); tests/test_ingest_tools.py pins them.
MARKER_VENV_SEGMENT = "virtualenv-by-marker"
MARKER_VENV_PREFIX = "pyvenv.cfg:"
NAME_VENV_SEGMENT = "virtualenv-by-name"
_VENV_TALLY_CLAUSE = (
    " Two keys here NAME A CLASS instead of a directory, and count virtualenv "
    "DIRECTORIES the SCAN was told to skip rather than findings: `%s` (a "
    "`pyvenv.cfg` MARKER the target wrote) and `%s` (a `venv`/`.venv` name "
    "alone), skipped under `--security standard` for the #1638 P09 walk saving, "
    "which produced no findings to count -- `tools-manifest.json`'s "
    "`excluded_dirs` names them. Every other key counts findings, a `%s<dir>` "
    "row one marker-confirmed virtualenv's worth at any depth."
    % (MARKER_VENV_SEGMENT, NAME_VENV_SEGMENT, MARKER_VENV_PREFIX))


def _is_venv_tally_row(segment):
    """True for any key shape the clause above speaks for (#1839, round 1 I4)."""
    return (segment in (MARKER_VENV_SEGMENT, NAME_VENV_SEGMENT)
            or str(segment).startswith(MARKER_VENV_PREFIX))


def _suppressed_rows(value):
    """The `{segment: count}` rows worth printing: named, countable, non-zero.

    Shared by both suppression lines so they can never disagree about which
    rows exist. Tolerant of a malformed block for the same reason the HTML is:
    neither line is worth a traceback mid-render.
    """
    if not isinstance(value, dict):
        return []
    return [(seg, n) for seg, n in sorted(value.items())
            if isinstance(seg, str) and isinstance(n, int)
            and not isinstance(n, bool) and n > 0]


def _suppressed_gated_line(gated):
    """#1701: what a directory-NAME exclusion withheld from `findings[]` and
    THIS RUN'S gate counted anyway (#1740: all three classes of it).

    Its own line, with its own wording, because it says the opposite of the one
    above: those findings were not lost from the gate, they were lost from the
    REPORT while still setting it. Without it a redteam FAIL renders as
    "HIGH: 0 -- FAILS THE GATE" over an empty findings list, with nothing
    anywhere saying why (fix round 1, F2). Silent when nothing was gated, which
    is every standard-mode run.
    """
    rows = _suppressed_rows(gated)
    if not rows:
        return ""
    return ("**Tool findings suppressed but GATED:** %s \u2014 withheld from the "
            "findings below for the DIRECTORY NAME they sit under (vendored, "
            "virtualenv-by-name or fixture corpus), and counted toward THIS "
            "RUN's gate, risk level and health "
            "grade anyway (`--security redteam`, and CRITICAL or secret-class "
            "per #1578 policy C). A gate verdict here may rest on "
            "findings this report does not list"
            % coverage_io.venv_tally(rows, MARKER_VENV_PREFIX))


def _code_span(text):
    """`text` in a Markdown code span whose fence is long enough that the text's
    own backticks stay inert -- for a glob or a path the TARGET authored.

    Callers JSON-quote the value first: that is what keeps a newline in a
    target-written path from forging a line of its own in this summary.
    """
    ticks = "`"
    while ticks in text:
        ticks += "`"
    return ticks + text + ticks


def _excluded_tools_line(value):
    """Show a measured tool-policy exclusion without inventing legacy data."""
    if not isinstance(value, dict):
        return ""
    count, globs = value.get("count"), value.get("globs")
    if (not isinstance(count, int) or isinstance(count, bool) or count < 0
            or not isinstance(globs, list)
            or any(not isinstance(glob, str) or not glob for glob in globs)):
        return ""
    policy = ", ".join(_code_span(json.dumps(glob, ensure_ascii=False))
                       for glob in globs) if globs else "none"
    # Silent without a policy: the clause is a disclosure about THIS run.
    # #1757: "every domain but SEC" -- the clause used to end "not just this
    # axis", which read as SEC included, and the owner ruling of 2026-09-25 made
    # that false. The SEC surface it could not take is the line ABOVE this one.
    cells = (" — a committed `exclude_paths:` prunes review CELLS too, not just"
             " this axis (every domain but SEC)") if globs else ""
    return "**Tool findings excluded by policy:** %d — globs: %s%s" % (count, policy, cells)


def _sec_carve_out_line(value):
    """#1757 (AGT-1355709320): the objective SEC surface a target's committed
    `exclude_paths:` could not take out of the SEC domain.

    Owner ruling 2026-09-25 -- such an exclusion is DISCLOSED in the coverage
    section rather than silently applied, and this is that disclosure on the
    human surface. Silent without a measurement, like its sibling above: the key
    is absent entirely on a run with no committed pruning policy.
    """
    count = value.get("count") if isinstance(value, dict) else None
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        return ""
    kept = [f for f in (value.get("files") or []) if isinstance(f, str) and f]
    # One LINE: 20 names, with the full list in the JSON block it summarizes --
    # and the tail SAID, the way the leftover line says it, so a reader can
    # never mistake a cut list for the whole carve-out.
    names = ", ".join(_code_span(json.dumps(f, ensure_ascii=False))
                      for f in kept[:20])
    if len(kept) > 20:
        names += " … (+%d more)" % (len(kept) - 20)
    return ("**`exclude_paths:` SEC carve-out:** %d file(s) kept for SEC review "
            "only: %s — a target's own exclusion cannot hide the objective SEC "
            "surface (#1757)" % (count, names or "none"))


def _config_line(config):
    """#1681 Plan 2: what the reviewed repository's own config asked for and
    did not get. Silent unless something was refused or clamped -- a config
    that asked for nothing odd says nothing here, so the line's presence
    always means a target tried to move its own review's settings.
    """
    # The KEY is target-authored too (fix round 2, M7): `load_resolution`
    # bounds it at 300, which is four times what this human-facing line gives
    # a value, so it goes through the same slice.
    src = config if isinstance(config, dict) else {}
    parts = ["`%s: %s` refused" % (_cfg_value(r.get("key")), _cfg_value(r.get("value")))
             for r in (src.get("refused") or []) if isinstance(r, dict)]
    parts += ["`%s: %s` clamped to %s" % (_cfg_value(c.get("key")),
                                          _cfg_value(c.get("requested")),
                                          _cfg_value(c.get("effective")))
              for c in (src.get("clamped") or []) if isinstance(c, dict)]
    if not parts:
        return ""
    return ("**Target config:** %s — the reviewed repository's `settings:` "
            "asked for this and the run did not honour it" % ", ".join(parts))


_CFG_VALUE_MAX = 80


def _cfg_value(value):
    """The summary-line rendering of one config value. Belt-and-braces bound
    (#1681 Plan 2 fix round 1): `config_schema.load_resolution` already
    bounds every value it reads off the run artifact, but this line is
    human-facing, so a huge number or string never gets to widen it either."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    # Inert as well as bounded (#1829 SEC-798292895): the key and the value are
    # the target repository's own text, and this line is read in a terminal.
    return tool_base.inert_text(value, limit=_CFG_VALUE_MAX)


def render_summary(report):
    """Render markdown summary of report with grades, stats, groups, and top findings."""
    s = report["summary"]
    gate_mode = report["meta"].get("gate_security_mode")
    health_line = _render_health(s.get("health"))
    lines = [
        # #1829 SEC-798292895: belt and braces for the two fields the
        # normalization boundary does not own -- the target path this run was
        # given, and a group name out of the reviewed repository's own group
        # table (`repo_config` names that file; this module does not).
        "# panopticon — %s" % tool_base.inert_text(report["meta"]["target"],
                                                 mode="path"),
        "",
        "**Grade:** %s  **Risk:** %s  **Gate:** %s%s%s" % (
            _grade_text(s),
            s["risk_level"], s["gate"],
            " (%s)" % gate_mode if gate_mode else "",
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
        # #1644: the divergence map is the detail for a MEASURED gap. When the
        # measurement itself could not be made -- an unreadable tools manifest
        # leaves both maps empty -- the reason lives in `coverage_note`, and
        # without it this line printed the bare word "incomplete" for the one
        # state an operator most needs named. The note is a PEER of the
        # divergence parts, not their fallback (#2013 review M5): a run can
        # carry both a measured divergence and a named caveat, and the
        # caveat is the one the operator cannot see anywhere else on the line.
        if s.get("coverage_note"):
            parts.append(s["coverage_note"])
        lines.insert(3, "**Coverage:** NOT CERTIFIED — %s"
                     % ("; ".join(parts) or "incomplete"))
    _cov = report["meta"].get("coverage") or {}
    excluded = _excluded_tools_line(_cov.get("tools_excluded"))
    if excluded:
        lines.insert(3, excluded)
    # #1757: coded AFTER the exclusion line so it renders ABOVE it (every
    # `insert(3, …)` here lands above whatever was already there) -- an
    # exclusion that was REFUSED outranks one that was applied.
    carve = _sec_carve_out_line(_cov.get("exclude_paths_sec_carve_out"))
    if carve:
        lines.insert(3, carve)
    sup = _suppressed_line(_cov.get("tools_suppressed"),
                           _cov.get("tools_suppressed_not_gated"))
    if sup:
        lines.insert(3, sup)
    # #1701: inserted AFTER the line above so it lands ABOVE it -- a count that
    # moved this run's gate outranks a count that did not.
    sup_gated = _suppressed_gated_line(_cov.get("tools_suppressed_gated"))
    if sup_gated:
        lines.insert(3, sup_gated)
    cleanup = tool_cleanup.markdown_line(
        _cov.get("tools_cleanup_failures"), _code_span)
    if cleanup:
        lines.insert(3, cleanup)
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
    # #1681 Plan 2: coded BEFORE the integrity inserts below so integrity stays
    # on top of it -- each `lines.insert(3, …)` in this function lands ABOVE
    # whatever was already there (#1701's comment above pins the direction),
    # so the LATER an insert is coded, the HIGHER it renders. An artifact-trust
    # problem outranks a disclosure about a target's own config.
    cfg_line = _config_line(report["meta"].get("config"))
    if cfg_line:
        lines.insert(3, cfg_line)
    # 5.1 surface 3: a person reading the report must meet the host-capability
    # limitation without opening JSON -- the same reason tools_absent and
    # produced_noscan are surfaced in the body rather than buried in the
    # JSON. Rendered on EVERY report, including the all-proven one: 5.1's
    # inverse says the absence of a warning must mean "measured and proven",
    # which only holds if the proven case is stated here rather than left
    # implicit. `host_capabilities` may be absent, None, or a malformed
    # non-dict shape (a foreign report.json fed to --compare, or a hand-built
    # test fixture) -- fail closed to {} rather than raising; host_disclosure
    # itself then fails closed on a non-str host / non-dict capabilities.
    hc = report["meta"].get("host_capabilities")
    hc = hc if isinstance(hc, dict) else {}
    # D10 N3: `cli_flags` travels with the rest of the envelope. Rebuilding it
    # from two keys dropped every operational fact before this surface could
    # say it, so the one line an operator needed -- "replies are not
    # schema-constrained this run" -- reached stderr and nothing else.
    envelope = {"host": hc.get("host"), "capabilities": hc.get("capabilities"),
                hosts.CLI_FLAGS: hc.get(hosts.CLI_FLAGS)}
    lines.insert(3, "**Host capabilities:** %s" % host_disclosure.headline(envelope))
    for gap in reversed(host_disclosure.lines(envelope) + host_disclosure.notes(envelope)):
        lines.insert(4, "  - %s" % gap)
    # ARC-3284703909 (#1761): one loop over `integrity.INTEGRITY_KEYS`, which
    # owns both which keys sink certification and the line each one prints. The
    # three hand-written inserts this replaced named three of FOURTEEN sinking
    # keys, so ten had no line of their own on this summary and nine of those
    # were named nowhere on it at all -- it said the bare word "incomplete" for
    # them, the hole #1644 closed for `tools_manifest_invalid` alone.
    # A key renders on exactly the truthiness that sinks `integrity_ok`, so the
    # summary and the gate cannot drift; the table's comment owns the order.
    # `evidence_text` neutralizes and bounds its own return (#1829
    # SEC-798292895), so this loop composes only the table's own sentences.
    integ = report["meta"].get("integrity") or {}
    for key, spec in integrity_mod.INTEGRITY_KEYS.items():
        value = integ.get(key)
        if not value or not spec.sentence:
            continue
        body = spec.sentence
        if "%s" in body:
            body = body % integrity_mod.evidence_text(key, value)
        lines.insert(3, "**%s:** %s" % ("Integrity" if spec.sinks else "Note", body))
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
        lines.append("- **%s** — %s" % (tool_base.inert_text(g["name"]), grades))
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
    Google tokens, PEM private keys) in EVERY string in the report, at any
    depth, BEFORE it reaches any shareable artifact -- report.json, the split
    parts, the -discarded.json sibling, report.json.html, the X0X candidates
    and the terminal summary all read from this one dict.

    Reviewers are instructed to write [REDACTED], but a credential one of them
    quoted-but-didn't-redact would otherwise flow verbatim into the pipeline's
    final, shareable output surface. Defense-in-depth backstop layered on the
    prompt-level instruction; single-sourced with the driver's tool-output
    redaction via scripts.redact so the two can never drift.

    #1634: this used to rewrite `findings` and `discarded_claims` only, which
    made it a list a producer had to be REMEMBERED for -- and build_report had
    already copied finding titles into `summary.top_issues` and
    `groups[].key_findings`, so a token in a title survived into the summary
    and the HTML. Walking the whole tree makes the backstop total: `meta`,
    `summary`, `groups`, `cross_panel`, `delta` and anything a future producer
    adds are covered without being named here. Structured fields are safe by
    construction -- the patterns are anchored to well-formed secret formats, so
    ids, codes, grades, hashes, file paths and the verbatim
    `meta.host_capabilities` posture come back byte-identical (pinned by
    test_structured_sections_survive_the_walk).

    This is the second layer: synthesize also redacts the findings BEFORE
    build_report, so derived fields are computed from masked text rather than
    masked afterwards. Redaction is idempotent, so both running is a no-op on
    text the first pass already handled.

    Mutates `report` in place (callers keep reading the same dict) and returns
    it; key order is preserved, and it is part of the artifact."""
    redacted = redact.redact_tree(report)
    report.clear()
    report.update(redacted)
    return report

def write_report(report, out_path, max_bytes=800000):
    """Write report to JSON file, splitting into parts if size exceeds max_bytes.
    Stage every file before publishing siblings, then the main report (#1124).
    """
    out_dir = os.path.dirname(os.path.abspath(out_path)) or "."
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
        targets = [(out_path, blob)]
        if discarded_sibling:
            targets.append((discarded_sibling[0], json.dumps(discarded_sibling[1], indent=2)))
        return safe_write.publish_texts(
            (path, os.path.join(out_dir, ".report-%s.tmp" % uuid.uuid4().hex), text)
            for path, text in targets)
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
    current_chunk: list[dict] = []
    # With indent=2, nesting one standalone finding adds four spaces to each
    # line. The non-empty wrapper is fixed; later items add a comma and newline.
    wrapper_bytes = len(b'{\n  "findings": [\n\n  ]\n}')
    current_bytes = wrapper_bytes
    for f in findings:
        item = json.dumps(f, indent=2)
        item_bytes = len(item.encode("utf-8")) + 4 * (item.count("\n") + 1)
        added_bytes = item_bytes + (2 if current_chunk else 0)
        if current_chunk and current_bytes + added_bytes > chunk_limit:
            chunks.append(current_chunk)
            current_chunk = [f]
            current_bytes = wrapper_bytes + item_bytes
        else:
            current_chunk.append(f)
            current_bytes += added_bytes
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

    return safe_write.publish_texts(
        (path, os.path.join(out_dir, ".part-%s.tmp" % uuid.uuid4().hex),
         json.dumps(content, indent=2)) for path, content in all_targets)


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
