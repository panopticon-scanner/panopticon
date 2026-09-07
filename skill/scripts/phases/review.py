"""Phase 4 -- review: the matrix-cell dispatch checkpoint and its cell artifacts."""
import functools
import os

import scripts.dispatch as dispatch
import scripts.evidence as evidence
import scripts.ingest_tools as ingest_tools
import scripts.ocrdb as ocrdb
import scripts.synth.findings as findings_mod
import scripts._version as _version
from . import engine
from . import runio
from . import coverage
from . import requests
from . import verify


def _get_valid_cell_data(review_root, manifest, group, domain):
    data = runio._load_json(runio._pano(review_root, "findings-%s-%s.json" % (group, domain)))
    if not (isinstance(data, dict) and isinstance(data.get("findings"), list)):
        return None
    meta = data.get("_panopticon")
    if (isinstance(meta, dict) and meta.get("run_id") == manifest.get("run_id")
            and meta.get("domain") == domain and meta.get("group") == group):
        return data
    return None

def _cell_done(review_root, manifest, group, domain):
    return _get_valid_cell_data(review_root, manifest, group, domain) is not None

def _render_security_checklist(domain):
    """The SEC cell's language-specific checklist pointer, or "" (#run10).

    `reference/security-checklists.md` is a real review asset -- per-language
    banned-construct lists (Rails mass assignment, `pickle.loads`, `dangerouslySetInnerHTML`,
    ...) that a domain menu code names but does not enumerate. Its ONLY consumer
    was the 4.x `panel-review.md` template, deleted in #1441, so it silently
    stopped reaching any reviewer: run-8 through run-10's SEC cells ran without
    it, and nothing noticed because a keeper test still asserted its contents.

    Handed over as an ABSOLUTE path rather than inlined: the reviewer has Read,
    the file is ~90 lines it should consult selectively (its own first line says
    to apply only the languages actually present), and a bare relative path --
    what the 4.x template used -- does not resolve from the reviewer's cwd.
    """
    if domain != "SEC":
        return ""
    return (
        "\n**Language checklists.** Read `%s` and apply the sections for the "
        "language(s) actually present in your file list, ignoring the rest. It "
        "enumerates the concrete banned constructs behind several menu codes; "
        "treat a hit as a candidate finding, still graded against the criteria "
        "above.\n" % os.path.abspath(_version.reference_path("security-checklists.md")))

def _render_menu(bundle, domain):
    lines = ["%s %s (%s)" % (m["code"], m["name"], m["severity"])
             for m in ocrdb.domain_menu(bundle, domain)]
    return "\n".join(lines) or "(no OCRDb bundle vendored — use general %s judgment)" % domain

def _render_criteria(bundle, domain):
    """The domain's explicit OCRDb pass/fail criteria for the advisor to grade a
    claim against, one code per line. Codes without criteria are omitted (they
    fall back to the menu one-liner). A domain with no criteria at all renders a
    note, so the {criteria} lens is never a blank section (#1035)."""
    blocks = ["%s %s — %s" % (c["code"], c["name"], c["criteria"])
              for c in ocrdb.domain_criteria(bundle, domain)]
    return "\n".join(blocks) or (
        "(no explicit OCRDb criteria for the %s domain in this bundle — grade "
        "against the menu one-liners above)" % domain)

# --- #1131 tool-aware review (SEC-first PoC) ---------------------------------
# Hand a review cell the static-analysis tool findings that already landed in
# its files, as a "don't re-derive" MAP (never an answer key): the reviewer
# skips re-deriving them and instead escalates any deeper issue a tool can't
# reach. SEC-only for now — every tool finding is panel:"security", so SEC needs
# no rule->domain routing, just file->group (which the cell's `files` already
# give us); other domains need a rule/CWE->domain index (deferred). The
# independent tool-verify round is untouched; this is purely a prompt input.
_TOOL_HIT_DOMAINS = frozenset({"SEC"})

_TOOL_HITS_CAP = 40

@functools.lru_cache(maxsize=None)
def _ingested_tool_findings(review_root, include_fixtures):
    """All normalized tool findings for this run, memoized per (review_root,
    include_fixtures). Mirrors the driver's tool-verify ingest (same
    include_fixtures) so the review-time map reflects the SAME findings the
    independent tool-verify round adjudicates. Returns () when the tools dir is
    absent or ingest fails — the map is advisory and must never break a review."""
    tools_dir = runio._pano(review_root, "tools")
    if not os.path.isdir(tools_dir):
        return ()
    try:
        findings, _disp = ingest_tools.ingest_dir_detailed(
            tools_dir, None, include_fixtures=include_fixtures)
    except Exception:  # noqa: BLE001 - advisory input; never break review on it
        return ()
    return tuple(findings)

def _format_tool_hits(hits):
    """Render a cell's already-reported tool findings as a 'don't re-derive'
    map. Empty string when there are none, so the prompt section vanishes for
    cells/domains with no hits."""
    if not hits:
        return ""
    lines = []
    for h in hits[:_TOOL_HITS_CAP]:
        loc = h.get("location") or {}
        f = loc.get("file") or "?"
        ln = loc.get("line_start")
        where = "%s:%s" % (f, ln) if ln else f
        rule = (h.get("tool_evidence") or {}).get("rule_id") or h.get("category") or "?"
        title = " ".join(str(h.get("title") or "").split())
        lines.append("- %s · %s · %s · %s"
                     % (where, rule, h.get("severity") or "?", title))
    extra = len(hits) - _TOOL_HITS_CAP
    if extra > 0:
        lines.append("- …and %d more tool finding(s) in these files." % extra)
    return (
        "## Tool findings already reported in your files\n\n"
        "Static-analysis tools already flagged the items below in the files you're "
        "reviewing, and they are verified independently — do **not** re-file them as "
        "your own findings. Your two jobs:\n\n"
        "1. **Skip re-deriving these.** Spend your attention on what tools cannot see.\n"
        "2. **Escalate when there is more.** If a hit exposes a deeper issue a tool "
        "cannot reach — the root cause, cross-file blast radius, a real exploit path, "
        "or a systemic pattern — file THAT finding and cite the `rule_id` it builds "
        "on. A bare restatement of a tool hit is not a finding.\n\n"
        + "\n".join(lines) + "\n\n"
    )

def _tool_hits_for_cell(review_root, manifest, domain, files):
    """The 'don't re-derive' tool-hit map (#1131) for one review cell, or '' when
    the domain is out of PoC scope or no tool hit lands in the cell's files."""
    if domain not in _TOOL_HIT_DOMAINS:
        return ""
    wanted = set(files or ())
    if not wanted:
        return ""
    findings = _ingested_tool_findings(review_root,
                                       verify._tools_include_fixtures(manifest))
    hits = [f for f in findings
            if ((f.get("location") or {}).get("file")) in wanted]
    hits.sort(key=lambda h: (str((h.get("location") or {}).get("file") or ""),
                             (h.get("location") or {}).get("line_start") or 0))
    return _format_tool_hits(hits)

def _cell_entry(review_root, manifest, group, domain, files, tests, host, bundle):
    file_list = runio._abs_file_list(review_root, files)
    test_list = "\n".join("- " + t for t in tests) or "- (no tests)"
    out_file = os.path.abspath(runio._pano(review_root, "findings-%s-%s.json" % (group, domain)))
    prompt = dispatch.render_prompt("domain-panel.md", {
        "domain": domain, "group": group, "file_list": file_list,
        "tests": test_list, "security_mode": manifest.get("security_mode", "standard"),
        "menu": _render_menu(bundle, domain),
        "criteria": _render_criteria(bundle, domain), "run_id": manifest["run_id"],
        "tool_hits": _tool_hits_for_cell(review_root, manifest, domain, files),
        "security_checklist": _render_security_checklist(domain),
        "out_file": out_file}, host)
    enforced = host == "claude"
    # run_id/group/domain restate the cell this entry IS, so a host can check a
    # findings file's own `_panopticon` stamp against the entry that asked for
    # it (group_runner.entry_is_done) instead of trusting the path alone. The
    # same three fields the domain-panel template requires in its output.
    return {"id": "review-%s-%s" % (group, domain),
            "agent": dispatch.registered_agent_name("domain-panel.md") if enforced else None,
            "enforced": enforced, "model": None, "prompt": prompt,
            "out_file": out_file, "run_id": manifest["run_id"],
            "group": group, "domain": domain}

def _load_cell_findings(review_root, manifest, group, domain):
    """The cell's reviewer findings, normalized + id-assigned exactly as
    findings_mod.load_findings does, or None when the cell file is absent/mismatched.
    Ids match synthesize's so the advisor's finding_id echo binds at synthesis.

    Strips findings_mod.AGENT_FORBIDDEN_FIELDS (source/reinforced/corroborated/
    corroborated_by/evidence) before normalizing, mirroring findings_mod.load_findings:
    a raw panel finding must never carry a self-asserted `evidence.status` into
    score_gate.should_engage_primary, or a forged "rejected" (factor 0.0) would
    let a finding duck the F_p gate entirely.

    verify_execute/verify_done feed this RAW per-cell list straight into
    score_gate.should_engage_primary -- no cross-cell dedup. synthesize's own
    engagement check (engaged_matrix_cells) scores the deduped/aggregated list
    produced by prepare_for_queue instead, so synth-engaged is a subset of
    driver-engaged, never the reverse. This is a bounded, safe discrepancy:
    verify_done gates synthesize (every driver-engaged cell already has a
    bundle before synthesize runs), but meta.coverage.verify_matrix.engaged can
    undercount when exact-duplicate findings collapse in dedup."""
    data = _get_valid_cell_data(review_root, manifest, group, domain)
    if data is None:
        return None
    out = []
    for f in data.get("findings") or []:
        if not isinstance(f, dict):
            continue
        raw = dict(f)
        for k in findings_mod.AGENT_FORBIDDEN_FIELDS:
            raw.pop(k, None)
        nf = findings_mod.normalize_finding(raw)
        # #1109: never trust an agent-supplied id -- always content-derive it, so
        # a crafted/colliding well-formed id can't bind a downstream verdict to
        # the wrong finding. Kept in lockstep with findings_mod.load_findings so the
        # advisor's finding_id echo still binds at synthesis.
        nf["id"] = evidence.matrix_finding_id(nf)
        out.append(nf)
    return out

def review_done(review_root, manifest):
    groups = coverage._discovered_groups(review_root)
    if not groups:
        return True   # vacuous (no groups)
    return all(_cell_done(review_root, manifest, g, d)
               for g, _ in groups for d in coverage._effective_domains(review_root, g))

def review_execute(review_root, manifest):
    # #5.0-16 H2: declare every review cell before dispatching any, so an
    # injected/undeclared findings file is caught by reconcile at synthesis.
    requests._write_driver_plan(review_root, manifest)
    host = manifest.get("host", "claude")
    bundle = runio._load_ocrdb_bundle()
    # group tests come from the committed matrix (parse_groups tests field)
    matrix, errors = runio.load_committed_groups(review_root)
    if errors:
        # #1092: same resume-reachable gap as coverage -- a corrupt groups.yml
        # would silently drop every group's committed tests from the prompts.
        raise runio.DriverError("review: " + "; ".join(errors))
    # #5: batch EVERY pending review cell across ALL groups into one checkpoint
    # (like the scout fan-out, #1056) instead of one group per round trip -- run-6
    # serialized 26 groups into 26 sequential trips while the host can dispatch
    # ~20 agents at once. group=None marks a batch; each entry is self-describing
    # (group+domain in its id/out_file), and the host installs the write-guard
    # from the full entry set, so the fail-closed allowlist still covers every cell
    # (_write_driver_plan above already declared them all for reconcile).
    all_entries, ngroups = [], 0
    for group, files in coverage._discovered_groups(review_root):
        domains = coverage._effective_domains(review_root, group)
        pending = [d for d in domains if not _cell_done(review_root, manifest, group, d)]
        if not pending:
            continue
        ngroups += 1
        tests = sorted((matrix.get(group) or {}).get("tests") or [])
        all_entries.extend(
            _cell_entry(review_root, manifest, group, d, files, tests, host, bundle)
            for d in pending)
    if all_entries:
        req = requests.write_dispatch_request(review_root, manifest["run_id"], "review",
                                     None, all_entries)
        return engine.PhaseResult(kind="checkpoint", checkpoint="review", group=None,
                           dispatch_request=req,
                           message="review: %d cell(s) across %d group(s)"
                                   % (len(all_entries), ngroups))
    return engine.PhaseResult(kind="advanced", message="review: all cells complete")
