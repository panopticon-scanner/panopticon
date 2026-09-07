"""The 5.0 resumable driver: a table-driven phase state machine.

`driver run` advances through PHASES, executing deterministic work itself and
STOPPING at each dispatch checkpoint (writing dispatch-request.json). The phase
cursor is never stored — it is recomputed from disk (`first not-done phase`)
every invocation, so a crash/compaction/interrupt resumes identically. See
docs/superpowers/specs/2026-08-15-panopticon-5.0-driver-skeleton-design.md.
"""
import argparse
import functools
import glob as _glob
import datetime
import json
import os
import shutil
import subprocess
import sys


# #5.0-01: when run directly (`python3 skill/scripts/driver.py run ...`, the
# documented entrypoint) the package roots are not on sys.path, so the
# `import scripts.*` below crash with ModuleNotFoundError. Bootstrap the same
# roots _child_env() puts on PYTHONPATH for subprocesses. Idempotent under
# pytest, whose conftest already provides them.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))                   # skill/scripts
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # skill


import scripts.diff_map as diff_map  # noqa: E402
import scripts.dispatch as dispatch  # noqa: E402
import scripts.evidence as evidence  # noqa: E402
import scripts.ingest_tools as ingest_tools  # noqa: E402
import scripts.ocrdb as ocrdb  # noqa: E402
import scripts.plan_contract as plan_contract  # noqa: E402
import scripts.run_manifest as run_manifest  # noqa: E402
import scripts.score_gate as score_gate  # noqa: E402
import scripts.setup_flow as setup_flow  # noqa: E402
import scripts.synth.findings as findings_mod  # noqa: E402
import scripts._version as _version  # noqa: E402
import scripts.phases.engine as engine
import scripts.phases.runio as runio
import scripts.phases.coverage as coverage
import scripts.phases.discovery as discovery
import scripts.phases.requests as requests
import scripts.phases.tools as tools


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
                                       _tools_include_fixtures(manifest))
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


def _verify_out_file(review_root, group, domain, stage):
    suffix = "-backup" if stage == "backup" else ""
    return os.path.abspath(runio._pano(review_root, "verdicts",
                                 "verdicts-%s-%s%s.json" % (group, domain, suffix)))


_MAX_VERIFY_ATTEMPTS = 3


def _verify_attempts(review_root, group, domain, stage):
    path = runio._pano(review_root, "verify-attempts.json")
    data = runio._load_json(path) if runio._json_parses(path) else {}
    if not isinstance(data, dict):
        return 0
    return int(data.get("%s/%s/%s" % (group, domain, stage), 0))


def _bump_verify_attempts(review_root, group, domain, stage):
    """Persisted per-(group, domain, stage) re-dispatch counter that BOUNDS the A2
    verdict-reconciliation retry loop, so a systematically-re-coding advisor
    surfaces as unanswered -> INCONCLUSIVE instead of wedging the run. Lives with
    the verdicts, so --reset clears it."""
    path = runio._pano(review_root, "verify-attempts.json")
    data = runio._load_json(path) if runio._json_parses(path) else {}
    if not isinstance(data, dict):
        data = {}
    key = "%s/%s/%s" % (group, domain, stage)
    n = int(data.get(key, 0)) + 1
    data[key] = n
    runio._write_json(path, data)
    return n


def _verify_bundle_labeled(review_root, manifest, group, domain, stage):
    """The verdict bundle exists, parses, and is labeled for THIS cell -- the
    advisor returned something coherent for it (vs no bundle, or an unloadable /
    mislabeled one). Separates an A2 reconciliation shortfall, which the bounded
    budget governs, from a first dispatch or an unloadable return, which keep the
    existing uncapped re-dispatch."""
    data = runio._load_json(_verify_out_file(review_root, group, domain, stage))
    if not (isinstance(data, dict) and isinstance(data.get("verdicts"), list)):
        return False
    meta = data.get("_panopticon") or {}
    return (meta.get("run_id") == manifest.get("run_id")
            and meta.get("domain") == domain and meta.get("group") == group
            and meta.get("stage", "primary") == stage)


def _verify_cell_done(review_root, manifest, group, domain, stage):
    if not _verify_bundle_labeled(review_root, manifest, group, domain, stage):
        return False
    # A2 (run-9): a labeled, parseable bundle is not "done" unless it actually
    # adjudicated every finding the advisor was handed. An advisor RE-CODED a
    # cell's findings -- a 4th TST-B1B while dropping a TST-B1A and a TST-B1C -- so
    # a 10-finding cell came back with 9 verdicts and 2 findings went silently
    # unadjudicated. The bundle was accepted as done, the cell never re-dispatched,
    # and the drop surfaced only as a quiet verdicts.unanswered:1 that sank
    # coverage_certified without naming a cause. Reconcile the verdict finding_ids
    # against the cell's findings (the exact set _render_findings hands the
    # advisor, matched on the same str(id) binding synthesis uses).
    #
    # PRIMARY only: the backup round adjudicates a severity-gated SUBSET by design,
    # so requiring 1:1 there would re-dispatch every backup cell forever.
    if stage != "primary":
        return True
    data = runio._load_json(_verify_out_file(review_root, group, domain, stage))
    cell = _load_cell_findings(review_root, manifest, group, domain)
    want = {str(f["id"]) for f in (cell or [])}
    got = {str(v.get("finding_id")) for v in data["verdicts"]
           if isinstance(v, dict) and v.get("finding_id") is not None}
    if want.issubset(got):
        return True
    # Incomplete: re-dispatch (a chance to fix a transient re-code), but BOUNDED --
    # once the budget is spent the gap is real and surfaces as unanswered ->
    # INCONCLUSIVE at synthesis, honest, rather than wedging the run.
    return _verify_attempts(review_root, group, domain, stage) >= _MAX_VERIFY_ATTEMPTS


def _render_findings(review_root, cell):
    """The cell's claims as a compact JSON array the advisor adjudicates.

    #run8 ARC-F2A: each claim's `location` is confined to review_root (see
    _confine_claim_location). The location is panel/LLM-supplied and the
    advisor's Read/Grep/Glob are unconfined, so an out-of-tree `location.file`
    embedded verbatim here would steer the advisor to read outside the review
    tree in BOTH verify rounds -- the prior _confined_to_root guard covered only
    the derived backup file list, never this channel."""
    slim = [{"id": f["id"], "code": f.get("code"), "severity": f["severity"],
             "title": f["title"], "category": f.get("category"),
             "location": _confine_claim_location(review_root, f.get("location")),
             "description": f.get("description", "")}
            for f in cell]
    return json.dumps(slim, indent=2)


def _verify_entry(review_root, manifest, group, domain, files, cell, host, bundle, stage):
    file_list = runio._abs_file_list(review_root, files)
    out_file = _verify_out_file(review_root, group, domain, stage)
    prompt = dispatch.render_prompt("domain-advisor.md", {
        "domain": domain, "group": group, "file_list": file_list,
        "findings": _render_findings(review_root, cell), "menu": _render_menu(bundle, domain),
        "criteria": _render_criteria(bundle, domain),   # #1035
        "run_id": manifest["run_id"], "stage": stage, "out_file": out_file}, host)
    # #975: pin the review root for the advisor too. Unlike the scout/panel file
    # list above, the findings JSON's `location` fields are carried verbatim from
    # the panel's raw claims and stay repo-relative on disk (_render_findings) —
    # Part A's abspath can't reach into that payload. The advisor inherits the
    # HOST's cwd (the user's checkout), never review_root/the --pr worktree, so
    # without this header a relative `location` resolves against the wrong tree.
    prompt = ("Repo root: %s\nEvery relative path in the claims below resolves "
              "against this root -- read files THERE, never in your session's "
              "default checkout.\n\n%s" % (os.path.abspath(review_root), prompt))
    enforced = host == "claude"
    return {"id": "verify-%s-%s-%s" % (group, domain, stage),
            "agent": dispatch.registered_agent_name("domain-advisor.md") if enforced else None,
            "enforced": enforced, "model": None, "prompt": prompt, "out_file": out_file}


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


def verify_execute(review_root, manifest):
    # #5.0-16 H3: snapshot every declared cell's bytes at the review->verify
    # boundary (idempotent) BEFORE any advisor runs, so a verify-phase
    # substitution is caught. review_done gates this phase, so all cells exist.
    requests._snapshot_review_out_files(review_root, manifest)
    os.makedirs(runio._pano(review_root, "verdicts"), exist_ok=True)
    host = manifest.get("host", "claude")
    bundle = runio._load_ocrdb_bundle()
    # PRIMARY round: one advisor per engaged (>= F_p), not-yet-verified cell.
    # #5: batch every pending primary advisor across ALL groups into one
    # checkpoint (like review + scout), instead of one group per round trip. The
    # BACKUP and TOOL rounds below stay sequential -- they depend on the primary
    # verdicts being complete first (verify_done gates them on all-primary-done).
    all_entries, ngroups = [], 0
    for group, files in coverage._discovered_groups(review_root):
        pending = []
        for domain in coverage._effective_domains(review_root, group):
            cell = _load_cell_findings(review_root, manifest, group, domain)
            if cell is None or not score_gate.should_engage_primary(cell):
                continue   # unreviewed, or below-gate: unverified + disclosed at synth
            if _verify_cell_done(review_root, manifest, group, domain, "primary"):
                continue
            # A2: a labeled-but-incomplete bundle already on disk means the advisor
            # returned a short/re-coded verdict set -- charge one attempt against
            # the bounded budget so an incomplete cell can't re-dispatch forever.
            if _verify_bundle_labeled(review_root, manifest, group, domain, "primary"):
                _bump_verify_attempts(review_root, group, domain, "primary")
            pending.append((domain, cell))
        if pending:
            ngroups += 1
            all_entries.extend(
                _verify_entry(review_root, manifest, group, d, files, c,
                              host, bundle, "primary") for d, c in pending)
    if all_entries:
        req = requests.write_dispatch_request(review_root, manifest["run_id"], "verify",
                                     None, all_entries)
        return engine.PhaseResult(kind="checkpoint", checkpoint="verify", group=None,
                           dispatch_request=req,
                           message="verify: %d primary advisor(s) across %d group(s)"
                           % (len(all_entries), ngroups))
    # BACKUP round (Task 4 fills this branch).
    backup = _verify_backup_execute(review_root, manifest, host, bundle)
    if backup is not None:
        return backup
    # TOOL round (#5.0-03): dispatch a per-finding advisor for each tool finding
    # so synthesize can promote tool_confirmed and stop counting them unanswered.
    tools = _verify_tools_execute(review_root, manifest, host)
    if tools is not None:
        return tools
    return engine.PhaseResult(kind="advanced", message="verify: all cells verified")


def verify_done(review_root, manifest):
    for group, _files in coverage._discovered_groups(review_root):
        for domain in coverage._effective_domains(review_root, group):
            cell = _load_cell_findings(review_root, manifest, group, domain)
            if cell is None or not score_gate.should_engage_primary(cell):
                continue
            if not _verify_cell_done(review_root, manifest, group, domain, "primary"):
                return False
    return (_verify_backup_done(review_root, manifest)
            and _verify_tools_done(review_root, manifest))


def _cell_backup_findings(review_root, manifest, group, domain):
    """The cell's primary-CONFIRMED findings that sit in a category scoring
    >= F_b on primary-stage evidence — the adversarial backup's scope. [] when
    the primary bundle is absent or no category clears F_b."""
    cell = _load_cell_findings(review_root, manifest, group, domain)
    if not cell:
        return []
    primary = runio._load_json(_verify_out_file(review_root, group, domain, "primary"))
    if not (isinstance(primary, dict) and isinstance(primary.get("verdicts"), list)):
        return []
    by_fid = {str(v.get("finding_id")): v for v in primary["verdicts"]
              if isinstance(v, dict) and v.get("finding_id")}
    for f in cell:
        f["evidence"] = evidence.derive_evidence(f, by_fid.get(str(f["id"])))
    by_cat = {}
    for f in cell:
        by_cat.setdefault(f.get("category") or "general", []).append(f)
    out = []
    for cat_findings in by_cat.values():
        if score_gate.should_summon_backup(cat_findings):
            out += [f for f in cat_findings
                    if (f["evidence"].get("status") == "advisor_confirmed")]
    return out


_REDACTED_CLAIM_PATH = "<redacted: location escapes review root>"


def _confine_claim_location(review_root, loc):
    """Return `loc` with an out-of-tree `location.file` neutralized.

    #run8 ARC-F2A: the verify claims JSON handed to the domain/tool advisor
    carries each finding's `location.file` VERBATIM, and the advisor's
    Read/Grep/Glob are unconfined -- so a path-traversal or committed-symlink
    location (e.g. `../../../.ssh/id_rsa`) planted by a redteam target would
    steer the advisor to read OUTSIDE review_root in every verify round.
    _confined_to_root already guarded the derived backup file LIST but never this
    channel. A genuine review finding always cites an in-tree file, so redacting
    an escaping path both defuses the steer and signals the advisor the location
    is untrusted. Non-dict/absent locations pass through unchanged."""
    if not isinstance(loc, dict):
        return loc
    path = loc.get("file")
    if isinstance(path, str) and path and not runio._confined_to_root(review_root, path):
        loc = dict(loc)
        loc["file"] = _REDACTED_CLAIM_PATH
    return loc


def _backup_scope_files(review_root, files, scope):
    """The files a backup advisor needs: the ones its scoped (advisor-confirmed,
    >= F_b) claims cite -- not the whole cell. The domain-advisor is claim-driven
    and its Read/Grep/Glob are unconfined, so a narrow list preserves coverage
    while dropping the whole-cell re-read cost (#1029). Falls back to the full
    group `files` if ANY scoped claim lacks a resolvable location.file, or names
    one that escapes review_root (absolute/`../` -- untrusted, #1096) -- a backup
    must never refute blind, and never read outside the tree."""
    located = []
    for f in scope:
        loc = f.get("location") if isinstance(f, dict) else None
        path = loc.get("file") if isinstance(loc, dict) else None
        if not path or not runio._confined_to_root(review_root, path):
            return list(files)
        if path not in located:
            located.append(path)
    return located or list(files)


def _verify_backup_execute(review_root, manifest, host, bundle):
    # #20: batch every pending BACKUP advisor across ALL groups into one
    # checkpoint (group=None), like review + verify-primary (#5). The backup
    # round is sequenced AFTER primary completes (verify_execute returns primary
    # checkpoints until none remain), but WITHIN the round the cells are
    # independent -- streaming one group per checkpoint just serialized 19 round
    # trips against a 20-wide host (run-7).
    all_entries, ngroups = [], 0
    for group, files in coverage._discovered_groups(review_root):
        pending = []
        for domain in coverage._effective_domains(review_root, group):
            scope = _cell_backup_findings(review_root, manifest, group, domain)
            if not scope:
                continue
            if _verify_cell_done(review_root, manifest, group, domain, "backup"):
                continue
            pending.append((domain, scope))
        if pending:
            ngroups += 1
            # #1029: the backup re-reads only its scoped claims' files, not the
            # whole group -- coverage-preserving (claim-driven, unconfined reads).
            all_entries.extend(
                _verify_entry(review_root, manifest, group, d,
                              _backup_scope_files(review_root, files, c), c,
                              host, bundle, "backup") for d, c in pending)
    if all_entries:
        req = requests.write_dispatch_request(review_root, manifest["run_id"], "verify",
                                     None, all_entries)
        return engine.PhaseResult(kind="checkpoint", checkpoint="verify", group=None,
                           dispatch_request=req,
                           message="verify: %d backup advisor(s) across %d group(s)"
                           % (len(all_entries), ngroups))
    return None


def _verify_backup_done(review_root, manifest):
    for group, _files in coverage._discovered_groups(review_root):
        for domain in coverage._effective_domains(review_root, group):
            if _cell_backup_findings(review_root, manifest, group, domain) \
                    and not _verify_cell_done(review_root, manifest, group, domain, "backup"):
                return False
    return True


def _tools_include_fixtures(manifest):
    """Whether tool-finding ingestion keeps test-fixture-corpus findings.

    ONE source of truth, shared by _tool_verify_queue (the driver's tool
    verify queue) and synthesize_execute (the --include-fixtures it forwards),
    so the driver and synthesize ingest the IDENTICAL set of tool findings.
    Fingerprint/id parity of the tool-verify queue depends on this agreement:
    if the driver ingested fixtures synthesize prunes (or vice versa),
    synthesize could queue a tool finding the driver never dispatched an
    advisor for -> unanswered -> a spurious INCONCLUSIVE.

    #1055: keyed on the explicit --include-fixtures flag ALONE. Redteam no
    longer auto-includes fixture TOOL findings -- adjudicating designed-
    vulnerable fixture CVEs (e.g. TR-010 on vulnerable-rust/Cargo.lock) burned
    verify budget to re-reject scaffolding by construction. Fixture CONTENT
    injection-hunting is unaffected: it is a review-panel job (groups.yml
    routing), independent of this tool-finding flag. Pass --include-fixtures
    to opt in to tool coverage of fixtures (incl. under redteam)."""
    flags = manifest.get("flags") or {}
    return bool(flags.get("include_fixtures"))


def _tool_verify_queue(review_root, manifest):
    """The tool-sourced verify-queue entries, computed EXACTLY as synthesize
    will, so their queue_ids AND finding ids match synthesize's for the same
    tool output. Returns a list of (queue_id, finding); [] when the tool scan
    did not run.

    Runs synthesize's OWN combined pipeline (agent findings from the cell files
    PLUS the ingested tool findings) -> prepare_for_queue -> build_verify_queue,
    then filters to is_tool_sourced entries. The full combined pipeline (not a
    tool-only slice) is what guarantees FINDING-ID parity: aggregate_tool_findings
    chooses its survivor for a repeated rule using the AGENT findings' loci, so a
    tool-only pipeline could keep a different survivor -- same fingerprint/queue_id
    but a different finding id -- and synthesize's match_verdict enforces the
    finding_id echo, so a mismatched id would drop the driver's verdict and force
    the very INCONCLUSIVE this phase exists to prevent. Feeding the identical
    inputs through the identical functions makes the (queue_id, id) pair the tool
    findings carry here byte-identical to what synthesize's report exports.

    Additive only: this CALLS findings_mod.load_findings/normalize_finding/
    prepare_for_queue and evidence.build_verify_queue; it changes none of them.
    include_fixtures/group/exclude are pinned to synthesize's main() tool-ingest
    call (group=None, exclude_globs=None) for identity; _tools_include_fixtures
    is the value synthesize_execute forwards."""
    ran = (runio._load_json(runio._pano(review_root, "tools-ran.json")) or {}).get("ran")
    tools_dir = runio._pano(review_root, "tools")
    if not ran or not os.path.isdir(tools_dir):
        return []
    findings = findings_mod.load_findings(
        sorted(_glob.glob(runio._pano(review_root, "findings-*.json"))))
    tool_findings, _disp = ingest_tools.ingest_dir_detailed(
        tools_dir, None, include_fixtures=_tools_include_fixtures(manifest))
    for tf in tool_findings:
        findings.append(findings_mod.normalize_finding(tf))
    prepared, _integration = findings_mod.prepare_for_queue(findings)
    flags = manifest.get("flags") or {}
    # #18: match synthesize's --max-verify DEFAULT (None = uncapped), not a
    # hardcoded 100. build_verify_queue caps the COMBINED queue and this method
    # only then filters to tool-sourced entries -- so a 100 cap, with agent
    # findings sorting first, STARVES tool findings (run-7: synthesize queued 36
    # tool findings, this dispatched only 6, leaving 30 permanently unanswered and
    # making tool_confirmed:0 an artifact, not a measurement). The docstring above
    # promises this queue is "computed EXACTLY as synthesize will" -- so it must
    # take the same default. (The manifest never carries max_verify today, so this
    # is uncapped in practice; if it ever does, it matches synthesize by key.)
    max_verify = flags.get("max_verify")
    queue, _cut = evidence.build_verify_queue(prepared, max_verify=max_verify)
    return [(e["queue_id"], e["finding"]) for e in queue
            if evidence.is_tool_sourced(e["finding"])]


def _tool_verdict_out_file(review_root, queue_id):
    """Where a tool finding's advisor verdict lands: verdicts/<queue_id>.json --
    the SAME directory the cell verdict bundles use, but a single-verdict file
    keyed by queue_id (synthesize's evidence.load_verdicts_detailed picks it up;
    load_verdict_bundles skips it as not-a-bundle)."""
    return os.path.abspath(runio._pano(review_root, "verdicts", "%s.json" % queue_id))


def _tool_verdict_done(review_root, queue_id):
    """A tool-finding verdict is settled once verdicts/<queue_id>.json parses as
    a single-verdict file synthesize will load -- a dict carrying a valid verdict
    value. Mirrors evidence.load_verdicts_detailed's own acceptance test (tolerant
    parse, VERDICT_VALUES), so 'done' means 'synthesize will match it', and a
    truncated/garbled return re-dispatches rather than reading as done."""
    path = _tool_verdict_out_file(review_root, queue_id)
    try:
        with open(path, encoding="utf-8") as fh:
            data = evidence.load_json_tolerant(fh.read())
    except (OSError, ValueError):
        return False
    return (isinstance(data, dict)
            and str(data.get("verdict", "")).upper() in evidence.VERDICT_VALUES)


def _tool_verify_entry(review_root, manifest, queue_id, finding, host):
    """One per-finding advisor (advisor.md) dispatch entry for a tool finding.

    Return-persist by construction: advisor.md is Read/Grep/Glob only (no Write),
    so the advisor RETURNS a verdict JSON and the HOST writes it to out_file --
    `delivery: return_json` flags that, exactly like the scout/setup-scan
    return-persist entries. Reuses render_prompt('advisor.md', {claim_json}) and
    the repo-root pin from dispatch.render_advisor_prompts. NO run_id echo line:
    the driver writes no verify-queue.json, so synthesize's verdict_run_id is None
    and match_verdict binds on the finding_id echo alone."""
    out_file = _tool_verdict_out_file(review_root, queue_id)
    # #run8 ARC-F2A: confine the tool finding's location too -- _tool_verify_entry
    # embeds the whole finding dict verbatim into the unconfined advisor's claim.
    safe_finding = finding
    if isinstance(finding, dict) and isinstance(finding.get("location"), dict):
        safe_finding = dict(finding)
        safe_finding["location"] = _confine_claim_location(review_root, finding["location"])
    claim = json.dumps(safe_finding, indent=2, ensure_ascii=False)
    prompt = dispatch.render_prompt("advisor.md", {"claim_json": claim}, host)
    prompt = ("Repo root: %s\nEvery relative path in the claim below resolves "
              "against this root -- read files THERE, never in your session's "
              "default checkout.\n\n%s" % (os.path.abspath(review_root), prompt))
    enforced = host == "claude"
    return {"id": "verify-tool-%s" % queue_id,
            "agent": dispatch.registered_agent_name("advisor.md") if enforced else None,
            "enforced": enforced, "model": None, "prompt": prompt,
            "out_file": out_file, "delivery": "return_json"}


def _verify_tools_execute(review_root, manifest, host):
    """Emit the tool-finding verify checkpoint when any tool finding still lacks
    a verdict; None when every tool finding is verified (or none exist). Runs as
    a round of the verify phase after primary/backup cells."""
    pending = [(qid, f) for qid, f in _tool_verify_queue(review_root, manifest)
               if not _tool_verdict_done(review_root, qid)]
    if not pending:
        return None
    entries = [_tool_verify_entry(review_root, manifest, qid, f, host)
               for qid, f in pending]
    req = requests.write_dispatch_request(review_root, manifest["run_id"], "verify",
                                 "tools", entries)
    return engine.PhaseResult(kind="checkpoint", checkpoint="verify", group="tools",
                       dispatch_request=req,
                       message="verify: %d tool advisor(s)" % len(entries))


def _verify_tools_done(review_root, manifest):
    return all(_tool_verdict_done(review_root, qid)
               for qid, _f in _tool_verify_queue(review_root, manifest))


def synthesize_done(review_root, manifest):
    # §5.1: gate on the durable tag-named report, not the convenience symlink, so
    # resume never depends on symlink creation having succeeded.
    return runio._json_parses(runio._report_out(review_root))


def _collect_host_usage(review_root, manifest):
    """Write `<run_dir>/usage.json` just before synthesize, so meta.cost.tokens
    is populated without the operator having to remember (#calibration-1).

    The D4 channel is host-supplied by design: the driver is a subprocess and
    cannot see per-dispatch token usage. collect_usage.py reads it out of the
    Claude host's own transcripts -- but it only lands in the report if it runs
    BETWEEN the last dispatch and synthesize. On the first external calibration
    run that ordering was left to the operator, who got it wrong, and the run
    reported `tokens: null` until synthesize was re-run by hand.

    Best-effort and non-fatal in every direction: a non-claude host, no
    transcript, a crash, or a timeout all leave usage.json absent, and
    synthesize's `load_run_usage` then reports null exactly as before. An
    absent number stays absent -- this must never be able to fail a run, and
    must never invent a figure.
    """
    if manifest.get("host") != "claude":
        return None          # other hosts write their own usage.json, or none
    if os.path.isfile(runio._pano(review_root, "usage.json")):
        return None          # already collected (resume) -- never overwrite
    # dirname of a non-top-level artifact IS the per-run folder -- the same
    # directory synthesize resolves as run_dir (dirname of --groups).
    run_dir = os.path.dirname(runio._pano(review_root, "usage.json"))
    # --project-dir locates the HOST SESSION's transcript, so it is the directory
    # the session runs in -- NOT the review root. #calibration-2: these are the
    # same path for a self-scan (every run 1-10), so passing review_root worked
    # until the first EXTERNAL target, where it resolved a transcript slug for
    # the scanned repo, found nothing, and silently reported `tokens: null`
    # again -- reintroducing exactly the gap this wiring removed. The driver
    # process is launched from the session cwd (only its children are chdir'd
    # to review_root), so getcwd() here is that directory.
    # #calibration-4 (gotify): getcwd() is only the session dir when the operator
    # launched the driver FROM it (`driver run <target>`). The equally natural
    # `cd <target> && driver run .` makes getcwd() the scanned repo again, which
    # resolves a transcript slug that does not exist -- rc 1, and meta.cost.tokens
    # silently stays null on a 612M-token run. The driver cannot infer the session
    # root, so let the operator state it; getcwd() remains the default because it
    # is right for the documented invocation.
    session_dir = manifest.get("session_dir") or os.getcwd()
    cmd = [sys.executable, runio._script("collect_usage.py"),
           "--run-dir", run_dir,
           "--project-dir", session_dir]
    # Pass the window explicitly. run-manifest.json is a _TOP_LEVEL artifact, so
    # it does NOT live in run_dir and collect_usage's own manifest lookup would
    # miss it -- falling back to counting the entire session transcript, which
    # bills every earlier run in the same session to this one. The driver holds
    # the manifest, so it is the authoritative source for the start stamp.
    created = manifest.get("created")
    if created:
        cmd += ["--since", created]
    # #1494: bound the window's END too. A floor alone only makes the number
    # reproducible until the NEXT run in the same session -- re-collecting an
    # earlier run afterwards silently bills it for the later run's tokens (fzf
    # read 0.443 B in-run and 0.751 B once ripgrep had run in the same session).
    # Usage is collected at synthesize, after every agent has finished, so "now"
    # is this run's true ceiling and freezes the ledger permanently.
    cmd += ["--until", datetime.datetime.now(datetime.timezone.utc)
            .strftime("%Y-%m-%dT%H:%M:%SZ")]
    try:
        proc = runio._run_child(cmd, review_root, "usage", timeout=120)
    except runio.DriverError as exc:
        print("driver: usage collection skipped (%s); meta.cost.tokens stays null"
              % exc, file=sys.stderr, flush=True)
        return None
    if proc.returncode != 0:
        # rc 1 is the documented "no transcript found, wrote nothing" path. Name
        # the directory that was searched and the flag that changes it: the most
        # likely cause is that it is the scanned repo rather than the session,
        # and that is not deducible from "produced nothing".
        print("driver: usage collection produced nothing (rc %d); "
              "meta.cost.tokens stays null. Searched host transcripts for "
              "project-dir %s -- if that is the SCANNED REPO rather than the "
              "directory your host session runs in, re-run with "
              "--session-dir <session root> (or from that directory)."
              % (proc.returncode, session_dir),
              file=sys.stderr, flush=True)
    return proc


def synthesize_execute(review_root, manifest):
    # #5.0-16 fallback: guarantee both integrity artifacts exist once, after
    # review and before synthesize, even when the verify phase was vacuously
    # done (no engaged cell -> verify_execute never ran, so no agent ran either
    # -- the snapshot here still captures authentic post-review bytes). Both are
    # idempotent no-ops when review_execute/verify_execute already wrote them.
    requests._write_driver_plan(review_root, manifest)
    requests._snapshot_review_out_files(review_root, manifest)
    _collect_host_usage(review_root, manifest)
    findings = sorted(_glob.glob(runio._pano(review_root, "findings-*.json")))
    verdicts_dir = runio._pano(review_root, "verdicts")
    os.makedirs(verdicts_dir, exist_ok=True)   # empty in P3 (verify is a no-op)
    report = runio._report_out(review_root)   # §5.1: durable, top-level, tag-named
    flags = manifest.get("flags") or {}
    cmd = [sys.executable, runio._script("synthesize.py"),
           "--out", report,
           "--groups", runio._pano(review_root, "groups.json"),
           "--security", manifest.get("security_mode", "standard"),
           "--run-id", manifest.get("run_id") or "",   # §5.1: X0X report provenance
           "--verdicts-dir", verdicts_dir]
    if (runio._load_json(runio._pano(review_root, "tools-ran.json")) or {}).get("ran"):
        cmd += ["--tools-dir", runio._pano(review_root, "tools")]
        # Pin synthesize's fixture posture to the tool-verify queue's
        # (#5.0-03): both must ingest the SAME tool findings or synthesize
        # could queue one the driver never dispatched a verdict for. Also
        # closes the latent gap where the manifest captured include_fixtures
        # but synthesize_execute never forwarded it.
        if _tools_include_fixtures(manifest):
            cmd += ["--include-fixtures"]
    for flag, key in (("--fail-on", "fail_on"), ("--severity", "severity"),
                      ("--gate-scope", "gate_scope")):
        if flags.get(key):
            cmd += [flag, str(flags[key])]
    diff_hunks = runio._pano(review_root, "diff-hunks.json")
    if os.path.isfile(diff_hunks):
        cmd += ["--diff-hunks", diff_hunks]
    if flags.get("diff_context") is not None:
        cmd += ["--diff-context", str(flags["diff_context"])]
    cmd += findings
    proc = runio._run_child(cmd, review_root, "synthesize")
    # A failing gate exits non-zero but still writes the report — that is a valid
    # outcome, not a driver error. Only an ABSENT report is a failure.
    if not runio._json_parses(report):
        raise runio.DriverError("synthesize produced no report.json (rc=%s): %s"
                          % (proc.returncode, runio._redact_output((proc.stderr or proc.stdout)[:400])))
    # §5.1: point the flat compat paths at the latest tag-named report, so every
    # existing reader of report.json / report.json.html resolves it unchanged, and
    # refresh runs/latest. The tag-named files are the durable top-level outputs;
    # the run folder can be cleared without touching them.
    tag = runio._run_tag(review_root)
    if tag:
        try:   # compat symlinks are best-effort; the tag-named report is authoritative
            runio._relink(runio._pano(review_root, "report.json"), f"{tag}-report.json")
            if os.path.exists(f"{report}.html"):
                runio._relink(runio._pano(review_root, "report.json.html"),
                        f"{tag}-report.json.html")
        except OSError:
            pass
        runio._ensure_run_symlinks(review_root)
    return engine.PhaseResult(kind="advanced", message="synthesize: report.json written")


# #run9 OPS-E1A: sentinel written when the run-start baseline probe FAILS
# (timeout/error/unexpected non-zero) -- distinct from a legitimately non-git
# target (no baseline at all). _tree_delta turns this into a fail-CLOSED integrity
# violation at validate, so a DoS'd/hung git probe can no longer silently disable
# the redteam clean-tree guard by reading as a clean tree that was never verified.
_TREE_BASELINE_PROBE_FAILED = "#panopticon:baseline-probe-failed\n"


def _write_probe_failed_baseline(baseline):
    os.makedirs(os.path.dirname(baseline), exist_ok=True)
    with runio._open_w_nofollow(baseline) as fh:
        fh.write(_TREE_BASELINE_PROBE_FAILED)
    return baseline


def capture_tree_baseline(review_root, runner=subprocess.run):
    """Snapshot the clean-tree baseline once (run start). Returns None (no
    baseline) for a legitimately non-git target -- the guard is N/A. A git-status
    PROBE FAILURE (timeout/error/unexpected non-zero) is NOT the same as non-git:
    it records a sentinel (loudly) so validate fails CLOSED rather than silently
    certifying a tree it never established a reference for (#run9 OPS-E1A)."""
    baseline = runio._pano(review_root, "tree-baseline.txt")
    if os.path.exists(baseline):
        return baseline
    try:
        proc = runner(["git", "-C", review_root, "status", "--porcelain", "-z"],
                      capture_output=True, text=True, timeout=15)
    except (subprocess.SubprocessError, OSError) as exc:
        print("driver: clean-tree baseline probe FAILED (%s); the integrity guard "
              "will fail closed at validate" % exc, file=sys.stderr, flush=True)
        return _write_probe_failed_baseline(baseline)
    if proc.returncode != 0:
        if "not a git repository" in (proc.stderr or "").lower():
            return None                              # non-git target: guard is N/A
        print("driver: clean-tree baseline probe exited %s (%s); the integrity guard "
              "will fail closed at validate"
              % (proc.returncode, (proc.stderr or "").strip()[:200]),
              file=sys.stderr, flush=True)
        return _write_probe_failed_baseline(baseline)
    os.makedirs(os.path.dirname(baseline), exist_ok=True)
    with runio._open_w_nofollow(baseline) as fh:
        fh.write(proc.stdout)
    return baseline


def _porcelain_z_records(output):
    """Parse `git status --porcelain -z` into a set of (XY, paths) records. Paths
    are RAW -- `-z` disables core.quotePath, so a non-ASCII name is emitted
    verbatim between NULs instead of C-quoted (`".panopticon/\\303\\251.py"`),
    which the old line-split mis-flagged. A rename/copy (X in R/C) carries BOTH
    endpoints: the entry's own (new) path plus the NUL-separated original path
    that immediately follows it (#1033/SEC-1)."""
    tokens = output.split("\0")
    records = set()
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if not tok:
            i += 1
            continue
        xy, path = tok[:2], tok[3:]
        if xy[:1] in ("R", "C") and i + 1 < len(tokens):
            records.add((xy, (path, tokens[i + 1])))   # (new, original)
            i += 2
        else:
            records.add((xy, (path,)))
            i += 1
    return records


def _outside_panopticon(path):
    """First path component is not `.panopticon` (a real boundary check:
    '.panopticon-evil.py' is NOT under .panopticon/)."""
    return path.split("/", 1)[0] != ".panopticon"


def _tree_delta(review_root, runner):
    """NEW porcelain records (vs. baseline) that touch a path outside
    .panopticon/. Empty when there is no baseline (non-git) — nothing to compare.
    A rename is checked on BOTH endpoints (#1033/SEC-1): a rename moving a real
    file INTO .panopticon/ still changed the outside tree via its source, which
    the old destination-only check silently missed."""
    try:
        with open(runio._pano(review_root, "tree-baseline.txt"), encoding="utf-8") as fh:
            raw = fh.read()
    except OSError:
        return []                                    # no baseline (non-git) -> nothing to compare
    if raw == _TREE_BASELINE_PROBE_FAILED:
        # #run9 OPS-E1A: the run-start baseline probe failed, so no clean-tree
        # reference exists -- the tree CANNOT be certified clean. Fail closed.
        return ["clean-tree baseline was never captured (git-status probe failed "
                "at run start); tree integrity cannot be certified"]
    baseline = _porcelain_z_records(raw)
    try:
        proc = runner(["git", "-C", review_root, "status", "--porcelain", "-z"],
                      capture_output=True, text=True, timeout=15)
        if proc.returncode != 0:
            # #run9 OPS-E1A: a baseline exists but the verification probe failed --
            # we can't confirm the tree is unchanged, so fail closed, never []-clean.
            return ["clean-tree verification git-status exited %s; tree integrity "
                    "cannot be certified" % proc.returncode]
    except (subprocess.SubprocessError, OSError) as exc:
        return ["clean-tree verification git-status failed (%s); tree integrity "
                "cannot be certified" % exc]
    new = _porcelain_z_records(proc.stdout) - baseline
    return sorted("%s %s" % (xy, " -> ".join(paths)) for xy, paths in new
                  if any(_outside_panopticon(p) for p in paths))


def validate_done(review_root, manifest):
    data = runio._load_json(runio._pano(review_root, "validate.json"))
    return (isinstance(data, dict) and data.get("run_id") == manifest.get("run_id")
            and data.get("tree_clean") is True)


def validate_execute(review_root, manifest, runner=subprocess.run):
    delta = _tree_delta(review_root, runner)
    # The PR worktree (when review_root IS the worktree) is released by run()
    # AFTER the run completes, NOT here: releasing mid-machine would delete the
    # review root (report.json + manifest) and break cursor derivation. (Ruling A)
    runio._write_json(runio._pano(review_root, "validate.json"),
                {"schema_version": 1, "run_id": manifest["run_id"],
                 "tree_clean": not delta, "unexpected_changes": delta})
    if delta:
        raise runio.DriverError("validate: reviewer side effects outside .panopticon/: "
                          + "; ".join(delta[:10]))
    return engine.PhaseResult(kind="advanced", message="validate: clean tree")


def _finalize_worktree(review_root, manifest):
    """On a completed --pr run, review_root IS the disposable worktree. Surface
    report.json to the caller's target .panopticon/ BEFORE releasing the worktree
    so the deliverable survives disposal (spec §4: no leak + report available).
    Best-effort surface; release is tolerant. No-op when there is no worktree."""
    worktree = manifest.get("worktree")
    if not worktree:
        return
    target = manifest.get("target") or review_root
    tag = run_manifest.run_tag(manifest)
    src_dir = os.path.join(review_root, ".panopticon")
    dst_dir = os.path.join(target, ".panopticon")
    # §5.1: surface the durable, top-level, tag-named outputs (report + optional
    # split part + html) so the caller's report is complete and self-consistent even
    # when split, then re-link report.json there. Falls back to a flat report.json
    # copy if there is no tag (no manifest — should not happen post-run).
    # #run7 OPS-E1A: surface EVERY durable tag-named artifact, not just part2 --
    # a split report (run-7 produced 4 parts + discarded + x0x) otherwise loses
    # part3+ on worktree release.
    if tag:
        names = sorted(os.path.basename(p) for p in
                       _glob.glob(os.path.join(src_dir, f"{tag}-report*.json")))
        names.append(f"{tag}-report.json.html")
    else:
        names = ["report.json"]
    failed = []
    for name in names:
        src, dst = os.path.join(src_dir, name), os.path.join(dst_dir, name)
        if os.path.realpath(src) == os.path.realpath(dst) or not os.path.isfile(src):
            continue
        try:
            os.makedirs(dst_dir, exist_ok=True)
            shutil.copyfile(src, dst)
        except OSError as e:
            failed.append((name, e))   # #run7 OPS-E1A: no longer silently swallowed
    if tag and os.path.isfile(os.path.join(dst_dir, f"{tag}-report.json")):
        try:
            runio._relink(os.path.join(dst_dir, "report.json"), f"{tag}-report.json")
            if os.path.isfile(os.path.join(dst_dir, f"{tag}-report.json.html")):
                runio._relink(os.path.join(dst_dir, "report.json.html"),
                        f"{tag}-report.json.html")
        except OSError:
            pass
    # #run7 OPS-E1A: the worktree is the ONLY other copy of the report. If ANY
    # artifact failed to surface, releasing it (git worktree remove --force) would
    # destroy the deliverable irrecoverably while run() still returns
    # status:complete. Keep the worktree and fail LOUD instead of silent loss.
    if failed:
        detail = "; ".join("%s (%s)" % (n, e) for n, e in failed)
        print("driver: FAILED to surface %d report artifact(s) to %s: %s -- KEEPING "
              "the worktree %s so the deliverable is recoverable (copy the report out, "
              "then `git -C %s worktree remove --force %s`)."
              % (len(failed), dst_dir, detail, worktree, target, worktree),
              file=sys.stderr, flush=True)
        return
    diff_map.release_worktree(worktree, repo=target)


SETUP_MANIFEST = "setup-manifest.json"


def _setup_manifest_path(review_root):
    return runio._pano(review_root, SETUP_MANIFEST)


def load_setup_manifest(review_root):
    return runio._load_json(_setup_manifest_path(review_root))


def _read_text(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _setup_scan_entry(review_root, prompt):
    """One return-persist dispatch entry for the read-only setup-scan agent
    (mirrors _scout_entry): the host dispatches it, gets proposal JSON back, and
    persists it to out_file.

    Unlike scout/panel/advisor roles, setup-scan is NEVER enforced: it is not in
    dispatch.ROLE_FILES, so no `panopticon-setup-scan` shell is ever registered
    for any host — dispatching it as "enforced" would ask the host to invoke a
    subagent that doesn't exist. It is read-only + return-persist by template
    tool_policy (Read/Grep/Glob only), so a plain general-purpose dispatch is
    sufficient and safe.
    """
    return {"id": "setup-scan",
            "agent": None,
            "enforced": False,
            "model": None,
            "prompt": prompt,
            "out_file": os.path.abspath(runio._pano(review_root, "setup-proposal.json"))}


def scan_done(review_root, manifest):
    return (runio._json_parses(runio._pano(review_root, "setup-proposal.json"))
            or runio._json_parses(runio._pano(review_root, "setup-complete.json")))


def scan_execute(review_root, manifest):
    """Provision + render the scan brief -> setup-scan checkpoint (vocab present);
    or flat-seed + readiness + a fallback-complete marker (vocab absent, Task 3)."""
    host = manifest.get("host", "claude")
    prov = setup_flow.provision(review_root)
    note = prov.get("gitignore_note")   # #1135: groups.yml needs `git add -f`
    vocab, present = setup_flow.load_bundled_vocabulary(manifest.get("vocabulary_path"))
    if not present:
        return _scan_fallback(review_root, manifest, host, note=note)   # Task 3
    # 5.2 stage 1: the spine is computed once, with the sizes the manifest
    # pinned, persisted for the record and rendered into the brief.
    spine = setup_flow.build_spine(review_root, max_per_group=manifest.get("max_per_group"),
                                   max_groups=manifest.get("max_groups"))
    setup_flow.write_spine(review_root, spine)
    layers, _ = setup_flow.load_bundled_layers()
    brief_path = setup_flow.render_scan_brief(review_root, vocab, layers=layers, spine=spine)
    entry = _setup_scan_entry(review_root, _read_text(brief_path))
    req = requests.write_dispatch_request(review_root, manifest["run_id"], "scan", None, [entry])
    msg = "setup-scan checkpoint" + ((" — " + note) if note else "")
    return engine.PhaseResult(kind="checkpoint", checkpoint="scan", group=None,
                       dispatch_request=req, message=msg)


def ingest_done(review_root, manifest):
    return (os.path.isfile(runio._pano(review_root, "groups.yml.draft"))
            or runio._json_parses(runio._pano(review_root, "setup-complete.json")))


def ingest_execute(review_root, manifest):
    res = setup_flow.ingest_proposal(review_root,
                                     max_per_group=manifest.get("max_per_group"),
                                     max_groups=manifest.get("max_groups"))
    if not res["ok"]:
        raise runio.DriverError("ingest: " + "; ".join(res["errors"]))
    return engine.PhaseResult(kind="advanced",
                       message="setup: draft written %s; report %s"
                       % (res["draft"], res["report_path"]))


SETUP_PHASES = (
    engine.Phase("scan", "checkpoint", scan_done, scan_execute),
    engine.Phase("ingest", "deterministic", ingest_done, ingest_execute),
)


_SETUP_ARTIFACTS = ("setup-scan-brief.md", "setup-spine.json", "setup-proposal.json",
                    "groups.yml.draft", "setup-report.md", "setup-report.json",
                    "setup-complete.json", SETUP_MANIFEST)


def _clear_setup_artifacts(review_root):
    """Remove derived setup artifacts + the setup-manifest for --reset. NEVER
    touches the committed groups.yml."""
    for name in _SETUP_ARTIFACTS:
        try:
            os.remove(runio._pano(review_root, name))
        except OSError:
            pass


def _scan_fallback(review_root, manifest, host, note=None):
    """Vocab-absent path (parity with orchestrator.run_setup): flat top-dir seed
    + readiness gate, then a fallback-complete marker so both setup phases'
    done-predicates are satisfied -> run_engine completes without a checkpoint
    and without entering ingest."""
    path, created, names = setup_flow.seed_flat_manifest(review_root)
    checks = setup_flow.readiness(review_root, host=host)
    gaps = [c[0] for c in checks if c[1] is False]
    runio._write_json(runio._pano(review_root, "setup-complete.json"), {
        "schema_version": 1,
        "mode": "fallback", "seed": path, "created": created, "groups": names,
        "readiness": [[c[0], c[1], c[2]] for c in checks],
        "gaps": gaps, "run_id": manifest["run_id"]})
    msg = ("setup: vocab-absent fallback — flat seed %s; readiness %s"
           % (path, "OK" if not gaps else "gaps: " + ", ".join(gaps)))
    if note:   # #1135: surface the "groups.yml needs `git add -f`" note
        msg += " — " + note
    return engine.PhaseResult(kind="advanced", message=msg)


def _drop_stale_fallback_marker(review_root):
    """A vocab-absent run wrote a mode:"fallback" setup-complete.json. Once the
    vocabulary is available again, that marker is stale — a real scan should
    supersede the flat seed. Remove it so the engine re-scans (self-healing; no
    --reset needed). No-op when there is no fallback marker or vocab is still
    absent."""
    marker = runio._load_json(runio._pano(review_root, "setup-complete.json"))
    if not (isinstance(marker, dict) and marker.get("mode") == "fallback"):
        return
    _vocab, present = setup_flow.load_bundled_vocabulary(None)
    if present:
        try:
            os.remove(runio._pano(review_root, "setup-complete.json"))
        except OSError:
            pass


def run_setup_flow(args, runner=subprocess.run, phases=SETUP_PHASES):
    """The `driver setup` entrypoint: a separate two-phase flow (NOT a run
    phase). Resolves the review root, pins a minimal setup-manifest once, and
    advances scan->ingest through run_engine. Writes a draft; the owner reviews
    and commits it."""
    review_root, _wt, _pr = runio.resolve_review_root(args.target, runner=runner)
    if getattr(args, "reset", False):
        _clear_setup_artifacts(review_root)               # Task 3
    _drop_stale_fallback_marker(review_root)
    manifest = load_setup_manifest(review_root)
    if manifest is not None and runio._foreign_manifest(
            manifest, review_root, _setup_manifest_path(review_root)):
        # #run7/#run8 AGT-C1A: a target repo can force-commit its own
        # .panopticon/setup-manifest.json (gitignored but `git add -f`-able) to
        # preset an attacker-chosen `vocabulary_path` -- which setup_flow reads and
        # embeds verbatim into the classifier scan brief -- or `host`. Mirror the
        # run-manifest guard (#1093): a manifest that is git-tracked in this tree,
        # or whose stamped review_root isn't THIS checkout, is not a legitimate
        # resume state; discard and rebuild from args.
        print("driver: ignoring foreign setup-manifest.json (stamped review_root "
              "%r != %r)" % (manifest.get("review_root"),
                             os.path.abspath(review_root)),
              file=sys.stderr, flush=True)
        manifest = None
    if manifest is None:
        # 5.2 size policy, pinned at scan time so the brief's arithmetic and
        # the ingest's layers agree (anti-drift, like the run manifest's
        # max_per_group). CLI > config.json, resolved HERE so a config edit
        # between scan and ingest cannot move the numbers; None = default.
        overrides = setup_flow.config_overrides(review_root)
        manifest = {"schema_version": 1, "run_id": run_manifest.new_run_id(),
                    "review_root": os.path.abspath(review_root),
                    "target": os.path.abspath(args.target),
                    "host": args.host or runio._DEFAULTS["host"],
                    "vocabulary_path": None,
                    "max_per_group": (getattr(args, "max_per_group", None)
                                      or overrides["max_per_group"]),
                    "max_groups": getattr(args, "max_groups", None) or overrides["max_groups"]}
        runio._write_json(_setup_manifest_path(review_root), manifest)
    try:
        result = engine.run_engine(review_root, manifest, phases)
    except runio.DriverError as exc:
        return runio._error_status(str(exc))
    if result.get("status") == "complete":
        if os.path.isfile(runio._pano(review_root, "groups.yml.draft")):
            result["message"] = ("setup complete — read .panopticon/setup-report.md, "
                                 "review .panopticon/groups.yml.draft, move it to "
                                 ".panopticon/groups.yml, and commit")
        else:
            msg = ("setup complete — vocab-absent fallback seeded a flat "
                  ".panopticon/groups.yml; review, edit, and commit it")
            gaps = (runio._load_json(runio._pano(review_root, "setup-complete.json")) or {}).get("gaps") or []
            if gaps:
                msg += (" — readiness gaps: %s (fix before running a review)"
                       % ", ".join(gaps))
            result["message"] = msg
    return result


_RESET_GLOBS = ("groups.json", "coverage-*.json", "scout-*.json", "tools-ran.json",
                "validate.json",
                "report.json", "dispatch-request.json", "tree-baseline.txt",
                "verify-queue.json", "findings-*.json",
                # #5.0-07: stale delta artifacts must not survive a --reset and
                # silently delta-scope (or content-check) the next run.
                # #5.0-16: the driver's own dispatch plan clears too, so a
                # --reset run re-declares cells from fresh coverage.
                "diff-hunks.json", "out-file-hashes.json",
                "dispatch-plan-driver.json")


PHASES = (
    engine.Phase("discovery", "deterministic", discovery.discovery_done, discovery.discovery_execute),
    engine.Phase("coverage", "mixed", coverage.coverage_done, coverage.coverage_execute),
    engine.Phase("tools", "deterministic", tools.tools_done, tools.tools_execute),
    engine.Phase("review", "checkpoint", review_done, review_execute),
    engine.Phase("verify", "mixed", verify_done, verify_execute),
    engine.Phase("synthesize", "deterministic", synthesize_done, synthesize_execute),
    engine.Phase("validate", "deterministic", validate_done, validate_execute),
)


def _cli_flags(args):
    if getattr(args, "tools", False) and getattr(args, "no_tools", False):
        raise ValueError("cannot specify both --tools and --no-tools")
    tools = False if getattr(args, "no_tools", False) else (
        True if getattr(args, "tools", False) else None)
    values = {"fail_on": getattr(args, "fail_on", None),
              "severity": getattr(args, "severity", None),
              "gate_scope": getattr(args, "gate_scope", None),
              "diff_context": getattr(args, "diff_context", None),
              "tools": tools,
              "include_fixtures": True if getattr(args, "include_fixtures", False) else None,
              "max_per_group": getattr(args, "max_per_group", None)}
    return {k: values.get(k) for k in run_manifest._FLAG_KEYS}


def _scope_from_args(args):
    """The {mode,target} scope implied by -f/-d/-g, or None if none was given
    (a bare re-invocation with no scope opinion — mirrors host/security_mode/
    base/flags: None never conflicts in conflicting_flags, and build_manifest
    defaults a None scope to {"mode":"repo","target":None} itself)."""
    if getattr(args, "scope_file", None):
        return {"mode": "file", "target": args.scope_file}
    if getattr(args, "scope_dir", None):
        return {"mode": "directory", "target": args.scope_dir}
    if getattr(args, "scope_group", None):
        return {"mode": "group", "target": args.scope_group}
    if getattr(args, "scope_changed", False):
        return {"mode": "changed", "target": None}
    if getattr(args, "scope_files", None):
        return {"mode": "files", "target": list(args.scope_files)}
    return None


def _clear_run_artifacts(review_root):
    """--reset: clear the current run's working folder (findings / verdicts /
    coverage / scouts / dispatch / ...) so a fresh run starts, while KEEPING the
    durable top-level tag-named report — reset reclaims the scratch, not the
    deliverable (§5.1). NEVER touches groups.yml (the committed matrix) or another
    run's folder/report. MUST run BEFORE the manifest is removed, so the tag still
    resolves; with no/corrupt manifest it degrades to the legacy flat sweep."""
    base = os.path.join(review_root, ".panopticon")
    tag = runio._run_tag(review_root)
    if tag:
        shutil.rmtree(os.path.join(base, "runs", tag), ignore_errors=True)
        # runs/latest now dangles (its target folder is gone) — drop the pointer;
        # report.json is left pointing at the kept durable report.
        try:
            os.remove(os.path.join(base, "runs", "latest"))
        except OSError:
            pass
    # Migration safety: sweep any legacy FLAT run artifacts a pre-5.1 run may have
    # left at top-level. The report.json SYMLINK points at the durable tag-named
    # report and is kept; only a STALE FLAT report.json (a real file — pre-5.1 or
    # a corrupt/orphaned state) is swept, preserving the I1 no-resume-on-stale-data
    # invariant. The tag-named reports themselves are never in _RESET_GLOBS.
    for pat in _RESET_GLOBS:
        for path in _glob.glob(os.path.join(base, pat)):
            if os.path.basename(path) == "report.json" and os.path.islink(path):
                continue
            try:
                os.remove(path)
            except OSError:
                pass
    for sub in ("tools", "verdicts"):
        shutil.rmtree(os.path.join(base, sub), ignore_errors=True)


def build_parser():
    parser = argparse.ArgumentParser(prog="driver")
    sub = parser.add_subparsers(dest="verb", required=True)
    # #1033: `next` was a silent, undifferentiated alias of `run` (run() is
    # already idempotent + resumes from disk), so it's removed rather than kept
    # as a confusing second spelling.
    for verb in ("run",):
        p = sub.add_parser(verb)
        p.add_argument("target", nargs="?", default=".")
        p.add_argument("--host", default=None, choices=["claude", "generic", "gemini"])
        p.add_argument("--security", default=None, choices=["standard", "redteam"])
        p.add_argument("--base", default=None)
        p.add_argument("--pr", type=int, default=None)
        p.add_argument("--reset", action="store_true")
        p.add_argument("--fail-on", default=None)
        p.add_argument("--severity", default=None)
        p.add_argument("--gate-scope", default=None)
        p.add_argument("--diff-context", type=int, default=None)
        tools_group = p.add_mutually_exclusive_group()
        tools_group.add_argument("--tools", action="store_true")
        tools_group.add_argument("--no-tools", action="store_true")
        p.add_argument("--include-fixtures", action="store_true")
        # The directory the HOST SESSION runs in, used only to locate its
        # transcripts for the cost ledger. Defaults to cwd (#calibration-4).
        p.add_argument("--session-dir", default=None)
        # Files per review subgroup. Fewer, larger cells cost less in total
        # (per-cell overhead is amortized) at the price of a wider lens per
        # reviewer. Anti-drift: use --reset to change it on an existing run.
        p.add_argument("--max-per-group", type=_positive_int, default=None)
        scope = p.add_mutually_exclusive_group()
        scope.add_argument("-f", "--file", dest="scope_file", default=None)
        scope.add_argument("-d", "--directory", dest="scope_dir", default=None)
        scope.add_argument("-g", "--group", dest="scope_group", default=None)
        scope.add_argument("-c", "--changes", dest="scope_changed",
                           action="store_true")
        scope.add_argument("--files", dest="scope_files", nargs="+", default=None)
    sp = sub.add_parser("setup")
    sp.add_argument("target", nargs="?", default=".")
    sp.add_argument("--host", default=None, choices=["claude", "generic", "gemini"])
    sp.add_argument("--reset", action="store_true")
    # 5.2 size policy (spec §5.3): files per dispatch unit and the leaf
    # ceiling. Unset = .panopticon/config.json (max_per_group / max_groups),
    # else the defaults (48; max(4, 2 x ceil(code_files / cap))).
    sp.add_argument("--max-per-group", type=_positive_int, default=None)
    sp.add_argument("--max-groups", type=_positive_int, default=None)
    return parser


def _positive_int(text):
    """argparse type for the size flags: `0` would silently fall through to
    the config/default and a negative cap breaks the ceiling formula."""
    try:
        value = int(text)
    except ValueError:
        value = 0
    if value < 1:
        raise argparse.ArgumentTypeError("expected a positive integer, got %r" % text)
    return value


def run(args, runner=subprocess.run, phases=PHASES):
    # #5.0-14: resolving the review root can fail loudly for a --pr run (gh
    # auth/network, a bad PR number, worktree acquisition) — keep it inside the
    # status protocol instead of letting a raw RuntimeError escape run().
    try:
        review_root, worktree, pr_base = runio.resolve_review_root(
            args.target, base=args.base, pr=args.pr, runner=runner)
    except (RuntimeError, ValueError, OSError) as exc:
        return runio._error_status("could not resolve review root: %s" % exc)
    if args.pr is not None:
        # A PR is a changed-files delta by definition. manifest["base"] holds the
        # user's EXPLICIT override only (anti-drift key); the gh-detected PR base
        # flows separately via manifest["pr_base"] -> orchestrator --pr-base, so
        # resolve_base applies its origin/<base> preference (#947 / spec §4 L51).
        base = args.base
        scope = {"mode": "changed", "target": None}
    else:
        base = args.base
        scope = _scope_from_args(args)
    # #5.0-09: verify .panopticon is a real in-repo directory BEFORE any write or
    # delete under it. A committed .panopticon symlink in a hostile target (or PR
    # fork checkout) would otherwise redirect the driver's own reset/manifest/
    # baseline writes outside the repo, because discovery's artifact_root guard
    # runs only later, inside the discovery subprocess.
    try:
        plan_contract.artifact_root(review_root)
    except ValueError as exc:
        if worktree:
            diff_map.release_worktree(worktree, repo=args.target)
        return runio._error_status("unsafe artifact root: %s" % exc)
    if args.reset:
        _clear_run_artifacts(review_root)   # §5.1: resolve the tag before the manifest goes
        run_manifest.reset_run(review_root)
    manifest = run_manifest.load_manifest(review_root)
    if runio._foreign_manifest(manifest, review_root, run_manifest.manifest_path(review_root)):
        # #1093: a target-committed run-manifest.json (foreign review_root) could
        # preset flags to skip tools / force gate:PASS. Drop it and rebuild from
        # the real CLI args, exactly like a corrupt manifest below.
        print("driver: ignoring foreign run-manifest.json (stamped review_root "
              "%r != %r)" % (manifest.get("review_root"), os.path.abspath(review_root)),
              file=sys.stderr, flush=True)
        manifest = None
    if manifest is None:
        # I1: no manifest means no prior run should count — clear any stale
        # derived artifacts so done()-predicates never resume on another run's
        # data (a lost/corrupt manifest, a partially-failed reset, or a
        # pre-existing 4.x groups.json).
        # #5.0-13: load_manifest also returns None for a CORRUPT (present-but-
        # unparseable) manifest — remove it first so write_manifest (write-once)
        # can't raise an uncaught FileExistsError and wedge the run.
        _clear_run_artifacts(review_root)
        run_manifest.reset_run(review_root)
        manifest = run_manifest.build_manifest(
            target=args.target, review_root=review_root,
            host=args.host or runio._DEFAULTS["host"],
            security_mode=args.security or runio._DEFAULTS["security"],
            base=base, flags=_cli_flags(args), worktree=worktree,
            scope=scope, pr=args.pr, pr_base=pr_base)
        run_manifest.write_manifest(review_root, manifest)
    else:
        conflicts = run_manifest.conflicting_flags(
            manifest, host=args.host, security_mode=args.security,
            base=base, flags=_cli_flags(args), scope=scope, pr=args.pr)
        if conflicts:
            return runio._error_status("flag drift (use --reset to start over): "
                                 + "; ".join(conflicts))
    # In-memory only, and deliberately NOT a manifest field: it names where the
    # HOST SESSION runs, which is a property of this invocation rather than of
    # the run, and it feeds nothing but the cost-ledger transcript lookup. Not
    # persisted means it is also not an anti-drift key -- resuming from a
    # different session is normal and must not be reported as drift. A resume
    # that needs it simply passes it again (#calibration-4).
    if getattr(args, "session_dir", None):
        manifest["session_dir"] = os.path.abspath(args.session_dir)
    # #1: a bare re-invocation of an ALREADY-complete run matches every manifest
    # field (conflicting_flags treats a None incoming value as no-conflict), so it
    # would advance straight to "complete" and hand back a possibly-stale report as
    # though it were a fresh scan -- the worst failure mode for a review tool.
    # Refuse loudly and name --reset instead; the durable report stays on disk.
    # (Guarded by `not args.reset`: a --reset run just cleared its derived
    # artifacts, so it can never be already-complete at this point.)
    if not args.reset and engine._first_not_done(phases, review_root, manifest) is None:
        report = runio._pano(review_root, "report.json")
        loc = report if os.path.exists(report) else review_root
        return runio._error_status(
            "run already complete (report at %s) -- use `--reset` to start a new "
            "run" % loc)
    # §5.1: point runs/latest at the active run folder now that the manifest (hence
    # the tag) is established — so the pointer exists throughout the run, not just
    # after synthesize writes the report.
    runio._ensure_run_symlinks(review_root)
    # I2: capture the clean-tree baseline unconditionally and BEFORE the engine
    # runs. Idempotent (returns the existing baseline if present) -> no-op on a
    # normal resume, but self-heals a baseline that a mid-first-run interrupt
    # left missing (which had silently disabled the clean-tree guard).
    capture_tree_baseline(review_root, runner=runner)
    try:
        result = engine.run_engine(review_root, manifest, phases)
    except runio.DriverError as exc:
        return runio._error_status(str(exc))
    if result.get("status") == "complete":
        _finalize_worktree(review_root, manifest)
    return result


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.verb == "setup":
        return engine.emit_status(run_setup_flow(args))
    return engine.emit_status(run(args))


if __name__ == "__main__":
    sys.exit(main())
