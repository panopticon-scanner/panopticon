"""Phase 5 -- verify: cell, backup and tool verification (one phase, three flavours)."""
import glob as _glob
import json
import os

import scripts.dispatch as dispatch
import scripts.evidence as evidence
import scripts.ingest_tools as ingest_tools
import scripts.score_gate as score_gate
import scripts.synth.findings as findings_mod
from scripts import hosts
from . import engine
from . import runio
from . import coverage
from . import requests
from . import review


# #1521 (OPS-D1A): `_render_findings` embedded a whole cell into the advisor
# prompt with no cap, while the sibling tool-hits channel (review._TOOL_HITS_CAP)
# is capped at 40. A reviewer that floods findings -- a menu-code loop, or a
# redteam target engineered to provoke one -- inflated every verify prompt for
# that cell without bound.
#
# The fix is NOT to drop claims. _verify_cell_done requires every finding in the
# cell to be adjudicated, so a truncated prompt would burn the whole re-dispatch
# budget and then report a real gap. Oversized cells are CHUNKED across several
# advisor dispatches instead: bounded prompt, every claim still adjudicated.
_CELL_CLAIMS_CAP = 25

# The dominant size term within one claim is its free text. Bounding it keeps a
# prompt linear in claim COUNT alone, and leaves every field the advisor needs
# to act (id to echo, location to go read) untouched.
_CLAIM_DESC_CAP = 2000


def _cell_chunks(cell):
    """A cell's claims split into advisor-sized slices, in order (#1521).

    An empty cell yields one empty chunk, so callers still emit exactly one
    dispatch for it rather than none."""
    cell = list(cell or [])
    if len(cell) <= _CELL_CLAIMS_CAP:
        return [cell]
    return [cell[i:i + _CELL_CLAIMS_CAP]
            for i in range(0, len(cell), _CELL_CLAIMS_CAP)]


def _verify_out_file(review_root, group, domain, stage, part=0):
    suffix = "-backup" if stage == "backup" else ""
    # Part 0 keeps the established filename: existing runs, the backup reader
    # and synthesize's bundle scan all already know it.
    part_suffix = "" if not part else "-part%d" % part
    return os.path.abspath(runio._pano(review_root, "verdicts",
                                 "verdicts-%s-%s%s%s.json"
                                 % (group, domain, suffix, part_suffix)))


def _cell_verdicts(review_root, group, domain, stage, parts=1):
    """Every verdict on disk for this cell/stage, merged across its parts."""
    merged = []
    for part in range(max(1, parts)):
        data = runio._load_json(
            _verify_out_file(review_root, group, domain, stage, part))
        if isinstance(data, dict) and isinstance(data.get("verdicts"), list):
            merged.extend(v for v in data["verdicts"] if isinstance(v, dict))
    return merged


def _part_done(review_root, manifest, group, domain, stage, part, chunk):
    """One chunk's advisor answered it: bundle labeled, and (primary) every
    claim in THIS slice adjudicated somewhere in the cell's bundles."""
    if not _verify_bundle_labeled(review_root, manifest, group, domain,
                                  stage, part):
        return False
    if stage != "primary":
        return True
    merged = _cell_verdicts(review_root, group, domain, stage, part + 1)
    got = {str(v.get("finding_id")) for v in merged
           if v.get("finding_id") is not None}
    return {str(f["id"]) for f in chunk}.issubset(got)


def _cell_parts_complete(review_root, manifest, group, domain, stage, cell):
    """True when every part of this cell is answered.

    The union across parts is what makes chunking safe: a cell counts as
    answered only once all of its slices are."""
    return all(_part_done(review_root, manifest, group, domain, stage, part, chunk)
               for part, chunk in enumerate(_cell_chunks(cell or [])))

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

def _verify_bundle_labeled(review_root, manifest, group, domain, stage, part=0):
    """The verdict bundle exists, parses, and is labeled for THIS cell -- the
    advisor returned something coherent for it (vs no bundle, or an unloadable /
    mislabeled one). Separates an A2 reconciliation shortfall, which the bounded
    budget governs, from a first dispatch or an unloadable return, which keep the
    existing uncapped re-dispatch."""
    data = runio._load_json(
        _verify_out_file(review_root, group, domain, stage, part))
    if not (isinstance(data, dict) and isinstance(data.get("verdicts"), list)):
        return False
    meta = data.get("_panopticon") or {}
    return (meta.get("run_id") == manifest.get("run_id")
            and meta.get("domain") == domain and meta.get("group") == group
            and meta.get("stage", "primary") == stage)

def _verify_cell_done(review_root, manifest, group, domain, stage, cell=None):
    """Every claim this cell handed the advisor came back adjudicated.

    `cell` is the claim set that was dispatched: the review cell for primary,
    the backup ROUND'S OWN scope for backup (a severity-gated subset, so
    loading the review cell there would demand verdicts nobody was asked for).

    A2 (run-9): a labeled, parseable bundle is not "done" unless it actually
    adjudicated every finding the advisor was handed. An advisor RE-CODED a
    cell's findings -- a 4th TST-B1B while dropping a TST-B1A and a TST-B1C --
    so a 10-finding cell came back with 9 verdicts and 2 findings went silently
    unadjudicated. The bundle was accepted as done, the cell never
    re-dispatched, and the drop surfaced only as a quiet verdicts.unanswered:1
    that sank coverage_certified without naming a cause.

    #1521: the reconcile now spans the cell's PARTS, since an oversized cell is
    chunked across several advisor dispatches.
    """
    if cell is None:
        cell = review._load_cell_findings(review_root, manifest, group, domain)
    if _cell_parts_complete(review_root, manifest, group, domain, stage, cell):
        return True
    # Nothing usable on disk for the first part: never dispatched, or an
    # unloadable return. Keep the existing UNCAPPED re-dispatch for that.
    if not _verify_bundle_labeled(review_root, manifest, group, domain, stage):
        return False
    # Labeled but incomplete: re-dispatch (a chance to fix a transient re-code),
    # but BOUNDED -- once the budget is spent the gap is real and surfaces as
    # unanswered -> INCONCLUSIVE at synthesis, honest, rather than wedging.
    return _verify_attempts(review_root, group, domain, stage) >= _MAX_VERIFY_ATTEMPTS

def _capped_description(description):
    """One claim's free text, bounded and VISIBLY marked when cut (#1521).

    The advisor re-reads the cited code either way; what a truncated tail costs
    it is context, not the ability to adjudicate. Saying so in-band matters --
    an advisor that cannot see the cut would treat a severed sentence as the
    reviewer's whole argument."""
    text = str(description or "")
    if len(text) <= _CLAIM_DESC_CAP:
        return text
    return ("%s\n\n[truncated: %d of %d characters shown. Read the cited "
            "location for the rest.]"
            % (text[:_CLAIM_DESC_CAP], _CLAIM_DESC_CAP, len(text)))


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
             "description": _capped_description(f.get("description", ""))}
            for f in cell]
    return json.dumps(slim, indent=2)

def _verify_entry(review_root, manifest, group, domain, files, cell, host,
                  bundle, stage, part=0):
    file_list = runio._abs_file_list(review_root, files)
    out_file = _verify_out_file(review_root, group, domain, stage, part)
    prompt = dispatch.render_prompt("domain-advisor.md", {
        "domain": domain, "group": group, "file_list": file_list,
        "findings": _render_findings(review_root, cell), "menu": review._render_menu(bundle, domain),
        "criteria": review._render_criteria(bundle, domain),   # #1035
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
    enforced = hosts.declares(host, hosts.TOOL_POLICY_ENFORCED)
    return {"id": "verify-%s-%s-%s%s" % (group, domain, stage,
                                         "" if not part else "-part%d" % part),
            "agent": dispatch.registered_agent_name("domain-advisor.md") if enforced else None,
            "enforced": enforced, "model": None, "prompt": prompt, "out_file": out_file}

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
            cell = review._load_cell_findings(review_root, manifest, group, domain)
            if cell is None or not score_gate.should_engage_primary(cell):
                continue   # unreviewed, or below-gate: unverified + disclosed at synth
            if _verify_cell_done(review_root, manifest, group, domain, "primary"):
                continue
            # A2: a labeled-but-incomplete bundle already on disk means the advisor
            # returned a short/re-coded verdict set -- charge one attempt against
            # the bounded budget so an incomplete cell can't re-dispatch forever.
            if _verify_bundle_labeled(review_root, manifest, group, domain, "primary"):
                _bump_verify_attempts(review_root, group, domain, "primary")
            # #1521: an oversized cell is chunked; re-dispatch only the parts
            # that are still unanswered.
            pending.extend(
                (domain, chunk, part)
                for part, chunk in enumerate(_cell_chunks(cell))
                if not _part_done(review_root, manifest, group, domain,
                                  "primary", part, chunk))
        if pending:
            ngroups += 1
            all_entries.extend(
                _verify_entry(review_root, manifest, group, d, files, c,
                              host, bundle, "primary", part)
                for d, c, part in pending)
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
            cell = review._load_cell_findings(review_root, manifest, group, domain)
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
    cell = review._load_cell_findings(review_root, manifest, group, domain)
    if not cell:
        return []
    # #1521: merged across the primary round's parts -- a chunked cell keeps its
    # later parts' verdicts in sibling files, and reading only part 0 would
    # silently narrow the backup's scope to the first slice.
    verdicts = _cell_verdicts(review_root, group, domain, "primary",
                              parts=len(_cell_chunks(cell)))
    if not verdicts:
        return []
    by_fid = {str(v.get("finding_id")): v for v in verdicts
              if v.get("finding_id")}
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
            if _verify_cell_done(review_root, manifest, group, domain, "backup",
                                  cell=scope):
                continue
            pending.extend(
                (domain, chunk, part)
                for part, chunk in enumerate(_cell_chunks(scope))
                if not _part_done(review_root, manifest, group, domain,
                                  "backup", part, chunk))
        if pending:
            ngroups += 1
            # #1029: the backup re-reads only its scoped claims' files, not the
            # whole group -- coverage-preserving (claim-driven, unconfined reads).
            all_entries.extend(
                _verify_entry(review_root, manifest, group, d,
                              _backup_scope_files(review_root, files, c), c,
                              host, bundle, "backup", part)
                for d, c, part in pending)
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
            scope = _cell_backup_findings(review_root, manifest, group, domain)
            if scope and not _verify_cell_done(review_root, manifest, group,
                                               domain, "backup", cell=scope):
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
    # take the same default. Uncapped unless the operator passes --max-verify
    # (AGT-679033153 made that flag reachable; before it, this was None on every
    # real run by construction, so the cap existed only for tests).
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
    enforced = hosts.declares(host, hosts.TOOL_POLICY_ENFORCED)
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
