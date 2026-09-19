"""The verify phase's TOOL round: one advisor per tool-sourced finding.

Split out of `phases/verify.py` (a pure move) so neither module sits on the
700-line ceiling. `verify.py` keeps the cell and backup rounds and calls
`_verify_tools_execute` / `_verify_tools_done` here as its third round.

The queue is recomputed rather than read: `_tool_verify_queue` runs
synthesize's OWN combined pipeline over the same inputs, so the (queue_id,
finding id) pairs the driver dispatches against are byte-identical to the
ones synthesize will later try to match a verdict to. `_tools_include_fixtures`
is the one flag both sides read, which is why `phases/review.py` and
`phases/synthesize.py` reach it here.

`_confine_claim_location` came along because this is the channel #run8
ARC-F2A was about -- a finding's `location.file` embedded verbatim in an
UNCONFINED advisor's claim -- and `verify._render_findings` calls it back
through this module. The dependency runs one way: nothing here reads
`verify`.
"""
import glob as _glob
import json
import os

import scripts.dispatch as dispatch
import scripts.evidence as evidence
import scripts.ingest_tools as ingest_tools
# #1720: ONE owner for the enforcement posture -- the loop re-derives it
# to CHECK the dispatch request this module writes, so both sides must
# read the same function or a run can refuse itself.
import scripts.loop_batch as loop_batch
import scripts.synth.corroborate as corroborate_mod
import scripts.synth.findings as findings_mod
from scripts import read_guard_hook
from . import coverage
from . import engine
from . import requests
from . import runio
from . import tools


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
    injection-hunting is unaffected: it is a review-panel job (the config's
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

    Additive only: it CALLS findings_mod.load_findings/normalize_finding,
    corroborate_mod.prepare_for_queue and evidence.build_verify_queue unchanged.
    include_fixtures/group/exclude are pinned to synthesize's main() tool-ingest
    call (group=None, exclude_globs=None) for identity; _tools_include_fixtures
    is the value synthesize_execute forwards. `target_root` is passed rather
    than derived, and stays identical for the same reason: `ingest_dir_detailed`
    derives exactly this root from the tools directory when a caller omits it
    (#1638 P09), so synthesize's own ingest of the same directory drops the same
    virtualenv findings this queue does."""
    ran = (runio._load_json(runio._pano(review_root, "tools-ran.json")) or {}).get("ran")
    tools_dir = runio._pano(review_root, "tools")
    if not ran or not os.path.isdir(tools_dir):
        return []
    findings = findings_mod.load_findings(
        sorted(_glob.glob(runio._pano(review_root, "findings-*.json"))))
    tool_findings, _disp = ingest_tools.ingest_dir_detailed(
        tools_dir, None, include_fixtures=_tools_include_fixtures(manifest),
        target_root=review_root)
    for tf in tool_findings:
        findings.append(findings_mod.normalize_finding(tf))
    prepared, _integration = corroborate_mod.prepare_for_queue(findings)
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
    prompt = tools.partial_audit_note(review_root, safe_finding) + prompt
    host_ev = runio.host_evidence(review_root)
    enforced = loop_batch.expected_enforced(review_root, host)
    # #1344 F4 (a): derived, not a literal -- advisor.md grants no Write, so
    # requests.delivery always answers "return_json" with no preamble here,
    # but the derivation is the one this module shares with the two
    # write-capable builders rather than a copy that could drift from it.
    mode, prefix = requests.delivery(host, host_ev, "advisor.md", out_file)
    # R-P5-2: the tool finding carries no group by construction, so its scope
    # is found by reverse-looking-up the cell containing its file. A redacted
    # (hostile/escaping) location confines to nothing rather than to the
    # redaction placeholder string.
    located = None
    if isinstance(safe_finding, dict) and isinstance(safe_finding.get("location"), dict):
        located = safe_finding["location"].get("file")
    if located == _REDACTED_CLAIM_PATH:
        located = None
    abs_files = coverage.group_files_containing(review_root, located)
    entry_id = "verify-tool-%s" % queue_id
    entry = {"id": entry_id,
            "agent": dispatch.registered_agent_name("advisor.md") if enforced else None,
            "enforced": enforced, "model": requests.bound_model(host, "advisor"),
            "prompt": requests.entry_marker(entry_id) + prefix + prompt,
            "marker": read_guard_hook.marker_line(entry_id),
            "out_file": out_file,
            "scope": requests.scope(files=abs_files)}
    if mode:
        entry["delivery"] = mode
    return entry

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
