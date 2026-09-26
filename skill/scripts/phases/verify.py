"""Phase 5 -- verify: cell, backup and tool verification (one phase, three
flavours). The TOOL round -- its queue, its entries and the claim-location
confinement they share with `_render_findings` -- is `phases/verify_tools.py`.
"""
from typing import Any
import json
import os
import sys

import scripts.dispatch as dispatch
import scripts.evidence as evidence
import scripts.score_gate as score_gate
# #1720: ONE owner for the enforcement posture -- the loop re-derives it
# to CHECK the dispatch request this module writes, so both sides must
# read the same function or a run can refuse itself.
import scripts.loop_batch as loop_batch
from scripts import read_guard_hook
from . import engine
from . import evidence_scope
from . import runio
from . import coverage
from . import requests
from . import review
from . import verify_tools


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
    merged: list[dict[str, Any]] = []
    for part in range(max(1, parts)):
        data = runio._load_json(
            _verify_out_file(review_root, group, domain, stage, part))
        if isinstance(data, dict) and isinstance(data.get("verdicts"), list):
            # #1638 P16 fix round 2, N1: the DRIVER's own reader of an
            # agent-written bundle, and the third of three -- it was the one the
            # F1 strip missed. `_cell_backup_findings` derives evidence from
            # what this returns and keeps only `advisor_confirmed`, so a primary
            # advisor planting `_backup_missing_evidence` on its own verdicts
            # emptied its cell's backup scope and no adversarial round was
            # dispatched at all. One sanitizer, every read path
            # (tests/test_agent_verdict_guard.py).
            merged.extend(evidence._agent_verdict(v) for v in data["verdicts"]
                          if isinstance(v, dict))
    return merged


def _chunk_answered(chunk, verdicts):
    """Every claim in this slice adjudicated somewhere in `verdicts` (A2).

    Extracted from `_part_done` so `phases/persist.py` can apply the SAME rule
    to a bundle that is not on disk yet -- the reply a return-persist advisor
    just handed back (spec 4.5). Two copies of one rule drift; this is the one
    copy, and `persist` reads it by module attribute."""
    got = {str(v.get("finding_id")) for v in verdicts
           if isinstance(v, dict) and v.get("finding_id") is not None}
    return {str(f["id"]) for f in chunk}.issubset(got)


def _part_done(review_root, manifest, group, domain, stage, part, chunk):
    """One chunk's advisor answered it: bundle labeled, and (primary) every
    claim in THIS slice adjudicated somewhere in the cell's bundles."""
    if not _verify_bundle_labeled(review_root, manifest, group, domain,
                                  stage, part):
        return False
    if stage != "primary":
        return True
    return _chunk_answered(
        chunk, _cell_verdicts(review_root, group, domain, stage, part + 1))


def _cell_parts_complete(review_root, manifest, group, domain, stage, cell):
    """True when every part of this cell is answered.

    The union across parts is what makes chunking safe: a cell counts as
    answered only once all of its slices are."""
    return all(_part_done(review_root, manifest, group, domain, stage, part, chunk)
               for part, chunk in enumerate(_cell_chunks(cell or [])))

_MAX_VERIFY_ATTEMPTS = 3

def _verify_attempts(review_root, group, domain, stage):
    data = _verify_attempts_doc(review_root)
    return int(data.get("%s/%s/%s" % (group, domain, stage), 0))

def _verify_attempts_doc(review_root):
    """The whole counter document: {} before the first bump, and a refusal when
    the file is PRESENT but unreadable (#1809) -- a torn budget read as empty
    refunds every re-dispatch this run already paid for."""
    return runio._load_state_json(
        runio._pano(review_root, "verify-attempts.json"),
        "the verify retry budget")

def _bump_verify_attempts(review_root, group, domain, stage):
    """Persisted per-(group, domain, stage) re-dispatch counter that BOUNDS the A2
    verdict-reconciliation retry loop, so a systematically-re-coding advisor
    surfaces as unanswered -> INCONCLUSIVE instead of wedging the run. Lives with
    the verdicts, so --reset clears it."""
    path = runio._pano(review_root, "verify-attempts.json")
    data = _verify_attempts_doc(review_root)
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
             "location": verify_tools._confine_claim_location(review_root,
                                                             f.get("location")),
             "description": _capped_description(f.get("description", ""))}
            for f in cell]
    return json.dumps(slim, indent=2)

def _verify_entry(review_root, manifest, group, domain, files, cell, host,
                  bundle, stage, part=0, grant=None, ambiguous=None):
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
    # #1638 P16: the backup round's grant is a bounded closure, and the advisor
    # has to be able to say it was too small. The block sits BETWEEN the
    # repo-root pin and the template (fix round 1, F4 -- it was ahead of the pin,
    # which the comment did not say): root first, then the fence over it, then
    # the claims.
    pin = ("Repo root: %s\nEvery relative path in the claims below resolves "
           "against this root -- read files THERE, never in your session's "
           "default checkout.\n\n" % os.path.abspath(review_root))
    prompt = pin + (_grant_block(review_root, grant, ambiguous) if grant else "") + prompt
    host_ev = runio.host_evidence(review_root)
    enforced = loop_batch.expected_enforced(review_root, host)
    # #1344 F4 (a): a host with no PROVEN artifact_write_guard gets return-persist
    # instead of unguarded self-write -- see requests.delivery. This preamble
    # goes OUTSIDE (before) the #975 repo-root pin above.
    mode, prefix = requests.delivery(host, host_ev, "domain-advisor.md", out_file)
    entry_id = "verify-%s-%s-%s%s" % (group, domain, stage,
                                      "" if not part else "-part%d" % part)
    # raw paths, deliberately not _prompt_safe'd: the read guard matches them
    # byte-for-byte after realpath (spec 7.2); never paste them into a prompt.
    abs_files = runio._abs_files(review_root, files)
    entry = {"id": entry_id,
            "agent": dispatch.registered_agent_name("domain-advisor.md") if enforced else None,
            "enforced": enforced, "model": requests.bound_model(host, "domain_advisor"),
            "prompt": requests.entry_marker(entry_id) + prefix + prompt,
            "marker": read_guard_hook.marker_line(entry_id),
            "out_file": out_file,
            # run_id/group/domain/stage restate the cell this entry IS, so
            # persist/entry_is_done can check a bundle's `_panopticon` stamp
            # against the entry that asked for it (mirrors review._cell_entry).
            "run_id": manifest["run_id"], "group": group, "domain": domain,
            "stage": stage,
            "files": abs_files,
            "scope": requests.scope(files=abs_files)}
    if mode:
        entry["delivery"] = mode
    return entry

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
    all_entries: list[dict[str, Any]] = []
    ngroups = 0
    for group, files in coverage._discovered_groups(review_root):
        pending: list[tuple[str, list[dict[str, Any]], int]] = []
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
        req, sha = requests.write_dispatch_request_bound(
            review_root, manifest["run_id"], "verify", None, all_entries)
        return engine.PhaseResult(kind="checkpoint", checkpoint="verify", group=None,
                           dispatch_request=req, request_sha256=sha,
                           message="verify: %d primary advisor(s) across %d group(s)"
                           % (len(all_entries), ngroups))
    # BACKUP round (Task 4 fills this branch).
    backup = _verify_backup_execute(review_root, manifest, host, bundle)
    if backup is not None:
        return backup
    # TOOL round (#5.0-03): dispatch a per-finding advisor for each tool finding
    # so synthesize can promote tool_confirmed and stop counting them unanswered.
    tool_round = verify_tools._verify_tools_execute(review_root, manifest, host)
    if tool_round is not None:
        return tool_round
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
            and verify_tools._verify_tools_done(review_root, manifest))

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
    # #1638 P16 fix round 3, D1: the SHARED duplicate rule, not a dict
    # comprehension. That comprehension was last-wins while
    # `evidence.match_verdict_by_id` is first-wins, so one primary bundle with
    # two verdicts for a finding made this function see `rejected` (scope
    # emptied, no adversarial round dispatched) and synthesis see
    # `advisor_confirmed` -- N1's outcome with no private key involved.
    by_fid = evidence.by_finding_id(verdicts, "primary")
    for f in cell:
        f["evidence"] = evidence.derive_evidence(f, by_fid.get(str(f["id"])))
    by_cat: dict[str, list[dict[str, Any]]] = {}
    for f in cell:
        by_cat.setdefault(f.get("category") or "general", []).append(f)
    out = []
    for cat_findings in by_cat.values():
        if score_gate.should_summon_backup(cat_findings):
            out += [f for f in cat_findings
                    if (f["evidence"].get("status") == "advisor_confirmed")]
    return out


# #1638 P16. The heading the backup prompt puts the grant under, and the wording
# that tells the advisor what to do with it. ONE definition: the entry builder
# renders it, `skill/agents/domain-advisor.md` refers to it by this exact
# heading, and tests/phases/test_verify.py + tests/test_domain_advisor_template.py
# each pin their own side of that agreement.
_GRANT_HEADING = "Evidence granted for this check (bounded closure)"
_GRANT_BLOCK = (
    "%s\n"
    "These files are the WHOLE of what your Read and Grep may reach this round: "
    "each claim's own file, the files its evidence names, and their one-hop "
    "in-repo imports, capped at %d per claim (truncated: %s) and, for the "
    "IMPORT/NAMED extras across this whole check, at %d (entry_truncated: %s); "
    "%s, which no cap bounds.%s Copy this "
    "list verbatim into every verdict's `evidence_scope.granted`, with the same "
    "`cap`, `truncated`, `entry_cap`, `entry_truncated` and `floor_count`. If "
    "you needed a file that is NOT listed here, return NEEDS_MORE_INFO and name "
    "the files you could not reach in `missing_evidence` -- a scope failure is "
    "recorded as one, and never counted as a refutation.\n\n%s\n\n")

# Fix round 1, F3: when the entry ceiling bit, SAY SO with a number. An advisor
# told only "truncated: no" reads its scope as complete, which is the same
# dishonesty the closure exists to remove on the other side.
_GRANT_OMITTED = (" %d further files omitted by the entry ceiling -- later "
                  "claims in this check are the ones short of evidence.")


def _grant_block(review_root, grant, ambiguous=None):
    """The prompt section that RECORDS what this backup entry was granted.

    Composed here rather than added as a template placeholder: spec 7.4 keeps
    the templates fixed, and a new placeholder would become mandatory for every
    `domain-advisor.md` render (including the primary and tool rounds, which are
    granted no closure). Paths go through `runio._abs_file_list`, so they are
    absolutized against the review root (#975) and prompt-sanitized (#1190) -- a
    control character in a target-tree filename cannot inject a bullet line here
    either."""
    omitted, floor = int(grant.get("omitted") or 0), int(
        grant.get("floor_count") or 0)
    return _GRANT_BLOCK % (
        _GRANT_HEADING, int(grant.get("cap") or 0),
        "yes" if grant.get("truncated") else "no",
        int(grant.get("entry_cap") or 0),
        "yes" if grant.get("entry_truncated") else "no",
        # N5: a backup chunk is often ONE finding, and the plural sentence is
        # then the one an advisor actually reads.
        ("1 of the files below is a claim file" if floor == 1
         else "%d of the files below are claim files" % floor),
        _GRANT_OMITTED % omitted if omitted else "",
        runio._abs_file_list(review_root, grant.get("granted") or [])
        + evidence_scope.disclosure(ambiguous))


def _backup_grant(review_root, files, scope, ambiguous=None):
    """The bounded EVIDENCE CLOSURE this backup entry is granted, recorded:
    `{granted, cap, truncated, entry_cap, entry_truncated, omitted,
    floor_count}` -- the files, the per-claim and per-entry ceilings, whether
    each bit, how many distinct EXTRA files the entry ceiling cost, and how many
    of the granted files are claim files (which no cap bounds).
    `evidence_scope.grant` is the one place that shape is defined, and its
    module docstring is where the WHY lives: #1029 granted each claim's
    `location.file` alone as a cost cut, plan 5/6 turned that list into a READ
    FENCE, and run-13's #1634 was published unverifiable because the backup held
    less evidence than the primary it was checking. The full-group fallback for
    an unlocatable or escaping `location.file` is unchanged (#1096): a backup
    must never refute blind, and never read outside the tree."""
    return evidence_scope.grant(review_root, files, scope, ambiguous=ambiguous)


def _backup_scope_files(review_root, files, scope):
    """Just the file list out of `_backup_grant` -- what the entry reads."""
    return _backup_grant(review_root, files, scope)["granted"]

def _verify_backup_execute(review_root, manifest, host, bundle):
    # #20: batch every pending BACKUP advisor across ALL groups into one
    # checkpoint (group=None), like review + verify-primary (#5). The backup
    # round is sequenced AFTER primary completes (verify_execute returns primary
    # checkpoints until none remain), but WITHIN the round the cells are
    # independent -- streaming one group per checkpoint just serialized 19 round
    # trips against a 20-wide host (run-7).
    all_entries, ngroups = [], 0
    for group, files in coverage._discovered_groups(review_root):
        pending: list[tuple[str, list[dict[str, Any]], int]] = []
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
        if pending and not files:
            # Fix round 4, N2: `grant()` keeps the grant non-empty by falling
            # back to THIS list, which guarantees nothing when it is empty --
            # the entry would ship `files: []`, a deny-all fence whose only
            # answer manufactures an unrefutable `backup_scope_limited`. A group
            # with no files has nothing to verify, so no entry is BUILT; and the
            # skip is said out loud, never silent.
            print("driver: verify backup SKIPPED for group %s -- no files, so "
                  "nothing to grant and an empty grant is a deny-all fence"
                  % group, file=sys.stderr)
            continue
        if pending:
            ngroups += 1
            # #1029/#1638 P16: the backup reads its scoped claims' BOUNDED
            # EVIDENCE CLOSURE -- their files, the producers those claims name,
            # and a one-hop import neighbourhood -- not the whole group, and the
            # grant it was given is recorded in its prompt.
            for d, c, part in pending:
                ambiguous: list[str] = []      # #1688: names that meant several files
                grant = _backup_grant(review_root, files, c, ambiguous)
                all_entries.append(
                    _verify_entry(review_root, manifest, group, d,
                                  grant["granted"], c, host, bundle, "backup",
                                  part, grant=grant, ambiguous=ambiguous))
    if all_entries:
        req, sha = requests.write_dispatch_request_bound(
            review_root, manifest["run_id"], "verify", None, all_entries)
        return engine.PhaseResult(kind="checkpoint", checkpoint="verify", group=None,
                           dispatch_request=req, request_sha256=sha,
                           message="verify: %d backup advisor(s) across %d group(s)"
                           % (len(all_entries), ngroups))
    return None

def _verify_backup_done(review_root, manifest):
    for group, files in coverage._discovered_groups(review_root):
        # N2: a cell that will never be dispatched must not hold the phase open.
        if not files:
            continue
        for domain in coverage._effective_domains(review_root, group):
            scope = _cell_backup_findings(review_root, manifest, group, domain)
            if scope and not _verify_cell_done(review_root, manifest, group,
                                               domain, "backup", cell=scope):
                return False
    return True


