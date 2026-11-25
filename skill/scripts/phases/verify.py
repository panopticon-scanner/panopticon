"""Phase 5 -- verify: cell, backup and tool verification (one phase, three
flavours). The TOOL round -- its queue, its entries and the claim-location
confinement they share with `_render_findings` -- is `phases/verify_tools.py`;
the confinement rule and the root pin themselves are `scripts.claim_scope`.
"""
from typing import Any
import json
import os
import sys

import scripts.claim_scope as claim_scope
import scripts.dispatch as dispatch
import scripts.evidence as evidence
import scripts.findings_contract as findings_contract
import scripts.score_gate as score_gate
# #1720: ONE owner for the enforcement posture -- the loop re-derives it
# to CHECK the dispatch request this module writes, so both sides must
# read the same function or a run can refuse itself.
import scripts.loop_batch as loop_batch
from scripts import read_guard_hook
from . import budget
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


def _part_verdicts(review_root, group, domain, stage, part):
    """The verdicts in ONE part's bundle on disk, sanitized; [] when it is absent
    or not a loadable bundle."""
    data = runio._load_json(
        _verify_out_file(review_root, group, domain, stage, part))
    if not (isinstance(data, dict) and isinstance(data.get("verdicts"), list)):
        return []
    # #1638 P16 fix round 2, N1: the DRIVER's own reader of an
    # agent-written bundle, and the third of three -- it was the one the
    # F1 strip missed. `_cell_backup_findings` derives evidence from
    # what this returns and keeps only `advisor_confirmed`, so a primary
    # advisor planting `_backup_missing_evidence` on its own verdicts
    # emptied its cell's backup scope and no adversarial round was
    # dispatched at all. One sanitizer, every read path
    # (tests/test_agent_verdict_guard.py).
    mine = [evidence._agent_verdict(v) for v in data["verdicts"]
            if isinstance(v, dict)]
    if findings_contract.bundle_version_defect(data, mine):   # #2104
        return []
    return mine


def _verdict_ids(verdicts):
    return [v.get("finding_id") for v in verdicts if isinstance(v, dict)]


def _scoped_verdicts(review_root, group, domain, stage, chunks):
    """#3702: the verdicts on disk for this cell/stage that COUNT: each part's
    bundle read alone, and only its verdicts for the claims that part was handed.
    A bundle that also names another part's claim, another cell's, or nothing's,
    is never done (`_part_done`), but it stays on disk once the budget is spent;
    what it says of claims it was not handed must decide nothing here either."""
    kept: list[dict[str, Any]] = []
    for part, chunk in enumerate(chunks):
        handed = {str(f["id"]) for f in chunk}
        kept.extend(v for v in _part_verdicts(review_root, group, domain, stage, part)
                    if str(v.get("finding_id")) in handed)
    return kept


def _chunk_answered(chunk, verdicts):
    """Every claim in this slice adjudicated somewhere in `verdicts` (A2).

    Extracted from `_part_done` so `phases/persist.py` can apply the SAME rule
    to a bundle that is not on disk yet -- the reply a return-persist advisor
    just handed back (spec 4.5). Two copies of one rule drift; this is the one
    copy, and `persist` reads it by module attribute."""
    return not evidence.claims_unanswered([f["id"] for f in chunk], _verdict_ids(verdicts))


def _chunk_exceeded(chunk, verdicts):
    """#3702: the ids `verdicts` names that this slice did not hand out, by the
    shared rule (`evidence.claims_out_of_scope`). `persist` reads it by module
    attribute, as it reads `_chunk_answered`."""
    return evidence.claims_out_of_scope([f["id"] for f in chunk], _verdict_ids(verdicts))


def _part_done(review_root, manifest, group, domain, stage, part, chunk):
    """One chunk's advisor answered it: bundle labeled, every claim in THIS slice
    adjudicated in THIS part's bundle, and nothing else named there.

    #3695: for a backup part too. It used to be done once its bundle was labeled,
    so a backup that answered 1 of its 20 scoped claims was never asked again and
    the other 19 silently went without a second opinion. `chunk` is a slice of the
    backup round's OWN scope there (`_cell_backup_findings`), never the review
    cell.

    #3702: a bundle that names a claim its part was not handed is not an answer:
    it is asked again, as a reply that does the same is refused (`persist`). And
    a claim is answered by its own part alone. Parts 0..part used to be merged
    here, so an earlier part could answer a later part's claim, which is one
    advisor speaking of a claim another was handed."""
    if not _verify_bundle_labeled(review_root, manifest, group, domain,
                                  stage, part):
        return False
    mine = _part_verdicts(review_root, group, domain, stage, part)
    return not _chunk_exceeded(chunk, mine) and _chunk_answered(chunk, mine)


def _cell_parts_complete(review_root, manifest, group, domain, stage, cell):
    """True when every part of this cell is answered.

    The union across parts is what makes chunking safe: a cell counts as
    answered only once all of its slices are."""
    return all(_part_done(review_root, manifest, group, domain, stage, part, chunk)
               for part, chunk in enumerate(_cell_chunks(cell or [])))

_MAX_VERIFY_ATTEMPTS = 3
# One spelling of the counter's name for the reader and the writer below, the
# way `review._ATTEMPTS_FILE` does it: two independent literals are the drift
# #1809 is otherwise closing.
_VERIFY_ATTEMPTS_FILE = "verify-attempts.json"

_VERIFY_ATTEMPTS_WHAT = "the verify retry budget"

def _verify_key(group, domain, stage):
    """A cell/stage's key in the budget. The key scheme is part of the on-disk
    contract a resumed run reads back, so it is spelled here, once."""
    return "%s/%s/%s" % (group, domain, stage)

def _parts_key(group, domain, stage):
    """#3679 review: how many parts a cell/stage was dispatched in, recorded beside
    its attempt count. A chunked cell's parts are answered separately, and synth
    cannot infer the part count from what came back, so a backup cell reads as
    answered only when EVERY recorded part did (`synth/backups.py`)."""
    return _verify_key(group, domain, stage) + "/parts"

def _claims_key(group, domain, stage):
    """#3695: the claim ids a cell/stage was handed -- its whole scope, in order --
    recorded beside its attempt and part counts. Synth cannot derive the scope
    (the backup's is `_cell_backup_findings`, and synth may not import phases), so
    it reads this to count the scoped claims that got no backup verdict."""
    return _verify_key(group, domain, stage) + "/claims"

def _part_size_key(group, domain, stage):
    """#3702: how many claims one part of this cell/stage holds, recorded beside
    its claims and part count, so a reader can tell which part was handed which
    claim without knowing `_CELL_CLAIMS_CAP`."""
    return _verify_key(group, domain, stage) + "/part_size"

def _scope_record(group, domain, stage, scope):
    """#3702: what one cell/stage hands its advisors, for `_charge_verify_dispatch`
    to record in the same write as the charge: the claim ids of its WHOLE scope in
    order, the number of parts, and the part size. Part N was handed
    `claims[N * part_size:(N + 1) * part_size]`.

    For the primary round as for the backup (#3679, #3695). Synthesis counts a
    bundle verdict only when this record shows that part was handed that claim
    (`synth/verdict_scope.py`): verdicts are matched to findings by id across the
    run, so without it any advisor could speak for any claim."""
    return {_parts_key(group, domain, stage): len(_cell_chunks(scope)),
            _claims_key(group, domain, stage): [str(f["id"]) for f in scope],
            _part_size_key(group, domain, stage): _CELL_CLAIMS_CAP}

def _verify_budget(review_root, group, domain, stage):
    """This budget's (path, key) for the one owner of the arithmetic."""
    return (runio._pano(review_root, _VERIFY_ATTEMPTS_FILE),
            _verify_key(group, domain, stage))

def _dispatch_key(entry):
    """The budget key one verify dispatch entry charges (#3185): its cell/stage,
    or `tool/<queue id>` for a tool advisor; None for anything else. The parts
    of a chunked cell share one key, so a checkpoint charges a cell once."""
    if not isinstance(entry, dict):
        return None
    if entry.get("group") and entry.get("domain") and entry.get("stage"):
        return _verify_key(entry["group"], entry["domain"], entry["stage"])
    entry_id = str(entry.get("id") or "")
    if entry_id.startswith(verify_tools.TOOL_ENTRY_PREFIX):
        return "tool/" + entry_id[len(verify_tools.TOOL_ENTRY_PREFIX):]
    return None

def _dispatch_keys(entries):
    return list(dict.fromkeys(k for k in map(_dispatch_key, entries or []) if k))

def _charge_verify_dispatch(review_root, entries, record=None):
    """#3185: one attempt per dispatched cell/stage or tool item, in ONE write,
    AT DISPATCH -- review's rule (`review._record_attempts`). Charging only when a
    labeled bundle came back short left every other return uncapped: nothing
    written, a garbage bundle, one nested past the depth bound, a refused reply.
    `record` (`_scope_record`: the claim ids each cell/stage was handed, in how many
    parts of what size) lands in the same write, so a charged cell always carries
    its scope."""
    # #3740: a cell/stage or tool item is charged when one of its entries is a new
    # hand-out. Emitted again with nothing changed on disk, it is the same dispatch;
    # its scope record is written all the same.
    charged = budget.new_handouts(review_root, entries)
    budget.bump_many(runio._pano(review_root, _VERIFY_ATTEMPTS_FILE),
                     _dispatch_keys(charged), _VERIFY_ATTEMPTS_WHAT, record=record)
    budget.mark_handouts(review_root, entries, charged, _budget_key)

def _give_back_verify_dispatch(review_root, entries):
    """Refund what `_charge_verify_dispatch` charged a checkpoint that never ran
    (persist.rollback_markers: an interrupt, a host-wide outage)."""
    budget.handouts_ended(review_root, entries)   # #3740: the next emission charges again
    return budget.give_back(runio._pano(review_root, _VERIFY_ATTEMPTS_FILE),
                            _dispatch_keys(entries), _VERIFY_ATTEMPTS_WHAT)

def _verify_exhausted(review_root, key):
    """This cell/stage or tool item has spent every dispatch its budget allows, and the
    last of them has ended (#3740: one still handed out has not failed)."""
    return (budget.count(runio._pano(review_root, _VERIFY_ATTEMPTS_FILE), key,
                         _VERIFY_ATTEMPTS_WHAT) >= _MAX_VERIFY_ATTEMPTS
            and not budget.outstanding(review_root, _BUDGET + key))


# #3740: this budget's name in the hand-out marks (`budget.mark_handouts`).
_BUDGET = "verify:"


def _budget_key(entry):
    key = _dispatch_key(entry)
    return _BUDGET + key if key else None

def _verify_attempts_key(review_root, key):
    """Attempts spent under one budget key -- `tool/<queue id>` for a tool advisor."""
    return budget.count(runio._pano(review_root, _VERIFY_ATTEMPTS_FILE), key,
                        _VERIFY_ATTEMPTS_WHAT)

def _verify_attempts(review_root, group, domain, stage):
    """Attempts spent on this cell/stage: 0 before the first bump, and a refusal
    when the file is PRESENT but unreadable (#1809) or its value is not a count
    (#1767) -- a budget read as empty refunds every re-dispatch this run
    already paid for."""
    path, key = _verify_budget(review_root, group, domain, stage)
    return budget.count(path, key, _VERIFY_ATTEMPTS_WHAT)

def _bump_verify_attempts(review_root, group, domain, stage):
    """One cell/stage's charge: the single-key form of `_charge_verify_dispatch`,
    which charges every dispatch (#3185). Lives with the verdicts, so --reset
    clears it."""
    path, key = _verify_budget(review_root, group, domain, stage)
    return budget.bump(path, key, _VERIFY_ATTEMPTS_WHAT)

def _verify_bundle_labeled(review_root, manifest, group, domain, stage, part=0):
    """The verdict bundle exists, parses, and is labeled for THIS cell -- the
    advisor returned something coherent for it (vs no bundle, or an unloadable /
    mislabeled one)."""
    data = runio._load_json(
        _verify_out_file(review_root, group, domain, stage, part))
    if not (isinstance(data, dict) and isinstance(data.get("verdicts"), list)):
        return False
    if findings_contract.bundle_version_defect(data, [   # #2104: refused whole, as at receipt
            evidence._agent_verdict(v) for v in data["verdicts"] if isinstance(v, dict)]):
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
    # #3185: whatever is on disk -- nothing, an unloadable return, or a labeled
    # bundle short of verdicts -- a cell/stage that has spent its dispatches is
    # done: the gap surfaces as unanswered -> not certified at synthesis, honest,
    # rather than wedging. Every dispatch is charged (`_charge_verify_dispatch`).
    return _verify_exhausted(review_root, _verify_key(group, domain, stage))

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
    claim_scope.confine_claim_location). The location is panel/LLM-supplied and
    the advisor's Read/Grep/Glob are unconfined, so an out-of-tree `location.file`
    embedded verbatim here would steer the advisor to read outside the review
    tree in BOTH verify rounds -- the prior _confined_to_root guard covered only
    the derived backup file list, never this channel."""
    slim = []
    for f in cell:
        claim = {"id": f["id"], "code": f.get("code"), "severity": f["severity"],
                 "title": runio.capped_title(f["title"]),
                 "category": f.get("category"),
                 "location": claim_scope.confine_claim_location(
                     review_root, f.get("location")),
                 "description": _capped_description(f.get("description", ""))}
        override = f.get("severity_override")
        if isinstance(override, dict):
            # The advisor needs the exact catalog-rung citation to grade it.
            # Carry only the public override contract, never arbitrary nested
            # agent keys that happen to sit beside it.
            claim["severity_override"] = {
                key: override[key] for key in ("from", "to", "reason", "rung")
                if key in override
            }
        slim.append(claim)
    return json.dumps(slim, indent=2)

def _verify_entry(review_root, manifest, group, domain, files, cell, host,
                  bundle, stage, part=0, grant=None, ambiguous=None,
                  guide_path=None):
    file_list = runio._abs_file_list(review_root, files)
    out_file = _verify_out_file(review_root, group, domain, stage, part)
    prompt = dispatch.render_prompt("domain-advisor.md", {
        "domain": domain, "group": group, "file_list": file_list,
        "findings": _render_findings(review_root, cell),
        "menu": review._render_menu(bundle, domain, guide_path),
        "criteria": review._render_criteria(bundle, domain),   # #1035
        "run_id": manifest["run_id"], "stage": stage, "out_file": out_file}, host)
    # #975: pin the review root for the advisor too. Unlike the scout/panel file
    # list above, the findings JSON's `location` fields are carried verbatim from
    # the panel's raw claims and stay repo-relative on disk (_render_findings) —
    # Part A's abspath can't reach into that payload. The advisor inherits the
    # HOST's cwd (the user's checkout), never review_root, so
    # without this header a relative `location` resolves against the wrong tree.
    # #1638 P16: the backup round's grant is a bounded closure, and the advisor
    # has to be able to say it was too small. The block sits BETWEEN the
    # repo-root pin and the template (fix round 1, F4 -- it was ahead of the pin,
    # which the comment did not say): root first, then the fence over it, then
    # the claims.
    pin = claim_scope.root_pin_paragraph(review_root, plural=True)
    prompt = pin + (_grant_block(review_root, grant, ambiguous) if grant else "") + prompt
    host_ev = runio.host_evidence(review_root)
    enforced = loop_batch.expected_enforced(review_root, host)
    # #1344/#1622: self-write requires both its static transport mechanism and
    # a PROVEN artifact-write boundary -- see requests.delivery. This preamble
    # goes OUTSIDE (before) the #975 repo-root pin above.
    mode, prefix = requests.delivery(host, host_ev, "domain-advisor.md", out_file)
    entry_id = "verify-%s-%s-%s%s" % (group, domain, stage,
                                      "" if not part else "-part%d" % part)
    # raw paths, deliberately not _prompt_safe'd: the read guard matches them
    # byte-for-byte after realpath (spec 7.2); never paste them into a prompt.
    abs_files = runio._abs_files(review_root, files)
    entry = {"id": entry_id,
            "agent": dispatch.registered_agent_name("domain-advisor.md") if enforced else None,
            "enforced": enforced, **requests.bound_policy(host, "domain_advisor", manifest),
            "prompt": requests.entry_marker(entry_id) + prefix + prompt,
            "marker": read_guard_hook.marker_line(entry_id),
            "out_file": out_file,
            # run_id/group/domain/stage restate the cell this entry IS, so
            # persist/entry_is_done can check a bundle's `_panopticon` stamp
            # against the entry that asked for it (mirrors review._cell_entry).
            "run_id": manifest["run_id"], "group": group, "domain": domain,
            "stage": stage,
            "files": abs_files,
            "scope": requests.scope(
                files=abs_files, reads=review._guide_reads(guide_path))}
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
    guide_path = review._ensure_ocrdb_guide(review_root, bundle)
    # PRIMARY round: one advisor per engaged (>= F_p), not-yet-verified cell.
    # #5: batch every pending primary advisor across ALL groups into one
    # checkpoint (like review + scout), instead of one group per round trip. The
    # BACKUP and TOOL rounds below stay sequential -- they depend on the primary
    # verdicts being complete first (verify_done gates them on all-primary-done).
    all_entries: list[dict[str, Any]] = []
    record: dict[str, Any] = {}
    ngroups = 0
    for group, files in coverage._discovered_groups(review_root):
        pending: list[tuple[str, list[dict[str, Any]], int]] = []
        for domain in coverage._effective_domains(review_root, group):
            cell = review._load_cell_findings(review_root, manifest, group, domain)
            if cell is None or not score_gate.should_engage_primary(cell):
                continue   # unreviewed, or below-gate: unverified + disclosed at synth
            if _verify_cell_done(review_root, manifest, group, domain, "primary"):
                continue
            # #1521: an oversized cell is chunked; re-dispatch only the parts
            # that are still unanswered.
            cell_pending = [(domain, chunk, part)
                            for part, chunk in enumerate(_cell_chunks(cell))
                            if not _part_done(review_root, manifest, group, domain,
                                              "primary", part, chunk)]
            if cell_pending:
                # #3702: the WHOLE cell's scope, not just the parts re-sent now.
                record.update(_scope_record(group, domain, "primary", cell))
            pending.extend(cell_pending)
        if pending:
            ngroups += 1
            all_entries.extend(
                _verify_entry(review_root, manifest, group, d, files, c,
                              host, bundle, "primary", part,
                              guide_path=guide_path)
                for d, c, part in pending)
    if all_entries:
        _charge_verify_dispatch(review_root, all_entries, record=record)
        req, sha = requests.write_dispatch_request_bound(
            review_root, manifest["run_id"], "verify", None, all_entries)
        return engine.PhaseResult(kind="checkpoint", checkpoint="verify", group=None,
                           dispatch_request=req, request_sha256=sha,
                           message="verify: %d primary advisor(s) across %d group(s)"
                           % (len(all_entries), ngroups))
    # BACKUP round (Task 4 fills this branch).
    backup = _verify_backup_execute(
        review_root, manifest, host, bundle, guide_path=guide_path)
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
    # #3702: and each part's verdicts only for the claims that part was handed,
    # which is what synthesis counts too.
    verdicts = _scoped_verdicts(review_root, group, domain, "primary",
                                _cell_chunks(cell))
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

def _verify_backup_execute(review_root, manifest, host, bundle, guide_path=None):
    # #20: batch every pending BACKUP advisor across ALL groups into one
    # checkpoint (group=None), like review + verify-primary (#5). The backup
    # round is sequenced AFTER primary completes (verify_execute returns primary
    # checkpoints until none remain), but WITHIN the round the cells are
    # independent -- streaming one group per checkpoint just serialized 19 round
    # trips against a 20-wide host (run-7).
    all_entries, ngroups = [], 0
    record: dict[str, Any] = {}
    for group, files in coverage._discovered_groups(review_root):
        pending: list[tuple[str, list[dict[str, Any]], int]] = []
        group_record: dict[str, Any] = {}
        for domain in coverage._effective_domains(review_root, group):
            scope = _cell_backup_findings(review_root, manifest, group, domain)
            if not scope:
                continue
            if _verify_cell_done(review_root, manifest, group, domain, "backup",
                                  cell=scope):
                continue
            chunks = _cell_chunks(scope)
            cell_pending = [(domain, chunk, part) for part, chunk in enumerate(chunks)
                            if not _part_done(review_root, manifest, group, domain,
                                              "backup", part, chunk)]
            if cell_pending:
                # #3679: the WHOLE cell's part count, not just the parts re-sent now.
                # #3695: and its whole scope, for the same reason.
                group_record.update(_scope_record(group, domain, "backup", scope))
            pending.extend(cell_pending)
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
            record.update(group_record)
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
                                  part, grant=grant, ambiguous=ambiguous,
                                  guide_path=guide_path))
    if all_entries:
        _charge_verify_dispatch(review_root, all_entries, record=record)
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

