"""The verify round: emit its queue, then resolve findings against the advisor
verdicts."""
import dataclasses
from typing import Any
from dataclasses import dataclass, field
import copy
import os
import sys

import scripts.citations as citations
from scripts.citations import load_cwe_catalog
import scripts.evidence as evidence_mod
import scripts.ingest_tools as ingest_tools
import scripts.ocrdb as ocrdb
import scripts.score_gate as score_gate
from . import codes as codes_mod
from . import corroborate as corroborate_mod
from . import findings as findings_mod
from . import grading as grading_mod
from . import plan as plan_mod
from . import severity_cap as severity_cap_mod
from . import verdict_scope as verdict_scope_mod


def emit_verify_queue(findings, run_dir, max_verify):
    """--emit-verify-queue (WS-0 S3): write <run_dir>/verify-queue.json from the
    prepared findings and return True (main exits 0 so the orchestrator runs
    the verify phase). With nothing to queue, remove a STALE queue file and
    return False: main goes on to emit the final report."""
    prepared, _ = corroborate_mod.prepare_for_queue(copy.deepcopy(findings))
    queue, cut = evidence_mod.build_verify_queue(prepared, max_verify)
    qpath = os.path.join(run_dir, "verify-queue.json")
    if queue:
        evidence_mod.write_verify_queue(queue, cut, qpath)
        print("verify queue: %d entries (%d cut by --max-verify) -> %s"
              % (len(queue), cut, qpath))
        return True
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
    return False


@dataclass(frozen=True)
class Resolved:
    """resolve_findings()'s result: every finding with its evidence object and
    fingerprint, partitioned for the sections downstream (WS-0 S2).

    `findings` is the deduped list (integration findings split off into
    `integration_findings`); `active`/`rejected` partition it by evidence
    status; `gate_eligible` is the subset grades and the gate are computed
    from. `verdict_stats`, `verify_matrix`, `tool_axis` and `ocrdb_coverage`
    are the meta.coverage sections this stage owns;
    `tool_names` is the adapter set inferred from the findings (the fallback when
    the tool
    layer reported none); `unanswered_gate` the gate-aware unanswered count
    certify() consumes."""
    findings: list
    active: list
    rejected: list
    gate_eligible: list
    integration_findings: list
    ocrdb_bundle: dict | None
    ocrdb_coverage: dict | None
    verdict_stats: dict
    verify_matrix: dict
    # Internal entry-attribution identities for #3753. The public matrix keeps
    # its existing schema; grading needs the actual engaged cells so a host
    # failure in a cell later answered by backup can be retired.
    verify_engaged_cells: tuple
    tool_axis: dict
    # Tool queue identities before and after verdict matching. These exclude
    # findings cut by --max-verify, because the driver never owed those a
    # launch, and let grading tie a ledger entry to the exact stranded claim.
    tool_advisor_queue_ids: tuple
    tool_advisor_pending_ids: tuple
    tool_names: set
    doc_policy: dict | None
    verdict_unloadable: list
    unanswered_gate: int
    # #1701: the source-scope drops this run's GATE counts.
    # They are NOT in `findings`/`active`/`rejected` -- the report body never
    # holds them -- so they are carried separately rather than partitioned out
    # of one of those lists. `[]` outside redteam; #3269's two reasons never enter.
    gated_suppressed: list = field(default_factory=list)
    # #1578 (owner ruling 2026-09-22, policy C): the other half of the same
    # partition -- the drops that cleared this run's `--severity` floor
    # and were still NOT counted: policy C declined
    # them, or #3269 marks them disclosure-only. Carried so the report publishes the
    # number: a narrowed gate that discloses nothing is the silence #1578 is
    # about, with a smaller blast radius.
    suppressed_not_gated: list = field(default_factory=list)
    # #3755: active scanner findings the path-context rule kept out of the gate, counted
    # per rule (`test-path`, `dev-manifest`). Each such row carries the same rule.
    context_not_gated: dict = field(default_factory=dict)
    # #2990: the ids of the findings whose severity normalize_finding did not
    # recognise and read as CRITICAL, taken BEFORE dedupe so an absorbed one is
    # named too; published as `meta.integrity.unknown_severity_findings`.
    unknown_severity_ids: list = field(default_factory=list)
    # #3667: the queued TOOL findings whose advisor never answered, of
    # `unanswered_gate`'s count. They stay in the report as `tool_reported`;
    # certify names them in `coverage_note` so the shortfall is said, not implied.
    unanswered_tools: int = 0


@dataclass(frozen=True)
class _Matches:
    matched: dict
    count: int
    unanswered: int
    engaged_cells: set
    misrouted: list
    unanswered_tools: int = 0


def holding_cells(findings):
    """{claim id: the cells that hold a finding with that id} over the findings as
    loaded, before dedupe collapses them (#3707). An id is derived from what a
    reviewer wrote and holds no group, so two cells can hold one id: honestly, or
    because one reviewer copied the other's claim."""
    holders: dict[str, set] = {}
    for finding in findings:
        if not isinstance(finding, dict) or not finding.get("id"):
            continue
        cell = evidence_mod.finding_cell(finding)
        if cell is not None:
            holders.setdefault(str(finding["id"]), set()).add(cell)
    return holders


def asked_cells(holders, scope):
    """`holders` less the cells that were never asked about the id (#3707, ruling 1):
    {claim id: the holding cells whose advisors the controller handed that claim, or
    may have}. These are the cells that decide the claim between them. A cell that was
    never asked can dismiss nothing, and its own instance is dismissed by nobody
    (`claim_verdict`). `scope.asked` reads the dispatch record: a cell that was asked
    and did not answer stays, and so does one the record cannot speak for."""
    if scope is None:
        return holders
    return {fid: {cell for cell in cells if scope.asked(cell, fid) is not False}
            for fid, cells in holders.items()}


def claim_verdict(finding, by_fid, run_id, holders):
    """The bundle verdict for `finding`, or None (#3707). A bundle verdict counts for a
    finding only when the bundle is stamped for the cell that finding came from; the
    candidates of each holding cell are resolved by themselves (a backup wins over
    its OWN cell's primary, `match_verdict_by_id`), and `evidence.across_cells`
    decides between the cells."""
    fid = finding.get("id")
    if not fid:
        return None
    own = evidence_mod.finding_cell(finding)
    candidates = by_fid.get(str(fid)) or []
    by_cell = {}
    # A finding that came from no cell (a tool finding) is no cell's instance of
    # anything: the cells that hold its id do not speak for it. For a cell's finding,
    # `holders` names the cells that were asked about the id.
    cells = {None} if own is None else holders.get(str(fid), {own})
    for cell in cells:
        theirs = [c for c in candidates if c.get(evidence_mod.CELL_FIELD) == cell]
        by_cell[cell] = evidence_mod.match_verdict_by_id({"id": fid}, {str(fid): theirs},
                                                         run_id=run_id)
    decided = evidence_mod.across_cells(by_cell, own)
    if own is None or own in cells:
        return decided
    # Its own cell was never asked (ruling 1, revised): the instance stands as it would
    # with no other cell holding the id. "No entry in the record" is a cell below the
    # verify gate, and it is also a cell whose findings file the driver refused, whose
    # CRITICAL synthesis still salvages. So another cell's REJECTED does not dismiss
    # it, and another cell's unanswered ask is not its shortfall. A CONFIRMED from a
    # cell that was asked still reports the claim as confirmed.
    return decided if _confirmed(decided) else None


def _own_verdict(fs, finding, queue_id, holders):
    """`finding`'s verdict on its OWN identity -- its queue id, then its own id --
    never through a dedupe alias, and with no side effects (#2991)."""
    v = (fs.verdicts or {}).get(queue_id) if queue_id else None
    if (isinstance(v, dict) and str(v.get("finding_id")) == str(finding.get("id"))
            and (fs.verdict_run_id is None or v.get("run_id") == fs.verdict_run_id)):
        return v
    if fs.verdict_bundles:
        return claim_verdict(finding, fs.verdict_bundles, fs.verdict_run_id, holders)
    return None


def _verdict_is(verdict, word):
    return isinstance(verdict, dict) and str(verdict.get("verdict", "")).upper() == word


def _confirmed(verdict):
    return _verdict_is(verdict, "CONFIRMED")


def _dismissed(verdict):
    return _verdict_is(verdict, "REJECTED")


def loaded_findings(findings):
    """Every finding dedupe was handed: the survivors and, while each still carries
    them, the members it absorbed."""
    return list(findings) + [member for survivor in findings
                             for member in survivor.get(corroborate_mod.ABSORBED_FIELD) or ()]


class Owed:
    """Which findings were owed an advisor's answer (#3711 review round 3, R1).

    Owed follows what the controller asked. The driver dispatches by cell FILE and
    hands the advisors every claim in it, so a finding's cell is the file it was
    loaded from (`evidence.finding_cell`), never the `domain` its reviewer wrote: a
    HIGH claim declared `COD` in `findings-g3-SEC.json` engages g3's SEC cell, and the
    LOW claim beside it was asked about too. Scored by declared domain, that LOW
    claim read as below the gate and owed nothing.

    A finding is owed when its cell's claims reach the verify gate, scored over
    every loaded finding of the cell, or when the dispatch record says its cell was
    asked about its id (`Scope.asked` is True). A record that cannot say changes
    nothing: the score stands. A finding loaded from no cell file keeps the older
    rule (`plan._finding_owed_verification`, on its declared cell): a matrix finding
    is owed when that cell is engaged, and any other finding always is."""

    def __init__(self, loaded, scope=None):
        by_cell: dict[tuple, list] = {}
        for finding in loaded:
            cell = evidence_mod.finding_cell(finding)
            if cell is not None:
                by_cell.setdefault(cell, []).append(finding)
        self.cells = {cell for cell, claims in by_cell.items()
                      if score_gate.should_engage_primary(claims)}
        self.declared = plan_mod.engaged_matrix_cells(loaded)
        self.scope = scope

    def __call__(self, finding):
        cell = evidence_mod.finding_cell(finding)
        if cell is None:
            return plan_mod._finding_owed_verification(finding, self.declared)
        if cell in self.cells:
            return True
        return (self.scope is not None and bool(finding.get("id"))
                and self.scope.asked(cell, finding["id"]) is True)


def _comes_back(theirs, waiting, own, owed):
    """Does a member dedupe dropped come back into the report as its own finding?
    `theirs` is the survivor's own verdict and `waiting` says the survivor is itself
    owed an answer and has none; `own` is the member's verdict and `owed` says an
    answer was owed for it.

    Dedupe is presentation (#3711 review round 2, P2). It runs before any verdict is
    read and keeps the most severe finding at a line, so what a member is merged
    under must not decide whether the report still shows it:
    - a CONFIRMED member, unless the survivor is CONFIRMED too (#2991);
    - under a REJECTED survivor, every member not itself REJECTED: the survivor goes
      to `discarded_claims` and would take them out of the report with it (#3716);
    - a member that is owed an answer and has none, unless the survivor is CONFIRMED
      or is itself owed and unanswered. Under a NEEDS_MORE_INFO survivor it read
      "unsure" and its shortfall was gone: INCONCLUSIVE became PASS, certified.
    Anything else stays merged, under a survivor that is in the report."""
    if _confirmed(theirs):
        return False
    if _confirmed(own):
        return True
    if _dismissed(theirs):
        return not _dismissed(own)
    return own is None and owed and not waiting


class Published:
    """The severity each finding's row settles at, as a rank (lower is more severe),
    before any verdict is applied (#3727).

    The controller lowers a claim's severity only after the merge: the code
    discipline and the `TST-A1*` cap. Each is decided here by the function that later
    applies it (`severity_cap.Caps.settled`), from the finding as loaded and the
    verdict it is about to be given."""

    def __init__(self, run, groups_meta, bundle):
        self.caps, self.bundle = severity_cap_mod.Caps(run, groups_meta), bundle

    def weight(self, finding, verdict):
        """What `finding` would weigh in the health score as its own row, on the
        verdict it is about to be given: nothing unless it counts on its own
        (`counts_on_its_own`, the gate's own test), else the severity it is published
        at times the lines it spans (`grading.own_weight`)."""
        status = evidence_mod.derive_evidence(finding, verdict)["status"]
        if not counts_on_its_own(status, self.caps.run, finding):
            return 0
        return grading_mod.own_weight(finding, self.caps.published(finding, status, self.bundle))

    def __call__(self, finding, verdict, capped=False):
        """`capped`: with the unverified-scanner cap too, the rank the row is really
        published at (`severity_cap.Caps.published`)."""
        status = evidence_mod.derive_evidence(finding, verdict)["status"]
        decide = self.caps.published if capped else self.caps.settled
        return evidence_mod.sev_rank({"severity": decide(finding, status, self.bundle)})

    def under(self, member, own, survivor, theirs):
        """Is `member` left under a row of lower severity than its own?

        The row's level is where it settles, before the unverified-scanner cap: a
        pair of a scanner finding and the claim merged into it is one row, the
        scanner's, as it always was. That holds for a claim the merge ranked where it
        settles. A `TST-A1*` claim ranks at its cap, and when it turns out uncapped
        the scanner finding won a pair it used to lose: main shows such a claim at
        HIGH, so it is held against the row as published, cap and all, and comes
        back beside the scanner's MEDIUM (#3728 review F1)."""
        level = self(member, own)
        ranked = corroborate_mod.merge_rank(member, self.bundle)[0]
        return level < self(survivor, theirs, capped=level < ranked)


def restore_confirmed(fs, findings, queue, holders=None, owed=None, published=None):
    """Give back the members dedupe dropped that the report must still show
    (`_comes_back`): each is appended to `findings` as its own finding and queued.
    Strips the carrier either way.

    #2991: dedupe picks a survivor by severity before any verdict binds, so a
    REJECTED (or NEEDS_MORE_INFO, or unverified) CRITICAL at one locus swallowed
    a CONFIRMED HIGH there: the HIGH left the report and a FAIL became a PASS.
    A claim's verdict is its own (#3202 withdrew the aliases that let one lend it).

    #3707: a member's own verdict is its claim's, decided across the cells that
    hold its id (`claim_verdict`). Pooled by id, a second cell's copy of the
    member answered for it: with the copy REJECTED the confirmed member was
    never restored and left the report altogether. And where several members to
    restore are instances of ONE id with ONE verdict, one of them is restored, the
    one dedupe itself would have kept, and none where the survivor is that id with
    that verdict already: a claim is published once on each verdict it has. The
    instances of an id do differ where a cell was never asked: its instance has no
    verdict, and an unsure or dismissed copy does not stand in for it.

    #3727: no member that is not itself REJECTED stays under a row that settles at a
    lower severity than its own. The merge ranks by the severity a finding can be
    published at as far as its content says (`corroborate.merge_rank`); the cap that
    depends on the run is known only here. So a survivor can still end below a
    member: a `TST-A1*` claim that ranked at its cap turns out uncapped, under the
    MEDIUM row that won the tie. Such a member comes back, whatever the survivor's
    verdict.

    `owed` says whether a finding was owed an answer (`Owed`, over every loaded
    finding); built here when not given. `published` gives the rank a finding is
    finally published at (`Published`); with none given, severity returns nothing."""
    holders = {} if holders is None else holders    # none given: each by its own cell
    if owed is None:
        owed = Owed(loaded_findings(findings), fs.scope)
    bundle = published.bundle if published is not None else corroborate_mod.LOAD
    queue_ids = {id(e["finding"]): e["queue_id"] for e in queue}
    taken = {e["queue_id"] for e in queue}
    for survivor in list(findings):
        absorbed = survivor.pop(corroborate_mod.ABSORBED_FIELD, [])
        if not absorbed:
            continue
        theirs = _own_verdict(fs, survivor, queue_ids.get(id(survivor)), holders)
        waiting = theirs is None and owed(survivor)
        returning = []  # (member, its queue id-to-be, the claim it is, under a lower row?)
        levels: dict[int, int] = {}     # id(member) -> the rank it is published at
        weights: dict[int, int] = {}    # id(finding) -> what it weighs as its own row
        prints = [(member, evidence_mod.finding_fingerprint(member)) for member in absorbed]
        owns = [(member, fp, _own_verdict(fs, member, fp, holders)) for member, fp in prints]
        # The CONFIRMED verdict of a finding in this group, if one has one.
        confirmed = next((verdict for verdict in [theirs] + [own for _m, _fp, own in owns]
                          if _confirmed(verdict)), None)
        if published is not None:
            weights[id(survivor)] = published.weight(survivor, theirs)
        for member, fp, own in owns:
            if published is not None:
                levels[id(member)] = published(member, own)
                # A scanner finding a claim absorbed was never asked about: the verify
                # queue is built on the merged list. Beside a CONFIRMED claim the pair
                # was confirmed as one (the row is `tool_confirmed`), so it weighs as
                # confirmed too. Weighed on its own missing verdict it weighed nothing,
                # and a one-line claim hid a scanner finding's 40-line hit. Any
                # CONFIRMED finding of the group covers it: a third claim that wins the
                # merge and says nothing must not uncover it.
                covered = (own is None and evidence_mod.is_tool_sourced(member)
                           and confirmed is not None)
                weights[id(member)] = published.weight(member, confirmed if covered else own)
            under = (published is not None and not _dismissed(own)
                     and published.under(member, own, survivor, theirs))
            if under or _comes_back(theirs, waiting, own, owed(member)):
                returning.append((member, fp, _claim_key(member, own), under))
        shown = _claim_key(survivor, theirs)
        kept: dict[tuple, dict[str, Any]] = {}
        for member, _fp, claim, _under in returning:
            # Of the instances of one claim, the one published at the highest severity;
            # among equals, the one the merge itself would keep.
            held = kept.get(claim)
            if claim is not None and (
                    held is None or levels.get(id(member), 0) < levels.get(id(held), 0)
                    or (levels.get(id(member), 0) == levels.get(id(held), 0)
                        and corroborate_mod.outranks(member, held, bundle))):
                kept[claim] = member
        back = []
        for member, fp, claim, under in returning:
            if claim is not None and ((claim == shown and not under)
                                      or kept[claim] is not member):
                continue        # this claim is in the report on this verdict already
            qid, n = fp, 0
            while qid in taken:
                n += 1
                qid = "%s-%d" % (fp, n)
            taken.add(qid)
            findings.append(member)
            back.append(member)
            queue.append({"queue_id": qid, "priority": evidence_mod.triage_priority(member),
                          "finding": member})
        _part_the_pair(survivor, absorbed, back)
        # #3786: a member that comes back brings its own lines, so whoever carried
        # them for it gives them up and one hit is not shown on two rows.
        corroborate_mod.return_carried(survivor, absorbed, back)
        if published is not None:
            # The row that is in the report for each merged member: the instance of
            # its claim that came back, or the survivor.
            stands_for = {id(member): kept[claim] for member, _fp, claim, _under in returning
                          if claim is not None and any(kept[claim] is row for row in back)}
            _weigh_the_group(survivor, absorbed, back, weights, stands_for)


def _weigh_the_group(survivor, absorbed, back, weights, stands_for=None):
    """Count a merge group once in the health score, at its heaviest counted finding
    (#3731). The group is what the merge itself put together: the survivor and all it
    absorbed, whatever has since come back. `weights` gives each finding's own weight
    as its own row, 0 for one that does not count on its own (`Published.weight`).

    Health is a sum over rows, and the merge kept the winning row whole. So a one-line
    claim that won the merge over a confirmed finding spanning 50 lines cut that
    finding's weight to a fiftieth: the letter went from F to B with the finding
    still in the report. And a hostile claim that covered two counted rows of one
    group turned their sum into one row's weight.

    Neither can happen to a maximum taken over the group. A cell cannot lower it by
    adding a finding, and a cell can only split a group, never join two: one maximum
    becomes a sum of maxima, which is never smaller. No row's own range or severity
    changes, and nothing is mixed: the weight is one finding's own.

    Stamped only where it differs from the sum of the rows' own weights. `weight_from`
    on a row says whose weight it carries when that is not its own: the row that
    stands for that finding (`stands_for`, else the survivor). `weight_with` on the
    group's other rows that weigh something names that row."""
    rows = [survivor] + list(back)
    group = rows + [member for member in absorbed if not any(member is row for row in rows)]
    heaviest = max(group, key=lambda finding: weights.get(id(finding), 0))  # the first of them
    weight = weights.get(id(heaviest), 0)
    if weight == sum(weights.get(id(row), 0) for row in rows):
        return
    carrier = (heaviest if any(heaviest is row for row in rows)
               else (stands_for or {}).get(id(heaviest), survivor))
    for row in rows:
        row[grading_mod.GROUP_WEIGHT] = (id(survivor), weight)
        if row is carrier:
            if heaviest is not row:
                row["weight_from"] = {"id": heaviest.get("id"), "weight": weight}
        elif weights.get(id(row), 0):
            row["weight_with"] = carrier.get("id")


def _claim_key(finding, verdict):
    """(id, verdict word): what the report shows once. None for a finding with no id."""
    if not finding.get("id"):
        return None
    word = str(verdict.get("verdict", "")).upper() if isinstance(verdict, dict) else None
    return str(finding["id"]), word


def _part_the_pair(survivor, absorbed, back):
    """A tool finding and an agent claim at one line collapse into one `reinforced`
    finding: one issue, seen twice. When one of the two comes back as its own
    finding they are published apart, and the survivor is no longer both. Left
    `reinforced`, an agent survivor counted as the tool claim too, beside the tool
    finding itself: `tool_axis.queued` counted one scanner finding twice."""
    def other_kind(member):
        return evidence_mod.is_tool_sourced(member) != evidence_mod.is_tool_sourced(survivor)
    returned = {id(member) for member in back}
    if (any(other_kind(member) for member in back)
            and not any(other_kind(member) for member in absorbed
                        if id(member) not in returned)):
        survivor.pop("reinforced", None)


def _owed_unanswered(fs, queue, matched, merged, holders, owed):
    """(findings owed an answer that have none, how many of them are tool findings).

    Accounting comes before merging (#3711 review round 2, P1). What the run owes
    is decided for every loaded finding, whatever it is merged under and whatever
    the report shows for it:
    - A finding is owed an answer when the controller asked for one (`Owed`): its
      cell, the file it was loaded from, reaches the verify gate over every loaded
      finding, or the dispatch record says the cell was asked about it.
    - It is unanswered when the report shows no verdict for it, or when its OWN
      cell gave none. Another cell's CONFIRMED reports the claim as confirmed, and
      the advisor that was asked and said nothing is still a shortfall.
    - A merged AGENT claim counts: its cell's advisors are handed every claim of
      the cell. A merged TOOL finding does not: the queue is built on the merged
      list, so no advisor was ever asked about it, and its survivor speaks for the
      one issue. It is owed again when it comes back (`_comes_back`).
    - One claim is counted once, however many cells hold its id."""
    queued = {id(e["finding"]) for e in queue}
    asked = [(e["finding"], matched.get(id(e["finding"])), e["queue_id"]) for e in queue]
    for member, survivor in merged:
        if id(survivor) in queued and not evidence_mod.is_tool_sourced(member):
            fp = evidence_mod.finding_fingerprint(member)
            asked.append((member, _own_verdict(fs, member, fp, holders), fp))
    claims: dict = {}       # the claim -> is it a tool finding
    for finding, shown, queue_id in asked:
        if not owed(finding):
            continue
        if shown is None or _own_verdict(fs, finding, queue_id, {}) is None:
            claims[str(finding["id"]) if finding.get("id") else id(finding)] = (
                evidence_mod.is_tool_sourced(finding))
    return len(claims), sum(claims.values())


def _bind_verdicts(fs, findings, queue, holders, merged=(), owed=None):
    """Bind and apply answers, measuring engagement before any verdict mutates it.
    `merged` is each (member, survivor) dedupe merged; `owed` says whether a finding
    was owed an answer (`Owed`, `_owed_unanswered`)."""
    verdicts = fs.verdicts or {}
    matched = {}
    matched_n = 0
    by_fid = fs.verdict_bundles or {}
    # Computed on PRE-verdict evidence (nothing below has applied a verdict yet)
    # and on this DEDUPED `findings` list, so it is a subset of (never
    # identical to) phases.verify.verify_execute's own engagement decision, which
    # scores the raw per-cell list -- see engaged_matrix_cells's docstring. It is
    # the verify-matrix disclosure's; what the run OWES is scored on every loaded
    # finding, by the cell it was loaded from (`Owed`).
    engaged_cells = plan_mod.engaged_matrix_cells(findings)
    if owed is None:
        owed = Owed(list(findings) + [member for member, _survivor in merged], fs.scope)
    # #1475: verdict files that EXIST for a cell but cannot be bound to it (the
    # finding_id echo names a different finding, or none at all). Collected
    # separately because they are the opposite failure from `unanswered`: an
    # advisor ran and answered, and the answer was mislabelled.
    verdict_misrouted: list[dict[str, Any]] = []
    for entry in queue:
        v = evidence_mod.match_verdict(entry, verdicts, run_id=fs.verdict_run_id,
                                       misrouted=verdict_misrouted)
        if v is None and by_fid:
            v = claim_verdict(entry["finding"], by_fid, fs.verdict_run_id, holders)
        matched[id(entry["finding"])] = v
    # (Reported only when verdicts were supplied at all: `resolve_findings`.)
    unanswered, unanswered_tools = _owed_unanswered(
        fs, queue, matched, merged, holders, owed)
    for entry in queue:
        v = matched[id(entry["finding"])]
        if v is not None:
            evidence_mod.apply_verdict(entry["finding"], v)
            matched_n += 1
    return _Matches(matched, matched_n, unanswered, engaged_cells, verdict_misrouted,
                    unanswered_tools)


def _verify_matrix(findings, matches):
    """An engaged cell is verified once any of its findings matched an answer."""
    # P5 verify-matrix disclosure: engaged cells (>= F_p) that received no
    # verdict -- the same cells that just drove `unanswered` above. A cell
    # counts as verified once ANY of its findings matched a verdict.
    verified_cells = set()
    for f in findings:
        if matches.matched.get(id(f)) is not None:
            grp, dom = f.get("_group"), f.get("domain")
            if grp is not None and dom is not None:
                verified_cells.add((grp, dom))
    return {
        "engaged": len(matches.engaged_cells),
        "unverified_engaged": sorted(list(k) for k in matches.engaged_cells
                                     if k not in verified_cells)}


def _verdict_stats(fs, findings, queue, cut, matches, holders):
    """Disclose lost, unknown and unmatched answers in stderr and the artifact."""
    verdicts, by_fid = fs.verdicts or {}, fs.verdict_bundles or {}
    unanswered, verdict_misrouted = matches.unanswered, matches.misrouted
    matched_n = matches.count
    if unanswered:
        print("synthesize: %d finding(s) owed a verdict had no verdict; left unverified"
              % unanswered, file=sys.stderr)
    if verdict_misrouted:
        print("synthesize: %d verdict(s) could not be bound to the cell they were "
              "dispatched for (an advisor answered, mislabelled): %s"
              % (len(verdict_misrouted),
                 ", ".join("%s (%s)" % (m["queue_id"], m["reason"])
                           for m in verdict_misrouted[:5])),
              file=sys.stderr)
    unknown = set(verdicts) - {e["queue_id"] for e in queue}
    if unknown:
        print("synthesize: verdict file(s) for unknown queue_id(s): %s"
              % ", ".join(sorted(unknown)), file=sys.stderr)
    # Verdict files that existed but could not be parsed/validated (#938). Their
    # findings are already counted as unanswered above (no verdict matched); the
    # count here records that a verdict was LOST to corruption, not that one was
    # never generated -- otherwise a malformed advisor return vanishes silently.
    verdict_unloadable = fs.verdict_unloadable or []
    if verdict_unloadable:
        # #2990: a bad entry inside a loadable bundle counts here too, so the
        # line names files and entries apart.
        entries = [u for u in verdict_unloadable if u.get("entry") is not None]
        files = [u for u in verdict_unloadable if u.get("entry") is None]
        print("synthesize: %d verdict file(s) and %d verdict entry(ies) were "
              "un-loadable (corrupt or invalid) and their findings left "
              "unverified: %s"
              % (len(files), len(entries), ", ".join(
                  "%s entry %s" % (u.get("file", "?"), u["entry"])
                  if u.get("entry") is not None else str(u.get("file", "?"))
                  for u in verdict_unloadable)),
              file=sys.stderr)
    # A run whose verdicts all failed to match now produces gate PASS / grade A
    # / risk LOW -- the safest-looking output there is -- because only verified
    # findings gate. Stderr is not what CI consumes, so the drop counts belong
    # in the artifact: supplied - matched - unknown is the number of verdicts
    # that named a queued finding but failed match_verdict's finding_id echo.
    # Includes bundle verdicts (by_fid) alongside queue_id-keyed `verdicts` --
    # under the P5 bundle flow `verdicts` is often empty while by_fid carries
    # the actual answers, and matched_n already counts bundle matches, so
    # leaving bundle verdicts out of "supplied" made the invariant go negative.
    _bundle_supplied = sum(len(vs) for vs in by_fid.values())
    _finding_ids = {f.get("id") for f in findings if f.get("id")}
    _bundle_unknown = sum(len(vs) for fid, vs in by_fid.items() if fid not in _finding_ids)
    out_of_scope, scope_not_recorded = verdict_scope_mod.counts(fs.bundle_files)
    for count, why in ((out_of_scope, "named a claim its advisor was not handed"),
                       (scope_not_recorded, "came with no record of what its advisor "
                                            "was handed")):
        if count:
            print("synthesize: %d bundle verdict(s) not counted: each %s"
                  % (count, why), file=sys.stderr)
    return {
        "queued": len(queue),
        "cut": cut,
        "supplied": len(verdicts) + _bundle_supplied,
        "matched": matched_n,
        "unknown": len(unknown) + _bundle_unknown,
        # Verdict files present on disk but un-loadable (corrupt/invalid). A
        # non-zero count means verification evidence was lost, distinct from a
        # finding that never had a verdict generated (#938).
        "unloadable": len(verdict_unloadable),
        # #1475: a verdict file existed for the cell but its finding_id echo
        # named a different finding (or none). These are ALSO counted in
        # `unanswered` -- the finding genuinely has no valid verdict -- but the
        # cause is the opposite of a missing dispatch, and the report has to be
        # able to tell an operator which one happened.
        "misrouted": len(verdict_misrouted),
        # #3702: bundle verdicts dropped at the loader, and in none of the counts
        # above. `out_of_scope`: for a claim the controller's dispatch record
        # does not show that advisor's part was handed. `scope_not_recorded`: in
        # a bundle the record holds no scope for at all. Either holds the letter
        # back (`verdict_scope.reasons`).
        "out_of_scope": out_of_scope,
        "scope_not_recorded": scope_not_recorded,
        # #3707: claim ids held by more than one cell. Each cell's advisors answer
        # for their own instance; a count here is why a claim one cell rejected can
        # still be reported. Disclosure only: an honest duplicate is no shortfall.
        "ids_in_several_cells": sum(1 for cells in holders.values() if len(cells) > 1),
        # Measured only when --verdicts-dir was passed at all. Emitting 0 for a
        # run with no verify phase would read as "nothing went unanswered",
        # which is the opposite of the truth; null means "not measured", the
        # same convention as tool_axis.rejection_rate.
        "unanswered": unanswered if fs.verdicts_supplied else None,
    }


def _derive_evidence(findings, catalog, matched, pre_verdict_fps):
    """Attach evidence while preserving identity captured before advisor changes."""
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



# #3667: why an ingested tool finding is not itself in the report. Both are
# collapses into ANOTHER tool finding that is: `aggregate_tool_findings` folds a
# rule's repeat hits in one file into one survivor (counted in its
# `occurrences`, the loci in `additional_loci`), and `dedupe` keeps the most
# severe of one rule on one artifact at one locus.
DROP_AGGREGATED = "aggregated_into_tool_finding"
DROP_DEDUPED = "deduplicated_into_tool_finding"


def _absorbed_into(findings):
    """{id(member): survivor} for every member `dedupe` collapsed, read before
    `restore_confirmed` strips the carrier."""
    return {id(m): survivor for survivor in findings
            for m in survivor.get(corroborate_mod.ABSORBED_FIELD) or ()}


def _tool_reconciliation(ingested, findings, absorbed_into):
    """#3667: per scanner, where each ingested tool finding went.

    `ingested` is the tool findings synthesize received, `findings` the
    pipeline's survivors (the report body plus `discarded_claims`). Every
    ingested finding lands in exactly one bucket, so
    `ingested == in_report + merged_into_agent + dropped` for each scanner, and
    `dropped_reasons` sums to `dropped`. A scanner whose findings all collapsed
    elsewhere is still listed, with its reasons."""
    present = {id(f) for f in findings}
    out: dict[str, dict[str, Any]] = {}
    for f in ingested:
        row = out.setdefault(evidence_mod.tool_name(f) or "", {
            "ingested": 0, "in_report": 0, "merged_into_agent": 0, "dropped": 0,
            "dropped_reasons": {}})
        row["ingested"] += 1
        survivor = absorbed_into.get(id(f))
        if id(f) in present:
            row["in_report"] += 1
        elif survivor is not None and not evidence_mod.is_tool_sourced(survivor):
            row["merged_into_agent"] += 1
        else:
            reason = DROP_DEDUPED if survivor is not None else DROP_AGGREGATED
            row["dropped"] += 1
            row["dropped_reasons"][reason] = row["dropped_reasons"].get(reason, 0) + 1
    return {tool: out[tool] for tool in sorted(out)}


def _tool_axis(findings, by_tool=None):
    """Measure tool-side decisions independently from the severity gate."""
    tool_like = [f for f in findings
                 if evidence_mod.is_tool_sourced(f) or f.get("reinforced")]

    def _tool_count(status):
        return sum(1 for f in tool_like if f["evidence"]["status"] == status)

    confirmed = _tool_count("tool_confirmed")
    rejected_n = _tool_count("rejected")
    decided = confirmed + rejected_n
    return {
        "queued": len(tool_like),
        "confirmed": confirmed,
        "rejected": rejected_n,
        "needs_more_info": _tool_count("needs_more_info"),
        "unanswered": _tool_count("tool_reported"),
        # Share of DECIDED tool claims an advisor refuted — the tool-side
        # mirror of the 27% agentic rejection rate. None when nothing was
        # decided, so an unverified run reports "unmeasured", not "0%".
        "rejection_rate": round(rejected_n / decided, 3) if decided else None,
        "by_tool": by_tool or {},
    }



@dataclass(frozen=True)
class _Partitions:
    active: list
    rejected: list
    gate_eligible: list


def context_rule(finding, run):
    """The rule that keeps `finding` out of the gate for WHERE it is, or None (#3755).

    A scanner finding ingest marked as sitting in a test path or a dev-only manifest
    (`evidence.path_context`). Owner's ruling, 2026-11-23:

    - `--security standard`: reported, and not counted. Whether an advisor confirms
      it no longer moves the gate, the grade or health.
    - `--security redteam`: counted only when CRITICAL or secret-class. That is
      #1578's policy C, asked of `ingest_tools.gates_when_suppressed` itself: the one
      rule for a finding in a directory the project does not ship.

    The mode is the gate's own (`gate_security_mode`), never the target's."""
    context = evidence_mod.path_context(finding)
    if context is None:
        return None
    if (run.gate_security_mode == plan_mod.REDTEAM
            and ingest_tools.gates_when_suppressed(finding)):
        return None
    return evidence_mod.PATH_CONTEXT_RULES[context]


def counts_on_its_own(status, run, finding=None):
    """Does a finding of this evidence status count for the gate, health and the
    letter? THE definition: `_partition_gate` filters the rows by it, and the merge
    asks it of each member before a row may stand for that member (`Published`), so
    the two cannot drift (#3731). With the `finding`, where it is counts too (#3755)."""
    if finding is not None and context_rule(finding, run) is not None:
        return False
    return status != "rejected" and bool(
        run.gate_unverified or status in evidence_mod.GATE_ELIGIBLE_DEFAULT)


def _partition_gate(findings, run):
    """Apply the run's evidence policy to active findings."""
    rejected = [f for f in findings if f["evidence"]["status"] == "rejected"]
    active = [f for f in findings if f["evidence"]["status"] != "rejected"]
    gate_eligible = [f for f in active
                     if counts_on_its_own(f["evidence"]["status"], run, f)]
    return _Partitions(active, rejected, gate_eligible)


def _mark_context_rule(active, run):
    """Say on each active row the path-context rule TOOK out of the gate that it did,
    and which rule (#3755): `gate: {"eligible": false, "rule": ...}`. Returns the count
    per rule, for `meta.coverage.tools_context_not_gated`.

    Only a row that would have counted without the rule: one no advisor answered is out
    on its evidence, as it would be anywhere, and is neither marked nor counted here.
    The key is the controller's alone: whatever a row carried under it is dropped first
    (an agent's finding cannot arrive with it, `findings.AGENT_FORBIDDEN_FIELDS`)."""
    counts: dict = {}
    for finding in active:
        finding.pop("gate", None)
        rule = context_rule(finding, run)
        if rule is not None and counts_on_its_own(finding["evidence"]["status"], run):
            finding["gate"] = {"eligible": False, "rule": rule}
            counts[rule] = counts.get(rule, 0) + 1
    return counts


def _scope_suppressed(gated_suppressed):
    """Apply the owner-ruled suppressed gate policy."""
    # The EVIDENCE filter `_partition_gate` applies is deliberately NOT applied
    # here, and this is the one
    # place the two populations still differ. A suppressed finding is withheld
    # from `findings[]`, so it is never queued for the verify round and can
    # never reach `tool_confirmed`; under the default `confirmed_only` policy
    # filtering on evidence would drop every one of them and leave #1701 open.
    # `security_gate.py` has no evidence axis at all, so it is not a precedent
    # either way. OWNER RULING, #1578, 2026-09-22: the asymmetry STANDS (option
    # A -- sending the suppressed set through tool-verify -- was rejected on
    # dispatch cost) but it is NARROWED to the findings worth blocking a merge
    # for. `ingest_tools.gates_when_suppressed` is the one definition:
    # CRITICAL/secret, except #3269's disclosure-only reasons. Bundled-library
    # lint noise must not drive a gate -- calibration-5/solidus: 592 of
    # eslint-security's 623 messages were one rule firing on jQuery under
    # `vendor/`, and gating all of them (option B) hard-FAILed such a tree on
    # unverified scanner output. A planted payload or a committed secret under
    # `vendor/` still gates. Both halves stay disclosed:
    # `meta.coverage.tools_suppressed_gated` counts what gated,
    # `tools_suppressed_not_gated` what this rule declined to count.
    gated = list(gated_suppressed or [])
    suppressed_not_gated = [f for f in gated
                            if not ingest_tools.gates_when_suppressed(f)]
    gated = [f for f in gated if ingest_tools.gates_when_suppressed(f)]

    return gated, suppressed_not_gated


def _unknown_severity_ids(findings):
    """Sorted distinct ids of the findings normalize_finding read as CRITICAL
    because their severity was not one it knows (#2990) or was absent (#3210)."""
    return sorted({str(f.get("id")) for f in findings
                   if isinstance(f, dict) and findings_mod.SEVERITY_AS_WRITTEN in f})


def _judged_hits_only(fs, queue):
    """`fs` with each REJECTED of an aggregated scanner finding held to the lines it
    judged (#3756, `evidence.judged_only`).

    Here, once, before anything binds a verdict: the verdict's word is read in many
    places below (`match_verdict`, `_own_verdict`, the member rules of
    `restore_confirmed`, `apply_verdict`), most of them without the finding in
    hand. Rewriting the loaded answer means every one of them reads the same word.
    The queue-id answers only: a bundle is a cell's, and no cell speaks for a
    finding that came from none (`claim_verdict`)."""
    verdicts = dict(fs.verdicts or {})
    changed = False
    for entry in queue:
        own = verdicts.get(entry["queue_id"])
        if isinstance(own, dict):       # one that echoes another id binds to nothing, later
            held = evidence_mod.judged_only(entry["finding"], own)
            changed = changed or held is not own
            verdicts[entry["queue_id"]] = held
    return dataclasses.replace(fs, verdicts=verdicts) if changed else fs


def resolve_findings(fs, run, gated_suppressed=(), groups_meta=None):
    """The verdict-matching cluster (WS-0 S2): dedupe, queue, bind advisor
    verdicts, derive every finding's evidence object and fingerprint, then
    partition for the gate under the two-axis severity x evidence model.

    Severity is never mutated here. Verdicts (from evidence.load_verdicts) are
    applied to queued findings; every finding gets an evidence object.
    `fs.verdicts_supplied` records whether --verdicts-dir was passed at all
    (distinct from whether it yielded any verdicts) so the aggregate "no
    verdict" note still fires for an existing-but-empty dir.
    """
    unknown_severity = _unknown_severity_ids(fs.findings)
    if unknown_severity:
        # #3210: stderr names both kinds apart; the finding's own
        # `severity_as_written` is None when none was written.
        absent = sum(1 for f in fs.findings if isinstance(f, dict)
                     and findings_mod.SEVERITY_AS_WRITTEN in f
                     and f[findings_mod.SEVERITY_AS_WRITTEN] is None)
        print("synthesize: %d finding(s) read as CRITICAL -- %d with an unknown "
              "severity, %d with none: %s"
              % (len(unknown_severity), len(unknown_severity) - absent, absent,
                 ", ".join(unknown_severity)), file=sys.stderr)
    ingested_tools = [f for f in fs.findings
                      if isinstance(f, dict) and evidence_mod.is_tool_sourced(f)]
    ocrdb_bundle = ocrdb.load_bundle()
    findings, integration_findings = corroborate_mod.prepare_for_queue(fs.findings, ocrdb_bundle)
    absorbed_into = _absorbed_into(findings)
    catalog = fs.catalog if fs.catalog is not None else load_cwe_catalog()
    ocrdb_coverage = codes_mod.validate_finding_codes(findings, ocrdb_bundle)
    queue, cut = evidence_mod.build_verify_queue(findings, run.max_verify)
    fs = _judged_hits_only(fs, queue)
    # #3707: which cells hold each claim id, from the findings as loaded: dedupe
    # is about to collapse the instances, and a verdict speaks for its own cell's.
    held = holding_cells(fs.findings)
    holders = asked_cells(held, fs.scope)
    # Round 2 of the #3711 review: what the run owes is scored on every loaded
    # finding, and each merge is remembered so the accounting can see through it.
    owed = Owed(loaded_findings(findings), fs.scope)
    # (A member that comes back is queued as well. It is one claim either way.)
    merged = [(member, survivor) for survivor in findings
              for member in survivor.get(corroborate_mod.ABSORBED_FIELD) or ()]
    # (before any identity is read)
    restore_confirmed(fs, findings, queue, holders, owed,
                      Published(run, groups_meta, ocrdb_bundle))
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
    pre_verdict_fps = {id(f): evidence_mod.finding_fingerprint(f) for f in findings}
    matches = _bind_verdicts(fs, findings, queue, holders, merged, owed)
    verify_matrix_cov = _verify_matrix(findings, matches)
    tool_entries = [entry for entry in queue
                    if evidence_mod.is_tool_sourced(entry["finding"])]
    tool_advisor_queue_ids = tuple(entry["queue_id"] for entry in tool_entries)
    tool_advisor_pending_ids = tuple(
        entry["queue_id"] for entry in tool_entries
        if matches.matched.get(id(entry["finding"])) is None)
    if ocrdb_coverage is not None:
        ocrdb_coverage.update(codes_mod.apply_verdict_quality(findings, matches.matched, ocrdb_bundle))
    verdict_stats = _verdict_stats(fs, findings, queue, cut, matches, held)
    _derive_evidence(findings, catalog, matches.matched, pre_verdict_fps)
    # #3231: after the verdict-quality step and the evidence it reads, before anything counts.
    severity_cap_mod.apply(findings, run, groups_meta)
    tool_axis = _tool_axis(findings, _tool_reconciliation(ingested_tools, findings,
                                                          absorbed_into))
    partitions = _partition_gate(findings, run)
    context_not_gated = _mark_context_rule(partitions.active, run)
    gated, suppressed_not_gated = _scope_suppressed(gated_suppressed)
    tool_names = {evidence_mod.tool_name(f) for f in findings
                  if evidence_mod.is_tool_sourced(f)}
    return Resolved(findings=findings, active=partitions.active, rejected=partitions.rejected,
                    gate_eligible=partitions.gate_eligible,
                    integration_findings=integration_findings,
                    ocrdb_bundle=ocrdb_bundle, ocrdb_coverage=ocrdb_coverage,
                    verdict_stats=verdict_stats, verify_matrix=verify_matrix_cov,
                    verify_engaged_cells=tuple(sorted(matches.engaged_cells)),
                    tool_axis=tool_axis,
                    tool_advisor_queue_ids=tool_advisor_queue_ids,
                    tool_advisor_pending_ids=tool_advisor_pending_ids,
                    tool_names=tool_names,
                    doc_policy=fs.doc_policy, verdict_unloadable=fs.verdict_unloadable or [],
                    # Measured only when --verdicts-dir was passed at all.
                    unanswered_gate=matches.unanswered if fs.verdicts_supplied else 0,
                    unanswered_tools=matches.unanswered_tools if fs.verdicts_supplied else 0,
                    gated_suppressed=gated, suppressed_not_gated=suppressed_not_gated,
                    context_not_gated=context_not_gated,
                    unknown_severity_ids=unknown_severity)
