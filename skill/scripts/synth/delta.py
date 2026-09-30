"""Delta review: diff hunks and on-diff / pre-existing classification."""
from dataclasses import dataclass
import os
import sys

from . import artifacts as artifacts_mod
from . import findings as findings_mod
import scripts.diff_map as diff_map
import scripts.evidence as evidence_mod


# The closed `payload_malformed` vocabulary (#1783, ARC-2340795244). Named once
# here because `meta.coverage.delta`'s published description enumerates these
# exact strings, so a literal typed in a second place can drift from the
# contract. Only MALFORMED_HUNKS_NOT_OBJECT can reach a report: the other three
# leave the payload with no `base`, so the review is not a delta one and the
# whole `meta.coverage.delta` block is null.
MALFORMED_UNREADABLE = "unreadable"
MALFORMED_NOT_OBJECT = "not an object"
MALFORMED_HUNKS_NOT_OBJECT = "hunks not an object"
# #2382: `discovery.write_diff_hunks` stamps `schema_version: 1` and the loader
# ignored it. An unsupported version rejects the WHOLE payload, the same
# fail-closed shape as `not an object`; an ABSENT key is accepted, because a
# hand-written artifact predating the key is not a version mismatch.
MALFORMED_SCHEMA_VERSION = "unsupported schema_version"

# #2382: the seven keys `verdicts._delta_meta` copies VERBATIM out of the
# artifact into `meta.coverage.delta`, with the type each one is published as.
# ONE table, read by the repair in the loader below and by the schema-parity test
# that asserts `report-schema.json` pins these same types -- a repair and a pin
# that disagreed about a key would build a report the schema rejects, and a
# schema error is terminal. The order is the order `keys_repaired` lists them in.
_ARTIFACT_KEY_TYPES = (("base", str), ("base_source", str), ("base_commit", str),
                       ("delta_start", str), ("delta_end", str),
                       ("includes_uncommitted", bool), ("files_changed", int))


@dataclass(frozen=True)
class HunksLoad:
    """What reading a diff-hunks.json cost (#1783, ARC-2340795244).

    The loader is deliberately TOTAL -- an unreadable or malformed artifact
    yields `{}` rather than raising, and the review runs on as a non-delta one.
    Every tolerance it applies is recorded here instead of being silent.

    `payload_malformed` is the reason the payload was rejected in whole or in
    part -- "unreadable", "not an object", "hunks not an object", "unsupported
    schema_version" -- and None when there was nothing to reject. `files` and
    `ranges` count the hunk map that survived: what the review is actually
    scoped to.

    `keys_repaired` names the artifact-carried keys of `meta.coverage.delta` that
    carried a value of the WRONG TYPE and were read as null (#2382), in
    `_ARTIFACT_KEY_TYPES` order. A tuple because this dataclass is frozen. It is
    published in `delta_artifact` and not in `delta`, because repairing `base`
    leaves no base -- so the very block that repair changed is null, and a key
    there could not carry the reason it is null.

    TWO counters for what did not survive, because the losses do not cost the
    same (#2169). `ranges_dropped` is a range that was not a two-integer pair:
    the map keeps the file, merely narrower. `paths_dropped` is a path whose
    value was not a list at all: that file leaves the map, so every finding in
    it classifies off-diff. Counting the second as one of the first published a
    lost file as a lost line range.

    `paths_without_ranges` is not a loss at all (#2381): it counts a path the map
    NAMES whose (well-formed) list is empty after cleaning. The file STAYS in the
    map and every finding in it classifies ON-diff, by `diff_map.classify`'s
    changed-file fail-open. A deletion-only, binary, mode-only or same-content
    rename change legitimately looks like this -- `diff_map.parse` emits such a
    key on purpose -- and so does a truncated map, which is why the shape is
    counted rather than refused. A path whose EVERY range was malformed lands
    here too, and in `ranges_dropped` as well: those are two different facts
    about one path -- the artifact is broken, AND the map still admits that file
    on-diff -- and a reader needs both."""
    payload_malformed: str | None = None
    keys_repaired: tuple[str, ...] = ()
    files: int = 0
    ranges: int = 0
    ranges_dropped: int = 0
    paths_dropped: int = 0
    paths_without_ranges: int = 0


@dataclass(frozen=True)
class DeltaContext:
    """The orchestrator's diff-hunks.json (#449) and the on-diff tolerance
    (WS-0 S2). `diff_hunks` None or without a `base` means a non-delta review:
    no finding is classified and the gate scopes to every active finding.

    `report` is the loader's `HunksLoad` when this context was built from a
    file by `from_args`, and None when a caller constructed it directly from a
    payload it already held -- in which case nothing measured how that payload
    was read, and `meta.coverage.delta` says so rather than reporting zero
    losses (#1783)."""
    diff_hunks: dict | None = None
    diff_context: int = 5
    report: HunksLoad | None = None

    @property
    def active(self):
        return bool(self.diff_hunks and self.diff_hunks.get("base"))

    @classmethod
    def from_args(cls, args):
        """--diff-hunks / --diff-context as main() read them (WS-0 S3), with
        the #957 notice when a delta review is run without --fail-on, and the
        artifact's own disclosures (#1783)."""
        diff_hunks, report = (load_diff_hunks_report(args.diff_hunks)
                              if args.diff_hunks else (None, None))
        if args.diff_hunks and not args.fail_on:
            # #957: a delta review is gate-first by intent, but the gate only
            # arms when --fail-on is passed. Without this notice a forgotten
            # flag yields a green-looking report whose gate silently reads OFF.
            print("synthesize: DELTA REVIEW WITH Gate: OFF -- no --fail-on was "
                  "passed, so nothing can gate this change; pass --fail-on "
                  "{critical,high,medium,low} to arm the gate", file=sys.stderr)
        ctx = cls(diff_hunks=diff_hunks, diff_context=args.diff_context, report=report)
        _disclose_load(ctx, args.diff_hunks)
        return ctx


def _dropped_phrase(report) -> str:
    """Which counters emptied a hunk map, with their numbers (#2169 review, F2).

    ONE definition, read by `_disclose_load` and by `zero_hunk_gate_gap`, so the
    two cannot name different losses for one read -- which they did while only
    the report side knew about dropped paths."""
    lost = []
    if report.ranges_dropped:
        lost.append("%d hunk range(s) were malformed and dropped"
                    % report.ranges_dropped)
    if report.paths_dropped:
        lost.append("%d whole path(s) were dropped for carrying no list of "
                    "ranges" % report.paths_dropped)
    return " and ".join(lost)


def _disclose_load(ctx, path):
    """Print what `load_diff_hunks_report` tolerated, in the #957 register.

    #1783 (ARC-2340795244). The asymmetry is the reason this exists. A payload
    with no `base` degrades to a non-delta review -- the WIDER gate, which fails
    closed. A payload WITH a base whose hunk map is missing, malformed or empty
    stays ACTIVE with nothing in it: every finding classifies off-diff, so under
    `--gate-scope on-diff` a change carrying findings reports a green gate, and
    that silence is indistinguishable from a genuinely empty diff."""
    report = ctx.report
    if report is None:
        return
    if report.payload_malformed:
        print("synthesize: DELTA ARTIFACT MALFORMED -- %s: %s; no diff hunks "
              "were read from it, so nothing scopes this review to the change"
              % (path, report.payload_malformed), file=sys.stderr)
    if report.keys_repaired:
        # #2382: the repair is fail-closed but it is not free. Reading `base` as
        # null widens the gate to every active finding, and a target-authored type
        # error must not make that switch quietly. In exactly that case the whole
        # `meta.coverage.delta` block is null, so this line and the sibling
        # `delta_artifact.keys_repaired` are the only two carriers of the fact.
        print("synthesize: DELTA ARTIFACT REPAIRED -- %s: %s carried a value of "
              "the wrong type and read as null%s"
              % (path, ", ".join(report.keys_repaired),
                 "; the review is NOT a delta one, so the gate scopes to every "
                 "active finding" if "base" in report.keys_repaired else ""),
              file=sys.stderr)
    if ctx.active and report.ranges == 0:
        # Zero ranges has two consequences, and which one this is depends on
        # whether the map names any file at all: `diff_map.classify` answers
        # off-diff for a path the map does not carry, and fails OPEN on BOTH
        # its arms for a path it carries with no range -- an unlined finding
        # there never reaches the range loop, and a lined one falls through it.
        # Naming the wrong one would be a second quiet inaccuracy on top of
        # the first, and naming only one of the two fail-open arms was a third.
        shape = ("the map is empty, so every finding classifies off-diff and a "
                 "--gate-scope on-diff gate has nothing to fail on"
                 if not report.files else
                 "the map names %d file(s) and not one range, so a finding in "
                 "one of them fails OPEN to on-diff -- any finding without a "
                 "line, and any lined one -- while findings elsewhere classify "
                 "off-diff" % report.files)
        # The two-readings warning holds only while the reason is UNKNOWN, and
        # #2169's review found this side still claiming it while the report side
        # said the opposite about the same read. So THREE arms, the same three
        # `zero_hunk_gate_gap` composes below: a rejection and a loader drop are
        # each a KNOWN cause, named on a line of its own, and sending the
        # operator to compare a known-broken artifact is the wrong instruction.
        # Only MALFORMED_HUNKS_NOT_OBJECT reaches here -- the other three leave
        # no `base` and no active delta (#2382 added the fourth).
        regenerate = "regenerate it (the driver's discovery phase writes it)"
        if report.payload_malformed is not None:
            cause = ("The map is empty of ranges because the payload was "
                     "rejected (%s), not because the change was: %s."
                     % (report.payload_malformed, regenerate))
        elif report.ranges_dropped or report.paths_dropped:
            cause = ("The map is empty of ranges because %s, not because the "
                     "change was: %s." % (_dropped_phrase(report), regenerate))
        else:
            cause = ("An empty change and a broken artifact look identical from "
                     "here: %s and compare before trusting a green gate."
                     % regenerate)
        print("synthesize: DELTA REVIEW WITH ZERO HUNKS -- %s resolved a base "
              "but carries no diff ranges: %s. %s"
              % (path, shape, cause), file=sys.stderr)
    # #2381 review: both consequence lines below speak of how findings
    # classify, which only an ACTIVE delta does -- a read with no `base` never
    # reaches `classify_findings` -- so an inactive read keeps the MALFORMED
    # line above alone rather than a warning about a gate it never scoped.
    if ctx.active and (report.ranges_dropped or report.paths_dropped):
        # #2169: ONE line carrying both numbers -- two lines for one read have
        # the operator reconciling what looks like two problems -- and the
        # consequence in a sentence of its OWN (review F1): embedded in the count
        # phrase it landed between "path(s)" and "dropped from", verbless.
        counts = []
        if report.ranges_dropped:
            counts.append("%d malformed hunk range(s)" % report.ranges_dropped)
        if report.paths_dropped:
            counts.append("%d whole path(s)" % report.paths_dropped)
        print("synthesize: DELTA ARTIFACT: %s dropped from %s%s"
              % (" and ".join(counts), path,
                 " -- a dropped path leaves the map, so every finding in that "
                 "file classifies off-diff." if report.paths_dropped else ""),
              file=sys.stderr)
    if ctx.active and report.paths_without_ranges and report.ranges:
        # #2381: the one FAIL-OPEN shape in this family, and the one nothing said
        # a word about. An empty list under a path is WELL FORMED, so neither drop
        # counter sees it, and the ZERO HUNKS arm above needs `ranges == 0` across
        # the WHOLE map -- one real range anywhere silences it. Hence the second
        # condition: the whole-map case belongs to that arm, which says the same
        # thing in more detail, and two lines for one read leave the operator
        # reconciling what looks like two problems (#2169's F1 lesson).
        #
        # DISCLOSED, NOT RECLASSIFIED (ruling 2026-09-30). `diff_map.parse` emits
        # a rangeless key on purpose for a file the diff changed without adding a
        # line, and deleting a line can introduce a finding, so classifying it
        # on-diff is that module's documented contract. What is wrong is that a
        # truncated or hand-edited map is indistinguishable from that legitimate
        # shape, and the counter this line reads is what a later gate rule would
        # need to make a verdict out of the difference.
        print("synthesize: DELTA ARTIFACT: %d named path(s) in %s carry no range "
              "-- every finding in those file(s) classifies on-diff (the "
              "changed-file fail-open), so a --gate-scope on-diff gate admits "
              "them on the artifact's word: a deletion-only, binary, mode-only "
              "or same-content rename change looks exactly like a truncated map "
              "from here." % (report.paths_without_ranges, path),
              file=sys.stderr)


def artifact_facts(ctx) -> dict | None:
    """`meta.coverage.delta_artifact`: what attempting the read cost (#2169).

    A dict whenever a `--diff-hunks` path was given (`from_args` builds a
    `HunksLoad` for the flag, not for a successful read), None when none was.
    The key's schema node in `report-schema.json` is the canonical statement of
    why it exists and of what it does NOT change about `meta.coverage.delta`.
    Here rather than in `verdicts`, so `HunksLoad`'s fields keep one reader;
    `path_read` is gone, redundant with presence (review F3/N6).

    `keys_repaired` is published here and NOT in `meta.coverage.delta` on purpose
    (#2382): the repair it discloses can read `base` as null, which makes the
    review a non-delta one and nulls that whole block."""
    report = ctx.report
    if report is None:
        return None
    return {"payload_malformed": report.payload_malformed,
            "keys_repaired": list(report.keys_repaired),
            "ranges_dropped": report.ranges_dropped,
            "paths_dropped": report.paths_dropped,
            "paths_without_ranges": report.paths_without_ranges}


def zero_hunk_population(active, fail_on, gate_unverified) -> list:
    """The findings in `active` this run's GATE would have judged, which is the
    population `zero_hunk_gate_gap` counts (#2222, owner ruling 2026-09-28,
    NARROWING #2178 from every active finding).

    Two filters, the gate's own two and in the gate's own order. One of them is
    SHARED with the gate and the other is MIRRORED, and that asymmetry is a
    consequence of the import graph, not a preference:

    - the EVIDENCE policy is mirrored -- every active finding under
      `--gate-unverified`, else the ones whose `evidence.status` is in
      `evidence.GATE_ELIGIBLE_DEFAULT`, which is how `verdicts._partition_gate`
      spells it. `verdicts` imports THIS module, so its function cannot be
      called from here and the policy cannot move here either; what is shared is
      the frozenset both read, and the mirror is the one predicate over it.
    - the SEVERITY floor is shared: `findings.severity_floor_admits` is its one
      definition, and `grading.gate_verdict` is that same predicate under
      `any()`. `grading` imports this module too, so `gate_verdict` is no more
      callable from here than `_partition_gate` is -- but a helper in a module
      BOTH sides import is, and the floor is the half small enough to be one.

    `test_delta.TestTheZeroHunkPopulation` asserts the result equals what the
    REAL `_partition_gate` and `gate_verdict` judge for a mixed fixture, which is
    what keeps the mirrored half from drifting silently.

    Deliberately NOT applied: the DELTA scoping. That is the filter the empty
    hunk map broke, so the count is what the gate WOULD have judged under the
    wider scope -- exactly the findings the zero-range map hid from it.

    RULING: with no `--fail-on` the floor admits EVERY severity, because
    `gate_verdict` reads no severity at all before returning OFF. An OFF gate
    over a zero-hunk map therefore still reports a gap, and `certify` keeps the
    OFF while refusing to certify -- the behaviour
    `test_grading.TestAZeroHunkDeltaGateCannotReadPass::test_off_is_preserved`
    pins, note clause included."""
    eligible = (list(active) if gate_unverified else
                [f for f in active
                 if f["evidence"]["status"] in evidence_mod.GATE_ELIGIBLE_DEFAULT])
    return [f for f in eligible
            if findings_mod.severity_floor_admits(f, fail_on)]


def zero_hunk_gate_gap(ctx, eligible_count, gate_scope) -> str | None:
    """The certification reason when this run's GATE scoped against a hunk map
    carrying no ranges, else None (#2178, owner ruling 2026-09-27).

    `_disclose_load` above only PRINTS this shape; #1783 left what to do about
    it open -- refuse to certify, or fall back to the wider scope. The ruling is
    refuse: the run reads INCONCLUSIVE. Falling back was rejected, because a
    benign empty `--changes` run would then go red on pre-existing findings it
    did not introduce.

    All four conditions are load-bearing. An INACTIVE delta degrades to the
    WIDER gate, which fails closed, so nothing was scoped away. A run that ASKED
    for `--gate-scope all` already gates on every active finding. An empty change
    with nothing this gate would have judged -- no findings at all, or none that
    survive `zero_hunk_population`'s two policies (#2222) -- is not a defect and
    still passes; `eligible_count` is that population's size. And `ranges == 0`
    is the measure, not `files == 0`: a map that names a file and gives it no
    range scopes the gate by `diff_map.classify`'s two FAIL-OPEN arms, which is
    not a measured diff either.

    `ctx.report` None means nothing measured the read (a caller that built the
    context from a payload it already held), so there is no `ranges` to trust and
    this stays silent for the reason `_disclose_load` does. `from_args` is the
    only builder a run uses, so an active delta in production always carries one.
    """
    report = ctx.report
    if not (ctx.active and report is not None and report.ranges == 0
            and eligible_count > 0 and gate_scope == "on-diff"):
        return None
    # The same THREE-arm split `_disclose_load` makes above, for the same
    # reason and now over the same counters (#2169 review, F2): the two-readings
    # ambiguity holds only while the reason is UNKNOWN, and a payload already
    # known broken -- rejected outright, or emptied by dropped ranges or dropped
    # paths -- must not send the operator off to compare it. The middle arm's
    # wording is `_dropped_phrase`, shared, so the two cannot disagree.
    if report.payload_malformed is not None:
        cause = ("the map is empty because the payload was rejected (%s), not "
                 "because the change was" % report.payload_malformed)
    elif report.ranges_dropped or report.paths_dropped:
        cause = ("the map is empty because %s, not because the change was"
                 % _dropped_phrase(report))
    else:
        cause = "an empty change and a broken artifact look identical from here"
    # The count is what the GATE would have judged (#2222): `zero_hunk_population`
    # above, i.e. the active set past the gate's evidence policy and any
    # `--fail-on` floor but before the delta scoping the empty map broke. The
    # clause says "any" because `certify` composes this note for an OFF gate too,
    # where no floor is applied at all. It is qualified so a reader does not take
    # the number for the reported `active` tally, which is wider.
    return ("zero-hunk delta gate — the diff-hunks map resolved a base and "
            "carries no diff ranges, so the --gate-scope on-diff source set "
            "for this run's %d gate-eligible finding(s) (the active set after "
            "the gate's evidence policy and any --fail-on floor, before delta "
            "scoping) is not a measured diff; "
            "%s: regenerate the diff-hunks artifact (the "
            "driver's discovery phase writes it)" % (eligible_count, cause))


def count_hunks(hunks):
    """(files, ranges) over a loaded hunk map -- what a delta review is scoped
    to. One definition, so the loader's report and `meta.coverage.delta` cannot
    disagree about the size of the diff (#1783)."""
    files = 0
    ranges = 0
    for rs in (hunks or {}).values():
        files += 1
        if isinstance(rs, (list, tuple)):
            ranges += len(rs)
    return files, ranges


def load_diff_hunks(path):
    """Load the orchestrator's diff-hunks.json; {} if absent/malformed.

    The compatibility name (#1783): it keeps the pre-report contract for
    callers that only want the data, and `load_diff_hunks_report` is the one
    to call -- it hands back the same data plus what reading it cost."""
    return load_diff_hunks_report(path)[0]


def load_diff_hunks_report(path):
    """`load_diff_hunks`'s data, plus the `HunksLoad` saying what it cost.

    Same return contract for the data half, so every existing caller of the
    old name is unaffected; `from_args` takes this form and discloses the
    report (#1783)."""
    try:
        data = artifacts_mod.read_json(path)
    except (OSError, ValueError):
        return {}, HunksLoad(payload_malformed=MALFORMED_UNREADABLE)
    if not isinstance(data, dict):
        return {}, HunksLoad(payload_malformed=MALFORMED_NOT_OBJECT)
    if "schema_version" in data:
        # #2382, honoured minimally: exactly the int 1. `True` and `1.0` both
        # compare equal to it and neither is a version this loader knows, so the
        # check is by type as well as by value. An unsupported version rejects the
        # whole payload, which leaves no `base` and hence no delta review -- the
        # same fail-closed degradation a non-object payload gets.
        version = data["schema_version"]
        if isinstance(version, bool) or not isinstance(version, int) or version != 1:
            return {}, HunksLoad(payload_malformed=MALFORMED_SCHEMA_VERSION)

    raw = data.get("hunks")
    malformed = None
    if not isinstance(raw, dict):
        # `discovery.write_diff_hunks` always emits a `hunks` object, empty
        # included, so an ABSENT key is as broken as a non-object one and
        # reads the same way here.
        malformed = MALFORMED_HUNKS_NOT_OBJECT
        raw = {}
    dropped = 0
    dropped_paths = 0
    rangeless_paths = 0
    hunks = {}
    for p, rs in raw.items():
        if not isinstance(rs, list):
            # #2169: the path is gone from the map, so this is NOT one dropped
            # range -- it is every range that file had, uncountable from here.
            dropped_paths += 1
            continue
        cleaned = []
        for r in rs:
            if isinstance(r, (list, tuple)) and len(r) == 2 and isinstance(r[0], int) and isinstance(r[1], int):
                cleaned.append((r[0], r[1]))
            else:
                dropped += 1
        if not cleaned:
            # #2381: well formed and NOT dropped -- the path stays in the map, so
            # every finding in it classifies on-diff. Counted whether the list
            # arrived empty (a legitimate deletion-only, binary, mode-only or
            # same-content rename change) or was emptied above (a broken
            # artifact): the fail-open is the same either way, and the two facts
            # are told apart by `ranges_dropped`, which is why both are kept.
            rangeless_paths += 1
        hunks[str(p)] = cleaned
    data["hunks"] = hunks
    # #2382: the seven artifact-carried keys, repaired HERE at the read. Nothing
    # normalized them before, so `verdicts._delta_meta` copied them verbatim into
    # `meta.coverage.delta` and a type pin on them would have let a target-authored
    # value end a paid-for run on a terminal schema error. The pass touches ONLY
    # these seven -- never `hunks`, which the loop above owns, and never a
    # controller-computed key: a boundary repair that coerced a key it did not own
    # flipped a verdict once in this repo.
    repaired = []
    for key, typ in _ARTIFACT_KEY_TYPES:
        if key not in data:
            # Absent is not repaired. `_delta_meta` reads these with `.get`, which
            # already answers None, so writing the key would publish a repair that
            # never happened.
            continue
        value = data[key]
        # `isinstance(True, int)` is True, so `files_changed` needs the bool
        # exclusion or a boolean is published as a count of changed files.
        kept = value is None or (isinstance(value, typ)
                                 and not (typ is int and isinstance(value, bool)))
        if not kept:
            data[key] = None
            repaired.append(key)
    files, ranges = count_hunks(hunks)
    return data, HunksLoad(payload_malformed=malformed,
                           keys_repaired=tuple(repaired), files=files,
                           ranges=ranges, ranges_dropped=dropped,
                           paths_dropped=dropped_paths,
                           paths_without_ranges=rangeless_paths)

def classify_findings(findings, hunks, tolerance):
    """Stamp each finding with delta = {on_diff, hunk, distance}."""
    # synthesize runs from the review root, so an absolute location.file (e.g.
    # the worktree-absolute paths --pr panels emit) relativizes correctly against
    # cwd before matching the git-relative hunk keys (#5.0-06).
    repo_root = os.getcwd()
    for f in findings:
        f["delta"] = diff_map.classify(f, hunks, tolerance, repo_root=repo_root)
