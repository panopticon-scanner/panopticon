"""Delta review: diff hunks and on-diff / pre-existing classification."""
from dataclasses import dataclass
import json
import os
import sys

import scripts.diff_map as diff_map


@dataclass(frozen=True)
class HunksLoad:
    """What reading a diff-hunks.json cost (#1783, ARC-2340795244).

    The loader is deliberately TOTAL -- an unreadable or malformed artifact
    yields `{}` rather than raising, and the review runs on as a non-delta one.
    Every tolerance it applies is recorded here instead of being silent.

    `payload_malformed` is the reason the payload was rejected in whole or in
    part -- "unreadable", "not an object", "hunks not an object" -- and None
    when there was nothing to reject. `files` and `ranges` count the hunk map
    that survived: what the review is actually scoped to. `ranges_dropped`
    counts what did not survive -- a range that was not a two-integer pair,
    plus one for any path whose value was not a list at all, whose ranges
    cannot be counted individually."""
    payload_malformed: str | None = None
    files: int = 0
    ranges: int = 0
    ranges_dropped: int = 0


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


def _disclose_load(ctx, path):
    """Print what `load_diff_hunks_report` tolerated, in the #957 register.

    #1783 (ARC-2340795244). The asymmetry is the reason this exists. A payload
    with no `base` degrades to a non-delta review -- the WIDER gate, which
    fails closed. A payload WITH a base whose hunk map is missing, malformed or
    empty stays ACTIVE with nothing in it: every finding classifies off-diff,
    and under `--gate-scope on-diff` the gate's source set is empty, so a
    change carrying findings reports a green gate. Silence there is
    indistinguishable from a genuinely empty diff, and the driver hands
    synthesize this artifact on file existence alone, from a fixed path inside
    the reviewed tree's own `.panopticon/`."""
    report = ctx.report
    if report is None:
        return
    if report.payload_malformed:
        print("synthesize: DELTA ARTIFACT MALFORMED -- %s: %s; no diff hunks "
              "were read from it, so nothing scopes this review to the change"
              % (path, report.payload_malformed), file=sys.stderr)
    if ctx.active and report.ranges == 0:
        # Zero ranges has two consequences, and which one this is depends on
        # whether the map names any file at all: `diff_map.classify` answers
        # off-diff for a path the map does not carry, and fails OPEN for a
        # lined finding in a path it carries with no range. Naming the wrong
        # one would be a second quiet inaccuracy on top of the first.
        shape = ("the map is empty, so every finding classifies off-diff and a "
                 "--gate-scope on-diff gate has nothing to fail on"
                 if not report.files else
                 "the map names %d file(s) and not one range, so a lined "
                 "finding in one of them fails OPEN to on-diff and every other "
                 "finding classifies off-diff" % report.files)
        print("synthesize: DELTA REVIEW WITH ZERO HUNKS -- %s resolved a base "
              "but carries no diff ranges: %s. An empty change and a broken "
              "artifact look identical from here: regenerate %s (the driver's "
              "discovery phase writes it) and compare before trusting a green "
              "gate." % (path, shape, path), file=sys.stderr)
    if report.ranges_dropped:
        print("synthesize: DELTA ARTIFACT: %d malformed hunk range(s) dropped "
              "from %s" % (report.ranges_dropped, path), file=sys.stderr)


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
    """Load the orchestrator's diff-hunks.json; {} if absent/malformed."""
    return load_diff_hunks_report(path)[0]


def load_diff_hunks_report(path):
    """`load_diff_hunks`'s data, plus the `HunksLoad` saying what it cost.

    Same return contract for the data half, so every existing caller of the
    old name is unaffected; `from_args` takes this form and discloses the
    report (#1783)."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}, HunksLoad(payload_malformed="unreadable")
    if not isinstance(data, dict):
        return {}, HunksLoad(payload_malformed="not an object")

    raw = data.get("hunks")
    malformed = None
    if not isinstance(raw, dict):
        # `discovery.write_diff_hunks` always emits a `hunks` object, empty
        # included, so an ABSENT key is as broken as a non-object one and
        # reads the same way here.
        malformed = "hunks not an object"
        raw = {}
    dropped = 0
    hunks = {}
    for p, rs in raw.items():
        if not isinstance(rs, list):
            dropped += 1
            continue
        cleaned = []
        for r in rs:
            if isinstance(r, (list, tuple)) and len(r) == 2 and isinstance(r[0], int) and isinstance(r[1], int):
                cleaned.append((r[0], r[1]))
            else:
                dropped += 1
        hunks[str(p)] = cleaned
    data["hunks"] = hunks
    files, ranges = count_hunks(hunks)
    return data, HunksLoad(payload_malformed=malformed, files=files,
                           ranges=ranges, ranges_dropped=dropped)

def classify_findings(findings, hunks, tolerance):
    """Stamp each finding with delta = {on_diff, hunk, distance}."""
    # synthesize runs from the review root, so an absolute location.file (e.g.
    # the worktree-absolute paths --pr panels emit) relativizes correctly against
    # cwd before matching the git-relative hunk keys (#5.0-06).
    repo_root = os.getcwd()
    for f in findings:
        f["delta"] = diff_map.classify(f, hunks, tolerance, repo_root=repo_root)
