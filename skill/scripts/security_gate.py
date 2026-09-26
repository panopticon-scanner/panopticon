#!/usr/bin/env python3
"""Fail-closed CI gate for trusted Panopticon scanner output."""
from typing import Any
import argparse
import collections
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import scripts.ingest_tools as ingest_tools
from scripts import evidence


GATE_SEVERITIES = frozenset({"HIGH", "CRITICAL"})

# #1578 (SEC-G2B): the modes this gate distinguishes, and the only thing the
# distinction changes. `redteam` says the target is untrusted, so a finding may
# not be dropped because of the DIRECTORY NAME it sits under -- the suppressed
# set is gated alongside the kept one. `standard` keeps the suppression (a
# self-scan drowns in bundled jQuery otherwise) and prints what it dropped.
# #1740: "the directory name it sits under" means EVERY such name, not the
# vendored list alone -- `venv`/`.venv`/`site-packages` with no `pyvenv.cfg`
# behind them, and the fixture corpus, are the same evidence and reach this
# gate through the same channel.
# #1578 owner ruling 2026-09-22 (policy C) narrows WHICH of them redteam
# re-admits: `ingest_tools.gates_when_suppressed` -- a CRITICAL or a
# secret-class finding, never a HIGH lint opinion about bundled code.
REDTEAM = "redteam"
SECURITY_MODES = ("standard", REDTEAM)

# #1790 owner ruling 2026-09-23: what this gate prints over the findings it
# declined to count. The wording is the ruling -- a pre-existing finding is not
# forgiven, it is governed somewhere else: the post-merge code-scanning audit
# (`scripts/code_scanning_audit.py`) fails the push to main on any OPEN alert,
# and an alert the owner has read and dismissed is not open. A reader who sees
# one of these listed and wants it gone dismisses it there, or fixes it; either
# way not here, on a commit whose diff never touched it.
BASELINE_HEADING = ("pre-existing (in the base commit's scan; governed by the "
                    "post-merge audit and GitHub dismissals)")


def load_manifest(path):
    """Load and validate a run_tools selected/produced manifest."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise ValueError("cannot read scanner manifest %s: %s" % (path, exc)) from exc
    if not isinstance(data, dict):
        raise ValueError("scanner manifest is not an object")
    selected = data.get("selected")
    produced = data.get("produced")
    missing = data.get("missing")
    # excluded_scope: adapters applicable only to --excluded files; disclosed,
    # never required. Optional for backward compatibility with older manifests.
    excluded_scope = data.get("excluded_scope", [])
    data["excluded_scope"] = excluded_scope
    if (not isinstance(selected, list) or not isinstance(produced, list)
            or not isinstance(missing, list) or not isinstance(excluded_scope, list)):
        raise ValueError("scanner manifest lists are malformed")
    if not selected or not all(isinstance(name, str) and name for name in selected):
        raise ValueError("scanner manifest selected no tools")
    if not all(isinstance(name, str) and name
               for name in produced + missing + excluded_scope):
        raise ValueError("scanner manifest tool names are malformed")
    if set(missing) != set(selected) - set(produced):
        raise ValueError("scanner manifest missing set is inconsistent")
    if set(excluded_scope) & set(selected):
        raise ValueError("scanner manifest excluded_scope overlaps selected")
    return data


def evaluate(tools_dir, manifest_path, exclude_globs=None, security_mode="standard",
             excluded_out=None):
    """Return (findings, dispositions, failures, high_findings, suppressed).

    #1578: `suppressed` is what a NAME-BASED exclusion dropped, each entry
    naming the segment that dropped it. It is never part of `findings` -- the
    report-side suppression is what makes tool output usable at all -- but under
    `redteam` PART of it is part of the gate: this gate blocks merges, and a
    payload landed as `app/vendor/patched_auth.rb` passing it outright on the
    strength of a conventional directory name is the defect. In `standard` mode
    the suppression stands and `main` prints the count beside the gate line, so
    the drop is disclosed rather than silent.

    WHICH part, owner ruling 2026-09-22 (policy C): `gate_counted`, i.e.
    `ingest_tools.gates_when_suppressed` -- a CRITICAL, or a secret-class
    finding (a secret adapter, or a credential CWE). The first cut re-admitted
    the whole set on severity alone and a vendor-heavy tree then failed a merge
    on bundled-library lint noise, which is the noise the suppression exists to
    keep out. The rest stays suppressed AND disclosed: `main` counts it beside
    the verdict, and the report publishes it as
    `meta.coverage.tools_suppressed_not_gated`.

    #1740: three classes reach it, not one (`ingest_tools.suppression_class`):
    `vendored`, `virtualenv-by-name` (a `venv`/`.venv`/`site-packages` segment
    with no `pyvenv.cfg` to confirm it) and `fixture-corpus` (this call never
    passes `include_fixtures`, so the corpus prune applies to the gate as well
    as to the report -- also on a directory name alone).

    Two kinds of drop are deliberately NOT here, in either mode. A drop backed
    by EVIDENCE rather than a name -- a `pyvenv.cfg` marker, the scanner's own
    `.panopticon/` artifacts, a nested checkout, generated bytecode -- is not a
    guess a redteam gate needs to second-guess. And `exclude_globs` are
    operator POLICY: the operator scoped those paths out of THIS gate, so they
    are excluded and counted, never gated, and a path matching both a glob and
    a name rule is counted as the operator's exclusion. `excluded_out`, when a
    list, collects that second set so `main` can COUNT it beside the verdict
    (fix round 1, ruling 3): un-gating a payload with `--exclude` is a
    legitimate operator act, and it may not be an invisible one.
    """
    manifest = load_manifest(manifest_path)
    suppressed: list[dict[str, Any]] = []
    findings, dispositions = ingest_tools.ingest_dir_detailed(
        tools_dir, "ci", exclude_globs=exclude_globs or [],
        suppressed_out=suppressed, excluded_out=excluded_out)
    # #1512: one definition of lost required coverage, shared with the report's
    # tool axis. Extracted, not duplicated -- the two views disagreeing is what
    # let a scanner that wrote unparseable bytes certify in the report while
    # this gate correctly failed it.
    failures = ["%s: %s" % (name, info["reason"]) for name, info
                in ingest_tools.lost_required_coverage(manifest, dispositions).items()]
    # excluded_scope adapters are disclosed, never required, and their output
    # (if any lingered) is known — not "unexpected".
    known = set(manifest["selected"]) | set(manifest.get("excluded_scope", []))
    unknown = set(dispositions) - known
    if unknown:
        failures.append("unexpected scanner output: %s" % ", ".join(sorted(unknown)))
    kept = [finding for finding in findings
            if finding.get("severity") in GATE_SEVERITIES]
    # #1578 fix round 1, ruling 2: the policy-admitted suppressed set does NOT
    # re-take `GATE_SEVERITIES`. Passing `gates_when_suppressed` IS the floor
    # for it -- a CRITICAL clears the severity test regardless, and a
    # secret-class finding gates whatever grade its tool put on it, which is
    # the ruling's point. Re-applying the floor meant admitting a finding and
    # discarding it on the next line, with `main` printing it as GATED anyway:
    # three committed secrets under `app/vendor/`, "3 GATED", `rc=0`. The
    # SEVERITY half of that instance is fixed at the parse
    # (`sarif_utils.SECRET_ADAPTERS`); this is the composition half, and it
    # still bites any secret-class finding its adapter grades below HIGH.
    #
    # The floor stays on everything the gate KEEPS: policy C narrows the
    # suppressed set and touches nothing else.
    #
    # THE TWO GATES COMPOSE THE SHARED PREDICATE DIFFERENTLY, and the line is
    # deliberate (fix round 2, review I4). `GATE_SEVERITIES` is a floor this
    # module hard-codes -- no operator chose it -- so a mode that says "do not
    # lose a finding to a directory name" may bypass it. `--fail-on` on the
    # driver side is the opposite: it is operator POLICY, in the same class as
    # `--exclude` and as the `--severity` floor `plan.ingest_tool_findings`
    # already applies to these very candidates (#1701 F1), and this codebase
    # does not override an operator flag. So a secret-class MEDIUM under
    # `vendor/` FAILS here and PASSES a `driver run --security redteam
    # --fail-on high`. That is not the two gates disagreeing about the RULE --
    # `gates_when_suppressed` answers identically on both sides -- it is one of
    # them being told, by its operator, which severities may block. Pinned on
    # both sides: `TestThePolicyIsTheFloorForTheSuppressedSet` here and
    # `test_the_driver_gate_keeps_the_operators_fail_on` in
    # tests/synth/test_plan.py.
    high = kept + (gate_counted(suppressed) if security_mode == REDTEAM else [])
    return findings, dispositions, failures, high, suppressed


def gate_counted(suppressed):
    """The suppressed findings `--security redteam` actually counts (#1578 C).

    Through `ingest_tools.gates_when_suppressed`, the one predicate the
    driver's own report gate asks as well: two answers to it is a merge that
    blocks in CI and passes in the report, or the reverse. Because `evaluate`
    applies no further filter to what this returns, its length IS the number
    that reached the gate -- which is what `main` prints, read back off the
    verdict's own list rather than re-derived.
    """
    return [f for f in suppressed if ingest_tools.gates_when_suppressed(f)]


def finding_identity(finding):
    """What two scans of two different commits agree on for the SAME finding.

    `(tool, rule id, normalized path, whitespace-collapsed message)`, every
    field read off an INGESTED finding and never off raw SARIF. The adapters
    disagree about how a path is spelled -- semgrep and gitleaks write the
    container mount (`/src/app.py`), bandit and trivy write a relative path --
    and `sarif_utils.norm_uri` at ingest is what makes those one file. Matching
    raw results would call every semgrep finding new on a tree it had already
    been reported on, which is the failure mode this whole flag exists to
    prevent.

    LINE NUMBERS ARE DELIBERATELY NOT IN IT. An edit anywhere above a finding
    moves it, so a line-keyed identity would call a whole file new on a diff
    that never touched it. Same reasoning, and the same three helpers, as
    `evidence.finding_fingerprint` -- `tool_name`, `tool_rule_id`, `norm_path`
    -- so this gate's idea of "the same finding" cannot drift from the one the
    report already uses.

    The MESSAGE is in it, because one rule fires many times in one file for
    different reasons and, once the line is gone, the message is the only field
    left that tells those apart. It is collapsed the way `sarif_to_findings`
    already collapses a title, so a scanner that re-wraps its own prose does not
    invent a finding.

    SEVERITY is not in it, and the reason is narrower than it first looks. A
    PARSER change cannot produce a grade difference between the two sides: both
    are ingested by the same `ingest_dir_detailed` call in the same process, so
    `#1790`'s own promotion moves baseline and head together. What CAN is the
    SCANNER: `ghcr.io/…-tools:latest` is unpinned, so an image shipping a rule
    pack that re-grades a rule from `warning` to `error` turns every standing
    occurrence of it HIGH on the head side while the baseline capture still
    carries the old grade. Keeping severity out means that day reds nobody's
    PR -- and costs what the review measured: the re-graded findings are
    DISCLOSED under the pre-existing heading on every route rather than counted.
    A strict full-tree lane that would count them is a follow-up, not this
    gate's job.
    """
    location = finding.get("location") or {}
    return (evidence.tool_name(finding) or "",
            str(evidence.tool_rule_id(finding) or ""),
            evidence.norm_path(location.get("file")),
            " ".join(str(finding.get("title") or "").split()))


def disclose_file_coverage(dispositions, label):
    """Usable findings do not assert complete per-file scanner coverage."""
    for tool, disposition in dispositions.items():
        facts = disposition.get("file_coverage") or {}
        if facts.get("status") == "partial":
            print("security-gate: %s %s partial file coverage: %d unparsed, "
                  "%d unavailable; capabilities unavailable: %s"
                  % (label, tool, facts["unparsed_files"], facts["unavailable_files"],
                     ", ".join(facts["capabilities_unavailable"]) or "none"), file=sys.stderr)


def load_baseline(baseline_dir, manifest_path, exclude_globs=None,
                  security_mode="standard"):
    """The base commit's gate population, or the reason there is none.

    Returns `(findings, why_not)`, and a caller that gets a `why_not` runs
    STRICT -- exactly as if no baseline had been named -- after saying so on
    stderr. Every failure here is one: a directory the artifact download never
    created, a manifest that will not parse, an ingest that raised. FAIL TOWARD
    STRICTNESS, NEVER TOWARD SILENCE: the cost of a missing baseline is a red
    check on findings the owner has already ruled on, and the cost of pretending
    one was read is a merge that carried a new HIGH through. The first is
    visible and annoying; the second is the gate not working.

    Ingested through `ingest_dir_detailed` with the SAME `exclude_globs` and
    the SAME `security_mode` as the head, because "the same finding" has to mean
    one thing on both sides. Under `redteam` the policy-C-admitted suppressed
    set is part of the population here too (`gate_counted`), so a CRITICAL under
    `vendor/` that the base commit already carried is pre-existing rather than
    new -- the delta applies to precisely the population `evaluate` counts, and
    to no other.

    FOUR probes, and every one of them exists because the layers underneath are
    TOLERANT (fix round 1, I2). `isdir` alone was the only structural check, and
    past it: `_capped_output_files` swallows a `PermissionError` and reports no
    files, the SARIF parse skips a file it cannot read instead of raising, and
    `load_manifest` validates a manifest's INTERNAL consistency without ever
    asking whether the scan behind it delivered. Three different broken
    baselines therefore produced an empty pool, a verdict line asserting
    `0 HIGH/CRITICAL pre-existing`, and not one word on stderr.

    So: the directory must exist and be readable (`os.access`, next to `isdir`,
    because an unreadable directory is not a directory this can use); the
    manifest must load; the ingest must not raise; and -- the probe that catches
    the other two silent cases -- the baseline's OWN coverage must be intact,
    through `ingest_tools.lost_required_coverage`, the same definition
    `evaluate` applies to the head. A baseline whose semgrep wrote unparseable
    bytes, or whose selected adapter left no file at all, is lost coverage
    exactly as it would be on the head side, and a baseline missing an
    adapter's findings excuses nothing it should have. That IS the safe
    direction -- the pool only ever shrinks -- but silently strict is still
    silent, and this gate's whole contract is that a degraded run says so.
    """
    if not os.path.isdir(baseline_dir) or not os.access(
            baseline_dir, os.R_OK | os.X_OK):
        return [], "%s is not a readable directory" % baseline_dir
    try:
        manifest = load_manifest(manifest_path)
    except ValueError as exc:
        return [], str(exc)
    suppressed: list[dict[str, Any]] = []
    try:
        findings, dispositions = ingest_tools.ingest_dir_detailed(
            baseline_dir, "ci", exclude_globs=exclude_globs or [],
            suppressed_out=suppressed)
    except Exception as exc:  # noqa: BLE001 - a broken baseline is not a verdict
        return [], "cannot ingest %s: %r" % (baseline_dir, exc)
    disclose_file_coverage(dispositions, "baseline")
    lost = ingest_tools.lost_required_coverage(manifest, dispositions)
    if lost:
        return [], ("%s did not deliver its own scan: %s"
                    % (baseline_dir, "; ".join(
                        "%s: %s" % (name, info["reason"])
                        for name, info in lost.items())))
    return (findings
            + (gate_counted(suppressed) if security_mode == REDTEAM else []),
            None)


def split_pre_existing(high, baseline):
    """Split a gate population into `(new, pre_existing)` against *baseline*.

    A MULTISET match, and that is the load-bearing word. Each baseline finding
    satisfies AT MOST ONE head finding, so a second `subprocess.run` added
    beside a pre-existing one -- same tool, same rule, same file, same message,
    a different line this identity cannot see -- finds the baseline's single
    copy already spent and counts as NEW. A set would have let an attacker add
    an unbounded number of copies of any finding the base commit happened to
    carry one of.

    Head order is preserved in both lists, so the printed rows read in the same
    order the strict gate printed them.
    """
    pool = collections.Counter(finding_identity(f) for f in baseline)
    new, pre_existing = [], []
    for finding in high:
        key = finding_identity(finding)
        if pool[key]:
            pool[key] -= 1
            pre_existing.append(finding)
        else:
            new.append(finding)
    return new, pre_existing


def _row(finding):
    """`  SEV ID path:line - message`, the one row shape both lists use.

    A pre-existing finding is printed exactly as legibly as the one that failed
    the build: a reader deciding whether the split is right needs the same
    fields on both sides of it.
    """
    location = finding.get("location") or {}
    return "  %s %s %s:%s - %s" % (
        finding.get("severity"), finding.get("id"),
        location.get("file"), location.get("line_start"),
        finding.get("title"))


def _by_class(suppressed):
    """`vendored (vendor: 2); fixture-corpus (fixture-corpus: 1)` from a
    suppressed list (#1740).

    Counted through `ingest_tools.suppressed_counts` and classified through
    `ingest_tools.suppression_class` -- the same two definitions the ingest
    stderr note and the report's `meta.coverage.tools_suppressed` use, so this
    line cannot drift from either.
    """
    counts = ingest_tools.suppressed_counts(suppressed)
    by_class: dict[str, list[str]] = {}
    for segment in sorted(counts):
        by_class.setdefault(ingest_tools.suppression_class(segment), []).append(
            "%s: %d" % (segment, counts[segment]))
    return "; ".join(
        "%s (%s)" % (cls, ", ".join(by_class[cls]))
        for cls in ingest_tools.SUPPRESSION_CLASSES if cls in by_class)


def main(argv=None):
    parser = argparse.ArgumentParser(description="fail-closed Panopticon scanner gate")
    parser.add_argument("--tools-dir", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--exclude", action="append", default=[])
    # #1578: the exclusion the report keeps is not one a redteam gate may keep.
    parser.add_argument("--security", dest="security_mode", default="standard",
                        choices=list(SECURITY_MODES))
    # #1790: the base commit's OWN capture, which `security.yml` uploads as
    # `raw-scanner-captures` on every push to main. Two flags and no default
    # between them -- the manifest is never guessed from the directory, because
    # a gate that guesses reads SOME manifest on a layout it did not expect and
    # cannot tell the operator which scan it just validated.
    parser.add_argument("--baseline-dir")
    parser.add_argument("--baseline-manifest")
    args = parser.parse_args(argv)
    if bool(args.baseline_dir) != bool(args.baseline_manifest):
        parser.error("--baseline-dir and --baseline-manifest are passed "
                     "together or not at all")
    excluded: list[dict[str, Any]] = []
    try:
        findings, dispositions, failures, high, suppressed = evaluate(
            args.tools_dir, args.manifest, args.exclude, args.security_mode,
            excluded_out=excluded)
        # #1839: the SCAN-side half of the same disclosure. Read back through
        # the one validator rather than widening `evaluate`'s tuple, which every
        # caller and test unpacks positionally.
        scan_skipped = ingest_tools.scan_skipped_venvs(load_manifest(args.manifest))
    except ValueError as exc:
        print("security-gate: %s" % exc, file=sys.stderr)
        return 2
    disclose_file_coverage(dispositions, "current")
    # No baseline named, or one that could not be read: `new` IS `high` and
    # every line below is the one this gate has always printed.
    new, pre_existing, delta = high, [], False
    if args.baseline_dir:
        baseline, why_not = load_baseline(
            args.baseline_dir, args.baseline_manifest, args.exclude,
            args.security_mode)
        if why_not:
            print("security-gate: baseline unusable, gating strictly on the "
                  "whole tree -- %s" % why_not, file=sys.stderr)
        else:
            new, pre_existing = split_pre_existing(high, baseline)
            delta = True
    note = ""
    if suppressed:
        # #1740: grouped by CLASS. "3 suppressed as vendored (venv: 1,
        # fixture-corpus: 1, vendor: 1)" was three different rulings printed
        # under one of their names, and an operator deciding whether to re-run
        # under redteam has to be able to tell a bundled library from a
        # directory someone named `venv` from this repo's own fixture corpus.
        if args.security_mode == REDTEAM:
            # #1578 policy C: under redteam the set SPLITS, so one number for
            # it would be a lie either way -- "GATED" over a lint drop that did
            # not move the verdict, or "NOT gated" over the CRITICAL that did.
            # Counted off the lists the verdict was computed from -- never
            # re-derived from the policy -- so the number and the exit code
            # beside it can never disagree (fix round 1, ruling 2). A
            # suppressed finding is the only kind carrying a `suppressed`
            # segment, which is what identifies it in either list.
            #
            # THREE numbers since the delta landed (#1790 fix round 1, I3), and
            # the invariant above is why. GATED asserts "this blocks the merge",
            # and with two numbers it said that about a suppressed CRITICAL the
            # base commit already carried -- `0 new ... 1 GATED ... rc=0`. So
            # GATED counts `new`, the population that actually gates;
            # pre-existing counts the ones the baseline excused; disclosed-only
            # is what policy C declined, unchanged. The three partition
            # `suppressed`, so nothing is counted twice or lost between them.
            gated = sum(1 for f in new if f.get("suppressed"))
            excused = sum(1 for f in pre_existing if f.get("suppressed"))
            verdict = (" -- %d GATED (CRITICAL/secret, #1578 policy C), "
                       "%d pre-existing, %d disclosed only, --security redteam"
                       % (gated, excused, len(suppressed) - gated - excused))
        else:
            verdict = (" -- NOT gated; re-run with --security redteam to gate "
                       "the CRITICAL and secret-class ones")
        # #1839: "or marker" -- the fourth class rests on a `pyvenv.cfg` the
        # target wrote rather than on a name, and this count now includes it.
        note = ("; %d suppressed by directory name or marker -- %s%s"
                % (len(suppressed), _by_class(suppressed), verdict))
    if excluded:
        # Fix round 1 (ruling 3): the operator's own globs, counted where the
        # verdict is. `--exclude '**/venv/**'` under redteam un-gates exactly
        # what this gate exists to catch, and the line said nothing at all.
        note += ("; %d excluded by --exclude (%s)"
                 % (len(excluded), ", ".join(sorted(set(args.exclude)))))
    if scan_skipped:
        # #1839 (run-14 SEC-1486247143): a virtualenv the RUNNER was told to
        # skip produced no finding, so nothing downstream could say it happened
        # -- one committed `pyvenv.cfg` took a subtree out of semgrep, trivy and
        # bandit and this line was byte-identical either way. `standard` keeps
        # the skip for its walk saving; it does not get to keep the silence.
        note += ("; %d %s removed from the scan as %s (%s)%s"
                 % (len(scan_skipped),
                    "directory" if len(scan_skipped) == 1 else "directories",
                    ingest_tools.MARKER_VENV_SEGMENT, ", ".join(scan_skipped),
                    "" if args.security_mode == REDTEAM
                    else " -- re-run with --security redteam to scan them"))
    # The verdict line SPLITS only when a baseline was actually read. Strict is
    # the historical line, byte for byte, because a named-but-unreadable
    # baseline must look exactly like no baseline to everything downstream.
    tally = ("%d HIGH/CRITICAL new; %d HIGH/CRITICAL pre-existing"
             % (len(new), len(pre_existing)) if delta
             else "%d HIGH/CRITICAL" % len(high))
    print("Ingested %d non-excluded tool findings; %s%s"
          % (len(findings), tally, note))
    if failures:
        print("security-gate: scanner coverage incomplete:", file=sys.stderr)
        for failure in failures:
            print("  - %s" % failure, file=sys.stderr)
        return 2
    # The gating rows first and the excused ones last, under their heading:
    # the heading has to sit immediately above the list it speaks for, or a
    # reader cannot tell where its scope ends.
    for finding in new[:20]:
        print(_row(finding))
    if pre_existing:
        print("%s:" % BASELINE_HEADING)
        for finding in pre_existing[:20]:
            print(_row(finding))
    return 1 if new else 0


if __name__ == "__main__":
    sys.exit(main())
