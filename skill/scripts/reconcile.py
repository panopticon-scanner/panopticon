#!/usr/bin/env python3
"""Run-3 reconciliation, stage 1: recompute finding_fingerprint on both a
run-2 and a run-3 report and diff them.

Run-2's *stored* fingerprints predate the P2 fingerprint-corruption fix
(SARIF findings hashed advisor prose, not rule content) and are therefore not
comparable across runs. This tool recomputes both sides through today's
`evidence.finding_fingerprint` and diffs those, never the stored values. The
stored value is preserved per-record anyway, because stage 2
(scripts/reconcile_apply.py) needs it to look up the issue that was filed
against it.

Usage: python3 skill/scripts/reconcile.py diff RUN2.json RUN3.json --out diff.json [--summary summary.md]
"""
import argparse
import json
import os
import sys
from collections import defaultdict
from dataclasses import dataclass

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import scripts.evidence as evidence


def _resolve_part_path(base_dir, part):
    """Resolve and validate a report part continuation path within base_dir (#1122).

    #run9 SEC-D1C: the lexical normpath check confines the STRING, but a
    same-directory symlink (`base_dir/part` is a link pointing outside base_dir)
    passes it — normpath does not resolve links — and the caller's open() then
    follows it, exfiltrating an arbitrary file into the merged report. Re-resolve
    the real path and re-confine against the real base before returning, and hand
    back the RESOLVED path so the caller opens the confined target, not the link.
    """
    part = str(part)
    base_norm = os.path.normpath(base_dir or ".")
    ppath = os.path.normpath(os.path.join(base_norm, part))
    if os.path.isabs(part) or not (ppath == base_norm or ppath.startswith(base_norm + os.sep)):
        raise ValueError("invalid meta.parts entry: %r" % part)
    real_base = os.path.realpath(base_norm)
    real_ppath = os.path.realpath(ppath)
    if not (real_ppath == real_base or real_ppath.startswith(real_base + os.sep)):
        raise ValueError(
            "meta.parts entry escapes the report directory via symlink: %r" % part)
    return real_ppath


# meta.review_type values that are narrower than the whole repository by
# construction (report-schema.json: repo|file|directory|group|changes|pr). A
# run scoped to any of them cannot corroborate a repo-wide close, however many
# files its groups happen to list.
NARROWER_REVIEW_TYPES = ("file", "directory", "group", "changes", "pr")


def _stated_files(doc):
    """The files ONE report document says it reviewed, or None when it doesn't say.

    `groups[].files` is a report's own statement of coverage; paths go through
    evidence.norm_path, the same normalization reconcile_key applies, so the set
    joins with a record's coarse_key[0]. Only string entries of a `files` LIST
    count -- a mapping is not a file list, and a non-string is not a path.
    Returns None ("unknown", which the caller fails CLOSED on) when the document
    states no usable path at all, an explicit empty list included: one honest
    whole-run guard beats one "was not reviewed" line per finding.
    """
    groups = doc.get("groups")
    if not isinstance(groups, list):
        return None
    stated = set()
    for group in groups:
        files = group.get("files") if isinstance(group, dict) else None
        for entry in files if isinstance(files, list) else ():
            path = evidence.norm_path(entry) if isinstance(entry, str) else ""
            if path:
                stated.add(path)
    return stated or None


def _merge_stated(base, more):
    """Union two coverage statements. A None side ("didn't say") contributes
    nothing; the result is None only when neither side stated anything."""
    if more is None:
        return base
    return more if base is None else base | more


def _stated_review_type(doc):
    """`(value,)` when ONE document declares meta.review_type, else `()`."""
    meta = doc.get("meta")
    if not isinstance(meta, dict) or "review_type" not in meta:
        return ()
    return (meta["review_type"],)


def _resolve_review_type(main_declared, part_declared):
    """The run's declared review type -- the MAIN report's, or the conflicting
    values when a part contradicts it.

    The main document is the authority: parts are continuations of ONE run and
    meta.review_type is written once per run, so a part can only CONTRADICT the
    report, never supply what the report itself omits (a silent report is missing
    information and resolves to None, which guards). A contradiction resolves to
    the tuple of distinct values, which keeps the evidence AND can never equal
    "repo" -- the fail-closed direction, where ignoring the part would be
    fail-open. Comparison is by equality, not hashing: a report can carry any
    JSON value here.
    """
    if not main_declared:
        return None
    distinct = list(main_declared[:1])
    for value in part_declared:
        if value not in distinct:
            distinct.append(value)
    if len(distinct) == 1:
        return distinct[0]
    return tuple(sorted(distinct, key=repr))


def _section(value):
    """A report document's findings / discarded-claims section value, as a list.

    A non-list value is no list of claims: a dict would be merged as its KEYS
    and announced downstream as skipped entries, and a scalar aborted the load
    outright (`TypeError: 'int' object is not iterable`). Both read as EMPTY
    here and count nothing -- the same rule `iter_records` applies to a section
    handed to it directly, so the two layers cannot disagree (#2365). Takes the
    VALUE, not (doc, key): the key stays a constant in its caller, where
    `tests/test_agent_findings_guard.py` classifies every reader of it.
    """
    return list(value) if isinstance(value, list) else []


def load_report(path):
    """Load a report, merging confined part and rejected-claim continuations.

    Also carries what the run says it LOOKED AT, which the cross-run diff needs
    to tell "fixed" from "never reviewed" (#1807): `reviewed_files` (the union of
    groups[].files of the main document, widened by any part's, normalized;
    None when the main document states none -- a part cannot supply the claim
    the report omits) and `review_type` (meta.review_type, the main document's,
    which a part can only contradict; see _resolve_review_type). Both keys are
    additive -- every other reader indexes `findings` / `discarded_claims` by
    name and is unaffected. Both are the report's own CLAIM about its coverage,
    per FILE and per RUN: what it actually completed (meta.coverage.cells) and
    whether the finding's own panel or tool axis ran on that file are further
    cross-checks this loader does not yet read (follow-ups #2084, #2087).
    """
    with open(path, encoding="utf-8") as fh:
        report = json.load(fh)
    findings = _section(report.get("findings"))
    discarded = _section(report.get("discarded_claims"))
    reviewed_files = _stated_files(report)
    declared_main = _stated_review_type(report)
    declared_parts = []
    # Anchor to an absolute path before resolving parts: os.path.dirname on a
    # bare filename (e.g. "run2.json", the common case from the CLI run in
    # its own directory) returns "", and joining/normpath'ing a relative
    # part against "" yields a relative path that never equals "" nor starts
    # with the separator — the confinement check below would then reject a
    # legitimate same-directory part. Absolute-anchoring keeps the check
    # correct in both cases.
    base_dir = os.path.dirname(os.path.abspath(path))
    for part in (report.get("meta") or {}).get("parts") or []:
        ppath = _resolve_part_path(base_dir, part)
        with open(ppath, encoding="utf-8") as fh:
            pdata = json.load(fh)
        findings.extend(_section(pdata.get("findings")))
        discarded.extend(_section(pdata.get("discarded_claims")))
        # A part may WIDEN a claim the report already made, never supply one
        # the report omits -- the main document is the authority for both
        # coverage fields (see _resolve_review_type for the same rule).
        if reviewed_files is not None:
            reviewed_files = _merge_stated(reviewed_files, _stated_files(pdata))
        declared_parts += _stated_review_type(pdata)
    # #run9 ARC-D1A: a large report ALSO spills discarded_claims to a
    # `<stem>-discarded.json` sibling (write_report #15), leaving an empty inline
    # list + a meta.discarded_claims_file pointer. The meta.parts merge above never
    # follows that pointer, so recovery silently loses EVERY rejected claim. Merge
    # the sibling back in, through the same confinement check.
    disc_file = (report.get("meta") or {}).get("discarded_claims_file")
    if disc_file:
        with open(_resolve_part_path(base_dir, disc_file), encoding="utf-8") as fh:
            discarded.extend(_section(json.load(fh).get("discarded_claims")))
    return {"findings": findings, "discarded_claims": discarded,
            "reviewed_files": reviewed_files,
            "review_type": _resolve_review_type(declared_main, declared_parts)}


def iter_records(report):
    """Normalize findings and discarded_claims into one flat identity list.

    fingerprint is recomputed via evidence.finding_fingerprint (today's
    algorithm); stored_fingerprint is the report's own (possibly pre-P2,
    possibly corrupted) value, kept only so stage 2 can reconstruct the
    filing-time ledger key.
    """
    out = []
    for kind, key in (("finding", "findings"), ("rejected", "discarded_claims")):
        entries = report.get(key)
        # #2365: a non-list value is no list of claims at all -- a dict would
        # otherwise iterate as its KEYS -- so it reads as empty and counts
        # nothing skipped; only a real entry that is not a dict is a skip.
        skipped = 0
        for f in entries if isinstance(entries, list) else []:
            if not isinstance(f, dict):
                skipped += 1
                continue
            loc = evidence.location_of(f)
            out.append({
                "id": f.get("id"),
                "kind": kind,
                "severity": f.get("severity"),
                "panel": f.get("panel"),
                "category": f.get("category"),
                "location_file": loc.get("file") or "",
                "stored_fingerprint": f.get("fingerprint"),
                "fingerprint": evidence.finding_fingerprint(f),
                "coarse_key": evidence.reconcile_key(f),
            })
        if skipped:
            # Never a silent skip: a dropped claim is a disclosure gap.
            print("reconcile: skipped %d non-dict %s entries" % (skipped, key),
                  file=sys.stderr)
    return out


def _group_by_fingerprint(records):
    grouped = defaultdict(list)
    for r in records:
        grouped[r["fingerprint"]].append(r)
    return grouped


def _by_id(recs):
    """Records sorted by id — the tool's output must be byte-stable and
    diffable regardless of the order findings arrived in."""
    return sorted(recs, key=lambda r: r["id"] or "")


def _degenerate(grouped, run_label):
    return sorted(
        ({"fingerprint": fp, "run": run_label,
          "ids": sorted(r["id"] or "" for r in recs)}
         for fp, recs in grouped.items() if len(recs) > 1),
        key=lambda d: (d["fingerprint"], d["run"]))


GUARD_REASONS = {
    "empty_run3": "run3 has zero records -- refusing to corroborate any close",
    "no_file_overlap": ("run2/run3 file sets share zero paths -- path-shape drift "
                        "suspected; refusing to corroborate closes"),
    "run3_not_repo_wide": ("run3 was a %s-scoped review -- a narrower run cannot "
                           "corroborate a repo-wide close"),
    "run3_files_unstated": ("run3's report does not state which files it reviewed "
                            "(no groups[].files) -- refusing to corroborate closes"),
}

# Why corroboration failed, carried on every ambiguous entry as `basis`, for a
# consumer that must word its own message (scripts/reconcile_apply.py keys its
# comment template on it -- reading the reason text would be substring
# archaeology). "scope": nothing in the new run's coverage can speak to this
# file, which is EVERY whole-run guard (a zero-record run and path-shape drift
# included -- neither is an "area still active" or a re-wording) plus the
# per-record not-reviewed arm; "active": its (file, panel) still carries records
# in run3; "identity": this record's own identity cannot be pinned.

REVIEW_TYPE_UNDECLARED = ("run3 did not declare a repo-wide review type (%r) -- "
                          "refusing to corroborate closes")


def _guard_reason(close_guard, run3_review_type):
    """The operator-facing sentence for an active guard, None when none is.

    The GUARD_REASONS lookup is deliberately a loud subscript: a guard name added
    without a reason must raise here, not write `"reason": None` onto every
    ambiguous entry for stage 2 to render as an empty code span.
    """
    if close_guard is None:
        return None
    if close_guard != "run3_not_repo_wide":
        return GUARD_REASONS[close_guard]
    if run3_review_type in NARROWER_REVIEW_TYPES:
        return GUARD_REASONS[close_guard] % run3_review_type
    # Absent, empty, mis-cased, non-string, a future enum value, or parts that
    # disagree: say what was found rather than inventing a scope for it.
    return REVIEW_TYPE_UNDECLARED % (run3_review_type,)


@dataclass(frozen=True)
class _RunIndex:
    """Identity lookups and per-kind activity used by the diff decisions."""
    by_fingerprint: dict
    by_coarse_key: dict
    files: set
    activity: dict

    @classmethod
    def build(cls, records):
        by_coarse_key = defaultdict(list)
        activity: dict[tuple[str, str], dict[str, int]] = {}
        for record in records:
            key = record["coarse_key"]
            by_coarse_key[key].append(record)
            counts = activity.setdefault((key[0], key[1]), {})
            counts[record["kind"]] = counts.get(record["kind"], 0) + 1
        return cls(_group_by_fingerprint(records), by_coarse_key,
                   {key[0] for key in by_coarse_key if key[0]}, activity)


def _select_close_guard(previous, current, reviewed_files, review_type):
    """Whole-run trust failures take precedence over per-record decisions.

    Files come from normalized coarse keys so path spelling cannot mimic drift.
    A record on a file never substitutes for the report's coverage declaration.
    """
    if not previous.by_fingerprint:
        return None
    if not current.by_fingerprint:
        return "empty_run3"
    if not (previous.files & current.files):
        return "no_file_overlap"
    if reviewed_files is None:
        return "run3_files_unstated"
    if review_type != "repo":
        return "run3_not_repo_wide"
    return None


def _recurring_entry(fp, recs, current):
    """Exact records plus all coarse siblings, unioned by object identity.

    `new` omits coarse siblings, so omitting them here would lose records.
    Both indexes hold the original dicts; equal-but-distinct records stay visible.
    """
    ck = recs[0]["coarse_key"]
    exact = fp in current.by_fingerprint
    if not exact and ck not in current.by_coarse_key:
        return None
    exact_side = current.by_fingerprint[fp] if exact else []
    seen = {id(record) for record in exact_side}
    run3_side = exact_side + [record for record in current.by_coarse_key.get(ck, ())
                              if id(record) not in seen]
    return {"fingerprint": fp, "coarse_key": list(ck),
            "match_tier": "exact" if exact else "coarse", "run2": _by_id(recs),
            "run3": _by_id(run3_side),
            "kind_changed": {r["kind"] for r in recs} != {r["kind"] for r in run3_side}}


def _close_refusal(recs, current, claimed, close_guard, guard_reason):
    """Return (reason, basis), or None when all close checks pass.

    Safe-direction order: whole-run guard, ambiguous identity, missing file,
    active file/panel, then missing coverage. Activity includes rejected claims
    and is reported before missing coverage under the same key.
    """
    file_, panel_ = recs[0]["coarse_key"][:2]
    if close_guard:
        return guard_reason, "scope"
    if len({r["coarse_key"] for r in recs}) > 1:
        return "degenerate group spans multiple coarse keys", "identity"
    if not file_:
        return "no file recorded -- (file,panel)-clear cannot corroborate a fix", "identity"
    if (file_, panel_) in current.activity:
        counts = current.activity[(file_, panel_)]
        parts = []
        if counts.get("finding"):
            parts.append("%d finding(s)" % counts["finding"])
        if counts.get("rejected"):
            parts.append("%d rejected claim(s)" % counts["rejected"])
        return ("%s still active on %s (%s in run3)" %
                (panel_ or "(no panel)", file_, ", ".join(parts))), "active"
    if file_ not in claimed:
        if file_ in current.files:
            return ("run3 produced records on %s but its report does not list "
                    "it among the files it reviewed (groups[].files) -- "
                    "refusing to corroborate a close" % file_), "scope"
        return ("%s was not reviewed in run3 -- absence of findings is "
                "not a fix" % file_), "scope"
    return None


def build_diff(run2_records, run3_records, run2_path, run3_path,
               run3_reviewed_files=None, run3_review_type=None):
    """Partition cross-run identities into recurring / closed / ambiguous / new.

    A finding RECURS if its exact finding_fingerprint OR its coarse reconcile_key
    (file, panel, category[, artifact]) appears in the other run -- the artifact is
    `tool_evidence.package_name`, present only on a tool finding that names one, so
    two vulnerable jars at one manifest are two identities (#2352). The coarse tier
    catches agent findings whose title was re-worded (#914); the coarse run3 side is
    populated from every record sharing that coarse key, so a re-worded run3
    finding is never silently dropped from the diff (#914 final-review F4).
    A non-recurring run2 finding is CLOSED only when ALL of the following hold:
    no close_guard is active (see below), its fingerprint-group carries exactly
    one coarse key (a degenerate multi-key group can't be trusted to mean one
    thing), it has a recorded file (an empty file can't be corroborated by any
    (file, panel) read), its (file, panel) is entirely clear in run3 (the
    drift-proof corroboration -- category is free-text and drifts), and run3
    CLAIMS to have reviewed that file (#1807: run3 being silent about a file it
    never opened is not evidence of a fix). Failing any of those routes it to
    AMBIGUOUS instead (kept open, never auto-closed) -- when corroboration cannot
    be performed, refuse to close. Every ambiguous entry also carries `basis`,
    the machine-readable reason class (see the comment above GUARD_REASONS).

    `run3_reviewed_files` (any iterable of normalized paths -- not a bare str --
    or None) and
    `run3_review_type` are run3's own statement of what it looked at (load_report:
    groups[].files and meta.review_type). A caller that states no reviewed files
    gets the fail-CLOSED reading -- the whole-run `run3_files_unstated` guard --
    never a close on silence. Nothing else can stand in for that claim: run3
    having a record on the file proves only that something read the path, not
    that the (file, panel) being corroborated was reviewed, so it changes the
    refusal's wording, not its outcome.

    close_guard fires when corroboration itself can't be trusted for the WHOLE
    run: run3 has zero records ("empty_run3": nothing ran / nothing loaded,
    which would otherwise read as "area clear" for everything), run2 and
    run3's non-empty file sets share no path at all ("no_file_overlap": e.g.
    absolute-vs-relative path drift between the two runs), run3's report does
    not state which files it reviewed ("run3_files_unstated": no coverage claim
    to check a close against), or run3 did not declare itself repo-wide
    ("run3_not_repo_wide": meta.review_type is anything but "repo" -- an
    ALLOWLIST, because the schema REQUIRES that field, so absent, empty,
    non-string, mis-cased, unknown, or contradicted by a part is all missing
    information). Any guard routes every non-recurring group to ambiguous
    regardless of its own (file, panel) read. The order is
    safe-direction-first: a whole-run trust failure is reported before the
    narrower per-file one.

    Same-side fingerprint collisions and finding<->rejected kind flips are
    surfaced, never silently merged. Every cohort and record list is sorted, so
    re-running on the same inputs yields a byte-identical diff.
    """
    previous = _RunIndex.build(run2_records)
    current = _RunIndex.build(run3_records)
    if isinstance(run3_reviewed_files, str):
        raise TypeError("run3_reviewed_files must be an iterable of paths, not a str")
    claimed3 = set(run3_reviewed_files or ())
    close_guard = _select_close_guard(previous, current, run3_reviewed_files, run3_review_type)
    guard_reason = _guard_reason(close_guard, run3_review_type)

    recurring, closed, ambiguous = [], [], []
    for fp, recs in sorted(previous.by_fingerprint.items()):
        recurrence = _recurring_entry(fp, recs, current)
        if recurrence is not None:
            recurring.append(recurrence)
            continue
        ck = recs[0]["coarse_key"]
        entry = {"fingerprint": fp, "coarse_key": list(ck)}
        refusal = _close_refusal(recs, current, claimed3, close_guard, guard_reason)
        if refusal is not None:
            entry.update(reason=refusal[0], basis=refusal[1])
            entry["run2"] = _by_id(recs)
            ambiguous.append(entry)
        else:
            entry["reason"] = "(file,panel) clear: 0 findings in %s on %s in run3" % (
                ck[1] or "(no panel)", ck[0] or "(no file)")
            entry["run2"] = _by_id(recs)
            closed.append(entry)

    g2, g3 = previous.by_fingerprint, current.by_fingerprint
    new = [{"fingerprint": fp, "coarse_key": list(g3[fp][0]["coarse_key"]),
            "run3": _by_id(g3[fp])} for fp in sorted(set(g3) - set(g2))
           if g3[fp][0]["coarse_key"] not in previous.by_coarse_key]

    degenerate = sorted(_degenerate(g2, "run2") + _degenerate(g3, "run3"),
                        key=lambda d: (d["fingerprint"], d["run"]))
    return {"schema_version": 1,
            "meta": {"run2_report": run2_path, "run3_report": run3_path,
                     "run2_count": len(run2_records), "run3_count": len(run3_records),
                     "close_guard": close_guard,
                     "close_guard_reason": guard_reason,
                     # fingerprint-GROUP counts, not record counts -- a
                     # degenerate collision can put >1 record under one
                     # fingerprint's group entry (render_summary's header
                     # discloses this same distinction for its own counts).
                     "counts": {"recurring": len(recurring), "closed": len(closed),
                                "ambiguous": len(ambiguous), "new": len(new)},
                     "degenerate_fingerprints": degenerate},
            "recurring": recurring, "closed": closed,
            "ambiguous": ambiguous, "new": new}


def _record_count(entries, side):
    return sum(len(e[side]) for e in entries)


def render_summary(diff):
    m = diff["meta"]
    recurring_n = _record_count(diff["recurring"], "run2")
    closed_n = _record_count(diff["closed"], "run2")
    ambiguous_n = _record_count(diff["ambiguous"], "run2")
    new_n = _record_count(diff["new"], "run3")
    lines = ["# Run-3 reconciliation summary", "",
            "run2: %s (%d records)" % (m["run2_report"], m["run2_count"]),
            "run3: %s (%d records)" % (m["run3_report"], m["run3_count"])]
    # N4: with the coverage guards, a guarded run is the common case -- say so
    # once here rather than only as the same reason repeated per entry below.
    if m.get("close_guard"):
        lines.append("guard: %s (%s)" % (m["close_guard"],
                                        m.get("close_guard_reason") or "no reason recorded"))
    lines += [
            "",
            ("## Cohorts (record counts, not fingerprint-group counts — " +
             "a degenerate collision can put >1 record under one fingerprint)"),
            "- recurring: %d" % recurring_n,
            "- closed: %d" % closed_n,
            "- ambiguous: %d" % ambiguous_n,
            "- new: %d" % new_n, ""]

    sev_counts: defaultdict[str, int] = defaultdict(int)
    for entry in diff["closed"]:
        for rec in entry["run2"]:
            sev_counts[rec.get("severity") or "UNKNOWN"] += 1
    lines.append("## closed by severity")
    for sev in sorted(sev_counts):
        lines.append("- %s: %d" % (sev, sev_counts[sev]))

    kc = [e for e in diff["recurring"] if e["kind_changed"]]
    if kc:
        lines.append("")
        lines.append("## kind changed (rejected <-> finding) on %d recurring fingerprint(s)"
                     % len(kc))
        for e in kc:
            ids = [r["id"] for r in e["run2"]] + [r["id"] for r in e["run3"]]
            lines.append("- %s: %s" % (e["fingerprint"], ", ".join(ids)))

    amb = diff["ambiguous"]
    if amb:
        lines.append("")
        lines.append("## ambiguous (kept open) — %d fingerprint(s) need human review"
                     % len(amb))
        for e in amb:
            lines.append("- %s: %s" % (e["fingerprint"], e["reason"]))

    degen = m["degenerate_fingerprints"]
    if degen:
        lines.append("")
        lines.append("## WARNING: degenerate fingerprint collisions (%d)" % len(degen))
        lines.append("These findings likely have missing panel/category/title/location "
                     "fields; the fingerprint alone cannot distinguish them. Inspect "
                     "before treating as a single cohort member.")
        for d in degen:
            lines.append("- [%s] %s: %s" % (d["run"], d["fingerprint"],
                                            ", ".join(d["ids"])))
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_diff = sub.add_parser("diff")
    p_diff.add_argument("run2_report")
    p_diff.add_argument("run3_report")
    p_diff.add_argument("--out", required=True)
    p_diff.add_argument("--summary")
    a = ap.parse_args(argv)

    if a.cmd == "diff":
        r2 = iter_records(load_report(a.run2_report))
        report3 = load_report(a.run3_report)
        r3 = iter_records(report3)
        diff = build_diff(r2, r3, a.run2_report, a.run3_report,
                          run3_reviewed_files=report3["reviewed_files"],
                          run3_review_type=report3["review_type"])
        with open(a.out, "w", encoding="utf-8") as fh:
            json.dump(diff, fh, indent=2, sort_keys=True)
        print("wrote %s (recurring=%d closed=%d ambiguous=%d new=%d)"
             % (a.out, len(diff["recurring"]), len(diff["closed"]),
                len(diff["ambiguous"]), len(diff["new"])))
        if a.summary:
            with open(a.summary, "w", encoding="utf-8") as fh:
                fh.write(render_summary(diff))
            print("wrote %s" % a.summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
