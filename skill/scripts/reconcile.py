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


def _resolve_review_type(declared):
    """The run's declared review type, or the conflicting values when the report
    and its parts disagree.

    Parts are continuations of ONE run and meta.review_type is written once per
    run, so a part declaring a different one is a malformed artifact. Returning
    the tuple of distinct values keeps the evidence AND can never equal "repo",
    which is the fail-closed direction (ignoring the part would be fail-open).
    Comparison is by equality, not hashing: a report can carry any JSON value
    here. None when no document declared one.
    """
    distinct = []
    for value in declared:
        if value not in distinct:
            distinct.append(value)
    if not distinct:
        return None
    if len(distinct) == 1:
        return distinct[0]
    return tuple(sorted(distinct, key=repr))


def load_report(path):
    """Load a report, merging confined part and rejected-claim continuations.

    Also carries what the run says it LOOKED AT, which the cross-run diff needs
    to tell "fixed" from "never reviewed" (#1807): `reviewed_files` (the union of
    groups[].files across the main document and every merged part, normalized;
    None when no document states any) and `review_type` (meta.review_type,
    resolved across the same documents by _resolve_review_type). Both keys are
    additive -- every other reader indexes `findings` / `discarded_claims` by
    name and is unaffected. Both are the report's own CLAIM about its coverage;
    what it actually completed (meta.coverage.cells) is a further cross-check
    this loader does not yet read (follow-up #2084).
    """
    with open(path, encoding="utf-8") as fh:
        report = json.load(fh)
    findings = list(report.get("findings") or [])
    discarded = list(report.get("discarded_claims") or [])
    reviewed_files = _stated_files(report)
    declared_types = list(_stated_review_type(report))
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
        findings.extend(pdata.get("findings") or [])
        discarded.extend(pdata.get("discarded_claims") or [])
        reviewed_files = _merge_stated(reviewed_files, _stated_files(pdata))
        declared_types += _stated_review_type(pdata)
    # #run9 ARC-D1A: a large report ALSO spills discarded_claims to a
    # `<stem>-discarded.json` sibling (write_report #15), leaving an empty inline
    # list + a meta.discarded_claims_file pointer. The meta.parts merge above never
    # follows that pointer, so recovery silently loses EVERY rejected claim. Merge
    # the sibling back in, through the same confinement check.
    disc_file = (report.get("meta") or {}).get("discarded_claims_file")
    if disc_file:
        with open(_resolve_part_path(base_dir, disc_file), encoding="utf-8") as fh:
            discarded.extend(json.load(fh).get("discarded_claims") or [])
    return {"findings": findings, "discarded_claims": discarded,
            "reviewed_files": reviewed_files,
            "review_type": _resolve_review_type(declared_types)}


def iter_records(report):
    """Normalize findings and discarded_claims into one flat identity list.

    fingerprint is recomputed via evidence.finding_fingerprint (today's
    algorithm); stored_fingerprint is the report's own (possibly pre-P2,
    possibly corrupted) value, kept only so stage 2 can reconstruct the
    filing-time ledger key.
    """
    out = []
    for kind, key in (("finding", "findings"), ("rejected", "discarded_claims")):
        for f in report.get(key) or []:
            loc = f.get("location") or {}
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

# Why corroboration failed, for a consumer that must word its own message
# (scripts/reconcile_apply.py keys its comment template on "scope" -- reading the
# reason text would be substring archaeology). "scope": the new run's coverage
# cannot speak to this file; "active": its (file, panel) still carries records;
# "identity": this record's own identity can't be pinned; "run": run3 produced
# nothing; "drift": the two runs' path shapes disagree.
GUARD_BASIS = {"empty_run3": "run", "no_file_overlap": "drift",
               "run3_files_unstated": "scope", "run3_not_repo_wide": "scope"}

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


def build_diff(run2_records, run3_records, run2_path, run3_path,
               run3_reviewed_files=None, run3_review_type=None):
    """Partition cross-run identities into recurring / closed / ambiguous / new.

    A finding RECURS if its exact finding_fingerprint OR its coarse reconcile_key
    (file, panel, category) appears in the other run -- the coarse tier catches
    agent findings whose title was re-worded (#914); the coarse run3 side is
    populated from every record sharing that coarse key, so a re-worded run3
    finding is never silently dropped from the diff (#914 final-review F4).
    A non-recurring run2 finding is CLOSED only when ALL of the following hold:
    no close_guard is active (see below), its fingerprint-group carries exactly
    one coarse key (a degenerate multi-key group can't be trusted to mean one
    thing), it has a recorded file (an empty file can't be corroborated by any
    (file, panel) read), its (file, panel) is entirely clear in run3 (the
    drift-proof corroboration -- category is free-text and drifts), and that
    file is one run3 READ (#1807: run3 being silent about a file it never opened
    is not evidence of a fix). Failing any of those routes it to AMBIGUOUS
    instead (kept open, never auto-closed) -- when corroboration cannot be
    performed, refuse to close. Every ambiguous entry also carries `basis`, the
    machine-readable reason class (see GUARD_BASIS).

    `run3_reviewed_files` / `run3_review_type` are run3's own statement of what
    it looked at (load_report: groups[].files and meta.review_type). A caller
    that states no reviewed files gets the fail-CLOSED reading -- the whole-run
    `run3_files_unstated` guard -- never a close on silence. "Read" is the union
    of that statement with the files run3 actually produced records on: a record
    on a file is proof it was read, and groups[].files under-states real coverage
    (it is discovery's filtered, truncated reviewable set, and a tool finding
    joins a group by path membership alone).

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
    g2 = _group_by_fingerprint(run2_records)
    g3 = _group_by_fingerprint(run3_records)
    fps2, fps3 = set(g2), set(g3)
    ck2 = {r["coarse_key"] for r in run2_records}
    ck3 = {r["coarse_key"] for r in run3_records}
    g3_by_ck = defaultdict(list)
    for r in run3_records:
        g3_by_ck[r["coarse_key"]].append(r)

    # (file, panel) still active in run3 -- the close corroboration. Counted
    # per kind (F5): a rejected claim on that (file, panel) blocks a close the
    # same as a live finding does (safe direction), but the reason string must
    # not call a rejected claim a "finding".
    active3 = {(ck[0], ck[1]) for ck in ck3}
    active3_counts: dict[tuple[str, str], dict[str, int]] = {}
    for r in run3_records:
        file_panel = (r["coarse_key"][0], r["coarse_key"][1])
        counts = active3_counts.setdefault(file_panel, {})
        counts[r["kind"]] = counts.get(r["kind"], 0) + 1

    # F2: refuse to corroborate ANY close when corroboration can't be trusted
    # for the whole run -- see close_guard in the docstring.
    # coarse_key[0] (not the raw location_file) so a trivial "./"-prefix or
    # backslash difference between runs -- already normalized away for coarse
    # matching -- doesn't spuriously trip the drift guard.
    files2 = {r["coarse_key"][0] for r in run2_records if r["coarse_key"][0]}
    files3 = {r["coarse_key"][0] for r in run3_records if r["coarse_key"][0]}
    # #1807: what run3 READ = what it CLAIMS it reviewed + what it demonstrably
    # produced records on. A record is proof of reading, and groups[].files
    # under-states coverage, so refusing on the claim alone would both state a
    # falsehood about a file run3 reported on and make that cohort permanently
    # un-closable.
    reviewed3 = (run3_reviewed_files or set()) | files3

    close_guard = None
    if run2_records and not run3_records:
        close_guard = "empty_run3"
    elif run2_records and run3_records:
        if not (files2 & files3):
            close_guard = "no_file_overlap"
        elif run3_reviewed_files is None:
            # #1807: no groups[].files anywhere in run3's report. Fail CLOSED --
            # without a coverage claim, "0 findings on that file" is unreadable.
            close_guard = "run3_files_unstated"
        elif run3_review_type != "repo":
            close_guard = "run3_not_repo_wide"
    guard_reason = _guard_reason(close_guard, run3_review_type)

    recurring, closed, ambiguous = [], [], []
    for fp in sorted(fps2):
        recs = g2[fp]
        ck = recs[0]["coarse_key"]  # one coarse key per fingerprint-group
        exact = fp in fps3
        coarse = ck in ck3
        if exact or coarse:
            # The run3 side carries the exact-fingerprint records PLUS every
            # coarse-key sibling (#954): `new` suppresses a run3 fingerprint
            # whose coarse key was seen in run2, so an exact entry that
            # ignored siblings would drop them from every cohort — the
            # exact-tier mirror of the coarse-tier vanishing bug (F4). Union
            # by object identity: both indexes hold the same record dicts.
            exact_side = g3[fp] if exact else []
            seen = {id(r) for r in exact_side}
            run3_side = exact_side + [r for r in g3_by_ck[ck]
                                      if id(r) not in seen]
            kinds2 = {r["kind"] for r in recs}
            kinds3 = {r["kind"] for r in run3_side}
            recurring.append({"fingerprint": fp, "coarse_key": list(ck),
                              "match_tier": "exact" if exact else "coarse",
                              "run2": _by_id(recs),
                              "run3": _by_id(run3_side),
                              "kind_changed": kinds2 != kinds3})
            continue

        file_, panel_ = ck[0], ck[1]
        fdisp, pdisp = file_ or "(no file)", panel_ or "(no panel)"
        # Decision order (safe direction first, #914 final-review ordering
        # note): (a) close_guard active; (b) degenerate multi-coarse-key
        # group; (c) no file recorded; (d) (file,panel) still active; (e) run3
        # never read that file (#1807); only then (f) closed. (d) before (e) so
        # a file run3 DID report on gets the reason a triager can act on.
        if close_guard:
            reason, basis = guard_reason, GUARD_BASIS[close_guard]
        elif len({r["coarse_key"] for r in recs}) > 1:
            reason, basis = "degenerate group spans multiple coarse keys", "identity"
        elif not file_:
            reason, basis = ("no file recorded -- (file,panel)-clear "
                             "cannot corroborate a fix"), "identity"
        elif (file_, panel_) in active3:
            counts = active3_counts[(file_, panel_)]
            parts = []
            if counts.get("finding"):
                parts.append("%d finding(s)" % counts["finding"])
            if counts.get("rejected"):
                parts.append("%d rejected claim(s)" % counts["rejected"])
            reason = "%s still active on %s (%s in run3)" % (pdisp, fdisp,
                                                             ", ".join(parts))
            basis = "active"
        elif file_ not in reviewed3:
            # run3 both omitted this file from groups[].files AND produced no
            # record on it, so nothing in its report speaks to the file.
            reason = ("%s was not reviewed in run3 -- absence of findings is "
                      "not a fix" % file_)
            basis = "scope"
        else:
            closed.append({"fingerprint": fp, "coarse_key": list(ck),
                           "reason": "(file,panel) clear: 0 findings in %s on %s in run3"
                           % (pdisp, fdisp),
                           "run2": _by_id(recs)})
            continue
        ambiguous.append({"fingerprint": fp, "coarse_key": list(ck),
                          "reason": reason, "basis": basis, "run2": _by_id(recs)})

    new = []
    for fp in sorted(fps3 - fps2):
        recs = g3[fp]
        ck = recs[0]["coarse_key"]
        if ck not in ck2:  # a run3 fp whose coarse key matched run2 IS that recurrence
            new.append({"fingerprint": fp, "coarse_key": list(ck), "run3": _by_id(recs)})

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
