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
    part = str(part)
    base_real = os.path.realpath(base_dir)
    ppath = os.path.realpath(os.path.join(base_real, part))
    if os.path.isabs(part) or not (ppath == base_real or ppath.startswith(base_real + os.sep)):
        raise ValueError("invalid meta.parts entry: %r" % part)
    return ppath


def load_report(path):
    """Load a report, merging meta.parts continuation files.

    Mirrors scripts/file_issues.py's merge (same confinement check) so a
    part cannot point outside the report's own directory.
    """
    with open(path, encoding="utf-8") as fh:
        report = json.load(fh)
    findings = list(report.get("findings") or [])
    discarded = list(report.get("discarded_claims") or [])
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
    return {"findings": findings, "discarded_claims": discarded}


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
}


def build_diff(run2_records, run3_records, run2_path, run3_path):
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
    (file, panel) read), and its (file, panel) is entirely clear in run3 (the
    drift-proof corroboration -- category is free-text and drifts). Failing any
    of those routes it to AMBIGUOUS instead (kept open, never auto-closed) --
    when corroboration cannot be performed, refuse to close.

    close_guard fires when corroboration itself can't be trusted for the WHOLE
    run: run3 has zero records ("empty_run3": nothing ran / nothing loaded,
    which would otherwise read as "area clear" for everything), or run2 and
    run3's non-empty file sets share no path at all ("no_file_overlap": e.g.
    absolute-vs-relative path drift between the two runs). Either guard routes
    every non-recurring group to ambiguous regardless of its own (file, panel)
    read.

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
    active3_counts = {}
    for r in run3_records:
        file_panel = (r["coarse_key"][0], r["coarse_key"][1])
        counts = active3_counts.setdefault(file_panel, {})
        counts[r["kind"]] = counts.get(r["kind"], 0) + 1

    # F2: refuse to corroborate ANY close when corroboration can't be trusted
    # for the whole run -- see close_guard in the docstring.
    close_guard = None
    if run2_records and not run3_records:
        close_guard = "empty_run3"
    elif run2_records and run3_records:
        # coarse_key[0] (not the raw location_file) so a trivial "./"-prefix or
        # backslash difference between runs -- already normalized away for
        # coarse matching -- doesn't spuriously trip the drift guard.
        files2 = {r["coarse_key"][0] for r in run2_records if r["coarse_key"][0]}
        files3 = {r["coarse_key"][0] for r in run3_records if r["coarse_key"][0]}
        if not (files2 & files3):
            close_guard = "no_file_overlap"

    recurring, closed, ambiguous = [], [], []
    for fp in sorted(fps2):
        recs = g2[fp]
        ck = recs[0]["coarse_key"]  # one coarse key per fingerprint-group
        exact = fp in fps3
        coarse = ck in ck3
        if exact or coarse:
            run3_side = g3[fp] if exact else g3_by_ck[ck]
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
        # group; (c) no file recorded; (d) (file,panel) still active; only
        # then (e) closed.
        if close_guard:
            ambiguous.append({"fingerprint": fp, "coarse_key": list(ck),
                              "reason": GUARD_REASONS[close_guard],
                              "run2": _by_id(recs)})
        elif len({r["coarse_key"] for r in recs}) > 1:
            ambiguous.append({"fingerprint": fp, "coarse_key": list(ck),
                              "reason": "degenerate group spans multiple coarse keys",
                              "run2": _by_id(recs)})
        elif not file_:
            ambiguous.append({"fingerprint": fp, "coarse_key": list(ck),
                              "reason": ("no file recorded -- (file,panel)-clear "
                                        "cannot corroborate a fix"),
                              "run2": _by_id(recs)})
        elif (file_, panel_) in active3:
            counts = active3_counts[(file_, panel_)]
            parts = []
            if counts.get("finding"):
                parts.append("%d finding(s)" % counts["finding"])
            if counts.get("rejected"):
                parts.append("%d rejected claim(s)" % counts["rejected"])
            ambiguous.append({"fingerprint": fp, "coarse_key": list(ck),
                              "reason": "%s still active on %s (%s in run3)"
                              % (pdisp, fdisp, ", ".join(parts)),
                              "run2": _by_id(recs)})
        else:
            closed.append({"fingerprint": fp, "coarse_key": list(ck),
                           "reason": "(file,panel) clear: 0 findings in %s on %s in run3"
                           % (pdisp, fdisp),
                           "run2": _by_id(recs)})

    new = []
    for fp in sorted(fps3 - fps2):
        recs = g3[fp]
        ck = recs[0]["coarse_key"]
        if ck not in ck2:  # a run3 fp whose coarse key matched run2 IS that recurrence
            new.append({"fingerprint": fp, "coarse_key": list(ck), "run3": _by_id(recs)})

    degenerate = sorted(_degenerate(g2, "run2") + _degenerate(g3, "run3"),
                        key=lambda d: (d["fingerprint"], d["run"]))
    return {"meta": {"run2_report": run2_path, "run3_report": run3_path,
                     "run2_count": len(run2_records), "run3_count": len(run3_records),
                     "close_guard": close_guard,
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
            "run3: %s (%d records)" % (m["run3_report"], m["run3_count"]),
            "", "## Cohorts (record counts, not fingerprint-group counts — "
                "a degenerate collision can put >1 record under one fingerprint)",
            "- recurring: %d" % recurring_n,
            "- closed: %d" % closed_n,
            "- ambiguous: %d" % ambiguous_n,
            "- new: %d" % new_n, ""]

    sev_counts = defaultdict(int)
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
        r3 = iter_records(load_report(a.run3_report))
        diff = build_diff(r2, r3, a.run2_report, a.run3_report)
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
