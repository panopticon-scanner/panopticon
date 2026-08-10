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


def build_diff(run2_records, run3_records, run2_path, run3_path):
    """Partition cross-run identities into recurring / closed / ambiguous / new.

    A finding RECURS if its exact finding_fingerprint OR its coarse reconcile_key
    (file, panel, category) appears in the other run -- the coarse tier catches
    agent findings whose title was re-worded (#914). A non-recurring run2
    finding is CLOSED only when its (file, panel) is entirely clear in run3 (the
    drift-proof corroboration -- category is free-text and drifts); otherwise it
    is AMBIGUOUS (kept open, never auto-closed). Same-side fingerprint collisions
    and finding<->rejected kind flips are surfaced, never silently merged. Every
    cohort and record list is sorted, so re-running on the same inputs yields a
    byte-identical diff.
    """
    g2 = _group_by_fingerprint(run2_records)
    g3 = _group_by_fingerprint(run3_records)
    fps2, fps3 = set(g2), set(g3)
    ck2 = {r["coarse_key"] for r in run2_records}
    ck3 = {r["coarse_key"] for r in run3_records}
    # (file, panel) still active in run3 -- the close corroboration.
    active3 = {(ck[0], ck[1]) for ck in ck3}
    active3_counts = {}
    for r in run3_records:
        fp_panel = (r["coarse_key"][0], r["coarse_key"][1])
        active3_counts[fp_panel] = active3_counts.get(fp_panel, 0) + 1

    recurring, closed, ambiguous = [], [], []
    for fp in sorted(fps2):
        recs = g2[fp]
        ck = recs[0]["coarse_key"]  # one coarse key per fingerprint-group
        exact = fp in fps3
        coarse = ck in ck3
        if exact or coarse:
            kinds2 = {r["kind"] for r in recs}
            kinds3 = {r["kind"] for r in g3[fp]} if exact else kinds2
            recurring.append({"fingerprint": fp, "coarse_key": list(ck),
                              "match_tier": "exact" if exact else "coarse",
                              "run2": _by_id(recs),
                              "run3": _by_id(g3[fp]) if exact else [],
                              "kind_changed": exact and kinds2 != kinds3})
        else:
            file_, panel_ = ck[0], ck[1]
            fdisp, pdisp = file_ or "(no file)", panel_ or "(no panel)"
            if (file_, panel_) in active3:
                ambiguous.append({"fingerprint": fp, "coarse_key": list(ck),
                                  "reason": "%s still active on %s (%d finding(s) in run3)"
                                  % (pdisp, fdisp, active3_counts[(file_, panel_)]),
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
