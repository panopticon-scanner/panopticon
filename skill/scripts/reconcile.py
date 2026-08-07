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
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import scripts.evidence as evidence


def _resolve_part_path(base_dir, part):
    part = str(part)
    ppath = os.path.normpath(os.path.join(base_dir, part))
    base_dir_norm = os.path.normpath(base_dir)
    if os.path.isabs(part) or not (ppath == base_dir_norm
                                   or ppath.startswith(base_dir_norm + os.sep)):
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
                "location_file": loc.get("file") or "",
                "stored_fingerprint": f.get("fingerprint"),
                "fingerprint": evidence.finding_fingerprint(f),
            })
    return out
