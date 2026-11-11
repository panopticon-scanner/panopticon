#!/usr/bin/env python3
"""Compare N reports of one panopticon version on one pinned repo (#3560).

5.4's reproducibility goal: the same version on the same commit gives highly
similar results, and CRITICAL/HIGH findings are caught consistently.

    python3 devtools/compare_runs.py A-report.json B-report.json [C ...]
            [--out comparison.json] [--line-window 5] [--allow-unknown-commit]

The runs must share `meta.version`, `meta.ocrdb_version` and the health
basis's `review_type`, `layout_fingerprint` and `profile`, and be full reviews.
A delta comparison would also need the base and head anchors to match, and v1
does not do that. The scanned commit (`meta.target_commit`) must be recorded
and equal on every run, and no run may be dirty (`meta.target_dirty`; absent
means unknown, never clean). `--allow-unknown-commit` accepts runs that
recorded neither fact, and the summary's first line then says the commit is
unverified. Anything mixed is refused with exit 2, naming each run's value.

The population is the active findings (`findings`, continuation parts
included); discarded claims are not compared.

MATCH KEY. What makes two findings from different runs the same finding:

- A tool-sourced finding (`source: tool:<name>`) matches on
  `evidence.finding_fingerprint`: panel, category, file, rule id and package.
  Tool output is deterministic and the fingerprint already ignores lines.
- An agent finding cannot use the fingerprint, which hashes the title, and a
  reviewer rewords the title every run. It is bucketed on (normalized file,
  category). The category is the one the report shows, so a code's catalog
  category counts. Within a bucket, findings cluster by single linkage on
  their line spans: two join when `[line_start, line_end]` overlap or the gap
  between them is at most W lines (default 5). Clustering, not pairwise
  matching, is what keeps a finding cited at L40, L44 and L48 in three runs as
  one. The commit is pinned, so code does not move between runs, and W only
  absorbs citation jitter. A finding naming a file but no line clusters with
  the other lineless ones in its bucket. A finding with no location is
  bucketed on its category alone.
- Panel and OCRDb code are not in the key, because two runs can file one issue
  under different panels or with and without a code. Both are listed per
  cluster.
- A cluster that one run contributes two or more findings to is kept whole
  and flagged `ambiguous`, with the per-run counts: the run counts once for
  presence, and the operator sees where the key is coarse.

Severity per run is the highest severity that run gave inside the cluster.
A run whose own findings in one cluster disagree on severity is listed.

No pass/fail thresholds: those come after real repeat runs.
"""
import argparse
import json
import os
import sys
if __name__ == "__main__":  # run by path: puts skill/ on sys.path (#3505)
    import runpy
    runpy.run_path(os.path.join(os.path.dirname(os.path.realpath(__file__)), "_skill_bootstrap.py"))
import scripts.evidence as evidence
import scripts.synth.render as render
from scripts.tools.base import inert_text

DEFAULT_LINE_WINDOW = 5
REFUSED = 2
SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
RANK = {name: rank for rank, name in enumerate(SEVERITIES)}
ESCALATION = ("CRITICAL", "HIGH")
# Report fields that must agree across runs: (label, reader).
IDENTITY = (
    ("version", lambda r: _meta(r).get("version")),
    ("ocrdb_version", lambda r: _meta(r).get("ocrdb_version")),
    ("review_type", lambda r: _basis(r).get("review_type")),
    ("layout_fingerprint", lambda r: _basis(r).get("layout_fingerprint")),
    ("profile", lambda r: _basis(r).get("profile")),
)
TITLE_LIMIT = 100


class Refused(Exception):
    """The inputs cannot be compared; the message names why."""


def _dict(value):
    return value if isinstance(value, dict) else {}


def _meta(report):
    return _dict(report.get("meta"))


def _summary(report):
    return _dict(report.get("summary"))


def _basis(report):
    return _dict(_dict(_summary(report).get("health")).get("basis"))


def load(path):
    """The report at `path` with its continuation parts merged; refuse an unreadable one."""
    report = render._read_json_report(path)
    if not isinstance(report, dict):
        raise Refused("cannot read report %s" % path)
    if not isinstance(report.get("findings"), list):
        raise Refused("%s has no findings list" % path)
    return report


def _mixed(label, values):
    return "%s differs across runs: %s" % (
        label, ", ".join("run%d=%r" % (i + 1, v) for i, v in enumerate(values)))


def check_inputs(reports, allow_unknown_commit=False):
    """The identity the runs share, or Refused naming the first mismatch."""
    if len(reports) < 2:
        raise Refused("need at least 2 reports, got %d" % len(reports))
    for i, report in enumerate(reports):
        if not _basis(report):
            raise Refused("run%d has no summary.health.basis; it predates #3528" % (i + 1))
    shared = {}
    for label, read in IDENTITY:
        values = [read(r) for r in reports]
        if len(set(map(json.dumps, values))) != 1:
            raise Refused(_mixed(label, values))
        shared[label] = values[0]
    if shared["review_type"] != "full":
        raise Refused("only full reviews can be compared; these are %r reviews (a delta "
                      "comparison also needs matching base and head anchors)"
                      % shared["review_type"])
    commits = [_meta(r).get("target_commit") for r in reports]
    dirty = [_meta(r).get("target_dirty") for r in reports]
    if any(d is True for d in dirty):
        raise Refused("a dirty tree was scanned: " + ", ".join(
            "run%d" % (i + 1) for i, d in enumerate(dirty) if d is True))
    known = [c for c in commits if c is not None]
    if len(set(known)) > 1:
        raise Refused(_mixed("target_commit", commits))
    verified = len(known) == len(reports) and all(d is False for d in dirty)
    if not verified and not allow_unknown_commit:
        raise Refused("the scanned commit is not verified on every run (target_commit "
                      "%s, target_dirty %s); pass --allow-unknown-commit to compare anyway"
                      % (commits, dirty))
    shared["target_commit"] = known[0] if known else None
    shared["commit_verified"] = verified
    return shared


def _span(finding):
    """(start, end) lines, or None for a finding that names no line."""
    loc = evidence.location_of(finding)
    start = loc.get("line_start")
    if not isinstance(start, int) or isinstance(start, bool):
        return None
    end = loc.get("line_end")
    if not isinstance(end, int) or isinstance(end, bool) or end < start:
        end = start
    return start, end


def bucket_key(finding):
    """The part of the match key that must be equal (see the module docstring)."""
    if evidence.is_tool_sourced(finding):
        return ("tool", evidence.finding_fingerprint(finding))
    file = evidence.norm_path(evidence.location_of(finding).get("file"))
    return ("agent", file, str(finding.get("category") or ""))


def _link(members, window):
    """Single-linkage groups of (run, finding, span) members, all with a span."""
    members = sorted(members, key=lambda m: (m[2], m[0]))
    groups: list[list] = []
    reach = 0
    for member in members:
        start, end = member[2]
        if groups and start - reach <= window:
            groups[-1].append(member)
            reach = max(reach, end)
        else:
            groups.append([member])
            reach = end
    return groups


def cluster(runs, window=DEFAULT_LINE_WINDOW):
    """Clusters of [(run index, finding)] across `runs` (lists of findings)."""
    buckets: dict[tuple, list] = {}
    for index, findings in enumerate(runs):
        for finding in findings:
            if isinstance(finding, dict):
                buckets.setdefault(bucket_key(finding), []).append(
                    (index, finding, _span(finding)))
    clusters = []
    for key in sorted(buckets, key=json.dumps):
        members = buckets[key]
        if key[0] == "tool":
            clusters.append((key, members))
            continue
        lineless = [m for m in members if m[2] is None]
        if lineless:
            clusters.append((key, lineless))
        clusters.extend((key, group) for group in
                        _link([m for m in members if m[2] is not None], window))
    return clusters


def _severity(finding):
    value = str(finding.get("severity") or "").upper()
    return value if value in RANK else None


def _top(severities):
    known = [s for s in severities if s is not None]
    return max(known, key=RANK.__getitem__) if known else None


def describe(number, key, members, n_runs):
    """One cluster's record: where it is, who found it and at what severity."""
    first = min(members, key=lambda m: m[0])[1]
    loc = evidence.location_of(first)
    spans = [m[2] for m in members if m[2] is not None]
    counts = [0] * n_runs
    by_run: list[list] = [[] for _ in range(n_runs)]
    for index, finding, _span_ in members:
        counts[index] += 1
        by_run[index].append(_severity(finding))
    split = {"run%d" % (i + 1): sorted({s or "?" for s in sevs}, key=str)
             for i, sevs in enumerate(by_run) if len({s for s in sevs}) > 1}
    return {
        "id": "C%03d" % number,
        "kind": key[0],
        "file": evidence.norm_path(loc.get("file")) or None,
        "category": first.get("category"),
        "lines": [min(s[0] for s in spans), max(s[1] for s in spans)] if spans else None,
        "title": first.get("title"),
        "panels": sorted({str(m[1].get("panel")) for m in members if m[1].get("panel")}),
        "codes": sorted({str(m[1].get("code")) for m in members if m[1].get("code")}),
        "present": [c > 0 for c in counts],
        "counts": counts,
        "ambiguous": any(c > 1 for c in counts),
        "severity": [_top(sevs) for sevs in by_run],
        "severity_split": split,
    }


def agreement(records, n_runs):
    """How many clusters every run, a majority of runs, and only one run found."""
    found = [sum(r["present"]) for r in records]
    total = len(found)
    tally = {"all": sum(f == n_runs for f in found),
             "majority": sum(2 * f > n_runs for f in found),
             "only_one": sum(f == 1 for f in found)}
    return {"clusters": total, **tally,
            "shares": {k: (round(v / total, 4) if total else None) for k, v in tally.items()},
            "ambiguous": sum(r["ambiguous"] for r in records)}


def critical_high(records):
    """Per cluster any run rated CRITICAL/HIGH: runs that caught it at the top
    severity any run gave, at a lower one, or not at all."""
    rows = []
    for record in records:
        top = _top(record["severity"])
        if top not in ESCALATION:
            continue
        sevs = record["severity"]
        rows.append({
            "id": record["id"], "title": record["title"], "top": top,
            "same": sum(s == top for s in sevs),
            "lower": sum(s is not None and s != top for s in sevs),
            "missed": sum(not p for p in record["present"]),
            "severity": sevs,
        })
    return rows


def scores(reports):
    """Health index, letter and provisional state per run, with the spread."""
    rows = []
    for report in reports:
        summary = _summary(report)
        rows.append({"score": _dict(summary.get("health")).get("score"),
                     "letter": summary.get("overall_grade"),
                     "provisional": summary.get("provisional_grade"),
                     "certified": summary.get("coverage_certified")})
    known = [r["score"] for r in rows
             if isinstance(r["score"], (int, float)) and not isinstance(r["score"], bool)]
    if not known:
        return {"runs": rows, "min": None, "max": None, "spread": None}
    return {"runs": rows, "min": min(known), "max": max(known),
            "spread": round(max(known) - min(known), 4)}


def cells(reports):
    """Planned vs answered review cells per run; `lost` marks a run that answered fewer."""
    rows = []
    for report in reports:
        basis = _basis(report)
        planned, answered = basis.get("cells_planned"), basis.get("cells_answered")
        known = isinstance(planned, int) and isinstance(answered, int)
        rows.append({"planned": planned, "answered": answered,
                     "lost": (answered < planned) if known else None})
    return rows


def compare(paths, window=DEFAULT_LINE_WINDOW, allow_unknown_commit=False):
    """The comparison document for the reports at `paths`."""
    if window < 0:
        raise Refused("--line-window must be 0 or more, got %d" % window)
    if len({os.path.realpath(p) for p in paths}) != len(paths):
        raise Refused("the same report was given twice")
    reports = [load(p) for p in paths]
    shared = check_inputs(reports, allow_unknown_commit)
    n_runs = len(reports)
    records = [describe(i + 1, key, members, n_runs) for i, (key, members)
               in enumerate(cluster([r["findings"] for r in reports], window))]
    return {
        "line_window": window,
        "runs": ["run%d: %s" % (i + 1, os.path.basename(p)) for i, p in enumerate(paths)],
        "identity": shared,
        "agreement": agreement(records, n_runs),
        "critical_high": critical_high(records),
        "scores": scores(reports),
        "cells": cells(reports),
        "clusters": records,
    }


def _text(value, mode="label"):
    return inert_text("" if value is None else str(value), limit=TITLE_LIMIT, mode=mode)


def _num(value):
    return "-" if value is None else ("%.1f" % value if isinstance(value, float) else str(value))


def summary_lines(doc):
    """The short text summary; the first line says when the commit is unverified."""
    ident = doc["identity"]
    n_runs = len(doc["runs"])
    lines = []
    if not ident["commit_verified"]:
        lines.append("COMMIT UNVERIFIED: not every run recorded a clean target commit; "
                     "differences may be code changes, not scanner variance")
    lines.append("compare_runs: %d runs of panopticon %s on %s (line window %d)" % (
        n_runs, _text(ident["version"]), _text(ident["target_commit"] or "unknown commit"),
        doc["line_window"]))
    lines += ["  " + _text(run, "path") for run in doc["runs"]]
    agree = doc["agreement"]
    shares = agree["shares"]
    lines.append("findings: %d clusters; all %d runs %d (%s), majority %d (%s), only one %d (%s); "
                 "ambiguous %d" % (
                     agree["clusters"], n_runs, agree["all"], _num(shares["all"]),
                     agree["majority"], _num(shares["majority"]),
                     agree["only_one"], _num(shares["only_one"]), agree["ambiguous"]))
    rows = doc["critical_high"]
    lines.append("CRITICAL/HIGH: %d clusters, %d caught at the same severity by every run" % (
        len(rows), sum(r["same"] == n_runs for r in rows)))
    for row in rows:
        if row["same"] != n_runs:
            lines.append("  %s %s: same %d, lower %d, missed %d -- %s" % (
                row["id"], row["top"], row["same"], row["lower"], row["missed"],
                _text(row["title"])))
    for record in doc["clusters"]:
        if record["severity_split"]:
            lines.append("  %s severity split within a run: %s -- %s" % (
                record["id"], ", ".join("%s %s" % (run, "/".join(sevs)) for run, sevs
                                        in sorted(record["severity_split"].items())),
                _text(record["title"])))
    sc = doc["scores"]
    lines.append("scores: min %s, max %s, spread %s" % (
        _num(sc["min"]), _num(sc["max"]), _num(sc["spread"])))
    for i, (row, cell) in enumerate(zip(sc["runs"], doc["cells"])):
        lines.append("  run%d: score %s, letter %s, provisional %s, certified %s; cells %s/%s%s" % (
            i + 1, _num(row["score"]), _text(row["letter"] or "-"),
            _text(row["provisional"] or "-"), row["certified"],
            _num(cell["answered"]), _num(cell["planned"]),
            " LOST CELLS (misses may be lost coverage)" if cell["lost"] else ""))
    return lines


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("reports", nargs="+", help="two or more -report.json files")
    ap.add_argument("--out", help="write the comparison JSON here")
    ap.add_argument("--line-window", type=int, default=DEFAULT_LINE_WINDOW,
                    help="most lines between two agent findings' spans for them to "
                         "match (default %(default)s)")
    ap.add_argument("--allow-unknown-commit", action="store_true",
                    help="compare runs that did not record a clean target commit")
    args = ap.parse_args(argv)
    try:
        doc = compare(args.reports, args.line_window, args.allow_unknown_commit)
    except Refused as exc:
        print("compare_runs: refused: %s" % exc, file=sys.stderr)
        return REFUSED
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2, sort_keys=True)
            fh.write("\n")
    print("\n".join(summary_lines(doc)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
