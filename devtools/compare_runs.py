#!/usr/bin/env python3
"""Compare N reports of one panopticon version on one pinned repo (#3560).

5.4's reproducibility goal: the same version on the same commit gives highly
similar results, and CRITICAL/HIGH findings are caught consistently.

    python3 devtools/compare_runs.py A-report.json B-report.json [C ...]
            [--out comparison.json] [--line-window 5] [--allow-unknown-commit]

The runs must share `meta.version`, `meta.ocrdb_version` and the health
basis's `review_type`, `layout_fingerprint` and `profile`, and be full reviews.
A delta comparison would also need the base and head anchors to match, and v1
does not do that. The scanned commit (`meta.target_commit`, a full SHA-1 or
SHA-256 object name; any other shape reads as unrecorded) must be recorded
and equal on every run, and no run may be dirty (`meta.target_dirty`; absent
means unknown, never clean). `--allow-unknown-commit` accepts runs that
recorded neither fact, and the summary's first line then says the commit is
unverified. Anything mixed is refused with exit 2, naming each run's value.

Models are disclosed, never refused (#3626): when the runs' `meta.model_strict`
differ, or any run ran a dispatch on a fallback rung (`meta.model_substitutions`,
#3582), the summary says so per entry, requested and bound shown apart. A report
from before #3582 reads as "not recorded", never as strict or as no fallbacks.

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
  bucketed on its category alone. Paths compare exactly as written, apart from
  a leading `./` (`evidence.norm_path`, the #2988 policy).
- Panel and OCRDb code are not in the key, because two runs can file one issue
  under different panels or with and without a code. Both are listed per
  cluster.
- A cluster that one run contributes two or more findings to is kept whole
  and flagged `ambiguous`, with the per-run counts: the run counts once for
  presence, and the operator sees where the key is coarse.

Severity per run is the highest severity that run gave inside the cluster.
A run whose own findings in one cluster disagree on severity is listed.

The output does not depend on input order. A cluster's representative title,
file and line come from its most severe member, then by file, line and title,
so reordering the findings inside a run changes nothing, and reordering the
runs only permutes the per-run lists.

No pass/fail thresholds: those come after real repeat runs.
"""
import argparse
import json
import os
import re
import sys
if __name__ == "__main__":  # run by path: puts skill/ on sys.path (#3505)
    import runpy
    runpy.run_path(os.path.join(os.path.dirname(os.path.realpath(__file__)), "_skill_bootstrap.py"))
import scripts.evidence as evidence
import scripts.model_disclosure as model_disclosure
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
# #3626: a run's model line names its request, bound model, route and reason; a title's
# bound would cut the disclosure mid-sentence.
MODEL_LIMIT = 300
# The schema's `meta.target_commit` pattern (#3560).
COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


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


def _shape_error(path):
    """Why the file at `path` cannot be merged, or None. Checked before the shared
    reader, which assumes these shapes."""
    try:
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, ValueError) as exc:
        return "cannot read it (%s)" % exc
    if not isinstance(raw, dict):
        return "its top level is not an object"
    meta = raw.get("meta", {})
    if not isinstance(meta, dict):
        return "its meta is not an object"
    parts = meta.get("parts", [])
    if not isinstance(parts, list) or not all(isinstance(p, str) for p in parts):
        return "its meta.parts is not a list of file names"
    disc = meta.get("discarded_claims_file")
    if disc is not None and not isinstance(disc, str):
        return "its meta.discarded_claims_file is not a file name"
    return None


def load(path):
    """The report at `path` with its continuation parts merged; refuse an unreadable one."""
    problem = _shape_error(path)
    if problem:
        raise Refused("report %s is malformed: %s" % (path, problem))
    try:
        report = render._read_json_report(path)
    except (AttributeError, TypeError) as exc:     # a part or sibling that is not an object
        raise Refused("report %s has a malformed continuation file (%s)" % (path, exc))
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
        if any(v is None for v in values):
            raise Refused("%s is not recorded on every run: %s" % (label, ", ".join(
                "run%d=%r" % (i + 1, v) for i, v in enumerate(values))))
        if len(set(map(json.dumps, values))) != 1:
            raise Refused(_mixed(label, values))
        shared[label] = values[0]
    if shared["review_type"] != "full":
        raise Refused("only full reviews can be compared; these are %r reviews (a delta "
                      "comparison also needs matching base and head anchors)"
                      % shared["review_type"])
    commits = [_commit(_meta(r).get("target_commit")) for r in reports]
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


def _commit(value):
    """`value` when it has the schema's commit shape, else None (unrecorded)."""
    return value if isinstance(value, str) and COMMIT.fullmatch(value) else None


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


def _representative_order(finding, span):
    """A total order over findings that ignores where they sat in the input."""
    severity = _severity(finding)
    return (-RANK[severity] if severity else 1,
            evidence.norm_path(evidence.location_of(finding).get("file")),
            span is None, span or (0, 0), str(finding.get("title") or ""),
            json.dumps(finding, sort_keys=True, default=str))


def describe(number, key, members, n_runs):
    """One cluster's record: where it is, who found it and at what severity."""
    first = min(members, key=lambda m: _representative_order(m[1], m[2]))[1]
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
        # #3626: disclosed, never refused -- runs that fell back, or ran non-strict,
        # did not run the same models (model_disclosure explains the reading).
        "models": model_disclosure.compare_models([_meta(r) for r in reports]),
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
    lines += model_lines(doc["models"])
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


def model_lines(models):
    """#3626: what the runs' models were, when it could change the comparison."""
    if not models["recorded"]:
        return ["models: model fallbacks not recorded on any run (the reports predate #3582)"]
    if not models["disclose"]:
        return ["models: every run %s, and none ran on a fallback"
                % model_disclosure.strict_word(models["strict"][0])]
    lines = ["MODELS DIFFER OR FELL BACK: %s; %d entr%s ran on a fallback in %s" % (
        ", ".join("run%d %s" % (i + 1, model_disclosure.strict_word(s))
                  for i, s in enumerate(models["strict"])),
        len(models["entries"]), "y" if len(models["entries"]) == 1 else "ies",
        "the runs that recorded it" if models["partial"] else "some run")]
    for i, value in enumerate(models["unreadable"]):
        if value:
            lines.append("  run%d: %s" % (i + 1, model_disclosure.unreadable_word(value)))
    for row in models["entries"]:
        shared = row["requested"]
        lines.append("  %s%s: %s%s%s" % (
            _text(row["entry"]), " (%s)" % _text(row["role"]) if row["role"] else "",
            "requested %s; " % _text(shared) if shared else "",
            "; ".join("run%d %s" % (i + 1, inert_text(model_disclosure.ran_word(
                ran, with_requested=not shared, with_route=row["routes_differ"]),
                limit=MODEL_LIMIT)) for i, ran in enumerate(row["runs"])),
            "" if row["same"] else " -- DIFFERS ACROSS RUNS"))
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
