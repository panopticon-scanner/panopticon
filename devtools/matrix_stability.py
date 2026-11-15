#!/usr/bin/env python3
"""How much a review's results move when the matrix does (#3651, phase 1).

`driver setup` proposes a different matrix nearly every time it is asked. Every
review-stability number so far froze one draft per target, so what a different
draft does to the results was never measured. This scores it, from finished
reports. It runs nothing and reads nothing but the reports it is given.

    python3 devtools/matrix_stability.py DRAFT-report.json [DRAFT-report.json ...]
            [--baseline FROZEN-report.json [FROZEN-report.json ...]]
            [--out stability.json] [--detail] [--line-window 5]
            [--allow-unknown-commit]

The positional reports are runs of one version on one commit, each under its
own setup draft. `--baseline` reports are runs on that same commit that all
used ONE matrix: the frozen-matrix repeat runs. They measure the review's own
run-to-run noise, so what a different draft adds is the difference between the
two groups. Without a baseline the script still reports the draft runs, and
says that noise is not separated.

WHAT IT REPORTS, for the baseline group and the draft group side by side:

- CRITICAL, HIGH and HIGH+ (either) finding sets, twice: every active finding,
  and the gate-eligible ones (confirmed evidence). Per group: the mean, lowest
  and highest pairwise Jaccard similarity, and how many findings every run,
  most runs, and only one run found. Two runs that both found nothing are
  identical (1.0).
- The gate: each verdict's count, and how many runs differ from the commonest.
- The letter (provisional ones marked) and the health score: lowest, highest,
  spread, mean and standard deviation.
- Per draft run against the baseline: how many of the findings MOST baseline
  runs found it missed, and how many it found that NO baseline run did.
- How far the drafts themselves differ: group count, shared group names, and
  the share of file pairs that are grouped together in both of two drafts.
  With three or more pairs, the correlation between that and the gate-eligible
  HIGH+ similarity of the same two runs: do results move with the matrix?

Findings are matched across runs by `compare_runs`' clustering, whose key holds
no group and no panel name, so it holds across matrices.

OUTPUT IS AGGREGATES ONLY by default: counts, ratios, hashes and run labels
(`draft1`, `base1`). No finding title, no path, no target name and no commit.
So the summary can leave the machine the runs were made on. `--detail` adds the
report file names and the matched clusters, for reading locally.

Refused with exit 2: fewer than two draft runs; a baseline that is not one
matrix, or has one run; runs of different versions, commits or profiles.
A dirty tree is accepted only for a run whose own report says its matrix is a
working-tree file, and the summary says so (see `compare_runs`).

No pass/fail thresholds: those are the owner's to set from the numbers.
"""
import argparse
import itertools
import json
import math
import os
import sys
if __name__ == "__main__":  # run by path: puts skill/ on sys.path (#3505)
    import runpy
    runpy.run_path(os.path.join(os.path.dirname(os.path.realpath(__file__)), "_skill_bootstrap.py"))
import compare_runs as cr
import scripts.evidence as evidence

REFUSED = cr.REFUSED
LEVELS = ("CRITICAL", "HIGH", "HIGH+")
POPULATIONS = ("gate_eligible", "all_active")
BASELINE, DRAFTS = "baseline", "drafts"


def _fingerprint(report):
    """(the matrix's identity, which field gave it). `meta.matrix.matrix_fingerprint` when
    the report carries one; else the layout fingerprint, which cannot see floor panels."""
    matrix = cr._dict(cr._meta(report).get("matrix"))
    if isinstance(matrix.get("matrix_fingerprint"), str) and matrix["matrix_fingerprint"]:
        return matrix["matrix_fingerprint"], "matrix_fingerprint"
    return cr._basis(report).get("layout_fingerprint"), "layout_fingerprint"


def run_sets(reports, window):
    """`{population: {level: [set of cluster numbers per run]}}`, and the clusters."""
    clusters = cr.cluster([r["findings"] for r in reports], window)
    sets: dict[str, dict[str, list[set]]] = {
        pop: {level: [set() for _ in reports] for level in LEVELS} for pop in POPULATIONS}
    for number, (_key, members) in enumerate(clusters):
        for pop in POPULATIONS:
            top: dict[int, str] = {}
            for index, finding, _span in members:
                status = cr._dict(finding.get("evidence")).get("status")
                if pop == "gate_eligible" and status not in evidence.GATE_ELIGIBLE_DEFAULT:
                    continue
                severity = cr._severity(finding)
                if severity and (index not in top or cr.RANK[severity] > cr.RANK[top[index]]):
                    top[index] = severity
            for index, severity in top.items():
                if severity in cr.ESCALATION:
                    sets[pop][severity][index].add(number)
                    sets[pop]["HIGH+"][index].add(number)
    return sets, clusters


def jaccard(one, two):
    """|one & two| / |one | two|; two empty sets are identical."""
    union = one | two
    return 1.0 if not union else len(one & two) / len(union)


def _spread(values):
    """{n, min, max, mean, stdev} of the numbers in `values`, None where there are none."""
    known = [float(v) for v in values
             if isinstance(v, (int, float)) and not isinstance(v, bool)]
    if not known:
        return {"n": 0, "min": None, "max": None, "mean": None, "stdev": None}
    mean = sum(known) / len(known)
    return {"n": len(known), "min": round(min(known), 4), "max": round(max(known), 4),
            "mean": round(mean, 4),
            "stdev": round(math.sqrt(sum((v - mean) ** 2 for v in known) / len(known)), 4)}


def set_agreement(run_sets_):
    """Pairwise similarity and found-by counts for one group's sets (one per run)."""
    pairs = [jaccard(a, b) for a, b in itertools.combinations(run_sets_, 2)]
    n_runs = len(run_sets_)
    found = [sum(1 for s in run_sets_ if cluster in s) for cluster in set().union(*run_sets_)] \
        if run_sets_ else []
    return {"runs": n_runs, "pairs": len(pairs), "jaccard": _spread(pairs),
            "sizes": _spread([len(s) for s in run_sets_]),
            "found": {"clusters": len(found), "all": sum(f == n_runs for f in found),
                      "majority": sum(2 * f > n_runs for f in found),
                      "only_one": sum(f == 1 for f in found)}}


def outcomes(reports):
    """The gate, the letter and the score across one group's reports."""
    gates: dict[str, int] = {}
    letters: dict[str, int] = {}
    for report in reports:
        summary = cr._summary(report)
        gates[str(summary.get("gate"))] = gates.get(str(summary.get("gate")), 0) + 1
        letter = (str(summary["overall_grade"]) if summary.get("overall_grade")
                  else "%s (provisional)" % summary["provisional_grade"]
                  if summary.get("provisional_grade") else "none")
        letters[letter] = letters.get(letter, 0) + 1
    return {"gate": dict(sorted(gates.items())),
            "gate_flips": len(reports) - max(gates.values(), default=0),
            "letters": dict(sorted(letters.items())),
            "letters_distinct": len(letters),
            "health": _spread([cr._dict(cr._summary(r).get("health")).get("score")
                               for r in reports])}


def _partition(report):
    """`{group name: set of files}` as the report's own `groups` list realised it."""
    out: dict[str, set] = {}
    groups = report.get("groups")
    for group in groups if isinstance(groups, list) else ():
        if isinstance(group, dict) and isinstance(group.get("name"), str):
            files = group.get("files")
            out.setdefault(group["name"], set()).update(
                f for f in (files if isinstance(files, list) else ()) if isinstance(f, str))
    return out


def _pairs(count):
    return count * (count - 1) // 2


def matrix_similarity(one, two):
    """How alike two partitions of the tree are.

    `co_grouping` is over pairs of files: of the pairs grouped together in either matrix,
    the share grouped together in both. 1.0 is the same cut (whatever the groups are named),
    and it falls as files that shared a group are split. Counted from the groups' overlaps,
    never by listing the pairs. `names` is the same ratio over group names."""
    together_one = sum(_pairs(len(files)) for files in one.values())
    together_two = sum(_pairs(len(files)) for files in two.values())
    both = sum(_pairs(len(a & b)) for a in one.values() for b in two.values())
    either = together_one + together_two - both
    return {"groups": [len(one), len(two)],
            "names": round(jaccard(set(one), set(two)), 4),
            "co_grouping": round(both / either, 4) if either else 1.0}


def _pearson(xs, ys):
    """Pearson's r, or None with fewer than three points or no variance on a side."""
    if len(xs) < 3:
        return None
    mean_x, mean_y = sum(xs) / len(xs), sum(ys) / len(ys)
    var_x = sum((x - mean_x) ** 2 for x in xs)
    var_y = sum((y - mean_y) ** 2 for y in ys)
    if not var_x or not var_y:
        return None
    return round(sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
                 / math.sqrt(var_x * var_y), 4)


def against_baseline(sets, base_index, draft_index):
    """Per draft run, for each population and level: findings most baseline runs found that
    it missed, and findings it found that no baseline run did."""
    rows = []
    for position, index in enumerate(draft_index):
        row: dict = {"run": "draft%d" % (position + 1)}
        for pop in POPULATIONS:
            row[pop] = {}
            for level in LEVELS:
                base = [sets[pop][level][i] for i in base_index]
                union = set().union(*base)
                majority = {c for c in union if 2 * sum(c in s for s in base) > len(base)}
                mine = sets[pop][level][index]
                row[pop][level] = {"baseline_majority": len(majority),
                                   "missed": len(majority - mine),
                                   "added": len(mine - union)}
        rows.append(row)
    return rows


def measure(draft_paths, baseline_paths=(), window=cr.DEFAULT_LINE_WINDOW,
            allow_unknown_commit=False, detail=False):
    """The stability document for the reports at the given paths."""
    paths = list(draft_paths) + list(baseline_paths)
    if window < 0:
        raise cr.Refused("--line-window must be 0 or more, got %d" % window)
    if len(draft_paths) < 2:
        raise cr.Refused("need at least 2 draft runs, got %d" % len(draft_paths))
    if len(baseline_paths) == 1:
        raise cr.Refused("a baseline of one run measures no noise; give 2 or more, or none")
    if len({os.path.realpath(p) for p in paths}) != len(paths):
        raise cr.Refused("the same report was given twice")
    reports = [cr.load(p) for p in paths]
    identity = cr.check_inputs(reports, allow_unknown_commit, allow_different_layouts=True)
    draft_index = list(range(len(draft_paths)))
    base_index = list(range(len(draft_paths), len(paths)))
    prints = [_fingerprint(r) for r in reports]
    if any(value is None for value, _source in prints):
        raise cr.Refused("a run records no matrix or layout fingerprint")
    base_prints = {prints[i][0] for i in base_index}
    if len(base_prints) > 1:
        raise cr.Refused("the baseline is not one matrix: its runs carry %d different "
                         "fingerprints (%s)" % (len(base_prints), ", ".join(sorted(base_prints))))
    sets, clusters = run_sets(reports, window)
    groups = {DRAFTS: draft_index, **({BASELINE: base_index} if base_index else {})}
    findings = {name: {pop: {level: set_agreement([sets[pop][level][i] for i in index])
                             for level in LEVELS} for pop in POPULATIONS}
                for name, index in groups.items()}
    partitions = [_partition(r) for r in reports]
    pair_rows = []
    for a, b in itertools.combinations(draft_index, 2):
        pair_rows.append({
            "runs": ["draft%d" % (a + 1), "draft%d" % (b + 1)],
            "same_matrix": prints[a][0] == prints[b][0],
            "matrix": matrix_similarity(partitions[a], partitions[b]),
            "high_plus_jaccard": round(jaccard(sets["gate_eligible"]["HIGH+"][a],
                                               sets["gate_eligible"]["HIGH+"][b]), 4)})
    doc = {
        "line_window": window,
        "version": identity["version"],
        "commit_verified": identity["commit_verified"],
        "dirty_fresh_matrix": len(identity["dirty_fresh_matrix"]),
        "runs": {"drafts": len(draft_index), "baseline": len(base_index)},
        "matrices": {
            "drafts_distinct": len({prints[i][0] for i in draft_index}),
            "fingerprints": {"draft%d" % (i + 1): prints[i][0] for i in draft_index},
            "baseline": next(iter(base_prints), None),
            "fingerprint_source": sorted({source for _value, source in prints}),
            "baseline_is_a_draft": bool(base_prints & {prints[i][0] for i in draft_index}),
        },
        "findings": findings,
        "outcomes": {name: outcomes([reports[i] for i in index])
                     for name, index in groups.items()},
        "draft_effect": ({pop: {level: (
            None if None in (findings[BASELINE][pop][level]["jaccard"]["mean"],
                             findings[DRAFTS][pop][level]["jaccard"]["mean"])
            else round(findings[BASELINE][pop][level]["jaccard"]["mean"]
                       - findings[DRAFTS][pop][level]["jaccard"]["mean"], 4))
            for level in LEVELS} for pop in POPULATIONS} if base_index else None),
        "against_baseline": (against_baseline(sets, base_index, draft_index)
                             if base_index else None),
        "draft_pairs": pair_rows,
        "matrix_movement": {
            "co_grouping": _spread([row["matrix"]["co_grouping"] for row in pair_rows]),
            "names": _spread([row["matrix"]["names"] for row in pair_rows]),
            "group_counts": _spread([len(partitions[i]) for i in draft_index]),
            "results_follow_matrix_r": _pearson(
                [row["matrix"]["co_grouping"] for row in pair_rows],
                [row["high_plus_jaccard"] for row in pair_rows])},
    }
    if detail:
        n_runs = len(reports)
        doc["detail"] = {
            "reports": {("draft%d" % (i + 1) if i in draft_index
                         else "base%d" % (i - len(draft_index) + 1)): os.path.basename(paths[i])
                        for i in range(n_runs)},
            "target_commit": identity["target_commit"],
            "clusters": [cr.describe(number + 1, key, members, n_runs)
                         for number, (key, members) in enumerate(clusters)]}
    return doc


def _num(value):
    return "-" if value is None else ("%.3f" % value if isinstance(value, float) else str(value))


def _set_line(label, row):
    j, found = row["jaccard"], row["found"]
    return ("    %-8s similarity mean %s (lowest %s, highest %s) over %d pair(s); %d finding(s): "
            "every run %d, most %d, only one %d"
            % (label, _num(j["mean"]), _num(j["min"]), _num(j["max"]), row["pairs"],
               found["clusters"], found["all"], found["majority"], found["only_one"]))


def summary_lines(doc):
    """The text summary: aggregates only, whatever `--detail` added to the document."""
    lines = []
    if not doc["commit_verified"]:
        lines.append("COMMIT UNVERIFIED: not every run recorded a clean target commit; "
                     "differences may be code changes, not matrix or scanner variance")
    if doc["dirty_fresh_matrix"]:
        lines.append("DIRTY TREE, FRESH MATRIX: %d run(s) scanned a tree whose config is not "
                     "in the commit; other uncommitted changes cannot be ruled out"
                     % doc["dirty_fresh_matrix"])
    matrices = doc["matrices"]
    lines.append("matrix_stability: %d draft run(s) under %d distinct matri%s, %d baseline "
                 "run(s); panopticon %s; line window %d"
                 % (doc["runs"]["drafts"], matrices["drafts_distinct"],
                    "x" if matrices["drafts_distinct"] == 1 else "ces", doc["runs"]["baseline"],
                    cr._text(doc["version"]), doc["line_window"]))
    if matrices["drafts_distinct"] == 1:
        lines.append("NOTE: the draft runs all share one matrix, so this measures the review's "
                     "own noise and nothing about drafts")
    if not doc["runs"]["baseline"]:
        lines.append("NOTE: no baseline was given, so the review's own run-to-run noise is not "
                     "separated from the drafts' effect")
    if matrices["fingerprint_source"] != ["matrix_fingerprint"]:
        lines.append("NOTE: some report predates meta.matrix; its matrix is identified by "
                     "layout_fingerprint, which cannot see a group's floor panels")
    if matrices["baseline_is_a_draft"]:
        lines.append("NOTE: the baseline's matrix is also one of the drafts")
    for pop in POPULATIONS:
        lines.append("%s findings:" % pop.replace("_", " "))
        for level in LEVELS:
            for name in (BASELINE, DRAFTS):
                if name in doc["findings"]:
                    lines.append("  %-9s%s" % (name, _set_line(level, doc["findings"][name][pop][level])
                                              .lstrip()))
            if doc["draft_effect"]:
                effect = doc["draft_effect"][pop][level]
                lines.append("  %-9s%-8s baseline mean minus drafts mean: %s"
                             % ("effect", level, _num(effect)))
    for name in (BASELINE, DRAFTS):
        if name not in doc["outcomes"]:
            continue
        row = doc["outcomes"][name]
        health = row["health"]
        lines.append("%s outcomes: gate %s (%d run(s) differ from the commonest); letters %s; "
                     "health lowest %s, highest %s, mean %s, stdev %s"
                     % (name, ", ".join("%s x%d" % (cr._text(g), n) for g, n in row["gate"].items()),
                        row["gate_flips"],
                        ", ".join("%s x%d" % (cr._text(g), n) for g, n in row["letters"].items()),
                        _num(health["min"]), _num(health["max"]), _num(health["mean"]),
                        _num(health["stdev"])))
    if doc["against_baseline"]:
        lines.append("each draft run against the baseline (gate-eligible HIGH+): findings most "
                     "baseline runs found that it missed / findings no baseline run found")
        for row in doc["against_baseline"]:
            cell = row["gate_eligible"]["HIGH+"]
            lines.append("  %s: missed %d of %d, added %d"
                         % (row["run"], cell["missed"], cell["baseline_majority"], cell["added"]))
    movement = doc["matrix_movement"]
    lines.append("how far the drafts differ: file pairs grouped together in both, mean %s "
                 "(lowest %s); shared group names, mean %s; group count %s to %s"
                 % (_num(movement["co_grouping"]["mean"]), _num(movement["co_grouping"]["min"]),
                    _num(movement["names"]["mean"]), _num(movement["group_counts"]["min"]),
                    _num(movement["group_counts"]["max"])))
    r = movement["results_follow_matrix_r"]
    lines.append("do results move with the matrix: %s"
                 % ("r = %s between two drafts' co-grouping and their gate-eligible HIGH+ "
                    "similarity, over %d pair(s)" % (_num(r), len(doc["draft_pairs"]))
                    if r is not None else
                    "not measurable (it needs three or more pairs that differ on both sides)"))
    return lines


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("drafts", nargs="+", help="reports of runs that each used its own draft")
    ap.add_argument("--baseline", nargs="+", default=[], metavar="REPORT",
                    help="reports of repeat runs that all used one frozen matrix")
    ap.add_argument("--out", help="write the stability JSON here")
    ap.add_argument("--detail", action="store_true",
                    help="add report file names and the matched clusters to the JSON "
                         "(titles and paths: for local reading, not for sharing)")
    ap.add_argument("--line-window", type=int, default=cr.DEFAULT_LINE_WINDOW,
                    help="most lines between two agent findings' spans for them to match "
                         "(default %(default)s)")
    ap.add_argument("--allow-unknown-commit", action="store_true",
                    help="measure runs that did not record a clean target commit")
    args = ap.parse_args(argv)
    try:
        doc = measure(args.drafts, args.baseline, args.line_window, args.allow_unknown_commit,
                      args.detail)
    except cr.Refused as exc:
        print("matrix_stability: refused: %s" % exc, file=sys.stderr)
        return REFUSED
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2, sort_keys=True)
            fh.write("\n")
    print("\n".join(summary_lines(doc)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
