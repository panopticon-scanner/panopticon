"""CI test-shard bookkeeping (#2933 phase 2). Stdlib only; read-only on its inputs.

Three subcommands, each run by one CI job:

- `check DIR --expect 3.11=3 ...` (the `shard-check` job). DIR holds every test
  job's manifest, written by `tests/ci_shard_manifest.py`. For each Python
  version it proves the jobs ran every collected test exactly once: the
  manifests agree on what was collected, their `selected` sets are pairwise
  disjoint, and their union is the whole collection. It also proves every
  version collected the same tests, which is what lets coverage gate on 3.12
  alone. This checks what the jobs RAN, not a simulation of the split, so a
  dropped shard, a `-m` filter that leaves a gap between the parallel and serial
  passes, or a filter that runs a test twice all fail it.
- `coverage-files DIR --expect N` (the `coverage` job). Exactly N `.coverage.*`
  data files, so the 90% gate never judges a partial combine.
- `merge-durations DIR --committed PATH -o PATH` (the `coverage` job). DIR holds
  each 3.12 coverage shard's manifest and `--store-durations` output
  (`durations-<label>.json` beside `manifest-<label>.json`). A manifest with no
  durations file, the serial leg's, is not part of the profile and is skipped. pytest-split
  merges a run's measurements into the file it read, so a shard's output is the
  committed profile with only that shard's tests updated. The merge therefore
  takes each shard's value only for the tests its manifest says it ran. It also
  scores the COMMITTED profile against this run's fresh times and prints a
  `::warning::` annotation when it is stale. It never fails the job for that.

Every message names counts and at most a few node ids, never file contents.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

MANIFEST_PREFIX = "manifest-"
DURATIONS_PREFIX = "durations-"
COVERAGE_DATA_PREFIX = ".coverage."
# A stale profile still splits, so these only warn (#2933 phase 2 ruling).
STALE_UNKNOWN_FRACTION = 0.10
STALE_MAX_MIN_RATIO = 1.15
_SHOWN = 5   # node ids quoted in one message


def load_manifests(directory):
    """{label: manifest} for every `manifest-<label>.json` in `directory`."""
    out = {}
    for name in sorted(os.listdir(directory)):
        if name.startswith(MANIFEST_PREFIX) and name.endswith(".json"):
            with open(os.path.join(directory, name), encoding="utf-8") as fh:
                out[name[len(MANIFEST_PREFIX):-len(".json")]] = json.load(fh)
    return out


def _quote(ids):
    ids = sorted(ids)
    shown = ", ".join(ids[:_SHOWN])
    return shown + (" (+%d more)" % (len(ids) - _SHOWN) if len(ids) > _SHOWN else "")


def partition_errors(manifests, expect):
    """Every way `manifests` fail to run each collected test exactly once, per
    version, as a list of messages. Empty means the partition holds.

    `expect` maps a Python version to how many jobs must have reported for it.
    """
    errors = []
    by_version: dict[str | None, list[tuple[str, dict]]] = {}
    for label, m in sorted(manifests.items()):
        by_version.setdefault(m.get("python"), []).append((label, m))
    for version in sorted(set(expect) | {v for v in by_version if v is not None}):
        if version not in expect:
            errors.append("python %s: %d unexpected manifest(s)"
                          % (version, len(by_version[version])))
    if None in by_version:
        errors.append("%d manifest(s) name no python version" % len(by_version[None]))
    collected_by_version = {}
    for version, count in sorted(expect.items()):
        legs = by_version.get(version, [])
        if len(legs) != count:
            errors.append("python %s: %d manifest(s), expected %d"
                          % (version, len(legs), count))
        if not legs:
            continue
        first_label, first = legs[0]
        collected = set(first["collected"])
        collected_by_version[version] = collected
        for label, m in legs[1:]:
            if set(m["collected"]) != collected:
                errors.append("python %s: %s collected differently from %s (%s)"
                              % (version, label, first_label,
                                 _quote(collected ^ set(m["collected"]))))
        seen: dict[str, list[str]] = {}
        for label, m in legs:
            selected = set(m["selected"])
            outside = selected - collected
            if outside:
                errors.append("python %s: %s ran %d test(s) it did not collect: %s"
                              % (version, label, len(outside), _quote(outside)))
            for nodeid in selected:
                seen.setdefault(nodeid, []).append(label)
        twice = {n: labels for n, labels in seen.items() if len(labels) > 1}
        if twice:
            pairs = sorted({" and ".join(labels) for labels in twice.values()})
            errors.append("python %s: %d test(s) ran in more than one job (%s): %s"
                          % (version, len(twice), "; ".join(pairs), _quote(twice)))
        missing = collected - set(seen)
        if missing:
            errors.append("python %s: %d collected test(s) ran in no job: %s"
                          % (version, len(missing), _quote(missing)))
    versions = sorted(collected_by_version)
    for version in versions[1:]:
        diff = collected_by_version[versions[0]] ^ collected_by_version[version]
        if diff:
            errors.append("python %s and %s collected different tests (%d): %s"
                          % (versions[0], version, len(diff), _quote(diff)))
    return errors


def coverage_file_errors(directory, expect):
    names = sorted(n for n in os.listdir(directory) if n.startswith(COVERAGE_DATA_PREFIX))
    if len(names) != expect:
        return ["%d coverage data file(s) (%s), expected %d"
                % (len(names), ", ".join(names) or "none", expect)]
    return []


def merge_durations(pairs):
    """{nodeid: seconds} from [(manifest, durations)], taking each shard's value
    only for the tests that shard ran. Rounded to 0.1 ms, the precision #3085
    committed. A test two shards ran, or a ran test with no measurement, is an
    error: the partition check should already have refused the first."""
    merged, errors = {}, []
    for manifest, durations in pairs:
        for nodeid in manifest["selected"]:
            if nodeid in merged:
                errors.append("measured twice: %s" % nodeid)
            elif nodeid not in durations:
                errors.append("ran but not measured: %s" % nodeid)
            else:
                merged[nodeid] = round(float(durations[nodeid]), 4)
    return merged, errors


def staleness(committed, pairs, merged):
    """(unknown fraction, max/min of the committed split's real group times).

    The shards' `selected` sets ARE the committed profile's split, so their real
    cost under this run's measurements is how well that profile still balances.
    """
    unknown = sum(1 for nodeid in merged if nodeid not in committed)
    fraction = unknown / len(merged) if merged else 0.0
    totals = [sum(merged.get(n, 0.0) for n in m["selected"]) for m, _d in pairs]
    ratio = (max(totals) / min(totals)) if totals and min(totals) > 0 else float("inf")
    return fraction, ratio


def stale_warnings(fraction, ratio):
    out = []
    if fraction > STALE_UNKNOWN_FRACTION:
        out.append("%.1f%% of parallel-pass tests are unknown to .test_durations "
                   "(warn above %.0f%%)" % (100 * fraction, 100 * STALE_UNKNOWN_FRACTION))
    if ratio > STALE_MAX_MIN_RATIO:
        out.append("the committed split's groups ran %.2fx apart (warn above %.2fx)"
                   % (ratio, STALE_MAX_MIN_RATIO))
    return out


def _parse_expect(values):
    expect = {}
    for value in values:
        version, _sep, count = value.partition("=")
        if not version or not count.isdigit():
            raise SystemExit("ci_shards: --expect takes VERSION=COUNT, got %r" % value)
        expect[version] = int(count)
    return expect


def main(argv=None):
    parser = argparse.ArgumentParser(prog="ci_shards")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check")
    check.add_argument("directory")
    check.add_argument("--expect", action="append", required=True, metavar="VERSION=COUNT")
    files = sub.add_parser("coverage-files")
    files.add_argument("directory")
    files.add_argument("--expect", type=int, required=True)
    merge = sub.add_parser("merge-durations")
    merge.add_argument("directory")
    merge.add_argument("--committed", required=True)
    merge.add_argument("-o", "--output", required=True)
    args = parser.parse_args(argv)

    if args.command == "check":
        manifests = load_manifests(args.directory)
        errors = partition_errors(manifests, _parse_expect(args.expect))
        for line in errors:
            print("ci_shards check: %s" % line, file=sys.stderr)
        if not errors:
            for label, m in sorted(manifests.items()):
                print("%-16s python %s collected %d selected %d"
                      % (label, m["python"], len(m["collected"]), len(m["selected"])))
            print("ci_shards check: %d manifests; every collected test ran exactly once"
                  % len(manifests))
        return 1 if errors else 0

    if args.command == "coverage-files":
        errors = coverage_file_errors(args.directory, args.expect)
        for line in errors:
            print("ci_shards coverage-files: %s" % line, file=sys.stderr)
        return 1 if errors else 0

    manifests = load_manifests(args.directory)
    pairs = []
    for label, manifest in sorted(manifests.items()):
        path = os.path.join(args.directory, "%s%s.json" % (DURATIONS_PREFIX, label))
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                pairs.append((manifest, json.load(fh)))
    if not pairs:
        print("ci_shards merge-durations: no shard durations in %s" % args.directory,
              file=sys.stderr)
        return 1
    merged, errors = merge_durations(pairs)
    for line in errors[:_SHOWN]:
        print("ci_shards merge-durations: %s" % line, file=sys.stderr)
    if errors:
        print("ci_shards merge-durations: %d error(s)" % len(errors), file=sys.stderr)
        return 1
    with open(args.committed, encoding="utf-8") as fh:
        committed = json.load(fh)
    fraction, ratio = staleness(committed, pairs, merged)
    with open(args.output, "w", encoding="utf-8") as fh:
        # The committed file's own layout, so a refresh is a plain copy.
        json.dump(merged, fh, sort_keys=True, indent=0)
        fh.write("\n")
    print("ci_shards merge-durations: %d tests, %.1f%% unknown to the committed profile, "
          "committed split %.2fx max/min" % (len(merged), 100 * fraction, ratio))
    for line in stale_warnings(fraction, ratio):
        print("::warning title=.test_durations is stale::%s; refresh it from this run's "
              "test-durations-python-3.12 artifact (#2933)" % line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
