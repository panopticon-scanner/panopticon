#!/usr/bin/env python3
"""Fail-closed CI gate for trusted Panopticon scanner output."""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import scripts.ingest_tools as ingest_tools


GATE_SEVERITIES = frozenset({"HIGH", "CRITICAL"})

# #1578 (SEC-G2B): the modes this gate distinguishes, and the only thing the
# distinction changes. `redteam` says the target is untrusted, so a finding may
# not be dropped because of the DIRECTORY NAME it sits under -- the suppressed
# set is gated alongside the kept one. `standard` keeps the suppression (a
# self-scan drowns in bundled jQuery otherwise) and prints what it dropped.
REDTEAM = "redteam"
SECURITY_MODES = ("standard", REDTEAM)


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
    if not all(isinstance(value, list)
               for value in (selected, produced, missing, excluded_scope)):
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


def evaluate(tools_dir, manifest_path, exclude_globs=None, security_mode="standard"):
    """Return (findings, dispositions, failures, high_findings, suppressed).

    #1578: `suppressed` is what the vendored-path exclusion dropped, each entry
    naming the segment that dropped it. It is never part of `findings` -- the
    report-side suppression is what makes tool output usable at all -- but under
    `redteam` it IS part of the gate: this gate blocks merges, and a payload
    landed as `app/vendor/patched_auth.rb` passing it outright on the strength
    of a conventional directory name is the defect. In `standard` mode the
    suppression stands and `main` prints the count beside the gate line, so the
    drop is disclosed rather than silent.
    """
    manifest = load_manifest(manifest_path)
    suppressed = []
    findings, dispositions = ingest_tools.ingest_dir_detailed(
        tools_dir, "ci", exclude_globs=exclude_globs or [],
        suppressed_out=suppressed)
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
    gated = findings + suppressed if security_mode == REDTEAM else findings
    high = [finding for finding in gated
            if finding.get("severity") in GATE_SEVERITIES]
    return findings, dispositions, failures, high, suppressed


def main(argv=None):
    parser = argparse.ArgumentParser(description="fail-closed Panopticon scanner gate")
    parser.add_argument("--tools-dir", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--exclude", action="append", default=[])
    # #1578: the exclusion the report keeps is not one a redteam gate may keep.
    parser.add_argument("--security", dest="security_mode", default="standard",
                        choices=list(SECURITY_MODES))
    args = parser.parse_args(argv)
    try:
        findings, _dispositions, failures, high, suppressed = evaluate(
            args.tools_dir, args.manifest, args.exclude, args.security_mode)
    except ValueError as exc:
        print("security-gate: %s" % exc, file=sys.stderr)
        return 2
    note = ""
    if suppressed:
        counts = ingest_tools.suppressed_counts(suppressed)
        note = ("; %d suppressed as vendored (%s)%s"
                % (len(suppressed),
                   ", ".join("%s: %d" % (seg, counts[seg]) for seg in sorted(counts)),
                   " -- GATED, --security redteam" if args.security_mode == REDTEAM
                   else " -- NOT gated; re-run with --security redteam to gate them"))
    print("Ingested %d non-excluded tool findings; %d HIGH/CRITICAL%s"
          % (len(findings), len(high), note))
    if failures:
        print("security-gate: scanner coverage incomplete:", file=sys.stderr)
        for failure in failures:
            print("  - %s" % failure, file=sys.stderr)
        return 2
    if high:
        for finding in high[:20]:
            location = finding.get("location") or {}
            print("  %s %s %s:%s - %s" % (
                finding.get("severity"), finding.get("id"),
                location.get("file"), location.get("line_start"),
                finding.get("title")))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
