#!/usr/bin/env python3
"""Fail-closed CI gate for trusted Panopticon scanner output."""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import scripts.ingest_tools as ingest_tools


GATE_SEVERITIES = frozenset({"HIGH", "CRITICAL"})


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


def evaluate(tools_dir, manifest_path, exclude_globs=None):
    """Return (findings, dispositions, failures, high_findings)."""
    manifest = load_manifest(manifest_path)
    findings, dispositions = ingest_tools.ingest_dir_detailed(
        tools_dir, "ci", exclude_globs=exclude_globs or [])
    failures = []
    for name in manifest["selected"]:
        disposition = dispositions.get(name)
        if name in manifest["missing"] or disposition is None:
            failures.append("%s: no output" % name)
        elif disposition.get("status") == "failed":
            failures.append("%s: %s" % (name, disposition.get("reason", "failed")))
    # excluded_scope adapters are disclosed, never required, and their output
    # (if any lingered) is known — not "unexpected".
    known = set(manifest["selected"]) | set(manifest.get("excluded_scope", []))
    unknown = set(dispositions) - known
    if unknown:
        failures.append("unexpected scanner output: %s" % ", ".join(sorted(unknown)))
    high = [finding for finding in findings
            if finding.get("severity") in GATE_SEVERITIES]
    return findings, dispositions, failures, high


def main(argv=None):
    parser = argparse.ArgumentParser(description="fail-closed Panopticon scanner gate")
    parser.add_argument("--tools-dir", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--exclude", action="append", default=[])
    args = parser.parse_args(argv)
    try:
        findings, _dispositions, failures, high = evaluate(
            args.tools_dir, args.manifest, args.exclude)
    except ValueError as exc:
        print("security-gate: %s" % exc, file=sys.stderr)
        return 2
    print("Ingested %d non-excluded tool findings; %d HIGH/CRITICAL"
          % (len(findings), len(high)))
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
