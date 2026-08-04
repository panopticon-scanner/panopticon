#!/usr/bin/env python3
"""Ingest raw static-analysis tool output into panopticon findings.

Files in *tools_dir* are matched by basename (without extension) against the
registered adapters in ``scripts.tools.ADAPTERS`` and routed to the matching
adapter for parsing. SARIF or JSON files whose basename has no registered
adapter are skipped with a diagnostic. Stdlib-only.
"""
import glob
import os
import sys

from scripts.tools.sarif_utils import (
    CWE_TAG,
    CVE_TAG,
    LEVEL_TO_SEV,
    NOISE_RULES,
    PREFIX,
    _is_test_path,
    _norm_uri,
    _rules_index,
    sarif_to_findings,
)

# Re-export shared SARIF helpers so existing callers/tests keep working.
__all__ = [
    "CWE_TAG",
    "CVE_TAG",
    "LEVEL_TO_SEV",
    "NOISE_RULES",
    "PREFIX",
    "_is_test_path",
    "_norm_uri",
    "_rules_index",
    "ingest_dir",
    "sarif_to_findings",
]


def ingest_dir(tools_dir, group, exclude_globs=None):
    """Ingest raw tool-output files from a directory and route them to the
    registered adapter for parsing. Files without a registered adapter or that
    fail to parse are skipped with a stderr diagnostic.

    exclude_globs (F-CAL-2): fnmatch patterns matched against each finding's
    location.file; matches are dropped with a single aggregate stderr note.
    Standardizes the fixture-noise filter that previously lived only as inline
    Python in CI (intentionally vulnerable apps under tests/fixtures/ dominate
    self-scans otherwise).
    """
    import fnmatch
    from scripts.tools import ADAPTERS
    out = []
    excluded = 0
    for path in sorted(glob.glob(os.path.join(tools_dir, "*.sarif"))
                       + glob.glob(os.path.join(tools_dir, "*.json"))):
        tool = os.path.splitext(os.path.basename(path))[0]
        adapter = ADAPTERS.get(tool)
        if adapter is None:
            print("ingest skip %s: no adapter registered" % path, file=sys.stderr)
            continue
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
        except OSError as e:
            print("ingest skip %s: %s" % (path, e), file=sys.stderr)
            continue
        # Some tools decorate stdout before the JSON payload (calibration
        # 2026-08-03: bandit's progress bar corrupted its SARIF). Trim to the
        # first JSON start token — object OR array (eslint emits a top-level
        # array) — so a cosmetic prefix never discards real findings.
        starts = [i for i in (raw.find(b"{"), raw.find(b"[")) if i != -1]
        first = min(starts) if starts else -1
        if first > 0:
            print("ingest note %s: stripped %d bytes of non-JSON prefix"
                  % (path, first), file=sys.stderr)
            raw = raw[first:]
        try:
            parsed = adapter.parse(raw, group)
        except Exception as e:  # noqa: BLE001 - tolerant by design
            print("ingest error %s: %s" % (path, e), file=sys.stderr)
            continue
        if exclude_globs:
            kept = []
            for f in parsed:
                fpath = str((f.get("location") or {}).get("file", ""))
                if any(fnmatch.fnmatch(fpath, g) for g in exclude_globs):
                    excluded += 1
                else:
                    kept.append(f)
            parsed = kept
        out.extend(parsed)
    if excluded:
        print("ingest: excluded %d finding(s) matching %s"
              % (excluded, ", ".join(exclude_globs)), file=sys.stderr)
    return out
