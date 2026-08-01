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


def ingest_dir(tools_dir, group):
    """Ingest raw tool-output files from a directory and route them to the
    registered adapter for parsing. Files without a registered adapter or that
    fail to parse are skipped with a stderr diagnostic."""
    from scripts.tools import ADAPTERS
    out = []
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
        try:
            out.extend(adapter.parse(raw, group))
        except Exception as e:  # noqa: BLE001 - tolerant by design
            print("ingest error %s: %s" % (path, e), file=sys.stderr)
            continue
    return out
