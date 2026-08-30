"""Shared SARIF ingestion helpers used by scripts.ingest_tools and adapters.

This module exists to break the circular import between scripts.ingest_tools
and scripts.tools.legacy_sarif. It is stdlib-only.
"""
import json
import os
import re
import sys

from scripts.provenance import tool_provenance
from .base import new_finding_id


LEVEL_TO_SEV = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "INFO"}
PREFIX = {"semgrep": "SG", "trivy": "TR", "gitleaks": "GL", "bandit": "BN", "gosec": "GS"}
CWE_TAG = re.compile(r"(CWE-\d+)", re.IGNORECASE)
CVE_TAG = re.compile(r"(CVE-\d{4}-\d{4,})", re.IGNORECASE)

# Bandit rules that are noise floor, not signal, on any codebase:
#   B101 assert-used         - fires on every pytest/unittest assertion
#   B404 import-subprocess    - flags the mere import of the subprocess module
#   B110 try-except-pass      - style nit, not a vulnerability
#   B112 try-except-continue  - style nit, not a vulnerability
# These are blunt heuristics that flood reports with low-value hits; the LLM
# security panel + advisor already review command-exec/error-handling with real
# context. B603 (subprocess-call-untrusted-input) and B607 (partial-exec-path)
# are deliberately NOT suppressed: they remain a tool-layer backstop for
# tool-only runs (no agentic review cells). Module constant so the suppression
# list is easy to extend later.
NOISE_RULES = {"B101", "B404", "B110", "B112"}

# Test-fixture corpus definition, kept in sync with orchestrator's
# FIXTURE_DIR_BASENAMES / FIXTURE_PARENT_DIRS / _is_fixture_dir (#434). The
# definition is mirrored here; update both places together.
_FIXTURE_DIR_BASENAMES = frozenset({"testdata", "__fixtures__"})
_FIXTURE_PARENT_DIRS = frozenset({"tests", "test", "spec"})


def _is_test_path(path):
    """True if a (normalized) path looks like a test file, e.g. tests/foo.py,
    test_foo.py, foo_test.py."""
    if not isinstance(path, str):
        return False
    if path.startswith("tests/"):
        return True
    base = os.path.basename(path)
    return base.startswith("test_") or base.endswith("_test.py")


def _is_fixture_path(path):
    """True if a repo-relative file path lives under a test-fixture corpus dir
    (e.g. ``tests/fixtures/...``, ``testdata/...``, ``__fixtures__/...``).

    Mirrors ``orchestrator._is_fixture_dir`` so the tool-ingest path prunes the
    same intentionally-vulnerable fixtures the agentic review path already
    prunes in standard mode (#434). The agentic path drops fixture FILES before
    review; the tool scanners (osv-scanner, trivy) still walk the whole repo and
    report real fixture paths, so this is where the tool path reaches parity.
    """
    if not isinstance(path, str):
        return False
    parts = path.split("/")
    # Inspect each ANCESTOR directory (everything but the file basename).
    for i in range(len(parts) - 1):
        name = parts[i]
        if name in _FIXTURE_DIR_BASENAMES:
            return True
        if name == "fixtures" and i >= 1 and parts[i - 1] in _FIXTURE_PARENT_DIRS:
            return True
    return False


is_test_path = _is_test_path
is_fixture_path = _is_fixture_path


def norm_uri(uri):
    """Normalize a SARIF artifactLocation URI to a repo-relative path.

    Strips the file:// scheme and the container-mount prefix (/src/), so tool
    findings share the same path space as agent findings. A plain relative
    path (even one that starts with 'src/') is returned unchanged.
    """
    if not isinstance(uri, str):
        return uri
    if uri.startswith("file://"):
        uri = uri[len("file://"):]
    if uri.startswith("/src/"):
        return uri[len("/src/"):]
    return uri.lstrip("/")


_norm_uri = norm_uri


def rules_index(run):
    idx = {}
    for r in (run.get("tool", {}).get("driver", {}).get("rules") or []):
        idx[r.get("id")] = r
    return idx


_rules_index = rules_index


def sarif_to_findings(sarif, tool_name, group, prefix, start=1):
    """Convert SARIF results to panopticon findings with normalized metadata."""
    out = []
    n = start
    for run in (sarif.get("runs") or []):
        if not isinstance(run, dict):
            continue
        rules = _rules_index(run)
        for res in (run.get("results") or []):
            if not isinstance(res, dict):
                continue
            try:
                level = str(res.get("level", "warning")).lower()
                sev = LEVEL_TO_SEV.get(level, "INFO")
                # #run10 COD-C3A: a location-less SARIF result is VALID (a
                # config-wide or project-level finding from semgrep/bandit/trivy/
                # gitleaks/gosec -- all of which route through this one shared
                # converter). Emitting a bare {} left the finding with NO `file`
                # key at all, so every consumer that reads location.file saw a
                # different shape than the located case. Emit the same keys with
                # empty values instead: the finding stays reportable and readers
                # (ingest prune, reconcile's location_file, the delta gate) all
                # already treat "" as "no file".
                loc = {"file": "", "line_start": None}
                locs = res.get("locations") or []
                if locs:
                    phys = locs[0].get("physicalLocation", {})
                    loc = {"file": _norm_uri(phys.get("artifactLocation", {}).get("uri")),
                           "line_start": phys.get("region", {}).get("startLine")}
                rule_id = res.get("ruleId")
                if tool_name == "bandit" and rule_id in NOISE_RULES:
                    continue
                rule = rules.get(res.get("ruleId"), {})
                tags = " ".join(str(t) for t in (rule.get("properties", {}).get("tags") or []))
                blob = " ".join([res.get("ruleId", ""), tags, json.dumps(res.get("properties", {}))])
                cwes = sorted(set(m.group(1).upper() for m in CWE_TAG.finditer(blob)))
                cves = sorted(set(m.group(1).upper() for m in CVE_TAG.finditer(blob)))
                cites = {}
                if cwes:
                    cites["cwe"] = cwes
                if cves:
                    cites["cve"] = cves
                title_text = (res.get("message", {}) or {}).get("text", res.get("ruleId", "finding"))
                finding = {
                    "id": new_finding_id(prefix, n),
                    # collapse newlines/control chars so a crafted SARIF message can't
                    # inject formatting into the rendered summary (mirrors
                    # normalize_finding's title collapse; CWE-117 log injection).
                    "title": " ".join(str(title_text).split()),
                    "severity": sev,
                    "confidence": "CERTAIN",
                    "panel": "security",
                    "category": res.get("ruleId", "tool"),
                    "source": "tool:%s" % tool_name,
                    "location": loc,
                    "_group": group,
                    # #467: the rule id is FIRST-CLASS tool evidence, matching
                    # the dependency adapters. provenance.confirmation_reasoning
                    # keeps carrying it too (back-compat: evidence.tool_rule_id
                    # falls back there for pre-#467 artifacts).
                    "tool_evidence": {"rule_id": res.get("ruleId")},
                }
                finding["provenance"] = tool_provenance(tool_name, reasoning=res.get("ruleId"))
                if cites:
                    finding["citations"] = cites
            except Exception as exc:  # noqa: BLE001 - tolerant by design: skip only this result
                print(f"sarif_utils: skipping result {res.get('ruleId', res.get('rule', {}).get('id'))}: {exc!r}", file=sys.stderr)
                continue
            out.append(finding)
            n += 1
    return out
