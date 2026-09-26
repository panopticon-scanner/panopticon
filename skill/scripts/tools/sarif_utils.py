"""Shared SARIF ingestion helpers used by scripts.ingest_tools and adapters.

This module exists to break the circular import between scripts.ingest_tools
and scripts.tools.legacy_sarif. It is stdlib-only.
"""
import json
import math
import os
import re
import sys

from scripts.provenance import tool_provenance
from .base import cvss_bucket, inert_text, new_finding_id


LEVEL_TO_SEV = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "INFO"}
SEVERITY_LABELS = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
                   "MODERATE": "MEDIUM", "LOW": "LOW"}
SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
PREFIX = {"semgrep": "SG", "trivy": "TR", "gitleaks": "GL", "bandit": "BN", "gosec": "GS"}
CWE_TAG = re.compile(r"(CWE-\d+)", re.IGNORECASE)
CVE_TAG = re.compile(r"(CVE-\d{4}-\d{4,})", re.IGNORECASE)

# #1578 (SEC-G2B), owner ruling 2026-09-22 -- policy C, fix round 1. Adapters
# whose findings are secrets BY CONSTRUCTION: a hit is a credential someone
# committed, not an opinion about code. TWO rules read this one set, which is
# why it is a named constant and not a literal in either of them.
#   1. `sarif_to_findings` below grades them HIGH. Real gitleaks SARIF carries
#      NO `level` on its results and no `defaultConfiguration` on its rules
#      (tests/goldens/tool-raw/gitleaks.raw), so `LEVEL_TO_SEV`'s "warning"
#      default graded every committed credential MEDIUM -- below
#      `security_gate.GATE_SEVERITIES`, which meant the CI gate could not fail
#      on ANY gitleaks finding, suppressed or not. A leaked secret has no
#      lesser grade, and a grade the scanner never stated is not one.
#   2. `ingest_tools.gates_when_suppressed` re-admits one of theirs to the
#      redteam gate even when it sits under a suppressed directory name.
# Defined here, not beside that predicate, because this module exists to break
# the cycle back to `ingest_tools` -- and two copies of the list would drift.
SECRET_ADAPTERS = frozenset({"gitleaks"})
# The SARIF toolComponent name a CWE taxonomy uses. gosec names its taxonomy
# "CWE" and puts a BARE number under it, which is why `CWE_TAG` cannot see it.
CWE_TAXONOMY = "CWE"

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

    The path is TARGET-authored text and lands in `location.file`, which the
    terminal summary prints, so it comes back INERT (#1829 SEC-4277410777): this
    is the one expression both finding builders' paths pass through -- the SARIF
    builder below, and the adapters that resolve their own locations (eslint,
    osv-scanner) before calling `make_finding`, which neutralizes the field
    again for the adapters that do not.
    """
    if not isinstance(uri, str):
        return uri
    if uri.startswith("file://"):
        uri = uri[len("file://"):]
    if uri.startswith("/src/"):
        uri = uri[len("/src/"):]
    else:
        uri = uri.lstrip("/")
    return inert_text(uri, mode="path")


_norm_uri = norm_uri


def rules_index(run):
    idx = {}
    for r in (run.get("tool", {}).get("driver", {}).get("rules") or []):
        if isinstance(r, dict):
            idx[r.get("id")] = r
    return idx


_rules_index = rules_index


def _properties(value):
    """Treat malformed optional SARIF property bags as absent."""
    return value if isinstance(value, dict) else {}


def _security_score(value):
    """SARIF security-severity 0 is absent, unlike an OSV zero group score."""
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return None
    try:
        score = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return score if math.isfinite(score) and 0 < score <= 10 else None


def _severity_label(value):
    if not isinstance(value, str):
        return None
    return SEVERITY_LABELS.get(value.strip().upper())


def _metadata_severity(properties):
    score = _security_score(properties.get("security-severity"))
    if score is not None:
        return cvss_bucket(score)
    label = _severity_label(properties.get("severity"))
    if label is not None:
        return label
    tags = properties.get("tags")
    labels = (_severity_label(tag) for tag in tags if isinstance(tag, str)) \
        if isinstance(tags, list) else ()
    return max((label for label in labels if label is not None),
               key=SEVERITY_RANK.__getitem__, default=None)


def _sarif_severity(result, rule):
    """Four sources, in this order: explicit result metadata, explicit rule
    metadata, the result's own `level`, the rule's `defaultConfiguration.level`
    -- and "warning" when a document states none of them.

    The last step is #1790, and the order is the whole of it. A `level` the
    scanner put on THIS result is a statement about this hit and outranks a
    default the rule carries for every hit; a default the rule carries outranks
    a grade nobody stated. Semgrep is the case that makes the step load-
    bearing: it writes no `level` on any result and `defaultConfiguration.level:
    error` on every ERROR-severity rule, so the "warning" floor graded every one
    of them MEDIUM -- below `security_gate.GATE_SEVERITIES` -- and the CI gate
    could not fail on a semgrep finding at all. That is the hole #1578 closed
    for gitleaks, reached from the other side.

    It ships with the gate change that makes it safe to merge, not before it
    (#1964 was split for this). On this repository's own tree the step promotes
    24 findings the gate had never seen as HIGH, every one of them already
    adjudicated as a dismissed alert on GitHub -- so a strict pre-merge gate
    would have failed main the day this line landed. `security_gate
    --baseline-dir` counts only findings absent from the base commit's own
    scan, which is what lets a correct severity and a green main coexist.

    THE STEP GRADES DOWN AS WELL AS UP, and the downward half is the larger one
    (fix round 1, review M5). Measured on two real captures of this repo:
    semgrep states no result `level` at all, and its rule defaults there are
    `error` ~24, `warning` ~9 and `note` **241**. So beside the 24
    MEDIUM -> HIGH promotions, 241 findings go MEDIUM -> LOW, and a rule
    defaulting to `none` now yields INFO where the "warning" floor yielded
    MEDIUM. That is more faithful -- semgrep's `note` IS its INFO grade, and
    the floor was inventing a grade the scanner never stated -- and it has no
    CI-gate effect, since that floor is HIGH/CRITICAL. It DOES change what a
    `driver run --severity medium` or `--fail-on medium` sees on such a tree:
    241 fewer tool findings on the axis. Pinned by
    `test_the_rule_default_grades_DOWN_as_well_as_up`.
    """
    for owner in (result, rule):
        explicit = _metadata_severity(_properties(owner.get("properties")))
        if explicit is not None:
            return explicit
    default = _properties(rule.get("defaultConfiguration")).get("level")
    for level in (result.get("level"), default):
        if isinstance(level, str) and level.lower() in LEVEL_TO_SEV:
            return LEVEL_TO_SEV[level.lower()]
    return LEVEL_TO_SEV["warning"]


def relationship_cwes(rule):
    """CWE ids a SARIF rule carries in `relationships[]` instead of in its tags.

    #1578 fix round 1 (review I1). `sarif_to_findings` scrapes CWEs out of the
    rule id, the rule's `properties.tags` and the result's `properties`, which
    covers bandit (`external/cwe/cwe-259`) and semgrep (`CWE-798: ...`) and
    missed gosec entirely: gosec's tags are `["security", "HIGH"]` and the CWE
    sits at `relationships[].target.id` as a bare `"798"` under the `CWE`
    toolComponent. Every gosec finding therefore reached the report with no
    citation at all, and G101 ("Potential hardcoded credentials", CWE-798) was
    invisible to the secret-class gate rule -- on the one ecosystem whose
    `vendor/` is THE canonical vendoring directory, which is #1578's own
    scenario.

    Tolerant by construction, like the rest of this parser: anything that is
    not a `{target: {id, toolComponent: {name: "CWE"}}}` with a numeric id
    contributes nothing, and no shape raises -- including a SCALAR
    `relationships` (fix round 2), which `or []` let through to a `TypeError`
    that `sarif_to_findings`'s per-result `except` then swallowed by dropping
    every result citing that rule with one `skipping result` line.
    """
    out: list[str] = []
    if not isinstance(rule, dict):
        return out
    relationships = rule.get("relationships")
    for rel in (relationships if isinstance(relationships, list) else []):
        target = rel.get("target") if isinstance(rel, dict) else None
        if not isinstance(target, dict):
            continue
        component = target.get("toolComponent")
        if not isinstance(component, dict) or component.get("name") != CWE_TAXONOMY:
            continue
        ident = target.get("id")
        if isinstance(ident, bool) or not isinstance(ident, (str, int)):
            continue
        text = str(ident).strip()
        if text.upper().startswith("CWE-"):
            text = text[len("CWE-"):]
        if text.isdigit():
            out.append("CWE-%s" % text)
    return out


def sarif_to_findings(sarif, tool_name, group, prefix, start=1):
    # SARIF in, NARF out. This is the second of the two envelope builders (see
    # make_finding); it emits a deliberately leaner envelope because a SARIF
    # result's message IS the title, with no separate prose body to carry.
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
                rule_id = res.get("ruleId")
                if tool_name == "bandit" and rule_id in NOISE_RULES:
                    continue
                rule = rules.get(rule_id, {})
                sev = _sarif_severity(res, rule)
                if tool_name in SECRET_ADAPTERS and SEVERITY_RANK[sev] < SEVERITY_RANK["HIGH"]:
                    # A committed secret has a minimum HIGH grade; explicit
                    # CRITICAL scanner metadata remains CRITICAL.
                    sev = "HIGH"
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
                rule_props = _properties(rule.get("properties"))
                result_props = _properties(res.get("properties"))
                rule_tags = rule_props.get("tags")
                tags = " ".join(str(t) for t in rule_tags) if isinstance(rule_tags, list) else ""
                blob = " ".join([res.get("ruleId", ""), tags,
                                 json.dumps(result_props, default=str)])
                # #1578 I1: the tag scrape, UNION the rule's CWE taxonomy
                # relationships -- gosec files its CWE only in the second.
                cwes = sorted(set(m.group(1).upper() for m in CWE_TAG.finditer(blob))
                              | set(relationship_cwes(rule)))
                cves = sorted(set(m.group(1).upper() for m in CVE_TAG.finditer(blob)))
                cites = {}
                if cwes:
                    cites["cwe"] = cwes
                if cves:
                    cites["cve"] = cves
                title_text = (res.get("message", {}) or {}).get("text", res.get("ruleId", "finding"))
                # The rule id, inert for the ARTIFACT but NOT for the lookups
                # above: `rules_index` and NOISE_RULES key on what the SARIF
                # actually said. A null rule id stays null -- `evidence.
                # tool_rule_id` falls back to provenance.confirmation_reasoning,
                # so a "None" string here would forge a rule id, and with it the
                # finding's fingerprint.
                inert_rule_id = inert_text(rule_id) if isinstance(rule_id, str) else rule_id
                finding = {
                    "id": new_finding_id(prefix, n),
                    # The message is target-derived text on its way to an
                    # operator's terminal: control chars are neutralized and the
                    # length is bounded, one neutralizer with make_finding
                    # (#1829 SEC-4277410777, #2069). The old collapse was
                    # `" ".join(split())`, which splits on whitespace only --
                    # ESC, NUL and BEL went straight through (CWE-117).
                    "title": inert_text(title_text),
                    "severity": sev,
                    "confidence": "CERTAIN",
                    "panel": "security",
                    # `or "tool"`: a category is what a finding is filed under,
                    # and a null or empty one names nothing.
                    "category": inert_text(rule_id or "tool"),
                    "source": "tool:%s" % tool_name,
                    "location": loc,
                    "_group": group,
                    # #467: the rule id is FIRST-CLASS tool evidence, matching
                    # the dependency adapters. provenance.confirmation_reasoning
                    # keeps carrying it too (back-compat: evidence.tool_rule_id
                    # falls back there for pre-#467 artifacts).
                    "tool_evidence": {"rule_id": inert_rule_id},
                }
                finding["provenance"] = tool_provenance(tool_name, reasoning=inert_rule_id)
                if cites:
                    finding["citations"] = cites
            except Exception as exc:  # noqa: BLE001 - tolerant by design: skip only this result
                print(f"sarif_utils: skipping result {res.get('ruleId', res.get('rule', {}).get('id'))}: {exc!r}", file=sys.stderr)
                continue
            out.append(finding)
            n += 1
    return out
