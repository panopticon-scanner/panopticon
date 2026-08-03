# Panopticon 4.0 Epistemics Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the severity-destroying confirmation machinery with a two-axis severity×evidence model and an orchestrator-dispatched verify phase.

**Architecture:** A new `scripts/evidence.py` module owns the evidence axis (status derivation, verify-queue triage, verdict ingestion). `synthesize.py` loses its kimi-CLI advisor subprocess loop and severity downgrades, gains `--emit-verify-queue` / `--verdicts-dir` two-pass CLI. Severity is never mutated after `normalize_finding`. Gate and grades key on confirmed evidence only by default.

**Tech Stack:** Python 3 stdlib only (project rule), pytest, ruff.

**Spec:** `docs/superpowers/specs/2026-08-03-epistemics-core-design.md` — read it first.

## Global Constraints

- Python stdlib only in `scripts/` (no new dependencies).
- Tolerant by design: malformed input is skipped with a stderr note; a run never aborts (see spec Section 5).
- `severity` and `confidence` are NEVER mutated by evidence code. `confidence` keeps only the existing corroboration bump in `cross_panel_corroboration` and dedupe's reinforce.
- Evidence statuses, exactly: `tool_confirmed`, `advisor_confirmed`, `corroborated`, `needs_more_info`, `unverified`, `rejected`.
- Gate-eligible by default: `tool_confirmed`, `advisor_confirmed` only.
- Report `meta.version` and schema version: `4.0.0`.
- Run `python3 -m pytest tests/ -q` and `python3 -m ruff check scripts/ tests/` before every commit.
- Commit messages follow the repo convention: `feat(...)`/`fix(...)`/`docs(...)`/`test(...)` prefixes.

---

### Task 1: `scripts/evidence.py` — module skeleton + `derive_evidence`

**Files:**
- Create: `scripts/evidence.py`
- Test: `tests/test_evidence.py` (create)

**Interfaces:**
- Consumes: finding dicts as produced by `synthesize.normalize_finding` (fields: `severity`, `confidence`, `source`, `provenance`, `citation_quality`, `reinforced`, `corroborated`, `corroborated_by`).
- Produces (later tasks rely on these exact names):
  - `EVIDENCE_STATUSES: tuple[str, ...]`
  - `GATE_ELIGIBLE_DEFAULT: frozenset[str]` == `{"tool_confirmed", "advisor_confirmed"}`
  - `SEV_ORDER: list[str]` == `["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]`
  - `is_tool_sourced(finding) -> bool`
  - `sev_rank(finding) -> int`
  - `derive_evidence(finding, verdict=None) -> dict` with keys `status`, `verified_by`, `reasoning`, `citation_quality`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_evidence.py
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))
import scripts.evidence as evidence


def _finding(**kw):
    f = {"id": "SEC-001", "title": "t", "severity": "HIGH",
         "confidence": "POSSIBLE", "panel": "security", "category": "injection",
         "location": {"file": "app.py", "line_start": 10},
         "citation_quality": "partial"}
    f.update(kw)
    return f


class TestDeriveEvidence(unittest.TestCase):
    def test_tool_sourced_is_tool_confirmed(self):
        f = _finding(source="tool:semgrep",
                     provenance={"confirmation_reasoning": "Reported by semgrep"})
        ev = evidence.derive_evidence(f)
        self.assertEqual(ev["status"], "tool_confirmed")
        self.assertEqual(ev["verified_by"], "tool:semgrep")
        self.assertEqual(ev["reasoning"], "Reported by semgrep")
        self.assertEqual(ev["citation_quality"], "partial")

    def test_confirmed_verdict_is_advisor_confirmed(self):
        ev = evidence.derive_evidence(
            _finding(), {"verdict": "CONFIRMED", "reasoning": "sink verified"})
        self.assertEqual(ev["status"], "advisor_confirmed")
        self.assertEqual(ev["verified_by"], "agent:advisor")
        self.assertEqual(ev["reasoning"], "sink verified")

    def test_rejected_verdict_is_rejected(self):
        ev = evidence.derive_evidence(
            _finding(), {"verdict": "REJECTED", "reasoning": "no sink"})
        self.assertEqual(ev["status"], "rejected")

    def test_needs_more_info_verdict(self):
        ev = evidence.derive_evidence(
            _finding(), {"verdict": "NEEDS_MORE_INFO", "reasoning": "need config"})
        self.assertEqual(ev["status"], "needs_more_info")
        self.assertEqual(ev["reasoning"], "need config")

    def test_verdict_beats_corroboration(self):
        ev = evidence.derive_evidence(
            _finding(corroborated=True, corroborated_by=["security", "database"]),
            {"verdict": "REJECTED", "reasoning": "r"})
        self.assertEqual(ev["status"], "rejected")

    def test_tool_beats_verdict(self):
        # Tool findings never enter the queue; if a verdict is passed anyway,
        # tool_confirmed still wins (precedence rule 1).
        ev = evidence.derive_evidence(
            _finding(source="tool:bandit"), {"verdict": "REJECTED"})
        self.assertEqual(ev["status"], "tool_confirmed")

    def test_cross_panel_corroborated(self):
        ev = evidence.derive_evidence(
            _finding(corroborated=True, corroborated_by=["security", "database"]))
        self.assertEqual(ev["status"], "corroborated")
        self.assertEqual(ev["verified_by"], ["security", "database"])

    def test_reinforced_is_corroborated(self):
        ev = evidence.derive_evidence(_finding(reinforced=True))
        self.assertEqual(ev["status"], "corroborated")
        self.assertEqual(ev["verified_by"], "tool+agent")

    def test_default_is_unverified(self):
        ev = evidence.derive_evidence(_finding())
        self.assertEqual(ev["status"], "unverified")
        self.assertIsNone(ev["verified_by"])
        self.assertIsNone(ev["reasoning"])

    def test_never_mutates_severity_or_confidence(self):
        for verdict in (None, {"verdict": "CONFIRMED"}, {"verdict": "REJECTED"},
                        {"verdict": "NEEDS_MORE_INFO"}):
            f = _finding()
            evidence.derive_evidence(f, verdict)
            self.assertEqual(f["severity"], "HIGH")
            self.assertEqual(f["confidence"], "POSSIBLE")

    def test_missing_citation_quality_defaults_none(self):
        f = _finding()
        del f["citation_quality"]
        self.assertEqual(evidence.derive_evidence(f)["citation_quality"], "none")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_evidence.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'scripts.evidence'`

- [ ] **Step 3: Write the implementation**

```python
# scripts/evidence.py
#!/usr/bin/env python3
"""Evidence axis for panopticon findings: status derivation, verify-queue
triage, and advisor verdict ingestion. Stdlib-only.

Two-axis model: severity means "impact if true" and is never mutated here;
evidence.status records how hard the claim has been verified.
"""
import json
import os
import sys

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
EVIDENCE_STATUSES = ("tool_confirmed", "advisor_confirmed", "corroborated",
                     "needs_more_info", "unverified", "rejected")
GATE_ELIGIBLE_DEFAULT = frozenset({"tool_confirmed", "advisor_confirmed"})
VERDICT_VALUES = {"CONFIRMED", "REJECTED", "NEEDS_MORE_INFO"}


def is_tool_sourced(finding):
    """Tool-emitted findings carry source='tool:<name>'; everything else is agentic."""
    return str(finding.get("source", "")).startswith("tool:")


def sev_rank(finding):
    """Lower is more severe; unknown severities sort last."""
    try:
        return SEV_ORDER.index(finding.get("severity", "INFO"))
    except ValueError:
        return len(SEV_ORDER)


def derive_evidence(finding, verdict=None):
    """Return the evidence dict for a finding.

    Precedence: tool_confirmed > advisor verdicts (CONFIRMED/REJECTED/
    NEEDS_MORE_INFO) > corroborated > unverified. Never mutates the finding.
    Self-asserted provenance.confirmation_status is deliberately ignored —
    a reviewer cannot confirm its own finding.
    """
    quality = finding.get("citation_quality") or "none"
    prov = finding.get("provenance") or {}
    if is_tool_sourced(finding):
        return {"status": "tool_confirmed",
                "verified_by": finding.get("source"),
                "reasoning": prov.get("confirmation_reasoning")
                or "Reported by static-analysis tool",
                "citation_quality": quality}
    v = str((verdict or {}).get("verdict", "")).upper()
    if v in VERDICT_VALUES:
        status = {"CONFIRMED": "advisor_confirmed",
                  "REJECTED": "rejected"}.get(v, "needs_more_info")
        return {"status": status, "verified_by": "agent:advisor",
                "reasoning": (verdict or {}).get("reasoning"),
                "citation_quality": quality}
    if finding.get("reinforced"):
        return {"status": "corroborated", "verified_by": "tool+agent",
                "reasoning": "Same locus reported independently by a tool and an agent",
                "citation_quality": quality}
    if finding.get("corroborated"):
        panels = list(finding.get("corroborated_by") or [])
        return {"status": "corroborated", "verified_by": panels,
                "reasoning": "Nearby locus independently flagged by panels: %s"
                % ", ".join(panels),
                "citation_quality": quality}
    return {"status": "unverified", "verified_by": None, "reasoning": None,
            "citation_quality": quality}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_evidence.py -v`
Expected: all PASS

- [ ] **Step 5: Ruff and commit**

```bash
python3 -m ruff check scripts/evidence.py tests/test_evidence.py
git add scripts/evidence.py tests/test_evidence.py
git commit -m "feat(evidence): evidence-status derivation for the two-axis model"
```

---

### Task 2: Triage — `triage_priority`, `build_verify_queue`, `write_verify_queue`

**Files:**
- Modify: `scripts/evidence.py`
- Test: `tests/test_verify_queue.py` (create)

**Interfaces:**
- Consumes: Task 1's helpers.
- Produces:
  - `triage_priority(finding) -> int` (lower = verify first)
  - `build_verify_queue(findings, max_verify=None) -> (entries, cut_count)` where each entry is `{"queue_id": "%03d-%s", "priority": int, "finding": <reference to the ORIGINAL dict, not a copy>}`
  - `write_verify_queue(entries, cut, path) -> None` writing `{"version": "4.0.0", "cut_by_max_verify": cut, "entries": [...]}` with underscore-prefixed finding keys stripped

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_verify_queue.py
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))
import scripts.evidence as evidence


def _finding(fid, sev, **kw):
    f = {"id": fid, "title": "t", "severity": sev, "confidence": "POSSIBLE",
         "panel": "security", "category": "injection",
         "location": {"file": "app.py", "line_start": 10}}
    f.update(kw)
    return f


class TestTriagePriority(unittest.TestCase):
    def test_priority_ordering(self):
        self.assertEqual(evidence.triage_priority(
            _finding("A-001", "CRITICAL", corroborated=True)), 0)
        self.assertEqual(evidence.triage_priority(
            _finding("A-002", "HIGH", reinforced=True)), 0)
        self.assertEqual(evidence.triage_priority(_finding("A-003", "HIGH")), 1)
        self.assertEqual(evidence.triage_priority(
            _finding("A-004", "MEDIUM", corroborated=True)), 2)
        self.assertGreater(evidence.triage_priority(_finding("A-005", "MEDIUM")),
                           evidence.triage_priority(
                               _finding("A-004", "MEDIUM", corroborated=True)))
        self.assertGreater(evidence.triage_priority(_finding("A-006", "LOW")),
                           evidence.triage_priority(_finding("A-005", "MEDIUM")))


class TestBuildVerifyQueue(unittest.TestCase):
    def test_tools_excluded_agentic_included(self):
        fs = [_finding("T-001", "HIGH", source="tool:semgrep"),
              _finding("AG-001", "LOW")]
        entries, cut = evidence.build_verify_queue(fs)
        self.assertEqual(cut, 0)
        self.assertEqual([e["finding"]["id"] for e in entries], ["AG-001"])

    def test_self_asserted_confirmed_still_queued(self):
        f = _finding("AG-002", "HIGH",
                     provenance={"discovered_by": "agent:panel_review",
                                 "confirmation_status": "CONFIRMED"})
        entries, _ = evidence.build_verify_queue([f])
        self.assertEqual(len(entries), 1)

    def test_priority_sorted_and_queue_ids_assigned(self):
        fs = [_finding("AG-010", "LOW"),
              _finding("AG-011", "CRITICAL", corroborated=True),
              _finding("AG-012", "HIGH")]
        entries, _ = evidence.build_verify_queue(fs)
        self.assertEqual([e["finding"]["id"] for e in entries],
                         ["AG-011", "AG-012", "AG-010"])
        self.assertEqual(entries[0]["queue_id"], "000-AG-011")
        self.assertEqual(entries[1]["queue_id"], "001-AG-012")

    def test_entries_reference_original_dicts(self):
        f = _finding("AG-020", "HIGH")
        entries, _ = evidence.build_verify_queue([f])
        self.assertIs(entries[0]["finding"], f)

    def test_max_verify_cuts_lowest_priority(self):
        fs = [_finding("AG-030", "LOW"), _finding("AG-031", "CRITICAL"),
              _finding("AG-032", "HIGH")]
        entries, cut = evidence.build_verify_queue(fs, max_verify=2)
        self.assertEqual(cut, 1)
        self.assertEqual([e["finding"]["id"] for e in entries],
                         ["AG-031", "AG-032"])

    def test_stable_order_for_equal_priority(self):
        fs = [_finding("AG-040", "HIGH"), _finding("AG-041", "HIGH")]
        entries, _ = evidence.build_verify_queue(fs)
        self.assertEqual([e["finding"]["id"] for e in entries],
                         ["AG-040", "AG-041"])


class TestWriteVerifyQueue(unittest.TestCase):
    def test_writes_payload_and_strips_private_keys(self):
        f = _finding("AG-050", "HIGH", _group="g1", _repo_root="/x")
        entries, cut = evidence.build_verify_queue([f])
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "q", "verify-queue.json")
            evidence.write_verify_queue(entries, cut, path)
            with open(path) as fh:
                payload = json.load(fh)
        self.assertEqual(payload["version"], "4.0.0")
        self.assertEqual(payload["cut_by_max_verify"], 0)
        self.assertEqual(payload["entries"][0]["queue_id"], "000-AG-050")
        self.assertNotIn("_group", payload["entries"][0]["finding"])
        self.assertNotIn("_repo_root", payload["entries"][0]["finding"])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_verify_queue.py -v`
Expected: FAIL with `AttributeError: module 'scripts.evidence' has no attribute 'triage_priority'`

- [ ] **Step 3: Append the implementation to `scripts/evidence.py`**

```python
def triage_priority(finding):
    """Sort key for the verify queue; lower verifies first.

    Spec order: corroborated CRITICAL/HIGH -> uncorroborated CRITICAL/HIGH ->
    corroborated MEDIUM -> everything else descending by severity.
    """
    sev = str(finding.get("severity", "INFO")).upper()
    corroborated = bool(finding.get("corroborated") or finding.get("reinforced"))
    if sev in ("CRITICAL", "HIGH"):
        return 0 if corroborated else 1
    if sev == "MEDIUM" and corroborated:
        return 2
    try:
        return 3 + SEV_ORDER.index(sev)
    except ValueError:
        return 3 + len(SEV_ORDER)


def build_verify_queue(findings, max_verify=None):
    """Return (entries, cut_count) for ALL agentic findings, priority-sorted.

    Entries hold REFERENCES to the original finding dicts (verdict application
    must mutate the real objects). Self-asserted provenance confirmation is
    ignored — everything non-tool queues. Stable order: (priority, input index),
    so recomputation in pass 2 reproduces pass 1's queue_ids exactly.
    """
    agentic = [(i, f) for i, f in enumerate(findings) if not is_tool_sourced(f)]
    agentic.sort(key=lambda t: (triage_priority(t[1]), t[0]))
    cut = 0
    if max_verify is not None and max_verify >= 0 and len(agentic) > max_verify:
        cut = len(agentic) - max_verify
        agentic = agentic[:max_verify]
    entries = []
    for qi, (_, f) in enumerate(agentic):
        entries.append({"queue_id": "%03d-%s" % (qi, f.get("id", "UNKNOWN")),
                        "priority": triage_priority(f),
                        "finding": f})
    return entries, cut


def write_verify_queue(entries, cut, path):
    """Serialize the queue for the orchestrating agent (pass 1 artifact)."""
    payload = {
        "version": "4.0.0",
        "cut_by_max_verify": cut,
        "entries": [{"queue_id": e["queue_id"], "priority": e["priority"],
                     "finding": {k: v for k, v in e["finding"].items()
                                 if not k.startswith("_")}}
                    for e in entries],
    }
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_verify_queue.py tests/test_evidence.py -v`
Expected: all PASS

- [ ] **Step 5: Ruff and commit**

```bash
python3 -m ruff check scripts/evidence.py tests/test_verify_queue.py
git add scripts/evidence.py tests/test_verify_queue.py
git commit -m "feat(evidence): verify-queue triage with priority order and --max-verify cap"
```

---

### Task 3: Verdict ingestion — `load_verdicts`, `match_verdict`, `apply_verdict`, `merge_citations`

**Files:**
- Modify: `scripts/evidence.py`
- Test: `tests/test_verdict_ingest.py` (create)

**Interfaces:**
- Consumes: queue entries from Task 2.
- Produces:
  - `merge_citations(best, other) -> None` — moved VERBATIM from `synthesize._merge_citations` (synthesize delegates to it in Task 5)
  - `load_verdicts(verdicts_dir) -> dict[queue_id, verdict]` — tolerant
  - `match_verdict(entry, verdicts) -> verdict | None` — finding_id echo check
  - `apply_verdict(finding, verdict) -> None` — mutates provenance/citations/references ONLY

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_verdict_ingest.py
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))
import scripts.evidence as evidence


def _entry(fid="SEC-001", queue_id="000-SEC-001", **kw):
    f = {"id": fid, "title": "t", "severity": "HIGH", "confidence": "POSSIBLE",
         "panel": "security", "category": "injection",
         "location": {"file": "app.py", "line_start": 10},
         "references": ["https://owasp.org"]}
    f.update(kw)
    return {"queue_id": queue_id, "priority": 1, "finding": f}


def _write(d, name, obj):
    path = os.path.join(d, name)
    with open(path, "w") as fh:
        if isinstance(obj, str):
            fh.write(obj)
        else:
            json.dump(obj, fh)
    return path


class TestLoadVerdicts(unittest.TestCase):
    def test_loads_valid_skips_malformed(self):
        with tempfile.TemporaryDirectory() as d:
            _write(d, "000-SEC-001.json",
                   {"finding_id": "SEC-001", "verdict": "CONFIRMED", "reasoning": "r"})
            _write(d, "001-SEC-002.json", "{not json")
            _write(d, "002-SEC-003.json", {"reasoning": "no verdict key"})
            _write(d, "notes.txt", "ignored")
            out = evidence.load_verdicts(d)
        self.assertEqual(set(out), {"000-SEC-001"})

    def test_missing_dir_returns_empty(self):
        self.assertEqual(evidence.load_verdicts("/nonexistent/dir"), {})
        self.assertEqual(evidence.load_verdicts(None), {})


class TestMatchVerdict(unittest.TestCase):
    def test_match_with_echo(self):
        v = {"finding_id": "SEC-001", "verdict": "CONFIRMED"}
        self.assertIs(evidence.match_verdict(_entry(), {"000-SEC-001": v}), v)

    def test_echo_mismatch_rejected(self):
        v = {"finding_id": "SEC-999", "verdict": "CONFIRMED"}
        self.assertIsNone(evidence.match_verdict(_entry(), {"000-SEC-001": v}))

    def test_missing_echo_accepted_with_warning(self):
        v = {"verdict": "CONFIRMED"}
        self.assertIs(evidence.match_verdict(_entry(), {"000-SEC-001": v}), v)

    def test_no_verdict_returns_none(self):
        self.assertIsNone(evidence.match_verdict(_entry(), {}))


class TestApplyVerdict(unittest.TestCase):
    def test_confirmed_updates_provenance_never_severity(self):
        e = _entry()
        f = e["finding"]
        evidence.apply_verdict(f, {"verdict": "CONFIRMED", "reasoning": "verified",
                                   "model": "claude-sonnet",
                                   "references": ["https://cwe.mitre.org", "https://owasp.org"],
                                   "citations": {"cwe": ["CWE-89"]}})
        self.assertEqual(f["provenance"]["confirmation_status"], "CONFIRMED")
        self.assertEqual(f["provenance"]["confirmed_by"], "agent:advisor")
        self.assertEqual(f["provenance"]["confirmation_reasoning"], "verified")
        self.assertEqual(f["provenance"]["confirmed_by_model"], "claude-sonnet")
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(f["confidence"], "POSSIBLE")
        self.assertEqual(f["citations"]["cwe"], ["CWE-89"])
        # de-duplicated references, order preserved
        self.assertEqual(f["references"],
                         ["https://owasp.org", "https://cwe.mitre.org"])

    def test_rejected_keeps_severity(self):
        e = _entry()
        evidence.apply_verdict(e["finding"], {"verdict": "REJECTED", "reasoning": "no"})
        self.assertEqual(e["finding"]["severity"], "HIGH")
        self.assertEqual(e["finding"]["provenance"]["confirmation_status"], "REJECTED")

    def test_existing_citation_keys_not_overwritten(self):
        e = _entry(citations={"cwe": ["CWE-79"]})
        evidence.apply_verdict(e["finding"],
                               {"verdict": "CONFIRMED",
                                "citations": {"cwe": ["CWE-89"], "owasp": ["A03:2021"]}})
        self.assertEqual(e["finding"]["citations"]["cwe"], ["CWE-79"])
        self.assertEqual(e["finding"]["citations"]["owasp"], ["A03:2021"])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_verdict_ingest.py -v`
Expected: FAIL with `AttributeError: ... no attribute 'load_verdicts'`

- [ ] **Step 3: Append the implementation to `scripts/evidence.py`**

```python
def merge_citations(best, other):
    """Merge other['citations'] into best['citations'] without overwriting
    keys that already exist in best. (Moved from synthesize._merge_citations.)"""
    oc = other.get("citations")
    if not oc:
        return
    if not best.get("citations"):
        best["citations"] = {}
    bc = best["citations"]
    for key, value in oc.items():
        if not value:
            continue
        if key not in bc or not bc[key]:
            bc[key] = value


def load_verdicts(verdicts_dir):
    """Load advisor verdict files keyed by queue_id (filename stem).

    Tolerant by design: unreadable/malformed files and files without a valid
    verdict key are skipped with a stderr note; never raises.
    """
    out = {}
    if not verdicts_dir or not os.path.isdir(verdicts_dir):
        return out
    for name in sorted(os.listdir(verdicts_dir)):
        if not name.endswith(".json"):
            continue
        path = os.path.join(verdicts_dir, name)
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError) as e:
            print("evidence: skipping malformed verdict %s: %s" % (name, e),
                  file=sys.stderr)
            continue
        if (not isinstance(data, dict)
                or str(data.get("verdict", "")).upper() not in VERDICT_VALUES):
            print("evidence: skipping verdict %s: missing/invalid verdict key" % name,
                  file=sys.stderr)
            continue
        out[name[:-len(".json")]] = data
    return out


def match_verdict(entry, verdicts):
    """Return the verdict for a queue entry, enforcing the finding_id echo.

    An explicit echo mismatch means the verdict answered a different claim ->
    treated as malformed (None). A missing echo is accepted with a warning.
    """
    v = verdicts.get(entry["queue_id"])
    if v is None:
        return None
    fid = entry["finding"].get("id")
    echoed = v.get("finding_id")
    if echoed is None:
        print("evidence: verdict %s has no finding_id echo; accepting"
              % entry["queue_id"], file=sys.stderr)
        return v
    if str(echoed) != str(fid):
        print("evidence: verdict %s echoes finding_id %r, expected %r; ignoring"
              % (entry["queue_id"], echoed, fid), file=sys.stderr)
        return None
    return v


def apply_verdict(finding, verdict):
    """Merge an advisor verdict into provenance/citations/references.

    Never touches severity or confidence — the two-axis invariant. Citation
    re-validation happens afterwards via citations.enrich_citations.
    """
    prov = finding.setdefault("provenance", {})
    v = str(verdict.get("verdict", "")).upper()
    prov["confirmation_status"] = {"CONFIRMED": "CONFIRMED",
                                   "REJECTED": "REJECTED"}.get(v, "NEEDS_MORE_INFO")
    prov["confirmed_by"] = "agent:advisor"
    prov["confirmation_reasoning"] = verdict.get("reasoning")
    if verdict.get("model"):
        prov["confirmed_by_model"] = verdict["model"]
    merge_citations(finding, {"citations": verdict.get("citations") or {}})
    existing = set(finding.get("references") or [])
    for ref in verdict.get("references") or []:
        if ref not in existing:
            finding.setdefault("references", []).append(ref)
            existing.add(ref)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_verdict_ingest.py tests/test_verify_queue.py tests/test_evidence.py -v`
Expected: all PASS

- [ ] **Step 5: Ruff and commit**

```bash
python3 -m ruff check scripts/evidence.py tests/test_verdict_ingest.py
git add scripts/evidence.py tests/test_verdict_ingest.py
git commit -m "feat(evidence): tolerant verdict ingestion with finding_id echo check"
```

---

### Task 4: Fix `GROUP_RE` for 3.0 dispatch filenames

**Files:**
- Modify: `scripts/synthesize.py:825` (the `GROUP_RE` constant)
- Test: `tests/test_synthesize.py` (add one test class)

**Interfaces:**
- Consumes: `dispatch.build_plan` out_file naming (`findings-{group}-{panel}-panel_review.json`, `findings-{group}-{panel}-lens_sweep-{lens}.json`).
- Produces: `GROUP_RE` matching BOTH 2.x (`findings-{group}-{panel}.json`) and 3.0 role-suffixed names, capturing the group in group(1).

- [ ] **Step 1: Write the failing test** (append to `tests/test_synthesize.py`)

```python
class TestGroupReMatchesDispatchNames(unittest.TestCase):
    def test_matches_names_actually_produced_by_dispatch(self):
        import scripts.dispatch as dispatch
        profile = {"group": "changes_1", "files": ["a.py"], "depth": "standard",
                   "panels": ["security"],
                   "lenses": {"security": [
                       {"name": "injection", "spawn": True, "priority": 1,
                        "depth_threshold": "shallow"}]}}
        plan = dispatch.build_plan(profile, host="claude")
        self.assertTrue(plan)
        for inv in plan:
            base = os.path.basename(inv["out_file"])
            m = syn.GROUP_RE.match(base)
            self.assertIsNotNone(m, base)
            self.assertEqual(m.group(1), "changes_1", base)

    def test_still_matches_legacy_2x_names(self):
        m = syn.GROUP_RE.match("findings-changes_1-security.json")
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "changes_1")
```

(Match the file's existing import style — it already imports `scripts.synthesize as syn` or similar; check the top of the file and reuse its alias. Add `import scripts.dispatch as dispatch` inside the test if the file doesn't import it.)

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_synthesize.py -k GroupRe -v`
Expected: the dispatch-names test FAILS (no match for `findings-changes_1-security-panel_review.json`); the legacy test passes.

- [ ] **Step 3: Fix the regex** in `scripts/synthesize.py`

```python
GROUP_RE = re.compile(
    r"^findings-(.+)-(?:code|test|security|architecture|database|redteam)"
    r"(?:-panel_review|-lens_sweep-[A-Za-z0-9_]+)?\.json$")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_synthesize.py -k GroupRe -v` then `python3 -m pytest tests/ -q`
Expected: PASS; full suite unchanged.

- [ ] **Step 5: Commit**

```bash
git add scripts/synthesize.py tests/test_synthesize.py
git commit -m "fix(synthesize): GROUP_RE matches 3.0 role-suffixed findings filenames"
```

---

### Task 5: Rewrite `build_report` around evidence; delete the downgrade machinery

This is the core task. `synthesize.py` stops mutating severity anywhere, derives evidence for every finding, and computes grades/gate from gate-eligible findings only.

**Files:**
- Modify: `scripts/synthesize.py`
- Modify: `tests/test_synthesize.py`
- Delete: `tests/test_synthesize_advisor.py` (its subjects are removed; coverage moves to `tests/test_evidence.py` / `tests/test_verify_queue.py`)

**Interfaces:**
- Consumes: everything `scripts/evidence.py` produces (Tasks 1–3).
- Produces (Task 6 relies on these):
  - `prepare_findings(findings) -> (findings, integration_findings)` — dedupe + cross-panel corroboration, extracted so pass 1 can reuse it
  - `build_report(findings, groups_meta, target, fail_on, timestamp, review_type="repo", security_mode="standard", verdicts=None, gate_unverified=False, max_verify=None) -> report`
  - report shape: `summary` has `overall_grade, risk_level, top_issues, gate, gate_policy, stats, evidence_stats`; NO `effort_to_remediate`, NO `recommendations` top-level key; every finding (incl. `discarded_claims`) has `evidence`; `meta.version == "4.0.0"`

**Deletions (all in `scripts/synthesize.py`):**
`_dispatch_advisor`, `_get_kimi_version`, `_render_advisor_prompt`, `_read_code_context`, `_KIMI_VERSION_CACHE`, `_ADVISOR_TEMPLATE_PATH`, `_partition_findings`, `apply_advisor_verdict`, `flag_for_advisor`, `_merge_citations` (replaced by `evidence.merge_citations`), the `import shutil` / `import subprocess` lines (no longer used), and the `advisor_results` / `advisor_dispatch` parameters everywhere. `_reinforce_merge` calls `evidence.merge_citations` instead of `_merge_citations`.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_synthesize.py`; delete `tests/test_synthesize_advisor.py` and the `_partition_findings`/`apply_advisor_verdict` test classes in `tests/test_synthesize.py` — the classes at roughly lines 1040–1210 asserting INFO downgrades and `advisor_dispatch` behavior)

```python
def _agentic(fid="AG-001", sev="HIGH", **kw):
    f = {"id": fid, "title": "finding %s" % fid, "severity": sev,
         "confidence": "POSSIBLE", "panel": "security", "category": "injection",
         "location": {"file": "app.py", "line_start": 10},
         "provenance": {"discovered_by": "agent:panel_review",
                        "confirmation_status": "UNVERIFIED"}}
    f.update(kw)
    return f


class TestEvidenceReport(unittest.TestCase):
    def _report(self, findings, verdicts=None, gate_unverified=False, fail_on="high"):
        return syn.build_report(findings, [], "target", fail_on, "2026-08-03T00:00:00Z",
                                verdicts=verdicts, gate_unverified=gate_unverified)

    def test_unverified_keeps_severity_and_does_not_gate(self):
        report = self._report([_agentic(sev="CRITICAL")])
        f = report["findings"][0]
        self.assertEqual(f["severity"], "CRITICAL")
        self.assertEqual(f["evidence"]["status"], "unverified")
        self.assertEqual(report["summary"]["gate"], "PASS")
        self.assertEqual(report["summary"]["overall_grade"], "A")

    def test_gate_unverified_opts_in(self):
        report = self._report([_agentic(sev="CRITICAL")], gate_unverified=True)
        self.assertEqual(report["summary"]["gate"], "FAIL")
        self.assertEqual(report["summary"]["overall_grade"], "F")
        self.assertEqual(report["summary"]["gate_policy"], "include_unverified")

    def test_confirmed_verdict_gates(self):
        verdicts = {"000-AG-001": {"finding_id": "AG-001", "verdict": "CONFIRMED",
                                   "reasoning": "verified"}}
        report = self._report([_agentic()], verdicts=verdicts)
        f = report["findings"][0]
        self.assertEqual(f["evidence"]["status"], "advisor_confirmed")
        self.assertEqual(report["summary"]["gate"], "FAIL")
        self.assertEqual(report["summary"]["overall_grade"], "D")

    def test_rejected_moves_to_discarded_with_severity_intact(self):
        verdicts = {"000-AG-001": {"finding_id": "AG-001", "verdict": "REJECTED",
                                   "reasoning": "not exploitable"}}
        report = self._report([_agentic()], verdicts=verdicts)
        self.assertEqual(report["findings"], [])
        d = report["discarded_claims"][0]
        self.assertEqual(d["severity"], "HIGH")
        self.assertEqual(d["evidence"]["status"], "rejected")
        self.assertEqual(d["evidence"]["reasoning"], "not exploitable")
        self.assertEqual(report["summary"]["gate"], "PASS")

    def test_needs_more_info_stays_visible_not_gating(self):
        verdicts = {"000-AG-001": {"finding_id": "AG-001",
                                   "verdict": "NEEDS_MORE_INFO",
                                   "reasoning": "need deploy config"}}
        report = self._report([_agentic()], verdicts=verdicts)
        f = report["findings"][0]
        self.assertEqual(f["evidence"]["status"], "needs_more_info")
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(report["summary"]["gate"], "PASS")

    def test_tool_finding_gates_without_verdict(self):
        tool = {"id": "TL-001", "title": "sqli", "severity": "HIGH",
                "confidence": "CERTAIN", "panel": "security",
                "category": "injection", "source": "tool:semgrep",
                "location": {"file": "app.py", "line_start": 5},
                "provenance": {"discovered_by": "tool:semgrep",
                               "confirmation_status": "TOOL"}}
        report = self._report([syn.normalize_finding(tool)])
        self.assertEqual(report["findings"][0]["evidence"]["status"],
                         "tool_confirmed")
        self.assertEqual(report["summary"]["gate"], "FAIL")

    def test_evidence_stats_counts_everything(self):
        verdicts = {"000-AG-001": {"finding_id": "AG-001", "verdict": "REJECTED",
                                   "reasoning": "r"}}
        report = self._report([_agentic(), _agentic(fid="AG-002", sev="LOW")],
                              verdicts=verdicts)
        stats = report["summary"]["evidence_stats"]
        self.assertEqual(stats["rejected"], 1)
        self.assertEqual(stats["unverified"], 1)

    def test_schema_theater_removed(self):
        report = self._report([_agentic()])
        self.assertNotIn("effort_to_remediate", report["summary"])
        self.assertNotIn("recommendations", report)
        self.assertEqual(report["meta"]["version"], "4.0.0")

    def test_citation_quality_lives_in_evidence(self):
        report = self._report([_agentic(citations={"cwe": ["CWE-89"]})])
        f = report["findings"][0]
        self.assertNotIn("citation_quality", f)
        self.assertIn(f["evidence"]["citation_quality"],
                      ("full", "partial", "minimal", "none"))


class TestSeverityImmutability(unittest.TestCase):
    def test_no_path_mutates_severity(self):
        cases = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            cases.append((_agentic(fid="AG-%s" % sev[:2], sev=sev), None))
        cases.append((_agentic(fid="AG-101"), {"verdict": "REJECTED", "reasoning": "r"}))
        cases.append((_agentic(fid="AG-102"), {"verdict": "NEEDS_MORE_INFO",
                                               "reasoning": "r"}))
        cases.append((_agentic(fid="AG-103"), {"verdict": "CONFIRMED",
                                               "reasoning": "r"}))
        for finding, verdict in cases:
            original = finding["severity"]
            verdicts = ({"000-%s" % finding["id"]:
                         dict(verdict, finding_id=finding["id"])}
                        if verdict else None)
            report = syn.build_report([finding], [], "t", "high",
                                      "2026-08-03T00:00:00Z", verdicts=verdicts)
            everywhere = report["findings"] + report["discarded_claims"]
            self.assertEqual(everywhere[0]["severity"], original,
                             "severity mutated for verdict=%r" % verdict)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_synthesize.py -k "EvidenceReport or SeverityImmutability" -v`
Expected: FAIL (`build_report` has no `verdicts`/`gate_unverified` params yet)

- [ ] **Step 3: Rewrite `build_report` and delete the old machinery**

At the top of `scripts/synthesize.py`, add `import scripts.evidence as evidence_mod` next to the other `scripts.` imports and delete `import shutil` and `import subprocess`. Apply the deletion list from this task's header. Replace both `_merge_citations` call sites in `_reinforce_merge` with `evidence_mod.merge_citations`. Then:

```python
def prepare_findings(findings):
    """Dedupe + cross-panel corroboration. Extracted so pass 1 (--emit-verify-queue)
    can compute the queue with the same deterministic pipeline as pass 2."""
    findings = dedupe(findings)
    integration = cross_panel_corroboration(findings)
    return findings, integration


def evidence_stats(findings):
    """Count findings by evidence status."""
    stats = {s: 0 for s in evidence_mod.EVIDENCE_STATUSES}
    for f in findings:
        st = (f.get("evidence") or {}).get("status")
        if st in stats:
            stats[st] += 1
    return stats


def _issue_sort(f):
    """Severity first; among equals, gate-eligible evidence leads."""
    eligible = ((f.get("evidence") or {}).get("status")
                in evidence_mod.GATE_ELIGIBLE_DEFAULT)
    return (_sev_rank(f), 0 if eligible else 1)


def build_report(findings, groups_meta, target, fail_on, timestamp, review_type="repo",
                 security_mode="standard", verdicts=None, gate_unverified=False,
                 max_verify=None):
    """Build a CodeReviewReport under the two-axis severity x evidence model.

    Severity is never mutated here. Verdicts (from evidence.load_verdicts) are
    applied to queued findings; every finding gets an evidence object; grades
    and the gate are computed from gate-eligible findings only (all non-rejected
    when gate_unverified is set).
    """
    findings, integration_findings = prepare_findings(findings)
    catalog = load_cwe_catalog()
    queue, _cut = evidence_mod.build_verify_queue(findings, max_verify)
    verdicts = verdicts or {}
    matched = {}
    for entry in queue:
        v = evidence_mod.match_verdict(entry, verdicts)
        if v is not None:
            evidence_mod.apply_verdict(entry["finding"], v)
        elif verdicts:
            print("synthesize: no verdict for queued finding %s; unverified"
                  % entry["queue_id"], file=sys.stderr)
        matched[id(entry["finding"])] = v
    # Re-validate citations after advisor merges (idempotent; preserves epss).
    citations.enrich_citations(findings, catalog, epss_enabled=False)
    for f in findings:
        f["evidence"] = evidence_mod.derive_evidence(f, matched.get(id(f)))
        f.pop("citation_quality", None)

    rejected = [f for f in findings if f["evidence"]["status"] == "rejected"]
    active = [f for f in findings if f["evidence"]["status"] != "rejected"]
    gate_eligible = (active if gate_unverified else
                     [f for f in active
                      if f["evidence"]["status"] in evidence_mod.GATE_ELIGIBLE_DEFAULT])

    by_panel = {p: [] for p in VALID_PANELS}
    for f in gate_eligible:
        by_panel.get(f["panel"], by_panel["code"]).append(f)

    known_groups = {g["name"] for g in groups_meta}
    group_objs = []
    for g in groups_meta:
        gfiles = set(g["files"])
        gfind = [f for f in active
                 if (f.get("_group") == g["name"])
                 or (f.get("_group") not in known_groups
                     and (f.get("location") or {}).get("file") in gfiles)]
        eligible_ids = {id(x) for x in gate_eligible}
        geligible = [f for f in gfind if id(f) in eligible_ids]
        gp = {p: [x for x in geligible if x["panel"] == p] for p in by_panel}
        group_objs.append({
            "name": g["name"],
            "files": g["files"],
            "panel_grades": {p: grade(gp[p]) for p in by_panel},
            "key_findings": [f.get("title", "") for f in gfind
                             if f["severity"] in ("CRITICAL", "HIGH")][:5],
        })

    overall = _worst_grade([grade(by_panel[p]) for p in by_panel])
    for f in findings:
        f.pop("_group", None)
        f.pop("_repo_root", None)
    return {
        "meta": {
            "target": target,
            "review_type": review_type,
            "timestamp": timestamp,
            "version": "4.0.0",
            "security_mode": security_mode,
            "models_used": _collect_models_used(findings),
        },
        "summary": {
            "overall_grade": overall,
            "risk_level": risk_level(gate_eligible),
            "top_issues": [f.get("title", "") for f in
                           sorted(active, key=_issue_sort)[:3]],
            "gate": gate_verdict(gate_eligible, fail_on),
            "gate_policy": ("include_unverified" if gate_unverified
                            else "confirmed_only"),
            "stats": severity_stats(active),
            "evidence_stats": evidence_stats(findings),
        },
        "groups": group_objs,
        "findings": active,
        "discarded_claims": rejected,
        "cross_panel": {"integration_findings": integration_findings},
    }
```

Notes for the implementer:
- `grade`, `risk_level`, `gate_verdict`, `severity_stats`, `dedupe`, `cross_panel_corroboration`, `_collect_models_used`, `_worst_grade` are all unchanged — they just receive pre-filtered lists now.
- In `validate_report`: remove `"recommendations"` from the required top-level keys tuple, and add per-finding evidence validation:

```python
        ev = f.get("evidence") or {}
        if ev.get("status") not in evidence_mod.EVIDENCE_STATUSES:
            errors.append("finding[%d] bad evidence.status: %r" % (i, ev.get("status")))
```

- In `main()`: the `build_report(...)` call currently passes `advisor_dispatch=_dispatch_advisor` — change it to pass nothing extra for now (Task 6 wires the new flags): `build_report(findings, groups_meta, args.target, args.fail_on, ts, review_type, security_mode)`. Also delete the `_repo_root` stamping loop (the block `for f in findings: f["_repo_root"] = repo_root` and the `repo_root` computation above it).
- In `render_summary`: replace the `prov = "reinforced" if ... else ...` chip with the evidence status, and add an Evidence line; also sort top findings by `_issue_sort`:

```python
        ev_status = (f.get("evidence") or {}).get("status", "unverified")
```
  and use `[%s·%s%s]` with `ev_status` where `prov` was used. After the `**Findings:**` line append:

```python
        "**Evidence:** %s" % ", ".join(
            "%s %d" % (k, v) for k, v in s["evidence_stats"].items() if v),
        "",
```
  and change the top-findings sort to `sorted(report["findings"], key=_issue_sort)[:10]`.

- [ ] **Step 4: Migrate the existing test file**

In `tests/test_synthesize.py`:
- Delete the test classes covering `_partition_findings`, `apply_advisor_verdict`, and advisor-dispatch error paths (approx. lines 1040–1215 — every test calling `syn._partition_findings` or asserting `severity == "INFO"` after downgrade). Their intent now lives in `TestEvidenceReport`/`TestSeverityImmutability` and Tasks 1–3 tests.
- Any `build_report(...)` call site passing `advisor_results=` or `advisor_dispatch=`: drop the argument.
- Fixtures constructing full report dicts for `validate_report`/`render_summary` (approx. lines 960–1020): remove `"effort_to_remediate"` and `"recommendations"` keys, add `"gate_policy": "confirmed_only"` and `"evidence_stats": {}` to `summary`, and give each fixture finding an `"evidence": {"status": "unverified", "verified_by": None, "reasoning": None, "citation_quality": "none"}` entry.
- Tests asserting grade/gate driven by agentic findings without verdicts: those findings are now `unverified` → expect grade "A"/gate "PASS", or pass `gate_unverified=True` to keep the old expectation. Choose per test intent: dedupe/reinforce tests keep `gate_unverified=True` (they test merging, not gating); gate tests get explicit new expectations.

- [ ] **Step 5: Run the full suite; fix stragglers by the two-axis rules**

Run: `python3 -m pytest tests/ -q`
Rules when adjudicating a failure: severity is never mutated; agentic findings without verdicts are `unverified` and don't gate by default; `discarded_claims` = rejected only, severities intact; no `effort_to_remediate`/`recommendations` anywhere.
Expected: all PASS.

- [ ] **Step 6: Ruff and commit**

```bash
python3 -m ruff check scripts/ tests/
git add -A scripts/synthesize.py tests/test_synthesize.py tests/test_synthesize_advisor.py
git commit -m "feat(synthesize): two-axis severity x evidence model; delete downgrade machinery"
```

---

### Task 6: Two-pass CLI — `--emit-verify-queue`, `--verdicts-dir`, `--gate-unverified`, `--max-verify`

**Files:**
- Modify: `scripts/synthesize.py` (`main()` only)
- Test: `tests/test_synthesize.py` (CLI tests), `tests/test_e2e.py`

**Interfaces:**
- Consumes: Task 5's `prepare_findings`/`build_report`, Task 2/3's queue + verdict functions.
- Produces: CLI contract used by SKILL.md (Task 10):
  - Pass 1: `synthesize.py --emit-verify-queue [--max-verify N] <findings...>` → writes `.panopticon/verify-queue.json` and exits 0 WITHOUT a report when the queue is non-empty; falls through to a full report when empty.
  - Pass 2: `synthesize.py --verdicts-dir DIR [--max-verify N] <findings...>` → full report with verdicts applied.
  - `--gate-unverified` on either pass.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_synthesize.py`)

```python
class TestTwoPassCli(unittest.TestCase):
    def _write_findings(self, d, findings):
        fp = os.path.join(d, ".panopticon", "findings-g1-security-panel_review.json")
        os.makedirs(os.path.dirname(fp), exist_ok=True)
        with open(fp, "w") as fh:
            json.dump({"findings": findings}, fh)
        return fp

    def test_pass1_emits_queue_not_report(self):
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            fp = self._write_findings(d, [_agentic()])
            out = os.path.join(d, "report.json")
            rc = syn.main(["--emit-verify-queue", "--out", out, fp])
            self.assertEqual(rc, 0)
            self.assertFalse(os.path.exists(out))
            with open(os.path.join(d, ".panopticon", "verify-queue.json")) as fh:
                queue = json.load(fh)
            self.assertEqual(queue["entries"][0]["queue_id"], "000-AG-001")

    def test_pass1_empty_queue_falls_through_to_report(self):
        tool = {"id": "TL-001", "title": "t", "severity": "LOW",
                "confidence": "CERTAIN", "panel": "security", "category": "x",
                "source": "tool:semgrep",
                "location": {"file": "a.py", "line_start": 1},
                "provenance": {"discovered_by": "tool:semgrep",
                               "confirmation_status": "TOOL"}}
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            fp = self._write_findings(d, [tool])
            out = os.path.join(d, "report.json")
            rc = syn.main(["--emit-verify-queue", "--out", out, fp])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(out))

    def test_pass2_applies_verdicts(self):
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            fp = self._write_findings(d, [_agentic()])
            vd = os.path.join(d, ".panopticon", "verdicts")
            os.makedirs(vd)
            with open(os.path.join(vd, "000-AG-001.json"), "w") as fh:
                json.dump({"finding_id": "AG-001", "verdict": "CONFIRMED",
                           "reasoning": "verified"}, fh)
            out = os.path.join(d, "report.json")
            rc = syn.main(["--verdicts-dir", vd, "--fail-on", "high",
                           "--out", out, fp])
            self.assertEqual(rc, 1)  # gate FAIL -> exit 1
            with open(out) as fh:
                report = json.load(fh)
            self.assertEqual(report["findings"][0]["evidence"]["status"],
                             "advisor_confirmed")
            self.assertEqual(report["summary"]["gate"], "FAIL")

    def test_gate_unverified_flag(self):
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            fp = self._write_findings(d, [_agentic(sev="CRITICAL")])
            out = os.path.join(d, "report.json")
            rc = syn.main(["--gate-unverified", "--fail-on", "critical",
                           "--out", out, fp])
            self.assertEqual(rc, 1)
```

Add this context manager near the top of the test file if it doesn't already have one:

```python
import contextlib

@contextlib.contextmanager
def _chdir(path):
    prev = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(prev)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_synthesize.py -k TwoPassCli -v`
Expected: FAIL with `unrecognized arguments: --emit-verify-queue`

- [ ] **Step 3: Implement in `main()`**

Add arguments after the existing `--tools-dir`:

```python
    ap.add_argument("--emit-verify-queue", action="store_true",
                    help="Pass 1: write .panopticon/verify-queue.json and skip the "
                         "report when agentic findings need verification")
    ap.add_argument("--verdicts-dir", metavar="DIR", default=None,
                    help="Pass 2: ingest advisor verdict files from DIR")
    ap.add_argument("--gate-unverified", action="store_true",
                    help="Let corroborated/needs_more_info/unverified findings "
                         "drive grades and the gate")
    ap.add_argument("--max-verify", type=int, default=None, metavar="N",
                    help="Cap the verify queue at the top-priority N entries "
                         "(pass the same value to both passes)")
```

After the `--severity` filter block and before `build_report`, insert:

```python
    if args.emit_verify_queue:
        import copy
        prepared, _ = prepare_findings(copy.deepcopy(findings))
        queue, cut = evidence_mod.build_verify_queue(prepared, args.max_verify)
        if queue:
            qpath = os.path.join(".panopticon", "verify-queue.json")
            evidence_mod.write_verify_queue(queue, cut, qpath)
            print("verify queue: %d entries (%d cut by --max-verify) -> %s"
                  % (len(queue), cut, qpath))
            return 0
        print("verify queue empty; emitting final report", file=sys.stderr)

    verdicts = evidence_mod.load_verdicts(args.verdicts_dir)
    report = build_report(findings, groups_meta, args.target, args.fail_on, ts,
                          review_type, security_mode, verdicts=verdicts,
                          gate_unverified=args.gate_unverified,
                          max_verify=args.max_verify)
```

(The `copy.deepcopy` matters: `prepare_findings` mutates member dicts — reinforce merge, confidence bumps — and the queue computation must not double-apply those when the run falls through or when pass 2 recomputes.)

- [ ] **Step 4: Update `tests/test_e2e.py`**

The existing e2e asserts grade "C" for a lone unverified MEDIUM agentic finding. Split the final assertion:

```python
            self.assertEqual(report["summary"]["overall_grade"], "A")
            self.assertEqual(report["summary"]["evidence_stats"]["unverified"], 1)
            # opting unverified findings into the gate restores the old behavior
            r3 = subprocess.run(
                [sys.executable, os.path.join(SCRIPTS, "synthesize.py"),
                 "--target", "src", "--groups", gj, "--gate-unverified",
                 "--out", out, fp],
                capture_output=True, text=True)
            self.assertEqual(r3.returncode, 0, r3.stderr)
            with open(out) as _fh:
                report = json.load(_fh)
            self.assertEqual(report["summary"]["overall_grade"], "C")
```

- [ ] **Step 5: Run tests, ruff, commit**

Run: `python3 -m pytest tests/ -q && python3 -m ruff check scripts/ tests/`
Expected: all PASS

```bash
git add scripts/synthesize.py tests/test_synthesize.py tests/test_e2e.py
git commit -m "feat(synthesize): two-pass CLI with verify queue and verdict ingestion"
```

---

### Task 7: Report schema 4.0.0

**Files:**
- Modify: `reference/report-schema.json`
- Modify: `tests/test_schema.py`, `tests/test_schemas.py`

**Interfaces:**
- Consumes: report shape from Task 5.
- Produces: schema that validates the new report; `tests/test_schemas.py:245` (`advisor_verdict` property assert) replaced by an `evidence` assert.

- [ ] **Step 1: Write the failing tests**

In `tests/test_schema.py`: update the inline report fixture — remove `"effort_to_remediate"` from `summary` and the `"recommendations"` key; add `"gate_policy": "confirmed_only"` and `"evidence_stats": {"tool_confirmed": 0, "advisor_confirmed": 0, "corroborated": 0, "needs_more_info": 0, "unverified": 1, "rejected": 0}` to `summary`; add to each fixture finding: `"evidence": {"status": "unverified", "verified_by": None, "reasoning": None, "citation_quality": "none"}`. Update the required-keys test (line ~83) from `("meta", "summary", "groups", "findings", "cross_panel", "recommendations")` to `("meta", "summary", "groups", "findings", "cross_panel")`. Add:

```python
    def test_schema_requires_evidence_on_findings(self):
        finding_props = self.schema["properties"]["findings"]["items"]
        self.assertIn("evidence", finding_props["properties"])
        self.assertIn("evidence", finding_props["required"])
        statuses = finding_props["properties"]["evidence"]["properties"]["status"]["enum"]
        self.assertEqual(set(statuses),
                         {"tool_confirmed", "advisor_confirmed", "corroborated",
                          "needs_more_info", "unverified", "rejected"})
```

In `tests/test_schemas.py` line ~245: replace `assert "advisor_verdict" in finding_props` with `assert "evidence" in finding_props`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_schema.py tests/test_schemas.py -v`
Expected: new asserts FAIL against the old schema.

- [ ] **Step 3: Edit `reference/report-schema.json`**

- Top-level `required`: drop `"recommendations"`; delete the `recommendations` property block if present.
- `summary.required`: `["overall_grade", "risk_level", "top_issues", "gate"]` (drop `effort_to_remediate`); delete the `effort_to_remediate`, `discarded_claims_count`, and `unverified_findings_count` property blocks; add:

```json
"gate_policy": {"type": "string", "enum": ["confirmed_only", "include_unverified"]},
"evidence_stats": {
  "type": "object",
  "properties": {
    "tool_confirmed": {"type": "integer"},
    "advisor_confirmed": {"type": "integer"},
    "corroborated": {"type": "integer"},
    "needs_more_info": {"type": "integer"},
    "unverified": {"type": "integer"},
    "rejected": {"type": "integer"}
  }
}
```

- `findings.items`: add `"evidence"` to `required`; delete the `advisor_verdict` property if present; add:

```json
"evidence": {
  "type": "object",
  "required": ["status"],
  "properties": {
    "status": {"type": "string",
               "enum": ["tool_confirmed", "advisor_confirmed", "corroborated",
                        "needs_more_info", "unverified", "rejected"]},
    "verified_by": {},
    "reasoning": {"type": ["string", "null"]},
    "citation_quality": {"type": "string",
                          "enum": ["full", "partial", "minimal", "none"]}
  }
}
```

(`verified_by` is intentionally untyped: string for tools/advisor, array of panels for corroboration, null for unverified.)

- [ ] **Step 4: Run tests, commit**

Run: `python3 -m pytest tests/test_schema.py tests/test_schemas.py tests/ -q`
Expected: all PASS

```bash
git add reference/report-schema.json tests/test_schema.py tests/test_schemas.py
git commit -m "feat(schema): report schema 4.0.0 with evidence axis"
```

---

### Task 8: `html_report.py` minimal compatibility patch

Minimal per spec: the HTML must not crash and its verified/unverified split must key on evidence. Full evidence-axis rendering is round 3.

**Files:**
- Modify: `scripts/html_report.py:606-608` (partition), `scripts/html_report.py:492` (citation quality read)
- Modify: `tests/test_html_report.py` (fixtures)

**Interfaces:**
- Consumes: report shape from Task 5.
- Produces: no new API; same `write_html(report, path, compare_report=None)`.

- [ ] **Step 1: Update fixtures to the 4.0 shape and add a failing test**

In `tests/test_html_report.py` (the module is imported as `hr`; the only public entry is `hr.write_html(report, path, compare_report=None)`): update `_minimal_report` — remove `"effort_to_remediate"` / `"recommendations"`, add `"gate_policy": "confirmed_only"` and `"evidence_stats": {"unverified": 1}` to `summary`, and give the fixture finding `"evidence": {"status": "advisor_confirmed", "verified_by": "agent:advisor", "reasoning": "verified", "citation_quality": "partial"}`. Add:

```python
import tempfile


class TestEvidencePartition(unittest.TestCase):
    def test_unverified_section_keys_on_evidence(self):
        report = _minimal_report()
        report["findings"][0]["evidence"] = {
            "status": "needs_more_info", "verified_by": "agent:advisor",
            "reasoning": "need config", "citation_quality": "none"}
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.html")
            hr.write_html(report, path)
            with open(path, encoding="utf-8") as fh:
                html = fh.read()
        self.assertIn("Unverified findings", html)
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m pytest tests/test_html_report.py -v`
Expected: FAIL (partition still reads `provenance.confirmation_status`, fixtures changed)

- [ ] **Step 3: Patch `scripts/html_report.py`**

Replace lines 606–608:

```python
    unverified_statuses = ("needs_more_info", "unverified")
    verified = [f for f in findings
                if (f.get("evidence") or {}).get("status") not in unverified_statuses]
    unverified = [f for f in findings
                  if (f.get("evidence") or {}).get("status") in unverified_statuses]
```

Replace line 492's quality read:

```python
    quality_html = _render_citation_quality(
        (finding.get("evidence") or {}).get("citation_quality"))
```

- [ ] **Step 4: Run tests, ruff, commit**

Run: `python3 -m pytest tests/test_html_report.py tests/ -q && python3 -m ruff check scripts/ tests/`

```bash
git add scripts/html_report.py tests/test_html_report.py
git commit -m "fix(html): key verified/unverified split on the evidence axis"
```

---

### Task 9: Rewrite `agents/advisor.md` for exploration

**Files:**
- Rewrite: `agents/advisor.md`

**Interfaces:**
- Consumes: queue entries — the orchestrating agent renders `{claim_json}` from a queue entry's `finding`.
- Produces: the verdict JSON contract of Task 3 (`finding_id` echo, `verdict`, `confidence`, `reasoning`, `explored`, `references`, `citations`, optional `model`). The advisor RETURNS the JSON; the orchestrating agent writes it to `.panopticon/verdicts/{queue_id}.json` (the advisor is read-only by design).

- [ ] **Step 1: Replace the file content entirely**

```markdown
---
name: advisor
description: Independent panopticon advisor that verifies a single finding by exploring the repository
model_preference: primary
tools:
  - Read
  - Grep
  - Glob
disallowedTools:
  - Bash
  - Edit
  - Write
  - Agent
---

You are an independent advisor verifying a single claim produced by another
reviewer. You have not seen this code before. Do not trust the claim; verify it.

## Claim

{claim_json}

## Your task

Verify the claim by exploring the repository yourself:

1. Read the cited file at the cited lines.
2. Grep for the symbols the claim names (functions, routes, config keys).
3. Chase the cross-file references that bear on the claim — middleware, callers,
   configuration, tests. A missing-authorization claim cannot be judged from the
   handler alone; check how the route is mounted.
4. Decide.

Return ONLY a raw JSON object:

```json
{
  "finding_id": "<the id field from the claim, echoed verbatim>",
  "verdict": "CONFIRMED|REJECTED|NEEDS_MORE_INFO",
  "confidence": "CERTAIN|LIKELY|POSSIBLE",
  "reasoning": "...",
  "explored": ["every/file/you/read/or/grepped"],
  "references": ["..."],
  "citations": {"cwe": ["CWE-89"], "owasp": ["A03:2021"], "cve": []}
}
```

- CONFIRMED: the code, as you explored it, supports the claim.
- REJECTED: the code contradicts the claim, or the claimed path cannot execute.
- NEEDS_MORE_INFO: the repository alone cannot settle it. State exactly what
  information is missing in `reasoning` — it becomes the auditor's next step.
- `explored` MUST list every file you read or grepped; it is the audit trail.
- Do not invent evidence. Only cite CVEs you can verify from the provided context
  or references. Never execute code. Never modify anything.
```

- [ ] **Step 2: Verify nothing referenced the old placeholders**

Run: `grep -rn "code_context" scripts/ agents/ SKILL.md prompts/ tests/`
Expected: no hits in `scripts/` or `agents/advisor.md` (Task 5 deleted `_render_advisor_prompt`/`_read_code_context`). If any test still references them, delete that test — its subject no longer exists.

- [ ] **Step 3: Run full suite and commit**

Run: `python3 -m pytest tests/ -q`

```bash
git add agents/advisor.md
git commit -m "feat(advisor): exploration-based verification contract with explored audit trail"
```

---

### Task 10: SKILL.md pipeline + DEVELOPMENT.md history + final sweep

**Files:**
- Modify: `SKILL.md`
- Modify: `DEVELOPMENT.md`

**Interfaces:**
- Consumes: the CLI contract from Task 6, advisor contract from Task 9.
- Produces: the orchestration spec agents actually follow.

- [ ] **Step 1: Update SKILL.md**

1. Frontmatter: `metadata.version: "4.0.0"`.
2. Global flags line: add `--gate-unverified` (unverified findings drive grades/gate) and `--max-verify N` (cap the verify queue).
3. Replace pipeline steps 7–8 with:

```markdown
7. **Synthesize (pass 1)** — `python3 scripts/synthesize.py --emit-verify-queue [flags] .panopticon/findings-*.json`.
   If it writes `.panopticon/verify-queue.json`, proceed to step 8; if it printed a report, skip to step 9.
8. **Verify** — for each entry in `verify-queue.json`, dispatch the `advisor` agent
   (parallel) with the entry's `finding` JSON rendered into the agent prompt. The
   advisor RETURNS a verdict JSON; write it verbatim to
   `.panopticon/verdicts/{queue_id}.json`. Advisors are read-only; the orchestrator
   performs the write. Then run
   `python3 scripts/synthesize.py --verdicts-dir .panopticon/verdicts [same flags] .panopticon/findings-*.json`.
9. **Validate** — `verification-before-completion`: check gate, print summary, write JSON.
```

4. Replace the "Citation and Provenance" section with:

```markdown
## Evidence

Findings carry two independent axes: **severity** (impact if true — never rewritten)
and **evidence.status** (how hard the claim was verified):

- `tool_confirmed` — emitted by a static-analysis tool.
- `advisor_confirmed` / `rejected` / `needs_more_info` — advisor verdicts from the
  verify phase. Rejected claims keep their severity and move to `discarded_claims`.
- `corroborated` — tool+agent reinforcement or multi-panel agreement (correlated
  witnesses: prioritized for verification, not gate-eligible by default).
- `unverified` — no verification attempted.

Grades and the CI gate count `tool_confirmed`/`advisor_confirmed` findings only;
`--gate-unverified` opts in everything non-rejected. Citations (CWE/OWASP/CVE/EPSS)
are audit metadata — they annotate findings but never decide truth.
```

5. Delete the old note about the kimi CLI advisor dispatch.

- [ ] **Step 2: Update DEVELOPMENT.md**

Add to Architecture: `scripts/evidence.py — evidence axis: status derivation, verify-queue triage, verdict ingestion.` Add to History:

```markdown
- **4.0.0** (current) — epistemics core: two-axis severity × evidence model.
  Severity is never mutated; evidence.status (tool_confirmed/advisor_confirmed/
  corroborated/needs_more_info/unverified/rejected) is the pipeline's verdict.
  Verification moved out of synthesize (kimi-CLI subprocess loop deleted) into an
  orchestrator-dispatched verify phase (`--emit-verify-queue` → advisor fan-out →
  `--verdicts-dir`). Citations demoted to audit metadata. Gate/grades key on
  confirmed evidence (default) with `--gate-unverified` opt-in. GROUP_RE fixed for
  3.0 filenames; effort_to_remediate/recommendations schema theater removed.
```

Update the "Current version" line to 4.0.0.

- [ ] **Step 3: Full verification**

Run: `python3 -m pytest tests/ -q && python3 -m ruff check scripts/ tests/`
Expected: all PASS, no lint errors. Also run `python3 -m pytest tests/test_skill_md.py -v` explicitly (it asserts SKILL.md references and flags).

- [ ] **Step 4: Commit**

```bash
git add SKILL.md DEVELOPMENT.md
git commit -m "docs(skill): 4.0.0 two-axis evidence model and verify-phase pipeline"
```
