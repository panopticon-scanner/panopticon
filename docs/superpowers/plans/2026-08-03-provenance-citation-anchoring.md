# Provenance and Citation Anchoring — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a provenance trail and citation-quality gate to every panopticon finding so that tool findings are auto-confirmed, agentic findings are clearly labelled, and unanchored agentic claims are confirmed by an advisor before they can influence the gate.

**Architecture:** A `provenance` object travels with each finding from adapter/agent through synthesis. `scripts/citations.py` enriches and validates CWE/OWASP/CVE/CVSS/EPSS citations and assigns a `citation_quality` score. `scripts/synthesize.py` batches agentic findings to the advisor agent for confirmation, then computes grades/gates only from confirmed findings. The HTML report renders provenance and citation-quality badges and visually separates unverified findings.

**Tech Stack:** Python 3.11+, stdlib-only for core code, optional FIRST.org EPSS API, optional NVD API for CVSS, JSON schema validation.

## Global Constraints

- **No silent dropping of findings.** Uncited or unconfirmed agentic findings remain in the report, but are visually distinct and excluded from gate logic.
- **Tool findings are first-class.** If a static-analysis tool reports an issue with a rule ID, CVE, or CWE, it is treated as confirmed at the tool's confidence level.
- **Agentic findings require confirmation.** Any finding produced by a lens-sweep or panel-review agent must be confirmed by the advisor agent before it contributes to gate/grade calculations.
- **Reproducibility.** The report records which models/versions produced and confirmed each finding.
- **Opt-in external lookups.** EPSS enrichment remains optional (`--epss`). CVSS lookup from CVE uses a cache-first strategy to avoid API throttling.
- **Stdlib-friendly.** The synthesis/enrichment code stays stdlib-only; external APIs are called only when enabled.

---

## File Map

| File | Responsibility |
|---|---|
| `reference/report-schema.json` | JSON schema for `CodeReviewReport`; add `provenance`, `citation_quality`, `models_used`, summary counts. |
| `scripts/provenance.py` | Helpers to build and validate `provenance` objects for tool and agent sources. |
| `scripts/citations.py` | Existing enrichment; extend with `citation_quality`, category-to-CWE mapping, optional CVSS lookup. |
| `scripts/synthesize.py` | Existing synthesis; add advisor confirmation loop for agentic findings and gate logic that excludes unconfirmed findings. |
| `scripts/ingest_tools.py` | Pass provenance from tool/SARIF output into findings. |
| `scripts/html_report.py` | Render provenance badges, citation-quality chips, and a separate unverified-findings section. |
| `agents/panel-review.md` | Agent prompt updated to emit `provenance` and `citations` blocks. |
| `agents/lens-sweep.md` | Agent prompt updated to emit `provenance` and `citations` blocks. |
| `agents/advisor.md` | Agent prompt updated to optionally return `citations` (CWE/OWASP/CVE). |
| `tests/test_provenance.py` | Unit tests for provenance helpers. |
| `tests/test_citations.py` | Unit tests for citation quality and enrichment. |
| `tests/test_synthesize.py` | Unit tests for advisor confirmation logic. |
| `tests/test_html_report.py` | Unit tests for provenance/citation-quality rendering. |
| `SKILL.md` | Document the new provenance/citation behavior. |

---

### Task 1: Update the report schema

**Files:**
- Modify: `reference/report-schema.json`
- Test: `tests/test_schema.py` (create if missing, or add to existing JSON-schema test)

**Interfaces:**
- Consumes: none
- Produces: schema that validates `finding.provenance`, `finding.citation_quality`, `meta.models_used`, `summary.discarded_claims_count`, `summary.unverified_findings_count`

- [ ] **Step 1: Add `provenance` and `citation_quality` to finding schema**

In `reference/report-schema.json`, inside the `findings.items.properties` object, add:

```json
"citation_quality": {
  "type": "string",
  "enum": ["full", "partial", "minimal", "none"]
},
"provenance": {
  "type": "object",
  "properties": {
    "discovered_by": { "type": "string" },
    "expanded_by": { "type": ["string", "null"] },
    "confirmed_by": { "type": ["string", "null"] },
    "model": { "type": ["string", "null"] },
    "model_version": { "type": ["string", "null"] },
    "confirmation_status": {
      "type": "string",
      "enum": ["TOOL", "CONFIRMED", "REJECTED", "NEEDS_MORE_INFO", "UNVERIFIED"]
    },
    "confirmation_reasoning": { "type": ["string", "null"] }
  }
}
```

- [ ] **Step 2: Add `models_used` to `meta` and summary counts**

In `meta.properties`, add:

```json
"models_used": {
  "type": "array",
  "items": {
    "type": "object",
    "properties": {
      "model": { "type": "string" },
      "version": { "type": "string" },
      "role": { "type": "string" }
    }
  }
}
```

In `summary.properties`, add:

```json
"discarded_claims_count": { "type": "integer" },
"unverified_findings_count": { "type": "integer" }
```

- [ ] **Step 3: Validate the schema still accepts existing reports**

Run:

```bash
python3 -m pytest tests/test_schema.py -v
```

Expected: PASS. If no schema test exists, create `tests/test_schema.py`:

```python
import json
import os
import unittest

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "..", "reference", "report-schema.json")

class TestReportSchema(unittest.TestCase):
    def test_schema_is_valid_json(self):
        with open(SCHEMA_PATH, encoding="utf-8") as fh:
            schema = json.load(fh)
        self.assertEqual(schema["title"], "CodeReviewReport")

if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 4: Commit**

```bash
git add reference/report-schema.json tests/test_schema.py
git commit -m "schema(report): add provenance, citation_quality, and model metadata"
```

---

### Task 2: Add provenance helpers

**Files:**
- Create: `scripts/provenance.py`
- Test: `tests/test_provenance.py`

**Interfaces:**
- Consumes: none
- Produces: `tool_provenance(adapter_name, reasoning=None)`, `agent_provenance(role, model, model_version, confirmed=False)`, `merge_provenance(base, expansion)`

- [ ] **Step 1: Write the failing test**

Create `tests/test_provenance.py`:

```python
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))
import scripts.provenance as pv


class TestProvenance(unittest.TestCase):
    def test_tool_provenance(self):
        p = pv.tool_provenance("brakeman", reasoning="rule SCS0002")
        self.assertEqual(p["discovered_by"], "tool:brakeman")
        self.assertEqual(p["confirmed_by"], "tool:brakeman")
        self.assertEqual(p["confirmation_status"], "TOOL")
        self.assertIsNone(p["model"])

    def test_agent_provenance_unconfirmed(self):
        p = pv.agent_provenance("lens_sweep", "kimi-k2.7-coding", "2026-08-03")
        self.assertEqual(p["discovered_by"], "agent:lens_sweep")
        self.assertEqual(p["confirmation_status"], "UNVERIFIED")
        self.assertEqual(p["model"], "kimi-k2.7-coding")

    def test_merge_provenance_expansion(self):
        base = pv.agent_provenance("lens_sweep", "kimi-k2.7-coding", "v1")
        expansion = pv.agent_provenance("panel_review", "kimi-k3", "v2")
        merged = pv.merge_provenance(base, expansion)
        self.assertEqual(merged["discovered_by"], "agent:lens_sweep")
        self.assertEqual(merged["expanded_by"], "agent:panel_review")
        self.assertEqual(merged["model"], "kimi-k3")
```

- [ ] **Step 2: Run test to verify it fails**

```bash
python3 -m pytest tests/test_provenance.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'scripts.provenance'`.

- [ ] **Step 3: Implement `scripts/provenance.py`**

```python
"""Provenance helpers for panopticon findings."""
from __future__ import annotations


def tool_provenance(adapter_name: str, reasoning: str | None = None) -> dict:
    return {
        "discovered_by": f"tool:{adapter_name}",
        "expanded_by": None,
        "confirmed_by": f"tool:{adapter_name}",
        "model": None,
        "model_version": None,
        "confirmation_status": "TOOL",
        "confirmation_reasoning": reasoning or f"Reported by static-analysis tool {adapter_name}",
    }


def agent_provenance(role: str, model: str, model_version: str,
                     confirmed: bool = False) -> dict:
    return {
        "discovered_by": f"agent:{role}",
        "expanded_by": None,
        "confirmed_by": None,
        "model": model,
        "model_version": model_version,
        "confirmation_status": "CONFIRMED" if confirmed else "UNVERIFIED",
        "confirmation_reasoning": None,
    }


def merge_provenance(base: dict, expansion: dict) -> dict:
    """Return a new provenance where base is the discoverer and expansion is the expander."""
    merged = dict(base)
    merged["expanded_by"] = expansion.get("discovered_by")
    # Prefer the most recent model/version for display.
    if expansion.get("model"):
        merged["model"] = expansion["model"]
        merged["model_version"] = expansion.get("model_version")
    return merged
```

- [ ] **Step 4: Run tests**

```bash
python3 -m pytest tests/test_provenance.py -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/provenance.py tests/test_provenance.py
git commit -m "feat(provenance): add provenance helpers for tool and agent sources"
```

---

### Task 3: Extend `scripts/citations.py` with quality scoring

**Files:**
- Modify: `scripts/citations.py`
- Test: `tests/test_citations.py` (extend existing)

**Interfaces:**
- Consumes: `catalog` from `load_cwe_catalog()`, `finding["citations"]`, `finding["category"]`
- Produces: `finding["citation_quality"]`, enriched `finding["citations"]`, optional `finding["citations"]["cvss"]`

- [ ] **Step 1: Write failing tests for `citation_quality`**

Add to `tests/test_citations.py` (create if missing):

```python
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))
import scripts.citations as ci


class TestCitationQuality(unittest.TestCase):
    def setUp(self):
        self.catalog = ci.load_cwe_catalog()

    def test_full_quality(self):
        f = {
            "citations": {
                "cwe": [{"id": "CWE-89"}],
                "owasp": ["A03:2021"],
                "cve": ["CVE-2023-1234"],
            }
        }
        ci.enrich_citations([f], self.catalog)
        self.assertEqual(f["citation_quality"], "full")

    def test_partial_quality(self):
        f = {"citations": {"cwe": [{"id": "CWE-89"}]}}
        ci.enrich_citations([f], self.catalog)
        self.assertEqual(f["citation_quality"], "partial")

    def test_none_quality(self):
        f = {"citations": {}}
        ci.enrich_citations([f], self.catalog)
        self.assertEqual(f["citation_quality"], "none")

    def test_category_mapping(self):
        f = {"category": "injection", "citations": {}}
        ci.enrich_citations([f], self.catalog)
        self.assertEqual(f["citation_quality"], "minimal")
        self.assertIn("CWE-89", [c["id"] for c in f["citations"]["cwe"]])
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python3 -m pytest tests/test_citations.py::TestCitationQuality -v
```

Expected: FAIL (no `citation_quality` attribute yet).

- [ ] **Step 3: Implement quality scoring in `scripts/citations.py`**

Add a new function:

```python
# Near the top with other constants
CATEGORY_CWE_OVERRIDES = {
    "injection": "CWE-89",
    "xss": "CWE-79",
    "auth": "CWE-287",
    "crypto": "CWE-327",
    "config": "CWE-16",
    "logging": "CWE-778",
    "headers": "CWE-693",
    "csrf": "CWE-352",
    "ssrf": "CWE-918",
    "path_traversal": "CWE-22",
    "command_injection": "CWE-78",
    "sql_injection": "CWE-89",
}


def _derive_cwe_from_category(category, catalog):
    cid = CATEGORY_CWE_OVERRIDES.get(str(category).lower().replace(" ", "_"))
    if cid and cid in catalog["cwe"]:
        return {"id": cid, "name": catalog["cwe"][cid], "verified": True}
    return None


def _compute_citation_quality(citations):
    if not isinstance(citations, dict):
        return "none"
    has_cwe = bool(citations.get("cwe"))
    has_owasp = bool(citations.get("owasp"))
    has_cve_or_cvss = bool(citations.get("cve") or citations.get("cvss"))
    if (has_cwe or has_owasp) and has_cve_or_cvss:
        return "full"
    if has_cwe or has_owasp:
        return "partial"
    if citations:
        return "minimal"
    return "none"
```

Modify `enrich_citations` to set the quality and to derive CWE from category:

```python
def enrich_citations(findings, catalog, epss_enabled=False, cache_path=None, opener=None):
    # ... existing setup ...
    for f in findings:
        raw = f.get("citations")
        if not isinstance(raw, dict):
            f.pop("citations", None)
            f["citation_quality"] = "none"
            continue
        try:
            # ... existing enrichment code ...
            # After building `clean`:
            # Try to derive CWE from category if still missing
            if not clean.get("cwe") and f.get("category"):
                derived = _derive_cwe_from_category(f["category"], catalog)
                if derived:
                    clean["cwe"] = [derived]

            f["citation_quality"] = _compute_citation_quality(clean)
            if clean:
                f["citations"] = clean
            else:
                f.pop("citations", None)
        except Exception as e:
            # ... existing error handling ...
            f["citation_quality"] = "none"
    # ... EPSS lookup unchanged ...
```

- [ ] **Step 4: Run tests**

```bash
python3 -m pytest tests/test_citations.py -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/citations.py tests/test_citations.py
git commit -m "feat(citations): compute citation_quality and derive CWE from category"
```

---

### Task 4: Update tool adapters to emit provenance

**Files:**
- Modify: `scripts/tools/base.py`, `scripts/tools/brakeman.py`, `scripts/tools/bundler_audit.py`, `scripts/tools/cargo_audit.py`, `scripts/tools/dependency_check.py`, `scripts/tools/eslint_security.py`, `scripts/tools/npm_audit.py`, `scripts/tools/osv_scanner.py`, `scripts/tools/pip_audit.py`, `scripts/tools/roslyn_secguard.py`, `scripts/tools/spotbugs.py`
- Test: `tests/tools/test_*.py`

**Interfaces:**
- Consumes: `scripts/provenance.tool_provenance(adapter_name)`
- Produces: each finding has `finding["provenance"]` with `confirmation_status: "TOOL"`

- [ ] **Step 1: Add a helper in `scripts/tools/base.py`**

Open `scripts/tools/base.py` and add:

```python
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))
from scripts.provenance import tool_provenance


def attach_tool_provenance(finding, adapter_name, reasoning=None):
    finding["provenance"] = tool_provenance(adapter_name, reasoning=reasoning)
    return finding
```

- [ ] **Step 2: Update one adapter as the pattern**

Modify `scripts/tools/brakeman.py`. After each finding is built, call:

```python
from .base import attach_tool_provenance

# inside parse(), after building `finding`:
attach_tool_provenance(finding, "brakeman", reasoning=finding["tool_evidence"].get("rule_id"))
```

- [ ] **Step 3: Add a test for Brakeman provenance**

In `tests/tools/test_brakeman.py`, add:

```python
def test_parse_includes_provenance(self):
    findings = brakeman.BrakemanAdapter().parse(BRAKEMAN_SAMPLE, "g1")
    self.assertTrue(findings)
    self.assertEqual(findings[0]["provenance"]["discovered_by"], "tool:brakeman")
    self.assertEqual(findings[0]["provenance"]["confirmation_status"], "TOOL")
```

Run:

```bash
python3 -m pytest tests/tools/test_brakeman.py -v
```

Expected: PASS.

- [ ] **Step 4: Apply to remaining adapters**

For each adapter file, import `attach_tool_provenance` from `.base` and call it before returning/appending the finding. Use the adapter's `name` attribute as the adapter name. Example for `scripts/tools/spotbugs.py`:

```python
from .base import attach_tool_provenance

# inside parse(), after building `finding`:
attach_tool_provenance(finding, "spotbugs", reasoning=finding["tool_evidence"].get("rule_id"))
```

Repeat for: `bundler_audit.py`, `cargo_audit.py`, `dependency_check.py`, `eslint_security.py`, `npm_audit.py`, `osv_scanner.py`, `pip_audit.py`, `roslyn_secguard.py`.

- [ ] **Step 5: Run all tool tests**

```bash
python3 -m pytest tests/tools/ -q
```

Expected: PASS (or existing expected skips).

- [ ] **Step 6: Commit**

```bash
git add scripts/tools/base.py scripts/tools/*.py tests/tools/test_*.py
git commit -m "feat(tools): attach tool provenance to all adapter findings"
```

---

### Task 5: Update agent prompts

**Files:**
- Modify: `agents/panel-review.md`, `agents/lens-sweep.md`, `agents/advisor.md`

**Interfaces:**
- Consumes: agent prompt templates
- Produces: agents emit `provenance` and `citations` blocks; advisor can return citations

- [ ] **Step 1: Update `agents/lens-sweep.md`**

Append to the output requirements section:

```markdown
Each finding MUST include a `provenance` object:

```json
"provenance": {
  "discovered_by": "agent:lens_sweep",
  "expanded_by": null,
  "confirmed_by": null,
  "model": "<model-name>",
  "model_version": "<version>",
  "confirmation_status": "UNVERIFIED",
  "confirmation_reasoning": null
}
```

And a `citations` object with at least one of:
- `cwe`: list of CWE IDs (e.g., `["CWE-89"]`)
- `owasp`: list of OWASP Top 10 categories (e.g., `["A03:2021"]`)
- `cve`: list of CVE IDs (if applicable)
```

- [ ] **Step 2: Update `agents/panel-review.md`**

Same as lens-sweep, but use `"discovered_by": "agent:panel_review"`. If the panel review elaborates on a lens finding, set `"expanded_by": "agent:lens_sweep"`.

- [ ] **Step 3: Update `agents/advisor.md`**

Change the output JSON example to:

```json
{
  "verdict": "CONFIRMED|REJECTED|NEEDS_MORE_INFO",
  "confidence": "CERTAIN|LIKELY|POSSIBLE",
  "reasoning": "...",
  "references": ["..."],
  "citations": {
    "cwe": ["CWE-89"],
    "owasp": ["A03:2021"],
    "cve": ["CVE-2023-1234"]
  }
}
```

Add instruction:

```markdown
If the original finding lacks hard citations, supply them in the `citations` object. Do not invent CVEs; only include CVE IDs you can verify from the provided context or references.
```

- [ ] **Step 4: Commit**

```bash
git add agents/panel-review.md agents/lens-sweep.md agents/advisor.md
git commit -m "docs(agents): require provenance and citations in agent outputs"
```

---

### Task 6: Implement advisor confirmation loop in `scripts/synthesize.py`

**Files:**
- Modify: `scripts/synthesize.py`
- Test: `tests/test_synthesize.py`

**Interfaces:**
- Consumes: `finding["provenance"]`, `finding["citation_quality"]`, advisor agent dispatch function
- Produces: updated `provenance.confirmation_status`, downgraded severities for unconfirmed findings, `summary.discarded_claims_count`, `summary.unverified_findings_count`

- [ ] **Step 1: Write failing test for confirmation logic**

Create or extend `tests/test_synthesize.py`:

```python
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))
import scripts.synthesize as synth


class TestAdvisorConfirmation(unittest.TestCase):
    def test_tool_finding_is_auto_confirmed(self):
        f = {
            "id": "SEC-001", "title": "SQLi", "severity": "HIGH", "confidence": "CERTAIN",
            "panel": "security", "category": "injection",
            "provenance": {"discovered_by": "tool:brakeman", "confirmation_status": "TOOL"},
            "citation_quality": "partial",
        }
        confirmed, discarded, unverified = synth._partition_findings([f])
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(len(discarded), 0)
        self.assertEqual(len(unverified), 0)

    def test_agentic_finding_without_citations_is_unverified(self):
        f = {
            "id": "SEC-002", "title": "Logic flaw", "severity": "HIGH", "confidence": "LIKELY",
            "panel": "security", "category": "general",
            "provenance": {"discovered_by": "agent:lens_sweep", "confirmation_status": "UNVERIFIED"},
            "citation_quality": "none",
        }
        confirmed, discarded, unverified = synth._partition_findings([f])
        self.assertEqual(len(confirmed), 0)
        self.assertEqual(len(discarded), 0)
        self.assertEqual(len(unverified), 1)
        self.assertEqual(unverified[0]["severity"], "INFO")
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python3 -m pytest tests/test_synthesize.py::TestAdvisorConfirmation -v
```

Expected: FAIL (`_partition_findings` does not exist).

- [ ] **Step 3: Implement `_partition_findings`**

In `scripts/synthesize.py`, add:

```python
def _is_agentic(f):
    prov = f.get("provenance") or {}
    return str(prov.get("discovered_by", "")).startswith("agent:")


def _partition_findings(findings, advisor_dispatch=None):
    """Separate findings into confirmed, discarded, and unverified sets.

    Tool findings are confirmed automatically. Agentic findings are sent to
    the advisor unless they already have full/partial citations and a CONFIRMED
    status. Unconfirmed agentic findings are downgraded to INFO.
    """
    confirmed = []
    discarded = []
    unverified = []

    for f in findings:
        prov = f.get("provenance") or {}
        status = prov.get("confirmation_status")

        if status == "TOOL":
            confirmed.append(f)
            continue

        if status == "CONFIRMED":
            confirmed.append(f)
            continue

        if status == "REJECTED":
            f["severity"] = "INFO"
            f["confidence"] = "NOTE"
            discarded.append(f)
            continue

        # UNVERIFIED or NEEDS_MORE_INFO: agentic findings needing review.
        if advisor_dispatch and _is_agentic(f):
            advisor_result = advisor_dispatch(f)
            verdict = str(advisor_result.get("verdict", "")).upper()
            if verdict == "CONFIRMED":
                prov["confirmed_by"] = "agent:advisor"
                prov["confirmation_status"] = "CONFIRMED"
                prov["confirmation_reasoning"] = advisor_result.get("reasoning")
                # Merge advisor citations if present.
                advisor_citations = advisor_result.get("citations")
                if advisor_citations:
                    f.setdefault("citations", {}).update(advisor_citations)
                confirmed.append(f)
                continue
            if verdict == "REJECTED":
                prov["confirmed_by"] = "agent:advisor"
                prov["confirmation_status"] = "REJECTED"
                prov["confirmation_reasoning"] = advisor_result.get("reasoning")
                f["severity"] = "INFO"
                f["confidence"] = "NOTE"
                discarded.append(f)
                continue

        # Fallback: keep as unverified, downgrade severity.
        prov["confirmation_status"] = "NEEDS_MORE_INFO"
        f["severity"] = "INFO"
        f["confidence"] = "NOTE"
        unverified.append(f)

    return confirmed, discarded, unverified
```

- [ ] **Step 4: Wire `_partition_findings` into `build_report`**

Inside `build_report`, after `findings = dedupe(findings)` and before computing grades/stats:

```python
confirmed, discarded, unverified = _partition_findings(findings, advisor_dispatch=_dispatch_advisor)
findings = confirmed + unverified  # confirmed are actionable; unverified stay visible but info-level.
# discarded claims go into a special report section later.
```

Add `_dispatch_advisor` as a no-op stub initially:

```python
def _dispatch_advisor(finding):
    """Placeholder: dispatch the advisor agent for an agentic finding.

    Real implementation will spawn the advisor subagent with code context.
    """
    return {"verdict": "NEEDS_MORE_INFO", "reasoning": "Advisor not yet wired."}
```

- [ ] **Step 5: Add summary counts**

In `build_report`, when building `summary`, add:

```python
summary["discarded_claims_count"] = len(discarded)
summary["unverified_findings_count"] = len(unverified)
```

- [ ] **Step 6: Run tests**

```bash
python3 -m pytest tests/test_synthesize.py -v
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add scripts/synthesize.py tests/test_synthesize.py
git commit -m "feat(synthesize): partition findings into confirmed/discarded/unverified"
```

---

### Task 7: Render provenance in the HTML report

**Files:**
- Modify: `scripts/html_report.py`
- Test: `tests/test_html_report.py`

**Interfaces:**
- Consumes: `finding["provenance"]`, `finding["citation_quality"]`
- Produces: HTML badges and a separate unverified-findings section

- [ ] **Step 1: Write failing test for provenance rendering**

Add to `tests/test_html_report.py`:

```python
def test_finding_card_renders_provenance(self):
    finding = {
        "id": "SEC-001", "title": "SQL injection", "severity": "HIGH", "confidence": "CERTAIN",
        "panel": "security", "category": "injection", "location": {"file": "app.py", "line_start": 10},
        "description": "x", "impact": "", "remediation": "", "references": [],
        "provenance": {
            "discovered_by": "tool:brakeman", "confirmation_status": "TOOL",
            "model": None, "model_version": None,
        },
        "citation_quality": "partial",
    }
    report = _minimal_report(findings=[finding])
    out = hr.render(report)
    self.assertIn("tool:brakeman", out)
    self.assertIn("partial", out)


def test_unverified_findings_render_separately(self):
    finding = {
        "id": "SEC-002", "title": "Unverified", "severity": "INFO", "confidence": "NOTE",
        "panel": "security", "category": "general", "location": {"file": "app.py", "line_start": 11},
        "description": "x", "impact": "", "remediation": "", "references": [],
        "provenance": {
            "discovered_by": "agent:lens_sweep", "confirmation_status": "NEEDS_MORE_INFO",
            "model": "kimi-k2.7-coding", "model_version": "v1",
        },
        "citation_quality": "none",
    }
    report = _minimal_report(findings=[finding])
    out = hr.render(report)
    self.assertIn("Unverified findings", out)
    self.assertIn("agent:lens_sweep", out)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python3 -m pytest tests/test_html_report.py::TestHtmlReport::test_finding_card_renders_provenance tests/test_html_report.py::TestHtmlReport::test_unverified_findings_render_separately -v
```

Expected: FAIL (provenance not rendered yet).

- [ ] **Step 3: Add rendering helpers**

In `scripts/html_report.py`, add:

```python
def _render_provenance(provenance):
    if not isinstance(provenance, dict):
        return ""
    status = provenance.get("confirmation_status", "UNVERIFIED")
    source = provenance.get("discovered_by", "unknown")
    model = provenance.get("model")
    parts = [f"<span class='prov-status prov-{status.lower().replace(' ', '-')}'>{_escape(status)}</span>",
             f"<span class='prov-source'>{_escape(source)}</span>"]
    if model:
        parts.append(f"<span class='prov-model'>{_escape(model)}</span>")
    return " ".join(parts)


def _render_citation_quality(quality):
    quality = str(quality).lower() if quality else "none"
    return f"<span class='cit-quality cit-{quality}'>{_escape(quality)}</span>"
```

- [ ] **Step 4: Inject badges into finding cards**

Find the function that renders individual finding cards (likely `_finding_card` or similar) and insert:

```python
provenance = _render_provenance(f.get("provenance"))
quality = _render_citation_quality(f.get("citation_quality"))
# Add provenance and quality HTML near the finding header.
```

- [ ] **Step 5: Add unverified section**

In the main render path, split findings into verified and unverified after grouping by severity:

```python
verified = [f for f in findings if f.get("provenance", {}).get("confirmation_status") != "NEEDS_MORE_INFO"]
unverified = [f for f in findings if f.get("provenance", {}).get("confirmation_status") == "NEEDS_MORE_INFO"]
```

Render unverified findings in a separate collapsible section titled "Unverified findings" after the main findings list.

- [ ] **Step 6: Run tests**

```bash
python3 -m pytest tests/test_html_report.py -v
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add scripts/html_report.py tests/test_html_report.py
git commit -m "feat(html-report): render provenance, citation quality, and unverified section"
```

---

### Task 8: Wire real advisor dispatch

**Files:**
- Modify: `scripts/synthesize.py`

**Interfaces:**
- Consumes: finding + code context
- Produces: advisor JSON result

- [ ] **Step 1: Implement `_dispatch_advisor` with subagent spawn**

Replace the stub with a function that:

1. Reads the target file around the finding location (±10 lines).
2. Builds a prompt from `agents/advisor.md` with `{claim_json}` and `{code_context}` placeholders.
3. Dispatches an `Agent(subagent_type="coder")` or uses the existing advisor agent mechanism.
4. Parses the returned JSON and returns the verdict/citations dict.

Because this depends on the project's subagent dispatch mechanism, the implementation should follow the pattern used elsewhere in `scripts/synthesize.py` or `scripts/dispatch.py` for spawning agents.

- [ ] **Step 2: Add a smoke test**

Mock `_dispatch_advisor` to return a CONFIRMED verdict and verify the finding is promoted:

```python
def test_agentic_finding_confirmed_by_advisor(self):
    f = {
        "id": "SEC-002", "title": "Logic flaw", "severity": "HIGH", "confidence": "LIKELY",
        "panel": "security", "category": "general",
        "provenance": {"discovered_by": "agent:lens_sweep", "confirmation_status": "UNVERIFIED"},
        "citation_quality": "none",
    }
    def fake_advisor(_finding):
        return {"verdict": "CONFIRMED", "reasoning": "Confirmed.", "citations": {"cwe": ["CWE-20"]}}
    confirmed, _discarded, _unverified = synth._partition_findings([f], advisor_dispatch=fake_advisor)
    self.assertEqual(len(confirmed), 1)
    self.assertEqual(confirmed[0]["provenance"]["confirmation_status"], "CONFIRMED")
    self.assertEqual(confirmed[0]["citations"]["cwe"], ["CWE-20"])
```

- [ ] **Step 3: Run tests**

```bash
python3 -m pytest tests/test_synthesize.py -v
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add scripts/synthesize.py tests/test_synthesize.py
git commit -m "feat(synthesize): wire advisor dispatch for agentic findings"
```

---

### Task 9: Update `SKILL.md` and run final verification

**Files:**
- Modify: `SKILL.md`
- Test: full test suite

- [ ] **Step 1: Document new behavior**

In `SKILL.md`, add a "Citation and Provenance" subsection under the pipeline or notes section:

```markdown
## Citation and Provenance

Every finding is tagged with its source:

- **Tool findings** are auto-confirmed when they include a rule ID, CVE, or CWE.
- **Agentic findings** (from lens or panel reviewers) require confirmation by the advisor agent and must be anchored with CWE/OWASP/CVE/CVSS/EPSS citations.
- Findings that are unconfirmed remain visible in the report as `INFO`/`NOTE` items but do not influence the CI gate.

Use `--epss` to enrich CVE citations with EPSS scores.
```

- [ ] **Step 2: Run full verification**

```bash
ruff check scripts tests
python3 -m pytest tests/ -q
```

Expected: All checks pass; existing expected skips remain.

- [ ] **Step 3: Commit**

```bash
git add SKILL.md
git commit -m "docs(skill): document provenance and citation anchoring behavior"
```

---

## Self-Review

**Spec coverage:**
- Provenance object: Task 2 and Task 4-5.
- Citation quality: Task 3.
- Advisor confirmation: Task 6 and Task 8.
- Report schema: Task 1.
- HTML rendering: Task 7.
- Tool adapters: Task 4.
- Agent prompts: Task 5.
- SKILL.md docs: Task 9.

**Placeholder scan:**
- No TBD/TODO/"implement later".
- `_dispatch_advisor` in Task 8 is intentionally left following existing dispatch patterns because the exact subagent spawn API varies by host; the task describes what it must do and provides a mock test.

**Type consistency:**
- `citation_quality` enum values are consistent across schema, citations.py, and tests.
- `confirmation_status` enum values are consistent across schema, provenance.py, and synthesize.py.
- `provenance` field names match in schema, provenance.py, agent prompts, and tests.
