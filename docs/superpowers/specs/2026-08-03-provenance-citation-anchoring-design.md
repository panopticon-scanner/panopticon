# Provenance and Citation Anchoring — Design

> **Goal:** Make every panopticon finding traceable to its source and its hard citations. Tool findings are auto-confirmed. Agentic findings are clearly labelled, require advisor confirmation, and must be anchored with CWE/OWASP/CVE/CVSS/EPSS citations before they can influence the gate or appear as actionable HIGH/CRITICAL items.

## Context

Panopticon already produces a `CodeReviewReport` with a `citations` object per finding and an `advisor` agent that can verify tenuous claims. What is missing is:

1. A **provenance trail** that records who discovered, expanded, and confirmed each finding — and which model/version did so.
2. A **citation-quality gate** that distinguishes tool-backed claims from agentic claims that still need anchoring.
3. An **advisor confirmation loop** that is automatically invoked for agentic findings lacking hard citations, rather than relying on manual review.

This design addresses those gaps without discarding valuable agentic findings. It keeps uncited claims visible but prevents them from driving a FAIL gate or being presented as verified security issues.

## Constraints

- **No silent dropping of findings.** Uncited or unconfirmed agentic findings remain in the report, but are visually distinct and excluded from gate logic.
- **Tool findings are first-class.** If a static-analysis tool reports an issue with a rule ID, CVE, or CWE, it is treated as confirmed at the tool's confidence level.
- **Agentic findings require confirmation.** Any finding produced by a lens-sweep or panel-review agent must be confirmed by the advisor agent before it contributes to gate/grade calculations.
- **Reproducibility.** The report records which models/versions produced and confirmed each finding.
- **Opt-in external lookups.** EPSS enrichment remains optional (`--epss`). CVSS lookup from CVE uses a cache-first strategy to avoid API throttling.
- **Stdlib-friendly.** The synthesis/enrichment code stays stdlib-only; external APIs are called only when enabled.

## Provenance Model

Every finding gains a `provenance` object:

```json
{
  "provenance": {
    "discovered_by": "tool:brakeman",
    "expanded_by": null,
    "confirmed_by": "tool:brakeman",
    "model": null,
    "model_version": null,
    "confirmation_status": "TOOL",
    "confirmation_reasoning": "Static analysis rule SCS0002 fired with CWE-89 mapping."
  }
}
```

For an agentic finding:

```json
{
  "provenance": {
    "discovered_by": "agent:lens_sweep",
    "expanded_by": "agent:panel_review",
    "confirmed_by": "agent:advisor",
    "model": "kimi-k2.7-coding",
    "model_version": "2026-08-03",
    "confirmation_status": "CONFIRMED",
    "confirmation_reasoning": "The SQL string is constructed with user input and no parameterization; CWE-89 applies."
  }
}
```

Fields:

| Field | Values | Meaning |
|---|---|---|
| `discovered_by` | `tool:<adapter>`, `agent:lens_sweep`, `agent:panel_review` | Original source of the finding. |
| `expanded_by` | same + `null` | If a second agent elaborated the finding. |
| `confirmed_by` | `tool:<adapter>`, `agent:advisor`, `null` | Who/what confirmed it. |
| `model` | model name or `null` | Model that produced/confirmed the agentic finding. |
| `model_version` | version/date or `null` | Version for reproducibility. |
| `confirmation_status` | `TOOL`, `CONFIRMED`, `REJECTED`, `NEEDS_MORE_INFO`, `UNVERIFIED` | Current confirmation state. |
| `confirmation_reasoning` | string | Human-readable justification from advisor or tool. |

## Citation Quality

`scripts/citations.py` computes a `citation_quality` enum per finding:

- `full` — CWE + OWASP + (CVE or CVSS vector).
- `partial` — CWE or OWASP, but no CVE/CVSS.
- `minimal` — only a category-derived CWE/OWASP mapping.
- `none` — no hard citations.

Enrichment steps:

1. Validate existing CWEs against `reference/cwe-catalog.json`.
2. Derive OWASP categories from validated CWEs.
3. Normalize CVE IDs and, when `--epss` is set, look up EPSS scores via FIRST.org API with local caching.
4. Optionally fetch CVSS scores/vectors for CVEs from a local cache or NVD API.
5. If no CWE is present, attempt a category-to-CWE mapping using the catalog.

Tool-sourced findings with `citation_quality` of `partial` or better are considered confirmed. Agentic findings need `partial` or better **and** advisor `CONFIRMED` status.

## Advisor Confirmation Flow

In `scripts/synthesize.py`, after deduplication and cross-panel corroboration:

1. Collect findings where `provenance.discovered_by` starts with `agent:`.
2. For each agentic finding, check `citation_quality`.
   - If `none` or `minimal`, flag as `NEEDS_MORE_INFO` unless the advisor supplies citations.
3. Dispatch `agents/advisor.md` for each flagged finding.
   - Input: finding JSON, surrounding code context (±10 lines), current citations.
   - Output: `{verdict, confidence, reasoning, references}` plus optional `citations` block (`cwe`, `owasp`, `cve`) if the advisor can supply them.
4. Apply advisor result:
   - `CONFIRMED` + citations present → `confirmation_status: CONFIRMED`, keep severity.
   - `CONFIRMED` + no citations → `confirmation_status: NEEDS_MORE_INFO`, downgrade severity to INFO.
   - `REJECTED` → `confirmation_status: REJECTED`, move to a `discarded_claims` appendix, downgrade to INFO.
   - `NEEDS_MORE_INFO` → keep as `UNVERIFIED` in main findings list, downgrade severity.

Advisor calls are batched by file to reduce context-switching and token cost.

## Report Schema Additions

- `finding.provenance` — object described above.
- `finding.citation_quality` — enum `full|partial|minimal|none`.
- `finding.provenance.model` / `model_version` — records the model that produced or confirmed the finding (e.g., the advisor model for `confirmed_by: agent:advisor`).
- `meta.models_used` — array of `{model, version, role}` for reproducibility.
- `summary.discarded_claims_count` — count of REJECTED agentic findings.
- `summary.unverified_findings_count` — count of NEEDS_MORE_INFO / UNVERIFIED findings.

## Pipeline Integration

1. **Agents** (`panel-review.md`, `lens-sweep.md`) updated to emit `provenance` and `citations` blocks.
2. **Tool adapters** updated to set `provenance.discovered_by = "tool:<name>"` and `confirmed_by = "tool:<name>"`.
3. **`scripts/ingest_tools.py`** passes provenance through from SARIF/tool output.
4. **`scripts/citations.py`** enriches and validates citations, assigns `citation_quality`.
5. **`scripts/synthesize.py`** runs advisor confirmation for agentic findings, then computes grades/gate using only confirmed findings.
6. **`scripts/html_report.py`** renders provenance and citation-quality badges; unverified findings appear in a separate collapsible section.

## Phase 2: Remediation Impact / Breaking vs Non-Breaking

This design intentionally stops at provenance and citations. The next phase will extend the advisor (or a dedicated `impact` lens) to analyze each remediation string and classify it:

- **Behavior-changing** — alters happy-path logic, public API, data formats, or defaults.
- **Breaking** — likely to break existing consumers or tests.
- **Non-breaking** — localized fix with no observable behavior change (e.g., replacing a vulnerable dependency, adding input validation that rejects previously accepted invalid input).

That phase will reuse the same provenance/citation structure: the impact classification is itself an agentic claim that must be confirmed and cited.

## Testing Strategy

- Unit tests for `citations.py`: validate CWE, derive OWASP, compute citation_quality, handle missing catalog gracefully.
- Unit tests for `synthesize.py`: agentic findings are confirmed/downgraded appropriately; tool findings pass through.
- Integration tests: run a small fixture with a known agentic finding and verify advisor confirmation is triggered.
- Report-schema validation: ensure new fields pass JSON schema checks.

## Open Questions

- Should CVSS lookup be enabled by default or behind `--cvss`? NVD API has rate limits.
- Should the advisor batch by file or by finding? Batch-by-file is more efficient but may conflate unrelated issues.
- How should we surface discarded claims to the user — hidden appendix or visible section?
