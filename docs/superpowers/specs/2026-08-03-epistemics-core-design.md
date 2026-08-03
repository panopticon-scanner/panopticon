# Panopticon 4.0 — Epistemics Core Design

**Date:** 2026-08-03
**Status:** Approved (pending spec review)
**Scope:** Round 1 of 3 (epistemics core). Round 2: Claude Code port. Round 3: hygiene + HTML.

## Context and locked decisions

Panopticon 3.0's confirmation machinery conflates two independent axes — how bad a
finding is (severity) and how sure we are it's real (evidence). Unverified agentic
findings get their severity overwritten to INFO, destroying the original claim;
citation quality gates truth (it measures compliance, not validity); the advisor is
a serial kimi-CLI subprocess loop inside `synthesize.py` fed ±10 lines of context,
which systematically kills cross-file findings — the most valuable class.

Decisions locked during brainstorming:

1. **Platform:** Claude Code first; Kimi secondary (round 2 makes this real).
2. **Primary use case:** audit deliverable — the JSON/HTML report is the product.
   Optimizes for completeness + defensibility; nothing is silently destroyed.
3. **Epistemics:** two-axis model — severity × evidence, orthogonal, both preserved.
4. **Verification:** orchestrator-dispatched advisor agents (host fan-out), not
   Python subprocesses.
5. **Sequencing:** epistemics core first; it is mostly host-neutral Python.
6. **Approach:** targeted surgery on `synthesize.py` (Approach A) — first-class
   evidence field; no big-bang rewrite; 2.2.x tolerance hardening preserved.

## Section 1: Pipeline architecture

The pipeline gains an explicit **verify** phase between fan-out and final synthesis.
`synthesize.py` supports two invocations of the same script:

```
discovery → scout → tools → fan-out (panels + lenses)
    → synthesize --emit-verify-queue            # pass 1: merge, dedupe, triage
    → [orchestrating agent fans out advisors]   # parallel, via host agent mechanism
    → synthesize --verdicts-dir .panopticon/verdicts/   # pass 2: final report
```

**Pass 1** (`--emit-verify-queue`): load, normalize, dedupe, enrich citations,
cross-panel corroboration, then triage. Writes `.panopticon/verify-queue.json`:
one entry per finding needing verification — the claim JSON plus file/line
pointers. If the queue is empty, pass 1 emits the final report directly
(single-invocation behavior preserved for tool-only or all-confirmed runs).

**Triage** revives the currently-dead `flag_for_advisor` as the queue selector,
extended: ALL agentic findings enter the queue (tools never do). Self-asserted
`provenance.confirmation_status` from reviewer agents is ignored — a panel or lens
agent cannot confirm its own finding; only verdict files and tool sourcing count
toward evidence. Priority order (verified first when budgets bite): corroborated
CRITICAL/HIGH → uncorroborated CRITICAL/HIGH → corroborated MEDIUM → everything
else descending by severity. Corroboration channels into verification priority,
not into the gate. `--max-verify N` caps the queue to the top-priority N entries;
findings cut by the cap land `unverified` and are counted in `evidence_stats`.
Default: unlimited.

Queue entries carry a `queue_id` — `{index:03d}-{finding_id}` assigned in priority
order — because agent-generated finding ids (`SEC-001`) can collide across
groups/panels. Verdict files are named by `queue_id` and must echo the finding id
in their body; a mismatch is treated as a malformed verdict.

**The orchestrating agent** (SKILL.md pipeline step) reads the queue and
dispatches one `advisor` agent per entry in parallel via the host's agent
mechanism (Agent tool on Claude Code; AgentSwarm on Kimi). Each advisor writes
`.panopticon/verdicts/{queue_id}.json`. No Python subprocess-spawning of
agents anywhere.

**Pass 2** (`--verdicts-dir`): rerun the same deterministic merge as pass 1 from
the findings files (no hidden state travels between passes — the queue file exists
for the orchestrating agent, not for pass 2), then ingest verdict files
(tolerantly), derive evidence status for every finding, build the report, gate,
write JSON + HTML. Pass 2 recomputes triage to know which findings were queued;
a queued finding with no verdict file lands `unverified` with a stderr note.

**Deleted from `synthesize.py`:** `_dispatch_advisor`, `_get_kimi_version`,
`_render_advisor_prompt`, `_read_code_context`, `_KIMI_VERSION_CACHE`,
`_ADVISOR_TEMPLATE_PATH`, the `advisor_dispatch` parameter and the entire
severity-downgrade branch of `_partition_findings`.

## Section 2: Evidence model

Every finding in the 4.0.0 report carries:

```json
"evidence": {
  "status": "tool_confirmed | advisor_confirmed | corroborated | needs_more_info | unverified | rejected",
  "verified_by": "tool:semgrep" | "agent:advisor" | ["security", "database"],
  "reasoning": "advisor's reasoning, verbatim (or corroboration summary)",
  "citation_quality": "full | partial | minimal | none"
}
```

Status derivation is deterministic, precedence order:

1. `tool_confirmed` — `source` is `tool:*` (unchanged auto-confirm), OR the finding
   is `reinforced` (tool+agent same-locus merge: a tool reported that locus by
   construction, so agent agreement never weakens it; `verified_by: "tool+agent"`).
   Neither enters the verify queue, so tool/advisor verdict collisions are
   impossible. *(Amended during implementation review: reinforced originally
   derived `corroborated`, which let agent agreement strip a scanner finding's
   gate influence.)*
2. `advisor_confirmed` — advisor verdict CONFIRMED.
3. `rejected` — advisor verdict REJECTED. Severity untouched; finding moves to the
   `discarded_claims` appendix with reasoning attached.
4. `needs_more_info` — advisor verdict NEEDS_MORE_INFO: an advisor looked and could
   not determine. Stays in the main findings list at claimed severity. Reasoning
   must state what information is missing.
5. `corroborated` — no advisor verdict, but cross-panel corroboration fired.
   Agent+agent corroboration is `corroborated`, never any `*_confirmed` status
   (correlated witnesses are not independent evidence).
6. `unverified` — everything else: no one has looked. Stays in the main findings
   list at claimed severity, clearly labeled.

Invariants:

- **`severity` is never mutated by the pipeline** after `normalize_finding`.
- **`confidence` is never mutated by the pipeline either** — it is purely the
  reviewer's self-assessment. *(Amended during implementation review: the
  original spec kept the legacy dedupe/corroboration confidence bumps; they are
  confidence-laundering now that the evidence axis exists, and are removed.)*
- `citation_quality` moves inside `evidence` as pure metadata — computed,
  displayed, never gating, never downgrading. The CONFIRMED→NEEDS_MORE_INFO
  citation demotion is deleted.
- `provenance` object unchanged (records *who*; evidence records *how sure*).
- `meta.version` → `4.0.0` (breaking schema change per versioning policy).

## Section 3: Gate and grading semantics

- **Gate-eligible evidence (default):** `tool_confirmed`, `advisor_confirmed` only.
  A finding at/above `--fail-on` severity with gate-eligible evidence → FAIL.
- `corroborated`, `needs_more_info`, `unverified` never gate by default;
  `--gate-unverified` opts all three in (everything non-rejected).
- `rejected` never gates, ever.
- Grades (overall + per-group per-panel) are computed from gate-eligible findings
  under the same policy flag.

Summary block reports both perspectives:

```json
"summary": {
  "overall_grade": "C",
  "risk_level": "MEDIUM",
  "gate": "PASS",
  "top_issues": [...],
  "stats": {...},
  "evidence_stats": {"tool_confirmed": 4, "advisor_confirmed": 2, "corroborated": 1,
                     "needs_more_info": 3, "unverified": 5, "rejected": 2}
}
```

**Removed from the schema:** `effort_to_remediate` (was hardcoded "MEDIUM") and the
always-empty `recommendations` block. No constants masquerading as analysis.

## Section 4: Advisor contract

`agents/advisor.md` is rewritten around exploration, not snippet-judging:

- **Input:** claim JSON + the finding's file/line pointers — no pre-cut context
  window. The prompt instructs: Read the cited file, Grep for relevant symbols,
  chase cross-file references (middleware, callers, config) before deciding.
- **Tools:** Read, Grep, Glob only. No Bash (it reads hostile code; the constraint
  lands now because the file is being rewritten anyway).
- **Output:** verdict JSON written to `.panopticon/verdicts/{queue_id}.json`:
  today's shape (verdict/confidence/reasoning/references/citations) plus the
  echoed `finding_id` and `explored` — the list of files actually read, for the
  audit trail.
- NEEDS_MORE_INFO verdicts must state what information is missing; that lands in
  `evidence.reasoning` as a concrete next step for the human auditor.

The contract (prompt in, verdict file out) is fixed here; registering the advisor
as a Claude Code subagent is round-2 plumbing.

## Section 5: Error handling

Tolerant-by-design extends to the new seams — never abort, never silently lose:

- Missing verdict file for a queued finding → `unverified`, stderr note.
- Malformed verdict JSON (including a `finding_id` echo mismatch) → `unverified`,
  stderr note; pass 2 never crashes.
- Verdict for an unknown queue_id/finding id → stderr warning, ignored.
- Pass 2 without `--verdicts-dir` (or dir absent) → clean degradation: all agentic
  findings land `unverified`/`corroborated`; report still builds and gates.
- Advisor prose-wrapped JSON → existing `load_json_tolerant` handles it.

## Section 6: Testing

- `test_synthesize*.py`: partition tests become evidence-derivation tests — one per
  status plus precedence cases (including proof that tool findings are excluded
  from the verify queue, making verdict collisions impossible).
- New `test_verify_queue.py`: triage selection (all agentic in, tools out,
  self-asserted CONFIRMED ignored), priority order (corroborated CRITICAL/HIGH
  first), `--max-verify` cap behavior, queue_id assignment, queue file shape,
  empty queue → direct final report.
- New `test_verdict_ingest.py`: every tolerance case in Section 5.
- **Severity-immutability regression test:** no synthesize code path mutates
  `severity` after `normalize_finding` — the tripwire for this round's core point.
- Schema tests updated for 4.0.0.
- `GROUP_RE` fixed to match 3.0 dispatch filenames
  (`findings-{group}-{panel}-panel_review.json`,
  `findings-{group}-{panel}-lens_sweep-{lens}.json`), with tests asserting against
  names actually produced by `dispatch.py` (closing the drift class, not just the
  instance).

## Scope boundary

**In:** everything above; `GROUP_RE` fix; dead-code removal; schema-theater
removal; `agents/advisor.md` rewrite; SKILL.md pipeline-step update for the verify
phase; report schema 4.0.0; HTML report patched only enough not to crash on the
new schema.

**Out (round 2):** Claude Code subagent registration, SKILL.md fan-out mechanics
per host, `_detect_host` env-var fix (`CLAUDECODE`), model-profile plumbing.

**Out (round 3):** Bash removal from panel-review/scout, HTML evidence-axis
rendering, orchestrator/scout panel-authority documentation, CATEGORY_CWE_OVERRIDES
accuracy, `--severity` filter semantics.
