# P2 — Run Integrity and Gate Trust

**Date:** 2026-08-05
**Status:** Approved (pending spec review)
**Scope:** Remediation 1 package P2: **#443** (pass 1 and pass 2 build
different verify queues), **#446** (`tool_confirmed` is gate-eligible but never
verified), **#450** (`meta.build_executing_tools` misses the zero-findings
case), **#438** (`--max-verify` ties break on input order). NOT in scope:
ARCH-103 (`html_report._fingerprint` recomputes identity — separately filed),
fan-out architecture (P3), and the PR-first review mode (#449, which consumes
this package's fingerprint-keyed identity as its baseline primitive).

## Context

Three defects share one root: the verify queue's identity is **positional**.

`queue_id` is `NNN-FINDING-ID` where `NNN` is the index within a
priority-sorted list (`evidence.build_verify_queue`). The two passes of a run
do not build the same list: pass 1 (`--emit-verify-queue`,
`synthesize.py:955`) calls `prepare_findings(...)` alone, while pass 2
(`build_report`, `synthesize.py:617-620`) calls `aggregate_tool_findings(...)`
**first**, then `prepare_findings(...)`. Aggregation changes the list's length
and order, so every position after the first merge shifts. In run 2, 13 of 380
verdicts landed on ids pass 2 did not recognize; those findings stayed
`unverified`, and re-filing them by identity **removed a false CRITICAL** and
moved the grade D→F. Separately, within one priority the sort falls back to
input index, so a `--max-verify` cut is decided by filename order (#438) —
which starved run 1's most valuable finding.

The fourth defect is the trust asymmetry. `GATE_ELIGIBLE_DEFAULT` contains
both `tool_confirmed` and `advisor_confirmed`, but only the latter is earned:
advisors rejected **104 of 380** agentic claims in run 2 (27%). Tool findings
are excluded from the queue by construction
(`build_verify_queue`'s `not is_tool_sourced(f)`), so nothing comparable is
ever applied to them — 2 of 21 reached the queue. Filed from that very run:
**#311**, Bandit `B105` "possible hardcoded password: `'gate-pass'`", citing a
line that maps a gate verdict to a **CSS class name**. Under `--fail-on low`
a CSS class could have failed a build.

Decisions locked during brainstorming:

1. **Strict gating.** Only *verified* findings may gate. An unverified tool
   finding is reported, never gate-eligible.
2. **All tool findings queue.** No FP-prone allowlist to maintain and drift;
   the tool-axis rejection rate gets measured across the board.
3. **`reinforced` findings queue too.** Two unverified claims agreeing is
   corroboration, not verification; their corroboration is preserved in
   `verified_by` rather than granting automatic gate eligibility.
4. **Clean break on verdict identity.** Verdict files are per-run artifacts;
   old positional ids are not migrated.

## Section 1: One queue, built once (#443)

- New `synthesize.prepare_for_queue(findings) -> (prepared, integration)`:
  runs `aggregate_tool_findings` then `prepare_findings`, in that order. Both
  passes call it — pass 1 (`--emit-verify-queue`) and pass 2 (`build_report`).
  This is the fix: the queue's *input list* becomes identical by construction,
  not by coincidence.
- `build_verify_queue` keeps returning `(entries, cut)` with entries holding
  **references** to the real finding dicts (verdict application mutates them).

## Section 2: Fingerprint-keyed identity (#443, #438)

- `queue_id` becomes the finding's `finding_fingerprint(...)` — 16 hex chars,
  already filename-safe, already excluding line numbers and free text so it
  survives code moves and re-wordings.
- **Collisions** (two agent findings sharing panel+category+file+title) get a
  deterministic `-<n>` suffix assigned in stable-sort order. Collisions are
  logged to stderr with both finding ids, since a collision usually means two
  near-duplicate findings that dedupe should have merged.
- **Sort key** becomes `(triage_priority, sev_rank, fingerprint)` — no input
  index anywhere, so which findings survive a `--max-verify` cut is a property
  of the findings, not of filename order (#438).
- `match_verdict`'s `finding_id` echo check is retained unchanged as a second
  guard against a verdict answering a different claim.

## Section 3: The tool axis becomes a claim axis (#446)

- **Queue everything.** `build_verify_queue` drops both exclusions
  (`is_tool_sourced` and `reinforced`); every finding is a claim awaiting
  verification.
- **New status `tool_reported`** added to `EVIDENCE_STATUSES`: a tool asserted
  it, no advisor checked it. `derive_evidence` returns `tool_reported` for a
  tool-sourced or reinforced finding with no verdict; a CONFIRMED verdict
  promotes it to `tool_confirmed`; REJECTED yields `rejected` and the finding
  moves to `discarded_claims` exactly as an agent claim does; NEEDS_MORE_INFO
  yields `needs_more_info` (not gate-eligible), same as for an agent claim.
  Reinforced findings keep `verified_by: "tool+agent"` so the corroboration is
  not lost.
- **Precedence inverts, and this is the load-bearing change.**
  `derive_evidence` today checks `is_tool_sourced` **before** looking at any
  verdict, so a tool finding short-circuits to `tool_confirmed` and an advisor
  rejection could never reach it. The new order is: **verdict first**
  (CONFIRMED / REJECTED / NEEDS_MORE_INFO), then source-based fallback
  (`tool_reported` for tool/reinforced, `corroborated`/`unverified` for
  agentic). Without this inversion every other part of #446 is inert.
- **`GATE_ELIGIBLE_DEFAULT` is unchanged as a set** —
  `{tool_confirmed, advisor_confirmed}` — but `tool_confirmed` now *means*
  advisor-verified, so the gate tightens without touching the gate's own
  logic. `tool_reported` is deliberately absent.
- **`meta.tool_axis`** records `{queued, confirmed, rejected, unanswered,
  rejection_rate}`, the tool-side mirror of the 27% agentic number. A
  calibration tool should not have an unmeasured input.

**Accepted consequence, recorded deliberately:** a scan that never runs the
verify phase now gates on **agentic-confirmed findings only** — tool findings
report but cannot fail a build. That is the intended meaning of "only verified
gates," and it is what makes a daily PR gate trustworthy. `--gate-unverified`
already exists for operators who want everything non-rejected to gate; its
behavior is unchanged and it remains the documented escape hatch.

## Section 4: meta tells the truth about what ran (#450)

`meta.build_executing_tools` stops being inferred from findings' `source`
prefix (which reports nothing when a build-executing adapter runs and finds
nothing — the *expected* outcome on hostile or dependency-heavy C# repos).
Instead `build_report` accepts a `tools_ran` argument: the adapter names
derived from the tool output files present in `--tools-dir` (an adapter that
produced an output file ran, regardless of whether it yielded findings).
`build_executing_tools` is then `sorted(tools_ran & EXECUTES_TARGET_BUILD)`.
When `tools_ran` is not supplied (library callers, tests), the field falls
back to today's findings-derived behavior so no caller breaks.

## Section 5: Testing

- **Identity:** a regression test that builds the queue through *both* passes
  from the same raw findings (including tool findings that aggregate) and
  asserts the two `queue_id` sets are identical — the test that would have
  caught #443.
- **Determinism:** the same findings shuffled into a different input order
  produce the same queue ids and the same `--max-verify` survivors (#438).
- **Collisions:** two findings sharing a fingerprint get distinct, stable ids
  across repeated builds.
- **Tool axis:** a tool finding with no verdict derives `tool_reported` and is
  not gate-eligible; with CONFIRMED it derives `tool_confirmed` and gates;
  with REJECTED it lands in `discarded_claims`. A reinforced finding queues
  and retains `verified_by: "tool+agent"`.
- **meta:** `build_executing_tools` names roslyn-secguard when `tools_ran`
  includes it and the run produced **zero** findings.
- Existing verdict-ingest and gate tests are updated, not deleted; any test
  asserting the old positional `queue_id` format is rewritten to the
  fingerprint contract.

## Error handling

- **Unknown verdict ids** (stale verdicts from a pre-P2 run, or a re-emitted
  queue) already print `verdict file(s) for unknown queue_id(s)`; that path is
  unchanged and is now the expected signal for a stale verdicts dir.
- **Fingerprint collision** never silently merges two findings: the `-<n>`
  suffix keeps them distinct and the collision is logged.
- **Missing `tools_ran`** falls back to findings-derived
  `build_executing_tools` (Section 4), so partial callers degrade rather than
  crash.
