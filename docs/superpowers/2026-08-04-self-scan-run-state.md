# Self-Scan Run 2 — State (2026-08-04)

Second self-scan, run against `main` at `5ee5e78` (post PR #27). The defining
difference from the 2026-08-03 run: **the tool scan ran first and its output was
fed into synthesis from the start**, which is what run 1 silently failed to do.

## What completed

| Stage | State |
|---|---|
| Tool scan (`run_tools.py --deps`) | ✅ 7 artifacts, `.panopticon/tools/` |
| Discovery | ✅ 11 groups, 132 files |
| Scout | ✅ 10 of 11 groups profiled |
| Dispatch plans | ✅ 74 entries, **all `enforced`** |
| Fan-out | ⚠️ **1 of 10 groups** (`._5`, 11 reviewers) — see Coverage |
| Synthesize pass 1 | ✅ with `--tools-dir` + `--tools-exclude 'tests/fixtures/*'` |
| Verify (advisors) | ❌ not run — 52-entry queue emitted |
| Synthesize pass 2 | ❌ not run |

**Raw findings so far:** 53 agent (all `._5`) + 48 tool (27 bandit, 21 semgrep,
35 fixture hits excluded) = 101.

## Coverage — stated honestly

- **Agent review covers `._5` only** (`skill/scripts/*.py`, 13 files, the core
  pipeline — scout-rated `risk: high`). Groups `._1 ._2 ._3 ._4 ._6 ._7 ._8
  ._10 ._11` are profiled and planned (63 rendered prompts sit in
  `.panopticon/prompts/`) but were not dispatched.
- **`._9` (`tests/fixtures/vulnerable-rust`) was deliberately excluded** from
  scout and fan-out: it is an intentionally vulnerable fixture. `--tools-exclude`
  handles this for tools; there is no agent-side equivalent, so exclusion was
  manual. That gap is itself a finding to file.
- **Tool coverage is repo-wide** — not limited to `._5`.

## Why fan-out stopped: the orchestrator-context bottleneck, quantified

Every reviewer is read-only by design (PR #26), so every finding must transit
the orchestrator's context to reach disk. One group of 11 reviewers consumed
roughly **55k tokens of orchestrator context** (~40k returned + ~15k
re-emitted to write the 11 findings files). The remaining 63 reviewers would
cost on the order of 300k more.

The fan-out is therefore bounded by orchestrator context, not by agent
capacity or wall-clock. This is the known ledger item — now with a number
against it.

## Defects observed in this run's own orchestration

1. **The hand-rolled scout prompt omits a schema-required field.** The
   assignment block lists `(group, files, surfaces, panels, lenses, depth, risk,
   tools, has_deps)` — `languages` is required by
   `reference/scope-profile-schema.json` and is absent. Six of ten scouts
   dropped it; it was backfilled by hand. Run 1's prompts had the same defect.
   This is the concrete argument for the pending `--render-scout`: a hand-rolled
   prompt drifts from the schema and nothing catches it.
2. **Scouts do not honor "Return ONLY the ScopeProfile JSON. No prose."** 4 of
   10 (`._2 ._5 ._7 ._8`) returned analysis prose around the JSON; `._5`
   returned the profile twice (fenced, then raw).
3. **`._3` violated its own template's spawn rule** — 14 files (≥5 ⇒
   `spawn: true`) yet returned `spawn: false` for every lens. Honored as
   returned rather than silently corrected.
4. **Group naming is still `._N`** (from `basename('.')`), as in run 1.

## Artifacts

- `.panopticon/` — findings, prompts, plans, tools, verify-queue (gitignored)
- `.panopticon.prev-20260803/` — run 1 preserved
- `docs/superpowers/2026-08-03-self-scan-report.json` — run 1 report
- `docs/superpowers/2026-08-04-issue-filing-handoff.md` — issue conventions

## Resuming

Prompts for the 63 undispatched reviewers are already rendered in
`.panopticon/prompts/`, and `.panopticon/prompt-manifest.json` maps each to its
`out_file`, agent type and model. A later session can dispatch any subset
without redoing discovery, scout, or planning.
