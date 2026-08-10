# 5.x Roadmap — Combined Review

**Date:** 2026-08-10
**Status:** Proposal for owner ruling — amends the 5.x sequencing in the OCRDb consumer design with the external session review (cost economics + orchestration architecture).
**Inputs:** `2026-08-10-ocrdb-charter-and-schema-design.md`, `2026-08-10-panopticon-5.0-ocrdb-consumer-design.md`, ocrdb-draft-0.1 taxonomy (320 entries, verified against RATIFICATION.md inventory), run-3 self-scan (F / FAIL / uncertified, 192 advisor-confirmed), session review of the 4.3.1 tree (1,086 tests green, ruff clean).

## What changes vs. the prior sequencing

Prior ruling: 5.0 = identity spine + filing churn fix; 5.1 = trends + panel evolution + trust chain; 5.2 = reach/host maturity.

Amendments:

1. **4.x freeze gains the `meta.cost` ledger** plus a short list of run-3 confirmed HIGH fixes. Without a 4.x baseline, "5.0 is cheaper" is unprovable forever.
2. **5.0 gains two more tracks: the driver state machine and the verify-phase redesign.** Rationale: they rewrite the same surfaces the identity spine rewrites (SKILL.md, both reviewer templates, dispatch, synthesize, goldens) — doing that churn twice across two majors is waste; and the verify-queue/verdict schema break is only allowed in a major. As specced, 5.0 *adds* per-dispatch tokens (grading menus, override adjudication) — acceptable only if the verify redesign is cutting a larger number in the same release, measured by the ledger.
3. **OCRDb 0.1 ratification gains three evidence gates** (below). 5.0 is NOT blocked on ratification: the consumer design's bundle-absent degradation is the feature flag — driver and verify tracks merge first, identity flips on at the 0.1 tag.
4. **5.1 gains incremental runs and depth-aware panel collapsing** (the remaining cost levers).

## 4.3.x freeze (small fixes only)

1. **`meta.cost` ledger (additive, non-breaking):** per-phase dispatch counts `{role, model, count}` and token usage where the host exposes it, under `meta.cost`. Then record **two reference baseline runs** (this repo + one external target) before any 5.0 work merges. This is the before-picture every 5.0 exit criterion keys on.
2. **Run-3 confirmed HIGH fixes, freeze-eligible:**
   - README quick-start documents an invocation syntax that does not exist — fix the examples.
   - Dockerfile fetches the FindSecBugs plugin from an unauthenticated URL with no checksum — pin a checksum/signature (supply-chain HIGH in a security tool).
   - **[Ruling 4]** CI raw-severity gate (#513): the tool's own reviewer flags the documented posture as contradicting the evidence model. Keep the documented strict floor, or align CI with confirmed-only gating. Either way, record the ruling so the finding stops recurring.

Nothing else lands in 4.x.

## OCRDb 0.1 — ratification gates (parallel track, ocrdb repo)

**Gate A — assignment-stability eval, run BEFORE the ratification session.** Sample ≥100 findings from run-3 across all five domains; the panel-tier model assigns codes 3× independently from the slice menus; report per-finding agreement at full-code tier and at category-prefix tier (e.g. `SEC-A1`).
Purpose: (a) an empirical merge criterion for ratification — sibling entries the assigner confuses above threshold get merged or coarsened (**taxonomy granularity is bounded by assigner reliability, not conceptual distinctness** — the confusable pairs are already flagged in RATIFICATION.md: SEC-A1A/A1B, the four TST silent-non-verification siblings, ARC-F2B/SEC-G2A); (b) the data for Ruling 2 (reconcile tier).

**Gate B — singleton rule.** A recurrence-1 entry (62 of 303 weighted) survives ratification only with a prior-art crosswalk or an explicit invention-budget note; otherwise it parks on an incubation list. Codes are immutable once released — don't spend them on one-offs from a single-repo, self-scan-biased corpus.

**Gate C — menu discipline.** The bundle build emits a menu form per entry: one line, `CODE name (SEV)`. Criteria text is excluded from reviewer menus (advisor-stage only). Whole-domain slices (e.g. `novel: [SEC]`, 65 entries) render as area/category headers + one-liners. This bounds the permanent per-dispatch tax the identity spine introduces.

The nine big rocks and per-domain questions in RATIFICATION.md stand as written.

## 5.0 — spine + identity + verify economics

Theme: **every contract break lands here, once.** Tracks are ordered; 1 and 2 do not depend on OCRDb.

### Track 1 — driver state machine

- A `panopticon run` driver owns the sequence: discovery → tool scan → plan build → guard lifecycle → fan-out bookkeeping (the `pending_entries` loop) → verify queue → both synthesize passes. The `[same flags]` contract becomes a single argparse pass; both-pass coherence is enforced by construction; worktree cwd rules (#956/#975) become code.
- The LLM orchestrator's remaining job: dispatch the prompts the driver renders, confirm out_files landed. **SKILL.md collapses to ~1 page** (invoke driver, dispatch loop, host notes).
- Per-host adapters: `dispatch.py`'s existing host dialects become the adapter seam. A new host is an adapter, not new pipeline prose — breadth gets cheaper, not narrower.
- **Integrity retirement pass:** re-evaluate every integrity check by adversary. Checks guarding against *orchestrator drift* (both-pass flag mismatch #957, the orchestrator-side portions of #493) are retired where the driver makes the failure structurally impossible — each retirement requires a one-line written rationale naming the adversary. All *agent-misbehavior* defenses stay untouched: write guard, content snapshots, mislabeled-findings (#937), injection fences.

### Track 2 — verify-phase redesign (breaking: queue + verdict schemas)

- **Batch advisors by file/cluster:** one dispatch adjudicates all queued findings sharing a file (batch cap; verdict schema becomes an array with per-item validation; a failed item re-queues alone, never the batch). Reading the file dominates advisor input tokens — run-3's 192 findings across ~40 files is plausibly a 4–6× dispatch cut.
- **Gate-aware default scope:** default queue = findings at/above `--fail-on` plus `tool_reported` HIGH+; below-threshold findings stay unverified and disclosed at `meta.coverage.verdicts.skipped_below_gate`. `--verify-all` restores 4.x behavior. (Under `confirmed_only` gating, verifying LOW/INFO cannot change the gate — today it only changes display, at one opus dispatch each.)
- **Advisor model tiering:** opus for HIGH+/gate-relevant, sonnet below (model-profiles change, non-breaking, can land early).
- **Exit criterion:** ≥3× reduction in verify-phase dispatches on the 4.3.x baseline reference runs with no gate-relevant coverage loss, per the ledger.

### Track 3 — OCRDb identity spine (consumer design as specced, four amendments)

- **[Ruling 2] Reconcile tier, informed by Gate A:** recommend `(file, category-prefix)` (e.g. `SEC-A1`) as the identity tier, with the full code carried on the finding for curation/trends/labels. Full-code identity only if Gate A shows ~90%+ full-code agreement — otherwise every confusable sibling pair is a ledger split (run 1 says A1A, run 2 says A1B → one "resolved" + one "new"), which is precisely the #914 churn this spine exists to kill.
- **[Ruling 3] Instance collision:** `(file, code)` collapses two distinct instances of the same issue type in one file. That's 4.x-parity coarseness, but 5.0 is the breaking window — decide deliberately: accept, or add a function/line-bucket tier to identity.
- **Menus per Gate C** — one-liners in reviewer prompts; criteria text reserved for advisors.
- **Not blocked on 0.1:** bundle absent → exact 4.x behavior (already in the consumer design). Tracks 1–2 merge first; Track 3 flips on at the 0.1 tag + vendored pin.

Everything else in the consumer design stands: slice dispatch, override discipline (disclosed + advisor-checked), advisor code confirmation, ledger migration, area-level GitHub labels, `meta.ocrdb_version`.

### 5.0 exit criteria

- All 4.x tests green, or consciously retired alongside the contract they covered (retirement rationale required).
- Reference-run cost ≤ baseline minus the Track-2 target, *despite* Track-3 menu overhead — the ledger proves it.
- SKILL.md ≤ ~1 page; every former prose invariant (`[same flags]`, cwd, guard/worktree lifecycle) enforced in code or structurally impossible.
- Churn regression: a run-3 finding re-worded by a different model reconciles as recurring, not new.

## 5.1

- Trend reports by code family (as specced) — now also over ledger history (cost trends).
- Panel evolution per the mapping audit (QAL panel; ARC-H/TST per ratification rulings).
- Trust chain: run-manifest, byte-identity completion, #480 revisit.
- **Incremental runs (new):** group-level content hashing; unchanged groups reuse prior confirmed findings, disclosed at `meta.coverage.reuse`. Builds directly on 5.0's reconcile identity. Biggest clock-cycle lever for repeat scans.
- **Depth-aware panel collapsing (new):** the scout's risk signal gates panel *count*, not just lens spawning; low-risk/small groups get one combined reviewer instead of 4–6. (Run 3: 89 reviewer dispatches for a 143-file repo.) Cheap after Track 1 — **[Ruling 6]** pull into 5.0 only if it doesn't threaten the ship date.

## 5.2 — reach/host maturity (unchanged)

## Rulings needed (owner)

1. Verify redesign in 5.0 (recommended here) or deferred to 5.1.
2. Reconcile identity tier — full code vs. category prefix (await Gate A data).
3. Instance-collision key — accept 4.x parity or add a finer tier.
4. CI gate posture (#513) — documented strict floor vs. evidence-model alignment.
5. Freeze scope — confirm the two HIGH fixes above; anything else from run-3 stays 5.x.
6. Panel collapsing — 5.1 (default) or pull to 5.0.

## Risks

- **5.0 is three tracks.** Mitigations: Track 3 is feature-flagged by bundle presence; tracks ordered 1→2→3; if the timeline slips, 5.0 ships Tracks 1–2 (their schema breaks alone justify the major) and Track 3 becomes 5.1, sliding trends to 5.2.
- **Gate A may invalidate full-code identity.** That is the gate working — the eval exists so the bet is placed on data, not on the taxonomy's conceptual elegance.
- **The retirement pass may delete a check that was silently guarding an agent-misbehavior case.** Hence the per-check written rationale naming the adversary; when in doubt, keep the check.
- **Cost rankings in this document are reasoned, not measured** (no ledger exists yet). The 4.3.x ledger + baselines convert them to measurements before any 5.0 optimization merges — that ordering is deliberate and load-bearing.

---

## Rulings (owner, adopted 2026-08-10 — with the triage caveats)

1. **Verify redesign in 5.0 — ADOPTED.** Schema break lands in the major; exit criterion (≥3× verify-dispatch cut, ledger-proven, no gate-relevant coverage loss) stands.
2. **Reconcile tier — await Gate A data; prior = category-prefix** (`(file, SEC-A1)` identity, full code carried for trends/labels). Full-code identity only at ~90%+ Gate A agreement.
3. **Instance collision — accept 4.x parity.** No line-bucket tier: it would break the #914 premise that issues survive code moves. Revisit only on observed 5.0 collapse pain.
4. **#513 — already ruled**: `security.yml` records "INTENTIONAL POLICY, not an oversight" with the no-advisor-phase rationale. No action.
5. **Freeze scope — trimmed by verification**: all three "run-3 confirmed HIGH" items were already resolved on main (README `--mode`/`--target` gone; FindSecBugs SHA-256-pinned, #539; #513 ruled). Freeze = `meta.cost` ledger (4.3.2) + baselines (run-4 2026-08-15 = baseline #1; external-target baseline TBD).
6. **Panel collapsing — stays 5.1.**

**OCRDb Gates A/B/C — ADOPTED** (Gate A eval to run before the ratification session; Gate B applies to the 62 verified singletons; Gate C menu form lands in the bundle build). **Added risk item:** Track 1's SKILL.md collapse invalidates most doc-guard pins — the integrity-retirement pass gains a doc-guard migration line item.

**Work order (owner):** 4.x freeze first (done at 4.3.2), then OCRDb (gap-analysis appendix, Gate A, ratification), then 5.x.
