# Integrity-retirement pass (5.0 P6.5 Slice B)

Every 4.x integrity check, re-evaluated by adversary (driver-design spec §8):
who is this check defending against? A check that defends against a
**misbehaving or miscoordinated reviewer/advisor agent** stays — the driver
changes who *sequences* the pipeline, it does not change whether reviewers are
*trusted*. A check that only ever fired because a **manual orchestrating LLM**
mis-followed a prose rule (`SKILL.md`'s deleted `## Pipeline` section) retires
as prose, because the driver makes the underlying mistake structurally
impossible to make in the first place.

Every check enumerated below is verified against `skill/scripts/synthesize.py`
(the KEEP list) or was already deleted with `## Pipeline` in P6.5 Slice B1 (the
RETIRE list). **No `synthesize.py` check is removed by this pass.**

## KEEP — agent-misbehavior defenses (all stay)

- KEEP: `unexpected_findings_files` / `missing_planned_files` (`reconcile_findings_files`, #146) — agent-misbehavior; the driver changes who sequences the pipeline, not whether reviewers are trusted.
- KEEP: `duplicate_out_files` (#936) — agent-misbehavior; the driver changes who sequences the pipeline, not whether reviewers are trusted.
- KEEP: `mislabeled_findings_files` (#937) — agent-misbehavior; the driver changes who sequences the pipeline, not whether reviewers are trusted.
- KEEP: `content_mismatched_files` / `content_hashes_checked` (#493 R4, `group_runner.verify_out_file_hashes`) — agent-misbehavior; the driver changes who sequences the pipeline, not whether reviewers are trusted.
- KEEP: `empty_dispatch_plans` — agent-misbehavior; the driver changes who sequences the pipeline, not whether reviewers are trusted.
- KEEP: `invalid_dispatch_plans` — agent-misbehavior; the driver changes who sequences the pipeline, not whether reviewers are trusted.
- KEEP: `invalid_verify_queue` — agent-misbehavior; the driver changes who sequences the pipeline, not whether reviewers are trusted.
- KEEP: `plans_seen` (`load_dispatch_plans_detailed`, C1) — agent-misbehavior; the driver changes who sequences the pipeline, not whether reviewers are trusted.
- KEEP: `write_guard_covers_bash` — agent-misbehavior; the driver changes who sequences the pipeline, not whether reviewers are trusted.
- KEEP: `unenforced_acknowledged` / `ack_stale` (#493 R2, plan-hash-bound ack) — agent-misbehavior; the driver changes who sequences the pipeline, not whether reviewers are trusted.
- KEEP: `out_of_scope` / `scope_ok` (#441, `out_of_scope_findings`) — agent-misbehavior; the driver changes who sequences the pipeline, not whether reviewers are trusted.
- KEEP: `certify()`'s INCONCLUSIVE gate (integrity/verdict/floor-cell gap forces INCONCLUSIVE over a clean PASS) — agent-misbehavior; the driver changes who sequences the pipeline, not whether reviewers are trusted.
- KEEP: self-asserted-field stripping (#983/#988, `AGENT_FORBIDDEN_FIELDS` incl. `source`, `reinforced`, `corroborated`, `corroborated_by`, `evidence`) — agent-misbehavior; the driver changes who sequences the pipeline, not whether reviewers are trusted.
- KEEP: the write-guard (`write_guard_hook.py`, #436) + tree-baseline clean-tree check (`driver.capture_tree_baseline` / `validate_execute`) — agent-misbehavior; the driver changes who sequences the pipeline, not whether reviewers are trusted. (This pair lives in the write-guard hook and the driver's `validate` phase, not `synthesize.py` — it predates the driver as the 4.x read-only-reviewer enforcement and continues unchanged as the driver's own validate phase; it was never orchestrator prose to begin with.)

Every one of the fourteen lines above defends against the same adversary: a
reviewer or advisor subagent that mis-targets its output, forges a trust
field, overwrites another reviewer's file, goes stale, strays outside its
assigned scope, or writes somewhere it shouldn't. None of that risk changes
when a driver — instead of an orchestrating LLM — sequences the calls that
hand that subagent its assignment. Nothing here was retired; nothing here
should be.

## RETIRE — orchestrator-drift hazards (now structurally impossible)

These were never `synthesize.py` code. They were hazards the deleted
`SKILL.md` `## Pipeline` prose warned a *manual orchestrating LLM* about —
"use the same flags for both synthesize passes," "glob every per-group plan
file," "resolve paths against the run root, not your own cwd." The driver
retires the prose by making the mistake it warned against impossible to
commit, and each hazard is re-anchored as a driver/dispatch test rather than
a runtime check, because there is no longer a runtime code path where the
mistake can occur.

- RETIRE: both-pass flag mismatch (#957) — driver makes it impossible via a single manifest-pinned flag set (`run_manifest.build_manifest`/`_FLAG_KEYS`) plus anti-drift refusal (`run_manifest.conflicting_flags`, `driver.run`'s "flag drift" error) on any re-invocation that disagrees with it; re-anchored as `tests/test_driver.py::TestDriverCLIAndEndToEnd::test_flag_drift_refused_no_synthesize_divergence`.
- RETIRE: plan-glob under-read — driver makes it impossible via `synthesize.load_dispatch_plans_detailed` globbing every `dispatch-plan*.json` on disk (never a single hardcoded filename), with `meta.integrity.plans_seen` disclosing the count so an under-read is visible rather than silent; re-anchored as `tests/test_synthesize.py::TestMultigroupPlanReconcile` (`test_multigroup_plans_clean_via_main` / `test_multigroup_plans_decoy_detected_via_main`, both asserting `plans_seen == 2` across two per-group plan files — pre-existing C1 coverage, tagged with a retired-hazard comment rather than duplicated per ruling B2-R1).
- RETIRE: cwd confusion — driver makes it impossible via `review_root` being resolved exactly once per run (`driver.resolve_review_root`) and every `out_file` being emitted ABSOLUTE and rooted at that resolved root (#935, `dispatch.build_plan`), so a reviewer subagent's cwd can never cause its write to land — or be looked for — in the wrong place; re-anchored as `tests/test_dispatch.py::TestDispatchPlan::test_build_plan_emits_absolute_out_file_rooted_at_root` (pre-existing #935 coverage). **Not tagged with an in-file comment in this pass** — the anchor test lives in `tests/test_dispatch.py`, which was outside this task's approved touch-set (`tests/test_driver.py` / `tests/test_synthesize.py` only); the anchor is recorded here instead. See the task-B2 report for this call.

None of the three retirements above touch `synthesize.py`: no integrity check
was deleted, weakened, or bypassed. What retired was the manual-pipeline
*prose* that used to be the only thing standing between an orchestrating LLM
and each hazard — prose already removed with `## Pipeline` in Slice B1. The
driver now occupies that ground structurally.
