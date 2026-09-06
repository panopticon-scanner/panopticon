# Changelog

## Unreleased — 5.2 grouping engine, plan 1

Setup now front-loads the grouping work so every later run reuses it
(spec: panopticon-docs `superpowers/specs/2026-09-06-panopticon-5.2-grouping-engine-design.md`).

- **Catalogs, full prose:** the capability roster grows from the R1 13 to 45
  entries harvested from the 5.2.0 vocab panel (>= 10 repos each), every entry
  carrying `definition`/`boundary`/`aliases`/`examples`; a 9-entry **layer**
  catalog (`layer_vocabulary.yml`) for splitting one oversize vertical; a
  `tests_catalog.yml` for the test-tree seeds. Both catalogs render into the
  setup-scan brief in full — the calibrated prose finally reaches the
  classifier (#1500). Proposed labels normalize through aliases; reserved names
  (`Tests`, `Commons`, `Ungrouped`, `Core`) are refused.
- **Proposal v2:** per group, optional `layers` (`{layer, match}`) and a
  `profile` (`purpose`, `surfaces`, `entry_points`, `trust_boundaries`);
  `custom:` groups and catalog entries without an affinity row get their
  review floor from the profile's surfaces (#1490 for setup-time groups).
- **Size policy (stage 3):** cap = `--max-per-group` > `config.json
  max_per_group` > 48; ceiling = `--max-groups` > `config.json max_groups` >
  `max(4, 2 * ceil(code_files / cap))`. A layer under 6 files merges back, a
  vertical over the cap splits by its layers (residual `Core`), over the
  ceiling the smallest layers collapse first, verticals are never merged.
  Committed groups always win; the outcome is written to `setup-report.md`
  / `setup-report.json`.
- **Tests axis:** a vertical's wildcard `tests` glob is scoped (under its
  `match` dirs or naming the vertical/an alias); the cross-cutting test trees
  form a `Tests` group last, at run time, from the leftovers.
- **Stage 1 spine:** `setup-spine.json` — depth-2 tree, languages, manifests
  and frameworks, already-claimed counts, test trees and the size arithmetic,
  bounded and sanitized (#1120) — is computed once with the sizes pinned in
  `setup-manifest.json` and rendered into the brief.
- Deferred: `driver run --max-per-group` still chunks at run time and does
  not read `config.json`; the durable profile (`profiles.yml`) and the scout
  short-circuit, and `--seats` calibration, are plan 2.

## 5.0.1 — Honest instrumentation

The first 5.0 point release: the residuals surfaced by the BursarBuddy
calibration and the 5.0 PR sweep, all keeping the pipeline's self-reporting and
gating honest.

- **Honest cost ledger:** `meta.cost` enumerates every 5.0 driver dispatch class
  from its own on-disk artifact — review cells, verify primary/backup, the tool
  round, and the scan — instead of only scout + a lumped advisor row (#1030).
- **Cheaper verify:** the second-witness backup re-reads only its scoped claims'
  files (not the whole cell), and the per-finding tool-advisor runs on a lighter
  model — the biggest cost lever, with zero coverage loss (#1029).
- **Honest tool certification:** coverage certifies against the runner's
  deterministic adapter manifest (`selected/produced/missing`), not the scout's
  free-form tool list, so a scout naming an absent/inapplicable tool no longer
  sinks the gate (#1031); `eslint-security` reports empty-valid on a
  nothing-to-lint target instead of a skip (#984).
- **Nightly image health:** a push-triggered keep-alive re-enables the
  `panopticon-tools` schedule, and a freshness heartbeat fails loudly on a stale
  image (#1032).
- **Driver robustness:** the clean-tree tamper guard reads `git status -z` and
  checks both rename endpoints, plus atomic manifest writes, spawn-error
  wrapping, and a tools crash-vs-skip marker (#1033).
- **OCRDb consumer & matrix hardening:** a distinct exit code for a corrupt
  bundle, a `ZZZ-X0X` sentinel for a domainless code, `code_domain_mismatch`
  disclosure, and the `{criteria}` advisor lens — the domain-advisor now grades
  against a code's explicit pass/fail criteria where defined (#1034, #1035).
- **Config dedup:** `model_resolver` is the single owner of the host
  role→model map; the duplicate `EMIT_MODEL_POLICY` is retired (#1036).
- **Severity discipline:** an explicit CRITICAL-vs-HIGH bar in the reviewer
  prompt so CRITICAL is earned, not defaulted-to (#1038).
- **OCRDb feedback groundwork:** an `x0x-report-schema.json` — Panopticon's
  catalog-gap findings as candidate records for OCRDb's new-code pool (schema
  only; emission wires up in 5.1).

## 5.0.0 — The matrix flagship

- Review is now a single resumable **driver** (`skill/scripts/driver.py`,
  subcommands `setup`/`run`/`next`) that the host drives through a status
  protocol; the legacy orchestrator is retired (P6 collapse). Phases:
  discovery → coverage → tools → review → verify → synthesize → validate.
- **Coverage:** per-group `scout` profiles widen a committed capability floor;
  the universal-tier floor `{COD,DAT,TST,ARC}` is injected but **surface-gated**
  per group — a testless / db-free / single-module group drops the floor cells
  it has nothing to review, disclosed at `global_floor_suppressed` (#5.0-19).
- **Verify:** every finding is adjudicated by an independent advisor; gate-
  eligible findings get a second (backup) witness, and deterministic tool
  (SARIF) findings are routed through a per-finding advisor so they can reach
  `tool_confirmed` and stop forcing spurious `INCONCLUSIVE` (#5.0-03).
- **Integrity:** driver-path anti-tamper controls are wired —
  `dispatch-plan-driver.json` declares every review cell (undeclared-file
  reconcile) and `out-file-hashes.json` snapshots each cell's bytes at the
  review→verify boundary (content-substitution check) (#5.0-16).
- **Enforcement:** fan-out reviewers/advisors hold a write-guarded, single-file
  `Write`; hostile-target path confinement and status-protocol crash hardening
  across the #1014–1027 series.
- **Reporting:** every report carries `meta.cost` (dispatch ledger) and
  `meta.integrity`; the CI gate keys on `summary.gate` + `summary.coverage_certified`.
- Validated end-to-end against the BursarBuddy answer-key corpus: recall 8/11,
  precision 1.0, perfect decoy discrimination, all controls firing on a real
  hostile target.

## 4.3.2 — 4.x freeze closer

- Added `meta.cost` dispatch ledger — `{phase, role, model, count}` rows derived
  from scout profiles, dispatch-plan union, and verify queue, plus a `tokens`
  slot reserved for host-reported usage.
- Fixed a ledger bug: `dispatch.build_plan` stamped `security_mode` on
  `lens_sweep` but omitted it from `panel_review`, so `plan_contract` rejected
  every plan with a panel and synthesize silently dropped all fan-out rows.

## 4.3.1 — External review point release

- Path-variant clustering: `evidence.norm_path` is the single owner of finding-path
  normalization so prefix/backslash dressing cannot split clusters.
- Delta discovery uses `--find-renames` for rename-semantics parity with
  `diff_map.hunk_map`.
- Un-loadable verdicts count as a gate-relevant coverage gap: a PASS with lost
  verdicts reads `INCONCLUSIVE`.

## 4.3.0 — 4.x series wrap

- Codex host support: `codex` model profiles, `--emit-host-agents codex`, and
  codex-runner wiring.
- Added `meta.integrity.empty_dispatch_plans` to the certification gate.

## 4.2.0 — Tool-policy enforcement

- Uniform read-only/return-JSON role contracts for every reviewer role.
- `--emit-host-agents` generates registered enforcement shells (claude/kimi
  dialects) from host-neutral templates.
- Per-role `enforced` plan entries dispatched via `subagent_type`;
  `meta.coverage.tool_policy_mode` records the runtime posture.
- Added clean-tree check in the validate step.

## 4.1.0 — Claude Code port

- Deterministic rendered prompts: dispatch-plan entries carry `prompt`, and
  `--render-advisor` renders verify-queue entries.
- Agent templates get host-neutral frontmatter (`tool_policy` as data);
  advisory-by-prompt on raw-prompt hosts.
- Explicit host selection (`--host`) with fixed env fallback (`CLAUDECODE`).

## 4.0.0 — Epistemics core

- Two-axis severity × evidence model: severity is never mutated; evidence.status
  is the pipeline verdict.
- Verification moved out of synthesize into an orchestrator-dispatched verify
  phase (`--emit-verify-queue` → advisor fan-out → `--verdicts-dir`).
- Gate/grades key on confirmed evidence by default, with `--gate-unverified` opt-in.
- Reinforced (tool+agent) findings gate as `tool_confirmed`; legacy confidence
  bumps removed.

## 3.0.0 — Multi-model reviewer dispatch

- Added role-based dispatch layer: `scout`, `lens_sweep`, `panel_review`, `advisor`.
- Added `scripts/model_resolver.py` for cross-platform model selection (Kimi / Claude / OpenRouter).
- Added `scripts/depth_planner.py` for depth-aware lens spawning.
- Added `scripts/dispatch.py` to emit `DispatchPlan` JSON for agent fan-out.
- Added `scripts/synthesize.py` advisor trigger and verdict application.
- Added Kimi Code custom agent files under `agents/`.
- Updated `SKILL.md` frontmatter and fan-out step.
- Added CI workflows for tests, lint, CodeQL, and full static-analysis scans.
- Updated `pyproject.toml` with project metadata; added `LICENSE`, `README.md`, `CODEOWNERS`, `CONTRIBUTORS.md`, `CONTRIBUTING.md`.

## Earlier releases

See [DEVELOPMENT.md](DEVELOPMENT.md) for the detailed pre-3.x version history.
