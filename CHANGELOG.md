# Changelog

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

See [DEVELOPMENT.md](DEVELOPMENT.md) for the detailed version history through 2.2.1.
