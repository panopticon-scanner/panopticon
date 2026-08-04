# Calibration Round — 2026-08-03 — Findings & FIXMEs

Systematic check of the tool layer against the fixtures target and a live
self-scan, verifying standardized results end-to-end (scan → ingest →
provenance/citations/paths → dedupe → report).

## Calibration results (after fixes)

- **Fixture suite** (`skill/scripts/run_fixture_tests.py`): 96 passed, 2 skipped
  in-container; all 4 vulnerable fixtures (railsgoat, WebGoat, AspGoat,
  vulnerable-rust) present and their integration tests green.
- **Live self-scan** (`run_tools.py --target . --deps`): 7 artifacts, **103
  ingested tool findings** — bandit 47, osv-scanner 22, semgrep 21, trivy 12,
  eslint-security 1. All findings carry `tool:` sources and TOOL provenance;
  zero unnormalized container paths; ingest stderr clean.
- Full test suite 479 passed / 7 skipped, ruff clean.

## Fixed this round

1. **Fixture runner mounted a path the restructure moved** — `run_fixture_tests.py`
   mounted `{repo}/scripts`; now mounts `{repo}/skill` (in-container pytest went
   from 17 collection errors to 96 passed).
2. **osv-scanner adapter parsed real output to zero findings** — the adapter
   (and its invented test fixtures) expected a flat `results[].package` shape;
   real osv nests `results[].packages[]` with severity in `groups[].max_severity`
   (numeric CVSS) and the lockfile path in `source.path`. Rewritten against the
   real shape (CVSS→severity buckets, path normalization); test fixtures replaced
   with goldens trimmed from a live run. 22 real findings (2 CRITICAL) had been
   silently dropped.
3. **Dedupe mass-collapsed dependency advisories** — one-survivor-per-category at
   a shared locus reduced 22 osv findings at `lockfile:1` to 3. Dedupe now
   sub-buckets by `tool_evidence.rule_id`; distinct advisories survive, same-rule
   duplicates still collapse, tool+agent category reinforcement preserved.
4. **pip-audit always exited 2** — `--desc` takes an optional value, so the bare
   flag swallowed the following positional path (`--desc /src` → argparse error).
   Now `--desc=on`.
5. **Adapter code skew: containers ran image-baked code** — local adapter fixes
   silently had no effect until an image rebuild. `run_tools.py` now mounts the
   checkout's `skill/scripts` over `/opt/panopticon/scripts` (same pattern as the
   fixtures runner).
6. **Language SAST never ran on bare invocations** — `LANG_TOOL` only fired from
   an explicit `--languages` flag that neither README nor CI passes; bandit never
   ran on this Python repo. Added extension-based `detect_languages()` with
   noise-dir pruning as the default.
7. **bandit's SARIF was corrupted by its own progress bar** — stdout decoration
   preceded the JSON. Fixed at the source (`bandit -q`) and generically: ingest
   trims any non-JSON prefix to the first object/array token. (First version of
   the trim beheaded eslint-security's top-level array — caught by immediate
   re-run, fixed, both shapes now regression-tested.)
8. **Legacy bare-eslint retired from language selection** — eslint ≥9 requires a
   project flat config, so the legacy `TOOL_CMD` path can never run on arbitrary
   targets (perpetual "exited 2; skipping"); JS/TS SAST is the eslint-security
   adapter with its bundled config.

## FIXME resolution (fix round, same day — PR #25)

All seven addressed: F-CAL-1 via a shared `base.run_tool` helper (capped stderr
excerpts on failure exits, all 16 adapters + the legacy TOOL_CMD path);
F-CAL-2 via `ingest_dir(..., exclude_globs=...)` + `synthesize --tools-exclude`,
with CI switched off its inline filter; F-CAL-3 by deduping `models_used` on
(model, role); F-CAL-4 by widening ID_RE to `{2,8}` and aligning the agent
templates (goldens regenerated); F-CAL-5 by deleting the legacy eslint entries;
F-CAL-6 resolved by decision (see below); F-CAL-7 documented in DEVELOPMENT.md.
The two parked round-2 queue_id residuals (non-string TypeError, >=1000-entry
width) were fixed in the same pass.

**F-CAL-6 decision:** semgrep's rule set stays untuned. Its MEDIUMs never gate
(CI gates HIGH/CRITICAL; local gates use --fail-on), the flagged
dependabot/workflow rules are legitimate hardening advice, and the new
`--tools-exclude` handles the only systematic noise source (fixtures). Revisit
only if semgrep MEDIUM volume becomes a triage burden in real audits.

## Original FIXME list (as collected — deferred at the time)

- **F-CAL-1: adapter `invoke()` contract discards stderr** across all 16
  adapters — every tool failure surfaces as "exited N; skipping" with no reason
  (pip-audit's argparse error was invisible). Extend the contract to return
  stderr (or log a capped excerpt on non-(0,1) exits) and update `run_adapters`.
- **F-CAL-2: fixture noise pollutes self-scans** — `tests/fixtures/**`
  intentionally-vulnerable apps dominate our own repo scans (trivy/eslint HIGHs,
  osv CVEs). The `_is_fixture` filter exists only as inline Python in
  `.github/workflows/security.yml`. Promote to a standard mechanism (ingest
  exclude-globs or a documented noise-floor path rule) so local runs and CI agree.
- **F-CAL-3: `models_used` duplicate entries** — agents self-report
  `model_version` inconsistently (observed: three haiku entries with versions
  `claude-haiku-4-5-20251001` / `4.5` / `20251001`). Dedupe by (model, role) or
  normalize version at ingestion.
- **F-CAL-4: `ID_RE` rejects real agent ids** — `^[A-Z]{2,4}-\d{3,}$` vs
  observed `STRUCT-001` (6 letters) → advisory schema errors on valid-looking
  ids. Widen to `{2,8}` or tighten the template instruction (and consider
  aligning the queue_id sanitizer's documented shape).
- **F-CAL-5: legacy eslint remnants** — `TOOL_CMD["eslint"]` and its
  `LEGACY_SARIF_TOOLS` entry remain; explicit `--tools eslint` still yields
  exit 2. Remove the dead entry or make it flat-config-aware.
- **F-CAL-6: semgrep rule noise on our own profile** — e.g. CWE-829 flagged on
  `.github/dependabot.yml`. Audit which semgrep rules matter for panopticon's
  own CI gate; candidates for a repo-local noise floor.
- **F-CAL-7: tools image rebuild cadence** — `bandit -q` argv comes from the
  checkout (effective immediately) and adapter code is now mounted, but the
  image's tool BINARIES still age; document a rebuild cadence next to the
  fixtures image's (DEVELOPMENT.md has monthly for fixtures, nothing for tools).

Round-3 opening ledger from the port PR (#23) still stands alongside these:
tool-policy enforcement design, `--render-scout`, version single-sourcing,
sys.path convention, Bash removal for scout/panel-review, HTML evidence-axis
rendering, parked queue_id edge cases.
