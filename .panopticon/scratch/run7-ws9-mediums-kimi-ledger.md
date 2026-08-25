# Kimi run-7 MEDIUM remediation ledger

## K1 repo-ops scripts (PR #1385)

### Addressed
- SEC-B2C scripts/file_fixmes.py:137/138 — scrubbed FIXME title/body
- SEC-B1A scripts/triage.py:102 — sanitized triage comment rationale/spot_check
- COD-F1A scripts/file_issues.py:253 — record() creates parent dir
- OPS-E1A scripts/file_issues.py:240 — load_ledger() warns on corruption
- COD-C2C scripts/reconcile_apply.py:53 — LOC_RE handles paths with colons
- ARC-F2D scripts/triage.py:82 — real ISO-8601 timestamp validation

### Dropped / overstated / FP
- TST-A1B scripts/file_issues.py:47 labels_for() coverage — already covered indirectly
- TST-A2D scripts/file_issues.py:64 title_for() truncation — low value
- TST-A3C scripts/file_issues.py:90 body_for() multi-locus branch — low value
- TST-A2B scripts/file_issues.py:351 create() retry branches — low value
- TST-A2D scripts/file_issues.py:271 resolve_part_path() guard — low value
- TST-A2B scripts/file_issues.py:384 main() continuation loading — low value
- TST-A3A scripts/triage.py:229 fully-mocked boundaries — hard to address cheaply
- [None] scripts/file_issues.py:310 subprocess finding — static argv, FP
- [None] scripts/file_issues.py:390 hook path finding — validated by resolve_part_path, FP

### Deferred
- ARC-F1A scripts/reconcile_apply.py:248 live-freshness check — design limitation

## K2 tool adapters + adapter tests (PR #1390)

### Addressed
- QAL-F1A / ARC-A2C — removed duplicated `sys.path` bootstrap in `base.py`, `sarif_utils.py`; switched `legacy_sarif.py`/`__init__.py` to relative imports
- ARC-A4C — dropped stale `"eslint"` prefix from `sarif_utils.PREFIX`
- ARC-D2B — converged `cargo_audit` severity fallback to `INFO`
- COD-C3B — fixed `osv_scanner` to parse OSV `severity` CVSS-V3 list using standard `"score"` key
- COD-C3B — expanded Brakeman severity map and added stderr diagnostic for unknown warning types
- ARC-A4A — lowered confidence to `LIKELY` for heuristic `eslint-security` rules
- QAL-D1A — extracted shared `_iter_source_files` in `eslint_security.py`
- COD-C2B — replaced `PipAuditAdapter` shared singleton `_manifest_path` with `contextvars.ContextVar`
- OPS-D1A — capped subprocess output in `base.run_tool` at `MAX_TOOL_OUTPUT_BYTES` (50 MiB) with truncation marker + concurrent stderr drain
- OPS-E1A / SEC-G2B — added stderr diagnostics when `sarif_utils` and `roslyn_secguard` skip SARIF result exceptions
- ARC-A2B — hardened `bundler_audit` with JSON parsing + text fallback + shape guard
- ARC-A4A — documented per-adapter `DROP_IF_NO_LOCATION` policy
- TST-G2A / QAL-D1A / TST-B1A — cleaned `test_ingest_tools.py` imports, deduped SARIF literals, strengthened progress-prefix assertions
- QAL-D1C / TST-X0X — deduplicated `_load` helper and fixed `jsonschema` skip guard in `test_schemas.py`
- TST-B1B — parsed `docker-publish.yml` structurally in `test_dockerfile.py`
- TST-B1F — broadened untrusted GitHub context denylist in `test_security_workflow.py`
- QAL-D1B / QAL-F1A / TST-A3B / TST-B1C / TST-G3D / TST-A2C / TST-B3A / TST-D1A / TST-G3B / TST-A3B / SEC-G2B — strengthened integration test assertions, fixed mocks, added timeouts, asserted diagnostics

### Dropped / overstated / FP
- SG-080 / SG-081 semgrep findings in `base.py` and `spotbugs.py` — already mitigated by `# nosec` comments and `defusedxml` preference

### Deferred
- None

## K3 CI/Docker/config (PR #1391)

### Addressed
- ARC-A2B `.github/apply-labels.sh` — replaced hand-rolled regex parser with a POSIX-robust YAML tokenizer and strengthened `tests/test_apply_labels.py`
- ARC-C1B/C1C `.github/workflows/docker-build-pr.yml` — added itself and `skill/scripts/**` to path filters; build `Dockerfile.fixtures` when it changes
- COD-F1A `.github/workflows/docker-publish.yml` — added concurrency guard
- COD-B1C `.github/workflows/docker-publish.yml` — removed unused `id-token: write`
- TST-A1B `.github/workflows/nvd-cache.yml` — extracted sync-skip decision into `.github/scripts/nvd-cache-decision.sh` + `tests/test_nvd_cache_decision.py`
- SEC-E2C/SEC-E3B/SEC-E3C/OPS-E1A `Dockerfile` — pinned base stage, added integrity checks (SpotBugs archive, rustup/dotnet install scripts), surfaced OSV DB warm failures
- ARC-B3B `Dockerfile` — documented toolchain bundling rationale
- SEC-E2A/QAL-D1B `pyproject.toml` — pinned build backend, removed duplicated dev/test pins

### Dropped / overstated / FP
- `[None]` `.env`/`.gitignore` AI-usage heuristics — tool artifacts, not defects
- `[None] security.yml pull_request_target` — known acceptable pattern for this repo

### Deferred
- None

## K4 docs (PR #1392)

### Addressed
- ARC-G2B `DEVELOPMENT.md` — updated architecture description to 5.x domain-panel dispatch, noted retired 4.x templates
- COD-D2C `DEVELOPMENT.md` — added `roslyn-secguard` to Dockerfile tool inventory
- ARC-A3A/AGT-A1B/AGT-D1C `skill/agents/domain-advisor.md` — hardened untrusted-data language for prior-reviewer claims, clarified backup round must also reconsider REJECTED verdicts
- QAL-E2B/QAL-D1A `skill/agents/lens-sweep.md` — marked retired back-compat, deduplicated/condensed untrusted-content preamble while keeping all required substrings, regenerated `tests/goldens/lens-sweep.rendered.txt`
- COD-D2D `skill/reference/kimi-tools.md` — updated manual pipeline and model table to `domain-panel`/`domain-advisor`
- README.md / CHANGELOG.md / `docs/PANOPTICON.md` / `skill/SKILL.md` — removed host-specific naming in favor of generic Agent-tool / `kimi` / `codex` references

### Dropped / overstated / FP
- `[None]` AI-usage heuristics in docs — false positives

### Deferred
- None

## K5 misc tests (PR pending)

### Addressed
- TST-E1A `tests/test_reconcile.py:10` — added `TestFixtures` existence check for the reconcile fixture directory and expected files
- TST-B3A `tests/test_reconcile.py:385` — guarded every `diff["ambiguous"][0]` access with a non-empty assertion
- TST-A3A `tests/test_triage.py:229` — added `TestGhRealBoundary` tests that exercise `triage.gh` through an actual subprocess via a PATH-shimmed fake `gh` executable

### Dropped / overstated / FP
- None

### Deferred
- None
