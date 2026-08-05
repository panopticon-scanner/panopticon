# Panopticon — Development Notes

Ruthless, standards-cited code review skill; Claude Code first-class, Kimi Code
supported, other SKILL.md hosts degraded-sequential. This file is the durable
design record that travels with the skill (installed dir / OneDrive), so future
work has context without the original spec/plan docs.

**Current version: 4.2.0** (semver — see Versioning below).

## What it is
A **discovery → scout → fan-out → synthesis** pipeline. It profiles a target with a
cheap "scout", builds a risk-tuned plan, and fans out rendered role prompts in
parallel via the host's agent mechanism (Agent tool on Claude Code, AgentSwarm
on Kimi). Each panel is reviewed by the `panel-review` agent (`agents/panel-review.md`)
through one of six panels: **code**, **test**, **security**, **architecture**, **database**, and **redteam**.
Optionally, findings are grounded with real static-analysis tools from a Docker
container. It synthesizes everything into a `CodeReviewReport` (terminal markdown
summary + JSON artifact) with standards citations and CI gating.

## Architecture
- `skill/` — the installable skill surface (symlink target); everything an agent loads lives here.
- `skill/SKILL.md` — orchestration spec (modes, pipeline, dispatch templates, flags). Instructions
  to the orchestrating agent; not a runnable script.
- `skill/scripts/orchestrator.py` — resolve a target (`-f/-d/-g/-c/--pr/-e`/repo) to cohesive
  ≤15-file groups (`groups.json`). Language-neutral. stdlib only.
- `skill/scripts/synthesize.py` — merge per-panel finding files (+ optional `--tools-dir` tool
  findings) into a validated `CodeReviewReport`: dedupe/reinforce, grade, gate, citations.
- `skill/scripts/dispatch.py` — DispatchPlan builder + template renderer (host-neutral frontmatter
  parser, rendered prompts, --render-advisor).
- `skill/scripts/model_resolver.py` — role+host → model resolution (profiles yml, env/CLI
  overrides, host-aware fallbacks).
- `skill/scripts/citations.py` — CWE validation (bundled catalog), OWASP derivation, reduced-SSVC,
  opt-in EPSS (`--epss`, stdlib urllib). Tolerant: a malformed citation never aborts a run.
- `skill/scripts/run_tools.py` — detect the `panopticon-tools` Docker image, run selected scanners
  against a read-only mount, collect SARIF. Degrades gracefully if Docker/image absent.
- `skill/scripts/ingest_tools.py` — SARIF → normalized findings (source `tool:<name>`, CWE/CVE citations).
- `skill/scripts/evidence.py` — evidence axis: status derivation, verify-queue triage, verdict ingestion.
- `Dockerfile` — `panopticon-tools` image: semgrep, gitleaks, trivy, bandit, brakeman, gosec,
  eslint. Build once: `docker build -t panopticon-tools <this dir>`.
- `skill/reference/` — `report-schema.json`, `scope-profile-schema.json`, `cwe-catalog.json`
  (curated CWE→OWASP map), `security-checklists.md`, `code-review-groups.example.yml`.
- `skill/agents/` — host-neutral role prompt templates: `scout.md`, `lens-sweep.md`, `panel-review.md`, `advisor.md`.
- `skill/prompts/` — `lenses.md` (per-panel lens catalog).

## Key design decisions (don't relitigate without reason)
- **Fan out via rendered prompts** dispatched by the host's agent mechanism (`scout`, `panel-review`, `lens-sweep`, `advisor`).
  The six panels (code/test/security/architecture/database/redteam) are selected per group
  by `compute_group_panels`; lenses are spawned only when the scout flags a surface.
- **Grade = worst-severity A–F rollup** (F if any CRITICAL … A if none). Deliberate for a
  gate; do NOT replace it. Severity + CVSS follow industry scales; the letter grade is ours.
- **The gate keys on evidence, not just severity.** `evidence.status`
  (`tool_reported`/`tool_confirmed`/`advisor_confirmed`/`corroborated`/
  `needs_more_info`/`unverified`/`rejected`) is derived by checking any advisor
  verdict FIRST, whatever the finding's source (P2, #446). A tool-sourced or
  reinforced (tool+agent) finding with no verdict is `tool_reported` — reported,
  not verified — and is NOT gate-eligible by default; only `tool_confirmed`/
  `advisor_confirmed` are (`evidence.GATE_ELIGIBLE_DEFAULT`).
  `meta.tool_axis.rejection_rate` reports how often advisors refute scanners
  among DECIDED tool claims (`None` until something is decided, never a
  misleading `0%`). `--gate-unverified` is the escape hatch for pipelines
  that want every non-rejected finding — verified or not — to gate,
  restoring the old all-claims-gate behavior. Severity itself is never
  mutated by any of this.
- **Citations are hybrid**: tools emit CWE/OWASP/CVE natively (authoritative); agents assert;
  `synthesize` validates/enriches. Never emit a guessed citation (no CVE → no EPSS; unlisted
  CWE → kept but `verified:false`; missing SSVC inputs → omitted).
- **Tool container is optional** and auto-detected; absent → clean fleet-only behavior.
- **Scan-time network is disabled** (`--network none` on every tool run):
  advisory/rules data is baked into the tools image (weekly rebuild).
  Parse-only adapters never execute target code. roslyn-secguard executes
  target build logic inside the no-egress, no-secret, read-only-mount
  container — the report records it in `meta.build_executing_tools`.
  pip-audit/npm-audit run only under `run_tools.py --online`.
- **Tolerant by design**: `load_findings` and `enrich_citations` skip/log malformed input,
  never abort the run (a bad finding must not lose a real CRITICAL or skip the CI gate).

## Running
Fresh session → `/panopticon` (`-f file`, `-d dir`, `-g "Group[Facet]"`, `-c` changes,
`--pr N`, `-e` explore, or whole repo). `--epss` enables EPSS lookups; `--fail-on high`
gates CI (keys off `summary.gate` in the JSON). Tool layer: build the image once (above);
it's used automatically when present, `--no-tools` to skip.

## Adding a new static-analysis tool

1. Create `skill/scripts/tools/<tool_name>.py` implementing `is_applicable()`, `invoke()`, and `parse()`.
2. Register it in `skill/scripts/tools/__init__.py` under `ADAPTERS`.
3. Add unit tests in `tests/tools/test_<tool_name>.py`.
4. If the tool needs installation, add it to `Dockerfile`.
5. Run `python3 -m pytest tests/tools/ tests/test_ingest_tools.py tests/test_run_tools.py -v`.

## Local scanner fixture suite

The `panopticon-fixtures` image contains vulnerable-by-design applications used to validate scanner adapters.

- Build: `docker build -f Dockerfile.fixtures -t panopticon-fixtures:latest .`
- Run tests: `python3 skill/scripts/run_fixture_tests.py`
- Force rebuild: `python3 skill/scripts/run_fixture_tests.py --rebuild`
- Tag snapshots: `docker tag panopticon-fixtures:latest panopticon-fixtures:YYYY-MM-DD`

Rebuild cadence: monthly, or whenever a new adapter is added. The same monthly cadence applies to the `panopticon-tools` image: adapter CODE is mounted from the checkout at run time (never stale), but the scanner BINARIES and their rule/advisory databases age with the image. The image pulls public fixtures at build time, so test runs require no network.

## Versioning
Scheme: a **minor** bump (2.x.0) per release round; **major** (x.0.0) reserved for breaking
changes to the report schema, CLI, or grade contract. Bump `SKILL.md` `metadata.version`,
`synthesize.build_report`'s `meta.version`, and `evidence.write_verify_queue`'s payload
`version` together.

History:
- **4.2.0** (current) — tool-policy enforcement: uniform read-only/return-JSON
  role contracts; `--emit-host-agents` generates registered enforcement shells
  (claude/kimi dialects) from the host-neutral templates; per-role `enforced`
  plan entries dispatched via `subagent_type`; `meta.tool_policy_mode`
  (enforced/advisory/mixed) in the audit artifact; clean-tree check in the
  validate step. SEC-101 remediation.
- **4.1.0** — Claude Code port: all reviewer dispatch moves to
  deterministic rendered prompts (dispatch plan entries carry `prompt`;
  `--render-advisor` renders verify-queue entries). Agent templates get
  host-neutral frontmatter (`tool_policy` as data; advisory-by-prompt on
  raw-prompt hosts). Host selection is explicit (`--host`) with fixed
  env fallback (`CLAUDECODE`; unknown → generic, model inherited). Claude
  model policy: scout/lens=haiku, panel=sonnet, advisor=opus. SKILL.md
  description is trigger-only; Host dispatch section maps the per-host
  mechanisms (research: `docs/superpowers/specs/2026-08-03-host-portability-research.md`).
- **2.0.0** — static-analysis upgrade: standards citations (CWE/OWASP/SSVC/EPSS) + the Docker
  tool container.
- **2.1.0** — bug-fix round: must-fixes surfaced by the build's review gates and the
  live real-tool smoke.
- **2.2.0** — accumulated bug-fix round from the self-review + baskin dogfood: repo-root
  clamp (CWE-22), docker-run timeout, catalog tolerance, SARIF path-normalization + per-result
  tolerance, cross-source reinforce (2-member tool+agent), citations hardening (case-insensitive
  ids, CWE-95, EPSS size-cap/UA), DoS guards, bandit noise floor, id-uniqueness + panel label,
  `--max-per-group` guard, docstrings, and test-coverage for the non-deterministic seams.
- **3.0.0** — Kimi port: introduces architecture, database, and redteam panels;
  replaces the fixed 9-lens catalog with a flexible lens model; rewrites orchestration for the
  Kimi Code agent platform; major version bump reflecting breaking changes to the skill contract.
- **4.0.0** — epistemics core: two-axis severity × evidence model.
  Severity is never mutated; evidence.status (tool_confirmed/advisor_confirmed/
  corroborated/needs_more_info/unverified/rejected) is the pipeline's verdict.
  Verification moved out of synthesize (kimi-CLI subprocess loop deleted) into an
  orchestrator-dispatched verify phase (`--emit-verify-queue` → advisor fan-out →
  `--verdicts-dir`). Citations demoted to audit metadata. Gate/grades key on
  confirmed evidence (default) with `--gate-unverified` opt-in. GROUP_RE fixed for
  3.0 filenames; effort_to_remediate/recommendations schema theater removed.
  Reinforced (tool+agent) findings gate as tool_confirmed; the legacy dedupe/corroboration confidence bumps are removed (confidence is never pipeline-mutated).

  **Update (P2, #446):** the line above no longer holds unmodified. A tool-sourced
  or reinforced finding with no advisor verdict is now `tool_reported`, not
  `tool_confirmed` — it takes an actual advisor CONFIRMED verdict to promote it.
  This closed the gap where an unverified tool HIGH (e.g. a Bandit B105 flagging
  a `gate-pass` CSS-class string as a "hardcoded password") could fail a build
  under `--fail-on low` on tool say-so alone. See "Key design decisions" above
  for the current posture; `--gate-unverified` is unchanged as the opt-in that
  restores every-non-rejected-finding-gates behavior.
- **2.3.0** — cross-dogfood round from a 61-panel run against a real 3-repo estate. Four
  fixes: (1) **cross-panel corroboration** — `synthesize` now runs a distinct agent-vs-agent pass
  (`cross_panel_corroboration`, keyed on file + line-proximity across DISTINCT panels, not category)
  that populates the previously-always-empty `cross_panel.integration_findings` and annotates
  `corroborated`/`corroborated_by` + a confidence bump, without collapsing the distinct lenses;
  extends the round-3 tool+agent dead-branch to agent+agent. (2) **discovery** —
  `orchestrator.discover_repo_files` (os.walk + prune) excludes noise (`tmp`/venv/`__pycache__`/
  `*.egg-info`/caches), targets `.github/workflows` back in (dotdirs were silently skipped → CI
  surface invisible), and surfaces real test files (were dropped in favor of their `__pycache__`).
  (3+4) **panel-prompt hardening** — the dispatch template now forbids any side effect beyond the
  findings file (no GitHub writes / dispatches), forbids claiming an unperformed action
  (confabulation), and forbids materializing a discovered secret value (cite file:line + class).
  +26 tests (153 total). Findings that drove this: a panel confabulated an issue-filing it never
  did; another copied a live DSN into its findings JSON; 3 scouts independently hit the discovery
  gaps; the reinforcement engine never fired despite heavy cross-lens agreement.
- **2.2.1** — four self-scan rounds of residual fixes; grade **F→D→C→C→B** on our own code.
  Round-2 residuals: `dedupe` no longer collapses no-line same-category findings (silent-drop);
  `load_cwe_catalog` is tolerant of a missing/corrupt catalog (upholds "never abort a run");
  `ingest_dir` logs skipped non-SARIF JSON instead of dropping it silently + docstrings corrected;
  `run_tools` tests tightened to exact argv/timeout + image-missing/bad-returncode branches.
  Round-3 residuals: **fixed the tool+agent reinforce branch, which had been dead since 2.2.0** —
  it required a literal `source:"agent:"` token, but real panel findings carry no `source` field,
  so cross-source corroboration never fired in production (only in tests that injected a synthetic
  source). Now classified by `_is_tool_sourced` (not-`tool:` ⇒ agent), matching the convention in
  `validate_report`/`render_summary`. Plus test coverage for the `_is_test_path` bandit branch and
  `load_json_tolerant`'s prose-fallback + `load_findings` malformed-input branches.
  Round-4 residuals: guarded the `--groups` load (last unguarded main-path load → tolerant);
  per-group grade attribution falls back to file-membership when a finding's `_group` token names
  no group in this run (overall grade/gate were already correct — this was display-only);
  reinforcement now generalizes to same-category tool+agent pairs inside >2-member clusters (was
  silently skipped whenever a third finding shared the line); + `run_tools` stdout-persist assertion
  and `orchestrator.main()` coverage for `--group`/`--files`/`--repo-scan`. **138 tests (was 125).**

  **Note on the treadmill:** each ruthless self-scan clears the prior MEDIUMs and surfaces a fresh,
  narrower batch (CRITICAL→HIGH→broad-MEDIUM→coverage-MEDIUM). We stopped at B by decision: all known
  MEDIUM+ are fixed and the code/security surfaces are clean; the residual LOW/INFO are logged below.
  Chasing empirical A/B round-by-round against our own reviewer does not obviously terminate.

### B-floor residuals (LOW/INFO from self-scan round 4 — future minors)
- Schema validation is advisory-only: an invalid report still writes + prints (by design; revisit if a
  strict mode is wanted). `gosec` is invoked with `./...` against a `/src` mount (relies on container cwd).
- `--file`/`--files` echo explicit paths verbatim and bypass the `_within` repo-confinement clamp that
  glob-derived scope gets (still 2.2.x backlog; low real risk on a local dev CLI over a trusted repo).
- SARIF-derived paths are rendered into the markdown summary without escaping (display-only; not opened).
- `test_related_tests_found` doesn't assert the nested-match it names. Bandit `B112`/`B404` are by-design
  (tolerant loops + the deliberate `subprocess` import) and stay as LOW tool findings.

## Shipped in 2.2.0 (delivered this round)
Deferred to a 2.2.1 sweep (minors flagged during this cycle): clamp `--file`/`--files` explicit
paths to the repo root (T1 only covered glob-derived scope); stderr log on a per-result SARIF
skip; annotate `reinforced` on same-category same-locus corroboration; and a few test-isolation
gaps (cross-tool noise-filter negative case, stdlib-fallback malformed-catalog path, multi-tool
timeout continue).
- Add CWE-95 (+ catalog completeness); log the finding id in the enrich backstop; set an EPSS
  HTTP User-Agent; restore the panel label in the summary line; add docstrings.
- Test coverage: EPSS-enabled attach path; `run_tools` argv (`:ro`); citation transfer to a
  non-tool survivor.

### Self-scan round 2 (2026-07-23) — validated 2.2.1 residuals
Re-ran Panopticon on itself at 2.2.0: **D / HIGH / 19 findings, zero CRITICAL** (was F/CRITICAL/24).
The round-1 criticals are resolved; these narrower residuals were hand-verified as real and lead 2.2.1:
- **`dedupe` silent-drop, no-line + same-category** (HIGH, `synthesize.py`): two distinct same-file
  findings that both omit `line_start` cluster to `(file, None)`; the `by_cat` branch then keeps one
  per category, silently dropping the other. Residual of the T6 silent-loss class. Fix: don't collapse
  same-category findings that lack a line (or fall back to a title/description discriminator).
- **`load_cwe_catalog()` unguarded** (MEDIUM, `citations.py:24` ← `synthesize.py:419`): bare
  `open()`+`json.load` with no try/except; a missing/corrupt bundled catalog crashes the whole
  synthesis run and drops the CI gate — violates the "tolerant by design, never abort a run" invariant.
  Fix: wrap catalog load, degrade to an empty catalog + stderr warning.
- **`ingest_tools` non-SARIF JSON silently dropped** (MEDIUM): module doc implies "simple native JSON"
  ingestion but only SARIF is implemented; unrecognized JSON is dropped with no diagnostic. Fix: log a
  skip, or align the docstring to SARIF-only.

### From the baskin dogfood run (2026-07-23) — tool↔fleet integration (2.2.0)
- **Tool noise floor**: bandit emitted 579 `B101` "assert used" findings from `tests/` on one run.
  Add a noise filter — skip `tests/` for SAST, drop `B101`, and/or a LOW-severity floor for tool findings.
- **Normalize SARIF paths**: `ingest_tools` keeps the raw `artifactLocation.uri` (`file:///src/...`);
  strip the `file://` scheme and the `/src/` container-mount prefix so tool paths match the agents'
  package-relative paths.
- **Cross-source reinforce is effectively dead**: `dedupe` keys on `(file, line_start, category)`,
  but tool rule-ids ≠ agent lens categories and tool paths carry `/src/` — so an identical tool+agent
  finding (observed: the CSRF at `templates/program_detail.html:151`) never merges. Fix the path
  normalization above AND match on `(file, line)` with looser/optional category (or map ruleId→lens).

### From Panopticon's self-review (2026-07-23) — graded itself F/CRITICAL, 24 findings
Correctness/security (do first):
- **Path-traversal / scope escape** (code+security both flagged, CWE-22): `expand_patterns` + catalog globs can escape the repo root via `..` or absolute paths (`orchestrator.py:154`). Clamp resolved paths under the repo root.
- **No docker-run subprocess timeout** (`run_tools.py:60`): a hung/slow tool blocks the pipeline forever. Add a per-run timeout.
- **`load_catalog` only catches `ImportError`** (`orchestrator.py:135`): a malformed `groups.yml` crashes with a raw traceback when PyYAML is installed. Catch parse errors too.
- **`sarif_to_findings` tolerance is per-file, not per-result** (`ingest_tools.py:20`): one malformed entry drops every result in that file. Guard per-result.
- **Untrusted-input DoS hardening** (`ingest_tools.py`/`citations.py`): cap EPSS response size (CWE-400), bound JSON nesting (RecursionError), sanitize SARIF `uri`/`message` before rendering (CWE-117).
- **`dedupe` cluster key is type/path-sensitive on `line_start`+file** (`synthesize.py:125`): normalize `line_start` to int and paths — ties directly to the `/src` path-prefix + dead-reinforce items above.
- Minor: enforce finding-`id` uniqueness (`synthesize.py:258`); make CWE/CVE regex case-insensitive (`citations.py:33`); `--max-per-group` lower-bound guard.
Test coverage (the non-determinism challenge — this is the headline):
- **`run_tools.run_tools()` has zero coverage** (CRITICAL): add tests asserting the real `docker run` argv (`:ro`, image, per-tool cmd) + continue-on-failure.
- **Ingest fixtures don't match real tool SARIF** (no `file:///src/` uri, no `taxa` CWE): replace with golden real-tool SARIF — would have caught the `/src/` bug.
- **`TOOL_CMD` argv asserted nowhere**: lock the semgrep-`--config` fix with a regression test. Cover the EPSS-enabled / empty-EPSS / CVE-tag branches. The scout+fleet orchestration (SKILL.md prose) has no automated test.

## Later — features (a future minor, or major if breaking)
- SonarQube per-axis A–E ratings; ISO 25010 mapping; **SARIF export** of our own report;
  OWASP Risk Rating scoring.
- SARIF `taxa`/relationships CWE extraction (for CodeQL-style tools).
- On-load usage hint / `argument-hint` (surface flags/modes when the skill loads).
