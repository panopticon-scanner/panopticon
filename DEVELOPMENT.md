# Panopticon — Development Notes

Ruthless, standards-cited code review skill; first-class support for the native
Agent-tool host, plus portable support for other SKILL.md-compatible agents. This file is the durable
design record that travels with the skill (installed dir / OneDrive), so future
work has context without the original spec/plan docs.

**Current version: 5.1.0** (semver — see Versioning below).

## What it is
A **discovery → scout → fan-out → synthesis** pipeline. It profiles a target with a
cheap "scout" whose returned `domains` WIDEN a deterministic per-group domain floor
(`coverage_model.effective_panels`: the committed `GLOBAL_FLOOR` of COD/DAT/TST/ARC
plus `applicable_sec_floor`, minus any per-group `exclude`), then fans out one
rendered prompt per resulting `(domain, group)` matrix cell. `driver loop`
dispatches pending entries through a host runner or prints a batch in session
mode (`--host generic` uses that mode). Each cell is reviewed by the `domain-panel` agent
(`agents/domain-panel.md`); its verifier is `domain-advisor`.
Review is keyed on the ten OCRDb **domains** (`groups_schema.DOMAINS`: SEC, COD,
ARC, TST, QAL, AGT, DAT, OPS, ACC, LNG) — a `panopticon.yml` group's `panels:` key is
parsed as a domain set. The 4.x six-panel vocabulary (code/test/security/
architecture/database/redteam) survives only as a reporting axis.
Findings are grounded with static-analysis tools from a Docker container when
the normal driver's readiness check passes; `--no-tools` explicitly runs without
that layer. It synthesizes everything into a `CodeReviewReport` (terminal markdown
summary + JSON artifact) with standards citations and CI gating.

## Architecture
- `skill/` — the installable skill surface (symlink target); everything an agent loads lives here.
- `skill/SKILL.md` — driver run-loop spec (modes, driver verbs, flags). Instructions
  the host follows to drive the driver; not a runnable script.
- `skill/scripts/discovery.py` — resolve a target (`-f/-d/-g/-c/--pr`/repo) to cohesive
  ≤15-file groups (`groups.json`); extracted from the retired `orchestrator.py` (5.0 Slice A).
  Language-neutral, stdlib only.
- `skill/scripts/driver.py` — the resumable driver: a table-driven phase state machine
  (`readiness`→`discovery`→`coverage`→`tools`→`review`→`verify`→`synthesize`→`validate`) that runs
  `discovery.py`/`dispatch.py`/`synthesize.py`/`run_tools.py` itself and stops at each dispatch
  checkpoint; the phase cursor is recomputed from disk every invocation (crash/compaction-resumable).
  Thin entry script: the CLI, the `PHASES` table, `run()` and `main()`. Each phase lives in
  `skill/scripts/phases/` (one module per phase, plus `runio`/`engine`/`requests`/`setup`).
- `skill/scripts/phases/readiness.py` and `readiness_checks.py` — the first, pre-dispatch
  checkpoint records Docker/image, runtime dependency and other environment checks in
  `readiness.json`; a failing required check stops the normal driver run. Host capability
  posture is established before the phases and rechecked on each invocation.
- `skill/scripts/orchestrate.py` and `loop_batch.py` — `driver loop` repeatedly calls the
  driver, reads each bound dispatch request, arms guards, runs pending entries, persists
  results and returns to the driver's done predicates. Batch records track ownership,
  rollback and crash recovery; a live or unprovable foreign owner blocks resume.
- `skill/scripts/runners/` — the one-entry host runner interface and headless Claude,
  Kimi and Codex adapters; session mode prints a batch for host-side dispatch.
  `skill/scripts/hosts.py` holds host claims and selection, while `host_probes.py` and
  `probes/` measure this run's capabilities. A declaration alone grants no enforcement:
  unknown or refuted security posture needs the documented, disclosed unenforced path.
- `skill/scripts/synthesize.py` — merge per-panel finding files (+ optional `--tools-dir` tool
  findings) into a validated `CodeReviewReport`: dedupe/reinforce, grade, gate, citations.
  Thin entry script: the work lives in `skill/scripts/synth/`, one stage per module.
- `skill/scripts/dispatch.py` — agent-template renderer + host enforcement-shell emitter
  (host-neutral frontmatter parser, `render_prompt`, `--render-advisor`,
  `--emit-host-agents`). The 4.x DispatchPlan builder it was named for is retired;
  the driver builds its own matrix-cell plan.
- `skill/scripts/model_resolver.py` — role+host → model resolution (profiles yml, env/CLI
  overrides, host-aware fallbacks).
- `skill/scripts/citations.py` — CWE validation (bundled catalog), OWASP derivation, reduced-SSVC,
  opt-in EPSS (`--epss`, stdlib urllib). Tolerant: a malformed citation never aborts a run.
- `skill/scripts/run_tools.py` — select scanners, run them against a read-only mount,
  and collect scanner captures. If Docker or the image is unavailable, a standalone
  invocation prints a skip warning and records missing coverage only when
  `--manifest` is supplied; the normal driver checks those prerequisites in readiness
  before dispatch.
- `skill/scripts/ingest_tools.py` — SARIF → normalized findings (source `tool:<name>`, CWE/CVE citations).
- `skill/scripts/evidence.py` — evidence axis: status derivation, verify-queue triage, verdict ingestion.
- `skill/scripts/group_runner.py` — fan-out resume + coverage primitives: `entry_is_done`/
  `pending_entries` (the done-predicate and resume set) and `fan_out_coverage` (planned-vs-executed,
  derived from the dispatch plan + the findings files on disk).
- `skill/scripts/write_guard_hook.py` and `read_guard_hook.py` — Claude `PreToolUse`
  hooks installed for dispatch: the former binds a reviewer to its own declared
  `out_file`; the latter confines `Read`/`Grep`/`Glob` to its entry scope. The loop
  installs and removes grants around batches; other hosts use their own runner controls.
- `skill/scripts/tools/__init__.py` — scanner adapter registry: semgrep, gitleaks,
  trivy, bandit, gosec, eslint-security, brakeman, bundler-audit, spotbugs,
  dependency-check, cargo-audit, roslyn-secguard, osv-scanner, pip-audit and
  npm-audit (the last two require `--online`). `Dockerfile` builds the
  `panopticon-tools` image: `docker build -t panopticon-tools <this dir>`.
- `skill/reference/` — `report-schema.json`, `scope-profile-schema.json`, `cwe-catalog.json`
  (curated CWE→OWASP map), `security-checklists.md`, `code-review-groups.example.yml`.
- `skill/agents/` — host-neutral role prompt templates: `scout.md`, `setup-scan.md`,
  `domain-panel.md`, `domain-advisor.md`, `advisor.md`.

## Key design decisions (don't relitigate without reason)
- **Fan out via rendered prompts** dispatched through the host runner (`scout`, `domain-panel`, `domain-advisor`, `advisor`).
  One cell per `(domain, group)`: the domain set is the committed floor widened by the
  scout's returned `domains` (`coverage_model.effective_panels`). The scout's judgement
  can only ADD domains, never remove a floor domain — #1193.
- **Grade = worst-severity A–F rollup** (F if any CRITICAL … A if none). Deliberate for a
  gate; do NOT replace it. Severity + CVSS follow industry scales; the letter grade is ours.
- **The gate keys on evidence, not just severity.** `evidence.status`
  (`tool_reported`/`tool_confirmed`/`advisor_confirmed`/`corroborated`/
  `needs_more_info`/`unverified`/`rejected`) is derived by checking any advisor
  verdict FIRST, whatever the finding's source (P2, #446). A tool-sourced or
  reinforced (tool+agent) finding with no verdict is `tool_reported` — reported,
  not verified — and is NOT gate-eligible by default; only `tool_confirmed`/
  `advisor_confirmed` are (`evidence.GATE_ELIGIBLE_DEFAULT`).
  `meta.coverage.tool_axis.rejection_rate` reports how often advisors refute scanners
  among DECIDED tool claims (`None` until something is decided, never a
  misleading `0%`). `--gate-unverified` is the escape hatch for pipelines
  that want every non-rejected finding — verified or not — to gate,
  restoring the old all-claims-gate behavior. Severity itself is never
  mutated by any of this. **The CI security workflow
  (`.github/workflows/security.yml`) deliberately adopts that
  `--gate-unverified` posture**: it runs no advisor phase, so every tool
  finding is unverified `tool_reported` and a confirmed-only gate would gate
  on nothing. CI therefore fails on any HIGH/CRITICAL tool finding on raw
  severity as a conservative pre-merge floor (fixture noise excluded via
  F-CAL-2) — a documented strict policy (#513), NOT the authority for the
  reported grade, which still comes from the evidence/advisor pipeline.
  The raw grade itself moved in #1790: a SARIF result stating no `level` of its
  own is now graded by its rule's `defaultConfiguration.level` rather than by an
  invented `warning` default. That is **bidirectional**, and the downward half is
  the larger one — on this repository's own captures semgrep's rule defaults are
  `error` ~24, `warning` ~9 and `note` **241**, so 24 findings went MEDIUM → HIGH
  and 241 went MEDIUM → LOW (a `none` default now yields INFO). No CI-gate effect,
  since that floor is HIGH/CRITICAL, but a `driver run --severity medium` or
  `--fail-on medium` sees a correspondingly smaller tool axis on such a tree.
  **That floor is applied to what a commit ADDS** (#1790, owner ruling
  2026-09-23; route coverage settled by the controller's C1 ruling the same
  day). Every route — push to `main`, same-repo PR, fork PR — downloads a base
  commit's own `raw-scanner-captures` artifact and passes it to the gate as
  `--baseline-dir`/`--baseline-manifest`; the gate ingests it through the same
  call with the same `--exclude` globs and the same security mode, and a head
  finding matching one of the baseline's — same tool, rule, normalized path and
  message, matched as a MULTISET so a second identical hit is still new, and
  with line numbers deliberately excluded so an unrelated edit above a finding
  does not resurrect it — is printed under `pre-existing (in the base commit's
  scan; …)` and not counted. **A new HIGH/CRITICAL still fails the check.**
  Which commit is the base depends on the route: a PR compares against its
  `base.sha`, a push to `main` against the previous main head
  (`github.event.before`). From there the workflow walks the base itself plus
  **up to five first-parent ancestors** looking for a **completed**
  `security.yml` run to download from — `completed`, not `successful`. A run
  whose gate went red still uploaded its captures (`if: always()`), and the
  gate refuses a *partial* baseline on its own terms anyway: `load_baseline`
  runs the same `lost_required_coverage` check over the baseline's manifest and
  dispositions that `evaluate` runs over the head, and rejects a baseline whose
  scan lost an adapter loudly and strictly. Filtering on `success` as well
  looked conservative and was in fact an absorbing state: a HIGH the owner
  dismisses on the Security tab rather than removing from tool output reds
  `main`'s own run, each following commit reaches the last green one a hop
  further back, and at the sixth nothing — no PR, no push — can find a baseline
  again. The walk is kept for the cases a status filter cannot help with: an
  artifact that has expired (90-day retention) and a cancelled run that has
  none. Downloadable is not the same as complete: the walk stops at the first
  artifact it can download, and it is the gate, not the run's conclusion,
  that decides whether that baseline is usable. A run that died mid-scan
  costs one strict, audible commit before the next hop heals it, and because
  `--limit 1` takes the newest completed run at a sha whatever its
  conclusion, a cancelled run costs one hop.

  Every route is delta-aware because a half-delta eats itself: leaving the push
  to `main` strict means main's own gate fails on the standing set, the run's
  conclusion is `failure`, no PR's lookup can then find a usable run at its
  base, and every PR falls back to strict on findings its author cannot clear.
  The standing set on `main` is instead governed by the post-merge audit below
  and by the owner's own GitHub dismissals, and it is **disclosed** under the
  pre-existing heading on every single run rather than hidden: a finding listed
  there is fixed or dismissed on the Security tab, not on a commit whose diff
  never touched it.

  **No baseline, no delta.** A run whose walk-back found nothing (no run within
  five hops, artifacts expired, an event with no base commit at all), or whose
  baseline is unusable — unreadable directory, malformed manifest, or a
  baseline whose own scan lost an adapter's coverage — is gated strictly on the
  whole tree. The workflow says so with a `::notice::` and the gate with one
  stderr line naming what was wrong. It fails toward strictness in every
  direction and never toward silence.

  **Two blind spots in the identity, both inherent to the ruling.** Replacement
  *inside one file is invisible*: five findings in a file that share one
  identity are matched five-for-five, so a diff deleting all five and adding
  five fresh ones gates on nothing. And a *pure move reads as new*: renaming a
  file turns every finding in it into a new one, because the path is part of
  the identity. The first is the one an author controls; a full-tree review, not
  this gate, is what catches it. **One residual to know about**: the tools image
  (`ghcr.io/…-tools:latest`) is unpinned, so an image that re-grades a semgrep
  rule from `warning` to `error` promotes every standing occurrence at once —
  severity is not part of the identity, so those are disclosed as pre-existing
  rather than counted, on every route. A scheduled strict full-tree lane that
  would count them is a follow-up.
  After that gate reads the unchanged raw captures and manifest, the workflow
  runs `scripts/code_scanning_reports.py` in runner temporary storage. It
  keeps only the two named, note-level AI-usage rules from the exact supported
  `Semgrep OSS` driver in a separate JSON/Markdown inventory. A similar tool
  name, elevated severity, taxonomy relationship, or any metadata beyond the
  reviewed low-confidence inventory shape keeps the result in Security. The
  helper strictly decodes JSON, validates each complete capture offline against
  the fixed official SARIF 2.1.0 Draft 7 schema in `scripts/reference/`, and
  resolves localized result-message IDs through the rule or driver message
  strings before routing. All schema-defined property-bag carriers, taxa, and
  relationships are checked recursively. Shared document, run, tool, driver,
  and run-cache context is checked without traversing sibling results or
  rules. Metadata on an unreferenced shared cache can therefore keep every
  candidate in the run in Security; this conservative tradeoff avoids a
  partial SARIF reference resolver. Unsupported external, taxonomy,
  configuration-override, or indexed candidate references also remain in
  Security. ID-bearing nested `message`, `description`, and `label` objects
  remain there as unsupported references; only the root result message uses
  the rule/global message resolver. The conventional unbacked `%SRCROOT%` base
  used by current Semgrep captures remains eligible. Malformed captures and
  dangling root message IDs fail preparation before anything is published.
  The raw captures are retained as their own artifact, and the helper publishes
  the Security and inventory directories atomically so a preparation failure
  cannot appear as an empty successful analysis.
- **`meta.coverage` is the single home for what a run actually observed**:
  `adapters` (per-file disposition — `ok`/`empty`/`failed`, a findings count,
  and a `reason` when failed), `tools_ran`, `build_executing_tools`,
  `tool_policy_mode`, `tool_axis`, and `verdicts` all live under it. An
  adapter classified `failed` (0-byte output, unparseable, or no registered
  adapter) is excluded from `tools_ran`/`build_executing_tools` — it is no
  longer counted as having run. `verdicts.cut` records how many findings
  `--max-verify` dropped from the verify queue. `tool_policy_mode` reads
  `unknown` when no dispatch plan was found (distinct from `advisory`, a
  plan that enforced nothing). The terminal HTML report's header renders a
  coverage line (verified/unverified/tool-reported/cut counts plus gate
  policy) next to the grade badge, so a PASS can't hide low verification.
  `summary.gate_policy` (`confirmed_only`/`include_unverified`) is unchanged
  by this consolidation and stays under `summary`, not `coverage`.
- **Citations are hybrid**: tools emit CWE/OWASP/CVE natively (authoritative); agents assert;
  `synthesize` validates/enriches. Never emit a guessed citation (no CVE → no EPSS; unlisted
  CWE → kept but `verified:false`; missing SSVC inputs → omitted).
- **Normal driver tool coverage is checked before dispatch.** Readiness refuses
  missing Docker or the tools image by default; `--no-tools` is the explicit,
  report-disclosed choice to review without scanner evidence. Standalone
  `run_tools.py` instead skips when the image is unavailable and records missing
  coverage in its manifest when requested.
- **Offline scans have no network** (`--network none`); advisory/rules data is
  baked into the tools image (weekly rebuild).
  Parse-only adapters never execute target code. roslyn-secguard executes
  target build logic inside the no-egress, no-secret, read-only-mount
  container — the report records it in `meta.coverage.build_executing_tools`.
  pip-audit/npm-audit run only under `run_tools.py --online`.
- **Tolerant by design**: `load_findings` and `enrich_citations` skip/log malformed input,
  never abort the run (a bad finding must not lose a real CRITICAL or skip the CI gate).
- **Fan-out resumes from artifacts, not an orchestrator's memory (P2 SP-A, #435,
  #444, #436).** `driver loop` owns pending-entry selection, bounded host launches,
  per-entry persistence and the ledger. `loop_batch` validates batch ownership and
  recovers interrupted work before another launch. A reviewer with a proved artifact
  write guard may write its own `out_file`; otherwise the entry returns JSON for the
  host to persist. Codex uses returned JSON. The runner's final text does not advance
  a phase until the driver's done predicate sees the required file on disk.
- **Write and read confinement follow proved host capabilities.** The installed
  Claude write hook keeps grants by entry ID and binds a reviewer through its dispatch
  marker (or the headless entry environment); a bound reviewer may write only its own
  `out_file`, never a sibling's. Its batch-wide union applies to the orchestrator, not
  to a bound reviewer. The Claude read hook similarly binds `Read`/`Grep`/`Glob` to
  the entry's declared scope. Kimi has its own read/write hook surface; Codex uses
  its read broker and returns findings for host persistence. `hosts.posture` uses
  probe evidence, not registry claims, to decide which controls a run can rely on.
- **Resume is a done-predicate, never a re-run-everything.** An entry is done iff its `out_file`
  exists AND parses as findings JSON (`group_runner.entry_is_done`) — missing, truncated, or
  corrupt is NOT done and is re-dispatched. `group_runner.pending_entries` is the exact resume set
  fan-out (re-)dispatches; status always comes from disk, never from what an agent claims to have
  done.
- **`meta.coverage.fan_out` is derived at synthesis, never trusted from a runner's return.**
  `synthesize` computes `{planned, executed, groups_complete, groups_partial}`
  (`group_runner.fan_out_coverage`) from the dispatch plan plus the findings files actually on
  disk, the same "classify/derive at synthesis" precedent as the rest of `meta.coverage`. This is
  the disclosure axis that makes a truncated run visible in the artifact instead of silently
  biased toward "no findings"; it only *produces* the signal — refuse-to-grade-on-divergence and
  panel reorder are SP-B policy, not SP-A.

## Running
Fresh session → `/panopticon` (`-f file`, `-d dir`, `-g <name>` one committed group, `-c`
changes, `--pr N`, or whole repo — see `docs/PANOPTICON.md` "Modes" for the authoritative
flag list). `--epss` enables EPSS lookups; `--fail-on high`
gates CI (keys off `summary.gate` in the JSON). Tool layer: build the image once (above);
normal runs require Docker and the tools image at readiness, or `--no-tools` to
skip the layer explicitly. `driver readiness` prints a read-only preflight.

### Test-only injection seams
Two module attributes exist so the unit suite can refuse a real launch, and neither may ever be
assigned outside `tests/`. `DEFAULT_RUNNER` (on each host-CLI launch seam —
`tests/conftest.py`'s `LAUNCH_SEAMS`, found by AST walk in `tests/test_host_launch_guard.py`) and
`skill/scripts/phases/readiness_checks.py`'s `DOCKER_RUNNER`, which the readiness phase resolves its
`docker version` / `docker image inspect` probes through. **Its production value is `None`**,
meaning "use `setup_flow.DEFAULT_RUNNER`"; a non-`None` value left in shipped code would make the
readiness checkpoint answer "ok" off a fake without probing Docker at all — and that is the check
gating every paid dispatch. `tests/phases/test_readiness.py::test_the_docker_runner_seam_is_none_in_production`
asserts both halves (the shipped default, in a fresh interpreter, and that no module under
`skill/scripts/` or `scripts/` assigns it).

## Adding a new static-analysis tool

1. Create `skill/scripts/tools/<tool_name>.py` implementing `is_applicable()`, `invoke()`, and `parse()`.
2. Pick a finding-ID `prefix` no other adapter uses (legacy SARIF tools take
   theirs from `sarif_utils.PREFIX` — add an explicit entry, never rely on the
   `TL` fallback). `tests/tools/test_prefix_registry.py` fails on collisions.
3. Register it in `skill/scripts/tools/__init__.py` under `ADAPTERS`.
4. Add unit tests in `tests/tools/test_<tool_name>.py`.
5. If the tool needs installation, add it to `Dockerfile`.
6. Run `python3 -m pytest tests/tools/ tests/test_ingest_tools.py tests/test_run_tools_*.py -v`.

## Local scanner fixture suite

The `panopticon-fixtures` image contains vulnerable-by-design applications used to validate scanner adapters.

- Build: `docker build -f Dockerfile.fixtures -t panopticon-fixtures:latest .`
- Run tests: `python3 skill/scripts/run_fixture_tests.py`
- Force rebuild: `python3 skill/scripts/run_fixture_tests.py --rebuild`
- Tag snapshots: `docker tag panopticon-fixtures:latest panopticon-fixtures:YYYY-MM-DD`

Rebuild cadence: monthly, or whenever a new adapter is added. The same monthly cadence applies to the `panopticon-tools` image: adapter CODE is mounted from the checkout at run time (never stale), but the scanner BINARIES and their rule/advisory databases age with the image. The image pulls public fixtures at build time, so test runs require no network.

### The containment lane

`.github/workflows/adapter-integration.yml` has two scheduled jobs. `integration` runs the whole
`tests/tools/` tree in the fixtures image under `PANOPTICON_REQUIRE_INTEGRATION=1`. `containment`
(#1655) runs one file — `tests/tools/test_hostile_csproj.py`, the only test that invokes an adapter
on a hostile project, executing `evil.csproj`'s MSBuild target with its live `curl` and its
marker-file write. That job adds two flags to the same `docker run`, and neither works without the
other: `-e PANOPTICON_CONTAINMENT_PROBE=1` is the opt-in, and `--network none` is what makes the
opt-in true. The probe does not trust the flag — before building it dials out, and if anything
answers it refuses and fails — so the lane is offline by construction, and both controls are pinned
on it by `tests/test_workflow_pins.py` (`EXPECTED_CONTAINMENT_LANES`, `uncontained_lanes()`). It is
its own job rather than a step in `integration` so that an adapter regression cannot hide a
containment one.

The fixture it scans is baked into the fixtures image and `dotnet restore`d there (#1655):
`roslyn-secguard` refuses a C# target with no restore output, and a read-only mount with no network
cannot produce one at scan time. It is restored, never built — the hostile target is hooked
`BeforeTargets="Build"`, so it may only fire inside the no-egress container.

To run it by hand, reproduce the lane rather than setting the flag on your shell — the command
below is the job's `run:` line verbatim. `Dockerfile.fixtures` is `FROM panopticon-tools:latest`,
so build or pull the tools image first (`docker build -t panopticon-tools:latest .`, or pull
`ghcr.io/<owner>/panopticon-tools:latest` and `docker tag` it).

```
docker build -f Dockerfile.fixtures -t panopticon-fixtures:latest .
docker run --rm \
  --network none \
  -v "$PWD:/work:ro" -w /work \
  -e FIXTURE_ROOT=/opt/panopticon-fixtures \
  -e PANOPTICON_REQUIRE_INTEGRATION=1 \
  -e PANOPTICON_CONTAINMENT_PROBE=1 \
  -e PYTHONDONTWRITEBYTECODE=1 \
  --entrypoint sh panopticon-fixtures:latest \
  -c "python3 -m pytest tests/tools/test_hostile_csproj.py -q -rs -p no:cacheprovider"
```

Drop nothing from it: without `PANOPTICON_REQUIRE_INTEGRATION=1` an unmet precondition *skips* where
the lane *fails*, and a hand run that disagrees with the lane is worse than no hand run. Reading a
red one: only `PANOPTICON_CONTAINMENT_PROBE is set but outbound egress is reachable` means the
containment control itself broke — every other failure means the probe never got to run (a missing
precondition, a fixture, the toolchain), so diagnose it as infrastructure before calling it a
containment regression.

## Pinned dependencies

Dependabot covers this repo's `pip` and `github-actions` dependencies. Three families sit outside it
and are maintained by `scripts/bump_pins.py <family> [--write]`, which never writes a checksum it
has not recomputed from the downloaded artifact:

| Family | What it pins | Who bumps it |
|---|---|---|
| `rustup` | `Dockerfile`'s `ARG RUSTUP_VERSION` + its two init SHA256s | `pin-freshness.yml`, Mondays, opens a PR |
| `requirements` | the `--hash=sha256:` lines in `.github/requirements-gate.txt`, `requirements-fixtures.txt` and `requirements-tools.txt` | you, beside the version bump |
| `gems` | `Dockerfile`'s `ARG <GEM>_VERSION` + `ARG <GEM>_GEM_SHA256` pairs | you; nothing schedules it yet |

The `rustup` family pins only the bootstrap installer. `RUST_TOOLCHAIN_VERSION` pins the compiler
separately; changing the rustup installer does not upgrade Rust. Keep `CARGO_AUDIT_VERSION` explicit
as well. Its `cargo install --locked` uses the crate release's packaged `Cargo.lock`, so changing
the cargo-audit version is a deliberate dependency-graph refresh: check that release's lockfile and
build the image before accepting it. This is not a repository-owned hash closure.

Trivy is installed from its official release archives, outside the apt mirror's update policy.
When updating `TRIVY_VERSION`, download the Linux-64bit and Linux-ARM64 archives over verified HTTPS,
compute their SHA256 digests, and update `TRIVY_SHA256_AMD64` and `TRIVY_SHA256_ARM64` together.
The Docker build checks the chosen archive's digest before extracting the `trivy` binary. Keep
ordinary distro apt packages unpinned so they continue to receive security updates.

The `gems` family also refuses to pin a release whose RUNTIME closure has grown past what the image
installs. The tools image installs each `.gem` with `--ignore-dependencies` (#1734), so the closure
is something this repo asserts rather than something RubyGems works out — and a release that
requires a new gem would carry a perfectly good digest and still be wrong to pin.

### Regenerating the pinned dependency hashes

The three requirements files are what the repo's **privileged** builds install (#1641, #1734): the
`security-fork.yml` gate, which runs under `pull_request_target` and is reachable from a fork PR a
maintainer has opted in (below); the fixture image, which installs as root at image build; and the
tools image, which does the same and is then published publicly as the trust root of every scan.
All three use `--require-hashes`, so pip refuses any artifact whose sha256 is not written in the
file — which also means a version bump with stale digests fails the build rather than installing
something unpinned.

**Scanning a fork PR (#1900).** Two workflows, and which one speaks for a fork PR is the whole
design. `security.yml` (check name `scan`) runs on pushes to main and on same-repo PRs only; on a
fork PR its job skips and says nothing. `security-fork.yml` (check name `fork-scan`) runs under
`pull_request_target` and is the fork PR's required check — the one to register in branch
protection.

Nothing scans a fork PR until you say so. From the moment it opens, `fork-scan` runs and **fails**:
a fork PR carries a real red check, never a skipped one, because a skipped check is what branch
protection counts as satisfied. Read the diff, then apply the `safe-to-scan` label — applying
*that label* is what starts the real scan, over the head you were looking at. Every new push to
the PR (and every reopen) revokes the label, so a force-push after your approval waits for you a
second time. `fork-scan` reports on the PR head because a `pull_request_target` run attaches its
checks to the PR head SHA.

Two consequences of "that label", which is a deliberately strict rule. **Applying any other label
to an already-scanned fork PR posts a fresh red `fork-scan`** over the earlier green; to clear it,
*remove* `safe-to-scan` and *add* it again, because GitHub does not fire a `labeled` event for a
label that is already present. The strictness buys the case it looks pedantic about: a looser rule
("any label, while `safe-to-scan` is standing") could green a head nobody reviewed, because the
gate reads the event payload — in the seconds between a push and the revoke finishing, the payload
still carries the label. And if the revoke ever *fails* rather than races, that window is not
seconds but indefinite: `unlabel` fails loudly on anything except a 404 (label already gone), but
it is **not a required check**, so a failed revoke shows up only in the Actions tab. Check there if
a fork PR is behaving oddly.

One caveat about the name. Branch protection matches a required check by name, and on the
`pull_request` route a fork PR runs its own workflow files — so a PR that *adds* a workflow with a
job named `fork-scan` can post a green check under that name. That is inherent to check names
rather than to this design, and it is why the outside-collaborator setting below is load-bearing:
the required `fork-scan` means what it says only while "require approval for all outside
collaborators" is on and the approving maintainer reads any workflow files the PR adds before
clicking *Approve and run*.

The fork path deliberately scans less than a main-branch run: no registry login, no `--deps` (so no
dependency scanner reading the PR's own lockfiles) and no SARIF upload, because under
`pull_request_target` the upload would be filed against `main`'s Security tab. The full set runs on
the push to main after the merge.

What the fork path does NOT scan less of is the delta. A fork PR is gated on exactly the same terms
as a same-repo one (#1790): `fork-scan` downloads the same base-commit `raw-scanner-captures`
artifact — from `security.yml`'s run on the base branch, which nothing in a fork can write — and
runs the same fetch step, with the same five-hop walk-back, and the same gate command. Both jobs
hold `actions: read` for that download and for nothing else. The fetch runs *between* the two
checkouts there, so the one step that carries a token runs before any fork-controlled content is on
disk, and `pull_request_target` is `branches: [main]`, so the sha it resolves is always a `main`
commit.

**Post-merge zero-alert audit.** On a push to `main`, `security.yml` follows its actionable SARIF
upload with a read-only `scripts/code_scanning_audit.py` check. The check independently proves that
the Security upload and CodeQL's separate Python upload both finished for the exact current main
SHA, then reads every page of `state=open` code-scanning alerts without a severity or tool filter.
Any open note, warning, or error fails. There is no alert-number baseline or allowlist: fixed and
dismissed findings pass because GitHub omits them from `state=open`, while a reopened or newly
fingerprinted alert is open again and fails.

This is a post-merge detector, not universal pre-merge protection. The fork workflow intentionally
uploads no SARIF, so a fork warning/note may first turn the main audit red after merge; the raw
HIGH/CRITICAL gate remains the fork's pre-merge floor — applied, since #1790, to the findings the
fork PR adds to its base commit rather than to every finding in the tree. That division is the
point: **this audit is what speaks for the standing set on `main`**, which is why the pre-merge gate
on every route is free to stop failing over it. A pre-existing finding clears by being fixed, or by
being dismissed on the Security tab (GitHub omits a dismissed alert from `state=open`, so the audit
passes); it never clears by being ignored, and the gate prints it under the pre-existing heading on
every run so nobody has to remember it is there. For a read-only reproduction, take the singular
`sarif-id` output from the main Security upload and run:

```bash
GH_TOKEN="$(gh auth token)" python3 scripts/code_scanning_audit.py \
  --repository OWNER/REPOSITORY --server-url https://github.com \
  --ref refs/heads/main --sha FULL_40_HEX_MAIN_SHA --sarif-id SECURITY_UPLOAD_UUID
```

Treat a clean result as current only after all five analyses are complete and the script confirms
that main still points at the audited SHA. API failures, incomplete processing, malformed metadata,
pagination failures, and a moving main head fail closed rather than report zero.

One thing `security.yml` does **not** give you: a fork PR also raises `pull_request`, and on that
route GitHub runs the PR's *own* copy of the workflow file, with a read-only token and no secrets.
Nothing that file says binds a fork PR. What binds one is a required approving review, the required
`fork-scan` check above, and the repository setting "require approval for all outside
collaborators" — which, unlike `pull_request_target`, does cover the `pull_request` route and
holds the run as `action_required`.

The versions are the input and yours to choose; the digests are not. After changing a
`name==version` line (or adding a package), run:

```bash
python3 scripts/bump_pins.py requirements --write      # all three files
python3 scripts/bump_pins.py requirements --file .github/requirements-gate.txt --write
```

Dependabot proposes version bumps: the root `pip` entry sees `requirements-fixtures.txt`,
`requirements-tools.txt`, and `pyproject.toml`; the `/.github` entry sees the gate file. The root
entry groups routine Python version updates and filters proposals that would break the current
pinned tools graph: all version updates for `mcp`, `opentelemetry-*`, and `pydantic-core` (Pydantic
2.13.5 requires exactly pydantic-core 2.46.5); major updates for `peewee`, `boltons`, `protobuf`,
`wcmatch`, and `wrapt`; and major/minor updates for `click`, `jsonschema`, `exceptiongroup`,
`importlib-metadata`, and `pyjwt`. Semgrep 1.177.0 constrains `boltons`, `exceptiongroup`, `pyjwt`,
and `wcmatch`; pinned OpenTelemetry packages constrain `importlib-metadata`, `protobuf`, and
`wrapt`. These filters match dependency names across the root entry, including the same name in
`pyproject.toml`; they are not specific to the tools file. Revisit them when upgrading the scanner
roots and other pinned parents together. They use `update-types`, so security updates remain
eligible, though a security fix that conflicts with this graph needs manual whole-graph resolution.
The digests are still this script's job, and `--require-hashes` fails the build until they match.

It reads every artifact PyPI publishes for that release, keeps the ones a linux build may install
(the `any` wheels plus the linux `x86_64` and `aarch64` ones — `docker-publish.yml` builds the
images for both architectures, and an x86_64-only hash block fails `--require-hashes` on the arm64
leg alone), verifies each published digest against the downloaded wheel, and rewrites the hash
block. It refuses to write anything it could not verify, and
refuses a release that offers no installable wheel rather than letting pip fall back to building an
sdist. It needs the network, so it is an **operator** tool — the suite never runs it against the
live index (`tests/test_bump_pins.py` drives it off a canned PyPI document).

The differences between the files are deliberate:

- `.github/requirements-gate.txt` is installed with `--no-deps`, so it must list the COMPLETE
  closure (hence jsonschema's four runtime dependencies). A missing one fails loudly at import.
- `requirements-tools.txt` is also installed with `--no-deps`, and its closure is 91 packages, so
  it is not written by hand. Bandit's native SARIF formatter depends on `jschema-to-python` and
  `sarif-om`; both remain explicit in the closure because `--no-deps` will not install them. A normal
  `bump_pins.py requirements` refresh preserves every explicit pin. For a fresh dependency resolution,
  resolve the complete Semgrep, Bandit with `sarif` extra (to retain both formatter packages), and
  pip-audit roots together for Python 3.12 on both supported Linux architectures. Flat transitive
  pins must move together when upstream constraints change:
  valid hashes and a successful `--no-deps` install alone do not prove the graph is compatible.
  Update the corresponding Docker `ARG` pins when a scanner root changes. Resolve the closure with
  `uv pip compile --generate-hashes --python-version 3.12 --python-platform x86_64-unknown-linux-gnu`
  (and again for `aarch64-unknown-linux-gnu`; the two resolve to the same set today), then re-run
  `bump_pins.py requirements --file requirements-tools.txt --write` so the digests are ones this
  repo re-verified against downloaded artifacts. Build the tools image for both architectures;
  its install now runs `python3 -m pip check` to reject declared dependency conflicts, followed by
  the existing scanner smoke tests for real startup and output. Run the related Dockerfile, workflow
  pin, smoke-adapter, and bump-pins tests when changing this closure. Do NOT commit
  `uv pip compile --universal` output directly: it adds packages
  behind environment markers, and `rewrite_requirements` does not carry a marker through a rewrite,
  so a win32-only package would arrive as an unconditional pin the linux build cannot satisfy.
- `requirements-fixtures.txt` is installed without `--no-deps`, so pip resolves pytest's graph and
  `--require-hashes` turns a missing dependency into a loud install-time failure instead.

The tools image's Node closure is pinned the same way but by npm: `tools-image/node/package.json`
is the declared list and `tools-image/node/package-lock.json` the 139-package closure, regenerated
with `npm install --package-lock-only --ignore-scripts`. The image installs it with
`npm ci --ignore-scripts`, which fails rather than resolving anything if the two disagree.

`tests/test_workflow_pins.py` holds the rule: every `pip install` in `.github/workflows/*.yml` and
`Dockerfile*` either installs from a `--require-hashes` file or is on that module's
`EXEMPT_INSTALLS` list with a reason, every pin in such a file carries a `--hash=` (a `TODO-hash`
placeholder is refused), and the pinned pip may not be older than the one the runner ships.

The third door is what a workflow **downloads and then runs**, and `scripts/workflow_guard.py`
holds it. It parses shell — statements split quote-aware on `;`, `&&`, `||` and `|`, argv from
`shlex`, comments dropped and `\`-continuations, heredocs and `$(…)`/`<(…)` substitutions lifted
first — and fails the suite when a `curl`/`wget` download is made executable, interpreted,
unpacked, moved onto `PATH` or handed to an interpreter on stdin without a checksum **bound to that
path**: a `sha256sum -c` (or `shasum -a 256 -c`) whose sums list — piped in, heredoc'd, or a file an
earlier statement wrote — names the file that was fetched, carries a digest, and runs before the
first use of it. A checksum whose failure is swallowed (`… || true`, `… &`, `if ! …`) is not a
check, because `bash -e` is what makes one a gate. A fetch piped straight into a shell
(`curl … | sh`, `eval "$(curl …)"`, `bash <(curl …)`) can never satisfy the rule: there is no file
to hash, so download to a file, check it, then run it.

The scope is the **job**, not the step: a job's `run:` steps are folded in order, because they share
the workspace and `/tmp` — `curl -o /tmp/x` in one step and `chmod +x /tmp/x; /tmp/x` in the next is
one fetch-and-exec that no per-step reading can see, and a `sha256sum -c` in a later step is a real
check of an earlier step's download. A step whose `shell:` is not bash/sh (pwsh, python, cmd) is
reported **unread** rather than clean. Exemptions are `(workflow, step name, reason)` tuples on
`tests/test_workflow_pins.py`'s `EXEMPT_FETCHES`, held to the same staleness and posture checks as
the install list. Run it by hand with `python3 scripts/workflow_guard.py .github/workflows/*.yml`;
CI gets **no separate lint step**, because `tests/test_workflow_pins.py` already applies it to the
whole fleet on every PR.

## Versioning
Scheme: a **minor** bump (2.x.0) per release round; **major** (x.0.0) reserved for breaking
changes to the report schema, CLI, or grade contract. Bump `SKILL.md` `metadata.version`,
`synth.report.build_report`'s `meta.version`, and `evidence.write_verify_queue`'s payload
`version` together.

History:
- **5.1.0** (current) — measurement. 231 commits, 37 issues: the release where the
  scanner's own numbers became worth reading. The grade moves from a max-severity
  rollup that SATURATED (ten Ds and one F across eleven runs — it could not tell
  any two codebases apart) to a bounded health index that discriminates (#1473,
  #1456, #1146); `meta.cost.tokens` goes from usually-null to collected
  automatically, with a window bounded at both ends so a run's ledger reproduces
  after the fact (#1450, #1453, #1494). Grouping becomes controllable rather than
  implicit: `--max-per-group` is exposed and defaulted to 48 after a measured cap
  series (#1462, #1488), subgroups roll up to their parent in the report (#1305),
  and a chunk states its parentage instead of having it inferred from its name
  (#1480). Per-run folders (#1130) and X0X catalog-gap emission (#1132) land as
  planned; tool-aware review ships as a SEC-cell PoC (#1307) with the full
  treatment deferred to 5.2 (#1131). The tool axis is repaired end to end —
  dependency-check no longer certifies off a build file alone (#1474), a tool
  verdict is keyed to its dispatched cell rather than an echoed id (#1475), and
  the void gosec axes were re-measured rather than caveated (#1477).
  The remaining 136 fixes are self-scan remediation from runs 6-10 plus the
  calibration apparatus that made five targets measurable — including two
  pre-registered predictions, one of which failed and was recorded as failed.
- **5.0.1** — honest instrumentation. The first 5.0 point release,
  clearing the residuals from the BursarBuddy calibration and the 5.0 PR sweep.
  `meta.cost` now enumerates every driver dispatch class (#1030); the verify
  backup re-reads only its scoped files and the tool-advisor runs lighter, the
  biggest cost lever at zero coverage loss (#1029); tool coverage certifies
  against the runner's deterministic adapter manifest, not the scout's advisory
  list (#1031, #984); a nightly image keep-alive + freshness heartbeat (#1032);
  the clean-tree tamper guard reads `git status -z` and checks both rename
  endpoints (#1033); OCRDb-consumer hardening incl. a corrupt-bundle exit code,
  a `ZZZ-X0X` domainless sentinel, and the `{criteria}` advisor lens (#1034,
  #1035); `model_resolver` becomes the single owner of the claude role→model map
  (#1036); an explicit CRITICAL-vs-HIGH severity bar (#1038); and an
  `x0x-report-schema.json` for the Panopticon→OCRDb candidate-pool loop (schema
  only, emission is 5.1).
- **5.0.0** — the matrix flagship. The review pipeline is now a
  single resumable driver (`skill/scripts/driver.py`, subcommands
  `setup`/`run`/`next`) that the host drives through a status protocol:
  discovery → coverage (per-group scout + surface-gated universal floor) →
  tools → review → verify (primary + backup + per-finding tool advisors) →
  synthesize → validate. This is the 5.0.0 sequence; the current driver puts
  readiness first. The legacy orchestrator is retired (P6 collapse).
  Highlights: driver-path integrity controls wired (`dispatch-plan-driver.json`
  reconcile + `out-file-hashes.json` content snapshot, #1024); tool findings
  routed through the verify phase to reach `tool_confirmed` (#5.0-03); the
  universal floor `{COD,DAT,TST,ARC}` is gated per group on observable surface
  signals so surfaceless groups don't manufacture noise (#1025); hostile-target
  path confinement, status-protocol crash hardening, and delta/`--pr` gate
  correctness across the #1014-1027 series. Validated end-to-end against the
  BursarBuddy answer-key corpus (recall 8/11, precision 1.0, perfect decoy
  discrimination, all controls firing on a real hostile target).
- **4.3.2** — the 4.x freeze closer (5.x roadmap combined review,
  adopted 2026-08-10): `meta.cost` dispatch ledger — `{phase, role, model,
  count}` rows derived from scout profiles, the dispatch-plan union, and the
  verify queue, plus a `tokens` slot (null until a host exposes usage).
  Additive and typed in report-schema. This is the before-picture every 5.0
  economics exit criterion measures against; run-4 (2026-08-15, untouched
  4.3.x) records baseline #1. **Ledger fix (2026-08-14, surfaced BY run-4's
  self-scan):** `dispatch.build_plan` stamped `security_mode` on `lens_sweep`
  entries but omitted it from `panel_review` entries, so `plan_contract`
  flagged every plan with a panel as invalid and synthesize excluded it from
  cost derivation — silently dropping ALL fan-out rows (`panel_review` +
  `lens_sweep`) from `meta.cost` on every run. Corrected so the ledger counts
  the full fan-out. Freeze audit note: the roadmap review's three
  "run-3 confirmed HIGH" freeze items were all already resolved on main
  (README --mode/--target syntax gone, FindSecBugs jar SHA-256-pinned per
  #539, #513 CI posture ruled intentional in security.yml) — the freeze
  reduced to this ledger. 4.x is now CLOSED to features; 5.x sequencing:
  5.0 = driver state machine + verify-phase redesign + OCRDb identity spine
  (feature-flagged by bundle presence), 5.1 = trends + panel evolution +
  trust chain + incremental runs + panel collapsing, 5.2 = reach.
  **OCRDb prerequisite met (2026-08-11):** the identity-spine catalog
  shipped as OCRDb v0.2.0 (7 domains, 357 single-homed codes, tagged +
  released), with Gate A assignment-stability recorded. The
  4.x-freeze → OCRDb → 5.x work order now clears 5.x to begin (Track 1
  first); run-4 (2026-08-15) still records cost baseline #1 before any
  5.0 economics work merges.
- **4.3.1** — external-review point release (first outside audit,
  Gemini Pro 3.1, triaged claim-by-claim against the tree). Path-variant
  clustering: `evidence.norm_path` becomes the sole owner of finding-path
  normalization and `dedupe`/`cross_panel_corroboration`/
  `aggregate_tool_findings` key on it, so `./`-prefix or backslash dressing
  from one emitter can no longer split a cluster and cost a finding its
  reinforcement (#977). Delta discovery's changed-file diff gains
  `--find-renames` for rename-semantics parity with `diff_map.hunk_map`
  (#978). Un-loadable verdicts now count as a gate-relevant coverage gap in
  `certify`: a PASS with lost verdicts reads `INCONCLUSIVE` (#979).
- **4.3.0** — 4.x series wrap. Codex host support: `codex` host in
  model-profiles (gpt-5.6-luna/terra per role with reasoning-effort levels),
  `--emit-host-agents codex`, dispatch/model-resolver/orchestrator wiring +
  codex-runner tests; `meta.integrity.empty_dispatch_plans` joins the
  certification gate. Ships on top of the issue-clearing sprint (2026-08-09/10,
  404 open issues -> the 4 tech-debt epics): PR/branch delta review with loud-fail
  base anchors (#449), trustworthy cross-run reconcile identity + safety-first
  close gate (#914), fixture/tool noise precision (#946), verdict-loss and
  comment-injection hardening (#938/#953), write-guard absolute out_files
  (#935), plan-integrity re-verification + hash-bound acks + out-file content
  hashing (#493), coverage-honest HTML (#490), scout/reviewer scope contracts
  (#431/#441), doc-severity policy (#487), config-declared gh account (#486),
  `--setup` readiness gate (#485), installed-flow coherence (#495).
- **4.2.0** — tool-policy enforcement: uniform read-only/return-JSON
  role contracts; `--emit-host-agents` generates registered enforcement shells
  (claude/kimi dialects) from the host-neutral templates; per-role `enforced`
  plan entries dispatched via `subagent_type`; `meta.coverage.tool_policy_mode`
  (enforced/advisory/mixed/unknown) in the audit artifact; clean-tree check in the
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
- **3.0.0** — Kimi port: introduces architecture, database, and redteam panels;
  replaces the fixed 9-lens catalog with a flexible lens model; rewrites orchestration for the
  Kimi Code agent platform; major version bump reflecting breaking changes to the skill contract.
- **2.3.0** — cross-dogfood round from a 61-panel run against a real 3-repo estate. Four
  fixes: (1) **cross-panel corroboration** — `synthesize` now runs a distinct agent-vs-agent pass
  (`cross_panel_corroboration`, keyed on file + line-proximity across DISTINCT panels, not category)
  that populates the previously-always-empty `cross_panel.integration_findings` and annotates
  `corroborated`/`corroborated_by` + a confidence bump, without collapsing the distinct lenses;
  extends the round-3 tool+agent dead-branch to agent+agent. (2) **discovery** —
  `discovery.discover_repo_files` (os.walk + prune; originally `orchestrator.discover_repo_files`,
  the module was later extracted to `discovery.py`) excludes noise (`tmp`/venv/`__pycache__`/
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
  and `orchestrator.main()` coverage for `--group`/`--files`/`--repo-scan` (now `discovery.main()`,
  since the module was extracted to `discovery.py`). **138 tests (was 125).**

  **Note on the treadmill:** each ruthless self-scan clears the prior MEDIUMs and surfaces a fresh,
  narrower batch (CRITICAL→HIGH→broad-MEDIUM→coverage-MEDIUM). We stopped at B by decision: all known
  MEDIUM+ are fixed and the code/security surfaces are clean; the residual LOW/INFO are logged below.
  Chasing empirical A/B round-by-round against our own reviewer does not obviously terminate.
- **2.2.0** — accumulated bug-fix round from the self-review + an internal-app dogfood: repo-root
  clamp (CWE-22), docker-run timeout, catalog tolerance, SARIF path-normalization + per-result
  tolerance, cross-source reinforce (2-member tool+agent), citations hardening (case-insensitive
  ids, CWE-95, EPSS size-cap/UA), DoS guards, bandit noise floor, id-uniqueness + panel label,
  `--max-per-group` guard, docstrings, and test-coverage for the non-deterministic seams.
- **2.1.0** — bug-fix round: must-fixes surfaced by the build's review gates and the
  live real-tool smoke.
- **2.0.0** — static-analysis upgrade: standards citations (CWE/OWASP/SSVC/EPSS) + the Docker
  tool container.

### B-floor residuals (LOW/INFO from self-scan round 4 — future minors)
- Schema validation is advisory-only: an invalid report still writes + prints (by design; revisit if a
  strict mode is wanted). `gosec` is invoked with `./...` against a `/src` mount (relies on container cwd).
- `--file`/`--files` echo explicit paths verbatim and bypass the `_within` repo-confinement clamp that
  glob-derived scope gets (still 2.2.x backlog; low real risk on a local dev CLI over a trusted repo).
- SARIF-derived paths are rendered into the markdown summary without escaping (display-only; not opened).
- `test_related_tests_found` doesn't assert the nested-match it names. Bandit `B404`/`B110`/`B112`
  (subprocess import + tolerant loops) are noise-floor and are now suppressed via
  `sarif_utils.NOISE_RULES`; `B603`/`B607` are kept as a tool-layer backstop for panel-less runs.

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

### From an internal-app dogfood run (2026-07-23) — tool↔fleet integration (2.2.0)
- **Tool noise floor**: bandit emitted 579 `B101` "assert used" findings from `tests/` on one run.
  Add a noise filter — skip `tests/` for SAST, drop `B101`, and/or a LOW-severity floor for tool findings.
- **Normalize SARIF paths**: `ingest_tools` keeps the raw `artifactLocation.uri` (`file:///src/...`);
  strip the `file://` scheme and the `/src/` container-mount prefix so tool paths match the agents'
  package-relative paths.
- **Cross-source reinforce is effectively dead**: `dedupe` keys on `(file, line_start, category)`,
  but tool rule-ids ≠ agent lens categories and tool paths carry `/src/` — so an identical tool+agent
  finding (observed: the CSRF finding whose tool path carried the `/src/` prefix) never merges. Fix the path
  normalization above AND match on `(file, line)` with looser/optional category (or map ruleId→lens).

### From Panopticon's self-review (2026-07-23) — graded itself F/CRITICAL, 24 findings
Correctness/security (do first):
- **Path-traversal / scope escape** (code+security both flagged, CWE-22): `expand_patterns` + catalog globs can escape the repo root via `..` or absolute paths (originally `orchestrator.py:154`; the module is retired — see `discovery.py`'s equivalent). Clamp resolved paths under the repo root.
- **No docker-run subprocess timeout** (`run_tools.py:60`): a hung/slow tool blocks the pipeline forever. Add a per-run timeout.
- **`load_catalog` only catches `ImportError`** (originally `orchestrator.py:135`; the module is retired — see `discovery.py`'s equivalent): a malformed `groups.yml` crashes with a raw traceback when PyYAML is installed. Catch parse errors too.
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
