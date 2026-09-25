# Changelog

## Unreleased — 5.2 Claude first-class host (#1344, family PR)

The Claude family's first-class-host PR under `docs/FAMILY-PR-GUARDRAILS.md`:
Claude already shipped its runner, probes, emit branch, registry row and both
guards, so this PR is the evidence a real `driver loop` gives, plus what that
evidence exposed.

- **`--max-budget-usd` is re-read after every entry, not once per checkpoint (#1760,
  AGT-4265600920).** The cap was compared with the ledger exactly once per loop iteration, at the
  top and ahead of arming — and a checkpoint is ONE batch, so a whole review round (every pending
  cell, each charged at dispatch) launched before the cap was looked at a second time, where the
  guide promises launching stops once the ledger's cumulative reported cost crosses it. It is now
  the batch's THIRD stop rule, beside the host-outage and identical-launch-failure ones (#1721,
  #1732): the queue is cancelled the moment the ledger reaches the cap, whatever is already in
  flight drains, persists and is charged as usual, and the run still ends on the same terminal
  `--max-budget-usd X reached` error one iteration later, off the same gate and the same ledger. So
  the overshoot falls from the whole checkpoint to the pool — up to `--concurrency` launches
  already in flight, plus the one worker that can turn over while the loop is still ledgering the
  result that reached the cap, which is the bound an outage has. The predicate fails CLOSED on a
  ledger line whose cost cannot be read as money, because `iter_batch` reads a `stop` that raises
  as "carry on" — #1648's fail-open one level down. **Operator-visible:** the batch's stderr line
  names the rule that stopped it as `the --max-budget-usd cap`, where a cap used to be rendered as
  "0 host-class failure(s)" — a host to go and wait out.
- **The guide now says where the second witness is spent (#1759, AGT-1456823651 /
  AGT-381210818).** A REJECTED advisor verdict was always settled by one advisor — the
  adversarial backup round is summoned only for primary-CONFIRMED findings in categories at or
  above `score_gate.BACKUP_FLOOR`, and the tool axis has no backup round at all — but the
  evidence chapter never stated the asymmetry or why it is deliberate. It does now, beside the
  sentence that says rejected claims keep their full advisor prose in `discarded_claims`.
- **A batch record names its MACHINE, and one record can be discarded without
  the run (#1912).** The owner stamp that `driver loop` recovers a crashed batch
  from carried the pid and `socket.gethostname()`, and a hostname is not a machine
  identity: on macOS the same laptop answers `mac.local`, `mac.lan` or a
  DHCP-assigned name depending on the network it woke up on, so a crash and the
  resume after it saw two different names — the resume read its own record as
  another machine's and offered `--reset`, the whole run of paid cells, as the
  only way forward. The record now carries a hardware machine id
  (`uuid.getnode()`, absent when that function falls back to its random
  multicast value) beside the hostname, and either id matching means this
  machine; a record from before the field, or one whose field is unusable, is
  judged by its hostname exactly as before. Comparing the first DNS label is
  deliberately NOT done — this repo lives on a mounted volume, so `mac.office`
  and `mac.home` really can be two machines sharing one run folder.
  **Operator-visible:** `driver loop --discard-batch N` is a new, narrow remedy
  for the two refusals that mean "the liveness question could not be answered"
  (another machine / no owner stamp). After confirming no other loop is working
  on the folder, it gives record `batch-N.json` exactly the rollback a dead
  owner's gets — artifacts deleted, entries ledgered as cancelled/rolled back,
  attempts refunded, record unlinked — and the invocation carries on with the
  rest of the run. It applies to that one number: a live owner still refuses (no
  flag can help), a dead one needs no acceptance, a second unreadable record
  still refuses, and an absent one is an error naming the folder. Both refusals
  now name `--discard-batch N` first and `--reset` second, the acceptance is
  recorded in `discarded-batches.json` in the run folder (with the owner stamp as
  found) and counted on the run manifest, and `--discard-batch` with `--reset` is
  refused as contradictory.
- **An unenforced claude launch now denies the tools a reviewer must not hold
  (#1753, AGT-4053314873).** An `--agent` launch lands in a registered shell
  whose `tools:` frontmatter the host enforces; the `--model` fall-through
  binds no shell, and `--setting-sources user` deliberately keeps the
  OPERATOR's user-scope `permissions.allow` — so a `Bash(*)` convenience rule
  in the operator's own settings reached a reviewer whose job is reading
  hostile content. That argv now carries
  `runners/claude.UNENFORCED_DENIED_TOOLS` — 24 names, grouped by what each
  would hand a reviewer: code execution, delegation, egress and off-machine
  publication, the write tools no reviewer role is granted, and the two
  read tools its `Read|Grep|Glob` matcher never sees — and deny rules beat
  allow rules, which is the point. **Measured on 2.1.276, and the reason for
  the `=` form:** `--disallowedTools` is VARIADIC, so the space form eats every
  following non-flag token including the prompt — `claude -p --output-format
  json --max-turns 2 --disallowedTools Bash "<prompt>"` exits 1 with no
  envelope and "Input must be provided either through stdin or as a prompt
  argument" — while `--disallowedTools=Bash,Glob "<prompt>"` runs and the
  reviewer reports "I have Read available; Bash and Glob are not in my current
  tool set". One token cannot swallow a neighbour, wherever it is placed. The
  ENFORCED argv is byte-identical to before: it is measured behaviour and its
  shell is already the control. **Residual:** a tool name this list has not
  heard of that the operator has allowed at user scope — a CLI upgrade is how
  one arrives. MCP tools are not part of it, since the same argv passes
  `--strict-mcp-config` with no `--mcp-config`.
- **`driver setup` refuses an unenforceable setup-scan (#1737, AGT-B1D).** The
  one dispatch that reads the whole untrusted tree was the only role with no
  registered shell: its tool grant was whatever the host hands a
  general-purpose agent, and the template's `Read, Grep, Glob` travelled as
  advisory prose in the brief. `setup_scan` is a driver role now, so
  `--emit-host-agents` writes `panopticon-setup-scan` for every host that
  registers shells (tools `Read, Grep, Glob`; **no bound model** — the
  session's own model runs the classification, R-F4-2), `registered-shell-tools`
  proves it grants no Bash, and the `scan` checkpoint dispatches that shell and
  only that one. `enforced` is derived from this invocation's measured posture
  like every other dispatch, and both entrypoints — `driver setup` as much as
  `driver loop --setup` — probe the host for themselves before the gate reads
  the evidence. **Operator-visible:** on a machine that has not registered its
  shells, `driver setup` now stops and names two remedies —
  `python3 skill/scripts/dispatch.py --emit-host-agents <host>` (the fix) or
  `--allow-unenforced` (the acceptance, recorded in
  `.panopticon/setup-unenforced-ack.json` and discarded once the posture
  proves enforcement). Registering the shells is a one-time step; until it is
  done `tool_policy_enforced` reads REFUTED for review runs too, which is the
  registry honestly reporting itself incomplete. The refusal names the remedy
  that can actually change the answer: emitting shells where the capability is
  REFUTED, and `driver loop --setup --host <h> --mode headless` where nothing
  measured it at all — on Codex that is the ONLY invocation that can, since its
  tool-policy probe needs a headless settings path and `driver setup` has no
  `--mode`. Probing costs no paid turn and, Kimi's `kimi --version` and `kimi doctor` reads aside,
  launches no host CLI at all: everything `driver setup` measures is a
  filesystem read.
- **`usage_ledger` follows the mode.** The probe is now `usage-source` (was
  `transcript-dir`): in headless mode it measures the launch envelope path —
  a run folder that can hold `dispatch-ledger.jsonl`, the host CLI on PATH,
  that CLI's `--help` advertising the runner's own `ENVELOPE_FLAGS` (`-p`,
  `--output-format`; an executable merely named `claude` is refuted), and,
  once launches are ledgered, their envelopes having carried usage — and never
  consults transcripts; in session mode it measures the session's transcript
  directory exactly as before. A headless run launched from any directory
  without transcripts (every fresh target) used to be *refuted* while its
  ledger was exact. The `--help` interrogation goes through the runner's own
  launcher, the seam the suite refuses real launches at.
  `runners.base.LEDGER_FILE` is the one owner of the ledger's name (the
  `Ledger` and `usage.json`'s `source` both read it); the remedy line names
  both modes' fixes.
- **`driver loop --reset` resets once.** The flag reached `driver.run` on every
  iteration, so each one cleared the run folder and re-minted the manifest and
  the loop re-launched its first checkpoint until `--max-iterations` (this
  branch's second real run: the same three scouts ten times). The first call
  consumes it.
- **`prompt_file` is granted to the entry's read scope.** The guide let a host
  point an agent at `prompt_file` (marker line first, pointer second), but every
  entry's `scope.reads` was empty, so the read guard denied the agent its own
  prompt. Stamping the file now grants it through `reads`.
- **The SEC cell may read the checklist its prompt points at.** The first real
  headless run's ledger recorded the SEC reviewer's Read of
  `skill/reference/security-checklists.md` as a denial: the prompt named the
  file, the scope did not. `review._cell_reads` grants it through `reads`,
  from the one path the pointer is rendered from.
- **Session-mode dispatch on Claude Code is templated.** `skill/workflows/dispatch.js`
  runs one workflow subagent per pending entry — inside its registered shell
  when the entry is enforced, on the entry's model otherwise — marker line
  first, and returns replies keyed by id, a skipped or dead subagent under
  `missing`; SKILL.md mandates it over one-off Agent calls. The read-guard
  probe's round trip now also binds a fake subagent through the Workflow
  transcript layout (16 rows).
- **The suite refuses the real `claude` binary by default.**
  `runners.claude.DEFAULT_RUNNER` is read at construction and `tests/conftest.py`
  swaps it for a refusal on every test (was per-test discipline; #1616); only a
  launcher a test injects explicitly runs, and none injects the real one. The
  same file now also points `HOME` at one throwaway directory for the whole
  process, before the registry expands `~`, so no probe or test reads the
  operator's real `~/.claude`.
- **`Glob`'s pattern is adjudicated (#1917).** Both read guards decided a
  `Glob` on its `path` alone, and the pattern is a PATH pattern expanded
  against it, so `Glob(path=<granted dir>, pattern="../Src/*")` could name
  entries outside the `dirs` grant — names, not content, since a following
  `Read` still meets the per-file rule, but it was the one read primitive whose
  second argument nothing looked at. Over a granted directory a pattern that is
  absent, empty, non-string, absolute, `~`-rooted or holds a `..` segment is now
  denied. `Grep`'s pattern is a regex over content and stays unadjudicated.
- **In-tree hard links keep their directory `Grep` (#1917).** The walk behind a
  directory read grant recorded every regular file with `st_nlink > 1`, so a
  `cp -al` fixture or a pnpm store — whose links all sit inside the review
  root, naming content the grant already covers — denied every directory
  `Grep`/`Glob` above it for nothing. It now counts the in-tree names of each
  inode and records a file only when its link count EXCEEDS them. A `git clone
  --local` target is deliberately NOT cleared: its links name the source
  repository's objects, it still overflows the cap and still loses its
  directory `Grep`, with `--no-hardlinks` named on stderr as the remedy.
  **Operator-visible:** the walk is now always complete (the count is only
  known at the end), so `CAP` bounds the findings rather than the files walked.
- **`read-guard-armed` measures the planted hard link (#1917).** The Claude
  readiness probe now does what the Codex one has done since #1642: it plants a
  hard link inside a directory grant naming a file outside it, records it with
  the driver's own walker, and requires the directory `Grep` to be refused **by
  the hard-link rule** rather than merely denied. A volume that cannot plant a
  link — or that plants one and then reports `st_nlink=1`, as some FUSE and
  network mounts do — makes that sub-check `unknown` instead of refuting a
  healthy host.
- **The guide is an index plus one chapter per section.**
  `skill/docs/PANOPTICON.md` keeps Overview, Required sub-skills, Modes and
  Global flags plus a Contents list; each H2 lives in `skill/docs/guide/`
  (`docs/guide` is symlinked onto it), wrapped at 100 columns with no prose
  changed. `driver readiness`'s `guide` row is true only when every chapter
  file is present (`hosts.guide_documents()`), and its remedy names the
  missing ones.

## Unreleased — 5.2 grouping engine, plan 1

Setup now front-loads the grouping work so every later run reuses it
(spec: panopticon-docs `superpowers/specs/2026-09-06-panopticon-5.2-grouping-engine-design.md`).

- **Catalogs, full prose:** the capability roster grows from the R1 13 to 45
  entries harvested from the 5.2.0 vocab panel (>= 10 repos each), every entry
  carrying `definition`/`boundary`/`aliases`/`examples`; a 9-entry **layer**
  catalog (`layer_vocabulary.yml`) for splitting one oversize vertical; a
  `tests_catalog.yml` for the test-tree seeds. Both catalogs render into the
  setup-scan brief in full — the calibrated prose finally reaches the
  classifier (#1500). Proposed labels normalize through aliases. The reserved
  names `Tests`, `Commons`, `Ungrouped` and `Core` may not be catalog entries,
  aliases, or proposed layers; a proposal may name a `Tests` group (a committed
  `Tests` suppresses the run-time sweep) but not `Commons` or `Ungrouped`,
  which the engine mints.
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
- **Setup engine fixes (from the first 5.2 self-scan, run-11):** the ceiling
  budgets CODE leaves only — `Tests` and the Commons categories hold exactly
  the files its numerator subtracts, so charging them to it made any repo of
  <= 96 code files with two verticals "over ceiling" by construction and told
  the owner to merge verticals (#1506). `chunk_files` packs to decided sizes,
  so an oversize group splits into exactly `ceil(files / cap)` near-equal
  chunks whatever its directory shape — it used to emit a phantom cell, and a
  starved trailing chunk, depending only on directory names (#1503). The
  Commons `CI` category claims the top level of `.github` (`*.yml`, `*.yaml`,
  `*.sh`, `*.json`), so `labels.yml` and friends stop reading as a catalog
  coverage gap (#1508). Globs: a trailing-slash directory pattern (`docs/`)
  now compiles as gitignore reads it instead of silently matching nothing,
  and a character class (`*.[ch]`) is refused at validation time instead of
  being escaped into a literal that claims the wrong files (#1501).
- **Tests axis:** a vertical's wildcard `tests` glob is scoped (under its
  `match` dirs or naming the vertical/an alias); the cross-cutting test trees
  form a `Tests` group last, at run time, from the leftovers.
- **Stage 1 spine:** `setup-spine.json` — depth-2 tree, languages, manifests
  and frameworks, already-claimed counts, test trees and the size arithmetic,
  bounded and sanitized (#1120) — is computed once with the sizes pinned in
  `setup-manifest.json` and rendered into the brief.
- **Compatibility (5.1 -> 5.2):** the `groups.yml` schema is unchanged and a
  5.1 setup proposal still validates; re-running `driver setup` is optional
  and never overwrites a committed `groups.yml`. Three run-time behaviours DO
  change without re-running setup: a wildcard `tests:` glob (`**/*_test.go`)
  is scoped to the vertical's own directories and files that name it (the
  files it used to credit elsewhere are reported once, to stderr and
  `scoped_tests_warnings`); leftover test-tree files sweep into a `Tests`
  group; a committed `Tests` (or `Tests:*`) suppresses that sweep. Escape
  hatch when the old crediting was intended: move the glob from `tests:` to
  `match:`.
- Deferred: `driver run --max-per-group` still chunks at run time and does
  not read `config.json`; the durable profile (`profiles.yml`) and the scout
  short-circuit, and `--seats` calibration, are plan 2.

## 5.1.0 — Measurement

The release where the scanner's own numbers became worth reading. 231 commits,
37 issues.

- **A grade that discriminates:** the max-severity rollup had SATURATED — ten Ds
  and one F across eleven runs, unable to tell any two codebases apart. It is
  replaced by a bounded health index (#1473, #1456, #1146).
- **A cost ledger that reproduces:** `meta.cost.tokens` goes from usually-null to
  collected automatically, over a window bounded at BOTH ends, so a run's ledger
  still reproduces after the fact (#1450, #1453, #1494).
- **Grouping becomes controllable rather than implicit:** `--max-per-group` is
  exposed and defaulted to 48 after a measured cap series (#1462, #1488),
  subgroups roll up to their parent in the report (#1305), and a chunk states its
  parentage instead of having it inferred from its name (#1480).
- **Per-run folders** (#1130) and **X0X catalog-gap emission** (#1132) land as
  planned. Tool-aware review ships as a SEC-cell proof of concept (#1307); the
  full treatment is deferred to 5.2 (#1131).
- **The tool axis is repaired end to end:** dependency-check no longer certifies
  off a build file alone (#1474), a tool verdict is keyed to its dispatched cell
  rather than an echoed id (#1475), and the void gosec axes were re-measured
  rather than caveated (#1477).
- **The remaining 136 fixes** are self-scan remediation from runs 6-10, plus the
  calibration apparatus that made five targets measurable — including two
  pre-registered predictions, one of which failed and was recorded as failed.

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
