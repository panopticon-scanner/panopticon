---
name: panopticon
description: Use when reviewing code, pull requests, branches, security posture, test quality, architecture, or database surfaces in a codebase
type: prompt
whenToUse: When reviewing code, pull requests, branches, security posture, test quality, architecture, or database surfaces in a codebase
arguments:
  - target
  - mode
  - security
  - out
disableModelInvocation: false
license: MIT
metadata:
  version: "4.3.2"
---

# panopticon

## Overview
Discovery → scout → fan-out → synthesis code review. Profiles a target, groups files, dispatches specialized reviewers in parallel, and synthesizes a validated CodeReviewReport with CI gating.

## Required sub-skills
- `superpowers:writing-plans` — before repo/PR/directory reviews with >15 files or >10 changes.
- `superpowers:subagent-driven-development` — for panel and lens dispatch.
- `superpowers:verification-before-completion` — before returning the report.

## Modes
Use `AskUserQuestion` when the target is ambiguous. `driver run [target]` is the entrypoint for every mode below — see Driver run-loop (5.0) for the execution loop.
- *(no scope flag)* — whole-repo committed-matrix review, driven by `.panopticon/groups.yml` (produced by `driver setup`).
- `-f <path>` / `--file <path>` — single-file scope.
- `-d <dir>` / `--directory <dir>` — directory scope.
- `-g <name>` / `--group <name>` — one committed group.
- `-c` / `--changes` — delta vs base (`--base <ref|sha>`; default main→master); diffs the live working tree, uncommitted changes included. An unresolvable base fails loudly — there is no `HEAD~1` fallback.
- `--pr <n>` — review a GitHub PR inside an isolated, disposable `git worktree` (never touches your checkout); the driver resolves the worktree once and runs every phase natively inside it (no separate staging step), releasing it on completion (`diff_map.release_worktree`) — a PR review is committed-only. Both `-c` and `--pr` emit `.panopticon/diff-hunks.json`. **Pass `--fail-on` or the gate stays OFF** — a delta run is gate-first by intent.
- `driver setup [target]` — one-time bootstrap: proposes `.panopticon/groups.yml.draft`. See Driver setup (5.0) below.

## Global flags
`--full` (force all panels), `--security {standard,redteam}` (default standard), `--fail-on {critical,high,medium,low}`, `--severity {all,medium,high,critical}` (report only findings at or above the threshold), `--out PATH`, `--tools` (require tool scan), `--no-tools` (skip tool scan), `--epss` (enrich CVE citations), `--gate-unverified` (unverified findings drive grades/gate), `--max-verify N` (cap the verify queue; PR-scale delta reviews queue EVERY finding incl. tool claims -- a 25-file PR queued 108 advisors -- so size N ~ 2x the changed-file count unless you want the full sweep), `--base <ref|sha>` (explicit delta base for `-c`/`--pr`/`--files`), `--diff-context N` (default 5; on-diff tolerance in lines), `--gate-scope {on-diff,all}` (default `on-diff` for delta reviews; scopes the gate to on-diff × gate-eligible findings), `--include-fixtures` (keep tool findings under test-fixture corpora; default prunes them for parity with the standard-mode review prune — pass for redteam self-scans), `--tools-exclude GLOB` (drop tool findings whose path matches GLOB; repeatable, for additional non-fixture paths), `--doc-paths GLOB` (doc-tree globs for the planning-doc severity policy; in standard mode, non-secret code findings under doc trees are soft-downgraded to INFO -- secrets keep severity, redteam bypasses entirely, and every downgrade is disclosed at `meta.coverage.doc_policy`). `--base` on `--files` makes it an explicit delta request — plain `--files` (no `--base`) is a normal whole-file review and emits no delta artifact.

## Driver run-loop (5.0)

The 5.0 driver (`skill/scripts/driver.py`) runs every mode from Modes above — whole-repo committed-matrix review, `-f`/`-d`/`-g` scope, `-c`/`--pr` delta — as one resumable state machine; the host drives it through its status protocol.

**Installed-flow substitution (#495):** `skill/` in every command below means THIS SKILL'S INSTALL DIRECTORY — literally `skill/` inside the panopticon repo, or the absolute path you installed it to elsewhere (e.g. `~/.claude/skills/panopticon/`). Run every command from the TARGET repo root regardless — `.panopticon/` artifacts and the write-guard resolve against cwd; only the script path substitutes.

Loop:
1. Run `python3 skill/scripts/driver.py run <target> --host claude [flags]` from the TARGET repo root. It advances to the first not-done phase and prints one status JSON line: `complete`, `error`, or `checkpoint`.
2. `complete` → done; the report is at `.panopticon/report.json` (gate = `summary.gate`). `error` → stop and surface `message`.
3. `checkpoint` → read `.panopticon/dispatch-request.json` (via `driver.load_dispatch_request`). It carries `entries` (host-agnostic: `id`/`agent`/`enforced`/`model`/`prompt`/`out_file`) — each entry is a unit of work to dispatch: a per-group scout, or a `(domain, group)` review/verify cell. Then **re-invoke `driver run`** (step 1) — the cursor is recomputed from disk every invocation, so the loop resumes identically after a crash/compaction, and each phase re-emits only its still-pending cells.

Phases run in order — `discovery` → `coverage` → `tools` → `review` → `verify` → `synthesize` → `validate`:
- **`discovery`** — `discovery.py --repo-scan` writes `.panopticon/groups.json` against the committed `groups.yml`; delta scopes (`-c`/`--pr`/`--base`) additionally write `.panopticon/diff-hunks.json`.
- **`coverage`** — one `scout` checkpoint per group (below), then widens that group's floor panels by the scout's valid domains.
- **`tools`** — deterministic, not discretionary: runs `python3 skill/scripts/run_tools.py --target . --out .panopticon/tools --deps` unless `--no-tools` was passed; a skip is never silent — it's always recorded in `tools-ran.json` and surfaced in the phase status message, and a no-output / Docker-absent skip additionally writes LOUDLY to stderr. Standard mode prunes tool findings under fixture-corpus paths by default (tool-path parity with the review-side prune, #434); `--include-fixtures` keeps them for a redteam self-scan.
- **`review`** / **`verify`** — the guard-confined self-write fan-out below, one checkpoint per pending `(domain, group)` cell.
- **`synthesize`** — runs `skill/scripts/synthesize.py --verdicts-dir .panopticon/verdicts` (`--tools-dir .panopticon/tools` added when `tools` produced output; `--diff-hunks .panopticon/diff-hunks.json` added when `discovery` emitted it) → `.panopticon/report.json`. SARIF is ingested via `skill/scripts/ingest_tools.py`, but only because `--tools-dir` was passed — a scan that ran but was never wired in would sit on disk un-ingested. Every report also carries `meta.cost` — the run's dispatch ledger, derived from the artifacts already on disk (scout profiles, the checkpoint entries, the verify queue), one `{phase, role, model, count}` row per dispatch class, plus a `tokens` slot that stays null until a host exposes per-dispatch usage — never hand-assemble it.
- **`validate`** — captures a `git status --porcelain` baseline (`.panopticon/tree-baseline.txt`) at run start and diffs it here; any new change outside `.panopticon/` fails the phase (`status: error`) — treat the run as compromised: discard the findings, inspect the flagged paths, re-run.

At a `scout` checkpoint (one entry per group, the run's first checkpoint), the scout is **read-only** and RETURNS a ScopeProfile — dispatch it (`enforced` → `subagent_type: entry["agent"]` (`panopticon-scout`, from the `skill/agents/scout.md` template); else general-purpose) and write its returned JSON to the entry's `out_file` (`scout-<group>.json`) after confirming it parses. No write-guard here — nothing self-writes. The guard-confined **self-write** fan-out below applies to `review` and `verify` checkpoints (whose reviewers/advisors write their own `out_file`).

Fan-out (per checkpoint) — ONE mechanism for review and verify:
- Install the write-guard from the request's entries, from the session root (not the worktree, for `--pr` runs — hook registration is session-rooted): `write_guard_hook.install(req["entries"])` — it confines every dispatched agent's Write to exactly the `out_file`s the entries declare.
- Dispatch one agent per entry: `enforced` → `subagent_type: entry["agent"]` (a registered `panopticon-*` shell, tools+model host-enforced); else general-purpose with `entry["prompt"]` and the model named by `entry["model"]` (omit when null). Each reviewer/advisor **self-writes** its own `entry["out_file"]` (a findings file for review, a verdict bundle for verify) and returns a one-line confirmation — findings/verdicts never transit the controller.
- Uninstall the guard after the fan-out (`write_guard_hook.uninstall()`) — it is **fail-closed while registered**: an absent, unreadable, or malformed allowlist DENIES guarded writes with a loud reason instead of silently allowing them.
- **Claude host (mechanical):** run the fan-out as a deterministic Workflow — one agent per entry, concurrency-bounded and journaled, re-running a stalled entry itself; the parent session receives only the tally.
- **generic host (portable):** the same contract without the Workflow — a nested per-group sub-orchestrator (or per-entry dispatch) holding scoped Write, dispatching pending-only, returning a tally. Any non-Claude host (Kimi, Codex, a bare CLI session) uses this path today — `driver run --host` accepts only `claude`/`generic`.

A malformed self-write fails its done-predicate (`_cell_done` / `_verify_cell_done`) so the cell reads as not-done and is re-dispatched on the next `driver run` — no corrupt findings/verdict silently lands. Register the enforcement shells once with `python3 skill/scripts/dispatch.py --emit-host-agents claude` (or `kimi`/`codex`; `--agents-dir DIR` for a non-default registration path). This also registers the legacy `panopticon-advisor` (`skill/agents/advisor.md`) and `panel_review`/`lens_sweep` roles that `driver run` doesn't currently dispatch (it uses `domain-panel.md`/`domain-advisor.md` instead); the legacy role's own prompt renderer (`dispatch.py --render-advisor`) still pins `Repo root: <path>` (#975) for its own, non-driver callers.

## Driver setup (5.0)

`driver setup [target]` runs the one-time bootstrap that proposes the capability `groups.yml`, as a separate two-phase flow on the same status protocol as `driver run` (it never runs during a review):
1. **scan** — provisions `.panopticon/` (`.gitignore` + `config.json`), renders the setup-scan brief, and emits a `scan` **checkpoint** naming the read-only `setup-scan` agent. Dispatch it exactly like `scout` (**return-persist**: dispatch, then write the returned proposal JSON to the entry's `out_file`, `.panopticon/setup-proposal.json`).
2. **ingest** — on re-invoke, the driver assembles the proposal (deterministic affinity floors), additive-merges it against any committed `groups.yml`, and writes `.panopticon/groups.yml.draft` → `complete`.

Setup writes a **draft**: review `.panopticon/groups.yml.draft`, move it to `.panopticon/groups.yml`, and commit it (setup never overwrites a committed file). A repo with no capability vocabulary falls back to a flat top-dir seed + a readiness gate and completes without a checkpoint. `driver setup --reset` clears the setup artifacts and starts over.

## Output
Terminal markdown summary + JSON artifact at `--out`. CI gate key: `summary.gate` (`PASS` / `FAIL` / `OFF` / `INCONCLUSIVE`). `INCONCLUSIVE` means gate-relevant coverage did not complete (a high-value panel ran partial, a scout-requested tool produced no output, or an undeclared findings file appeared (integrity)) — treat it as NOT certified, distinct from a real `FAIL`. `summary.coverage_certified` and `meta.coverage.divergence` carry the detail; `main` exits `1` on FAIL, `2` on INCONCLUSIVE, `0` otherwise. Exit `2` is also argparse's usage-error code; a genuine INCONCLUSIVE run still writes a full report artifact, whereas a usage error does not, so disambiguate the two by checking whether the report exists. Consumers should key certification on `summary.gate` and `summary.coverage_certified`, not on `overall_grade` alone — a tool-only coverage gap yields `INCONCLUSIVE` with a real grade still attached. When `meta.coverage.resume` shows pending work in either phase, the terminal summary also prints a `**Resume:**` line (fan-out/verify done vs. total) directly under the Grade/Gate line; a fully-complete or resume-absent run prints no such line, so a resumed run never reads as a fresh full scan.

## Testing scanner fixtures (optional)
Panopticon includes a local Docker-based fixture suite for validating scanner adapters against intentionally vulnerable applications.

```bash
# Use existing fixtures image
python3 skill/scripts/run_fixture_tests.py

# Force rebuild (clones latest public fixtures)
python3 skill/scripts/run_fixture_tests.py --rebuild

# Run only one language/test target
python3 skill/scripts/run_fixture_tests.py --test rust
```

This is optional and not part of CI. Rebuild the image periodically to pull updated fixtures.

## Evidence

Findings carry two independent axes: **severity** (impact if true — never rewritten) and **evidence.status** (how hard the claim was verified):
- `tool_reported` — a static-analysis tool emitted it (or a tool+agent same-locus merge did); no advisor has checked it. NOT gate-eligible.
- `tool_confirmed` — a tool reported it AND an advisor independently confirmed it. Gate-eligible.
- `advisor_confirmed` / `rejected` / `needs_more_info` — advisor verdicts from the verify phase. Rejected claims keep their severity and move to `discarded_claims`. A verdict that lands unloadable (a parse/schema failure surfaced at `meta.coverage.verdicts.unloadable`, never silently dropped) and forces `INCONCLUSIVE` — lost verify coverage never certifies a clean gate (#979).
- `corroborated` — multi-panel agreement (correlated witnesses: prioritized for verification, not gate-eligible by default).
- `unverified` — no verification attempted.

Grades and the CI gate count `tool_confirmed`/`advisor_confirmed` findings only — i.e. only claims an advisor verified, whatever their source. Run a verify phase (or pass `--gate-unverified`) or the gate has nothing to fail on.

Every finding queues for verification, tool claims included, so `--max-verify N` now caps a queue holding the whole finding set: each tool finding costs one advisor dispatch, and an unverified tool HIGH competes with an agent HIGH for the same capped budget. Size N with that in mind — anything cut stays `unverified` or `tool_reported` and cannot gate.
Citations (CWE/OWASP/CVE/EPSS) are audit metadata — they annotate findings but never decide truth.

## Notes
Fan-out reviewers and advisors hold scoped `Write` for their own `out_file` only, guarded by the write-guard hook — never anywhere else in the repo. The scout never writes at all: fully read-only, its returned JSON persisted by the driver (see Driver run-loop above). Every role is otherwise constrained the same way: no other repo/GitHub writes, no claiming unperformed actions, no materializing discovered secrets.

Hostile-content review (redteam mode, deliberately vulnerable corpora, repos that may contain planted injection payloads) should run with enforcement registered via `--emit-host-agents` so `meta.coverage.tool_policy_mode` reads `enforced`.
