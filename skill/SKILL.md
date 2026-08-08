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
  version: "4.2.0"
---

# panopticon

## Overview
Discovery → scout → fan-out → synthesis code review. Profiles a target, groups files, dispatches specialized reviewers in parallel, and synthesizes a validated CodeReviewReport with CI gating.

## Required sub-skills
- `superpowers:writing-plans` — before repo/PR/directory reviews with >15 files or >10 changes.
- `superpowers:subagent-driven-development` — for panel and lens dispatch.
- `superpowers:verification-before-completion` — before returning the report.

## Modes
Use `AskUserQuestion` when the target is ambiguous. Otherwise map flags directly:
- `-f <path>` / `--file <path>` — single file + related tests + neighbors.
- `-d <dir>` / `--directory <dir>` — directory review.
- `-g <name>` / `--group <name>` — group from `.panopticon/groups.yml` (use `-g "Group[Facet]"` for a facet).
- `-c` / `--changes` — branch diff vs merge base (fallback `HEAD~1`).
- `--pr <n>` — PR diff (fetch the PR diff via `gh` or `curl`, extract changed paths, and pass them to the internal `--files` path).
- `-e` / `--explore` — discover and catalog groups; no panels unless asked.
- *(none)* — whole-repo scan.

## Global flags
`--full` (force all panels), `--security {standard,redteam}` (default standard), `--fail-on {critical,high,medium,low}`, `--severity {all,medium,high,critical}` (report only findings at or above the threshold), `--out PATH`, `--tools` (require tool scan), `--no-tools` (skip tool scan), `--epss` (enrich CVE citations), `--gate-unverified` (unverified findings drive grades/gate), `--max-verify N` (cap the verify queue).

## Pipeline
1. `TodoList`: discovery → scout → tools → panels → lens sub-reviews → synthesis.
2. **Discovery** — run `python3 scripts/orchestrator.py` to produce `groups.json`.
3. **Scout** — dispatch the `scout` role (`agents/scout.md`) per group — its template has no placeholders; dispatch its body plus tool-policy line as the prompt — via `subagent_type: panopticon-scout` when that registered shell exists (fresh session after registration), else a general-purpose agent; the scout RETURNS the ScopeProfile JSON; the orchestrator writes it to `.panopticon/scout-{group}.json`.
   Append the group's name, its file list from `groups.json`, and the `security_mode` to the prompt body — the scout template itself carries no assignment.
4. **Tool scan** — optional Docker container; SARIF ingested by `skill/scripts/ingest_tools.py`.
5. **Plan dispatch** — run `python3 skill/scripts/dispatch.py <scope-profile.json> --host <your host: claude|kimi|generic> --out .panopticon/dispatch-plan.json` to produce a `DispatchPlan` of role-based agents.
   Pass your host explicitly — env detection is fallback only. Add --agents-dir DIR when your registered agents live somewhere non-default.
6. **Fan-out** — run the `group_runner` contract (`scripts/group_runner.py`,
   `scripts/write_guard_hook.py`): every reviewer writes its own findings file
   directly, so fan-out is bounded by agent capacity, not by how much of a
   truncated report the orchestrator's context can still hold.
   `panel_review` filenames omit `{lens}`.
   - **Before fan-out** — if the target is a git repository, capture a
     baseline: `git status --porcelain > .panopticon/tree-baseline.txt`. Then
     install the write-guard from the plan:
     `python3 -c "import sys; sys.path.insert(0,'skill'); import scripts.write_guard_hook as wg, json; wg.install(json.load(open('.panopticon/dispatch-plan.json')))"`.
   - **Resume** — dispatch only `pending_entries(plan)`: an entry whose
     `out_file` already exists and parses as findings JSON is done; never
     re-dispatch it.
   - **The role contract** — every reviewer holds scoped `Write` (the guard
     blocks any target outside the plan's declared `out_file` set) and
     **writes its own `entry.out_file` directly**. Its final message is a
     short confirmation only, NOT its findings — findings never re-transit the
     orchestrator's context. This is the change that makes coverage
     capacity-bound rather than context-bound.
   - **Claude host (mechanical)** — run fan-out as a deterministic Workflow:
     one agent per pending entry, dispatched with `entry.prompt` and
     `entry.model.model` (or `subagent_type: entry.agent` when
     `entry.enforced`), each writing its own `entry.out_file`. The Workflow
     bounds concurrency and journals progress, so a stalled or failed entry is
     re-run by the loop itself — never lost, never a manual re-dispatch. The
     parent session receives only the Workflow's final tally, never per-entry
     findings.
   - **Other hosts (portable)** — dispatch one nested sub-orchestrator per
     group (the run-2 verify pattern): it holds scoped `Write`, runs its
     group's `pending_entries`, and returns a per-group tally. Prose contract:
     never end a turn with an entry unresolved; resume via the done-predicate
     (`pending_entries`), not a fixed dispatch list; status comes from disk,
     not recollection.
   - **After fan-out** — uninstall the guard:
     `python3 -c "import sys; sys.path.insert(0,'skill'); import scripts.write_guard_hook as wg; wg.uninstall()"`.
   - **Coverage** — do not hand-assemble a tally for the artifact:
     `synthesize` derives `meta.coverage.fan_out` from the dispatch plan plus
     the findings files actually on disk (`fan_out_coverage`, step 7).
   - **Working directory** — run the install/uninstall (and the whole pipeline)
     from the repo root, where `.panopticon/` lives: `install` writes the
     allowlist to `.panopticon/write-allowlist.json` and registers the hook in
     `.claude/settings.local.json`, and the hook resolves both relative to the
     session's working directory — they must be the same root or the guard is
     inert. Verified live: from the repo root, an in-allowlist write succeeds and
     an out-of-scope write is denied by the harness.
   - **Lifecycle** — an aborted run leaves the guard installed; the next run's
     `install` is idempotent, or clear it with `wg.uninstall()`. The hook's
     settings file is git-ignored so a leftover never trips the clean-tree check.
   See Host dispatch below for the full per-host mechanism.
7. **Synthesize (pass 1)** — `python3 scripts/synthesize.py --emit-verify-queue [flags] .panopticon/findings-*.json`.
   If it prints a "verify queue: N entries" line, proceed to step 8; if it printed a report, skip to step 9.
8. **Verify** — Run `python3 scripts/dispatch.py --render-advisor .panopticon/verify-queue.json --out .panopticon/advisor-prompts`,
   then dispatch each `.panopticon/advisor-prompts/{queue_id}.md` file's contents
   as an `advisor` agent (`agents/advisor.md`) in parallel — via `subagent_type: panopticon-advisor` when that registered shell exists, else general-purpose. The advisor RETURNS a
   verdict JSON; write it verbatim to `.panopticon/verdicts/{queue_id}.json`.
   Advisors are read-only; the orchestrator performs the write.
   On resume, dispatch only `group_runner.pending_verdicts(queue, .panopticon/verdicts)` —
   never re-dispatch a `queue_id` that already has a valid verdict on disk; status
   comes from disk, not recollection. The fan-out/verify skip-counts surface in
   `meta.coverage.resume` and the terminal summary's `Resume:` line, so a resumed
   run never reads as a fresh full scan.
   Then run
   `python3 scripts/synthesize.py --verdicts-dir .panopticon/verdicts [same flags] .panopticon/findings-*.json`
   to produce the final report.
   `[same flags]` is a requirement, not a convenience: `--severity` filtering and
   `--tools-dir` ingestion both run before the verify queue is built, so a flag that
   differs between the two passes feeds them different finding sets — and the verdicts
   pass 1 asked for will name findings that pass 2 has no queue entry for.
9. **Validate** — `verification-before-completion`: compare `git status --porcelain`
   against `.panopticon/tree-baseline.txt`; any NEW modification outside `.panopticon/`
   means a reviewer had side effects — treat the run as compromised: discard the
   findings files, restore or flag the modified paths to the user (never silently
   delete their content), report the violation, and re-run. Then check gate, print
   summary, write JSON.

## Host dispatch

One plan, one prompt per reviewer; each host realizes the same `group_runner`
contract — pending-only dispatch, reviewer self-write, tally-only return — with
its own mechanism:

- **Claude Code (mechanical)** — fan-out runs as a deterministic Workflow: one
  agent per entry in `pending_entries(plan)`. If `entry.enforced` is
  true, dispatch with `subagent_type: entry.agent` (a registered
  `panopticon-*` enforcement shell — tools and model are host-enforced) and
  `entry.prompt` as the task. If false, dispatch general-purpose with
  `entry.prompt` and the model named by `entry.model.model` (omit when null).
  Each reviewer holds scoped `Write` (guarded — see Fan-out above) and writes
  its own `entry.out_file` directly; the Workflow bounds concurrency, journals
  progress, and re-runs a stalled or failed entry itself. The parent session
  receives only the Workflow's final tally, never per-entry findings.
  Register once with `python3 scripts/dispatch.py --emit-host-agents claude`.
- **Kimi Code (portable)** — the `group_runner` role is a nested
  sub-orchestrator per group (the run-2 verify pattern): it holds scoped
  `Write`, dispatches only its group's `pending_entries`, and returns a
  per-group tally to the parent — never the findings themselves. Within a
  group, dispatch is AgentSwarm raw-prompt dispatch (`prompt_template`/`items`)
  or per-entry `Agent` dispatch. Model selection is driven by the registered
  agent file's `model_preference` (`primary` for `scout`/`lens_sweep`,
  `secondary` for `panel_review`/`advisor`); per-dispatch `model` overrides
  require `KIMI_CODE_EXPERIMENTAL_SECONDARY_MODEL=1` or
  `KIMI_CODE_EXPERIMENTAL_FLAG=1`.

  1. Register the enforcement shells once (fresh session required after):
     ```bash
     python3 scripts/dispatch.py --emit-host-agents kimi
     # or explicit:
     python3 scripts/dispatch.py --emit-host-agents kimi --out ~/.kimi-code/agents
     ```
  2. Build the dispatch plan with `--host kimi`.
  3. Fan out. Which `subagent_type` to use depends on `entry.enforced`, the
     same way it does for Claude — and until step 1 has run, every entry is
     unenforced:
     - `entry.enforced` true → `subagent_type: entry.agent` (the registered
       `panopticon-*` profile, so tool restrictions are host-enforced).
     - `entry.enforced` false → a built-in Kimi profile: `coder` for
       `panel_review`, `explore` for `lens_sweep`/`scout`, `plan` for
       `advisor`. `entry.agent` is a host-neutral placeholder in this case
       (`panel-review`, `lens-sweep`) and is NOT a valid `subagent_type`.

     Prefer the swarm manifest, which applies that mapping for you and
     re-checks registration against the live agents dir:
     ```bash
     python3 scripts/dispatch.py --emit-kimi-swarm .panopticon/dispatch-plan.json --out .panopticon/kimi-swarm.json
     ```
     Then invoke each batch. Raw-prompt dispatch does not honor the shell, so
     an enforced entry must go through its registered profile.

     **Routing results back:** each batch carries `routing` — a single object
     for an `Agent` call, or a list index-aligned with `items` for an
     `AgentSwarm` batch. Under the `group_runner` contract each reviewer
     writes its own `routing[i].out_file` directly; the sub-orchestrator
     confirms completion via the done-predicate (does `out_file` exist and
     parse?) and rolls the group's results into its tally — it does not
     re-write findings content itself. A batch may merge entries from
     different panels and groups, so item order is the only other link and it
     is not a contract.
  4. Verification phase: render advisors with `--render-advisor` and dispatch
     them the same way as panels/lenses.
- **Other hosts (portable, degraded)** — no sub-agent nesting or Workflow
  primitive available: run `pending_entries(plan)` sequentially in-session
  with the same prompts, one reviewer at a time; expect no parallelism. Still
  apply the resume predicate (skip entries already done) and the self-write
  contract where the host lets a dispatched agent write files; where it
  doesn't, the in-session orchestrator persists the reviewer's returned
  findings to `out_file` on its behalf — a disclosed, weaker posture than the
  guarded self-write hosts get.

Tool policy is host-ENFORCED for entries with `enforced: true` (registered
shells) and prompt-advisory otherwise. The report's `meta.coverage.tool_policy_mode`
records which posture a run actually had. When any entry is unenforced, tell
the user in one line before fan-out. `tool_policy_mode` is derived from the
fan-out plan entries (panel_review/lens_sweep); scout and advisor shell
dispatch is instructed in steps 3 and 8 but not recorded in the mode. The
write-guard is orthogonal to this axis: it governs WHERE a reviewer's Write
may target, installed for the fan-out phase regardless of `enforced`, and
does not change how tool restrictions are enforced — `tool_policy_mode` gains
no new value from it.

## Output
Terminal markdown summary + JSON artifact at `--out`. CI gate key: `summary.gate`
(`PASS` / `FAIL` / `OFF` / `INCONCLUSIVE`). `INCONCLUSIVE` means gate-relevant
coverage did not complete (a high-value panel ran partial, or a scout-requested
tool produced no output) — treat it as NOT certified, distinct from a real
`FAIL`. `summary.coverage_certified` and `meta.coverage.divergence` carry the
detail; `main` exits `1` on FAIL, `2` on INCONCLUSIVE, `0` otherwise. Exit `2`
is also argparse's usage-error code; a genuine INCONCLUSIVE run still writes a
full report artifact, whereas a usage error does not, so disambiguate the two
by checking whether the report exists. Consumers should key certification on
`summary.gate` and `summary.coverage_certified`, not on `overall_grade` alone
— a tool-only coverage gap yields `INCONCLUSIVE` with a real grade still
attached. When `meta.coverage.resume` shows pending work in either phase, the
terminal summary also prints a `**Resume:**` line (fan-out/verify done vs.
total) directly under the Grade/Gate line; a fully-complete or resume-absent
run prints no such line, so a resumed run never reads as a fresh full scan.

## Testing scanner fixtures (optional)
Panopticon includes a local Docker-based fixture suite for validating scanner adapters against intentionally vulnerable applications.

```bash
# Use existing fixtures image
python3 scripts/run_fixture_tests.py

# Force rebuild (clones latest public fixtures)
python3 scripts/run_fixture_tests.py --rebuild

# Run only one language/test target
python3 scripts/run_fixture_tests.py --test rust
```

This is optional and not part of CI. Rebuild the image periodically to pull updated fixtures.

## Evidence

Findings carry two independent axes: **severity** (impact if true — never rewritten)
and **evidence.status** (how hard the claim was verified):

- `tool_reported` — a static-analysis tool emitted it (or a tool+agent
  same-locus merge did); no advisor has checked it. NOT gate-eligible.
- `tool_confirmed` — a tool reported it AND an advisor independently confirmed
  it. Gate-eligible.
- `advisor_confirmed` / `rejected` / `needs_more_info` — advisor verdicts from the
  verify phase. Rejected claims keep their severity and move to `discarded_claims`.
- `corroborated` — multi-panel agreement (correlated witnesses: prioritized for verification, not gate-eligible by default).
- `unverified` — no verification attempted.

Grades and the CI gate count `tool_confirmed`/`advisor_confirmed` findings
only — i.e. only claims an advisor verified, whatever their source. Run a
verify phase (or pass `--gate-unverified`) or the gate has nothing to fail on.

Every finding queues for verification, tool claims included, so `--max-verify N`
now caps a queue holding the whole finding set: each tool finding costs one
advisor dispatch, and an unverified tool HIGH competes with an agent HIGH for the
same capped budget. Size N with that in mind — anything cut stays `unverified` or
`tool_reported` and cannot gate.
Citations (CWE/OWASP/CVE/EPSS) are audit metadata — they annotate findings but
never decide truth.

## Notes
Fan-out reviewers (`panel_review`, `lens_sweep`) hold scoped `Write` for their
own `out_file` only, guarded by the write-guard hook — never anywhere else in
the repo. Otherwise every reviewer role is read-only: no other repo/GitHub
writes, no claiming unperformed actions, no materializing discovered secrets.
Scouts and advisors stay fully read-only; the orchestrator performs their
writes (steps 3 and 8).

Hostile-content review (redteam mode, deliberately vulnerable corpora, repos that may
contain planted injection payloads) should run with enforcement registered via
`--emit-host-agents` so `meta.coverage.tool_policy_mode` reads `enforced`.
