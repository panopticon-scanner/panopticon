---
name: panopticon
description: Discovery → scout → fan-out → synthesis code review for Kimi Code. Profiles a target, groups files, dispatches specialized reviewers in parallel, and synthesizes a validated CodeReviewReport with CI gating.
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
  version: "3.0.0"
---

# panopticon

## Overview
Discovery → scout → fan-out → synthesis code review for Kimi Code. Profiles a target, groups files, dispatches specialized reviewers in parallel, and synthesizes a validated `CodeReviewReport` with CI gating.

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
`--full` (force all panels), `--security {standard,redteam}` (default standard), `--fail-on {critical,high,medium,low}`, `--severity {all,medium,high,critical}` (report only findings at or above the threshold), `--out PATH`, `--tools` (require tool scan), `--no-tools` (skip tool scan), `--epss` (enrich CVE citations).

## Pipeline
1. `TodoList`: discovery → scout → tools → panels → lens sub-reviews → synthesis.
2. **Discovery** — run `python3 scripts/orchestrator.py` to produce `groups.json`.
3. **Scout** — dispatch the `scout` custom agent (`agents/scout.md`) per group; output `ScopeProfile` to `.panopticon/scout-{group}.json`.
4. **Tool scan** — optional Docker container; SARIF ingested by `scripts/ingest_tools.py`.
5. **Plan dispatch** — run `python3 scripts/dispatch.py <scope-profile.json> --host <host> --out .panopticon/dispatch-plan.json` to produce a `DispatchPlan` of role-based agents.
6. **Fan-out** — `AgentSwarm` dispatching custom agents by name from the plan:
   - `panel-review` agents for holistic panel review
   - `lens-sweep` agents for mechanical lens sweeps
   - Each agent writes its findings file to `.panopticon/findings-{group}-{panel}-{role}-{lens}.json` (`panel_review` entries omit `{lens}`)
7. **Synthesize** — `python3 scripts/synthesize.py` merges findings, tags tenuous claims, and (if any are flagged) spawns `advisor` agents (`agents/advisor.md`) before producing the final `CodeReviewReport`.
8. **Validate** — `verification-before-completion`: check gate, print summary, write JSON.

## Output
Terminal markdown summary + JSON artifact at `--out`. CI gate key: `summary.gate`.

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

## Notes
Reviewers are read-only: no repo/GitHub writes, no claiming unperformed actions, no materializing discovered secrets.
