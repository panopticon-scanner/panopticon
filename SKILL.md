---
name: panopticon
description: "Use when reviewing code, pull requests, branches, security posture, test quality, architecture, or database surfaces in a codebase. Use for repo-wide scans, directory reviews, changed-file reviews, or targeted file/group review. Do not use for writing new code, formatting/linting only, or performance benchmarking."
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
- `--pr <n>` — PR diff.
- `-e` / `--explore` — discover and catalog groups; no panels unless asked.
- *(none)* — whole-repo scan.

## Global flags
`--full` (force all panels), `--security {standard,redteam}` (default standard), `--fail-on {critical,high,medium,low}`, `--severity {all,medium,high,critical}` (report only findings at or above the threshold), `--out PATH`, `--tools` (require tool scan), `--no-tools` (skip tool scan), `--epss` (enrich CVE citations).

## Pipeline
1. `TodoList`: discovery → scout → tools → panels → lens sub-reviews → synthesis.
2. **Discovery** — run `python3 scripts/orchestrator.py` to produce `groups.json`.
3. **Scout** — dispatch a `coder` subagent per group with `prompts/scout.md`; output `ScopeProfile`.
4. **Plan** — code always; test iff tests/logic present; security iff risky surfaces; architecture iff repo-scope files; database iff `db_sql` surface. `--full` overrides.
5. **Tool scan** — optional Docker container; SARIF ingested by `scripts/ingest_tools.py`.
6. **Fan-out** — `AgentSwarm` of panel reviewers (`coder` subagents with `prompts/panel-template.md`). Each panel spawns lens specialists when the scout flags `spawn: true`.
7. **Synthesize** — `python3 scripts/synthesize.py` merges findings into `CodeReviewReport`.
8. **Validate** — `verification-before-completion`: check gate, print summary, write JSON.

## Output
Terminal markdown summary + JSON artifact at `--out`. CI gate key: `summary.gate`.

## Notes
Reviewers are read-only: no repo/GitHub writes, no claiming unperformed actions, no materializing discovered secrets.
