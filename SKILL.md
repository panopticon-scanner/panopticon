---
name: panopticon
description: "Discovery → scout → fan-out → synthesis code review. Profiles a target with a cheap scout, builds a risk-tuned plan, dispatches the native code-reviewer/security-reviewer/test-reviewer agents in parallel across cohesive file groups, and synthesizes a CodeReviewReport (markdown summary + JSON artifact) with CI gating. USE FOR: code review, PR/branch review, security audit, test-quality assessment, risk-scoped review, exploring an unfamiliar repo for high-value targets. DO NOT USE FOR: writing new code, formatting/linting, or performance benchmarking."
license: MIT
metadata:
  version: "3.0.0"
---

# panopticon

## Overview
A discovery → scout → fan-out → synthesis layer over Claude Code's native review
fleet. The two scripts (`scripts/orchestrator.py`, `scripts/synthesize.py`) are the
deterministic edges; the middle is agent dispatch.

## Required sub-skills
- `superpowers:writing-plans` — before discovery on complex targets (repo, pr, folder >15, changes >10).
- `superpowers:subagent-driven-development` — scheduling the group×panel dispatch.
- `superpowers:verification-before-completion` — after report assembly, before returning.
- `superpowers:writing-skills` — when modifying this skill (RED-GREEN-REFACTOR).

## Modes
| Flag | Mode | Behavior |
|------|------|----------|
| `-f <path>` | File | Review one file + its related tests + immediate neighbors. |
| `-d <dir>` | Directory | Review implementation under a directory, grouped by cohesion. |
| `-g <name>` / `-g "Group[Facet]"` | Group | Resolve against the learned catalog in `.panopticon/groups.yml`. The facet form scopes the review to code touching that surface. Unknown group → fall back to explore and warn. |
| `-c` | Changes | Review the branch diff vs. the merge base (fallback `HEAD~1`), changed lines + surrounding context. |
| `--pr <n>` | PR | Fetch the PR diff/files, group by logical change. |
| `-e` | Explore | Discover → catalog → risk-rank → persist to `.panopticon/groups.yml`. Does not run panels unless asked. |
| *(none)* | Repo | Whole-repo scan, grouped by functional area. |

## Global flags
`--full` (force all panels), `--tier {auto,sonnet,opus}` (default auto),
`--fail-on {critical,high,medium,low}` (CI gate, default off),
`--severity {all,medium,high,critical}`, `--out PATH`,
`--tools` (require the tool scan; error if the `panopticon-tools` image is absent),
`--no-tools` (force-skip the tool scan), `--epss` (enrich CVE citations with live EPSS
scores during synthesis).

## Pipeline
1. Parse & mode.
2. **Discovery** — run `python3 scripts/orchestrator.py` with the flag matching the mode: `-f`→`--file PATH`, `-d`→`--directory DIR`, `-g NAME`→`--group NAME` (accepts `"Group[Facet]"`), default repo→`--repo-scan`. For `-c` and `--pr`, first collect the changed file paths (via `git`/`gh`) and pass them with `--files PATH...`. Output: `groups.json`.
3. Scout (adaptive) — dispatch a Sonnet subagent per `prompts/scout.md`; one for small
   targets, per-group otherwise; facet subgroups get a facet-scoping pass. Output:
   ScopeProfile per group.
4. Plan (bounded floor) — code panel always on code; security iff risk surfaces; test
   iff tests/logic present; docs/markup/style-only → minimal/skip. Tier from risk;
   Sonnet first-pass with Opus escalation on CONFIRMED CRITICAL/HIGH. `--full` overrides.
5. **Tool scan (optional, if the `panopticon-tools` image is present)** —
   `python3 scripts/run_tools.py --target <t> --out .panopticon/tools --languages <langs> [--deps]`
   (auto-skips when Docker/image absent; `--no-tools` forces skip; `--tools` makes absence
   an error), which writes SARIF to `.panopticon/tools/`. Synthesize then ingests that
   directory via `--tools-dir .panopticon/tools` (using `scripts/ingest_tools.py`),
   merging tool-grounded findings into the same run — no separate finding files are
   written for tools. Containers run with a read-only (`:ro`) mount as a non-root user;
   network is allowed so semgrep/trivy can fetch their rules/DB — the tools only parse
   code, never execute it.
6. Fan-out — dispatch the selected panel agents in parallel (see prompt template). Hand
   each group's tool findings to that group's `security` agent and instruct it to focus
   on what tools structurally miss (business logic, authz, novel attacks) and to emit
   citation calls (`cwe`/`owasp`/`cve`) plus SSVC inputs nested at `citations.ssvc.inputs`
   with keys `exploitation` (none|poc|active), `exposure` (small|controlled|open), and
   `impact` (low|medium|high|very_high), e.g.
   `"citations": {"ssvc": {"inputs": {"exploitation": "...", "exposure": "...", "impact": "..."}}}`.
7. Synthesize — `python3 scripts/synthesize.py --target T [--groups groups.json]
   [--tools-dir .panopticon/tools] [--fail-on SEV] [--out PATH] [--epss]
   .panopticon/findings-*.json`. During this step, citations are validated/enriched
   (`scripts/citations.py`) and tool+agent findings are reinforced.
8. Output — print the markdown summary; JSON artifact at --out. CI keys off `summary.gate`
   (documented wrapper below).

## Panel dispatch prompt template
```
You are the {panel} reviewer for panopticon group "{group}".
Files: {file_list}
Emphasis lenses (from prompts/lenses.md): {lenses}
{If security}: apply reference/security-checklists.md sections for {languages}.

Review ONLY the listed files. Write findings as raw JSON {"findings": [...]} to
.panopticon/findings-{group}-{panel}.json and return ONLY the path + count.

SIDE-EFFECT BOUNDARY: your ONLY action is writing that one findings file. Perform NO
GitHub writes (issues, PRs, comments, labels, token/credential mints), NO dispatches, NO
repo mutations. Never report an action you did not actually perform — a review that claims
"filed an issue" or any external effect it did not verifiably do is a forged result. Verify
before you assert.

SECRET HANDLING: if you discover a secret / credential / token / password / live DSN VALUE,
cite {file, line} and the class only — NEVER copy the literal value into a finding title,
description, or any other output. Materializing a found secret into the findings artifact
expands its exposure and is itself a defect.

Each finding: id ^[A-Z]{2,4}-\d{3,}$, severity CRITICAL|HIGH|MEDIUM|LOW|INFO,
panel "{panel}", category (lens name), location {file,line_start[,line_end,function]},
title, description, impact, remediation, references[]. Never fabricate line numbers.
Security CRITICAL/HIGH: add cvss {score,vector} and exploit_scenario.
```

## Panel → agent mapping
- code → `code-reviewer` (Opus) / `code-reviewer-sonnet`
- security → `security-reviewer` (Opus) / `security-reviewer-sonnet`
- test → `test-reviewer` (Opus only)

## Explore (-e)
Scan repo → propose functional-area groups + facets → risk-rank → write/update
`.panopticon/groups.yml`, proposing a diff (never clobber). Do not run panels
unless asked to review a discovered target.

## CI gating
`--fail-on high` sets `summary.gate`. For a true nonzero CI exit, wrap:
`jq -e '.summary.gate != "FAIL"' .panopticon/report-*.json`

## Notes
Ruthless but high-signal. File-based findings handoff keeps context small. Never
fabricate line numbers. Validate the report before returning. A panel's only side effect
is its findings file — never mutate the repo/GitHub, never claim an action you didn't do,
never materialize a discovered secret value (cite file:line + class instead).
