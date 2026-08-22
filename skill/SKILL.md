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
  version: "5.0.1"
---

# panopticon

Discovery → scout → fan-out → synthesis code review. Profiles a target, groups
files, dispatches specialized reviewers in parallel, and synthesizes a validated
CodeReviewReport with CI gating.

The full user guide, driver run-loop spec, output schema, and role contracts
are kept in [`docs/PANOPTICON.md`](docs/PANOPTICON.md) so this skill metadata
file stays focused on the host-facing contract.

## Required sub-skills

- `superpowers:writing-plans` — before repo/PR/directory reviews with >15 files
  or >10 changes.
- `superpowers:subagent-driven-development` — for panel and lens dispatch.
- `superpowers:verification-before-completion` — before returning the report.

## Installed-flow substitution

`skill/` in every command means **this skill's install directory** — literally
`skill/` inside the panopticon repo, or the absolute path you installed it to
elsewhere (e.g., `~/.claude/skills/panopticon/`). Run every command from the
**target repo root** regardless — `.panopticon/` artifacts and the write-guard
resolve against cwd; only the script path substitutes.

## Quick reference

- `driver setup [target]` — one-time bootstrap; produces `.panopticon/groups.yml.draft`.
- `driver run [target] [flags]` — the resumable review loop.
- Key flags: `--full`, `--security {standard,redteam}`, `--fail-on {critical,high,medium,low}`,
  `--severity {all,medium,high,critical}`, `--out PATH`, `--tools`, `--no-tools`,
  `--max-verify N`, `--base <ref>`, `--pr <n>`, `--changes`.
- CI gate key: `summary.gate` (`PASS` / `FAIL` / `OFF` / `INCONCLUSIVE`).

See [`docs/PANOPTICON.md`](docs/PANOPTICON.md) for the complete contract.
