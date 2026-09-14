---
name: panopticon
description: Use when reviewing code, pull requests, branches, security posture, test quality, architecture, or database surfaces in a codebase
type: prompt
whenToUse: When reviewing code, pull requests, branches, security posture, test quality, architecture, or database surfaces in a codebase
arguments:
  - target
  - host
  - security
disableModelInvocation: false
license: MIT
metadata:
  version: "5.1.0"
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
- `superpowers:subagent-driven-development` — for matrix-cell and advisor dispatch.
- `superpowers:verification-before-completion` — before returning the report.

## Installed-flow substitution

`skill/` in every command means **this skill's install directory** — literally
`skill/` inside the panopticon repo, or the absolute path you installed it to
elsewhere (e.g., `~/.<agent-config>/skills/panopticon/`). Run every command from the
**target repo root** regardless — `.panopticon/` artifacts and the write-guard
resolve against cwd; only the script path substitutes.

## Quick reference

- `driver setup [target] [--max-per-group N] [--max-groups N]` — one-time bootstrap; produces
  `.panopticon/groups.yml.draft` + `setup-report.md` (read the report first).
- `driver loop [target] [driver run flags] [--mode {headless,session}] [--concurrency N]
  [--max-iterations N] [--max-budget-usd X] [--setup]` — the whole review on rails (the host
  contract); session mode prints `dispatch` and you `driver persist <id> --file <reply>` each
  return-persist reply, then re-run. `--mode` defaults to headless when the host has a headless
  runner and session when it does not (Claude and Codex have headless runners) — `--mode headless`
  on a host without one is an error, not a silent downgrade.
- `driver loop [target] --host codex --mode headless` — Codex's first-class path through
  the same loop, with scoped read/search/list tools and every role returning JSON for the
  loop to persist. Register the Codex shells first (see the guide): Codex is enforced-only, so
  the loop refuses up front when a role's shell is missing, except under `--setup` (whose
  setup-scan entry needs none). Manual session mode
  cannot prove these controls. The shared review gate still requires `--allow-unenforced`
  when `artifact_write_guard` is unproven; obtain the operator's explicit acceptance before
  using it. Codex reports tokens but not cost or effective model identity: dollar budgets
  cannot bound its spend, so also set `--max-iterations` and `--entry-timeout` and narrow scope.
- `driver persist ENTRY_ID [--file PATH] [--setup] [--pr N] [--base REF] [target]` — persist one
  return-persist reply (session mode). On a `--pr`/`--base` run pass the same `--pr`/`--base`:
  persist has to resolve the same review root the loop did (a PR run's is the PR worktree), or it
  reads a different tree's dispatch request and finds no such entry.
- **Session mode on Claude Code is templated, never ad hoc.** Dispatch the printed batch with the
  shipped workflow: `Workflow({scriptPath: "skill/workflows/dispatch.js", args: {checkpoint,
  entries}})`, `entries` being the request's entries reduced to `id, agent, enforced, model,
  marker, prompt_file, delivery, out_file` (never the inline `prompt`). It runs one subagent per
  entry — inside its registered `panopticon-*` shell when the entry is `enforced`, on the entry's
  `model` otherwise — marker line first (the read guard binds through the workflow transcript
  layout) and `prompt_file` second (granted to the entry's read scope), and returns `persist`
  (reply text per return-persist id, for `driver persist <id>`), `self_wrote` and `missing` (a
  skipped or dead subagent, re-emitted by the next loop entry).
  Do not hand-dispatch entries with one-off Agent calls.
- `driver run [target] [flags]` — the single-step primitive `driver loop` calls; drive by hand
  only when debugging a phase.
- Key flags: `--host NAME`, `--security {standard,redteam}`,
  `--fail-on {critical,high,medium,low}`, `--severity {all,medium,high,critical}`,
  `--tools`, `--no-tools`, `--max-per-group N`, `--gate-scope`, `--base <ref>`,
  `--pr <n>`, `--changes`, `--max-verify N`, `--allow-unenforced` (required to
  dispatch write-capable reviewers on a host that cannot mediate Write).
- CI gate key: `summary.gate` (`PASS` / `FAIL` / `OFF` / `INCONCLUSIVE`).

See [`docs/PANOPTICON.md`](docs/PANOPTICON.md) for the complete contract.
