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
  Save the review plan to `.panopticon/runs/<tag>/plan.md` (or
  `.panopticon/scratch/<run>/` before a run exists) — never to
  `docs/superpowers/`, which is not this review's artifact space.
- `superpowers:subagent-driven-development` — for matrix-cell and advisor dispatch.
- `superpowers:verification-before-completion` — before returning the report.

## Dependencies

Two kinds, and `driver readiness` reports both.

**Python packages** — `pyyaml` and `jsonschema`, declared in `pyproject.toml`
and imported by the run itself (`pyyaml` by discovery, `jsonschema` by the
completion path that validates the published report against its schema).
Neither is optional and neither fails cheaply: a missing `pyyaml` takes
discovery down with a traceback, and a missing `jsonschema` is fail-closed by
design, so the run exits `artifact invalid` *after* the whole review has been
paid for. `driver readiness` has a gating `dependencies` row that says which
one is absent and the `pip install` that fixes it — run it before you run
anything.

**The three `superpowers:*` sub-skills above** are the only other external
things this skill asks for. Panopticon does not ship them and does not install
them, and a missing one is a disclosure rather than a stop. The lookup is
read-only: `driver readiness` reports which of the three it found and where,
and nothing in this skill ever writes to the roots below.

Where hosts typically look:

| Host | Root |
| --- | --- |
| Claude Code | `~/.claude/plugins/…/superpowers/` |
| Codex | `~/.codex/skills/` |
| Kimi | `~/.kimi/skills/` |
| Other agents | `~/.agents/skills/` |

**A missing sub-skill is not a stop, and not a reason to go hunting through a
host's plugin tree.** Proceed with the built-in default, which is what the
driver does anyway:

- `superpowers:writing-plans` → write the plan yourself to
  `.panopticon/runs/<tag>/plan.md`.
- `superpowers:subagent-driven-development` → dispatch per cell through the
  driver: `driver loop` in headless mode, or the printed `dispatch` batch
  through `skill/workflows/dispatch.js` in session mode.
- `superpowers:verification-before-completion` → the `validate` phase IS the
  verification; never return a report from a run whose `validate` did not pass.

Disclose in the report which sub-skill was unavailable — the review is still
valid, but a reader has to know which of these paths it took.

## Installed-flow substitution

`skill/` in every command means **this skill's install directory** — literally
`skill/` inside the panopticon repo, or the absolute path you installed it to
elsewhere (e.g., `~/.<agent-config>/skills/panopticon/`). Run every command from the
**target repo root** regardless — `.panopticon/` artifacts and the write-guard
resolve against cwd; only the script path substitutes.

## Quick reference

- `driver readiness [target] [--host NAME] [--json]` — run this FIRST. The preflight, and
  the only verb that writes nothing under the target and launches nothing (host CLIs are
  looked up with `which`, never started): one compact table — or `--json` for the object —
  covering the guide's path, which required sub-skills are installed and where, the
  committed matrix's group/code/test counts, any run left to resume, which host CLIs are
  on PATH, the Docker daemon and the `panopticon-tools` image, and the last run's measured
  host capabilities. Every failing row carries its remedy on its own line. Exit 0 when
  nothing gating fails and 1 otherwise, so a host can `driver readiness && driver loop`.
  The host it reports on is resolved exactly as `driver loop` resolves one (`--host`, else
  the run's manifest, else the default), so a bare invocation still checks a real host; its
  row is marked `→` and GATES when its binary is off PATH — `driver loop` would resolve that
  host to headless and have nothing to launch. `--json` says which rule picked it
  (`selected_from`).
- `driver setup [target] [--max-per-group N] [--max-groups N]` — one-time bootstrap; produces
  `panopticon.yml.draft` (repo root) + `.panopticon/setup-report.md` (read the report first).
- `driver migrate-config [target]` — one-way move of a legacy `.panopticon/groups.yml` into the
  root `panopticon.yml`. Nothing reads the old path any more; commit the new file and delete
  the old one.
- `driver loop [target] [driver run flags] [--mode {headless,session}] [--concurrency N]
  [--max-iterations N] [--max-budget-usd X] [--setup]` — the whole review on rails (the host
  contract); session mode prints `dispatch` and you `driver persist <id> --file <reply>` each
  return-persist reply, then re-run. `--mode` defaults to headless when the host has a headless
  runner and session when it does not (Claude, Codex and Kimi have headless runners) — `--mode headless`
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
