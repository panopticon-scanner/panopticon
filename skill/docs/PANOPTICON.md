# panopticon

## Overview
Discovery → scout → fan-out → synthesis code review. Profiles a target, groups files, dispatches
specialized reviewers in parallel, and synthesizes a validated CodeReviewReport with CI gating.

## Required sub-skills
- `superpowers:writing-plans` — before repo/PR/directory reviews with >15 files or >10 changes. Save
  the review plan to `.panopticon/runs/<tag>/plan.md` (or `.panopticon/scratch/<run>/` before a run
  exists) — never to `docs/superpowers/`, which is not this review's artifact space.
- `superpowers:subagent-driven-development` — for matrix-cell and advisor dispatch.
- `superpowers:verification-before-completion` — before returning the report.

## Modes
Use `AskUserQuestion` when the target is ambiguous. `driver loop [target]` is the entry point for
every mode below (`driver run [target]` is the single-step primitive it calls) — see Driver run-loop
(5.0) for the execution loop.
- *(no scope flag)* — whole-repo committed-matrix review, driven by the root `panopticon.yml`
  (produced by `driver setup`; `.panopticon.yml` is a read-only alias).
- `-f <path>` / `--file <path>` — single-file scope.
- `-d <dir>` / `--directory <dir>` — directory scope.
- `-g <name>` / `--group <name>` — one committed group.
- `-c` / `--changes` — delta vs base (`--base <ref|sha>`; default main→master); diffs the live
  working tree, uncommitted changes included. An unresolvable base fails loudly — there is no
  `HEAD~1` fallback.
- `--pr <n>` — review a GitHub PR inside an isolated, disposable `git worktree` (never touches your
  checkout); the driver resolves the worktree once and runs every phase natively inside it (no
  separate staging step), releasing it on completion (`diff_map.release_worktree`) — a PR review is
  committed-only. Both `-c` and `--pr` emit `.panopticon/diff-hunks.json`. The worktree holds
  attacker-controlled PR content, so the review runs against **your** grouping, not the PR's: the
  operator's `panopticon.yml` overwrites whatever the PR shipped under either name — a PR-shipped
  config at `panopticon.yml` or `.panopticon.yml` (file *or* symlink) is removed with
  `lstat`+`unlink`, never opened and never followed (CWE-59), before yours is copied in — and each
  removal, refresh and overwrite is disclosed. The overwrite is excluded from the diff map, so the
  on-diff gate never attributes it to the PR. **Acquisition runs no command the target authored,
  except through the fetch's transport settings** (#2012; residual #2041: the fetch honours the
  checkout's own `core.sshCommand` and `remote.<name>.uploadpack`, which are operator config and
  never PR content): of the five calls that build the worktree, only `git fetch` keeps your
  environment, because a private repository's PR head is fetchable only through your credential
  helper, which lives in the `HOME` and gitconfig `safe_git`'s fresh allowlisted environment strips
  — and even that one carries `core.fsmonitor=false` and the same pinned empty `core.hooksPath`
  every confined launch uses, because a fetch writes a ref and `reference-transaction` fires from
  the target's hooks directory on it. `worktree list` and `rev-parse` go through `safe_git.probe`;
  `worktree add --detach`, `update-ref -d` and the teardown's `worktree remove --force` through
  `safe_git.mutate`, the one entry point allowed to write, which pins the same hooks directory and
  empties every repository-configured `filter.*`/`diff.*` command (each disclosed as
  `panopticon --pr: suppressed <key> in <repo>`, by key, never by value). That matters because
  `worktree add` is a **checkout**: on the old path the target's `filter.*.smudge` ran on the PR's
  content and its output, not the committed bytes, was what got reviewed, and a `post-checkout` hook
  ran from whatever `core.hooksPath` the repository asked for. **Pass `--fail-on` or the gate stays
  OFF** — a delta run is gate-first by intent.
- `driver setup [target] [--max-per-group N] [--max-groups N]` — one-time bootstrap: proposes
  `panopticon.yml.draft` at the repo root and writes `.panopticon/setup-report.md`. See Driver setup
  (5.2) below.

## Global flags
`--full` (force all panels), `--security {standard,redteam}` (default standard),
`--fail-on {critical,high,medium,low}`, `--severity {all,medium,high,critical}` (report only
findings at or above the threshold), `--out PATH`, `--tools` (require tool scan), `--no-tools` (skip
tool scan), `--reset` (discard the current run's working artifacts and start a NEW run — keeps every
durable tag-named report on disk, only reclaims `.panopticon/runs/<tag>/` and the run-manifest, so
it is safe to run on a finished review), `--epss` (enrich CVE citations), `--gate-unverified`
(unverified findings drive grades/gate), `--max-verify N` (cap the verify queue; PR-scale delta
reviews queue EVERY finding incl. tool claims -- a 25-file PR queued 108 advisors -- so size N ~ 2x
the changed-file count unless you want the full sweep), `--max-per-group N` (files per review chunk
at run time, default 48; a positive integer, pinned in the run-manifest on the first run so a resume
never repartitions cells that are already done — `driver setup` takes the same flag for the
setup-time cap, see Driver setup), `--base <ref|sha>` (explicit delta base for
`-c`/`--pr`/`--files`), `--diff-context N` (default 5; on-diff tolerance in lines),
`--gate-scope {on-diff,all}` (default `on-diff` for delta reviews; scopes the gate to on-diff ×
gate-eligible findings), `--include-fixtures` (keep tool findings under test-fixture corpora;
default prunes them in every mode — incl. redteam, #1055 — for parity with the review-side prune,
though under redteam the prune is disclosed and the gate counts it anyway, #1740; pass to opt in),
`--tools-exclude GLOB` (drop tool findings whose path matches GLOB; repeatable, for additional
non-fixture paths), `--doc-paths GLOB` (doc-tree globs for the planning-doc severity policy; in
standard mode, non-secret code findings under doc trees are soft-downgraded to INFO -- secrets keep
severity, redteam bypasses entirely, and every downgrade is disclosed at
`meta.coverage.doc_policy`). `--base` on `--files` makes it an explicit delta request — plain
`--files` (no `--base`) is a normal whole-file review and emits no delta artifact.

## Contents

- [Driver run-loop (5.0)](guide/driver-run-loop.md) — the host contract: `driver loop` in headless
  and session mode, the readiness checkpoint, the phase order, what the loop does at every
  checkpoint, and every way a run stops.
- [Driver setup (5.2)](guide/driver-setup.md) — the one-time `driver setup` bootstrap: its two
  phases, the size caps, the `settings:` trust classes a target may commit, glob semantics, and
  upgrading an older tree.
- [Output](guide/output.md) — the terminal summary and the JSON artifact: the CI gate key, the exit
  codes, schema validation, per-run folders, and secret redaction.
- [Host capabilities (5.2)](guide/host-capabilities.md) — the five measured capabilities, the four
  surfaces that disclose them, and where each host stands, including `--host generic` and the
  not-selectable `gemini` row.
- [Code layout (5.2)](guide/code-layout.md) — which module owns what behind
  `skill/scripts/synthesize.py`, `skill/scripts/driver.py` and `skill/scripts/host_probes.py`.
- [Testing scanner fixtures (optional)](guide/testing-scanner-fixtures.md) — the local Docker
  fixture suite for validating scanner adapters against intentionally vulnerable applications.
- [Evidence](guide/evidence.md) — the two independent axes a finding carries, severity and
  `evidence.status`; what the grades and the gate count, and how citations are treated.
- [Notes](guide/notes.md) — reviewer confinement: the write guard, the read guard, hostile-content
  review, and the two refusals that cover a prepared tree.
