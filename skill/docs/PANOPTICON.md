# panopticon

## Overview
Discovery → scout → fan-out → synthesis code review. Profiles a target, groups files, dispatches
specialized reviewers in parallel, and synthesizes a validated CodeReviewReport with CI gating.

## Required sub-skills
- `superpowers:writing-plans` — before repo/PR/directory reviews with >15 files or >10 changes. Save
  the review plan to `.panopticon/runs/<tag>/plan.md` once a run has a tag, which
  `.panopticon/runs/latest` points at. Before then, keep it outside the target, in a file from
  `mktemp`, and put nothing under `.panopticon/`: first contact halts on a `.panopticon/` it did not
  create. Never save it to `docs/superpowers/`, which is not this review's artifact space. Use only
  its task breakdown: what to review, and in what order. Skip its TDD steps and commits, because a
  review changes no code, and skip its handoff, which waits on a user and must never block an
  autonomous run.
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
- **Delta review was withdrawn in 5.4 (#3735) and its code removed in 5.5 (#3736).** `-c` /
  `--changes`, `--pr <n>`, `--base <ref>` and `--gate-scope` are refused at the command line, on
  every verb, before anything is launched or written: exit 2, with one message naming the flag.
  Reviewing a diff was never calibrated or stress-tested, and the five-gate review found a `--pr`
  run that passed, certified, with a new finding on a changed line. Panopticon is a
  whole-repository audit; scope one with `-f`, `-d`, `-g` or `--files`. A run folder that was
  started as a delta review is not resumed (`--reset` discards it and starts a whole-repository
  run). A report an earlier version made by a delta review still renders, with one line saying
  that it was one and that its gate judged only changed lines.
- `driver setup [target] [--max-per-group N] [--max-groups N]` — one-time bootstrap: proposes
  `panopticon.yml.draft` at the repo root and writes `.panopticon/setup-report.md`. See Driver setup
  (5.2) below.

## Global flags
`--security {standard,redteam}` (default standard), `--fail-on {critical,high,medium,low,off}`
(default critical: with no flag and no committed `fail_on`, a confirmed CRITICAL fails the gate;
`off` is the operator's opt-out, and the terminal summary, `summary.gate_disabled` and an HTML
banner all say the gate was disabled),
`--severity {all,medium,high,critical}` (report only
findings at or above the threshold), `--out PATH`, `--tools` (require tool scan), `--no-tools` (skip
tool scan), `--reset` (discard the current run's working artifacts and start a NEW run — keeps every
durable tag-named report on disk, only reclaims `.panopticon/runs/<tag>/` and the run-manifest, so
it is safe to run on a finished review), `--epss` (enrich CVE citations), `--gate-unverified`
(unverified findings drive health and the gate), `--max-verify N` (cap the verify queue; every finding is
queued, tool claims included, unless you cap it), `--max-per-group N` (files per review chunk
at run time, default 48; a positive integer, pinned in the run-manifest on the first run so a resume
never repartitions cells that are already done; a full review at any other value reports its
health score as provisional, since the group size changes how much a scan finds (#1495) — `driver
setup` takes the same flag for the setup-time cap, see Driver setup), `--include-fixtures` (keep
tool findings under test-fixture corpora;
default prunes them in every mode — incl. redteam, #1055 — for parity with the review-side prune,
though under redteam the prune is disclosed and the gate counts it anyway, #1740; pass to opt in),
`--tools-exclude GLOB` (drop tool findings whose path matches GLOB; repeatable, for additional
non-fixture paths), `--doc-paths GLOB` (doc-tree globs for the planning-doc severity policy; in
standard mode, non-secret code findings under doc trees are soft-downgraded to INFO -- secrets keep
severity, redteam bypasses entirely, and every downgrade is disclosed at
`meta.coverage.doc_policy`). Only a path that names an existing regular file under `--root` (else
`--target`), spelled with no `.`, `..` or empty component and reached through no symlink, is
downgraded; a doc-glob match that names no such file keeps its severity and is counted in
`doc_policy.not_a_doc_file` (#3207). `--files` is a normal whole-file review of the files it names.
`--base`, `--diff-context` and `--gate-scope` belonged to delta review and are refused (#3735,
#3736).

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
  restored `gemini` row (#1621 -> #3494).
- [Code layout (5.2)](guide/code-layout.md) — which module owns what behind
  `skill/scripts/synthesize.py`, `skill/scripts/driver.py` and `skill/scripts/host_probes.py`.
- [Testing scanner fixtures (optional)](guide/testing-scanner-fixtures.md) — the local Docker
  fixture suite for validating scanner adapters against intentionally vulnerable applications.
- [Evidence](guide/evidence.md) — the two independent axes a finding carries, severity and
  `evidence.status`; what health and the gate count, and how citations are treated.
- [Notes](guide/notes.md) — reviewer confinement: the write guard, the read guard, hostile-content
  review, and the two refusals that cover a prepared tree.
