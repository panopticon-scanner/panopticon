# Family PR guardrails

One document for every agent family that makes its CLI a **first-class host**.
It says what you are building, what you may not break, and how the PR proves
itself. Everything else about *how* you work is yours to decide.

Three families have landed under it -- Claude (#1618), Codex (#1619) and Kimi
(#1620) -- and section 2 is the record of what each one proves. Their landing
changed nothing in sections 3 and 5: those bind the next PR exactly as they
bound theirs, whether that PR is a re-attempt for a retired row or a host with
no row yet.

If you were handed this file as your first instruction, the launch prompt at
the bottom is what your operator ran. Read the whole document once before
touching the tree; then keep only the checklists open.

## 1. The deliverable

Panopticon runs the same review pipeline on every host. The host-specific
part is a thin seam, and your PR fills in that seam for your family:

| You deliver | Where | Reference implementation |
|---|---|---|
| A headless runner | `skill/scripts/runners/<host>.py` exposing `Runner(HostRunner)` — `prepare`, `run_entry`, `launch_env` if your host needs more than `os.environ`, and `CLI` / `ENVELOPE_FLAGS` if your usage figures come from a launch envelope | `skill/scripts/runners/claude.py` |
| Probes for every capability you claim | `skill/scripts/probes/<host>.py` for the probe functions, with the probe id registered in `skill/scripts/host_probes.py` (`PROBE_IDS` **and** `PROBE_CAPABILITY`, plus the `probes=` mapping on your `HostSpec` row). A probe that spawns your CLI puts a module-level `DEFAULT_RUNNER` in that same module and adds it to `LAUNCH_SEAMS` in `tests/conftest.py` | `probes/common.py`'s `probe_registered_shell_tools`, `probes/claude.py`'s `probe_write_guard_armed` / `probe_read_guard_armed` |
| A shell emitter branch | `skill/scripts/dispatch.py` `emit_host_agents` (one `elif` for your `shell_format`) | the claude / kimi / codex branches already there |
| Your registry row, and only yours | `skill/scripts/hosts.py` `HOSTS[<host>]` | any existing row |
| Read and write confinement for your host | your own primitive: tool omission, sandbox policy, `--add-dir`, `disallowedTools`, a hook, whatever your host actually enforces | three different primitives for the same guarantee: `skill/scripts/read_guard_hook.py` + `write_guard_hook.py` (Claude), `skill/scripts/kimi_guard_hook.py` (Kimi), `skill/scripts/codex_read_tools.py` behind a read-only sandbox (Codex). Copy the *idea*, not the file |
| Tests and docs for all of the above | `tests/`, `docs/PANOPTICON.md`, `skill/SKILL.md` | the guards in `tests/test_skill_md.py` |

The seam's contract, in `skill/scripts/runners/base.py`:

- `Runner.prepare(run_dir, review_root)` is idempotent and acquires whatever
  your host needs for one run under `run_dir` (`.panopticon/runs/<tag>/`):
  Claude resolves its three guard paths and creates the folder, Kimi mints a
  per-run home. It does NOT arm the guards -- `orchestrate.Guards.arm` writes
  `host-settings.json` through the hooks' own installers before every batch,
  so a `prepare` that wrote it too would be a second definition of the same
  contract, immediately overwritten (#1616 item 5). Nothing in the loop
  assumes a hooks file.
- `Runner.run_entry(entry, env) -> RunResult` launches one entry as a child
  process and returns `RunResult(entry_id, ok, text, usage, cost_usd, model,
  session_id, denials, error)`. It never raises: a crash is
  `RunResult.failed(entry_id, error)`. The pool is inherited, in both its
  shapes: `iter_batch` yields `(entry, result, timing)` as each entry
  completes — the loop persists and ledgers it there and then (#1636) — and
  `run_batch` drains that and returns results in entry order. Your family
  overrides neither; only the session runner does, to print the batch
  instead of launching it.
- `env` is an **overlay**: `PANOPTICON_ENTRY_ID`, `PANOPTICON_WRITE_ALLOWLIST`,
  `PANOPTICON_READ_SCOPE`. The child must get `os.environ` **plus** these three;
  a child that gets only these three has no `PATH` and cannot start.
- `Runner.launch_env(overlay=None) -> dict` is that merge, and it is the **one**
  place your family prepares a child environment. The default is `os.environ`
  plus the overlay; override it if your host needs more, and do not rebuild the
  dict inside `run_entry` — call this. Claude's pops `CLAUDECODE` so a nested
  session will launch, Kimi's points `KIMI_CODE_HOME` at the run's home and
  drops its own session markers, Codex needs nothing beyond the default and so
  does not override it; find your own equivalent. The probes call it too (the
  usage probe interrogates your CLI's `--help` under it), so a preparation that
  lives only in `run_entry` means the probe measures your CLI under an
  environment you never launch with (#1626).
- `CLI` and `ENVELOPE_FLAGS` name the binary you launch and the argv tokens that
  make ONE launch print the parseable envelope your usage figures come from
  (claude: `-p --output-format`; codex: `exec --json`). The **usage-source probe
  reads them**: it looks for `CLI` on PATH and requires its `--help` to advertise
  every flag in `ENVELOPE_FLAGS` before it will believe the dispatch ledger, so
  any executable that merely shares your binary's name proves nothing. Leaving
  either empty is legal and honest — the probe reads `unknown` for
  `usage_ledger` and its detail says which one you left empty — and is right for
  a host whose usage evidence is not a launch envelope at all (Kimi reads a
  session wire file and maps `usage_ledger` to its own probe). What it will
  never do is read `proven` from an empty list (#1626).
- `OUTPUT_SCHEMA_FLAG` is optional and empty by default. Set it to the argv
  token(s) that make ONE launch constrain its final message to a JSON Schema
  (claude: `("--json-schema",)`; codex: `("--output-schema",)`), and append
  `schema.schema_argv(self.OUTPUT_SCHEMA_FLAG, entry)` (`runners/schema.py`) to the argv your
  `command()` builds — that helper returns the flag plus the entry's
  `output_schema` only when the entry names one AND the path is one of the
  schemas published under `skill/reference/`, and `[]` otherwise, so you append
  it unconditionally. **Check what your CLI wants after the flag — a path or
  the text.** codex's `--output-schema <FILE>` takes the path, which is what
  `schema_argv` hands over by default; claude's `--json-schema <schema>` takes
  the JSON itself and refuses a path (`--json-schema is not valid JSON`, exit
  1, no envelope — run 14 burned 3 × 103 launches on it), so the claude runner
  passes `inline=True` and gets the published file as one line of JSON. The
  `--help` probe that marks the flag `advertised` cannot see this: it reads the
  flag's name, not its shape (#1732). **The driver now proves the shape for
  you**, with one real launch on the first headless invocation of every run —
  see the shape-proof bullet below — so a family that gets this wrong costs its
  operators one launch and a disclosure line rather than three launches per
  entry per checkpoint. Check it anyway: a refuted shape means nothing you
  ship under that flag ever reaches a launch. Leaving it empty is the right answer for a CLI that
  advertises no such flag (Kimi): nothing is stamped on your entries and your
  `command()` is unchanged. Do **not** pass the flag on your own authority: a
  CLI that does not know the option exits non-zero on it and takes every entry
  of every checkpoint down with it, so the driver stamps `output_schema` on an
  entry only after the **cli-flags probe** (`probes/common.probe_cli_flags`)
  has seen your CLI advertise it.
- `HELP_ARGV` goes with it, and defaults to `("--help",)`. It is the argv that
  makes your CLI print the help text listing that flag — the **subcommand your
  runner actually drives**, not necessarily the bare binary: codex sets
  `("exec", "--help")` because `--output-schema` belongs to `codex exec` and
  `codex --help` lists subcommands, not their options. Set it whenever your
  flags live behind a subcommand; a wrong answer here reads as "the CLI does
  not advertise the flag", which is fail-safe (no schema is passed) and
  silently costs you the feature.
- The cli-flags probe runs on **every headless run** for every host whose
  registry row declares the fact (`HostSpec.cli_flag_facts`, pinned by test to
  the runners that declare `OUTPUT_SCHEMA_FLAG`), independent of what your host
  claims. It is one `--help` read through `Runner.runner`, and its answer is
  recorded in `host-capabilities.json` under `cli_flags`, **beside**
  `capabilities` and never inside it: a CLI upgraded between two turns of a
  resumable loop must not read as posture drift. `advertised` is a tri-state
  (`true` / `false` / `null` when the read could not be made) and only `true`
  passes the flag; `host_disclosure.notes` says so on all four surfaces when it
  is anything else.
- **The shape proof runs automatically, once per run**, for any family whose
  `OUTPUT_SCHEMA_FLAG` is non-empty and whose flag the `--help` read found
  `advertised` (#1732). It happens **inside the loop**
  (`loop_batch.prove_output_schema_shape`, driven from `orchestrate.loop`), on
  the first batch that carries a schema-stamped `return_json` entry and
  **after `Guards.arm`** — so the probe launch is confined by that batch's own
  read scope and write allowlist, and the `host-settings.json` your argv names
  has been written. `probes/shape.py` builds the entry: the reserved id
  **`probe-output-schema`**, which is never in a dispatch request, never
  ledgered and never persisted; the published
  `skill/reference/probe-output-schema.json`; and the `agent`, `enforced` and
  `model` **copied off a real pending cell**, so it goes out under the same
  shell, posture and model an entry will. It runs through **your own
  `run_entry`** with `max_turns = 1` and `entry_timeout = 30` (saved and
  restored around the launch), and its env is `Guards.env_for(probe_entry)` —
  the same three binding keys a cell gets. Its `out_file` is under the run
  folder and deliberately **not** in the write allowlist: a probe with a side
  effect is not a probe, and the guard denying a write is the correct outcome.
  The verdict is written beside `advertised` as `shape`: `proven`, `refuted`
  (an entry-class failure in under 2000 ms, from a CLI that really started,
  with no envelope — the launch refusing its own argv) or `unmeasured`
  (a host-class failure, a timeout, a `LaunchRefused`, or a refusal of yours
  that never reached the CLI). Only `refuted` changes anything: the flag comes
  off that batch's entries in memory before they launch, and every later
  request is regenerated without it. Two consequences for a family PR: do not
  use `probe-output-schema` as an entry id, and make sure your `run_entry`
  builds the same argv for it as for the cell it was cloned from — a
  precondition refusal of your own reads as `unmeasured`, so the shape of your
  flag simply never gets proven.
- `RunResult.stderr` (#1732) is what your CLI printed on stderr, and you fill
  it on a FAILED result only: `base.stderr_head(proc.stderr)` gives you the
  first `base.STDERR_HEAD` (200) characters, redacted before they are cut. The
  ledger writes it as a row field on failed rows (redacted and bounded again
  there), so an operator reading `dispatch-ledger.jsonl` gets the CLI's own
  diagnosis beside your composed `error` message. It is deliberately NOT fed
  to the outage classifier — `host_error` still decides whose failure it was —
  and a successful result carries none.
- `Runner.teardown(status)` releases whatever `prepare` acquired. The loop calls
  it exactly once, from `orchestrate._finish`, on a terminal status and never
  between iterations, and hands it that status so a runner can drop a scratch
  area on `complete` and keep it for debugging otherwise. Kimi's per-run home is
  what needed it; Claude and Codex release nothing and inherit the no-op.
- `namespace` and `dispatch_request` are set by the loop **before** `prepare`
  (`"setup"` under `--setup` and otherwise `None`; the absolute path the pending
  entries came from), and `run_home` is read off the runner **after** it -- a
  scratch directory outside the reviewed tree, so a probe can find this run's
  children without opening a file the target is free to rewrite.
- `roles` and `request_sha256` are set by the loop **per checkpoint**, before
  each batch (#1727). `roles` is the tuple of `dispatch.ROLE_FILES` keys that
  checkpoint dispatches, and you MUST pass it through: every
  `base.registered_agent(entry)` / `base.refuse_unregistered_agent(entry)` call
  on your launch path becomes `(entry, roles=self.roles)`. The allowlist alone
  accepts any registered shell for any round, so without this a
  `verify` entry naming `panopticon-domain-panel` launches a reviewer's
  write-granting charter in a round that only adjudicates. The `scan`
  checkpoint's row is `("setup_scan",)` (#1737): `--setup` dispatches one
  shell, and only that one. `request_sha256` is
  the hash the run manifest recorded for `dispatch_request`; only session mode
  reads it (it prints it so the host can check the file it is about to read),
  and a headless runner, which gets its entries in memory, needs nothing from
  it.
- `HONOURS_MAX_TURNS = False` says your CLI has no turn cap for `--max-turns` to
  reach. The loop sets `runner.max_turns` unconditionally, so declare it rather
  than accepting the flag and ignoring it in silence; Codex does.
- `default_concurrency` is yours to set, up to `base.MAX_CONCURRENCY` (8).
  `driver loop --concurrency` overrides it and is clamped to the same
  ceiling by `HostRunner.batch_width`, which is the ONE place the bound is
  applied -- never re-derive the pool width yourself (#1576).
- `runner_for(host, mode)` finds you by module name. `headless_available(host)`
  is true once `skill/scripts/runners/<host>.py` exposes `Runner`; until then
  `driver loop --host <host>` runs in session mode and says so.

The loop (`driver loop`, in `skill/scripts/orchestrate.py`) owns everything
else: arming and disarming guards around every batch, persisting
`delivery: return_json` replies through `phases/persist.py`, the dispatch
ledger, `usage.json`, retries, the per-entry cap of three consecutive failed
launches, and the session-mode `dispatch` exit. It also owns what happens to a
reply it could not use: a refused reply, and the partial output a timed-out
launch printed, are kept redacted under `runs/<tag>/rejected/` and named by the
ledger row — your runner returns the evidence on the `RunResult`
(`RunResult.failed(entry_id, error, usage=..., text=...)`, both optional) and
writes nothing itself, because `runners/` may not import `phases/`. Do not reimplement any of it in
your runner, and do not import `driver`, `orchestrate`, `synthesize`, or
`phases` from `runners/` (the layout test forbids it). Your runner's whole
input is `entry`, `env`, and the paths in `env`; its whole output is
`RunResult`.

## 2. The capability registry is the contract

`skill/scripts/hosts.py` declares five capabilities. A claim is a promise; only
a probe makes it **proven**. Anything unprobed reads `unknown` forever, and
`unknown` fails closed everywhere.

| Capability | What it means for your host |
|---|---|
| `tool_policy_enforced` | The shells you register really do restrict the reviewer's tools, on the **effective** surface (not just the file you wrote). |
| `read_scope_confined` | A reviewer can read only the files in its entry's `scope` (`entry["scope"]["files"]`, or `["dirs"]` for the setup scan). |
| `artifact_write_guard` | A self-writing reviewer can write only its own `out_file`. If your host cannot mediate writes, do not claim it: every role then runs as `delivery: return_json` and the loop writes the file. That bridge already exists and is the honest default. `--allow-unenforced` records an operator's acceptance of an unmediated write in `unenforced-ack.json`; it is a risk acceptance, not a substitute for a probe you could write. |
| `model_binding` | The model named on the entry is the model that runs. |
| `usage_ledger` | Tokens and cost per launch come back in the envelope your runner parses. |

Rules that follow from the registry:

- `driver_selectable` flips **in the same PR** that proves the security
  capabilities (`tool_policy_enforced`, `read_scope_confined`), and never
  before: a row that is selectable while proving nothing is what #1344 exists
  to end, and it is what cost Gemini its row (#1621). The shortfall is pinned
  by name in `tests/test_generic_retirement_bar.py`
  (`test_todays_shortfall_is_pinned_so_it_moves_consciously`), and it reads
  `{}` on this base because every host the bar examines -- claude, codex
  (#1619) and kimi (#1620) -- clears both. A PR that flips a row re-pins that
  assertion, alongside the `--host generic` paragraph in
  `docs/PANOPTICON.md`, in the same commit as the probes that earn it.
- Populate `discovery_surface` for your host from the #1657 spike table:
  what the REVIEWED tree can ship that your CLI discovers from it, one row
  per cell, `OPEN` when nothing in your launch closes it and `CONTROLLED`
  when something does. Every CONTROLLED entry needs a pinned control in
  `probes/common.CONTROLS`, asserted against your runner's own `command()`
  argv (or, when the control is not a flag, against its mechanism) by
  `tests/probes/test_discovery_surface.py`. An empty row is not a neutral
  default: it makes `target-discovery-surface` scan nothing and report that
  the target ships nothing -- the reassuring answer, reached by not looking.
- Never test a host by name in a phase (`host == "codex"`). Route every
  decision through `hosts.posture()` or `hosts.declares()`; an AST guard in
  `tests/test_host_posture_wiring.py` rejects the comparison.
- A probe returns `(state, by, detail)` with state `proven`, `refuted`, or
  `unknown`. A probe that cannot run returns `unknown` with the reason. Never a
  guess, never a boolean.
- A probe must be able to **refute**. For each probe, run the mutation: break
  the thing it checks (remove the tool restriction, widen the read scope, point
  the write at a second file) and show the probe flips to `refuted`. Put that
  evidence in the PR description; a probe that can only say `proven` is not a
  probe.

### The seam, as built

Every family fills in the same shape. A `Runner` in
`skill/scripts/runners/<host>.py` implements the contract in `runners/base.py`,
which also owns the single `LaunchRefused` every launch site raises and catches
-- one class, so two `except` clauses cannot disagree about what a refusal
means. The probes live in `skill/scripts/probes/<host>.py` and are registered
in `skill/scripts/host_probes.py`, which is the registry and not the probes.
Every module that starts a host CLI exposes a module-level `DEFAULT_RUNNER` and
is listed in `tests/conftest.py`'s `LAUNCH_SEAMS` -- six seams across three
families today -- and `tests/test_host_launch_guard.py` walks the AST so a
seventh cannot be added silently. A family's `DEFAULT_RUNNER` ships as `None`,
the sentinel `HostRunner.launcher(runner, DEFAULT_RUNNER)` resolves to the
seam's own `HostRunner.launch` (#1575): a `subprocess.run`-shaped call that
puts the child in its own session, registers it while it runs, and ends the
whole PROCESS GROUP on the entry timeout. Do not call `subprocess.run` in a
family -- a host CLI spawns its own workers, and a timeout that kills the
direct pid leaves them running and charging.

### What each landed host proves

**Claude (#1618)** claims all five. `tool_policy_enforced` is proven by the
shared `registered-shell-tools` probe in `probes/common.py`; the other four by
`read-guard-armed`, `write-guard-armed`, `entry-model-bound` and `usage-source`
in `probes/claude.py`. `skill/scripts/runners/claude.py` sets `CLI = "claude"`,
`ENVELOPE_FLAGS = ("-p", "--output-format")` and `default_concurrency = 8`; its
`prepare` resolves the run folder's `host-settings.json` / allowlist / scope
paths (the loop's `Guards.arm` is what writes that file) and its `launch_env`
pops `CLAUDECODE` so a nested session will start. Every launch also carries
`--setting-sources user`, `--strict-mcp-config` and `--disable-slash-commands`
(#1657), so a target's `.claude/settings*.json`, `.mcp.json`,
`.claude/skills/*/SKILL.md` and `.claude/commands` are not read -- the last two
because `--disable-slash-commands` is "Disable all skills" in `claude --help`; `--settings` is a separate channel that still
applies under `--setting-sources user`, which is what keeps the two guards
armed. `--bare` and `--safe-mode` are never passed -- both disable hooks. Still open
on #1657: a target's `.claude/agents/*.md` and its plugin/workflow directories,
which only `--safe-mode` would close. Confinement is two PreToolUse
hooks, `skill/scripts/read_guard_hook.py` and
`skill/scripts/write_guard_hook.py`. Evidence: `driver loop . --host claude
--reset --no-tools -d skill/scripts/runners` reached `status: complete` with 15
of 15 launches ok, all five capabilities `proven`, and four natural read
denials -- each a verifier's Grep over a directory, which the guard denies by
design.

**Codex (#1619)** claims the two security capabilities and nothing else, so
every Codex role runs as `delivery: return_json` and the loop writes the file.
`tool_policy_enforced` is proven by `codex-effective-tools` and
`read_scope_confined` by `codex-read-scope`, both in `probes/codex.py`, and
both interrogate the **effective** runtime surface through the localhost-only
Responses fixture in `skill/scripts/codex_host.py`: a read-only TOML profile is
not evidence, because parent-runtime permission overrides are reapplied to
child agents. `skill/scripts/runners/codex.py` sets `CLI = "codex"`,
`ENVELOPE_FLAGS = ("exec", "--json")`, `HONOURS_MAX_TURNS = False` and
`default_concurrency = 4`. Confinement is a read-only sandbox plus the scoped
MCP read broker `skill/scripts/codex_read_tools.py`, which the emit branch
registers as `panopticon_scope` with `read_file` / `search` / `list_files` and
no write tool at all. The child's process cwd is the same empty, run-owned
scratch directory `--cd` names, outside the review root (`codex_host.launch_cwd`,
#1657): both roots are one directory, so whichever the CLI keys discovery off,
the target's `AGENTS.md`, `.codex/skills` and `.codex/config.toml` are out of
reach -- `features.skip_host_skill_discovery` is measured NOT to close them. Evidence: `driver loop . --host codex --mode headless -d
skill/scripts/runners --no-tools --allow-unenforced` reached `status:
complete`, with both claimed capabilities `proven` and the three unclaimed ones
`unknown`, each detail saying in as many words that the host does not claim it,
so there is nothing to prove.

**Kimi (#1620)** claims all five, proven by `kimi-shell-surface`,
`kimi-read-guard-armed`, `kimi-write-guard-armed`, `kimi-model-alias-bound` and
`kimi-usage-wire`, all in `probes/kimi.py`. `skill/scripts/runners/kimi.py`
sets `CLI = "kimi"` and leaves `ENVELOPE_FLAGS` empty on purpose -- Kimi's
usage evidence is a session wire file, not a launch envelope -- and its
`prepare` mints a per-run Kimi home outside the reviewed tree, which
`teardown(status)` removes; `launch_env` points `KIMI_CODE_HOME` at it.
Confinement is `skill/scripts/kimi_guard_hook.py`, registered as two PreToolUse
hooks in that home's `config.toml`, over a `tools.disabled` deny-list derived
from the CLI's own vocabulary minus what the role templates grant. Each launch
also carries `--skills-dir=<per-run home>/no-skills`, an empty run-owned
directory that replaces both auto-discovered skill roots (#1657), and the
freshness of that home is itself the control on target-planted MCP: kimi reads
`<git root>/.mcp.json` and `<cwd>/.kimi-code/mcp.json` only for a cwd with a
workspace-trust record under `KIMI_CODE_HOME`, and a home linking only
`credentials`/`oauth` has none. Still open on #1657: the target's `AGENTS.md`,
loaded root-to-leaf into the system prompt, which no flag or config key
disables. Evidence:
run `kimi-standard-repo-20260913-88aaffdb` reached `status: complete` -- 284
ledger rows, 37 launches, 23.2M tokens read off the wire files, all five
capabilities `proven`. That run was measured before the branch's four
gate-review fix rounds, and the PR records that a run on the corrected branch
is still owed.

**Gemini** is registered and **not** driver-selectable (#1621, retired
2026-09-13 by #1625). The row stays, so the name still resolves everywhere and
every surface answers for it honestly; it claims nothing, and `--host gemini`
is refused with the remedy rather than a bare word list. A Gemini operator runs
`--host generic`, the same path as any host whose family has not shipped a
runner. A re-attempt starts from the Kimi or Codex shape -- a
`skill/scripts/runners/gemini.py`, its own `probes/gemini.py`, an emit branch,
both security capabilities probed and mutation-refuted -- clears section 5 in
full, and attaches a real `driver loop . --host gemini` run. The row flips back
in the same PR as the probes that earn it, never ahead of them.

## 3. What you may not do

These are the guardrails. Every one of them has cost a real run before.

Repository:

- Work on a branch named `feat/1344-<host>-first-class-host`, rebased on
  `main` before you open the PR. Never commit to `main`. One PR per family,
  against `main`, milestone `5.2`, label `enhancement`. Conventional commit
  messages (`feat(runners): …`, `fix(probes): …`, `docs(hosts): …`).
- Change `skill/scripts/hosts.py` in exactly one place: your row. Do not
  touch another family's row, runner, probes, or emit branch. Host-specific
  tool-name mapping lives inside your emit branch, never in the shared
  templates under `skill/agents/`.
- Never commit anything under `.panopticon*/` (it is git-ignored on purpose).
  The self-scan review matrix lives at the repo root as `panopticon.yml`,
  committed by construction and maintained by the core stack (#1638 P06,
  #1681), guarded by `tests/test_matrix_coverage.py`. Your PR still commits
  nothing under `.panopticon*/` -- run artifacts least of all.
  Never commit shells, settings, or anything else that lives under a home
  directory.
- Do not weaken a test or a doc guard to make it pass. Update an expectation
  only when its own comment says your PR is the one that moves it — the
  retirement-bar pin, the host table in `docs/PANOPTICON.md`, that
  document's `gemini` sentence, and this document's own §2/§6 guards in
  `tests/test_family_guardrails_doc.py` (each names the PR that moves it:
  yours, when you add your host's §2 paragraph) — and nothing else. If a
  guard blocks you for
  another reason, that is a finding to report, not a line to delete.
- Do not `git stash`, do not force-push a shared branch, do not rewrite
  history after a review has started.
- Text that came out of a scan (findings, agent replies, run logs) goes
  through `scripts/sanitize.py` (`scrub()` then `defang()`) before it is
  pasted into an issue or a PR body.

Machine:

- Register your own shells with `python3 skill/scripts/dispatch.py
  --emit-host-agents <host>`; that writes only `panopticon-*` files under your
  family's registration dir and prunes only those. It writes one shell per
  `dispatch.ROLE_FILES` row -- today `panopticon-scout`,
  `panopticon-advisor`, `panopticon-domain-panel`, `panopticon-domain-advisor`
  and `panopticon-setup-scan` (#1737: `driver setup`'s classifier, whose shell
  grants Read/Grep/Glob and deliberately binds NO model, so the session's own
  model runs it). Your emit branch must render every one of them. Do not hand-edit anything
  else under `~/.claude`, `~/.codex`, `~/.kimi-code`, or the Gemini config, and
  never touch this repo's `.claude/settings.local.json` (it is the Claude
  write-guard's install target; the headless loop never touches it either).
- One Panopticon run at a time on this machine. Two loops against the same
  target race on `dispatch-request.json` and the ledger.
- Runs cost money. Use `--max-budget-usd` and `--max-iterations` on any run
  you are not sure about, and `-d`/`-g` scoping while you iterate.

Suite:

- The test suite must never launch the real host binary. Your `Runner` takes
  an injectable `runner=` callable (whose default resolves to the seam's own
  `HostRunner.launch`) and every test passes a fake; loop-level tests patch
  `scripts.runners.base.runner_for`. A test that shells out to `codex`,
  `gemini`, or `kimi` is a defect, even when it passes on your machine.
- Tests use temp dirs only: never this repo's `.panopticon/`, never a home
  directory, never the network.

## 4. What you may do

Everything else. In particular, use every capability your default
installation ships: parallel workers and sub-agents (Claude's workflows and
subagents, Kimi's swarm, Codex's own, and whatever your CLI ships for the same
job), skills, plugins, extensions, MCP servers, planning modes, background
jobs. The
guardrails above bind every worker you spawn exactly as they bind you; how you
split the work, review it, and pace it is your call. The only process rule is
the one in the next section: the PR proves itself.

Treat `docs/PANOPTICON.md` as the user guide (the "Driver run-loop" and "Host
capabilities" sections are the ones that matter to you), `CONTRIBUTING.md` as
the repo's own rules, and the specs in the private docs repo (your operator
will paste the relevant sections if you cannot reach it) as the authority when
this file and the code disagree.

## 5. How the PR proves itself

Run these on your final tree and quote the results in the PR description:

```
python -m pytest tests/ -q
python -m ruff check skill/scripts/ tests/
```

CI runs the test command on Python 3.11, 3.12, 3.13 and 3.14, and the lint
command once on 3.12. The local interpreter is newer than the CI floor, so run
at least your own test files under 3.11 before pushing (`uv run --python 3.11 --with pytest --with
pyyaml -q python -m pytest tests/runners tests/probes tests/test_host_probes.py
-q` is enough). Argparse and `typing` differ across that range; the 3.11 leg is
the one that finds it.

Then the evidence only a real run can give:

1. `driver loop . --host <host>` on this repository, from a clean tree,
   reaching `status: complete`. Attach the scrubbed
   `.panopticon/runs/<tag>/host-capabilities.json`; every capability you claim
   must read `proven`, with a `by` that names your probe and a `detail` that
   names the file or surface it inspected.
2. The mutation runs from section 2, one per probe, each showing `refuted`.
3. `python3 skill/scripts/dispatch.py --emit-host-agents <host>` followed by
   `driver setup .` showing your shells registered and no shadow shells --
   `panopticon-setup-scan` included, without which `driver setup` refuses
   unless the operator passes `--allow-unenforced` (#1737).
4. For read confinement: one dispatched reviewer attempting a read outside its
   `scope` and being denied, on your host, by your primitive. Show the denial.

The PR description names every test whose expectation you moved and quotes
the comment that authorised it. The owner reviews and merges; nothing merges
on green CI alone.

## 6. Launch prompt

What the operator pastes into your CLI. `<host>` is the host this PR makes
first-class: a re-attempt for a row that was retired, or a host with no
registry row yet. Every family recorded in section 2 has already landed its
own, so their PRs are worked examples to read, not work to repeat.

```
You are the <host> family agent for Panopticon. Your deliverable is the
<host> first-class host PR described in docs/FAMILY-PR-GUARDRAILS.md in this
repository. Read that file first and follow it exactly; it is the whole set
of constraints. Within them, use every tool, skill, plugin, and parallel
capability your installation provides, and manage the work however you judge
best. Work on branch feat/1344-<host>-first-class-host, open one PR against
main with the evidence section 5 asks for, and stop there: the owner reviews
and merges. If the guardrails and the code disagree, say so in the PR rather
than picking silently.
```

## 7. Owner decision (2026-09-15, D1)

Spec 8.1 made deleting `--host generic` (F5) mechanical: it ships once every
remaining driver-selectable host has `tool_policy_enforced` and
`read_scope_confined` proven, with `artifact_write_guard` bridged by
construction. On this base that criterion was **met** -- the pin in section 2
reads `{}`.

Met was not due. `--host generic` is the only path left for a Gemini operator
and for any host whose family has not shipped a runner, so deleting it was an
owner **policy** decision rather than a consequence of the bar clearing: the
bar could say that no remaining selectable host fell short, but it could not
say there was anywhere else for those operators to go. The decision, its
options and a recommendation were written up as section 8.3 of the
first-class-hosts design spec in the private docs repo (panopticon-docs #55).

The owner's ruling, D1 (2026-09-15), chose **option 1**: keep `--host generic`
as the permanent, unenforced, ack-gated fallback, and retire F5 -- there is no
deletion left to ship. The row stays registered and selectable, and its notice was reworded
from a deprecation to a posture statement (`hosts.is_unenforced_fallback`,
`host_disclosure.GENERIC_FALLBACK_NOTICE`): it names the capability it lacks
and the role it plays, and drops the promise of a removal the bar was never
able to trigger on its own. Spec 8.1's bar itself is **kept**, reframed from
F5's entry criterion into a standing NO-REGRESSION GUARD: every remaining
driver-selectable host must go on clearing both security capabilities. Two
tests carry it -- `test_generic_retirement_bar` states the criterion, and
`test_todays_shortfall_is_pinned_so_it_moves_consciously` pins today's
shortfall at `{}`, so a family PR that regresses a capability fails the pin
(the criterion itself is only enforced once the fallback row is gone). A family PR that lands after this decision still gets `--host
generic` as the fallback it describes, permanently.
