# Family PR guardrails

One document for every agent family (Codex, Kimi, and Claude when it touches
its own host code) that authors its **first-class host** PR. It says
what you are building, what you may not break, and how the PR proves itself.
Everything else about *how* you work is yours to decide.

If you were handed this file as your first instruction, the launch prompt at
the bottom is what your operator ran. Read the whole document once before
touching the tree; then keep only the checklists open.

## 1. The deliverable

Panopticon runs the same review pipeline on every host. The host-specific
part is a thin seam, and your PR fills in that seam for your family:

| You deliver | Where | Reference implementation |
|---|---|---|
| A headless runner | `skill/scripts/runners/<host>.py` exposing `Runner(HostRunner)` | `skill/scripts/runners/claude.py` |
| Probes for every capability you claim | `skill/scripts/host_probes.py` (a probe id in `PROBE_IDS` **and** `PROBE_CAPABILITY`, and the `probes=` mapping on your `HostSpec` row) | `probe_registered_shell_tools`, `probe_write_guard_armed`, `probe_read_guard_armed` |
| A shell emitter branch | `skill/scripts/dispatch.py` `emit_host_agents` (one `elif` for your `shell_format`) | the claude / kimi / codex branches already there |
| Your registry row, and only yours | `skill/scripts/hosts.py` `HOSTS[<host>]` | any existing row |
| Read and write confinement for your host | your own primitive: tool omission, sandbox policy, `--add-dir`, `disallowedTools`, a hook, whatever your host actually enforces | `skill/scripts/read_guard_hook.py`, `skill/scripts/write_guard_hook.py` (Claude-only by construction; copy the *idea*, not the file) |
| Tests and docs for all of the above | `tests/`, `docs/PANOPTICON.md`, `skill/SKILL.md` | the guards in `tests/test_skill_md.py` |

The seam's contract, in `skill/scripts/runners/base.py`:

- `Runner.prepare(run_dir, review_root)` is idempotent and arms whatever your
  host needs for one run under `run_dir` (`.panopticon/runs/<tag>/`). Claude
  writes `host-settings.json` there; your host may need something else or
  nothing. Nothing in the loop assumes a hooks file.
- `Runner.run_entry(entry, env) -> RunResult` launches one entry as a child
  process and returns `RunResult(entry_id, ok, text, usage, cost_usd, model,
  session_id, denials, error)`. It never raises: a crash is
  `RunResult.failed(entry_id, error)`. `run_batch` (a thread pool) is inherited.
- `env` is an **overlay**: `PANOPTICON_ENTRY_ID`, `PANOPTICON_WRITE_ALLOWLIST`,
  `PANOPTICON_READ_SCOPE`. The child must get `os.environ` **plus** these three;
  a child that gets only these three has no `PATH` and cannot start. Claude also
  pops `CLAUDECODE` so a nested session will launch; find your own equivalent.
- `default_concurrency` is yours to set. `driver loop --concurrency` overrides it.
- `runner_for(host, mode)` finds you by module name. `headless_available(host)`
  is true once `skill/scripts/runners/<host>.py` exposes `Runner`; until then
  `driver loop --host <host>` runs in session mode and says so.

The loop (`driver loop`, in `skill/scripts/orchestrate.py`) owns everything
else: arming and disarming guards around every batch, persisting
`delivery: return_json` replies through `phases/persist.py`, the dispatch
ledger, `usage.json`, retries, the per-entry cap of three consecutive failed
launches, and the session-mode `dispatch` exit. Do not reimplement any of it in
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
  to end, and it is what cost Gemini its row (#1621). Today's shortfall is
  pinned by name in `tests/test_generic_retirement_bar.py`
  (`test_todays_shortfall_is_pinned_so_it_moves_consciously`), which reads
  `{}` on this base because claude is the only host the bar examines. Your PR
  puts your host back into that set and re-pins the assertion, alongside the
  `--host generic` paragraph in `docs/PANOPTICON.md`, in the same commit as
  the probes that earn it.
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

Findings already recorded for your family, so you do not rediscover them:

- **Codex.** Parent-runtime permission overrides are reapplied to child
  agents, so a read-only TOML profile is not evidence of the effective policy.
  Your `tool_policy_enforced` probe must interrogate the effective surface. The
  shipped `probe_registered_shell_tools` looks for a `tools:` line your emitted
  shell does not have; it will refute you as written, so write your own probe.
  Read confinement is `--add-dir` plus sandbox policy (issue #1086). Two of
  your registered roles are told to `Write` while your shell is read-only
  (the Codex half of #1520): resolve it by not claiming `artifact_write_guard`
  and letting the `return_json` bridge carry those roles, unless you can prove
  a real guard.
- **Kimi.** A tool name in a shell that matches nothing in the installed CLI
  is warned about and restricts nothing; your probe must verify the shells'
  tool vocabulary against the installed CLI. Agent discovery lets a target's
  `.agents/agents/panopticon-scout.md` shadow the registered shell; the
  shadow-shell scan already refutes `tool_policy_enforced` when it sees one,
  and your probe should agree with it.
- **Gemini.** Retired 2026-09-13 after #1621 failed its gate review twice; the
  row is registered but **not** driver-selectable, and Gemini operators run
  `--host generic`. A future Gemini PR starts from the Kimi/Codex shape and
  must clear §5 before the row flips back.

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
  Never commit shells, settings, or anything else that lives under a home
  directory.
- Do not weaken a test or a doc guard to make it pass. Update an expectation
  only when its own comment says your PR is the one that moves it — the
  retirement-bar pin, the host table in `docs/PANOPTICON.md`, and that
  document's `gemini` sentence, and nothing else. If a guard blocks you for
  another reason, that is a finding to report, not a line to delete.
- Do not `git stash`, do not force-push a shared branch, do not rewrite
  history after a review has started.
- Text that came out of a scan (findings, agent replies, run logs) goes
  through `scripts/sanitize.py` (`scrub()` then `defang()`) before it is
  pasted into an issue or a PR body.

Machine:

- Register your own shells with `python3 skill/scripts/dispatch.py
  --emit-host-agents <host>`; that writes only `panopticon-*` files under your
  family's registration dir and prunes only those. Do not hand-edit anything
  else under `~/.claude`, `~/.codex`, `~/.kimi-code`, or the Gemini config, and
  never touch this repo's `.claude/settings.local.json` (it is the Claude
  write-guard's install target; the headless loop never touches it either).
- One Panopticon run at a time on this machine. Two loops against the same
  target race on `dispatch-request.json` and the ledger.
- Runs cost money. Use `--max-budget-usd` and `--max-iterations` on any run
  you are not sure about, and `-d`/`-g` scoping while you iterate.

Suite:

- The test suite must never launch the real host binary. Your `Runner` takes
  an injectable `runner=` callable (the Claude runner takes `subprocess.run`)
  and every test passes a fake; loop-level tests patch
  `scripts.runners.base.runner_for`. A test that shells out to `codex`,
  `gemini`, or `kimi` is a defect, even when it passes on your machine.
- Tests use temp dirs only: never this repo's `.panopticon/`, never a home
  directory, never the network.

## 4. What you may do

Everything else. In particular, use every capability your default
installation ships: parallel workers and sub-agents (Claude's workflows and
subagents, Kimi's swarm, and whatever Codex and Gemini ship for the same job),
skills, plugins, extensions, MCP servers, planning modes, background jobs. The
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

CI runs the same two commands on Python 3.11, 3.12, 3.13, and 3.14. The
local interpreter is newer than the CI floor, so run at least your own test
files under 3.11 before pushing (`uv run --python 3.11 --with pytest --with
pyyaml -q python -m pytest tests/runners tests/test_host_probes.py -q` is
enough). Argparse and `typing` differ across that range; the 3.11 leg is the
one that finds it.

Then the evidence only a real run can give:

1. `driver loop . --host <host>` on this repository, from a clean tree,
   reaching `status: complete`. Attach the scrubbed
   `.panopticon/runs/<tag>/host-capabilities.json`; every capability you claim
   must read `proven`, with a `by` that names your probe and a `detail` that
   names the file or surface it inspected.
2. The mutation runs from section 2, one per probe, each showing `refuted`.
3. `python3 skill/scripts/dispatch.py --emit-host-agents <host>` followed by
   `driver setup .` showing your shells registered and no shadow shells.
4. For read confinement: one dispatched reviewer attempting a read outside its
   `scope` and being denied, on your host, by your primitive. Show the denial.

The PR description names every test whose expectation you moved and quotes
the comment that authorised it. The owner reviews and merges; nothing merges
on green CI alone.

## 6. Launch prompt

What the operator pastes into your CLI. `<host>` is `codex` or `kimi`.

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
