## Driver run-loop (5.0)

The 5.0 driver (`skill/scripts/driver.py`) runs every mode from Modes above — whole-repo
committed-matrix review, `-f`/`-d`/`-g` scope, `-c`/`--pr` delta — as one resumable state machine;
the host drives it through its status protocol.

**Installed-flow substitution (#495):** `skill/` in every command below means THIS SKILL'S INSTALL
DIRECTORY — literally `skill/` inside the panopticon repo, or the absolute path you installed it to
elsewhere (e.g. `~/.<agent-config>/skills/panopticon/`). Run every command from the TARGET repo root
regardless — `.panopticon/` artifacts and the write-guard resolve against cwd; only the script path
substitutes.

The host contract (5.2, plan 6):

- **Headless (default):** `python3 skill/scripts/driver.py loop <target> [flags]` from the target
  repo root. One process runs the whole review: it calls the engine in-process, and at every
  checkpoint arms the guards, runs each entry through the host's runner
  (`skill/scripts/runners/<host>.py` — `claude -p` per entry for Claude, `codex exec` for Codex,
  `kimi -p` per entry for Kimi), tears the guards down, and calls the engine again until `complete`,
  `error` or `paused`. Read the report. Replies are persisted, ledgered and counted into
  `usage.json` **as each entry completes**, not when the batch does (#1636): the entries in a
  checkpoint run concurrently and finish out of order, each one printing a
  `driver loop: <id> done (<ms> ms, <k>/<n>)` progress line on stderr as it lands, so a crash, a
  `kill` or a compaction mid-batch keeps everything a batch that had already CLOSED had finished,
  and re-running resumes from disk without repeating those; what the killed batch itself had in
  flight is taken back on the next run rather than left half-done (#1698, below). **Ctrl-C is
  deliberately not that** (#1662): it means complete stoppage, cancellation and rollback to the last
  checkpoint. No entry still queued is launched. Every running child is terminated before anything
  else, and as a whole **process group** (SIGTERM to the group, then SIGKILL to whatever has not
  exited within one shared grace window). All three shipped runners register their children for this
  (#1575): Claude, Codex and Kimi launch through the seam's own `HostRunner.launch`, a `Popen` with
  `start_new_session=True`, so each CLI leads its own group and one signal reaches the workers it
  spawned rather than only its own pid. That no longer depends on the terminal's process-group
  SIGINT — which a Ctrl-C at a terminal does deliver, but a Ctrl-C sent to the loop process alone
  does not, and which was the only thing reaching those children while the runners launched through
  a blocking `subprocess.run` that hands back no handle. The same group kill bounds a per-entry
  **timeout**: `--entry-timeout` now ends the tree, not just the CLI at the root of it. Both guards
  then come down **before** any artifact is deleted, so a child that outlived either route is denied
  its write rather than allowed to re-create what is being rolled back. Every entry of the batch is
  then written to the ledger, at the interrupt's own timestamp: a `cancelled` row for one it cut,
  and for one that HAD completed a `rolled_back` marker row beside the real row, which is left
  exactly as it was — the spend it records is a fact, and the marker is what tells a later reader
  that the artifact that spend bought was deleted. Both kinds carry `cost_usd: null` and
  `ok: false`, so `total_cost`, `usage.json` and the usage probe read what they always did. The
  per-entry artifacts the batch had written are deleted **as a unit** — by the list in
  `runs/<tag>/batch-<n>.json`, which the loop writes before its first launch and removes when the
  batch ends, never by a glob over the run folder — so a record still on disk is a batch that ended
  NEITHER way, and the next `driver loop` is what settles it (below). The interrupted **phase**
  therefore re-runs from its checkpoint on the next `driver loop`, with the retry budget it had (an
  operator's interrupt is not a cell failing, so it is given back); phases completed before it are
  untouched, and `usage.json` keeps whatever spend the host had already reported, because spend is a
  fact and is never rolled back. The run ends `error` with a message beginning `interrupted:` that
  says how many of how many entries had been handled and have been rolled back. To discard the
  **whole** run instead of the interrupted phase, re-run with `--reset`.
- **Session mode:** `driver loop --mode session <target>`, and the automatic fallback. When no
  headless runner exists for the host — every host but Claude, Codex and Kimi today, `generic`
  included — the loop degrades to session mode on its own and says so on stderr; pass
  `--mode headless` to require a runner instead, which on such a host is an `error` naming the
  missing `runners/<host>.py`. Either way, or when you simply want to dispatch the agents yourself,
  the loop prints a `dispatch` status naming the pending entry ids and each entry's `prompt_file`,
  leaves the guards armed, and exits 0. Cross-reference those ids against the request file the
  status's own `dispatch_request` field names — read the field, never a fixed path: a review's
  request is per-run (`.panopticon/runs/<tag>/dispatch-request.json`) and `--setup`'s is its own
  top-level `.panopticon/setup-dispatch-request.json`. On Claude Code, run those entries with the
  shipped workflow `skill/workflows/dispatch.js` (`skill/SKILL.md` names the call; it is the
  mandated, templated path — not one-off Agent calls; its enforced/agentType branch, marker-first
  prompt and reply routing are pinned by `tests/test_workflow_dispatch_script.py`, run through a
  small Node harness rather than left untested as Workflow-tool source usually is); on another host,
  however that host likes — but whatever text you dispatch an agent with must begin with
  `entry["marker"]` (`panopticon-entry: <id>`, the first line of `entry["prompt"]`): it already does
  when you pass `entry["prompt"]` verbatim; if you point the agent at `prompt_file` instead, put the
  marker line first and the pointer second — the file is granted to the entry's read scope
  (`scope.reads`, stamped alongside `prompt_file`), so the guard allows that read; `reads` is the
  entry's extra-file allowance, and a builder may grant more there (a SEC cell's prompt points at
  `skill/reference/security-checklists.md`, which its `reads` carries too). On Claude, this is how
  session mode binds an agent to its entry — the read guard reads the marker back from the agent's
  own transcript when `PANOPTICON_ENTRY_ID` is not in its environment (headless mode binds through
  that env var instead, so no marker is needed there); an agent dispatched without the marker is
  denied every read, with a reason naming it. Codex's manual-session posture remains unproven: its
  headless runner supplies the controls described below. Pipe each **return-persist** reply into
  `driver persist <id> --file <reply.txt>` (fully:
  `python3 skill/scripts/driver.py persist <id> --file <reply.txt>`), then re-run
  `driver loop --mode session <target>` with the same flags. Under `--setup`, BOTH commands need
  `--setup` too, so they resolve setup's namespace rather than the review's — the printed status's
  `persist` and `then` hints already carry it. On a `--pr` or `--base` run, pass the same
  `--pr`/`--base` to **both** as well: a PR run's review root is the PR worktree, not your checkout,
  and `driver persist` has to resolve the same one the loop did or it reads a different tree's
  dispatch request and refuses the entry as unknown. The loop **refuses to advance** until the
  entries' out files exist on disk and pass the phase's own done predicate — a re-entry with nothing
  done re-emits the same set; there is no way to advance on a claim.
- **`driver readiness [target] [--host NAME] [--json]` is the preflight, and it is not part of the
  loop.** Run it before you launch anything. It writes nothing under the target and launches nothing
  — host CLIs are located with `shutil.which` and never started, and the Docker probe is the
  readiness phase's own — and prints ONE compact document (a table, or the object under `--json`):
  `guide` (the absolute path of `PANOPTICON.md` inside this install, and whether it exists),
  `sub_skills` (each required `superpowers:*` sub-skill and where it was found, or null), `matrix`
  (the resolved config path, plus groups, code files and test files from the committed
  `panopticon.yml`, or the remedy when there is none), `existing_run` (the tag under `runs/latest`,
  the last state recorded for that run — `complete`, `checkpoint`, `error`, `started` for a run
  folder that has recorded none of those yet, and `none` for no run in this tree at all — and how
  many dispatch entries are still pending, or `null` when that run's request no longer matches the
  hash its manifest recorded, in which case the row says why), `cli` (each host whose registry row
  names a headless binary, plus the selected host always, and whether it is on PATH), `tools_image`
  (the daemon, the image, and the same copy-pasteable remedy the readiness checkpoint refuses with)
  and `capabilities` (what the last run MEASURED, read back from
  `runs/latest/host-capabilities.json`, never re-probed). The host the document is ABOUT is resolved
  by `runio.resolve_host` — the very function `driver loop` asks, in the same order: `--host`, else
  this run's manifest, else the driver's default. So a BARE `driver readiness <target>` reports on
  the same host a bare `driver loop <target>` would drive, and `selected_from` (`"--host"` |
  `"manifest"` | `"default"`, echoed in the table header) says which of the three answered. Gating
  rows are `guide`, `matrix`, `tools_image` and the resolved host's own `cli` row, marked `→` in the
  table: `driver loop` resolves a host to headless whenever `skill/scripts/runners/<H>.py` exists,
  which is a fact about this repo and not about this machine, so a binary that is not there is a
  loop that cannot start, and the row's remedy names both ways out (install it, or
  `driver loop --host H --mode session`). A resolved host that names no CLI of ours — `generic` —
  passes: session mode needs no binary. Every OTHER host's `cli` row, and every `sub_skills` row, is
  reported and never gates — session mode and the built-in defaults in SKILL.md's Dependencies
  section respectively cover them. A row with nothing to remedy carries `null` there and renders
  blank; only the three rows nothing is checked against render `--`. Exit 0 when nothing gating
  fails, 1 otherwise — `driver readiness && driver loop`.
  Since the guide became an index plus chapters (2026-09-24), that `guide` row's `exists` is true
  only when every chapter file is present too, and its remedy names the ones that are not.
- **The loop's first step is the readiness checkpoint.** Before any paid dispatch — before the loop
  arms a guard or runs an entry — the engine runs `readiness` (below). (It is not the very first
  thing the process does: `driver run` establishes the host capability posture first, which on a
  host whose probes interrogate its CLI costs a `--help`-class launch. Readiness itself launches
  nothing, and nothing is *dispatched* before it.): Docker daemon, `panopticon-tools` image, the
  committed `panopticon.yml`, plus this run's host posture and target root as informational rows. It
  **fails closed** — a missing image with tools enabled ends the loop as `error`, with the
  pull/build/`--no-tools` remedies in the message and nothing dispatched — because the alternative
  is what run-13 did: pay for twelve scouts, discover the image was absent, and send 85 panels out
  with no scanner evidence. `--no-tools` is the disclosed opt-out, not a way to silence the check.
- `driver run <target>` remains the single-step primitive underneath both (one status line per
  invocation: `complete`, `error`, or `checkpoint`). It is what the loop calls; drive it by hand
  only when debugging a phase. Re-invoking on an **already-complete** run refuses with an `error`
  naming `--reset` (#1), in every mode.
- **The dispatch request is bound to the run that wrote it (#1727).** `dispatch-request.json` lives
  inside the REVIEWED tree, so the driver hashes the exact bytes it writes and records that sha256
  in the run manifest — `.panopticon/run-manifest.json`, or `setup-manifest.json` under `--setup`,
  which keeps its own request. Every reader checks the file against that record before it trusts a
  single field: the loop (which also carries the hash its own writing phase returned in memory, so a
  manifest edited afterwards is caught too), the re-entry read that decides which grants to disarm,
  and `driver persist`. A file that no longer matches is refused — nothing is armed, launched,
  charged or persisted — and the remedy is always the same, because the request is rolling: re-run
  `driver run`/`driver loop` and the next invocation regenerates both the file and the record.
  Session mode prints the hash as `request_sha256` beside `dispatch_request`, so a host that reads
  the file itself can make the same check (`sha256sum` on the path the status names). The loop also
  refuses an entry whose `agent` names an enforcement shell its checkpoint does not dispatch — a
  `verify` entry naming `panopticon-domain-panel` is a registered shell, but it is the review
  round's write-granting charter, and the routing is the driver's to state, not the request's.

`driver loop` flags, on top of every `driver run` flag: `--mode {headless,session}` (default:
headless when the host has a headless runner, otherwise session), `--concurrency N` (the pool width;
per-host default, 8 for Claude and 4 for Codex and Kimi — and whichever of the two applies is
clamped to `MAX_CONCURRENCY`, 8, the one ceiling the runner seam applies to the flag and the default
alike, with a single `concurrency N clamped to the ceiling 8` line on stderr when it bites (#1576)),
`--max-iterations N` (default 50 — after that the loop exits `error` naming the entries that never
became done), `--max-budget-usd X` (headless; stops launching once the ledger's cumulative reported
cost crosses it and exits `error` naming the ledger. The ledgered costs are summed as **exact
decimal** money, never as floats, so the boundary is the amount you typed — three $0.15 entries
reach a $0.45 budget, where a float sum of them is 0.44999999999999996 and buys one more entry. A
**non-finite** cost — `NaN`, `±Infinity` — never enters the ledger: it is stored as `null`, noted in
that row's `error`, and reported on stderr. A ledger line whose cost cannot be read back as money
stops the run instead (`error`, naming the line), because a gate that cannot see what it has spent
must not go on spending — it used to sum such a line as `NaN`, and `NaN >= budget` is false, so the
gate simply went quiet. It cannot bound spend when the host reports no cost), `--max-turns N` and
`--entry-timeout SECONDS` (per entry, headless; Codex uses the timeout, not a native turn limit),
`--setup` (run `driver setup`'s flow on rails). None of them is an anti-drift key — they say how
this invocation runs entries, not what the run is.

**Codex headless host.** Register its five role shells with
`python3 skill/scripts/dispatch.py --emit-host-agents codex`, then use
`python3 skill/scripts/driver.py loop <target> --host codex --mode headless`. Registration writes
only the owned `panopticon-*` TOML files under the configured Codex agents directory; it does not
edit global Codex settings. The TOML carries the role instructions, native feature restrictions, and
the scoped MCP tool mapping. The runner consumes that role configuration as launch-local settings
rather than dispatching an unrestricted child from the calling session. Setup-scan has a registered
shell of its own (#1737) but no bound role model — its shell binds none, so the session's model runs
it — and `driver loop --setup --host codex` gives that entry the same controls with a
repository-directory scope. Codex runs **enforced-only**: every reviewer entry launches through its
registered shell, and there is no unenforced fallback the way there is on Claude — the shell is
where the tool restriction lives, so a launch without one would be an unrestricted child, not a
degraded reviewer. `driver loop` therefore refuses once, up front, when a role's shell is missing
from the registration directory (a machine that has not run `--emit-host-agents codex`, or one whose
shells were pruned), naming that command rather than failing every entry three times. `--setup` is
exempt from that up-front refusal, and stays exempt after #1737 gave `setup-scan` a shell of its
own: a fresh machine can still run `driver loop --setup --host codex` before it has registered
anything, because that dispatch has a legitimate shell-less shape — but it is no longer a silent
one. The entry names `panopticon-setup-scan` when the posture proves enforcement, and when it does
not, `driver setup` refuses unless the operator passes `--allow-unenforced`.

Codex exposes only the bounded MCP tools `read_file`, `search`, and `list_files`, served by
`skill/scripts/codex_read_tools.py`. Each launch binds `PANOPTICON_ENTRY_ID` to its row in the
loop's `PANOPTICON_READ_SCOPE` file: exact `scope.files` and `scope.reads`, or descendants of
`scope.dirs` for setup. Escaping paths, symlinks outside the scope, and missing or malformed grants
are denied. So is a **hard link** inside a directory grant: a regular file that only `scope.dirs`
admits is refused when it carries more than one link (`st_nlink` > 1, read off the open descriptor),
because a link planted in the granted subtree can name an inode outside it and the link IS the file.
Exact grants are not narrowed this way — a file `scope.files` or `scope.reads` names is the one the
orchestrator chose, and stays readable whatever its link count. The cost is deliberate: ordinary
hard-linked build output under a directory grant is unreadable by design — `read_file` refuses it, a
directory-wide `search` skips it and says so in a `[skipped …]` line rather than failing the whole
search — at most eight are named, inside a 2 KiB block with long paths elided in the middle, and any
beyond that arrive as one `[skipped N more …]` count, so a tree full of planted links can neither
hide the disclosure nor crowd the matches out of the answer — and `list_files` still lists a name
`read_file` will then refuse, because listing names is not reading content. Claude's and Kimi's read
guards apply the same rule to reads whose argument is a FILE path (`Read`, `ReadMediaFile`, `Grep`
of a file). A `Grep` or `Glob` whose argument is a granted DIRECTORY is adjudicated by path and then
traversed by the host's own tool, so those guards answer it from a list instead (#1683): the driver
walks the granted directory ONCE, when the grant is issued, records the multiply-linked regular
files beneath it in the entry's scope, and the hook denies a directory `Grep`/`Glob` whenever a
recorded path lies at, above or below the argument. A link BELOW the argument is named in the
denial, which says to grep a narrower directory or a file by its path; a recorded path AT or ABOVE
it means the grant is closed whole and the denial says to Read files by name instead, because
narrowing is refused at every depth there. Those comparisons are case- and normalization-folded as
well as byte-exact, so `Grep <root>/src` cannot walk past a recorded `<root>/Src/x.txt` on a
case-insensitive volume (APFS, HFS+, NTFS) — folding a DENIAL can only over-deny, and the grant
itself is never folded, since that would admit `/REPO/x` under a `/repo` grant. A clean tree is
unaffected: nothing recorded, nothing denied. Two limits, stated: past 256 recorded files the walk
stops and the grant records the granted DIRECTORY itself, which denies every directory `Grep`/`Glob`
beneath it until the tree is fixed; and a link planted AFTER the grant is issued is not in the list
— the tree is static for the length of a run, and a hook may not walk the target on every call.
`driver setup` discloses either case on stderr with the count and the first offending path, and
names the remedy: **re-clone the target without hard links (`git clone --no-hardlinks`, or a fresh
clone) to restore directory `Grep`/`Glob` for the setup scan.** A locally-cloned checkout is the
common case — `git clone <local path>` hardlinks its object store by default, and those links do
name inodes outside the tree (the source repo), which is the class this rule exists for; the guard
cannot tell one from a planted link, so it refuses both. Codex has no such gap: its broker reads the
files itself. There is no reviewer shell command, patch, browser, write, or agent-spawning tool. The
native read-only sandbox is defense in depth; `--add-dir` grants writable roots, not a read fence,
so it is not the confinement primitive. A launch-local copy of the CLI's bundled model catalog
removes tool-enabling patch, multi-agent, and experimental-tool metadata while retaining model
identity and reasoning settings; effective-surface probes check the result rather than trusting TOML
alone. Nothing changes another host's runner or the calling session's configuration.

The role profile keeps scout on `gpt-5.6-luna`/medium and domain-panel on `gpt-5.6-terra`/high.
Advisor and domain-advisor use the explicit `gpt-5.6-sol`/high slug: the supported CLI's bundled
catalog does not list the `gpt-5.6` alias. An unavailable or ambiguous model fails closed rather
than silently selecting another tier; if your Codex build's catalog (`codex debug models --bundled`)
spells the tier differently, set `PANOPTICON_MODEL_<ROLE>` — e.g. `PANOPTICON_MODEL_DOMAIN_PANEL` —
to a slug it lists, which is what the refusal itself names.

Every Codex role uses `delivery: return_json`; the shared loop validates and persists replies,
records launches and denials, and handles retries. Codex does **not** claim `artifact_write_guard`,
because it provides no self-writing path. The existing shared review gate still requires
`--allow-unenforced` when that capability is unproven, even with write tools omitted. Obtain the
operator's explicit acceptance before supplying the flag; it records an acknowledgement, not proof
of confinement. This is a shared-gate limitation, not a reason to claim a guard that does not exist.

Codex's JSONL envelope reports token usage but not measured dollars or the effective model identity.
The runner therefore returns `cost_usd: null` and `model: null`; `model_binding` and `usage_ledger`
remain unclaimed and `unknown`. Cached input is a subset of input: it is subtracted from
`input_tokens` before being recorded as `cache_read_input_tokens`, so the shared ledger does not
count it twice. Use `--max-iterations`, `--entry-timeout`, and `-d`/`-g` scoping to bound work;
`--max-budget-usd` alone cannot stop Codex spend while every reported cost is null. Concurrency
defaults to four and remains controlled by the shared pool.

What the loop does at every checkpoint (the duties that used to be prose for the host to remember):

**What a headless launch refuses to discover (#1657).** Every reviewer child starts in, or beside,
the tree under review, and all three CLIs discover configuration from the current directory — so a
hostile target can ship `.claude/settings.local.json`, `.mcp.json`, `.codex/skills/<x>/SKILL.md`,
`.kimi-code/mcp.json` or an `AGENTS.md` and have it loaded as instructions rather than read as data.
The launch surface is narrowed per host. **Claude:** `--setting-sources user` (the target's project
and local settings, and any hooks they declare, are not read), `--strict-mcp-config` (no
`--mcp-config` is passed, so the reviewer gets no MCP servers at all) and `--disable-slash-commands`
("Disable all skills" per `claude --help`, so it is what closes a planted
`.claude/skills/<x>/SKILL.md` as well as `.claude/commands`), on top of the
`--settings <run>/host-settings.json` that arms the two guards — `--settings` is a separate channel
that still applies under `--setting-sources user`, which is what keeps the guards armed. `--bare`
and `--safe-mode` are never passed: both disable hooks, and either would silently un-arm the read
and write guards. **Codex:** the child's process cwd is the same empty, run-owned scratch directory
`--cd` names, outside the review root — not the review root itself — so whichever root the CLI keys
its discovery off, it finds nothing of the target's; `project_doc_max_bytes = 0` suppresses
`AGENTS.md`, while `features.skip_host_skill_discovery` is measured **not** to suppress project
skills and is not what protects a run. **Kimi:** `--skills-dir=<per-run home>/no-skills` replaces
both auto-discovered skill roots with one empty run-owned directory (the config's
`merge_all_available_skills = false` covers the operator's skills, not the target's), and reads go
through the per-run `$KIMI_CODE_HOME`. **Still open and tracked on #1657:** a target's `AGENTS.md`
under kimi (loaded root-to-leaf into the system prompt; no flag or config key disables it, and the
kimi child's cwd is deliberately still the review root) and `.claude/agents/*.md` plus the
plugin/workflow directories under claude (only `--safe-mode` closes them, and it unarms the guards).
This paragraph is what is narrowed, not what is closed; the `target-discovery-surface` probe (#1657
step 3) is what reports a target's discoverable files run by run, and it **refuses the run when the
target ships a file no control closes** — an `AGENTS.md` under kimi, a `.claude/agents/*.md` or a
hook/workflow/plugin directory under claude. Files a control DOES close are disclosed instead, on
stderr and in `host-capabilities.json`, naming the control that closed them. `--allow-unenforced`
runs it unenforced: the run proceeds with `tool_policy_enforced` refuted and the report says so.

The hook names and `--agent`/`--settings` examples below describe Claude's adapter. Codex consumes
the same entries and neutral guard files through its scoped read tools; it does not install or rely
on Claude hooks, and always uses the return-persist path.

- **The loop re-checks the pending set on disk** before every batch and after it — a runner that
  lost entries to a concurrency cap, a crash or a budget stop simply gets them re-emitted next
  iteration. Nothing advances on a runner's claim; the engine's done predicates are the only way
  forward.
- **The loop arms both guards** for exactly the pending entries, and only the loop does:
  `write_guard_hook.install` confines each agent's Write to its declared `out_file`;
  `read_guard_hook.install` confines its Read/Grep/Glob to its entry's `scope`. Write confinement is
  **per entry, not per batch** (#1571): the allowlist is a version-2 document keyed by entry id —
  `{"version": 2, "entries": {"<entry id>": ["<path>", …]}, "paths": […]}` — and a writer is **bound
  to the entry** it was dispatched for (`PANOPTICON_ENTRY_ID` in headless mode; the
  `panopticon-entry:` marker read back from its own transcript in session mode) and may write only
  that entry's `out_file` — **a peer entry's artifact is not writable**, on the Claude guard and on
  Kimi's alike; an agent nothing could bind is denied; the orchestrator, which is bound to no entry,
  keeps the batch-wide union. A stale version-1 (flat-list) allowlist denies every write and names
  the version rather than silently restoring that union. A findings path is also checked **component
  by component** (#1640): every directory from the review root down to the file's own parent must be
  a real directory, not a symlink; no component may be `..`; and the resolved destination must still
  sit inside that root's `.panopticon` tree — so a target repo that commits `.panopticon/runs` (or
  any other intermediate directory) as a link to somewhere else does not get a grant at one end and
  an authorized write at the other; the run stops with a message naming the component. Both the
  Claude guard and Kimi's apply that walk. **Headless:** on Claude both hooks register in
  `runs/<tag>/host-settings.json`, passed to the host with `--settings` (on Kimi they register in
  the per-run Kimi home's `config.toml`, which `runners/kimi.py` builds from the operator's own plus
  the two hook entries — Kimi has no `--settings` flag, only `$KIMI_CODE_HOME/config.toml`; that
  home is built under your temp root rather than in the run folder, because it carries your
  credential surface and the children's transcripts, and the run folder keeps only a
  `kimi-home-path` pointer to it. **Operator MCP servers are disabled in the per-run home** (#1640):
  whatever `~/.kimi-code/config.toml` holds, the generated one carries `mcp.enabled = false` and an
  empty `mcp.servers`, because an MCP server's tools are supplied at runtime by another process,
  under names neither `tools.disabled` nor the guard hooks have heard — so the home carries no
  surface it cannot mediate. A **target-planted** MCP file is stopped by something else, measured on
  a real launch 2026-09-18: the 0.42.0 CLI reads `<git root>/.mcp.json` and
  `<cwd>/.kimi-code/mcp.json` only when a workspace-trust record for the cwd exists under
  `KIMI_CODE_HOME`, and the per-run home is a fresh directory that links only the credential stores
  — so no record exists, the files are never read, and the planted servers never spawn. The inert
  `[mcp]` block is a second layer, not that mechanism; adding `workspace-trust` to what the home
  carries would undo it. The runner says on stderr how many servers it dropped, as a count; the two
  guard-armed probes REFUTE an armed config whose `[mcp]` block is live. The run removes the home
  when it completes, and strips its `config.toml` and credential symlinks — keeping the transcripts
  — when it errors, is interrupted or is `kill`ed. A run ended with `SIGKILL` (or a power loss)
  reaches none of that: it can leave a `$TMPDIR/panopticon-kimi-*` directory holding your `api_key`
  and live OAuth symlinks, and nothing prunes it afterwards, so remove those by hand), with the
  allowlist (`runs/<tag>/write-allowlist.json`) and scope file (`runs/<tag>/read-scope.json`) bound
  absolutely into the hook commands and exported to each entry's process as
  `PANOPTICON_WRITE_ALLOWLIST` / `PANOPTICON_READ_SCOPE`, plus `PANOPTICON_ENTRY_ID` — the target's
  own `.claude/settings.local.json` is **never touched**, so the session-root class of failure
  (#1493, #calibration-4) cannot occur. **Session mode:** the session root's
  `.claude/settings.local.json` and `<session>/.panopticon/…`, as before; the loop arms before it
  prints `dispatch`, drops the finished entries' grants on the next re-entry, and disarms everything
  on `complete`. Both guards are **fail-closed while registered**: an absent, unreadable, or
  malformed allowlist/scope file denies guarded access with a loud reason instead of silently
  allowing it.
- **The loop dispatches one agent per entry** through the runner: `enforced` →
  `--agent entry["agent"]` (a registered `panopticon-*` shell, tools+model host-enforced); else
  `--model entry["model"]` and no agent. Prompts go inline (there is no controller context to
  protect across a process boundary); `prompt_file` remains on every entry for session mode, and
  `files` (present on scout, review-cell, and verify-cell entries) is the entry's absolute file list
  — the read scope the read guard confines it to. `output_schema` is on a return-persist entry when
  its role publishes a JSON Schema for the reply AND this machine's CLI advertises the flag that
  takes one (recorded by the **cli-flags probe** — one `<cli> --help` read per headless run for
  every host whose runner declares such a flag, claude and codex today — in the evidence artifact's
  `cli_flags` block, beside `capabilities` rather than in it, so a CLI upgraded mid-run is not
  posture drift; absent or unknown means no schema is passed, which is the fail-safe — a CLI that
  does not know the option exits non-zero on it). The same block is carried into
  `meta.host_capabilities` and said on all four disclosure surfaces by `host_disclosure.notes`,
  which is separate from the capability lines because the fact gates nothing.
  `entry["delivery"] == "return_json"` marks a **return-persist** entry — set on any entry whose
  role's template grants no `Write`, or whose host has not proven `artifact_write_guard`; absent
  means the agent self-writes under the write guard. A self-writing entry **self-writes** its own
  `entry["out_file"]` (a findings file for review, a verdict bundle for verify) and returns a
  one-line confirmation — findings/verdicts never transit the loop.
- **The loop persists** every `delivery: "return_json"` reply through `phases.persist` — the same
  tolerant parse and the same shape check the phase's done predicate applies (scout shape, findings
  contract + `_panopticon` stamp, verdict list + stamp, a valid tool verdict) — and writes
  `out_file` atomically. For a **review-cell or verify-cell** reply the `_panopticon` stamp is the
  DRIVER's to fill: it wrote those keys onto the entry, it is holding the entry, and it is choosing
  the path, so a returned reply that omits `run_id`/`group`/`domain`/`stage` is stamped from the
  entry and marked `stamped_by: "controller"`. A key the reply DOES carry and that contradicts the
  entry is never overwritten — that reply is still refused. The stamp remains **mandatory** for a
  **self-written** file (a reviewer or advisor writing its own `out_file` under the write guard):
  nobody checked that file's identity on the way in, so its own stamp is the only thing that says
  which cell it belongs to, and `_cell_done`/`_verify_cell_done` still require it. A reply that
  fails is refused and written nowhere; the entry stays pending, and the loop's per-entry failure
  cap (Errors, below) bounds the retries — the phase's own attempt budget cannot, because it only
  counts an out_file that actually reached disk. The refused reply itself is kept, redacted, at
  `runs/<tag>/rejected/<entry-id>-<attempt>.json`, the launch's ledger row names it as
  `rejected_file`, and the entry's NEXT prompt carries the reason and a `prior_rejection` stamp so
  the retry is told what to fix.
- **The loop ledgers** every launch in `runs/<tag>/dispatch-ledger.jsonl` (entry id, checkpoint,
  mode, model, usage, cost, `denials` — the host envelope's `permission_denials`, verbatim — error,
  and on a FAILED row `stderr`: the first 200 characters of what the CLI printed on stderr, redacted
  before they are cut and redacted again at the ledger, which is the one thing that appends to this
  file. A successful row carries no `stderr` key at all, so its shape is unchanged. Run 14 is why:
  309 launches were ledgered as `claude -p printed no JSON envelope (exit 1)` — the symptom — while
  the diagnosis (`--json-schema is not valid JSON: JSON Parse error: Unrecognized token '/'`) went
  to a stream nothing kept) and rewrites `runs/<tag>/usage.json`
  (`{"total", "by_phase", "corrupt_rows"}` — `corrupt_rows` counts the ledger lines whose cost could
  not be read as money, whose tokens are still counted because they were still spent) from it after
  every batch, so `meta.cost.tokens` is exact and host-supplied on the headless path. In session
  mode `collect_usage.py` still runs from synthesize as before. Usage is never estimated from
  counts.
- **The loop tears the guards down** scoped after each batch and unconditionally on `complete` — the
  `teardown` field on the terminal status is now executed, not printed for a person to remember.
- **The loop rolls a crashed batch back before it resumes** — a `batch-<n>.json` still on disk means
  a run that reached no teardown at all (`SIGKILL`, an OOM kill, a power loss), and the next
  `driver loop` takes that batch back BEFORE the engine can read a half-written artifact as a
  finished cell (#1698). It is a rollback and not a cleanup: the artifacts the record lists are
  deleted, every entry of the batch gets the same `cancelled`/`rolled_back` row a Ctrl-C would have
  written (with `previous process stopped` as the reason rather than `Ctrl-C`), and the interrupted
  checkpoint's per-cell attempt marker is given back. The leftover used to be simply OVERWRITTEN by
  the next batch that happened to carry the same iteration number, so a reply the killed run had
  half-written stayed on disk and the phase read it as done. Nothing is deleted on the record's own
  say-so — it lives inside the reviewed tree — so every entry id, `out_file` and checkpoint in it
  must match the dispatch request this run is hash-bound to, and a record naming anything else is
  refused with nothing deleted. Under `--reset` no recovery is attempted at all: that flag discards
  the whole run instead.
- **The record names its owning process**, and only a dead owner is recovered — a manifest on disk
  is a CRASHED batch only when the process that opened it is gone, and a loop that is still running
  has one for as long as its batch is in flight (#1698). It carries the pid and the hostname of
  whichever process last wrote it, and the resume asks the operating system. Three refusals come out
  of that answer, each printed and exiting non-zero before a single grant is installed or a single
  entry is launched. **The owner is still running here** — another `driver loop` holds this run
  folder; wait for it to finish, or stop it and re-run. `--reset` is deliberately not offered there,
  because resetting a run folder another loop is working in is the accident being prevented: a
  second loop used to delete the first's in-flight artifacts, cancel its entries, refund their
  attempts and unlink its record, after which the first's own Ctrl-C found nothing to take back.
  **The owner is a pid on another machine** — the record names a host that is not this machine, and
  this one cannot ask that one whether the process is still running; a pid number from over there
  names some unrelated local process here, so the loop refuses to decide either way. **The record
  carries no owner stamp** — an absent or malformed owner is either a record from before the field
  existed or one the target wrote, and neither is evidence that a crash happened. A fourth refusal
  guards the other end: **a record this batch would overwrite**, a leftover carrying the iteration
  number this batch is about to open, refused before the guards are armed rather than silently
  replaced (that `O_EXCL` used to escape as a `FileExistsError` traceback with the write guard still
  armed). For those last three `--reset` is the only escape and it discards the whole run, so reach
  for it once you know no other `driver loop` is working there. Under `--setup` these records live
  in the flat `.panopticon/` beside setup's other artifacts rather than in a run folder, and
  `--setup --reset` sweeps them — all but one whose owner is still running, which it leaves alone
  and says so on stderr.
- **Errors:** a launch failure, non-zero exit, `is_error` or non-JSON envelope is a failed entry
  (ledgered, re-emitted next iteration). So is a reply persist refuses — the runner reported success
  but the entry did not advance, so the ledger row is written `ok: false` with the refusal as its
  `error` (the usage and cost stay the real launch's: those tokens were spent either way). Either
  kind counts toward a **per-entry cap of 3 consecutive failed launches**, after which the loop
  exits `error` naming the entry, the count and its last error; a clean, accepted launch clears that
  entry's streak, so the cap bounds an entry that is stuck rather than one that is merely flaky. It
  is not a flag — re-run to resume from disk, which starts every streak at zero. In session mode the
  streak is per-invocation, since nothing there advances except a human persisting a reply that
  passes the phase's done predicate. A failure the **host** caused — an auth refusal, a quota, a
  plan or session limit, a rate limit, or the provider itself being down — is not that entry's
  failure and is never counted toward that cap (#1623). It is recognised from the **host's own error
  surface** — the CLI's error line or the provider error object it printed, never the agent's reply,
  which on two of the three families is quoted into the failure message and routinely mentions
  quotas, 403s and authentication because that is what the reviewed code is about — and only from a
  structured shape in it: an error kind the provider names (`authentication_error`,
  `insufficient_quota`) or a status touching its reason (`403 Forbidden`, `auth_error: 403`), never
  a bare word or a bare number. The loop stops **launching** as soon as the batch's most recent
  launches are host-class — two of them, or one full `--concurrency` round, whichever is larger —
  cancelling whatever is still queued and draining what is already in flight, so an outage that
  begins at entry 12 of 78 costs the pool's width in further launches rather than 66 (#1721). It
  then ends with the terminal status `paused` whenever the batch **ends** in host-class failures,
  even when an earlier launch in it failed for its own reasons — that one keeps its charge, and a
  success from a launch made *after* the first host-class failure is what says the host is back and
  cancels the pause. The status names the host, the failure class, how many launches it took down,
  how many of the batch's entries were never launched at all, and the exact command that resumes the
  run — with every flag the run was invoked with, because the engine refuses a resume that changed
  one and a resume that dropped `--max-budget-usd` would run unbounded. Nothing is lost by stopping:
  no entry's attempt budget was charged and the failed launches left nothing behind, so every reply
  that did land is kept and re-running the loop resumes this run where it stopped; the interrupted
  checkpoint's per-cell attempt marker is given back exactly as a Ctrl-C gives it back, for the
  cells the host failed and the cells the stop never launched (neither was ever given a turn) — and
  that give-back happens whenever the stop cancelled anything, not only when the batch ends
  `paused`, since a later launch answering cleanly can close the run after the stop has already
  fired, so three paused runs during one outage do not drop the cells the way three automatic
  iterations of it used to. `paused` exits **non-zero**, so a CI job cannot read an outage as a
  clean review. A batch that mixes the two classes charges only the entry-class failures, and the
  cap above is unchanged for them. A **second stop rule** sits beside the host-class one and ends
  the run the same way (#1732): when the first `max(2, --concurrency)` results of a batch, by
  arrival, are all entry-class launch failures, each in under 2000 ms, carrying byte-identical
  redacted messages, that is the **launch** being refused before any entry did any work — the argv
  or the configuration, not N different entries and not the host. Run 14 is the case: 103
  tool-verify entries each exited in ~120 ms with the same message over one wrong argv token, and
  the per-entry cap needed three whole rounds (309 launches, ~35 minutes) to notice. A success, a
  persist refusal (the launch came back), a host-class failure (the rule above owns that one), an
  unmeasured duration or two different messages each break it, so the two rules can never describe
  the same results. A uniform batch pauses with a message of its own, composed once rather than per
  entry, naming the count, the window, the message and the same resume command — and it charges
  **nobody**: every failed id gets its attempt marker back, exactly as the host-class rule gives
  them back, and no entry's streak is incremented. The loop's own "stopped launching after N" line
  says which rule fired, so an argv defect does not read as a host outage. A **review cell** is
  bounded separately, by its own three-dispatch retry budget: once a cell has spent it the phase
  advances rather than wedging on a cell that cannot be recovered, so the run reaches `complete`
  having lost it. That is not a clean run and the terminal status says so — `cells_exhausted: <n>`,
  with the same count and each cell's `group/domain` in the message. The key is ABSENT, not zero,
  when nothing was lost, so a clean run's status is unchanged for everything that already parses it.
  **A dispatch entry does not get to describe itself** (#1720): the request travels through
  `.panopticon/dispatch-request.json`, a file inside the reviewed tree, so an entry's `agent` must
  be one of the registered panopticon shell names (`panopticon-scout`, `panopticon-domain-panel`,
  `panopticon-domain-advisor`, `panopticon-advisor`, `panopticon-setup-scan` — and on kimi, where
  the name becomes a `--agent-file=` path, that path must still resolve inside the registration
  directory), and an entry's `enforced` flag must agree with the posture this run's own capability
  evidence proves. A foreign, traversing or absent `agent` refuses the ENTRY — never a quiet
  fall-back to a bare, unenforced launch; a disagreeing `enforced` flag refuses the whole RUN before
  the batch opens, so nothing is launched and nothing is charged, and the remedy is `--reset` or a
  fresh readiness run rather than a retry. The engine's own refusals (flag drift, posture drift,
  shadow shells, unmediated Write) surface unchanged; Ctrl-C in headless mode cancels the queue,
  terminates any child its runner registered a handle for (the terminal's own process-group SIGINT
  reaches the rest), ledgers what it cut, disarms both guards, rolls the interrupted phase back to
  its checkpoint, and exits `error` with a message beginning "interrupted:" — the next `driver loop`
  re-runs that phase from scratch, and `--reset` discards the whole run instead. A `SIGKILL` or a
  power loss reaches none of that teardown, so it leaves the batch's own record behind instead, and
  the next `driver loop` rolls that batch back before it resumes (#1698, above).

Phases run in order — `readiness` → `discovery` → `coverage` → `tools` → `review` → `verify` →
`synthesize` → `validate`:
- **`readiness`** — the scanner/environment checkpoint, and deliberately the FIRST step, because
  `coverage` is the first one that spends money (#1637 P08). It probes the Docker daemon and the
  `panopticon-tools` image, re-reads the committed `panopticon.yml`, and records this run's host
  posture and target root as informational rows; the verdict lands at
  `.panopticon/runs/<tag>/readiness.json`
  (`{schema_version, run_id, checked_at, ready, flags: {tools}, checks: [{name, ok, detail}]}`). It
  **fails closed**: a missing image with tools enabled is an `error` before a single dispatch entry
  is written, carrying every failed row's remedy verbatim —
  `docker pull ghcr.io/panopticon-scanner/panopticon-tools:latest && docker tag ghcr.io/panopticon-scanner/panopticon-tools:latest panopticon-tools:latest`,
  or `docker build -t panopticon-tools <the panopticon repo root>`, or `--no-tools`. **`--no-tools`
  is the disclosed opt-out**: the two docker rows become `ok: null` ("not applicable"), the run
  proceeds without scanner evidence, and that choice is stated in `tools-ran.json`, in the report's
  tool coverage and in `meta.tools.panels_with_scanner_context` — it is never silent. It launches no
  host binary and dispatches nothing (the capability posture is already established, on every
  invocation, before any phase runs), and its pass is re-evaluated whenever the manifest's `tools`
  flag differs from the one the artifact was written under, so a `--no-tools` pass can never stand
  in for a tools-enabled run.
- **`discovery`** — `discovery.py --repo-scan` writes `.panopticon/groups.json` against the
  committed `panopticon.yml`; delta scopes (`-c`/`--pr`/`--base`) additionally write
  `.panopticon/diff-hunks.json`. **Discovery completes only on a well-formed groups artifact**
  (#1643): the driver stamps the artifact with this run's `run_id` and then requires it — a `groups`
  LIST whose every record carries a non-empty `name` and a `files` list of strings, and at least one
  group carrying at least one file (an empty leaf beside real ones is normal; an artifact whose
  every record is empty is the same empty success as no record at all) unless the scope legitimately
  selected nothing (`-c`/`--pr` over an empty delta, or `--files` whose list pruned to nothing) —
  because the predicate used to be "it parses", and `{}` parses, so a corrupt or truncated child
  output completed the phase, coverage derived zero groups and every later `all(...)` over that
  empty collection was true by definition; one malformed round is re-run, and a second identical one
  ends the run `error` (`discovery produced no usable groups`) rather than letting it walk to a
  report having dispatched no review cell. The same rule holds for the other two phases whose
  predicate was parse-only: `coverage` counts a group covered only when `coverage-<group>.json`
  carries this run's `run_id` and an `effective` list (an empty list is a real answer; an absent one
  is the file not having been computed), and `synthesize` is done only on a report carrying a
  `summary` — the phase validates its own artifact against the published schema, and a parse-only
  predicate let any parseable file at that path skip that check entirely. In all three the execute
  side applies the SAME test, so a predicate cannot refuse a file its own phase then declines to
  recompute.
- **`coverage`** — one batched `scout` checkpoint carrying every pending group's scout (below), then
  widens each group's floor panels by its scout's valid domains.
- **`tools`** — deterministic, not discretionary: runs
  `python3 skill/scripts/run_tools.py --target . --out .panopticon/tools --deps` unless `--no-tools`
  was passed; a skip is never silent — it's always recorded in `tools-ran.json` and surfaced in the
  phase status message, and a no-output / Docker-absent skip additionally writes LOUDLY to stderr.
  An **environmental** skip is not done (#1637 P08): the phase counts as complete only when the scan
  RAN, CRASHED, or was switched off with `--no-tools`, so a marker written because Docker or the
  image went missing mid-run is re-evaluated on the next `driver run` — one `docker image inspect` —
  and installing the image retries the scan while every scout and review artifact already on disk
  stays there. With `readiness` failing closed ahead of it, that branch is only reachable when the
  environment moved underneath a run in flight. The retry is scoped to the **invocation**, not to
  the engine step: each `driver run` mints one token, the marker records which invocation attempted
  the scan, and a skip carrying the current token is done for that invocation — without which the
  engine, which recomputes its cursor every step, would re-select `tools` immediately and spin.
  **`--no-tools` is the non-destructive rescue** when the environment will not come back: it is the
  one anti-drift flag a run in flight may relax (OFF only — turning tools back on stays drift,
  because the panels already dispatched cannot un-see what they were shown), the manifest records
  the change with its previous value and a timestamp in `flag_changes`, and the report discloses it
  as `meta.tools.disabled_mid_run` and in the body. `--reset`, which throws every paid scout away,
  is no longer the only exit. Every mode prunes tool findings under fixture-corpus paths by default
  — both standard and redteam (#1055: redteam no longer auto-includes them in the report BODY;
  fixture CONTENT injection-hunting stays a review-panel job via `panopticon.yml`) — for tool-path
  parity with the review-side prune (#434); `--include-fixtures` opts in. Python **virtualenvs are
  excluded from the tool axis** in every mode — any directory carrying a `pyvenv.cfg`, plus the
  conventional `.venv`/`venv` names (#1638 P09) — both at ingest, at any depth, and — for the
  scanners that expose the knob (semgrep `--exclude`, trivy `--skip-dirs`, bandit's `--exclude` plus
  the target's `.bandit`) — in the scan itself, where the virtualenvs are the ones found near the
  target root: `tools-manifest.json` lists each directory the scan DETECTED with its reason under
  `excluded_dirs` and a `skipped` flag saying whether the scanners were told to leave it alone, and
  the `depth_bound` beside it says how deep that walk looked, so the manifest list is a bounded
  subset of what ingest prunes. **Three of those prunes rest on a directory NAME and nothing else**
  — a vendored directory (#1578), a `venv`/`.venv`/`site-packages` segment with no `pyvenv.cfg`
  behind it, and the fixture corpus — so each one is disclosed per segment in
  `meta.coverage.tools_suppressed`, on the ingest's stderr line and on the gate's own verdict line,
  grouped by class (`vendored` / `virtualenv-by-name` / `fixture-corpus`), and under
  `--security redteam` all three are **gated anyway when the finding is CRITICAL or secret-class**
  (#1740 widens #1578's one class to all of them; the #1578 owner ruling of 2026-09-22 -- policy C
  -- narrows WHICH findings, to a CRITICAL or a secret adapter's hit or a credential CWE, so
  bundled-library lint noise cannot drive a merge gate while a planted payload or a committed secret
  under `vendor/` still can; a **secret adapter's findings are graded HIGH at the parse**
  (`tools/sarif_utils.py` `SECRET_ADAPTERS`), because real gitleaks SARIF states no `level` at all
  and the `warning` default had been grading every committed credential MEDIUM -- below the gate
  floor, so the CI gate could not fail on one at any path): one predicate,
  `ingest_tools.gates_when_suppressed`, answers for both gates, `security_gate` counts them and
  prints how many it counted against how many it disclosed only,
  `meta.coverage.tools_suppressed_gated` publishes the counted half and `tools_suppressed_not_gated`
  the declined half (a subset of `tools_suppressed`), and the runner stops handing a name-only
  virtualenv to the scanners' exclusion knobs, so there is a finding left to re-admit — semgrep and
  trivy scan it, and so does bandit **unless the target ships its own `.bandit`**: with no marker
  virtualenv to skip no exclusion flag is added at all, so the argv is just
  `bandit --ini <target>/.bandit …` and bandit reads that target-authored file's `exclude` entries
  itself (this repo's list names `venv` and `.venv`, so panopticon's own redteam self-scan keeps
  that one bandit blind spot; a target with no `.bandit` is scanned, since bandit's parser defaults
  name no virtualenv). Narrowing a target-authored config by security mode is the
  target-controlled-configuration question tracked under #1924 (the scan-root half of the class;
  #1877 closed the cwd half). A prune that rests on EVIDENCE instead — a `pyvenv.cfg` marker, a
  nested `.worktrees` checkout, `.git`, panopticon's own `.panopticon/` artifacts, generated
  bytecode — stays silent in both modes, and `--tools-exclude`/`--exclude` globs stay operator
  policy: excluded, counted, and never re-admitted by any mode. dependency AUDITING is untouched,
  since pip-audit/osv-scanner/trivy read `requirements*.txt`, `pyproject.toml` and the lockfiles at
  the target root rather than the venv tree. **pip-audit audits a GENERATED, sanitized requirements
  list** (#1646), never the repository's own file: `pip-audit --requirement <path>` RESOLVES what
  that file names, and requirements syntax admits `-e .`, `./local/path`, `git+https://…`,
  `https://…/x.tar.gz`, `--index-url`, `--find-links`, `-r` and `-c` — resolving any of the first
  four invokes the reviewed repository's **PEP 517** metadata/build hooks, so the target's own code
  ran under the scanner account, online (pip-audit is the one ONLINE_ONLY adapter). Both branches —
  `requirements*.txt` and the static `[project.dependencies]` read — now write a temp file holding
  only lines that parse as a bare **PEP 508** requirement (`name[extras] specifier ; marker`, no
  URL, no path, no option line); `\`-continuations are joined BEFORE classification, the way pip
  joins them, so `--extra\` + `-index-url …` is judged as the option line it reassembles into;
  `--hash=` tokens are stripped from a kept line; and `-r`/`-c` includes are followed **one level**,
  confined to the target root, so the ordinary `requirements.txt → -r requirements-base.txt` layout
  still audits. "No path" has a trap in it: pip decides a requirement is a local archive on a
  **suffix match** (`is_archive_file`, against its `ARCHIVE_EXTENSIONS`) *before* it considers
  whether the string looks like a path at all, so a bare `evil.tar.gz` with no separator resolves to
  `file://<cwd>/evil.tar.gz` and runs its build backend — such a name is dropped as `archive name`,
  and, belt and braces, pip-audit is given an explicitly empty **working directory** (`-w` on the
  container, `cwd=` on the process) so cwd-relative resolution has nothing to find even if the
  grammar ever slips. The manifest it reads must itself resolve inside the target: a symlinked
  `requirements.txt` pointing out of the tree is treated as absent and named in `source` as
  `outside target`, never read. The fix is the generated file, not a pip-audit flag — `--no-deps`
  was the rejected alternative. That makes the dependency audit PARTIAL, so it is disclosed rather
  than left silent: `tools-manifest.json` carries `sanitized.pip-audit`
  (`{source, kept, dropped: [{line, reason}], hashes_stripped}`, credentials masked at the
  producer), the report copies it to `meta.tools.sanitized`, `report.json.html` prints *pip-audit: N
  requirement lines not audited (editable/local/VCS)* beside the coverage line, and the per-finding
  tool advisor is told the same before it is asked whether a package is present. Those dropped lines
  are target-authored text bound for two published artifacts, so the disclosure is **bounded** like
  every other path here: the manifest is read to at most **1 MiB** or 20,000 lines
  (`truncated: true` when that bit), at most **200** rows are listed with the remainder counted in
  `dropped_truncated` (the printed N is the true total, not the listed rows), and each row is
  redacted and then cut to 200 characters. `tools-ran.json` is unchanged. **The two online adapters
  reach their advisory endpoints, and reach them only through the proxy** (#1645): `--network none`
  covers every other scanner, and pip-audit/npm-audit got Docker's *default bridge* instead — every
  service reachable from the runner's network, private ones included — because `--online` decides
  *whether* they run and never *where* they may connect. A run that selects one now creates a
  per-run `--internal` network with no external route and one digest-pinned **tinyproxy** sidecar
  bridging it to the internet under `FilterDefaultDeny Yes`, and each online container runs on that
  network alone with `HTTP_PROXY`/`HTTPS_PROXY` pointed at the sidecar and an explicitly empty
  `NO_PROXY` (the first and only environment ever passed into a scanner container, composed from the
  sidecar's address rather than read from the host): pip-audit may reach `pypi.org`,
  `files.pythonhosted.org` and `api.osv.dev`, npm-audit `registry.npmjs.org`, and a `CONNECT` may
  reach port 443 and nothing else. ONE table (`skill/scripts/tools/egress.py`) is read by both the
  proxy config writer and the manifest, so `tools-manifest.json`'s `network`
  (`{"<tool>": "none" | "proxied:<allowlist>" | "excluded:<reason>"}`, copied to
  `meta.tools.network` and printed beside the coverage line) names the allowlist the proxy is
  actually enforcing instead of a second copy that can drift from it. It **fails closed**: a network
  or sidecar that will not come up does NOT put the adapter back on the bridge — it does not run,
  and it is disclosed as `excluded_scope` with the reason, exactly like an absent scanner, so
  certification sees the gap. The containment is a standard **rootful** Docker daemon's — rootless
  Docker and podman implement `--internal` differently and this guarantee is not stated for them,
  though the disclosure still is — and it is *proxy* containment rather than a firewall: Docker
  documents that a container on an `--internal` network may still communicate with that network's
  **gateway** address, so a service the operator bound on the docker host at that address is not
  fenced by this control (host firewalling is out of scope). Teardown removes sidecar and network in
  `finally`; the sidecar itself runs under a `timeout` covering the scan's own worst case, so a
  controller that dies without tearing down leaves nothing running; and the stale sweep is a
  label-and-age-filtered `container prune`/`network prune`, which by construction cannot reach a
  scan running beside this one. `tools-ran.json` stays the certification summary — whether the scan
  ran, and whether its captures were redacted — while the per-adapter egress postures live in
  `tools-manifest.json` and the report, beside `sanitized`, which it does not carry either. **Raw
  captures are redacted before they are written** (#1639 P11): `.panopticon/tools/<tool>.sarif|json`
  is what an operator copies into a CI artifact, and a secret scanner's output is a list of other
  people's credentials by construction, so every capture path — the buffered one, the streaming one
  and its over-cap truncation branch — passes its bytes through ONE choke point,
  `run_tools._redact_capture`, immediately before the atomic write, with the same pattern set the
  report is masked with, never a second copy. Structure survives because the capture is PARSED, not
  because the patterns are trusted to stay inside a string: a JSON capture — every one but spotbugs'
  XML — goes through `redact.redact_tree`, the per-string-leaf walk synthesis uses, so `ruleId`,
  `locations`, `region` line numbers and `level` are never seen as text and ingest is unchanged; a
  non-JSON capture takes the flat `redact.redact` pass, where every pattern but one is anchored to a
  character class that cannot cross a `"` at all, and the exception — a PEM body, which has to cross
  quotes because source code embeds a key one quoted literal per line — is bounded to 16KB and can
  never span two `-----BEGIN` blocks, so what a flat pass over a structured document could swallow
  is bounded rather than open-ended. The same bound is a coverage limit, and it is the one hole to
  know about before publishing a capture: a PEM block whose body runs longer than 16KB is not masked
  at all — header included — so a capture quoting one very large key still carries it. The document
  is re-serialized only when masking actually fired, in the producer's own layout where that is
  recognisable, so every committed real-scanner golden comes back byte-identical through the pass.
  `gitleaks` additionally runs with `--redact`, which masks the matched secret inside the scanner
  (v8.18.4 rewrites the finding's Line/Match/Secret only, so the SARIF's rule id and location are
  untouched) — defence in depth, not a substitute. The byte cap is still measured on the RAW stream,
  the only count that bounds memory, so the truncation marker's numbers describe raw bytes rather
  than the size of the file on disk — and because a raw cut can split a token into a fragment no
  length-anchored pattern matches, a truncated capture is dropped back to its last line break first
  (except on output with no line breaks, or a last line over 64KB, where the prefix is kept as cut).
  `tools-manifest.json` records `redacted` from what the runner OBSERVED — every capture it wrote
  went through the choke point — and the tools phase copies that into `tools-ran.json`
  (`redacted: true`) rather than asserting it — from THIS run's manifest only, since a runner that
  writes captures and then dies leaves the previous run's file in place, so the claim is readable
  from the run's own artifacts and goes false if the pass is ever bypassed.
- **`review`** / **`verify`** — the guard-confined self-write fan-out below. Like the scout (#1056),
  `review` batches every pending `(domain, group)` cell across ALL groups into ONE checkpoint, and
  `verify`'s PRIMARY round batches every pending advisor into one (#5) — so the host dispatches them
  concurrently instead of one round-trip per group. A batched checkpoint carries `group: null`; each
  entry is self-describing (`id` = `review-<group>-<domain>`). `verify`'s adversarial BACKUP round
  batches the same way (all pending backup cells in one `group: null` checkpoint, #20) but is
  sequenced AFTER primary completes; the per-finding TOOL round is likewise a separate checkpoint —
  each round depends on the prior round's verdicts being complete. The BACKUP round is granted a
  **bounded closure**, not the whole cell and not the claim file alone (#1638 P16): each scoped
  claim's `location.file`, every in-repo path that claim's own evidence names (`description`,
  `exploit_scenario`, `remediation`, `evidence.reasoning`, `references`) — a named path is resolved
  in one order (#1688): exactly as written, then by **unique suffix** among the claiming cell's own
  files, then by unique suffix repo-wide over the listing discovery already wrote, then by content,
  so that `helpers/config.py` and a bare `config.py` reach the file the claim meant; identical
  candidates collapse to one, and a name that still means two DIFFERENT files resolves to NEITHER
  (granting the wrong one is a read fence around evidence the claim was not about) with the refusal
  disclosed in the backup's own prompt as `ambiguous: config.py (3 candidates, differing)` — and its
  one-hop in-repo import neighbourhood in both directions — what it imports, and the same-group
  files that import it — de-duplicated, with every claim's own `location.file` always granted (the
  floor: a claim whose file the fence denied could only ever answer NEEDS_MORE_INFO) and the EXTRAS
  capped at 12 files per claim and 48 for the whole check (the review matrix's own per-group ceiling
  at the default `--max-per-group`, so a backup is never granted more code than a review cell is);
  `evidence_scope.floor_count` records how much of a grant is claim files, which no cap bounds. A
  `location.file` that does not resolve to an existing in-root file makes the whole check fall back
  to the group, and **a backup entry is never dispatched with an empty read grant** — an empty grant
  is a deny-all fence, so the advisor could open nothing and the only answer left to it would
  manufacture an unrefutable `backup_scope_limited`. Every path must exist under the review root and
  confine to it, so a claim naming `../x` or an absolute path contributes nothing (#1096) rather
  than widening the fence; only an unresolvable `location.file` still falls back to the whole group.
  The grant is **recorded**, not just made: the prompt states it under "Evidence granted for this
  check (bounded closure)", the same list is the entry's read scope (the read guard and the Codex
  broker admit nothing else), and the advisor copies it into each verdict as
  `evidence_scope: {granted, cap, truncated, entry_cap, entry_truncated, floor_count}`, and a prompt
  line names how many files the entry ceiling omitted when it bit. An advisor that still needed a
  file it was not given returns `NEEDS_MORE_INFO` with `missing_evidence: [paths]`, and that is read
  as an **evidence-scope failure, not a disagreement**: it does not displace a primary CONFIRMED,
  the finding keeps `backup_confirmed: false` with `evidence.status: backup_scope_limited` —
  gate-eligible and weighted exactly as the primary-only `advisor_confirmed` it would otherwise be,
  but NOT counted as "verified" in the report's coverage line, which gets its own
  `backup-scope-limited` segment instead — and `report.json.html` names the files the backup could
  not see. An agent-written verdict is untrusted input and enters the controller through exactly ONE
  sanitizer, on every read path (`tests/test_agent_verdict_guard.py` walks the tree and fails if a
  new reader appears without it): it strips every `_`-prefixed key — `_backup_missing_evidence` is a
  controller carrier, so an advisor cannot plant one to launder a rejection, fabricate a disclosure,
  or empty its own cell's backup scope — and drops the advisor's declared `stage`, which comes only
  from the controller's `_panopticon` stamp (from the filename for a legacy single-verdict file), so
  a primary bundle cannot declare itself the adversarial round. Where a backup round returns several
  verdicts for one finding, the least favourable to it wins (REJECTED > NEEDS_MORE_INFO bare >
  NEEDS_MORE_INFO scope-limited > CONFIRMED — a bare one says the advisor looked, a scope-limited
  one that it was not allowed to); duplicate primaries keep first-wins. Both rules live in one
  function (`evidence.resolve_duplicates`) that the driver and synthesis each call, because two
  readers of one bundle answering differently is how the driver came to skip an adversarial round
  while the report published the finding as advisor-confirmed. A backup `NEEDS_MORE_INFO` that names
  nothing is substantive and still wins, exactly as before. Run-13 is why: the redaction-order
  defect was confirmed by the primary, reproduced by hand, and published as unverifiable because the
  backup was fenced to one of the three files the call order spans. Each `review` cell's **`TST`**
  prompt also carries an `Inventory:` line — `complete`, `empty`, or `split` (test files named after
  this group's modules are claimed by another group) — because a reviewer fenced to its own cell
  cannot tell an empty test inventory from a target with no tests, and run-13's `Ungrouped_1` panel
  published the second reading of the first fact. The driver computes the state (per
  `panopticon.yml` entry, so a run-time `<name>_N` chunk answers as its parent) and the reviewer
  files **no finding** about it — it only withholds the coverage claim it cannot support; the
  per-group states land in `meta.coverage.test_inventory` and next to the coverage line in
  `report.json.html`, and the fix is the target's `panopticon.yml`, not its test suite.
- **`synthesize`** — runs `skill/scripts/synthesize.py --verdicts-dir .panopticon/verdicts`
  (`--tools-dir .panopticon/tools` added when `tools` produced output;
  `--diff-hunks .panopticon/diff-hunks.json` added when `discovery` emitted it) →
  `.panopticon/report.json`. It also emits a sibling `.panopticon/report-x0x.json` — the run's
  `<DOM>-X0X` / `ZZZ-X0X` catalog-gap findings packaged as OCRDb new-code **candidate records**
  (schema `skill/reference/x0x-report-schema.json`), mechanically clustered, with
  `generated_by.run_id` from the run manifest; adjudication (the gap rationale, the
  new_code/refine/retire verdict) happens downstream in OCRDb's pool. SARIF is ingested via
  `skill/scripts/ingest_tools.py`, but only because `--tools-dir` was passed — a scan that ran but
  was never wired in would sit on disk un-ingested. Every report also carries `meta.cost` — the
  run's dispatch ledger, derived from the artifacts already on disk (scout profiles, the checkpoint
  entries, the verify queue), one `{phase, role, model, count}` row per dispatch class, plus a
  `tokens` slot that stays null until a host exposes per-dispatch usage — never hand-assemble it. It
  also carries `meta.tools.panels_with_scanner_context` — `{with, without}` over this run's review
  cells, recorded per cell at the moment its prompt was rendered and rendered next to the tool
  coverage line in `report.json.html`. Run-13's report looked complete while 85 of its panels had
  been shown no tool findings at all; this is the field that says so.
- **`validate`** — captures a working-tree baseline (`.panopticon/tree-baseline.txt`) at run start
  and diffs it here; any change outside `.panopticon/` fails the phase (`status: error`) — treat the
  run as compromised: discard the findings, inspect the flagged paths, re-run. The baseline records
  `git status --porcelain` records **and a content digest for every path that status names**
  (#1514): status records alone cannot see a rewrite of a file that was already dirty at run start,
  which is the normal starting state for a coding-agent review. Ignored files are out of scope by
  policy — `git status` without `--ignored` never reports them, so build outputs and caches are
  neither baselined nor audited. Detection only: user content is never reverted. A baseline written
  before this change (resume across the upgrade), a failed probe, or a tree too large to digest all
  report that content equality was not established and fail closed rather than certify a check that
  did not run.

At the `scout` checkpoint (one batched checkpoint, one entry per still-pending group, the run's
first checkpoint — #1056 emits them together so they dispatch concurrently instead of one round-trip
per group), each scout is **read-only** and RETURNS a ScopeProfile. The loop dispatches every entry
(`enforced` → `--agent entry["agent"]` — `panopticon-scout`, from the `skill/agents/scout.md`
template; else `--model`) and persists each returned JSON to its `out_file` (`scout-<group>.json`)
after confirming it parses. No write-guard here — nothing self-writes. The read guard is armed here
too, exactly as at every checkpoint that carries entries: `read_guard_hook.install` before the batch
and `read_guard_hook.uninstall` after, each scout entry confined to the files its group names. The
guard-confined **self-write** path applies to `review` and `verify` checkpoints (whose
reviewers/advisors write their own `out_file`).

A malformed self-write fails its done-predicate (`_cell_done` / `_verify_cell_done`) so the cell
reads as not-done and is re-dispatched on the next iteration — no corrupt findings/verdict silently
lands. Register the enforcement shells once with
`python3 skill/scripts/dispatch.py --emit-host-agents claude` (or `kimi`/`codex`; `--agents-dir DIR`
for a non-default registration path). This also registers `panopticon-advisor`
(`skill/agents/advisor.md`) — the per-finding tool-advisor `driver run` dispatches (return-persist)
for each tool finding in the verify phase (#5.0-03) — and the matrix-cell roles
`domain-panel.md`/`domain-advisor.md`. `emit_host_agents` iterates `dispatch.ROLE_FILES`, so it
registers exactly five shells — `panopticon-scout`, `panopticon-advisor`, `panopticon-domain-panel`,
`panopticon-domain-advisor` and `panopticon-setup-scan` — and **removes any other `panopticon-*`
shell it finds in the same directory**, so a role retired upstream stops being dispatchable here as
soon as you re-emit (a 4.x install carried live `panopticon-panel-review` / `panopticon-lens-sweep`
agents until this landed). Files outside the `panopticon-` namespace are never touched. The
advisor's own prompt renderer (`dispatch.py --render-advisor`) still pins `Repo root: <path>` (#975)
for its other, non-driver callers.
