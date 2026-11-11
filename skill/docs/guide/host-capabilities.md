## Host capabilities (5.2)

Every `driver run` invocation **assesses the host before anything dispatches**, writes the result to
`runs/<tag>/host-capabilities.json`, and compares it against what the previous invocation stored — a
posture that moved mid-run refuses to continue and names the capability that moved, in which
direction, and `--reset` (#1344 F3a). That refusal covers the three **security** capabilities
(`tool_policy_enforced`, `read_scope_confined`, `artifact_write_guard`) only. `model_binding` and
`usage_ledger` are operational — spec 8.1 excludes them from the retirement bar and they gate
nothing — so a move in either of those is written into the artifact, state and reason both, and the
run continues (#1626). `usage_ledger` is the one capability whose subject the run itself produces
(the dispatch ledger the loop appends to after every batch), so a CLI release that stopped reporting
tokens used to refuse every re-invocation permanently, with `--reset` — discarding the paid-for
batches — as the only exit. A token counter going quiet costs you a cost figure, not a run. The
assessment runs every invocation rather than only at setup, but #3272 stops rebuying an identical
measurement: each host probe is cached under `$PANOPTICON_STATE_DIR` (default
`~/.local/state/panopticon`), keyed by the host CLI's recorded `(sha256, version)`, the host and the
installed measuring code and registration/settings inputs that probe reads. Only `proven` and
`refuted` measurements are reusable: `unknown` is measured again. A CLI, source or settings change,
an entry older than 24 hours, or a timestamp in the future re-probes; a missing CLI identity disables
reuse. Target-tree shadow and discovery scans are never cached, so a file planted between resumptions
is still found. The run artifact remains a record re-established each invocation, never trusted
cache input — a tampered or truncated one self-heals rather than becoming the authority, and no cache
file lives in the reviewed tree.

The hook, frontmatter, launch-envelope and transcript-directory mechanisms in the following
paragraph describe Claude's probes. Each family supplies evidence for the same capability names
using its own effective runtime controls; Codex's and Kimi's probes are described immediately
afterward.

Five capabilities are measured. `tool_policy_enforced` — every driver role has a registered
enforcement shell whose `tools:` grant matches its template, *and* the reviewed tree ships nothing
that shadows those shells. `artifact_write_guard` — reviewer-controlled artifact writes are
impossible or confined to the declared `out_file`. A family can prove an absent reviewer-selectable
write surface or a mediated self-write path; transport is a separate static registry fact. Current
Claude/Kimi proof covers the write-tool surface. On a headless Claude run the proof includes one real
`claude -p` canary launch (#3218/#3272, about $0.0005 on `claude-haiku-5-5`): the runner's enforced argv, both
guards armed in a sandbox, one out-of-scope Read, a Write to its own `out_file` and one to a peer's.
The same launch supplies independent verdicts. Write proves only when the own file was written and
the peer's was not, so a CLI whose permission layer denies every granted Write cannot prove the
capability. Read proves only when the real CLI's `permission_denials` names the out-of-scope path;
if its secret reaches the own file or reply, read confinement is refuted. A launch that measured
nothing (no envelope, an error, or a requested tool not attempted) is retried once and then reads
UNKNOWN, which still refuses the run. That refusal asks for a re-run first
(the next run probes again) and names `--allow-unenforced` only after it (#3220).
Bash-path writes belong to `tool_policy_enforced`.
When that posture is REFUTED and the operator passes `--allow-unenforced`,
`unenforced-ack.json` records the named gap rather than broadening the claim. In headless mode,
with no flag or with tool policy UNKNOWN, no acknowledgement is written, because the launch argv
closes Bash; the gap appears only in the `tool_policy_enforced` posture line. A session dispatch
has no such argv, so over the same gap it refuses without `--allow-unenforced`, and with the flag it
records the gap (#3226, see the guide's notes).
`usage_ledger` — probed by `usage-source`, which follows the mode: in headless
mode the run folder can hold the dispatch ledger, the host's CLI is on PATH and its `--help`
advertises the flags that make a launch print the JSON envelope (`-p`, `--output-format` — any
executable merely named `claude` is refuted), and once the loop has ledgered successful launches
their envelopes must have carried usage, so `meta.cost.tokens` is the launch envelopes' exact
figures (`usage.json`, rewritten after every batch); in session mode the host's transcript directory
for this session exists and reads, which is what `collect_usage` depends on. A headless run launched
from a directory with no transcripts (every fresh target) used to be refuted here while its ledger
was exact. `model_binding` is now probed by `entry-model-bound` (#1344 F4): every registered shell's
`model:` frontmatter must equal what `model_resolver.resolve_model` resolves for that role; a shell
that binds a different model, or none, is `refuted` — *registration silently wins* over the entry.
`PANOPTICON_MODEL_*` overrides are the usual cause: `resolve_model` honours them, a persisted shell
deliberately does not. One claude behaviour change follows from this (R-F4-1): an **unenforced**
claude dispatch used to inherit the calling session's model and now names the role's profile model
instead; an **enforced** dispatch is unchanged, since the shell it dispatches into already binds
that model. An unenforced claude dispatch also carries an explicit tool deny-list on its argv now
(#1753, `runners/claude.UNENFORCED_DENIED_TOOLS` as one `--disallowedTools=` token, since the flag
is variadic and would otherwise eat the prompt): with no registered shell there is no host-enforced
`tools:` grant, and `--setting-sources user` deliberately keeps the operator's own user-scope
`permissions.allow` rules, so a `Bash(*)` convenience rule would otherwise reach a reviewer that
reads hostile content — deny beats allow, which is the point. The residual is a tool name the list
has not heard of that the operator has allowed at user scope; MCP tools are not part of it, since
the same argv passes `--strict-mcp-config` with no `--mcp-config`. An **enforced** dispatch needs
none of it: its shell's `tools:` frontmatter is an allow-list, and an allow-list also closes the
names nobody has thought of yet. `read_scope_confined` is probed by `read-guard-armed` (#1344 plan
5): the host arms the read guard in a sandbox, binds four fake subagents through fake transcripts —
three in the Agent-tool layout, one in the Workflow-tool layout the shipped dispatch workflow relies
on — and drives eighteen payloads through it — an in-scope Read allowed, an outside Read denied,
Grep of an in-scope file allowed, a directory Grep denied, Glob denied, an unbound subagent denied,
the orchestrator never confined, a directory-scoped entry allowed to Grep and Glob inside its
directory but not to Read outside it, the workflow-bound subagent allowed inside its scope and
denied outside it, a Read under the directory grant's own `.git` store denied and one under its
`.github/` allowed (#3271: a dirs grant never covers <root>/.git), and four headless env-binding
payloads. Any row that disagrees refutes the capability and names the row. In headless mode that
hook round-trip is joined by the shared real-CLI canary's explicit out-of-scope Read denial, and the
two guard probes prove the file the runner will arm — `runs/<tag>/host-settings.json` — rather than
the session root's settings file, so a headless run cannot be refuted by a session root it never uses.
Each resolves to `proven`, `refuted` or `unknown`, and **`unknown` is not benign**: it means nobody
looked, and it is treated exactly as `refuted` wherever posture is consumed. The two are kept apart
because "we did not measure" and "we measured and it is off" have different remedies. A capability
the host does not CLAIM can never read `proven`, whatever an artifact on disk says; a `refuted`
entry passes that mask untouched, since a refutation grants nothing.

Codex claims the three security capabilities. `codex-effective-tools` interrogates the installed
CLI's effective headless tool surface under the launch restrictions; `codex-read-scope` exercises
scoped allowed and denied accesses; and `codex-write-surface-absent` proves
`artifact_write_guard` by omission. All three share one live measurement of every registered role
and the shell-less setup fallback. These are real offline CLI checks, not paid reviewer turns, and
their details name the inspected registration/runtime surfaces. Removing a tool restriction,
widening a tested read grant or exposing one write route on one role refutes the corresponding
probe. The import proof attempts every curated filesystem/process/network module, a real `file:`
URL, and the otherwise-unlisted `node:http2` builtin; every route must fail as an unsupported
import. Its exact host-global inventory also records the six classifications established by live
function-body inspection: `store`/`load` are ephemeral state under `history.persistence="none"`,
`exit`/`notify` are output/control channels, and `as_settled`/`stream_settled` are Promise-settlement
iterators. The
reviewer prompt's own tool-policy paragraph is **rendered from that same surface** rather than
written beside it (#1639 P14): it names `panopticon_scope`'s `read_file`, `search` and `list_files`
with the descriptions the broker publishes and states that there is no shell — run-13 found it
advertising shell commands to a launch that has never had one — and a parity test pins the names it
lists to the `enabled_tools` allowlist the launch argv carries. A missing, incompatible, or
unavailable runtime yields `unknown` with its reason, never an assumed proof. Plain `driver setup`
readiness and manual/session dispatch cannot establish the headless launch controls: without that
headless context these two probes return `unknown`, because parent runtime overrides can replace a
child's role permissions. Use `driver loop --host codex --mode headless` for the proven path.
On a cold or invalidated cache this costs one `codex debug models --bundled` dump plus one `codex
exec` per role (the five registered roles, plus one more measuring the shell-less setup fallback,
run concurrently), all against a localhost fixture rather than a paid endpoint. An unchanged next
`driver run` reuses those rows; a changed `(sha256, version)`, host or probe setting measures again.
`driver setup` costs NONE of it (#1737): it takes no `--mode`, so `settings_path` is None, and all
three Codex probes short-circuit to `unknown` before they launch anything — which is exactly why an
unenforceable Codex setup is refused with `driver loop --setup --host codex --mode headless` as its
remedy rather than a registration command that could not change the answer.

The write-absence proof checks the exact `ALL_TOOLS` and Responses surfaces; allowlists the complete
non-ECMAScript Code Mode host-global set; rejects filesystem, process, network and `file:` imports;
and requires the only effective MCP server to be the controller-bound `panopticon_scope`, with only
`read_file`, `search` and `list_files`, empty resource/template lists and unsupported resource
reads. The runner still refuses every delivery except `return_json`; the controller, not the
reviewer, owns `out_file`, validates the returned role schema, stamps the entry identity and writes
the artifact. The capability concerns reviewer-selectable artifact paths. Codex housekeeping under
controller-selected runtime and `CODEX_HOME` paths is outside it; exposing an arbitrary or
reviewer-selectable host path would refute it. `model_binding` and `usage_ledger` remain unclaimed
and `unknown`, so a healthy headless Codex posture is three of five proven.

### Codex production output-schema compatibility

Codex production replies use four provider-facing projections: review, primary verify, backup
verify and tool-advisor. Every exposed object is closed and fully required. Review preserves true
omission through 64 strict full-finding variants (with nested `anyOf`/`$defs` for location,
severity-override and CVSS sub-shapes); verify separates primary from backup; and tool-advisor
exposes exactly the seven fields its prompt requests. An unknown verify stage carries no generation
schema and falls back to receipt validation.

The projections do **not** replace `phases.persist.ROLE_SCHEMAS`. Those three broad Draft-7 schemas
remain the receipt authority for legacy and optional-field compatibility, and every constrained
reply must still pass its role schema after controller stamping. Claude also continues to receive
those original schemas byte-for-byte on inline `--json-schema`; only Codex selects the strict
generation projections. CI applies the complete strict-provider compatibility screen to every one
of those finite shipped projections. A Codex launch only repeats the target-writable path's
published-schema containment check; it does not parse and walk the same shipped schema again for
every entry (#3272 cut 15).

The once-per-run output-schema proof uses the largest production projection (review), not the toy
shape. A provider refusal records `refuted`, removes every generation schema before that batch
launches and leaves fenced JSON plus receipt validation. An unmeasured proof changes nothing. The
review projection is kept below 64 KiB so complexity cannot silently turn into a per-entry outage.

Kimi claims all five. They are measured by the family's own probes (#1344): `kimi-shell-surface`
(the registered shells; every tool name they allow or forbid verified against the installed CLI's
vocabulary — a name that matches nothing restricts nothing; every tool in that vocabulary either
granted by a template or disabled by the `config.toml` the runner generates, since an unenforced
entry runs as the default agent; and, once a child of this run has launched, its own
`llm.tools_snapshot` compared against that shell's grant), `kimi-read-guard-armed` and
`kimi-write-guard-armed` (round-trips through `kimi_guard_hook.py` as a real PreToolUse subprocess,
exactly as the CLI invokes it, **plus** the arming: the generated `config.toml` parses and registers
that hook with this run's scope/allowlist file baked into its command, and its `[mcp]` block is
inert — MCP enabled, or any server left in it, refutes both), `kimi-model-alias-bound` (each role's
entry tier resolves to an alias in the installed config's `[models]` table), and `kimi-usage-wire`
(`wire_path` + `parse_wire` end to end on a synthetic session written at the per-run home's own
layout — the channel the runner reads, not the operator's `~/.kimi-code/sessions`).

Agy claims all five (#3493), measured under an isolated per-run home (`runners/agy_home.py`) with
`cwd` pinned at `<run_home>/workspace`: `agy-shell-surface` (the registered shells in
`~/.gemini/config/agents` verified against the installed CLI's versioned tool vocabulary and loaded
cleanly via `agy agents` with no `[project]` shadow), `agy-read-guard-armed` and
`agy-write-guard-armed` (`agy -p "/hooks" --output-format json` confirms the single `"matcher": "*"`
`PreToolUse` hook invoking `skill/scripts/agy_guard_hook.py`, plus 0-quota hook subprocess
round-trips and a live `agy` unknown-tool + out-of-scope read canary), `agy-model-bound` (every
role's shell frontmatter tier matches its profile and `agy --agent <shell> --model <slug>
[--effort <level>] --output-format json -p "/model"` reports the resolved runtime model; a role
with an effort, such as the domain roles' `gemini-4-carbon` + `high`, also runs the read-only
`-p "/effort"`, and stays UNKNOWN until the owner's capture defines which field carries the
effective level, #3564), and `agy-usage-envelope`
(`agy --help` advertises `-p` and `--output-format`, `parse_envelope` maps token usage, and any
existing `dispatch-ledger.jsonl` carries token counts on every `ok` row). agy's
`--output-format json` envelope reports no answering model: its documented fields are
`conversation_id`, `status`, `response`, `error`, `duration_seconds`, `num_turns`,
`structured_output`, `json_schema` and `usage` (https://antigravity.google/docs/cli/headless/).
So an agy ledger row records the bound `requested_model` (and `requested_effort` when set) with
`model` null, `usage.json`'s `by_model` has no agy split, and both probe details say so. What
holds per launch is that headless agy exits non-zero instead of falling back from `--model`. If
a future envelope reports a model that differs from the bound one, the driver says so on stderr
(#3550).

Gemini claims all five (#3494, restoring the row #1621 had retired), measured under an isolated
per-run home (`runners/gemini_home.py`, copying only `oauth_creds.json` and `google_accounts.json`)
with `cwd` pinned at `<run_home>/workspace`: `gemini-shell-surface` (no system policy `.toml` or
system `settings.json` / `system-defaults.json` overrides `--admin-policy`, the registered Tier 5
TOML policy shells in `~/.gemini/cli-agents` with allow `900` / explicit deny `950` / catch-all deny
`100` are verified against the installed CLI's versioned `0.55` tool vocabulary, `-p` prompts have
all `@` tokens escaped as `\@` so `handleAtCommand` does not expand `@<path>` via `read_many_files`
— note that inline `@decorator` tokens in quoted prompt excerpts are therefore seen by the model as
`\@decorator`, while files read via `read_file` are unaffected — and user-level `settings.json` locks
`mcpServers = {}`, `mcp.allowed = []`, `skills.enabled = false`, `experimental.enableAgents = false`,
`general.plan.enabled = false`, `security.folderTrust.enabled = false`, and
`context.loadMemoryFromIncludeDirectories = false` with `context.fileName` omitted and no extensions
copied into `<run_home>/.gemini/extensions/`, plus no shadow in the target tree or `~/.gemini/agents`),
`gemini-read-guard-armed` and `gemini-write-guard-armed` (isolated `settings.json` registers a single
`"matcher": "*"` `BeforeTool` hook invoking `skill/scripts/gemini_guard_hook.py` with authoritative
`argv` policy paths, proven by hook subprocess round-trips across read-scope, `include_pattern`,
git-pathspec-magic, strict `TOOL_INPUT_KEYS`, and v2 write-allowlist cases), `gemini-model-bound`
(every role's resolved model in `skill/reference/model-profiles.yml` belongs to `Runner.KNOWN_MODELS`,
`gemini -m <slug>` is advertised by `gemini --help`, model aliases in `MODEL_ALIASES` read `unknown`,
and any existing `dispatch-ledger.jsonl` records no silent model reroute where the bound
`requested_model` is absent from the envelope's `stats.models` keys), and
`gemini-usage-envelope` (`gemini --help` advertises `-p` and `--output-format`, `parse_envelope` maps
standard and cache-read-only `stats.models` token usage, and any existing `dispatch-ledger.jsonl`
carries token counts on every `ok` row). For headless Gemini authentication, individual operators
must `export GEMINI_API_KEY` in the shell that runs panopticon (the primary path — a key saved through
`gemini`'s interactive sign-in dialog is stored in the OS keychain under the operator's `HOME` and is
not visible to the isolated `<run_home>`, so when `selectedType` is `gemini-api-key` and
`GEMINI_API_KEY` is unset, or when no Gemini auth is configured at all, `driver readiness` and
`gemini-shell-surface` fail early with that remedy)
or configure Vertex AI (`GOOGLE_GENAI_USE_VERTEXAI=true`, `GOOGLE_CLOUD_PROJECT`,
`GOOGLE_CLOUD_LOCATION`); personal-account `oauth-personal` ("Sign in with Google") for individuals is
rejected by Google (`IneligibleTierError: This client is no longer supported for Gemini Code Assist
for individuals`), though Code Assist Standard/Enterprise accounts with `GOOGLE_CLOUD_PROJECT` may
still use `oauth-personal`.

`self_write_delivery` is true only for Claude, Kimi, Agy and Gemini. A write-template role self-writes only when
that static mechanism fact and a proven `artifact_write_guard` both hold (and on Gemini, `tool_policy_enforced`
is also `proven`, since `unenforced.toml` is read-only and denies `write_file`); Codex and generic
remain return-persist. Delivery is never evidence for the gate, so generic still refuses without
`--allow-unenforced`. Codex's proof by omission covers the complete reviewer write surface, so it
carries no Bash-path gap while remaining return-persist.

**The posture is disclosed, and the disclosure is not gating.** An unproven capability does not sink
`summary.gate`, `summary.coverage_certified` or `meta.integrity.integrity_ok`, and no combination of
them moves a grade. Claude's read guard, Codex's headless scoped tools and Kimi's per-run-home hook
can prove `read_scope_confined`; other hosts still lack that proof, so the ratchet to gating remains
a later decision. Two refusals *do* exist and are separate machinery, not this — the shadow-shell
refusal and the unproven artifact-write-boundary refusal, both under Notes.

Four surfaces carry it, and all four are mandatory:
1. **stderr, once per run, before the first dispatch** — `driver: host capabilities: <headline>`,
   then one indented
   `driver:   <capability> is <state> on host '<host>' -- probe <id>: <detail>. fix: <remedy>` line
   per capability that is not `proven`. Same channel and register as
   `driver: tool scan CRASHED (rc=…)`. *Once per run* is literal (#1596): `driver run` is a
   resumable loop and the posture is reassessed on every invocation, so every later invocation whose
   disclosure is **unchanged** prints a single
   `host '<host>': N of 5 capabilities proven, M not -- unchanged since <probed_at>` line instead of
   repeating a block that is byte-identical by construction (F3a refuses the run outright if a
   security capability moves). It collapses to a headline rather than to silence, because a resumer
   must see the posture they are resuming under. Beside the capability lines the block carries the
   run's **operational notes**, which gate nothing — among them the output-schema flag. That fact
   has two halves: `advertised`, read once per headless run out of `<cli> --help`, and `shape`,
   which is what one real launch found out about what the CLI takes AFTER the flag (#1732). The
   shape is `proven`, `refuted` or `unmeasured`; only `refuted` changes the run, and what it changes
   is that entries launch without the flag and reply in fenced JSON, which the driver validates
   against the role's receipt schema. **That launch happens inside the loop**, once per run, on the
   first batch that carries a schema-stamped `return_json` entry — after `Guards.arm`, so it is
   confined by that batch's own read scope and write allowlist and the settings file its argv names
   has been written, and it goes out under a real cell's `agent`/`enforced`/`model` so it measures
   the argv a cell will really launch with. Codex uses the largest production projection (review)
   for this launch, so a provider change that refuses a real projection is caught before it can
   burn every cell; other families retain the tiny shape. Its `out_file` is deliberately outside the write
   allowlist: a probe that wrote anything would be a probe with a side effect. Before that batch
   this line says the shape is unmeasured *until the first batch launches*; afterwards the verdict
   is on `host-capabilities.json`, so a later invocation — a resume, or the next turn of the loop —
   reads it back rather than spending another launch, and `--reset` measures again. Run 14 is why
   the two halves are separate: the CLI advertised `--json-schema`, the driver handed it the
   schema's path where it wants the text, and 309 launches went to that gap while this line said "5
   of 5 capabilities proven". Whether it has already been said is read off the **run manifest's**
   own `posture_disclosed` stamp — never off `host-capabilities.json`, which sits on a `.panopticon`
   path a hostile target can pre-commit, while a foreign run-manifest halts the run at first
   contact (#3271). A disclosure that changes at all — including a `detail` that moved under an
   unchanged state, or an operational note — says the whole thing again. A line that contradicts
   itself is not printable at all: the probe and detail print only when the artifact's own recorded
   state is present and equal to the claim-masked one every surface renders; otherwise the line
   carries the masked state and says what the artifact records instead (a different state, quoted
   only if it is a known token; or a probe or detail with no state at all), rather than printing
   that other measurement's probe and detail beside a status that refutes them (#1597).
2. **`meta.host_capabilities` in the report JSON** —
   `{"host", "schema_version", "probed_at", "capabilities"}`. `capabilities` is the artifact's own
   map VERBATIM, one `{"state", "by", "detail"}` entry per capability, so the *reason* survives and
   two runs can be diffed rather than merely compared. `probed_at` is when this posture was
   **established** — when the record was last actually written, which is when the posture last
   *changed*, not merely when a cached probe was last launched. (The assessment runs every
   invocation; unchanged keyed measurements are reused and the artifact is rewritten only when
   something an operator cares about moved.) That is the stronger reading, not a
   weaker one. §5.2 refuses the run outright when a **security** capability's state drifts in either
   direction, and rewrites the record — carrying `probed_at` forward with it — when a state holds
   but its reason moves, or when one of the two operational capabilities moves at all (#1626). So
   the interval this timestamp opens is one over which the *enforcement* posture held unbroken;
   `model_binding` and `usage_ledger` can have moved within it, and the `capabilities` map says what
   they last measured. So a run that produced a report at all is proof that the exact posture you
   are reading has held **continuously from `probed_at` to the end of that run**: a probe timestamp
   would name one moment, and this names an interval. `meta.timestamp` is synthesis time and answers
   a different question. All four keys fail closed to `null` (`{}` for `capabilities`) on an
   artifact that is absent, truncated, or not a JSON object, so a malformed record reads as "nobody
   looked" rather than as a posture.
3. **A `**Host capabilities:**` line in the rendered report body** — in synthesize's terminal
   summary and in `report.json.html`, with the per-capability lines indented beneath it. A person
   must meet the limitation without opening JSON. It renders on **every** report, the all-proven one
   included: the absence of a warning has to mean *measured and proven*, which only holds if the
   proven case is stated out loud. A report carrying no such line at all was not written by this
   version.
4. **`driver setup` readiness rows** — a `host-capabilities` row carrying the headline, plus one
   `host-capability:<name>` row per unproven capability carrying the command that would fix it,
   because readiness is where an operator looks *before* a run to find out what to fix. A `refuted`
   capability is a fault that can be cleared and reports `false`; an `unknown` one is NOT APPLICABLE
   and reports `null`, so it lands in setup's `limitations` clause rather than in its
   `readiness gaps` and never blocks. These rows render the posture **this invocation established**
   — `driver setup` probes for itself before either phase runs (#1737) and surface 4 reads that
   envelope rather than measuring a second one (#1603), so it cannot hand you a remedy for a
   capability the same invocation just proved, and the whole-tree shadow and discovery scans stay at
   one per invocation. Readiness runs on **every** `driver setup` — the normal scan→ingest path as
   well as the vocab-absent fallback — and the rows are kept in that run's setup artifact, so the
   disclosure survives the line scrolling past. Registering no enforcement shells (`generic`) is not
   an exemption: that host claims nothing, so five-of-five-unproven is its entire story and it gets
   the entire disclosure.

All four render from one module, `skill/scripts/host_disclosure.py`, which formats and never reads.
Four hand-written copies of §5.1's wording rule — *name the capability, the host, the probe, and the
remedy; "unenforced" alone is not a disclosure, it is a mood* — drift within a release while each
surface's own test keeps passing, which is the failure the disclosure exists to prevent, reproduced
inside the fix for it.

**`gemini` was retired by #1621 and restored by #3494.** When #1621 (2026-09-13) retired `gemini` from
`driver_selectable`, its row stayed in the registry while `--host gemini` was refused with
`--host generic` as the remedy, and any run started under an unselectable host in its manifest is
refused by **both** `driver loop` and `driver run`, in the same sentence — the manifest is
authoritative on a resume, so neither entrypoint may dispatch for it, and the refusal names
`--host generic --reset` because it is the manifest that has to change (#1624). That sentence is
written once, in the registry (`hosts.unselectable_host_message`), so the two cannot drift. #3494
restored `gemini` as a 5/5 first-class selectable host with its own headless runner, TOML policy
shells in `~/.gemini/cli-agents`, `BeforeTool` guard hook and five capability probes. A manifest
naming a host with **no** registry row at all is a different case and is settled one layer earlier:
`run_manifest.load_manifest` discards it as unusable — exactly as it treats a corrupt manifest —
says so on stderr, and the driver rebuilds the run from the CLI args, so such a name reaches neither
refusal and is never probed or dispatched for (#1344).

**`--host generic` is the permanent, unenforced fallback (owner ruling D1, 2026-09-15, spec 8.3
option 1).** Spec D4 first called it deprecated and said F5 would delete it once every remaining
host cleared spec 8.1's bar; D1 retired F5 instead, so the row's presence is no longer a question
later evidence can reopen. It claims nothing, so every run under it is unenforced and ack-gated
exactly as described above, and it prints a one-line `NOTICE` to stderr — once per `driver run`
invocation and once per `driver setup` invocation, from the *resolved* host, so a resumed run that
omits `--host` prints it too. It is a notice, not a gate: no flag, exit code, grade or gate changes
because of it. **It remains the path for any host without a family runner**, which is why it is kept.
Spec 8.1's bar (every remaining driver-selectable host has
`tool_policy_enforced` and `read_scope_confined` PROVEN; `artifact_write_guard` bridged by
construction, since a write-capable entry self-writes only when its host has both the static
transport mechanism and a proven boundary, and is otherwise return-persist) survives D1 as a
NO-REGRESSION GUARD rather than an entry criterion.
`test_generic_retirement_bar` states that criterion as a test and
`test_todays_shortfall_is_pinned_so_it_moves_consciously` pins today's shortfall at `{}` (the pin is
what a regressing family PR fails; the criterion is enforced only once the fallback row is gone),
and on this base it is **met**: every selectable family host — claude (#1070, plan 5), codex (#1619),
kimi (#1620), agy (#3493) and gemini (#3494, restoring the row #1621 had retired) — clears it by
the probes its family PR shipped. Met no longer implies due: D1 settled the question the bar could
never answer on its own — whether any host without a family runner has anywhere else to go — by
keeping the row for good.
