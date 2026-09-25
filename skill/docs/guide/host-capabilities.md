## Host capabilities (5.2)

Every `driver run` invocation **probes the host before anything dispatches**, writes the result to
`runs/<tag>/host-capabilities.json`, and compares it against what the previous invocation stored — a
posture that moved mid-run refuses to continue and names the capability that moved, in which
direction, and `--reset` (#1344 F3a). That refusal covers the three **security** capabilities
(`tool_policy_enforced`, `read_scope_confined`, `artifact_write_guard`) only. `model_binding` and
`usage_ledger` are operational — spec 8.1 excludes them from the retirement bar and they gate
nothing — so a move in either of those is written into the artifact, state and reason both, and the
run continues (#1626). `usage_ledger` is the one capability whose subject the run itself produces
(the dispatch ledger the loop appends to after every batch), so a CLI release that stopped reporting
tokens used to refuse every re-invocation permanently, with `--reset` — discarding the paid-for
batches — as the only exit. A token counter going quiet costs you a cost figure, not a run. Probing
every invocation rather than once at setup is deliberate: setup-time evidence is unbounded in age,
and a write-guard hook uninstalled the day after setup would read `proven` forever. The artifact is
a record re-established each invocation, never trusted input — so a tampered or truncated one
self-heals rather than merely being noticed.

The hook, frontmatter, launch-envelope and transcript-directory mechanisms in the following
paragraph describe Claude's probes. Each family supplies evidence for the same capability names
using its own effective runtime controls; Codex's and Kimi's probes are described immediately
afterward.

Five capabilities are measured. `tool_policy_enforced` — every driver role has a registered
enforcement shell whose `tools:` grant matches its template, *and* the reviewed tree ships nothing
that shadows those shells. `artifact_write_guard` — the host can mediate a reviewer's `Write` and
confine it to the declared `out_file` (a sandbox arm/deny round-trip, plus the place the host would
arm being writable). `usage_ledger` — probed by `usage-source`, which follows the mode: in headless
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
that model. `read_scope_confined` is probed by `read-guard-armed` (#1344 plan 5): the host arms the
read guard in a sandbox, binds four fake subagents through fake transcripts — three in the Agent-tool
layout, one in the Workflow-tool layout the shipped dispatch workflow relies on — and drives
seventeen payloads through it — an in-scope Read allowed, an outside Read denied, Grep of an in-scope
file allowed, a directory Grep denied, Glob denied, an unbound subagent denied, the orchestrator
never confined, a directory-scoped entry allowed to Grep and Glob inside its directory but not to
Read outside it, the workflow-bound subagent allowed inside its scope and denied outside it, a clean
subdirectory of a grant that recorded a hard link elsewhere still greppable, and four headless
env-binding payloads. It then plants a hard link inside a directory grant, naming a file outside it,
records it with the driver's own walker and requires the directory `Grep` to be refused **by the
hard-link rule** — the wording, not just a denial, since every entry there denies that path for some
other reason too, and a volume that cannot plant a link reads `unknown` rather than refuting a
healthy host (#1917). Any row that disagrees refutes the capability and names the row. In
headless mode the two guard probes prove the file the runner will arm —
`runs/<tag>/host-settings.json` — rather than the session root's settings file, so a headless run
cannot be refuted by a session root it never uses. Each resolves to `proven`, `refuted` or
`unknown`, and **`unknown` is not benign**: it means nobody looked, and it is treated exactly as
`refuted` wherever posture is consumed. The two are kept apart because "we did not measure" and "we
measured and it is off" have different remedies. A capability the host does not CLAIM can never read
`proven`, whatever an artifact on disk says; a `refuted` entry passes that mask untouched, since a
refutation grants nothing.

Codex claims only `tool_policy_enforced` and `read_scope_confined`. `codex-effective-tools`
interrogates the installed CLI's effective headless tool surface under the launch restrictions;
`codex-read-scope` exercises scoped allowed and denied accesses. These are real offline CLI checks,
not paid reviewer turns, and their details name the inspected registration/runtime surfaces.
Removing a tool restriction or widening a tested read grant must refute the corresponding probe. The
reviewer prompt's own tool-policy paragraph is **rendered from that same surface** rather than
written beside it (#1639 P14): it names `panopticon_scope`'s `read_file`, `search` and `list_files`
with the descriptions the broker publishes and states that there is no shell — run-13 found it
advertising shell commands to a launch that has never had one — and a parity test pins the names it
lists to the `enabled_tools` allowlist the launch argv carries. A missing, incompatible, or
unavailable runtime yields `unknown` with its reason, never an assumed proof. Plain `driver setup`
readiness and manual/session dispatch cannot establish the headless launch controls: without that
headless context these two probes return `unknown`, because parent runtime overrides can replace a
child's role permissions. Use `driver loop --host codex --mode headless` for the proven path.
Re-probing is deliberate and happens on every `driver run` — so once per `driver loop` iteration —
and it costs one `codex debug models --bundled` dump plus one `codex exec` per role (the five
registered roles, plus one more measuring the shell-less setup fallback, run concurrently), all
against a localhost fixture rather than a paid endpoint; size a long run with that in mind.
`driver setup` costs NONE of it (#1737): it takes no `--mode`, so `settings_path` is None, and both
Codex probes short-circuit to `unknown` before they launch anything — which is exactly why an
unenforceable Codex setup is refused with `driver loop --setup --host codex --mode headless` as its
remedy rather than a registration command that could not change the answer. `artifact_write_guard`,
`model_binding`, and `usage_ledger` stay unclaimed and `unknown`; the return-JSON bridge and
measured token fields do not upgrade those claims.

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

**The posture is disclosed, and the disclosure is not gating.** An unproven capability does not sink
`summary.gate`, `summary.coverage_certified` or `meta.integrity.integrity_ok`, and no combination of
them moves a grade. Claude's read guard, Codex's headless scoped tools and Kimi's per-run-home hook
can prove `read_scope_confined`; other hosts still lack that proof, so the ratchet to gating remains
a later decision. Two refusals *do* exist and are separate machinery, not this — the shadow-shell
refusal and the unmediated-`Write` refusal, both under Notes.

Four surfaces carry it, and all four are mandatory:
1. **stderr, once per run, before the first dispatch** — `driver: host capabilities: <headline>`,
   then one indented
   `driver:   <capability> is <state> on host '<host>' -- probe <id>: <detail>. fix: <remedy>` line
   per capability that is not `proven`. Same channel and register as
   `driver: tool scan CRASHED (rc=…)`. *Once per run* is literal (#1596): `driver run` is a
   resumable loop and the posture is re-probed on every invocation, so every later invocation whose
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
   against the same schema on receipt. **That launch happens inside the loop**, once per run, on the
   first batch that carries a schema-stamped `return_json` entry — after `Guards.arm`, so it is
   confined by that batch's own read scope and write allowlist and the settings file its argv names
   has been written, and it goes out under a real cell's `agent`/`enforced`/`model` so it measures
   the argv a cell will really launch with. Its `out_file` is deliberately outside the write
   allowlist: a probe that wrote anything would be a probe with a side effect. Before that batch
   this line says the shape is unmeasured *until the first batch launches*; afterwards the verdict
   is on `host-capabilities.json`, so a later invocation — a resume, or the next turn of the loop —
   reads it back rather than spending another launch, and `--reset` measures again. Run 14 is why
   the two halves are separate: the CLI advertised `--json-schema`, the driver handed it the
   schema's path where it wants the text, and 309 launches went to that gap while this line said "5
   of 5 capabilities proven". Whether it has already been said is read off the **run manifest's**
   own `posture_disclosed` stamp — never off `host-capabilities.json`, which sits on a `.panopticon`
   path a hostile target can pre-commit, while a foreign run-manifest is discarded and rebuilt from
   the CLI args. A disclosure that changes at all — including a `detail` that moved under an
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
   *changed*, not merely when the probes last ran. (They run on every invocation; the artifact is
   rewritten only when something an operator cares about moved.) That is the stronger reading, not a
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
   disclosure survives the line scrolling past. Registering no enforcement shells (`generic`, and
   `gemini`'s registry row) is not an exemption: those hosts claim nothing, so five-of-five-unproven
   is their entire story and they get the entire disclosure.

All four render from one module, `skill/scripts/host_disclosure.py`, which formats and never reads.
Four hand-written copies of §5.1's wording rule — *name the capability, the host, the probe, and the
remedy; "unenforced" alone is not a disclosure, it is a mood* — drift within a release while each
surface's own test keeps passing, which is the failure the disclosure exists to prevent, reproduced
inside the fix for it.

**`gemini` is registered but not driver-selectable (#1621, 2026-09-13).** Its family PR did not
clear the gate, so the row stays in the registry — the name resolves, it still claims nothing, and
every surface above still answers for it honestly — while `--host gemini` is refused with the remedy
rather than a word list. A Gemini operator runs `--host generic`, the same path as any host whose
family has not shipped a runner. A run *started* under gemini before the retirement is refused by
**both** `driver loop` and `driver run`, in the same sentence — the manifest is authoritative on a
resume, so neither entrypoint may dispatch for it, and the refusal names `--host generic --reset`
because it is the manifest that has to change (#1624). The sentence is written once, in the registry
(`hosts.unselectable_host_message`), so the two cannot drift. A manifest naming a host with **no**
registry row at all is a different case and is settled one layer earlier:
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
because of it. **It remains the path for any host without a family runner** — Gemini among them —
which is why it is kept. Spec 8.1's bar (every remaining driver-selectable host has
`tool_policy_enforced` and `read_scope_confined` PROVEN; `artifact_write_guard` bridged by
construction, since every write-capable entry on a host that has not proven that guard is already
return-persist) survives D1 as a NO-REGRESSION GUARD rather than an entry criterion.
`test_generic_retirement_bar` states that criterion as a test and
`test_todays_shortfall_is_pinned_so_it_moves_consciously` pins today's shortfall at `{}` (the pin is
what a regressing family PR fails; the criterion is enforced only once the fallback row is gone),
and on this base it is **met**: gemini left the selectable set at #1621, leaving claude, codex and
kimi — claude cleared by its own read guard (#1070, plan 5), codex (#1619) and kimi (#1620) each by
the probes its family PR shipped. Met no longer implies due: D1 settled the question the bar could
never answer on its own — whether a Gemini operator, or any host without a family runner, has
anywhere else to go — by keeping the row for good.
