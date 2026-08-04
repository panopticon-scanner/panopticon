# Cross-Host Portability Research: Panopticon Skill (Claude Code / Kimi Code CLI / OpenAI Codex CLI)

Research date: 2026-08-03. All findings verified against official docs as of this date; blog/community sources are marked explicitly and treated as lower-confidence corroboration only.

**Critical disambiguation found during research:** MoonshotAI ships two related-but-distinct products:
- `MoonshotAI/kimi-cli` ("Kimi CLI") — the **legacy** product, explicitly being wound down. Its docs (`moonshotai.github.io/kimi-cli`, `github.com/MoonshotAI/kimi-cli`) describe a **YAML** custom-agent format (`version`, `name`, `extend`, `system_prompt_path`, `tools: ["module:ClassName"]`, `exclude_tools`, `subagents`).
- `MoonshotAI/kimi-code` ("Kimi Code CLI") — the **current/successor** product ("Kimi CLI is evolving into Kimi Code CLI... This project will be gradually wound down"). Its docs (`www.kimi.com/code/docs/en/kimi-code-cli/...`, `github.com/MoonshotAI/kimi-code`) describe a **Markdown+YAML-frontmatter** custom-agent format (`name`, `description`, `whenToUse`, `override`, `model_preference`, `tools`, `disallowedTools`).

All Kimi answers below use the **kimi-code** (current) docs as ground truth. Where search results surfaced kimi-cli (legacy) content, I flag it and discard it in favor of kimi-code.

Source: https://github.com/MoonshotAI/kimi-cli (README banner) — confirms the wind-down/migration relationship.

---

## 1. Kimi Code CLI — Skills

**skills_dir default / discovery:**
- User level: `$KIMI_CODE_HOME/skills/` (default `~/.kimi-code/skills/`), and `~/.agents/skills/`
- Project level (nearest `.git` ancestor): `.kimi-code/skills/`, `.agents/skills/`
- Discovery priority: **Project > User > Extra > Built-in** (more specific wins)
- `--skills-dir` CLI flag replaces auto-discovered dirs for that launch only (repeatable, stacks). `extra_skill_dirs` in `config.toml` adds dirs permanently on top of auto-discovered ones.
- Built-in skills: `kimi-cli-help`, `skill-creator`.
- Note: an **older/legacy kimi-cli doc** (moonshotai.github.io/kimi-cli) additionally described a "brand group" merge behavior (`~/.kimi/skills/`, `~/.claude/skills/`, `~/.codex/skills/` merged with priority kimi>claude>codex via `merge_all_available_skills=true`). This did **not** appear in the current kimi-code docs I fetched (which show only `$KIMI_CODE_HOME/skills/` + `~/.agents/skills/`). Treat brand-group cross-tool merging as **kimi-cli legacy behavior, unconfirmed for current kimi-code** — mark this specific sub-point **inferred/uncertain**, not documented for the current product.

**SKILL.md format:** YAML frontmatter + Markdown body. Two forms: directory form `<name>/SKILL.md` (recommended) or flat `<name>.md` file directly in a skills dir (name defaults to filename).

**Frontmatter fields read (current kimi-code docs):**
| Field | Purpose |
|---|---|
| `name` | Skill identifier (case-insensitive); required for directory form |
| `description` | One-line summary used by the model to decide when to trigger |
| `type` | `prompt`/`inline` (default; automatic + manual invocation) or `flow` (manual-only, Mermaid/D2 diagram workflows invoked via `/flow:<name>`) |
| `whenToUse` | Free-text description of trigger context |
| `disableModelInvocation` | `true` prevents automatic (model-initiated) invocation — manual-only |
| `arguments` | Named parameters (array or space-separated string), accessible via `$<name>` placeholders in the body |
| `metadata` | Arbitrary key-value map (mentioned in one fetch, not deeply detailed) |

Confidence: **documented** (fetched directly from `www.kimi.com/code/docs/en/kimi-code-cli/customization/skills.html` and `raw.githubusercontent.com/MoonshotAI/kimi-code/main/docs/en/customization/skills.md`).

Sources:
- https://www.kimi.com/code/docs/en/kimi-code-cli/customization/skills.html
- https://raw.githubusercontent.com/MoonshotAI/kimi-code/main/docs/en/customization/skills.md
- https://moonshotai.github.io/kimi-cli/en/customization/skills.html (legacy product — brand-group merge claim only, not corroborated on current docs)

---

## 2. Kimi Code CLI — Custom agents (agent-file format)

**Current format (kimi-code, confirmed via two independent fetches of official docs):** Markdown file with YAML frontmatter; body is the system prompt. This is a **changed format** vs. the legacy kimi-cli YAML format — see disambiguation note above.

Full field table:
| Field | Required | Notes |
|---|---|---|
| `name` | No | kebab-case identifier; defaults to filename |
| `description` | Yes | Shown to the main agent when picking a sub-agent |
| `whenToUse` | No | Guidance on when to apply this agent |
| `override` | No | Whether this file may replace a same-name built-in agent |
| `model_preference` | No | `primary` or `secondary` — **only takes effect if the secondary-model experiment is enabled** (see §3) |
| `tools` | No | Allowlist; glob matching supported for MCP tools (e.g. `mcp__github__*`) |
| `disallowedTools` | No | Denylist, same syntax, applied after `tools` |
| `subagents` | No | Allowlist of sub-agent names this agent may delegate to |

Canonical example (verbatim from docs):
```markdown
---
name: reviewer
description: Strict code reviewer that reports severity-ranked findings
whenToUse: Code reviews and PR checks
override: false
model_preference: primary
tools:
  - Read
  - Grep
  - Glob
  - mcp__github__*
disallowedTools:
  - Bash
---

You are a strict code reviewer. Read the diff, then report findings grouped by severity…
```

**Auto-discovery locations** (separate from the `--agent-file` CLI flag, which loads/selects a single agent file for the whole session):
- Priority: **Explicit > Project > Extra > User > Plugin > Built-in**
- User: `$KIMI_CODE_HOME/agents/` (default `~/.kimi-code/agents/`), `~/.agents/agents/`
- Project: `.kimi-code/agents/`, `.agents/agents/`
- Extra: `extra_agent_dirs` in `config.toml`
- Plugin: directories declared in an enabled plugin manifest's `agents` field

Discovered agent files become selectable as `subagent_type` values for the `Agent`/`AgentSwarm` tools — this is the mechanism panopticon would use to register `lens-sweep`, `panel-review`, `scout`, `advisor` as named Kimi subagent profiles if it wanted named-profile dispatch rather than pure raw-prompt dispatch.

**Recency:** The changelog I could access (0.2.0–0.31.1) did not contain an explicit "agent format changed from YAML to Markdown" entry, so I cannot pin an exact version/date for this migration — it's presented as the current stable format on the kimi-code docs site, contrasted with the legacy kimi-cli YAML format. Confidence: **documented** for the current field set; **undocumented** for the exact migration date.

Sources:
- https://www.kimi.com/code/docs/en/kimi-code-cli/customization/agents.html
- https://raw.githubusercontent.com/MoonshotAI/kimi-code/main/docs/en/customization/agents.md

---

## 3. Kimi Code CLI — AgentSwarm raw-prompt dispatch

**Yes — AgentSwarm can dispatch raw/free-form prompts, not just registered agent names.** Confirmed via the official Built-in Tools reference (`www.kimi.com/code/docs/en/kimi-code-cli/reference/tools.html`).

**`Agent` tool parameters:**
- `prompt` (required) — complete task description (free text)
- `description` (required) — 3–5 word summary
- `subagent_type` (optional, defaults to `coder`) — selects a **profile** (built-in: `coder`, `explore`, `plan`, or any auto-discovered custom agent file); this is a model/tools/system-prompt profile selector, **not** a requirement that the dispatched work itself be pre-registered — the `prompt` field carries the actual ad-hoc task.
- `resume` (optional) — ID of an existing agent to resume; mutually exclusive with `subagent_type`
- `run_in_background` (optional, default `false`)
- `model` (optional) — `"secondary"` or `"primary"`, only meaningful when the secondary-model experiment is enabled (see below)

**`AgentSwarm` tool parameters:**
- `prompt_template` (required) — a shared template with a placeholder
- `items` (required for new spawns, min 2 items without `resume_agent_ids`) — array of values substituted into the placeholder, one subagent spawned per item — **this is exactly the raw-prompt fan-out shape** (render N prompts from a template + a list, dispatch all as free text)
- `subagent_type` (optional, defaults to `coder`) — same profile-selection semantics as `Agent`
- `model` (optional) — `"secondary"`/`"primary"`, gated by the same experiment
- `resume_agent_ids` (optional) — resume existing subagents instead of/alongside spawning new ones
- Capacity: up to 128 total subagents per call; waits for all to finish; returns an aggregated report

**Tool restrictions per-dispatch:** **Not available as an AgentSwarm/Agent call parameter.** There is no `tools`/`disallowedTools` argument on the dispatch call itself. The only way to constrain tools per dispatch is indirectly: define a custom agent file (§2) with a `tools`/`disallowedTools` allowlist and reference it via `subagent_type`. Pure ad-hoc raw-prompt dispatch inherits whatever tools the selected profile (default `coder`) has.

**Model override per-dispatch:** Yes, via the `model` param (`"secondary"`/`"primary"`), **but this is experimental and off by default.** Enable with `KIMI_CODE_EXPERIMENTAL_SECONDARY_MODEL=1` or the master flag `KIMI_CODE_EXPERIMENTAL_FLAG=1` (also settable via `/experiments` slash command; `/secondary_model` configures which model is "secondary"). Changelog: added in **v0.29.1 (2026-07-24)** as "experimental secondary-model bindings for newly spawned subagents, including per-agent model preferences."

Confidence: **documented** for parameter existence and raw-prompt support; **documented** for the experimental gating of the `model` override; **documented (negative)** for absence of per-dispatch tool restriction.

Sources:
- https://www.kimi.com/code/docs/en/kimi-code-cli/reference/tools.html
- https://www.kimi.com/code/docs/en/kimi-code-cli/release-notes/changelog.html
- https://www.kimi.com/code/docs/en/kimi-code-cli/customization/agents.html

---

## 4. Kimi Code CLI — Headless/CLI flag status (`--agent-file`, `--prompt`, `--output-format stream-json`)

All three are **stable** in the current kimi-code CLI reference — none are marked experimental or gated by `KIMI_CODE_EXPERIMENTAL_FLAG` in the docs I fetched:

- **`--agent-file PATH`** — "Load a custom agent from a Markdown file for the new session and select it. Cannot be repeated or combined with `--agent`, `--session`, or `--continue`." (Note: this loads/selects **the** agent for the whole session, distinct from the auto-discovered per-subagent profiles in §2.)
- **`--prompt` / `-p`** — "Run a single prompt non-interactively and stream the Assistant output to stdout. This mode does not open the TUI." Cannot combine with `--yolo`/`--auto`/`--plan`; uses `auto` permission by default.
- **`--output-format {text|stream-json}`** — text is default; `stream-json` emits JSONL (one JSON object per line: Assistant messages, tool_calls, Tool result messages) for programmatic integration. Only usable together with `--prompt`.

`KIMI_CODE_EXPERIMENTAL_FLAG=1` is a real, currently-documented **master experimental switch** — it still exists and currently gates (at minimum): `KIMI_CODE_EXPERIMENTAL_SUB_SKILL` (sub-skill discovery, added v0.11.0/2026-06-05), `KIMI_CODE_EXPERIMENTAL_GOAL_COMMAND` (goal mode, v0.8.0/2026-06-02), and the secondary-model experiment (v0.29.1/2026-07-24). It does **not** currently gate `--agent-file`, `--prompt`, or `--output-format stream-json` per the docs — those read as stabilized/always-on flags today. I could not find a changelog entry documenting when/if they were ever gated behind the experimental flag, so I can't confirm whether panopticon's original design assumption (needing `KIMI_CODE_EXPERIMENTAL_FLAG=1` for these three specifically) reflects a past requirement that has since been dropped, or a misattribution. Confidence: **documented** for current stable status; **undocumented** for historical gating of these three specific flags.

Also relevant: `AgentSwarm` itself shipped via `/swarm` in **v0.12.0 (2026-06-09)**, and `KIMI_CODE_AGENT_SWARM_MAX_CONCURRENCY` (rate-limit-aware ramp-up throttle) was added in **v0.18.0 (2026-06-18)** — both are current/stable, not flagged experimental.

Sources:
- https://www.kimi.com/code/docs/en/kimi-code-cli/reference/kimi-command.html
- https://www.kimi.com/code/docs/en/kimi-code-cli/release-notes/changelog.html

---

## 5. Kimi Code CLI — Env vars for host detection

**Documented, general-purpose env vars** (from the official env-vars reference — none of these are session-identity markers, they're config/credential inputs):
`KIMI_CODE_HOME`, `KIMI_DISABLE_TELEMETRY`, `KIMI_MODEL_NAME`, `KIMI_MODEL_API_KEY`, `KIMI_MODEL_PROVIDER_TYPE`, `KIMI_MODEL_BASE_URL`, `KIMI_MODEL_MAX_CONTEXT_SIZE`, `KIMI_MODEL_CAPABILITIES`, `KIMI_MODEL_DISPLAY_NAME`, `KIMI_MODEL_MAX_OUTPUT_SIZE`, `KIMI_MODEL_REASONING_KEY`, `KIMI_MODEL_THINKING_EFFORT`, `KIMI_MODEL_ADAPTIVE_THINKING`, `KIMI_API_KEY`, `KIMI_BASE_URL`, `ANTHROPIC_API_KEY`, `ANTHROPIC_BASE_URL`, `OPENAI_API_KEY`, `OPENAI_BASE_URL`, `GOOGLE_API_KEY`, `VERTEXAI_API_KEY`, `GOOGLE_CLOUD_PROJECT`, `GOOGLE_CLOUD_LOCATION`, `KIMI_CODE_OAUTH_HOST`, `KIMI_OAUTH_HOST`, `KIMI_CODE_BASE_URL`, `KIMI_REGISTRY_API_KEY`.

**`KIMI_SESSION_ID` / `KIMI_CODE_VERSION` (or equivalent session-identity vars set INTO the child-process environment by Kimi, for a script to detect "I'm running under Kimi"): undocumented.** I searched the official env-vars page and changelog and found no such variable named or described. This is a real gap, not just a search miss — the env-vars reference page appears to enumerate only *inbound* config/credential variables Kimi *reads*, not variables it *sets* for spawned processes. If panopticon needs host detection, this must be treated as **undocumented / not guaranteed** for Kimi; a more reliable signal would be a CLI-provided template variable inside the system prompt context (`${KIMI_WORK_DIR}`, `${KIMI_SKILLS}`, `${KIMI_NOW}` were mentioned as system-prompt template vars, not shell env vars — separate mechanism) or explicit `--agent-file`/config wiring rather than env-var sniffing.

Sources:
- https://www.kimi.com/code/docs/en/kimi-code-cli/configuration/env-vars.html
- https://www.kimi.com/code/docs/en/kimi-code-cli/release-notes/changelog.html

---

## 6. OpenAI Codex CLI — Skills

**Location:** Official current guidance (`developers.openai.com/codex/skills` → redirects to `learn.chatgpt.com/docs/build-skills`) plus `github.com/openai/codex/blob/main/docs/skills.md`:

Discovery locations, in precedence order:
| Scope | Path |
|---|---|
| Repo (cwd) | `$CWD/.agents/skills` |
| Repo (root) | `$REPO_ROOT/.agents/skills` |
| User | `$HOME/.agents/skills` |
| Admin | `/etc/codex/skills` |
| System | bundled with Codex |

**Important:** current official Codex docs describe `.agents/skills` (the generic cross-runtime path), **not** `~/.codex/skills`. (Some third-party guides/blogs from late 2025 reference `~/.codex/skills/` and `.codex/skills/` — these appear to be either stale or describing an earlier/alternate layout; I'm flagging the `.agents/skills` path as the one confirmed on the current official page and treating `~/.codex/skills` claims as **lower confidence / possibly outdated**.)

**AGENTS.md relationship:** Separate mechanism — Codex reads `AGENTS.md` (project root + a global `~/.codex/AGENTS.md`) before every task as always-on project instructions; skills are the on-demand, task-triggered counterpart. They are not the same file format and don't nest inside each other.

**Frontmatter fields Codex reads:** Per the official build-skills doc — **only `name` and `description`** are documented as read/required. Quote: "The SKILL.md file must include name and description" — no mention of `allowed-tools`, `license`, `metadata`, `compatibility`, etc. being consumed by Codex itself (even though the open spec defines them — see §10). This is the most minimal frontmatter surface of the three hosts.

**Extra file:** an optional `agents/openai.yaml` alongside SKILL.md — **not** part of the portable skill content; it's Codex/ChatGPT-app-specific UI metadata (display name, icon, brand color) and an `allow_implicit_invocation` (default `true`) flag controlling automatic vs. explicit triggering, plus declared MCP-server/tool dependencies. A skill built for multi-host portability can ignore this file entirely on Kimi/Claude and it will be safely unused.

Confidence: **documented**.

Sources:
- https://learn.chatgpt.com/docs/build-skills (redirect target of https://developers.openai.com/codex/skills)
- https://github.com/openai/codex/blob/main/docs/skills.md
- https://github.com/openai/skills/blob/main/skills/.system/skill-creator/SKILL.md

---

## 7. OpenAI Codex CLI — Sub-agents / parallelism

**Mechanism exists but is model/instruction-driven, not a documented, stable, directly-callable API with a fixed parameter schema** — this is a meaningfully different shape from Kimi's `Agent`/`AgentSwarm` tools or Claude's `Task` tool.

What's confirmed from the **official** subagents doc (`developers.openai.com/codex/subagents` → `learn.chatgpt.com/docs/agent-configuration/subagents`):
- You ask Codex in natural language to delegate work ("spawn two agents," "delegate this work in parallel"); Codex "handles orchestration across agents, including spawning new subagents, routing follow-up instructions, waiting for results, and closing agent threads" — described as **Codex's own internal behaviors**, not a schema the skill author calls directly.
- Underlying tool *names* `spawn_agent`, `followup_task` (give an agent a new task, triggers a turn), `send_message` (message a running agent, no new turn) are referenced in official docs, but **no parameter table/JSON schema for them is published** on the official pages I could fetch (the content appears deliberately narrative/user-facing rather than an API reference).
- `/agent` CLI slash command switches between active agent threads / inspects them interactively.
- **Proactive** (automatic, unprompted) delegation is gated to **"Ultra" tier** — "With Ultra, ChatGPT can proactively delegate work when parallel agents would materially improve speed or quality." Direct/explicit user-requested delegation is implied to work more broadly, but I could not confirm a specific tier gate for that path either way (**undocumented**).
- **Custom agent config** (TOML, `[agents.<name>]` or similar in `config.toml`): required fields `name`, `description`, `developer_instructions`; optional `model`, `model_reasoning_effort`, `sandbox_mode`, `mcp_servers`, `skills.config`. Global toggles under `[agents]`: `agents.enabled`, `agents.max_concurrent_threads_per_session`, `agents.default_subagent_model`, `agents.default_subagent_reasoning_effort`.
- Community source (obra/superpowers `codex-tools.md` reference file, see §11) states subagent dispatch requires **`multi_agent = true`** in `~/.codex/config.toml` to enable `spawn_agent`/`wait_agent`/`close_agent` at all — this **conflicts** with a separate community claim ("Current Codex releases enable subagent workflows by default") found via web search summaries (non-official, `morphllm.com`/`shipyard.build` blog-tier sources). I could not resolve this conflict against an official source; **treat "subagents enabled by default" as unconfirmed / possibly version-dependent**, and treat explicit config enablement (`multi_agent = true` or `agents.enabled = true`) as the safe assumption for a portable skill.

**Raw/free-form prompt dispatch:** Not explicitly confirmed or denied on the official pages for the low-level tool. Community sources describe a `spawn_agent(prompt: string)` shape (single required `prompt` string, no pre-registered name needed) and a `spawn_agents_parallel` variant taking a list of `{prompt}` items — structurally similar to Kimi's `AgentSwarm.items`. This is **inferred/community-sourced, not confirmed on developers.openai.com/learn.chatgpt.com** — those official pages describe delegation narratively rather than exposing this schema.

**Per-dispatch tool restrictions / model override:** **Undocumented** at the individual dispatch-call level in official docs. What IS documented is that a *named, pre-configured* custom agent (TOML `[agents.<name>]` block) can carry its own `model`, `model_reasoning_effort`, and `sandbox_mode` — so tool/model control is achieved the same way as Kimi: by defining a named profile ahead of time and delegating to that profile, not by parameterizing an ad-hoc call.

**Practical implication for panopticon's rendered-prompt dispatch design:** Codex does not offer a documented, stable, script-invokable "give me a raw prompt string, get a subagent" primitive the way Kimi's AgentSwarm or Claude's Task tool do. The more defensible design for Codex is either (a) rely on natural-language delegation instructions inside the rendered prompt and hope the model self-delegates (unreliable/undocumented reach), or (b) fall back to running the pipeline **sequentially within a single Codex session** (feeding rendered role-prompts one at a time as ordinary turns/instructions), or (c) shell out via `codex exec` subprocesses from the orchestrator script itself (documented, stable, scriptable — see below) rather than depending on Codex's in-session subagent tool.

`codex exec` (documented, stable, official): non-interactive one-shot runs; streams progress to stderr, final message to stdout; supports `--json` (JSONL event stream), `--output-schema` (structured output), and `codex exec resume` to continue a session. This is a legitimate, documented, scriptable fan-out mechanism **external to** Codex's in-session subagent tool — i.e., panopticon's own `dispatch.py`/`orchestrator.py` could itself invoke `codex exec` N times as subprocesses (analogous to how it might invoke `kimi -p ... --output-format stream-json`), sidestepping the uncertainty around Codex's internal spawn_agent tool entirely.

Confidence: mixed — CLI-level (`codex exec`, TOML custom agent fields) is **documented**; low-level in-session tool schema and default-enablement are **inferred/undocumented/conflicting**.

Sources:
- https://learn.chatgpt.com/docs/agent-configuration/subagents (official; narrative-level detail only)
- https://developers.openai.com/codex/subagents (redirects to above)
- https://learn.chatgpt.com/docs/agent-approvals-security (official; codex exec / sandbox behavior)
- https://raw.githubusercontent.com/obra/superpowers/main/skills/using-superpowers/references/codex-tools.md (community, but a maintained cross-host skill framework's own reverse-engineered mapping — moderate confidence)
- Community/blog (lower confidence, used only for corroboration, not as primary fact source): https://www.morphllm.com/codex-multi-agent, https://codex.danielvaughan.com/2026/04/11/codex-cli-multi-agent-orchestration-v2-complete-guide/

---

## 8. OpenAI Codex CLI — Env vars for host detection

**Documented (official, `learn.chatgpt.com/docs/config-file/environment-variables`):**
- `CODEX_HOME` — relocates the user-level data root (default `~/.codex`); config, credentials, `history.jsonl`, SQLite state DB all live under it.
- Provider API key variable names are **not fixed** — Codex reads whatever variable name you configure via `env_key` in the model-provider config, so there's no single constant like `OPENAI_API_KEY` guaranteed.
- `RUST_LOG` — logging filter (`error|warn|info|debug|trace`, or targeted filters like `codex_core=debug`).
- Sandbox-state signals **set into the child-process environment by Codex** (useful for host detection from inside a shelled-out script): `CODEX_SANDBOX` (e.g. `CODEX_SANDBOX=seatbelt` on macOS) and `CODEX_SANDBOX_NETWORK_DISABLED` (`=1` when network is off; used especially on Windows where OS-level firewall sandboxing isn't available, so this is an env-level control there rather than just an indicator elsewhere).
- Note: `~/.codex/.env` is loaded at startup, but **`CODEX_`-prefixed variables are filtered out of it for security** — you can't self-set fake `CODEX_*` vars via that file to spoof host detection.
- `CODEX_SESSION_ID` / `CODEX_VERSION`: **undocumented** — not found on the official env-vars page or in the changelog/GitHub issues I checked. Same gap pattern as Kimi (§5): no documented session-identity env var.

Confidence: **documented** for `CODEX_HOME`, `CODEX_SANDBOX`, `CODEX_SANDBOX_NETWORK_DISABLED`, `RUST_LOG`; **undocumented** for session-id/version vars.

Sources:
- https://learn.chatgpt.com/docs/config-file/environment-variables (official; redirect target of developers.openai.com/codex/environment-variables)
- https://github.com/openai/codex/issues/30356 (community, corroborates `CODEX_SANDBOX_NETWORK_DISABLED` behavior)

---

## 9. OpenAI Codex CLI — Gotchas for skills that shell out to python3 scripts

From the official agent-approvals-security doc (`learn.chatgpt.com/docs/agent-approvals-security`):

- **Network is off by default.** Any python3 script that needs outbound network (e.g. fetching CWE data, calling an LLM API directly, `pip install`) will fail silently/be blocked unless network is explicitly enabled (`network_access = true` under `[sandbox_workspace_write]` in config, or `--sandbox danger-full-access`).
- **Filesystem writes are workspace-scoped** in the default `workspace-write` sandbox mode. `.git`, `.agents`, and `.codex` directories are **protected as read-only regardless of sandbox mode** — a script that tries to write scratch state into `.agents/` or that expects to `git commit` hooks-writeable `.git/` internals could be blocked even in write-enabled sandboxes.
- **Approval prompts block headless/non-interactive execution.** Default `--ask-for-approval on-request` will prompt for sandbox escalations (e.g. a script's first attempt to hit the network or write outside workspace) — this halts a non-interactive `codex exec` run rather than degrading gracefully; the error surfaces to the parent workflow instead of the child process getting a clean permission-denied it can catch-and-continue from.
- **For CI/headless use**, the documented safe pattern is `--ask-for-approval never` combined with an explicit sandbox level chosen up front (`--sandbox read-only` for pure analysis, or `--sandbox workspace-write` — sometimes stacked with `--dangerously-bypass-approvals-and-sandbox` in throwaway/ephemeral CI containers per community sources, though that specific bypass flag is **not something I found in the official docs**, only in community write-ups about subagent orchestration — treat with caution).
- **Network allowlisting, if enabled:** DNS-rebinding protection blocks hostnames that resolve to non-public addresses; local/private destinations are blocked unless `allow_local_binding = true`; `network_proxy` with a domain allowlist is the documented way to constrain outbound traffic for a script that needs, say, only `pypi.org` or a specific vulnerability-feed API.
- Practical implication for panopticon's `scripts/tools/*.py` (pip_audit, npm_audit, osv_scanner, etc.): any tool wrapper that shells out to a package-registry/vuln-DB network call needs the skill's SKILL.md/AGENTS.md guidance to either (a) tell the operator to run Codex with network enabled up front, or (b) treat network-dependent tool wrappers as best-effort/skippable when running under Codex's default sandbox, distinct from Claude Code and Kimi where the operator's own shell permission model applies instead.

Confidence: **documented** for sandbox/approval mechanics; **community-sourced/lower-confidence** for the exact bypass-flag CLI syntax used in some blog write-ups.

Sources:
- https://learn.chatgpt.com/docs/agent-approvals-security (official; redirect target of developers.openai.com/codex/agent-approvals-security)

---

## 10. The agentskills.io / open SKILL.md specification

Official spec: https://agentskills.io/specification

**Standard frontmatter fields (the actual open spec):**
| Field | Required | Notes |
|---|---|---|
| `name` | Yes | ≤64 chars, lowercase+digits+hyphens, no leading/trailing/double hyphen, **must match parent directory name** |
| `description` | Yes | ≤1024 chars, must state what + when |
| `license` | No | License name or pointer to bundled license file |
| `compatibility` | No | ≤500 chars; environment requirements (e.g. `"Requires Python 3.14+ and uv"`, `"Designed for Claude Code (or similar products)"`) — spec explicitly notes "Most skills do not need the compatibility field" |
| `metadata` | No | Arbitrary string→string map for client-specific extras |
| `allowed-tools` | No | Space-separated pre-approved tool list, e.g. `Bash(git:*) Bash(jq:*) Read` — **explicitly marked "Experimental. Support for this field may vary between agent implementations"** |

**Explicitly a host dialect, NOT in the open spec:** Kimi's `type`, `whenToUse`, `arguments`, `disableModelInvocation` (§1) do not appear anywhere in the agentskills.io field table. Spec-compliant runtimes are required to ignore unrecognized frontmatter keys, which is exactly what makes Kimi-specific fields safe to include in a portable SKILL.md — Claude Code and Codex will simply ignore them.

**Portability guidance in the spec itself:**
- "spec-compliant runtimes ignore frontmatter keys they do not recognize" — the core portability guarantee.
- Progressive disclosure model (name+description ~100 tokens loaded always; full SKILL.md body loaded on activation, <5000 tokens recommended, <500 lines; scripts/references/assets loaded on demand) is presented as universal guidance, not host-specific.
- No dedicated "multi-host targeting" section beyond: keep to `name`+`description`+plain Markdown if you want it to "work everywhere," and use `compatibility` only when you truly have environment requirements.
- Validation tooling exists: `skills-ref validate ./my-skill` (https://github.com/agentskills/agentskills/tree/main/skills-ref) checks frontmatter validity/naming conventions against the spec.

Corroborating community claim (search-result summary, not independently verified against a primary source): the spec/format is described as supported by "27+ AI coding agents" including Claude Code, Cursor, Codex, Gemini CLI, VS Code/Copilot, Amp, Roo Code, Goose, Windsurf, Continue, Cline, Aider — treat the count and full list as **unverified marketing-adjacent claim**, but the core interoperability principle (name+description+plain-Markdown skills are broadly portable) is consistent with what I independently confirmed for Kimi (§1) and Codex (§6).

Confidence: **documented** for the field table and portability principle; **unverified** for the "27+ agents" breadth claim.

Sources:
- https://agentskills.io/specification
- https://github.com/agentskills/agentskills/tree/main/skills-ref

---

## 11. Community patterns for one skill repo serving multiple hosts

Primary example investigated: **obra/superpowers** (MIT, actively maintained, per-harness support explicitly including Claude Code, Codex App, Codex CLI, Cursor, Factory Droid, Gemini CLI, GitHub Copilot CLI, **Kimi Code**, OpenCode, Pi, Antigravity).

**Pattern 1 — vocabulary abstraction + per-harness reference files ("Platform Adaptation").**
Skills are written using abstract verbs ("dispatch a subagent," "your instructions file," "track a task") rather than hardcoding a specific tool name. A `references/<harness>-tools.md` file per supported harness maps each abstract action to that harness's concrete native mechanism. Recent releases explicitly **pruned** reference files down to only the harnesses that still have harness-specific content worth stating — e.g. `claude-code-tools.md` and `copilot-tools.md` were **deleted** because "they had nothing harness-specific left" once the abstraction layer stabilized; `codex-tools.md`, `pi-tools.md`, `antigravity-tools.md` remain because those harnesses have real deltas (subagent dispatch mechanics, task tracking, instructions-file path).

Concrete example from `references/codex-tools.md` (fetched): "dispatch a subagent" → requires `multi_agent = true` in `~/.codex/config.toml`, then maps to `spawn_agent`/`wait_agent`/`close_agent`; documents lifecycle guidance (close reviewer subagents on completion, keep implementer subagents alive through fix cycles) and sandbox-driven fallbacks (when branch/push is blocked, commit locally and defer PR/push to the native App UI, emitting a suggested branch name/commit message instead of executing the disallowed operation).

**Pattern 2 — per-host plugin manifest performs the abstraction-to-native mapping, not the skill content itself.**
For Kimi specifically, a `.kimi-plugin/plugin.json` manifest (a) points Kimi Code at the *same* `skills/` directory used by every other host (no copies), (b) loads a bootstrapping `using-superpowers` skill at `sessionStart`, and (c) supplies a `skillInstructions` mapping table translating abstract actions to Kimi-native tool names — e.g. "Dispatch a subagent" → Kimi's `Agent` tool (not `AgentSwarm` — worth noting the reference implementation maps to the singular-dispatch tool, not the batch one), "Invoke a skill" → Kimi's native `Skill` tool, "Ask the user" → `AskUserQuestion`, "Create/manage todos" → `TodoList`, file ops → `Read`/`Write`/`Edit`, shell → `Bash`, search → `Grep`/`Glob`, network → `FetchURL`/`WebSearch`. Explicitly stated design goal: **"There are no copied skills, symlinks, hooks, or extra runtime dependencies."** — one canonical `skills/` tree, host-specific manifests do the translation.

**Pattern 3 — `~/.agents/skills/` as the shared cross-runtime install root.**
Confirmed (both from the Codex official docs in §6 and from superpowers' own docs): "Codex, Copilot CLI, and Gemini CLI all recognize `~/.agents/skills/` as a cross-runtime alias." Kimi's current docs (§1) list `~/.agents/skills/` as one of two generic user-level search paths (alongside `~/.config/agents/skills/`, which Kimi's docs mark as "recommended" over `~/.agents/skills/` — so Kimi supports it but has a mildly different preferred generic path than the Codex/Copilot/Gemini convention). Community write-ups (dev.to, agensi.io — lower confidence) describe two concrete implementation patterns on top of this: (a) keep the canonical skill tree at `~/.agents/skills/` and symlink `~/.claude/skills`, `~/.gemini/skills`, `~/.copilot/skills` etc. back to it (git tracks symlinks natively, so this survives clone/pull for a team); (b) a setup script that auto-detects which host directories exist locally and creates the symlinks, so "edit once, every local agent sees it."

**Synthesis for panopticon's own design:** the mature-repo pattern is *not* "write one universal prompt/dispatch call that works unchanged everywhere" — it's "write the skill body in host-agnostic vocabulary, then maintain a small, explicit, per-host mapping layer (reference doc and/or plugin manifest) that translates 'dispatch a subagent with this rendered prompt' into whatever that host's actual primitive is" — which for Codex specifically means acknowledging that primitive may be `codex exec` subprocess calls from the orchestrator rather than an in-session tool call, given the documentation gaps found in §7.

Confidence: **documented** for the `~/.agents/skills` cross-runtime-alias claim (corroborated by both Codex's own docs and superpowers' docs independently) and for the superpowers repo's own file structure/manifest content (fetched directly); **inferred** for the Kimi `Agent`-vs-`AgentSwarm` mapping choice being a deliberate design decision vs. an oversight in the reference implementation.

Sources:
- https://github.com/obra/superpowers
- https://raw.githubusercontent.com/obra/superpowers/main/skills/using-superpowers/references/codex-tools.md
- https://raw.githubusercontent.com/obra/superpowers/main/docs/README.kimi.md
- https://github.com/obra/superpowers/blob/main/skills/writing-skills/SKILL.md
- https://learn.chatgpt.com/docs/build-skills (Codex `.agents/skills` corroboration)

---

## Appendix: panopticon skill's current shape (for context, not part of the research questions)

`/Volumes/Mini Vault/untitled_folder/projects/panopticon/skill/` currently has: `SKILL.md`; role-prompt templates in `agents/` (`lens-sweep.md`, `panel-review.md`, `scout.md`, `advisor.md`); a Python orchestration layer in `scripts/` (`dispatch.py`, `orchestrator.py`, `synthesize.py`, `citations.py`, `model_resolver.py`, `provenance.py`, `evidence.py`, `depth_planner.py`, `ingest_tools.py`, `run_tools.py`, `_run_adapter.py`, `html_report.py`, `run_fixture_tests.py`) plus `scripts/tools/*.py` wrappers around external SAST/dependency scanners (pip_audit, npm_audit, osv_scanner, bundler_audit, brakeman, spotbugs, roslyn_secguard, dependency_check, eslint_security, cargo_audit); reference data in `reference/` (CWE catalog, model profiles, report/scope-profile JSON schemas, security checklists). The presence of `dispatch.py`/`orchestrator.py` plus discrete role-prompt template files strongly suggests the intended design is exactly the "render a template into a raw prompt string, then hand it to whatever the host's subagent primitive is" shape discussed in §3/§7/§11 above.
