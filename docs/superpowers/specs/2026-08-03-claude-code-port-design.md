# Panopticon Round 2 — Claude Code Port & Host-Neutral Dispatch Design

**Date:** 2026-08-03
**Status:** Approved (pending spec review)
**Scope:** Round 2 of 3. Round 1 (epistemics core) shipped in 4.0.0. Round 3: hygiene + HTML.

## Context and locked decisions

Panopticon 4.0.0 is epistemically sound but host-coupled: SKILL.md says "for Kimi
Code" and dispatches via `AgentSwarm`; `agents/*.md` use Kimi agent frontmatter;
`_detect_host` checks a wrong env var for Claude (`CLAUDE_CODE`; real sessions set
`CLAUDECODE`) and defaults to kimi; `model-profiles.yml`'s claude entries name
models Claude's Agent tool does not accept.

Decisions locked during brainstorming:

1. **Distribution:** portable skill (clone/symlink install) on every host — no
   plugin packaging. Therefore reviewers are dispatched as **rendered prompts**,
   not registered custom agents.
2. **Uniform mechanism:** Kimi moves to rendered-prompt dispatch too (confirmed
   possible: AgentSwarm accepts `prompt_template` + `items` without a registered
   agent name). One flow, one SKILL.md description of it.
3. **Codex:** design for it (host-neutral contract, documented degraded mode);
   build and test nothing Codex-specific this round.
4. **Claude model policy:** scout=`haiku`, lens_sweep=`haiku`,
   panel_review=`sonnet`, advisor=`opus`; overridable via existing
   `PANOPTICON_MODEL_*` env vars and CLI flags.
5. **Approach:** deterministic renderer in `dispatch.py` (Approach A) — plan
   entries carry fully rendered prompts; host mechanics reduce to one-liners in
   SKILL.md. No LLM-mediated template rendering; no host-adapter class layer.

## Research inputs (2026-08-03)

Background research (full report with citations:
`scratchpad/host-portability-research.md`, archived alongside this spec as
`2026-08-03-host-portability-research.md`) established:

- **Kimi Code** (current product; distinct from the legacy `kimi-cli`):
  AgentSwarm dispatches raw prompts via `prompt_template`+`items`;
  `subagent_type` selects a tool/model *profile* (default `coder`). **No
  per-dispatch tool restrictions**; model override is experimental-flag-gated.
  Skills load from `~/.kimi-code/skills/` (and `~/.agents/skills/`). The session
  env vars we sniff (`KIMI_SESSION_ID`, `KIMI_CODE_VERSION`) are undocumented.
- **Codex CLI**: reads only `name` + `description` from skill frontmatter; skills
  live under `.agents/skills` tiers. In-session subagent dispatch is not a
  documented stable API; the defensible modes are sequential in-session execution
  or external `codex exec` subprocessing. Sandbox: network off by default,
  `.git`/`.agents` read-only, headless runs hard-fail on approval prompts.
- **Cross-host pattern** (mature example: obra/superpowers): host-agnostic
  vocabulary in the skill body plus a small per-host mapping — exactly the
  "Host dispatch" section this design adds.

Design consequences adopted from research:

- **Explicit host beats sniffing.** The orchestrating agent knows what host it
  is; SKILL.md instructs it to pass `--host claude|kimi|generic` to
  `dispatch.py`. `_detect_host` remains as best-effort fallback only
  (fixed to check `CLAUDECODE`/`CLAUDE_CODE_*`; Kimi vars kept, harmless if
  absent; unknown → `generic`).
- **Tool policy is advisory-by-prompt on BOTH main hosts** under raw-prompt
  dispatch (Claude general-purpose agents take no tool restrictions; Kimi
  raw-prompt dispatch has no per-dispatch restrictions either). The spec states
  this plainly; it strengthens round 3's case for flipping Bash off in the
  scout/panel templates.
- **The trigger-only description is load-bearing on Codex** — `description` is
  all Codex reads.

## Section 1: Host-neutral role templates

`agents/*.md` keep filenames and bodies; frontmatter becomes host-neutral data:

```yaml
---
name: scout
description: Profiles files and selects depth/lenses for a review group
tool_policy:
  allowed: [Read, Grep, Glob, Bash]
  forbidden: [Edit, Write, Agent]
---
```

- Kimi-dialect fields (`model_preference`, `disallowedTools`) are removed; model
  choice already lives in `model-profiles.yml` keyed by role.
- The renderer converts `tool_policy` into an injected prompt line on every host
  ("Your only tools are …; you must not use …"). Native enforcement applies only
  where a host offers it (currently: neither main host, under raw-prompt
  dispatch) — advisory status stated in SKILL.md.
- Current tool values are preserved verbatim this round; changing them (e.g.
  removing Bash from scout/panel-review) is round 3 — now a one-line data edit.
- Templates affected: `scout.md`, `panel-review.md`, `lens-sweep.md`,
  `advisor.md` (+ `prompts/panel-template.md` retired when — verified during
  implementation — nothing in the skill surface or tests references it after
  the renderer lands; otherwise it stays and the spec's plan notes why).

## Section 2: Renderer in `dispatch.py`

`build_plan` entries gain a `prompt` field: template loaded from
`agents/<role>.md`, frontmatter stripped, placeholders filled from the plan
entry, tool-policy line injected. Placeholder inventory: `{panel}`, `{group}`,
`{file_list}`, `{security_mode}`, `{depth}`, `{lenses}`, `{lens}`, `{out_file}`
(role templates) and `{claim_json}` (advisor template, filled per queue entry).
Replacement uses the brace-safe two-step token pattern (values may contain
braces). `{lenses}` renders as a bulleted list of non-spawned lens names.

**Advisor rendering** (the last LLM-mediated render) becomes deterministic:
`python3 scripts/dispatch.py --render-advisor .panopticon/verify-queue.json
--out .panopticon/advisor-prompts/` writes one rendered prompt per queue entry
(`{queue_id}.md`, claim JSON embedded). The orchestrator dispatches each file's
contents and writes the returned verdict to
`.panopticon/verdicts/{queue_id}.json`, exactly as in 4.0.0.

**Fail-fast exception to tolerant-by-design:** tolerance is for external inputs
(findings, verdicts, catalogs). Templates are shipped assets — a missing
template, an unfilled placeholder, or an unknown placeholder in a template
aborts at plan/render time with a message naming the template and placeholder.

## Section 3: Host detection and model resolution

- `--host` passed explicitly by the orchestrating agent is authoritative
  (SKILL.md instructs this). `_detect_host` fallback order: Kimi env vars →
  `kimi`; `CLAUDECODE` or any `CLAUDE_CODE_*` → `claude`; otherwise `generic`.
  The silent default-to-kimi is removed.
- `generic` host resolves every role to `{"model": null}` = inherit the
  session's model — the safe default for unknown hosts (including Codex).
- `model-profiles.yml` claude block: scout `haiku`, lens_sweep `haiku`,
  panel_review `sonnet`, advisor `opus` (names the Agent tool accepts).
  `_hardcoded_fallback` becomes host-aware: kimi keeps current values; claude
  mirrors the policy above; anything else `{"model": null}`.
- Override precedence unchanged: CLI flags > `PANOPTICON_MODEL_<ROLE>` env >
  host profile > fallback.

## Section 4: SKILL.md rewrite

- **Frontmatter `description` becomes trigger-only and host-neutral**: "Use when
  reviewing code, pull requests, branches, security posture, test quality,
  architecture, or database surfaces in a codebase." No workflow summary, no
  host name. `whenToUse` (Kimi) keeps the same text; other Kimi-dialect fields
  remain (Claude/Codex ignore unknown fields; Codex reads only
  name/description).
- **Fan-out step**: "run dispatch with `--host <your host>`; for each entry in
  `dispatch-plan.json`, dispatch `entry.prompt` with `entry.model` via your
  host's agent mechanism."
- **New "Host dispatch" section** (the per-host mapping layer):
  - *Claude Code*: Agent tool, general-purpose, parallel; pass `entry.model`
    (`haiku`/`sonnet`/`opus`); omit model when null.
  - *Kimi Code*: AgentSwarm with `prompt_template`/`items` raw-prompt dispatch;
    select an appropriate profile via `subagent_type`; model overrides only
    under the experimental flag.
  - *Other hosts (e.g. Codex)*: run entries sequentially in-session with the
    same prompts; expect no parallelism; tool policy is prompt-advisory.
- **Verify step**: replace "render the finding JSON into the agent prompt" with
  `--render-advisor` + dispatch the produced prompt files; orchestrator writes
  verdicts (advisors stay read-only).
- Remove remaining "for Kimi Code" phrasing repo-wide in the skill surface;
  README's supported-hosts section updated to match reality (Claude Code
  first-class, Kimi supported, others degraded-sequential).

## Section 5: Testing

- **Golden render tests**: fixed plan entry per role → exact rendered prompt
  (`tests/goldens/*.txt`); asserts frontmatter stripped, placeholders filled,
  tool-policy line present.
- **Fail-fast tests**: unfilled placeholder names the placeholder + template;
  missing template errors at plan time; unknown placeholder in a template
  errors.
- **Advisor render tests**: queue fixture → `advisor-prompts/{queue_id}.md`
  files, claim JSON embedded brace-safely.
- **Host detection matrix**: `CLAUDECODE` / `CLAUDE_CODE_*` / Kimi vars / none →
  `claude`/`claude`/`kimi`/`generic`; explicit `--host` wins over environment.
- **Model resolution**: claude tiers per policy; `generic` → null models;
  fallback host-awareness.
- **`test_skill_md` extended**: pins the Host dispatch section heading, the
  `--gate-unverified`/`--max-verify` flags (round-1 deferred item), and the
  trigger-only description shape (no "Kimi" in the description field).
- **Acceptance (manual, final plan task)**: live dogfood on the primary host —
  `/panopticon --changes` (or `-d skill/scripts`) run from a Claude Code session
  against this repo, exercising discovery → scout → fan-out → verify →
  synthesize end-to-end with the rendered-prompt flow.

## Section 6: Scope boundary

**In:** template migration (4 agent files + panel-template retirement check),
renderer + `--render-advisor`, host detection + model resolution fixes, SKILL.md
rewrite (description SDO, Host dispatch section, verify step), README honesty
pass, all tests above, research report archived into `docs/`.

**Out (round 3):** flipping tool_policy values (Bash removal for scout/
panel-review), HTML evidence-axis rendering, round-1 deferred minors.

**Out entirely:** plugin packaging; Codex-specific code or testing; reliance on
undocumented host APIs (Codex `spawn_agent`, Kimi session env vars as anything
more than fallback hints).
