# Panopticon — Kimi Support Hardening Design

**Date:** 2026-08-05
**Status:** Approved (pending spec review)
**Scope:** Update and complete Kimi Code CLI support without degrading Claude Code support.

## Context

Panopticon's runtime target has historically been Claude Code, with Kimi Code CLI supported as a secondary host. The skill already emits Kimi enforcement shells, resolves Kimi models, and documents Kimi dispatch in `SKILL.md`. However, several gaps make Kimi support feel incomplete or out of date:

1. **No default Kimi agents directory.** `--emit-host-agents kimi` requires `--out DIR`; Claude defaults to `~/.claude/agents`.
2. **Emitted Kimi agent files are minimal.** They omit `whenToUse`, `model_preference`, and `override` fields that Kimi's agent format supports.
3. **Model identifiers are not Kimi-dispatch-native.** Kimi's `Agent`/`AgentSwarm` tool `model` parameter only accepts `primary` or `secondary`; concrete aliases like `kimi-for-coding` are not valid per-dispatch values.
4. **No bridge from dispatch plan to Kimi tool calls.** Users must manually translate `.panopticon/dispatch-plan.json` entries into `Agent`/`AgentSwarm` invocations.
5. **Host detection relies on undocumented env vars.** `_detect_host()` uses `KIMI_CODE_VERSION` / `KIMI_SESSION_ID`, which Kimi Code CLI docs do not guarantee.
6. **No concise Kimi quick-reference doc.** Host-portability research exists, but there is no single user-facing `reference/kimi-tools.md`.

This spec hardens Kimi support while keeping every Claude behavior intact.

## Constraints

- Do not degrade Claude Code support.
- Preserve all existing Claude tests and default paths.
- Keep the host-neutral template files (`skill/agents/*.md`) as the single source of truth; registration files remain generated artifacts.
- Avoid a full host abstraction refactor — stay scoped to Kimi polish and concrete helpers.

## Section 1: Default Kimi agents directory

**File:** `skill/scripts/dispatch.py`

Add a Kimi default agents directory constant:

```python
KIMI_AGENTS_DIR = os.path.join(os.path.expanduser("~"), ".kimi-code", "agents")
```

Update `_registration_dir()` so that when `host == "kimi"` and no `--agents-dir` is supplied, the function returns `KIMI_AGENTS_DIR`.

Update `main()` so that `--emit-host-agents kimi` without `--out` defaults to `KIMI_AGENTS_DIR`.

**Claude guard:** the `host == "claude"` branch continues to use `~/.claude/agents`; no change.

## Section 2: Richer Kimi enforcement-shell files

**File:** `skill/scripts/dispatch.py::emit_host_agents()`

Extend the Kimi branch of agent-file generation to include:

- `whenToUse` — copied from the template frontmatter `description`, guiding the main agent's delegation choice.
- `model_preference` — `primary` for cheap roles (`scout`, `lens_sweep`), `secondary` for expensive roles (`panel_review`, `advisor`). This is the Kimi-native way to influence model selection.
- `override: false` — explicit, safe default.

Example generated file (`panopticon-scout.md`):

```markdown
---
name: panopticon-scout
description: Profiles files and selects depth/lenses for a review group
whenToUse: Profiles files and selects depth/lenses for a review group
override: false
model_preference: primary
tools:
  - Read
  - Grep
  - Glob
disallowedTools:
  - Bash
  - Edit
  - Write
  - Agent
---

You are panopticon's `scout` reviewer (a registered enforcement shell)...
```

**Claude guard:** Claude emission keeps its current frontmatter (`name`, `description`, `tools`, `model`) and charter body; no new fields are added.

## Section 3: Kimi-native model identifiers

**Files:** `skill/scripts/model_resolver.py`, `skill/reference/model-profiles.yml`

Kimi's `Agent`/`AgentSwarm` `model` parameter accepts only `primary` or `secondary`. Concrete model aliases belong in the agent file's `model_preference`, not in the dispatch call.

- Change `reference/model-profiles.yml` so the `kimi` host entries use `model: primary` / `model: secondary` for dispatch-facing values.
- Add an optional `alias` key to the profile entries for human-readable naming (e.g., `alias: k3`).
- Update `model_resolver.py` so that for `host == "kimi"`, `resolve_model()` returns `{"model": "primary" | "secondary", "max_context_size": ..., "max_output_size": ..., "alias": "..."}`. The `alias` field is optional and is preserved for logging/documentation; it is not passed as the dispatch `model`.
- Role mapping: `scout` and `lens_sweep` → `primary`; `panel_review` and `advisor` → `secondary`.

**Claude guard:** Claude host resolution continues to return concrete model names (`haiku`, `sonnet`, `opus`) in `model.model`.

## Section 4: Dispatch plan → Kimi invocation helper

**File:** `skill/scripts/dispatch.py`

Add a new subcommand `--emit-kimi-swarm` that reads a `.panopticon/dispatch-plan.json` and writes a JSON file describing ready-to-use Kimi `Agent`/`AgentSwarm` batches.

For each plan entry:

- `subagent_type` is `panopticon-<role>` if `entry.enforced` is true; otherwise fall back to a built-in profile: `panel_review` → `coder`, `lens_sweep`/`scout` → `explore`, `advisor` → `plan`.
- `prompt` is the entry's rendered `prompt`.
- `model` is `entry.model.model` (`primary` / `secondary`).
- `description` is derived from `role`, `panel`, `lens`, and `group`.
- `routing` carries `out_file` (plus `role`/`panel`/`lens`/`group`) per item,
  index-aligned with `items`. Without it a batch's results cannot be mapped
  back to the files the orchestrator must write, since a batch groups by
  `(subagent_type, model)` and can therefore span panels and groups.
- `enforced` is re-verified against the live registration dir at emit time;
  the plan's flag is a snapshot and registration may have been removed since.

The helper groups entries by `(subagent_type, model)` and emits one `AgentSwarm` batch per group, plus singleton `Agent` entries for groups with only one item (to satisfy AgentSwarm's `min 2 items` rule).

Output shape:

```json
{
  "batches": [
    {
      "tool": "AgentSwarm",
      "subagent_type": "panopticon-panel-review",
      "model": "secondary",
      "description": "panel_review security for group g-security (batch)",
      "prompt_template": "{{item}}",
      "items": [...],
      "routing": [
        {"out_file": "...", "role": "panel_review", "panel": "security",
         "lens": null, "group": "g-security"}
      ]
    },
    ...
  ]
}
```

This gives Kimi users a concrete bridge from `dispatch-plan.json` to actual tool calls without requiring them to hand-roll `AgentSwarm` templates.

**Claude guard:** this is an additional emitter only; the dispatch plan JSON format itself does not change.

## Section 5: Reliable host detection

**File:** `skill/scripts/dispatch.py::_detect_host()`

Keep the existing best-effort env-var sniffing, but emit a stderr warning when it fires:

```
WARNING: host detected from environment; pass --host explicitly for stable behavior
```

Document in `SKILL.md` and `reference/kimi-tools.md` that `--host kimi` is the recommended explicit path.

**Claude guard:** no behavior change for Claude; the warning applies uniformly.

## Section 6: SKILL.md Kimi section rewrite

**File:** `skill/SKILL.md`

Expand the current one-paragraph Kimi dispatch note into a complete subsection:

1. **Installation / registration**
   ```bash
   python3 skill/scripts/dispatch.py --emit-host-agents kimi
   # or explicit:
   python3 skill/scripts/dispatch.py --emit-host-agents kimi --out ~/.kimi-code/agents
   ```
   Note that a fresh Kimi session is required after registration before the shells are dispatchable.

2. **Fan-out**
   - For each plan entry, dispatch via the `Agent` tool with `subagent_type: panopticon-<role>` and `prompt: entry.prompt`.
   - Alternatively, batch same-role entries using `AgentSwarm`; use the `--emit-kimi-swarm` helper to generate the batches.

3. **Model selection**
   - Registered agent files carry `model_preference` (`primary` for scout/lens, `secondary` for panel/advisor).
   - Per-dispatch `model` override requires the secondary-model experiment: `KIMI_CODE_EXPERIMENTAL_SECONDARY_MODEL=1` or `KIMI_CODE_EXPERIMENTAL_FLAG=1`.

4. **Verification phase**
   - Advisors rendered with `--render-advisor` are dispatched the same way as panels/lenses.

**Claude guard:** the Claude Code section remains unchanged.

## Section 7: Kimi quick-reference doc

**New file:** `skill/reference/kimi-tools.md`

A concise user-facing reference covering:

- Skill install path: symlink `skill/` to `~/.kimi-code/skills/panopticon/`.
- Agent registration command.
- Typical invocation: `kimi /panopticon --mode repo`.
- Manual pipeline overview (discovery → scout → plan → fan-out → synthesis).
- Example `AgentSwarm` batch generated by `--emit-kimi-swarm`.
- Model override note.
- Troubleshooting:
  - "custom agents not found" → register shells and start a fresh session.
  - "model override ignored" → enable the secondary-model experiment.

## Section 8: Testing

**Files:** `tests/test_dispatch.py`, `tests/test_model_resolver.py`

Tests as shipped (this list is the traceability index — keep it matching the
suite, not the other way round):

`tests/test_dispatch.py`
1. `TestKimiDefaultAgentsDir` + `TestEmitHostAgents::test_cli_kimi_defaults_to_kimi_agents_dir` — §1
2. `TestEmitHostAgents::test_kimi_agent_file_includes_model_preference_and_when_to_use` — §2
3. `test_emit_kimi_swarm_groups_entries_by_subagent_type` — §4
4. `test_emit_kimi_swarm_carries_out_file_routing_per_item` — §4 routing
5. `test_emit_kimi_swarm_maps_unenforced_scout_and_advisor` — §4 fallback profiles
6. `test_emit_kimi_swarm_downgrades_a_stale_enforced_entry` — §4 registration re-check
7. `test_emit_kimi_swarm_rejects_a_malformed_plan` — §4 input validation
8. `test_cli_emit_kimi_swarm_writes_manifest_and_requires_out` — §4 CLI path
9. `TestDetectHost::test_warns_when_inferred_from_{kimi,claude}_env` — §5

`tests/test_model_resolver.py`
10. `test_kimi_roles_resolve_to_primary_secondary` — §3
11. `test_kimi_override_is_normalized_to_a_dispatch_tier` — §3 invariant enforcement
12. `test_registration_model_ignores_ambient_overrides` — §2 override-free emission
13. `test_kimi_override_precedence_still_applies_within_the_contract` — §3
14. `test_claude_defaults_preserved` (regression guard) — asserts the Kimi
    normalization never runs for Claude, under both override paths

**Claude guard:** `test_cli_override` / `test_env_override` / `test_cli_beats_env`
were retargeted from `kimi` to `claude`. They assert override *precedence*,
which is host-agnostic; they previously demonstrated arbitrary strings passing
through for Kimi, which §3 now forbids. Precedence within the Kimi contract is
covered by test 13.

## Section 9: Migration / rollout

1. Implement sections 1–5 in `skill/scripts/dispatch.py` and `skill/scripts/model_resolver.py`.
2. Update `skill/reference/model-profiles.yml`.
3. Rewrite the Kimi subsection of `skill/SKILL.md`.
4. Create `skill/reference/kimi-tools.md`.
5. Add tests and run the full pytest suite plus ruff.
6. Run `--emit-host-agents kimi` locally and verify the generated files load in Kimi Code CLI.

## Open questions

None at design time; all choices were confirmed in the brainstorming session.

## Approval

Design approved by user on 2026-08-05.
