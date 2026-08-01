# Panopticon Multi-Model Reviewer Dispatch — Design

> **Goal:** Add a modular, cross-platform dispatch layer so each panopticon panel can run a main reviewer plus up to three lightweight lens-sweep agents, with an independent advisor verifying uncited claims.

## Context

Panopticon currently groups files, dispatches one panel reviewer per panel, and optionally spawns lens specialists. The weakest gap relative to other review products is **claim reliability**: agentic findings can be uncited or unproven, and there is no cheap, mechanical way to independently verify them. This design introduces three reviewer roles — `lens_sweep`, `panel_review`, and `advisor` — mapped to different model tiers per host. The result is more modular scan depths: a style-only PR gets a shallow sweep, while a financial/auth/PII change gets deeper mechanical coverage plus independent advisor review.

## Constraints

- **Cross-platform**: the same skill must work on Kimi Code and Claude without host-specific code paths outside the model resolver.
- **Modular depth**: scan depth is a function of which lenses are spawned, not a rewrite of the pipeline.
- **No infinite recursion**: the advisor runs at most once per flagged claim.
- **Minimal integration changes**: existing grouping, tool scanning, and SARIF ingestion are left untouched.
- **Read-only reviews**: agents parse source only; no repo or GitHub mutations.
- **Native Kimi features**: use Kimi Code custom agent files and `model_preference` so roles bind to the right model tier automatically.

## Roles

| Role | Purpose | Typical model (Kimi) | Typical model (Claude) |
|---|---|---|---|
| `scout` | Profile files and choose depth/lenses | K2.7 Coding | Claude Haiku |
| `lens_sweep` | Narrow mechanical check of a single lens | K2.7 Coding | Claude Haiku |
| `panel_review` | Holistic panel review across all assigned lenses | K2.7 Coding | Claude Sonnet |
| `advisor` | Independent verification of tenuous claims | K3 | Claude Opus |

### `scout`

- Reads the assigned files and emits a `ScopeProfile`.
- Detects surfaces, sets group `depth`, ranks lenses, and assigns `priority` and `depth_threshold` to each lens.
- Uses a large context window because it ingests the whole group at once.

### `lens_sweep`

- Receives one lens, one panel, and the same file list as the panel.
- Emits only candidate findings for that lens.
- Each finding must include a citation or rule reference.
- Output is raw JSON: `{"findings": [...]}`.
- Tool allowlist is narrow: `Read`, `Grep`, `Glob` only.

### `panel_review`

- Receives the full panel scope and all lenses not spawned as mechanical agents.
- Performs holistic review, synthesis, and remediation advice.
- May produce narrative and higher-level findings.

### `advisor`

- Receives one flagged claim plus supporting code context.
- Returns a verdict: `CONFIRMED`, `REJECTED`, or `NEEDS_MORE_INFO`.
- Provides independent reasoning and citations.

## Depth Levels

The scout assigns a `depth` to each group based on detected surfaces and change risk.

| Depth | Trigger | Lens agents spawned | Advisor |
|---|---|---|---|
| `shallow` | Style/docs-only changes; no risky surfaces | 0–1 (style only) | Off |
| `standard` | Normal code changes; some risky surfaces | Up to 2 (priority lenses) | On for uncited HIGH/CRITICAL |
| `deep` | auth/crypto/money_pii/external_api present, or `--security redteam` | Up to 3 (all priority lenses) | On for any uncited finding |

Lenses are ranked by the scout. Lenses that do not get their own `lens_sweep` agent remain as instructions in the `panel_review` prompt.

## Model Resolver

A host-agnostic model profile maps roles to concrete model identifiers, context windows, and output budgets.

**`reference/model-profiles.yml`**:

```yaml
hosts:
  kimi:
    scout:
      model: kimi-for-coding
      max_context_size: 131072
      max_output_size: 16384
    lens_sweep:
      model: kimi-for-coding
      max_context_size: 131072
      max_output_size: 8192
    panel_review:
      model: kimi-for-coding
      max_context_size: 131072
      max_output_size: 16384
    advisor:
      model: k3
      max_context_size: 524288
      max_output_size: 32768
  claude:
    scout:
      model: claude-haiku
      max_context_size: 200000
      max_output_size: 4096
    lens_sweep:
      model: claude-haiku
      max_context_size: 200000
      max_output_size: 4096
    panel_review:
      model: claude-sonnet
      max_context_size: 200000
      max_output_size: 8192
    advisor:
      model: claude-opus
      max_context_size: 200000
      max_output_size: 16384

roles:
  scout:
    description: Profiles files and selects depth/lenses
  lens_sweep:
    description: Cheap, narrow mechanical lens sweep
  panel_review:
    description: Main reviewer for a panel
  advisor:
    description: Independent claim verification
```

**Resolution order** (highest precedence first):

1. CLI flag `--model-<role>`
2. Environment variable `PANOPTICON_MODEL_<ROLE>`
3. Host default in `model-profiles.yml`
4. Hardcoded fallback

The host is detected from environment hints or via `--host kimi|claude|openrouter`.

### Secondary model binding (Kimi Code)

On Kimi Code, enabling the experimental `secondary_model` config causes agents with `model_preference: secondary` to bind to the configured secondary model automatically. This lets `lens_sweep` agents run on a cheap model while `panel_review` and `advisor` stay on the primary model, without the skill manually selecting models per spawn.

## Advisor Trigger Flow

After the main reviewer and lens agents finish, `synthesize.py` tags findings that need advisor review:

- `confidence` below `LIKELY` and no `references`
- HIGH/CRITICAL finding with fewer than 2 citations
- Two reviewers contradict each other at the same locus
- Optional: auth/crypto/money_pii findings in `deep` mode

**Advisor input**:

```json
{
  "claim": { "title", "description", "severity", "panel", "lens" },
  "location": { "file", "line_start", "line_end" },
  "existing_references": [...],
  "code_context": "...",
  "question": "Is this claim independently supported by the code?"
}
```

**Advisor output**:

```json
{
  "verdict": "CONFIRMED|REJECTED|NEEDS_MORE_INFO",
  "confidence": "CERTAIN|LIKELY|POSSIBLE",
  "reasoning": "...",
  "references": [...]
}
```

The synthesizer updates the original finding:

- `CONFIRMED` → keep or upgrade confidence, append advisor references
- `REJECTED` → downgrade to INFO or drop
- `NEEDS_MORE_INFO` → flag for human review

Advisor recursion is capped at one pass.

## Pipeline Integration

1. **Scout** (`agents/scout.md`) reads files and emits a `ScopeProfile` with `depth`, ranked lenses, and file list.
2. **New `scripts/dispatch.py`** module:
   - Reads the `ScopeProfile`
   - Calls `DepthPlanner` to decide which lenses become mechanical agents
   - Calls `ModelResolver` to pick models
   - Emits a `DispatchPlan`: list of agent invocations with role, agent name, model config, panel, lens, files
3. **Fan-out** runs the mixed agent swarm in parallel using Kimi Code `AgentSwarm`:
   - Dispatches `panel_review`, `lens_sweep`, and `advisor` agents by name
   - Each agent writes its findings file to `.panopticon/findings-{group}-{panel}-{role}-{lens}.json`
4. **Synthesizer** merges findings, tags tenuous claims, and conditionally spawns advisors.

## Custom Agent Files

Three role-specific Kimi Code agent files replace the single panel template for role-aware invocations:

- `agents/lens-sweep.md`
- `agents/panel-review.md`
- `agents/advisor.md`

Each file has YAML frontmatter declaring:

- `name`: agent identifier used in `AgentSwarm`
- `description`: shown to the main agent when selecting a sub-agent
- `model_preference`: `primary` for panel/advisor, `secondary` for lens sweep
- `tools`: allowlist appropriate to the role
- `disallowedTools`: prevents destructive operations

Example `agents/lens-sweep.md`:

```markdown
---
name: lens-sweep
description: Cheap mechanical lens sweep for panopticon; emits narrow, cited findings only
model_preference: secondary
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

You are the {lens} lens sweep for panopticon panel {panel} in group {group}.
Files: {file_list}
Security mode: {security_mode}
Depth: {depth}

Emit findings as raw JSON `{"findings": [...]}` to `{out_file}` and return ONLY the path + count.
Each finding must cite a rule, pattern, or line of code.
```

The existing `prompts/panel-template.md` is preserved as a fallback for hosts or callers that do not yet use role-based dispatch.

## Schema Additions

### `reference/scope-profile-schema.json`

- `depth`: `"shallow" | "standard" | "deep"` at the group level
- `files`: list of files reviewed by the scout
- `lens.priority`: integer rank within the panel
- `lens.depth_threshold`: minimum depth at which this lens spawns its own agent

### `reference/report-schema.json`

- `finding.source_role`: `"lens_sweep" | "panel_review" | "advisor"`
- `finding.advisor_verdict`: optional `"CONFIRMED" | "REJECTED" | "NEEDS_MORE_INFO"`
- `finding.depth`: scan depth that produced the finding

## Error Handling

- If a `lens_sweep` agent fails or returns invalid JSON, log the error and have the main reviewer cover that lens.
- If the `advisor` fails, leave the original finding marked `uncited` rather than dropping it.
- If `ModelResolver` cannot detect the host, default to `standard` depth and emit a warning.

## Testing

- Unit tests for `DepthPlanner` and `ModelResolver`.
- Fixture test: style-only change → `shallow` depth, no advisor.
- Fixture test: auth/PII change → `deep` depth, advisor invoked.
- Mock-agent test: advisor upgrades/downgrades findings correctly.
- Cross-host test: same config resolves to different models on Kimi vs Claude.

## Open Questions / Future Work

- **Phase 5**: formatted HTML reports with grades, heatmaps, and issue lists.
- **Phase 6**: comparison mode for base-vs-head or version-vs-version deltas.
- **Phase 7**: remediation risk classification using the breaking-vs-non-breaking framing.
- **Citation expansion**: anchor more findings with CWE, CVE, OWASP, and EVSS sources.
- **Additional static-analysis tools**: extend beyond Phase 1 with AST-based and domain-specific scanners.

## Success Criteria

- A style-only PR runs `shallow` depth and spawns at most one lens agent.
- An auth/PII/financial PR runs `deep` depth and spawns up to three lens agents plus advisor review.
- The same configuration resolves to host-appropriate models on Kimi and Claude.
- Advisor verdicts are visible in the final `CodeReviewReport`.
- All new modules are covered by tests.
