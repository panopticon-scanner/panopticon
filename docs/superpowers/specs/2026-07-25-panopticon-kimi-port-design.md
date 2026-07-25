# Panopticon Kimi Code Port — Design Spec

## Objective

Port the mature Claude Code skill `panopticon` to Kimi Code as a personal skill at `~/.kimi-code/skills/panopticon/`, replacing the current Claude-native review workflow. The port will be as Kimi-native as possible, retain the proven discovery → scout → fan-out → synthesis pipeline, expand the lens model, add architecture and database review panels, and introduce an optional red-team security panel.

## Background

The current skill lives in `~/.claude/skills/panopticon/` and is at version 2.3.0. It is a discovery → scout → fan-out → synthesis layer over Claude Code's native review fleet (`code-reviewer`, `security-reviewer`, `test-reviewer`). Key deterministic components:

- `scripts/orchestrator.py` — target resolution and cohesive ≤15-file grouping.
- `scripts/synthesize.py` — merging, deduplication, reinforcement, grading, gating, citations.
- `scripts/citations.py` — CWE/OWASP/SSVC/EPSS validation and enrichment.
- `scripts/run_tools.py` + `scripts/ingest_tools.py` — optional Docker-based SAST/SCA tool layer.
- `prompts/scout.md` + `prompts/lenses.md` — profiling and review-emphasis catalog.
- `reference/` — schemas, CWE catalog, security checklists.

## Target Location

```
~/.kimi-code/skills/panopticon/
```

The skill will be a personal Kimi skill. It does **not** modify managed Superpowers skills; it competes with/replaces the user's prior custom review workflow.

## Design Decisions

### 1. Skill Structure

- **Concise `SKILL.md`**: rewritten in Kimi skill style (frontmatter, trigger-focused description, overview, quick reference, workflow with cross-skill references).
- **Supporting files preserved**: `scripts/`, `prompts/`, `reference/`, `Dockerfile`, `tests/`, `DEVELOPMENT.md`.
- **No inline heavy reference**: lenses, checklists, schemas, and panel prompts stay in supporting files.

Rationale: Kimi skills are discovered via the `description` field and loaded into context. A tight main doc keeps token costs down while the deterministic scripts and reference material remain accessible.

### 2. Kimi-Native Orchestration

The skill drives the pipeline using Kimi tools rather than a single monolithic script:

- **`AskUserQuestion`** — interactive mode selection when the target is ambiguous.
- **`TodoList`** — tracks discovery, scout, tool scan, panels, lens sub-reviews, synthesis.
- **`AgentSwarm`** — parallel panel fan-out.
- **`Agent` (`coder`)** — panel reviewers and lens specialists.
- **`Bash`** — runs deterministic Python scripts (`orchestrator.py`, `run_tools.py`, `synthesize.py`).

Cross-skill references:

- `superpowers:writing-plans` — before large repo/PR reviews.
- `superpowers:subagent-driven-development` — for panel and lens dispatch.
- `superpowers:verification-before-completion` — before returning the final report.

### 3. Panels

Panels expand from three to five, plus a red-team override:

| Panel | Default Lenses | Trigger |
|-------|----------------|---------|
| `code` | `structure`, `correctness`, `style` | Always on code files. |
| `test` | `coverage`, `test_quality`, `test_design` | When tests or testable logic are present. |
| `security` | `known_vulns`, `injection`, `novel` | When risky surfaces are present. |
| `architecture` | `architecture` | When repo-scope files are present (`.github/`, Docker/k8s, root structure). |
| `database` | `database` | When scout detects `db_sql` surfaces. |
| `redteam` | `redteam` | Optional; runs instead of baseline `security` when `--security redteam` is set. |

### 4. Flexible Lens Model

Lenses are pluggable focus units. The scout selects which lenses apply to a group and which deserve dedicated sub-agents.

**Catalog (`prompts/lenses.md`):**

- Code: `structure`, `correctness`, `style`
- Test: `coverage`, `test_quality`, `test_design`
- Security: `known_vulns`, `injection`, `novel`
- Architecture: `architecture`
- Database: `database`
- Red-team: `redteam`

**Lens dispatch rule:**

- Spawn dedicated lens reviewers when the group has ≥5 files **or** scout risk is `high`.
- Otherwise, lenses are rendered as emphasis blocks inside the panel reviewer's prompt.

Adding a new lens requires only:

1. Entry in `prompts/lenses.md`.
2. Mapping in `prompts/scout.md`.
3. Optional default panel assignment in `ScopeProfile` schema.

### 5. Red-Team Security Mode

The Kimi port relaxes Claude's safety constraints to allow aggressive adversarial hunting.

- Flag: `--security {standard,redteam}` (default `standard`).
- In `redteam` mode, the `security` panel is replaced by the `redteam` panel.
- The `redteam` lens explicitly hunts exploit chains, trust-boundary bypasses, privilege escalation, shadow-IT/config abuse, and multi-step attacks.
- Findings are tagged `panel: redteam` and gated like security findings, but surfaced distinctly in the markdown summary.

Boundaries remain absolute:

- No writes to GitHub, the repo, or external systems.
- No claiming an unperformed action.
- No materializing discovered secret values into findings.

### 6. Subagent Tool Autonomy

Reviewer subagents are `coder` agents that use `Read`, `Grep`, and `Bash` themselves rather than receiving all file contents upfront. This keeps context small and lets reviewers drill into cross-references. Panel reviewers receive file lists, scout profiles, lens assignments, and tool findings; they decide what to read.

### 7. Tool Container Integration

The Docker-based tool layer (`Dockerfile`, `run_tools.py`, `ingest_tools.py`) is preserved unchanged. The skill auto-detects the `panopticon-tools` image and runs it when present. Tool findings are handed to the relevant panel reviewer (especially `security`, `database`, and `architecture`).

### 8. Synthesis & Output

`scripts/synthesize.py` is updated for the new panels and red-team mode:

- Panel enum includes `architecture`, `database`, `redteam`.
- Each finding records `panel` and `lens`.
- Cross-panel corroboration extends to architecture ↔ security and database ↔ security.
- Red-team findings are gated like security findings but summarized separately.

Output remains:

- Terminal markdown summary.
- JSON `CodeReviewReport` at `--out`.

### 9. Versioning

Bump the skill version from **2.3.0** to **3.0.0**. This is a major version because:

- The report schema gains new panels and a `security_mode` field.
- The runtime target changes from Claude Code to Kimi Code.
- The red-team mode changes the security review contract.

Update both `SKILL.md` frontmatter `metadata.version` and `synthesize.build_report`'s `meta.version`.

### 10. Schema Updates

`reference/report-schema.json`:

- `meta.security_mode`: `"standard" | "redteam"`
- Panel enum extended with `architecture`, `database`, `redteam`.

`reference/scope-profile-schema.json`:

- `lenses[]`: objects with `name` and `spawn` boolean.
- `panels[]`: panels scheduled for the group.

### 11. Testing Strategy

1. Run the existing pytest suite after script changes.
2. Invoke the ported skill against itself (`~/.kimi-code/skills/panopticon/`) in red-team mode.
3. Iterate on findings and re-run.
4. Run baseline pressure scenarios per `superpowers:writing-skills`: one WITHOUT the new `SKILL.md` to establish failure modes, then WITH the skill to verify compliance.

## File Layout

```
~/.kimi-code/skills/panopticon/
├── SKILL.md                          # Concise Kimi-native orchestration spec
├── DEVELOPMENT.md                    # Durable design record
├── Dockerfile                        # panopticon-tools image
├── scripts/
│   ├── orchestrator.py               # + architecture/database detection
│   ├── synthesize.py                 # + new panels, redteam mode, lens metadata
│   ├── citations.py                  # unchanged
│   ├── run_tools.py                  # unchanged
│   └── ingest_tools.py               # unchanged
├── prompts/
│   ├── scout.md                      # + architecture/database/redteam surfaces
│   ├── lenses.md                     # Flexible lens catalog
│   └── panel-template.md             # Kimi panel dispatch template
├── reference/
│   ├── report-schema.json            # + architecture/database/redteam, security_mode
│   ├── scope-profile-schema.json     # + lenses, panels
│   ├── security-checklists.md        # unchanged
│   ├── cwe-catalog.json              # unchanged
│   └── code-review-groups.example.yml # unchanged
└── tests/                            # Supporting pytest suite
```

## Migration Path

1. Copy current project to `~/.kimi-code/skills/panopticon/`.
2. Rewrite `SKILL.md` for Kimi.
3. Update `prompts/scout.md` and `prompts/lenses.md`.
4. Add `prompts/panel-template.md`.
5. Update schemas.
6. Patch `orchestrator.py` and `synthesize.py` for new panels/red-team mode.
7. Run tests and self-review.

## Open Questions

None at design time; all major choices were confirmed in the brainstorming session.

## Approval

Design approved by user on 2026-07-25.
