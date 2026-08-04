# Panopticon Round 3a — Tool-Policy Enforcement Design

**Date:** 2026-08-03
**Status:** Approved (pending spec review)
**Scope:** The first round-3 slice. Remaining ledger items (`--render-scout`,
version single-sourcing, HTML evidence axis, sys.path convention) are separate
smaller rounds. BursarBuddy corpus work is EXTERNAL (separate agent, standalone
repo + private key repo) — this spec only defines panopticon's side of that
relationship.

## Context

SEC-101 (advisor-confirmed HIGH from the round-2 dogfood): reviewer tool policy
is prompt-advisory text. On Claude Code, reviewers run as general-purpose
subagents holding Bash/Edit/Write/Agent while reading hostile repository
content; prompt injection in a reviewed repo can invoke tools the policy
forbids. Kimi raw-prompt dispatch has the same gap (no per-dispatch tool
restrictions — round-2 research). The risk becomes routine once calibration
runs target corpora that deliberately plant injection payloads.

Round 2 locked "portable skill, rendered prompts, no plugin." The resolution
that preserves it: **generate** host-native registered agents from the existing
host-neutral templates — registration is a local materialization step, not a
packaging format.

Decisions locked during brainstorming:

1. **Full stack**: least-privilege role contracts + generated registration +
   post-fan-out clean-tree check.
2. **Fallback posture: proceed and record.** Unregistered hosts run
   advisory-mode exactly as today; the plan and the audit artifact say so
   structurally. No hard registration requirement (hostile-corpus runs get
   SHOULD-level guidance, not a wall).

## Section 1: Least-privilege role contracts

All four roles converge on one contract: **read-only tools (Read, Grep, Glob),
return JSON, the orchestrator writes every artifact.**

- `skill/agents/panel-review.md`: task text switches from "emit findings to
  `{out_file}`" to the return-JSON form lens-sweep uses ("Return ONLY a raw
  JSON object `{"findings": [...]}` as your final message — you cannot write
  files; the orchestrator writes your findings to `{out_file}`.");
  `tool_policy` becomes `allowed: [Read, Grep, Glob]`,
  `forbidden: [Bash, Edit, Write, Agent]`.
- `skill/agents/scout.md`: same tool_policy change (drops Bash); its body
  already returns the ScopeProfile JSON.
- `lens-sweep.md` and `advisor.md` are already on this contract — unchanged.
- SKILL.md steps 3/6 unify: every reviewer returns JSON; the orchestrator
  persists to the entry's `out_file` (scout: `.panopticon/scout-{group}.json`).
  The panel-writes-via-Bash special case is deleted.
- Goldens regenerate (template bodies change).

Least privilege is the prerequisite that makes registration meaningful: roles
that need no dangerous tool can be registered with none.

## Section 2: Generated host-native registration

New dispatch mode:

```
python3 scripts/dispatch.py --emit-host-agents claude [--out DIR]   # default ~/.claude/agents/
python3 scripts/dispatch.py --emit-host-agents kimi  --out DIR      # Kimi agents dir
```

Deterministically generated from the host-neutral templates — single source of
truth; no plugin; the portable-skill decision stands.

**The registered agent file is an enforcement shell, not the work order.**

- Frontmatter (claude dialect): `name: panopticon-<role>`, `description` from
  the template, `tools:` from `tool_policy.allowed` (comma list), `model:` from
  the claude policy (scout/lens `haiku`, panel `sonnet`, advisor `opus`).
- Frontmatter (kimi dialect): `name`, `description`, `tools`,
  `disallowedTools` per the current kimi-code agent format.
- Body: a short role charter — "You are panopticon's `<role>` reviewer. Follow
  the dispatched task exactly. Your tool restrictions are host-enforced." The
  fully rendered prompt still arrives as the task message at dispatch time,
  exactly as today; registration changes what the agent MAY do, never what it
  is asked to do. (This sidesteps placeholders entirely.)
- Idempotent (re-run refreshes byte-identically for unchanged templates);
  fail-fast on template errors; prints each file written.
- Install docs: one extra command per host in README next to the symlink step.

## Section 3: Enforcement signal → plan → audit artifact

- `build_plan` gains registration detection, **per role**: entry N is enforced
  iff `panopticon-<role>.md` exists in the host's agents dir (`--agents-dir`
  override for tests/CI). A partial registration therefore yields a `mixed`
  run honestly rather than all-or-nothing. Each plan entry gains
  `"enforced": true|false`; when true, `"agent"` is the registered name
  (`panopticon-<role>`).
- SKILL.md Host dispatch becomes conditional: enforced → dispatch
  `subagent_type: entry.agent` with `entry.prompt`; else general-purpose with
  the advisory prompt (today's behavior).
- Pass-2 synthesize reads `.panopticon/dispatch-plan*.json` when present and
  derives `meta.tool_policy_mode`: `enforced` (all entries), `advisory`
  (none), `mixed` (some). No plan files → `advisory`. The audit artifact states
  the conditions it ran under; SKILL.md instructs a one-line warning when not
  fully enforced.
- Report schema: optional `meta.tool_policy_mode` enum. Version bump 4.2.0
  (SKILL.md metadata, build_report meta.version, write_verify_queue payload —
  all three documented locations).

## Section 4: Post-fan-out clean-tree check (detection layer)

SKILL.md Validate step gains: after fan-out and verify, run
`git status --porcelain` on the target; any modification outside
`.panopticon/` means a reviewer had side effects despite policy — treat the
run as compromised: discard findings files, report the violation, re-run.
Prose-level by design: the check is about orchestrator trust in its own run;
synthesize stays subprocess-free; a compromised run should never reach
synthesis. With enforcement registered this should be impossible — which is
why checking it is cheap insurance.

## Section 5: External calibration corpora (e.g. BursarBuddy)

BursarBuddy is developed by a separate agent as a standalone public repo with
a private answer-key repo; panopticon takes no dependency on it in this round.
Panopticon's side of the relationship, fully contained in this spec:

- SKILL.md Notes gain SHOULD-level guidance: hostile-content review (redteam
  mode, deliberately vulnerable corpora, repos with planted injection
  payloads) should run with enforcement registered.
- `meta.tool_policy_mode` gives ANY external harness a structural way to
  verify the posture of a measured run — an advisory-mode score and an
  enforced-mode score are distinguishable artifacts.

## Section 6: Testing

- **Emitter goldens** per host: exact frontmatter (tools line, model, name) and
  charter body for all four roles into a temp dir; second run byte-identical;
  broken template fails fast naming the template.
- **Registration detection**: `enforced` true/false per agents-dir state;
  `--agents-dir` override respected.
- **`tool_policy_mode` derivation**: enforced/advisory/mixed/no-plan cases.
- **Contract migration**: panel-review template + golden updates; SKILL.md test
  pins the uniform return-JSON contract sentence and the clean-tree
  instruction; existing `test_agent_templates` tool-policy expectations updated
  (scout/panel lose Bash).
- **Live acceptance (controller-executed)**: emit + register on this machine;
  mini fan-out dispatching by `subagent_type`; prove enforcement — a
  registered read-only reviewer demonstrably cannot execute Bash; report
  `meta.tool_policy_mode: enforced`.

## Scope boundary

**In:** Sections 1–6; version 4.2.0; README/SKILL.md/DEVELOPMENT.md updates.
**Out:** remaining round-3 ledger items (`--render-scout`, version
single-sourcing, HTML evidence axis, sys.path convention); all BursarBuddy
repo work (external); plugin packaging (permanently, per round 2).
