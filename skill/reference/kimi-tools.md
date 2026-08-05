# Kimi Code CLI Quick Reference for Panopticon

## Install the skill

Symlink the installable skill surface into Kimi's skills directory:

```bash
ln -s "$(pwd)/skill" ~/.kimi-code/skills/panopticon
```

## Register the enforcement shells

Kimi supports per-agent tool restrictions only through registered custom-agent
files, not per-dispatch parameters. Generate them once:

```bash
python3 skill/scripts/dispatch.py --emit-host-agents kimi
```

This writes `panopticon-scout.md`, `panopticon-panel-review.md`,
`panopticon-lens-sweep.md`, and `panopticon-advisor.md` to
`~/.kimi-code/agents/`. Start a fresh Kimi session after registration so the
new agent types are discoverable.

## Run a review

Interactive:

```bash
kimi /panopticon --mode repo
```

Manual pipeline:

```bash
# 1. discovery
python3 skill/scripts/orchestrator.py --repo-scan --repo . --out .panopticon/groups.json

# 2. scout each group (dispatched by orchestrating agent)
#    see SKILL.md "Host dispatch" for subagent instructions

# 3. plan
python3 skill/scripts/dispatch.py .panopticon/scout-<group>.json --host kimi --out .panopticon/dispatch-plan.json

# 4. fan out (or generate a Kimi swarm manifest)
python3 skill/scripts/dispatch.py --emit-kimi-swarm .panopticon/dispatch-plan.json --out .panopticon/kimi-swarm.json

# 5. synthesis
python3 skill/scripts/synthesize.py --emit-verify-queue .panopticon/findings-*.json

# 6. verify (advisors)
python3 skill/scripts/dispatch.py --render-advisor .panopticon/verify-queue.json --out .panopticon/advisor-prompts
# dispatch each .panopticon/advisor-prompts/*.md as panopticon-advisor

# 7. final report
python3 skill/scripts/synthesize.py --verdicts-dir .panopticon/verdicts .panopticon/findings-*.json
```

## Model selection

Registered agent files set `model_preference`:

| Role | Preference |
|------|------------|
| `scout` | `primary` |
| `lens_sweep` | `primary` |
| `panel_review` | `secondary` |
| `advisor` | `secondary` |

To override per dispatch, enable the secondary-model experiment:

```bash
KIMI_CODE_EXPERIMENTAL_SECONDARY_MODEL=1 kimi /panopticon --mode repo
```

## Troubleshooting

- **"custom agents not found"** — re-run `--emit-host-agents kimi` and start a
  fresh Kimi session.
- **"model override ignored"** — per-dispatch `model` requires the
  secondary-model experiment flag.
- **Host inferred from environment** — pass `--host kimi` explicitly to
  `dispatch.py` for stable behavior.
