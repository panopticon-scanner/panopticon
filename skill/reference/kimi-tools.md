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

# 3. plan (one per group -- give each its own --out file, e.g.
#    dispatch-plan-<group>.json, so synthesize's dispatch-plan*.json glob
#    sees every group's plan at steps 5/7 below, not just the last one).
#    Refuses to write the plan (exit 1) if panel_review/lens_sweep would be
#    unenforced -- register the shells above first, or add
#    --allow-unenforced to accept prompt-advisory tool policy explicitly.
python3 skill/scripts/dispatch.py .panopticon/scout-<group>.json --host kimi --out .panopticon/dispatch-plan-<group>.json

# 4. fan out (or generate a Kimi swarm manifest) -- carries the same gate:
#    refuses (exit 1, no manifest written) on an unenforced panel_review/
#    lens_sweep entry in the plan unless --allow-unenforced is passed here
#    too.
python3 skill/scripts/dispatch.py --emit-kimi-swarm .panopticon/dispatch-plan-<group>.json --out .panopticon/kimi-swarm-<group>.json

# 5. synthesis
python3 skill/scripts/synthesize.py --emit-verify-queue .panopticon/findings-*.json

# 6. verify (advisors)
python3 skill/scripts/dispatch.py --render-advisor .panopticon/verify-queue.json --out .panopticon/advisor-prompts
# dispatch each .panopticon/advisor-prompts/*.md as panopticon-advisor

# 7. final report
python3 skill/scripts/synthesize.py --verdicts-dir .panopticon/verdicts .panopticon/findings-*.json
```

### What `--emit-kimi-swarm` produces

```json
{
  "batches": [
    {
      "tool": "AgentSwarm",
      "subagent_type": "panopticon-panel-review",
      "model": "secondary",
      "description": "panel_review security for group g-security (batch)",
      "prompt_template": "{{item}}",
      "items": ["<rendered prompt 1>", "<rendered prompt 2>"],
      "routing": [
        {"out_file": ".panopticon/findings-g-security-security-panel_review.json",
         "role": "panel_review", "panel": "security", "lens": null, "group": "g-security"},
        {"out_file": ".panopticon/findings-g-code-code-panel_review.json",
         "role": "panel_review", "panel": "code", "lens": null, "group": "g-code"}
      ]
    }
  ]
}
```

`routing` is index-aligned with `items` (a single object for an `Agent`
batch). Write each returned result to its own `out_file` — a batch groups by
`(subagent_type, model)`, so it can span panels and groups.

## Model selection

Registered agent files set `model_preference`:

| Role | Preference |
|------|------------|
| `scout` | `primary` |
| `lens_sweep` | `primary` |
| `panel_review` | `secondary` |
| `advisor` | `secondary` |

Only `primary` and `secondary` are valid per-dispatch `model` values — a
concrete alias (`k3`, `kimi-for-coding`) belongs in an agent file's
`model_preference`, not in the dispatch call. `model_resolver` normalizes a
known alias back to its tier and warns if an override is neither.

To override per dispatch, enable the secondary-model experiment (or the master
experimental flag):

```bash
KIMI_CODE_EXPERIMENTAL_SECONDARY_MODEL=1 kimi /panopticon --mode repo
# or
KIMI_CODE_EXPERIMENTAL_FLAG=1 kimi /panopticon --mode repo
```

## Troubleshooting

- **"custom agents not found"** — re-run `--emit-host-agents kimi` and start a
  fresh Kimi session.
- **"model override ignored"** — per-dispatch `model` requires
  `KIMI_CODE_EXPERIMENTAL_SECONDARY_MODEL=1` or `KIMI_CODE_EXPERIMENTAL_FLAG=1`.
- **"findings written to the wrong file"** — write each batch result to its
  `routing[i].out_file`, not by assuming item order. A batch can merge entries
  from different panels and groups.
- **Host inferred from environment** — pass `--host kimi` explicitly to
  `dispatch.py` for stable behavior.
