# Panopticon

A portable, standards-cited code-review skill for AI coding agents.

Panopticon profiles a target codebase, groups files by risk, dispatches specialized reviewer agents in parallel, and synthesizes a validated `CodeReviewReport` with grades, citations, and CI gating. It can also ground findings in real static-analysis tools via an optional Docker scanner image.

## Supported agent platforms

The skill uses the open `SKILL.md` format and works with:

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code/overview) — first-class: parallel fan-out via the Agent tool
- [Kimi Code CLI](https://code.kimi.com/) — supported: AgentSwarm raw-prompt dispatch
- [OpenAI Codex CLI](https://developers.openai.com/codex/cli) — supported: isolated parallel fan-out via `codex exec`
- Other agents that read `SKILL.md` files — degraded: sequential dispatch, same prompts

## Installation

### Kimi Code CLI

Clone or symlink the repository into your Kimi skills directory:

```bash
# default Kimi skills location (see `kimi config get skills_dir`)
mkdir -p ~/.kimi/skills
ln -s "$(pwd)/skill" ~/.kimi/skills/panopticon
```

Then register the enforcement shells into your Kimi agents directory (one-time; re-run after template changes):

```bash
python3 skill/scripts/dispatch.py --emit-host-agents kimi --out <your kimi agents dir>
```

Then invoke it with:

```bash
kimi /panopticon
```

### Claude Code

Clone or symlink into Claude's skills directory:

```bash
ln -s "$(pwd)/skill" ~/.claude/skills/panopticon
```

Then invoke it with `/panopticon` or describe a review task, and register the enforcement shells (one-time; re-run after template changes):

```bash
python3 skill/scripts/dispatch.py --emit-host-agents claude
```

Note: Claude Code loads registered agents at session start — after first registration (or re-registration), start a fresh session before the enforcement shells are dispatchable.

### OpenAI Codex CLI

Expose the skill through Codex's shared skills directory and register its
read-only role profiles:

```bash
mkdir -p ~/.agents/skills
ln -s "$(pwd)/skill" ~/.agents/skills/panopticon
python3 skill/scripts/dispatch.py --emit-host-agents codex
```

Invoke it with `$panopticon` or select it from `/skills`. Plans built with
`--host codex` run through the bundled `codex_runner.py` adapter automatically.

### Python Package / CLI (Development & Direct Use)

Install in editable mode for local development or direct CLI execution:

```bash
pip install -e .
```


## Quick start

From inside a repo you want to review:

```bash
kimi /panopticon
```

Or point it at a file, directory, PR, or changeset (see `skill/SKILL.md` → Modes
for the full flag list):

```bash
kimi /panopticon -f src/auth.py        # a single file + its tests and neighbors
kimi /panopticon -d src/payments       # a directory
kimi /panopticon -c                    # review this branch vs its base
kimi /panopticon -c --base release-2   # review vs an explicit base
kimi /panopticon --pr 217              # review PR 217 in an isolated worktree
```

## Repository layout

| Path | Purpose |
|------|---------|
| `skill/` | The installable skill surface — symlink THIS directory into your agent's skills dir |
| `skill/SKILL.md` | Skill entry point and driver run-loop spec |
| `skill/scripts/` | Runnable Python modules (driver, discovery, synthesizer, dispatch, tools) |
| `skill/agents/` | Custom agent definitions (`scout`, `panel-review`, `lens-sweep`, `advisor`) |
| `skill/reference/` | Schemas, CWE catalog, security checklists, example group profiles |
| `scripts/` | Project maintenance, issue filing, and triage CLI scripts |
| `tests/` | pytest suite |
| `Dockerfile` | `panopticon-tools` scanner image |
| `Dockerfile.fixtures` | Test fixture image definition |
| `docs/` | Design docs and implementation plans |

## Development

See [DEVELOPMENT.md](DEVELOPMENT.md) for architecture decisions, version history, and current backlog.

### Running tests

```bash
python -m pytest tests/ -q
python -m ruff check skill/scripts/ tests/
```

### Running static-analysis tools locally

Build the scanner image once:

```bash
docker build -t panopticon-tools .
```

Then run:

```bash
python skill/scripts/run_tools.py --target . --deps
```

## License

[MIT](LICENSE)
