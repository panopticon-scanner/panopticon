# Panopticon

A portable, standards-cited code-review skill for AI coding agents.

Panopticon profiles a target codebase, groups files by risk, dispatches specialized reviewer agents in parallel, and synthesizes a validated `CodeReviewReport` with grades, citations, and CI gating. It can also ground findings in real static-analysis tools via an optional Docker scanner image.

## Supported agent platforms

The skill uses the open `SKILL.md` format and works with:

- Native Agent-tool host — first-class: parallel fan-out via the Agent tool
- `kimi` CLI — supported: AgentSwarm raw-prompt dispatch
- `codex` CLI — supported: isolated parallel fan-out via `codex exec`
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
python3 skill/scripts/dispatch.py --emit-host-agents kimi --agents-dir <your kimi agents dir>
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
`dispatch.py --host codex` run through the bundled `codex_runner.py` adapter
automatically. Note the scope: `--host codex` is a **plan-building/agent-emission**
flag on `dispatch.py`. The 5.x driver itself takes `driver run --host
claude|generic|gemini` — a Codex run drives the `generic` host path (see
`docs/PANOPTICON.md`, "Modes").

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

Or point it at a file, directory, PR, or changeset (see `docs/PANOPTICON.md` → Modes
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
| `skill/SKILL.md` | Skill entry point (frontmatter + quick reference) |
| `docs/PANOPTICON.md` | Full user guide, driver run-loop spec, and schema contracts |
| `skill/scripts/` | Runnable Python modules (driver, discovery, synthesizer, dispatch, tools) |
| `skill/agents/` | Custom agent definitions (`scout`, `domain-panel`, `domain-advisor`, `advisor`) |
| `skill/reference/` | Schemas, CWE catalog, security checklists, example group profiles |
| `scripts/` | Project maintenance, issue filing, and triage CLI scripts |
| `tests/` | pytest suite |
| `Dockerfile` | `panopticon-tools` scanner image |
| `Dockerfile.fixtures` | Test fixture image definition |

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
python skill/scripts/run_tools.py --deps
```

## License

[MIT](LICENSE)
