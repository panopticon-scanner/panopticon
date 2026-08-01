# Panopticon

A portable, standards-cited code-review skill for AI coding agents.

Panopticon profiles a target codebase, groups files by risk, dispatches specialized reviewer agents in parallel, and synthesizes a validated `CodeReviewReport` with grades, citations, and CI gating. It can also ground findings in real static-analysis tools via an optional Docker scanner image.

## Supported agent platforms

The skill uses the open `SKILL.md` format and works with:

- [Kimi Code CLI](https://code.kimi.com/)
- [Claude Code](https://docs.anthropic.com/en/docs/claude-code/overview)
- Other agents that read `SKILL.md` files

## Installation

### Kimi Code CLI

Clone or symlink the repository into your Kimi skills directory:

```bash
# default Kimi skills location (see `kimi config get skills_dir`)
mkdir -p ~/.kimi/skills
ln -s "$(pwd)" ~/.kimi/skills/panopticon
```

Then invoke it with:

```bash
kimi /panopticon
```

### Claude Code

Clone or symlink into Claude's skills directory:

```bash
ln -s "$(pwd)/panopticon" ~/.claude/skills/panopticon
```

Then invoke it with `/panopticon` or describe a review task.

## Quick start

From inside a repo you want to review:

```bash
kimi /panopticon --mode repo
```

Or point it at a file, directory, PR, or changeset:

```bash
kimi /panopticon --mode file --target src/auth.py
kimi /panopticon --mode changes
kimi /panopticon --mode pr --pr 217
```

## Repository layout

| Path | Purpose |
|------|---------|
| `SKILL.md` | Skill entry point and orchestration spec |
| `scripts/` | Runnable Python modules (orchestrator, synthesizer, dispatch, tools) |
| `agents/` | Kimi Code custom agent definitions (`scout`, `panel-review`, `lens-sweep`, `advisor`) |
| `reference/` | Schemas, CWE catalog, security checklists, example group profiles |
| `tests/` | pytest suite |
| `Dockerfile` | `panopticon-tools` scanner image |
| `docs/` | Design docs and implementation plans |

## Development

See [DEVELOPMENT.md](DEVELOPMENT.md) for architecture decisions, version history, and current backlog.

### Running tests

```bash
python -m pytest tests/ -q
python -m ruff check scripts/ tests/
```

### Running static-analysis tools locally

Build the scanner image once:

```bash
docker build -t panopticon-tools .
```

Then run:

```bash
python scripts/run_tools.py --target . --deps
```

## License

[MIT](LICENSE)
