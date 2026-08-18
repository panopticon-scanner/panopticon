# Contributing to Panopticon

Thanks for your interest in improving Panopticon.

## How to contribute

1. Open an issue to discuss large changes before writing code.
2. Fork the repository and create a feature branch.
3. Make focused, minimal changes that match the existing style.
4. Add or update tests for changed behavior.
5. Run the full test suite and lint locally:
   ```bash
   python -m pytest tests/ -q
   python -m ruff check skill/scripts/ tests/
   ```
6. Open a pull request against `main`.

## Code style

- Python 3.11+.
- Ruff is used for linting; configuration is in `pyproject.toml`.
- Keep the skill cross-platform: isolate host-specific code inside dedicated host adapters (e.g. `model_resolver.py`, `dispatch.py`, `emit_host_agents`).
- Agent prompts and skill docs should not name competitors.

## Testing

- All changes should include tests.
- The CI matrix runs on Python 3.11, 3.12, and 3.13.
- Security scans run on every PR; intentionally vulnerable fixtures live in `tests/fixtures/` and are excluded from the gate.

## Reporting security issues

Please open a private security advisory rather than a public issue for vulnerabilities in the tool itself.
