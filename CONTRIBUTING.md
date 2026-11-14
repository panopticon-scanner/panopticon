# Contributing to Panopticon

Thanks for your interest in improving Panopticon.

## How to contribute

1. Open an issue to discuss large changes before writing code.
2. Fork the repository and create a feature branch.
3. Make focused, minimal changes that match the existing style.
4. Add or update tests for changed behavior.
5. Run the full test suite and lint locally:
   ```bash
   python3 -m pytest tests/ -q
   python3 -m ruff check skill/scripts/ tests/
   ```
6. Open a pull request against `main`.

## Releases and backports

`main` is the unstable development line. Starting with v5.5.0, the supported
stable line is `release/5.5`; v5.5.x patch releases are tagged from that branch.
The project owner creates release branches and tags releases.

Fixes always merge to `main` first. Apply `backport:5.5` when a fix affects the
supported 5.5 line, and track the backport in the `5.5.x` milestone. After the
main PR merges:

1. branch from `release/5.5` and run
   `git cherry-pick -x -m 1 <PR merge commit>`;
2. keep one fix per backport PR;
3. expect main's `## Unreleased` CHANGELOG hunk to conflict, and move that
   user-visible entry under a `## 5.5.x` heading on the release branch;
4. open the PR with base `release/5.5` and merge only after its required checks
   pass.

Feature work never lands on `release/5.5`, and fixes are never developed there
first.

Dependabot security updates also enter through the default branch. [GitHub does
not send security-update PRs to a non-default
`target-branch`](https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference#target-branch);
such entries configure version updates only. Handle a relevant Dependabot
security fix on `main`, apply `backport:5.5`, and use the same cherry-pick flow
above rather than adding a misleading release-branch update entry.

### Stable tools image

The stable branch uses the exact tools-image digest it was cut with. The
branch-owned source of truth is `skill/scripts/tools_image.py`'s
`DEFAULT_IMAGE`; the release-cut commit replaces main's local development name
with `ghcr.io/panopticon-scanner/panopticon-tools@sha256:<manifest-digest>`.
The target repository's `panopticon.yml` cannot override this value: reviewed
code must not select the executable scanner image used to inspect itself.

A 5.5.x backport that does not need scanner changes reuses the existing digest.
If a patch needs a rebuilt image, build and publish it from `release/5.5`
without moving main's `:latest` or `:weekly` tags, then update `DEFAULT_IMAGE`
to the new manifest digest in that backport PR. The readiness failure prints
the exact pinned `docker pull` command; it never falls back to a moving main tag
or an unpinned local build on a release branch.

## Code style

- Python 3.11+.
- Ruff is used for linting; configuration is in `pyproject.toml`.
- Keep the skill cross-platform: isolate host-specific code inside dedicated host adapters (e.g. `model_resolver.py`, `dispatch.py`, `emit_host_agents`).
- Agent prompts and skill docs should not name competitors.

## Testing

- All changes should include tests.
- The CI matrix runs on Python 3.11, 3.12, 3.13, and 3.14.
- Security scans run on every PR; intentionally vulnerable fixtures live in `tests/fixtures/` and are excluded from the gate.

## Reporting security issues

See [SECURITY.md](SECURITY.md): open a private security advisory (Security tab, "Report a vulnerability") rather than a public issue for vulnerabilities in the tool itself.

## Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
