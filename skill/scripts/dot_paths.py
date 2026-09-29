"""The dot-path policy: which root dot-paths are reviewable surface.

Both of `discovery.discover_repo_files`'s methods -- the `git ls-files`
listing's filter and the `os.walk` fallback -- ask `allowed()` about every
dot-path, so a non-git target cannot review less of a tree than a git one.
They used to disagree: `_filter_reviewable` tested each ancestor DIRECTORY
while the walk tested the whole FILE path, so every file directly under
`.github/` was reviewable surface on a git target and invisible on a non-git
one (#1771, ARC-1940929242) -- against two docstrings that said both methods
shared one policy.

The allowlist itself is #1784 / ARC-124841687. The policy was
`(".github/workflows",)` plus a blanket skip of every other root dot-path, so
73 of the 74 dot-leading globs the shipped catalogs claim -- and the
deterministic SEC floor's own `.circleci` / `.env` / `.npmrc` /
`.pre-commit-config.yaml` hints -- named files no group could ever receive. A
file discovery never returns is never `Ungrouped` either, so nothing reported
the gap: #1508 (top-level `.github/*.yml`) and #1838 (the CI and secret-file
floor) both rest on claims that could not fire. Owner ruling 2026-09-27: WIDEN
to exactly what the shipped catalogs and the floor name and no further --
pruning those claims was rejected, and .git / .venv / cache / scratch noise
stays pruned.

The policy lives in its own module because `discovery.py` is at its size
ratchet (`tests/test_flat_module_ceiling.py`), and the ratchet's answer to a
module that needs more room is a split, never a raised pin. All three
directions are pinned against the shipped files by
`tests/test_discovery_catalog.py`: every dot-leading catalog glob and every
dot-leading floor hint reaches a file BOTH methods keep, every entry BELOW is
named by one of them (so a widened entry reddens, which is the drift that ends
in "allow every dot-path"), and the noise classes are dropped by both methods.

Stdlib plus `repo_config`, which owns the target config's own dot spelling --
that name is never spelled here (`tests/test_repo_config_literals.py`).
"""
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scripts import repo_config
else:
    try:
        from scripts import repo_config
    except ModuleNotFoundError:
        import repo_config

# Root dot-DIRECTORIES: everything beneath one is surface. DIRS and FILES stay
# apart so the target's committed config in its dot spelling is reviewable
# while this project's own `.panopticon/` run-artifact directory stays pruned.
DIRS = frozenset(
    ".buildkite .ci .circleci .config .devcontainer .github .husky .idea .mvn"
    " .tx .vscode .woodpecker".split())
# Root dot-FILES, one row per name the catalogs or the floor spell out.
FILES = frozenset(
    ".air.toml .bandit .coderabbit.yaml .codespellrc .dockerignore"
    " .editorconfig .eslintignore .eslintrc .eslintrc.cjs .eslintrc.js"
    " .eslintrc.json .eslintrc.mjs .eslintrc.yaml .eslintrc.yml"
    " .flake8 .git-blame-ignore-revs .gitattributes .gitignore .gitlab-ci.yml"
    " .gitmodules .gitpod.yml .goreleaser.yml .htaccess .ignore .mailmap"
    " .markdownlint.yaml .netrc .npmrc .nvmrc .oxfmtrc.json .oxlintrc.json"
    " .pgpass .php-cs-fixer.dist.php .pre-commit-config.yaml .python-version"
    " .releaserc .rubocop.yml .ruby-version .rustfmt.toml .shellcheckrc"
    " .spectral.yaml .tool-versions .typos.toml .yamllint.yaml".split()
) | {name for name in repo_config.CONFIG_NAMES if name.startswith(".")}
# Root dot-file STEMS, for the families a catalog claims in several spellings
# (`.env*`, `.codecov.yaml|.yml`, `.travis.yml|.yaml`). A stem is WIDER than
# those names: it admits the whole family, including spellings no catalog names
# yet (`.golangci.toml`, `.prettierrc.yaml`). That is deliberate -- each family
# here is hand-written tool CONFIG, which is reviewable surface whichever
# extension its owner picked, and a tool that adds one should not need a
# discovery release. `.eslint*` is the exception and stays as eight exact
# names in FILES: its family also contains `.eslintcache`, which is generated
# state, the `.mypy_cache` class the ruling keeps pruned.
FILE_STEMS = (".clang", ".codecov", ".drone", ".env", ".golangci",
              ".prettier", ".travis", ".yarnrc")


def allowed(rel, isdir=False):
    """True when the policy admits `rel` -- a file path, or a directory path
    when `isdir`.

    A ROOT dot-path must be named above: as a DIRECTORY when anything follows
    it, else as a FILE. Below the root only a dot-FILE is surface
    (`config/.env`, unchanged behaviour), because a nested dot-directory is
    tool state no shipped catalog claims.
    """
    parts = rel.split("/")
    head, rest = parts[0], parts[1:]
    if head.startswith("."):
        if not (head in DIRS if isdir or rest
                else head in FILES or head.startswith(FILE_STEMS)):
            return False
    return not any(seg.startswith(".") for seg in (rest if isdir else rest[:-1]))
