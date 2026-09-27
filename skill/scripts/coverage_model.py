"""Compute a group's effective panel set: floor forces ON, exclude forces OFF
(loudly), the scout widens the undeclared middle. Pure (no I/O, no state);
importing it pulls in `discovery` for the TST naming rule (#1770), which touches
`sys.path` as it always has. See spec §5.
"""

from typing import TYPE_CHECKING

import os

# #1770 ARC-3682668884: the TST floor's test-file signal is the UNION of
# discovery's naming rule and the local hints, so `discovery.TEST_PATTERNS` is a
# dependency of this module rather than a second, drifting derivation of "is
# this a test file". No module-level import runs the other way: `discovery`
# does not import this module, and the one edge back in its closure is lazy --
# `discovery._capability_aliases` imports `setup_proposal` (which imports this
# module) at CALL time, and it must stay lazy. This module, in turn, binds the
# `discovery` module object here and reads `discovery.is_test_file` only at
# call time, so neither order can see a half-initialised module. Same fallback
# shape as `discovery` uses for its own siblings -- this module is imported both as
# `scripts.coverage_model` (the driver's children, which get `skill/` on
# PYTHONPATH) and flat by `setup_flow` / `grouping_engine` / `setup_proposal`,
# and the flat mode has only `skill/scripts` on sys.path.
if TYPE_CHECKING:
    from scripts import discovery
else:
    try:
        from scripts import discovery
    except ModuleNotFoundError:
        import discovery

# #5.0-11: the universal-tier domains ride a GLOBAL floor — every group reviews
# code/database/test/architecture regardless of its committed vertical floor.
# capability_affinity.yml documents these as "matrix-level, NOT affinity rows",
# but nothing implemented that: setup writes only the affinity (vertical) floor,
# so without this the flagship review silently skipped COD/DAT/TST/ARC on every
# group. Still subject to a per-group exclude (a docs-only group may opt out).
GLOBAL_FLOOR = frozenset({"COD", "DAT", "TST", "ARC"})
# #1084: domains a committed config's `exclude` can never silence. SEC is
# non-excludable so a target can't commit `exclude: [SEC]` to exempt its own
# code from security review. Deliberately NOT added to GLOBAL_FLOOR (that would
# reintroduce the #5.0-19 surfaceless-group noise) -- SEC still runs only where
# the floor or scout put it, but once there it cannot be excluded away.
NON_EXCLUDABLE = frozenset({"SEC"})


# #5.0-19: the universal-tier floor is GATED per group on OBSERVABLE file
# signals rather than injected unconditionally. BursarBuddy calibration
# (2026-08-16): DAT/TST/ARC on surfaceless groups produced 59 of 97 noise
# findings and caught ZERO answer-key vulns, because a testless / db-free /
# single-module group has nothing for those panels to review. COD stays
# universal (code is always present). The gate keys ONLY on objective file
# signals -- scout-asserted ScopeProfile fields (surfaces / has_tests) are
# intentionally NOT consulted here (#1193). A scout that wants a domain it did
# not objectively surface still gets it via scout_added in effective_panels, so
# coverage can widen but never narrow below observable signals.
_DB_FILE_HINTS = ("schema.prisma", ".prisma", ".sql", "migration", "/models/",
                  "/model/", "schema", "entity", "entities", ".orm", "seed",
                  "repository", "database", "/db.")
# These are HALF of the TST signal; `_has_test_surface` unions them with
# discovery's naming rule. Do not add a naming convention here that belongs in
# `discovery.TEST_PATTERNS` -- the union already picks that one up everywhere.
_TEST_FILE_HINTS = (".test.", ".spec.", "_test.", "_spec.", "/__tests__/",
                    "/tests/", "/test/", ".feature", "conftest", "test_")

# #run8 SEC-G2A: objective file signals that force a deterministic SEC review.
# SEC is deliberately NOT in GLOBAL_FLOOR (a blanket SEC floor reintroduces the
# #5.0-19 surfaceless-group noise), but a group whose FILES carry a security
# surface must be security-reviewed even when neither the committed `panels:`
# nor the scout asked for it -- otherwise a mis-reporting scout, or an
# adversarial/forgetful root config that never lists SEC, silently exempts its
# own code from security review (the exact outcome NON_EXCLUDABLE was built to
# prevent, reached via an unguarded path). Like the global floor this keys ONLY
# on deterministic signals, never scout-asserted surfaces (#1193). Three
# categories: the supply-chain surface (SEC E1-E3: CI/CD, container,
# dependency/build manifests), the db/SQLi surface (reuses _DB_FILE_HINTS), and
# unambiguous auth/crypto/secrets filename markers.
_SEC_SUPPLY_CHAIN_HINTS = (
    ".github/workflows/", ".gitlab-ci", "jenkinsfile", ".circleci",
    "dockerfile", "docker-compose", ".dockerignore", "/helm/", "/k8s/",
    "requirements.txt", "package.json", "package-lock", "gemfile", "go.mod",
    "cargo.toml", "pom.xml", "build.gradle", "pyproject.toml", "poetry.lock",
    # #1838 SEC-71240568: the surface above is CI/container/manifest files,
    # but the supply chain also includes every BUILD tool and second-tier CI
    # system that executes code on its own -- a Makefile target, a setup.py,
    # a Terraform plan, a pre-commit hook, a project file MSBuild loads
    # (roslyn-secguard's own hostile-csproj fixture is why that class is
    # here), and a lockfile whose name is not already a superstring of a
    # manifest listed above. Table-driven, same style as the block above.
    # `/configure`, `/workspace` and `.mk` are deliberately broad markers:
    # the first two still catch a head-of-segment name (`workspace_list.go`,
    # `ConfigureProfile.tsx` -- killing those needs a basename-exact table,
    # outside this fix) even after anchoring to a directory boundary, and
    # `.mk` also reaches `.mkv`/`.mkd` media and doc files since a substring
    # extension check cannot end-anchor. A false positive costs one SEC cell
    # per group, same calibration as the block below.
    "makefile", ".mk", "/setup.py", "setup.cfg", "tox.ini", "noxfile.py", ".tf",
    ".pre-commit-config.yaml", ".travis.yml", "azure-pipelines.yml",
    "bitbucket-pipelines.yml", ".drone.yml", "appveyor.yml", ".buildkite/",
    ".github/actions/", ".csproj", ".sln", "directory.build.props",
    "nuget.config", "go.sum", "cargo.lock", "yarn.lock", "pnpm-lock",
    "composer.json", "composer.lock", "mix.exs", "build.sbt",
    "cmakelists.txt", "/configure", "rakefile", "gruntfile.js", "gulpfile.js",
    "webpack.config", "vite.config", "build.bazel", "/workspace",
    "pnpm-workspace", "module.bazel", "justfile", "taskfile", "podfile", "pubspec.yaml",
    ".gemspec", ".devcontainer/", "/ansible/", "serverless.yml",
    "template.yaml",
    # #1838 SEC-71240568 review finding 2: each of the above CI systems has
    # two equally-valid YAML spellings, and the first pass pinned only one --
    # so the other spelling was a live miss for its own tool. Both spellings,
    # as explicit rows (`.pre-commit-config.yaml` is intentionally excluded:
    # that tool recognizes only the `.yaml` spelling, not `.yml`).
    ".travis.yaml", "azure-pipelines.yaml", "bitbucket-pipelines.yaml",
    ".drone.yaml", "appveyor.yaml", "serverless.yaml", "template.yml",
)
_SEC_CODE_HINTS = (
    "auth", "login", "session", "token", "oauth", "jwt",
    "crypto", "cipher", "encrypt", "secret", "password", "credential",
)
# #run10 SEC-G2A: the code hints above key on security-relevant *names*, but a
# group can carry the highest-value secret surface of all -- the secret-bearing
# FILES themselves -- without any of those words appearing. A `.env`, a private
# key, an `.npmrc` with a token: none match `auth`/`secret`/`password`, so a
# root config that never lists SEC exempted exactly the files most worth
# reviewing. These are extension/exact-name markers, deliberately unambiguous:
# a false positive costs one SEC cell, a false negative costs the review.
_SEC_SECRET_FILE_HINTS = (
    ".env", ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".asc",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "authorized_keys", "known_hosts",
    ".npmrc", ".netrc", ".pgpass", "htpasswd", ".htaccess",
    "secrets.", "credentials.", "keyfile", "vault",
)
_SEC_FILE_HINTS = (_SEC_SUPPLY_CHAIN_HINTS + _SEC_CODE_HINTS
                   + _SEC_SECRET_FILE_HINTS + _DB_FILE_HINTS)


# #1489: extensions with no code surface for COD to review. Deliberately a
# DENYLIST, so the gate fails OPEN: an unrecognized extension counts as source
# and keeps COD. Only a group that is ENTIRELY recognized assets loses it --
# stricter than the >=95%-non-source shape that was measured, because dropping a
# floor domain wrongly is worse than spending one cell.
#
# .svg is listed: it is reviewable text, but not by COD. The one real finding
# these groups produced was ARC's (a sprite set drifted out of parity with the
# readme logos) and ARC keeps its own >=2-directories gate, so that path is
# untouched.
_ASSET_EXTENSIONS = frozenset((
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp", ".tiff",
    ".tif", ".avif", ".heic",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp3", ".mp4", ".wav", ".ogg", ".oga", ".webm", ".mov", ".avi", ".m4a",
    ".zip", ".gz", ".bz2", ".xz", ".tar", ".7z", ".rar",
    ".pdf", ".bin", ".exe", ".dll", ".so", ".dylib", ".class", ".jar", ".wasm",
    ".psd", ".ai", ".sketch", ".fig",
))


def has_code_surface(files):
    """True when at least one file could carry a COD defect (#1489).

    Fails open: only files whose extension is a KNOWN asset type are discounted,
    so anything unfamiliar still counts as reviewable source.
    """
    for f in files or ():
        if os.path.splitext(str(f))[1].lower() not in _ASSET_EXTENSIONS:
            return True
    return False


def _any_hint(files, hints):
    for f in files or ():
        # Treat a repository-relative root like every nested directory boundary.
        # Slash-delimited hints such as /tests/ still require both path separators.
        low = "/" + str(f).lower().lstrip("/")
        if any(h in low for h in hints):
            return True
    return False


def _has_test_surface(files):
    """The TST floor's signal: `discovery.is_test_file` OR `_TEST_FILE_HINTS`.

    Both halves are load-bearing (#1770 ARC-3682668884). Only discovery's
    `TEST_PATTERNS` know the SUFFIX conventions -- `AppTest.java`,
    `AccountTests.cs`, `AuthTest.php`, `app_tests.py` -- which no substring hint
    matches, so before the union a flat Java layout and every standard C#/PHP
    repo drew no guaranteed TST cell. Only the hints cover the plumbing the
    naming rule misses: a `conftest`, a `/tests/` corpus, a `.feature` file.

    The path is passed to `is_test_file` AS GIVEN, because those patterns are
    anchored and case-SENSITIVE (`Test\\.java$`); `_any_hint` lowercases instead.
    """
    for f in files or ():
        if discovery.is_test_file(str(f)):
            return True
    return _any_hint(files, _TEST_FILE_HINTS)


def applicable_global_floor(files, scout, global_floor=GLOBAL_FLOOR):
    """Subset of `global_floor` whose review surface is objectively present for
    this group (#5.0-19, #1193). COD is universal; DAT/TST/ARC gate ONLY on
    deterministic file signals. Scout-asserted ScopeProfile fields are ignored
    here so a mis-reporting scout cannot suppress a floor domain whose surface
    objectively exists (files present), and a scout-requested domain that is not
    objectively surfaced is still available via scout_added in effective_panels.
    The TST signal is the UNION of discovery's naming rule
    (`discovery.is_test_file` / `TEST_PATTERNS`) and `_TEST_FILE_HINTS`, so the
    two derivations of "is this a test file" cannot drift apart and leave the
    guarantee above unkept for a whole language's convention (#1770).
    Pure; the return is always a subset of `global_floor`.

    - COD: any file that is not a recognized binary/media asset (#1489). COD was
      previously unconditional, so a pure-asset group -- which `chunk_files`
      produces reliably, because it packs by directory -- still drew a COD cell.
      Across 7 calibration runs those cells returned 0 findings in every
      instance, against a 2.71-5.83 corpus baseline.
    - DAT: any db/schema/model/migration/seed file.
    - TST: any test-file signal, per `_has_test_surface`.
    - ARC: the group spans >= 2 distinct file directories (real cross-module
      structure).
    """
    files = list(files or [])
    keep = set()
    if "COD" in global_floor and has_code_surface(files):
        keep.add("COD")
    if "DAT" in global_floor and _any_hint(files, _DB_FILE_HINTS):
        keep.add("DAT")
    if "TST" in global_floor and _has_test_surface(files):
        keep.add("TST")
    distinct_dirs = {os.path.dirname(str(f)) for f in files}
    if "ARC" in global_floor and len(distinct_dirs) >= 2:
        keep.add("ARC")
    return frozenset(keep & set(global_floor))


def applicable_sec_floor(files):
    """`frozenset({"SEC"})` when this group carries an OBJECTIVE security surface
    (see _SEC_FILE_HINTS), else an empty frozenset (#run8 SEC-G2A).

    Keys ONLY on deterministic file signals, never scout-asserted surfaces
    (#1193), so a mis-reporting or adversarial scout -- or a root config that
    never lists `panels: [SEC]` -- cannot suppress security review of a group
    whose surface objectively exists. SEC is NON_EXCLUDABLE, so once floored here
    it also cannot be excluded away (#1084). Pure; a surfaceless group with none
    of these signals still spends no SEC cell (#5.0-19 stays honored).
    """
    return frozenset({"SEC"}) if _any_hint(files, _SEC_FILE_HINTS) else frozenset()


def effective_panels(floor, scout_added, exclude, global_floor=GLOBAL_FLOOR,
                     signal_floor=frozenset()):
    """Return (effective_set, disclosure_dict).

    effective = (global_floor | signal_floor | floor | scout_added) - exclude.
    floor ∩ exclude is assumed empty (validated by groups_schema); exclude still
    wins mechanically here so a bad file degrades safe (a panel is never both run
    and disclosed-off). The global_floor (universal-tier COD/DAT/TST/ARC) and the
    signal_floor (objective-signal domains such as SEC via applicable_sec_floor)
    are folded into the declared floor so they are forced on AND disclosed
    (#5.0-11, #run8 SEC-G2A). A signal_floor domain that is also NON_EXCLUDABLE
    (SEC) therefore both force-runs and survives a committed `exclude`.
    """
    floor = set(floor) | set(global_floor) | set(signal_floor)
    scout_added = set(scout_added)
    raw_exclude = set(exclude)
    # #1084: a non-excludable domain (SEC) is dropped from the exclude set, so a
    # committed `exclude: [SEC]` can never remove it from what actually runs.
    exclude = raw_exclude - NON_EXCLUDABLE
    effective = (floor | scout_added) - exclude
    # NB: "floor" is the DECLARED floor (not netted against exclude); `effective`
    # is what actually runs. In a validation-forbidden floor∩exclude overlap a
    # domain can appear in both "floor" and "excluded" — the loudest disclosure.
    disclosure = {
        "floor": sorted(floor),
        "scout_added": sorted(scout_added - exclude),
        "excluded": sorted(exclude),
    }
    rejected = sorted(raw_exclude & NON_EXCLUDABLE)
    if rejected:
        # surface the attempted-but-ignored exclusion so it's never silent
        # (#1084). This does not assert the domain actually ran: a domain
        # named here can still be absent from `effective` when neither the
        # floor nor the scout ever put it there (#1838 SEC-71240568) -- check
        # `effective` (or `floor`) to know whether it ran.
        disclosure["exclude_rejected"] = rejected
    return effective, disclosure


# 5.2 §6.2: the scout brief's surface -> domain prose (skill/agents/scout.md
# "## Domains") as code, so domain selection is reproducible from surfaces and
# the setup post-pass can floor a `custom:` capability from its profile
# (#1490). The 13 surfaces are the scout's enum; anything else is ignored.
SURFACES = frozenset({
    "db_sql", "http_web", "auth", "crypto", "fs", "concurrency", "external_api",
    "money_pii", "serialization", "templating", "secrets_config",
    "architecture", "database",
})
_SEC_SURFACES = SURFACES - {"architecture"}
_DAT_SURFACES = frozenset({"db_sql", "database"})


def surfaces_to_domains(surfaces):
    """The scout mapping as a function: COD always; SEC on any surface but
    `architecture`; DAT on `db_sql`/`database`; ARC on `architecture`.
    TST/QAL/AGT/OPS/ACC/LNG come from non-surface signals and stay with the
    live scout. Unknown surfaces are ignored. Returns a sorted list."""
    found = {s for s in (surfaces or []) if isinstance(s, str)} & SURFACES
    out = {"COD"}
    if found & _SEC_SURFACES:
        out.add("SEC")
    if found & _DAT_SURFACES:
        out.add("DAT")
    if "architecture" in found:
        out.add("ARC")
    return sorted(out)
