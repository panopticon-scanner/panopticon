"""Compute a group's effective panel set: floor forces ON, exclude forces OFF
(loudly), the scout widens the undeclared middle. Pure. See spec §5.
"""

import os

# #5.0-11: the universal-tier domains ride a GLOBAL floor — every group reviews
# code/database/test/architecture regardless of its committed vertical floor.
# capability_affinity.yml documents these as "matrix-level, NOT affinity rows",
# but nothing implemented that: setup writes only the affinity (vertical) floor,
# so without this the flagship review silently skipped COD/DAT/TST/ARC on every
# group. Still subject to a per-group exclude (a docs-only group may opt out).
GLOBAL_FLOOR = frozenset({"COD", "DAT", "TST", "ARC"})
# #1084: domains a committed groups.yml `exclude` can never silence. SEC is
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
_TEST_FILE_HINTS = (".test.", ".spec.", "_test.", "_spec.", "/__tests__/",
                    "/tests/", "/test/", ".feature", "conftest", "test_")

# #run8 SEC-G2A: objective file signals that force a deterministic SEC review.
# SEC is deliberately NOT in GLOBAL_FLOOR (a blanket SEC floor reintroduces the
# #5.0-19 surfaceless-group noise), but a group whose FILES carry a security
# surface must be security-reviewed even when neither the committed `panels:`
# nor the scout asked for it -- otherwise a mis-reporting scout, or an
# adversarial/forgetful groups.yml that never lists SEC, silently exempts its
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
)
_SEC_CODE_HINTS = (
    "auth", "login", "session", "token", "oauth", "jwt",
    "crypto", "cipher", "encrypt", "secret", "password", "credential",
)
# #run10 SEC-G2A: the code hints above key on security-relevant *names*, but a
# group can carry the highest-value secret surface of all -- the secret-bearing
# FILES themselves -- without any of those words appearing. A `.env`, a private
# key, an `.npmrc` with a token: none match `auth`/`secret`/`password`, so a
# groups.yml that never lists SEC exempted exactly the files most worth
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
        low = str(f).lower()
        if any(h in low for h in hints):
            return True
    return False


def applicable_global_floor(files, scout, global_floor=GLOBAL_FLOOR):
    """Subset of `global_floor` whose review surface is objectively present for
    this group (#5.0-19, #1193). COD is universal; DAT/TST/ARC gate ONLY on
    deterministic file signals. Scout-asserted ScopeProfile fields are ignored
    here so a mis-reporting scout cannot suppress a floor domain whose surface
    objectively exists (files present), and a scout-requested domain that is not
    objectively surfaced is still available via scout_added in effective_panels.
    Pure; the return is always a subset of `global_floor`.

    - COD: any file that is not a recognized binary/media asset (#1489). COD was
      previously unconditional, so a pure-asset group -- which `chunk_files`
      produces reliably, because it packs by directory -- still drew a COD cell.
      Across 7 calibration runs those cells returned 0 findings in every
      instance, against a 2.71-5.83 corpus baseline.
    - DAT: any db/schema/model/migration/seed file.
    - TST: any test-file signal.
    - ARC: the group spans >= 2 distinct file directories (real cross-module
      structure).
    """
    files = list(files or [])
    keep = set()
    if "COD" in global_floor and has_code_surface(files):
        keep.add("COD")
    if "DAT" in global_floor and _any_hint(files, _DB_FILE_HINTS):
        keep.add("DAT")
    if "TST" in global_floor and _any_hint(files, _TEST_FILE_HINTS):
        keep.add("TST")
    distinct_dirs = {os.path.dirname(str(f)) for f in files}
    if "ARC" in global_floor and len(distinct_dirs) >= 2:
        keep.add("ARC")
    return frozenset(keep & set(global_floor))


def applicable_sec_floor(files):
    """`frozenset({"SEC"})` when this group carries an OBJECTIVE security surface
    (see _SEC_FILE_HINTS), else an empty frozenset (#run8 SEC-G2A).

    Keys ONLY on deterministic file signals, never scout-asserted surfaces
    (#1193), so a mis-reporting or adversarial scout -- or a groups.yml that
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
        # surface the attempted-but-ignored exclusion so it's never silent (#1084)
        disclosure["exclude_rejected"] = rejected
    return effective, disclosure
