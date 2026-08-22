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

    - COD: always (kept whenever it is in `global_floor`).
    - DAT: any db/schema/model/migration/seed file.
    - TST: any test-file signal.
    - ARC: the group spans >= 2 distinct file directories (real cross-module
      structure).
    """
    files = list(files or [])
    keep = set()
    if "COD" in global_floor:
        keep.add("COD")
    if "DAT" in global_floor and _any_hint(files, _DB_FILE_HINTS):
        keep.add("DAT")
    if "TST" in global_floor and _any_hint(files, _TEST_FILE_HINTS):
        keep.add("TST")
    distinct_dirs = {os.path.dirname(str(f)) for f in files}
    if "ARC" in global_floor and len(distinct_dirs) >= 2:
        keep.add("ARC")
    return frozenset(keep & set(global_floor))


def effective_panels(floor, scout_added, exclude, global_floor=GLOBAL_FLOOR):
    """Return (effective_set, disclosure_dict).

    effective = (global_floor | floor | scout_added) - exclude. floor ∩ exclude
    is assumed empty (validated by groups_schema); exclude still wins
    mechanically here so a bad file degrades safe (a panel is never both run and
    disclosed-off). The global_floor (universal-tier COD/DAT/TST/ARC) is folded
    into the declared floor so it is forced on AND disclosed (#5.0-11).
    """
    floor = set(floor) | set(global_floor)
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
