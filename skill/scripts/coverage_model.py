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


# #5.0-19: the universal-tier floor is GATED per group on OBSERVABLE surface
# signals rather than injected unconditionally. BursarBuddy calibration
# (2026-08-16): DAT/TST/ARC on surfaceless groups produced 59 of 97 noise
# findings and caught ZERO answer-key vulns, because a testless / db-free /
# single-module group has nothing for those panels to review. COD stays
# universal (code is always present). The gate keys on FILE signals first,
# falling back to the scout's reported surfaces -- NOT the scout's discretionary
# domain request -- so an under-reporting scout still cannot suppress a floor
# domain whose surface objectively exists (files present), preserving the
# #5.0-11 guarantee while dropping the cells that only manufacture noise. A
# scout that DID request the domain gets it via scout_added regardless, so the
# floor only ever matters for domains the scout omitted.
_DB_FILE_HINTS = ("schema.prisma", ".prisma", ".sql", "migration", "/models/",
                  "/model/", "schema", "entity", "entities", ".orm", "seed",
                  "repository", "database", "/db.")
_DB_SURFACES = frozenset({"db_sql", "database", "persistence", "orm", "sql"})
_TEST_FILE_HINTS = (".test.", ".spec.", "_test.", "_spec.", "/__tests__/",
                    "/tests/", "/test/", ".feature", "conftest", "test_")
_TEST_SURFACES = frozenset({"tests", "testing", "test"})
_ARCH_SURFACES = frozenset({"architecture", "arch"})


def _any_hint(files, hints):
    for f in files or ():
        low = str(f).lower()
        if any(h in low for h in hints):
            return True
    return False


def applicable_global_floor(files, scout, global_floor=GLOBAL_FLOOR):
    """Subset of `global_floor` whose review surface is objectively present for
    this group (#5.0-19). COD is universal; DAT/TST/ARC gate on deterministic
    file signals, falling back to the scout's reported surfaces, so a group with
    no persistence / no tests / no cross-module structure does not spend a cell
    finding nothing. Pure; the return is always a subset of `global_floor` (a
    caller passing a reduced floor, e.g. tests, gets a reduced result).

    - COD: always (kept whenever it is in `global_floor`).
    - DAT: any db/schema/model/migration/seed file, or a db-ish scout surface.
    - TST: any test-file signal, a scout `has_tests`/`tests`, or a test surface.
    - ARC: the group spans >= 2 distinct file directories (real cross-module
      structure) or the scout reported an architecture surface.
    """
    files = list(files or [])
    scout = scout or {}
    surfaces = {str(s).lower() for s in (scout.get("surfaces") or [])}
    keep = set()
    if "COD" in global_floor:
        keep.add("COD")
    if "DAT" in global_floor and (_any_hint(files, _DB_FILE_HINTS)
                                  or surfaces & _DB_SURFACES):
        keep.add("DAT")
    if "TST" in global_floor and (_any_hint(files, _TEST_FILE_HINTS)
                                  or bool(scout.get("has_tests"))
                                  or bool(scout.get("tests"))
                                  or surfaces & _TEST_SURFACES):
        keep.add("TST")
    distinct_dirs = {os.path.dirname(str(f)) for f in files}
    if "ARC" in global_floor and (len(distinct_dirs) >= 2
                                  or surfaces & _ARCH_SURFACES):
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
    scout_added, exclude = set(scout_added), set(exclude)
    effective = (floor | scout_added) - exclude
    # NB: "floor" is the DECLARED floor (not netted against exclude); `effective`
    # is what actually runs. In a validation-forbidden floor∩exclude overlap a
    # domain can appear in both "floor" and "excluded" — the loudest disclosure.
    disclosure = {
        "floor": sorted(floor),
        "scout_added": sorted(scout_added - exclude),
        "excluded": sorted(exclude),
    }
    return effective, disclosure
