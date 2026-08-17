"""Compute a group's effective panel set: floor forces ON, exclude forces OFF
(loudly), the scout widens the undeclared middle. Pure. See spec §5.
"""

# #5.0-11: the universal-tier domains ride a GLOBAL floor — every group reviews
# code/database/test/architecture regardless of its committed vertical floor.
# capability_affinity.yml documents these as "matrix-level, NOT affinity rows",
# but nothing implemented that: setup writes only the affinity (vertical) floor,
# so without this the flagship review silently skipped COD/DAT/TST/ARC on every
# group. Still subject to a per-group exclude (a docs-only group may opt out).
GLOBAL_FLOOR = frozenset({"COD", "DAT", "TST", "ARC"})


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
