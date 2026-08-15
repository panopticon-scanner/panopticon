"""Compute a group's effective panel set: floor forces ON, exclude forces OFF
(loudly), the scout widens the undeclared middle. Pure. See spec §5.
"""


def effective_panels(floor, scout_added, exclude):
    """Return (effective_set, disclosure_dict).

    effective = (floor | scout_added) - exclude. floor ∩ exclude is assumed
    empty (validated by groups_schema); exclude still wins mechanically here so
    a bad file degrades safe (a panel is never both run and disclosed-off).
    """
    floor, scout_added, exclude = set(floor), set(scout_added), set(exclude)
    effective = (floor | scout_added) - exclude
    disclosure = {
        "floor": sorted(floor),
        "scout_added": sorted(scout_added - exclude),
        "excluded": sorted(exclude),
    }
    return effective, disclosure
