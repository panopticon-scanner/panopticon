#!/usr/bin/env python3
"""Select which lenses become mechanical agents based on panel depth."""

DEPTH_RANK = {"shallow": 0, "standard": 1, "deep": 2}
DEPTH_LIMIT = {"shallow": 1, "standard": 2, "deep": 3}


def _depth_gte(lens_depth, panel_depth):
    return DEPTH_RANK.get(lens_depth, 0) <= DEPTH_RANK.get(panel_depth, 0)


def plan_lenses(profile, panel_name):
    """Return up to 3 lens names to spawn as mechanical agents for panel_name.

    Selection criteria:
    - panel_name is in profile.panels
    - lens.spawn is True
    - lens.depth_threshold <= profile.depth
    - sorted by priority ascending
    - capped at the depth limit
    """
    depth = profile.get("depth", "standard")
    limit = DEPTH_LIMIT.get(depth, 2)
    if panel_name not in profile.get("panels", []):
        return []
    lenses = profile.get("lenses", {}).get(panel_name, [])
    candidates = []
    for lens in lenses:
        if not lens.get("spawn", False):
            continue
        threshold = lens.get("depth_threshold", "standard")
        if not _depth_gte(threshold, depth):
            continue
        candidates.append((lens.get("priority", 99), lens["name"]))
    candidates.sort()
    return [name for _, name in candidates[:limit]]
