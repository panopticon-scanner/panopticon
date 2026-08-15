"""Deterministic core of the 5.0 `panopticon setup` scan flow.

Loads the curated capability vocabulary + affinity table, validates and
assembles a setup-scan agent's proposal into a matrix groups mapping (panel
floors from the affinity table; custom groups scout-only), and additive-merges
it against a committed groups.yml without ever clobbering it. Pure: every
function is a total function of its inputs (the only I/O is reading a data file
whose path it is handed). See
docs/superpowers/specs/2026-08-14-panopticon-5.0-setup-scan-design.md.
"""

import yaml

import groups_schema


def load_vocabulary(path):
    """Return ({"names": [...], "hints": {name: [...]}}, errors)."""
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh) or {}

    # Guard: doc must be a mapping
    if not isinstance(doc, dict):
        return {"names": [], "hints": {}}, [
            "vocabulary: root must be a mapping"
        ]

    # Guard: capabilities must be a list
    capabilities = doc.get("capabilities")
    if capabilities is None:
        capabilities = []
    elif not isinstance(capabilities, list):
        return {"names": [], "hints": {}}, [
            "vocabulary: capabilities must be a list"
        ]

    names, hints, errors, seen = [], {}, [], set()
    for entry in capabilities:
        # Guard: each entry must be a mapping
        if not isinstance(entry, dict):
            errors.append("vocabulary: capability entry must be a mapping")
            continue

        name = entry.get("name")
        if not name or not isinstance(name, str):
            errors.append("vocabulary: capability with missing/empty name")
            continue
        if name in seen:
            errors.append("vocabulary: duplicate capability %r" % name)
            continue

        seen.add(name)
        names.append(name)

        # Guard: hints must be a list (if present)
        raw_hints = entry.get("hints")
        if raw_hints is None:
            entry_hints = []
        elif not isinstance(raw_hints, list):
            errors.append("vocabulary %s: hints must be a list" % name)
            entry_hints = []
        else:
            entry_hints = [h for h in raw_hints if isinstance(h, str)]

        hints[name] = entry_hints

    return {"names": names, "hints": hints}, errors


def load_affinity(path, vocabulary):
    """Return ({capability: [domain]}, errors). Domains validate against
    groups_schema.DOMAINS; keys validate against the vocabulary names."""
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh) or {}

    # Guard: doc must be a mapping
    if not isinstance(doc, dict):
        return {}, ["affinity: root must be a mapping"]

    # Guard: affinity must be a mapping (if present)
    affinity_block = doc.get("affinity")
    if affinity_block is None:
        affinity_block = {}
    elif not isinstance(affinity_block, dict):
        return {}, ["affinity: affinity must be a mapping"]

    known = set(vocabulary.get("names") or [])
    affinity, errors = {}, []

    for cap, domains in affinity_block.items():
        if cap not in known:
            errors.append("affinity: %r is not a known capability" % cap)
            continue

        # Guard: domains must be a list (if present)
        if domains is None:
            domains = []
        elif not isinstance(domains, list):
            errors.append("affinity %s: domains must be a list" % cap)
            domains = []

        floor = []
        for d in domains:
            if d not in groups_schema.DOMAINS:
                errors.append("affinity %s: %r is not a known domain" % (cap, d))
            else:
                floor.append(d)
        affinity[cap] = floor

    return affinity, errors
