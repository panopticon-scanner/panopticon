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


def validate_proposal(proposal):
    """Return a list of human-readable errors (empty = valid)."""
    if not isinstance(proposal, dict):
        return ["proposal: top-level must be a mapping"]
    groups = proposal.get("groups")
    if not isinstance(groups, list) or not groups:
        return ["proposal: 'groups' must be a non-empty list"]
    errors = []
    for i, g in enumerate(groups):
        if not isinstance(g, dict):
            errors.append("proposal group %d: must be a mapping" % i)
            continue
        cap = g.get("capability")
        label = cap if isinstance(cap, str) and cap else "#%d" % i
        if not cap or not isinstance(cap, str):
            errors.append("proposal group %s: missing/empty capability" % label)
        # Guard: after stripping custom: prefix, name must not be empty
        if isinstance(cap, str) and cap and _group_name(cap) == "":
            errors.append("proposal group %s: custom: prefix cannot be empty" % label)
        match = g.get("match")
        if (not isinstance(match, list) or not match
                or not all(isinstance(m, str) for m in match)):
            errors.append("proposal group %s: match must be a non-empty list of strings" % label)
        tests = g.get("tests")
        if tests is not None and (not isinstance(tests, list)
                                  or not all(isinstance(t, str) for t in tests)):
            errors.append("proposal group %s: tests must be a list of strings" % label)
    return errors


def _group_name(capability):
    """Strip a leading `custom:` prefix to get the committed group name."""
    return capability.split("custom:", 1)[1] if capability.startswith("custom:") else capability


def assemble(proposal, vocabulary, affinity):
    """Return (groups_mapping | None, disclosure).

    Matched capability -> affinity floor; custom/unknown -> empty floor
    (scout-only). The assembled mapping is round-tripped through
    groups_schema.parse_groups; a schema violation returns (None, disclosure)
    with the errors, so setup fails loudly rather than writing a bad draft.
    Collisions (same post-_group_name name) are merged: first occurrence's floor
    wins, match/tests are unioned, collision is recorded in disclosure.
    """
    errors = validate_proposal(proposal)
    if errors:
        return None, {"groups": [], "errors": errors}
    known = set(vocabulary.get("names") or [])
    out = {}
    disclosure = {"groups": [], "errors": [], "collisions": []}
    # Track which group names have been added to disclosure (only first)
    disclosed_names = set()
    for g in proposal["groups"]:
        cap = g["capability"]
        name = _group_name(cap)
        is_custom = cap.startswith("custom:") or cap not in known
        # Determine floor_source: distinguish known-but-missing from custom/unknown
        if is_custom:
            floor = []
            floor_source = "empty(scout-only)"
        elif cap in affinity:
            floor = list(affinity[cap])
            floor_source = "affinity"
        else:
            # Known capability but missing from affinity table
            floor = []
            floor_source = "affinity(missing)"
        new_match = list(g["match"])
        new_tests = list(g.get("tests") or [])
        if name in out:
            # Collision: merge into existing group
            # Keep first occurrence's floor and is_custom status
            # Union match and tests (de-duplicated, order-preserving)
            existing = out[name]
            # Union match: preserve order, deduplicate
            merged_match = list(existing["match"])
            for m in new_match:
                if m not in merged_match:
                    merged_match.append(m)
            # Union tests: preserve order, deduplicate
            merged_tests = list(existing["tests"])
            for t in new_tests:
                if t not in merged_tests:
                    merged_tests.append(t)
            out[name]["match"] = merged_match
            out[name]["tests"] = merged_tests
            # Record collision (capability that was merged in)
            disclosure["collisions"].append({
                "name": name, "capability": cap
            })
        else:
            # First occurrence of this name
            out[name] = {
                "match": new_match,
                "tests": new_tests,
                "panels": floor,
            }
            # Add to disclosure (only once per name)
            disclosure["groups"].append({
                "name": name, "capability": cap, "custom": is_custom,
                "floor": floor,
                "floor_source": floor_source,
            })
            disclosed_names.add(name)
    parsed, perrors = groups_schema.parse_groups({"groups": out})
    if perrors:
        disclosure["errors"] = perrors
        return None, disclosure
    return out, disclosure


def merge_additive(committed, assembled, claims):
    """Additive, never-clobber merge (spec §5).

    committed/assembled: {name: {"match": [...], "tests": [...], "panels": [...]}}.
    claims: {name: [file]} — the assembled groups that claimed previously-
    unassigned files (from orchestrator.assign_by_catalog; Task 6). A group that
    claims nothing new is dropped as redundant. Existing entries (match/tests/
    panels + any owner edit) are never rewritten; an existing group is only
    *extended* with globs/tests it does not already carry.
    """
    merged = {name: {k: (list(v) if isinstance(v, list) else v)
                     for k, v in body.items()}
              for name, body in committed.items()}
    diff = {"new_groups": [], "extended_groups": [], "dropped_redundant": []}
    for name, body in assembled.items():
        if not claims.get(name):
            diff["dropped_redundant"].append(name)
            continue
        if name in merged:
            existing = merged[name]
            new_match = [p for p in body.get("match", [])
                         if p not in existing.get("match", [])]
            new_tests = [t for t in body.get("tests", [])
                         if t not in existing.get("tests", [])]
            if new_match or new_tests:
                existing["match"] = list(existing.get("match", [])) + new_match
                existing["tests"] = list(existing.get("tests", [])) + new_tests
                diff["extended_groups"].append(
                    {"name": name, "added_match": new_match, "added_tests": new_tests})
        else:
            merged[name] = {
                "match": list(body.get("match", [])),
                "tests": list(body.get("tests", [])),
                "panels": list(body.get("panels", [])),
            }
            diff["new_groups"].append(
                {"name": name, "match": list(body.get("match", [])),
                 "panels": list(body.get("panels", []))})
    return merged, diff


def dump_groups_yaml(groups, header=True):
    """Serialize a groups mapping to canonical mapping-form groups.yml text.
    Insertion order preserved; only non-empty fields emitted; round-trips
    through groups_schema.parse_groups. yaml.safe_dump handles quoting of
    indicator-leading scalars (e.g. '**/auth/**')."""
    cleaned = {}
    for name, body in groups.items():
        entry = {}
        for key in ("match", "tests", "panels", "exclude"):
            vals = body.get(key) or []
            if vals:
                entry[key] = list(vals)
        cleaned[name] = entry
    body_text = yaml.safe_dump({"groups": cleaned}, sort_keys=False,
                               default_flow_style=False, allow_unicode=True)
    if not header:
        return body_text
    return ("# panopticon groups catalog (matrix form) -- match/tests/panels/exclude.\n"
            "# gitignore-flavored globs; first matching group wins; edit and commit.\n"
            + body_text)
