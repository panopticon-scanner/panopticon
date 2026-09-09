"""Deterministic core of the `panopticon setup` scan flow.

Loads the curated capability vocabulary + affinity table (5.0) and the layer
catalog (5.2), validates and assembles a setup-scan agent's proposal into a
matrix groups mapping (panel floors from the affinity table or the profile
surfaces; custom groups scout-only; aliases canonicalized through the
catalogs; layers as subgroups), and additive-merges it against a committed
groups.yml without ever clobbering it. Pure: every function is a total
function of its inputs (the only I/O is reading a data file whose path it is
handed). See docs/superpowers/specs/2026-08-14-panopticon-5.0-setup-scan-design.md
and the 5.2 grouping-engine spec (§3 catalogs, §5.3 assembly).
"""

import re

import yaml

import coverage_model
import groups_schema

# 5.2: names the engine mints itself -- the Tests sweep, the Commons fold, the
# residual sink, and the residual LAYER. A catalog entry or alias carrying one
# of these would collide with an engine-owned group (spec §3, §4.6).
RESERVED_GROUP_NAMES = frozenset({"Tests", "Commons", "Ungrouped", "Core"})


def alias_key(label):
    """Fold a catalog name/alias or a proposed label to its comparison key:
    casefold, then drop everything that is not a letter or digit, so
    `Rate Limiting`, `rate_limiting`, `rate-limiting` and `RateLimiting` are
    one key. Aliases match on this key (spec §3.2)."""
    return re.sub(r"[^0-9a-z]", "", str(label or "").casefold())


# Reserved names compared the way aliases are, so `tests`, `Un-grouped` and
# `CORE` are refused alongside the canonical spellings.
_RESERVED_KEYS = frozenset(alias_key(n) for n in RESERVED_GROUP_NAMES)
# Top-level names a PROPOSAL may not take: the engine mints these at run time.
# `Tests` is deliberately absent (R4 -- a committed Tests suppresses the
# sweep) and `Core` is a layer name, refused by _NOT_LAYER_KEYS instead.
_ENGINE_OWNED_KEYS = frozenset({alias_key("Commons"), alias_key("Ungrouped")})


def _load_catalog(path, root_key, kind, noun):
    """Shared loader for the capability and layer catalogs -- one entry shape
    (spec §3). Returns ({"names", "hints", "entries", "aliases"}, errors):

    - names:   canonical names in file order
    - hints:   {name: [glob]} -- optional, non-authoritative match suggestions
    - entries: {name: the entry mapping as loaded} (definition/boundary/...)
    - aliases: {alias_key: canonical name}; every name maps to itself

    Permissive about prose completeness (tests/test_catalog_data.py enforces
    the SHIPPED data so fixtures can stay minimal); strict about the two
    things that break routing: a duplicate name, and an alias that resolves
    to two entries (first owner kept, collision reported)."""
    empty = {"names": [], "hints": {}, "entries": {}, "aliases": {}}
    with open(path, encoding="utf-8") as fh:
        try:
            doc = yaml.safe_load(fh) or {}
        except yaml.YAMLError as exc:
            return empty, ["%s: cannot parse %s: %s" % (kind, path, exc)]
    if not isinstance(doc, dict):
        return empty, ["%s: root must be a mapping" % kind]
    items = doc.get(root_key)
    if items is None:
        items = []
    elif not isinstance(items, list):
        return empty, ["%s: %s must be a list" % (kind, root_key)]
    names, hints, entries, aliases, errors = [], {}, {}, {}, []
    for entry in items:
        if not isinstance(entry, dict):
            errors.append("%s: %s entry must be a mapping" % (kind, noun))
            continue
        name = entry.get("name")
        if not name or not isinstance(name, str):
            errors.append("%s: %s with missing/empty name" % (kind, noun))
            continue
        if name in entries:
            errors.append("%s: duplicate %s %r" % (kind, noun, name))
            continue
        if alias_key(name) in _RESERVED_KEYS:
            errors.append("%s: %s name %r is reserved" % (kind, noun, name))
            continue
        raw_hints = entry.get("hints")
        if raw_hints is None:
            entry_hints = []
        elif not isinstance(raw_hints, list):
            errors.append("%s %s: hints must be a list" % (kind, name))
            entry_hints = []
        else:
            entry_hints = [h for h in raw_hints if isinstance(h, str)]
        raw_aliases = entry.get("aliases")
        if raw_aliases is None:
            entry_aliases = []
        elif not isinstance(raw_aliases, list):
            errors.append("%s %s: aliases must be a list" % (kind, name))
            entry_aliases = []
        else:
            entry_aliases = [a for a in raw_aliases if isinstance(a, str)]
        names.append(name)
        hints[name] = entry_hints
        entries[name] = entry
        for label in [name] + entry_aliases:
            key = alias_key(label)
            if not key:
                continue
            if key in _RESERVED_KEYS:
                errors.append("%s: alias %r of %s is reserved"
                              % (kind, label, name))
                continue
            owner = aliases.get(key)
            if owner is not None and owner != name:
                errors.append("%s: %s %r of %s collides with %s"
                              % (kind, "name" if label == name else "alias",
                                 label, name, owner))
                continue
            aliases[key] = name
    return ({"names": names, "hints": hints, "entries": entries,
             "aliases": aliases}, errors)


def load_vocabulary(path):
    """Return ({"names", "hints", "entries", "aliases"}, errors) for
    capability_vocabulary.yml. `names`/`hints` are the 5.0 keys every existing
    caller reads; `entries`/`aliases` are the 5.2 additions (#1500)."""
    return _load_catalog(path, "capabilities", "vocabulary", "capability")


def load_layers(path):
    """Same shape for layer_vocabulary.yml (spec §3.3)."""
    return _load_catalog(path, "layers", "layers", "layer")


def canonicalize(label, catalog):
    """Resolve a proposed label to its canonical catalog name through
    `aliases`, or None when it resolves to nothing (the label then stays
    `custom:<label>` -- expected and allowed, spec §3.4)."""
    return (catalog.get("aliases") or {}).get(alias_key(label))


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


# #1107: an untrusted proposal (a target repo can ship
# .panopticon/setup-proposal.json) must not drive assemble()'s collision merge
# with pathological structure. These bound the group count, per-group match/tests
# counts, and single-entry length so the O(n) list-membership merge stays cheap.
_MAX_GROUPS = 500
_MAX_GROUP_ENTRIES = 1000       # match or tests entries in one group
_MAX_ENTRY_LEN = 4096           # a single match glob / test path / capability name

# 5.2 §5.2: the additive proposal fields. `layers` becomes `Parent:Layer`
# subgroups (bounded like groups); `profile` is prose the setup agent wrote
# about the group and feeds the floor (#1490) and, in plan 2, profiles.yml.
_MAX_LAYERS = 12                # layers proposed for one group
_MAX_PROFILE_STR = 512          # one profile string / one profile list item
_MAX_PROFILE_LIST = 32          # items in one profile list
_PROFILE_STR_FIELDS = ("purpose",)
_PROFILE_LIST_FIELDS = ("surfaces", "entry_points", "trust_boundaries")
# Names a proposed LAYER may not take: the engine-owned names (`Core` is the
# residual layer the engine mints itself) and the spec's "not layers" --
# tests are the `tests:` axis, config and docs are Commons (spec §3.3).
_NOT_LAYER_KEYS = frozenset({alias_key(n) for n in RESERVED_GROUP_NAMES}) | frozenset({
    "test", "config", "configuration", "doc", "docs", "documentation"})


def _validate_str_list(group_label, field, values, required):
    """Shared shape/caps check for a proposal group's `match`/`tests` list
    (#run7 QAL-D1A: the two fields validated with near-verbatim duplicated code).

    Returns a list of errors (empty = ok). `required` toggles the non-empty
    requirement (and the corresponding message); an absent optional field
    (`values is None`, required=False) is skipped. Enforces the #1107 caps
    on entry count and single-entry length.
    """
    errors = []
    if values is None and not required:
        return errors
    if required:
        ok_shape = (isinstance(values, list) and values
                    and all(isinstance(v, str) for v in values))
        noun = "a non-empty list of strings"
    else:
        ok_shape = isinstance(values, list) and all(isinstance(v, str) for v in values)
        noun = "a list of strings"
    if not ok_shape:
        errors.append("proposal group %s: %s must be %s" % (group_label, field, noun))
        return errors
    if len(values) > _MAX_GROUP_ENTRIES:
        errors.append("proposal group %s: too many %s entries (%d > %d)"
                      % (group_label, field, len(values), _MAX_GROUP_ENTRIES))
    elif any(len(v) > _MAX_ENTRY_LEN for v in values):
        errors.append("proposal group %s: a %s entry exceeds %d chars"
                      % (group_label, field, _MAX_ENTRY_LEN))
    # #1501: the setup agent authors globs too, and one the compiler cannot
    # translate renders an EMPTY group -- which then reads as a catalog
    # coverage gap rather than as the proposal error it is. Same rule as the
    # committed catalog; layers route through here too, so this is the one
    # place a proposal glob is checked.
    errors.extend(groups_schema.glob_errors(
        "proposal group %s" % group_label, field, values))
    return errors


def _validate_layers(group_label, layers):
    """Shape/caps check for a proposal group's optional `layers` list
    (spec §5.2): each entry is `{"layer": name, "match": [glob, ...]}`.
    Two entries whose names fold to one alias_key are a duplicate (they
    would become the same `Parent:Layer` subgroup). Layer globs may not
    negate: the carrier layer's `!` globs are minted by the engine from the
    other layers' POSITIVE globs (R2), so a negation authored inside a layer
    would evict files from the vertical itself rather than route them
    between its layers. Names are only shape-checked here -- an invalid or
    chunk-colliding name is dropped with a warning by `_keep_layers` (the
    group survives its layers)."""
    if layers is None:
        return []
    if not isinstance(layers, list):
        return ["proposal group %s: layers must be a list" % group_label]
    if len(layers) > _MAX_LAYERS:
        return ["proposal group %s: too many layers (%d > %d)"
                % (group_label, len(layers), _MAX_LAYERS)]
    errors, seen = [], set()
    for j, layer in enumerate(layers):
        if not isinstance(layer, dict):
            errors.append("proposal group %s: layer %d must be a mapping" % (group_label, j))
            continue
        lname = layer.get("layer")
        if not lname or not isinstance(lname, str):
            errors.append("proposal group %s: layer %d: missing/empty layer name"
                          % (group_label, j))
            continue
        if len(lname) > _MAX_ENTRY_LEN:
            errors.append("proposal group %s: layer %d: name exceeds %d chars"
                          % (group_label, j, _MAX_ENTRY_LEN))
            continue
        key = alias_key(lname)
        if key in seen:
            errors.append("proposal group %s: duplicate layer %r" % (group_label, lname))
        seen.add(key)
        match = layer.get("match")
        errors.extend(_validate_str_list("%s layer %s" % (group_label, lname),
                                         "match", match, required=True))
        if isinstance(match, list):
            for glob in match:
                if isinstance(glob, str) and glob.startswith("!"):
                    errors.append("proposal group %s: layer %s: negation %r is not "
                                  "allowed in a layer (the engine derives the carrier's "
                                  "negations; put exclusions in the group's match)"
                                  % (group_label, lname, glob))
    return errors


def _validate_profile(group_label, profile):
    """Shape/caps check for a proposal group's optional `profile` mapping
    (spec §5.2). Strict on keys and on the surfaces enum: the profile is
    what floors a `custom:` capability, so a misspelled key or surface must
    fail loudly rather than silently weaken the floor."""
    if profile is None:
        return []
    if not isinstance(profile, dict):
        return ["proposal group %s: profile must be a mapping" % group_label]
    errors = []
    allowed = set(_PROFILE_STR_FIELDS) | set(_PROFILE_LIST_FIELDS)
    for key in sorted((k for k in profile if k not in allowed), key=str):
        errors.append("proposal group %s: unknown profile field %r" % (group_label, key))
    for field in _PROFILE_STR_FIELDS:
        value = profile.get(field)
        if value is None:
            continue
        if not isinstance(value, str):
            errors.append("proposal group %s: profile.%s must be a string" % (group_label, field))
        elif len(value) > _MAX_PROFILE_STR:
            errors.append("proposal group %s: profile.%s exceeds %d chars"
                          % (group_label, field, _MAX_PROFILE_STR))
    for field in _PROFILE_LIST_FIELDS:
        values = profile.get(field)
        if values is None:
            continue
        if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            errors.append("proposal group %s: profile.%s must be a list of strings"
                          % (group_label, field))
            continue
        if len(values) > _MAX_PROFILE_LIST:
            errors.append("proposal group %s: too many profile.%s entries (%d > %d)"
                          % (group_label, field, len(values), _MAX_PROFILE_LIST))
        elif any(len(v) > _MAX_PROFILE_STR for v in values):
            errors.append("proposal group %s: a profile.%s entry exceeds %d chars"
                          % (group_label, field, _MAX_PROFILE_STR))
    surfaces = profile.get("surfaces")
    if isinstance(surfaces, list):
        for s in surfaces:
            if isinstance(s, str) and s not in coverage_model.SURFACES:
                errors.append("proposal group %s: profile.surfaces %r is not a known surface"
                              % (group_label, s))
    return errors


def validate_proposal(proposal):
    """Return a list of human-readable errors (empty = valid)."""
    if not isinstance(proposal, dict):
        return ["proposal: top-level must be a mapping"]
    if "schema_version" in proposal and not isinstance(proposal.get("schema_version"), int):
        return ["proposal: schema_version must be an integer"]
    groups = proposal.get("groups")
    if not isinstance(groups, list) or not groups:
        return ["proposal: 'groups' must be a non-empty list"]
    if len(groups) > _MAX_GROUPS:
        return ["proposal: too many groups (%d > %d)" % (len(groups), _MAX_GROUPS)]
    errors = []
    for i, g in enumerate(groups):
        if not isinstance(g, dict):
            errors.append("proposal group %d: must be a mapping" % i)
            continue
        cap = g.get("capability")
        label = cap if isinstance(cap, str) and cap else "#%d" % i
        if not cap or not isinstance(cap, str):
            errors.append("proposal group %s: missing/empty capability" % label)
        elif len(cap) > _MAX_ENTRY_LEN:
            errors.append("proposal group %s: capability name exceeds %d chars"
                          % (label, _MAX_ENTRY_LEN))
        # Guard: after stripping custom: prefix, name must not be empty
        if isinstance(cap, str) and cap and _group_name(cap) == "":
            errors.append("proposal group %s: custom: prefix cannot be empty" % label)
        errors.extend(_validate_str_list(label, "match", g.get("match"), required=True))
        errors.extend(_validate_str_list(label, "tests", g.get("tests"), required=False))
        errors.extend(_validate_layers(label, g.get("layers")))
        errors.extend(_validate_profile(label, g.get("profile")))
    return errors


def _group_name(capability):
    """Strip a leading `custom:` prefix to get the committed group name."""
    return capability.split("custom:", 1)[1] if capability.startswith("custom:") else capability


def _union_into(target, values):
    """Append each of `values` not already in `target` (order-preserving,
    de-duplicated union in place)."""
    for v in values:
        if v not in target:
            target.append(v)


def _floor_for(is_custom, cap, affinity, surfaces):
    """(floor, floor_source) for one group -- spec §5.3 step 6 and R3.

    An affinity row always wins. Otherwise the profile's surfaces derive the
    floor through coverage_model.surfaces_to_domains (`"profile"`, #1490) --
    minus COD, which the run-time global floor supplies whenever code is
    present (DAT/ARC stay: the global floor gates them on file hints an
    ORM- or CI-heavy group may not carry). With no surfaces the 5.0 empty
    sources stand."""
    if not is_custom and cap in affinity:
        return list(affinity[cap]), "affinity"
    if surfaces:
        derived = [d for d in coverage_model.surfaces_to_domains(surfaces) if d != "COD"]
        return derived, "profile"
    return [], ("empty(scout-only)" if is_custom else "affinity(missing)")


def _keep_layers(name, proposed, layer_aliases, warnings):
    """Canonicalize a group's proposed layers through the layer catalog
    (spec §5.3 step 1) and drop the ones that may not be layers: reserved /
    not-a-layer names (`Core`, `Tests`, `Config`, `Docs`, ...), names that
    are not a valid subgroup token (groups_schema._invalid_name) and names
    that collide with a sibling's chunk names (`API_1` next to `API`, which
    groups_schema refuses in a committed groups.yml). Dropping is disclosed
    in `warnings`; the group itself is kept. A name the catalog does not
    know is kept verbatim (custom layers are allowed, like custom
    capabilities) and flagged `canonical: False` for the report and the
    promotion ratchet."""
    kept = []
    for layer in proposed:
        raw = layer["layer"]
        key = alias_key(raw)
        canonical = layer_aliases.get(key)
        lname = canonical if canonical is not None else raw.strip()
        if key in _NOT_LAYER_KEYS:
            warnings.append("%s: layer %r dropped (reserved or not a layer -- tests are the "
                            "tests: axis, config and docs are Commons)" % (name, raw))
            continue
        if groups_schema._invalid_name(lname):
            warnings.append("%s: layer %r dropped (not a valid group name)" % (name, raw))
            continue
        if alias_key(lname) == alias_key(name):
            warnings.append("%s: layer %r is named like its group (becomes %s:%s -- "
                            "consider a role name such as Core or API)"
                            % (name, raw, name, lname))
        kept.append({"layer": lname, "match": list(layer["match"]),
                     "canonical": canonical is not None})
    names = {layer["layer"] for layer in kept}
    out = []
    for layer in kept:
        m = groups_schema._CHUNK_SUFFIX_RE.match(layer["layer"])
        if m and m.group("base") in names:
            warnings.append("%s: layer %r dropped (collides with the chunk names of layer "
                            "%r)" % (name, layer["layer"], m.group("base")))
            continue
        out.append(layer)
    return out


def _clean_profile(profile):
    """Copy the known profile fields only, lists de-duplicated."""
    out = {}
    for field in _PROFILE_STR_FIELDS:
        if profile.get(field):
            out[field] = profile[field]
    for field in _PROFILE_LIST_FIELDS:
        values = []
        _union_into(values, profile.get(field) or [])
        out[field] = values
    return out


def assemble(proposal, vocabulary, affinity, layers=None):
    """Return (groups_mapping | None, disclosure).

    Each assembled group is `{"match", "tests", "panels", "layers", "profile"}`;
    `layers` is the canonicalized `[{"layer", "match", "canonical"}]` list
    (empty when none proposed) and `profile` the cleaned profile mapping
    (empty when none). `layers` is the loaded layer catalog (load_layers) used
    to canonicalize layer names; None skips canonicalization (every proposed
    layer is then custom).

    Names canonicalize through the vocabulary's `aliases` (spec §3.4) -- so
    `authentication`, `AUTH` and `custom:authentication` all become `Auth`
    and keep Auth's affinity floor; #run7 COD-C2D's case/whitespace fold is
    the degenerate case (every known name is its own alias). A label that
    resolves to nothing is custom (`custom:` prefix or not); custom spellings
    that fold to one alias_key are one group, named by the first spelling.

    Floor outcomes (`floor_source`):
    - affinity row present                -> `"affinity"`
    - else profile surfaces present       -> `"profile"` (surfaces_to_domains, #1490)
    - else custom                         -> `"empty(scout-only)"`
    - else known but no affinity row      -> `"affinity(missing)"`

    Collisions (same canonical name) merge: match/tests/layers/profile lists
    are unioned, the first non-empty `purpose` is kept, and the floor is
    recomputed from the MERGED state so the outcome is order-independent
    (#run9 ARC-D2B: a known capability and its custom alias in either order
    keep the known floor). Every collision is recorded.

    `Commons` and `Ungrouped` (any spelling) are engine-owned at the top
    level -- the run-time sweep mints them -- so a proposal naming one is an
    error. `Tests` is allowed (R4: a committed Tests suppresses the sweep)
    and `Core` is only reserved as a layer.

    Dropped layers are reported in `disclosure["warnings"]`; the mapping is
    round-tripped through groups_schema.parse_groups in the nested form the
    draft is written in (leaf fields only, layers as subgroups) and a
    violation returns (None, disclosure) so setup fails loudly.
    """
    errors = validate_proposal(proposal)
    if errors:
        return None, {"groups": [], "errors": errors, "collisions": [], "warnings": []}
    known = set(vocabulary.get("names") or [])
    aliases = dict(vocabulary.get("aliases") or {})
    for n in known:
        aliases.setdefault(alias_key(n), n)
    layer_aliases = dict((layers or {}).get("aliases") or {})
    out = {}
    custom_seen = {}     # alias_key -> first spelling of a custom name
    disclosure = {"groups": [], "errors": [], "collisions": [], "warnings": []}
    for g in proposal["groups"]:
        raw = g["capability"]
        label = _group_name(raw).strip()
        if alias_key(label) in _ENGINE_OWNED_KEYS:
            disclosure["errors"].append(
                "proposal group %r: name is engine-owned (the run-time sweep mints "
                "Commons and Ungrouped) -- rename it" % raw)
            continue
        canonical = aliases.get(alias_key(label))
        if canonical is not None:
            cap, name, is_custom = canonical, canonical, False
        else:
            # custom: spellings that fold to one key are one group, named by
            # the first spelling seen (disclosed via `normalized`).
            cap, is_custom = raw, True
            name = custom_seen.setdefault(alias_key(label), label)
        normalized = None if name == _group_name(raw) else {"from": raw, "to": name}
        profile = _clean_profile(g.get("profile") or {})
        kept_layers = _keep_layers(name, g.get("layers") or [], layer_aliases,
                                   disclosure["warnings"])
        if name not in out:
            floor, floor_source = _floor_for(is_custom, cap, affinity, profile["surfaces"])
            out[name] = {"match": list(g["match"]), "tests": list(g.get("tests") or []),
                         "panels": floor, "layers": kept_layers, "profile": profile}
            disclosure["groups"].append({
                "name": name, "capability": cap, "custom": is_custom,
                "floor": floor, "floor_source": floor_source,
                # record the alias/case fixup so canonicalization is visible
                "normalized": normalized,
            })
            continue
        # Collision: merge into the existing group, then recompute the floor
        # from the merged state (order-independent).
        existing = out[name]
        dgroup = next(d for d in disclosure["groups"] if d["name"] == name)
        _union_into(existing["match"], g["match"])
        _union_into(existing["tests"], g.get("tests") or [])
        have = {alias_key(layer["layer"]) for layer in existing["layers"]}
        for layer in kept_layers:
            if alias_key(layer["layer"]) not in have:
                existing["layers"].append(layer)
                have.add(alias_key(layer["layer"]))
        for field in _PROFILE_STR_FIELDS:
            if not existing["profile"].get(field) and profile.get(field):
                existing["profile"][field] = profile[field]
        for field in _PROFILE_LIST_FIELDS:
            _union_into(existing["profile"][field], profile[field])
        # `is_custom == dgroup["custom"]` always holds here: a label that
        # resolves through the aliases is known in every spelling
        # (`custom:Auth` and `Auth` both canonicalize before the lookup), so
        # a known group never collides with a custom one -- the merged floor
        # only has to be recomputed from the merged surfaces.
        floor, floor_source = _floor_for(dgroup["custom"], dgroup["capability"], affinity,
                                         existing["profile"]["surfaces"])
        existing["panels"], dgroup["floor"], dgroup["floor_source"] = floor, floor, floor_source
        disclosure["collisions"].append({"name": name, "capability": raw})
    if disclosure["errors"]:
        return None, disclosure
    parsed, perrors = groups_schema.parse_groups({"groups": _nested_leaves(out)})
    if perrors:
        disclosure["errors"] = perrors
        return None, disclosure
    return out, disclosure


def _nested_leaves(groups):
    """The assembled mapping in the shape the draft is written (a layered
    group nests its layers as subgroups, the carrier holding the parent's
    globs), leaf fields only -- what groups_schema.parse_groups validates."""
    nested = {}
    for name, body in groups.items():
        leaf = {k: list(v) for k, v in body.items() if k in groups_schema.RESERVED}
        if body.get("layers"):
            subs = {layer["layer"]: {"match": list(layer["match"])} for layer in body["layers"]}
            subs.setdefault("Core", dict(leaf))
            nested[name] = subs
        else:
            nested[name] = leaf
    return nested


def flatten_groups(groups):
    """{flat_id: leaf} for a nested groups mapping: a leaf stays under its
    name; a parent `{"subgroups": {sub: leaf}}` yields `Parent:Sub` leaves
    (the flat ids groups_schema.parse_groups mints). Lists are copied."""
    flat = {}
    for name, body in groups.items():
        subs = body.get("subgroups")
        if isinstance(subs, dict):
            for sub, leaf in subs.items():
                flat["%s:%s" % (name, sub)] = {k: (list(v) if isinstance(v, list) else v)
                                                for k, v in leaf.items()}
        else:
            flat[name] = {k: (list(v) if isinstance(v, list) else v)
                          for k, v in body.items() if k != "subgroups"}
    return flat


def _copy_body(body):
    """Deep-enough copy of a group body (lists and the subgroups mapping)."""
    out = {}
    for k, v in body.items():
        if k == "subgroups" and isinstance(v, dict):
            out[k] = {sub: {sk: (list(sv) if isinstance(sv, list) else sv)
                            for sk, sv in leaf.items()} for sub, leaf in v.items()}
        else:
            out[k] = list(v) if isinstance(v, list) else v
    return out


def _all_globs(body, field):
    """A body's `field` globs, including every subgroup's, order-preserving.

    A subgroup's negation of a SIBLING's positive glob is dropped: it is the
    carrier's partition (`!src/auth/http/**` routing files to `Auth:API`),
    not a claim boundary, and collapsed into one leaf it would shrink the
    claim (`src/auth/**` minus http) instead of reproducing it."""
    out = list(body.get(field) or [])
    subs = body.get("subgroups") or {}
    siblings = {g for leaf in subs.values() for g in (leaf.get(field) or [])
                if not g.startswith("!")}
    for leaf in subs.values():
        _union_into(out, [g for g in (leaf.get(field) or [])
                          if not (g.startswith("!") and g[1:] in siblings)])
    return out


def merge_additive(committed, assembled, claims):
    """Additive, never-clobber merge (spec §5).

    committed/assembled: {name: body} where a body is a leaf
    {"match", "tests", "panels"[, "exclude"]} or a parent
    {"subgroups": {sub: leaf}} (layers, 5.2). claims: {name: [file]} -- the
    assembled groups that claimed previously-unassigned files (from
    discovery.assign_by_catalog). A group that claims nothing new is dropped
    as redundant. Committed entries are never rewritten:

    - new name           -> adopted as proposed (leaf or parent); `new_groups`
    - committed leaf     -> only EXTENDED with globs it does not carry. When
                            the assembled side is a parent, its subgroup globs
                            extend the leaf (minus the carrier's partition
                            negations, which would shrink the committed claim)
                            and the layers are NOT introduced (`layers_dropped`):
                            a committed leaf stays a leaf.
    - committed parent   -> untouched, `skipped_committed_parent`: the owner's
                            subgroup structure is theirs to edit.
    """
    merged = {name: _copy_body(body) for name, body in committed.items()}
    diff = {"new_groups": [], "extended_groups": [], "dropped_redundant": [],
            "layers_dropped": [], "skipped_committed_parent": []}
    for name, body in assembled.items():
        if not claims.get(name):
            diff["dropped_redundant"].append(name)
            continue
        subs = body.get("subgroups") or {}
        if name not in merged:
            if subs:
                merged[name] = {"subgroups": _copy_body({"subgroups": subs})["subgroups"]}
                diff["new_groups"].append(
                    {"name": name, "match": _all_globs(body, "match"),
                     "panels": [], "subgroups": list(subs)})
            else:
                merged[name] = {"match": list(body.get("match", [])),
                                "tests": list(body.get("tests", [])),
                                "panels": list(body.get("panels", []))}
                diff["new_groups"].append(
                    {"name": name, "match": list(body.get("match", [])),
                     "panels": list(body.get("panels", [])), "subgroups": []})
            continue
        existing = merged[name]
        if existing.get("subgroups"):
            diff["skipped_committed_parent"].append(name)
            continue
        new_match = [p for p in _all_globs(body, "match") if p not in existing.get("match", [])]
        new_tests = [t for t in _all_globs(body, "tests") if t not in existing.get("tests", [])]
        if new_match or new_tests:
            existing["match"] = list(existing.get("match", [])) + new_match
            existing["tests"] = list(existing.get("tests", [])) + new_tests
            diff["extended_groups"].append(
                {"name": name, "added_match": new_match, "added_tests": new_tests})
        if subs:
            diff["layers_dropped"].append({"name": name, "layers": list(subs)})
    return merged, diff


def _yaml_leaf(body):
    """Only the non-empty leaf fields, in schema order."""
    entry = {}
    for key in ("match", "tests", "panels", "exclude"):
        vals = body.get(key) or []
        if vals:
            entry[key] = list(vals)
    return entry


def dump_groups_yaml(groups, header=True, exclude_paths=None):
    """Serialize a groups mapping to canonical mapping-form groups.yml text.
    Insertion order preserved; only non-empty fields emitted; a parent body
    (`subgroups`) nests its leaves under the parent name (the #1305 schema);
    round-trips through groups_schema.parse_groups. yaml.safe_dump handles
    quoting of indicator-leading scalars (e.g. '**/auth/**').

    `exclude_paths` (#1504) is carried through as a top-level sibling of
    `groups:`. It is NOT part of the mapping this function otherwise shapes, so
    a draft written without it silently dropped a committed exclusion -- and
    the operator is told to move the draft over the committed file. Omitted
    entirely when empty, so a repo that never had the key does not gain one."""
    cleaned = {}
    for name, body in groups.items():
        subs = body.get("subgroups")
        if isinstance(subs, dict) and subs:
            cleaned[name] = {sub: _yaml_leaf(leaf) for sub, leaf in subs.items()}
        else:
            cleaned[name] = _yaml_leaf(body)
    document = {"groups": cleaned}
    if exclude_paths:
        document["exclude_paths"] = list(exclude_paths)
    body_text = yaml.safe_dump(document, sort_keys=False,
                               default_flow_style=False, allow_unicode=True)
    if not header:
        return body_text
    return ("# panopticon groups catalog (matrix form) -- match/tests/panels/exclude.\n"
            "# gitignore-flavored globs; first matching group wins; edit and commit.\n"
            "# A group whose keys are names (no match:) is a parent; its subgroups\n"
            "# are its layers and roll up to it in the report.\n"
            + body_text)
