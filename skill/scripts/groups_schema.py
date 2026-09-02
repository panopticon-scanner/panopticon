"""Parse + validate the 5.0 matrix `groups.yml` (match/tests/panels/exclude).

Extends the 4.x groups.yml (match-only) with the matrix fields. Pure: takes an
already-loaded dict, returns (groups, errors). No file I/O. See spec §3.

5.1 adds one level of subgrouping: a top-level group body is either a LEAF
(contains a reserved field: match/tests/panels/exclude) or a PARENT (its keys
are subgroup names, each itself a leaf). `parse_groups` flattens both shapes
into a single dict keyed by review-unit id: a leaf `Foo` -> id "Foo", and a
subgroup `Bar` under parent `Baz` -> id "Baz:Bar". Every value carries an
explicit `parent` field (self for a leaf, the parent's name for a subgroup).
Subgroups cannot themselves be parents ("one nesting level only").
"""
import re

DOMAINS = frozenset(
    {"SEC", "COD", "ARC", "TST", "QAL", "AGT", "DAT", "OPS", "ACC", "LNG"})

# #5.0-02: group names are interpolated into artifact FILENAMES and into trusted
# reviewer prompts, so a name from a (possibly hostile) committed groups.yml must
# be a strict token — no path separators, '..', leading dot, control chars, or
# trailing newline, which would escape .panopticon or inject into the task text.
# ':' is deliberately excluded from the allowed charset: it is reserved as the
# internal flat-id delimiter between a parent and its subgroup, never part of
# an authored name.
_GROUP_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")

# A group body is a leaf iff it contains any of these fields; otherwise its
# keys are taken to be subgroup names (a parent).
RESERVED = frozenset({"match", "tests", "panels", "exclude"})

# The residual sink's name, mirrored from discovery.UNGROUPED_SINK. This module
# stays pure (no imports from discovery), so the two are pinned equal by a test
# rather than by an import.
RESIDUAL_SINK = "Ungrouped"

# A group that outgrows --max-per-group splits into `<id>_1`, `<id>_2`, ..., and
# the unmatched residual lands in `Ungrouped_1`, ... . Those names are minted
# from the SAME flat-id space an author writes in, so an authored `API_1`
# alongside an authored `API` is indistinguishable from API's first chunk: both
# emit findings-API_1-<domain>.json and one silently clobbers the other. The
# ambiguity lives in the name itself, so it is rejected at the source rather
# than resolved downstream.
_CHUNK_SUFFIX_RE = re.compile(r"(?P<base>.+)_\d+\Z")


def _as_domain_set(name, field, raw, errors):
    out = set()
    if raw is None:
        return out
    if not isinstance(raw, list):
        errors.append(f"group {name}: {field} must be a list")
        return out
    for d in raw:
        if not isinstance(d, str) or d not in DOMAINS:
            errors.append(f"group {name}: {field} {d!r} is not a known domain")
        else:
            out.add(d)
    return out


def _invalid_name(name):
    return not isinstance(name, str) or ".." in name or not _GROUP_NAME_RE.match(name)


def _name_error(name):
    return ("group name %r is invalid: must match "
            "[A-Za-z0-9][A-Za-z0-9_.-]{0,63} with no path separators, "
            "'..', or control characters (#5.0-02)" % (name,))


def _parse_leaf(name, raw, errors):
    """Parse a single leaf group body -> {match, tests, floor, exclude}.

    `name` is used only to label error messages (may be a flat id like
    "UI:Admin" for a subgroup). `raw` is assumed to already be a dict.
    """
    raw_match = raw.get("match")
    if not isinstance(raw_match, list) or not raw_match:
        errors.append(f"group {name}: match must be a non-empty list")
        match = []
    else:
        invalid_match = [x for x in raw_match if not isinstance(x, str) or not x.strip()]
        if invalid_match:
            errors.append(f"group {name}: match entries must be non-empty strings")
        match = [x for x in raw_match if isinstance(x, str) and x.strip()]
    raw_tests = raw.get("tests")
    if raw_tests is None:
        tests = []
    elif not isinstance(raw_tests, list):
        errors.append(f"group {name}: tests must be a list")
        tests = []
    else:
        invalid_tests = [x for x in raw_tests if not isinstance(x, str) or not x.strip()]
        if invalid_tests:
            errors.append(f"group {name}: tests entries must be non-empty strings")
        tests = [x for x in raw_tests if isinstance(x, str) and x.strip()]
    floor = _as_domain_set(name, "panels", raw.get("panels"), errors)
    exclude = _as_domain_set(name, "exclude", raw.get("exclude"), errors)
    for d in sorted(floor & exclude):
        errors.append(f"group {name}: {d} is in both floor and exclude")
    return {
        "match": match,
        "tests": tests,
        "floor": floor,
        "exclude": exclude,
    }


def _reserved_name_errors(groups):
    """Authored ids that collide with a machine-minted chunk name.

    Operates on FLAT ids, which is what makes it scope-correct for free:
    `Product:API` chunks to `Product:API_1`, so an authored `Product:API_1`
    collides while a top-level `API_1` does not.
    """
    errors = []
    for gid in sorted(groups):
        m = _CHUNK_SUFFIX_RE.match(gid)
        base = m.group("base") if m else None
        if base is not None and base in groups:
            errors.append(
                f"group {gid}: collides with the chunk names of group {base} "
                f"(an oversize group splits into {base}_1, {base}_2, ...). Both "
                f"would write findings-{gid}-<domain>.json and one would "
                f"silently clobber the other -- rename it")
        # Top-level only: the residual sink owns `Ungrouped` and its chunks.
        # A subgroup `Foo:Ungrouped` is namespaced and cannot collide.
        if ":" not in gid and RESIDUAL_SINK in (gid, base):
            errors.append(
                f"group {gid}: {RESIDUAL_SINK!r} and {RESIDUAL_SINK}_<n> are "
                f"reserved for the unmatched-file sink; a group named this "
                f"would share a findings file with it -- rename it")
    return errors


def parse_groups(doc):
    """Return (groups, errors). `groups` maps a flat review-unit id -> a
    normalized group dict with keys match/tests/floor/exclude/parent.

    A top-level name whose body is a leaf yields id == name, parent == name.
    A top-level name whose body is a parent (keys are subgroup names, each a
    leaf) yields, for each subgroup `sub`, id "name:sub" with parent == name.
    """
    groups, errors = {}, []
    groups_dict = (doc or {}).get("groups") or {}
    # #run7 ARC-D2B: accept the legacy list form `groups: [{name: ..., ...}]`.
    # load_catalog and _committed_matrix already normalize it, but _matrix_catalog
    # (the reader main() uses for --repo-scan grouping) went straight to
    # parse_groups, so a list-valued groups.yml silently became {} here and EVERY
    # committed group was dropped to Commons/._N. Normalize once in the owner.
    if isinstance(groups_dict, list):
        groups_dict = {g.get("name"): g for g in groups_dict
                       if isinstance(g, dict) and g.get("name")}
    if not isinstance(groups_dict, dict):
        errors.append("groups must be a mapping/object")
        groups_dict = {}
    for name, raw in groups_dict.items():
        if _invalid_name(name):
            errors.append(_name_error(name))
            continue

        raw_was_none = raw is None
        raw_was_non_dict = raw is not None and not isinstance(raw, dict)
        if raw_was_none:
            raw = {}
        elif raw_was_non_dict:
            errors.append(f"group {name}: definition must be a mapping")
            raw = {}

        if not raw_was_none and not raw_was_non_dict and not raw:
            # Authored as a literal empty mapping `{}` — always an error,
            # whether at leaf position or here at the top level.
            errors.append(f"group {name}: definition must not be empty")
            continue

        # None / non-dict bodies are coerced above to {} and, for back-compat
        # with the pre-subgroup schema, always parsed as a (defaults-only,
        # erroring) leaf rather than as an empty parent.
        if raw_was_none or raw_was_non_dict or (RESERVED & set(raw)):
            leaf = _parse_leaf(name, raw, errors)
            leaf["parent"] = name
            groups[name] = leaf
            continue

        # Parent: keys are subgroup names, each itself required to be a leaf.
        for sub, sub_raw in raw.items():
            if _invalid_name(sub):
                errors.append(_name_error(sub))
                continue
            flat_id = f"{name}:{sub}"

            sub_was_none = sub_raw is None
            sub_was_non_dict = sub_raw is not None and not isinstance(sub_raw, dict)
            if sub_was_none:
                sub_raw = {}
            elif sub_was_non_dict:
                errors.append(f"group {flat_id}: definition must be a mapping")
                sub_raw = {}

            if not sub_raw:
                errors.append(f"group {flat_id}: definition must not be empty")
                continue

            if not (RESERVED & set(sub_raw)):
                errors.append(f"group {flat_id}: subgroups cannot nest")
                continue

            leaf = _parse_leaf(flat_id, sub_raw, errors)
            leaf["parent"] = name
            groups[flat_id] = leaf
    errors.extend(_reserved_name_errors(groups))
    return groups, errors


def parse_exclude_paths(doc):
    """Return (globs, errors) for a top-level `exclude_paths:` list.

    `globs` is a list of non-empty string path-globs; `([], [])` when the key
    is absent. A non-list value is an error (globs == []). Non-string or
    empty-string entries are errors individually; the valid string entries
    are still kept.
    """
    errors = []
    raw = (doc or {}).get("exclude_paths")
    if raw is None:
        return [], errors
    if not isinstance(raw, list):
        errors.append("exclude_paths must be a list")
        return [], errors
    invalid = [x for x in raw if not isinstance(x, str) or not x.strip()]
    if invalid:
        errors.append("exclude_paths entries must be non-empty strings")
    globs = [x for x in raw if isinstance(x, str) and x.strip()]
    return globs, errors
