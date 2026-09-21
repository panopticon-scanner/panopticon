"""Parse + validate the 5.0 matrix in the root config (match/tests/panels/exclude).

Extends the 4.x matrix (match-only) with the matrix fields. Pure: takes an
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
import sys

DOMAINS = frozenset(
    {"SEC", "COD", "ARC", "TST", "QAL", "AGT", "DAT", "OPS", "ACC", "LNG"})

# #5.0-02: group names are interpolated into artifact FILENAMES and into trusted
# reviewer prompts, so a name from a (possibly hostile) committed config must
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


# #1501: the committed config and the Commons catalog are documented as taking
# "gitignore-flavored globs", but `discovery._glob_to_re` is a hand-rolled
# translator, and a glob it cannot translate does not error -- it renders an
# EMPTY group and inflates `Ungrouped`, the signal we read as catalog
# coverage. So the compiler now handles gitignore's trailing-slash directory
# form exactly, and this is the one place that names the form it cannot: a
# character class, whose safe translation needs bracket-content parsing this
# compiler does not do (it `re.escape`s the brackets, so `*.[ch]` used to
# claim a file literally named `main.[ch]` and never `main.c`).
#
# Lives here, in the pure schema module, because this is where authored globs
# are validated; `discovery` imports it for the same reason `setup_proposal`
# does -- one rule, three callers, never a second copy.
def glob_defect(pattern):
    """The reason `pattern` cannot be compiled faithfully, or None.

    A returned string is a complete operator-facing sentence naming the fix.
    """
    if not isinstance(pattern, str):
        return None
    if "[" in pattern:
        return ("character classes are not supported -- write each spelling "
                "as its own glob ('*.c' and '*.h', not '*.[ch]'), or use '?' "
                "for a single character")
    return None


def glob_errors(label, field, globs):
    """`glob_defect` over one authored list, as parse errors."""
    return ["%s: %s glob %r is invalid: %s" % (label, field, g, defect)
            for g in globs for defect in [glob_defect(g)] if defect]



# One disclosure per (caller, pattern): `glob_to_re` is called per (path,
# pattern), so an unconditional print would emit a line per file scanned.
_warned_globs = set()


def glob_to_re(pat, label="config"):
    """Compile one gitignore-flavored glob to a regex over repo-relative paths.

    #1740 fix round 2: THE translator, for every consumer of a committed glob.
    It lived in `discovery` while `run_tools`/`ingest_tools` matched the same
    `exclude_paths:` lines with `fnmatch`, so one committed line meant two
    different things -- `tests/*` excluded the whole subtree from the gate and
    only the direct children from discovery, and `docs/` excluded a tree from
    discovery and nothing at all from the gate. `label` names the caller in the
    two disclosures below, which is all that moving it here changed.

    Semantics (#499): ``*`` and ``?`` stay within a path segment, ``**``
    crosses segments, and a pattern containing no ``/`` matches the basename
    at any depth (gitignore's unanchored form). Patterns with a ``/`` are
    anchored to the repo root, and a TRAILING ``/`` claims the directory and
    everything under it (#1501: ``docs/`` is gitignore's most natural idiom
    and used to compile to a regex requiring the path to end in ``/``, which a
    repo-relative FILE path never does -- a silent zero-match).
    """
    # A glob this compiler cannot translate faithfully must never be
    # translated wrongly (#1501). A setup proposal carrying one is refused
    # outright, but a committed root config's parse errors are disclosed and
    # NOT blocking (this module's standing policy, `_committed_matrix`), so
    # one still reaches this compiler -- where the old behaviour was to
    # `re.escape` the brackets into a literal that claimed the wrong files.
    # Disclose and compile to a never-matching regex instead: refuse to guess.
    defect = glob_defect(pat)
    if defect:
        if (label, pat) not in _warned_globs:
            _warned_globs.add((label, pat))
            print("%s: glob %r matches nothing: %s (#1501)"
                  % (label, pat[:80], defect), file=sys.stderr)
        return re.compile(r"(?!)")
    # Collapse runs of adjacent segment-crossing wildcards BEFORE compiling.
    # `**/**/.../x` compiles to sequential `(?:[^/]+/)*` quantifiers -- the
    # textbook catastrophic-backtracking ReDoS shape -- and repo-supplied
    # root-config `match:` patterns reach this compiler, so a hostile repo
    # could hang discovery (run-4 self-scan). Adjacent `**`
    # segments are semantically redundant, so fold each run down to one.
    pat = re.sub(r"(?:\*\*/)+", "**/", pat)
    pat = re.sub(r"\*\*\*+", "**", pat)
    # #run7 SEC-H4A: the `**`-collapse above only tames adjacent `**` runs. A
    # SINGLE-`*` pattern like `a*a*...Z` compiles to `a[^/]*a[^/]*...Z` -- the
    # classic (.*a)+ catastrophic-backtracking shape (empirically >5s on a
    # moderate filename), unaffected by the collapse. Atomic groups can't fix it
    # (a glob `*` MUST backtrack so a trailing literal can match), so bound
    # complexity AFTER the collapse: a legitimate glob has a handful of wildcards,
    # so an over-long / over-wildcarded pattern is hostile or degenerate --
    # disclose it and compile to a never-matching regex rather than hang discovery
    # (which reads the root config from the untrusted redteam target, BEFORE
    # dispatch).
    if len(pat) > 256 or pat.count("*") > 20:
        print("%s: ignoring over-complex glob pattern "
              "(len=%d, wildcards=%d): %r"
              % (label, len(pat), pat.count("*"), pat[:80]), file=sys.stderr)
        return re.compile(r"(?!)")   # matches nothing
    anchored = "/" in pat[:-1] if pat.endswith("/") else "/" in pat
    if pat.startswith("/"):
        pat = pat[1:]
    # `docs/` == `docs/**`: the directory tree, never the directory's own
    # path. Anchoring was already decided on the authored form above, so an
    # unanchored `docs/` still means "a docs directory at any depth", exactly
    # as gitignore reads it.
    if pat.endswith("/"):
        pat += "**"
    out, i = [], 0
    while i < len(pat):
        c = pat[i]
        if c == "*":
            if pat[i:i + 3] == "**/":
                out.append(r"(?:[^/]+/)*")
                i += 3
            elif pat[i:i + 2] == "**":
                out.append(r".*")
                i += 2
            else:
                out.append(r"[^/]*")
                i += 1
        elif c == "?":
            out.append(r"[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    body = "".join(out)
    if not anchored:
        body = r"(?:.*/)?" + body
    return re.compile("^" + body + "$")


def matched_glob(path, patterns, label="config"):
    """The committed glob that EXCLUDES `path`, or None (#1740 fix round 2).

    gitignore's last-match-wins over an ordered list, with `!` negating, which
    is what `discovery.match_patterns` does for `match:`/`tests:` -- the same
    rule, returning the pattern instead of a bool because the tool side has to
    disclose WHICH glob dropped a finding (`security_gate`'s verdict line, the
    ingest's `excluded_out` rows).

    `path` must already be repo-relative and "/"-separated; every caller
    normalizes before it asks.
    """
    hit = None
    for pat in patterns or ():
        if not isinstance(pat, str) or not pat:
            continue
        negate = pat.startswith("!")
        raw = pat[1:] if negate else pat
        if raw and glob_to_re(raw, label).match(path):
            hit = None if negate else pat
    return hit


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
    errors.extend(glob_errors("group %s" % name, "match", match))
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
    errors.extend(glob_errors("group %s" % name, "tests", tests))
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
    # parse_groups, so a list-valued config silently became {} here and EVERY
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
    errors.extend(glob_errors("exclude_paths", "entry", globs))
    return globs, errors
