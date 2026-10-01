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

Glob matching uses bounded bitset transitions, never backtracking regexes.
Literal comparisons and anchored-prefix rejection avoid most corpus work;
the general engine uses O(tokens * path length) bounded work and O(tokens)
matching state. Discovery's total cost still multiplies files by patterns.
"""
import re
import sys
from functools import lru_cache

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

# #1757 (AGT-1355709320), owner ruling 2026-09-25: a target-authored
# `exclude_paths:` may not remove a file the objective SEC floor matches from the
# SEC domain. A review cell is (group x domain) and no domain can be restricted
# to a subset of a group's files, so those files get a GROUP of their own that
# reviews SEC and nothing else -- minted under this name by
# `exclude_carve_out.install`, and recognised by `phases/coverage.py` through the
# marker field below. Both names live HERE, with the residual sink they are
# reserved alongside: this module owns the authored-name vocabulary, every reader
# of a committed config already has it, and the carve-out module is the only
# other place that needs them.
SEC_CARVE_OUT_SINK = "exclude_paths_sec_carve_out"
SEC_CARVE_OUT_MARKER = "sec_carve_out"

# The MINTED top-level names, with the owner each is reserved for. A committed
# group of one of these names would write the same
# `findings-<group>-<domain>.json` as the minted one and silently clobber a cell,
# so they are refused at the source (`_reserved_name_conflicts`).
_MINTED_SINKS = ((RESIDUAL_SINK, "the unmatched-file sink"),
                 (SEC_CARVE_OUT_SINK, "the #1757 SEC carve-out"))

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
_warned_globs: set[tuple[str, str]] = set()


class _GlobMatcher:
    """Bitset glob NFA with literal fast paths, without regex or recursion.

    Bit i means the first i tokens match the consumed path prefix. A second
    bitset tracks nonempty, unfinished segments for **/. Epsilon transitions
    skip wildcards; precomputed doubling masks close whole runs in at most
    five shifts under the star cap. Each bitset has at most 258 bits, including
    the accepting state and the trailing-slash expansion. Work is bounded by
    O(tokens * path length), with O(tokens) bits of per-match state.
    ``pattern`` is diagnostic text; matching returns True or None.
    """

    def __init__(self, pattern: str, tokens: tuple[str, ...] | None = None,
                 anchored: bool = True):
        self.pattern = pattern
        self._valid = tokens is not None
        self._anchored = anchored
        self._literal: str | None = None
        self._prefix = ""
        self._basename_suffix = ""
        self._letters: dict[str, int] = {}
        self._star = self._globstar = self._directory = self._question = 0
        self._closures: list[tuple[int, int]] = []
        self._accept = 1 << len(tokens or ())
        epsilon = 0
        prefix: list[str] = []
        for i, atom in enumerate(tokens or ()):
            source, destination = 1 << i, 1 << (i + 1)
            if atom in ("*", "**", "**/"):
                epsilon |= source
                if atom == "*":
                    self._star |= destination
                elif atom == "**":
                    self._globstar |= destination
                else:
                    self._directory |= destination
            elif atom == "?":
                self._question |= source
            else:
                self._letters[atom] = self._letters.get(atom, 0) | source
                if len(prefix) == i:
                    prefix.append(atom)
        self._prefix = "".join(prefix)
        if tokens is not None and len(prefix) == len(tokens):
            self._literal = self._prefix
            self._basename_suffix = "/" + self._literal
        shift = 1
        while epsilon:
            self._closures.append((epsilon, shift))
            # Sources with a run of twice as many epsilon edges ahead.
            epsilon &= epsilon >> shift
            shift *= 2
        self._start = 1
        for mask, shift in self._closures:
            self._start |= (self._start & mask) << shift

    def match(self, path: str) -> bool | None:
        if not self._valid:
            return None
        if self._literal is not None:
            return True if (path == self._literal or (
                not self._anchored and path.endswith(self._basename_suffix))) else None
        if self._anchored and not path.startswith(self._prefix):
            return None
        previous, partial = self._start, 0
        letters = self._letters
        star, globstar = self._star, self._globstar
        directory, question = self._directory, self._question
        closures = self._closures
        for char in path:
            if char == "/":
                current = ((previous & letters.get(char, 0)) << 1) | (
                    previous & globstar) | partial
                # An unanchored pattern can restart at every basename boundary.
                if not self._anchored:
                    current |= 1
                partial = 0
            else:
                current = ((previous & (letters.get(char, 0) | question)) << 1) | (
                    previous & (star | globstar))
                partial = (previous | partial) & directory
            for mask, shift in closures:
                current |= (current & mask) << shift
            previous = current
        return True if previous & self._accept else None


def glob_to_re(pat, label="config"):
    """Compile one gitignore-flavored glob to a bounded repo-path matcher.

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
    repo-relative FILE path never does -- a silent zero-match). Newlines are
    ordinary filename characters, and matches consume the entire path.
    """
    # A glob this compiler cannot translate faithfully must never be
    # translated wrongly (#1501). A setup proposal carrying one is refused
    # outright, but a committed root config's parse errors are disclosed and
    # NOT blocking (this module's standing policy, `_committed_matrix`), so
    # one still reaches this compiler -- where the old behaviour was to
    # `re.escape` the brackets into a literal that claimed the wrong files.
    # Disclose and return a never-matching matcher instead: refuse to guess.
    defect = glob_defect(pat)
    if defect:
        if (label, pat) not in _warned_globs:
            _warned_globs.add((label, pat))
            print("%s: glob %r matches nothing: %s (#1501)"
                  % (label, pat[:80], defect), file=sys.stderr)
        return _GlobMatcher(r"(?!)")
    # Collapse runs of adjacent segment-crossing wildcards BEFORE compiling.
    # `**/**/.../x` compiles to sequential `(?:[^/]+/)*` quantifiers -- the
    # textbook catastrophic-backtracking ReDoS shape -- and repo-supplied
    # root-config `match:` patterns reach this compiler, so a hostile repo
    # could hang discovery (run-4 self-scan). Adjacent `**`
    # segments are semantically redundant, so fold each run down to one.
    pat = re.sub(r"(?:\*\*/)+", "**/", pat)
    pat = re.sub(r"\*\*\*+", "**", pat)
    # Preserve the existing authored-pattern complexity limits, after collapse.
    # These are validation policy, not the execution bound: even an accepted
    # twenty-star pattern can stall a backtracking regex. _GlobMatcher bounds
    # work for every accepted pattern independently of these limits.
    if len(pat) > 256 or pat.count("*") > 20:
        print("%s: ignoring over-complex glob pattern "
              "(len=%d, wildcards=%d): %r"
              % (label, len(pat), pat.count("*"), pat[:80]), file=sys.stderr)
        return _GlobMatcher(r"(?!)")   # matches nothing
    anchored = "/" in pat[:-1] if pat.endswith("/") else "/" in pat
    if pat.startswith("/"):
        pat = pat[1:]
    # `docs/` == `docs/**`: the directory tree, never the directory's own
    # path. Anchoring was already decided on the authored form above, so an
    # unanchored `docs/` still means "a docs directory at any depth", exactly
    # as gitignore reads it.
    if pat.endswith("/"):
        pat += "**"
    return _compile_glob(pat, anchored)


@lru_cache(maxsize=512)
def _compile_glob(pat: str, anchored: bool) -> _GlobMatcher:
    """Cache only validated, normalized patterns; disclosures stay per caller.

    Keys are at most 258 characters after trailing-slash expansion. Anchoring
    is part of the key because it is decided before stripping a leading slash.
    """
    out, tokens, i = [], [], 0
    while i < len(pat):
        c = pat[i]
        if c == "*":
            if pat[i:i + 3] == "**/":
                tokens.append("**/")
                out.append(r"(?:[^/]+/)*")
                i += 3
            elif pat[i:i + 2] == "**":
                tokens.append("**")
                out.append(r"[\s\S]*")
                i += 2
            else:
                tokens.append("*")
                out.append(r"[^/]*")
                i += 1
        elif c == "?":
            tokens.append("?")
            out.append(r"[^/]")
            i += 1
        else:
            tokens.append(c)
            out.append(re.escape(c))
            i += 1
    body = "".join(out)
    if not anchored:
        body = r"(?:[\s\S]*/)?" + body
    return _GlobMatcher("^" + body + r"\Z", tuple(tokens), anchored)


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
    out: set[str] = set()
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
        tests: list[str] = []
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


def _reserved_name_conflicts(groups):
    """Yield (id, message) for every authored id that collides with another
    id or a machine-minted name -- a case twin, a chunk twin, or the reserved
    residual-sink name. `_reserved_name_errors` and `colliding_ids` are both
    thin views over this one generator, so the collision rules exist once.

    Operates on FLAT ids, which is what makes it scope-correct for free:
    `Product:API` chunks to `Product:API_1`, so an authored `Product:API_1`
    collides while a top-level `API_1` does not.
    """
    by_key: dict[str, str] = {}
    for gid in sorted(groups):
        key = gid.casefold()
        earlier = by_key.get(key)
        if earlier is not None:
            yield gid, (
                f"group {gid}: collides with group {earlier} on "
                f"case-insensitive findings artifacts -- rename one group")
        else:
            by_key[key] = gid
    for gid in sorted(groups):
        m = _CHUNK_SUFFIX_RE.match(gid)
        base = m.group("base") if m else None
        owner = by_key.get(base.casefold()) if base is not None else None
        if owner is not None:
            yield gid, (
                f"group {gid}: collides with the chunk names of group {owner} "
                f"(an oversize group splits into {owner}_1, {owner}_2, ...). Both "
                f"would write findings-{gid}-<domain>.json and one would "
                f"silently clobber the other -- rename it")
        # Top-level only: a minted sink owns its own name and its chunks.
        # A subgroup `Foo:Ungrouped` is namespaced and cannot collide.
        folded = (gid.casefold(), base.casefold() if base is not None else None)
        for sink, owner in _MINTED_SINKS:
            if ":" in gid or sink.casefold() not in folded:
                continue
            yield gid, (
                f"group {gid}: {sink!r} and {sink}_<n> are "
                f"reserved for {owner}; a group named this "
                f"would share a findings file with it -- rename it")


def _reserved_name_errors(groups):
    """The messages `_reserved_name_conflicts` yields, id dropped."""
    return [message for _gid, message in _reserved_name_conflicts(groups)]


def colliding_ids(groups):
    """The ids `_reserved_name_conflicts` yields, message dropped: every
    authored id that collides with another id or a machine-minted name."""
    return {gid for gid, _message in _reserved_name_conflicts(groups)}


# The one wording for "this config still uses the 4.x list form", returned as a
# disclosure so every reader prints the same line (#2229).
LEGACY_LIST_NOTICE = ("legacy list form -- normalizing to mapping; "
                      "re-run --setup to rewrite")


def normalize_groups_mapping(raw):
    """Return (mapping, errors, disclosures) for a committed `groups:` value.

    The ONE normalizer (#2229, ARC-1814846877): five readers each carried a
    copy of this, and one of them a different predicate entirely. A list
    `groups: [{name: ..., ...}]` is the 4.x form (#run7 ARC-D2B) -- it becomes
    a mapping keyed by `name`, entries that are not a named mapping are
    dropped, and the caller gets `LEGACY_LIST_NOTICE` to print. An absent or
    empty value is `{}` with nothing to say. Anything else that is not a
    mapping is ONE named error rather than an AttributeError inside whichever
    reader looked first (#2189: `groups: API`).
    """
    errors: list[str] = []
    disclosures: list[str] = []
    raw = raw or {}
    if isinstance(raw, list):
        disclosures.append(LEGACY_LIST_NOTICE)
        raw = {g.get("name"): g for g in raw
               if isinstance(g, dict) and g.get("name")}
    if not isinstance(raw, dict):
        errors.append("groups must be a mapping/object")
        raw = {}
    return raw, errors, disclosures


def is_leaf_body(body):
    """True iff an authored group body is a LEAF: it carries a RESERVED field
    (match/tests/panels/exclude). The leaf-vs-parent rule lives here and
    nowhere else (#2229 -- it had three homes). A None or non-mapping body is
    a leaf for back-compat with the pre-subgroup schema, and an empty mapping
    is one too: `parse_groups` refuses it as an empty definition rather than
    reading it as a parent with no subgroups.
    """
    if not isinstance(body, dict) or not body:
        return True
    return bool(RESERVED & set(body))


def committed_bodies(groups):
    """A `parse_groups` result as the nested AUTHORED shape a never-clobber
    reader merges against: `{name: {match, tests, panels, exclude}}` for a
    top-level leaf and `{name: {"subgroups": {sub: leaf}}}` for a parent
    (#1305), in the order the ids arrived.

    The one un-flattener (#2229): `discovery._committed_matrix` and
    `setup_flow.migrate_config` each had their own, and both re-read the
    AUTHORED bodies after validating them -- which is how a scalar `match:`
    reached a catalog character-split and a name the schema had just rejected
    came back anyway (#2189). Built from the VALIDATED leaves instead, so
    nothing here is a glob the schema refused. `panels`/`exclude` are the
    parsed domain SETS, so they come back sorted rather than in authored
    order; the authored file is never rewritten from this.
    """
    out: dict[str, dict] = {}
    for gid, leaf in groups.items():
        body = {"match": list(leaf.get("match") or []),
                "tests": list(leaf.get("tests") or []),
                "panels": sorted(leaf.get("floor") or ()),
                "exclude": sorted(leaf.get("exclude") or ())}
        parent = leaf.get("parent")
        if parent and parent != gid:
            subs = out.setdefault(parent, {"subgroups": {}})["subgroups"]
            subs[gid[len(parent) + 1:]] = body
        else:
            out[gid] = body
    return out


def parse_groups(doc):
    """Return (groups, errors). `groups` maps a flat review-unit id -> a
    normalized group dict with keys match/tests/floor/exclude/parent.

    A top-level name whose body is a leaf yields id == name, parent == name.
    A top-level name whose body is a parent (keys are subgroup names, each a
    leaf) yields, for each subgroup `sub`, id "name:sub" with parent == name.
    """
    groups = {}
    # The legacy-list disclosure is dropped here -- this function is pure and
    # returns two values by contract. A reader that has a stderr to print it on
    # calls `normalize_groups_mapping` itself and passes the mapping in.
    groups_dict, errors, _disclosures = normalize_groups_mapping(
        (doc or {}).get("groups"))
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
        # erroring) leaf rather than as an empty parent -- which is what
        # `is_leaf_body` says about an empty mapping too.
        if raw_was_none or raw_was_non_dict or is_leaf_body(raw):
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

            if not is_leaf_body(sub_raw):
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
    errors: list[str] = []
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
    # `exclude_paths:` documents no negation. `glob_to_re` would honour a
    # leading `!` while discovery's walk would not, so a negated entry is
    # refused here, before either consumer can read it differently.
    negated = [g for g in globs if g.lstrip().startswith("!")]
    if negated:
        errors.append("exclude_paths entries must not use `!` negation: %s"
                      % ", ".join(repr(g) for g in negated))
        globs = [g for g in globs if g not in negated]
    errors.extend(glob_errors("exclude_paths", "entry", globs))
    return globs, errors
