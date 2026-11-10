"""Catalog matching and scoped assignment for discovery."""
import functools
import os

from scripts import groups_schema
from scripts import tests_axis


def _glob_to_re(pat):
    """Compile one gitignore-flavored glob to a regex over repo-relative paths.

    The compiler itself is `groups_schema.glob_to_re` (#1740 fix round 2): the
    tool side matches the SAME committed `exclude_paths:` lines and must read
    them the same way, so the translator lives beside `glob_defect` in the
    module that owns the glob vocabulary. This wrapper is discovery's own name
    for it, and pins the label its disclosures carry.
    """
    return groups_schema.glob_to_re(pat, "discovery")


def match_patterns(path, patterns):
    """gitignore-style decision for one path against an ordered pattern list.

    Later patterns override earlier ones (last match wins); a ``!`` prefix
    negates, so ``["skill/scripts/**", "!skill/scripts/tools/**"]`` claims
    the scripts tree except the tools subtree.
    """
    matched = False
    for pat in patterns:
        negate = pat.startswith("!")
        if negate:
            pat = pat[1:]
        if _glob_to_re(pat).match(path):
            matched = not negate
    return matched

def _decide(path, tagged):
    """gitignore-style decision over a TAGGED pattern list ``[(glob, tag)]``
    (tag is ``"match"`` or ``"tests"``). Last match wins, ``!`` negates.
    Returns ``(matched, tag, glob)`` for the deciding pattern so the caller
    can tell whether a positive claim came from the scoped ``tests:`` axis."""
    matched, tag, glob = False, None, None
    for pat, src in tagged:
        negate = pat.startswith("!")
        if _glob_to_re(pat[1:] if negate else pat).match(path):
            matched, tag, glob = (not negate), src, pat
    return matched, tag, glob


_VOCAB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "capability_vocabulary.yml")


@functools.lru_cache(maxsize=1)
def _capability_aliases():
    """``{canonical name: [alias labels]}`` from the shipped capability
    vocabulary, so a committed `Auth` group's `tests:` globs also credit
    `tests/authentication/`. Empty when the file is unreadable: aliases only
    ever ADD credit, so running without them is safe."""
    import yaml
    from scripts import setup_proposal
    try:
        vocab, _ = setup_proposal.load_vocabulary(_VOCAB_PATH)
    except (OSError, ValueError, yaml.YAMLError):
        return {}
    # The loader keeps the raw entry; re-check the shape so a scalar `aliases`
    # (a loader ERROR, not a crash) cannot explode into per-character labels.
    return {name: [a for a in (entry.get("aliases") or []) if isinstance(a, str)]
            if isinstance(entry.get("aliases"), list) else []
            for name, entry in vocab.get("entries", {}).items()}


def assign_scoped(files, catalog, aliases=None, prefixes=None):
    """Assign files to catalog groups (#499) with SCOPED `tests:` globs (5.2 §4.2).

    Groups claim files in catalog order, first match wins, each file lands in
    at most one group. Inside a group, ``match`` + ``tests`` form ONE
    gitignore-style last-match-wins list. The one 5.2 addition: when the
    deciding positive pattern is a WILDCARD ``tests:`` glob, the file credits
    the group only if it lies under one of the group's distinguishing literal
    ``match:`` prefixes or its path carries the group's name or an alias
    (``tests_axis.scope_ok``). Otherwise the file falls through to the next
    group. Literal ``tests:`` paths always credit.

    Sibling subgroups share their parent's distinguishing prefixes, so a
    wildcard ``tests:`` glob on ``Auth:Core`` would otherwise credit a test
    that sits under ``Auth:API``'s own ``match:`` directory just because
    ``Auth:Core`` is listed first. When the deciding pattern is a wildcard
    ``tests:`` glob on a subgroup and a SIBLING that also matches the file
    owns a deeper literal prefix over it, the file is left for that sibling.

    ``aliases`` is ``{canonical name: [labels]}`` (default: the shipped
    vocabulary); ``prefixes`` is ``tests_axis.distinguishing_prefixes`` of the
    catalog (pass the FULL catalog's when assigning a partial one).

    Returns ``(assigned, leftovers, warnings)``: ``assigned`` maps group ->
    sorted files (empty groups omitted), ``leftovers`` are files no group
    credited, ``warnings`` name every wildcard ``tests:`` glob that matched
    files but credited none -- the "your glob is too broad" signal."""
    if aliases is None:
        aliases = _capability_aliases()
    if prefixes is None:
        prefixes = tests_axis.distinguishing_prefixes(catalog)
    matchable = []
    tagged_of, own_prefixes, parent_of = {}, {}, {}
    for name, g in catalog.items():
        tagged = ([(p, "match") for p in (g.get("match") or [])]
                  + [(p, "tests") for p in (g.get("tests") or [])])
        if not tagged:
            continue
        labels = tests_axis.group_labels(name) or [str(name)]
        extra = labels[1:] + [a for lab in labels for a in aliases.get(lab, [])]
        keys = tests_axis.name_keys(labels[0], extra)
        matchable.append((name, tagged, keys, prefixes.get(labels[0], [])))
        tagged_of[name] = tagged
        if len(labels) > 1:
            parent_of[name] = labels[0]
            own_prefixes[name] = sorted({tests_axis.literal_prefix(p)
                                         for p in (g.get("match") or [])
                                         if isinstance(p, str) and not p.startswith("!")
                                         and tests_axis.literal_prefix(p)})

    def own_depth(name, f):
        return max([len(p) for p in own_prefixes.get(name, []) if tests_axis._under(f, p)]
                   or [0])

    def deeper_sibling_claims(name, f):
        mine = own_depth(name, f)
        return any(own_depth(sib, f) > mine and _decide(f, tagged_of[sib])[0]
                   for sib, parent in parent_of.items()
                   if sib != name and parent == parent_of[name])

    assigned: dict[str, list[str]] = {name: [] for name, *_ in matchable}
    seen: dict[tuple[str, str], list[int]] = {}                       # (group, glob) -> [matched, credited]
    leftovers = []
    for f in files:
        for name, tagged, keys, pfx in matchable:
            matched, tag, glob = _decide(f, tagged)
            if not matched:
                continue
            if tag == "tests" and not tests_axis.is_literal_glob(glob):
                tally = seen.setdefault((name, glob), [0, 0])
                tally[0] += 1
                if not tests_axis.scope_ok(f, keys, pfx):
                    continue        # a later group may still claim it
                if name in parent_of and deeper_sibling_claims(name, f):
                    continue        # the sibling whose directory it is takes it
                tally[1] += 1
            assigned[name].append(f)
            break
        else:
            leftovers.append(f)
    warnings = [
        ("%s: tests glob %r matched %d file(s) but credited none (a wildcard "
         + "tests: glob is scoped to the group's match: prefixes and name/aliases; "
         + "move it to match: to claim unconditionally)") % (name, glob, hit)
        for (name, glob), (hit, credited) in sorted(seen.items())
        if hit and not credited]
    return ({n: sorted(fs) for n, fs in assigned.items() if fs},
            sorted(leftovers), warnings)


def assign_by_catalog(files, catalog):
    """``assign_scoped`` for callers that want the 5.0 two-tuple. Warnings are
    dropped here; ``catalog_groups`` (the scan path) reports them."""
    assigned, leftovers, _ = assign_scoped(files, catalog)
    return assigned, leftovers
