"""Pure helpers for the tests axis (5.2 spec §4).

Two jobs, both mechanical and both side-effect free:

1. Scoped `tests:` matching (`scope_ok`): a WILDCARD `tests:` glob credits a
   file to a vertical only if the file lies under one of the vertical's
   distinguishing literal `match:` prefixes, or its path carries the
   vertical's name or an alias. That is what makes `**/*_test.go` safe to
   write on every vertical instead of letting the first vertical swallow
   every test in the repo. Literal `tests:` paths always credit.
2. Path affinity (`attach_by_affinity`): under the Tests floor, a leftover
   test file attaches to the vertical whose `match:` prefix shares the most
   leading directories with it.

`discovery` owns the I/O (which catalog, which files); this module owns the
decisions so they can be tested exhaustively without a repo.
"""
import os
import re

TEST_TOKENS = frozenset({"test", "tests", "spec", "specs"})
# What discovery._glob_to_re treats as a wildcard: `*`, `**` and `?`. It has
# no character classes, so `[ab]` is a literal there and must be one here --
# the two matchers have to agree on what "literal" means (#1501).
_WILDCARD = re.compile(r"[*?]")
# `RateLimiting` -> Rate|Limiting; `HTTPServer` -> HTTP|Server; but an acronym
# plural (`APIs`, `IDs`) stays one token -- the word after the run must be a
# real word (>= 2 lowercase letters), not a lone `s`.
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z]{2})")
_SEPARATORS = re.compile(r"[^A-Za-z0-9]+")


def tokens(s):
    """Casefolded token run: `RateLimiting` / `rate_limiting` / `rate-limiting`
    all give ['rate', 'limiting']; `__tests__` gives ['tests'], `Identity &
    Access` gives ['identity', 'access'] (punctuation never forms a token)."""
    return [p.casefold() for p in _SEPARATORS.split(_CAMEL.sub("_", s or "")) if p]


def _singular(tok):
    # `tools` ~ `tool`, `adapters` ~ `adapter`; leave 3-letter tokens (`sms`)
    # and non-plural words alone -- this is a fold, not a stemmer.
    return tok[:-1] if len(tok) > 3 and tok.endswith("s") and not tok.endswith("ss") else tok


def _norm(toks):
    return tuple(_singular(t) for t in toks)


def name_keys(name, aliases=()):
    """Token tuples that identify a group: canonical name first, then aliases,
    plural-folded, empties and duplicates dropped. Position matters to
    `_carries`: only the canonical key (index 0) may match by prefix."""
    keys = []
    for label in [name] + list(aliases or []):
        key = _norm(tokens(label))
        if key and key not in keys:
            keys.append(key)
    return keys


def group_labels(group_id):
    """`Auth` -> ['Auth']; a subgroup id `Auth:API` -> ['Auth', 'API'] (either
    half identifies the subgroup's tests)."""
    return [part for part in str(group_id).split(":") if part]


def stem_tokens(path):
    """Filename stem tokens with test affix tokens removed:
    `tests/test_driver.py` -> ['driver'], `e2e/checkout.spec.ts` -> ['checkout']."""
    stem = os.path.splitext(os.path.basename(path))[0]
    return [t for t in tokens(stem) if t not in TEST_TOKENS]


def _runs_contain(seq, key):
    n = len(key)
    return n > 0 and any(tuple(seq[i:i + n]) == key for i in range(len(seq) - n + 1))


def _carries(seq, keys):
    """Does a token run `seq` carry one of `keys`?

    Three ways, in order: the key as a whole-token run (`auth` in
    `auth_handlers`); the key's tokens fused into one (`OAuth` tokenizes to
    o|auth but the path says `oauth/`; likewise GraphQL, WebSocket); or, for
    the CANONICAL key only, the run as a leading prefix of the key (`tools/`
    names `ToolAdapters`). The prefix rule is confined to the canonical name
    on purpose: applied to every alias and stem it credits `test_setup.py`
    to Onboarding via the alias SetupWizard, `test_data.py` to ImportExport
    via DataImport -- the over-claim the scoping exists to stop (R1)."""
    seq = _norm(seq)
    if not seq:
        return False
    for i, key in enumerate(keys):
        if _runs_contain(seq, key):
            return True
        if len(key) > 1 and "".join(key) in seq:
            return True
        if i == 0 and len(seq) < len(key) and tuple(key[:len(seq)]) == seq:
            return True
    return False


def path_carries_name(path, keys):
    """True if a directory segment or the affix-stripped filename stem carries
    one of `keys` (from `name_keys`) as a whole-token run."""
    parts = path.split("/")
    for segment in parts[:-1]:
        if _carries(tokens(segment), keys):
            return True
    return _carries(stem_tokens(path), keys)


def is_literal_glob(glob):
    """A glob that names exactly one path: no wildcard AND at least one `/`.
    A slash-less basename (`conftest.py`) matches at every depth under the
    gitignore semantics discovery uses, so it is a wildcard in effect and is
    scoped like one."""
    bare = glob.removeprefix("!")
    return "/" in bare and not _WILDCARD.search(bare)


def literal_prefix(glob):
    """Leading wildcard-free segments of a glob (`internal/auth/**/*_test.go` ->
    `internal/auth`; `**/*_test.go` -> ''). A literal path is its own prefix."""
    kept = []
    for segment in glob.removeprefix("!").split("/"):
        if _WILDCARD.search(segment):
            break
        kept.append(segment)
    return "/".join(s for s in kept if s)


def _under(path, prefix):
    return bool(prefix) and (path == prefix or path.startswith(prefix + "/"))


def distinguishing_prefixes(catalog):
    """{top-level group: sorted literal `match:` prefixes owned by that group
    alone}. Subgroup ids (`API:Handlers`) roll up to their top-level owner;
    negated globs contribute nothing; a prefix two owners share belongs to
    neither. Every top-level group gets a key (possibly [])."""
    owners = {}
    tops = []
    for gid, body in catalog.items():
        top = group_labels(gid)[0] if group_labels(gid) else str(gid)
        if top not in tops:
            tops.append(top)
        for glob in (body or {}).get("match") or []:
            if not isinstance(glob, str) or glob.startswith("!"):
                continue
            prefix = literal_prefix(glob)
            if prefix:
                owners.setdefault(prefix, set()).add(top)
    return {top: sorted(p for p, who in owners.items() if who == {top}) for top in tops}


def scope_ok(path, keys, prefixes):
    """The scoped-tests decision for one file against one vertical."""
    return any(_under(path, p) for p in prefixes) or path_carries_name(path, keys)


def shared_dir_depth(path, prefix):
    """Leading directory segments `path`'s directory shares with `prefix`."""
    a = os.path.dirname(path).split("/") if os.path.dirname(path) else []
    b = [s for s in prefix.split("/") if s]
    n = 0
    for x, y in zip(a, b):
        if x != y:
            break
        n += 1
    return n


def attach_by_affinity(files, homes):
    """Attach each file to the group whose `match:` prefix shares the deepest
    directory prefix with it (depth >= 2 -- a single shared top-level directory
    such as `src` says nothing). Ties go to the alphabetically first group.
    Returns ({group: sorted files}, sorted unattached)."""
    attached, unattached = {}, []
    for f in sorted(files):
        best, best_depth = None, 1
        for name in sorted(homes):
            depth = max([shared_dir_depth(f, p) for p in homes[name]] or [0])
            if depth > best_depth:
                best, best_depth = name, depth
        if best is None:
            unattached.append(f)
        else:
            attached.setdefault(best, []).append(f)
    return {n: sorted(fs) for n, fs in attached.items()}, sorted(unattached)
