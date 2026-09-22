"""Phase 5 -- the BOUNDED EVIDENCE CLOSURE a backup advisor is granted.

#1638 P16, owner ruling D4. `verify._backup_scope_files` granted the backup
adversary exactly each scoped claim's `location.file` (#1029, a cost cut taken
when advisor reads were still unconfined). Since plan 5/6 they are not: the read
guard and the Codex broker fence every advisor to the list the entry declares,
so that grant became a READ FENCE -- and a claim about behaviour that CROSSES
files became unadjudicable from inside it.

Run-13 is the worked example. #1634 (redaction runs after rendering) was
CONFIRMED by the primary advisor, which saw the whole cell, and came back
NEEDS_MORE_INFO from the backup, which was granted `synth/render.py` alone while
the defect lived in the call ORDER between it, `synth/grading.py` and
`synthesize.py`. Synthesis prefers the backup, so a reproduced defect was
published as unverifiable. The backup received LESS evidence than the primary it
was supposed to check.

The closure is the bounded answer -- three sources, in priority order:

  (a) the claim's own `location.file`;
  (b) every in-repo path the claim's OWN evidence names -- `description`,
      `exploit_scenario`, `remediation`, `evidence.reasoning`, `references`.
      A claim that says "the call sites in grading.py" is telling the driver
      what it needs; nothing else in the finding schema does. Since #1688 that
      name no longer has to be spelled as a full repo-relative path: it is
      resolved exactly, then by unique SUFFIX inside the claiming cell, then by
      unique suffix repo-wide, then by CONTENT -- and a name that still means
      two DIFFERENT files resolves to neither, because the wrong `config.py` is
      a read fence pointed at evidence the claim was not about. That refusal is
      DISCLOSED (`disclosure`), not silent;
  (c) its one-hop in-repo import neighbourhood, BOTH directions: the modules
      the claim file imports, and the files in the same group that import IT
      (the "orchestration call sites" the run-13 backup could not see).

De-duplicated, truncated at `CAP`, and RECORDED: `grant()` returns the list with
the cap and whether it truncated, which the entry puts in the prompt and the
advisor copies into its verdict (`evidence_scope`). A file the advisor still
needed is named in `missing_evidence`, which `scripts.evidence` reads as an
evidence-scope failure rather than a refutation.

Bounded, never widened: every candidate must EXIST under `review_root` and pass
`runio._confined_to_root`, so an absolute or `../` path a hostile repo planted in
a claim contributes nothing (#1096) -- it does not reach the grant, and it does
not trigger the whole-group fallback either. Only an unresolvable
`location.file` does that, exactly as before.

Its own module rather than more of `phases/verify.py`: verify.py is 603 of the
700-line package ceiling and this is a self-contained, I/O-light concern (a path
scanner and a small import resolver) with one caller.
"""
from typing import Any
import ast
import hashlib
import os
import re

import scripts.run_manifest as run_manifest
from . import runio

# How many files one claim's closure may grant. Twelve is the smallest number
# that covered every cross-file claim in the run-13 ledger (the redaction-order
# defect needs three, the malformed-diff gate four) with room for an import
# neighbourhood, and small enough that a claim whose free text names thirty
# paths -- an injection attempt, or an essay -- cannot turn a fenced backup back
# into a whole-repo read. A module constant, not a CLI flag: `driver run/loop`
# flags are a documented, tested surface (quick reference, flag-parity tests)
# and this number is a calibration detail, not an operator decision.
CAP = 12

# How many files ONE BACKUP ENTRY's grant may hold in total, across every claim
# in its chunk (fix round 1, F3). `CAP` bounds a claim, which is what D4
# specifies, and the union of up to `verify._CELL_CLAIMS_CAP` = 25 claims was
# unbounded: measured at 276 files granted over a 2-file group, 275 of them from
# outside it, while the prompt said "truncated: no". 48 is the review matrix's
# own per-group ceiling -- the number that already decides how much code one cell
# may be asked about -- so a backup is never granted more than a review cell is.
ENTRY_CAP = 48

# The claim fields whose free text may name a producer. `evidence.reasoning` is
# read through `_EVIDENCE_FIELD` because it is nested.
_TEXT_FIELDS = ("description", "exploit_scenario", "remediation")
_EVIDENCE_FIELD = "evidence"

# Conservative on purpose: a path-shaped token with a known source extension,
# bounded by non-path characters so `see grading.py.` and `[a.py:12]` both
# yield the path and `notafile.python` yields nothing. Prose that merely
# mentions a word is not a path; a wrong guess here spends read budget, and a
# missed one only leaves today's behaviour.
_PATH_RE = re.compile(
    r"(?<![\w./-])([\w./-]+\.(?:py|js|ts|rb|go|java|cs|rs|toml|yml|yaml|json|md))"
    r"(?![\w./-])")

# Extensions whose imports this module can resolve. Anything else gets (a)+(b):
# a closure is only worth granting when it is derived, not guessed.
_PY = ".py"

# How much of a same-named candidate step 4 reads before it gives up on telling
# two files apart. Four MiB covers every source file in a reviewable tree by a
# wide margin, and a file larger than it is not source: reading further would
# spend the closure's whole IO budget proving that two vendored archives differ.
# Oversized counts as DISTINCT, never as identical -- see `_digest`.
_HASH_BYTES = 4 * 1024 * 1024

# The controller's own seed for a scope-limited backup's `missing_evidence`.
# ONE line per name the driver refused to guess at, written into the dispatch
# BEFORE the advisor runs: an ambiguity the advisor is not told about is one it
# discovers as a file it cannot open, and "the file I needed was not granted"
# and "the file I needed could have been three files" are different answers.
_AMBIGUOUS_LINE = "ambiguous: %s (%d candidates, %s)"

# Why a name resolved to no file. Three of the four never compare content, and
# the line used to say "differing" for all of them (fix round 1, R1-2) -- a
# fabricated detail in the one place the advisor is told what the driver
# actually knows. `too many` read nothing at all; `unreadable` and `oversized`
# mean this module could not read a candidate WHOLE, so it cannot call it a
# copy of anything and the ambiguity stands.
_TOO_MANY, _UNREADABLE, _OVERSIZED, _DIFFERING = (
    "too many", "unreadable", "oversized", "differing")
_AMBIGUOUS_BLOCK = (
    "\nNames these claims used that resolve to more than one file, so this "
    "driver granted NONE of them rather than guess which one the claim meant. "
    "If your answer needs one, return NEEDS_MORE_INFO and copy its line into "
    "`missing_evidence`:\n%s\n")


def _norm(path):
    """`./a/b.py` -> `a/b.py`; anything not a usable relative path -> None."""
    if not isinstance(path, str) or not path:
        return None
    path = path.strip()
    while path.startswith("./"):
        path = path[2:]
    return path or None


def _usable(review_root, path):
    """A repo-relative path that EXISTS as a file under `review_root` and does
    not escape it. Both halves matter: existence keeps prose out of the grant,
    confinement keeps a planted `../` out of the read fence (#1096)."""
    path = _norm(path)
    if not path or not runio._confined_to_root(review_root, path):
        return None
    return path if os.path.isfile(os.path.join(review_root, path)) else None


def _claim_text(claim):
    """Every free-text field of the claim whose evidence may name a producer."""
    out = []
    for key in _TEXT_FIELDS:
        value = claim.get(key)
        if isinstance(value, str):
            out.append(value)
    ev = claim.get(_EVIDENCE_FIELD)
    if isinstance(ev, dict) and isinstance(ev.get("reasoning"), str):
        out.append(ev["reasoning"])
    for ref in claim.get("references") or []:
        if isinstance(ref, str):
            out.append(ref)
    return out


def _repo_files(review_root, cache):
    """Every file THIS RUN discovered, repo-relative -- the tree step 3 searches.

    `.panopticon/groups.json` is discovery's OWN listing, already computed and
    already on disk: it came from `git ls-files` (so the target's .gitignore
    defines the surface, #500), it is pruned of excluded dirs, dot-dirs and --
    unless the run asked for them -- fixture corpora, and every entry is
    repo-relative. Reading it is one JSON load. Walking the tree again here
    would be a second, slower and DIFFERENT surface, and an `os.walk` would
    descend `.git` and vendored virtualenvs the review itself never looks at.

    It must be THIS RUN's listing, and that is checked, not assumed (fix round
    1, R1-3): `discovery_execute` stamps `groups.json` with the run binding, and
    this applies the same test the discovery done-predicate does. It matters
    because with no manifest `_pano` falls back to the TOP-LEVEL
    `.panopticon/groups.json` -- a path the reviewed target can commit -- and a
    planted listing steers the grant: the claim names `config.py`, the listing
    says the repo's only `config.py` is `secrets/config.py`, and the read fence
    is pointed there. A foreign stamp, a missing stamp and a missing manifest
    are all "no listing".

    No listing (that, or a `closure()` call outside a run) means no repo-wide
    step: the name stays unresolved, which is exactly today's behaviour. This
    resolver may widen a grant only from evidence the run already holds, never
    by discovering -- or being handed -- a tree of its own.

    `cache` is one dict per entry, so a chunk naming thirty paths loads the
    listing once rather than thirty times.
    """
    if "files" not in cache:
        doc = runio._load_json(runio._pano(review_root, "groups.json")) or {}
        run_id = (run_manifest.load_manifest(review_root) or {}).get("run_id")
        out: set[str] = set()
        if run_id and doc.get("run_id") == run_id:
            for group in doc.get("groups") or []:
                if isinstance(group, dict):
                    out.update(p for p in (_norm(f) for f in group.get("files")
                                           or []) if p)
        cache["files"] = sorted(out)
    return cache["files"]


def _candidates(review_root, paths, name):
    """The files in `paths` that `name` could mean, sorted and de-duplicated.

    A path matches when it IS the name or ENDS with it on a component boundary,
    so `helpers/config.py` matches `src/app/helpers/config.py` and `config.py`
    never matches `myconfig.py`. Every match is re-checked with `_usable`: a
    listing entry that no longer exists, or whose realpath leaves the tree
    through a planted symlink, is not a candidate at all -- suffix resolution
    may not do what #1096 forbade the exact path from doing. Sorted, because
    every first-wins choice below has to be the same on every run.
    """
    tail = "/" + name
    out = set()
    for path in paths or []:
        norm = _norm(path)
        if not norm or not (norm == name or norm.endswith(tail)):
            continue
        usable = _usable(review_root, norm)
        if usable:
            out.add(usable)
    return sorted(out)


def _digest(review_root, rel, cache):
    """`(sha256-of-the-first-_HASH_BYTES, None)`, or `(None, why)`.

    `(None, why)` means "this module cannot call the file identical to
    anything": `_UNREADABLE` for a file it could not open, `_OVERSIZED` for one
    it could not read whole. Either way the ambiguity stands -- the fail-closed
    direction, because the cost of guessing wrong is a read fence around the
    wrong file -- and `why` is what the disclosure says instead of inventing
    "differing" for a comparison that never happened (R1-2).

    MEMOISED in the entry's `cache` (fix round 1, R1-1): a path's bytes do not
    change inside one dispatch, and without the memo the read bound was per
    NAME per CLAIM -- 48 claims naming one ambiguous basename read its twelve
    candidates 48 times over. One read per candidate path per entry, ever.
    """
    memo = cache.setdefault("digests", {})
    if rel not in memo:
        try:
            with open(os.path.join(review_root, rel), "rb") as fh:
                blob = fh.read(_HASH_BYTES + 1)
        except OSError:
            memo[rel] = (None, _UNREADABLE)
        else:
            memo[rel] = ((None, _OVERSIZED) if len(blob) > _HASH_BYTES
                         else (hashlib.sha256(blob).hexdigest(), None))
    return memo[rel]


def _collapse(review_root, candidates, cache):
    """Step 4: `(the one path several same-named candidates all ARE, None)`, or
    `(None, why they stay ambiguous)`.

    Two files with the same bytes are not an ambiguity -- whichever is granted,
    the backup reads the same evidence -- so identical candidates collapse to
    the first in sorted order. Any difference, and none is granted.

    Bounded exactly twice over: more than `CAP` candidates is not a near-miss
    but a common basename, and is ambiguous without a single read; at or under
    the cap each candidate is read once, at most `_HASH_BYTES` of it. So the
    worst case a hostile tree can buy with one name is twelve bounded reads --
    and the first candidate this module cannot read whole ends the comparison
    there, because nothing later can make the set identical.
    """
    if len(candidates) > CAP:
        return None, _TOO_MANY
    digests = []
    for rel in candidates:
        digest, why = _digest(review_root, rel, cache)
        if digest is None:
            return None, why
        digests.append(digest)
    if len(set(digests)) != 1:
        return None, _DIFFERING
    return candidates[0], None


def _resolve_named(review_root, group_files, name, cache):
    """The ONE file a named path means: `(path, ambiguity)`. Owner ruling #1688.

    A claim that says `helpers/config.py`, or just `config.py`, is naming the
    producer it needs; `_usable` alone resolves only a path spelled EXACTLY as
    it sits in the tree, so the commonest way a claim asks for cross-file
    evidence was the one way it was refused. In order:

      1. exactly as written -- `_usable`: normalized, confined, existing;
      2. unique suffix among the CLAIMING CELL's own files. The cell is the
         context the claim was written in, so a match there is the one its
         author meant, and it costs no reads;
      3. unique suffix repo-wide, over the listing this run discovered;
      4. several matches at step 2 or 3: compare CONTENT (`_collapse`).

    A step-2 ambiguity does not fall through to step 3: the cell is the nearer
    context and widening the search could only add candidates to a question
    that has already been answered "more than one".

    Steps 2-4 are what this issue ADDED, and they are what an injected essay of
    path-shaped tokens can spend: a listing scan and up to twelve bounded reads
    per name. So they are bounded per ENTRY (fix round 1, R1-1c): at most
    `ENTRY_CAP` distinct names are ever searched for, and a name past that is
    dropped in silence -- it could not have been granted anyway, the entry
    ceiling being spent, and disclosing it would hand the essay a second
    channel. Step 1 is deliberately OUTSIDE that bound: it is one `isfile` on a
    path that exists as written, it is what this module did before #1688, and
    counting it would make `grant`'s `omitted` -- the "N further files omitted
    by the entry ceiling" the prompt prints -- stop counting at 48.

    `(path, None)` when the name resolves, `(None, record)` when it meant
    several different files -- `{"name", "reason", "candidates"}`, where
    `reason` is which of the four ways it stayed ambiguous -- and `(None, None)`
    when it meant none: an unresolvable name is still simply dropped, which is
    what keeps prose that merely looks like a path out of the grant.
    """
    exact = _usable(review_root, name)
    if exact:
        return exact, None
    name = _norm(name)
    if not name or name.startswith("/") or ".." in name.split("/"):
        # An absolute or dot-segmented name never becomes a suffix search:
        # `../outside.py` is the shape #1096 rejects, and it must not reach the
        # tree through a basename match either.
        return None, None
    searched = cache.setdefault("searched", set())
    if name not in searched:
        if len(searched) >= ENTRY_CAP:
            return None, None
        searched.add(name)
    found = _candidates(review_root, group_files, name)
    if not found:
        found = _candidates(review_root, _repo_files(review_root, cache), name)
    if len(found) == 1:
        return found[0], None
    if not found:
        return None, None
    collapsed, why = _collapse(review_root, found, cache)
    if collapsed:
        return collapsed, None
    return None, {"name": name, "reason": why, "candidates": len(found)}


def named_paths(review_root, claim, group_files=None, unresolved=None,
                cache=None, cap=CAP):
    """(b): the in-repo files this claim's own evidence names, in text order.

    Each name goes through `_resolve_named` (#1688), so the claiming cell's own
    files are searched by suffix before the rest of the tree. `unresolved`, when
    the caller passes a list, collects one record per name that meant more than
    one file -- de-duplicated by name, because the same ambiguous basename in
    three claims is one thing for the advisor to be told.

    `cache` is the ENTRY's working memory (fix round 1, R1-1), threaded down
    from `grant` so one dispatch resolves a given name once and reads a given
    candidate once. It is keyed to one `(review_root, group_files)` pair --
    which is what an entry is -- so a caller that changes either starts a new
    one. Two bounds live here, and both exist because claim text is
    panel-authored and steerable by whatever the reviewed repo plants in it:

      * a claim stops resolving once it holds more paths than the caller's
        `cap` could grant. One PAST the cap, not at it: `grant` reads the closure's
        LENGTH to decide `truncated`, and stopping exactly at the cap would
        report a truncated closure as complete;
      * an entry SEARCHES the tree for at most `ENTRY_CAP` distinct names --
        see `_resolve_named`, which owns that bound because it is the search
        this issue added that has to be bounded.

    Each distinct name is resolved once per entry and the answer reused, so the
    cost of a claim repeating a name, or fifty claims sharing one, is a dict
    lookup.
    """
    out: list[str] = []
    cache = {} if cache is None else cache
    seen = cache.setdefault("names", {})
    for text in _claim_text(claim):
        for match in _PATH_RE.findall(text):
            if len(out) > cap:            # the CALLER's cap, not the constant
                return out
            key = _norm(match) or match   # `./x.py` and `x.py` are one name
            if key not in seen:
                seen[key] = _resolve_named(review_root, group_files, match,
                                           cache)
            path, ambiguity = seen[key]
            if path:
                if path not in out:
                    out.append(path)
            elif ambiguity and unresolved is not None and not any(
                    r.get("name") == ambiguity["name"] for r in unresolved):
                unresolved.append(ambiguity)
    return out


def disclosure(ambiguous):
    """The prompt block that TELLS a backup advisor what the driver refused to
    guess -- `""` when nothing was ambiguous.

    Controller-authored and rendered into the dispatch before the advisor runs,
    exactly like the grant block it follows: nothing here is read back from a
    verdict, so `_agent_verdict` (the one sanitizer) and its AST guard are
    untouched, and an advisor cannot fabricate, empty or edit a record of what
    its own scope was missing.

    Names reach here from a claim's free text, which a hostile repo steers, so
    they go through `runio._prompt_safe` (#1190) even though `_PATH_RE`'s
    charset already excludes newlines: one of those two defences is the one
    that gets edited.
    """
    if not ambiguous:
        return ""
    return _AMBIGUOUS_BLOCK % "\n".join(
        "- " + runio._prompt_safe(_AMBIGUOUS_LINE
                                  % (record.get("name"),
                                     int(record.get("candidates") or 0),
                                     record.get("reason") or _DIFFERING))
        for record in ambiguous)


def _module_targets(node):
    """The dotted module paths one import statement could name.

    `(parts, level)` pairs. `from a import b` yields both `a` and `a.b`: `b` may
    be a submodule (a file we want) or a name inside `a.py` (the file we want) --
    resolution below picks whichever actually exists.
    """
    if isinstance(node, ast.Import):
        return [(alias.name.split("."), 0) for alias in node.names]
    if isinstance(node, ast.ImportFrom):
        base = (node.module or "").split(".") if node.module else []
        out = [(base, node.level)] if base else []
        out += [(base + [alias.name], node.level) for alias in node.names]
        return out
    return []


def _search_roots(review_root, rel_path, level):
    """Directories to resolve a module against, nearest first.

    Relative imports (`level > 0`) resolve against the importing file's package,
    walked up `level - 1` times -- exactly Python's rule. Absolute imports are
    tried against the importing file's own directory and each ancestor up to
    `review_root`, which is the conservative stand-in for sys.path: it is how
    `skill/scripts/synthesize.py`'s `import scripts.synth.render` resolves to
    `skill/scripts/synth/render.py` in a repo whose source root is not the repo
    root. Nearest-first, so the closest match wins.
    """
    parts = os.path.dirname(rel_path).split("/") if os.path.dirname(rel_path) else []
    if level:
        if len(parts) < level - 1:      # `from ...` above the repo root
            return []
        return ["/".join(parts[:len(parts) - (level - 1)])]
    roots = []
    while True:
        roots.append("/".join(parts))
        if not parts:
            return roots
        parts = parts[:-1]


def _resolve(review_root, rel_path, parts, level):
    """The in-repo file a single import target names, or None."""
    if not parts or any(not p for p in parts):
        return None
    for root in _search_roots(review_root, rel_path, level):
        stem = "/".join([p for p in [root] if p] + list(parts))
        for candidate in (stem + _PY, stem + "/__init__" + _PY):
            found = _usable(review_root, candidate)
            if found and found != rel_path:
                return found
    return None


def _imports_of(review_root, rel_path):
    """The in-repo files `rel_path` imports, in source order.

    Tolerant by construction: an unreadable or unparseable file imports nothing
    as far as this is concerned. A backup grant is a best-effort widening, and
    a SyntaxError in the target tree must never fail a run.
    """
    if not rel_path.endswith(_PY):
        return []
    try:
        with open(os.path.join(review_root, rel_path), encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), rel_path)
    except (OSError, ValueError, SyntaxError, RecursionError):
        return []
    out = []
    for node in ast.walk(tree):
        for parts, level in _module_targets(node):
            found = _resolve(review_root, rel_path, parts, level)
            if found and found not in out:
                out.append(found)
    return out


def _mentions(review_root, rel_path, needle):
    """Cheap pre-filter: does this file's text contain `needle` at all?

    A group can hold dozens of files and a chunk dozens of claims; parsing every
    one for every claim is the difference between a millisecond and a second per
    entry. A file that never spells the claim module's name cannot import it.
    """
    try:
        with open(os.path.join(review_root, rel_path), encoding="utf-8",
                  errors="replace") as fh:
            return needle in fh.read()
    except OSError:
        return False


def _importers(review_root, rel_path, group_files):
    """(c, second direction): same-group files that import `rel_path`."""
    stem = os.path.basename(rel_path)[:-len(_PY)]
    out = []
    for other in group_files or []:
        other = _norm(other)
        if (not other or other == rel_path or not other.endswith(_PY)
                or other in out):
            continue
        if not _mentions(review_root, other, stem):
            continue
        if rel_path in _imports_of(review_root, other):
            out.append(other)
    return out


def _closure_paths(review_root, claim, group_files, unresolved=None,
                   cache=None, cap=CAP):
    """The FULL ordered closure, before the cap -- (a), then (b), then (c)."""
    claim = claim if isinstance(claim, dict) else {}
    loc = claim.get("location")
    loc = loc if isinstance(loc, dict) else {}
    primary = _norm(loc.get("file"))
    if primary is not None and not runio._confined_to_root(review_root, primary):
        primary = None
    out = [primary] if primary else []
    for path in named_paths(review_root, claim, group_files, unresolved,
                            cache, cap):
        if path not in out:
            out.append(path)
    if primary and primary.endswith(_PY):
        for path in (_imports_of(review_root, primary)
                     + _importers(review_root, primary, group_files)):
            if path not in out:
                out.append(path)
    return out


def closure(review_root, claim, group_files, cap=CAP, unresolved=None):
    """The bounded evidence closure for ONE claim, capped, in priority order.

    `[]` when the claim has no usable `location.file` -- the whole-group
    fallback that case needs is `grant`'s decision, not this function's.

    `unresolved` is a PARALLEL list the caller may pass to collect the names
    that meant more than one file (#1688), rather than a second return value: a
    closure is a list of paths to everything that reads one, and the disclosure
    has exactly one consumer.

    One claim is its own entry here, so it gets a fresh resolver cache and the
    whole `ENTRY_CAP` name budget. `grant` is the caller that spends one budget
    across a chunk.
    """
    return _closure_paths(review_root, claim, group_files,
                          unresolved, cap=cap)[:max(0, cap)]


def _fallback(files, cap, entry_cap, floor_count=0):
    """The whole-group grant, in the same recorded shape (#1029/#1096).

    Deliberately NOT subject to `entry_cap`: the group is already bounded -- the
    matrix chunks a group at `--max-per-group` (default 48, so at defaults this
    grants exactly `ENTRY_CAP` and the exemption is a no-op) -- and narrowing the
    safety net is how a backup ends up refuting blind, which is the one thing the
    fallback exists to prevent. At a raised `--max-per-group` the fallback is
    correspondingly larger; that is the operator's own bound on how much code one
    cell covers."""
    return {"granted": list(files), "cap": cap, "truncated": False,
            "entry_cap": entry_cap, "entry_truncated": False,
            "omitted": 0, "floor_count": floor_count}


def _claim_floor(review_root, scope):
    """Every scoped claim's own `location.file`, in claim order, or None if one
    of them does not resolve to an existing in-root file (the whole-group
    fallback case).

    The #1029 floor, and the reason it is computed FIRST (fix round 2, N3): the
    grant is a read fence the guard enforces, so a claim denied its own file
    cannot be adjudicated at all -- the only answer left to the advisor is
    NEEDS_MORE_INFO, which is now `backup_scope_limited`: gate-eligible at 1.5
    and permanently unrefutable. A ceiling that manufactures those is worse than
    no ceiling. So the floor is exempt from both caps and `entry_cap` bounds the
    closure EXTRAS alone.

    Resolution is `_usable`: NORMALIZE, then confine, then require the file to
    exist. Order and existence are both load-bearing (fix round 3, D2). Confining
    before normalizing let `"./"` and whitespace-only paths pass the fence test,
    normalize to None and drop out of the floor with no fallback -- an EMPTY
    grant, which is a deny-all fence and the very outcome above. Existence closes
    the same hole by its other door: a grant of one path the advisor cannot open
    is an empty fence in everything but name. `location.file` is panel-supplied
    and steerable by injection (`runio._confined_to_root`), so "unresolvable"
    must mean every way of being unusable, not one of them."""
    floor = []
    for claim in scope or []:
        loc = claim.get("location") if isinstance(claim, dict) else None
        path = _usable(review_root, loc.get("file") if isinstance(loc, dict)
                       else None)
        if not path:
            return None
        if path not in floor:
            floor.append(path)
    return floor


def grant(review_root, files, scope, cap=CAP, entry_cap=ENTRY_CAP,
          ambiguous=None):
    """The evidence grant for one backup entry:
    `{granted, cap, truncated, entry_cap, entry_truncated, omitted, floor_count}`.

    Every scoped claim's own `location.file` first -- the floor, always granted
    -- then the union of their closure EXTRAS in claim order, up to `entry_cap`.
    Claim order, so the ceiling takes the tail of the chunk rather than a slice
    of every claim: an early claim keeps a whole, coherent neighbourhood instead
    of every claim getting a useless fragment. The total is therefore at most
    `max(entry_cap, len(floor))`.

    `truncated` says a single claim's closure hit `cap`; `entry_truncated` says
    the EXTRAS hit `entry_cap` -- it is a statement about extras only, so a floor
    larger than `entry_cap` reports `false` and `floor_count` is what tells the
    reader why the grant exceeds its own ceiling (fix round 3, D5). `omitted`
    counts the DISTINCT extra files the ceiling cost. All of it is stated in the
    prompt and echoed in the verdict, so "my scope was complete" is never
    something the advisor has to assume.

    The grant is NEVER empty (fix round 3, D2): an empty `files` list is a
    deny-all read fence -- the guard refuses every Read, Grep and Glob -- so an
    entry carrying one asks an advisor to adjudicate with nothing, and the only
    answer left to it manufactures an unrefutable `backup_scope_limited`.
    Whatever the claims say, the backup is handed the closure or the whole group.

    Falls back to the whole group `files` when a scoped claim has no resolvable,
    confined `location.file` (unchanged from #1029/#1096): a backup must never
    refute blind. A path the claim NAMED but that escapes the root is simply not
    granted -- it never widens the fence and never triggers the fallback.

    `ambiguous` is an optional list the caller passes to collect every name
    these claims used that meant more than one file (#1688), for the caller to
    DISCLOSE. It is a parallel list and not an eighth key on purpose: the dict
    above is the shape the advisor copies into its verdict's `evidence_scope`,
    and three docstrings plus the report schema pin it.
    """
    entry_cap = max(0, entry_cap)
    floor = _claim_floor(review_root, scope)
    if not floor:
        # `None` (a claim whose file does not resolve) and `[]` (no claims at
        # all) both mean "nothing here bounds the grant" -- fall back.
        return _fallback(files, cap, entry_cap)
    granted, truncated, omitted = list(floor), False, set()
    budget = max(0, entry_cap - len(floor))
    # R1-1: ONE resolver cache for the whole entry -- one read per candidate
    # path and one resolution per distinct name, however many claims name it.
    cache: dict[str, Any] = {}
    for claim in scope:
        paths = _closure_paths(review_root, claim, files, ambiguous, cache, cap)
        if len(paths) > cap:
            truncated = True
        for entry in paths[:max(0, cap)]:
            if not entry or entry in granted:
                continue          # already granted: never an omission
            if len(granted) - len(floor) >= budget:
                omitted.add(entry)
                continue
            granted.append(entry)
    # `granted` is non-empty by construction here (it starts as the floor, and
    # the floor is non-empty or we fell back above), so an `or list(files)` net
    # would only hide a future bug: a ceiling of zero must fail CLOSED to the
    # floor, never open to the whole group (fix round 2, N4).
    return {"granted": granted, "cap": cap, "truncated": truncated,
            "entry_cap": entry_cap, "entry_truncated": bool(omitted),
            "omitted": len(omitted), "floor_count": len(floor)}
