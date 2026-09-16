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
      what it needs; nothing else in the finding schema does;
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
import ast
import os
import re

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


def named_paths(review_root, claim):
    """(b): the in-repo files this claim's own evidence names, in text order."""
    out = []
    for text in _claim_text(claim):
        for match in _PATH_RE.findall(text):
            path = _usable(review_root, match)
            if path and path not in out:
                out.append(path)
    return out


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


def _closure_paths(review_root, claim, group_files):
    """The FULL ordered closure, before the cap -- (a), then (b), then (c)."""
    claim = claim if isinstance(claim, dict) else {}
    loc = claim.get("location")
    loc = loc if isinstance(loc, dict) else {}
    primary = _norm(loc.get("file"))
    if primary is not None and not runio._confined_to_root(review_root, primary):
        primary = None
    out = [primary] if primary else []
    for path in named_paths(review_root, claim):
        if path not in out:
            out.append(path)
    if primary and primary.endswith(_PY):
        for path in (_imports_of(review_root, primary)
                     + _importers(review_root, primary, group_files)):
            if path not in out:
                out.append(path)
    return out


def closure(review_root, claim, group_files, cap=CAP):
    """The bounded evidence closure for ONE claim, capped, in priority order.

    `[]` when the claim has no usable `location.file` -- the whole-group
    fallback that case needs is `grant`'s decision, not this function's.
    """
    return _closure_paths(review_root, claim, group_files)[:max(0, cap)]


def _fallback(files, cap, entry_cap):
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
            "omitted": 0}


def _claim_floor(review_root, scope):
    """Every scoped claim's own `location.file`, in claim order, or None if one
    of them has no resolvable, confined path (the whole-group fallback case).

    The #1029 floor, and the reason it is computed FIRST (fix round 2, N3): the
    grant is a read fence the guard enforces, so a claim denied its own file
    cannot be adjudicated at all -- the only answer left to the advisor is
    NEEDS_MORE_INFO, which is now `backup_scope_limited`: gate-eligible at 1.5
    and permanently unrefutable. A ceiling that manufactures those is worse than
    no ceiling. So the floor is exempt from both caps and `entry_cap` bounds the
    closure EXTRAS alone."""
    floor = []
    for claim in scope or []:
        loc = claim.get("location") if isinstance(claim, dict) else None
        path = loc.get("file") if isinstance(loc, dict) else None
        if not path or not runio._confined_to_root(review_root, path):
            return None
        path = _norm(path)
        if path and path not in floor:
            floor.append(path)
    return floor


def grant(review_root, files, scope, cap=CAP, entry_cap=ENTRY_CAP):
    """The evidence grant for one backup entry:
    `{granted, cap, truncated, entry_cap, entry_truncated, omitted}`.

    Every scoped claim's own `location.file` first -- the floor, always granted
    -- then the union of their closure EXTRAS in claim order, up to `entry_cap`.
    Claim order, so the ceiling takes the tail of the chunk rather than a slice
    of every claim: an early claim keeps a whole, coherent neighbourhood instead
    of every claim getting a useless fragment. The total is therefore at most
    `max(entry_cap, len(floor))`.

    `truncated` says a single claim's closure hit `cap`; `entry_truncated` says
    the extras hit `entry_cap`, with `omitted` counting the DISTINCT files it
    cost. Both are stated in the prompt and echoed in the verdict, so "my scope
    was complete" is never something the advisor has to assume.

    Falls back to the whole group `files` when a scoped claim has no resolvable,
    confined `location.file` (unchanged from #1029/#1096): a backup must never
    refute blind. A path the claim NAMED but that escapes the root is simply not
    granted -- it never widens the fence and never triggers the fallback.
    """
    entry_cap = max(0, entry_cap)
    floor = _claim_floor(review_root, scope)
    if floor is None or not scope:
        return _fallback(files, cap, entry_cap)
    granted, truncated, omitted = list(floor), False, set()
    budget = max(0, entry_cap - len(floor))
    for claim in scope:
        paths = _closure_paths(review_root, claim, files)
        if len(paths) > cap:
            truncated = True
        for entry in paths[:max(0, cap)]:
            if not entry or entry in granted:
                continue          # already granted: never an omission
            if len(granted) - len(floor) >= budget:
                omitted.add(entry)
                continue
            granted.append(entry)
    # No `or list(files)`: the floor is non-empty whenever `scope` is, so an
    # emptied grant can only come from a zero ceiling -- and a ceiling of zero
    # handing back the whole group would be the one direction a ceiling must
    # never fail (fix round 2, N4).
    return {"granted": granted, "cap": cap, "truncated": truncated,
            "entry_cap": entry_cap, "entry_truncated": bool(omitted),
            "omitted": len(omitted)}
