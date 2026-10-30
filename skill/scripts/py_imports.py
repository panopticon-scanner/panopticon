"""scripts.py_imports: which in-repo Python files one file imports, and which import it.

Moved out of `phases/evidence_scope.py` (#3231), where it was the one-hop import
closure a backup advisor is granted. It has two more readers now, and one of them
is on the far side of a layering rule: `phases/inventory.py` asks whether another
group's test imports a module (C1), and `synth/severity_cap.py` asks whether ANY
test does before a coverage-absence claim may stay HIGH (C2). `scripts.synth` may
not import `scripts.phases` (tests/test_layout.py rule 3), so the resolver lives
here, flat, and all three call the same one.

Resolution is conservative and confined: every candidate must EXIST under
`review_root` and pass `claim_scope.confined_to_root`, and source is read through
`safe_write.read_regular_bytes` under a 4 MiB cap -- a file in the reviewed tree is
untrusted input, so an oversized, special or symlinked one imports nothing.
"""
import ast
import os

import scripts.claim_scope as claim_scope
import scripts.safe_write as safe_write

# The one language whose imports this module resolves.
PY = ".py"

# How much of one source file is read to parse its imports. Four MiB is the
# smallest read class for an individual reviewable source file; a larger one is
# treated as outside the source-review boundary and imports nothing.
SOURCE_BYTES = 4 * 1024 * 1024


def norm(path):
    """`./a/b.py` -> `a/b.py`; anything not a usable relative path -> None."""
    if not isinstance(path, str) or not path:
        return None
    path = path.strip()
    while path.startswith("./"):
        path = path[2:]
    return path or None


def usable(review_root, path):
    """A repo-relative path that EXISTS as a file under `review_root` and does
    not escape it (#1096)."""
    path = norm(path)
    if not path or not claim_scope.confined_to_root(review_root, path):
        return None
    return path if os.path.isfile(os.path.join(review_root, path)) else None


def module_targets(node):
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


def search_roots(rel_path, level):
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


def resolve(review_root, rel_path, parts, level):
    """The in-repo file a single import target names, or None."""
    if not parts or any(not p for p in parts):
        return None
    for root in search_roots(rel_path, level):
        stem = "/".join([p for p in [root] if p] + list(parts))
        for candidate in (stem + PY, stem + "/__init__" + PY):
            found = usable(review_root, candidate)
            if found and found != rel_path:
                return found
    return None


def source(review_root, rel_path, cache):
    """Memoized text of one confined source file, or None."""
    memo = cache.setdefault("source", {})
    if rel_path not in memo:
        try:
            if not claim_scope.confined_to_root(review_root, rel_path):
                raise OSError("not a confined path")
            raw = safe_write.read_regular_bytes(os.path.join(review_root, rel_path),
                                                SOURCE_BYTES)
            memo[rel_path] = raw.decode("utf-8", errors="replace")
        except (OSError, safe_write.ReadLimitExceeded):
            memo[rel_path] = None
    return memo[rel_path]


def imports_of(review_root, rel_path, cache):
    """Memoized in-repo imports; unsafe or unparseable source imports nothing."""
    memo = cache.setdefault("imports", {})
    if rel_path in memo:
        return memo[rel_path]
    text = source(review_root, rel_path, cache) if rel_path.endswith(PY) else None
    try:
        tree = ast.parse(text, rel_path) if text is not None else None
    except (ValueError, SyntaxError, RecursionError, MemoryError):
        tree = None
    if tree is None:
        memo[rel_path] = []
        return []
    out = []
    for node in ast.walk(tree):
        for parts, level in module_targets(node):
            found = resolve(review_root, rel_path, parts, level)
            if found and found not in out:
                out.append(found)
    memo[rel_path] = out
    return out


def importers(review_root, rel_path, candidates, cache):
    """The files among `candidates` that import `rel_path`, in their order.

    A cheap text pre-filter on the module's stem runs before any parse, so a
    candidate that never spells the name is never parsed."""
    stem = os.path.basename(rel_path)[:-len(PY)]
    out = []
    for other in candidates or []:
        other = norm(other)
        if (not other or other == rel_path or not other.endswith(PY)
                or other in out):
            continue
        text = source(review_root, other, cache)
        if text is None or stem not in text:
            continue
        if rel_path in imports_of(review_root, other, cache):
            out.append(other)
    return out
