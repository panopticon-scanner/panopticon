"""The one place that puts panopticon on sys.path (#3505).

An entry script run by path (`python3 skill/scripts/driver.py run`, the way
hosts and the installed skill invoke it) starts with its own directory,
`skill/scripts`, at sys.path[0] and `skill/` nowhere. Every import in this tree
is `scripts.*`, which needs `skill/` instead. Such a script runs this file once,
by path, inside its `if __name__ == "__main__":` block and before anything else
from this tree:

    if __name__ == "__main__":
        import runpy
        runpy.run_path(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                    "_bootstrap.py"))

By path rather than `import _bootstrap`, because under `python3 -P` (or
PYTHONSAFEPATH, which the driver sets for its children) the script's own
directory is not on sys.path at all. This file then:

- drops every sys.path entry that resolves to `skill/scripts`, so a bare
  `import evidence` cannot load a second copy of `scripts.evidence`;
- puts `skill/` first, so our `scripts` package wins over any other `scripts`
  on the path (the target repo's own, or one in site-packages).

Paths are compared by realpath because an installed skill may be a symlink.
Running it again is a no-op: the rewrite is idempotent. Imported as a module
(tests, the tools image's PYTHONPATH), an entry script never reaches its
`__main__` block, and `skill/` is already on the path.

`devtools/_skill_bootstrap.py` runs this same file, so this stays the only sys.path
mutation in the tree, which the guard in tests/test_import_shape.py enforces.
Stdlib only, and nothing from this tree: it runs before `scripts` resolves.
"""
import os
import sys

SCRIPTS = os.path.dirname(os.path.realpath(__file__))
SKILL = os.path.dirname(SCRIPTS)


def _resolves_to(entry, target):
    try:
        return os.path.realpath(entry or os.curdir) == target
    except (OSError, ValueError):
        return False


def rewritten(entries):
    """`entries` without `skill/scripts` (or a stale `skill/`), `skill/` first."""
    return [SKILL] + [entry for entry in entries
                      if not _resolves_to(entry, SCRIPTS) and not _resolves_to(entry, SKILL)]


# Run by path (`runpy.run_path`, so `__name__` is "<run_path>"), this rewrites
# sys.path. Imported as `scripts._bootstrap` -- only a test does that -- it
# changes nothing, so `rewritten` can be checked on a plain list.
if __name__ != "scripts._bootstrap":
    sys.path[:] = rewritten(sys.path)
