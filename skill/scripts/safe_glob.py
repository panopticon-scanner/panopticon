"""#3701: match a pattern UNDER a directory, with the directory taken as it is spelled.

`glob.glob(os.path.join(directory, "findings-*.json"))` reads the whole joined
string as one pattern, so a `[`, `*` or `?` in `directory` is a wildcard too. A
review root at `repo[x]/` then matched nothing: `[x]` is the character class
"x", which is the directory `repox`, not `repo[x]`. The run found none of its
own findings files, dispatch plans, scout replies or coverage files, lost every
agent finding with no reason given, and `--reset` cleared nothing. Worse than
matching nothing, it could match a SIBLING: an empty `repo[x]/` beside
`repox/requirements-dev.txt` read as a Python tree.

`under` is the one place this package calls `glob`. The directory is escaped;
only the parts after it are a pattern. `tests/test_safe_glob.py` fails if any
other module here calls `glob.glob` or `glob.iglob`.
"""
import glob
import os


def under(directory, *pattern):
    """The paths under `directory` that match `pattern`, unsorted, as `glob.glob`
    returns them. `directory` is literal, whatever characters it holds. `pattern`
    is one or more path parts, each of which may hold wildcards:
    `under(run_dir, "findings-*.json")`, `under(home, "sessions", "*", "wire.jsonl")`.
    A name the caller builds a pattern part from is the caller's to vouch for: the
    run tag in `<tag>-report*.json` is alphanumerics and hyphens by construction."""
    return glob.glob(os.path.join(glob.escape(os.fspath(directory)), *pattern))
