"""Single source of truth for panopticon's version (#439).

Edit the version HERE and nowhere else. pyproject.toml, DEVELOPMENT.md's
"Current version" line, and SKILL.md's frontmatter must state the same value —
tests/test_version.py enforces the sync, so a bump that misses one of them
fails CI instead of shipping a stale 3.0.0 the way pyproject and citations'
User-Agent did through runs 2 and 3. Code (report meta, verify-queue payload,
EPSS User-Agent) imports the constant rather than restating it.

Also the single owner for resolving paths to files bundled under
skill/reference/ — see reference_path() below. Used by citations.py,
model_resolver.py, and ocrdb.py (#dedup of 3 identical inline spellings).
A 4th, in codex_runner.py, computes an equivalent-but-differently-normalized
string (via os.path.dirname twice rather than an os.pardir join) and is left
inline so its resolved path stays byte-identical.
"""
import os

__version__ = "5.0.0"


def reference_path(*parts):
    """Absolute path to a file bundled under skill/reference/, resolved
    relative to this package (single owner; #dedup of 3 inline spellings —
    see module docstring for the 4th, intentionally-excluded call site)."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        os.pardir, "reference", *parts)
