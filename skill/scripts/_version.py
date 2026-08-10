"""Single source of truth for panopticon's version (#439).

Edit the version HERE and nowhere else. pyproject.toml, DEVELOPMENT.md's
"Current version" line, and SKILL.md's frontmatter must state the same value —
tests/test_version.py enforces the sync, so a bump that misses one of them
fails CI instead of shipping a stale 3.0.0 the way pyproject and citations'
User-Agent did through runs 2 and 3. Code (report meta, verify-queue payload,
EPSS User-Agent) imports the constant rather than restating it.
"""

__version__ = "4.3.2"
