"""Make panopticon's packages importable from any test without per-file
sys.path juggling (#547).

pytest imports this before collecting tests, so a test can do
`import scripts.tools.base` (needs skill/ on the path), `import evidence`
(skill/scripts/), or `import file_issues` (repo-root scripts/) with no
boilerplate. Previously 18 tests/tools/ files each repeated the same
`sys.path.insert(...)` line.
"""
import os
import sys

_TESTS = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_TESTS)
FIXTURE_ROOT = os.environ.get("FIXTURE_ROOT", os.path.join(_TESTS, "fixtures"))

# Public path anchors (#run7 TST-G1B): tests that need the repo or skill root
# previously each re-derived it via nested dirname(__file__) / os.pardir. Import
# these instead: `from conftest import REPO_ROOT` / `SKILL_ROOT`.
REPO_ROOT = _REPO
SKILL_ROOT = os.path.join(_REPO, "skill")
for _p in reversed((_TESTS,
                    os.path.join(_REPO, "skill"),
                    os.path.join(_REPO, "skill", "scripts"),
                    os.path.join(_REPO, "scripts"))):
    if _p in sys.path:
        sys.path.remove(_p)
    sys.path.insert(0, _p)
