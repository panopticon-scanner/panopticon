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
for _p in reversed((os.path.join(_REPO, "skill"),
                    os.path.join(_REPO, "skill", "scripts"),
                    os.path.join(_REPO, "scripts"))):
    if _p in sys.path:
        sys.path.remove(_p)
    sys.path.insert(0, _p)
