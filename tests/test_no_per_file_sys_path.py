"""Guard the TST-G1A class: no per-file sys.path juggling under tests/.

tests/conftest.py exists precisely so a test can import panopticon's packages
with no boilerplate -- its docstring records that 18 tests/tools/ files each
repeated the same `sys.path.insert(...)` line before #547 centralized it, and
#1210 removed the last 18. `tests/test_bump_pins.py` then landed with a fresh
one, so run-11 re-found the class (#1527).

A per-file insert is not merely redundant: it is an unscoped, module-level,
never-undone mutation of sys.path that persists for the rest of the pytest
session, so what it shadows depends on collection order.

The conftest-consistent way to reach repo-root `scripts/` is `import bump_pins`
(that directory is already on the path), NOT `from scripts import bump_pins` --
conftest deliberately does not add the repo root, because doing so would add a
second portion to the `scripts` namespace package.
"""
import pathlib
import re
import unittest

SELF = pathlib.Path(__file__).resolve()
ROOT = SELF.parent
CONFTEST = ROOT / "conftest.py"
# conftest.py is the ONE file allowed to set the path up; this file quotes the
# pattern in its docstring and plants it in a fixture, so it exempts itself --
# test_detector_catches_a_planted_offender keeps that from going vacuous.
_EXEMPT = frozenset({CONFTEST, SELF})
_SYS_PATH_MUTATION = re.compile(r"\bsys\.path\s*\.\s*(insert|append|extend)\s*\(")


def _mutation_sites(path):
    out = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if _SYS_PATH_MUTATION.search(line):
            out.append((i + 1, stripped))
    return out


class TestNoPerFileSysPath(unittest.TestCase):
    def test_only_conftest_touches_sys_path(self):
        offenders = []
        for path in sorted(ROOT.rglob("*.py")):
            if path.resolve() in _EXEMPT:
                continue
            for lineno, text in _mutation_sites(path):
                offenders.append("%s:%d  %s"
                                 % (path.relative_to(ROOT.parent), lineno, text))
        self.assertEqual(
            offenders, [],
            "Per-file sys.path mutation under tests/ (TST-G1A). tests/conftest.py "
            "already puts tests/, skill/, skill/scripts/ and scripts/ on the path "
            "-- import through it (`import bump_pins`, not `from scripts import "
            "bump_pins`):\n  " + "\n  ".join(offenders))

    def test_conftest_still_sets_the_path_up(self):
        # The guard above is only meaningful while conftest actually does the
        # job the other files are being told to rely on.
        self.assertTrue(_mutation_sites(CONFTEST),
                        "conftest.py no longer sets sys.path up; the guard above "
                        "would now be enforcing an empty promise")

    def test_detector_catches_a_planted_offender(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "test_planted.py"
            p.write_text("import sys\nsys.path.insert(0, '/x')\n")
            self.assertTrue(_mutation_sites(p), "detector missed a per-file insert")
            p.write_text("import sys\n# sys.path.insert(0, '/x')\nprint(sys.path)\n")
            self.assertEqual(_mutation_sites(p), [],
                             "detector flagged a commented-out insert")


if __name__ == "__main__":
    unittest.main()
