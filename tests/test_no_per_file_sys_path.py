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
import io
import pathlib
import tokenize
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
CONFTEST = ROOT / "conftest.py"
_MUTATORS = frozenset({"insert", "append", "extend"})


def _mutation_sites(path):
    """Real `sys.path.<mutator>(` CALLS, found by tokenizing rather than
    grepping.

    A regex over raw lines flagged this file's own docstring and its planted
    fixtures, which is why this guard used to have to exempt itself. Tokens
    carry no prose: a comment or a string that merely NAMES the pattern is not
    a call, so the exemption is gone and the guard covers itself.
    """
    source = path.read_text(encoding="utf-8")
    names = []
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type == tokenize.NAME or (token.type == tokenize.OP
                                               and token.string in (".", "(")):
                names.append(token)
    except (tokenize.TokenError, SyntaxError) as exc:
        raise AssertionError("%s does not tokenize: %s" % (path, exc)) from exc
    lines = source.splitlines()
    out = []
    for i in range(len(names) - 5):
        window = [t.string for t in names[i:i + 6]]
        if window == ["sys", ".", "path", ".", window[4], "("] and window[4] in _MUTATORS:
            lineno = names[i].start[0]
            out.append((lineno, lines[lineno - 1].strip()))
    return out


class TestNoPerFileSysPath(unittest.TestCase):
    def test_only_conftest_touches_sys_path(self):
        offenders = []
        for path in sorted(ROOT.rglob("*.py")):
            if path.resolve() == CONFTEST:
                continue          # the one place that is allowed to do this
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
            p.write_text('"""Prose naming sys.path.insert(0, x)."""\n'
                         'NOTE = "sys.path.append(1)"\n')
            self.assertEqual(_mutation_sites(p), [],
                             "detector flagged the pattern inside a string")
            p.write_text("import sys\nsys.path .extend(['/x'])\n")
            self.assertTrue(_mutation_sites(p),
                            "detector missed a call written with odd spacing")


if __name__ == "__main__":
    unittest.main()
