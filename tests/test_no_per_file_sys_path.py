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
import ast
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
CONFTEST = ROOT / "conftest.py"
_MUTATORS = frozenset({"insert", "append", "extend", "remove", "pop", "clear",
                       "reverse", "sort", "__setitem__", "__delitem__",
                       "__iadd__", "__imul__"})


def _mutation_sites(path):
    """Find AST writes to sys.path, including ordinary import aliases.

    Imported path names may be mutated in place; assigning a new value to
    that local name alone only rebinds it and does not change sys.path.
    This is a static guard, not interprocedural alias/data-flow analysis.
    """
    source = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        raise AssertionError("%s does not parse: %s" % (path, exc)) from exc
    modules, paths = {"sys"}, set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.asname or alias.name for alias in node.names
                           if alias.name == "sys")
        elif isinstance(node, ast.ImportFrom) and node.module == "sys":
            paths.update(alias.asname or alias.name for alias in node.names
                         if alias.name == "path")

    def module_path(node):
        return (isinstance(node, ast.Attribute) and node.attr == "path"
                and isinstance(node.value, ast.Name) and node.value.id in modules)

    def path_value(node):
        return module_path(node) or (isinstance(node, ast.Name) and node.id in paths)

    lines, hits = source.splitlines(), set()
    for node in ast.walk(tree):
        if (module_path(node) and isinstance(node.ctx, (ast.Store, ast.Del))
                or isinstance(node, ast.Subscript) and path_value(node.value)
                and isinstance(node.ctx, (ast.Store, ast.Del))
                or isinstance(node, ast.AugAssign) and path_value(node.target)
                or isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and path_value(node.func.value) and node.func.attr in _MUTATORS):
            hits.add(node.lineno)
    return [(line, lines[line - 1].strip()) for line in sorted(hits)]


def _tree_offenders(root):
    return ["%s:%d  %s" % (path.relative_to(root.parent), lineno, text)
            for path in sorted(root.rglob("*.py")) if path != root / "conftest.py"
            for lineno, text in _mutation_sites(path)]


class TestNoPerFileSysPath(unittest.TestCase):
    def test_only_conftest_touches_sys_path(self):
        offenders = _tree_offenders(ROOT)
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

    def test_detector_catches_planted_mutations(self):
        mutations = ["sys.path = []", "sys.path: list = []", "del sys.path",
                     "sys.path[0] = '/x'", "sys.path[:] = []", "del sys.path[0]",
                     "del sys.path[:]", "sys.path += ['/x']", "sys.path *= 2",
                     "sys.path, other = [], 1"]
        mutations += ["sys.path.insert(0, '/x')", "sys.path.append('/x')",
                      "sys.path .extend(['/x'])", "sys.path.remove('/x')",
                      "sys.path.pop()", "sys.path.clear()", "sys.path.reverse()",
                      "sys.path.sort()", "sys.path.__setitem__(0, '/x')",
                      "sys.path.__delitem__(0)", "sys.path.__iadd__(['/x'])",
                      "sys.path.__imul__(2)"]
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "test_planted.py"
            for source in mutations:
                for prefix, expression in (
                        ("import sys", source),
                        ("import sys as system", source.replace("sys.", "system."))):
                    with self.subTest(source=source, prefix=prefix):
                        path.write_text(prefix + "\n" + expression + "\n")
                        self.assertEqual(_mutation_sites(path), [(2, expression)])
            for source in ("entries.append('/x')", "entries[:] = []",
                           "del entries[0]", "entries += ['/x']"):
                path.write_text("from sys import path as entries\n" + source + "\n")
                self.assertEqual(_mutation_sites(path), [(2, source)])
            path.write_text("from sys import path\npath.clear()\n")
            self.assertEqual(_mutation_sites(path), [(2, "path.clear()")])

    def test_prose_reads_and_local_rebinding_are_harmless(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "test_planted.py"
            path.write_text('import sys\n# sys.path.clear()\n'
                            'NOTE = "sys.path = []"\n'
                            'print(sys.path, sys.path[0], sys.path[:])\n'
                            'sys.path.count("/x")\n'
                            'from sys import path as entries\n'
                            'entries = []\n'
                            'other.path.append("/x")\n')
            self.assertEqual(_mutation_sites(path), [])

    def test_parse_errors_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "test_broken.py"
            path.write_text("import sys\nsys.path = [\n")
            with self.assertRaisesRegex(AssertionError, "does not parse"):
                _mutation_sites(path)

    def test_only_canonical_conftest_is_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "tests"
            (root / "nested").mkdir(parents=True)
            for path in (root / "conftest.py", root / "nested" / "conftest.py"):
                path.write_text("import sys\nsys.path.clear()\n")
            self.assertEqual(_tree_offenders(root),
                             ["tests/nested/conftest.py:2  sys.path.clear()"])


if __name__ == "__main__":
    unittest.main()
