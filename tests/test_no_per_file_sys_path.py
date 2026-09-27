"""Guard declarative test import roots and canonical test helper imports."""
import ast
import os
import pathlib
import subprocess
import sys
import tempfile
import tomllib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
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
            for path in sorted(root.rglob("*.py"))
            for lineno, text in _mutation_sites(path)]


class TestNoPerFileSysPath(unittest.TestCase):
    def test_helpers_import_without_plugin_or_allocations(self):
        code = '''import os, pathlib, sys, tempfile
def forbidden(*args, **kwargs):
    raise AssertionError("helper import allocated a temporary directory")
tempfile.mkdtemp = forbidden
before = (os.environ["HOME"], os.environ["USERPROFILE"], os.environ["PATH"], tuple(sys.path),
          tuple(sorted(pathlib.Path(os.environ["TMPDIR"]).iterdir())))
for name in sys.argv[1:]:
    __import__(name)
after = (os.environ["HOME"], os.environ["USERPROFILE"], os.environ["PATH"], tuple(sys.path),
         tuple(sorted(pathlib.Path(os.environ["TMPDIR"]).iterdir())))
assert before == after, (before, after)
assert not ({"conftest", "tests.conftest", "scripts.hosts"} & sys.modules.keys())
'''
        with tempfile.TemporaryDirectory() as directory:
            env = dict(os.environ, HOME=directory, USERPROFILE=directory,
                       TMPDIR=directory, PYTHONPATH=str(ROOT.parent))
            env.pop("PANOPTICON_TEST_HOME", None)
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            modules = ["tests._test_helpers", "tests.tools.helpers",
                       "tests.tools.git_repo", "tests.run_tools_test_helpers"]
            for order in (modules, list(reversed(modules))):
                result = subprocess.run([sys.executable, "-c", code, *order],
                                        cwd=directory, env=env,
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_external_cwd_selected_collection_has_one_canonical_identity(self):
        code = '''import pathlib, sys, pytest
root = pathlib.Path(sys.argv[1]).resolve()
class Check:
    def pytest_collection_finish(self, session):
        sources = {}
        for name, module in tuple(sys.modules.items()):
            path = getattr(module, "__file__", None)
            if not path or not path.endswith(".py"):
                continue
            resolved = pathlib.Path(path).resolve()
            if not resolved.is_relative_to(root / "tests") or resolved.name == "conftest.py":
                continue
            assert name == "tests" or name.startswith("tests."), (name, resolved)
            sources.setdefault(resolved, set()).add(id(module))
        assert all(len(ids) == 1 for ids in sources.values()), sources
        assert "conftest" not in sys.modules
        from tests.tools import git_repo
        from scripts import hosts, tools
        assert pathlib.Path(git_repo.__file__).resolve() == root / "tests/tools/git_repo.py"
        assert pathlib.Path(hosts.__file__).resolve() == root / "skill/scripts/hosts.py"
        assert pathlib.Path(tools.__file__).resolve() == root / "skill/scripts/tools/__init__.py"
        assert session.items, "selected collection found no tests"
raise SystemExit(pytest.main(["-c", str(root / "pyproject.toml"), "--collect-only", "-q",
                              *sys.argv[2:]], plugins=[Check()]))
'''
        with tempfile.TemporaryDirectory() as directory:
            env = dict(os.environ)
            env.pop("PYTHONPATH", None)
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            selected = [ROOT / "test_diff_map.py", ROOT / "test_tree_baseline.py"]
            for order in (selected, list(reversed(selected))):
                result = subprocess.run([sys.executable, "-c", code,
                                         str(ROOT.parent), *(str(p) for p in order)],
                                        cwd=directory, env=env, capture_output=True,
                                        text=True, timeout=45)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_no_test_file_touches_sys_path(self):
        offenders = _tree_offenders(ROOT)
        self.assertEqual(
            offenders, [],
            "Test-side sys.path mutation under tests/ (TST-G1A):\n  "
            + "\n  ".join(offenders))

    def test_pytest_roots_are_declarative(self):
        config = tomllib.loads((ROOT.parent / "pyproject.toml").read_text())
        options = config["tool"]["pytest"]["ini_options"]
        self.assertEqual(options["pythonpath"], ["skill", "skill/scripts", "scripts", "."])
        self.assertIn("--import-mode=importlib", options["addopts"])

    def test_test_imports_are_canonical(self):
        offenders = []
        local = {path.stem for path in ROOT.rglob("*.py") if path.stem != "__init__"}
        for path in ROOT.rglob("*.py"):
            tree = ast.parse(path.read_text(), filename=str(path))
            for node in ast.walk(tree):
                names = ([alias.name for alias in node.names] if isinstance(node, ast.Import)
                         else ["." * node.level + (node.module or "")]
                         if isinstance(node, ast.ImportFrom) else [])
                for name in names:
                    if (name == "conftest" or name.endswith(".conftest")
                            or name in local or name.startswith("tools.")
                            or name == "tools"):
                        offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}: {name}")
        self.assertEqual(offenders, [])

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

    def test_all_conftests_are_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "tests"
            (root / "nested").mkdir(parents=True)
            for path in (root / "conftest.py", root / "nested" / "conftest.py"):
                path.write_text("import sys\nsys.path.clear()\n")
            self.assertEqual(_tree_offenders(root),
                             ["tests/conftest.py:2  sys.path.clear()",
                              "tests/nested/conftest.py:2  sys.path.clear()"])


if __name__ == "__main__":
    unittest.main()
