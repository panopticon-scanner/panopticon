"""#3506: one import shape, kept that way by the AST (#3505, part of #1516).

Every module under `skill/scripts/` is imported as `scripts.<name>`, with
`skill/` on sys.path. An entry script run by path gets `skill/` there from
`skill/scripts/_bootstrap.py`, which it runs by its own `__file__`; a devtools
CLI runs `devtools/_skill_bootstrap.py`, which runs that same file. Nothing
else edits sys.path, so no file can load under two names (`x` and `scripts.x`),
which is how two module objects with two sets of state and two patch targets
used to appear.

The rules, each over `skill/scripts/`, `devtools/` and `tests/`:

1. no sys.path write outside `skill/scripts/_bootstrap.py`;
2. no import fallback for a module of this tree (a `try:` import whose
   ImportError arm imports something else), and no `__package__` switch, which
   is the same fallback spelled as a branch;
3. no bare import of a `skill/scripts` module (`import evidence`,
   `from evidence import x`, `import skill.scripts.evidence`): only
   `scripts.*` names it;
4. every entry script that imports `scripts.*` runs its bootstrap in its
   `if __name__ == "__main__":` block before the first such import;
5. the count of `noqa: E402` comments per surface only goes down;
6. `runpy.run_path` (in skill/scripts and devtools) runs only the sibling
   bootstrap, so the by-path load cannot become a way to run anything else.

Plus the measurements that motivate them: a driver-shaped process loads no file
twice, at import and at call time; an installed copy of the skill, run by path
from a target repo with its own `scripts/` and a decoy `scripts` package on
PYTHONPATH, imports only its own modules; and the `devtools/` and
`skill/scripts/` portions share no module name.

This replaces tests/test_no_per_file_sys_path.py and the import half of
tests/test_module_identity.py (owner ruling on #3506); their checks live here.
"""
import ast
import importlib
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import tokenize
import tomllib
import unittest

from tests._test_helpers import REPO_ROOT, SKILL_ROOT

ROOT = pathlib.Path(REPO_ROOT)
SCRIPTS = ROOT / "skill" / "scripts"
DEVTOOLS = ROOT / "devtools"
TESTS = ROOT / "tests"
SURFACES = (SCRIPTS, DEVTOOLS, TESTS)

# Rule 1: the one sys.path write, and how many sites it has.
PERMITTED_WRITES = {"skill/scripts/_bootstrap.py": 1}

# Rule 4: the file each surface's entry scripts run by path.
BOOTSTRAP_FOR = {SCRIPTS: "_bootstrap.py", DEVTOOLS: "_skill_bootstrap.py"}

# Rule 5: E402 suppressions per surface. Shrink-only: a count that goes down is
# lowered here in the same change, and one that goes up fails. The 26 in tests/
# are real (imports after conftest's environment setup, and the like).
E402_CEILING = {"skill/scripts": 0, "devtools": 0, "tests": 26}

_MUTATORS = frozenset({"insert", "append", "extend", "remove", "pop", "clear",
                       "reverse", "sort", "__setitem__", "__delitem__",
                       "__iadd__", "__imul__"})
_IMPORT_ERRORS = frozenset({"ImportError", "ModuleNotFoundError"})


def _parse(path):
    source = path.read_text(encoding="utf-8")
    try:
        return source, ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        raise AssertionError("%s does not parse: %s" % (path, exc)) from exc


def _py_files(root):
    """Every Python file under `root`, fixtures and goldens included."""
    return sorted(p for p in pathlib.Path(root).rglob("*.py") if "__pycache__" not in p.parts)


def _rel(path):
    return str(pathlib.Path(path).relative_to(ROOT))


def _module_names(directory):
    """The importable top-level names of one flat directory."""
    directory = pathlib.Path(directory)
    return ({p.stem for p in directory.glob("*.py") if p.stem != "__init__"}
            | {p.name for p in directory.iterdir()
               if p.is_dir() and (p / "__init__.py").exists()})


SKILL_MODULES = frozenset(_module_names(SCRIPTS))
DEVTOOLS_MODULES = frozenset(_module_names(DEVTOOLS))


# --- rule 1: sys.path writes ------------------------------------------------

def _mutation_sites(path):
    """AST writes to sys.path, through any alias this file can see.

    Caught: a store, delete, slice or subscript assignment, augmented
    assignment or mutating method call on `sys.path`, reached as `sys.path`
    (with `sys` under any import name), `getattr(sys, "path")`, a
    `from sys import path` name, or a local name bound to any of those
    (`_p = sys.path`); `setattr(sys, "path", ...)`; and `site.addsitedir(...)`.
    Rebinding a name to a new value changes nothing and is not a write. This is
    a static guard, not interprocedural data-flow analysis.
    """
    source, tree = _parse(path)
    modules, paths, site_modules, site_calls = {"sys"}, set(), {"site"}, set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "sys":
                    modules.add(alias.asname or alias.name)
                elif alias.name == "site":
                    site_modules.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module == "sys":
            paths.update(alias.asname or alias.name for alias in node.names
                         if alias.name == "path")
        elif isinstance(node, ast.ImportFrom) and node.module == "site":
            site_calls.update(alias.asname or alias.name for alias in node.names
                              if alias.name == "addsitedir")

    def names(node, *wanted):
        return isinstance(node, ast.Name) and node.id in wanted

    def sys_attr_call(node, func):
        # `getattr(sys, "path")` / `setattr(sys, "path", ...)`
        return (isinstance(node, ast.Call) and names(node.func, func)
                and len(node.args) >= 2 and names(node.args[0], *modules)
                and isinstance(node.args[1], ast.Constant) and node.args[1].value == "path")

    def path_value(node):
        return (isinstance(node, ast.Attribute) and node.attr == "path"
                and names(node.value, *modules)
                or sys_attr_call(node, "getattr")
                or names(node, *paths))

    # Local aliases, to a fixed point: `_p = sys.path`, `_q = _p`, `(_r := _p)`.
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            targets, value = [], None
            if isinstance(node, ast.Assign):
                targets, value = node.targets, node.value
            elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)) and node.value is not None:
                targets, value = [node.target], node.value
            if value is not None and path_value(value):
                for target in targets:
                    if isinstance(target, ast.Name) and target.id not in paths:
                        paths.add(target.id)
                        changed = True

    lines, hits = source.splitlines(), set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Attribute) and node.attr == "path" and names(node.value, *modules)
                and isinstance(node.ctx, (ast.Store, ast.Del))
                or isinstance(node, ast.Subscript) and path_value(node.value)
                and isinstance(node.ctx, (ast.Store, ast.Del))
                or isinstance(node, ast.AugAssign) and path_value(node.target)
                or isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and path_value(node.func.value) and node.func.attr in _MUTATORS
                or sys_attr_call(node, "setattr")
                or isinstance(node, ast.Call) and (
                    isinstance(node.func, ast.Attribute) and node.func.attr == "addsitedir"
                    and names(node.func.value, *site_modules)
                    or names(node.func, *site_calls))):
            hits.add(node.lineno)
    return [(line, lines[line - 1].strip()) for line in sorted(hits)]


def _tree_offenders(root):
    """`file:line  text` for every sys.path write under `root`, over the same
    walk the production check uses."""
    root = pathlib.Path(root)
    return ["%s:%d  %s" % (path.relative_to(root.parent), lineno, text)
            for path in _py_files(root)
            for lineno, text in _mutation_sites(path)]


# --- rule 2: import fallbacks -------------------------------------------------

def _ours(name):
    top = name.split(".")[0]
    return top in ("scripts", "skill") or top in SKILL_MODULES or top in DEVTOOLS_MODULES


def _imported_names(node):
    if isinstance(node, ast.Import):
        return [alias.name for alias in node.names]
    if isinstance(node, ast.ImportFrom) and not node.level and node.module:
        return [node.module]
    return []


def _catches_import_errors(handler):
    """An arm that names ImportError or ModuleNotFoundError. A broad arm
    (`except Exception:`) swallowing a lazy import is not a fallback mode, and
    a broad arm that imports a bare name is rule 3's."""
    if handler.type is None:
        return False
    names = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    return any(isinstance(n, ast.Name) and n.id in _IMPORT_ERRORS for n in names)


def _fallback_sites(path):
    """A `try:` that imports one of our modules and has an arm catching its
    ImportError, or a read of `__package__` (the same switch as a branch)."""
    _, tree = _parse(path)
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Try) and any(map(_catches_import_errors, node.handlers)):
            body_imports = [name for stmt in node.body for sub in ast.walk(stmt)
                            for name in _imported_names(sub)]
            if any(_ours(name) for name in body_imports):
                hits.append((node.lineno, "try-import fallback for %s"
                             % ", ".join(sorted(n for n in body_imports if _ours(n)))))
        elif isinstance(node, ast.Name) and node.id == "__package__":
            hits.append((node.lineno, "__package__ switch"))
    return hits


# --- rule 3: bare imports -----------------------------------------------------

def _dynamic_import_names(node):
    """The literal module name of `__import__("x")` / `import_module("x")`."""
    if not (isinstance(node, ast.Call) and node.args
            and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
        return []
    func = node.func
    name = func.id if isinstance(func, ast.Name) else (
        func.attr if isinstance(func, ast.Attribute) else None)
    return [node.args[0].value] if name in ("__import__", "import_module") else []


def _bare_import_sites(path):
    """Imports that name a skill/scripts module other than as `scripts.*`,
    including a literal `__import__("x")` or `importlib.import_module("x")`."""
    _, tree = _parse(path)
    hits = []
    for node in ast.walk(tree):
        for name in _imported_names(node) + _dynamic_import_names(node):
            top = name.split(".")[0]
            if top in SKILL_MODULES or top == "skill":
                hits.append((node.lineno, name))
    return hits


def _test_import_sites(path, local):
    """tests/ imports that bypass the `tests.*` package (or reach a conftest)."""
    tree = ast.parse(path.read_text(), filename=str(path))
    offenders = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = ["." * node.level + (node.module or "")]
            if (node.level or node.module == "tests"
                    or (node.module or "").startswith("tests.")):
                names.extend(alias.name for alias in node.names
                             if alias.name == "conftest")
        else:
            continue
        for name in names:
            if (name == "conftest" or name.endswith(".conftest")
                    or name in local or name.startswith("tools.")
                    or name == "tools"):
                offenders.append((node.lineno, name))
    return offenders


# --- rule 4: entry scripts bootstrap -----------------------------------------

def _is_main_guard(node):
    return (isinstance(node, ast.If) and isinstance(node.test, ast.Compare)
            and isinstance(node.test.left, ast.Name) and node.test.left.id == "__name__"
            and len(node.test.comparators) == 1
            and isinstance(node.test.comparators[0], ast.Constant)
            and node.test.comparators[0].value == "__main__"
            and isinstance(node.test.ops[0], ast.Eq))


def _runs_bootstrap(node, filename):
    """A `__main__` block whose body calls `runpy.run_path(... "<filename>")`."""
    if not _is_main_guard(node):
        return False
    for sub in ast.walk(node):
        if (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute)
                and sub.func.attr == "run_path"
                and any(isinstance(c, ast.Constant) and c.value == filename
                        for c in ast.walk(sub))):
            return True
    return False


def _top_level_imports(tree):
    return [(node.lineno, name) for node in tree.body for name in _imported_names(node)]


def _needs_scripts(tree, surface):
    """Module-level imports that need `skill/` on sys.path: `scripts.*` itself,
    or (in devtools/) a sibling that does."""
    direct = [line for line, name in _top_level_imports(tree)
              if name.split(".")[0] == "scripts"]
    if surface != DEVTOOLS:
        return direct
    needing = _devtools_needing_scripts()
    return direct + [line for line, name in _top_level_imports(tree)
                     if name.split(".")[0] in needing]


def _devtools_needing_scripts():
    """devtools modules whose import, directly or through siblings, needs `scripts`."""
    deps, needs = {}, set()
    for path in _py_files(DEVTOOLS):
        _, tree = _parse(path)
        names = [name.split(".")[0] for _, name in _top_level_imports(tree)]
        deps[path.stem] = {n for n in names if n in DEVTOOLS_MODULES}
        if "scripts" in names:
            needs.add(path.stem)
    changed = True
    while changed:
        changed = False
        for module, siblings in deps.items():
            if module not in needs and siblings & needs:
                needs.add(module)
                changed = True
    return needs


def _entry_offenders(surface, files=None):
    """Entry scripts (a `__main__` block) whose module-level imports need
    `skill/` before any block runs its bootstrap."""
    filename = BOOTSTRAP_FOR[surface]
    offenders = []
    for path in files or sorted(surface.glob("*.py")):
        if path.name in BOOTSTRAP_FOR.values():
            continue
        _, tree = _parse(path)
        if not any(_is_main_guard(node) for node in tree.body):
            continue
        needs = _needs_scripts(tree, surface)
        if not needs:
            continue
        boots = [node.lineno for node in tree.body if _runs_bootstrap(node, filename)]
        if not boots or min(boots) > min(needs):
            offenders.append("%s:%d" % (path.name, min(needs)))
    return offenders


_SIBLING = 'os.path.join(os.path.dirname(os.path.realpath(__file__)), %r)'


def _run_path_offenders(path, surface):
    """`run_path` calls that are not exactly `runpy.run_path(<the sibling
    bootstrap>)`, the sibling spelled from this file's own realpath. A matching
    file name joined to any other directory (the cwd, a variable) is refused."""
    _, tree = _parse(path)
    allowed = ast.dump(ast.parse(_SIBLING % BOOTSTRAP_FOR[surface], mode="eval").body)
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and (
                isinstance(node.func, ast.Attribute) and node.func.attr == "run_path"
                or isinstance(node.func, ast.Name) and node.func.id == "run_path"):
            exact = (ast.unparse(node.func) == "runpy.run_path" and not node.keywords
                     and len(node.args) == 1 and ast.dump(node.args[0]) == allowed)
            if not exact:
                hits.append((node.lineno, ast.unparse(node)))
    return hits


# --- rule 5: the E402 ratchet ------------------------------------------------

_NOQA_CODES = re.compile(r"noqa:\s*([A-Z]+[0-9]+(?:\s*,\s*[A-Z]+[0-9]+)*)")


def _e402_count(paths):
    """`noqa` comments whose code list names E402 (prose after it does not count)."""
    count = 0
    for path in paths:
        source = path.read_text(encoding="utf-8")
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            match = token.type == tokenize.COMMENT and _NOQA_CODES.search(token.string)
            if match:
                count += "E402" in re.split(r"\s*,\s*", match.group(1))
    return count


# --- the process the rules protect -------------------------------------------

def _python(args, cwd, pythonpath, extra_env=None, timeout=180):
    """One fresh interpreter, elsewhere, with exactly `pythonpath` set."""
    env = {key: value for key, value in os.environ.items()
           if not key.startswith("PYTHON") and key != "PANOPTICON_TEST_HOME"}
    env.update(extra_env or {})
    env["PYTHONPATH"] = os.pathsep.join(pythonpath)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    # Keep the trusted interpreter argv visible as the sole positional argument.
    argv = [sys.executable, "-B", *args]
    popenargs = [argv]
    return subprocess.run(
        *popenargs, cwd=cwd, env=env,
        capture_output=True, text=True, timeout=timeout)


# Pair detection by FILE identity: `x` and `scripts.x` are one file loaded twice.
_CENSUS_TAIL = """
files = {}
for name, module in list(sys.modules.items()):
    path = getattr(module, "__file__", None)
    if path and os.path.realpath(path).startswith(ROOT):
        files.setdefault(os.path.realpath(path), []).append(name)
print(json.dumps(sorted(sorted(names) for names in files.values() if len(names) > 1)))
"""
_CENSUS_HEAD = "import json\nimport os\nimport sys\nROOT = %r\n"

# The three modules `driver run` loads on any invocation, then five setup paths
# CALLED, which is the only way to see an import inside a function body.
_DRIVER_IMPORTS = ("import scripts.driver\nimport scripts.setup_flow\n"
                   "import scripts.dispatch\n")
_SETUP_CALLS = ("scripts.setup_spine.load_bundled_layers()\n"
                "scripts.setup_spine.load_bundled_vocabulary()\n"
                "scripts.setup_spine.build_spine('.')\n"
                "try:\n"
                "    scripts.setup_config.migrate_config('.')\n"
                "except ValueError:\n"
                "    pass\n"
                "scripts.discovery_catalog._capability_aliases()\n")

# The audit an installed run carries in a `sitecustomize` on PYTHONPATH: at exit,
# every file of the installed skill loaded under two names, and the directories
# every `scripts.*` module came from.
_AUDIT = """import atexit, json, os, sys
def _audit():
    root = os.environ["AUDIT_ROOT"]
    files, dirs = {}, set()
    for name, module in list(sys.modules.items()):
        path = getattr(module, "__file__", None)
        if not path:
            continue
        path = os.path.realpath(path)
        if path.startswith(root):
            files.setdefault(path, []).append(name)
        if name == "scripts" or name.startswith("scripts."):
            dirs.add(os.path.dirname(path))
    doubled = sorted(sorted(v) for v in files.values() if len(v) > 1)
    with open(os.environ["AUDIT_OUT"], "w") as fh:
        json.dump({"doubled": doubled, "dirs": sorted(dirs)}, fh)
atexit.register(_audit)
"""

# Entry scripts the installed-skill run drives, each with `--help` (imports
# everything at module level, then exits 0 without touching the target).
_INSTALLED_ENTRIES = ("driver.py", "dispatch.py", "discovery.py", "synthesize.py",
                      "security_gate.py", "run_tools.py", "reconcile.py",
                      "collect_usage.py", "run_fixture_tests.py",
                      "capture_goldens.py", "model_resolver.py")


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class SysPathWriteTest(unittest.TestCase):
    """Rule 1."""

    def test_the_bootstrap_is_the_only_sys_path_write(self):
        found = {}
        for surface in SURFACES:
            for offender in _tree_offenders(surface):
                where = offender.split(":", 1)[0]
                rel = _rel(surface.parent / where)
                found[rel] = found.get(rel, 0) + 1
        self.assertEqual(
            found, PERMITTED_WRITES,
            "sys.path is written only by skill/scripts/_bootstrap.py (#3505). An "
            "entry script runs it by path in its `__main__` block; a devtools CLI "
            "runs devtools/_skill_bootstrap.py, which runs the same file.")

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
            # The escapes a text guard missed: an alias by assignment (and
            # through a second name, a walrus, getattr), setattr, addsitedir.
            for source, expression in (
                    ("import sys\n_p = sys.path\n", "_p.insert(0, '/x')"),
                    ("import sys\n_p = sys.path\n_q = _p\n", "_q.append('/x')"),
                    ("import sys\n(_p := sys.path)\n", "_p[:] = []"),
                    ("import sys\n_p = getattr(sys, 'path')\n", "_p.extend(['/x'])"),
                    ("import sys\n", "getattr(sys, 'path').insert(0, '/x')"),
                    ("import sys\n", "setattr(sys, 'path', [])"),
                    ("import site\n", "site.addsitedir('/x')"),
                    ("import site as s\n", "s.addsitedir('/x')"),
                    ("from site import addsitedir\n", "addsitedir('/x')")):
                with self.subTest(source=source + expression):
                    path.write_text(source + expression + "\n")
                    line = source.count("\n") + 1
                    self.assertEqual(_mutation_sites(path), [(line, expression)])

    def test_prose_reads_and_local_rebinding_are_harmless(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "test_planted.py"
            path.write_text('import sys\n# sys.path.clear()\n'
                            'NOTE = "sys.path = []"\n'
                            'print(sys.path, sys.path[0], sys.path[:])\n'
                            'sys.path.count("/x")\n'
                            'from sys import path as entries\n'
                            'entries = []\n'
                            'other.path.append("/x")\n'
                            'snapshot = list(sys.path)\n'
                            'snapshot.append("/x")\n'
                            'getattr(sys, "argv").append("x")\n'
                            'other.addsitedir("/x")\n')
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
            (root / "fixtures").mkdir()
            for path in (root / "conftest.py", root / "nested" / "conftest.py",
                         root / "fixtures" / "conftest.py"):
                path.write_text("import sys\nsys.path.clear()\n")
            self.assertEqual(_tree_offenders(root),
                             ["tests/conftest.py:2  sys.path.clear()",
                              "tests/fixtures/conftest.py:2  sys.path.clear()",
                              "tests/nested/conftest.py:2  sys.path.clear()"])


class ImportFallbackTest(unittest.TestCase):
    """Rule 2."""

    def test_no_module_of_this_tree_has_an_import_fallback(self):
        offenders = ["%s:%d  %s" % (_rel(path), line, what)
                     for surface in SURFACES for path in _py_files(surface)
                     for line, what in _fallback_sites(path)]
        self.assertEqual(
            offenders, [],
            "an import of this tree with a fallback arm: `scripts.*` always "
            "resolves now (#3505), so the arm is a second module name waiting "
            "to happen. Import `scripts.<name>` once, with no try.")

    def test_the_detector_reads_the_shape(self):
        planted = {
            "try:\n    from scripts import x\nexcept ModuleNotFoundError:\n    import x\n": 1,
            "try:\n    import scripts.x as x\nexcept ImportError:\n    x = None\n": 1,
            "try:\n    from scripts import x\nexcept (OSError, ImportError):\n    pass\n": 1,
            "try:\n    from scripts import x\nexcept Exception:\n    pass\n": 0,
            "try:\n    from scripts import x\nexcept:\n    pass\n": 0,
            "if True:\n    try:\n        import evidence\n"
            "    except ImportError:\n        pass\n": 1,
            "root = 'scripts.' if __package__ else ''\n": 1,
            # Third-party, or no import-error arm: not a fallback.
            "try:\n    import yaml\nexcept ImportError:\n    yaml = None\n": 0,
            "try:\n    from scripts import x\nexcept ValueError:\n    pass\n": 0,
            "from scripts import x\n": 0,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "planted.py"
            for source, expected in planted.items():
                with self.subTest(source=source):
                    path.write_text(source)
                    self.assertEqual(len(_fallback_sites(path)), expected)


class BareImportTest(unittest.TestCase):
    """Rule 3, plus the tests/ package rule it grew from."""

    def test_skill_modules_are_imported_only_as_scripts(self):
        offenders = ["%s:%d  %s" % (_rel(path), line, name)
                     for surface in SURFACES for path in _py_files(surface)
                     for line, name in _bare_import_sites(path)]
        self.assertEqual(
            offenders, [],
            "a skill/scripts module imported under its bare name loads a second "
            "copy of `scripts.<name>`. Write `from scripts import <name>`.")

    def test_the_detector_sees_every_spelling(self):
        planted = {"import evidence\n": 1, "from evidence import x\n": 1,
                   "import evidence as e\n": 1, "import phases.engine\n": 1,
                   "import skill.scripts.evidence\n": 1,
                   "from skill.scripts import evidence\n": 1,
                   "def f():\n    import evidence\n": 1,
                   "__import__('groups_schema').parse_groups({})\n": 1,
                   "importlib.import_module('evidence')\n": 1,
                   "importlib.import_module('scripts.evidence')\n": 0,
                   "__import__('json')\n": 0,
                   "from scripts import evidence\n": 0,
                   "import scripts.evidence as evidence\n": 0,
                   "from . import engine\n": 0, "import json\n": 0}
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "planted.py"
            for source, expected in planted.items():
                with self.subTest(source=source):
                    path.write_text(source)
                    self.assertEqual(len(_bare_import_sites(path)), expected)

    def test_test_imports_are_canonical(self):
        offenders = []
        local = {path.stem for path in TESTS.rglob("*.py") if path.stem != "__init__"}
        for path in TESTS.rglob("*.py"):
            offenders.extend(f"{path.relative_to(TESTS)}:{line}: {name}"
                             for line, name in _test_import_sites(path, local))
        self.assertEqual(offenders, [])

    def test_import_detector_catches_conftest_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "test_planted.py"
            for statement in ("import conftest", "import tests.conftest",
                              "from tests import conftest",
                              "from tests.tools import conftest as plugin",
                              "from . import conftest"):
                with self.subTest(statement=statement):
                    path.write_text(statement + "\n")
                    self.assertEqual(len(_test_import_sites(path, {"conftest"})), 1)

    def test_pytest_roots_are_declarative(self):
        config = tomllib.loads((ROOT / "pyproject.toml").read_text())
        options = config["tool"]["pytest"]["ini_options"]
        self.assertEqual(options["pythonpath"], ["skill", "devtools", "."])
        self.assertIn("--import-mode=importlib", options["addopts"])


class EntryBootstrapTest(unittest.TestCase):
    """Rule 4."""

    def test_every_entry_script_bootstraps_before_it_imports_scripts(self):
        offenders = [*_entry_offenders(SCRIPTS), *_entry_offenders(DEVTOOLS)]
        self.assertEqual(
            offenders, [],
            "these entry scripts import `scripts.*` (or, in devtools/, a sibling "
            "that does) before running their bootstrap, so `python3 <file>` "
            "fails with ModuleNotFoundError. Put the `if __name__ == "
            "\"__main__\":` block that run_paths %s above the first such import."
            % " / ".join(sorted(BOOTSTRAP_FOR.values())))

    def test_the_check_has_entry_scripts_to_check(self):
        # Vacuity guard: the rule must see the documented entrypoints.
        for surface, name in ((SCRIPTS, "driver.py"), (SCRIPTS, "dispatch.py"),
                              (DEVTOOLS, "triage.py"), (DEVTOOLS, "file_issues.py")):
            _, tree = _parse(surface / name)
            self.assertTrue(_needs_scripts(tree, surface), name)
            self.assertTrue(any(_runs_bootstrap(n, BOOTSTRAP_FOR[surface])
                                for n in tree.body), name)

    def test_the_check_catches_a_missing_or_late_bootstrap(self):
        boot = ('if __name__ == "__main__":\n    import runpy\n'
                '    runpy.run_path(os.path.join(os.path.dirname(__file__), "_bootstrap.py"))\n')
        tail = 'def main():\n    pass\n\nif __name__ == "__main__":\n    main()\n'
        cases = {"import os\nfrom scripts import x\n" + tail: 1,
                 "import os\nfrom scripts import x\n" + boot + tail: 1,
                 "import os\n" + boot + "from scripts import x\n" + tail: 0,
                 "import os\n" + boot.replace("_bootstrap.py", "other.py")
                 + "from scripts import x\n" + tail: 1,
                 "import os\nfrom scripts import x\n": 0,     # not an entry script
                 "import os\n" + tail: 0}                     # imports nothing of ours
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "entry.py"
            for source, expected in cases.items():
                with self.subTest(source=source):
                    path.write_text(source)
                    self.assertEqual(len(_entry_offenders(SCRIPTS, [path])), expected)


class RunPathTest(unittest.TestCase):
    """Rule 6."""

    def test_run_path_runs_only_the_sibling_bootstrap(self):
        offenders = ["%s:%d  %s" % (_rel(path), line, text)
                     for surface in (SCRIPTS, DEVTOOLS) for path in _py_files(surface)
                     for line, text in _run_path_offenders(path, surface)]
        self.assertEqual(offenders, [], "runpy.run_path is for the bootstrap only "
                         "(%s)" % " / ".join(sorted(BOOTSTRAP_FOR.values())))

    def test_the_detector_reads_the_target(self):
        sibling = _SIBLING % "_bootstrap.py"
        cases = {"runpy.run_path(%s)\n" % sibling: 0,
                 "runpy.run_path(%s)\n" % sibling.replace("_bootstrap.py", "other.py"): 1,
                 "runpy.run_path(%s)\n" % (_SIBLING % "_skill_bootstrap.py"): 1,
                 "d = os.getcwd()\nrunpy.run_path(os.path.join(d, '_bootstrap.py'))\n": 1,
                 'runpy.run_path(os.path.join(HERE, "_bootstrap.py"))\n': 1,
                 "runpy.run_path(%s, run_name='x')\n" % sibling: 1,
                 'runpy.run_path(target)\n': 1,
                 'from runpy import run_path\nrun_path("x.py")\n': 1,
                 'runpy.run_module("x")\n': 0}
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "planted.py"
            for source, expected in cases.items():
                with self.subTest(source=source):
                    path.write_text(source)
                    self.assertEqual(len(_run_path_offenders(path, SCRIPTS)), expected)


class E402RatchetTest(unittest.TestCase):
    """Rule 5."""

    def test_no_surface_grows_its_e402_count(self):
        counts = {name: _e402_count(_py_files(ROOT / name)) for name in E402_CEILING}
        self.assertEqual(
            counts, E402_CEILING,
            "a `noqa: E402` count moved. Up: an import below code again, which "
            "the bootstrap made unnecessary in skill/scripts and devtools. Down: "
            "lower E402_CEILING in the same change.")

    def test_the_counter_reads_comments_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "planted.py"
            path.write_text("import a  # noqa: E402\nimport b  # noqa: E402,F401\n"
                            "import c  # noqa: F401\nNOTE = '# noqa: E402'\n"
                            "import d  # noqa: F401 -- not E402's\n")
            self.assertEqual(_e402_count([path]), 2)


class BootstrapTest(unittest.TestCase):
    """`_bootstrap.rewritten`, on lists: importing `scripts._bootstrap` under
    its package name changes nothing, so the suite's own sys.path is untouched."""

    def setUp(self):
        from scripts import _bootstrap
        self.bootstrap = _bootstrap

    def test_importing_it_by_package_name_writes_nothing(self):
        # A fresh interpreter, so the snapshot is taken before the first import.
        program = ("import json, sys\nbefore = list(sys.path)\n"
                   "import scripts._bootstrap\nprint(json.dumps(before == sys.path))\n")
        with tempfile.TemporaryDirectory() as elsewhere:
            proc = _python(["-c", program], elsewhere, [SKILL_ROOT, str(SCRIPTS)])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout), True)
        before = list(sys.path)
        importlib.reload(self.bootstrap)        # and again, in this process
        self.assertEqual(sys.path, before)
        self.assertEqual(self.bootstrap.SCRIPTS, os.path.realpath(SCRIPTS))
        self.assertEqual(self.bootstrap.SKILL, os.path.realpath(SKILL_ROOT))

    def test_scripts_dir_goes_and_skill_comes_first_once(self):
        scripts, skill = self.bootstrap.SCRIPTS, self.bootstrap.SKILL
        before = [scripts, "/somewhere/else", skill, "/other", scripts + os.sep]
        after = self.bootstrap.rewritten(before)
        self.assertEqual(after, [skill, "/somewhere/else", "/other"])
        self.assertEqual(self.bootstrap.rewritten(after), after)

    def test_running_it_twice_by_path_changes_nothing_the_second_time(self):
        # driver -> a child, or two entry scripts in one process: the second run
        # neither stacks a duplicate entry nor reorders anything.
        program = ("import json, os, runpy, sys\n"
                   "boot = sys.argv[1]\n"
                   "runpy.run_path(boot)\nfirst = list(sys.path)\n"
                   "runpy.run_path(boot)\nprint(json.dumps([first, sys.path]))\n")
        boot = os.path.join(self.bootstrap.SCRIPTS, "_bootstrap.py")
        roots = ["/before", self.bootstrap.SCRIPTS, self.bootstrap.SKILL, "/after"]
        with tempfile.TemporaryDirectory() as elsewhere:
            proc = _python(["-c", program, boot], elsewhere, roots)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        first, second = json.loads(proc.stdout)
        self.assertEqual(second, first)
        self.assertEqual(first[0], self.bootstrap.SKILL)
        self.assertEqual(first.count(self.bootstrap.SKILL), 1)
        self.assertNotIn(self.bootstrap.SCRIPTS, first)
        others = [p for p in first if p in ("/before", "/after")]
        self.assertEqual(others, ["/before", "/after"])

    def test_a_symlinked_install_is_recognised(self):
        with tempfile.TemporaryDirectory() as directory:
            link = os.path.join(directory, "linked-skill")
            os.symlink(self.bootstrap.SKILL, link)
            after = self.bootstrap.rewritten([os.path.join(link, "scripts"), link, "/x"])
        self.assertEqual(after, [self.bootstrap.SKILL, "/x"])


class SkillBootstrapTest(unittest.TestCase):
    """`devtools/_skill_bootstrap.install(repo)`, which `replay_report --repo`
    uses to run ANOTHER checkout's `_bootstrap.py` (it imports that checkout's
    code anyway): a checkout without one fails by name, never falls back."""

    _PROGRAM = ("import runpy, sys\n"
                "ns = runpy.run_path(sys.argv[1])\n"
                "print(ns['install'](sys.argv[2]))\n")

    def test_another_checkout_s_bootstrap_runs_and_puts_its_skill_first(self):
        with tempfile.TemporaryDirectory() as directory:
            other = pathlib.Path(os.path.realpath(directory)) / "other"
            shutil.copytree(SCRIPTS, other / "skill" / "scripts",
                            ignore=shutil.ignore_patterns("__pycache__"))
            proc = _python(["-c", self._PROGRAM + "print(sys.path[0])\n",
                            str(DEVTOOLS / "_skill_bootstrap.py"), str(other)],
                           directory, [])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.split(), [str(other / "skill")] * 2)

    def test_a_checkout_without_one_fails_by_name(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = _python(["-c", self._PROGRAM, str(DEVTOOLS / "_skill_bootstrap.py"),
                            directory], directory, [])
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("has no skill/scripts/_bootstrap.py", proc.stderr)
        self.assertIn(directory, proc.stderr)


class ModuleIdentityTest(unittest.TestCase):
    """No file loads twice in the processes the rules protect."""

    def _census(self, program, roots=(SKILL_ROOT,)):
        with tempfile.TemporaryDirectory() as elsewhere:
            proc = _python(["-c", (_CENSUS_HEAD % os.path.realpath(SKILL_ROOT))
                            + program + _CENSUS_TAIL], elsewhere, roots)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return json.loads(proc.stdout)

    def test_a_driver_shaped_process_loads_no_file_twice(self):
        self.assertEqual(self._census(_DRIVER_IMPORTS), [])

    def test_calling_setup_paths_loads_no_file_twice(self):
        self.assertEqual(self._census(_DRIVER_IMPORTS + _SETUP_CALLS), [])

    def test_the_census_sees_a_planted_double_import(self):
        # Vacuity guard: one file under both of its names, both roots on the path.
        doubled = self._census("import scripts.plan_contract\nimport plan_contract\n",
                               (SKILL_ROOT, os.path.join(SKILL_ROOT, "scripts")))
        self.assertEqual(doubled, [["plan_contract", "scripts.plan_contract"]])

    def test_the_two_portions_share_no_module_name(self):
        # pytest puts both on sys.path flat; a shared basename would resolve to
        # whichever came first, silently.
        shared = sorted(SKILL_MODULES & DEVTOOLS_MODULES)
        self.assertEqual(shared, [], "module name(s) in both skill/scripts and "
                         "devtools: %s. Rename one side." % ", ".join(shared))


class InstalledSkillTest(unittest.TestCase):
    """The contract #3505 must keep: `skill/` copied to an agent's skills
    directory (or symlinked there), entry scripts run by path from a target
    repo that has its own `scripts/`, with a decoy `scripts` package on
    PYTHONPATH and under `python3 -P` -- and only the copy's own modules load,
    each once."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        tmp = pathlib.Path(os.path.realpath(cls._tmp.name))
        cls.install = tmp / "home" / ".claude" / "skills" / "panopticon"
        shutil.copytree(SKILL_ROOT, cls.install,
                        ignore=shutil.ignore_patterns("__pycache__"))
        cls.linked = tmp / "home" / ".kimi" / "skills" / "panopticon"
        cls.linked.parent.mkdir(parents=True)
        os.symlink(cls.install, cls.linked)
        cls.target = tmp / "target"
        for name in ("__init__.py", "evidence.py", "hosts.py"):
            _write(cls.target / "scripts" / name,
                   "raise SystemExit('target scripts/%s imported')\n" % name)
        cls.decoy = tmp / "decoy"
        _write(cls.decoy / "scripts" / "__init__.py",
               "raise SystemExit('decoy scripts package imported')\n")
        cls.audit = tmp / "audit"
        _write(cls.audit / "sitecustomize.py", _AUDIT)
        cls.out = tmp / "audit.json"

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _run(self, root, entry, flags):
        if self.out.exists():
            self.out.unlink()
        proc = _python([*flags, str(root / "scripts" / entry), "--help"],
                       self.target, [str(self.audit), str(self.decoy)],
                       {"AUDIT_OUT": str(self.out), "AUDIT_ROOT": str(self.install),
                        "HOME": str(self.install.parents[2])}, timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return json.loads(self.out.read_text())

    def test_entry_scripts_import_only_the_installed_copy(self):
        runs = [(self.install, flags, entry) for flags in ([], ["-P"])
                for entry in _INSTALLED_ENTRIES]
        runs += [(self.linked, flags, "driver.py") for flags in ([], ["-P"])]
        for root, flags, entry in runs:
            with self.subTest(root=root.parent.parent.name, flags=flags, entry=entry):
                audit = self._run(root, entry, flags)
                self.assertEqual(audit["doubled"], [])
                self.assertTrue(audit["dirs"])
                for directory in audit["dirs"]:
                    self.assertTrue(directory.startswith(str(self.install)), directory)

    def test_the_audit_sees_a_double_import(self):
        # Vacuity guard for the audit: `python3 -c` with both roots, one file
        # under both names, must report the pair.
        if self.out.exists():
            self.out.unlink()
        proc = _python(["-c", "import scripts.plan_contract, plan_contract"],
                       self.audit, [str(self.audit), str(self.install),
                                     str(self.install / "scripts")],
                       {"AUDIT_OUT": str(self.out), "AUDIT_ROOT": str(self.install)})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(self.out.read_text())["doubled"],
                         [["plan_contract", "scripts.plan_contract"]])


class TestHelperImportTest(unittest.TestCase):
    """The tests/ package half of the old guard: helpers import cleanly and the
    suite collects every tests/ file under one canonical name."""

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
            modules = ["tests._test_helpers", "tests.tools.helpers",
                       "tests.tools.git_repo", "tests.run_tools_test_helpers"]
            for order in (modules, list(reversed(modules))):
                result = _python(["-c", code, *order], directory, [str(ROOT)],
                                 {"HOME": directory, "USERPROFILE": directory,
                                  "TMPDIR": directory})
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
            selected = [TESTS / "test_diff_map.py", TESTS / "test_tree_baseline.py"]
            for order in (selected, list(reversed(selected))):
                result = _python(["-c", code, str(ROOT), *(str(p) for p in order)],
                                 directory, [], timeout=45)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
