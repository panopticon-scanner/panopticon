"""Layout rules for the `scripts.synth` / `scripts.phases` packages (WS-0).

AST-based, loud on purpose: every rule names the file, line and statement it
rejects. Spec: panopticon-docs superpowers/specs/2026-09-06-panopticon-5.2-
ws0-god-module-refactor-design.md section 6.3.

1. Package modules and the entry scripts reach into a package module only by
   module attribute (`from . import findings`, `import scripts.synth.findings
   as findings_mod`): never `from .findings import X` / `from
   scripts.synth.findings import X`. A name bound that way is a second lookup
   site, so `mock.patch("scripts.synth.findings.X")` silently misses it.
   Tests may bind names.
2. No flat import of either package anywhere under skill/scripts/ or tests/
   (`import synth.findings`, `from phases import runio`): skill/scripts/ is
   also on sys.path, so a flat import builds a SECOND module object with its
   own state and its own patch targets.
3. `synth/*` never imports `scripts.driver` or `scripts.phases.*`.
4. `synthesize.py` and `driver.py` hold no module-level re-export
   (`NAME = some_module.attr`): a name lives in exactly one module.
5. Size ratchet: no package module exceeds LINE_CEILING lines. Raising the
   number here is a visible decision; drifting past it is not.
"""
import ast
import os
import sys
import unittest

from conftest import REPO_ROOT, SKILL_ROOT

SCRIPTS = os.path.join(SKILL_ROOT, "scripts")
TESTS = os.path.join(REPO_ROOT, "tests")
PACKAGES = ("synth", "phases")          # rules apply to whichever exist
EXPECTED_PACKAGES = ("synth",)          # S1 lands synth; D1 extends to phases
ENTRY_SCRIPTS = ("synthesize.py", "driver.py")
LINE_CEILING = 700
_SKIP_DIRS = {"fixtures", "goldens", "__pycache__"}


def _py_files(base):
    for d, dirs, files in os.walk(base):
        dirs[:] = sorted(x for x in dirs if x not in _SKIP_DIRS)
        for f in sorted(files):
            if f.endswith(".py"):
                yield os.path.join(d, f)


def _package_dirs():
    return [(p, os.path.join(SCRIPTS, p)) for p in PACKAGES
            if os.path.isdir(os.path.join(SCRIPTS, p))]


def _package_files():
    return [os.path.join(d, f) for _p, d in _package_dirs()
            for f in sorted(os.listdir(d)) if f.endswith(".py")]


def _parse(path):
    with open(path, encoding="utf-8") as fh:
        return ast.parse(fh.read(), path)


def _rel(path):
    return os.path.relpath(path, REPO_ROOT)


def _where(path, node):
    return "%s:%d: %s" % (_rel(path), node.lineno, ast.unparse(node))


def _is_package_module(modname):
    """`scripts.synth.findings` -> True; `scripts.synth` / `scripts.x` -> False."""
    parts = modname.split(".")
    return len(parts) == 3 and parts[0] == "scripts" and parts[1] in PACKAGES


class LayoutTest(unittest.TestCase):

    def test_expected_packages_exist_with_docstring_only_init(self):
        for pkg in EXPECTED_PACKAGES:
            init = os.path.join(SCRIPTS, pkg, "__init__.py")
            self.assertTrue(os.path.isfile(init), "missing package: %s" % _rel(init))
            body = _parse(init).body
            self.assertTrue(
                len(body) == 1 and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str),
                "%s must hold only a docstring (no re-exports, no registry)" % _rel(init))

    def test_rule1_package_modules_reached_by_module_attribute_only(self):
        offenders = []
        files = _package_files() + [os.path.join(SCRIPTS, e) for e in ENTRY_SCRIPTS]
        for path in files:
            for node in ast.walk(_parse(path)):
                if not isinstance(node, ast.ImportFrom):
                    continue
                if node.level == 1 and node.module:            # from .findings import X
                    offenders.append(_where(path, node))
                elif node.level == 0 and node.module and _is_package_module(node.module):
                    offenders.append(_where(path, node))       # from scripts.synth.findings import X
        self.assertEqual(offenders, [], "bind package modules, not their names:\n"
                         + "\n".join(offenders))

    def test_rule2_no_flat_package_imports(self):
        offenders = []
        for base in (SCRIPTS, TESTS):
            for path in _py_files(base):
                for node in ast.walk(_parse(path)):
                    if isinstance(node, ast.Import):
                        if any(a.name.split(".")[0] in PACKAGES for a in node.names):
                            offenders.append(_where(path, node))
                    elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                        if node.module.split(".")[0] in PACKAGES:
                            offenders.append(_where(path, node))
        self.assertEqual(offenders, [], "flat package import (double-module hazard):\n"
                         + "\n".join(offenders))

    def test_rule3_synth_never_imports_driver_or_phases(self):
        forbidden_roots = ("scripts.driver", "scripts.phases", "driver", "phases")
        offenders = []
        synth_dir = os.path.join(SCRIPTS, "synth")
        for path in _package_files():
            if os.path.dirname(path) != synth_dir:
                continue
            for node in ast.walk(_parse(path)):
                if isinstance(node, ast.Import):
                    mods = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    mods = [node.module] + [node.module + "." + a.name for a in node.names]
                else:
                    continue
                if any(m == r or m.startswith(r + ".") for m in mods for r in forbidden_roots):
                    offenders.append(_where(path, node))
        self.assertEqual(offenders, [], "synth/* must not depend on the driver side:\n"
                         + "\n".join(offenders))

    def test_rule4_entry_scripts_hold_no_re_exports(self):
        stdlib = set(sys.stdlib_module_names)
        offenders = []
        for entry in ENTRY_SCRIPTS:
            path = os.path.join(SCRIPTS, entry)
            tree = _parse(path)
            module_aliases = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for a in node.names:
                        if a.name.split(".")[0] not in stdlib:
                            module_aliases.add(a.asname or a.name.split(".")[0])
                elif isinstance(node, ast.ImportFrom) and node.module \
                        and node.module.split(".")[0] not in stdlib:
                    for a in node.names:
                        module_aliases.add(a.asname or a.name)
            for node in tree.body:
                if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                    continue
                value = node.value
                while isinstance(value, ast.Attribute):
                    value = value.value
                if isinstance(value, ast.Name) and value.id in module_aliases:
                    offenders.append(_where(path, node))
        self.assertEqual(offenders, [], "re-export in an entry script (a name lives in "
                         "exactly one module):\n" + "\n".join(offenders))

    def test_rule5_size_ratchet(self):
        over = []
        for path in _package_files():
            with open(path, encoding="utf-8") as fh:
                n = len(fh.read().splitlines())
            if n > LINE_CEILING:
                over.append("%s: %d lines" % (_rel(path), n))
        self.assertEqual(over, [], "module over the %d-line ceiling; split it or raise "
                         "LINE_CEILING deliberately:\n%s" % (LINE_CEILING, "\n".join(over)))


if __name__ == "__main__":
    unittest.main()
