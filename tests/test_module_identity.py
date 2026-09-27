"""#1766 (ARC-A2C): one module object per file, and one owner for the bootstrap.

Findings ARC-188610019, ARC-2452079063, ARC-3214704952 and ARC-11100703 are four
views of one seam. `skill/scripts/` holds no `__init__.py` and is itself on
`sys.path` in several live paths, so every module in it has two reachable names
-- `x` and `scripts.x` -- and a process that imports one file under both names
builds TWO module objects from it, each with its own module state and its own
patch targets. Measured before this guard landed: nine modules were doubled in a
driver-shaped process, and `dispatch.py`'s flat `import model_resolver` gave
`dispatch.registration_model` a second `model_resolver` with its own profile
cache, which `mock.patch.object(scripts.model_resolver, ...)` could not reach.

Four assertions, each pinning one half of the architecture:

* the CENSUS -- in a driver-shaped process (only `skill/` on PYTHONPATH, then the
  three entry modules the driver's own run imports) no file is loaded twice,
  apart from the residual named in `RESIDUAL`, which the flat-import mode owns;
* the BOOTSTRAP GATE -- the `sys.path` mutation sites under `skill/scripts/` and
  `scripts/` are the enumerated few. A new one is how the census grows back, and
  a site that DISAPPEARS fails too, so the list stays a measurement and not a
  permission;
* the two `scripts` PORTIONS are name-disjoint -- `scripts/` and `skill/scripts/`
  are two portions of one namespace package, so a basename in both would resolve
  to whichever portion came first on `sys.path`, silently;
* no PACKAGE module carries an import FALLBACK -- a module under `synth/`,
  `phases/`, `runners/` or `probes/` can only be reached as `scripts.<pkg>.<mod>`,
  so `scripts` has already resolved and a `except ModuleNotFoundError: from x
  import y` arm there is dead code pretending to be a mode.

The flat-import mode itself lives in `tests/test_layout.py` (rule 2 and
`FLAT_MODULES`); this file pins what that mode must NOT cost. Consolidating the
remaining flat imports is tracked in #1516.

The `sys.path`-write detector is `tests/test_no_per_file_sys_path.py`'s, imported
rather than copied: that guard covers `tests/` and this one covers the two
production surfaces, and two guards that disagree about what a `sys.path` write
looks like are two different rules.
"""
import ast
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

from tests._test_helpers import REPO_ROOT, SKILL_ROOT
from tests.test_no_per_file_sys_path import _mutation_sites

# Pair detection, by FILE identity rather than by name: `x` and `scripts.x` are
# the same file loaded twice. Printed as JSON so the parent asserts on the list
# and not on a formatted line.
_CENSUS_TAIL = """
doubled = []
for name, flat in sorted(sys.modules.items()):
    if "." in name or flat is None:
        continue
    packaged = sys.modules.get("scripts." + name)
    if packaged is None:
        continue
    one = getattr(flat, "__file__", None)
    two = getattr(packaged, "__file__", None)
    if one and two and os.path.realpath(one) == os.path.realpath(two):
        doubled.append(name)
print(json.dumps(doubled))
"""
_CENSUS_PREAMBLE = "import json\nimport os\nimport sys\n\n"

# The driver-shaped process: only `skill/` on PYTHONPATH (what
# `phases/child._child_env` gives a phase child, minus the flat roots), and the
# three modules `driver run` loads on any invocation.
_CENSUS_PROGRAM = (_CENSUS_PREAMBLE + "import scripts.driver\n"
                   "import scripts.setup_flow\nimport scripts.dispatch\n"
                   + _CENSUS_TAIL)

# The same detection over a deliberately doubled import, for the mechanics test:
# both roots on the path and one file imported under both of its names.
_PLANTED_PROGRAM = (_CENSUS_PREAMBLE + "import scripts.plan_contract\n"
                    "import plan_contract\n" + _CENSUS_TAIL)

# Modules still loaded twice, each with the flat-mode owner that requires it.
# Every entry traces back to one rule: `discovery` is in `tests/test_layout.py`'s
# `FLAT_MODULES`, so it must import with only `skill/scripts` on `sys.path`.
#
# * `diff_map`, `plan_contract`, `repo_config` -- `discovery.py` imports these
#   three flat, after its own bootstrap, and that is the mode `FLAT_MODULES`
#   pins for it.
# * `coverage_model`, `groups_schema` -- `setup_proposal.py` imports them flat.
#   It is reached flat on purpose: `discovery._capability_aliases` imports it at
#   CALL time (the edge must stay lazy, see `coverage_model`'s own note), and
#   `tests/test_coverage_model.py` pins that the standalone flat `--repo-scan`
#   path still returns its aliases. `setup_proposal.py` also sits at its
#   shrink-only pin in `tests/test_flat_module_ceiling.py`, so the guarded
#   `try: from scripts import ... except ModuleNotFoundError` shape its siblings
#   use cannot be added to it without raising that pin.
#
# This is an equality, not a subset: a residual that goes away must fail here
# too, so the list cannot outlive the flat imports it records (#1516).
RESIDUAL = ("coverage_model", "diff_map", "groups_schema", "plan_contract",
            "repo_config")

# The two production surfaces. `tests/` is `tests/test_no_per_file_sys_path.py`'s,
# where the rule is ZERO sites rather than an enumerated few.
BOOTSTRAP_SURFACES = ("skill/scripts", "scripts")

# Every module allowed to put an import root on `sys.path`, as a repo-relative
# path. These are entry scripts (invoked by path, so their package roots are not
# on `sys.path` yet) plus the few library modules that are also run directly.
# The list is a census taken with the same AST walk below, not a wish: adding a
# module here is the visible decision that a new copy of the bootstrap is worth
# it, and the alternative is always to import the package.
PERMITTED_BOOTSTRAPS = (
    "scripts/code_scanning_reports.py",
    "scripts/file_issues.py",
    "scripts/open_pin_pr.py",
    "scripts/replay_report.py",
    "scripts/sanitize.py",
    "scripts/triage.py",
    "skill/scripts/_run_adapter.py",
    "skill/scripts/capture_goldens.py",
    "skill/scripts/dispatch.py",
    "skill/scripts/discovery.py",
    "skill/scripts/driver.py",
    "skill/scripts/reconcile.py",
    "skill/scripts/run_fixture_tests.py",
    "skill/scripts/run_tools.py",
    "skill/scripts/score_gate.py",
    "skill/scripts/security_gate.py",
    "skill/scripts/setup_flow.py",
    "skill/scripts/synthesize.py",
)

_BOOTSTRAP_ADVICE = (
    "a `sys.path` write under skill/scripts/ or scripts/ hands every module in "
    "that directory a SECOND importable name, which is how the dual-identity "
    "census grows back. Import the package (`from scripts import x`) instead of "
    "adding a site; if a site genuinely belongs here, add its path to "
    "PERMITTED_BOOTSTRAPS as a visible decision. A site that has GONE fails the "
    "same way: drop its entry, the list is a measurement."
)

# The four packages `tests/test_layout.py` rule 2 forbids a flat import of. A
# module under any of them is reachable only as `scripts.<pkg>.<mod>`.
PACKAGE_DIRS = ("synth", "phases", "runners", "probes")

# Package modules allowed to keep an `except ModuleNotFoundError` import arm,
# path -> reason. Empty, and the one candidate stays out on its own terms:
# `runners/base._headless_module` catches `ModuleNotFoundError` around an
# `importlib.import_module` CALL, which is a runtime lookup of an optional
# per-host module and not an import statement, so the walk below never sees it.
# `except ImportError` is deliberately out of scope: `synth/validate_schema` uses
# that shape for a declared runtime dependency and fails CLOSED on it, which is
# a dependency check rather than a second import mode.
EXEMPT_FALLBACKS: dict[str, str] = {}


def _bootstrap_sites(root=REPO_ROOT):
    """Repo-relative path -> its `sys.path` write sites, over both surfaces."""
    found = {}
    for surface in BOOTSTRAP_SURFACES:
        base = pathlib.Path(root, *surface.split("/"))
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.py")):
            sites = _mutation_sites(path)
            if sites:
                relative = path.relative_to(root).as_posix()
                found[relative] = ["%s:%d: %s" % (relative, line, text)
                                   for line, text in sites]
    return found


def _module_names(directory):
    """The importable basenames of one `scripts` portion."""
    return {name[:-3] for name in os.listdir(directory)
            if name.endswith(".py") and name != "__init__.py"}


def _catches_module_not_found(handler):
    """True when this `except` clause names ModuleNotFoundError."""
    if handler.type is None:
        return False
    clause = handler.type
    caught = clause.elts if isinstance(clause, ast.Tuple) else [clause]
    return any(ast.unparse(node).split(".")[-1] == "ModuleNotFoundError"
               for node in caught)


def _fallback_sites(source, label):
    """`try: <import> except ModuleNotFoundError:` blocks in one module."""
    sites = []
    for node in ast.walk(ast.parse(source, filename=label)):
        if not isinstance(node, ast.Try):
            continue
        imports = [stmt for stmt in node.body
                   if isinstance(stmt, (ast.Import, ast.ImportFrom))]
        if not imports:
            continue
        if any(_catches_module_not_found(handler) for handler in node.handlers):
            sites.append("%s:%d: %s"
                         % (label, node.lineno,
                            "; ".join(ast.unparse(stmt) for stmt in imports)))
    return sites


def _package_fallbacks(root=REPO_ROOT):
    offenders = []
    for package in PACKAGE_DIRS:
        base = pathlib.Path(root, "skill", "scripts", package)
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.py")):
            relative = path.relative_to(root).as_posix()
            if relative in EXEMPT_FALLBACKS:
                continue
            offenders.extend(
                _fallback_sites(path.read_text(encoding="utf-8"), relative))
    return offenders


class ModuleIdentityCensusTest(unittest.TestCase):
    """No file is loaded twice in the process the driver actually runs in."""

    def _census(self, program=_CENSUS_PROGRAM, roots=(SKILL_ROOT,)):
        """Run one census program in a fresh interpreter, elsewhere, and clean.

        The cwd is a temporary directory and PYTHONPATH is exactly `roots`, so
        the process sees the import roots under test and nothing this suite or
        the host happens to have on the path.
        """
        with tempfile.TemporaryDirectory() as elsewhere:
            env = {key: value for key, value in os.environ.items()
                   if key != "PYTHONPATH"}
            env["PYTHONPATH"] = os.pathsep.join(roots)
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            proc = subprocess.run(  # nosec B603
                [sys.executable, "-c", program], cwd=elsewhere, env=env,
                capture_output=True, text=True, timeout=180)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return json.loads(proc.stdout)

    def test_no_module_is_loaded_twice_beyond_the_named_residual(self):
        doubled = self._census()
        self.assertEqual(
            doubled, list(RESIDUAL),
            "the driver-shaped process loads %d module(s) from one file under "
            "both `x` and `scripts.x`:\n  %s\nexpected only the flat-mode "
            "residual:\n  %s\nEach extra pair is two module objects with two "
            "sets of module state and two patch targets -- import the package "
            "(`from scripts import x`) at the importing site. A residual that "
            "has GONE fails here too: drop it from RESIDUAL (#1516)."
            % (len(doubled), "\n  ".join(doubled) or "(none)",
               "\n  ".join(RESIDUAL)))

    def test_the_census_sees_a_planted_double_import(self):
        # Vacuity guard: "no pairs" must mean the detection works, not that it
        # never looks. One file imported under both of its names, with both
        # roots on the path, is the shape the census exists to find.
        doubled = self._census(_PLANTED_PROGRAM,
                              (SKILL_ROOT, os.path.join(SKILL_ROOT, "scripts")))
        self.assertEqual(doubled, ["plan_contract"])


class BootstrapGateTest(unittest.TestCase):
    """The `sys.path` bootstrap has an owner and a fixed guest list."""

    def test_the_bootstrap_sites_are_the_enumerated_few(self):
        found = _bootstrap_sites()
        self.assertEqual(
            sorted(found), sorted(PERMITTED_BOOTSTRAPS),
            "%s\nsites found:\n  %s"
            % (_BOOTSTRAP_ADVICE,
               "\n  ".join(line for lines in found.values() for line in lines)))

    def test_permitted_names_only_files_that_exist(self):
        missing = [relative for relative in PERMITTED_BOOTSTRAPS
                   if not os.path.isfile(os.path.join(REPO_ROOT, relative))]
        self.assertEqual(
            missing, [],
            "PERMITTED_BOOTSTRAPS names path(s) that are not a module any "
            "more: %s -- drop the entry" % ", ".join(missing))

    def test_a_new_site_is_named_and_a_quiet_module_is_not(self):
        planted = {
            "skill/scripts/entry.py": "import sys\nsys.path.insert(0, '/x')\n",
            "skill/scripts/tools/deep.py": ("from sys import path as roots\n"
                                            "roots.append('/x')\n"),
            "scripts/filer.py": "import sys as system\nsystem.path += ['/x']\n",
            "skill/scripts/quiet.py": "import os\nVALUE = os.sep\n",
            "tests/test_elsewhere.py": "import sys\nsys.path.insert(0, '/x')\n",
        }
        with tempfile.TemporaryDirectory() as directory:
            for relative, body in planted.items():
                path = pathlib.Path(directory, *relative.split("/"))
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body, encoding="utf-8")
            self.assertEqual(sorted(_bootstrap_sites(directory)),
                             ["scripts/filer.py", "skill/scripts/entry.py",
                              "skill/scripts/tools/deep.py"])


class ScriptsPortionsTest(unittest.TestCase):
    """`scripts/` and `skill/scripts/` are two portions of one namespace
    package. Nothing declares a precedence between them, and the entry scripts
    that put `skill/` on `sys.path` do it conditionally, so a basename carried
    by both portions would resolve to whichever one came first -- with no error
    and no way for a caller to tell which it got."""

    def test_the_two_portions_share_no_module_name(self):
        shared = sorted(_module_names(os.path.join(SKILL_ROOT, "scripts"))
                        & _module_names(os.path.join(REPO_ROOT, "scripts")))
        self.assertEqual(
            shared, [],
            "module name(s) in BOTH `scripts` portions: %s -- `import "
            "scripts.<name>` would resolve to whichever portion came first on "
            "sys.path. Rename one side." % ", ".join(shared))


class PackageFallbackTest(unittest.TestCase):
    """A package module's flat-import fallback is dead code, not a mode."""

    def test_no_package_module_carries_an_import_fallback(self):
        offenders = _package_fallbacks()
        self.assertEqual(
            offenders, [],
            "%d import fallback(s) in a PACKAGE module:\n  %s\na module under "
            "synth/, phases/, runners/ or probes/ is reachable only as "
            "`scripts.<pkg>.<mod>` -- `tests/test_layout.py` rule 2 forbids the "
            "flat package import that would reach the fallback arm -- so "
            "`scripts` has already resolved and the arm cannot run. Delete it, "
            "or record it in EXEMPT_FALLBACKS with the runtime reason."
            % (len(offenders), "\n  ".join(offenders)))

    def test_the_detector_reads_the_shape_and_not_the_words(self):
        fallback = ("try:\n    from scripts._version import __version__\n"
                    "except ModuleNotFoundError:\n"
                    "    from _version import __version__\n")
        self.assertEqual(len(_fallback_sites(fallback, "planted.py")), 1)
        for benign in (
                # a runtime lookup of an optional module, not an import
                # statement: runners/base._headless_module's real shape
                "import importlib\ntry:\n    m = importlib.import_module(n)\n"
                "except ModuleNotFoundError:\n    m = None\n",
                # a declared dependency checked with ImportError, which fails
                # closed rather than binding a second identity
                "try:\n    import jsonschema\nexcept ImportError:\n"
                "    jsonschema = None\n",
                # no handler names ModuleNotFoundError at all
                "try:\n    import yaml\nexcept OSError:\n    yaml = None\n"):
            with self.subTest(source=benign.splitlines()):
                self.assertEqual(_fallback_sites(benign, "planted.py"), [])
        tupled = ("try:\n    import x\n"
                  "except (OSError, ModuleNotFoundError):\n    x = None\n")
        self.assertEqual(len(_fallback_sites(tupled, "planted.py")), 1)

    def test_the_surface_is_every_package_and_nothing_flat(self):
        with tempfile.TemporaryDirectory() as directory:
            fallback = ("try:\n    from scripts import x\n"
                        "except ModuleNotFoundError:\n    import x\n")
            for relative in ("skill/scripts/synth/report.py",
                             "skill/scripts/phases/deep/nested.py",
                             "skill/scripts/runners/base.py",
                             "skill/scripts/probes/common.py",
                             "skill/scripts/evidence.py",
                             "skill/scripts/tools/semgrep.py"):
                path = pathlib.Path(directory, *relative.split("/"))
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(fallback, encoding="utf-8")
            self.assertEqual(
                sorted(site.split(":")[0] for site in _package_fallbacks(directory)),
                ["skill/scripts/phases/deep/nested.py",
                 "skill/scripts/probes/common.py",
                 "skill/scripts/runners/base.py",
                 "skill/scripts/synth/report.py"])


if __name__ == "__main__":
    unittest.main()
