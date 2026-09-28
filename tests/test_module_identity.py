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
  apart from the residual named in `RESIDUAL`, which the flat-import mode owns.
  It measures IMPORT time only; see `RESIDUAL`'s comment for the call-time class;
* the BOOTSTRAP CEILING -- every `sys.path` write site under `skill/scripts/` and
  `scripts/` belongs to an enumerated module, and no module carries more sites
  than `PERMITTED_BOOTSTRAPS` records. Shrink-only, at SITE granularity: a third
  insert in an already-permitted file is the way the census grows back, so it has
  to be a visible decision too. Each site is reported with the ROOT it adds,
  because the two roots are not the same hazard;
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

Two definitions are imported rather than restated: the `sys.path`-write detector
from `tests/test_no_per_file_sys_path.py` (that guard covers `tests/`, this one
the two production surfaces, and two guards that disagree about what a `sys.path`
write looks like are two different rules) and the package tuple from
`tests/test_layout.py` (whose rules define what a package IS here).
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
from tests.test_layout import PACKAGES
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
# The census measures IMPORT time only, so this list is not the whole debt: a
# flat `import x` inside a FUNCTION body mints its second copy when that function
# is first called, in a process this program never drives. That is a separate
# class with its own instances -- `discovery._capability_aliases`'s lazy
# `import setup_proposal` is the known one -- and it is tracked with the rest
# under #1516 rather than measured here.
#
# This is an equality, not a subset: a residual that goes away must fail here
# too, so the list cannot outlive the flat imports it records (#1516).
RESIDUAL = ("coverage_model", "diff_map", "groups_schema", "plan_contract",
            "repo_config")

# The two production surfaces. `tests/` is `tests/test_no_per_file_sys_path.py`'s,
# where the rule is ZERO sites rather than an enumerated few.
BOOTSTRAP_SURFACES = ("skill/scripts", "scripts")

# What a site adds, resolved from the call's argument by AST. The two roots are
# different animals and the advice below differs accordingly; anything this walk
# cannot resolve is reported as unresolved rather than guessed at.
_FLAT_ROOT = "flat root skill/scripts"
_PACKAGE_ROOT = "package root skill"
_UNRECOGNISED = "unrecognised root"

# Every module allowed to put an import root on `sys.path`, and how many sites it
# may carry. Entry scripts (invoked by path, so their package roots are not on
# `sys.path` yet) plus the few library modules that are also run directly;
# `dispatch.py` and `driver.py` add both roots and so carry two sites each.
#
# A SHRINK-ONLY ceiling, the shape `tests/test_flat_module_ceiling.py`'s PENDING
# uses: a count is never raised, a new module gets no entry at all, and a site
# that goes away lowers its count in the same change. Counting SITES rather than
# files is the point -- a third `sys.path.insert` inside an already-permitted
# module is exactly how the dual-identity census grows back, and the file-level
# form of this list could not see one. No line number enters the literal.
PERMITTED_BOOTSTRAPS = {
    "scripts/code_scanning_reports.py": 1,
    "scripts/file_issues.py": 1,
    "scripts/open_pin_pr.py": 1,
    "scripts/replay_report.py": 1,
    "scripts/sanitize.py": 1,
    "scripts/triage.py": 1,
    "skill/scripts/_run_adapter.py": 1,
    "skill/scripts/capture_goldens.py": 1,
    "skill/scripts/discovery.py": 1,
    "skill/scripts/dispatch.py": 2,
    "skill/scripts/driver.py": 2,
    "skill/scripts/reconcile.py": 1,
    "skill/scripts/run_fixture_tests.py": 1,
    "skill/scripts/run_tools.py": 1,
    "skill/scripts/security_gate.py": 1,
    "skill/scripts/setup_flow.py": 1,
    "skill/scripts/synthesize.py": 1,
}

# Modules whose bootstrap root the static walk below cannot follow, so the gate
# reports "unrecognised root" for them rather than guessing. One today:
# `replay_report.py` joins a FUNCTION-local `repo` with "skill". Shrink-only --
# making one resolvable is a fix, adding one is not.
UNRESOLVED_ROOTS = ("scripts/replay_report.py",)

# Per-root advice, because "any `sys.path` write" is not one hazard. Of the 20
# sites in 18 modules, SEVEN add the flat root, TWELVE add the package root and
# one builds its root in a form this walk cannot follow; advice that lumps them
# together tells the `scripts/`-side filers to stop doing the very thing that
# makes `from scripts import x` work at all.
_ROOT_ADVICE = {
    _FLAT_ROOT:
        "mints a SECOND importable name for every module in skill/scripts/, "
        "which is how the dual-identity census grows back. Import the package "
        "(`from scripts import x`) instead of adding a site.",
    _PACKAGE_ROOT:
        "grants the package name `scripts.*`, which is what makes `from scripts "
        "import x` resolve at all -- benign, and still enumerated: an entry "
        "script that needs it is a decision, and a library module that wants it "
        "is a module its callers should have imported through the package.",
    _UNRECOGNISED:
        "adds a directory this walk could not resolve from the AST. Build the "
        "root from `__file__` the way its neighbours do, so the gate can say "
        "which root it is.",
}

_CEILING_ADVICE = (
    "PERMITTED_BOOTSTRAPS is shrink-only: a count is never raised. Import the "
    "package instead of adding a site; if a new site genuinely belongs, raising "
    "its module's count is the visible decision, and the root it adds decides "
    "how much that costs (see the per-site labels above)."
)

# Package modules allowed to keep an import fallback, path -> reason. Empty, and
# the one candidate stays out on its own terms:
# `runners/base._headless_module` catches `ModuleNotFoundError` around an
# `importlib.import_module` CALL and its handler re-raises or returns None -- a
# runtime lookup of an optional per-host module, with no import statement in
# either half, so the walk below never sees it.
EXEMPT_FALLBACKS: dict[str, str] = {}


def _module_constants(tree):
    """Module-level names assigned exactly once, name -> value node.

    Enough to follow `_SKILL = os.path.join(..., "skill")` from the
    `sys.path.insert(0, _SKILL)` that uses it. A name assigned twice is dropped:
    a static walk cannot say which value reaches the site.
    """
    single, seen = {}, set()
    for node in tree.body:
        if isinstance(node, ast.AnnAssign):
            targets = [node.target]
        elif isinstance(node, ast.Assign):
            targets = node.targets
        else:
            continue
        for target in targets:
            if not isinstance(target, ast.Name):
                continue
            if target.id in seen:
                single.pop(target.id, None)
            else:
                seen.add(target.id)
                single[target.id] = node.value
    return single


_IDENTITY_CALLS = frozenset({"abspath", "realpath", "str", "Path", "fspath",
                             "normpath"})


def _resolve_path(node, module, constants, depth=0):
    """Symbolically resolve a `sys.path` argument to a directory, or None.

    Pure AST, no evaluation: the spellings this tree actually uses --
    `dirname`/`abspath`/`join` around `__file__`, pathlib's
    `parent`/`parents[N]`/`resolve`/`/`, and a module-level constant built from
    those. Anything else returns None and is reported as unresolved rather than
    guessed at.
    """
    if node is None or depth > 12:
        return None
    if isinstance(node, ast.Name):
        if node.id == "__file__":
            return module
        return _resolve_path(constants.get(node.id), module, constants, depth + 1)
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.Attribute):
        if node.attr == "parent":
            inner = _resolve_path(node.value, module, constants, depth + 1)
            return os.path.dirname(inner) if inner else None
        return None
    if isinstance(node, ast.Subscript):                     # Path(x).parents[N]
        base = node.value
        if not (isinstance(base, ast.Attribute) and base.attr == "parents"
                and isinstance(node.slice, ast.Constant)
                and isinstance(node.slice.value, int)):
            return None
        inner = _resolve_path(base.value, module, constants, depth + 1)
        for _hop in range(node.slice.value + 1):
            inner = os.path.dirname(inner) if inner else None
        return inner
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):   # Path / x
        left = _resolve_path(node.left, module, constants, depth + 1)
        right = _resolve_path(node.right, module, constants, depth + 1)
        return os.path.join(left, right) if left and right else None
    if not isinstance(node, ast.Call):
        return None
    if isinstance(node.func, ast.Attribute):
        name, bound = node.func.attr, node.func.value
    elif isinstance(node.func, ast.Name):
        name, bound = node.func.id, None
    else:
        return None
    if name == "resolve" and not node.args and bound is not None:
        return _resolve_path(bound, module, constants, depth + 1)
    parts = [_resolve_path(arg, module, constants, depth + 1) for arg in node.args]
    if not all(parts):
        return None
    if name == "dirname" and len(parts) == 1:
        return os.path.dirname(*parts)
    if name == "join" and parts:
        return os.path.join(*parts)
    if name in _IDENTITY_CALLS and len(parts) == 1:
        return parts.pop()
    return None


def _root_label(resolved, root):
    """What the resolved directory IS, relative to the repo."""
    if not resolved:
        return _UNRECOGNISED
    relative = os.path.relpath(os.path.normpath(resolved), root)
    if relative == os.path.join("skill", "scripts"):
        return _FLAT_ROOT
    if relative == "skill":
        return _PACKAGE_ROOT
    return "root %s" % relative.replace(os.sep, "/")


def _added_roots(path, root):
    """lineno -> the root label for each `sys.path` insert/append/extend call."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    constants = _module_constants(tree)
    labels = {}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in ("insert", "append", "extend")
                and ast.unparse(node.func.value).endswith("path")):
            continue
        added = [arg for arg in node.args
                 if not (isinstance(arg, ast.Constant)
                         and isinstance(arg.value, int))]
        seen = sorted({_root_label(_resolve_path(arg, str(path), constants), root)
                       for arg in added})
        labels[node.lineno] = ", ".join(seen) if seen else _UNRECOGNISED
    return labels


def _bootstrap_sites(root=REPO_ROOT):
    """Repo-relative path -> [(lineno, source text, root label)] per site."""
    found = {}
    for surface in BOOTSTRAP_SURFACES:
        base = pathlib.Path(root, *surface.split("/"))
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.py")):
            sites = _mutation_sites(path)
            if not sites:
                continue
            labels = _added_roots(path, root)
            found[path.relative_to(root).as_posix()] = [
                (line, text, labels.get(line, _UNRECOGNISED))
                for line, text in sites]
    return found


def _describe(sites):
    """The offending sites, each with the root it adds, plus the advice for it."""
    lines = ["%s:%d: %s   [%s]" % (relative, line, text, label)
             for relative, entries in sorted(sites.items())
             for line, text, label in entries]
    labels = {label for entries in sites.values() for _l, _t, label in entries}
    for label in sorted(labels):
        lines.append("%s -- %s" % (label, _ROOT_ADVICE.get(
            label, "adds a root outside skill/; it belongs to no import mode "
                   "this project has")))
    return "\n  ".join(lines)


def _unpermitted(found, permitted=None):
    """Sites in a module the literal does not name at all."""
    permitted = PERMITTED_BOOTSTRAPS if permitted is None else permitted
    return {relative: entries for relative, entries in found.items()
            if relative not in permitted}


def _over_count(found, permitted=None):
    """Named modules carrying more sites than their count allows."""
    permitted = PERMITTED_BOOTSTRAPS if permitted is None else permitted
    return {relative: entries for relative, entries in found.items()
            if relative in permitted and len(entries) > permitted[relative]}


def _stale_counts(found, permitted=None, root=REPO_ROOT):
    """Counts that are now too high: the module lost a site (or all of them).

    Reported by its own test, never by the ceiling: a change that REMOVES a
    bootstrap is the guard working, and it must not fail the gate that exists to
    stop new ones.
    """
    permitted = PERMITTED_BOOTSTRAPS if permitted is None else permitted
    rows = []
    for relative, pinned in sorted(permitted.items()):
        if not os.path.isfile(os.path.join(root, *relative.split("/"))):
            continue                       # reported by the existence test
        actual = len(found.get(relative, ()))
        if actual < pinned:
            rows.append("%s: %d site(s), pinned at %d" % (relative, actual, pinned))
    return rows


def _module_names(directory):
    """The importable basenames of one `scripts` portion."""
    return {name[:-3] for name in os.listdir(directory)
            if name.endswith(".py") and name != "__init__.py"}


def _catches_an_import_error(handler):
    """True when this `except` clause names ModuleNotFoundError or ImportError.

    Both, because `ModuleNotFoundError` is a SUBCLASS of `ImportError`: `except
    ImportError: import x` is the identical dead arm written one name wider.
    """
    if handler.type is None:
        return False
    clause = handler.type
    caught = clause.elts if isinstance(clause, ast.Tuple) else [clause]
    return any(ast.unparse(node).split(".")[-1]
               in ("ModuleNotFoundError", "ImportError") for node in caught)


def _fallback_sites(source, label):
    """`try: <import> / except (ModuleNotFound|Import)Error: <import>` blocks.

    Keyed on the HANDLER body holding an import, which is what a fallback IS. A
    handler that sets a name to None, returns a diagnostic or re-raises is a
    dependency check, not a second identity of the same file, and does not match.
    """
    sites = []
    for node in ast.walk(ast.parse(source, filename=label)):
        if not isinstance(node, ast.Try):
            continue
        for handler in node.handlers:
            imports = [stmt for stmt in handler.body
                       if isinstance(stmt, (ast.Import, ast.ImportFrom))]
            if imports and _catches_an_import_error(handler):
                sites.append("%s:%d: %s"
                             % (label, handler.lineno,
                                "; ".join(ast.unparse(stmt) for stmt in imports)))
    return sites


def _package_fallbacks(root=REPO_ROOT):
    """Every import fallback under the packages `tests/test_layout.py` governs.

    `skill/scripts/tools/` is deliberately NOT on this surface even though it has
    an `__init__.py`: `PACKAGES` is what the layout rules mean by a package here,
    and the adapter family's own fallback shape (`except ImportError: import
    xml.etree.ElementTree as ET`) substitutes a DIFFERENT implementation for a
    missing third-party package rather than re-importing one file under a second
    name, which is not what this gate is about.
    """
    offenders = []
    for package in PACKAGES:
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
        return sorted(json.loads(proc.stdout))

    def test_no_module_is_loaded_twice_beyond_the_named_residual(self):
        doubled = self._census()
        expected = sorted(RESIDUAL)
        self.assertEqual(
            doubled, expected,
            "the driver-shaped process loads %d module(s) from one file under "
            "both `x` and `scripts.x`:\n  %s\nexpected only the flat-mode "
            "residual:\n  %s\ndisagreeing names:\n  %s\nEach extra pair is two "
            "module objects with two sets of module state and two patch targets "
            "-- import the package (`from scripts import x`) at the importing "
            "site. A residual that has GONE fails here too: drop it from "
            "RESIDUAL (#1516)."
            % (len(doubled), "\n  ".join(doubled) or "(none)",
               "\n  ".join(expected),
               "\n  ".join(sorted(set(doubled) ^ set(expected))) or "(none)"))

    def test_the_census_sees_a_planted_double_import(self):
        # Vacuity guard: "no pairs" must mean the detection works, not that it
        # never looks. One file imported under both of its names, with both
        # roots on the path, is the shape the census exists to find.
        doubled = self._census(_PLANTED_PROGRAM,
                              (SKILL_ROOT, os.path.join(SKILL_ROOT, "scripts")))
        self.assertEqual(doubled, ["plan_contract"])


class BootstrapCeilingTest(unittest.TestCase):
    """The `sys.path` bootstrap has an owner, a fixed guest list and a per-module
    site ceiling that only ever goes down."""

    def setUp(self):
        self.found = _bootstrap_sites()

    def test_no_unnamed_module_bootstraps(self):
        offenders = _unpermitted(self.found)
        self.assertEqual(
            sorted(offenders), [],
            "%d module(s) write to `sys.path` without an entry in "
            "PERMITTED_BOOTSTRAPS:\n  %s\n%s"
            % (len(offenders), _describe(offenders), _CEILING_ADVICE))

    def test_no_module_carries_more_sites_than_its_count_allows(self):
        offenders = _over_count(self.found)
        self.assertEqual(
            sorted(offenders), [],
            "%d module(s) over their `sys.path` site count (%s):\n  %s\n%s"
            % (len(offenders),
               ", ".join("%s allows %d" % (name, PERMITTED_BOOTSTRAPS[name])
                         for name in sorted(offenders)),
               _describe(offenders), _CEILING_ADVICE))

    def test_permitted_names_only_files_that_exist(self):
        missing = [relative for relative in sorted(PERMITTED_BOOTSTRAPS)
                   if not os.path.isfile(os.path.join(REPO_ROOT, relative))]
        self.assertEqual(
            missing, [],
            "PERMITTED_BOOTSTRAPS names path(s) that are not a module any "
            "more: %s -- trim the literal, a retired script's entry is a "
            "permission nobody asked for" % ", ".join(missing))

    def test_a_module_that_gave_up_a_site_lowers_its_count(self):
        # The shrink-only half, and the ONLY test that fails on a vanished
        # site: removing a bootstrap is the guard working, so it must not red
        # the ceiling above -- it reds here, where the remedy is one number.
        stale = _stale_counts(self.found)
        self.assertEqual(
            stale, [],
            "%d PERMITTED_BOOTSTRAPS count(s) higher than the tree:\n  %s\n"
            "trim the literal to what is there -- a count left high quietly "
            "re-permits the site it recorded" % (len(stale), "\n  ".join(stale)))

    def test_every_site_adds_one_of_this_project_s_two_roots(self):
        labels = {label for entries in self.found.values()
                  for _l, _t, label in entries}
        # Vacuity: both roots really are present, so a walk that resolved
        # nothing could not pass the two assertions below by being empty.
        self.assertLessEqual({_FLAT_ROOT, _PACKAGE_ROOT}, labels, sorted(labels))
        # A site that resolves to anything else adds a directory that belongs to
        # no import mode this project has -- including one outside the tree.
        foreign = sorted("%s   [%s]" % (relative, label)
                         for relative, entries in self.found.items()
                         for _l, _t, label in entries
                         if label.startswith("root "))
        self.assertEqual(
            foreign, [],
            "%d site(s) add a root that is neither `skill/` nor "
            "`skill/scripts/`:\n  %s\nthis guard knows two roots; a third is a "
            "new import mode and needs a decision, not an insert"
            % (len(foreign), "\n  ".join(foreign)))
        # Shrink-only: a site whose root this static walk cannot follow is named
        # here so the per-root advice is never silently wrong. Making one
        # resolvable is welcome; a NEW one is not.
        unresolved = {relative for relative, entries in self.found.items()
                      for _l, _t, label in entries if label == _UNRECOGNISED}
        self.assertLessEqual(
            unresolved, set(UNRESOLVED_ROOTS),
            "%s build their `sys.path` root in a form this walk cannot follow, "
            "so the gate cannot say which root they add. Build it from "
            "`__file__` the way their neighbours do."
            % ", ".join(sorted(unresolved - set(UNRESOLVED_ROOTS))))

    def test_a_third_site_in_a_permitted_module_is_named(self):
        # Finding 1 of the round-0 review: the file-level form of this list
        # could not see a new insert inside `dispatch.py`, the one module whose
        # two roots this project argues about. Planted on a synthetic tree.
        planted = {
            "skill/scripts/dispatch.py":
                "import os\nimport sys\n"
                "sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))\n"
                "sys.path.insert(0, os.path.dirname(os.path.dirname(\n"
                "    os.path.abspath(__file__))))\n"
                "sys.path.insert(0, '/tmp/rogue')\n",
            "skill/scripts/driver.py":
                "import os\nimport sys\n"
                "sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))\n"
                "sys.path.insert(0, os.path.dirname(os.path.dirname(\n"
                "    os.path.abspath(__file__))))\n",
        }
        with tempfile.TemporaryDirectory() as directory:
            for relative, body in planted.items():
                path = pathlib.Path(directory, *relative.split("/"))
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body, encoding="utf-8")
            found = _bootstrap_sites(directory)
            permitted = {"skill/scripts/dispatch.py": 2,
                         "skill/scripts/driver.py": 2}
            self.assertEqual(sorted(_over_count(found, permitted)),
                             ["skill/scripts/dispatch.py"])
            self.assertEqual(_unpermitted(found, permitted), {})
            self.assertEqual(_stale_counts(found, permitted, directory), [])
            self.assertIn("/tmp/rogue", _describe(_over_count(found, permitted)))

    def test_a_vanished_site_lowers_a_count_without_failing_the_ceiling(self):
        planted = {"skill/scripts/dispatch.py":
                   "import os\nimport sys\n"
                   "sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))\n",
                   "skill/scripts/quiet.py": "import os\nVALUE = os.sep\n"}
        with tempfile.TemporaryDirectory() as directory:
            for relative, body in planted.items():
                path = pathlib.Path(directory, *relative.split("/"))
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body, encoding="utf-8")
            found = _bootstrap_sites(directory)
            permitted = {"skill/scripts/dispatch.py": 2}
            self.assertEqual(_over_count(found, permitted), {})
            self.assertEqual(_unpermitted(found, permitted), {})
            self.assertEqual(_stale_counts(found, permitted, directory),
                             ["skill/scripts/dispatch.py: 1 site(s), pinned at 2"])

    def test_a_new_module_is_named_and_a_quiet_one_is_not(self):
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
            found = _bootstrap_sites(directory)
            self.assertEqual(sorted(_unpermitted(found, {})),
                             ["scripts/filer.py", "skill/scripts/entry.py",
                              "skill/scripts/tools/deep.py"])

    def test_the_root_walk_reads_the_spellings_this_tree_uses(self):
        cases = {
            "os.path.dirname(os.path.abspath(__file__))": _FLAT_ROOT,
            "os.path.dirname(os.path.dirname(os.path.abspath(__file__)))":
                _PACKAGE_ROOT,
            "str(Path(__file__).resolve().parent.parent)": _PACKAGE_ROOT,
            "os.path.join(repo, 'skill')": _UNRECOGNISED,
        }
        module = os.path.join(REPO_ROOT, "skill", "scripts", "planted.py")
        for source, expected in cases.items():
            with self.subTest(source=source):
                node = ast.parse(source, mode="eval").body
                self.assertEqual(
                    _root_label(_resolve_path(node, module, {}), REPO_ROOT),
                    expected)
        # A module-level constant is followed; a name assigned twice is not.
        tree = ast.parse('_SKILL = os.path.join(os.path.dirname('
                         'os.path.dirname(os.path.abspath(__file__))), "skill")\n'
                         'OTHER = "/a"\nOTHER = "/b"\n')
        constants = _module_constants(tree)
        filer = os.path.join(REPO_ROOT, "scripts", "planted.py")
        self.assertEqual(
            _root_label(_resolve_path(ast.parse("_SKILL", mode="eval").body,
                                      filer, constants), REPO_ROOT),
            _PACKAGE_ROOT)
        self.assertNotIn("OTHER", constants)


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
            "%s is reachable only as `scripts.<pkg>.<mod>` -- "
            "`tests/test_layout.py` rule 2 forbids the flat package import that "
            "would reach the fallback arm -- so `scripts` has already resolved "
            "and the arm cannot run. Delete it, or record it in "
            "EXEMPT_FALLBACKS with the runtime reason."
            % (len(offenders), "\n  ".join(offenders),
               "/, ".join(PACKAGES) + "/"))

    def test_the_detector_reads_the_shape_and_not_the_words(self):
        for fallback in (
                # the arm #1766 deleted from synth/report.py
                "try:\n    from scripts._version import __version__\n"
                "except ModuleNotFoundError:\n"
                "    from _version import __version__\n",
                # the same arm one exception name wider: ModuleNotFoundError IS
                # an ImportError, so this is the identical dead code
                "try:\n    from scripts import x\nexcept ImportError:\n"
                "    import x\n",
                # a tuple that contains either name
                "try:\n    import x\n"
                "except (OSError, ModuleNotFoundError):\n    import x\n",
                "try:\n    import x\nexcept (ImportError, OSError):\n"
                "    import x\n"):
            with self.subTest(source=fallback.splitlines()):
                self.assertEqual(len(_fallback_sites(fallback, "planted.py")), 1)
        for benign in (
                # a runtime lookup of an optional module, not an import
                # statement: runners/base._headless_module's real shape
                "import importlib\ntry:\n    m = importlib.import_module(n)\n"
                "except ModuleNotFoundError:\n    m = None\n",
                # synth/validate_schema's shape: a declared dependency checked
                # at the boundary, whose handler returns a diagnostic
                "try:\n    import jsonschema\nexcept ImportError:\n"
                "    return ['schema: jsonschema not installed']\n",
                # the optional-dependency-set-to-None shape
                "try:\n    import yaml\nexcept ModuleNotFoundError:\n"
                "    yaml = None\n",
                # no handler names an import error at all
                "try:\n    import yaml\nexcept OSError:\n    import x\n"):
            with self.subTest(source=benign.splitlines()):
                self.assertEqual(_fallback_sites(benign, "planted.py"), [])

    def test_the_surface_is_the_layout_packages_and_nothing_else(self):
        with tempfile.TemporaryDirectory() as directory:
            fallback = ("try:\n    from scripts import x\n"
                        "except ModuleNotFoundError:\n    import x\n")
            inside = ["skill/scripts/%s/mod.py" % package for package in PACKAGES]
            outside = ["skill/scripts/evidence.py",      # a flat module
                       "skill/scripts/tools/semgrep.py"]  # not in PACKAGES
            for relative in inside + outside + ["skill/scripts/phases/deep/nest.py"]:
                path = pathlib.Path(directory, *relative.split("/"))
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(fallback, encoding="utf-8")
            self.assertEqual(
                sorted(site.split(":")[0] for site in _package_fallbacks(directory)),
                sorted(inside + ["skill/scripts/phases/deep/nest.py"]))


if __name__ == "__main__":
    unittest.main()
