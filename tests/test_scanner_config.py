"""The scanner-owned configuration block's own tests (#1762 ARC-2609514778).

`scripts.scanner_config` was lifted out of `run_tools` whole in split 1 of 3, so
the centre of this file is a PARITY golden rather than new behaviour: the docker
argv every tool pinned to a scanner-owned config is launched with, captured from
the tree before the move and compared token for token after it. A pure
extraction that changes one flag, one path or one flag's POSITION is not a pure
extraction, and nothing else in the suite compares a whole argv.

It also holds the patch-rule guard for the WHOLE split family (part 2 added
`tool_capture` to `_SPLITS` and part 3 `tools_manifest`): the rule is about what
`run_tools` re-binds, so one derivation covers every module lifted out of it, and
each part added a row rather than a file.
"""
import ast
import contextlib
import io
import os
import pathlib
import tempfile
import unittest
from unittest import mock

import scripts.run_tools as rt
import scripts.scanner_config as sc
import scripts.tool_capture as tc
import scripts.tools_manifest as tm

from tests._test_helpers import REPO_ROOT
from tests.run_tools_test_helpers import _FakeResult

# Four tokens on the argv are host-specific and cannot be pinned: the docker
# binary `executable.resolve` found, the scan target's own temporary directory,
# the per-launch scratch the staged config lives in and the per-launch cidfile
# (each a fresh `mkdtemp`, by design). Each is replaced by a placeholder and
# NOTHING else is: every flag, every value and the order they sit in are
# compared literally.
_DOCKER = "<docker>"
_TARGET = "<target>"
_STAGED = "<staged>"
_CIDFILE = "<cidfile>"


def _normalise(argv, target):
    """*argv* with the four host-specific tokens replaced by placeholders.

    The staged config keeps its BASENAME (`bandit.ini`, `.trivyignore`): which
    file was staged is the claim, and only the scratch directory holding it is
    unpinnable. The cidfile has no such half -- the whole path is per-launch.
    """
    inside = "%s/" % rt.SCANNER_CONFIG_MOUNT
    out, previous = [_DOCKER], None
    for token in argv[1:]:
        original = token
        if previous == "--cidfile":
            token = _CIDFILE
        elif token.startswith(target + ":"):
            token = _TARGET + token[len(target):]
        elif ":" + inside in token:
            host, mount = token.split(":", 1)
            token = "%s/%s:%s" % (_STAGED, os.path.basename(host), mount)
        out.append(token)
        previous = original
    return out


def _argv_cases():
    """Every case the golden pins: each tool `SCANNER_OWNED_CONFIG` stages, in
    both security modes, with and without a `.bandit` in the target.

    The third dimension is not decoration. The owner ruling of 2026-09-25 on
    #1924 splits bandit's `--ini` by MODE *and* by whether the operator
    committed one, and that branch also takes bandit's own `-s` list off the
    argv (`_without_skip_list`) -- four argv shapes from one table entry, all of
    them built by moved code.
    """
    for tool in sorted(rt.SCANNER_OWNED_CONFIG):
        for mode in rt.SECURITY_MODES:
            for planted in (False, True):
                yield ("%s/%s/%s" % (tool, mode,
                                     "own-ini" if planted else "no-ini"),
                       tool, mode, planted)


def _dispatch_argv(tool, security_mode, planted):
    """The normalised docker argv one faked launch of *tool* really builds.

    Through `run_tools()`, the public entry the dispatch tests already use, so
    the golden is the argv the production loop assembles and not one this test
    composes from the pieces. The three container ceilings are pinned to their
    documented defaults because they are read from the environment at import:
    an operator with `PANOPTICON_TOOL_CPUS` set would otherwise fail a parity
    check about something this split does not touch.
    """
    calls = []

    def runner(cmd, **_kw):
        calls.append(list(cmd))
        return _FakeResult(returncode=0, stdout=b'{"runs":[]}', stderr=b'')
    with tempfile.TemporaryDirectory() as d:
        if planted:
            with open(os.path.join(d, ".bandit"), "w", encoding="utf-8") as fh:
                fh.write("[bandit]\nexclude = vendor\ntests = B101\n")
        with mock.patch.object(rt, "CONTAINER_MEMORY", "6g"), \
                mock.patch.object(rt, "CONTAINER_CPUS", "4"), \
                mock.patch.object(rt, "CONTAINER_PIDS_LIMIT", "1024"), \
                contextlib.redirect_stderr(io.StringIO()):
            rt.run_tools(d, [tool], os.path.join(d, "out"), runner=runner,
                         venv_dirs=[], security_mode=security_mode)
        if len(calls) != 1:
            raise AssertionError("expected one docker launch for %s, got %d"
                                 % (tool, len(calls)))
        return _normalise(calls[0], os.path.abspath(d))


# Captured from the tree at the commit this split branched from, BEFORE any code
# moved (the command is in the PR's implementation notes). A difference here is
# the extraction being wrong: fix the extraction, never this table.
GOLDEN = {
    "bandit/redteam/no-ini": [
        "<docker>", "run", "--cidfile", "<cidfile>", "--rm", "--memory", "6g",
        "--memory-swap", "6g", "--cpus", "4", "--pids-limit", "1024", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "-w", "/panopticon-empty-cwd", "-v",
        "<staged>/bandit.ini:/panopticon-config/bandit.ini:ro", "--network", "none",
        "-v", "<target>:/src:ro", "panopticon-tools", "bandit", "--ini",
        "/panopticon-config/bandit.ini", "--ignore-nosec", "-q", "-r",
        "--exclude=.svn,CVS,.bzr,.hg,.git,__pycache__,.tox,.eggs,*.egg,.worktrees",
        "/src", "-s", "B101,B404,B110,B112", "-f", "sarif"
    ],
    "bandit/redteam/own-ini": [
        "<docker>", "run", "--cidfile", "<cidfile>", "--rm", "--memory", "6g",
        "--memory-swap", "6g", "--cpus", "4", "--pids-limit", "1024", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "-w", "/panopticon-empty-cwd", "-v",
        "<staged>/bandit.ini:/panopticon-config/bandit.ini:ro", "--network", "none",
        "-v", "<target>:/src:ro", "panopticon-tools", "bandit", "--ini",
        "/panopticon-config/bandit.ini", "--ignore-nosec", "-q", "-r",
        "--exclude=.svn,CVS,.bzr,.hg,.git,__pycache__,.tox,.eggs,*.egg,.worktrees",
        "/src", "-s", "B101,B404,B110,B112", "-f", "sarif"
    ],
    "bandit/standard/no-ini": [
        "<docker>", "run", "--cidfile", "<cidfile>", "--rm", "--memory", "6g",
        "--memory-swap", "6g", "--cpus", "4", "--pids-limit", "1024", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "-w", "/panopticon-empty-cwd", "-v",
        "<staged>/bandit.ini:/panopticon-config/bandit.ini:ro", "--network", "none",
        "-v", "<target>:/src:ro", "panopticon-tools", "bandit", "--ini",
        "/panopticon-config/bandit.ini", "-q", "-r",
        "--exclude=.svn,CVS,.bzr,.hg,.git,__pycache__,.tox,.eggs,*.egg,.worktrees",
        "/src", "-s", "B101,B404,B110,B112", "-f", "sarif"
    ],
    "bandit/standard/own-ini": [
        "<docker>", "run", "--cidfile", "<cidfile>", "--rm", "--memory", "6g",
        "--memory-swap", "6g", "--cpus", "4", "--pids-limit", "1024", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "-w", "/panopticon-empty-cwd", "--network",
        "none", "-v", "<target>:/src:ro", "panopticon-tools", "bandit", "--ini",
        "/src/.bandit", "-q", "-r",
        "--exclude=.svn,CVS,.bzr,.hg,.git,__pycache__,.tox,.eggs,*.egg,.worktrees",
        "/src", "-f", "sarif"
    ],
    "trivy/redteam/no-ini": [
        "<docker>", "run", "--cidfile", "<cidfile>", "--rm", "--memory", "6g",
        "--memory-swap", "6g", "--cpus", "4", "--pids-limit", "1024", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "-w", "/panopticon-empty-cwd", "-v",
        "<staged>/.trivyignore:/panopticon-config/.trivyignore:ro", "--network",
        "none", "-v", "<target>:/src:ro", "panopticon-tools", "trivy", "fs",
        "--skip-db-update", "--offline-scan", "--format", "sarif",
        "--ignorefile=/panopticon-config/.trivyignore", "/src"
    ],
    "trivy/redteam/own-ini": [
        "<docker>", "run", "--cidfile", "<cidfile>", "--rm", "--memory", "6g",
        "--memory-swap", "6g", "--cpus", "4", "--pids-limit", "1024", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "-w", "/panopticon-empty-cwd", "-v",
        "<staged>/.trivyignore:/panopticon-config/.trivyignore:ro", "--network",
        "none", "-v", "<target>:/src:ro", "panopticon-tools", "trivy", "fs",
        "--skip-db-update", "--offline-scan", "--format", "sarif",
        "--ignorefile=/panopticon-config/.trivyignore", "/src"
    ],
    "trivy/standard/no-ini": [
        "<docker>", "run", "--cidfile", "<cidfile>", "--rm", "--memory", "6g",
        "--memory-swap", "6g", "--cpus", "4", "--pids-limit", "1024", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "-w", "/panopticon-empty-cwd", "-v",
        "<staged>/.trivyignore:/panopticon-config/.trivyignore:ro", "--network",
        "none", "-v", "<target>:/src:ro", "panopticon-tools", "trivy", "fs",
        "--skip-db-update", "--offline-scan", "--format", "sarif",
        "--ignorefile=/panopticon-config/.trivyignore", "/src"
    ],
    "trivy/standard/own-ini": [
        "<docker>", "run", "--cidfile", "<cidfile>", "--rm", "--memory", "6g",
        "--memory-swap", "6g", "--cpus", "4", "--pids-limit", "1024", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "-w", "/panopticon-empty-cwd", "-v",
        "<staged>/.trivyignore:/panopticon-config/.trivyignore:ro", "--network",
        "none", "-v", "<target>:/src:ro", "panopticon-tools", "trivy", "fs",
        "--skip-db-update", "--offline-scan", "--format", "sarif",
        "--ignorefile=/panopticon-config/.trivyignore", "/src"
    ],
}


class TestTheDockerArgvSurvivesTheExtraction(unittest.TestCase):
    """#1762 split 1/3 is a pure move, and this is what "pure" is allowed to
    mean: every scanner-owned config launch builds the same argv it built
    before the block left `run_tools`.

    The argv is the whole product of this block -- the `--ini`/`--ignorefile`
    pin, the `-v` config mount, the suppression knob under redteam, the skip
    list that comes off when the operator's own ini is honoured -- and each of
    those is assembled by a different moved function. One golden per case
    catches a dropped flag, a re-ordered insert and a mount that lost its `:ro`
    in the same assertion.
    """

    def test_every_scanner_owned_config_argv_matches_the_pre_split_golden(self):
        for label, tool, mode, planted in _argv_cases():
            with self.subTest(case=label):
                self.assertEqual(GOLDEN[label],
                                 _dispatch_argv(tool, mode, planted))

    def test_the_golden_pins_every_case_and_no_stale_one(self):
        # Vacuity guard. A `SCANNER_OWNED_CONFIG` that lost an entry, or a mode
        # that stopped being generated, makes the loop above pass by iterating
        # over less -- which is the one way a golden goes quiet.
        self.assertEqual(sorted(GOLDEN),
                         sorted(label for label, *_rest in _argv_cases()))


class TestTheStagedConfigIsTheScannersOwn(unittest.TestCase):
    """The three assertions that read nothing but this module's own constants.

    Moved here unchanged from `tests/test_run_tools_core.py` and
    `tests/test_run_tools_dispatch.py` when #1762 part 1 moved what they pin:
    every other test of the staged config drives the whole dispatch loop and so
    still belongs beside `run_tools`.
    """

    def test_the_ini_holds_exactly_one_key_and_no_target_text(self):
        lines = [ln for ln in sc.BANDIT_INI_TEXT.splitlines() if ln.strip()]
        self.assertEqual(lines[0], "[bandit]")
        self.assertEqual(len([ln for ln in lines if "=" in ln]), 1)
        self.assertEqual(len(lines), 2)
        value = lines[1].split("=", 1)[1]
        for owned in sc.BANDIT_SCANNER_EXCLUDES:
            self.assertIn(owned, [e.strip() for e in value.split(",")])

    def test_no_scanner_owned_exclude_entry_can_split_or_inject(self):
        # A future entry with a comma would inject a second exclusion; one with
        # a newline would inject a second ini KEY. Neither is a target input --
        # which is exactly why it has to be pinned here rather than validated at
        # runtime on data nobody can supply.
        for entry in tuple(sc.BANDIT_DEFAULT_EXCLUDES) + tuple(sc.BANDIT_SCANNER_EXCLUDES):
            for char in (",", "\n", "\r", "="):
                self.assertNotIn(char, entry, entry)

    def test_the_ignorefile_declares_nothing(self):
        # Every non-comment line would be a vulnerability id trivy stops
        # reporting, so there are none -- and no target-derived text either.
        active = [ln for ln in sc.TRIVY_IGNOREFILE_TEXT.splitlines()
                  if ln.strip() and not ln.lstrip().startswith("#")]
        self.assertEqual(active, [])


# ONE rule for the whole split: a name `scanner_config` owns is patched THERE,
# because that is where the moved code looks it up. The names below are the
# EXCEPTION the rule needs -- the ones `run_tools` still binds, because code that
# stayed behind reads them or a test reads them through `run_tools.<name>`. They
# are READ bindings: patching one reaches nothing either, so the walk further
# down refuses that too.
#
# Each list is asserted equal to what `run_tools`'s `from scripts.<module>
# import (...)` really binds, read with `ast`, so it cannot drift from the code
# it describes. Everything else a split module defines is derived, not listed: a
# symbol C3 adds is covered the moment it lands.
RE_EXPORTED = frozenset({
    "BANDIT_DEFAULT_EXCLUDES", "BANDIT_SCANNER_EXCLUDES", "BANDIT_INI_NAME",
    "BANDIT_INI_TEXT", "CONFIG_TARGET_BANDIT", "SCANNER_CONFIG_MOUNT",
    "SCANNER_OWNED_CONFIG", "TRIVY_IGNOREFILE_NAME", "TRIVY_IGNOREFILE_TEXT",
    "TARGET_MOUNT", "_SCANNER_CONFIG_POSTURE", "_SUPPRESSION_POSTURE",
})
# #1762 part 2 (`tool_capture`): the watchdog's deadline and the spool's cap,
# both still read on the dispatch side, plus the redaction ledger the manifest
# writer reads back.
RE_EXPORTED_TOOL_CAPTURE = frozenset({
    "MAX_TOOL_OUTPUT_BYTES", "TOOL_TIMEOUT", "_REDACTED_CAPTURES",
})
# #1762 part 3 (`tools_manifest`): the walk bound the manifest publishes as
# `depth_bound` and is `write_manifest`'s def-time default, plus the two posture
# ledgers `run_tools` clears and fills where the argv is built.
RE_EXPORTED_TOOLS_MANIFEST = frozenset({
    "VENV_MAX_DEPTH", "_IGNORE_FILE_POSTURE", "_NETWORK_POSTURE",
})
_ROOT = pathlib.Path(REPO_ROOT)          # `_test_helpers` exports it as a str
_RUN_TOOLS = _ROOT / "skill" / "scripts" / "run_tools.py"
_SCANNER_CONFIG = _ROOT / "skill" / "scripts" / "scanner_config.py"
_TOOL_CAPTURE = _ROOT / "skill" / "scripts" / "tool_capture.py"
_TOOLS_MANIFEST = _ROOT / "skill" / "scripts" / "tools_manifest.py"
_TESTS = _ROOT / "tests"
# One row per module `run_tools` has been split into (#1762): the module object,
# the file its names are DERIVED from, and the allowlist of names `run_tools`
# still re-binds out of it. All three parts have landed; a fourth split would
# add a row and nothing else here.
_SPLITS = (
    ("scanner_config", sc, _SCANNER_CONFIG, RE_EXPORTED),
    ("tool_capture", tc, _TOOL_CAPTURE, RE_EXPORTED_TOOL_CAPTURE),
    ("tools_manifest", tm, _TOOLS_MANIFEST, RE_EXPORTED_TOOLS_MANIFEST),
)
# The aliases the run_tools tests bind, as a FLOOR. The set actually used is
# read from each file's own bindings as well, because a fixed list missed both
# `tests/conftest.py`'s `_run_tools` and any `from scripts import run_tools as
# X`; a module reached through another module (`rft.run_tools`,
# tests/test_run_fixture_tests.py) is recognised by its last segment.
_RUN_TOOLS_ALIASES = frozenset({"rt", "run_tools", "scripts.run_tools"})


def _parse(path):
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _dotted(node):
    """`a.b.c` as a string, or None for an expression that is not a name path."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def _names_run_tools(dotted, aliases):
    return dotted is not None and (dotted in aliases
                                   or dotted.split(".")[-1] == "run_tools")


def _aliases_in(tree):
    """Every name *tree* binds to the `run_tools` MODULE, from its own imports
    and assignments, on top of the conventional aliases."""
    names = set(_RUN_TOOLS_ALIASES)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[-1] == "run_tools":
                    names.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "run_tools":
                    names.add(alias.asname or alias.name)
    for _ in range(3):        # `X = rt`, then `Y = X`: settle a short chain
        for node in ast.walk(tree):
            if (isinstance(node, ast.Assign)
                    and _names_run_tools(_dotted(node.value), names)):
                names.update(t.id for t in node.targets
                             if isinstance(t, ast.Name))
    return names


def _defined_in(path):
    """Every name the module at *path* DEFINES at module level.

    Read from the AST rather than `vars()` on purpose: `vars()` also holds what
    the module imported (`REDTEAM` and `SECURITY_FLAG` from `tools.base`,
    `redact` and `safe_write` in `tool_capture`), and `run_tools` binds those
    legitimately from their own owner.
    """
    names = set()
    for node in _parse(path).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            names.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
    return names


def _functions_in(path):
    """The module-level callables the module at *path* defines, in source order."""
    return [node.name for node in _parse(path).body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]


def _re_exported_by_run_tools(module, path=None):
    """The names `run_tools` binds out of *module*, read with `ast`."""
    names = set()
    for node in ast.walk(_parse(path or _RUN_TOOLS)):
        if (isinstance(node, ast.ImportFrom) and node.module
                and node.module.split(".")[-1] == module):
            names.update(alias.asname or alias.name for alias in node.names)
    return names


def _patch_sites(path, watched):
    """`(lineno, name)` for every patch in *path* that aims a *watched* name at
    the `run_tools` module, in each spelling that reaches a module attribute:
    `patch.object(rt, "NAME")`, `monkeypatch.setattr(rt, "NAME", v)`, the bare
    builtin `setattr(rt, "NAME", v)`, and the string forms
    `patch("scripts.run_tools.NAME")` / `setattr("scripts.run_tools.NAME", v)`.

    A patch of a MODULE attribute (`patch.object(rt.os, "lstat")`) is a
    different thing and stays legal: `rt.os` and `sc.os` are the same object, so
    it reaches the moved code too.

    What this does NOT see, stated so it is not over-trusted: an all-keyword
    `patch.object(target=rt, attribute="NAME")`, a non-literal attribute
    (`monkeypatch.setattr(rt, name_var, v)` or the bare builtin
    `setattr(rt, name_var, v)`) and a computed target string
    (`patch("scripts.run_tools.%s" % name)`).

    Aimed at a RE-EXPORTED CONSTANT, every one of those is silently ineffective:
    the attribute EXISTS, so nothing refuses the patch and the moved code goes on
    reading its own module's value. That is the residual this guard cannot close,
    and it is why the allowlist is kept to constants nothing patches.

    Aimed at a MOVED FUNCTION the strong half of the rule keeps the name off
    `run_tools` entirely, and three of the four then fail loudly:
    `patch.object`, `monkeypatch.setattr` and the string form all refuse an
    attribute that does not exist and raise `AttributeError`. Only the bare
    builtin `setattr` stays silent -- it CREATES the attribute, leaving a dead
    binding with the test passing -- and only in its non-literal spelling, since
    the literal one is in the offender corpus below. All four classifications
    were measured against this tree, not reasoned about.
    """
    tree = _parse(path)
    aliases = _aliases_in(tree)
    out = []

    def by_attribute(node):
        if len(node.args) < 2 or not _names_run_tools(_dotted(node.args[0]), aliases):
            return
        target = node.args[1]
        if isinstance(target, ast.Constant) and target.value in watched:
            out.append((node.lineno, target.value))

    def by_string(node):
        if not node.args:
            return
        target = node.args[0]
        if not (isinstance(target, ast.Constant)
                and isinstance(target.value, str)):
            return
        module, _sep, name = target.value.rpartition(".")
        if name in watched and _names_run_tools(module, aliases):
            out.append((node.lineno, name))

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = _dotted(node.func)
        if func is None:
            continue
        parts = func.split(".")
        if parts[-1] == "object" and len(parts) >= 2 and parts[-2] == "patch":
            by_attribute(node)
        elif parts[-1] == "setattr":
            # `monkeypatch.setattr` takes either (target, name, value) or
            # ("dotted.path.NAME", value); so does the builtin.
            if node.args and isinstance(node.args[0], ast.Constant):
                by_string(node)
            else:
                by_attribute(node)
        elif parts[-1] == "patch":
            by_string(node)
    return out


class TestThePatchRuleIsOneRule(unittest.TestCase):
    """#1762: `mock.patch` a moved name on `run_tools` and it reaches nothing,
    because the moved code reads the module it moved INTO -- the test passes and
    the behaviour it claims to change is untouched. That is the one failure mode
    a pure extraction can leave behind, and a green suite cannot see it, so it is
    guarded from BOTH sides: no moved name gets a second binding, and no test
    aims a patch at `run_tools` for a name that moved.

    Derived from each module's own AST rather than from a list, because a list
    stops growing: part 2 (`tool_capture`) is covered by adding one row to
    `_SPLITS`, and part 3 (`tools_manifest`) was.
    """

    def test_the_allowlist_is_exactly_what_run_tools_re_exports(self):
        # Each `RE_EXPORTED*` is the exception list the re-export comment in
        # `run_tools` describes in prose. If the two disagree, one of them is
        # lying and every assertion below is measuring the wrong set.
        for module, _mod, _path, allowed in _SPLITS:
            with self.subTest(module=module):
                self.assertEqual(sorted(allowed),
                                 sorted(_re_exported_by_run_tools(module)))

    def test_every_re_exported_name_is_still_defined_by_its_owner(self):
        for module, _mod, path, allowed in _SPLITS:
            stale = sorted(allowed - _defined_in(path))
            with self.subTest(module=module):
                self.assertEqual(stale, [], "re-exported name(s) `%s` no longer "
                                            "defines: %s" % (module, ", ".join(stale)))

    def test_no_moved_function_is_bound_on_run_tools(self):
        # The strong half of the rule, and the one that needs no allowlist at
        # all: a FUNCTION that moved is never re-exported, so its new module is
        # unambiguously the place to patch it. The two anchors keep the
        # derivation honest against a file that stopped defining anything.
        for module, mod, path, allowed in _SPLITS:
            functions = _functions_in(path)
            self.assertIn({"scanner_config": "_scanner_owned_config",
                           "tool_capture": "_stream_and_write",
                           "tools_manifest": "write_manifest"}[module], functions)
            for name in functions:
                with self.subTest(module=module, function=name):
                    self.assertNotIn(name, allowed,
                                     "%s is re-exported; a moved function must "
                                     "be patched on %s only" % (name, module))
                    self.assertTrue(hasattr(mod, name))
                    self.assertFalse(hasattr(rt, name),
                                     "%s is bound on run_tools too; patching it "
                                     "there would be silently ineffective" % name)

    def test_nothing_a_split_module_owns_is_bound_on_run_tools_unannounced(self):
        for module, mod, path, allowed in _SPLITS:
            for name in sorted(_defined_in(path) - allowed):
                with self.subTest(module=module, name=name):
                    self.assertTrue(hasattr(mod, name), "%s left %s" % (name, module))
                    self.assertFalse(hasattr(rt, name),
                                     "%s is bound on run_tools without being in "
                                     "the re-export list; either add it there "
                                     "(with the reason) or drop the binding" % name)

    def test_no_test_patches_a_moved_name_through_run_tools(self):
        # The other side of the rule. A re-exported name is a READ binding, so
        # patching THAT on `run_tools` is just as ineffective as patching one
        # that was never bound -- both are refused here, anywhere under tests/.
        watched = set()
        for _module, _mod, path, allowed in _SPLITS:
            watched |= _defined_in(path) | allowed
        offenders = []
        for path in sorted(_TESTS.rglob("*.py")):
            for lineno, name in _patch_sites(path, watched):
                offenders.append("%s:%d  patches run_tools.%s"
                                 % (path.relative_to(_ROOT), lineno, name))
        self.assertEqual(
            offenders, [],
            "%d patch(es) of a moved name aimed at run_tools:\n  %s\n"
            "the moved code reads its OWN module's globals, so this patch passes "
            "while changing nothing -- target the module it moved into instead"
            % (len(offenders), "\n  ".join(offenders)))

    # Two conventional aliases, one unconventional one and the `_run_tools` that
    # `tests/conftest.py` really binds: the planted file declares them so the
    # walk has to RESOLVE them rather than recognise a spelling.
    PLANTED_IMPORTS = ("import scripts.run_tools as rt\n"
                       "import scripts.run_tools as _run_tools\n"
                       "from scripts import run_tools\n"
                       "from scripts import run_tools as weird\n"
                       "import scripts.scanner_config as sc\n"
                       "import scripts.tool_capture as tc\n"
                       "import scripts.tools_manifest as tm\n")

    def test_the_patch_walk_catches_a_planted_offender(self):
        # Non-vacuity, on a synthetic file: the scan above asserts an EMPTY
        # list, which a detector that sees nothing also satisfies.
        watched = {"SCANNER_OWNED_CONFIG", "_scanner_owned_config",
                   "MAX_TOOL_OUTPUT_BYTES", "_stream_and_write",
                   "_NETWORK_POSTURE", "write_manifest"}
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "test_planted.py"
            for source in (
                    'mock.patch.object(rt, "SCANNER_OWNED_CONFIG", {})',
                    'patch.object(run_tools, "SCANNER_OWNED_CONFIG", {})',
                    'mock.patch.object(scripts.run_tools, "_scanner_owned_config")',
                    'mock.patch("scripts.run_tools.SCANNER_OWNED_CONFIG")',
                    'patch("run_tools._scanner_owned_config")',
                    # part 2's names, and the spellings a fixed alias list and a
                    # patch-only walk both missed (C1 re-review nit 1).
                    'mock.patch.object(rt, "MAX_TOOL_OUTPUT_BYTES", 1)',
                    'mock.patch.object(rt, "_stream_and_write", None)',
                    'monkeypatch.setattr(_run_tools, "SCANNER_OWNED_CONFIG", {})',
                    'monkeypatch.setattr(weird, "_stream_and_write", None)',
                    'monkeypatch.setattr("scripts.run_tools.MAX_TOOL_OUTPUT_BYTES", 1)',
                    'setattr(rt, "_stream_and_write", None)',
                    # part 3's names: the ledger the manifest reads back, and
                    # the writer itself.
                    'mock.patch.object(rt, "_NETWORK_POSTURE", {})',
                    'monkeypatch.setattr(rt, "write_manifest", None)'):
                with self.subTest(source=source):
                    path.write_text(self.PLANTED_IMPORTS + "x = %s\n" % source,
                                    encoding="utf-8")
                    self.assertTrue(_patch_sites(path, watched),
                                    "detector missed %s" % source)
            for source in (
                    # a MODULE attribute: the same object from both modules.
                    # `rt.os`, not `rt.tempfile` -- part 2 took `tempfile` out of
                    # `run_tools`, so that spelling can no longer appear in a
                    # working test and would document nothing.
                    'mock.patch.object(rt.os, "lstat")',
                    # a name run_tools still owns.
                    'mock.patch.object(rt, "CONTAINER_PIDS_LIMIT", "")',
                    'monkeypatch.setattr(_run_tools, "docker_available", None)',
                    # the right targets.
                    'mock.patch.object(sc, "SCANNER_OWNED_CONFIG", {})',
                    'mock.patch.object(tc, "MAX_TOOL_OUTPUT_BYTES", 1)',
                    'mock.patch("scripts.scanner_config.SCANNER_OWNED_CONFIG")',
                    'monkeypatch.setattr(tc, "_stream_and_write", None)',
                    'mock.patch.object(tm, "write_manifest", None)',
                    # not a patch at all.
                    'mock.patch.dict(os.environ, {"SCANNER_OWNED_CONFIG": "1"})'):
                with self.subTest(source=source):
                    path.write_text(self.PLANTED_IMPORTS + "x = %s\n" % source,
                                    encoding="utf-8")
                    self.assertEqual(_patch_sites(path, watched), [],
                                     "detector flagged %s" % source)

    def test_the_alias_walk_reads_the_bindings_a_file_really_makes(self):
        # `tests/conftest.py` is the file the fixed list missed: it binds
        # `_run_tools` and patches through it with `monkeypatch.setattr`.
        aliases = _aliases_in(_parse(_TESTS / "conftest.py"))
        self.assertIn("_run_tools", aliases)
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "test_chain.py"
            path.write_text("from scripts import run_tools as base\n"
                            "mirror = base\n"
                            "again = mirror\n", encoding="utf-8")
            self.assertLessEqual({"base", "mirror", "again"},
                                 _aliases_in(_parse(path)))

    def test_the_patch_walk_visits_the_whole_test_tree(self):
        # Including `tests/tools/`, which is where an adapter-side patch would
        # land, and which the brief's pytest set does not otherwise reach.
        # 289 files today, 180 of them at the top level: a floor under 180
        # would still be cleared by a walk that stopped recursing, which is the
        # collapse this guards against.
        visited = sorted(_TESTS.rglob("*.py"))
        self.assertGreater(len(visited), 250, "the test-tree walk collapsed")
        self.assertIn(_TESTS / "tools" / "test_legacy_sarif.py", visited)
        # and it really parses them: a file that does not parse must not be
        # skipped silently.
        with tempfile.TemporaryDirectory() as d:
            broken = pathlib.Path(d) / "test_broken.py"
            broken.write_text("def t(:\n", encoding="utf-8")
            with self.assertRaises(SyntaxError):
                _patch_sites(broken, {"x"})


class TestTheSplitModulesShareOneLedger(unittest.TestCase):
    """`run_tools` binds every ledger its extracted modules own -- all four of
    the manifest's postures and the redaction set -- so the whole claim rests on
    each name addressing ONE object: `run_tools()` clears it, the code that
    moved (or the loop that stayed) fills it, `write_manifest` reads it back.
    Rebind either side and the manifest would publish an empty posture with
    nothing failing.

    Part 3 is why the count is five rather than three: the network and
    ignore-file postures moved to `tools_manifest` beside their only reader, and
    `run_tools` still clears both and fills them where the argv is built."""

    def test_the_ledgers_are_the_same_object_in_both_modules(self):
        for owner, name in ((sc, "_SUPPRESSION_POSTURE"),
                            (sc, "_SCANNER_CONFIG_POSTURE"),
                            (tc, "_REDACTED_CAPTURES"),
                            (tm, "_NETWORK_POSTURE"),
                            (tm, "_IGNORE_FILE_POSTURE")):
            with self.subTest(ledger=name):
                self.assertIs(getattr(rt, name), getattr(owner, name))


if __name__ == "__main__":
    unittest.main()
