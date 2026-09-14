"""The suite must never start a host's CLI, and that must be structural.

The guardrails' rule is "no test launches `codex` or `claude`". I-5 made that
true for the two Codex launch seams by moving their launcher to a module
attribute the autouse fixture in tests/conftest.py can swap. N-M3 then found a
THIRD door by accident -- `setup_flow.readiness()` probes `codex --version`
through a runner bound as a DEFAULT ARGUMENT, which no monkeypatch can reach --
and a fourth is `runners/claude.py`, which binds its launcher the same way.
The Kimi family PR arrived with a fifth and a sixth: `runners/kimi.py`, and
the kimi probes, where `run_probes("kimi", ...)` spawns `kimi --version` and
`kimi doctor` -- which is why the walk below is the pin and the count in
tests/conftest.py is not. #1627 moved that sixth seam from `host_probes.py`
into `probes/kimi.py` and the walk followed it there on its own: it reads the
whole `skill/scripts/` tree, package directories included.

Per-seam discipline is what failed here twice, so this file does not name
seams. It finds them: a module is a host-CLI launch seam if it imports
`subprocess` AND either puts a registered host name at the head of a literal
argv in a position an argv can go (handed to a call, or returned from one) or
declares one as its runner's `CLI` constant, annotated or not. Every module
the walk finds must read a module-level `DEFAULT_RUNNER`, and every one of
those must be refusing while the autouse guard is in place. Adding a seventh
seam therefore turns this file red instead of quietly reopening the hole.

The `subprocess` gate is what keeps the walk from mistaking data for a
launch: a module holding `FAMILIES = ["claude", "codex", ...]` starts nothing,
and telling it to grow a `DEFAULT_RUNNER` would be a demand for meaningless
code with no correct way to a green suite.

The walk is AST-based on purpose: a text scan over these modules flags the
prose that explains the rule, and the comments here quote the very argv they
are about.
"""
import ast
import importlib
import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest

from scripts import codex_host
from scripts import hosts

_SCRIPTS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "skill", "scripts")


def _imports_subprocess(tree):
    """Naming a host is not launching one. Spawning is, and in this tree it
    always goes through `subprocess` -- so a module that does not import it
    cannot start a binary no matter what strings it holds."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(alias.name.split(".")[0] == "subprocess" for alias in node.names):
                return True
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] == "subprocess":
                return True
    return False


def _argv_positions(tree):
    """List literals somewhere an argv can actually go: handed to a call
    (`runner([...])`, `_probe(runner, [...])`) or returned from one
    (`codex_host.command()` builds the argv and hands it back). A list sitting
    in a module constant is data."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for value in list(node.args) + [keyword.value for keyword in node.keywords]:
                yield value
        elif isinstance(node, ast.Return) and node.value is not None:
            yield node.value


def _cli_constants(tree):
    """`CLI = "codex"` and `CLI: str = "codex"`. The annotated form is an
    ast.AnnAssign, and a walk that reads only ast.Assign is defeated by one
    type annotation -- which would be a family author's honest style choice,
    not an attack, and just as silent either way."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        else:
            continue
        for target in targets:
            if isinstance(target, ast.Name) and target.id == "CLI":
                yield value


def _spawns_a_host_cli(tree, host_names):
    """Why this module is a launch seam, or [] if it is not one.

    Two shapes, because the families write the launch differently:
    codex_host/setup_flow build the argv as a list literal whose head is the
    binary, and the runners keep the binary in a class-level `CLI` constant
    that `command()` reads. Both are additionally gated on the module
    importing `subprocess`, so a data module that merely lists the families is
    not told to grow a launcher it would never call.

    OUT OF SCOPE, deliberately: an argv whose head is a variable
    (`_BINARY = "kimi"; runner([_BINARY, ...])`) and a tuple argv. Following a
    name to its binding is a dataflow analysis, and this file is a tripwire.
    Declare the binary as a literal `CLI` constant or as a literal argv head
    and the guard sees it; both real families already do.
    """
    if not _imports_subprocess(tree):
        return []
    reasons = []
    for value in _argv_positions(tree):
        if isinstance(value, ast.List) and value.elts:
            head = value.elts[0]
            if isinstance(head, ast.Constant) and head.value in host_names:
                reasons.append("argv %r at line %d" % (head.value, head.lineno))
    for value in _cli_constants(tree):
        if isinstance(value, ast.Constant) and value.value in host_names:
            reasons.append("CLI = %r at line %d" % (value.value, value.lineno))
    return reasons


def _seams(root=None):
    """[(import name, relative path, reasons)] for every host-CLI launch seam."""
    root = _SCRIPTS if root is None else root
    host_names = set(hosts.known_hosts())
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for filename in sorted(filenames):
            if not filename.endswith(".py"):
                continue
            path = os.path.join(dirpath, filename)
            with open(path, encoding="utf-8") as fh:
                reasons = _spawns_a_host_cli(ast.parse(fh.read()), host_names)
            if not reasons:
                continue
            relative = os.path.relpath(path, root)
            module = "scripts." + relative[:-3].replace(os.sep, ".")
            found.append((module, relative, reasons))
    return found


class TestEverySeamThatCanStartAHostCliIsCovered(unittest.TestCase):

    def test_the_walk_finds_the_seams_we_know_about_and_no_others(self):
        """A guard that silently found nothing would pass forever, and one
        that found everything would demand a launcher from data modules."""
        found = sorted(relative for _, relative, _ in _seams())
        self.assertEqual(found, sorted(["codex_host.py", "setup_flow.py",
                                        os.path.join("probes", "kimi.py"),
                                        os.path.join("runners", "claude.py"),
                                        os.path.join("runners", "codex.py"),
                                        os.path.join("runners", "kimi.py")]))

    def test_every_seam_reads_a_module_level_launcher(self):
        """A launcher bound as a default argument is unreachable by a patch,
        so the autouse guard cannot cover it and the test that forgets to
        inject one reaches the real binary and stays green."""
        for module_name, relative, reasons in _seams():
            module = importlib.import_module(module_name)
            self.assertTrue(
                hasattr(module, "DEFAULT_RUNNER"),
                "%s launches a host CLI (%s) but binds its launcher where no "
                "monkeypatch can reach it. Give it `DEFAULT_RUNNER = "
                "subprocess.run` at module level, take `runner=None` and "
                "resolve `DEFAULT_RUNNER if runner is None else runner` in the "
                "body, then add the module to LAUNCH_SEAMS in tests/conftest.py"
                % (relative, "; ".join(reasons)))

    def test_the_autouse_guard_is_refusing_through_every_seam(self):
        """Not "the fixture lists six modules" -- the guarantee itself,
        asserted through whatever the walk finds today."""
        for module_name, relative, _ in _seams():
            module = importlib.import_module(module_name)
            launcher = getattr(module, "DEFAULT_RUNNER", None)
            self.assertIsNot(
                launcher, subprocess.run,
                "%s's launcher is still the real one -- it has a DEFAULT_RUNNER "
                "but is missing from LAUNCH_SEAMS in tests/conftest.py, so the "
                "autouse guard never swaps it" % relative)
            with self.assertRaises(codex_host.LaunchRefused):
                launcher(["a-host-cli", "--version"])


class TestTheWalkRecognisesSeamsAndOnlySeams(unittest.TestCase):
    """The walk is the whole guarantee, so its two failure modes -- missing a
    real seam, and flagging something that launches nothing -- are pinned on
    synthetic modules in a temp directory rather than argued about."""

    def _module(self, name, source):
        root = getattr(self, "_root", None)
        if root is None:
            root = self._root = tempfile.mkdtemp(prefix="launch-guard-")
            self.addCleanup(shutil.rmtree, root, True)
        with open(os.path.join(root, name), "w", encoding="utf-8") as fh:
            fh.write(textwrap.dedent(source))
        return root

    def test_an_annotated_cli_constant_is_still_a_seam(self):
        """`CLI: str = "kimi"` is an ast.AnnAssign, not an ast.Assign. A walk
        that reads only the second is defeated by a type annotation -- one
        token between a family author and an uncovered launch seam."""
        root = self._module("kimi.py", '''
            import subprocess

            class Runner:
                CLI: str = "kimi"

                def __init__(self, runner=subprocess.run):
                    self.runner = runner
            ''')
        self.assertEqual([relative for _, relative, _ in _seams(root)], ["kimi.py"])

    def test_a_literal_argv_in_a_new_module_is_still_a_seam(self):
        """The other shape, so narrowing the walk cannot quietly lose it."""
        root = self._module("probe.py", '''
            import subprocess

            def version(runner=subprocess.run):
                return runner(["gemini", "--version"], capture_output=True)
            ''')
        self.assertEqual([relative for _, relative, _ in _seams(root)], ["probe.py"])

    def test_a_module_that_only_names_hosts_is_not_a_seam(self):
        """A data module listing the families launches nothing. Flagging it
        would demand a DEFAULT_RUNNER that nothing would ever call, and the
        only way to a green suite would be to write meaningless code."""
        root = self._module("host_notes.py", '''
            FAMILIES = ["claude", "codex", "gemini", "kimi"]
            DEFAULT_FAMILY = FAMILIES[0]
            ''')
        self.assertEqual(_seams(root), [])


if __name__ == "__main__":
    unittest.main()
