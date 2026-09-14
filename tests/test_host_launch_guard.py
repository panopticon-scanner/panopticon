"""The suite must never start a host's CLI, and that must be structural.

The guardrails' rule is "no test launches `codex` or `claude`". I-5 made that
true for the two Codex launch seams by moving their launcher to a module
attribute the autouse fixture in tests/conftest.py can swap. N-M3 then found a
THIRD door by accident -- `setup_flow.readiness()` probes `codex --version`
through a runner bound as a DEFAULT ARGUMENT, which no monkeypatch can reach --
and a fourth is `runners/claude.py`, which binds its launcher the same way.

Per-seam discipline is what failed here twice, so this file does not name
seams. It finds them: a module is a host-CLI launch seam if it names a
registered host as the head of a command literal (`["codex", "--version"]`) or
declares one as its runner's `CLI`. Every module the walk finds must read a
module-level `DEFAULT_RUNNER`, and every one of those must be refusing while
the autouse guard is in place. Adding a fifth seam therefore turns this file
red instead of quietly reopening the hole.

The walk is AST-based on purpose: a text scan over these modules flags the
prose that explains the rule, and the comments here quote the very argv they
are about.
"""
import ast
import importlib
import os
import subprocess
import unittest

from scripts import codex_host
from scripts import hosts

_SCRIPTS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "skill", "scripts")


def _spawns_a_host_cli(tree, host_names):
    """Why this module is a launch seam, or [] if it is not one.

    Two shapes, because the two families write the launch differently:
    codex_host/setup_flow build the argv as a list literal whose head is the
    binary, and the runners keep the binary in a class-level `CLI` constant
    that `command()` reads.
    """
    reasons = []
    for node in ast.walk(tree):
        if isinstance(node, ast.List) and node.elts:
            head = node.elts[0]
            if isinstance(head, ast.Constant) and head.value in host_names:
                reasons.append("argv %r at line %d" % (head.value, head.lineno))
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if (isinstance(target, ast.Name) and target.id == "CLI"
                        and isinstance(node.value, ast.Constant)
                        and node.value.value in host_names):
                    reasons.append("CLI = %r at line %d"
                                   % (node.value.value, node.value.lineno))
    return reasons


def _seams():
    """[(import name, relative path, reasons)] for every host-CLI launch seam."""
    host_names = set(hosts.known_hosts())
    found = []
    for dirpath, dirnames, filenames in os.walk(_SCRIPTS):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for filename in sorted(filenames):
            if not filename.endswith(".py"):
                continue
            path = os.path.join(dirpath, filename)
            with open(path, encoding="utf-8") as fh:
                reasons = _spawns_a_host_cli(ast.parse(fh.read()), host_names)
            if not reasons:
                continue
            relative = os.path.relpath(path, _SCRIPTS)
            module = "scripts." + relative[:-3].replace(os.sep, ".")
            found.append((module, relative, reasons))
    return found


class TestEverySeamThatCanStartAHostCliIsCovered(unittest.TestCase):

    def test_the_walk_finds_the_seams_we_know_about(self):
        """A guard that silently found nothing would pass forever."""
        found = dict((relative, reasons) for _, relative, reasons in _seams())
        for expected in ("codex_host.py", "setup_flow.py",
                         os.path.join("runners", "claude.py"),
                         os.path.join("runners", "codex.py")):
            self.assertIn(expected, found)

    def test_every_seam_reads_a_module_level_launcher(self):
        """A launcher bound as a default argument is unreachable by a patch,
        so the autouse guard cannot cover it and the test that forgets to
        inject one reaches the real binary and stays green."""
        for module_name, relative, reasons in _seams():
            module = importlib.import_module(module_name)
            self.assertTrue(
                hasattr(module, "DEFAULT_RUNNER"),
                "%s launches a host CLI (%s) but binds its launcher where no "
                "monkeypatch can reach it; give it a module-level "
                "DEFAULT_RUNNER read at call time" % (relative, "; ".join(reasons)))

    def test_the_autouse_guard_is_refusing_through_every_seam(self):
        """Not "the fixture lists four modules" -- the guarantee itself,
        asserted through whatever the walk finds today."""
        for module_name, relative, _ in _seams():
            module = importlib.import_module(module_name)
            launcher = getattr(module, "DEFAULT_RUNNER", None)
            self.assertIsNot(launcher, subprocess.run,
                             "%s's launcher is still the real one" % relative)
            with self.assertRaises(codex_host.LaunchRefused):
                launcher(["a-host-cli", "--version"])


if __name__ == "__main__":
    unittest.main()
