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
argv -- a list OR a tuple -- in a position an argv can go (handed to a call,
or returned from one) or declares one as its runner's `CLI` constant,
annotated or not. #1640 widened "a registered host name" by one hop: the head
may be the name of a module-level string constant of that same module, since
`_BINARY = "kimi"; runner([_BINARY, ...])` launches kimi exactly as the
literal does and used to be invisible here. Every module the walk finds must
read a module-level `DEFAULT_RUNNER`, and every one of those must be refusing
while the autouse guard is in place. Adding a seventh seam therefore turns
this file red instead of quietly reopening the hole.

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


def _module_constants(tree):
    """{name: string} for this module's own `NAME = "literal"` / `NAME: str =
    "literal"`, module level only.

    #1640: the ONE HOP the walk below follows. A module-level string constant
    is not dataflow -- it is the assignment three lines up, in the same file,
    reachable by reading `tree.body`. A name bound anywhere else (a function
    body, an import, an attribute, a call) is not here, on purpose.
    """
    out = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        else:
            continue
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                out[target.id] = value.value
    return out


def _host_named_by(node, constants, host_names):
    """The registered host `node` names, or None. A `Constant` is itself; a
    `Name` is resolved one hop against `constants`."""
    if isinstance(node, ast.Constant):
        value = node.value
    elif isinstance(node, ast.Name):
        value = constants.get(node.id)
    else:
        return None
    return value if value in host_names else None


def _spawns_a_host_cli(tree, host_names):
    """Why this module is a launch seam, or [] if it is not one.

    Two shapes, because the families write the launch differently:
    codex_host/setup_flow build the argv as a list (or tuple) literal whose
    head is the binary, and the runners keep the binary in a class-level `CLI`
    constant that `command()` reads. Either head may be the binary spelled
    literally or a MODULE-LEVEL string constant of this same module, resolved
    one hop (`_BINARY = "kimi"; runner([_BINARY, ...])`, and `CLI = _BINARY`).
    All of it is additionally gated on the module importing `subprocess`, so a
    data module that merely lists the families is not told to grow a launcher
    it would never call.

    OUT OF SCOPE, deliberately, and this is the whole of the new limit: an
    argv head that is neither a string literal nor a module-level string
    constant of THIS module. A name bound by an import (`from x import BIN`),
    read off an attribute (`spec.cli`), or returned by a call is not followed
    -- one hop, no imports, no attributes, no calls -- because following any
    of those means resolving another module and parsing it, which is a
    dataflow analysis, and this file is a tripwire. Two narrower shapes are
    out for the same reason and are named here so nobody has to rediscover
    them: a constant assigned inside a module-level `if` (`if os.name ==
    "posix": _BINARY = "kimi"`) is not in `tree.body` directly and is not
    read, and an f-string head (`runner([f"kimi", ...])`) is an
    `ast.JoinedStr`, not a `Constant`, however much it looks like a literal.
    A name assigned twice resolves LAST-wins, which is what the module would
    really run: `"kimi"` then `"echo"` is not a seam, `"echo"` then `"kimi"`
    is. Declare the binary as a plain literal, as an unconditional
    module-level string constant, or as a `CLI` constant and the guard sees
    it; all three real families already do.
    """
    if not _imports_subprocess(tree):
        return []
    constants = _module_constants(tree)
    reasons = []
    for value in _argv_positions(tree):
        # A tuple argv launches exactly as a list one does -- `subprocess.run`
        # takes any sequence -- and an `ast.List`-only test failed it silently.
        if isinstance(value, (ast.List, ast.Tuple)) and value.elts:
            head = value.elts[0]
            named = _host_named_by(head, constants, host_names)
            if named:
                reasons.append("argv %r at line %d" % (named, head.lineno))
    for value in _cli_constants(tree):
        named = _host_named_by(value, constants, host_names)
        if named:
            reasons.append("CLI = %r at line %d" % (named, value.lineno))
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


class TestAClaudeEntryIsRefusedUnlessTheTestOptsIn(unittest.TestCase):
    """#1616 item 8: the launcher swap above stops the real binary starting,
    and stops there. A test that reaches `claude.Runner.run_entry` without
    meaning to gets the refusal INSIDE the runner, where `run_entry`'s
    never-raise contract turns it into an ordinary failed RunResult -- one
    more failed entry among the ones the test is about, easy to read past.

    The autouse fixture in tests/conftest.py replaces the method itself, so
    reaching it is loud. `@pytest.mark.claude_runner` (module-level in
    tests/runners/test_claude.py) is how the tests that really drive the
    family's own `run_entry` -- with an injected `runner=<fake>` -- opt back
    in; this file is not marked, so the refusal is live here.
    """

    def test_run_entry_raises_rather_than_returning_a_failed_result(self):
        import scripts.runners.claude as claude_runner
        import scripts.runners.base as runners_base
        with self.assertRaises(runners_base.LaunchRefused) as cm:
            claude_runner.Runner("claude").run_entry(
                {"id": "review-app-SEC", "prompt": "p"}, {})
        self.assertIn("claude_runner", str(cm.exception))    # names the way out


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

    def test_an_argv_head_held_in_a_module_constant_is_a_seam(self):
        """#1640 (run-13 AGT-3260033205). `runner([_BINARY, ...])` was OUT OF
        SCOPE by declaration, and the declaration was the finding: a launcher
        written this way is absent from `_seams()`, so the autouse fixture is
        never told to swap its runner and the real `kimi` starts inside the
        suite. One hop through a module-level string constant is not a
        dataflow analysis -- it is reading the assignment three lines up."""
        root = self._module("headless.py", '''
            import subprocess

            _BINARY = "kimi"

            DEFAULT_RUNNER = subprocess.run

            def launch(runner=None):
                runner = DEFAULT_RUNNER if runner is None else runner
                return runner([_BINARY, "-p", "hello"])
            ''')
        seams = _seams(root)
        self.assertEqual([relative for _, relative, _ in seams], ["headless.py"])
        self.assertIn("argv 'kimi'", seams[0][2][0])

    def test_a_tuple_argv_is_a_seam(self):
        """The other form the issue names. `subprocess.run` takes any
        sequence, so a tuple argv launches exactly as a list one does -- and
        the walk used to test `isinstance(value, ast.List)`, which a tuple
        fails silently."""
        root = self._module("exec.py", '''
            import subprocess

            def launch(runner=subprocess.run):
                return runner(("codex", "exec", "--json"))
            ''')
        seams = _seams(root)
        self.assertEqual([relative for _, relative, _ in seams], ["exec.py"])
        self.assertIn("argv 'codex'", seams[0][2][0])

    def test_a_cli_constant_bound_to_a_module_constant_is_a_seam(self):
        """`CLI = _BINARY` is the same hop on the other shape: the runners
        keep the binary in a class-level `CLI` the launcher reads, and a
        family author who spells that constant once at module level and
        references it is writing ordinary code, not hiding a launch."""
        root = self._module("runner_mod.py", '''
            import subprocess

            _BINARY = "claude"

            class Runner:
                CLI = _BINARY

                def command(self, runner=subprocess.run):
                    return runner([self.CLI, "-p"])
            ''')
        seams = _seams(root)
        self.assertEqual([relative for _, relative, _ in seams], ["runner_mod.py"])
        self.assertIn("CLI = 'claude'", "; ".join(seams[0][2]))

    def test_an_argv_head_imported_from_another_module_is_still_out_of_scope(self):
        """The new limit, pinned as a limit rather than left to the docstring.

        Following a name across a module boundary means resolving the import,
        parsing the other module, and doing it for attribute access and call
        results too -- which is the dataflow analysis this file declines to
        be. The walk reads ONE hop, in THIS module's own body. A launcher
        written this way is invisible to the tripwire, and that is a known
        gap with a known remedy (declare the binary as a literal, a
        module-level string constant, or a `CLI` constant), not an oversight.
        """
        root = self._module("imported.py", '''
            import subprocess
            from vendor.names import KIMI

            def launch(runner=subprocess.run):
                return runner([KIMI, "--version"])
            ''')
        self.assertEqual(_seams(root), [])

    def test_an_argv_head_read_off_an_attribute_is_out_of_scope_too(self):
        """The same limit on the other two shapes it names: an attribute and
        a call result. `spec.cli` may be a host name at runtime; deciding that
        statically is the analysis, not the tripwire."""
        root = self._module("attribute.py", '''
            import subprocess

            def launch(spec, runner=subprocess.run):
                return runner([spec.cli, "--version"]) or runner([name_of(), "-p"])
            ''')
        self.assertEqual(_seams(root), [])

    def test_a_constant_assigned_inside_an_if_is_out_of_scope(self):
        """Named in the docstring's limit, and pinned here so the naming
        cannot drift from the behaviour. `_module_constants` reads `tree.body`
        directly; a name bound inside a module-level `if` is one statement
        deeper, and walking into branches means deciding which one runs."""
        root = self._module("conditional.py", '''
            import os
            import subprocess

            if os.name == "posix":
                _BINARY = "kimi"
            else:
                _BINARY = "kimi.exe"

            def launch(runner=subprocess.run):
                return runner([_BINARY, "-p"])
            ''')
        self.assertEqual(_seams(root), [])

    def test_an_f_string_argv_head_is_out_of_scope(self):
        """The other named limit. `f"kimi"` parses to `ast.JoinedStr`, not
        `ast.Constant` -- a human reader calls it a string literal and the
        walk does not, which is exactly the kind of gap worth writing down."""
        root = self._module("fstring.py", '''
            import subprocess

            def launch(runner=subprocess.run):
                return runner([f"kimi", "-p"])
            ''')
        self.assertEqual(_seams(root), [])

    def test_a_rebound_constant_resolves_last_wins(self):
        """Not a limit but a rule, and undocumented rules are how a tripwire
        gets quietly narrowed: the LAST module-level assignment is what the
        module would really run, so it is what the walk reads."""
        shadowed = self._module("shadowed.py", '''
            import subprocess

            _BINARY = "kimi"
            _BINARY = "echo"

            def launch(runner=subprocess.run):
                return runner([_BINARY, "-p"])
            ''')
        self.assertEqual(_seams(shadowed), [])
        promoted = self._module("promoted.py", '''
            import subprocess

            _BINARY = "echo"
            _BINARY = "kimi"

            def launch(runner=subprocess.run):
                return runner([_BINARY, "-p"])
            ''')
        self.assertEqual([relative for _, relative, _ in _seams(promoted)],
                         ["promoted.py"])

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
