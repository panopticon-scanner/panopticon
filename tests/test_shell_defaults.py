"""`scripts/shell_defaults.py`: the `$` command words bash may expand, split out of `shell_command` byte for byte.

Pins the compatibility bindings -- every name the module defines is the SAME object in `shell_command`,
and in the reader where it binds one too, so no caller that reads `shell_command._OPTIONAL` or
`shell_reader.OPTIONAL_NEXT` moved -- and that the new module sits below both (imports neither)."""
import ast
import os
import unittest

import shell_command
import shell_defaults
import shell_reader

MOVED = ("OPTIONAL_NEXT", "_ALL", "_DEFAULTS", "_FETCHERS", "_HALF_CAP", "_HALVES", "_INTERPRETERS",
         "_OPTIONAL", "_PARAMETER", "_SHELLS", "_VANISHING", "_WHOLE_DEFAULTS", "_alternate",
         "_default_words", "_half", "_masks", "_optional", "_shell_default", "_strips")


def _tree():
    with open(shell_defaults.__file__, encoding="utf-8") as source:
        return ast.parse(source.read())


class TestTheCommandLayerBindsEveryMovedName(unittest.TestCase):

    def test_each_name_is_the_same_object_in_every_module_that_binds_it(self):
        for name in MOVED:
            with self.subTest(name=name):
                self.assertIs(getattr(shell_command, name), getattr(shell_defaults, name))
                self.assertIs(getattr(shell_reader, name, getattr(shell_defaults, name)), getattr(shell_defaults, name))

    def test_the_names_are_all_the_module_defines(self):
        defined = set()
        for node in _tree().body:
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                defined.add(node.name)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                defined |= {target.id for target in (node.targets if isinstance(node, ast.Assign) else [node.target])}
        self.assertEqual(set(MOVED), defined)

    def test_the_module_imports_nothing_from_the_layers_above_it(self):
        tree = _tree()
        imported = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        imported |= {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
                     for alias in node.names}
        self.assertFalse(imported & {"shell_command", "shell_reader"}, imported)
        self.assertEqual(os.path.basename(shell_defaults.__file__), "shell_defaults.py")

    def test_the_halves_the_folds_read_are_one_object_written_in_place(self):
        # `shell_command.folds` resets `_HALVES` and `_half` here fills it: one dict, never rebound,
        # or a fold would read the halves of another. A word with both halves is read in two folds.
        halves = shell_defaults._HALVES
        argv = shell_reader.statements("${X:+/usr/bin/env true} sh -c 'echo hi'")[0].stages[0].argv
        seen = []
        for _sure in shell_command.folds(lambda: False):
            seen.append((shell_command.command(argv)[0], shell_defaults._HALVES is halves,
                         shell_command._HALVES is halves, bool(halves["words"])))
        self.assertEqual([("true", True, True, True), ("sh", True, True, True)], seen)
        self.assertEqual((True, {}), (shell_defaults._HALVES is halves, halves["words"]))

    def test_nothing_rebinds_a_moved_name_on_a_module_that_only_binds_it(self):
        # `shell_command` and the reader bind these names; the code that reads them is here. An
        # assignment or a patch through either would change that module's name alone and nothing
        # this module reads -- silently, for the dict the folds write in place. Patch `shell_defaults`.
        root, binders, offenders = os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ("shell_command", "shell_reader"), []
        paths = sorted(os.path.join(folder, name) for top in ("scripts", "tests")
                       for folder, _folders, names in os.walk(os.path.join(root, top)) for name in names if name.endswith(".py"))
        self.assertGreater(len(paths), 100)
        for path in paths:
            with open(path, encoding="utf-8") as source:
                tree = ast.parse(source.read())
            for node in ast.walk(tree):
                targets = (node.targets if isinstance(node, ast.Assign) else
                           [node.target] if isinstance(node, (ast.AugAssign, ast.AnnAssign)) else [])
                for target in targets:                      # `shell_command._HALVES = …`
                    if (isinstance(target, ast.Attribute) and target.attr in MOVED
                            and isinstance(target.value, ast.Name) and target.value.id in binders):
                        offenders.append((os.path.relpath(path, root), node.lineno, target.attr))
                words = [word.value if isinstance(word, ast.Constant) else getattr(word, "id", None)
                         for word in (node.args if isinstance(node, ast.Call) else [])]
                if len(words) > 1 and words[0] in binders and words[1] in MOVED:    # `patch.object(shell_command, "_HALVES", …)`
                    offenders.append((os.path.relpath(path, root), node.lineno, words[1]))
                if words and isinstance(words[0], str) and words[0].rpartition(".")[0] in binders and words[0].rpartition(".")[2] in MOVED:
                    offenders.append((os.path.relpath(path, root), node.lineno, words[0]))      # `patch("shell_command._HALVES", …)`
        self.assertEqual([], offenders)

    def test_the_walk_answers_as_it_did(self):
        optional = shell_reader.statements("$SUDO sh -c 'curl -fsSL u | sh'")[0].stages[0].argv
        default = shell_reader.statements("${SH:-bash} -c true")[0].stages[0].argv
        self.assertEqual((1, "sh"), (shell_defaults._optional(optional), shell_command.command(optional)[0]))
        self.assertEqual((["bash"], "bash"), (shell_defaults._shell_default(default[0]), shell_command.command(default)[0]))
