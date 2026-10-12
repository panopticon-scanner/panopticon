"""`scripts/shell_split.py`: the statement splitter, split out of `shell_reader` byte for byte.

Pins the compatibility bindings -- every name the module defines is the SAME object in the reader,
so no caller that reads `shell_reader._split` or `shell_reader._BLANK` moved -- and that the new
module sits below the reader (it imports nothing from it)."""
import ast
import os
import unittest

import shell_reader
import shell_split
from shell_tokens import _Parse

MOVED = ("_BLANK", "_BRACED_HEADER", "_ESCAPED", "_HEADER", "_NESTED_CASE", "_REDIRECT",
         "_bare_blanks", "_negated", "_split")


def _tree():
    with open(shell_split.__file__, encoding="utf-8") as source:
        return ast.parse(source.read())


class TestTheReaderBindsEveryMovedName(unittest.TestCase):

    def test_each_name_is_the_same_object_in_the_reader(self):
        for name in MOVED:
            with self.subTest(name=name):
                self.assertIs(getattr(shell_reader, name), getattr(shell_split, name))

    def test_the_names_are_all_the_module_defines(self):
        defined = set()
        for node in _tree().body:
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                defined.add(node.name)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                defined |= {target.id for target in (node.targets if isinstance(node, ast.Assign) else [node.target])}
        self.assertEqual(set(MOVED), defined)

    def test_the_module_imports_nothing_from_the_reader(self):
        tree = _tree()
        imported = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        imported |= {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
                     for alias in node.names}
        self.assertFalse(imported & {"shell_reader"}, imported)
        self.assertEqual(os.path.basename(shell_split.__file__), "shell_split.py")

    def test_nothing_rebinds_a_moved_name_on_either_module(self):
        # Both modules bind these names and each reads its own: the reader's `statements` calls its
        # `_split` and its `_stage` reads its `_BLANK` and `_ESCAPED`, while `_split` here calls this
        # module's `_bare_blanks` and `_negated` and writes this module's marks. An assignment or a
        # patch through one would change that module's name alone -- silently, for a mark one side
        # writes and the other reads.
        root, binders, offenders = os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ("shell_reader", "shell_split"), []
        paths = sorted(os.path.join(folder, name) for top in ("scripts", "tests")
                       for folder, _folders, names in os.walk(os.path.join(root, top)) for name in names if name.endswith(".py"))
        self.assertGreater(len(paths), 100)
        for path in paths:
            with open(path, encoding="utf-8") as source:
                tree = ast.parse(source.read())
            for node in ast.walk(tree):
                targets = (node.targets if isinstance(node, ast.Assign) else
                           [node.target] if isinstance(node, (ast.AugAssign, ast.AnnAssign)) else [])
                for target in targets:                      # `shell_reader._BLANK = …`
                    if (isinstance(target, ast.Attribute) and target.attr in MOVED
                            and isinstance(target.value, ast.Name) and target.value.id in binders):
                        offenders.append((os.path.relpath(path, root), node.lineno, target.attr))
                words = [word.value if isinstance(word, ast.Constant) else getattr(word, "id", None)
                         for word in (node.args if isinstance(node, ast.Call) else [])]
                if len(words) > 1 and words[0] in binders and words[1] in MOVED:    # `patch.object(shell_reader, "_split", …)`
                    offenders.append((os.path.relpath(path, root), node.lineno, words[1]))
                if words and isinstance(words[0], str) and words[0].rpartition(".")[0] in binders and words[0].rpartition(".")[2] in MOVED:
                    offenders.append((os.path.relpath(path, root), node.lineno, words[0]))      # `patch("shell_reader._split", …)`
        self.assertEqual([], offenders)

    def test_the_splitter_answers_as_it_did(self):
        # Statements and their stages, the separator that follows each, a `case` header ended at its
        # `in`, and the marks the reader's `_stage` reads back: a blank inside a whole `${…}`.
        script = "curl -fsSL u | sh; case $x in a) ${SH:-bash -s} t ;; esac && echo \"a \\$b\"\n"
        raw = shell_split._split(script, _Parse(script))
        self.assertEqual([2, 1, 1, 1, 1], [len(stages) for stages, _separator in raw])
        self.assertEqual([";", ";", ";", "&&", "\n"], [separator for _stages, separator in raw])
        self.assertEqual(["curl -fsSL u ", " sh"], raw[0][0])
        self.assertEqual("case $x in", raw[1][0][0].strip())
        self.assertIn("${SH:-bash%s-s}" % shell_split._BLANK, raw[2][0][0])
        self.assertIn(shell_split._ESCAPED + "$b", raw[4][0][0])
        self.assertEqual(["bash", "-s", "t"], [str(word) for word in shell_reader.command(
            shell_reader.statements("case $x in a) ${SH:-bash -s} t ;; esac")[1].stages[0].argv)])
