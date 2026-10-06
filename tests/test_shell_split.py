"""`scripts/shell_split.py`: the statement splitter split out of `shell_reader` byte for byte.

Pins the compatibility bindings -- every name the reader imports back is the SAME object, so no
caller that reads `shell_reader._split` or `shell_reader._MARKS` moved -- and that the new module
sits below the reader (imports nothing from it), as `shell_command` and `shell_tokens` do."""
import ast
import os
import unittest

import shell_reader
import shell_split

MOVED = ("_BLANK", "_BRACED_HEADER", "_ESCAPE_AT", "_ESCAPED", "_HEADER", "_MARKS", "_NESTED_CASE",
         "_QUOTE_END", "_QUOTED_AT", "_REDIRECT", "_split")


class TestTheReaderBindsEveryMovedName(unittest.TestCase):

    def test_each_name_is_the_same_object_in_both_modules(self):
        for name in MOVED:
            with self.subTest(name=name):
                self.assertIs(getattr(shell_reader, name), getattr(shell_split, name))

    def test_the_splitter_imports_nothing_from_the_reader(self):
        tree = ast.parse(open(shell_split.__file__, encoding="utf-8").read())
        imported = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        imported |= {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
                     for alias in node.names}
        self.assertNotIn("shell_reader", imported, imported)
        self.assertEqual(os.path.basename(shell_split.__file__), "shell_split.py")

    def test_the_splitter_cuts_as_the_reader_always_did(self):
        # Three statements -- the pipeline, the function body, its closing brace -- and the
        # `|` inside the quotes is text, not a stage boundary.
        context = shell_reader._Parse("x")
        cut = shell_split._split("echo 'a | b' | sh && f() { :; }\n", context)
        self.assertEqual(["&&", ";", "\n"], [separator for _stages, separator in cut])
        self.assertEqual(2, len(cut[0][0]))
        self.assertIn("'a | b'", cut[0][0][0])
        statements = shell_reader.statements("echo 'a | b' | sh && f() { :; }\n")
        self.assertEqual(["echo", "a | b"], list(statements[0].stages[0].argv))
        self.assertEqual(["sh"], list(statements[0].stages[1].argv))


if __name__ == "__main__":
    unittest.main()
