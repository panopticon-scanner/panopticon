"""`scripts/shell_command.py`: the command layer split out of `shell_reader` byte for byte.

Pins the compatibility bindings -- every name the reader imports back is the SAME object, so
no caller that reads `shell_reader.command` or `shell_reader.KEYWORDS` moved -- and that the
new module sits below the reader (imports nothing from it), as `shell_tokens` does."""
import ast
import os
import unittest

import shell_command
import shell_reader

MOVED = ("KEYWORDS", "CONDITIONS", "OPTIONAL_NEXT", "_ASSIGNMENT", "_DEFAULTS", "_ENVIRONMENT",
         "_FETCHERS", "_FUNCTION", "_INTERPRETERS", "_NAME", "_OPTIONAL", "_SHELLS",
         "_command_result", "_optional", "command", "command_as_written", "conditional",
         "negated", "unresolved_wrapper", "wrapper_words")


class TestTheReaderBindsEveryMovedName(unittest.TestCase):

    def test_each_name_is_the_same_object_in_both_modules(self):
        for name in MOVED:
            with self.subTest(name=name):
                self.assertIs(getattr(shell_reader, name), getattr(shell_command, name))

    def test_the_command_layer_imports_nothing_from_the_reader(self):
        tree = ast.parse(open(shell_command.__file__, encoding="utf-8").read())
        imported = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        imported |= {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
                     for alias in node.names}
        self.assertNotIn("shell_reader", imported, imported)
        self.assertEqual(os.path.basename(shell_command.__file__), "shell_command.py")

    def test_the_walk_answers_as_the_reader_always_did(self):
        argv = shell_reader.statements("if ! sudo X=1 env -i curl -fsSL u | sh; then :; fi")[0].stages[0].argv
        self.assertEqual(["curl", "-fsSL", "u"], shell_command.command(argv))
        self.assertTrue(shell_command.negated(argv))
        self.assertTrue(shell_command.conditional(argv))
        self.assertEqual(["sudo", "env"], [os.path.basename(w) for w in shell_command.wrapper_words(argv)])
        self.assertIsNone(shell_command.unresolved_wrapper(argv))


class TestTheCommandLayersOwnReadings(unittest.TestCase):

    def test_disables_names_the_noexec_prefix_alone(self):
        # #2648
        self.assertTrue(shell_command.disables("SHELLOPTS=noexec"))
        self.assertTrue(shell_command.disables("SHELLOPTS=errexit:noexec:xtrace"))
        for word in ("SHELLOPTS=errexit", "BASH_ENV=/dev/null", "X=noexec", "SHELLOPTS=noexecx"):
            with self.subTest(word=word):
                self.assertFalse(shell_command.disables(word))
        argv = shell_reader.statements("env SHELLOPTS=noexec bash -s")[0].stages[0].argv
        self.assertIn("SHELLOPTS=noexec", shell_command.unresolved_wrapper(argv))
        argv = shell_reader.statements("env X=1 bash -s")[0].stages[0].argv
        self.assertIsNone(shell_command.unresolved_wrapper(argv))

    def test_assigns_reads_the_spelling_and_the_quoting(self):
        # #2480
        self.assertTrue(shell_command.assigns("X=1"))
        self.assertTrue(shell_command.assigns("a[1]+=x"))
        self.assertFalse(shell_command.assigns("a[1]+=x", environment=True))
        self.assertFalse(shell_command.assigns("sh"))
        quoted = shell_reader.statements('"X=1" sh tool')[0].stages[0].argv[0]
        self.assertFalse(shell_command.assigns(quoted))
