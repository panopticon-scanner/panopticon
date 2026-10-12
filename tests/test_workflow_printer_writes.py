"""`scripts/workflow_printer_writes.py`: how a printer's text is decoded, split out of
`workflow_printers` byte for byte (#3013).

Pins the compatibility bindings -- every name the module defines is the SAME object in
`workflow_printers`, so no caller that reads `workflow_printers._decoded` or
`workflow_printers._formatted` moved -- that the new module sits below it (it imports nothing from it,
and only what stands below both), and that every name another file reads through `workflow_printers`
is still bound there. No test patches or watches a moved name by a table: the readers that moved are
called by `printed` and `_apart`, which stay, and look up nothing of the walk's own."""
import ast
import os
import unittest

import shell_reader
import workflow_printer_writes
import workflow_printers
import workflow_programs

MOVED = ("_CONVERSION", "_COUNT", "_ESCAPE", "_ESCAPES", "_KNOWN", "_LONG", "_OCTAL", "_PAD", "_PLAIN",
         "_WRITERS", "_decoded", "_echoed", "_formatted", "_written")
# Every name a file under `scripts/`, `tests/` or `skill/` read through `workflow_printers` on `main`
# when the half moved (ddeadc0f): by a `from` import or as an attribute. Nothing reads one by `getattr`
# over a list or patches one by a table (checked by running every module that imports it, and by
# reading each for both shapes: the lesson of #3011's first head).
READ_THROUGH_IT = ("ANY", "Named", "_ECHO", "_LONG", "_PAST_DEPTH", "_PRINTERS", "_WRITERS", "_apart",
                   "_cat_reads_stdin", "_decoded", "_echoed", "_formatted", "_passes_through", "_piped",
                   "fed", "file_operand", "handed", "operand", "printed", "producer", "rendered",
                   "spellings", "substituted", "unspelled", "unsubstituted", "worded")
# PR #2699's pin of the printers' own move out of `workflow_programs`, and what else that module
# re-exports of this one: the same objects through all three.
THROUGH_PROGRAMS = ("ANY", "Named", "_PRINTERS", "_piped", "file_operand", "handed", "printed", "producer",
                    "spellings", "unspelled", "worded")
BELOW = {"re", "shell_reader"}


def _tree(module):
    with open(module.__file__, encoding="utf-8") as source:
        return ast.parse(source.read())


def _defined(module):
    names = set()
    for node in _tree(module).body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            for target in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                names |= {leaf.id for leaf in ast.walk(target) if isinstance(leaf, ast.Name)}
    return names


def _imported(module):
    tree = _tree(module)
    return ({node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
            | {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names})


class TestWorkflowPrintersBindsEveryMovedName(unittest.TestCase):

    def test_each_name_is_the_same_object_in_workflow_printers(self):
        for name in MOVED:
            with self.subTest(name=name):
                self.assertIs(getattr(workflow_printers, name), getattr(workflow_printer_writes, name))

    def test_the_names_are_all_the_module_defines(self):
        self.assertEqual(set(MOVED), _defined(workflow_printer_writes))

    def test_workflow_printers_defines_none_of_them_itself(self):
        # A definition left behind would shadow the import: two objects under one name.
        self.assertFalse(_defined(workflow_printers) & set(MOVED))

    def test_the_module_imports_only_what_stands_below_both(self):
        imported = _imported(workflow_printer_writes)
        self.assertNotIn("workflow_printers", imported)
        self.assertEqual(BELOW, imported)
        self.assertEqual(os.path.basename(workflow_printer_writes.__file__), "workflow_printer_writes.py")
        up = {name for name in _imported(shell_reader) if name.startswith("workflow_")}
        self.assertEqual(set(), up)             # and the reader reads nothing of the guard back up

    def test_nothing_rebinds_a_moved_name_on_either_module(self):
        # Both modules bind these names and each reads its own: `printed` reads `workflow_printers`'
        # `_decoded` and `_apart` its `_WRITERS`, `_formatted` and `_echoed`, while `_formatted` and
        # `_echoed` here read this module's `_written` and tables. An assignment or a patch through one
        # would change that module's name alone, silently. This reads LITERAL names, by assignment, by
        # `patch.object(module, "name", ...)` and by `patch("module.name", ...)`.
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        binders, offenders = ("workflow_printers", "workflow_printer_writes"), []
        paths = sorted(os.path.join(folder, name) for top in ("scripts", "tests")
                       for folder, _folders, names in os.walk(os.path.join(root, top))
                       for name in names if name.endswith(".py"))
        self.assertGreater(len(paths), 100)
        for path in paths:
            with open(path, encoding="utf-8") as source:
                tree = ast.parse(source.read())
            aliases = {alias.asname or alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
                       for alias in node.names if alias.name in binders}
            for node in ast.walk(tree):
                targets = (node.targets if isinstance(node, ast.Assign) else
                           [node.target] if isinstance(node, (ast.AugAssign, ast.AnnAssign)) else [])
                for target in targets:                      # `workflow_printers._WRITERS = ...`
                    if (isinstance(target, ast.Attribute) and target.attr in MOVED
                            and isinstance(target.value, ast.Name) and target.value.id in aliases):
                        offenders.append((os.path.relpath(path, root), node.lineno, target.attr))
                words = [word.value if isinstance(word, ast.Constant) else getattr(word, "id", None)
                         for word in (node.args if isinstance(node, ast.Call) else [])]
                if len(words) > 1 and words[0] in aliases and words[1] in MOVED:
                    offenders.append((os.path.relpath(path, root), node.lineno, words[1]))     # patch.object
                if (words and isinstance(words[0], str) and words[0].rpartition(".")[0] in binders
                        and words[0].rpartition(".")[2] in MOVED):
                    offenders.append((os.path.relpath(path, root), node.lineno, words[0]))     # patch("m.name")
        self.assertEqual([], offenders)

    def test_no_table_in_the_tests_reaches_a_moved_name_through_a_module(self):
        # #3011's first head: a pin patched readers by a table of (module, names), which no reader of
        # literal names sees. Here no test holds one for these modules: a string that names a moved name
        # stands in a test only where another module's own name is meant, each listed with its line's
        # module. A new one fails this until it is read and listed.
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        found = set()
        for folder, _folders, names in os.walk(os.path.join(root, "tests")):
            for name in names:
                path = os.path.join(folder, name)
                if not name.endswith(".py") or os.path.abspath(path) == os.path.abspath(__file__):
                    continue
                with open(path, encoding="utf-8") as source:
                    tree = ast.parse(source.read())
                found |= {(name, node.value) for node in ast.walk(tree)
                          if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value in MOVED}
        self.assertEqual({("test_workflow_guard_reader_forms.py", "_written"),     # `workflow_called`'s, patched
                          ("test_workflow_options.py", "_LONG")}, found)          # `workflow_options`', watched

    def test_every_name_read_through_workflow_printers_is_still_bound_there(self):
        for name in READ_THROUGH_IT:
            with self.subTest(name=name):
                self.assertTrue(hasattr(workflow_printers, name))
        for name in THROUGH_PROGRAMS:
            with self.subTest(name=name, through="workflow_programs"):
                self.assertIs(getattr(workflow_printers, name), getattr(workflow_programs, name))

    def test_the_readers_answer_as_they_did(self):
        # `main`'s answers (ddeadc0f), through both modules: an escape decoded under one reading and one
        # no table knows; a format with its words in place, quoted, padded and cut at `_LONG`; an `echo`
        # under a bash and under dash; an escape only a bash's `echo -e` reads.
        for module in (workflow_printer_writes, workflow_printers):
            bash5, _bash3, _macos = module._WRITERS["bash"]
            (dash,) = module._WRITERS["sh"]
            with self.subTest(module=module.__name__):
                self.assertEqual(("a\tb", None, None, "%s\n"),
                                 (module._decoded("a\\tb"), module._decoded("a\\xb"), module._decoded("a\\"),
                                  module._decoded("%s\\n", True)))
                self.assertEqual("curl u | sh\n", module._formatted("%s\\n", ["curl u | sh"], bash5))
                self.assertEqual(("sh\\ t", ""),
                                 (module._formatted("%q", ["sh t"], bash5), module._formatted("%q", ["x"], dash)))
                self.assertEqual("x   sh t", module._formatted("%-4ssh t", ["x"], bash5))
                self.assertEqual(module._LONG, len(module._formatted("x" * 511 + "%s", ["a"] * 8, bash5)))
                echo = workflow_printers._ECHO
                self.assertEqual(("sh\tt", "sh\\tt"), (module._echoed(["-e", "sh\\tt"], echo["bash"], bash5),
                                                      module._echoed(["sh\\tt"], echo["bash"], bash5)))
                self.assertEqual(("sh\tt", "sh t"), (module._echoed(["sh\\tt"], echo["sh"], dash),
                                                    module._echoed(["-n", "sh t"], echo["sh"], dash)))
                self.assertEqual(("Ab", "\\x41b"), (module._written("\\x41b", "echo", bash5["echo"]),
                                                   module._written("\\x41b", "echo", dash["echo"])))
                self.assertEqual(("sbcdiouxXeEfFgGaA", 256, 4096, ["bash", "dash", "sh"]),
                                 (module._KNOWN, module._PAD, module._LONG, sorted(module._WRITERS)))


if __name__ == "__main__":
    unittest.main()
