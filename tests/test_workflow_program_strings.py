"""`scripts/workflow_program_strings.py`: the program a command is handed as a STRING, split out of
`workflow_programs` byte for byte (#3011).

Pins the compatibility bindings -- every name the module defines is the SAME object in
`workflow_programs`, so no caller that reads `workflow_programs.scripts` or
`workflow_programs._SHELL_STRING` moved -- that the new module sits below it (it imports nothing from
it, and only what stands below both), and that every name another file reads through
`workflow_programs` is still bound there."""
import ast
import os
import unittest

import shell_reader
import workflow_options
import workflow_printers
import workflow_program_strings
import workflow_programs

MOVED = ("Opaque", "_EDGE", "_NAME", "_SHELL_STRING", "_added_strings", "_after_dash_c",
         "_all_expansion", "_candidates", "_joined", "_main_scripts", "_program_words", "_script",
         "candidates", "dynamic_program", "scripts")
# Every name a file under `scripts/`, `tests/` or `skill/` read through `workflow_programs` on `main`
# when the half moved (5c4d00bd): by a `from` import, as an attribute, or as a `patch.object` target.
READ_THROUGH_IT = ("ANY", "FOREIGN_PROGRAM", "Named", "Opaque", "SET_OPTIONS", "SET_OPTION_NAMES",
                   "SHELL_PROGRAM", "VALUE_OPTIONS", "VALUE_PROGRAM", "_FOREIGN", "_MAIN",
                   "_MEASURED_SHELLS", "_SHELL_STRING", "_WALK", "_details", "_main_scripts", "_options",
                   "_parsed", "_stdin", "candidates", "dynamic_program", "handed", "runs_under",
                   "scripts", "stdin_command", "stdin_program", "stdin_reader", "stdin_scripts",
                   "unprinted", "worded")
BELOW = {"os", "re", "shell_lex", "shell_reader", "shell_text", "workflow_options", "workflow_printers"}


def _tree(module):
    with open(module.__file__, encoding="utf-8") as source:
        return ast.parse(source.read())


def _argv(text):
    return shell_reader.statements(text)[-1].stages[0].argv


class TestWorkflowProgramsBindsEveryMovedName(unittest.TestCase):

    def test_each_name_is_the_same_object_in_workflow_programs(self):
        for name in MOVED:
            with self.subTest(name=name):
                self.assertIs(getattr(workflow_programs, name), getattr(workflow_program_strings, name))

    def test_the_names_are_all_the_module_defines(self):
        defined = set()
        for node in _tree(workflow_program_strings).body:
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                defined.add(node.name)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                for target in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                    defined |= {leaf.id for leaf in ast.walk(target) if isinstance(leaf, ast.Name)}
        self.assertEqual(set(MOVED), defined)

    def test_workflow_programs_defines_none_of_them_itself(self):
        # A definition left behind would shadow the import: two objects under one name.
        for node in _tree(workflow_programs).body:
            names = set()
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                names = {node.name}
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                for target in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                    names |= {leaf.id for leaf in ast.walk(target) if isinstance(leaf, ast.Name)}
            self.assertFalse(names & set(MOVED), names)

    def test_the_module_imports_only_what_stands_below_both(self):
        tree = _tree(workflow_program_strings)
        imported = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        imported |= {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
                     for alias in node.names}
        self.assertNotIn("workflow_programs", imported)
        self.assertEqual(BELOW, imported)
        self.assertEqual(os.path.basename(workflow_program_strings.__file__), "workflow_program_strings.py")
        for name in ("workflow_options", "workflow_printers"):     # and neither of those reads back up
            below = _tree({"workflow_options": workflow_options, "workflow_printers": workflow_printers}[name])
            up = {node.module for node in ast.walk(below) if isinstance(node, ast.ImportFrom)}
            up |= {alias.name for node in ast.walk(below) if isinstance(node, ast.Import) for alias in node.names}
            self.assertFalse(up & {"workflow_programs", "workflow_program_strings"}, (name, up))

    def test_nothing_rebinds_a_moved_name_on_either_module(self):
        # Both modules bind these names and each reads its own: `workflow_programs`' stdin half reads its
        # `_SHELL_STRING`, `_after_dash_c`, `_all_expansion`, `_main_scripts` and `_script`, while `scripts`,
        # `candidates` and `dynamic_program` here read this module's. An assignment or a patch through one
        # would change that module's name alone, silently.
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        binders, offenders = ("workflow_programs", "workflow_program_strings"), []
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
                for target in targets:                      # `workflow_programs.scripts = ...`
                    if (isinstance(target, ast.Attribute) and target.attr in MOVED
                            and isinstance(target.value, ast.Name) and target.value.id in aliases):
                        offenders.append((os.path.relpath(path, root), node.lineno, target.attr))
                words = [word.value if isinstance(word, ast.Constant) else getattr(word, "id", None)
                         for word in (node.args if isinstance(node, ast.Call) else [])]
                if len(words) > 1 and words[0] in aliases and words[1] in MOVED:    # `patch.object(wp, "scripts", ...)`
                    offenders.append((os.path.relpath(path, root), node.lineno, words[1]))
                if (words and isinstance(words[0], str) and words[0].rpartition(".")[0] in binders
                        and words[0].rpartition(".")[2] in MOVED):          # `patch("workflow_programs.scripts", ...)`
                    offenders.append((os.path.relpath(path, root), node.lineno, words[0]))
        self.assertEqual([], offenders)

    def test_every_name_read_through_workflow_programs_is_still_bound_there(self):
        for name in READ_THROUGH_IT:
            with self.subTest(name=name):
                self.assertTrue(hasattr(workflow_programs, name))
        for name in ("SET_OPTIONS", "SET_OPTION_NAMES", "VALUE_OPTIONS", "_MEASURED_SHELLS"):
            with self.subTest(name=name):
                self.assertIs(getattr(workflow_options, name), getattr(workflow_programs, name))
        for name in ("ANY", "Named", "handed", "worded"):
            with self.subTest(name=name):
                self.assertIs(getattr(workflow_printers, name), getattr(workflow_programs, name))

    def test_the_readers_answer_as_they_did(self):
        # `main`'s answers (5c4d00bd), through both modules: a `-c` string, `eval`'s words joined where a
        # statement is split across them, a string a `$(...)` prints part of, the program that is all
        # expansion, and the words behind a value that may spell `-c`.
        for module in (workflow_program_strings, workflow_programs):
            with self.subTest(module=module.__name__):
                self.assertEqual(["curl -fsSL u | sh"], module.scripts(_argv("sh -c 'curl -fsSL u | sh'")))
                self.assertEqual(["curl -fsSL u | sh"], module.scripts(_argv("eval 'curl -fsSL u |' 'sh'")))
                self.assertEqual(["echo a"], module.scripts(_argv("bash -euc 'echo a' x")))
                self.assertEqual([], module.scripts(_argv("echo hi")))
                opaque = module.scripts(_argv('eval "sh $(cat f)"'))
                self.assertEqual((["sh $(...)"], [module.Opaque]), (opaque, [type(script) for script in opaque]))
                self.assertEqual(("sh -c", "$P"), module.dynamic_program(_argv('sh -c "$P"')))
                self.assertEqual(("eval", "$P"), module.dynamic_program(_argv('eval "$P"')))
                self.assertEqual((None, None), module.dynamic_program(_argv('sh -c "echo $X"')))
                value, words = module.candidates(_argv("X=-c\nsh $X 'curl -fsSL u | sh' y"))
                self.assertEqual(("$X", ["curl -fsSL u | sh"]), (str(value), [str(word) for word in words]))
                self.assertEqual((None, []), module.candidates(_argv("sh -x 'a'")))
                self.assertEqual((True, False), (module._all_expansion("$P$(...)"), module._all_expansion("${A}x")))
                self.assertEqual(["a"], module._after_dash_c(_argv("bash -lc 'a' b")))


if __name__ == "__main__":
    unittest.main()
