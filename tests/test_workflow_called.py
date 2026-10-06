"""`scripts/workflow_called.py`: what a called function leaves in the caller's value table
(#2664 fix round, #2785). Pins the one-way layering -- the module imports the value table and
the reader, never the uses module or the guard -- and the helper's own readings."""
import ast
import os
import unittest

import shell_reader
import workflow_called
from workflow_values import Values


def body_of(script):
    stmts = shell_reader.statements(script)
    return stmts, [True] * len(stmts)


class TestTheModuleSitsBelowTheUsesModule(unittest.TestCase):

    def test_it_imports_nothing_from_the_uses_module_or_the_guard(self):
        tree = ast.parse(open(workflow_called.__file__, encoding="utf-8").read())
        imported = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        imported |= {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
                     for alias in node.names}
        self.assertFalse(imported & {"workflow_uses", "workflow_guard", "workflow_forms"}, imported)
        self.assertEqual(os.path.basename(workflow_called.__file__), "workflow_called.py")


class TestWhatACallCarriesOut(unittest.TestCase):
    """`_carry`, the body walk behind `record_called`, on a body read from its header."""

    def carried(self, script, certain=True, start=None):
        table = Values({"T": ["old"]}) if start is None else start
        stmts, sure = body_of(script)
        workflow_called._carry(table, stmts, sure, certain)
        return table

    def test_a_sure_call_replaces_and_an_unsure_one_adds(self):
        self.assertEqual({"T": ["/tmp/p"]}, self.carried("f() { T=/tmp/p; }\n").scalars)
        self.assertEqual({"T": ["old", "/tmp/p"]},
                         self.carried("f() { T=/tmp/p; }\n", certain=False).scalars)

    def test_a_local_dies_with_the_call_where_declare_g_and_export_do_not(self):
        self.assertEqual({"T": ["old"]}, self.carried("f() { local T=x; }\n").scalars)
        self.assertEqual({"T": ["old"]}, self.carried("f() { local T; T=x; }\n").scalars)
        self.assertEqual({"T": ["old"]}, self.carried("f() { declare T=x; }\n").scalars)
        self.assertEqual({"T": ["x"]}, self.carried("f() { declare -g T=x; }\n").scalars)
        self.assertEqual({"T": ["x"]}, self.carried("f() { export T=x; }\n").scalars)

    def test_an_unset_and_a_read_in_the_body_reach_the_caller(self):
        self.assertEqual({}, self.carried("f() { unset T; }\n").scalars)
        self.assertEqual({"T": ["$T"]}, self.carried("f() { read T; }\n").scalars)

    def test_a_subshell_or_compound_body_carries_nothing(self):
        for script in ("f() ( T=x )\n", "f() ( T=x; )\n", "f() if c; then T=x; fi\n"):
            with self.subTest(script=script):
                self.assertEqual({"T": ["old"]}, self.carried(script).scalars)

    def test_the_brace_on_the_next_line_is_a_body_too(self):
        self.assertEqual({"T": ["x"]}, self.carried("f()\n{\nT=x\n}\n").scalars)
        self.assertEqual({"T": ["x"]}, self.carried("g ( )\n{\nT=x\n}\n").scalars)


if __name__ == "__main__":
    unittest.main()
