"""`scripts/workflow_valued.py`: the value table's reading half split out of `workflow_values`
byte for byte. Pins the compatibility bindings -- every name values imports back is the SAME
object, so no caller that reads `workflow_values.valued` moved -- and that the new module sits
below values (imports nothing from it), as `shell_command` and `shell_split` do below the reader."""
import ast
import os
import unittest

import shell_reader
import workflow_valued
import workflow_values

MOVED = ("_CANDIDATES", "_ELEMENT", "_GLOB", "_LONGEST", "_REFERENCES", "_TAIL", "_VALUE", "_as_word",
         "_deduped", "_element", "_glued", "_held", "_joined", "_lists", "_unknown", "valued",
         "valued_argvs")


class TestValuesBindsEveryMovedName(unittest.TestCase):

    def test_each_name_is_the_same_object_in_both_modules(self):
        for name in MOVED:
            with self.subTest(name=name):
                self.assertIs(getattr(workflow_values, name), getattr(workflow_valued, name))

    def test_the_reading_half_imports_nothing_from_values_or_above(self):
        tree = ast.parse(open(workflow_valued.__file__, encoding="utf-8").read())
        imported = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        imported |= {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
                     for alias in node.names}
        self.assertFalse(imported & {"workflow_values", "workflow_uses", "workflow_called",
                                     "workflow_annotate", "workflow_guard"}, imported)
        self.assertEqual(os.path.basename(workflow_valued.__file__), "workflow_valued.py")

    def test_a_word_resolves_as_values_always_resolved_it(self):
        table = workflow_values.Values()
        for statement in shell_reader.statements("T=cuda_1; T=$T.run\n"):
            workflow_values.record(table, statement.stages[0], True)
        self.assertEqual(["cuda_1.run"], workflow_valued.valued("$T", table))
        (argv,) = workflow_valued.valued_argvs(["sh", "$T"], table)
        self.assertEqual(["sh", "cuda_1.run"], [str(word) for word in argv])


if __name__ == "__main__":
    unittest.main()
