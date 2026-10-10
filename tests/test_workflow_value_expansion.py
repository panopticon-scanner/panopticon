"""`workflow_value_expansion`: the bounded value readers split out of `workflow_values` byte for byte.

Pins the compatibility surface -- every moved name is the SAME object through
the old module and through the callers that bind one directly -- and the
one-way layer: the expansion leaf imports none of the assignment or use
modules above it.
"""
import ast
import os
import unittest

import workflow_annotate
import workflow_called
import workflow_uses
import workflow_value_expansion as expansion
import workflow_values


MOVED = ("PAST", "_CANDIDATES", "_ELEMENT", "_GLOB", "_LONGEST", "_PRODUCT",
         "_REFERENCES", "_TAIL", "_VALUE", "_as_word", "_capped", "_deduped",
         "_element", "_glued", "_held", "_joined", "_lists", "_unknown",
         "valued", "valued_argvs")


def _tree():
    with open(expansion.__file__, encoding="utf-8") as source:
        return ast.parse(source.read())


class TestTheValueLayerBindsEveryMovedName(unittest.TestCase):

    def test_each_name_is_the_same_object_through_the_compatibility_module(self):
        for name in MOVED:
            with self.subTest(name=name):
                self.assertIs(getattr(workflow_values, name), getattr(expansion, name))

    def test_each_direct_caller_keeps_the_same_object(self):
        bindings = ((workflow_uses, ("PAST", "_as_word", "valued", "valued_argvs")),
                    (workflow_called, ("PAST", "_CANDIDATES")),
                    (workflow_annotate, ("valued",)))
        for module, names in bindings:
            for name in names:
                with self.subTest(module=module.__name__, name=name):
                    self.assertIs(getattr(module, name), getattr(expansion, name))

    def test_the_names_are_all_the_new_module_defines(self):
        defined = set()
        for node in _tree().body:
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                defined.add(node.name)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                defined |= {target.id for target in targets}
        self.assertEqual(set(MOVED), defined)

    def test_the_module_imports_only_the_layers_below_it(self):
        tree = _tree()
        imported = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        imported |= {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
                     for alias in node.names}
        self.assertEqual({"itertools", "re", "shell_reader", "workflow_operands"}, imported)
        self.assertEqual("workflow_value_expansion.py", os.path.basename(expansion.__file__))

    def test_nothing_rebinds_a_moved_name_on_a_compatibility_module(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        binders = ("workflow_values", "workflow_uses", "workflow_called", "workflow_annotate")
        offenders = []
        paths = sorted(os.path.join(folder, name) for top in ("scripts", "tests")
                       for folder, _folders, names in os.walk(os.path.join(root, top))
                       for name in names if name.endswith(".py"))
        self.assertGreater(len(paths), 100)
        for path in paths:
            with open(path, encoding="utf-8") as source:
                tree = ast.parse(source.read())
            for node in ast.walk(tree):
                targets = (node.targets if isinstance(node, ast.Assign) else
                           [node.target] if isinstance(node, (ast.AugAssign, ast.AnnAssign)) else [])
                for target in targets:
                    if (isinstance(target, ast.Attribute) and target.attr in MOVED
                            and isinstance(target.value, ast.Name) and target.value.id in binders):
                        offenders.append((os.path.relpath(path, root), node.lineno, target.attr))
                words = [word.value if isinstance(word, ast.Constant) else getattr(word, "id", None)
                         for word in (node.args if isinstance(node, ast.Call) else [])]
                if len(words) > 1 and words[0] in binders and words[1] in MOVED:
                    offenders.append((os.path.relpath(path, root), node.lineno, words[1]))
                if (words and isinstance(words[0], str)
                        and words[0].rpartition(".")[0] in binders
                        and words[0].rpartition(".")[2] in MOVED):
                    offenders.append((os.path.relpath(path, root), node.lineno, words[0]))
        self.assertEqual([], offenders)
