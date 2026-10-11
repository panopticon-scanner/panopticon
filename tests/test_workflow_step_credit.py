"""The branch and step-credit layer split from workflow_forms byte for byte.

Pins the compatibility bindings and the one-way dependency: every moved name
is the same object through workflow_forms, while the new leaf imports nothing
from that facade.
"""
import ast
import os
import unittest

import workflow_forms
import workflow_guard
import workflow_step_credit


MOVED = ("_BRANCH_ALTERNATE", "_BRANCH_CLOSE", "_BRANCH_OPEN", "_SETTERS",
         "_arm", "_as_set", "_errexit_states", "regions", "step_credit")


def _tree():
    with open(workflow_step_credit.__file__, encoding="utf-8") as source:
        return ast.parse(source.read())


class TestTheFormsFacadeBindsEveryMovedName(unittest.TestCase):

    def test_each_name_is_the_same_object_in_both_modules(self):
        for name in MOVED:
            with self.subTest(name=name):
                self.assertIs(getattr(workflow_forms, name),
                              getattr(workflow_step_credit, name))

    def test_the_names_are_all_the_module_defines(self):
        defined = set()
        for node in _tree().body:
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                defined.add(node.name)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                defined |= {target.id for target in targets if isinstance(target, ast.Name)}
        self.assertEqual(set(MOVED), defined)

    def test_the_new_layer_imports_nothing_from_the_forms_facade(self):
        tree = _tree()
        imported = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        imported |= {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
                     for alias in node.names}
        self.assertNotIn("workflow_forms", imported, imported)
        self.assertEqual("workflow_step_credit.py",
                         os.path.basename(workflow_step_credit.__file__))

    def test_the_guard_answer_stays_the_same_through_the_facade(self):
        digest = "a" * 64
        script = ("curl -fsSLo /tmp/tool https://example.test/tool\nset +e\n"
                  f'echo "{digest}  /tmp/tool" | sha256sum -c -\n'
                  "chmod +x /tmp/tool && /tmp/tool\n")
        found = workflow_guard.job_defects([("step", script)])
        self.assertEqual(1, len(found), found)
        self.assertIn("runs after a `set +e`", found[0][1])
