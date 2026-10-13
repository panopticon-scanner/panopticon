"""`scripts/workflow_defect.py`: why one fetch is a defect, split out of `workflow_guard` byte for byte
(for #3050, #3051 and #2433).

Pins the compatibility bindings -- every name the module defines is the SAME object in
`workflow_guard`, so no caller that reads `workflow_guard._binds` or `workflow_guard._UNSHARED_IF`
moved -- that the new module sits below it (it imports nothing from it, and nothing it imports reads
either back), that no file rebinds a moved name through either module or holds one in a string, and
that every name another file reads through `workflow_guard` is still bound there. No swap a test makes
on `workflow_guard` moved away from its lookups: the tests patch `_job_defects`, `read`, `_defects` and
`statements` there and assign its `folds`, and this module binds none of the five, so each is still
looked up in `workflow_guard`'s globals alone, where `_defects` and `_job_defects` also read `_defect`
and `_SOFT_STEP` through its own bindings of them."""
import ast
import os
import unittest

import shell_reader
import workflow_defect
import workflow_guard

MOVED = ("_SOFT_STEP", "_UNSHARED_BRANCH", "_UNSHARED_IF", "_binds", "_defect", "_runs_after_failure",
         "_unshared")
# The seven imports that left `workflow_guard` with them: only the moved code read them there.
LEFT = ("_check_at_use", "_clears_nested", "_describe", "_remedy", "at_directory", "names_file",
        "streams_to_executor")
# Every name a file under `scripts/`, `tests/` or `skill/` read through `workflow_guard` on `main` when
# the judgment moved (2dcb42b1), by a `from` import or as an attribute: only tests do. None holds a
# moved or a left name in a string, so no table patches or watches one (read from every file's AST:
# the lesson of #3011's first head).
READ_THROUGH_IT = ("CHECKSUM_TOOLS", "EXECUTORS", "Idle", "Step", "UNNAMED", "_UNSHARED_BRANCH",
                   "_UNSHARED_IF", "_binds", "_checks", "_defects", "_fetch_records", "_job_defects",
                   "_uses", "fetch_exec_defect", "fetch_exec_defects", "fetches", "folds", "job_defects",
                   "main", "parse_fetch", "read", "run_jobs", "run_steps", "shell_reader", "statements",
                   "streamed_fetch")
# What the tests swap on `workflow_guard`: patched, or assigned (`folds`, by
# `tests/test_workflow_in_front_of_a_command.py`).
SWAPPED = ("_defects", "_job_defects", "folds", "read", "statements")
BELOW = {"os", "re", "shell_reader", "workflow_checks", "workflow_fetch", "workflow_forms",
         "workflow_programs", "workflow_uses"}
BINDERS = ("workflow_defect", "workflow_guard")
# `main`'s answers (2dcb42b1). A statement's condition is its step's `if:` and the `if`/`while` branch
# it sits in; the check is statement 0, the use statement 1.
AFTER_FAILURE = ((None, False), (("always()", None), True), ((" Failure( ) ", None), True),
                 (("!cancelled() && x", None), True), (("success()", None), False),
                 (("github.ref == 'main'", None), False), ((None, "b"), False))
BINDS = (({}, True), ({0: ("x", None), 1: ("x", None)}, True), ({0: ("x", None)}, False),
         ({1: ("always()", None)}, False), ({0: ("always()", None), 1: ("always()", None)}, True),
         ({0: (None, "b"), 1: (None, "b")}, True), ({0: (None, "b")}, False))
UNSHARED = (({0: (None, "b")}, "_UNSHARED_BRANCH"), ({0: ("x", None)}, "_UNSHARED_IF"),
            ({0: ("x", "b"), 1: ("y", "b")}, "_UNSHARED_IF"))


def _tree(module):
    with open(module.__file__, encoding="utf-8") as source:
        return ast.parse(source.read())


def _defined(tree):
    names = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            for target in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                names |= {leaf.id for leaf in ast.walk(target) if isinstance(leaf, ast.Name)}
    return names


def _imported(tree):
    return ({node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
            | {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names})


def _files(*tops):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    paths = sorted(os.path.join(folder, name) for top in tops
                   for folder, _folders, names in os.walk(os.path.join(root, top))
                   for name in names if name.endswith(".py")
                   and os.path.abspath(os.path.join(folder, name)) != os.path.abspath(__file__))
    for path in paths:
        with open(path, encoding="utf-8") as source:
            yield os.path.relpath(path, root), ast.parse(source.read())


def _rebinds(names):
    """Each assignment or patch of one of `names` through either module, by LITERAL name: by
    assignment, by `patch.object(module, "name", ...)` and by `patch("module.name", ...)`."""
    offenders = []
    for path, tree in _files("scripts", "tests"):
        aliases = {alias.asname or alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
                   for alias in node.names if alias.name in BINDERS}
        for node in ast.walk(tree):
            targets = (node.targets if isinstance(node, ast.Assign) else
                       [node.target] if isinstance(node, (ast.AugAssign, ast.AnnAssign)) else [])
            for target in targets:                          # `workflow_guard.folds = ...`
                if (isinstance(target, ast.Attribute) and target.attr in names
                        and isinstance(target.value, ast.Name) and target.value.id in aliases):
                    offenders.append((path, node.lineno, target.attr))
            words = [word.value if isinstance(word, ast.Constant) else getattr(word, "id", None)
                     for word in (node.args if isinstance(node, ast.Call) else [])]
            if len(words) > 1 and words[0] in aliases and words[1] in names:   # `patch.object(wg, "read", ...)`
                offenders.append((path, node.lineno, words[1]))
            if (words and isinstance(words[0], str) and words[0].rpartition(".")[0] in BINDERS
                    and words[0].rpartition(".")[2] in names):          # `patch("workflow_guard.read", ...)`
                offenders.append((path, node.lineno, words[0]))
    return offenders


class TestWorkflowGuardBindsEveryMovedName(unittest.TestCase):

    def test_each_name_is_the_same_object_in_workflow_guard(self):
        for name in MOVED:
            with self.subTest(name=name):
                self.assertIs(getattr(workflow_guard, name), getattr(workflow_defect, name))

    def test_the_names_are_all_the_module_defines(self):
        self.assertEqual(set(MOVED), _defined(_tree(workflow_defect)))

    def test_workflow_guard_defines_none_of_them_itself(self):
        # A definition left behind would shadow the import: two objects under one name.
        self.assertFalse(_defined(_tree(workflow_guard)) & set(MOVED))

    def test_the_module_imports_only_what_stands_below_both(self):
        self.assertEqual(BELOW, _imported(_tree(workflow_defect)))
        self.assertEqual(os.path.basename(workflow_defect.__file__), "workflow_defect.py")
        self.assertIn("workflow_defect", _imported(_tree(workflow_guard)))
        here = os.path.dirname(os.path.abspath(workflow_defect.__file__))
        for name in sorted(BELOW - {"os", "re"}):
            with self.subTest(below=name), open(os.path.join(here, name + ".py"), encoding="utf-8") as source:
                self.assertFalse(set(BINDERS) & _imported(ast.parse(source.read())))
        # and the reader reads nothing of the guard back up
        self.assertFalse({name for name in _imported(_tree(shell_reader)) if name.startswith("workflow_")})

    def test_the_swaps_the_tests_make_stay_where_the_lookups_are(self):
        # A swap reaches only the readers that look the name up in `workflow_guard`'s globals. This
        # module binds none of the five, by a definition or an import, and names none of them, or a
        # swap would stand where nobody reads it; each is still bound in `workflow_guard`.
        tree = _tree(workflow_defect)
        bound = _defined(tree) | {alias.asname or alias.name for node in ast.walk(tree)
                                  if isinstance(node, (ast.Import, ast.ImportFrom)) for alias in node.names}
        self.assertFalse(bound & set(SWAPPED))
        self.assertFalse({leaf.id for leaf in ast.walk(tree) if isinstance(leaf, ast.Name)} & set(SWAPPED))
        for name in SWAPPED:
            with self.subTest(name=name):
                self.assertTrue(hasattr(workflow_guard, name))

    def test_nothing_rebinds_a_moved_name_on_either_module(self):
        # Both modules bind these names and each reads its own: `_defects` and `_job_defects` read
        # `workflow_guard`'s `_defect` and `_SOFT_STEP`, while `_defect` here reads this module's
        # `_binds` and `_unshared`. An assignment or a patch through one would change that module's
        # name alone, silently. The same reading finds each of the five swaps the tests make, so its
        # silence on the moved names is theirs.
        self.assertEqual([], _rebinds(MOVED))
        self.assertEqual(set(SWAPPED), {word.rpartition(".")[2] for _path, _line, word in _rebinds(SWAPPED)})

    def test_no_test_holds_a_moved_name_in_a_string(self):
        # #3011's first head: a pin patched readers by a table of (module, names), which no reader of
        # literal names sees. No file under `scripts/` or `tests/` holds a moved name, or one that left
        # with them, as a string; the same reading finds the strings the swaps are made by.
        def strings(names):
            return {(path, node.value) for path, tree in _files("scripts", "tests") for node in ast.walk(tree)
                    if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value in names}
        self.assertEqual(set(), strings(MOVED + LEFT))
        self.assertLessEqual({"_defects", "_job_defects", "read", "statements"},
                             {value for _path, value in strings(SWAPPED)})

    def test_every_name_read_through_workflow_guard_is_still_bound_there(self):
        for name in READ_THROUGH_IT:
            with self.subTest(name=name):
                self.assertTrue(hasattr(workflow_guard, name))

    def test_the_judgment_answers_as_it_did(self):
        # `main`'s answers, through both modules: an `if:` that runs after a failed step, in any
        # spacing and case, and three that do not; a check that binds its use when both halves of
        # their conditions match and only then; and the half of the check's condition a use lacks.
        for module in (workflow_defect, workflow_guard):
            for when, answer in AFTER_FAILURE:
                with self.subTest(module=module.__name__, when=when):
                    self.assertIs(answer, module._runs_after_failure(when))
            for conditions, answer in BINDS:
                with self.subTest(module=module.__name__, binds=conditions):
                    self.assertIs(answer, module._binds(conditions, 0, 1))
            for conditions, name in UNSHARED:
                with self.subTest(module=module.__name__, unshared=conditions):
                    self.assertIs(getattr(module, name), module._unshared(conditions, 0, 1))


if __name__ == "__main__":
    unittest.main()
