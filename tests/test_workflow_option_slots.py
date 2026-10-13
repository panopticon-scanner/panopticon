"""`scripts/workflow_option_slots.py`: the words that may stand in a shell's option slot, split out of
`workflow_options` byte for byte (#2889).

Pins the compatibility bindings -- every name the module defines is the SAME object in
`workflow_options`, and the five `workflow_programs` re-exported before are the same object there
too, so no caller that reads `workflow_options._value` or `workflow_programs._before_operand` moved
-- that the new module sits below both (it imports the reader and nothing else), and that no file
rebinds a moved name through any of the three. No watcher of `tests/test_workflow_options.py` moved:
`WALK_ONLY` watches each of the walk's readers on the module that LOOKS IT UP, and the two that moved
(`_one_word`, `_literal`) are looked up by readers that stayed, in `workflow_options`' own globals;
`TABLES` wraps every binding of a table's object, and the three patterns `_one_word` reads are one
object under both modules' names. Both facts are held here, so a later move cannot break them
unseen.

#2889's rule then came to live here: three names of its own (`ADDED`), an import of the leaf that says
what is written in a word, and one answer that moved -- a tilde alone is a value (`ANSWERS`)."""
import ast
import os
import unittest

import shell_reader
import workflow_option_slots
import workflow_options
import workflow_programs

MOVED = ("_BARE", "_DEFAULT_PARAMETER", "_ONE_DEFAULT", "_ONE_PARAMETER", "_VALUE", "_before_operand",
         "_literal", "_may_spell_option", "_one_word", "_value")
# The five `workflow_programs` re-exported from `workflow_options` when the readers moved (13cdb9f7).
THROUGH_PROGRAMS = ("_BARE", "_VALUE", "_before_operand", "_may_spell_option", "_value")
PATTERNS = ("_DEFAULT_PARAMETER", "_ONE_DEFAULT", "_ONE_PARAMETER")
# #2889's own, defined here and bound in `workflow_options` as the moved names are.
ADDED = ("_TILDE", "_may_be_name", "_reopened")
BINDERS = ("workflow_option_slots", "workflow_options", "workflow_programs")
# `main`'s answers (13cdb9f7) for a word as the reader hands it on, the second word of each line:
# (`_value`, `_before_operand`, `_may_spell_option`, `_one_word`, `_literal`) -- but for the tilde's
# first, which #2889 turned: `HOME=-c; sh ~ 'P'` runs `P`.
ANSWERS = (
    ("sh -c P", (False, True, False, False, True)),
    ("sh +x P", (False, True, False, False, True)),
    ("sh -a.b P", (False, True, False, False, True)),
    ("sh pipefail", (False, True, False, False, True)),
    ("sh interactive-comments", (False, True, False, False, True)),
    ("sh ./x.sh", (False, False, False, False, True)),
    ("sh - P", (False, True, False, False, True)),
    ("sh $X P", (True, True, True, False, False)),
    ("sh ${X:--c} P", (True, True, True, False, False)),
    ("sh ${X}c", (True, True, True, False, False)),
    ("sh $X/x.sh", (False, True, True, False, False)),
    ("sh -$Y P", (False, True, True, False, False)),
    ("sh x$Y", (False, True, False, False, False)),
    ("sh $(echo -c) P", (True, True, True, False, False)),
    ("sh <(echo x)", (True, True, True, False, False)),
    ('sh "$X" P', (True, True, True, True, False)),
    ('sh "${X:-$Y}"', (True, True, True, True, False)),
    ('sh "$@" P', (True, True, True, False, False)),
    ('sh "${!X}"', (True, True, True, False, False)),
    ("sh ~ P", (True, False, False, False, False)),
    ("sh *.sh", (False, True, True, False, False)),
    ("sh -[c] P", (False, True, True, False, False)),
    ("sh $'\\q' P", (True, True, True, False, False)),
)


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


def _word(text):
    return shell_reader.statements(text)[-1].stages[0].argv[1]


class TestWorkflowOptionsBindsEveryMovedName(unittest.TestCase):

    def test_each_name_is_the_same_object_in_workflow_options(self):
        for name in MOVED:
            with self.subTest(name=name):
                self.assertIs(getattr(workflow_options, name), getattr(workflow_option_slots, name))

    def test_workflow_programs_still_binds_the_five_it_re_exported(self):
        for name in THROUGH_PROGRAMS:
            with self.subTest(name=name):
                self.assertIs(getattr(workflow_programs, name), getattr(workflow_option_slots, name))

    def test_the_names_are_all_the_module_defines(self):
        self.assertEqual(set(MOVED) | set(ADDED), _defined(_tree(workflow_option_slots)))
        for name in ADDED:
            with self.subTest(name=name):
                self.assertIs(getattr(workflow_options, name), getattr(workflow_option_slots, name))

    def test_workflow_options_defines_none_of_them_itself(self):
        # A definition left behind would shadow the import: two objects under one name.
        self.assertFalse(_defined(_tree(workflow_options)) & (set(MOVED) | set(ADDED)))
        self.assertFalse(_defined(_tree(workflow_programs)) & (set(MOVED) | set(ADDED)))

    def test_the_module_imports_the_reader_and_nothing_above_it(self):
        # ... and since #2889 the leaf that says what is written in a word, which stands below every reader
        self.assertEqual({"re", "shell_reader", "workflow_option_words"}, _imported(_tree(workflow_option_slots)))
        self.assertEqual(os.path.basename(workflow_option_slots.__file__), "workflow_option_slots.py")
        self.assertIn("workflow_option_slots", _imported(_tree(workflow_options)))
        # and the reader reads nothing of this lane back up
        self.assertFalse({name for name in _imported(_tree(shell_reader)) if name.startswith("workflow_")})

    def test_nothing_rebinds_a_moved_name_on_any_of_the_three(self):
        # Three modules bind these names and each reads its own: `_after_value` and the walks read
        # `workflow_options`' `_value`, `_literal` and `_one_word`, `_one_word` reads this module's
        # patterns. An assignment or a patch through one would change that module's name alone,
        # silently. This reads LITERAL names; the patches driven by a table are the next test's.
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        offenders = []
        paths = sorted(os.path.join(folder, name) for top in ("scripts", "tests")
                       for folder, _folders, names in os.walk(os.path.join(root, top))
                       for name in names if name.endswith(".py"))
        self.assertGreater(len(paths), 100)
        for path in paths:
            with open(path, encoding="utf-8") as source:
                tree = ast.parse(source.read())
            aliases = {alias.asname or alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
                       for alias in node.names if alias.name in BINDERS}
            for node in ast.walk(tree):
                targets = (node.targets if isinstance(node, ast.Assign) else
                           [node.target] if isinstance(node, (ast.AugAssign, ast.AnnAssign)) else [])
                for target in targets:                      # `workflow_options._value = ...`
                    if (isinstance(target, ast.Attribute) and target.attr in MOVED
                            and isinstance(target.value, ast.Name) and target.value.id in aliases):
                        offenders.append((os.path.relpath(path, root), node.lineno, target.attr))
                words = [word.value if isinstance(word, ast.Constant) else getattr(word, "id", None)
                         for word in (node.args if isinstance(node, ast.Call) else [])]
                if len(words) > 1 and words[0] in aliases and words[1] in MOVED:    # `patch.object(wo, "_value", ...)`
                    offenders.append((os.path.relpath(path, root), node.lineno, words[1]))
                if (words and isinstance(words[0], str) and words[0].rpartition(".")[0] in BINDERS
                        and words[0].rpartition(".")[2] in MOVED):          # `patch("workflow_options._value", ...)`
                    offenders.append((os.path.relpath(path, root), node.lineno, words[0]))
        self.assertEqual([], offenders)

    def test_the_walks_watch_tables_stand_where_the_lookups_are(self):
        # `tests/test_workflow_options.py` watches the walk's readers by a table, `WALK_ONLY`: each is
        # patched on the module that LOOKS IT UP, and must then be seen to run. `_one_word` and
        # `_literal` moved, their callers did not: `_run`, `_in_every_reading`, `_stdin_walk` and
        # `_value_after_dash_c` read both names in `workflow_options`' globals, so that row still
        # holds them -- and no reader that moved calls anything the table watches, or a watcher would
        # stand where nobody reads it. The walk's tables are watched by OBJECT, every binding of one
        # wrapped: the three patterns must be one object under both modules' names.
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_workflow_options.py")
        with open(path, encoding="utf-8") as source:
            tree = ast.parse(source.read())
        modules = {alias.asname or alias.name: alias.name for node in tree.body if isinstance(node, ast.Import)
                   for alias in node.names}

        def table(label):
            found = [node.value for node in ast.walk(tree) if isinstance(node, ast.Assign)
                     and any(isinstance(target, ast.Name) and target.id == label for target in node.targets)]
            self.assertEqual(1, len(found), label)
            return found[0]

        watched = {modules[row.elts[0].id]: {name.value for name in row.elts[1].elts} for row in table("WALK_ONLY").elts}
        self.assertNotIn("workflow_option_slots", watched)
        self.assertLessEqual({"_one_word", "_literal"}, watched["workflow_options"])
        callers = {node.name for node in _tree(workflow_options).body if isinstance(node, ast.FunctionDef)
                   and {"_one_word", "_literal"} & {leaf.id for leaf in ast.walk(node) if isinstance(leaf, ast.Name)}}
        self.assertEqual({"_run", "_in_every_reading", "_stdin_walk", "_value_after_dash_c"}, callers)
        every = set().union(*watched.values())
        for node in _tree(workflow_option_slots).body:
            if isinstance(node, ast.FunctionDef):
                with self.subTest(reader=node.name):
                    loaded = {leaf.id for leaf in ast.walk(node) if isinstance(leaf, ast.Name)}
                    self.assertFalse(loaded & every)
        tables = {name.value for name in table("TABLES").elts}
        self.assertEqual(set(PATTERNS), tables & set(MOVED))
        reads = {leaf.id for node in _tree(workflow_option_slots).body if isinstance(node, ast.FunctionDef)
                 and node.name == "_one_word" for leaf in ast.walk(node) if isinstance(leaf, ast.Name)}
        self.assertLessEqual(set(PATTERNS), reads)
        for name in PATTERNS:
            with self.subTest(pattern=name):
                self.assertIs(getattr(workflow_options, name), getattr(workflow_option_slots, name))

    def test_the_readers_answer_as_they_did(self):
        # `main`'s answers (13cdb9f7), through every module that binds a reader: an option word, a name,
        # a path, a `$` word with and without text of its own, a lifted substitution, a quoted expansion
        # that is one word and one that may be none, a tilde, a pattern, an ANSI-C word no text spells.
        for module in (workflow_option_slots, workflow_options):
            for text, answers in ANSWERS:
                with self.subTest(module=module.__name__, text=text):
                    word = _word(text)
                    self.assertEqual(answers, (module._value(word), module._before_operand(word),
                                               module._may_spell_option(word), module._one_word(word),
                                               module._literal(word)))
        for text, answers in ANSWERS:
            with self.subTest(module="workflow_programs", text=text):
                word = _word(text)
                self.assertEqual(answers[:3], (workflow_programs._value(word), workflow_programs._before_operand(word),
                                               workflow_programs._may_spell_option(word)))


if __name__ == "__main__":
    unittest.main()
