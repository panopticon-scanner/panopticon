"""#2425, #2489: the step's literal assignments and array literals as bounded value facts.

`workflow_uses.static_values` is the table a walk reads a `$T` or a
`"${a[@]}"` through: per name, the candidate texts the step's own
assignments leave (`T=cuda_1.run`, `p=./cuda_*.run`), and the words of an
array literal (`declare -a a=(sh tool)`). These are its unit pins -- what a
stage assigns, when a value is held and when it is emptied, how one word
resolves, how an argv is spliced -- and no guard-level row: the guard does
not read through the table yet.
"""
import unittest

import shell_reader
import workflow_uses as wu
from workflow_operands import _Reparsed


def statements(script):
    return list(shell_reader.statements(script))


def table(script, index=None):
    """The table `static_values` leaves at `index`, past the last statement by default."""
    stmts = statements(script)
    return wu.static_values(stmts, index if index is not None else len(stmts))


def only_stage(script):
    """The one stage of a script of one statement."""
    (statement,) = statements(script)
    (stage,) = statement.stages
    return stage


class TestWhatAStageAssigns(unittest.TestCase):
    """#2425: a statement that only assigns, and a declaration's operands."""

    def test_a_literal_assignment_records_its_text(self):
        rows = {
            "T=cuda_1.run": {"T": ["cuda_1.run"]},
            'T="cuda_1.run"': {"T": ["cuda_1.run"]},       # the quotes are gone
            "T='cuda_1.run'": {"T": ["cuda_1.run"]},
            "T=./cuda_1.run": {"T": ["./cuda_1.run"]},
            "export T=cuda_1.run": {"T": ["cuda_1.run"]},
            "declare T=cuda_1.run": {"T": ["cuda_1.run"]},
            "readonly T=cuda_1.run": {"T": ["cuda_1.run"]},
            "typeset T=cuda_1.run": {"T": ["cuda_1.run"]},
            "local T=cuda_1.run": {"T": ["cuda_1.run"]},
            # `command export` runs the builtin in the step's shell, as `command cd` does.
            "command export T=cuda_1.run": {"T": ["cuda_1.run"]},
            "p=./cuda_*.run": {"p": ["./cuda_*.run"]},     # bash globs no assignment
        }
        for script, expected in rows.items():
            with self.subTest(script=script):
                values = table(script)
                self.assertEqual(expected, values.scalars)
                self.assertEqual({}, values.arrays)

    def test_nothing_is_recorded_where_bash_sets_nothing_in_the_shell(self):
        # A bare `export T` keeps T as it was; a prefix assignment is the
        # command's environment, made after bash expanded the command's words;
        # `env T=x` is a command that sets T in its own environment only, and
        # `sudo export T=x` runs no builtin of the step's shell.
        for script in ("export T", 'T=cuda_1.run sh "$T"', "env T=cuda_1.run",
                       "sudo export T=cuda_1.run", "local T"):
            with self.subTest(script=script):
                values = table(script)
                self.assertEqual(({}, {}), (values.scalars, values.arrays))

    def test_an_append_extends_and_a_reference_resolves_as_assigned(self):
        rows = {
            "T=a; T+=b": ["ab"],
            # The known suffix of a value the guard cannot see: a price.
            "T+=b": ["b"],
            "U=cuda_1.run; T=$U": ["cuda_1.run"],
            # `_cleared` leaves an assignment's value to `record`, which reads it.
            "T=cuda_1; T=$T.run": ["cuda_1.run"],
            'T="$PWD/cuda_1.run"': ["$PWD/cuda_1.run"],
        }
        for script, expected in rows.items():
            with self.subTest(script=script):
                self.assertEqual(expected, table(script).scalars["T"])

    def test_a_substitution_in_a_value_stays_its_marker(self):
        (candidate,) = table("T=$(cmd)").scalars["T"]
        self.assertTrue(shell_reader.has_substitution(candidate))

    def test_assigned_names_each_value_with_its_append_flag(self):
        rows = {
            "T=x": ({"T": (False, "x")}, {}),
            "T+=x": ({"T": (True, "x")}, {}),
            "a+=(c)": ({}, {"a": (True, ["c"])}),
            'T=x sh "$T"': ({}, {}),
        }
        for script, expected in rows.items():
            with self.subTest(script=script):
                self.assertEqual(expected, wu.assigned(only_stage(script)))


class TestWhenAValueIsHeldAndEmptied(unittest.TestCase):
    """#2425: a value is held wherever a statement assigns it, and replaced or
    emptied only where `_certainty` says the step's shell surely runs it."""

    def test_a_certain_assignment_replaces_and_an_uncertain_one_adds(self):
        rows = {
            "T=a; T=b": ["b"],
            "T=a; false && T=b": ["a", "b"],
            "T=a; if false; then T=b; fi": ["a", "b"],
            "T=a; T=b &": ["a", "b"],
            # Bash keeps `a`, as the group is a subshell; `_certainty` reads the
            # group as uncertain, and the table holds both: the fail-closed one.
            "T=a; ( T=b )": ["a", "b"],
        }
        for script, expected in rows.items():
            with self.subTest(script=script):
                self.assertEqual({"T": expected}, table(script).scalars)

    def test_a_certain_unset_read_or_bare_local_empties_the_name(self):
        for script in ("T=a; unset T", "T=a; read -r T", "T=a; local T",
                       "arr=(a b); unset arr", "arr=(a b); read -ra arr"):
            with self.subTest(script=script):
                values = table(script)
                self.assertEqual(({}, {}), (values.scalars, values.arrays))

    def test_an_uncertain_unset_empties_nothing(self):
        self.assertEqual({"T": ["a"]}, table("T=a; false && unset T").scalars)

    def test_a_for_header_leaves_the_value_as_measured(self):
        # Measured: `_cleared` drops a name for an assignment, a declaration,
        # `read` and `unset`, never for a `for` header (`_bound_after` rebinds
        # a glob there), so the table keeps `a` where bash ends the loop at `y`.
        stmts = statements("T=a; for T in x y; do :; done")
        self.assertEqual({"T": ["a"]}, wu.static_values(stmts, 2).scalars)
        self.assertEqual({"T": ["a"]}, wu.static_values(stmts, len(stmts)).scalars)

    def test_a_function_body_and_a_pipeline_record_nothing(self):
        # A call's own assignments are not read (a price); a pipeline's
        # stages run in subshells, where bash keeps no assignment.
        self.assertEqual({"T": ["a"]}, table("f() { T=b; }; T=a; f").scalars)
        self.assertEqual({}, table("T=a | cat; echo").scalars)

    def test_a_name_keeps_its_last_eight_candidates(self):
        script = "T=0" + "".join("; false && T=%d" % number for number in range(1, 10))
        self.assertEqual([str(number) for number in range(2, 10)], table(script).scalars["T"])


class TestHowAWordResolves(unittest.TestCase):
    """#2425 and the #2581 rows: a whole or embedded reference, and a default."""

    def test_a_reference_stands_for_its_candidates(self):
        values = table("T=cuda_1.run; X=*")
        rows = {"$T": ["cuda_1.run"], "${T}": ["cuda_1.run"], "x/$T": ["x/cuda_1.run"],
                "./cuda_$X.run": ["./cuda_*.run"]}
        for word, expected in rows.items():
            with self.subTest(word=word):
                self.assertEqual(expected, wu.valued(word, values))

    def test_a_default_stands_where_the_name_is_unassigned(self):
        unassigned, assigned = wu.Values(), table("X=1")
        rows = {"${X:-*}": (["*"], ["1"]), "${X-*}": (["*"], ["1"]),
                "${X:=*}": (["*"], ["1"]), "${X=*}": (["*"], ["1"]),
                "./cuda_${X:-*}.run": (["./cuda_*.run"], ["./cuda_1.run"])}
        for word, (bare, held) in rows.items():
            with self.subTest(word=word):
                self.assertEqual(bare, wu.valued(word, unassigned))
                self.assertEqual(held, wu.valued(word, assigned))

    def test_a_null_value_takes_a_colon_default_only(self):
        values = table("X=")
        rows = {"${X:-d}": ["d"], "${X:=d}": ["d"], "${X-d}": [""], "${X=d}": [""]}
        for word, expected in rows.items():
            with self.subTest(word=word):
                self.assertEqual(expected, wu.valued(word, values))

    def test_every_other_expansion_form_stays_as_written(self):
        values = table("T=x; X=1")
        for word in ("${X:+y}", "${T#x}", "${T%x}", "${T//a/b}", "${T:0:3}", "${#T}", "${!T}"):
            with self.subTest(word=word):
                self.assertEqual([], wu.valued(word, values))

    def test_a_word_with_nothing_held_resolves_to_nothing(self):
        values = table("T=x")
        for word in ("cuda_1.run", "$UNSET", "${UNSET}", "$1", "$@"):
            with self.subTest(word=word):
                self.assertEqual([], wu.valued(word, values))

    def test_the_product_of_candidates_is_ordered_and_capped(self):
        two = table("T=a; false && T=b")
        self.assertEqual(["aa", "ab", "ba", "bb"], wu.valued("$T$T", two))
        three = table("; ".join("%s=1; false && %s=2; false && %s=3" % (name, name, name)
                                for name in "ABC"))
        self.assertEqual(["111", "112", "113", "121", "122", "123", "131", "132"],
                         wu.valued("$A$B$C", three))

    def test_nothing_inside_a_lifted_substitution_is_matched(self):
        stmts = statements('T=cuda_1.run\nsh "$(printf %s "$T")"')
        word = stmts[1].stages[0].argv[1]
        self.assertTrue(shell_reader.is_marker(word))
        self.assertNotIn("$", word)
        self.assertEqual([], wu.valued(word, wu.static_values(stmts, 1)))

    def test_a_value_keeps_its_substitution_through_a_use(self):
        (text,) = wu.valued("$T", table("T=$(pwd)/cuda_1.run"))
        self.assertTrue(shell_reader.has_substitution(text))
        self.assertEqual("$(...)/cuda_1.run", shell_reader.readable(text))

    def test_a_value_that_doubles_itself_stays_bounded(self):
        values = table("T=12345678\n" + "T=$T$T\n" * 64)
        self.assertTrue(values.scalars["T"])
        self.assertTrue(all(len(text) <= wu._LONGEST for text in values.scalars["T"]))
        self.assertEqual([], wu.valued("$T" * 5000, table("T=x")))


class TestAnArrayLiteral(unittest.TestCase):
    """#2489: an array literal's words, an element, and the splice of all of them."""

    def test_a_literal_records_its_words(self):
        rows = {"arr=(sh tool)": "arr", "declare -a arr=(sh tool)": "arr",
                "export arr=(sh tool)": "arr", "local -a a=(sh tool)": "a",
                "typeset -a arr=(sh tool)": "arr", "readonly -a arr=(sh tool)": "arr"}
        for script, name in rows.items():
            with self.subTest(script=script):
                values = table(script)
                self.assertEqual({name: ["sh", "tool"]}, values.arrays)
                self.assertEqual({}, values.scalars)

    def test_a_literal_behind_a_function_header_is_read_unfolded(self):
        # The reader folds a literal into its word behind a declaration only,
        # and here a function header stands in front of the `local` (#2348).
        stage = statements('f() { local -a a=(sh tool); "${a[@]}"; }')[0].stages[0]
        self.assertEqual(({}, {"a": (False, ["sh", "tool"])}), wu.assigned(stage))

    def test_an_append_extends_and_two_literals_are_two(self):
        self.assertEqual({"arr": ["a", "b", "c"]}, table("arr=(a b); arr+=(c)").arrays)
        self.assertEqual({"a": ["x", "y"], "b": ["z", "w"]}, table("a=(x y) b=(z w)").arrays)
        values = table("T=x arr=(a b)")
        self.assertEqual(({"T": ["x"]}, {"arr": ["a", "b"]}), (values.scalars, values.arrays))

    def test_a_quoted_parenthesis_is_a_scalar(self):
        values = table("T='(a b)'")
        self.assertEqual(({"T": ["(a b)"]}, {}), (values.scalars, values.arrays))

    def test_a_reassigned_literal_keeps_its_first_words_as_measured(self):
        # Measured: the reader counts a literal's parentheses as a group, so
        # `_certainty` reads every literal's statement as uncertain, and a
        # later literal over held words leaves them as they were.
        self.assertEqual({"arr": ["a", "b"]}, table("arr=(a b); arr=(c d)").arrays)
        self.assertEqual({"arr": ["c", "d"]}, table("arr=(a b); unset arr; arr=(c d)").arrays)

    def test_a_glob_inside_a_literal_is_a_plain_star(self):
        # The lexer escapes a literal's `*`, so the word holds it plain.
        values = table("a=(./cuda_*.run)")
        self.assertEqual({"a": ["./cuda_*.run"]}, values.arrays)
        self.assertEqual(["./cuda_*.run"], wu.valued("${a[0]}", values))
        self.assertEqual([], wu.valued("${a[1]}", values))

    def test_an_element_is_one_word_or_all_of_them(self):
        values = table("arr=(sh tool)")
        rows = {"${arr[0]}": ["sh"], "${arr[1]}": ["tool"], "${arr[2]}": [],
                "${arr[@]}": ["sh tool"], "${arr[*]}": ["sh tool"], "${nope[0]}": [],
                "${arr[01]}": [], "${arr[%s]}" % ("9" * 5000): []}
        for word, expected in rows.items():
            with self.subTest(word=word[:16]):
                self.assertEqual(expected, wu.valued(word, values))

    def test_argvs_splice_an_array_and_substitute_a_value(self):
        values = table("arr=(sh tool); a=(./cuda_*.run); T=cuda_1.run")
        self.assertEqual([["sh", "tool"]], wu.valued_argvs(["${arr[@]}"], values))
        self.assertEqual([["sh", "tool", "x"]], wu.valued_argvs(["${arr[*]}", "x"], values))
        (argv,) = wu.valued_argvs(["sh", "${a[0]}"], values)
        self.assertIsInstance(argv[1], _Reparsed)
        self.assertEqual([["sh", "cuda_1.run"]], wu.valued_argvs(["sh", "$T"], values))
        (argv,) = wu.valued_argvs(["sh", "$T"], values)
        self.assertIs(str, type(argv[1]))
        (argv,) = wu.valued_argvs(["sh", "$T"], table("T=./cuda_*.run"))
        self.assertIsInstance(argv[1], _Reparsed)
        argv = ["sh", "$INPUT"]
        self.assertEqual([argv], wu.valued_argvs(argv, values))

    def test_a_word_bash_expands_as_a_pattern_stays_one(self):
        word = only_stage("sh {$T,x}").argv[1]
        (argv,) = wu.valued_argvs(["sh", word], table("T=cuda_1.run"))
        self.assertIsInstance(argv[1], _Reparsed)
        self.assertEqual("{cuda_1.run,x}", argv[1])

    def test_argvs_are_capped(self):
        values = table("T=a; false && T=b; false && T=c")
        argvs = wu.valued_argvs(["$T", "$T"], values)
        self.assertEqual(8, len(argvs))
        self.assertEqual(["a", "a"], argvs[0])


class TestTheTableAtAStatement(unittest.TestCase):
    """`static_values`: the values live at one statement of one step's shell."""

    def test_the_table_holds_what_the_statements_before_the_index_assign(self):
        stmts = statements('T=a\nsh "$T"\nT=b\nU=c')
        self.assertEqual(wu.Values(), wu.static_values(stmts, 0))
        self.assertEqual({"T": ["a"]}, wu.static_values(stmts, 1).scalars)
        self.assertEqual({"T": ["a"]}, wu.static_values(stmts, 2).scalars)
        self.assertEqual({"T": ["b"], "U": ["c"]}, wu.static_values(stmts, 4).scalars)
        self.assertEqual({"T": ["b"], "U": ["c"]}, wu.static_values(stmts, 9).scalars)

    def test_another_scope_is_not_read(self):
        stmts = statements("T=a\nU=b\nsh x")
        scopes = {0: "one", 1: "two", 2: "two"}
        self.assertEqual({"U": ["b"]}, wu.static_values(stmts, 2, scopes=scopes).scalars)

    def test_working_is_accepted_and_changes_nothing(self):
        stmts = statements("cd sub\nT=cuda_1.run\nsh x")
        working = {0: ".", 1: "sub", 2: "sub"}
        values = wu.static_values(stmts, 2, working)
        self.assertEqual({"T": ["cuda_1.run"]}, values.scalars)
        self.assertEqual(wu.static_values(stmts, 2), values)


if __name__ == "__main__":
    unittest.main()
