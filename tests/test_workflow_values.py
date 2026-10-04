"""#2425, #2489: the step's literal assignments and array literals as bounded value facts.

`workflow_values` is the table a walk reads a `$T` or a `"${a[@]}"` through:
per name, the candidate texts the step's own assignments leave
(`T=cuda_1.run`, `p=./cuda_*.run`), and the candidate word-lists of its
array literals (`declare -a a=(sh tool)`); `workflow_uses.static_values` is
that table live at one statement. These are its unit pins -- what a stage
assigns, when a value is held and when it is emptied, how one word
resolves, how an argv is spliced -- and no guard-level row: the guard does
not read through the table yet.
"""
import unittest

import shell_reader
import workflow_uses as wu
import workflow_values as wv
from workflow_operands import _Reparsed


def statements(script):
    return list(shell_reader.statements(script))


def table(script, index=None):
    """The table `static_values` leaves at `index`, past the last statement by default."""
    stmts = statements(script)
    return wu.static_values(stmts, index if index is not None else len(stmts))


def at_use(script):
    """The table at the last statement whose command holds a reference: the use."""
    stmts = statements(script)
    index = max(position for position, statement in enumerate(stmts)
                if any("$" in str(word) for word in shell_reader.command(
                    statement.stages[0].argv if statement.stages else [])))
    return wu.static_values(stmts, index)


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
            # `command export` runs the builtin in the step's shell, as `command cd` does,
            # and so do `builtin export` and a timed assignment.
            "command export T=cuda_1.run": {"T": ["cuda_1.run"]},
            "builtin export T=cuda_1.run": {"T": ["cuda_1.run"]},
            "time T=cuda_1.run": {"T": ["cuda_1.run"]},
            "time -p T=cuda_1.run": {"T": ["cuda_1.run"]},
            "export -n T=cuda_1.run": {"T": ["cuda_1.run"]},   # un-exported, as assigned
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
        # `env T=x` is a command that sets T in its own environment only,
        # `sudo export T=x` runs no builtin of the step's shell, and
        # `builtin T=x` names no builtin at all.
        for script in ("export T", 'T=cuda_1.run sh "$T"', "env T=cuda_1.run",
                       "sudo export T=cuda_1.run", "local T", "builtin T=cuda_1.run"):
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
            # A value the table cannot see, and a scalar the statement only may
            # assign, are `record`'s.
            "arr=([1]=tool [0]=sh)": ({}, {}),
            "declare -l T=CUDA_1.RUN": ({}, {}),
            "a=(p q) T=cuda_1.run": ({}, {"a": (False, ["p", "q", "T=cuda_1.run"])}),
        }
        for script, expected in rows.items():
            with self.subTest(script=script):
                self.assertEqual(expected, wv.assigned(only_stage(script)))


class TestWhenAValueIsHeldAndEmptied(unittest.TestCase):
    """#2425: a value is held wherever a statement assigns it, and replaced or
    emptied only where the step's shell surely runs the statement."""

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

    def test_a_name_an_uncertain_statement_assigns_first_may_be_unset(self):
        # The "maybe unset" candidate, over which a default stands.
        values = table("if x; then F=x; fi")
        self.assertEqual({"F": ["x", ""]}, values.scalars)
        self.assertEqual(["x", "./install.sh"], wv.valued("${F:-./install.sh}", values))
        self.assertEqual(["x", "", "./install.sh"], wv.valued("${F-./install.sh}", values))
        self.assertEqual([["sh", "x"], ["sh"], ["sh", "./install.sh"]],
                         wv.valued_argvs(["sh", "${F-./install.sh}"], values))

    def test_a_certain_unset_or_bare_local_empties_the_name(self):
        for script in ("T=a; unset T", "T=a; local T", "arr=(a b); unset arr",
                       "T=a; builtin unset T"):
            with self.subTest(script=script):
                values = table(script)
                self.assertEqual(({}, {}), (values.scalars, values.arrays))
        # `unset -f` unsets a function, bare or behind `builtin`.
        self.assertEqual({"T": ["a"]}, table("T=a; builtin unset -f T").scalars)

    def test_an_uncertain_unset_marks_the_name_maybe_unset(self):
        rows = {"T=a; false && unset T": {"T": ["a", ""]},
                "T=a; false && builtin unset T": {"T": ["a", ""]},
                "U=b; false && unset T": {"U": ["b"]}}
        for script, expected in rows.items():
            with self.subTest(script=script):
                self.assertEqual(expected, table(script).scalars)
        self.assertEqual({"arr": [["a"], []]}, table("arr=(a); false && unset arr").arrays)
        self.assertEqual(["a", ""], wv.valued("$T", table("T=a; false && unset T")))

    def test_a_for_header_assigns_its_words(self):
        stmts = statements("T=a; for T in x y; do :; done")
        self.assertEqual({"T": ["x", "y"]}, wu.static_values(stmts, 2).scalars)
        rows = {
            "for T in cuda_1.run; do :; done": ["cuda_1.run"],
            # A glob stays its text, which `valued_argvs` makes live.
            "for T in ./cuda_*.run; do :; done": ["./cuda_*.run"],
            # After the loop bash holds its last word, `x`, and the table both:
            # an over-report, a price.
            'T=cuda_1.run; for T in "$T" x; do :; done': ["cuda_1.run", "x"],
            # A word the table cannot see is the stand-in `$T`; with no word
            # written out the loop may not run, so `a` stays beside it.
            'T=a; for T in "$@"; do :; done': ["a", "$T"],
            "T=a; for T in $(ls); do :; done": ["a", "$T"],
            "T=a; for T; do :; done": ["a", "$T"],
            'for T in "$@"; do :; done': ["$T", ""],
            # A word written out runs the loop: the known words and the stand-in.
            "for T in $(ls ./*.run) x; do :; done": ["x", "$T"],
            'for T in "$@" x; do :; done': ["x", "$T"],
            'for T in "${nope[@]}" x; do :; done': ["x", "$T"],
            # Every word expands, perhaps to nothing: the words join `a`.
            "T=a; for T in $X; do :; done": ["a", "$X"],
            'arr=(p q); T=a; for T in "${arr[@]}"; do :; done': ["a", "p", "q"],
            "if c; then for T in x; do :; done; fi": ["x", ""],
            # `for` here is `echo`'s word, not a header.
            "T=a; echo for T in other": ["a"],
        }
        for script, expected in rows.items():
            with self.subTest(script=script):
                self.assertEqual(expected, table(script).scalars["T"])

    def test_a_header_expands_its_brace_words_as_bash_does_first(self):
        # x17: bash walks `cuda_1.run` and `x.run`; a quoted brace is one word.
        values = table("for T in {cuda_1,x}.run; do :; done")
        self.assertEqual({"T": ["cuda_1.run", "x.run"]}, values.scalars)
        self.assertEqual([["sh", "cuda_1.run"], ["sh", "x.run"]],
                         wv.valued_argvs(["sh", "$T"], values))
        self.assertEqual({"T": ["{p,q}"]}, table('for T in "{p,q}"; do :; done').scalars)
        # An extglob group stays its text, and is live where it is used.
        (argv,) = wv.valued_argvs(["sh", "$T"], table("for T in @(a|b).run; do :; done"))
        self.assertIsInstance(argv[1], _Reparsed)
        # z01-z03: a brace word the table cannot expand, with a reference in it or
        # past 64 words, is the stand-in and no written word: the loop may not run.
        rows = {"for s in {install,setup}${SUFFIX}.sh; do :; done": {"s": ["$s", ""]},
                "for s in {install,setup,$EXTRA}.sh; do :; done": {"s": ["$s", ""]},
                "T=x; for T in {1..100}.run; do :; done": {"T": ["x", "$T"]}}
        for script, expected in rows.items():
            with self.subTest(script=script):
                self.assertEqual(expected, table(script).scalars)

    def test_a_call_records_nothing_and_a_pipeline_its_last_stage_unsure(self):
        # A call's own assignments are not read (a price); a pipeline's stages
        # run in subshells, but its last runs in the shell under `lastpipe`.
        self.assertEqual({"T": ["a"]}, table("f() { T=b; }; T=a; f").scalars)
        rows = {"T=a | cat; echo": {}, "T=a; echo | { T=x; }": {"T": ["a", "x"]},
                "T=a; cat | T=b": {"T": ["a", "b"]}}
        for script, expected in rows.items():
            with self.subTest(script=script):
                self.assertEqual(expected, table(script).scalars)

    def test_a_name_past_eight_candidates_holds_its_stand_in_alone(self):
        # x20: the guard's reading without the table, rather than the last eight.
        nine = "T=cuda_1.run" + "".join("; false && T=%d" % number for number in range(1, 9))
        self.assertEqual({"T": ["$T"]}, table(nine).scalars)
        self.assertEqual({"T": ["$T", "9"]}, table(nine + "; false && T=9").scalars)
        self.assertEqual({"T": ["$T"]}, table("for T in 1 2 3 4 5 6 7 8 9; do :; done").scalars)
        append = "A=1; false && A=2; false && A=3; B=x; false && B=y; false && B=z; A+=$B"
        self.assertEqual(["$A"], table(append).scalars["A"])


class TestAValueTheTableCannotSee(unittest.TestCase):
    """#2425: a name set to a value the table cannot see holds its own
    reference, the stand-in -- the reading the guard makes without the table."""

    def test_a_certain_one_holds_the_stand_in_alone(self):
        rows = {
            "T=a; read -r T": ({"T": ["$T"]}, {}),
            "arr=(a b); read -ra arr": ({"arr": ["$arr"]}, {}),
            "T=x; printf -v T '%s' cuda_1.run": ({"T": ["$T"]}, {}),     # x08
            "T=x; printf -vT '%s' cuda_1.run": ({"T": ["$T"]}, {}),      # q01
            "REPLY=x; read -r < list": ({"REPLY": ["$REPLY"]}, {}),      # q02
            "T=x; getopts ab T": ({"T": ["$T"], "OPTARG": ["$OPTARG"], "OPTIND": ["$OPTIND"]}, {}),
            "OPTARG=x; set -- -a cuda_1.run; getopts a: o":                          # q04
                ({"OPTARG": ["$OPTARG"], "o": ["$o"], "OPTIND": ["$OPTIND"]}, {}),
            "T=x; select T in cuda_1.run; do break; done <<< 1":                     # z11
                ({"T": ["$T"], "REPLY": ["$REPLY"]}, {}),
            "arr=(echo hi); mapfile -t arr < list": ({"arr": ["$arr"]}, {}),         # x22
            "arr=(echo hi); arr[0]=sh; arr[1]=tool": ({"arr": ["$arr"]}, {}),        # x23
            "arr=(a); readarray arr": ({"arr": ["$arr"]}, {}),
            "arr=(a b); declare arr[1]=x": ({"arr": ["$arr"]}, {}),
            # Behind `builtin` as bare, for the table alone.
            "T=a; builtin read -r T": ({"T": ["$T"]}, {}),
            "REPLY=x; builtin read -r": ({"REPLY": ["$REPLY"]}, {}),
            "T=x; builtin printf -v T y": ({"T": ["$T"]}, {}),
            "T=x; builtin getopts ab T":
                ({"T": ["$T"], "OPTARG": ["$OPTARG"], "OPTIND": ["$OPTIND"]}, {}),
            "arr=([1]=tool [0]=sh)": ({"arr": ["$arr"]}, {}),            # x10
            "declare -a arr=([0]=sh)": ({"arr": ["$arr"]}, {}),
            "declare -A m=([k]=tool)": ({"m": ["$m"]}, {}),              # y13
            "declare -l T=CUDA_1.RUN": ({"T": ["$T"]}, {}),              # y11
            "declare -u T=x": ({"T": ["$T"]}, {}),
            "typeset -i n=1": ({"n": ["$n"]}, {}),
            "local -n R=T": ({"R": ["$R"]}, {}),
        }
        for script, expected in rows.items():
            with self.subTest(script=script):
                values = table(script)
                self.assertEqual(expected, (values.scalars, values.arrays))

    def test_the_stand_in_reads_as_the_use_was_written(self):
        values = table("arr=([1]=tool [0]=sh); T=x; read -r T")
        self.assertEqual([["${arr[@]}"]], wv.valued_argvs(["${arr[@]}"], values))
        self.assertEqual([["sh", "$T"]], wv.valued_argvs(["sh", "$T"], values))
        # It is braced where text would lengthen its name.
        self.assertEqual(["${T}x"], wv.valued("${T}x", values))
        self.assertEqual({"T": ["ax", "${T}x"]},
                         table("T=a; false && read -r T; T+=x").scalars)
        # x22, x23: bash runs `sh tool`; the use stays as written, main's reading.
        for script in ("arr=(echo hi); mapfile -t arr < list",
                       "arr=(echo hi); arr[0]=sh; arr[1]=tool"):
            with self.subTest(script=script):
                self.assertEqual([["${arr[@]}"]],
                                 wv.valued_argvs(["${arr[@]}"], table(script)))

    def test_mapfile_sets_the_name_after_its_options_or_mapfile(self):
        rows = {"MAPFILE=(a); mapfile < list": {"MAPFILE": ["$MAPFILE"]},
                "cb=x; mapfile -C cb -c 1 arr": {"cb": ["x"], "arr": ["$arr"]},
                "readarray -tu 3 arr": {"arr": ["$arr"]},
                "mapfile -u3 -- arr": {"arr": ["$arr"]},
                # A word the table cannot read may be an option: each name after it.
                "mapfile $opts arr": {"arr": ["$arr"]},
                "arr=(a); builtin mapfile arr": {"arr": ["$arr"]}}
        for script, expected in rows.items():
            with self.subTest(script=script):
                values = table(script)
                self.assertEqual((expected, {}), (values.scalars, values.arrays))

    def test_an_elements_assignment_or_unset_leaves_its_array_unseen(self):
        # Bash changes the array each time, as the table cannot follow.
        rows = {
            "arr=(cuda_1 x); arr[0]+=.run": ({"arr": ["$arr"]}, {}),
            "a=(p); a[0]=x b=y": ({"a": ["$a"], "b": ["y"]}, {}),
            "local -a arr; arr[$i]=sh": ({"arr": ["$arr"]}, {}),
            # The reader takes a subscript holding `]` for a command.
            "arr=(echo hi); arr[${#arr[@]}]=x": ({"arr": ["$arr"]}, {}),
            "arr=(echo sh tool); unset 'arr[0]'": ({"arr": ["$arr"]}, {}),
            "arr=(echo hi); read -r 'arr[0]'": ({"arr": ["$arr"]}, {}),
            "arr=(a); printf -v 'arr[1]' y": ({"arr": ["$arr"]}, {}),
            # x13's twin: a word of an open unfolded literal may be an assignment.
            "x=1; a=(p q) x[0]=y": ({"x": ["$x"]}, {"a": [["p", "q", "x[0]=y"]]}),
        }
        for script, expected in rows.items():
            with self.subTest(script=script):
                values = table(script)
                self.assertEqual(expected, (values.scalars, values.arrays))
        # Bash refuses an element's PREFIX assignment: "not a valid identifier".
        values = table("a=(p); a[0]=x sh y")
        self.assertEqual(({}, {"a": [["p"]]}), (values.scalars, values.arrays))

    def test_a_name_taken_from_a_value_gives_every_held_name_its_stand_in(self):
        # Bash sets whatever `$n` or `$k` names: `eval`'s rule, the old kept.
        self.assertEqual({"T": ["a", "$T"], "n": ["T", "$n"]},
                         table('T=a; n=T; read -r "$n" < list').scalars)
        for script in ('T=a; export "$k=$v"', "T=a; export $(cat .env | xargs)",
                       'T=a; export "${p}_HOME=/x"', 'T=a; unset "$n"', 'T=a; local "$n"',
                       'T=a; declare "$n=x"', 'T=a; readonly "$n"', 'T=a; printf -v "$n" x',
                       'T=a; read -ra "$n"', 'T=a; builtin read "$n"',
                       'T=a; false && read -r "$n"'):
            with self.subTest(script=script):
                self.assertEqual({"T": ["a", "$T"]}, table(script).scalars)
        self.assertEqual({"T": ["a", "$T"], "OPTARG": ["$OPTARG"], "OPTIND": ["$OPTIND"]},
                         table('T=a; getopts ab "$n"').scalars)
        # A name-less `mapfile` sets `MAPFILE`; one naming `"$n"` does not.
        values = table('arr=(a); mapfile -t "$n"')
        self.assertEqual(({"arr": ["$arr"]}, {"arr": [["a"]]}), (values.scalars, values.arrays))
        # A `$` in an option's argument, a subscript or a value names nothing.
        rows = {'T=a; U=b; read -p "$prompt" T': {"T": ["$T"], "U": ["b"]},
                "arr=(a); U=b; read -r 'arr[$i]'": {"U": ["b"], "arr": ["$arr"]},
                'U=b; export "T=$v"': {"U": ["b"], "T": ["$v"]},
                'T=a; unset -f "$fn"': {"T": ["a"]}}
        for script, expected in rows.items():
            with self.subTest(script=script):
                self.assertEqual(expected, table(script).scalars)

    def test_an_uncertain_one_adds_the_stand_in(self):
        rows = {"T=a; false && read -r T": ({"T": ["a", "$T"]}, {}),
                "T=x; if true; then read -r T < list; fi": ({"T": ["x", "$T"]}, {}),   # y09
                "T=x; false && declare -l T=Y": ({"T": ["x", "$T"]}, {}),
                "arr=(a); false && read -ra arr": ({"arr": ["$arr"]}, {"arr": [["a"]]}),
                "arr=(a); false && mapfile arr": ({"arr": ["$arr"]}, {"arr": [["a"]]}),
                "arr=(a); false && arr[0]=b": ({"arr": ["$arr"]}, {"arr": [["a"]]}),
                "T=a; false && builtin read -r T": ({"T": ["a", "$T"]}, {}),
                # z10: a pipeline's last stage runs in the shell under `lastpipe`.
                "shopt -s lastpipe; T=x; echo cuda_1.run | read -r T": ({"T": ["x", "$T"]}, {}),
                "arr=(a); cat list | mapfile -t arr": ({"arr": ["$arr"]}, {"arr": [["a"]]}),
                "T=x; echo a | printf -v T y": ({"T": ["x", "$T"]}, {})}
        for script, expected in rows.items():
            with self.subTest(script=script):
                values = table(script)
                self.assertEqual(expected, (values.scalars, values.arrays))

    def test_eval_source_and_dot_add_every_held_name_its_stand_in(self):
        for script in ("T=x; eval T=cuda_1.run", "T=x; . ./vars.sh",       # x07, x09
                       "T=x; source ./vars.sh", "T=x; builtin eval :"):
            with self.subTest(script=script):
                self.assertEqual({"T": ["x", "$T"]}, table(script).scalars)
        values = table("arr=(a); eval :")
        self.assertEqual(({"arr": ["$arr"]}, {"arr": [["a"]]}), (values.scalars, values.arrays))
        self.assertEqual([["a"], ["$arr"]], wv.valued_argvs(["${arr[@]}"], values))

    def test_a_default_stands_beside_a_value_the_table_cannot_see(self):
        # It may be null: the stand-in, a reference held as written, a `$(...)`.
        values = table("T=a; false && read -r T")
        self.assertEqual(["a", "$T", "d"], wv.valued("${T:-d}", values))
        self.assertEqual(["a", "$T", "d"], wv.valued("${T-d}", values))
        self.assertEqual(["$T", "d"], wv.valued("${U:-d}", table("U=$T")))
        marker, default = wv.valued("${T:-d}", table("T=$(cmd)"))
        self.assertTrue(shell_reader.has_substitution(marker))
        self.assertEqual("d", default)


class TestHowAWordResolves(unittest.TestCase):
    """#2425 and the #2581 rows: a whole or embedded reference, and a default."""

    def test_a_reference_stands_for_its_candidates(self):
        values = table("T=cuda_1.run; X=*")
        rows = {"$T": ["cuda_1.run"], "${T}": ["cuda_1.run"], "x/$T": ["x/cuda_1.run"],
                "./cuda_$X.run": ["./cuda_*.run"]}
        for word, expected in rows.items():
            with self.subTest(word=word):
                self.assertEqual(expected, wv.valued(word, values))

    def test_a_default_stands_where_the_name_is_unassigned(self):
        unassigned, assigned = wv.Values(), table("X=1")
        rows = {"${X:-*}": (["*"], ["1"]), "${X-*}": (["*"], ["1"]),
                "${X:=*}": (["*"], ["1"]), "${X=*}": (["*"], ["1"]),
                "./cuda_${X:-*}.run": (["./cuda_*.run"], ["./cuda_1.run"])}
        for word, (bare, held) in rows.items():
            with self.subTest(word=word):
                self.assertEqual(bare, wv.valued(word, unassigned))
                self.assertEqual(held, wv.valued(word, assigned))

    def test_a_null_value_takes_a_colon_default_and_keeps_a_plain_one_beside_it(self):
        # `""` cannot say whether the name was set empty or left unset, so under
        # `-` and `=` it stands for both: bash gives `""` here, an over-report.
        values = table("X=")
        rows = {"${X:-d}": ["d"], "${X:=d}": ["d"], "${X-d}": ["", "d"], "${X=d}": ["", "d"]}
        for word, expected in rows.items():
            with self.subTest(word=word):
                self.assertEqual(expected, wv.valued(word, values))

    def test_the_assignment_a_colon_equals_default_makes_is_not_read(self):
        # x11, x12: bash holds `cuda_1.run` after `:=`; the table does not (a price).
        self.assertEqual({"T": [""]}, table('T=; : "${T:=cuda_1.run}"').scalars)
        self.assertEqual({"T": ["x", ""]},
                         table('if false; then T=x; fi; : "${T:=cuda_1.run}"').scalars)

    def test_arithmetic_is_not_read_as_bash_computes_it(self):
        # Bash holds 5, 6 and 1: numbers, a price.
        rows = {"T=a; let T=5": ["a"], "T=5; ((T++))": ["5"], "T=a; ((T=x+1))": ["a", "x+1"]}
        for script, expected in rows.items():
            with self.subTest(script=script):
                self.assertEqual(expected, table(script).scalars["T"])

    def test_every_other_expansion_form_stays_as_written(self):
        values = table("T=x; X=1")
        for word in ("${X:+y}", "${T#x}", "${T%x}", "${T//a/b}", "${T:0:3}", "${#T}", "${!T}"):
            with self.subTest(word=word):
                self.assertEqual([], wv.valued(word, values))

    def test_a_word_with_nothing_held_resolves_to_nothing(self):
        values = table("T=x")
        for word in ("cuda_1.run", "$UNSET", "${UNSET}", "$1", "$@"):
            with self.subTest(word=word):
                self.assertEqual([], wv.valued(word, values))

    def test_the_product_of_candidates_is_ordered_and_capped(self):
        two = table("T=a; false && T=b")
        self.assertEqual(["aa", "ab", "ba", "bb"], wv.valued("$T$T", two))
        three = table("; ".join("%s=1; false && %s=2; false && %s=3" % (name, name, name)
                                for name in "ABC"))
        self.assertEqual(["111", "112", "113", "121", "122", "123", "131", "132"],
                         wv.valued("$A$B$C", three))

    def test_nothing_inside_a_lifted_substitution_is_matched(self):
        stmts = statements('T=cuda_1.run\nsh "$(printf %s "$T")"')
        word = stmts[1].stages[0].argv[1]
        self.assertTrue(shell_reader.is_marker(word))
        self.assertNotIn("$", word)
        self.assertEqual([], wv.valued(word, wu.static_values(stmts, 1)))

    def test_a_value_keeps_its_substitution_through_a_use(self):
        (text,) = wv.valued("$T", table("T=$(pwd)/cuda_1.run"))
        self.assertTrue(shell_reader.has_substitution(text))
        self.assertEqual("$(...)/cuda_1.run", shell_reader.readable(text))

    def test_a_value_that_doubles_itself_stays_bounded(self):
        values = table("T=12345678\n" + "T=$T$T\n" * 64)
        self.assertTrue(values.scalars["T"])
        self.assertTrue(all(len(text) <= wv._LONGEST for text in values.scalars["T"]))
        self.assertEqual([], wv.valued("$T" * 5000, table("T=x")))


class TestAnArrayLiteral(unittest.TestCase):
    """#2489: an array literal's candidate word-lists, an element, and the splice."""

    def test_a_literal_records_its_words(self):
        rows = {"arr=(sh tool)": "arr", "declare -a arr=(sh tool)": "arr",
                "export arr=(sh tool)": "arr", "local -a a=(sh tool)": "a",
                "typeset -a arr=(sh tool)": "arr", "readonly -a arr=(sh tool)": "arr"}
        for script, name in rows.items():
            with self.subTest(script=script):
                values = table(script)
                self.assertEqual({name: [["sh", "tool"]]}, values.arrays)
                self.assertEqual({}, values.scalars)

    def test_a_literal_behind_a_function_header_is_read_unfolded(self):
        # The reader folds a literal into its word behind a declaration only,
        # and here a function header stands in front of the `local` (#2348).
        stage = statements('f() { local -a a=(sh tool); "${a[@]}"; }')[0].stages[0]
        self.assertEqual(({}, {"a": (False, ["sh", "tool"])}), wv.assigned(stage))

    def test_a_literal_expands_its_brace_words_as_bash_does_first(self):
        # x18, x19: bash holds `cuda_1.run x.run`.
        for script in ("declare -a a=({cuda_1,x}.run)", "a=({cuda_1,x}.run)"):
            with self.subTest(script=script):
                values = table(script)
                self.assertEqual({"a": [["cuda_1.run", "x.run"]]}, values.arrays)
                self.assertEqual([["sh", "cuda_1.run"]], wv.valued_argvs(["sh", "${a[0]}"], values))
        # z03b: one it cannot expand leaves the name unseen, as x10's, folded or not.
        for script in ("a=({1..100}.run)", "declare -a a=({1..100}.run)", "a=({a,$X}.sh x)"):
            with self.subTest(script=script):
                values = table(script)
                self.assertEqual(({"a": ["$a"]}, {}), (values.scalars, values.arrays))
                self.assertEqual([], wv.valued("${a[0]}", values))
                self.assertEqual([["sh", "${a[0]}"]], wv.valued_argvs(["sh", "${a[0]}"], values))
        # `${X:-a,b}` is a reference, no brace group.
        self.assertEqual({"a": [["${X:-a,b}"]]}, table("a=(${X:-a,b})").arrays)

    def test_a_literal_is_as_sure_as_its_statement(self):
        # The reader counts a literal's parentheses as a group; the table does
        # not, so a literal alone replaces, and a real group or branch adds.
        rows = {
            "arr=(a b); arr=(c d)": [["c", "d"]],
            "declare -a arr=(echo hi); declare -a arr=(sh tool)": [["sh", "tool"]],
            "arr=(a b); unset arr; arr=(c d)": [["c", "d"]],
            "arr=(a b); false && arr=(c d)": [["a", "b"], ["c", "d"]],
            "arr=(a); if x; then arr=(b); fi": [["a"], ["b"]],
            "arr=(a); arr=(b) &": [["a"], ["b"]],
            "false && arr=(a)": [["a"], []],
            "( arr=(a b) )": [["a", "b"], []],
            "( declare -a arr=(a) )": [["a"], []],
            "{ arr=(a); }": [["a"]],
        }
        for script, expected in rows.items():
            with self.subTest(script=script):
                self.assertEqual({"arr": expected}, table(script).arrays)

    def test_an_append_extends_each_candidate_and_two_literals_are_two(self):
        rows = {"arr=(a b); arr+=(c)": {"arr": [["a", "b", "c"]]},
                "arr=(a b); false && arr+=(c)": {"arr": [["a", "b"], ["a", "b", "c"]]},
                "a=(x y) b=(z w)": {"a": [["x", "y"]], "b": [["z", "w"]]}}
        for script, expected in rows.items():
            with self.subTest(script=script):
                self.assertEqual(expected, table(script).arrays)
        values = table("T=x arr=(a b)")
        self.assertEqual(({"T": ["x"]}, {"arr": [["a", "b"]]}), (values.scalars, values.arrays))

    def test_a_scalar_inside_an_open_unfolded_literal_may_be_assigned(self):
        # x13: the reader lost where `(p q)` closed; `T=cuda_1.run` is read both
        # as a word of the literal and as a scalar the statement may assign.
        values = table("T=x; a=(p q) T=cuda_1.run")
        self.assertEqual({"T": ["x", "cuda_1.run"]}, values.scalars)
        self.assertEqual({"a": [["p", "q", "T=cuda_1.run"]]}, values.arrays)

    def test_a_quoted_parenthesis_is_a_scalar(self):
        values = table("T='(a b)'")
        self.assertEqual(({"T": ["(a b)"]}, {}), (values.scalars, values.arrays))

    def test_a_subshells_quoted_parentheses_replace_the_outer_value(self):
        # y12: bash keeps `sh tool`; the table reads a literal and replaces it (a price).
        self.assertEqual({"arr": [["x", "y"]]}, table("arr=(sh tool); ( arr='(x y)' )").arrays)

    def test_a_folded_literal_is_re_split_on_blanks(self):
        # x21: bash's `${a[1]}` is `./cuda_1.run`; the re-split shifts it (a price).
        values = table('declare -a a=("my file" ./cuda_1.run)')
        self.assertEqual({"a": [["my", "file", "./cuda_1.run"]]}, values.arrays)
        self.assertEqual(["file"], wv.valued("${a[1]}", values))

    def test_a_glob_inside_a_literal_is_a_plain_star(self):
        # The lexer escapes a literal's `*`, so the word holds it plain.
        values = table("a=(./cuda_*.run)")
        self.assertEqual({"a": [["./cuda_*.run"]]}, values.arrays)
        self.assertEqual(["./cuda_*.run"], wv.valued("${a[0]}", values))
        self.assertEqual([], wv.valued("${a[1]}", values))

    def test_an_element_is_one_word_or_all_of_them(self):
        values = table("arr=(sh tool)")
        rows = {"${arr[0]}": ["sh"], "${arr[1]}": ["tool"], "${arr[2]}": [],
                "${arr[@]}": ["sh tool"], "${arr[*]}": ["sh tool"], "${nope[0]}": [],
                "${arr[01]}": [], "${arr[%s]}" % ("9" * 5000): []}
        for word, expected in rows.items():
            with self.subTest(word=word[:16]):
                self.assertEqual(expected, wv.valued(word, values))

    def test_an_element_reads_each_candidate_and_a_bare_name_is_element_zero(self):
        # Bash reads `$a` and `${a}` as `${a[0]}`; an empty candidate has no word.
        two = table("arr=(a b); false && arr=(c d)")
        maybe = table("false && arr=(a)")
        rows = {"${arr[0]}": (["a", "c"], ["a"]), "$arr": (["a", "c"], ["a"]),
                "${arr}": (["a", "c"], ["a"]), "${arr[1]}": (["b", "d"], []),
                "${arr[@]}": (["a b", "c d"], ["a", ""])}
        for word, (both, unset) in rows.items():
            with self.subTest(word=word):
                self.assertEqual(both, wv.valued(word, two))
                self.assertEqual(unset, wv.valued(word, maybe))
        # `arr=s` is `arr[0]=s`.
        self.assertEqual(["s"], wv.valued("$arr", table("arr=(a); arr=s")))

    def test_a_name_is_one_variable_however_it_is_assigned(self):
        # r19b, x05, x06, y10: bash keeps one variable per name.
        rows = {
            "arr=(a); arr=s": ({}, {"arr": [["s"]]}),
            "T=other; T=(cuda_1.run)": ({}, {"T": [["cuda_1.run"]]}),
            "arr=(x tool); arr=sh": ({}, {"arr": [["sh", "tool"]]}),
            "arr=(cuda_1 x); arr+=.run": ({}, {"arr": [["cuda_1.run", "x"]]}),
            "T=a; T+=(b)": ({}, {"T": [["a", "b"]]}),
            "T=a; false && T=(b)": ({"T": ["a"]}, {"T": [["b"]]}),
        }
        for script, expected in rows.items():
            with self.subTest(script=script):
                values = table(script)
                self.assertEqual(expected, (values.scalars, values.arrays))
        self.assertEqual([["s"]], wv.valued_argvs(["${arr[@]}"], table("arr=(a); arr=s")))
        self.assertEqual(["cuda_1.run"], wv.valued("$T", table("T=other; T=(cuda_1.run)")))
        self.assertEqual([["sh", "tool"]],
                         wv.valued_argvs(["${arr[@]}"], table("arr=(x tool); arr=sh")))
        self.assertEqual(["cuda_1.run"],
                         wv.valued("${arr[0]}", table("arr=(cuda_1 x); arr+=.run")))
        both = table("T=a; false && T=(b)")
        self.assertEqual(["a", "b"], wv.valued("$T", both))
        self.assertEqual([["b"], ["a"]], wv.valued_argvs(["${T[@]}"], both))

    def test_a_default_stands_where_an_array_has_no_word_zero(self):
        # Bash: `arr=(); echo "${arr-d}"` prints `d`, under each of the four forms.
        maybe, empty = table("false && arr=(x)"), table("arr=()")
        for word in ("${arr:-d}", "${arr-d}", "${arr:=d}", "${arr=d}"):
            with self.subTest(word=word):
                self.assertEqual(["x", "d"], wv.valued(word, maybe))
                self.assertEqual(["d"], wv.valued(word, empty))
        self.assertEqual([], wv.valued("$arr", empty))

    def test_argvs_splice_an_array_and_substitute_a_value(self):
        values = table("arr=(sh tool); a=(./cuda_*.run); T=cuda_1.run")
        self.assertEqual([["sh", "tool"]], wv.valued_argvs(["${arr[@]}"], values))
        self.assertEqual([["sh", "tool", "x"]], wv.valued_argvs(["${arr[*]}", "x"], values))
        (argv,) = wv.valued_argvs(["sh", "${a[0]}"], values)
        self.assertIsInstance(argv[1], _Reparsed)
        self.assertEqual([["sh", "cuda_1.run"]], wv.valued_argvs(["sh", "$T"], values))
        (argv,) = wv.valued_argvs(["sh", "$T"], values)
        self.assertIs(str, type(argv[1]))
        (argv,) = wv.valued_argvs(["sh", "$T"], table("T=./cuda_*.run"))
        self.assertIsInstance(argv[1], _Reparsed)
        argv = ["sh", "$INPUT"]
        self.assertEqual([argv], wv.valued_argvs(argv, values))

    def test_argvs_splice_each_candidate_and_drop_an_empty_word(self):
        two = table("arr=(a b); false && arr=(c d)")
        self.assertEqual([["a", "b", "x"], ["c", "d", "x"]],
                         wv.valued_argvs(["${arr[@]}", "x"], two))
        self.assertEqual([["a", "x"], ["x"]],
                         wv.valued_argvs(["${arr[@]}", "x"], table("false && arr=(a)")))
        # Bash drops an unquoted empty expansion: `$SUDO sh x` runs `sh x`.
        self.assertEqual([["sh", "x"]], wv.valued_argvs(["$SUDO", "sh", "x"], table("SUDO=")))
        self.assertEqual([], wv.valued_argvs(["$E"], table("E=")))

    def test_a_word_bash_expands_as_a_pattern_stays_one(self):
        word = only_stage("sh {$T,x}").argv[1]
        (argv,) = wv.valued_argvs(["sh", word], table("T=cuda_1.run"))
        self.assertIsInstance(argv[1], _Reparsed)
        self.assertEqual("{cuda_1.run,x}", argv[1])

    def test_argvs_are_capped(self):
        values = table("T=a; false && T=b; false && T=c")
        argvs = wv.valued_argvs(["$T", "$T"], values)
        self.assertEqual(8, len(argvs))
        self.assertEqual(["a", "a"], argvs[0])


class TestTheTableAtAStatement(unittest.TestCase):
    """`workflow_uses.static_values`: the values live at one statement of one step."""

    def test_the_table_holds_what_the_statements_before_the_index_assign(self):
        stmts = statements('T=a\nsh "$T"\nT=b\nU=c')
        self.assertEqual(wv.Values(), wu.static_values(stmts, 0))
        self.assertEqual({"T": ["a"]}, wu.static_values(stmts, 1).scalars)
        self.assertEqual({"T": ["a"]}, wu.static_values(stmts, 2).scalars)
        self.assertEqual({"T": ["b"], "U": ["c"]}, wu.static_values(stmts, 4).scalars)
        self.assertEqual({"T": ["b"], "U": ["c"]}, wu.static_values(stmts, 9).scalars)

    def test_an_assignment_inside_a_forked_group_is_not_sure(self):
        # x01-x04: bash keeps `cuda_1.run`, as the group runs in a child; z04 with
        # a literal's lines inside, z05 and its twins an `&&` list sent off whole.
        for script in ('T=cuda_1.run; ( :; T=x; : ); sh "$T"',
                       'T=cuda_1.run\n(\n  T=x\n)\nsh "$T"',
                       'T=cuda_1.run; { T=x; } &\nwait; sh "$T"',
                       'T=cuda_1.run; { T=x; } | cat; sh "$T"',
                       'T=cuda_1.run\n(\n  arr=(\n    a\n  )\n  T=x\n)\nsh "$T"',
                       'T=cuda_1.run; { T=x; } && : &\nwait; sh "$T"',
                       'T=cuda_1.run; T=x || : &\nwait; sh "$T"',
                       'T=cuda_1.run; T=x &&\n: &\nwait; sh "$T"'):
            with self.subTest(script=script):
                self.assertEqual({"T": ["cuda_1.run", "x"]}, at_use(script).scalars)
        for script in ('T=cuda_1.run; { T=x; }; sh "$T"', 'T=cuda_1.run; { T=x; } && :; sh "$T"',
                       # A list is not followed past a compound command (a limit).
                       'T=cuda_1.run; T=x && if c; then :; fi &\nwait; sh "$T"'):
            with self.subTest(script=script):
                self.assertEqual({"T": ["x"]}, at_use(script).scalars)
        self.assertEqual({"T": ["a", "b", "c"], "U": ["d"]},
                         table("T=a; ( T=b; T=c; ); U=d").scalars)

    def test_a_loop_body_sees_what_it_assigns_on_an_earlier_pass(self):
        # y04, y05: bash's second pass runs `cuda_1.run`; a `T=b` after the loop
        # never reaches the body.
        rows = {'T=x; for i in 1 2; do sh "$T" || :; T=cuda_1.run; done; T=b':
                    ["x", "cuda_1.run"],
                'T=x; n=0; while [ $n -lt 2 ]; do sh "$T" || :; T=cuda_1.run; '
                'n=$((n+1)); done': ["x", "cuda_1.run"],
                'for i in 1; do for j in 1; do sh "$T"; T=x; done; T=y; done; T=z':
                    ["x", "", "y"],
                # z08, z09: and so does a use in the condition, its head's own command.
                'T=x; until sh "$T" 2>/dev/null; do T=cuda_1.run; done': ["x", "cuda_1.run"],
                'T=x; while ! sh "$T"; do T=cuda_1.run; done': ["x", "cuda_1.run"],
                'T=x; while ! sh "$T"; do T=y; done; T=b': ["x", "y"],
                'T=x; if c; then until sh "$T"; do T=y; done; fi': ["x", "y"],
                # A later command of the condition, or one on the lines after a bare
                # `while`, is not found (a limit).
                'T=x; while a; b "$T"; do T=y; done': ["x"],
                'T=x; while\n  sh "$T"\ndo\n  T=y\ndone': ["x"]}
        for script, expected in rows.items():
            with self.subTest(script=script):
                self.assertEqual(expected, at_use(script).scalars["T"])

    def test_a_function_body_holds_what_the_body_assigns_alone(self):
        # y01-y03: a call's values are its caller's at the call, which the table
        # at the body cannot know, so it claims none of them.
        self.assertEqual(wv.Values(), at_use('T=x; f() { sh "$T"; }; T=cuda_1.run; f'))
        for script in ('T=x; f() { T=cuda_1.run; sh "$T"; }; f',
                       'f() { local T=cuda_1.run; sh "$T"; }; f'):
            with self.subTest(script=script):
                self.assertEqual({"T": ["cuda_1.run"]}, at_use(script).scalars)
        nested = 'f() {\n  g() { T=z; }\n  T=y\n  sh "$T"\n}\nf'
        self.assertEqual({"T": ["y"]}, at_use(nested).scalars)
        # The `if` around the definition is not around the call: `T=x` is sure.
        inside = 'if c; then\n  f() {\n    T=x\n    sh "$T"\n  }\nfi\nf'
        self.assertEqual({"T": ["x"]}, at_use(inside).scalars)
        # q03: a subshell body ends where its parentheses close, and a `{ }` body
        # where its `}` does, at the step's end too or opened on its own line.
        rows = {'T=cuda_1.run\ng() ( T=x )\nsh "$T"': ["cuda_1.run"],
                'T=a\ng() ( T=b; sh "$T" )\ng': ["b", ""],
                'T=a\ng() (\n  :\n)\nT=b\nsh "$T"': ["b"],
                'T=x; f() { T=cuda_1.run; sh "$T"; }': ["cuda_1.run"],
                'T=x\nf()\n{\n  T=y\n  sh "$T"\n}\nf': ["y"]}
        for script, expected in rows.items():
            with self.subTest(script=script):
                self.assertEqual(expected, at_use(script).scalars["T"])

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

    def test_workflow_uses_re_exports_the_table(self):
        for name in ("Values", "assigned", "record", "valued", "valued_argvs"):
            with self.subTest(name=name):
                self.assertIs(getattr(wv, name), getattr(wu, name))


if __name__ == "__main__":
    unittest.main()
