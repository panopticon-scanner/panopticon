"""#2425, #2489: the step's literal assignments and array literals as bounded value facts.

`workflow_values` is the table a walk reads a `$T` or a `"${a[@]}"` through:
per name, the candidate texts the step's own assignments leave
(`T=cuda_1.run`, `p=./cuda_*.run`), and the candidate word-lists of its
array literals (`declare -a a=(sh tool)`); `workflow_uses.static_values` is
that table live at one statement. These are its unit pins -- what a stage
assigns, when a value is held and when it is emptied, how one word
resolves, how an argv is spliced -- then the caller's side of the contract
(`workflow_uses._resolved`, a call's `start`, the `-c` stdin rule) and the
guard's rows: `uses()` reads a stage through the table where the stage as
written names no use. A guard row's comment carries its truth, b5 b3 dash gh
(bash 5.2.21, bash 3.2.57, dash, a GitHub runner's bash with `sh` = dash;
FR fetched and ran the download, F- fetched only), and main's answer.
"""
import unittest

import shell_reader
import workflow_guard as wg
import workflow_uses as wu
import workflow_values as wv
from workflow_operands import _Reparsed

URL = "https://example.test/"
GET = "curl -fsSLo cuda_1.run %scuda_1.run\n" % URL
TOOL = "curl -fsSLo tool %stool\n" % URL
SH = "running it under `sh`"


def statements(script):
    return list(shell_reader.statements(script))


def defects(script):
    """The guard's sentences for a job of one step."""
    return [why for _name, why in wg.job_defects([("step", script)])]


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

    def test_a_coprocess_assigns_the_words_its_compound_opens_with(self):
        # s08: the words after `coproc [NAME] {` or `(` are read as a lead `{`'s;
        # a prefix assignment stays one, and `coproc a=(x)`, a simple command,
        # opens no compound.
        rows = {"coproc { T=x; }": ({"T": (False, "x")}, {}),
                "coproc W { T=x; }": ({"T": (False, "x")}, {}),
                "coproc ( T=x )": ({"T": (False, "x")}, {}),
                "coproc W ( T=x )": ({"T": (False, "x")}, {}),
                "{ coproc { T=x; }; }": ({"T": (False, "x")}, {}),
                "coproc { a=(x y); }": ({}, {"a": (False, ["x", "y"])}),
                "coproc { T=x sh foo; }": ({}, {}), "coproc a=(x)": ({}, {}),
                "coproc T=x": ({}, {})}
        for script, expected in rows.items():
            with self.subTest(script=script):
                self.assertEqual(expected, wv.assigned(statements(script)[0].stages[0]))


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
        # `${X:-a,b}` is a reference, no brace group; one beside a group rides along,
        # and a braced one beside it, or one inside it, cannot be expanded.
        self.assertEqual({"a": [["${X:-a,b}"]]}, table("a=(${X:-a,b})").arrays)
        self.assertEqual(["a$X", "b$X"], wv._braced("{a,b}$X"))
        self.assertEqual([None, None], [wv._braced("{a,b}${X}"), wv._braced("{a,$X}")])

    def test_a_literal_its_later_lines_continue_is_unseen(self):
        # m05: bash runs `sh -e cuda_1.run`; the words on the lines after the
        # opener's are not gathered, so the use stays as written. m06 is read.
        values = at_use('args=(\n  -e cuda_1.run\n)\nsh "${args[@]}"')
        self.assertEqual(({"args": ["$args"]}, {}), (values.scalars, values.arrays))
        self.assertEqual([["sh", "${args[@]}"]], wv.valued_argvs(["sh", "${args[@]}"], values))
        self.assertEqual({"args": [["-e", "cuda_1.run"]]}, table("args=(-e cuda_1.run)").arrays)
        rows = {"a=(cuda_1.run\n  x\n)": ({"a": ["$a"]}, {}),
                "declare -a a=(\n  x\n)": ({"a": ["$a"]}, {}),
                "a=(x) b=(\n  y\n)": ({"b": ["$b"]}, {"a": [["x"]]}),
                # A subshell opened on a one-line literal's line is no open literal.
                "arr=(p)\n( arr=(a b)\n)": ({}, {"arr": [["p"], ["a", "b"]]})}
        for script, expected in rows.items():
            with self.subTest(script=script):
                values = table(script)
                self.assertEqual(expected, (values.scalars, values.arrays))

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

    def test_a_stand_in_has_no_word_past_zero(self):
        # A named limit: the stand-in a maybe `read -ra` gives stands for
        # `${arr[0]}` but has no word 1, so `${arr[1]}` reads the literal's alone.
        values = at_use('arr=(x y)\nif c; then read -ra arr < f; fi\nsh "${arr[1]}"')
        self.assertEqual(({"arr": ["$arr"]}, {"arr": [["x", "y"]]}),
                         (values.scalars, values.arrays))
        self.assertEqual([["sh", "y"]], wv.valued_argvs(["sh", "${arr[1]}"], values))
        self.assertEqual([["sh", "x"], ["sh", "$arr"]],
                         wv.valued_argvs(["sh", "${arr[0]}"], values))

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
        # a literal's lines inside, z05 and its twins an `&&` list sent off whole,
        # f02, f03, f09 and theirs a compound sent off or piped whole from its head,
        # t05 and its twin one piped into, and a coprocess's (s08), whose close, or
        # a `select`'s or a function's (s09), closes no outer compound; a function
        # body defined after a keyword on its line runs only where it is called.
        z04 = 'T=cuda_1.run\n(\n  arr=(\n    a\n  )\n  T=x\n)\nsh "$T"'
        for script in ('T=cuda_1.run; ( :; T=x; : ); sh "$T"',
                       'T=cuda_1.run\n(\n  T=x\n)\nsh "$T"',
                       'T=cuda_1.run; { T=x; } &\nwait; sh "$T"',
                       'T=cuda_1.run; { T=x; } | cat; sh "$T"', z04,
                       'T=cuda_1.run; { T=x; } && : &\nwait; sh "$T"',
                       'T=cuda_1.run; T=x || : &\nwait; sh "$T"',
                       'T=cuda_1.run; T=x &&\n: &\nwait; sh "$T"',
                       'T=cuda_1.run; if T=x; then :; fi &\nwait; sh "$T"',
                       'T=cuda_1.run; while T=x; false; do :; done &\nwait; sh "$T"',
                       'T=cuda_1.run; if T=x; then :; fi | cat\nsh "$T"',
                       'T=cuda_1.run; until T=x; do :; done | cat\nsh "$T"',
                       'T=cuda_1.run; for T in x; do :; done &\nwait; sh "$T"',
                       'T=cuda_1.run; coproc { :; T=x; }\nwait; sh "$T"',
                       'T=cuda_1.run; coproc W { :; T=x; }\nwait; sh "$T"',
                       'T=cuda_1.run; { T=x; coproc { :; }; } &\nwait; sh "$T"',
                       'T=cuda_1.run; while T=x; false; do select v in a; do break; done; done &'
                       '\nwait; sh "$T"',
                       'T=cuda_1.run; echo | { :; T=x; }; sh "$T"',
                       'T=cuda_1.run; echo | if :; T=x; then :; fi; sh "$T"',
                       'T=cuda_1.run; coproc { T=x; sh "$T"; }\nwait; sh "$T"',
                       'T=cuda_1.run; coproc W { T=x; }\nwait; sh "$T"',
                       'T=cuda_1.run; { f() { :; }; T=x; } &\nwait; sh "$T"',
                       'T=cuda_1.run; {\n  f() {\n    :\n  }\n  T=x\n} &\nwait; sh "$T"',
                       'T=cuda_1.run; { f() { :; T=x; }; }; sh "$T"'):
            with self.subTest(script=script):
                self.assertEqual(["cuda_1.run", "x"], at_use(script).scalars["T"])
        self.assertEqual(["$arr", ""], at_use(z04).scalars["arr"])
        # A use in the same child sees what the child assigned before it as its own.
        for script in ('T=a; { T=x; sh "$T"; } &', 'T=a\n(\n  T=x\n  sh "$T"\n)',
                       'T=a; T=x && sh "$T" &', 'T=a; if T=x; then sh "$T"; fi &',
                       'T=a; coproc { T=x; sh "$T"; }\nwait', 'T=a; coproc W { T=x; sh "$T"; }'):
            with self.subTest(script=script):
                self.assertEqual({"T": ["x"]}, at_use(script).scalars)
        # A `( )` opener's own stage is unsure, a coprocess's too.
        self.assertEqual(["a", "x"], at_use('T=a; coproc ( T=x; sh "$T" )').scalars["T"])
        # s01, s03-s06: a use in a later stage of the statement that closes the child
        # is outside it; t06, a use inside a `( )` whose closing line pipes on, gains
        # the old value too (a price).
        later = {'T=cuda_1.run; { T=x; } | sh "$T"': 2,
                 'T=cuda_1.run\n(\n  T=x\n) | sh "$T"': 3,
                 'T=cuda_1.run; { T=x; } | { sh "$T"; }': 2,
                 'T=cuda_1.run; if T=x; then :; fi | sh "$T"': 3,
                 'T=cuda_1.run; for T in x; do :; done | sh "$T"': 3}
        for script, index in later.items():
            with self.subTest(script=script):
                self.assertEqual(["cuda_1.run", "x"], table(script, index).scalars["T"])
        t06 = 'T=a; ( :; T=cuda_1.run; sh "$T" ) | cat'
        self.assertEqual(["a", "cuda_1.run"], at_use(t06).scalars["T"])
        for script in ('T=cuda_1.run; { T=x; }; sh "$T"', 'T=cuda_1.run; { T=x; } && :; sh "$T"',
                       'T=cuda_1.run; if T=x; then :; fi\nsh "$T"',
                       # A `{` word in a group's command opens no function body.
                       'T=cuda_1.run; { echo {; T=x; }; sh "$T"',
                       # A list is not followed past a compound command (a limit).
                       'T=cuda_1.run; T=x && if c; then :; fi &\nwait; sh "$T"',
                       'T=cuda_1.run; T=x && { :; } &\nwait; sh "$T"',
                       # v02: a block nested in a one-line function's body inside a
                       # forked group is taken to close that body (a limit: bash
                       # runs `cuda_1.run`).
                       'T=cuda_1.run; { f() { { :; }; }; T=x; } &\nwait; sh "$T"'):
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
                # Past the condition's later commands (l3's twin).
                'T=x; while sh "$T"; c; do T=cuda_1.run; done': ["x", "cuda_1.run"],
                # A later command of the condition, or one on the lines after a bare
                # `while`, is not found (a limit).
                'T=x; while a; b "$T"; do T=y; done': ["x"],
                'T=x; while\n  sh "$T"\ndo\n  T=y\ndone': ["x"]}
        for script, expected in rows.items():
            with self.subTest(script=script):
                self.assertEqual(expected, at_use(script).scalars["T"])
        # l3 at its condition's first command, `sh "$T"` (`at_use` takes `[ $n -lt 3 ]`).
        l3 = 'T=x; while sh "$T" 2>/dev/null; n=$((n+1)); [ $n -lt 3 ]; do T=cuda_1.run; done'
        self.assertEqual(["x", "cuda_1.run"], table(l3, 1).scalars["T"])

    def test_a_serial_reassignment_before_the_use_in_its_loop_body_is_sure(self):
        # g01: bash surely ran it on the pass that reaches the use. One that may
        # not run, or runs in a child, adds, as main reads them; so does one in a
        # nested loop's body (a limit), and after the loop each word stays (r11).
        both = ["./cuda_*.run", "other.run"]
        rows = {'for f in ./cuda_*.run; do f=other.run; sh "$f"; done': ["other.run"],
                'while read -r f; do f=other.run; sh "$f"; done < list': ["other.run"],
                'for f in ./cuda_*.run; do f=other.run; sh "$f"; done | tee log': ["other.run"],
                'for f in a; do f=b; if c; then sh "$f"; fi; done': ["b"],
                'for f in ./cuda_*.run; do false && f=other.run; sh "$f"; done': both,
                'for f in ./cuda_*.run; do if false; then f=other.run; fi; sh "$f"; done': both,
                'for f in ./cuda_*.run; do ( f=other.run ); sh "$f"; done': both,
                'for f in ./cuda_*.run; do while false; do f=other.run; done; sh "$f"; done': both,
                'for i in 1; do for f in ./cuda_*.run; do f=other.run; sh "$f"; done; done':
                    both,
                'for f in ./cuda_*.run; do f=other.run true; sh "$f"; done': ["./cuda_*.run"],
                'f=x; for i in 1; do f=a; done; sh "$f"': ["x", "a"],
                'for i in 1; do while c; do f=a; done; sh "$f"; done': ["a", ""]}
        for script, expected in rows.items():
            with self.subTest(script=script):
                self.assertEqual(expected, at_use(script).scalars["f"])

    def test_a_function_body_holds_what_the_body_assigns_alone(self):
        # y01-y03: a call's values are its caller's at the call, which the table
        # at the body cannot know, so it claims none of them -- in a `( )` body
        # opened on the next line too, and k8's `{ }` after `function g()`: the
        # use reads as written, the stand-in.
        for script in ('T=x; f() { sh "$T"; }; T=cuda_1.run; f',
                       'T=x\ng()\n(\n  sh "$T"\n)\nT=cuda_1.run\ng',
                       'T=x\nfunction g\n(\n  sh "$T"\n)\nT=cuda_1.run\ng',
                       'T=a\nfunction g()\n{\n  sh "$T"\n}\nT=cuda_1.run\ng'):
            with self.subTest(script=script):
                self.assertEqual(wv.Values(), at_use(script))
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
        # where its `}` does, at the step's end too or opened on its own line;
        # n2, n3, n1: a subshell body opened on the next line, or holding a group.
        rows = {'T=cuda_1.run\ng() ( T=x )\nsh "$T"': ["cuda_1.run"],
                'T=a\ng() ( T=b; sh "$T" )\ng': ["b", ""],
                'T=a\ng() (\n  :\n)\nT=b\nsh "$T"': ["b"],
                'T=x; f() { T=cuda_1.run; sh "$T"; }': ["cuda_1.run"],
                'T=x\nf()\n{\n  T=y\n  sh "$T"\n}\nf': ["y"],
                'T=x\ng()\n(\n  T=y\n)\nT=cuda_1.run\nsh "$T"': ["cuda_1.run"],
                'T=x\ng()\n(\n  T=cuda_1.run\n  sh "$T"\n)\ng': ["cuda_1.run"],
                'T=x\ng() (\n  { T=cuda_1.run; }\n  sh "$T"\n)\ng': ["cuda_1.run"],
                'T=x\ng() (\n  { T=cuda_1.run; }\n  sh "$T"\n)\ng\nsh "$T"': ["x"],
                'function g\n(\n  T=y\n)\nT=b\nsh "$T"': ["b"]}
        # u1-u6: a body that is neither `{ }` nor `( )` is walked as the code around
        # it, never sure outside it; u5's use inside reads the code before it too.
        body = 'T=cuda_1.run\nsh "$T"'
        rows.update({'T=a\ng()\nif c; then T=y; fi\n' + body: ["cuda_1.run"],
                     'T=a\ng() if c; then T=y; fi\n' + body: ["cuda_1.run"],
                     'T=a\ng() for i in 1; do :; done\n' + body: ["cuda_1.run"],
                     'T=a\ng() [[ -n x ]]\n' + body: ["cuda_1.run"],
                     'T=a\ng() while false\ndo\n  :\ndone\n' + body: ["cuda_1.run"],
                     'T=a\ng()\nif arr=(a b); then\n  T=cuda_1.run\n  sh "$T"\nfi\ng':
                         ["a", "cuda_1.run"],
                     'T=cuda_1.run\ng() for T in x; do :; done\nsh "$T"': ["cuda_1.run", "x"],
                     'T=cuda_1.run\ng()\nif T=x; then :; fi\nsh "$T"': ["cuda_1.run", "x"],
                     'T=cuda_1.run\nfunction g\nwhile T=x; false; do :; done\nsh "$T"':
                         ["cuda_1.run", "x"],
                     'T=cuda_1.run\ng()\n(\n  T=y\n)\nif T=x; then :; fi\nsh "$T"': ["x"],
                     # h6: a `g ()` header marks its body too.
                     'T=cuda_1.run\ng () for T in x; do :; done\nsh "$T"': ["cuda_1.run", "x"]})
        # k1, k2, w2: a `function g()` header's own `()` opens no `( )` body;
        # k7: a call's own assignments are not read (a price: bash runs `x`).
        rows.update({'T=cuda_1.run\nfunction g()\n{\n  T=x\n}\nsh "$T"': ["cuda_1.run"],
                     'T=cuda_1.run\nfunction g ()\n{\n  T=x\n}\nsh "$T"': ["cuda_1.run"],
                     'T=cuda_1.run\nfunction g()\nwhile T=x; false; do :; done\nsh "$T"':
                         ["cuda_1.run", "x"],
                     'T=cuda_1.run\nfunction g()\n{\n  T=x\n}\ng\nsh "$T"': ["cuda_1.run"]})
        # Limits: b2p, a one-line `function f {` after a `{`, is read to the group's
        # `}` (bash runs `x`); k3, a `g ( )` header, is no definition (bash runs
        # `cuda_1.run`).
        rows.update({'T=cuda_1.run; { function f { :; }; T=x; }\nsh "$T"': ["cuda_1.run"],
                     'T=cuda_1.run\ng ( )\n{\n  T=x\n}\nsh "$T"': ["x"]})
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

    def test_a_call_hands_the_body_its_table_as_start(self):
        # `_function_use` passes the caller's table at the call: a body index starts
        # from a copy of it, which the walk does not write back.
        stmts = statements('f() {\n  sh "$T"\n  T=y\n  sh "$T"\n}\nf')
        start = table("T=cuda_1.run")
        self.assertEqual({"T": ["cuda_1.run"]}, wu.static_values(stmts, 1, start=start).scalars)
        self.assertEqual({"T": ["y"]}, wu.static_values(stmts, 3, start=start).scalars)
        self.assertEqual({"T": ["cuda_1.run"]}, start.scalars)
        # y01: no call context is the empty table; outside a body `start` is not read.
        self.assertEqual(wv.Values(), wu.static_values(stmts, 1))
        self.assertEqual(wv.Values(), wu.static_values(stmts, 5, start=start))

    def test_a_copy_keeps_a_lifted_substitution(self):
        # `copy.deepcopy` cannot rebuild a marked text; `Values.copy` keeps the object.
        values = table("T=$(pwd)/cuda_1.run; a=(x y)")
        copied = values.copy()
        self.assertEqual(values, copied)
        self.assertIs(values.scalars["T"][0], copied.scalars["T"][0])
        self.assertIsNot(values.arrays["a"], copied.arrays["a"])
        self.assertIsNot(values.arrays["a"][0], copied.arrays["a"][0])


class TestTheCallersContract(unittest.TestCase):
    """`workflow_uses._resolved`: the argvs `use()` weighs after a stage as
    written, on the terms `valued_argvs` leaves its caller, and the made argvs it
    drops beyond them: one headed by an assignment the table put there, the
    command bash runs (behind a written `env`, the wrapper's), and a shell whose
    `-c` string is a bare printer."""

    def resolved(self, script, argv):
        return list(wu._resolved(argv, table(script)))

    def test_nothing_is_made_where_nothing_resolves(self):
        for argv in (["sh", "x"], ["sh", "$INPUT"], ["sh", "${T#x}"], []):
            with self.subTest(argv=argv):
                self.assertEqual([], self.resolved("T=cuda_1.run", argv))

    def test_without_a_blank_the_argvs_are_valued_argvs(self):
        script = "T=cuda_1.run; false && T=x; arr=(sh tool); E="
        for argv in (["sh", "$T"], ["${arr[@]}", "$T"], ["$E", "sh", "${T}x"], ["sh", "x$T"]):
            with self.subTest(argv=argv):
                self.assertEqual(wv.valued_argvs(argv, table(script)), self.resolved(script, argv))

    def test_one_whole_reference_splits_on_its_values_blanks(self):
        # Bash splits an unquoted `$CMD`; the quoted twin over-reports (a price).
        rows = {"$CMD": ["sh", "cuda_1.run"], "${CMD}": ["sh", "cuda_1.run"],
                "${CMD:-x}": ["sh", "cuda_1.run"], "${a[0]}": ["sh", "cuda_1.run"]}
        for word, expected in rows.items():
            with self.subTest(word=word):
                script = "CMD='sh  cuda_1.run'; a=('sh cuda_1.run')"
                self.assertEqual([expected], self.resolved(script, [word]))
        # Text around a reference keeps its blanks, as a `-c` string's does.
        self.assertEqual([["sh", "-c", 'sh "cuda_1.run x"']],
                         self.resolved("T='cuda_1.run x'", ["sh", "-c", 'sh "$T"']))
        self.assertEqual([["sh", "./cuda_1.run x"]],
                         self.resolved("T='cuda_1.run x'", ["sh", "./$T"]))
        # A part bash globs is a live pattern, the rest plain.
        (argv,) = self.resolved("p='./cuda_*.run x'", ["sh", "$p"])
        self.assertEqual(["sh", "./cuda_*.run", "x"], argv)
        self.assertEqual([_Reparsed, str], [type(word) for word in argv[1:]])

    def test_a_made_argv_is_read_again_and_one_left_empty_is_dropped(self):
        # A resolved first word may be a wrapper, whose assignments are its own, and `$E`
        # may vanish.
        self.assertEqual([["sh", "x"]], self.resolved("W=env", ["$W", "sh", "x"]))
        self.assertEqual([["sh", "x"]], self.resolved("W=env; A=T=y", ["$W", "$A", "sh", "x"]))
        self.assertEqual([], self.resolved("E=", ["$E"]))
        # bash runs the command `T=y`: an expansion is never an assignment.
        self.assertEqual([], self.resolved("A=T=y", ["$A", "sh", "x"]))
        # Nor is a split value's first word, or a written one an empty value leaves first.
        self.assertEqual([], self.resolved("CMD='T=y sh x'", ["$CMD"]))
        self.assertEqual([], self.resolved("E=", ["$E", "T=y", "sh", "x"]))

    def test_a_made_shell_whose_dash_c_string_only_prints_is_dropped(self):
        # The `-c` printer rule is the table's: a made `sh -c 'cat'` adds no stdin row; a
        # printer that names an operand is no bare one, and its argv is kept.
        self.assertEqual([], self.resolved("CMD=sh", ["$CMD", "-c", "cat"]))
        self.assertEqual([], self.resolved("S=tee", ["sh", "-c", "$S"]))
        self.assertEqual([["sh", "-c", "sh"]], self.resolved("CMD=sh", ["$CMD", "-c", "sh"]))
        self.assertEqual([["sh", "-c", 'cat "$0"', "x"]],
                         self.resolved("T=x", ["sh", "-c", 'cat "$0"', "$T"]))

    def test_a_shells_dash_c_string_is_its_program(self):
        # The `-c` printer rule the table applies to an argv it made: ONE bare `cat` or
        # `tee` (no operand but `-`, no redirection) only hands its input on as data and
        # reads no program off standard input; every other string still may, fail-closed
        # as main read them all: a printer with an operand or a redirection (`cat "$0"`,
        # `tee x`, `cat > x`), a wrapper `command()` keeps (`builtin .`, `busybox sh`) and
        # a reader the guard does not list (`csh`, `sudo -s`) report, and so, the price,
        # does a command the rule does not know (`echo sh`, `awk -f`).
        rows = {("sh", "-c", "cat"): False, ("bash", "-ec", "cat -"): False,
                ("sh", "-c", "tee x"): True, ("sh", "-c", "T=x"): False,
                ("sh", "-c", 'cat "$0"'): True, ("sh", "-c", "cat > x"): True,
                ("sh", "-c", "sh"): True, ("sh", "-c", "exec bash -s"): True,
                ("sh", "-c", "$CMD"): True, ("sh", "-c", "cat | sh"): True,
                ("sh", "-c", "cat; sh"): True, ("sh", "-c", "source /dev/stdin"): True,
                ("sh", "-c", "python3"): True, ("sh", "-c", "builtin . /dev/stdin"): True,
                ("sh", "-c", "busybox sh"): True, ("sh", "-c", "csh"): True,
                ("sh", "-c", "sudo -s"): True, ("sh", "-c", "echo sh"): True,
                # unknown to the rule, main's report kept:
                ("sh", "-c", "awk -f /dev/stdin"): True,
                ("sh",): True, ("eval", "cat"): True, ("python3", "-c", "x"): True}
        for argv, expected in rows.items():
            with self.subTest(argv=argv):
                self.assertIs(expected, wu._on_stdin(list(argv)))


class TestADownloadNamedThroughAValue(unittest.TestCase):
    """#2425 and the #2581 rows: `uses()` reads a stage through the step's own
    values where the stage as written names no use."""

    def assertReports(self, script, how=SH, dest="cuda_1.run"):
        found = defects(script)
        self.assertEqual(1, len(found), found)
        self.assertIn("-> %s and %s with nothing verifying" % (dest, how), found[0])

    def test_a_value_the_step_assigns_names_the_download(self):
        # Main CLEAN on every row.
        rows = ('T=cuda_1.run\nsh "$T"\n',                              # t01   FR FR FR FR
                'export T=cuda_1.run\nsh "$T"\n',                       # t05a  FR FR FR FR
                'declare T=cuda_1.run\nsh "$T"\n',                      # t05b  FR FR F- FR
                'readonly T=cuda_1.run\nsh "$T"\n',                     # t05c  FR FR FR FR
                'f() { local T=cuda_1.run; sh "$T"; }\nf\n',            # t05d  FR FR FR FR
                'T="$PWD/cuda_1.run"\nsh "$T"\n',                       # t07   FR FR FR FR
                "p=./cuda_*.run\nsh $p\n",                              # t08   FR FR FR FR
                "X='*'\nsh ./cuda_$X.run\n",                            # t09   FR FR FR FR
                "sh ./cuda_${X:-*}.run\n",                              # t10   FR FR FR FR
                'T=cuda_1.run\nfalse && T=other.run\nsh "$T"\n',        # t11   FR FR FR FR
                'T=cuda_1\nT+=.run\nsh "$T"\n',                         # t17   FR FR F- FR
                "export T=cuda_1.run\nsh -c 'sh \"$T\"'\n",             # t29b  FR FR FR FR
                'T=cuda_1.run\nsh -c "sh $T"\n',                        # t29c  FR FR FR FR
                'U=cuda_1.run\nT=$U\nsh "$T"\n',                        # t30   FR FR FR FR
                'T=cuda_1.run\n( T=other.run )\nsh "$T"\n',             # t31   FR FR FR FR
                'for T in cuda_1.run; do sh "$T"; done\n',              # tf1   FR FR FR FR
                'if false; then F=x; fi\nsh "${F:-./cuda_1.run}"\n',    # td1   FR FR FR FR
                # FR FR FR FR: a glob written beside a reference stays live.
                "X=cuda\np=./${X}_*.run\nsh $p\n")
        for use in rows:
            with self.subTest(use=use):
                self.assertReports(GET + use)
        # t06 FR FR FR FR: the first use is the `chmod`.
        self.assertReports(GET + 'T=./cuda_1.run\nchmod +x "$T"\n"$T"\n', "making it executable")

    def test_a_whole_reference_splits_and_a_made_argv_is_read_again(self):
        # Main CLEAN on each. n01, n04 FR FR FR FR: bash splits the unquoted value;
        # n03 FR FR FR FR: `env` is a wrapper the made argv is read through.
        for use in ("CMD='sh cuda_1.run'\n$CMD\n", "T='cuda_1.run x'\nsh $T\n",
                    "W=env\n$W sh cuda_1.run\n"):
            with self.subTest(use=use):
                self.assertReports(GET + use)

    def test_a_call_carries_its_table_into_the_body(self):
        # Main CLEAN on each, the value at CALL time: fu1, fu2, n09 (a lifted `$(...)`
        # in the value) and n10 (a body defined before the fetch) FR FR FR FR.
        for script in (GET + 'T=cuda_1.run\nf() { sh "$T"; }\nf\n',
                       GET + 'f() { sh "$T"; }\nT=cuda_1.run\nf\n',
                       GET + 'T="$(pwd)/cuda_1.run"\nf() { sh "$T"; }\nf\n',
                       'T=cuda_1.run\nf() { sh "$T"; }\n' + GET + "f\n"):
            with self.subTest(script=script):
                self.assertReports(script)
        # fu3 F- F- F- F-: `T=x` before the call; gx F- F- F- F-: the table closes
        # the `( )` body that main's `_function_ranges` reads to the step's end.
        for use in ('T=cuda_1.run\nf() { sh "$T"; }\nT=x\nf\n',
                    'T=cuda_1.run; g() ( : ); T=x; sh "$T"\n'):
            with self.subTest(use=use):
                self.assertEqual([], defects(GET + use))

    def test_a_value_that_names_no_download_stays_clean(self):
        # Main CLEAN on each, F- F- F- F- on each but t16's F-+sha F-+sha F-+sha F-.
        check = 'echo "%s  cuda_1.run" | sha256sum -c -\n' % ("a" * 64)
        for use in ('T=other.run\nsh "$T"\n',                           # t02
                    'T=cuda_1.run\nT=x\nsh "$T"\n',                      # t03
                    'sh "$INPUT"\n',                                     # t04
                    'T=cuda_1.run\nmkdir -p sub\ncd sub\nsh "$T"\n',     # t13
                    'T=cuda_1.run sh "$T"\n',                            # t14: a prefix
                    'T=cuda_1.run true\nsh "$T"\n',                      # n07: never a value
                    'T=cuda_1.run\nunset T\nsh "$T"\n',                  # t15a
                    'T=cuda_1.run\nread -r T < /dev/null || true\nsh "$T"\n',    # t15b
                    'T=cuda_1.run\n' + check + 'sh "$T"\n',              # t16: binds by name
                    'sh "$GITHUB_WORKSPACE/scripts/x.sh"\n',             # t28
                    "T='cuda_{1,2}.run'\nsh $T\n",                       # t32: no brace in a value
                    # h58, h59: bash runs `X=1` and `FOO=1`, as an empty `$E` leaves `X=1` to run
                    'A=X=1\n$A sh cuda_1.run || :\n', "CMD='FOO=1 sh cuda_1.run'\n$CMD || :\n",
                    'E=\n$E X=1 sh cuda_1.run || :\n',
                    # a reference held as written is a plain word: bash runs `sh x`, `sh other.run`
                    '[[ x =~ (.*) ]]\nF=${BASH_REMATCH[1]}\nsh "$F" || :\n',
                    '[[ x =~ (.*) ]]\nF=${BASH_REMATCH[1]}\nsh $F || :\n',
                    'OTHER=%sother.run\nNAME=${OTHER##*/}\nsh "$NAME" || :\n' % URL,
                    'OTHER=%sother.run\nNAME=${OTHER##*/}\nsh $NAME || :\n' % URL,
                    'F=$U\nsh $F || :\n'):
            with self.subTest(use=use):
                self.assertEqual([], defects(GET + use))

    def test_a_made_assignment_behind_a_written_wrapper_is_the_wrappers(self):
        # m2a FR FR FR FR; main the same: a written `env` takes the made `X=1` as its own and runs
        # `sh`; the table makes no argv of it, and main's wrapper report stands (a precision price).
        found = defects(GET + "A=X=1\nenv $A sh cuda_1.run\n")
        self.assertEqual(1, len(found), found)
        self.assertIn("dynamic command operand behind a wrapper", found[0])

    def test_the_prices_over_report(self):
        # Main CLEAN on each, and bash runs nothing (F- F- F- F-): t08q, t09q and n02
        # lost their quotes to the reader (the quoting price), t12's `false &&` value
        # stays a candidate (a value the shell may not assign), and t29a's child sees no
        # `T`, unexported, which the table does not ask.
        for use in ('p=./cuda_*.run\nsh "$p"\n', "X='*'\nsh \"./cuda_$X.run\"\n",
                    "CMD='sh cuda_1.run'\n\"$CMD\"\n",
                    'T=other.run\nfalse && T=cuda_1.run\nsh "$T"\n',
                    "T=cuda_1.run\nsh -c 'sh \"$T\"'\n"):
            with self.subTest(use=use):
                self.assertReports(GET + use)
        # Main CLEAN on each -- the prices: h45 F- F- F- F-, a heredoc-fed child's own
        # assignment is read as the step's; k24 F- F- FR F-, `((i++))` is not read, so `T`
        # holds the old number; h15 F- F- F- F-, `set -f` is not read, so `$p` globs.
        for script, dest in (
                (GET + "sh <<'EOF'\nT=cuda_1.run\nEOF\nsh \"$T\" || :\n", "cuda_1.run"),
                ("curl -fsSLo cuda_0.run %scuda_0.run\ni=0\n((i++)) || :\nT=cuda_$i.run\n"
                 'sh "$T" || :\n' % URL, "cuda_0.run"),
                (GET + "set -f\np=./cuda_*.run\nsh $p || :\n", "cuda_1.run")):
            with self.subTest(script=script):
                self.assertReports(script, dest=dest)
        # n05o F- F- F- F-; main CLEAN; the -c child's own assignment is read as the
        # step's (its twin n05 hides a run).
        self.assertReports("curl -fsSLo x.run %sx.run\nT=cuda_1.run\nsh -c 'T=x.run'\n"
                           'sh "$T" || :\n' % URL, dest="x.run")

    def test_a_check_through_a_value_is_not_read(self):
        # F-+sha F-+sha F-+sha F-; main CLEAN -- the check through a value is not read (the
        # price); the code fix is a filed follow-up.
        for fetch, name, dest in (("curl -fsSLO %stool.sh\n" % URL, "F", "tool.sh"),
                                  (GET, "FILE", "cuda_1.run")):
            script = fetch + '%s=%s\necho "%s  $%s" | sha256sum -c -\nsh "$%s"\n' % (
                name, dest, "a" * 64, name, name)
            with self.subTest(dest=dest):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertIn("-> %s and running it under `sh`; no checksum in the job names %s,"
                              % (dest, dest), found[0])

    def test_a_value_the_table_cannot_see_reads_as_written(self):
        # The stand-in: main's answer, CLEAN, and no claim. y06, x16 and x14 are FR FR
        # FR FR (`"$@"` and `$(ls ...)` hold the download), which the guard misses as
        # main does; n05 and n08 FR FR FR FR are the limits a child's assignments
        # make: a `-c` string's are read as the step's (`T=x` replaces `cuda_1.run`;
        # its twin over-reports), and a `$(...)`'s are not read at all. h44 FR FR FR FR,
        # main CLEAN -- the named limit: the heredoc's `T=x` is read as the step's; k23
        # FR FR F- FR, main CLEAN -- the named limit: `((i++))` is not read, so `T` holds
        # `cuda_0.run`.
        for use in ('set -- cuda_1.run\nT=a; for T in "$@"; do :; done; sh "$T"\n',
                    'set -- cuda_1.run\nT=a; for T in "$@"; do sh "$T"; done\n',
                    'for T in $(ls ./*.run) x; do sh "$T"; done\n',
                    "T=cuda_1.run\nsh -c 'T=x'\nsh \"$T\"\n",
                    'x=$(T=cuda_1.run; sh "$T")\n',
                    "T=cuda_1.run\nsh <<'EOF'\nT=x\nEOF\nsh \"$T\"\n",
                    'i=0\n((i++)) || :\nT=cuda_$i.run\nsh "$T"\n'):
            with self.subTest(use=use):
                self.assertEqual([], defects(GET + use))
        # FR FR FR FR; main CLEAN -- `${URL##*/}` is not evaluated, the named limit; FR FR F-
        # FR, main CLEAN -- `BASH_REMATCH`, a name bash sets itself, is not read.
        fetch = 'URL=%scuda_1.run\ncurl -fsSLo cuda_1.run "$URL"\n' % URL
        for use in ('NAME=${URL##*/}\nsh "$NAME"\n',
                    '[[ $URL =~ /([^/]+)$ ]]\nF=${BASH_REMATCH[1]}\nsh "$F"\n'):
            with self.subTest(use=use):
                self.assertEqual([], defects(fetch + use))

    def test_the_use_as_written_is_weighed_first(self):
        # The use as written is weighed first: the fetch wrote the NAME, which only the
        # use as written spells; each is main's sentence, FR FR FR FR. p02, p04
        # (`chmod +x` first), p07, p08, p10.
        fetch = 'curl -fsSLo "%s" https://example.test/p\n'
        rows = (("T=cuda_1.run\n", "$T", 'sh "$T"\n', SH),
                ("T=./install.sh\n", "$T", 'chmod +x "$T"\n"$T"\n', "making it executable"),
                ("T=a.sh\nif c; then T=b.sh; fi\n", "$T", 'sh "$T"\n', SH),
                ("p=./cuda_1.run\n", "$p", "sh $p\n", SH),
                ("printf 'x.sh\\n' > f\nread -r T < f\n", "${T}", 'sh "${T}"\n', SH))
        for before, dest, use, how in rows:
            with self.subTest(before=before, dest=dest, use=use):
                found = defects(before + fetch % dest + use)
                self.assertEqual(["fetches https://example.test/p -> %s and %s with nothing "
                                  "verifying what arrived -- verify it first: `echo \"<sha256>"
                                  "  %s\" | sha256sum -c -` between the download and that use"
                                  % (dest, how, dest)], found)

    def test_a_brace_header_keeps_mains_answer(self):
        # Main's sentence on each, through the glob binding: the table hands the
        # header's name its stand-in. z01, z02, z03 and c1x FR FR F- FR; z03b FR FR F-
        # FR, CLEAN on main and here: the array holds its stand-in, no claim (a brace
        # word is expanded at record time).
        fetch = "curl -fsSLo %s https://example.test/%s\n"
        rows = (("install.sh", "bash", "s in {install,setup}${SUFFIX}.sh", 'bash "$s"'),
                ("install.sh", "bash", "s in {install,setup,$EXTRA}.sh", 'bash "$s" || :'),
                ("install.sh", "bash", "s in {install,setup}.sh", 'bash "$s"'),
                ("5.run", "sh", "T in {1..100}.run", 'sh "$T" 2>/dev/null || :'))
        for dest, shell, header, body in rows:
            with self.subTest(header=header):
                use = "for %s; do %s; done\n" % (header, body)
                self.assertReports(fetch % (dest, dest) + use, "running it under `%s`" % shell,
                                   dest)
        use = 'a=({1..100}.run); sh "${a[0]}"\n'
        self.assertEqual([], defects(fetch % ("1.run", "1.run") + use))

    def test_a_dash_c_string_is_the_program_of_a_redirected_shell(self):
        # The use as written keeps main's stdin reading; the `-c` printer rule is the
        # table's, for an argv it made. c01, c04 F- F- F- F-, main's over-report and the
        # price: the guard does not follow where a `-c` printer's stream goes, so main's
        # blanket report stays for the literal -- the table's resolved twin adds none.
        # c02 F- F- F- F-: main's one sentence, the value command word's.
        fetch = "curl -fsSLo i.sh %si.sh\n" % URL
        for use, shell in (("sh -c 'cat' < i.sh\n", "sh"), ("bash -c 'cat' < i.sh\n", "bash")):
            with self.subTest(use=use):
                self.assertReports(fetch + use, "running it under `%s` from standard input"
                                   % shell, "i.sh")
        found = defects(fetch + "CMD=sh\n$CMD -c 'cat' < i.sh\n")
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0].startswith("runs `$CMD` with `-c`"), found)
        # c03, n06 (`sh` reads it; `cat | sh` is not ONE command), then k01, k07, where the
        # printed stream is run: each FR FR FR FR, main's report, kept.
        for use in ("sh -c 'sh' < i.sh\n", "sh -c 'cat | sh' < i.sh\n",
                    "sh -c 'cat' < i.sh | sh\n", "sh -c 'cat > x.sh' < i.sh; sh x.sh\n"):
            with self.subTest(use=use):
                self.assertReports(fetch + use, "running it under `sh` from standard input",
                                   "i.sh")
        # f02 FR FR FR FR; main reported: an interpreter word past `builtin` reads it.
        self.assertReports(fetch + "bash -c 'builtin . /dev/stdin' < i.sh\n",
                           "running it under `bash` from standard input", "i.sh")
        # p11 FR FR FR FR, main CLEAN: a made `cat "$0"` prints the download, the table reports.
        self.assertReports(GET + "T=cuda_1.run\nsh -c 'cat \"$0\"' \"$T\" | sh\n",
                           "running it under `sh`", "cuda_1.run")
        # h01 FR FR FR FR; main reported: `csh` is no printer, so it reads the program.
        self.assertReports(fetch + "sh -c 'csh' < i.sh\n",
                           "running it under `sh` from standard input", "i.sh")


class TestADownloadNamedThroughAnArray(unittest.TestCase):
    """#2489 and the `${a[0]}` row: an array literal the step assigns, spliced
    or read by its element at the use."""

    def assertReports(self, script, dest="tool"):
        found = defects(script)
        self.assertEqual(1, len(found), found)
        self.assertIn("-> %s and %s with nothing verifying" % (dest, SH), found[0])

    def test_an_array_the_step_assigns_names_the_download(self):
        # Main CLEAN on each, FR FR F- FR (dash has no arrays): t20, t21, t22, ta1 and
        # ta2d -- `declare -a` stops main's literal-as-command read -- and t26.
        for use in ('declare -a arr=(sh tool)\n"${arr[@]}"\n',
                    'export arr=(sh tool)\n"${arr[@]}"\n',
                    'f() { local -a a=(sh tool); "${a[@]}"; }\nf\n',
                    'declare -a arr=(echo hi)\ndeclare -a arr=(sh tool)\n"${arr[@]}"\n',
                    'declare -a arr=(echo hi)\nif true; then declare -a arr=(sh tool); fi\n'
                    '"${arr[@]}"\n'):
            with self.subTest(use=use):
                self.assertReports(TOOL + use)
        self.assertReports(GET + 'a=(./cuda_*.run)\nsh "${a[0]}"\n', "cuda_1.run")

    def test_a_literal_main_reads_as_its_command_makes_one_row(self):
        # t24, ta2 FR FR F- FR: main reports each through the literal read as its
        # command; the splice adds no second row.
        for use in ('arr=(sh tool)\n"${arr[@]}"\n',
                    'arr=(echo hi)\nif true; then arr=(sh tool); fi\n"${arr[@]}"\n'):
            with self.subTest(use=use):
                self.assertReports(TOOL + use)
        # t27 FR FR -- FR, posthog's: main's sentence, the transfer it cannot parse.
        found = defects('fetch=(curl --fail --location)\n"${fetch[@]}" %stool --output tool\n'
                        "chmod +x tool\n./tool\n" % URL)
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0].startswith("runs `curl` with unresolved transfers"), found)

    def test_an_array_that_runs_no_download_stays_clean(self):
        # Main CLEAN, F- F- F- F-: t23 assigns and never runs; t25 runs `echo hi`.
        for use in ("declare -a arr=(sh tool)\n", 'declare -a arr=(echo hi)\n"${arr[@]}"\n'):
            with self.subTest(use=use):
                self.assertEqual([], defects(TOOL + use))

    def test_a_literal_alone_is_read_as_run_through_the_table(self):
        # F- F- F- F-; main CLEAN -- main's literal-as-run reading, widened by the table (the
        # price; the reader lane's follow-up).
        found = defects(GET + "X=_1\na=(cuda$X.run)\n")
        self.assertEqual(1, len(found), found)
        self.assertIn("-> cuda_1.run and running it with nothing verifying", found[0])

    def test_a_quoted_literal_word_over_reports(self):
        # t33, main CLEAN, F- F- F- F-: bash globs no quoted word; the reader lost the quotes.
        self.assertReports(GET + "a=('./cuda_*.run')\nsh \"${a[0]}\"\n", "cuda_1.run")


if __name__ == "__main__":
    unittest.main()
