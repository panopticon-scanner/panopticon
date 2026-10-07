"""`scripts/workflow_called.py`: what a called function may leave in the caller's value table
(#2664 fix rounds, #2785). Pins the one-way layering -- the module imports the value table, the
command layer and the wrappers' table, never the uses module or the guard -- and the fail-closed
carry's own rules: every assignment the body may make is added unsure and the caller's own kept;
`local` dies with the call; a wrapper in front of the name runs no function; a definition after
the call is no function yet; every definition before it counts; the functions a body calls are
followed to a bound; a subshell body reaches nothing."""
import ast
import os
import unittest

import shell_reader
import workflow_called
import workflow_uses
from workflow_values import Values


def stmts_of(script):
    return shell_reader.statements(script)


def called(script, at=-1):
    """The table after `record_called` at statement `at` of `script` (the call: its last)."""
    stmts = stmts_of(script)
    table = Values({"T": ["old"]})
    workflow_called.record_called(table, stmts, at % len(stmts), workflow_uses._function_ranges(stmts)[0])
    return table.scalars


class TestTheModuleSitsBelowTheUsesModule(unittest.TestCase):

    def test_it_imports_nothing_from_the_uses_module_or_the_guard(self):
        tree = ast.parse(open(workflow_called.__file__, encoding="utf-8").read())
        imported = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        imported |= {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
                     for alias in node.names}
        self.assertFalse(imported & {"workflow_uses", "workflow_guard", "workflow_forms"}, imported)
        self.assertEqual(os.path.basename(workflow_called.__file__), "workflow_called.py")


class TestWhatACallMayLeave(unittest.TestCase):

    def test_an_assignment_is_added_unsure_and_the_callers_value_kept(self):
        # The fail-closed carry (round 2's direction): a use after the call reads both.
        self.assertEqual({"T": ["old", "/tmp/p"]}, called("f() { T=/tmp/p; }\nf\n"))
        self.assertEqual({"T": ["old", "/tmp/p"]}, called("f()\n{\nT=/tmp/p\n}\nf\n"))
        self.assertEqual({"T": ["old", "/tmp/p"]}, called("g ( )\n{\nT=/tmp/p\n}\ng\n"))
        # Past a `return` the body takes, and under a condition inside the body, alike.
        self.assertEqual({"T": ["old", "/tmp/p"]}, called("f() { return; T=/tmp/p; }\nf\n"))
        self.assertEqual({"T": ["old", "/tmp/p"]}, called("f() { if c; then T=/tmp/p; fi; }\nf\n"))
        # A stand-in, `+=`, `unset` and `read`: each as an uncertain assignment is read.
        self.assertEqual({"T": ["old", "$1"]}, called("f() { T=$1; }\nf x\n"))
        self.assertEqual({"T": ["old", "oldb"]}, called("f() { T+=b; }\nf\n"))
        self.assertEqual({"T": ["old", ""]}, called("f() { unset T; }\nf\n"))
        self.assertEqual({"T": ["old", "$T"]}, called("f() { read T; }\nf\n"))

    def test_a_local_dies_with_the_call_where_declare_g_export_and_readonly_do_not(self):
        for script in ("f() { local T=x; }\nf\n", "f() { local T; T=x; }\nf\n", "f() { declare T=x; }\nf\n"):
            with self.subTest(script=script):
                self.assertEqual({"T": ["old"]}, called(script))
        for script in ("f() { declare -g T=x; }\nf\n", "f() { declare -gx T=x; }\nf\n",
                       "f() { export T=x; }\nf\n", "f() { readonly T=x; }\nf\n"):
            with self.subTest(script=script):
                self.assertEqual({"T": ["old", "x"]}, called(script))

    def test_a_wrapper_in_front_of_the_name_runs_no_function(self):
        for script in ("f() { T=x; }\nenv f\n", "f() { T=x; }\nsudo f\n", "f() { T=x; }\ntimeout 5 f\n",
                       "f() { T=x; }\ncommand f\n", "f() { T=x; }\nnice f\n", "f() { T=x; }\nnohup f\n"):
            with self.subTest(script=script):
                self.assertEqual({"T": ["old"]}, called(script))
        # A function named like a wrapper is the call bash makes of it (the round-4 seat's F5).
        self.assertEqual({"T": ["old", "x"]}, called("sudo() { T=x; }\nsudo y\n"))
        # `time` (one `-p`, then one `--`) and `eval` (one `--`), then a group, `!` or an
        # assignment: a call. A second `-p`, or a `-p` past the `--`, is the command, as
        # bash 5.2.21 reads it (round 6: the round-5 head stepped over any number).
        for line in ("time -p f", "time -- f", "time -p -- f", "time { f; }", "time X=1 f", "time ! f",
                     "time eval f", "eval time f", "eval -- f"):
            with self.subTest(line=line):
                self.assertEqual({"T": ["old", "x"]}, called("f() { T=x; }\n%s\n" % line, at=2))
        for line in ("time -p -p f", "time -- -p f", "time -- -- f", "eval -p f"):
            with self.subTest(line=line):
                self.assertEqual({"T": ["old"]}, called("f() { T=x; }\n%s\n" % line, at=2))
        # A keyword, a prefix assignment or a `case` arm in front is not a wrapper: the
        # function runs (the arm: the round-3 seat's C91).
        self.assertEqual({"T": ["old", "x"]}, called("f() { T=x; }\ncase y in y) f;; esac\n", at=3))
        self.assertEqual({"T": ["old", "x"]}, called("f() { T=x; }\nif f; then :; fi\n", at=2))
        self.assertEqual({"T": ["old", "x"]}, called("f() { T=x; }\nX=1 f\n"))

    def test_every_definition_before_the_call_counts_and_none_after(self):
        # Two conditional definitions: both bodies may run; the live one is not known.
        self.assertEqual({"T": ["old", "x", "y"]},
                         called("if c; then f() { T=x; }; else f() { T=y; }; fi\nf\n"))
        self.assertEqual({"T": ["old", "x"]}, called("f() { T=x; }\ntrue && f() { :; }\nf\n"))
        self.assertEqual({"T": ["old", "x"]}, called("f() { T=x; }\nif true; then f() { :; }; fi\nf\n"))
        # Defined after the call: bash has no such function at call time.
        self.assertEqual({"T": ["old"]}, called("f\nf() { T=x; }\n", at=0))

    def test_the_functions_a_body_calls_are_followed_to_a_bound(self):
        self.assertEqual({"T": ["old", "x"]}, called("g() { T=x; }\nf() { g; }\nf\n"))
        self.assertEqual({"T": ["old", "x"]}, called("h() { T=x; }\ng() { h; }\nf() { g; }\nf\n"))
        chain = "".join("f%d() { f%d; }\n" % (n, n + 1) for n in range(12)) + "f12() { T=x; }\nf0\n"
        self.assertEqual({"T": ["old"]}, called(chain), "past %d functions nothing is read" % workflow_called._DEPTH)
        near = "".join("f%d() { f%d; }\n" % (n, n + 1) for n in range(5)) + "f5() { T=x; }\nf0\n"
        self.assertEqual({"T": ["old", "x"]}, called(near))
        # Recursion ends at the bound too.
        self.assertEqual({"T": ["old", "x"]}, called("f() { T=x; f; }\nf\n"))

    def test_a_subshell_body_reaches_nothing(self):
        for script in ("f() ( T=x )\nf\n", "f() ( T=x; )\nf\n"):
            with self.subTest(script=script):
                self.assertEqual({"T": ["old"]}, called(script))

        # A `{` after the `(` (round 9, F2): still the subshell; a `(` the body's `}` outlives.
        for script in ("f() ( { T=x; } )\nf\n", "f() ( echo { ; T=x )\nf\n", "function f ( { T=x; } )\nf\n",
                       "f() ( { T=x; }; : )\nf\n"):
            with self.subTest(script=script):
                self.assertEqual({"T": ["old"]}, called(script))
        for script in ("f() { ( : ); T=x; }\nf\n", "f() { (T=y; U=z); T=x; }\nf\n", "f() { { T=x; }; }\nf\n"):
            with self.subTest(script=script):
                self.assertIn("x", called(script)["T"])      # a brace body: carried


def effects(script):
    """`_effects`' written names and `anything` for the bodies the step's last statement, a call,
    carries."""
    stmts = stmts_of(script)
    starts = workflow_uses._function_ranges(stmts)[0]
    return workflow_called._effects(stmts, workflow_called._reached(stmts, len(stmts) - 1, starts))[:2]


def snapshot(table):
    """`table` as a value to compare: each name's candidates, with the lifted markers each carries."""
    def texts(values):
        return tuple((str(text), tuple(sorted(getattr(text, "markers", {})))) for text in values)
    return (tuple(sorted((name, texts(values)) for name, values in table.scalars.items())),
            tuple(sorted((name, tuple(map(texts, lists))) for name, lists in table.arrays.items())))


class TestWhatACallSitesBodiesMaySet(unittest.TestCase):
    """Round 11 (the round-10 verdict's B3: the memo goes): a call site carries its bodies `_BUDGET`
    times a step, and past that each name they may set takes the cap's stand-in -- the names a dry
    carry, each name they spell held, shows them set (`_effects`), and where one may set a name it
    does not spell (`anything`), every name the table holds."""

    def test_the_names_a_body_sets(self):
        self.assertEqual(({"T"}, False), effects("X=1\ng() { T=$X; }\ng\n"))
        for body in (": 0; : 1", ": s0; : s1", "echo $X; : words here"):
            with self.subTest(body=body):
                self.assertEqual((frozenset(), False), effects("g() { %s; }\ng\n" % body))

    def test_a_write_the_body_does_not_spell_and_one_only_a_held_name_shows(self):
        self.assertIn("REPLY", effects("g() { read -r; }\ng\n")[0])            # bash's default name
        self.assertIn("T", effects("g() { unset T; }\ng\n")[0])                # a held name's "maybe unset"
        self.assertNotIn("T", effects("g() { local T; T=x; }\ng\n")[0])        # dies with the call

    def test_a_statement_that_may_set_any_name_sets_its_plain_names_too(self):
        # Round 11, the round-10 verdict's B1 (sets 59-61): `export "$K=v" X=P` may set any name, and
        # sets `X` as well -- in the bodies' names, and in the names a statement of the step may set.
        # (Every name such a statement spells shows set too: it may be.) In a body, a `declare` or
        # `typeset` without `-g` makes its names local, so only the step's own sets them for good.
        body = ('export "$K=v" X=P', 'export X=P "$K=v"', 'declare -g "$K=v" X=P', 'typeset -g "$K=v" X=P')
        for line in body:
            with self.subTest(line=line):
                written, anything = effects("g() { %s; }\ng\n" % line)
                self.assertTrue(anything)
                self.assertIn("X", written)
        for line in body + ('declare "$K=v" X=P', 'typeset "$K=v" X=P'):
            with self.subTest(line=line):
                self.assertIn("X", workflow_called._Step(stmts_of(line + "\n")).set_at(0))

    def test_a_carry_walks_the_statements_that_may_write_alone(self):
        # What a statement writes is its words' and whether the names it spells are held, so one
        # dry step tells, and a carry skips the rest: a K-statement body that sets one name costs
        # a carry that one statement (round 9).
        for line, writes in (("T=x", True), ("T+=x", True), ("A=(x y)", True), ("unset T", True),
                             ("local T", True), ("read -r", True), ("read -r T", True), ("eval :", True),
                             ("for i in a b; do :; done", True), ("printf -v T x", True),
                             ("mapfile T", True), ("readarray -t T", True), ("getopts ab T", True),
                             ("declare T=x", True), ("typeset T=x", True), ("export T=x", True),
                             ("readonly T=x", True), ("source ./env", True), (". ./env", True),
                             # where bash may write a name the step does not read: unsure, walked
                             (": ${T:=x}", True), (": ${T=x}", True), ("echo a${T:=x}b", True),
                             (": $(( T=1 ))", True), (": $[ T=1 ]", True), (": ${A[T=2]}", True),
                             ("A[i++]=y", True), ("let T=1", True), ("(( T++ ))", True),
                             ("(( T += 1 ))", True), ("cat > ${T:=f}", True), ("cat <<EOF\n$((T=1))\nEOF", True),
                             (": 0", False), ('echo "$X"', False), ('sh "$T"', False), ("f", False)):
            with self.subTest(line=line):
                self.assertEqual(writes, workflow_called._writes(stmts_of(line + "\n")[0], "____"))

    def test_a_carry_of_a_body_that_may_set_any_name_walks_the_names_it_spells(self):
        # Round 11: such a carry gives each name it does not spell its own stand-in apart, once a
        # walk, so it copies and walks only the names its bodies spell -- not the whole table.
        from unittest import mock
        real, given = workflow_called._carry, []

        def carry(table, stmts, head, close, positions=None, names=None):
            given.append(names)
            return real(table, stmts, head, close, positions, names)
        stmts = stmts_of("A=1\nB=2\ng() { eval :; T=$X; }\ng\n")
        with mock.patch.object(workflow_called, "_carry", carry):
            workflow_called.record_called(Values({"A": ["1"], "B": ["2"]}), stmts, len(stmts) - 1,
                                          workflow_uses._function_ranges(stmts)[0])
        self.assertTrue(given and given[-1] is not None and {"T", "X"} <= given[-1])
        self.assertFalse({"A", "B"} & given[-1])

    def test_a_body_that_may_set_any_name(self):
        for body in ('eval "$C"', ". ./env.sh", "source ./env.sh", 'export "$K=v"', 'read -r "$N"'):
            with self.subTest(body=body):
                self.assertTrue(effects("g() { %s; }\ng\n" % body)[1])


class TestEachVisitIsACarryOrTheStandIn(unittest.TestCase):
    """Round 11: within the budget, the table `record_called` leaves at every visit of a call site is
    the one a fresh carry of the same bodies leaves (round 8's semantics); past it, the one each name
    the bodies may set leaves holding the cap's stand-in on both sides -- where one may set any name,
    each name the table holds too -- though a walk stands each in once, then what changed since
    (`_Step.since`). Each script visits a site more than once: a later statement rebuilds the
    table, a loop walks its body again."""

    SCRIPTS = (
        "g() { read -r; }\ng\nsh \"$REPLY\"\nsh \"$REPLY\"\n",
        "T=a\ng() { T=$X; }\nfor i in 1 2; do\nX=a; g\nX=b; g\ndone\nsh \"$T\"\nsh \"$T\"\n",
        "T=a\ng() { unset T; }\nfor i in 1 2; do\nX=a; g\ndone\nsh \"${T:-x}\"\nsh \"$T\"\n",
        "V=1\ng() { eval :; }\ng\nsh \"$V\"\nsh \"$V\"\n",
        "g() { eval :; }\nfor i in 1 2; do\nV=a; g\nV=b; g\ndone\nsh \"$V\"\n",
        "A=(x)\ng() { A+=(y); }\nfor i in 1 2; do\nX=a; g\ndone\n\"${A[@]}\"\n",
        "h() { T=$X; }\ng() { h; }\nfor i in 1 2; do\nX=a; g\nX=b; g\ndone\nsh \"$T\"\n",
        # Two call sites of the same bodies: a redefinition between them (of the function or of
        # one it calls), `unset -f`, positional and indirect state, a nameref, a name taken from a
        # value or `eval`, an array's state.
        "f() { T=a; }\nf\nf() { T=P; }\nf\nsh \"$T\"\nsh \"$T\"\n",
        "h() { T=a; }\ng() { h; }\ng\nh() { T=P; }\ng\nsh \"$T\"\nsh \"$T\"\n",
        "f() { T=P; }\nf\nunset -f f\nf\nsh \"$T\"\nsh \"$T\"\n",
        "f() { T=$1; }\nf a\nf P\nsh \"$T\"\nsh \"$T\"\n",
        "f() { T=${!X}; }\nX=A\nf\nX=B\nf\nsh \"$T\"\nsh \"$T\"\n",
        "f() { declare -n R=X; R=P; }\nf\nf\nsh \"$X\"\nsh \"$X\"\n",
        "f() { printf -v \"$N\" %s P; }\nN=T\nf\nN=U\nf\nsh \"$T\"\nsh \"$U\"\n",
        "f() { eval \"$C\"; }\nC=T=P\nf\nC=U=P\nf\nsh \"$T\"\nsh \"$U\"\n",
        "f() { T=${A[1]}; }\nA=(a b)\nf\nA=(c P)\nf\nsh \"$T\"\nsh \"$T\"\n",
        # A body that may set any name: writes and a named call between, a `local` it keeps, an
        # array in a loop, two such bodies, a top-level `eval` between, a plain name set beside any.
        "V=1\ng() { eval :; }\nh() { W=2; }\ng\nV=3\nh\ng\nsh \"$V\"\nsh \"$W\"\n",
        "g() { local V; eval :; }\nV=1\ng\nV=2\ng\nsh \"$V\"\nsh \"$V\"\n",
        "A=(x)\ng() { . ./env; }\nfor i in 1 2; do\nA+=(y); g\nB=$i; g\ndone\n\"${A[@]}\"\nsh \"$B\"\n",
        "g() { eval :; }\nk() { eval :; T=1; }\nT=0; g; k; g; U=2; k\nsh \"$T\"\nsh \"$U\"\n",
        "g() { eval \"$C\"; }\nC=x\ng\neval y\nD=1\ng\nsh \"$C\"\nsh \"$D\"\n",
        "g() { local V; eval :; }\nk() { eval :; }\nV=1\ng\nk\nsh \"$V\"\nsh \"$V\"\n",
        "g() { eval :; }\nX=0\ng\nexport \"$K=v\" X=1\ng\nsh \"$X\"\nsh \"$X\"\n",
        # Round 11: the names such a body does not spell take their own stand-in apart from its walk
        # -- once a walk, then what changed since -- beside a `read`, a `local` around such a callee,
        # and arrays.
        "g() { eval :; read -r; }\nT=1\ng\nT=2\ng\nsh \"$REPLY\"\nsh \"$T\"\n",
        "h() { eval :; }\ng() { local W; h; W=2; }\nW=1\ng\nV=3\ng\nsh \"$W\"\nsh \"$V\"\n",
        "g() { eval :; A=(x y); }\nA=(a)\nB=(b)\ng\nB+=(c)\ng\n\"${A[@]}\"\n\"${B[@]}\"\n")

    def visits(self, check, budget):
        from unittest import mock
        real, seen = workflow_called.record_called, []

        def checked(table, stmts, position, starts):
            expected = check(table.copy(), stmts, position, starts)
            real(table, stmts, position, starts)
            seen.append(position)
            self.assertEqual(snapshot(expected), snapshot(table))
        for script in self.SCRIPTS:
            with self.subTest(script=script), mock.patch.object(workflow_called, "_BUDGET", budget), \
                    mock.patch.object(workflow_uses, "record_called", checked):
                seen.clear()
                stmts = stmts_of(script)
                for index in range(len(stmts)):
                    workflow_uses.static_values(stmts, index)
                self.assertGreater(len(seen), len(set(seen)))       # a site visited again

    def test_within_the_budget_every_visit_is_a_fresh_carry(self):
        def carried(table, stmts, position, starts):
            for start, close in workflow_called._reached(stmts, position, starts):
                workflow_called._carry(table, stmts, start, close)
            return table
        self.visits(carried, 10 ** 9)

    def test_past_it_every_name_the_bodies_may_set_holds_the_stand_in(self):
        def stood(table, stmts, position, starts):
            bodies = workflow_called._reached(stmts, position, starts)
            written, anything, _active, _spelled = workflow_called._effects(stmts, bodies) if bodies else (
                set(), False, (), set())
            for name in (written | {*table.scalars, *table.arrays}) if anything else written:
                workflow_called.stand_in(table, name)
            return table
        self.visits(stood, 0)


if __name__ == "__main__":
    unittest.main()
