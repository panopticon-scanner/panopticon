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


if __name__ == "__main__":
    unittest.main()
