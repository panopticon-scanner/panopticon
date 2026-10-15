"""#2975: three function-header spellings the reader did not take as headers, so the body was read as the name's
arguments and a run inside it was never seen -- a header right behind a group's `(` (`( f() { sh t; }; f )`, part B) and
a name bash takes and the reader's pattern did not (`a.b`, `a:b`, `a+b`, `@f`, part C) read their headers now; a header
on the line of another header's `{` (`f() { g() { sh t; }; g; }`, part A) still does not, pinned below as a limit: read as
a header, a gate in its body would be credited as the outer body's own, the nested one-line definition being no entry
of the function table, and `f() { g() { CHECK || exit 1; }; }` ⏎ `f` ⏎ `sh t` (every parent runs the download: `g` is
never called) would read CLEAN. #2977: the header test at every `(` joined and split the whole stage, and the `esac`
test at every `)` joined it again, so one statement of n headers cost n joins (8,000 `f() `: 6 s on the forge, about
x3.4 a doubling); the words in front are carried word to word now, and both tests are lookups.

Marks are a letter a `shell:` setting -- unset, `bash`, `sh`, `bash {0}`, `sh {0}` -- R where the guard reports, C where
it reads the step CLEAN: first the job's, then the main pass's. The rows are the #2954-side kit's (families S6, S2, S3;
truth: eight parents on the forge, the download runs under 16 of 16 for S6 and S2, and under the bash parents only for S3,
where dash refuses the name). The kit's own-line and `function` spellings reported already and keep their marks; the S3
own-line rows over-report under `sh` as they did (main's posture, not this PR's).
"""
import unittest

import shell_reader
import workflow_guard as wg
import workflow_options as wo

SHELLS = (None, "bash", "sh", "bash {0}", "sh {0}")
FETCH = "curl -fsSLo t https://example.test/t\n"
REPORTED = ("RRRRR", "RRRRR")
CLEAN = ("CCCCC", "CCCCC")


def marks(text):
    """(the job's marks, the main pass's) for a job of one step whose `run:` is `text`."""
    job = mains = ""
    for shell in SHELLS:
        step = [wg.Step("step", text + "echo done\n", shell)]
        job += "R" if wg.job_defects(step) else "C"
        with wo.mains_answer():
            mains += "R" if wg._job_defects(step) else "C"
    return job, mains


class TestAHeaderOnTheLineOfAnotherHeadersBrace(unittest.TestCase):
    """S6 (part A): the inner `()` is read as a subshell and the body as the inner name's arguments, as on
    `main` -- a limit pinned here, not a fix. The front starts over at a header's `{` in a scratch build, and
    the five rows report; but the function table holds no nested one-line definition, so a gate in the inner
    body is credited as the outer body's own, and `f() { g() { CHECK || exit 1; }; }` ⏎ `f` ⏎ `sh t` -- `g`
    never called, every parent runs the download, REPORTED on `main` -- reads CLEAN. Part A lands with the
    table's reading of a nested definition (#2975 stays open for it)."""

    def test_the_kits_rows_read_as_they_did(self):
        # s6.run, s6.tight, s6.call-outside, s6.fetch, s6.pipe: CLEAN on main and here; truth: runs, 16 of 16.
        for text in (FETCH + "f() { g() { sh t; }; g; }\nf\n", FETCH + "f(){ g(){ sh t; }; g; }\nf\n",
                     FETCH + "f() { g() { sh t; }; }\nf\ng\n",
                     "f() { g() { curl -fsSLo t https://example.test/t; }; g; }\nf\nsh t\n",
                     "f() { g() { curl -fsSL https://example.test/t | sh; }; g; }\nf\n"):
            with self.subTest(text=text[:40]):
                self.assertEqual(CLEAN, marks(text))

    def test_the_gate_in_a_nested_definition_never_called_still_reports(self):
        # The row that holds part A back (`tests/test_workflow_guard_reader_forms.py` pins it as `main`'s too).
        sums = "echo '%s  t' > sums\n" % ("a" * 64)
        self.assertEqual(REPORTED, marks(FETCH + sums + "f() { g() { sha256sum -c sums || exit 1; }; }\nf\nsh t\n"))

    def test_the_spellings_that_reported_keep_their_marks(self):
        # s6.second (a `;` before the inner header), s6.kw, s6.kw~nl, s6.run~nl, s6.pipe~nl.
        for text in (FETCH + "f() { echo hi; g() { sh t; }; g; }\nf\n",
                     FETCH + "function f { function g { sh t; }; g; }\nf\n",
                     FETCH + "function f {\n  function g {\n    sh t\n  }\n  g\n}\nf\n",
                     FETCH + "f() {\n  g() {\n    sh t\n  }\n  g\n}\nf\n",
                     "f() {\n  g() {\n    curl -fsSL https://example.test/t | sh\n  }\n  g\n}\nf\n"):
            with self.subTest(text=text[:40]):
                self.assertEqual(REPORTED, marks(text))


class TestAHeaderBehindAGroupsParenthesis(unittest.TestCase):
    """S2 (part B): behind the group's `(` the header was not taken as one."""

    def test_the_kits_rows_report(self):
        # paren.fn1, paren.fn1-sp, paren.fn1-fetch: CLEAN on main; truth: runs, 16 of 16.
        for text in (FETCH + "( f() { sh t; }; f )\n", FETCH + "( f () { sh t; }; f )\n",
                     "( f() { curl -fsSLo t https://example.test/t; }; f )\nsh t\n"):
            with self.subTest(text=text[:40]):
                self.assertEqual(REPORTED, marks(text))

    def test_the_spellings_that_reported_keep_their_marks(self):
        # paren.fn1-kw, paren.fn1~nl, paren.subst.
        for text in (FETCH + "( function f { sh t; }; f )\n", FETCH + "(\n  f() {\n    sh t\n  }\n  f\n)\n",
                     FETCH + "echo \"$(f() { sh t; }; f)\"\n"):
            with self.subTest(text=text[:40]):
                self.assertEqual(REPORTED, marks(text))

    def test_a_gate_in_the_groups_function_reads_as_the_plain_subshell_gate(self):
        # `( f() { CHECK || exit 1; }; f )` ⏎ `sh t`: the `exit 1` ends the subshell, and the parent runs the
        # download where no `-e` stops it at the subshell's status -- `main` reported every setting, the
        # function unread; now the row reads as `( CHECK || exit 1 )` ⏎ `sh t` does on `main`, CLEAN under
        # the `-e` settings, REPORTED under `{0}`. Never called, the gate is no gate: reported.
        sums = "echo '%s  t' > sums\n" % ("a" * 64)
        check = "sha256sum -c sums || exit 1"
        self.assertEqual(("CCCRR", "CCCRR"), marks(FETCH + sums + "( f() { %s; }; f )\nsh t\n" % check))
        self.assertEqual(("CCCRR", "CCCRR"), marks(FETCH + sums + "( %s )\nsh t\n" % check))
        self.assertEqual(REPORTED, marks(FETCH + sums + "( f() { %s; } )\nsh t\n" % check))


class TestANameBashTakes(unittest.TestCase):
    """S3 (part C): `a.b`, `a:b`, `a+b` and `@f` are names to bash; the reader's pattern stopped at `[A-Za-z0-9_-]`."""

    def test_the_kits_rows_report(self):
        # name.dot1, name.colon1, name.plus1, name.at1, name.kw-dot, name.dot-fetch: CLEAN on main; truth: runs
        # under the bash parents (12 of 16; dash refuses the name).
        for text in (FETCH + "a.b() { sh t; }\na.b\n", FETCH + "a:b() { sh t; }\na:b\n", FETCH + "a+b() { sh t; }\na+b\n",
                     FETCH + "@f() { sh t; }\n@f\n", FETCH + "function a.b { sh t; }\na.b\n",
                     "a.b() { curl -fsSLo t https://example.test/t; }\na.b\nsh t\n"):
            with self.subTest(text=text[:40]):
                self.assertEqual(REPORTED, marks(text))

    def test_the_own_line_spellings_keep_their_marks(self):
        # name.dot1~nl, name.colon1~nl, name.kw-dot~nl: the body on its own lines was read as a command already.
        for text in (FETCH + "a.b() {\n  sh t\n}\na.b\n", FETCH + "a:b() {\n  sh t\n}\na:b\n",
                     FETCH + "function a.b {\n  sh t\n}\na.b\n"):
            with self.subTest(text=text[:40]):
                self.assertEqual(REPORTED, marks(text))


class TestTheSplitter(unittest.TestCase):
    """`shell_reader.statements` on the shapes: the header is a header, the body's command its own stage."""

    @staticmethod
    def commands(text):
        return [[str(w) for w in shell_reader.acted(stage.argv)] for s in shell_reader.statements(text) for stage in s.stages]

    def test_the_group_header_and_the_wider_names_are_headers(self):
        self.assertIn(["sh", "t"], self.commands("( f() { sh t; }; f )\n"))
        self.assertIn(["sh", "t"], self.commands("( f () { sh t; }; f )\n"))
        self.assertIn(["sh", "t"], self.commands("a.b() { sh t; }\n"))
        self.assertIn(["sh", "t"], self.commands("@f() { sh t; }\n"))

    def test_a_header_on_another_headers_line_reads_as_it_did(self):
        # Part A, the limit: the inner body is the inner name's arguments, as on `main`.
        self.assertIn(["g", "{", "sh", "t"], self.commands("f() { g() { sh t; }; g; }\n"))
        self.assertIn(["g", "{", "sh", "t"], self.commands("f(){ g(){ sh t; }; g; }\n"))

    def test_what_is_no_header_stays_a_subshell_or_a_word(self):
        # `f (x)` is no header; `echo (a)` is a syntax error bash never runs; `x=1 (f)` a subshell.
        for text in ("( sh t )\n", "( ( sh t ) )\n", "echo a; ( sh t; )\n"):
            with self.subTest(text=text):
                self.assertIn(["sh", "t"], self.commands(text))


if __name__ == "__main__":
    unittest.main()
