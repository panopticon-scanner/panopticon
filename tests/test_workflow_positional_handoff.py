"""#3047 (the function half) + #3091: a call of a function the step defines reads as its body as the call makes it.

A command handed on through a function's arguments ran under every shell and read CLEAN: `run() { "$@"; }; run sh
cuda_1.run`, a retry loop around `"$@"`, `f() { sh "$1"; }; f cuda_1.run`; and a fetched file handed to a body indirectly
(#3091): `f tool`, `cat tool | f`, `f $T`, a heredoc of `$(cat tool)`. `workflow_called_fetches.called` reads each such
call, in a fold of its own (`shell_folds._CALLED`) beside `main`'s, as the body's statements with the call's words in its
positionals -- `$N`, `"$@"` spliced, `NAME=$N` set, a `shift` dropping them -- the guard reporting where either fold
reads a run; `main`'s reading of the call never changes (the issue's trap: a check a body credits is credited in the
fold alone, and takes no report away).

Marks are a letter a `shell:` setting -- unset, `bash`, `sh`, `bash {0}`, `sh {0}` -- R where the guard reports, C where
it reads the step CLEAN: first the job's, then the main pass's. Truth: the #2863 record's kit `F5-positional` (eight
parents, two child families: every fn row runs under all 16, the controls under none) and #3091's table.
"""
import unittest
from unittest import mock

import pytest

import shell_folds
import shell_reader
import workflow_guard as wg
import workflow_options as wo
import workflow_programs as wp
from tests.test_shell_reader import LinearGrowth
from workflow_called_fetches import _DEPTH, _INLINED, called

SHELLS = (None, "bash", "sh", "bash {0}", "sh {0}")
FETCH = "curl -fsSLo cuda_1.run https://example.test/cuda_1.run\n"
TOOL = "curl -fsSL -o tool https://example.test/tool\n"
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


def words(statements):
    """Each statement's stages' words and its separator, as strings."""
    return [([[str(word) for word in stage.argv] for stage in statement.stages], statement.separator)
            for statement in statements]


def folded(stmts):
    """`called(stmts)` in the fold that reads each call as its body."""
    shell_folds._CALLED.update(on=True, met=False)
    try:
        return called(stmts)
    finally:
        shell_folds._CALLED.update(on=False, met=False)


def in_fold(text):
    return folded(shell_reader.statements(text))


class TestACallStandsForItsBodyAsTheCallMakesIt(unittest.TestCase):

    def test_the_kits_runner_rows_report(self):
        # #3047's `"$@"` family: CLEAN on `main`, the download runs under all 16 parents.
        for body, call in (('run() { "$@"; }', "run sh cuda_1.run"), ('run() { "$@" || :; }', "run sh cuda_1.run"),
                           ('retry() { for i in 1 2 3; do "$@" && return 0; sleep 0; done; return 1; }', "retry sh cuda_1.run"),
                           ('run() { echo "+ $*"; "$@"; }', "run sh cuda_1.run"), ('run() { "$@"; }', "run bash cuda_1.run"),
                           ('run() { "$@"; }', "run bash -c 'sh cuda_1.run'"), ('run() { $@; }', "run sh cuda_1.run"),
                           ('f() { shift; "$@"; }', "f x sh cuda_1.run"),
                           ('f() { local cmd="$1"; shift; "$cmd" "$@"; }', "f sh cuda_1.run")):
            with self.subTest(body=body, call=call):
                self.assertEqual(REPORTED, marks("%s%s\n%s\n" % (FETCH, body, call)))

    def test_the_kits_stream_rows_report(self):
        # The stream twins: nothing fetched first, the download runs where the call stands.
        for text in ('run() { "$@"; }\nrun sh -c \'curl -fsSL https://example.test/i.sh | sh\'\n',
                     'run() { "$@"; }\ncurl -fsSL https://example.test/i.sh | run sh\n',
                     'retry() { for i in 1 2 3; do "$@" && return 0; sleep 0; done; return 1; }\n'
                     "retry bash -c 'curl -fsSL https://example.test/i.sh | bash'\n"):
            with self.subTest(text=text):
                self.assertEqual(REPORTED, marks(text))

    def test_the_kits_positional_rows_report(self):
        # #3047's `$1` family, #3091's A02: the call's word where the body's `"$1"` stands, as program or operand.
        for body, call in (('f() { sh "$1"; }', "f cuda_1.run"), ("f() { sh $1; }", "f cuda_1.run"),
                           ('f() { sh "$1"; }', "f ./cuda_1.run"), ('f() { "$1" cuda_1.run; }', "f sh")):
            with self.subTest(body=body, call=call):
                self.assertEqual(REPORTED, marks("%s%s\n%s\n" % (FETCH, body, call)))

    def test_the_kits_controls_read_as_on_main(self):
        # A body that names the run itself and a pattern argument (#2585) reported; a function never called, a
        # call whose first word is `echo`, the words quoted whole, and a single-quoted copy (`cmd='$1'`: no `$` of it
        # live) run nothing. `eval`, `sudo`, `env`, `time`, `exec "$@"` and a bare `$*` report on `main` already.
        for body, call in (("run() { sh cuda_1.run; }", "run"), ('f() { sh "$1"; }', "f ./cuda_*.run"),
                           ('run() { eval "$@"; }', "run sh cuda_1.run"), ('run() { sudo "$@"; }', "run sh cuda_1.run"),
                           ('run() { exec "$@"; }', "run sh cuda_1.run"), ("run() { $*; }", "run sh cuda_1.run")):
            with self.subTest(body=body, call=call):
                self.assertEqual(REPORTED, marks("%s%s\n%s\n" % (FETCH, body, call)))
        for body, call in (('run() { "$@"; }', "true sh cuda_1.run"), ('run() { "$@"; }', "run echo sh cuda_1.run"),
                           ('run() { "$@"; }', 'run "sh cuda_1.run"'),
                           ("f() { local cmd='$1'; shift; \"$cmd\" \"$@\"; }", "f sh cuda_1.run")):
            with self.subTest(body=body, call=call):
                self.assertEqual(CLEAN, marks("%s%s\n%s\n" % (FETCH, body, call)))

    def test_the_set_rows_are_the_other_half(self):
        # #3047's `set --` half is #3108's (the table holds the positionals): as on `main` here.
        for text in ('set -- cuda_1.run\nsh "$1"\n', "set -- cuda_1.run\nsh $1\n", 'set -- sh cuda_1.run\n"$@"\n',
                     "set -- sh cuda_1.run\n$@\n"):
            with self.subTest(text=text):
                self.assertEqual(CLEAN, marks(FETCH + text))


class TestAFetchedFileHandedToABodyIndirectly(unittest.TestCase):

    def test_the_issues_rows_report(self):
        # #3091's table: the file as an argument (the definition before and after the fetch), through `cat`, a
        # nested call, a variable, a tilde path, a heredoc or here-string of `$(cat tool)`, a process substitution.
        for text in ('f() { sh "$1"; }\n' + TOOL + "f tool\n", TOOL + 'f() { sh "$1"; }\nf tool\n',
                     "f() { sh; }\n" + TOOL + "cat tool | f\n", 'g() { sh "$1"; }\nf() { g "$1"; }\n' + TOOL + "f tool\n",
                     "g() { sh; }\nf() { g; }\n" + TOOL + "f < tool\n", 'f() { sh "$1"; }\n' + TOOL + "T=tool\nf $T\n",
                     'f() { sh "$1"; }\n' + TOOL + 'T=tool\nf "$T"\n',
                     'f() { sh "$1"; }\ncurl -fsSL -o ~/tool https://example.test/tool\nf ~/tool\n',
                     "f() { sh; }\n" + TOOL + "f <<EOF\n$(cat tool)\nEOF\n", "f() { sh; }\n" + TOOL + 'f <<< "$(cat tool)"\n',
                     'f() { sh "$1"; }\n' + TOOL + "f <(cat tool)\n"):
            with self.subTest(text=text):
                self.assertEqual(REPORTED, marks(text))

    def test_the_controls(self):
        # A body naming the file, the download piped or redirected into the call (#2973) and `. ./tool` in a body
        # reported on `main`; a function never called, or called with another file, runs nothing of it.
        for text in ("f() { sh tool; }\n" + TOOL + "f\n", "f() { sh; }\ncurl -fsSL https://example.test/tool | f\n",
                     "f() { sh; }\n" + TOOL + "f < tool\n", "f() { . ./tool; }\n" + TOOL + "f\n"):
            with self.subTest(text=text):
                self.assertEqual(REPORTED, marks(text))
        for text in ('f() { sh "$1"; }\n' + TOOL, 'f() { sh "$1"; }\n' + TOOL + "f other.sh\n"):
            with self.subTest(text=text):
                self.assertEqual(CLEAN, marks(text))

    def test_the_named_limit_a_process_substitution_redirected_in(self):
        # THE NAMED LIMIT: `sh < <(cat tool)` reads CLEAN on `main` inline, so its call twin does too -- a reader
        # gap of its own, not this fold's.
        self.assertEqual(CLEAN, marks(TOOL + "sh < <(cat tool)\n"))
        self.assertEqual(CLEAN, marks("f() { sh; }\n" + TOOL + "f < <(cat tool)\n"))


class TestWhatACallStandsFor(unittest.TestCase):

    def test_outside_the_fold_the_statements_are_as_written_and_the_fold_is_asked_for(self):
        stmts = shell_reader.statements('f() { sh "$1"; }\nf tool\n')
        shell_folds._CALLED.update(on=False, met=False)
        self.assertEqual(stmts, called(stmts))
        self.assertTrue(shell_folds._CALLED["met"])
        shell_folds._CALLED["met"] = False
        called(shell_reader.statements('f() { sh "$1"; }\necho f\n'))
        self.assertFalse(shell_folds._CALLED["met"])            # no call: no fold to read

    def test_a_one_stage_body_takes_the_calls_place(self):
        # In its pipeline, under its heredoc, behind its keywords, with its redirection and its substitution.
        read = in_fold('f() { sh "$1"; }\ng() { sh; }\ncat tool | g\ng <<EOF\n$(cat tool)\nEOF\nif f x; then :; fi\n'
                       'f t > out\nf <(cat tool)\n')
        self.assertEqual([([["cat", "tool"], ["sh"]], "\n"), ([["sh"]], "\n"), ([["if", "sh", "x"]], ";")],
                         words(read)[4:7])
        self.assertEqual(("$(cat tool)", True), read[5].stages[0].stdin_heredoc)
        self.assertEqual((["sh", "t"], ["out"]), ([str(w) for w in read[9].stages[0].argv], list(read[9].stages[0].writes)))
        self.assertEqual(["cat tool"], list(read[10].stages[0].substitutions))
        self.assertTrue(shell_reader.has_substitution(read[10].stages[0].argv[1]))

    def test_a_longer_body_stands_in_order_with_the_calls_separator_behind(self):
        read = in_fold('retry() { for i in 1 2 3; do "$@" && return 0; sleep 0; done; return 1; }\nretry sh t || exit 1\n')
        self.assertEqual([([["for", "i", "in", "1", "2", "3"]], ";"), ([["do", "sh", "t"]], "&&"), ([["return", "0"]], ";"),
                          ([["sleep", "0"]], ";"), ([["done"]], ";"), ([["return", "1"]], "||"), ([["exit", "1"]], "\n")],
                         words(read)[7:])

    def test_a_shift_drops_the_calls_words_and_a_copy_sets_the_name(self):
        # The copy is an assignment the walk reads (`workflow_annotate` marks `$c` as its literal `sh`); the binder
        # leaves `$c` as written.
        read = in_fold('f() { local c="$1"; shift; "$c" "$@" || :; }\nf sh t\ng() { shift 2; "$@"; }\ng a b sh t\n')
        self.assertEqual([([["local", "c=sh"]], ";"), ([["$c", "t"]], "||"), ([[":"]], "\n")], words(read)[5:8])
        self.assertEqual(([["sh", "t"]], "\n"), words(read)[-1])

    def test_a_call_in_a_body_is_followed_and_a_header_line_is_no_word(self):
        # A parenthesised body (`k() (…)`): its header's line opens a group, and the call reads as written, a
        # named limit (the use reader's `_subshell` tells the shapes apart; this fold does not).
        read = in_fold('g() { sh "$1"; }\nf() { g "$1"; }\nf tool\nfunction h {\n  sh "$1"\n  echo "$#"\n}\nh t\n'
                       'k() (sh "$1")\nk t\n')
        self.assertEqual([([["sh", "tool"]], "\n")], words(read)[4:5])
        self.assertEqual([([["sh", "t"]], "\n"), ([["echo", "$#"]], "\n")], words(read)[9:11])
        self.assertEqual(([["k", "t"]], "\n"), words(read)[-1])

    def test_a_body_that_reads_nothing_of_its_call_is_not_stood_for(self):
        # The carries, checks and gates of a call keep `main`'s readings: a body with no positional and no
        # stdin reader reads where it stands; a one-stage stdin reader stands for a call given input alone.
        read = in_fold('f() { T=x; }\nf a\ng() { GATE || false; }\ng || exit 1\nh() { sh; }\nh\ncat t | h\n')
        self.assertEqual(([["f", "a"]], "\n"), words(read)[2])
        self.assertEqual(([["g"]], "||"), words(read)[6])
        self.assertEqual(([["h"]], "\n"), words(read)[10])
        self.assertEqual(([["cat", "t"], ["sh"]], "\n"), words(read)[11])
        shell_folds._CALLED.update(on=False, met=False)
        called(shell_reader.statements('f() { T=x; }\nf a\n'))
        self.assertFalse(shell_folds._CALLED["met"])

    def test_a_cd_a_set_and_an_unset_of_the_bodys_own_or_the_steps(self):
        # Behind a `cd` of the body's own a relative word of the call names nothing here (as the use reader reads
        # a body's `cd`): it stays `$1`, an absolute one is given; `set --` gives the body its own words; a
        # certain `unset -f` before the call leaves no function to stand for.
        read = in_fold('f() { cd /; sh "$1"; }\nf ./t\nf /opt/t\ng() { set -- other; sh "$1"; }\ng t\n'
                       'h() { sh "$1"; }\nunset -f h\nh t\n')
        self.assertEqual([([["cd", "/"]], ";"), ([["sh", "$1"]], "\n"), ([["cd", "/"]], ";"), ([["sh", "/opt/t"]], "\n")],
                         words(read)[3:7])
        self.assertEqual(([["sh", "other"]], "\n"), words(read)[10])
        self.assertEqual(([["h", "t"]], "\n"), words(read)[-1])
        # A definition that may never have run (in a branch, behind `&&`) is no function to stand for, and an
        # `unset -f` there takes none away: as `main` installs them (`workflow_uses._functions_before`).
        read = in_fold('if false; then f() { sh "$1"; }; fi\nf t\ng() { sh "$1"; }\nfalse && unset -f g\ng t\n'
                       'true && h() { sh "$1"; }\nh t\n')
        self.assertEqual(([["f", "t"]], "\n"), words(read)[4])
        self.assertEqual(([["sh", "t"]], "\n"), words(read)[9])
        self.assertEqual(([["h", "t"]], "\n"), words(read)[-1])

    def test_what_stays_as_written(self):
        # A call before its definition; a single-quoted `'$@'`; a pipeline around a body of two statements;
        # a positional the call did not pass; and a recursion, bounded.
        read = in_fold('f tool\nf() { sh "$1"; }\ng() { \'$@\'; }\ng sh t\nh() { echo x; sh; }\ncat t | h\n'
                       'i() { sh "$2"; }\ni t\nr() { r "$@"; }\nr sh t\n')
        self.assertEqual(([["f", "tool"]], "\n"), words(read)[0])
        self.assertEqual(([["$@"]], "\n"), words(read)[5])
        self.assertEqual(([["cat", "t"], ["h"]], "\n"), words(read)[9])
        self.assertEqual(([["sh", "$2"]], "\n"), words(read)[12])
        self.assertEqual(([["r", "sh", "t"]], "\n"), words(read)[-1])

    def test_the_step_grows_by_the_budget_at_most(self):
        text = 'f() { echo a; sh "$1"; }\n' + "f t\n" * 100
        read = in_fold(text)
        self.assertEqual(len(shell_reader.statements(text)) + _INLINED, len(read))
        self.assertEqual(([["f", "t"]], "\n"), words(read)[-1])


class TestTheFoldsFlipClearsTheCaches(unittest.TestCase):

    def test_a_flip_of_the_called_fold_clears_parsed(self):
        # `workflow_programs._parsed`, keyed on the text alone, is registered in `shell_folds._STALE` (#3048 round 2):
        # a flip of `_CALLED` clears it as a flip of `_LOCALE` does, so no reading crosses the fold's edge.
        wp._parsed.cache_clear()
        wp._parsed("sh t")
        self.assertEqual(1, wp._parsed.cache_info().currsize)
        try:
            shell_folds._flip(shell_folds._CALLED, True)
            self.assertEqual(0, wp._parsed.cache_info().currsize)
            wp._parsed("sh t")
        finally:
            shell_folds._flip(shell_folds._CALLED, False)
        self.assertEqual(0, wp._parsed.cache_info().currsize)


class TestTheReadingIsLinear(LinearGrowth, unittest.TestCase):
    """n calls of a chain of definitions `_DEPTH` deep: each call is followed to its end, in time linear in n."""

    CHAIN = "".join('f%d() { f%d "$@"; }\n' % (i, i + 1) for i in range(1, _DEPTH)) + 'f%d() { sh "$1"; }\n' % _DEPTH

    @staticmethod
    def make(n):
        return TestTheReadingIsLinear.CHAIN + "f1 t\n" * n

    @pytest.mark.serial
    def test_n_calls_followed_to_the_depth_read_in_linear_time(self):
        # Growth, not speed: `LinearGrowth` times `shell_reader.statements`, here the parse with `called` behind it
        # in its fold, at 250 and 1,000 calls; every call stands for the chain's last body, `sh t`.
        real = shell_reader.statements

        def check(n, parsed):
            self.assertEqual(n, sum(1 for s in parsed if [str(w) for w in s.stages[0].argv] == ["sh", "t"]))

        with mock.patch.object(shell_reader, "statements", lambda script: folded(real(script))):
            self.assert_linear_growth(250, self.make, check)


if __name__ == "__main__":
    unittest.main()
