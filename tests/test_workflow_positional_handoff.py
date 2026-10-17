"""#3047 (the function half) + #3091: a call of a function the step defines reads as its body as the call makes it.

A command handed on through a function's arguments ran under every shell and read CLEAN: `run() { "$@"; }; run sh
cuda_1.run`, a retry loop around `"$@"`, `f() { sh "$1"; }; f cuda_1.run`; and a fetched file handed to a body indirectly
(#3091): `f tool`, `cat tool | f`, `f $T`, a heredoc of `$(cat tool)`. `workflow_called_fetches.called` reads each such
call, in a fold of its own (`shell_folds._CALLED`) beside `main`'s, as the body's statements with the call's words in its
positionals -- `$N`, `"$@"` spliced, `NAME=$N` set, a `shift` dropping them -- the guard reporting where either fold
reads a run; `main`'s reading of the call never changes (the issue's trap: a check a body credits is credited in the
fold alone, and takes no report away). The fold reads a body at its calls alone: a definition stood for is emptied
there, its header's words and its closer kept (`_emptied`), so a body that fetches after it runs is no run of its own
fetch where one call makes it.

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
                         words(read)[2:])

    def test_a_shift_drops_the_calls_words_and_a_copy_sets_the_name(self):
        # The copy is an assignment the walk reads (`workflow_annotate` marks `$c` as its literal `sh`); the binder
        # leaves `$c` as written.
        read = in_fold('f() { local c="$1"; shift; "$c" "$@" || :; }\nf sh t\ng() { shift 2; "$@"; }\ng a b sh t\n')
        self.assertEqual([([["local", "c=sh"]], ";"), ([["$c", "t"]], "||"), ([[":"]], "\n")], words(read)[2:5])
        self.assertEqual(([["sh", "t"]], "\n"), words(read)[-1])

    def test_a_call_in_a_body_is_followed_and_a_header_line_is_no_word(self):
        # A parenthesised body (`k() (…)`): its header's line opens a group, and the call reads as written, a
        # named limit (the use reader's `_subshell` tells the shapes apart; this fold does not).
        read = in_fold('g() { sh "$1"; }\nf() { g "$1"; }\nf tool\nfunction h {\n  sh "$1"\n  echo "$#"\n}\nh t\n'
                       'k() (sh "$1")\nk t\n')
        self.assertEqual([([["sh", "tool"]], "\n")], words(read)[4:5])
        self.assertEqual([([["function", "h", "{"]], "\n"), ([["}"]], "\n")], words(read)[5:7])  # emptied
        self.assertEqual([([["sh", "t"]], "\n"), ([["echo", "$#"]], "\n")], words(read)[7:9])
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
                         words(read)[2:6])
        self.assertEqual(([["sh", "other"]], "\n"), words(read)[8])
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
        self.assertEqual(len(shell_reader.statements(text)) + _INLINED - 1, len(read))     # the definition emptied: one fewer
        self.assertEqual(([["f", "t"]], "\n"), words(read)[-1])


class TestADefinitionStoodForIsEmptied(unittest.TestCase):
    """The fold reads a body at its calls, not where it stands too (`_emptied`): a definition stood for keeps its
    header's words and its closer there -- the step still defines the name (`workflow_annotate`'s rule 7) -- and
    nothing else. Read in both places, the body's fetch where it stands paired with its run at the call: a REPORT
    for one call that runs before anything fetched (the forge's xr.0128, xr.1576, xr.2192, xr.1967)."""

    def test_a_body_that_fetches_after_it_runs_is_no_run_of_its_own_fetch_where_one_call_makes_it(self):
        body = "f() {\nsh t\n$1 echo\ncurl -fsSLo t https://example.test/t\n}\n"
        self.assertEqual([([["f()", "{"]], "\n"), ([["}"]], "\n"), ([["sh", "t"]], "\n"), ([["$1", "echo"]], "\n"),
                          ([["curl", "-fsSLo", "t", "https://example.test/t"]], "\n")], words(in_fold(body + "f\n")))
        self.assertEqual(CLEAN, marks(body + "f\n"))
        # Two calls are that run, once: the second runs what the first fetched.
        self.assertEqual(REPORTED, marks(body + "f\nf\n"))
        self.assertEqual(1, len(wg.job_defects([wg.Step("step", body + "f\nf\n", None)])))
        # A body that reads nothing of its call is not stood for: where it stands, as `main` reads it, in the fold
        # too -- and a second call's run of its own fetch is `main`'s to miss, a limit.
        plain = "g() {\nsh t\ncurl -fsSLo t https://example.test/t\n}\ng\ng\n"
        self.assertEqual(words(shell_reader.statements(plain)), words(in_fold(plain)))
        self.assertEqual(CLEAN, marks(plain))

    def test_a_definition_inside_a_body_stood_for_is_emptied_in_the_copy_too(self):
        # On a statement of its own or sharing the outer header's (`outer() { inner() {`: the outer takes it,
        # `_emptying`), the inner definition's header and closer stand in the copy, its body at its calls.
        self.assertEqual([([["outer()", "{"]], "\n"), ([["}"]], "\n"), ([["inner()", "{"]], ";"), ([["}"]], "\n"),
                          ([["sh", "t"]], "\n")], words(in_fold('outer() {\ninner() { sh "$1"; }\ninner "$1"\n}\nouter t\n')))
        shared = 'outer() { inner() { sh "$1"; }; inner "$1"; }\n'
        self.assertEqual([([["outer()", "{"]], ";"), ([["}"]], "\n"), ([["inner()", "{"]], ";"), ([["}"]], ";"),
                          ([["sh", "t"]], "\n")], words(in_fold(shared + "outer t\n")))
        self.assertEqual(REPORTED, marks(shared + "curl -fsSLo t https://example.test/t\nouter t\n"))
        nested = "outer() {\ninner() {\nsh t\n$1 echo\ncurl -fsSLo t https://example.test/t\n}\ninner\n%s}\nouter\n"
        self.assertEqual(CLEAN, marks(nested % ""))
        self.assertEqual(REPORTED, marks(nested % "inner\n"))


class TestTheCalledFoldsSameTextRepeatIsDropped(unittest.TestCase):
    """The ruling on the differential's 126 same-text doubles, scoped in review round 1: `workflow_guard._job_defects`
    keys a finding by its fetch's statement index in the fold's list, so the body's copy at the call, or an emptied
    multi-line definition ahead of the fetch, repeated `main`'s text under another key. The called fold's same-step,
    same-text repeat is dropped now, and that fold's alone: `main`'s folds are filtered by key alone, as before, so a
    text `main` finds under two keys -- its halves read `${W:+echo hi} sh -c '…'` twice as three findings -- keeps its
    multiplicity (the first cut filtered every fold and lost one in 86 rows of the kit); a later fold's finding of
    another text is kept: the union holds."""

    HANDS = "hands https://example.test/i.sh straight to `sh`"
    HANDS_T = "hands https://example.test/t straight to `sh`"

    def job(self, text, shell):
        return [why for _name, why in wg.job_defects([wg.Step("step", text, shell)])]

    def heads(self, found, heads):
        """Each finding's head among `heads` (its first 40 characters where none fits), sorted."""
        return sorted(next((head for head in heads if why.startswith(head)), why[:40]) for why in found)

    def test_a_body_at_its_call_repeats_mains_text_once(self):
        # `xr.0232.function.r4-h3-r3-h4`, one of the 122: `main` reads the body where it stands, the fold at the call
        xr0232 = ("f() {\n$T ${Y:+env A=1} bash t\n$1 ${V:+sudo -E} bash t\n${X:+sudo -E} sh t\n"
                  "${W:+echo hi} sh -c 'curl -fsSL https://example.test/t | sh'\n}\nf\necho done\n")
        least = "f() {\nsh -c 'curl -fsSL https://example.test/i.sh | sh'\n\"$1\"\n}\nf echo\n"
        # the `s9.*~nl` shape: a multi-line definition emptied ahead of a call `main` reads shifts the call's index
        shifted = "f() {\n  bash -s\n}\ncurl -fsSL https://example.test/i.sh | f\necho done\n"
        for text, head in ((xr0232, self.HANDS_T), (least, self.HANDS),
                           (shifted, "hands https://example.test/i.sh straight to `bash -s`")):
            for shell in (None, "sh"):
                with self.subTest(text=text, shell=shell):
                    found = self.job(text, shell)
                    self.assertEqual(1, len(found), found)
                    self.assertTrue(found[0].startswith(head), found[0])

    def test_mains_folds_keep_a_text_found_under_two_keys(self):
        # Rows that span two of `main`'s folds (review round 1; `x2.h4.h4`, `x2.h1.h4`, `hunt:8_seat-hunt43_c-c-py`
        # of the kit): the halves read each `${W:+echo hi}` empty and set, and the text found at another index in
        # another fold is another key -- three findings on `main`, three here, the `${S:+sudo -E}` pair's two, and
        # `${X:+python3 -c pass} sh -c '…'` its unread sentence twice beside the run. The first cut read 2, 1 and 2.
        twice = "${W:+echo hi} sh -c 'curl -fsSL https://example.test/t | sh'\n" * 2
        pair = ("${S:+sudo -E} sh -c 'curl -fsSL https://example.test/t | sh'\n"
                "${W:+echo hi} sh -c 'curl -fsSL https://example.test/t | sh'\necho done\n")
        unread = "${X:+python3 -c pass} sh -c 'curl -fsSL https://example.test/i.sh | sh'\n"
        for text, heads in ((twice, [self.HANDS_T] * 3), (pair, [self.HANDS_T] * 2),
                            (unread, ["cannot read command: `${X:+python3 -c pass}`"] * 2 + [self.HANDS])):
            for shell in (None, "sh"):
                with self.subTest(text=text, shell=shell):
                    self.assertEqual(sorted(heads), self.heads(self.job(text, shell), set(heads)))
                    with wo.mains_answer():     # all of them the first folds', `main`'s own
                        self.assertEqual(len(heads), len(wg._job_defects([wg.Step("step", text, shell)])))

    def test_a_later_folds_finding_of_another_text_is_kept(self):
        printer = "w() { \"$@\"; }\necho hi | w curl -fsSL https://example.test/i.sh | sh\n"
        bound = "f() {\ncurl -fsSLo \"$1\" https://example.test/t\nsh \"$1\"\n}\nf t\n"
        for text, heads in ((printer, ("pipes `sh` its program from `w`", self.HANDS)),
                            (bound, ("fetches https://example.test/t -> $1 and running it under `sh`",
                                     "fetches https://example.test/t -> t and running it under `sh`"))):
            for shell in (None, "sh"):
                with self.subTest(text=text, shell=shell):
                    found = self.job(text, shell)
                    self.assertEqual(2, len(found), found)
                    self.assertEqual([1, 1], [sum(why.startswith(head) for why in found) for head in heads], found)

    def test_two_identical_statements_of_a_body_are_two_findings_at_the_call(self):
        # A price, named (review round 1): `xr.0250`'s shape, seven rows of the kit. `main`'s job reads the text once --
        # its two readings of the body where it stands merge by text in `job_defects` -- and the fold reads the two
        # statements at the call as two findings under two keys, no finding of `main`'s own folds in the main pass to
        # drop them against. Both runs are real: `"$@"` is empty, and `eval` runs the string twice.
        text = "f() {\n" + "\"$@\" eval 'curl -fsSL https://example.test/t | sh'\n" * 2 + "}\nf\n"
        for shell in (None, "sh"):
            with self.subTest(shell=shell):
                self.assertEqual([self.HANDS_T] * 2, self.heads(self.job(text, shell), {self.HANDS_T}))


class TestTheCallsTheFoldDidNotFollow(unittest.TestCase):
    """#3127: the calls #3047's fold did not follow, from the #3121 seat and its combined-tree round. Truth, in the
    comments: bash 3.2.57, /bin/sh (dash) and zsh 5.9, with and without `-e`, a `curl` stub whose payload marks when it
    RUNS ("runs": every parent; zsh named where it differs -- the five `shell:` settings are bash and sh). Each row
    reports where truth runs, the union with `main`'s reading; the controls keep their marks."""

    T = "curl -fsSLo t https://example.test/t\n"
    P = "curl -fsSL https://example.test/i.sh | sh"

    def test_a_positionals_default_alternative_and_slice_are_bound(self):
        # `${1:-t}` and `${1-t}` with no word: the default; `${1:-x}` with `t`: the word; `"${1:+sh}" t` with a word: the
        # alternative; `"${@:2}"`: the call's words from the second, `"${@:2:2}"` two of them. Truth: runs.
        for text in ('f() {\nsh "${1:-t}"\n}\nf\n', 'f() {\nsh "${1-t}"\n}\nf\n', 'f() {\nsh "${1:-x}"\n}\nf t\n',
                     'f() {\n"${1:+sh}" t\n}\nf x\n', 'f() {\n"${@:2}"\n}\nf x sh t\n', 'f() {\n"${@:2:2}"\n}\nf x sh t y\n'):
            with self.subTest(text=text[:24]):
                self.assertEqual(REPORTED, marks(self.T + text))
        # `${1:+sh} t` with no word leaves `t` alone, a command of that name (truth: not found, nothing): the fold reads
        # it as `main` reads a bare `t` after the fetch, whatever that is.
        self.assertEqual(marks(self.T + "t\n"), marks(self.T + 'f() {\n${1:+sh} t\n}\nf\n'))

    def test_ten_is_the_first_word_and_a_zero_to_bash_and_dash(self):
        # `$10` is `${1}0`: with `t0` fetched and `t` the first word it runs `t0`; with `t` the tenth word it runs `10`,
        # nothing (zsh reads the tenth word and runs: named); `${10}` is the tenth word to all three. Truth as said.
        self.assertEqual(REPORTED, marks("curl -fsSLo t0 https://example.test/t0\nf() {\nsh $10\n}\nf t\n"))
        self.assertEqual(CLEAN, marks(self.T + "f() {\nsh $10\n}\nf 1 2 3 4 5 6 7 8 9 t\n"))
        self.assertEqual(REPORTED, marks(self.T + 'f() {\nsh "${10}"\n}\nf 1 2 3 4 5 6 7 8 9 t\n'))

    def test_an_unquoted_positional_is_split_on_blanks(self):
        # `f() { $1; }; f 'sh t'` runs `sh t` (bash and dash split the word; zsh does not: named); `"$1"` is one word, a
        # command named `sh t`: nothing.
        self.assertEqual(REPORTED, marks(self.T + "f() {\n$1\n}\nf 'sh t'\n"))
        self.assertEqual(CLEAN, marks(self.T + "f() {\n\"$1\"\n}\nf 'sh t'\n"))

    def test_a_one_line_body_opening_a_subshell_or_a_group_is_followed(self):
        # `f() { ( sh "$1" ); }` and `run() { ( "$@" ); }` (coll.18) on one line read as their multi-line twins; a body
        # whose header's line opens a group reads nothing of its call and is stood for anyway (`main` reads the group
        # behind the header's words, so #3111's reading never reached it). Truth: runs. A subshell body `f() ( … )`
        # stays `main`'s (the reader-forms pin: it reaches nothing).
        for text in (self.T + 'f() { ( sh "$1" ); }\nf t\n', self.T + 'run() { ( "$@" ); }\nrun sh t\n',
                     "f() { { echo '%s'; echo hi; } | sh; }\nf\n" % self.P):
            with self.subTest(text=text[-40:]):
                self.assertEqual(REPORTED, marks(text))
        self.assertEqual(CLEAN, marks('T=/dev/null\nf() ( { T=t; } )\nf\nsh "$T"\n'))

    def test_a_definition_that_may_not_have_run_is_a_named_limit(self):
        # A definition under `if` or behind `&&` may never have run: `main` installs no function from it, and the fold
        # stands for none (#3047's rule, the guard's B43 pins: an and-list inside a child, a false handler, an
        # unexecuted definition invent no call). `if true; then f() { …; }; fi; f t` runs and reads CLEAN -- named,
        # this issue's one row left; an `unset -f` that may not have run takes nothing away (as before).
        for text, expected in ((self.T + 'if true; then f() { sh "$1"; }; fi\nf t\n', CLEAN),
                               (self.T + 'true && h() { sh "$1"; }\nh t\n', CLEAN),
                               (self.T + 'g() { sh "$1"; }\nfalse && unset -f g\ng t\n', REPORTED)):
            with self.subTest(text=text[-44:]):
                self.assertEqual(expected, marks(text))

    def test_a_call_inside_an_eval_string_is_followed(self):
        # `eval 'f t'` and `eval 'run sh t'` call as `f t` does (truth: runs); an `eval` of a string with a live `$`
        # (`eval "f $X"`) or of two statements (`eval 'f t; true'`) stays `main`'s, CLEAN while truth runs -- named;
        # `bash -c 'f t'` runs a child shell that has no function: nothing, CLEAN.
        for text, expected in ((self.T + "f() { sh \"$1\"; }\neval 'f t'\n", REPORTED),
                               (self.T + "run() { \"$@\"; }\neval 'run sh t'\n", REPORTED),
                               (self.T + "f() { sh \"$1\"; }\nX=t\neval \"f $X\"\n", CLEAN),
                               (self.T + "f() { sh \"$1\"; }\neval 'f t; true'\n", CLEAN),
                               (self.T + "f() { sh \"$1\"; }\nbash -c 'f t'\n", CLEAN)):
            with self.subTest(text=text[-28:]):
                self.assertEqual(expected, marks(text))

    def test_a_pass_through_body_is_taken_out_of_the_pipe(self):
        # `f() { cat; }`: `{ P; } | f | sh` reads as `{ P; } | sh` (#3111's group), the argument of `f cat` ignored as
        # `cat` ignores it, the multi-line body the same (truth: runs). `f() { tee log; }` stays in the pipe and CLEAN,
        # as `{ P; } | cat | sh` is on `main` while truth runs both: the `| cat |` and `| tee |` links are #3111's
        # `_grouped`, which reads the stage in front of the shell alone -- named.
        for text, expected in (("f() { cat; }\n{ echo '%s'; } | f | sh\n" % self.P, REPORTED),
                               ("f() { cat; }\n{ echo '%s'; } | f cat | sh\n" % self.P, REPORTED),
                               ("f() {\ncat\n}\n{ echo '%s'; } | f | sh\n" % self.P, REPORTED),
                               ("f() { tee log; }\n{ echo '%s'; } | f | sh\n" % self.P, CLEAN),
                               ("{ echo '%s'; } | cat | sh\n" % self.P, CLEAN)):
            with self.subTest(text=text[:22]):
                self.assertEqual(expected, marks(text))

    def test_an_alias_is_a_named_limit(self):
        # `alias r=sh; r t` runs under dash alone (bash expands no alias in a script, nor does zsh): a reading that needs
        # the step's shell, which the fold is not handed -- CLEAN, named.
        self.assertEqual(CLEAN, marks(self.T + "alias r=sh\nr t\n"))


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
