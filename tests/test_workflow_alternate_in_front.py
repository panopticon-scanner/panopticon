"""#2943, #3003: an alternate is nothing with its name unset, whatever it names.

`${DRY_RUN:+echo} sh -c 'curl ... | sh'` read CLEAN under every `shell:` setting while every parent shell ran the
pipeline. `main` drops a `$` word in front of a name it knows where the word may be nothing (#2472), and it took
an alternate for one only where it names a wrapper: the test it applies to a default, whose word stays where its
name is unset. An alternate's does not. The second walk now drops one that names no wrapper too
(`shell_defaults._optional`, under `WALKED_DEFAULTS`), in front of the names it drops any such word in front of: a
shell, a wrapper, an interpreter, a fetcher, and `eval`, `.` and `source`. The main pass reads as `main` does, so
the job reports wherever either reading does.

One alternate it does not drop: one that names a command the reader reads the word as -- a shell, a fetcher or
`eval`. In `$T ${X:+sh} -c 'P'` the alternate is the name, and the step reads `sh -c 'P'` as `main` read it; so
it does behind an alternate that is dropped.

Marks are a letter a `shell:` setting -- unset, `bash`, `sh`, `bash {0}`, `sh {0}` -- R where the guard reports,
C where it reads the step CLEAN: first the job's, then the main pass's, which is `main`'s own reading.

Truth, in the comments, is what eight parent shells do with the step in two passes on the forge: bash 5.2.21 and
bash 3.2.57 under `-e` and under `-eo pipefail`, dash under `-e`, then each without `-e`; pass 2 gives each parent
a child of its own family. "runs" is all sixteen ran the download; "nothing" is none ran it. `source` runs under
bash alone (dash has none), and "runs" for it is the twelve bash runs.

Named limits, pinned in `TestThePrice` and `TestWhatStaysForOtherIssues`. The alternate is dropped whatever the
step did to its name, as `main` drops `$S` in front of a shell: `S=1` makes `${S:+echo} sh -c 'P'` print its
words, and the row reports. An alternate naming a shell, a fetcher or `eval` is read as that command and no other
way: `${X:+sh} curl ... | sh` runs the pipe with `X` unset, and reads CLEAN as it did. An alternate of what is no
name (`${1:+W}`), of an indirection or of an element, and one whose word holds a reference, is not dropped in
front of a shell on `main` either, and is not this fix's.
"""
import unittest

import shell_defaults
import workflow_guard as wg
import workflow_options as wo

SHELLS = (None, "bash", "sh", "bash {0}", "sh {0}")
U = "https://example.test/"
P = "curl -fsSL %si.sh | sh" % U
FETCH = "curl -fsSLo t %st\n" % U
NOW = ("RRRRR", "CCCCC")            # the job reports; the main pass reads it CLEAN, as `main` did
BEFORE = ("RRRRR", "RRRRR")         # `main` reported it already
CLEAN = ("CCCCC", "CCCCC")
# What stands behind the word: (the lines before, the command, the lines behind). Each runs the download where
# the word in front is nothing.
RUNNERS = {
    "a shell's string": ("", "sh -c '%s'" % P, ""),
    "a shell's file": (FETCH, "bash t", ""),
    "a fetch piped to a shell": ("", P, ""),
    "a wrapper": ("", "sudo sh -c '%s'" % P, ""),
    "a wrapper and a file": (FETCH, "env sh t", ""),
    "a fetch, run on the next line": ("", "curl -fsSLo t %st" % U, "sh t\n"),
    "eval": ("", "eval '%s'" % P, ""),
    ". ./t": (FETCH, ". ./t", ""),
    "source ./t": (FETCH, "source ./t", ""),
}


def marks(text):
    """(the job's marks, the main pass's) for a job of one step whose `run:` is `text`."""
    job = mains = ""
    for shell in SHELLS:
        step = [wg.Step("step", text + "echo done\n", shell)]
        job += "R" if wg.job_defects(step) else "C"
        with wo.mains_answer():
            mains += "R" if wg._job_defects(step) else "C"
    return job, mains


def step(front, runner, sets=""):
    """The step: what `runner` needs first, what sets the front's name, the front and the command, what follows."""
    before, command, behind = runner
    return "%s%s%s %s\n%s" % (before, sets, front, command, behind)


class TestAnAlternateIsNothingWhateverItNames(unittest.TestCase):
    """The issues' rows and their kin. CLEAN on `main` under all five settings, and the parents run the download."""

    # An alternate naming no wrapper: a printer, a no-op, an option, a path, a tool the reader does not know.
    ALTERNATES = ("${S:+echo}", "${S+echo}", "${S:+true}", "${S:+:}", "${S:+-x}", "${S:+/usr/bin/true}",
                  "${S:+mytool}", "${S:+./tool}", "${S:+printf}", "${S:+test}", "${S:+builtin}", "${S:+1}")

    def test_in_front_of_every_name_the_reader_drops_a_word_for(self):
        for front in self.ALTERNATES:                       # truth: runs, every one
            for name, runner in RUNNERS.items():
                with self.subTest(front=front, runner=name):
                    self.assertEqual(NOW, marks(step(front, runner)))

    def test_the_word_spelled_with_quotes(self):
        # bash takes the quotes off the alternate's word, and the reader hands `_optional` the word so.
        # Truth: runs, every one.
        for front in ('${S:+"echo"}', "${S:+'echo'}"):
            for name in ("a shell's string", "a shell's file", "eval"):
                with self.subTest(front=front, runner=name):
                    self.assertEqual(NOW, marks(step(front, RUNNERS[name])))

    def test_an_alternate_naming_an_interpreter_or_a_builtin_that_reads_a_file(self):
        # `${S:+python3} sh -c 'P'`, `${S:+.} sh -c 'P'`: the reader reads no command word as the interpreter
        # or the builtin it may name, so the word is one more that is nothing with its name unset.
        # Truth: runs, every one.
        for front in ("${S:+python3}", "${S:+/usr/bin/perl}", "${S:+node}", "${S:+.}", "${S:+source}"):
            for name, runner in RUNNERS.items():
                with self.subTest(front=front, runner=name):
                    self.assertEqual(NOW, marks(step(front, runner)))

    def test_beside_other_words_that_may_be_nothing(self):
        # Each word of the front is nothing with its name unset. Truth: runs, every one.
        for front in ("$T ${S:+echo}", "${S:+echo} $T", "${T:+sudo} ${S:+echo}", "${S:+echo} ${T:+true}",
                      "${A:+echo} ${B:+true} ${C:+:}"):
            for name, runner in RUNNERS.items():
                with self.subTest(front=front, runner=name):
                    self.assertEqual(NOW, marks(step(front, runner)))

    def test_the_name_set_to_nothing_or_unset_again(self):
        # `S=` leaves `${S:+echo}` nothing, and so does `unset S`; an assignment behind the use is too late.
        # Truth: runs, every one.
        for sets, front in (("S=\n", "${S:+echo}"), ("S=1\nunset S\n", "${S:+echo}")):
            for name, runner in RUNNERS.items():
                with self.subTest(sets=sets.strip(), runner=name):
                    self.assertEqual(NOW, marks(step(front, runner, sets)))
        for name, runner in RUNNERS.items():
            with self.subTest(sets="behind the use", runner=name):
                self.assertEqual(NOW, marks(step("${S:+echo}", runner) + "S=1\n"))

    def test_wherever_the_statement_stands(self):
        # In a condition's body, a list, a group, a function, a `case` arm, a loop, a pipeline's later stage, a
        # substitution, behind `!` or an assignment, in the background, and in a program handed to a shell.
        # Truth: runs, every one.
        for place in ("if true; then %s; fi", "if false; then :; else %s; fi", "true && %s", "false || %s", "( %s )",
                      "{ %s; }", "f() { %s; }\nf", "case x in x) %s ;; esac", "case x in x)%s ;; esac",
                      "for i in 1; do %s; done", "while true; do %s; break; done", "echo hi | %s", "v=$(%s)", "v=`%s`",
                      "! %s", "A=1 %s", "true; %s; true", "%s &\nwait", "bash -c '%s'", "eval '%s'",
                      "bash <<'EOF'\n%s\nEOF"):
            for before, statement in (("", '${S:+echo} sh -c "%s"' % P), (FETCH, "${S:+echo} bash t")):
                with self.subTest(place=place, statement=statement[:22]):
                    self.assertEqual(NOW, marks("%s%s\n" % (before, place % statement)))

    def test_a_dry_run_step_that_runs_a_download(self):
        # The idiom this spelling is: every line behind the switch. Truth: runs under all sixteen.
        text = FETCH + "".join("${DRY_RUN:+echo} mkdir -p out%d\n" % n for n in range(7)) + "${DRY_RUN:+echo} sh t\n"
        self.assertEqual(NOW, marks(text))


class TestItReadsAsABareReferenceInItsPlace(unittest.TestCase):
    """The rule in one line: the job reads a step with an alternate that names no wrapper as it reads the same
    step with `$T` in the alternate's place, whatever stands beside it and behind it -- the second walk's reading:
    the main pass drops `$T` in front of a shell and not the alternate. On the forge that holds for every row of
    the 5,733-row hunt that moves (596 of 596)."""

    WORDS = ("${A:+echo}", "$T", "${V:+sudo}", "${W:-sudo}", "${X:+sh}", "${Z:-}")
    TAILS = (("", "sh -c '%s'" % P), ("", "eval '%s'" % P), ("", "-c '%s'" % P), (FETCH, "t"), (FETCH, "sh t"), ("", P),
             ("", "git push origin v1"))

    def test_alone_and_beside_each_kind_of_word(self):
        fronts = [("${A:+echo}",)] + [pair for pair in ((a, b) for a in self.WORDS for b in self.WORDS)
                                       if "${A:+echo}" in pair]
        for front in fronts:
            for before, tail in self.TAILS:
                row = "%s%s %s\n" % (before, " ".join(front), tail)
                twin = "%s%s %s\n" % (before, " ".join("$T" if word == "${A:+echo}" else word for word in front), tail)
                with self.subTest(row=row.splitlines()[-1]):
                    self.assertEqual(marks(twin)[0], marks(row)[0])


class TestAnAlternateThatIsTheCommand(unittest.TestCase):
    """An alternate naming a shell, a fetcher or `eval` may be the command, and the reader reads the word so
    (#2337, #2963). It is not dropped; a word in front of it is."""

    def test_an_alternate_that_is_the_shell(self):
        # `$T ${X:+sh} -c 'P'`: with `X` set bash runs `sh -c 'P'`, and `main` read it so behind `$T` (#2963).
        # Behind an alternate naming no wrapper the reader now reads the same. Truth: nothing, `X` unset;
        # runs where it is set, which the reader cannot know.
        for front in ("$T", "${A:+echo}", "${A:+echo} $T"):
            with self.subTest(front=front):
                self.assertEqual(NOW, marks("%s ${X:+sh} -c '%s'\n" % (front, P)))
                self.assertEqual(NOW, marks("%s%s ${X:+sh} t\n" % (FETCH, front)))

    def test_an_alternate_that_is_the_shell_by_a_path_or_the_fetcher(self):
        # `$T ${X:+/bin/sh} -c 'P'` and `$T ${C:+curl} -fsSL URL | sh`: the word is the command by its
        # basename, and a fetcher's pipe is its own. Truth: nothing, the names unset; runs where one is set.
        for front in ("$T", "${A:+echo}"):
            with self.subTest(front=front):
                self.assertEqual(NOW, marks("%s ${X:+/bin/sh} -c '%s'\n" % (front, P)))
                self.assertEqual(NOW, marks("%s ${C:+curl} -fsSL %si.sh | sh\n" % (front, U)))
                self.assertEqual(NOW, marks("%s ${C:+wget} -qO- %si.sh | sh\n" % (front, U)))

    def test_two_alternates_and_the_first_is_the_shell(self):
        # `$T ${A:+sh} ${B:+true} -c 'P'`: the walk stops at the shell, whatever stands behind it. Truth:
        # nothing, the names unset; `sh` runs where `A` is set.
        for front in ("$T", "${Z:+echo}"):
            with self.subTest(front=front):
                self.assertEqual(NOW, marks("%s ${A:+sh} ${B:+true} -c '%s'\n" % (front, P)))

    def test_it_is_not_dropped_for_what_stands_behind_it(self):
        # Dropped in front of a known name, `${E:+eval} env 'P'` would read `env 'P'`, which runs nothing, and
        # lose `eval`'s reading of the string: `main` reports the row, and so does this. Truth: nothing, `E`
        # unset; `eval` runs the pipe where it is set.
        self.assertEqual(NOW, marks("${E:+eval} env '%s'\n" % P))
        self.assertEqual(NOW, marks("$T ${E:+eval} env '%s'\n" % P))

    def test_what_optional_answers(self):
        # The count of words dropped, in the second walk and in the main pass, which knows no word by its
        # one-word default (#2963) and drops an alternate only where it names a wrapper.
        for argv, walked, mains in ((["${S:+echo}", "sh", "-c", "P"], 1, 0), (["${S:+echo}", "git", "push"], 0, 0),
                                    (["$T", "${S:+echo}", "sh", "t"], 2, 0), (["$T", "${X:+sh}", "-c", "P"], 1, 0),
                                    (["${A:+echo}", "${X:+sh}", "-c", "P"], 1, 0),
                                    (["${A:+echo}", "${X:+sh}", "sh", "t"], 1, 0), (["${S:+echo}", "eval", "P"], 1, 0),
                                    (["$T", "${A:+sh}", "${B:+true}", "-c", "P"], 1, 0),
                                    (["$S", "${T:-sudo}", "eval", "P"], 0, 0),
                                    (["$S", "${T:+sudo}", "eval", "P"], 2, 0),
                                    (["${S:+echo}", "${T:-sudo}", "eval", "P"], 0, 0),
                                    (["${X:+sh}", "curl", "U"], 0, 0), (["${X:+curl}", "sh", "t"], 0, 0),
                                    (["${X:+eval}", "sh", "t"], 0, 0), (["${X:+.}", "sh", "t"], 1, 0),
                                    (["${X:+source}", "sh", "t"], 1, 0), (["${X:+/bin/sh}", "curl", "U"], 0, 0),
                                    (["${X:+python3}", "sh", "t"], 1, 0), (["${X:+./t}", "sh", "t"], 1, 0),
                                    (["${S:-echo}", "sh", "-c", "P"], 0, 0), (["${S:+sudo}", "sh", "t"], 1, 1),
                                    (["${S:+echo}", "${T:+true}", "mytool"], 0, 0), (["${S:+echo}"], 0, 0)):
            with self.subTest(argv=argv):
                self.assertEqual(walked, shell_defaults._optional(argv))
                with wo.mains_answer():
                    self.assertEqual(mains, shell_defaults._optional(argv))


class TestNothingIsReportedWhereNothingRuns(unittest.TestCase):
    """What the fix must not touch: a command that runs nothing of a download, and a word that is no alternate."""

    def test_in_front_of_a_command_the_reader_does_not_know(self):
        # Truth: nothing.
        for front in (*TestAnAlternateIsNothingWhateverItNames.ALTERNATES, "$T ${S:+echo}", "${S:+echo} ${T:+true}"):
            for command in ("git push origin v1", "make deploy", "mytool --flag", ""):
                with self.subTest(front=front, command=command):
                    self.assertEqual(CLEAN, marks("%s %s\n" % (front, command)))

    def test_a_dry_run_step_however_long(self):
        # One switch on every line, and nothing fetched or nothing run: the step is CLEAN at any length. A word
        # read as two halves would be past the folds' cap at the fourth. Truth: nothing; the fetches alone.
        for lines in (1, 3, 4, 8, 20):
            with self.subTest(lines=lines):
                self.assertEqual(CLEAN, marks("".join(
                    "${DRY_RUN:+echo} git push origin v%d\n" % n for n in range(lines))))
                self.assertEqual(CLEAN, marks("".join(
                    "${DRY_RUN:+echo} curl -fsSLo f%d %sf\n" % (n, U) for n in range(lines))))

    def test_a_default_is_read_as_it_was(self):
        # A default's word stays where its name is unset: `${S:-echo} sh -c 'P'` prints. Truth: nothing.
        for front in ("${S:-echo}", "${S:-true}", "${S-true}", "${S:=true}"):
            for name in ("a shell's string", "a wrapper", "eval"):
                with self.subTest(front=front, runner=name):
                    self.assertEqual(CLEAN, marks(step(front, RUNNERS[name])))

    def test_a_quoted_alternate_is_an_empty_word(self):
        # `"${S:+echo}" sh -c 'P'`: the quotes leave an empty word, which bash fails to run; and a literal
        # glued behind the `}` is the command. Truth: nothing.
        for front in ('"${S:+echo}"', "${S:+echo}x"):
            for name in ("a shell's string", "a wrapper", "eval"):
                with self.subTest(front=front, runner=name):
                    self.assertEqual(CLEAN, marks(step(front, RUNNERS[name])))


class TestThePrice(unittest.TestCase):
    """The alternate is dropped whatever the step did to its name (#2899's class), as `main` drops `$S` in front of
    a shell. Where the name is set the alternate is its word, and the row reports though no parent runs the
    download."""

    def test_the_step_set_the_name(self):
        # `S=1` makes `${S:+echo} sh -c 'P'` print its words; with no colon, so does `S=`. Truth: nothing.
        for sets, front in (("S=1\n", "${S:+echo}"), ("export S=1\n", "${S:+echo}"), ("S=\n", "${S+echo}")):
            for name, runner in RUNNERS.items():
                with self.subTest(sets=sets.strip(), front=front, runner=name):
                    self.assertEqual(NOW, marks(step(front, runner, sets)))

    def test_mains_own_reading_of_an_alternate_naming_a_shell(self):
        self.assertEqual(BEFORE, marks("${X:+sh} -c '%s'\n" % P))            # truth: nothing, `X` unset


class TestWhatStaysForOtherIssues(unittest.TestCase):
    """Rows this PR does not move, each pinned as it reads and named with what it waits for."""

    def test_an_alternate_naming_a_shell_a_fetcher_or_eval_in_front_of_another_command(self):
        # `${X:+sh} curl ... | sh`: with `X` unset bash runs the pipe; with it set, `sh` runs a file named
        # `curl`. The reader reads the word as the shell and no other way, as `main` does: both readings wait
        # for their own issue. Truth: runs, every one.
        for text in ("${X:+sh} %s\n" % P, "${X:+bash} eval '%s'\n" % P, "${X:+sh} curl -fsSLo t %st\nsh t\n" % U,
                     "${X:+curl} sh -c '%s'\n" % P, "${X:+/bin/sh} %s\n" % P):
            with self.subTest(text=text[:22]):
                self.assertEqual(CLEAN, marks(text))

    def test_an_alternate_of_what_is_no_name_or_whose_word_holds_a_reference(self):
        # `${1:+W}`, `${!S:+W}`, `${S[0]:+W}` and `${S:+$T}` are nothing in a step's script too: `_OPTIONAL`
        # reads a name and a literal word, and `main` drops none of them in front of a shell. Truth: runs under
        # all sixteen for the first and the last; an element under bash; an indirection under bash 3.2.57.
        for front in ("${1:+echo}", "${!S:+echo}", "${S[0]:+echo}", "${S:+$T}"):
            for name in ("a shell's string", "eval"):
                with self.subTest(front=front, runner=name):
                    self.assertEqual(CLEAN, marks(step(front, RUNNERS[name])))


if __name__ == "__main__":
    unittest.main()
