"""#3002, #3007, #3038: the other words bash makes nothing of in front of a command, and what stands behind them.

`main` drops an unquoted `$` word in front of a name it knows (#2472); the second walk knows `eval`, `.` and
`source` behind such words (#2997) and drops an alternate whatever it names (#3003). Three holes stayed in that one
reader, `shell_defaults._optional`, each CLEAN under every `shell:` setting while the parent shells run the pipeline:

- #3002: a `$` word in front of a default or an alternate of several words (`$T ${S:+sudo -E} sh -c 'P'`), and a
  default that is only a blank (`${S:- } sh -c 'P'`);
- #3007: a default naming a wrapper in front of the wrapper's own words (`${SUDO:-sudo} -E sh -c 'P'`), and a
  printer piped to a shell behind a word that is nothing (`$SUDO echo 'P' | sh`);
- #3038: a default naming a wrapper whose name the step set to `command` (`S=command; ${S:-sudo} eval 'P'`).

And the limits #2997's and #3003's fixes pinned as shared with `main`: the other words that are nothing with their
name unset -- a positional parameter, `$@` and a quoted `"$@"`, an array, an indirection, a pattern taken off, a
substring, a case change, a default that holds one more name, an alternate of any of them.

The second walk reads them all now, in folds of its own (`shell_defaults._drops`): every fold `main` reads is read
as it was, and each is read once more with these words read as nothing. So the job reports wherever either reading
does, the main pass reads as `main` does, and a check that stands behind such a word is never credited at the cost
of a report (#3037's class: `TestNoReportIsLostToACheck`).

Marks are a letter a `shell:` setting -- unset, `bash`, `sh`, `bash {0}`, `sh {0}` -- R where the guard reports,
C where it reads the step CLEAN: first the job's, then the main pass's, which is `main`'s own reading.

Truth, in the comments, is what eight parent shells do with the step in two passes on the forge: bash 5.2.21 and
bash 3.2.57 under `-e` and under `-eo pipefail`, dash under `-e`, then each without `-e`; pass 2 gives each parent
a child of its own family. "runs" is all sixteen ran the download; "nothing" is none fetched or ran; "the fetch
alone" is the step's own `curl -o` and no run. "bash runs" is the twelve bash runs, where dash refuses the form.

Named limits, pinned in `TestThePrice` and `TestWhatStaysForOtherIssues`. The reader has one grammar for the five
settings, so a form dash refuses -- an array, a substring, a case change, `function` -- reports under the two `sh`
settings too, as #2997's `source` does. A word is read as nothing whatever the step did to its name (#2899's class):
`set -- echo` makes `$1 sh -c 'P'` print its words, and the row reports; so does a default naming a wrapper in front
of that wrapper's own words where the step set its name to another word. The names a job's steps set to `command`
are the job's, read wherever a text spells the assignment and whatever follows it. A quoted nothing beside a word
(`""$@`), a quoted reference as a default (`${S:-"$T"}`) and a quoted `"$@"` the PARENT expands inside a `-c` string
leave an empty word bash fails to run; the reader has taken the quotes off. Not this batch's: a substitution that
prints nothing (#2693), two references glued (#3016), `coproc` (#2894), a filter that passes its input on behind a
dropped word (`workflow_printers`), and a `$` word where a default wrapper's own words end.
"""
import unittest

import shell_command
import shell_defaults
import shell_reader
import shell_wrappers
import workflow_guard as wg
import workflow_options as wo

SHELLS = (None, "bash", "sh", "bash {0}", "sh {0}")
U = "https://example.test/t"
P = "curl -fsSL %s | sh" % U
FETCH = "curl -fsSLo t %s\n" % U
CHECK = 'echo "%s  t" | sha256sum -c -' % ("a" * 64)
NOW = ("RRRRR", "CCCCC")            # the job reports; the main pass reads it CLEAN, as `main` did
BEFORE = ("RRRRR", "RRRRR")         # `main` reported it already
CLEAN = ("CCCCC", "CCCCC")
# What stands behind the words: (the lines before, the command). Each runs the download where the words in front
# are nothing.
SHELL = ("", "sh -c '%s'" % P)
EVAL = ("", "eval '%s'" % P)
PIPE = ("", P)
FILE = (FETCH, "bash t")
DOT = (FETCH, ". ./t")
WRAPPED = ("", "sudo sh -c '%s'" % P)
RUNNERS = {"a shell's string": SHELL, "eval": EVAL, "a fetch piped to a shell": PIPE, "a shell's file": FILE,
           ". ./t": DOT, "a wrapper": WRAPPED}


def marks(text):
    """(the job's marks, the main pass's) for a job of one step whose `run:` is `text`."""
    job = mains = ""
    for shell in SHELLS:
        step = [wg.Step("step", text + "\necho done", shell)]
        job += "R" if wg.job_defects(step) else "C"
        with wo.mains_answer():
            mains += "R" if wg._job_defects(step) else "C"
    return job, mains


def reports(text):
    """The job's marks alone, for a test that holds only that the job reports: half of `marks`' runs."""
    return "".join("R" if wg.job_defects([wg.Step("step", text + "\necho done", shell)]) else "C"
                   for shell in SHELLS)


def step(front, runner, sets=""):
    """The step: what `runner` needs first, what sets the front's name, then the front and the command."""
    before, command = runner
    return "%s%s%s %s" % (before, sets, front, command)


class TestAWordInFrontOfSeveralWords(unittest.TestCase):
    """#3002, first half: a `$` word in front of a default or an alternate that holds a blank. The reader kept
    only a stage's FIRST such word whole, so `$T` stayed the command and nothing behind it was read."""

    FRONTS = ("$T ${S:+sudo -E}", "$A $B ${S:+sudo -E}", "$T ${S:-sudo -E}", "${T:+env} ${S:+sudo -E}",
              "$T ${S:+env A=1}", "$T ${S:- }")

    def test_the_issues_rows(self):
        # The six fronts of the issue's kit in front of its next words. Truth: runs, every one (the kit's 76
        # rows, both places).
        for front in self.FRONTS:
            for name in ("a shell's string", "a fetch piped to a shell", "a shell's file", "a wrapper"):
                with self.subTest(front=front, runner=name):
                    self.assertEqual(NOW, marks(step(front, RUNNERS[name])))
            with self.subTest(front=front, runner="bash -c"):
                self.assertEqual(NOW, marks("%s bash -c '%s'" % (front, P)))

    def test_on_a_function_headers_line(self):
        for front in self.FRONTS:                           # truth: runs, every one
            with self.subTest(front=front):
                self.assertEqual(NOW, marks("f() { %s sh -c '%s'; }\nf" % (front, P)))

    def test_in_front_of_eval_and_dot(self):
        # The alternate is nothing with its name unset and a builtin runs; behind a default naming `command` it
        # runs too. Truth: runs, every one.
        for front in ("$T ${S:+sudo -E}", "$T ${S:+env A=1}", "$T ${S:-command --}"):
            for name in ("eval", ". ./t"):
                with self.subTest(front=front, runner=name):
                    self.assertEqual(NOW, marks(step(front, RUNNERS[name])))

    def test_behind_the_other_words_that_are_nothing(self):
        for front in ("$1 ${S:+sudo -E}", '"$@" ${S:+sudo -E}', "${S#x} ${T:+sudo -E}"):    # truth: runs
            with self.subTest(front=front):
                self.assertEqual(NOW, marks(step(front, SHELL)))

    def test_a_word_behind_the_word_kept_whole(self):
        # `main` reads a stage's first such word and the words behind it; one more word in front changes nothing
        # of that. Truth: runs, every one.
        for front, was in (("${S:+sudo -E} $T", BEFORE), ("$A ${S:+sudo -E} $B", NOW),
                           ("${A:+sudo -E} ${B:+env A=1}", BEFORE), ("$T ${A:+sudo -E} ${B:+env A=1}", NOW)):
            with self.subTest(front=front):
                self.assertEqual(was, marks(step(front, SHELL)))

    def test_the_default_is_its_words_where_its_name_is_unset(self):
        # `$T ${S:-echo hi} sh -c 'P'` prints: a default's words stay. An alternate's do not.
        self.assertEqual(CLEAN, marks(step("$T ${S:-echo hi}", SHELL)))        # truth: nothing
        self.assertEqual(NOW, marks(step("$T ${S:+echo hi}", SHELL)))          # truth: runs
        self.assertEqual(NOW, marks("$T ${S:-sh -c} '%s'" % P))                # truth: runs

    def test_the_controls(self):
        # What `main` reported it reports still, and a printer's words are printed. Truth: runs for the first
        # three, nothing for the `echo` rows.
        for front in ("", "$T", "${S:+sudo -E}"):
            with self.subTest(front=front):
                self.assertEqual(BEFORE, marks(step(front, SHELL).strip()))
        for front in self.FRONTS:
            with self.subTest(front=front, runner="echo"):
                self.assertEqual(CLEAN, marks("%s echo '%s'" % (front, P)))


class TestADefaultThatIsOnlyABlank(unittest.TestCase):
    """#3002, second half: `${S:- }` is nothing to bash -- the default is a blank, which it splits away -- and
    `_OPTIONAL` read an empty default only."""

    def test_the_issues_rows(self):
        for front in ("${S:- }", "${S:- } $T", "${S:-  }", "${S:= }"):         # truth: runs, every one
            for name in ("a shell's string", "a fetch piped to a shell", "a wrapper", "eval"):
                with self.subTest(front=front, runner=name):
                    self.assertEqual(NOW, marks(step(front, RUNNERS[name])))

    def test_what_main_read_of_one_already(self):
        # In front of a file's reader `main` reads the word whole and drops it (#2731), and with no colon too.
        for text in (step("${S:- }", FILE), step("${S:- }", DOT), step("${S- }", SHELL), step("${S:+ }", SHELL)):
            with self.subTest(text=text[-30:]):
                self.assertEqual(BEFORE, marks(text))                          # truth: runs, every one

    def test_the_controls(self):
        # Quoted, the blank is a word bash fails to run; with a letter beside it the default is that word; and
        # a printer prints. Truth: nothing, every one.
        for text in (step('"${S:- }"', SHELL), step("${S:- x}", SHELL), "${S:- } echo '%s'" % P):
            with self.subTest(text=text[:12]):
                self.assertEqual(CLEAN, marks(text))


class TestTheOtherWordsThatAreNothing(unittest.TestCase):
    """The limits #2997's and #3003's fixes pinned as shared with `main`: each is nothing with its name unset,
    and the second walk drops it now where it dropped a bare `$S`."""

    # Truth: runs, every one.
    EVERY_SHELL = ("$1", "${1}", "${10}", "$@", '"$@"', '"${@}"', "${@}", "${*}", "$!", "${S#x}", "${S##x}",
                   "${S%x}", "${S%%x}", "${S:-$T}", "${S:-${T}}", "${S:-${T:-}}", "${S-$T}", "${S:=$T}",
                   "${1:+echo}", "${1+echo}", "${1:-}", "${S:+$T}", '${S:+"x"}', "$1 $2", "$@ $S", "$S $1")
    # Truth: bash runs, and dash refuses the form -- but `${!S}` and its like, which bash 5.2.21 refuses too with
    # the name unset: bash 3.2.57 runs those, and the case changes and the transformations run under 5.2.21 alone.
    BASH_ALONE = ("${S/x/y}", "${S//x/y}", "${S:0}", "${S:1:2}", "${S: -1}", "${S^^}", "${S,}", "${S@Q}",
                  "${S[0]}", "${S[@]}", "${S[*]}", '"${S[@]}"', '"${S[@]:1}"', '"${@:2}"', '"${S[@]/x/y}"',
                  "${!S}", "${!S[@]}", '"${!S[@]}"', "${!1}", "${!S:+echo}", "${S[0]:+echo}", '"${S[@]:+echo}"',
                  "${@+echo}")

    def test_in_front_of_a_shell_and_of_eval(self):
        for front in self.EVERY_SHELL + self.BASH_ALONE:
            for name in ("a shell's string", "eval"):
                with self.subTest(front=front, runner=name):
                    self.assertEqual(NOW, marks(step(front, RUNNERS[name])))

    def test_in_front_of_the_other_names(self):
        for front in ("$1", '"$@"', "${S#x}", '"${S[@]}"'):                    # truth: runs; bash runs the array
            for name in ("a fetch piped to a shell", "a shell's file", ". ./t", "a wrapper"):
                with self.subTest(front=front, runner=name):
                    self.assertEqual(NOW, marks(step(front, RUNNERS[name])))
            # An interpreter, as `main` reports the written `python3 t`. The forge's download is a shell script,
            # which no python runs, so its truth is the fetch alone, there as here.
            with self.subTest(front=front, runner="an interpreter"):
                self.assertEqual(NOW, marks("%s%s python3 t" % (FETCH, front)))
            with self.subTest(front=front, runner="a fetch, run on the next line"):
                self.assertEqual(NOW, marks("%s curl -fsSLo t %s\nsh t" % (front, U)))

    def test_beside_the_words_main_drops(self):
        # A wrapper that execs still runs no builtin: `"$@" ${S:-sudo} eval 'P'` runs `sudo eval`.
        for front in ('"$@" ${S:-sudo}', "${S:-sudo} $1", "${S#x} ${T:-command}"):          # truth: runs
            with self.subTest(front=front, runner="a shell's string"):
                self.assertEqual(NOW, marks(step(front, SHELL)))
        self.assertEqual(NOW, marks(step("${S#x} ${T:-command}", EVAL)))                    # truth: runs
        for front in ('"$@" ${S:-sudo}', "${S:-sudo} $1", "$1 ${T:-sudo}"):                 # truth: nothing
            with self.subTest(front=front, runner="eval"):
                self.assertEqual(CLEAN, marks(step(front, EVAL)))

    def test_a_word_that_is_one(self):
        # Each is a word with its name unset, or no expansion at all, and bash fails to run it: a quoted
        # reference, `"$*"`, a `$@` in single quotes or behind a backslash, a count, the shell's PID, `$1` and a
        # `0`, a default that is a word, an error. Truth: nothing, every one.
        for front in ('"$1"', '"$S"', '"$*"', '"${S[*]}"', '"${S[0]}"', "'$@'", chr(92) + "$@", '"$@"x', "$#",
                      "$$", "$10", "${#S}", "${S:-x}", "${S:?}", "${S:-${T:-x}}", '"$1" "$@"'):
            for name in ("a shell's string", "eval"):
                with self.subTest(front=front, runner=name):
                    self.assertEqual(CLEAN, marks(step(front, RUNNERS[name])))

    def test_the_forms_no_shell_makes_nothing_of(self):
        # The grammar hunt's: a default cannot assign to a positional parameter, to `$@` or to `$*`; bash 5.2.21
        # refuses a case change or a transformation of an unset indirection and 3.2.57 has neither; a quoted
        # default keeps its word where there is no element; an array's keys take no operator. Truth: nothing.
        for front in ("${1:=}", "${@:=}", "${*:=$T}", "${!S^^}", "${!S,}", "${!S@Q}", '"${S[@]:-}"', '"${@:-}"',
                      '"${S[@]:-x}"', '"${@:?}"', '"${!S[@]#x}"'):
            with self.subTest(front=front):
                self.assertEqual(CLEAN, marks(step(front, SHELL)))

    def test_only_in_front_of_a_name_the_reader_knows(self):
        for text in ("$1 echo '%s'" % P, "$1 /x/eval '%s'" % P, '"$@" true'):               # truth: nothing
            with self.subTest(text=text[:12]):
                self.assertEqual(CLEAN, marks(text))
        # `$1 A=1 sh -c 'P'`: bash reads an assignment off the words as written, and `A=1` behind another word
        # is none; with `$1` gone it is the command, and bash fails to run it. Truth: nothing.
        self.assertEqual(CLEAN, marks("$1 A=1 sh -c '%s'" % P))

    def test_beside_what_else_stands_in_front_of_a_command(self):
        # Behind `!` and an assignment, in front of a written wrapper, and where `builtin` hands the words on
        # (#2665). Truth: runs, every one; `builtin` under bash alone.
        for text in ("! $1 sh -c '%s'" % P, "A=1 $1 sh -c '%s'" % P, "$1 nohup sh -c '%s'" % P,
                     "$1 exec sh -c '%s'" % P, "$1 xargs sh -c '%s' < /dev/null" % P,
                     "$1 wget -qO- %s | sh" % U, '"$@" command eval \'%s\'' % P, "$1 builtin eval '%s'" % P,
                     "builtin $1 eval '%s'" % P, 'builtin "$@" eval \'%s\'' % P, "builtin ${S#x} eval '%s'" % P):
            with self.subTest(text=text[:22]):
                self.assertEqual(NOW, marks(text))
        # Behind a WRITTEN wrapper `main` reports a `$` command word as one it cannot read. Unmoved.
        for text in ("sudo $1 sh -c '%s'" % P, "env $1 sh -c '%s'" % P, "command $1 eval '%s'" % P):
            with self.subTest(text=text[:22]):
                self.assertEqual(BEFORE, marks(text))


class TestADefaultNamingAWrapperInFrontOfItsOwnWords(unittest.TestCase):
    """#3007, hole 1: `_optional` dropped a default naming a wrapper only where the very NEXT word is a name it
    knows; with the wrapper's option next, the default stayed the command and nothing behind it was read."""

    # Truth: runs, every one -- but `command -p`, which bash 3.2.57 does not run, and `exec -a`, which dash has not.
    ISSUES = ("${SUDO:-sudo} -E", "${S:-env} A=1", "${S:-env} -i", "${S:-nice} -n 5", "${S:-command} --",
              "${S:-command} -p", "${S:-exec} -a x")

    def test_the_issues_rows(self):
        for front in self.ISSUES:
            with self.subTest(front=front):
                self.assertEqual(NOW, marks(step(front, SHELL)))

    def test_command_runs_a_builtin_behind_its_options(self):
        for front in ("${S:-command} --", "${S:-command} -p", "$T ${S:-command} -p"):       # truth: runs
            with self.subTest(front=front):
                self.assertEqual(NOW, marks(step(front, EVAL)))

    def test_its_other_spellings_and_what_it_stands_in_front_of(self):
        for front in ("${S:=sudo} -E", "${S-sudo} -E", "${S:-sudo} -E -H", "${S:-sudo} -u root",
                      "${S:-sudo} --", "${S:-timeout} 5", "${S:-sudo} -E env A=1"):         # truth: runs
            with self.subTest(front=front):
                self.assertEqual(NOW, marks(step(front, SHELL)))
        for name in ("a fetch piped to a shell",):
            with self.subTest(runner=name):
                self.assertEqual(NOW, marks(step("${S:-sudo} -E", RUNNERS[name])))
        self.assertEqual(NOW, marks("${S:-sudo} -E bash -c '%s'" % P))
        # By a path, as `main` reads one in front of a shell. Not forge-verified: the forge's `sudo` is a stub
        # on PATH, and no `/usr/bin/sudo` runs there (truth on it: nothing).
        self.assertEqual(NOW, marks(step("${S:-/usr/bin/sudo} -E", SHELL)))

    def test_behind_words_that_are_nothing(self):
        for front in ("$T ${S:-sudo} -E", "$A $B ${S:-env} A=1", "$1 ${S:-sudo} -E"):       # truth: runs
            with self.subTest(front=front):
                self.assertEqual(NOW, marks(step(front, SHELL)))

    def test_the_written_wrapper_and_the_default_with_no_word_of_its_own(self):
        for text in ("sudo -E sh -c '%s'" % P, step("${S:-sudo}", SHELL), step("${S:-nohup}", SHELL),
                     step("${S:-sudo} -E", FILE)):                                      # truth: runs, every one
            with self.subTest(text=text[-30:]):
                self.assertEqual(BEFORE, marks(text))

    def test_a_wrapper_that_execs_runs_no_builtin(self):
        for front in ("${S:-sudo} -E", "${S:-env} A=1", "${S:-nice} -n 5", "$T ${S:-sudo} -E"):
            with self.subTest(front=front):                                             # truth: nothing
                self.assertEqual(CLEAN, marks(step(front, EVAL)))

    def test_the_controls(self):
        # An alternate is nothing with its name unset, and `-E` is then the command; so is it behind a bare
        # word. A default naming a word that is no wrapper is that word. Truth: nothing, every one.
        for front in ("${S:+sudo} -E", "$S -E", "${S:-echo} -E"):
            with self.subTest(front=front):
                self.assertEqual(CLEAN, marks(step(front, SHELL)))
        for text in ("${S:-sudo} -E echo '%s'" % P, "${S:-sudo} -E", "${SUDO:-sudo} -E $PKG install -y curl",
                     "${S:-sudo} -E $T echo hi"):
            with self.subTest(text=text):
                self.assertEqual(CLEAN, marks(text))


class TestAPrinterBehindAWordThatIsNothing(unittest.TestCase):
    """#3007, hole 2: `$SUDO echo 'P' | sh`. The reader knew no printer behind a dropped word, so the stage in
    front of the shell was a command it does not follow."""

    FRONTS = ("$S", "$A $B", "${S:-}", "${S:-sudo}", "${S:+sudo}", "${S:-command}")       # the issue's six

    def test_the_issues_rows(self):
        for front in self.FRONTS:                           # truth: runs, every one
            with self.subTest(front=front, printer="echo"):
                self.assertEqual(NOW, marks("%s echo '%s' | sh" % (front, P)))
            with self.subTest(front=front, printer="printf"):
                self.assertEqual(NOW, marks("%s printf '%%s\\n' '%s' | sh" % (front, P)))
        for front in ("$S", "$A $B", "${S:+sudo}"):         # `main` read `cat t` behind the other three
            with self.subTest(front=front, printer="cat"):
                self.assertEqual(NOW, marks("%s%s cat t | sh" % (FETCH, front)))
        for front in ("${S:-}", "${S:-sudo}", "${S:-command}"):
            with self.subTest(front=front, printer="cat"):
                self.assertEqual(BEFORE, marks("%s%s cat t | sh" % (FETCH, front)))

    def test_behind_the_other_words_that_are_nothing(self):
        for front in ("$1", '"$@"', "${S:- }", "${S#x}", "$T ${S:+sudo -E}"):               # truth: runs
            with self.subTest(front=front):
                self.assertEqual(NOW, marks("%s echo '%s' | sh" % (front, P)))

    def test_wherever_the_printed_text_goes(self):
        for text in ("$S echo '%s' | bash" % P, "$S echo '%s' | sudo sh" % P, '$S echo "%s" | sh -s' % P,
                     "$S /bin/echo '%s' | sh" % P, "%s$S cat t > u\nsh u" % FETCH,
                     'sh -c "$($S echo \'%s\')"' % P, 'eval "$($S echo \'%s\')"' % P):     # truth: runs
            with self.subTest(text=text[:28]):
                self.assertEqual(NOW, marks(text))

    def test_cat_reading_the_fetched_file_on_its_input(self):
        # Since #3057 `main` reads the file `cat` reads on its standard input as the program a shell behind the
        # pipe runs, written out and behind the words `main` drops; behind the other words that are nothing the
        # second walk reads it. Truth: runs, every one.
        for front in ("", "$A $B ", "${S:-} ", "${S:-sudo} ", "${S:-command} "):
            with self.subTest(front=front):
                self.assertEqual(BEFORE, marks("%s%scat < t | sh" % (FETCH, front)))
        for front in ("$S", "${S:+sudo}", "$1", '"$@"'):
            with self.subTest(front=front):
                self.assertEqual(NOW, marks("%s%s cat < t | sh" % (FETCH, front)))
        # No shell reads it, or the file is not the fetched one. Truth: the fetch alone.
        for text in ("%s$S cat < t" % FETCH, "%s$S cat < u | sh" % FETCH):
            with self.subTest(text=text[-14:]):
                self.assertEqual(CLEAN, marks(text))

    def test_the_controls(self):
        self.assertEqual(BEFORE, marks("echo '%s' | sh" % P))                              # truth: runs
        # No shell reads it; what it prints fetches nothing; a quoted word is one; `true` prints nothing; the
        # file is not the fetched one. Truth: nothing, or the fetch alone.
        for text in ("$S echo '%s'" % P, "$S echo hi | sh", "$S echo '%s' | cat" % P, '"$S" echo \'%s\' | sh' % P,
                     "$S true '%s' | sh" % P, "%s$S cat u | sh" % FETCH):
            with self.subTest(text=text[:28]):
                self.assertEqual(CLEAN, marks(text))


class TestADefaultWhoseNameTheStepSets(unittest.TestCase):
    """#3038: a default naming a wrapper is the wrapper with its name unset -- and with it set, what the step
    set. `S=command; ${S:-sudo} eval 'P'` runs `P`."""

    def test_the_issues_row_and_its_spellings(self):
        for sets in ("S=command\n", "S=builtin\n", 'S="command"\n', "export S=command\n", "readonly S=command\n",
                     "if true; then S=command; fi\n", "S=command; ", "f() { S=command; }\nf\n"):
            with self.subTest(sets=sets.strip()):           # truth: runs; `builtin` under bash alone
                self.assertEqual(NOW, marks(step("${S:-sudo}", EVAL, sets)))

    def test_the_other_defaults_and_the_words_beside_them(self):
        for front in ("${S:-env}", "${S:=sudo}", "${S:-nohup}", "$T ${S:-sudo}", "${S:-sudo} $T"):
            with self.subTest(front=front):                 # truth: runs, every one
                self.assertEqual(NOW, marks(step(front, EVAL, "S=command\n")))

    def test_a_name_set_to_nothing_with_no_colon_in_the_word(self):
        for sets in ("S=\n", 'S=""\n', "S=''\n"):           # truth: runs: bash makes no word of `${S-sudo}`
            with self.subTest(sets=sets.strip()):
                self.assertEqual(NOW, marks(step("${S-sudo}", EVAL, sets)))
        self.assertEqual(CLEAN, marks(step("${S:-sudo}", EVAL, "S=\n")))       # truth: nothing: `sudo eval`

    def test_a_default_of_several_words_in_front_of_builtin(self):
        # `main` reads `${S:-sudo -E} eval 'P'` without the word (#2731); in front of `builtin eval` nothing
        # read it. Truth: bash runs.
        self.assertEqual(BEFORE, marks(step("${S:-sudo -E}", EVAL, "S=command\n")))
        self.assertEqual(NOW, marks("S=command\n${S:-sudo -E} builtin eval '%s'" % P))
        self.assertEqual(CLEAN, marks("${S:-sudo -E} builtin eval '%s'" % P))  # truth: nothing

    def test_the_controls(self):
        # Unset, or set to a wrapper that execs or to a word that is no command, the word runs no builtin; nor
        # is `S` another name's assignment, or a longer word's. Truth: nothing, every one.
        for sets in ("", "S=sudo\n", "S=env\n", "S=1\n", "T=command\n", "XS=command\n", "S=commander\n",
                     "S=command-not\n", "S=$command\n"):
            with self.subTest(sets=sets.strip()):
                self.assertEqual(CLEAN, marks(step("${S:-sudo}", EVAL, sets)))
        for front, runner in (("${S:-sudo}", ("", "/x/eval '%s'" % P)), ("${S:-sudo}", ("", "echo '%s'" % P))):
            with self.subTest(front=front, command=runner[1][:8]):
                self.assertEqual(CLEAN, marks(step(front, runner, "S=command\n")))

    def test_whatever_the_default_names(self):
        # Set, a default is what the step set, whatever word it would have been: `S=command; ${S:-echo} eval 'P'`
        # runs `P`. Truth: runs, every one; `builtin` under bash alone.
        for sets, front, runner in (("S=command\n", "${S:-echo}", EVAL), ("S=command\n", "${S:-true}", EVAL),
                                    ("S=builtin\n", "${S:-echo}", EVAL), ("S=command\n", "${S:-echo}", SHELL),
                                    ("S=\n", "${S-echo}", SHELL), ("S=command\n", "$T ${S:-echo}", EVAL)):
            with self.subTest(sets=sets.strip(), front=front, command=runner[1][:4]):
                self.assertEqual(NOW, marks(step(front, runner, sets)))
        # Unset, set to another word, or set to nothing with a colon in the word, it prints. Truth: nothing.
        for sets, front, runner in (("", "${S:-echo}", EVAL), ("S=1\n", "${S:-echo}", EVAL),
                                    ("S=\n", "${S:-echo}", SHELL), ("S=command\n", "${S:-echo}", ("", "echo hi"))):
            with self.subTest(sets=sets.strip(), front=front, command=runner[1][:4]):
                self.assertEqual(CLEAN, marks(step(front, runner, sets)))

    def test_the_names_are_the_jobs_and_no_other_jobs(self):
        text = "${S:-sudo} eval '%s'" % P
        sets = [wg.Step("first", "S=command", None), wg.Step("second", text, None)]
        self.assertTrue(wg.job_defects(sets))               # a step's assignment is read for the steps after it
        self.assertFalse(wg.job_defects([wg.Step("only", text, None)]))        # and the next job has none
        self.assertFalse(shell_wrappers.set_to("runs", "S"))                   # nor has anything outside a job


class TestWhereverTheStatementStands(unittest.TestCase):
    """The same reading in each place the hunt put the statement."""

    PLACES = {
        "a `-c` string": "sh -c '%s'",
        "a heredoc": "sh <<'EOF'\n%s\nEOF",
        "a function": "f() { %s; }\nf",
        "a `function` function": "function f { %s; }\nf",
        "a group": "{ %s; }",
        "a subshell": "( %s )",
        "a branch": "if true; then %s; fi",
        "an `else` branch": "if false; then :; else %s; fi",
        "an `elif` condition": "if false; then :; elif %s; then :; fi",
        "after `&&`": "true && %s",
        "after `||`": "false || %s",
        "after `;`": "true; %s",
        "a condition": "if %s; then :; fi",
        "a `for` body": "for x in 1; do %s; done",
        "a `while` body": "while :; do %s; break; done",
        "a `case` arm": "case x in x) %s ;; esac",
        "a substitution": "x=$(%s)",
        "the background": "%s &\nwait",
        "behind `!`": "! %s",
        "a pipe's first stage": "%s | cat",
        "a pipe's later stage": "true | %s",
        "behind an assignment": "A=1 %s",
        "with a redirection": "%s > /dev/null",
    }
    STATEMENTS = ("$T ${S:+sudo -E} bash t", "$T ${S:- } bash t", "$1 ${S:+sudo -E} bash t", "$1 bash t",
                  '"$@" bash t', "${S#x} bash t", "$A ${S:+sudo -E} $B bash t", "$T ${S:-sudo} -E bash -c 'bash t'",
                  "$S cat t | sh")

    def test_every_place(self):
        # A statement that needs no quote the place could not hold. Truth: runs, every one; under bash alone in
        # a `function` function, which dash has not.
        for place, shape in self.PLACES.items():
            for statement in self.STATEMENTS:
                if "'" in shape and "'" in statement:
                    continue
                with self.subTest(place=place, statement=statement):
                    self.assertEqual("RRRRR", reports(FETCH + shape % statement))


class TestNoReportIsLostToACheck(unittest.TestCase):
    """#3037's class, which this batch must not widen: a check behind a word that is nothing is credited only in
    the folds that drop the word, and the folds `main` reads keep their reports. Each row reported on `main`."""

    RUNS = ('${X:-eval} "$(cat t)"', '$S eval "$(cat t)"', "$S . ./t", 'builtin eval "$(cat t)"')

    def test_a_check_behind_each_new_word(self):
        # Truth with every name unset: the check runs and fails, and the step stops under `-e`. With the word
        # set to a printer -- `set -- echo` -- no check runs and every shell runs the file: the guard cannot tell
        # which, and reports as `main` did.
        for front in ("$1", '"$@"', "${S#x}", "${S:- }", "$T ${S:+sudo -E}", "${1:+echo}", '"${S[@]}"'):
            for shape in ("sh -c '%s'", "eval '%s'"):
                for run in self.RUNS:
                    with self.subTest(front=front, shape=shape[:4], run=run[:10]):
                        text = "%s%s %s\n%s" % (FETCH, front, shape % CHECK.replace("'", '"'), run)
                        self.assertEqual("RRRRR", reports(text))

    def test_a_check_behind_a_default_naming_a_wrapper(self):
        for front in ("${S:-sudo} -E", "${S:-env} A=1", "${S:-command} --"):
            for run in self.RUNS:
                with self.subTest(front=front, run=run[:10]):
                    self.assertEqual("RRRRR", reports("%s%s sh -c '%s'\n%s" % (FETCH, front, CHECK, run)))

    def test_the_fetch_only_the_second_walk_reads(self):
        fetch = "${X:-curl} -fsSLo t %s\n" % U
        for front in ("$1", '"$@"', "${S#x}"):
            with self.subTest(front=front):
                self.assertEqual("RRRRR", reports("%s%s sh -c '%s'\nsh t" % (fetch, front, CHECK)))

    def test_the_written_check_is_credited_as_it_was(self):
        # No word in front of the check: it gates the run under `-e`, as on `main`. Truth: the check fails and
        # the step stops under `-e`; with no `-e` the file runs -- behind `$1` too, which `main` did not read.
        self.assertEqual("CCCRR", reports("%s%s\nsh t" % (FETCH, CHECK)))
        self.assertEqual("CCCRR", reports("%s%s\n$1 sh t" % (FETCH, CHECK)))


class TestThePrice(unittest.TestCase):
    """Rows that report though no parent runs the download, each named."""

    def test_a_form_dash_refuses_reports_under_sh_too(self):
        # The reader has one grammar. Truth: bash runs; dash stops at `Bad substitution`, or at `function`.
        for text in (step("${S^^}", SHELL), step('"${S[@]}"', SHELL), step("${S:0}", EVAL),
                     "function f { $1 sh -c '%s'; }\nf" % P):
            with self.subTest(text=text[:14]):
                self.assertEqual(NOW, marks(text))

    def test_the_word_is_read_whatever_the_step_did_to_its_name(self):
        # #2899's class, as `main` reads `$S` in front of a shell. Truth: nothing, every one -- the word is a
        # printer, a word that is no command, or a PID.
        for sets, front in (("set -- echo\n", "$1"), ("set -- 1\n", '"$@"'), ("S=(echo)\n", '"${S[@]}"'),
                            ("S=1\n", "${S#x}"), ("T=echo\n", "${S:-$T}"), ("set -- 1\n", "${1:+echo}"),
                            ("true &\nwait\n", "$!")):
            with self.subTest(sets=sets.strip(), front=front):
                self.assertEqual(NOW, marks(step(front, SHELL, sets)))
        self.assertEqual(NOW, marks("f() { \"$@\" sh -c '%s'; }\nf echo" % P))  # the words a call hands on
        # ...and where the word it becomes is a wrapper that execs, in front of a builtin.
        self.assertEqual(NOW, marks(step("$1", EVAL, "set -- sudo\n")))

    def test_what_the_step_did_runs_it_as_often(self):
        # The same reading where the step's word is nothing or a wrapper. Truth: runs, every one.
        for sets, front in (("set --\n", "$1"), ("set -- sudo\n", "$1"), ("S=()\n", '"${S[@]}"'),
                            ("S=x\n", "${S#x}"), ("T=sudo\n", "${S:-$T}")):
            with self.subTest(sets=sets.strip(), front=front):
                self.assertEqual(NOW, marks(step(front, SHELL, sets)))

    def test_a_default_naming_a_wrapper_is_read_whatever_the_step_set(self):
        # `workflow_annotate` resolves the word to the step's literal only in front of a name the reader knows;
        # in front of the wrapper's own words it stays as written. Truth: nothing -- `echo -E sh -c 'P'`,
        # `1 -E ...`.
        for sets in ("S=echo\n", "S=1\n"):
            with self.subTest(sets=sets.strip()):
                self.assertEqual(NOW, marks(step("${S:-sudo} -E", SHELL, sets)))
                self.assertEqual(CLEAN, marks(step("${S:-sudo}", SHELL, sets)))     # resolved: `echo sh -c 'P'`

    def test_the_names_a_job_sets_are_read_wherever_and_whenever(self):
        # #3038's names are a job's: a text that only spells the assignment, one unset or set again before the
        # word, and another step's. Truth: nothing, every one (`sudo eval`).
        for sets in ("echo S=command\n", "S=command\nunset S\n", "S=command\nS=sudo\n"):
            with self.subTest(sets=sets.strip()):
                self.assertEqual(NOW, marks(step("${S:-sudo}", EVAL, sets)))

    def test_a_quoted_nothing_and_a_quoted_reference(self):
        # The quotes leave an empty word, which bash fails to run; the reader has taken them off. Truth:
        # nothing -- but `"$@"""`, which bash 3.2.57 makes no word of.
        for front in ('""$@', '$@""', '${S:-"$T"}'):
            with self.subTest(front=front):
                self.assertEqual(NOW, marks(step(front, SHELL)))
        self.assertEqual(NOW, marks(step('"$@"""', SHELL)))

    def test_a_quoted_splat_the_parent_expands(self):
        # Inside the double quotes the PARENT makes `""` of `\"$@\"`, and the child fails to run it. Truth: the
        # fetch alone.
        self.assertEqual(NOW, marks('%ssh -c "%s"' % (FETCH, chr(92) + '"$@' + chr(92) + '" bash t')))

    def test_a_check_the_guard_does_not_credit_stops_the_step_all_the_same(self):
        # `sha256sum -c sums` with no `sums` the guard can bind is no check to it, written out or not: the run
        # behind a word that is nothing reports as the written run does on `main`. Truth: the check fails and the
        # step stops under `-e`; with no `-e` the file runs.
        self.assertEqual(BEFORE, marks("%ssha256sum -c sums\nsh t" % FETCH))
        for front in ("$1", '"$@"', "${S#x}"):
            with self.subTest(front=front):
                self.assertEqual(NOW, marks("%ssha256sum -c sums\n%s sh t" % (FETCH, front)))

    def test_what_bash_3_2_alone_runs(self):
        # A default assigned to all of an array, and a negative subscript: bash 5.2.21 refuses both under `-e`,
        # dash has no array. Truth: bash 3.2.57 with no `-e` runs the first, both bashes with no `-e` the second.
        for front in ("${S[@]:=}", "${S[-1]}"):
            with self.subTest(front=front):
                self.assertEqual(NOW, marks(step(front, SHELL)))


class TestWhatStaysForOtherIssues(unittest.TestCase):
    """Rows this PR does not move, each pinned as it reads and named with what it waits for."""

    def test_a_substitution_that_prints_nothing_is_2693(self):
        for front in ("$(true)", "`true`", "$(:) $S"):      # truth: runs, every one
            with self.subTest(front=front):
                self.assertEqual(CLEAN, marks(step(front, SHELL)))

    def test_two_references_glued_are_3016(self):
        for front in ("$S$T", "$1$2", '"$@"$S', "${S:-$T$V}"):          # truth: runs, every one
            with self.subTest(front=front):
                self.assertEqual(CLEAN, marks(step(front, SHELL)))

    def test_coproc_is_2894(self):
        self.assertEqual(CLEAN, marks("coproc $S eval '%s'\nwait" % P))        # truth: bash 5.2.21 runs

    def test_a_filter_that_passes_its_input_on(self):
        # `head -n 99 t | sh`, `sed -n p t | sh` and `tee /dev/null < t | sh` read CLEAN written out too: the
        # printers' lane, whatever stands in front. Truth: runs, every one. (`cat < t | sh` is read since #3057:
        # `TestAPrinterBehindAWordThatIsNothing`.)
        for stage in ("head -n 99 t", "sed -n p t", "tee /dev/null < t"):
            for front in ("", "$S "):
                with self.subTest(stage=stage, front=front):
                    self.assertEqual(CLEAN, marks("%s%s%s | sh" % (FETCH, front, stage)))

    def test_a_file_a_printer_writes_and_a_shell_runs_is_3027(self):
        for front in ("", "$S "):                           # truth: runs, both
            with self.subTest(front=front):
                self.assertEqual(CLEAN, marks("%secho '%s' > run.sh\nsh run.sh" % (front, P)))

    def test_a_dollar_word_where_a_default_wrappers_own_words_end(self):
        # Behind a WRITTEN wrapper `main` reads a `$` command word as one it cannot read, and reports
        # (`sudo -E $T echo hi` too); behind a default naming one it reads nothing, here as there. Truth: runs.
        for text in ("${S:-sudo} -E $T sh -c '%s'" % P, "${S:-sudo} -E ${T:-env} A=1 sh -c '%s'" % P):
            with self.subTest(text=text[:28]):
                self.assertEqual(CLEAN, marks(text))
        self.assertEqual(BEFORE, marks("sudo -E $T sh -c '%s'" % P))

    def test_an_alternate_naming_a_wrapper_in_front_of_its_own_words(self):
        # With `S` unset it is nothing and `-E` is the command: truth, nothing. With `S` set it is `sudo -E`,
        # and the pipeline runs: the reader reads neither half of a one-word alternate that is no shell.
        self.assertEqual(CLEAN, marks(step("${S:+sudo} -E", SHELL)))
        self.assertEqual(CLEAN, marks(step("${S:+sudo} -E", SHELL, "S=1\n")))

    def test_the_dollar_dash_and_a_quoted_substring_from_the_end(self):
        # `$-` is empty in a dash with no option set (`shell: sh {0}` alone runs); `"${@: -1}"` holds a blank,
        # and the reader reads no quoted word whole. Truth: bash 3.2.57 runs the second.
        for front in ("$-", '"${@: -1}"'):
            with self.subTest(front=front):
                self.assertEqual(CLEAN, marks(step(front, SHELL)))

    def test_a_default_that_is_a_blank_behind_builtin_is_2976s_kind(self):
        # The reader keeps a `${…}` with a bare blank whole only where it may be its stage's command word, and
        # behind `builtin` it is not the first word. Truth: bash runs (`builtin eval 'P'`).
        self.assertEqual(CLEAN, marks("builtin ${S:- } eval '%s'" % P))

    def test_a_quoted_default_naming_a_wrapper(self):
        # `"${SUDO:-sudo}" sh -c 'P'` is `sudo sh -c 'P'` with the name unset: the quotes keep a word bash would
        # keep anyway. `main` reads a quoted default that names a shell (#2337), and the second walk one naming a
        # fetcher or `eval` (#2963); one naming a wrapper it keeps as the command, here as there. Truth: runs,
        # every one.
        for text in ('"${S:-sudo}" sh -c \'%s\'' % P, '"${S:-env}" sh -c \'%s\'' % P, '"${S:-sudo}" %s' % P,
                     '"${S:-command}" eval \'%s\'' % P, '"${S:-sudo}" -E sh -c \'%s\'' % P):
            with self.subTest(text=text[:20]):
                self.assertEqual(CLEAN, marks(text))
        self.assertEqual(BEFORE, marks('"${SH:-bash}" -c \'%s\'' % P))

    def test_a_quoted_reference_to_a_name_the_step_set_is_2769(self):
        # `SUDO=sudo; "$SUDO" sh -c 'P'`: the value table cannot see quoting, and the reader keeps the word.
        # Truth: runs, every one.
        for text in ('S=sudo\n"$S" sh -c \'%s\'' % P, 'S=command\n"$S" eval \'%s\'' % P,
                     'S=command\n"${S:-sudo}" eval \'%s\'' % P):
            with self.subTest(text=text[:22]):
                self.assertEqual(CLEAN, marks(text))

    def test_a_default_whose_name_the_step_set_to_another_wrapper(self):
        # `S=sudo; ${S:-env} -E sh -c 'P'` is `sudo -E sh -c 'P'`. The reader reads the wrapper the default names,
        # and `env` takes no `-E`: it reads on through no such word. Truth: runs.
        self.assertEqual(CLEAN, marks(step("${S:-env} -E", SHELL, "S=sudo\n")))

    def test_a_quoted_default_of_the_words_the_step_set(self):
        # `set -- sudo; "${@:-}" sh -c 'P'` is `sudo sh -c 'P'`; with no word set the quotes keep an empty one,
        # which is why the reader does not drop it (`TestTheOtherWordsThatAreNothing`). Truth: runs.
        self.assertEqual(CLEAN, marks(step('"${@:-}"', SHELL, "set -- sudo\n")))

    def test_a_default_naming_time_in_front_of_its_option(self):
        # A `time` an expansion makes is no reserved word: bash runs /usr/bin/time, which execs and runs no
        # builtin. The reader has one reading of the word, the keyword's (`"time" eval 'P'` reports on `main`),
        # so a default naming it reads on through no option. Truth: runs.
        self.assertEqual(CLEAN, marks(step("${S:-time} -p", SHELL)))

    def test_busybox_is_no_name_the_reader_knows(self):
        for front in ("", "$S ", "$1 "):                    # truth: runs, every one
            with self.subTest(front=front):
                self.assertEqual(CLEAN, marks("%sbusybox sh -c '%s'" % (front, P)))


class TestTheSecondWalkAlone(unittest.TestCase):
    """The readings are the second walk's, in the folds `_masks` adds for them: `_optional` gives them where a
    fold's set holds `_DROPPED`, and nowhere in the main pass or outside `folds`."""

    ROWS = (
        (["$1", "sh", "-c", P], 1),
        (["$1", "$2", "eval", P], 2),
        (["${S#x}", "sh", "-c", P], 1),
        (["${S:- }", "curl", U], 1),                        # (#3002) a default that is only a blank
        (["$S", "${T:-$V}", ".", "./t"], 2),
        (["$S", "echo", P], 1),                             # (#3007) a printer
        (["$A", "$B", "printf", P], 2),
        (["${S:+sudo}", "cat", "t"], 1),
        (["$T", "${S:-sudo}", "-E", "sh", "-c", P], 1),     # the word in front of a default that reads on
        (["$1", "${T:-sudo}", "sh", "-c", P], 2),
        (["$1", "${T:-sudo}", "eval", P], 0),               # a wrapper that execs runs no builtin
        (["$1", "/x/eval", P], 0),
        (["$1", "true", P], 0),
        (["${1:=}", "sh", "-c", P], 0),
        (["${!S^^}", "sh", "-c", P], 0),
    )

    def setUp(self):
        self.addCleanup(shell_defaults._HALVES.update, empty=frozenset(), words={}, both=False, on=False, drops=False,
                        both_dropped=False)

    def fold(self, dropped):
        shell_defaults._HALVES.update(on=True, empty=frozenset({shell_defaults._DROPPED} if dropped else ()))

    def test_optional_counts_the_words_in_the_folds_that_drop_them(self):
        for argv, count in self.ROWS:
            with self.subTest(argv=argv[:-1]):
                self.fold(True)
                self.assertEqual(count, shell_defaults._optional(argv))
                with wo.mains_answer():
                    self.assertEqual(0, shell_defaults._optional(argv))
                self.fold(False)
                self.assertEqual(0, shell_defaults._optional(argv))
                shell_defaults._HALVES.update(on=False)     # outside `folds`: as `main` reads it
                self.assertEqual(0, shell_defaults._optional(argv))

    def test_a_fold_that_met_such_a_word_is_read_again_with_it_dropped(self):
        argv = shell_reader.statements("$1 sh -c 'true'")[0].stages[0].argv
        seen = []
        for _sure in shell_command.folds(lambda: False):
            seen.append((shell_command.command(argv)[0], shell_defaults._DROPPED in shell_defaults._HALVES["empty"]))
        self.assertEqual([("$1", False), ("sh", True)], seen)
        plain = shell_reader.statements("$S sh -c 'true'")[0].stages[0].argv
        self.assertEqual(1, sum(1 for _sure in shell_command.folds(lambda: bool(shell_command.command(plain)) and False)))

    def test_the_folds_mains_reading_stays_among(self):
        # One word dropped, and a two-halved word behind it that only the fold that drops the first one meets:
        # `main`'s fold, that one again with the word dropped (`sudo -E sh`, whose command is `sh`), then that
        # one with the two-halved word read empty. `main`'s own fold is not read again with it empty: no fold of
        # `main`'s reaches the word, and each would read as the first. No fold `main` reads is lost.
        argv = shell_reader.statements("$T ${S:+sudo -E} sh -c 'true'")[0].stages[0].argv
        seen = []
        for _sure in shell_command.folds(lambda: False):
            seen.append((shell_command.command(argv)[0], shell_defaults._HALVES["empty"]))
        dropped = frozenset({shell_defaults._DROPPED})
        self.assertEqual([("$T", frozenset()), ("sh", dropped), ("sh", shell_defaults._ALL | dropped)], seen)
        # Where one of `main`'s folds meets one too, the sets of halves are read in both kinds of fold.
        argvs = [statement.stages[0].argv for statement in
                 shell_reader.statements("${S:+sudo -E} sh -c 'true'\n$T ${U:+env A=1} sh -c 'true'")]
        seen = []
        for _sure in shell_command.folds(lambda: False):
            for argv in argvs:
                shell_command.command(argv)
            seen.append(shell_defaults._HALVES["empty"])
        self.assertEqual([frozenset(), shell_defaults._ALL, dropped], seen[:3])
        self.assertIn(shell_defaults._ALL | dropped, seen)

    def test_what_main_drops_is_dropped_in_every_fold(self):
        for argv, count in ((["$S", "sh", "-c", P], 1), (["${S:-sudo}", "sh", "-c", P], 1),
                            (["$S", "eval", P], 1), (["$A", "$B", "curl", U], 2)):
            for dropped in (False, True):
                with self.subTest(argv=argv[:-1], dropped=dropped):
                    self.fold(dropped)
                    self.assertEqual(count, shell_defaults._optional(argv))

    def test_the_words_the_two_patterns_read(self):
        for word in ("$1", "$9", "$@", "$!", "${1}", "${10}", "${@}", "${*}", "${S#x}", "${S%%x}", "${S/x/y}",
                     "${S^^}", "${S,}", "${S:0}", "${S: -1}", "${S@Q}", "${S[0]}", "${S[@]}", "${!S}", "${!S[@]}",
                     "${!1}", "${S:+w}", "${1:+w}", "${S:+$T}", "${S:- }", "${S:-$T}", "${S:-${T:-}}", "${S:=$T}",
                     "${S[@]:=}", "${!S[0]^^}", "${!S[@]^^}"):
            with self.subTest(word=word):
                self.assertTrue(shell_defaults._NOTHING.fullmatch(word))
        for word in ("$0", "${0}", "$#", "$$", "$?", "$-", "$*", "${#S}", "${S:-x}", "${S:?}", "${S:-${T:-x}}",
                     "${S:-$T$V}", "${S:+a b}", "${1:=}", "${10:=$T}", "${@:=}", "${*=}", "${!S^^}", "${!S,}",
                     "${!S@Q}", "${!S@}", "${!S*}", "$S$T", "x$1", "$1x"):
            with self.subTest(word=word):
                self.assertFalse(shell_defaults._NOTHING.fullmatch(word))
        for word in ("$@", "${@}", "${S[@]}", "${!S[@]}", "${@:2}", "${S[@]:1}", "${S[@]/x/y}", "${S[@]#x}",
                     "${S[@]^^}", "${@:+w}", "${S[@]:+w}"):
            with self.subTest(splat=word):
                self.assertTrue(shell_defaults._SPLAT.fullmatch(word))
        for word in ("$1", "$*", "$S", "${S[*]}", "${S[0]}", "${@:-}", "${S[@]:-}", "${S[@]-x}", "${@:=}",
                     "${@:?}", "${!S[@]#x}", "${@: -1}", "$@x"):
            with self.subTest(splat=word):
                self.assertFalse(shell_defaults._SPLAT.fullmatch(word))

    def test_the_reader_says_which_quotes_stood(self):
        for text, double in (('"$@" sh', True), ('"${S[@]}" sh', True), ("'$@' sh", False),
                             (chr(92) + "$@ sh", False), ('"$"@ sh', False)):
            with self.subTest(text=text):
                word = shell_reader.statements(text)[0].stages[0].argv[0]
                self.assertEqual((True, double), (getattr(word, "kept", False), getattr(word, "double", False)))
        self.assertFalse(getattr(shell_reader.statements("$@ sh")[0].stages[0].argv[0], "kept", False))

    def test_a_word_behind_words_that_are_nothing_is_kept_whole(self):
        # `_split` keeps a stage's first `${…}` with bare blanks whole; behind words bash may make nothing of it
        # is still the first that may be the command (#3002). Not behind one kept whole itself (#2976), a
        # written word, or a quoted one that is a word.
        for text, at in (("$T ${S:+sudo -E} sh", 1), ("$A $B ${S:+sudo -E} sh", 2), ("$1 ${S:+sudo -E} sh", 1),
                         ('"$@" ${S:+sudo -E} sh', 1), ("${S:- } ${T:+sudo -E} sh", None),
                         ("x ${S:+sudo -E} sh", None), ('"$1" ${S:+sudo -E} sh', None)):
            with self.subTest(text=text):
                argv = shell_reader.statements(text)[0].stages[0].argv
                wholes = [index for index, word in enumerate(argv) if getattr(word, "whole", None) is not None]
                self.assertEqual([0] if text.startswith("${") else ([at] if at else []), wholes)

    def test_a_default_naming_a_wrapper_reads_on_through_its_own_words(self):
        self.fold(True)
        for argv, words in ((["${S:-sudo}", "-E", "sh", "-c", P], ["sudo"]), (["${S:-env}", "A=1", "sh"], ["env"]),
                            (["${S:-sudo}", "sh", "-c", P], None),      # no word of its own: `_optional` drops it
                            (["${S:-sudo}", "-E", "$CMD", "x"], None), (["${S:+sudo}", "-E", "sh"], None),
                            (["${S:-time}", "-p", "sh"], None), (["${S:-sudo}", "-E"], None)):
            with self.subTest(argv=argv):
                self.assertEqual(words, shell_defaults._shell_default(argv[0], argv))
        self.fold(False)
        self.assertIsNone(shell_defaults._shell_default("${S:-sudo}", ["${S:-sudo}", "-E", "sh", "-c", P]))
        self.assertEqual(["sh"], shell_defaults._shell_default("${S:-sh}", ["${S:-sh}", "-c", P]))     # `main`'s

    def test_the_names_a_job_sets(self):
        for text, runs, empty in (("S=command", {"S"}, set()), ("A=1 S='builtin'; T=", {"S"}, {"T"}),
                                  ('export S="command" T=""', {"S"}, {"T"}), ("S=commander T=x", set(), set()),
                                  ("echo $S=command; xS=command", {"xS"}, set()), ("S=command-x", set(), set())):
            with self.subTest(text=text):
                found = []
                for _sure in shell_command.folds(lambda: False):
                    shell_wrappers.shadows(text)
                    found.append(({name for name in ("S", "T", "xS") if shell_wrappers.set_to("runs", name)},
                                  {name for name in ("S", "T") if shell_wrappers.set_to("empty", name)}))
                self.assertEqual([(runs, empty)], found)
        self.assertFalse(shell_wrappers.set_to("runs", "S"))


if __name__ == "__main__":
    unittest.main()
