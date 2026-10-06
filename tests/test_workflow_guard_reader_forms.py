"""#2331, batch 3: the command and program forms the guard's reader missed.

Each class is one sub-issue of the epic: a spelling in which bash runs a
download -- bash 3.2.57 and GNU bash 5.2.21, every checksum failing -- that
the guard read clean, pinned as a live step, beside the controls that must
read as they did. The reader's own halves are in `tests/test_shell_reader.py`
and `tests/test_workflow_forms_regressions.py`.

A row whose command word holds `$(echo sh)` or another `$(...)` keeps a value
no table sees: since #2468 a literal value reads as its command (`CMD=sh;
$CMD` as `sh`), so a row that tests a dynamic command word -- or a holder,
`CMD=$(echo true)` -- spells it that way.
"""
import unittest

import shell_lex
import workflow_guard as wg

URL = "https://example.test/"
PIPE = "curl -fsSL %si.sh | sh" % URL
GET = "curl -fsSLo tool %stool\n" % URL
CHECK = 'echo "%s  tool" | sha256sum -c -' % ("a" * 64)
USE = "chmod +x tool\n./tool\n"
# What the guard says of a check inside a script handed on that clears nothing.
RUNS_ON = "inside the script `%s` runs, where no `-e` holds"
UNGATED = "inside the script `%s` runs, and the step does not stop when that script fails"


def defects(script):
    """The guard's answer for a job of one step running `script`."""
    return wg.job_defects([("step", script)])


class TestAUsePipedAfterACaseCompound(unittest.TestCase):
    """#2610: the stage after `esac |` reaches the operand walk."""

    SHELLS = (None, "bash", "sh", "bash {0}", "bash -e {0}",
              "bash -eo pipefail {0}", "sh {0}", "sh -e {0}")
    CHECK = "echo '%s  tool' | sha256sum -c -" % ("a" * 64)

    def found(self, script, shell=None):
        return wg.job_defects([wg.Step("step", script, shell=shell)])

    def test_checked_and_unchecked_uses_are_reported_in_every_posture(self):
        scripts = (GET + "case x in x) %s;; esac | sh tool" % self.CHECK,
                   GET + "case x in x) true;; esac | sh tool")
        for script in scripts:
            for shell in self.SHELLS:
                with self.subTest(script=script, shell=shell):
                    found = self.found(script, shell)
                    self.assertEqual(1, len(found), found)
                    self.assertIn("running it under `sh`", found[0][1])

    def test_the_sequential_control_keeps_its_existing_branch_answer(self):
        # Main already sees this use and reports that the case-bound check may
        # be skipped. This control pins that answer rather than calling it a
        # clean credit, as #2610's initial acceptance text did.
        found = self.found(GET + "case x in x) %s;; esac\nsh tool" % self.CHECK)
        self.assertEqual(1, len(found), found)
        self.assertIn("branch the use is not in", found[0][1])

    def test_clean_case_and_direct_must_trip_controls_keep_their_answers(self):
        self.assertEqual([], self.found("case x in x) echo harmless;; esac | cat"))
        found = self.found(GET + "sh tool")
        self.assertEqual(1, len(found), found)
        self.assertIn("running it under `sh`", found[0][1])
class TestNestedCaseArmPayloads(unittest.TestCase):
    """#2617: nested arm bodies reach the operand walk, not only the lexer."""

    SHELLS = (None, "bash", "sh", "bash {0}", "bash -e {0}",
              "bash -eo pipefail {0}", "sh {0}", "sh -e {0}")

    @staticmethod
    def nested(body, depth=2):
        return "case a in a) " * depth + body + ";; esac" * depth

    def test_payloads_at_two_and_three_levels_under_every_shell_posture(self):
        scripts = (
            self.nested(PIPE),
            self.nested(PIPE, 3),
            "case a in a)case a in a) " + PIPE + ";;esac;;esac",
            "case a in (b|a) case a in (a|b) " + PIPE + ";; esac;; esac",
            "x=$(" + self.nested(PIPE) + ")",
            "x=$(" + self.nested(PIPE, 3) + ")",
            "case a in a) :;& b) " + self.nested(PIPE, 1) + ";; esac",
            "case a in a) :;;& a) " + self.nested(PIPE, 1) + ";; esac",
            "case a in a) case a in a) :;& b) " + PIPE + ";; esac;; esac",
            "case a in a) case a in a) :;;& a) " + PIPE + ";; esac;; esac",
        )
        for script in scripts:
            for shell in self.SHELLS:
                with self.subTest(script=script, shell=shell):
                    found = wg.job_defects([wg.Step("step", script, shell=shell)])
                    self.assertTrue(found)
                    self.assertTrue(any("straight to `sh`" in reason for _, reason in found), found)

    def test_clean_nested_bodies_beside_their_must_trip_controls(self):
        for body, payload in (
            (self.nested("echo harmless"), self.nested(PIPE)),
            ("x=$(" + self.nested("echo harmless", 3) + ")",
             "x=$(" + self.nested(PIPE, 3) + ")"),
            (self.nested("echo '@@casearm@@curl https://example.test/i.sh | sh'"),
             self.nested(PIPE)),
        ):
            with self.subTest(script=body):
                self.assertEqual([], defects(body))
                self.assertTrue(defects(payload))
        self.assertTrue(defects(self.nested(PIPE, 1)))

    def test_an_inner_check_does_not_cover_a_sibling_of_the_parent_arm(self):
        script = (GET + "case b in a) case a in a) echo '" + "a" * 64
                  + "  tool' | sha256sum -c -;; esac;; b) sh tool;; esac")
        self.assertTrue(defects(script))
def stdin_step(runner, body=CHECK, form="heredoc", pre="", end="", fetched=True):
    """A step that hands `runner` the script `body` on its standard input -- a
    quoted heredoc, a here-string or an `echo` piped in (`form`) -- after the
    lines `pre` and before `end`, between GET and the use of `tool` where
    `fetched`."""
    stdin = {"heredoc": "%s <<'EOF'\n%s\nEOF\n" % (runner, body),
             "here-string": "%s <<< '%s'\n" % (runner, body),
             "piped": "echo '%s' | %s\n" % (body, runner)}[form]
    return (GET if fetched else "") + pre + stdin + end + (USE if fetched else "")


class TestAssignmentPrefixes(unittest.TestCase):
    """#2348: `A+=x`, `a[1]=x` and `arr=(a)` in front of a command are
    assignments, and bash runs the command behind them."""

    def test_the_command_behind_each_prefix_is_read(self):
        for script in (GET + "A+=x sh tool\n", GET + "a[1]=x sh tool\n",
                       GET + "a[1]+=x sh tool\n", GET + "arr=(a) sh tool\n",
                       GET + "arr+=(a b) sh tool\n", "arr=( a ) %s\n" % PIPE,
                       "arr=(a) sh -c '%s'\n" % PIPE):
            with self.subTest(script=script):
                self.assertTrue(defects(script))
        # Behind a literal, `[s]h` is the pattern #2294 reports where a
        # command starts, as it is with nothing in front of it.
        found = defects("arr=( a ) [s]h -c '%s'\n" % PIPE)
        self.assertEqual(1, len(found), found)
        self.assertIn("is a pattern", found[0][1])

    def test_the_controls_read_as_they_did(self):
        # A scalar prefix, and an append on a line of its own, were read
        # already; `a[1]x]=y` is no assignment, and #2294 reports the pattern
        # bash expands where the command starts.
        for script in (GET + "X=1 sh tool\n", GET + "A+=x true\nsh tool\n"):
            with self.subTest(script=script):
                self.assertTrue(defects(script))
        found = defects(GET + "a[1]x]=y sh tool\n")
        self.assertEqual(1, len(found), found)
        self.assertIn("is a pattern", found[0][1])
        # A literal's words are the array's, not a command: nothing runs.
        for script in ("arr=(a b)\n", "arr=( %s )\n" % URL, "declare -a a=(x y) b+=(z)\n"):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))

    def test_an_array_that_holds_a_fetch_is_read_where_it_is_written(self):
        # posthog's ci-hog.yml keeps curl's options in an array and runs it
        # through `"${fetch[@]}"`, which the guard does not follow: the
        # literal, alone in its statement, still reads as the fetch it holds.
        script = ('fetch=(curl --fail --location)\n'
                  '"${fetch[@]}" %stool --output tool\nchmod +x tool\n./tool\n' % URL)
        self.assertTrue(defects(script))

    def test_a_check_behind_a_prefix_is_read_too(self):
        # The prefix was read as the command, so the checksum behind it went
        # uncredited; a `|| true` after it still stops nothing.
        body = "echo '%s  tool' | %ssha256sum -c -%s\nsh tool\n"
        for prefix in ("A+=x ", "a[1]=x ", "arr=(a b) "):
            with self.subTest(prefix=prefix):
                self.assertEqual([], defects(GET + body % ("a" * 64, prefix, "")))
                self.assertTrue(defects(GET + body % ("a" * 64, prefix, " || true")))


class TestOptionsAfterDashC(unittest.TestCase):
    """#2332: the option words after `-c` are the shell's, and the program
    it runs is the first word after them."""

    def test_the_program_after_the_options_is_read(self):
        for script in ("sh -c -e 'curl -fsSLo t %stool; chmod +x t; ./t'\n" % URL,
                       "bash -c -x '%s'\n" % PIPE, "sh -c -- '%s'\n" % PIPE,
                       "bash -ec -- '%s'\n" % PIPE, "bash -c -- '%s'\n" % PIPE,
                       "bash -c -o pipefail '%s'\n" % PIPE,
                       'x=$(curl -fsSL %si.sh)\nsh -c -- "$x"\n' % URL):
            with self.subTest(script=script):
                self.assertTrue(defects(script))

    def test_the_controls_read_as_they_did(self):
        for script in ("sh -c '%s'\n" % PIPE, "sh -ec '%s'\n" % PIPE,
                       'x=$(curl -fsSL %si.sh)\nsh -c "$x"\n' % URL):
            with self.subTest(script=script):
                self.assertTrue(defects(script))
        # The options change nothing where the program fetches nothing, and a
        # `--long` word after `-c` is one bash and dash refuse: nothing runs.
        for script in ("sh -c -e 'echo hi'\n", "bash -c -x -- 'echo hi'\n",
                       "bash -c --norc '%s'\n" % PIPE):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))


class TestValuesBeforeAShellsProgram(unittest.TestCase):
    """#2344: a value that may be a shell's `-c`, and an `o` that takes a
    value from the middle of an option word; #2484: the words after the
    value's first operand are positional parameters, never the program --
    but where that operand was an option's own value (`--rcfile FILE`) the
    shell reads on, so a later word that may expand to an option re-opens
    the words after it."""

    def test_each_spelling_is_read(self):
        # Bash 3.2.57 and 5.2.21 run each, `[-]c` where a file named `-c`
        # makes the pattern one; the value is never followed, the words
        # after it are read (`candidates`).
        for script in ("X=-c\nsh $X '%s'\n" % PIPE, "sh $(echo -c) '%s'\n" % PIPE,
                       "echo -c | xargs -I{} sh {} '%s'\n" % PIPE, "sh $'-c' '%s'\n" % PIPE,
                       "bash -eo pipefail {-c,'%s'}\n" % PIPE, "X=[-]c\nsh $X '%s'\n" % PIPE,
                       "bash -euo pipefail [-]c '%s'\n" % PIPE,
                       "sh $'\\x2dc' '%s'\n" % PIPE, "bash -oe pipefail <<'EOF'\n%s\nEOF\n" % PIPE,
                       GET + "X=-c\nsh $X 'sh tool'\n"):
            with self.subTest(script=script):
                self.assertTrue(defects(script))

    def test_numeric_ansi_c_escapes_spell_the_shells_c_option(self):
        # #2470: Bash 3.2 and 5.2 decode the hex and octal forms; Bash 5.2
        # also decodes both Unicode forms. Any supported shell can run the
        # program, so each spelling must expose its fetch-and-execute.
        for option in (r"$'-\x63'", r"$'-\143'", r"$'-\u0063'", r"$'-\U00000063'"):
            with self.subTest(option=option):
                found = defects("sh %s '%s'\n" % (option, PIPE))
                self.assertEqual(1, len(found), found)
                self.assertIn("hands %si.sh straight to `sh`" % URL, found[0][1])

    def test_an_ansi_c_code_point_outside_ascii_keeps_the_fetch_sentence(self):
        # #2614: these words, like `\q`, are unknown rather than a refusal
        # of the whole step. Both bashes and dash still run the adjacent pipe.
        for escape in ("\\200", "\\x80", "\\u00e9", "\\U000000e9", "\\400", "\\cé", "\\q"):
            with self.subTest(escape=escape):
                prose = "echo $'%s build ok'" % escape
                self.assertEqual([], defects(prose))
                found = defects(prose + "; " + PIPE)
                self.assertEqual(1, len(found), found)
                self.assertIn("hands %si.sh straight to `sh`" % URL, found[0][1])

    def test_an_ansi_c_assignment_keeps_the_fetch_sentence(self):
        found = defects("MSG=$'caf\\u00e9'; echo \"$MSG\"; " + PIPE)
        self.assertEqual(1, len(found), found)
        self.assertIn("hands %si.sh straight to `sh`" % URL, found[0][1])

    def test_an_ansi_c_backslash_newline_keeps_the_fetch_sentence(self):
        prose = "echo $'a\\\nb'"
        self.assertEqual([], defects(prose))
        found = defects(prose + "; " + PIPE)
        self.assertEqual(1, len(found), found)
        self.assertIn("hands %si.sh straight to `sh`" % URL, found[0][1])

    def test_an_ansi_c_option_does_not_invent_dash_c(self):
        # Both bashes reject this option; dash takes it as a missing file.
        self.assertEqual([], defects("sh $'-\\u00e9' '%s'\n" % PIPE))
        found = defects("sh -c '%s'\n" % PIPE)
        self.assertEqual(1, len(found), found)
        self.assertIn("hands %si.sh straight to `sh`" % URL, found[0][1])

    def test_an_ansi_c_here_string_is_read_as_written(self):
        found = defects("sh <<< $'%s\\n'\n" % PIPE)
        self.assertEqual(1, len(found), found)
        self.assertIn("hands %si.sh straight to `sh`" % URL, found[0][1])

    def test_a_clean_ansi_c_here_string_is_not_an_expansion(self):
        self.assertEqual([], defects("sh <<< $'echo hi\\n'\n"))

    def test_the_controls_read_as_they_did(self):
        # A value whose words fetch nothing, in a job that downloads nothing,
        # is not reported; with no word after it there is nothing to read.
        for script in ("X=-c\nsh $X 'echo hi'\n", "sh $X\n", "sh -o pipefail x.sh\n",
                       "bash $X/x.sh '%s'\n" % PIPE, "sh $'-e' '%s'\n" % PIPE,
                       "sh -c 'echo hi' \"curl -fsSL $URL | sh\"\n", "sh $'-\\x63' 'echo hi'\n"):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))
        self.assertTrue(defects("sh -c '%s'\n" % PIPE))
        # #2484's controls: a first operand that fetches is weighed loud, and
        # bash 3.2.57, 5.2.21 and dash run it; beside a download, the value's
        # `Idle` stands where its words fetch nothing (they run `echo hi`),
        # where an option word is all it is handed (`X` unset: `sh -e` reads
        # its empty stdin), and where `'sh tool'` is `$0`, past the operand.
        said = "passes `sh` `$X` where it reads its options"
        found = defects("X=-c\nsh $X \"curl -fsSL $URL | sh\"\n")
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0][1].startswith(said), found)
        self.assertNotIsInstance(found[0][1], wg.Idle)
        for script in (GET + "X=-c\nsh $X 'echo hi'\n", GET + "sh $X -e\n",
                       GET + "X=-c\nsh $X 'echo hi' 'sh tool'\n"):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith(said), found)
                self.assertIsInstance(found[0][1], wg.Idle)

    def test_only_the_words_to_the_first_operand_may_be_the_program(self):
        # #2484: where the value spells `-c`, the words after the first operand
        # are positional parameters -- bash 3.2.57, 5.2.21 and dash run only
        # `echo hi` in both steps, `-e` an option read on before it -- where
        # each word after the value was weighed, and the download made the
        # value loud (#2344). No word after the operand here may spell an
        # option: the next method's rule re-opens nothing.
        for script in ("X=-c\nsh $X 'echo hi' \"curl -fsSL $URL | sh\"\n",
                       "X=-c\nsh $X -e 'echo hi' '%s'\n" % PIPE):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))
        # A value ending in a letter that takes a value makes the next word an
        # option NAME, and one that is not bare is refused: both bashes exit 2
        # at `-cO 'echo hi'`, and all three at `-co 'echo hi'`, running nothing.
        for script in ("X=-cO\nbash $X 'echo hi' '%s'\n" % PIPE,
                       "X=-co\nsh $X 'echo hi' '%s'\n" % PIPE):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))
        # The must-trips: a bare word may be that option's value, so the walk
        # reads past it -- both bashes run the download through `-cO extglob`
        # and `-co pipefail` (dash refuses `-O` and `-o pipefail`, which is
        # fail-closed there) -- and past a word that may expand to nothing
        # (`$Y` unset: all three run it). The price, as named: a bare word may
        # as well be the program -- `X=-c` runs `tool`, the download `$0` --
        # and is weighed, the walk reading on to the download.
        for script, shell in (("X=-cO\nbash $X extglob '%s'\n" % PIPE, "bash"),
                              ("X=-co\nsh $X pipefail '%s'\n" % PIPE, "sh"),
                              ("X=-c\nsh $X $Y '%s'\n" % PIPE, "sh"),
                              ("X=-c\nsh $X tool '%s'\n" % PIPE, "sh")):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith("passes `%s` `$X`" % shell), found)
        # A carried download past the first operand is `$0`, never the
        # program (all three run nothing of it): the value's `Idle` alone,
        # beside the fetch, where #2479 read it as the carried one. A `$`
        # word there re-opens the words AFTER it, never itself.
        found = defects("x=$(curl -fsSL %si.sh)\nX=-c\nsh $X 'echo hi' \"$x\"\n" % URL)
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0][1].startswith("passes `sh` `$X`"), found)

    def test_a_word_that_may_spell_an_option_past_the_operand_reopens_them(self):
        # The first operand may be an option's own value (`--rcfile FILE`),
        # and bash then reads on, so a later word that may expand to an option
        # word -- `$Y`, `"$Y"`, `-$Y`, `$(echo -c)`, a backquote, `${Y:--c}`,
        # after a literal `--norc` too -- re-opens the words after it. With
        # `--rcfile` and `-c`, bash 5.2.21 and 3.2.57 run each download (dash
        # too, as the step's shell); #2484's truncation alone read each CLEAN.
        # Each is the value's sentence, loud.
        said = "passes `bash` `$X` where it reads its options"
        for script in ("X=--rcfile\nY=-c\nbash $X /dev/null $Y '%s'\n" % PIPE,
                       "X=--rcfile\nY=-c\nbash $X /dev/null \"$Y\" '%s'\n" % PIPE,
                       "X=--rcfile\nY=c\nbash $X /dev/null -$Y '%s'\n" % PIPE,
                       "X=--rcfile\nbash $X /dev/null $(echo -c) '%s'\n" % PIPE,
                       "X=--rcfile\nbash $X /dev/null `echo -c` '%s'\n" % PIPE,
                       "X=--rcfile\nY=-c\nbash $X /dev/null --norc $Y '%s'\n" % PIPE,
                       "X=--rcfile\nbash $X /dev/null ${Y:--c} '%s'\n" % PIPE):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith(said), found)
                self.assertNotIsInstance(found[0][1], wg.Idle)
        # A download carried there is handed to the shell (#2479); all three
        # run it.
        found = defects("x=$(curl -fsSL %si.sh)\nX=--rcfile\nY=-c\nbash $X /dev/null $Y \"$x\"\n"
                        % URL)
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0][1].startswith(
            "carries %si.sh in `$x` and hands it to `bash $X /dev/null $Y`" % URL), found)
        # A literal `--` re-opens nothing (all three run nothing: the download
        # is a file name), nor does a word with literal text of its own (only
        # `echo hi` runs in all three).
        for script in ("X=--rcfile\nbash $X /dev/null -- '%s'\n" % PIPE,
                       "X=-c\nsh $X 'echo hi' x$Y '%s'\n" % PIPE,
                       "X=-c\nsh $X 'echo hi' \"echo $Y\" '%s'\n" % PIPE):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))
        # The price, named: a value that was `-c` after all, a `$` word between
        # its program and a later program-like parameter, is weighed again --
        # FLAGGED, loud, though all three run only `echo hi` (the base's reading).
        found = defects("X=-c\nsh $X 'echo hi' \"$Y\" '%s'\n" % PIPE)
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0][1].startswith("passes `sh` `$X`"), found)
        self.assertNotIsInstance(found[0][1], wg.Idle)
        # A literal `-c` past the operand is `scripts`' to read, as it was:
        # the value's `Idle` beside the stream (all three run it).
        found = defects("X=--rcfile\nbash $X /dev/null -c \"%s\"\n" % PIPE)
        self.assertEqual(2, len(found), found)
        self.assertTrue(found[0][1].startswith(said), found)
        self.assertIsInstance(found[0][1], wg.Idle)
        self.assertIn("straight to `sh`", found[1][1])


class TestADynamicCommandWord(unittest.TestCase):
    """#2337: a command word that may expand to a shell."""

    def test_each_is_read(self):
        # A default that spells a shell is that shell; another dynamic word
        # handed `-c` makes the program after it a candidate (`candidates`).
        for script in ("${X:-sh} -c '%s'\n" % PIPE, '"${X:-bash}" -c \'%s\'\n' % PIPE,
                       "$CMD -c '%s'\n" % PIPE, "${X:-[s]h} -c '%s'\n" % PIPE,
                       GET + "${X:-sh} tool\n", GET + "CMD=$(echo sh)\n$CMD -c 'sh tool'\n"):
            with self.subTest(script=script):
                self.assertTrue(defects(script))

    def test_the_controls_read_as_they_did(self):
        for script in ("${X:-sh} -c 'echo hi'\n", "$CMD --flag\n", "$CMD -c 'echo hi'\n",
                       "$PYTHON -c 'import sys'\n", GET + "$CMD --flag\n"):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))
        # Fail-closed: beside a download no checksum clears (#2481), a
        # program no word here names is reported, as a script in a
        # substitution is (`Idle`).
        self.assertTrue(defects(GET + "$PYTHON -c 'import sys'\n"))


class TestAValueCommandWordConsumesAStream(unittest.TestCase):
    """#2602: a download piped or redirected into a `$` command word."""

    def test_each_stream_shape_is_reported(self):
        # Bash 3.2.57, 5.2.21 and dash execute the payload in every row. The
        # `SUDO=` NL `curl … | $SUDO sh` row that stood here reads as `sh` since
        # #2472 and is pinned with its family (TestAnOptionalWrapperSpelledByVariable).
        rows = (("CMD=$(echo sh)\ncurl -fsSL %si.sh | $CMD\n" % URL, "$CMD"),
                ("CMD=$(echo sh)\ncurl -fsSL %si.sh | \"$CMD\"\n" % URL, "$CMD"),
                ("CMD=$(echo sh)\ncurl -fsSL %si.sh | ${CMD}\n" % URL, "${CMD}"),
                ("curl -fsSL %si.sh | $(echo sh)\n" % URL, "$(...)"),
                ("CMD=$(echo sh)\ncurl -fsSL %si.sh | $CMD -s\n" % URL, "$CMD"),
                ("CMD=$(echo sh)\ncurl -fsSL %si.sh | tee f | $CMD\n" % URL, "$CMD"),
                ("CMD=$(echo eval)\n$CMD \"$(curl -fsSL %si.sh)\"\n" % URL, "$CMD"))
        for script, word in rows:
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith(
                    "pipes a download into `%s`, a command word this guard does not follow" % word
                ), found)

    def test_a_carried_download_reaches_the_value_consumer(self):
        found = defects("CMD=$(echo sh)\nx=$(curl -fsSL %si.sh)\necho \"$x\" | $CMD\n" % URL)
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0][1].startswith(
            "carries %si.sh in `$x` and hands it to `$CMD`" % URL), found)

    def test_the_stream_price_and_controls_are_explicit(self):
        # `CMD=$(echo cat)` executes no payload, but an unknown command gets the same
        # fail-closed stream answer. A named file and the literal shell stay unchanged.
        found = defects("CMD=$(echo cat)\ncurl -fsSL %si.sh | $CMD\n" % URL)
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0][1].startswith("pipes a download into `$CMD`"), found)
        self.assertEqual([], defects("curl -fsSLo f %si.sh\n" % URL))
        found = defects("curl -fsSL %si.sh | sh\n" % URL)
        self.assertEqual(1, len(found), found)
        self.assertIn("straight to `sh`", found[0][1])

    def test_a_redirected_download_is_run_by_a_value_command_word(self):
        for command in ("CMD=$(echo sh)\n$CMD", "CMD=$(echo cat)\n$CMD"):
            with self.subTest(command=command):
                found = defects("curl -fsSLo i.sh %si.sh\n%s < i.sh\n" % (URL, command))
                self.assertEqual(1, len(found), found)
                self.assertIn("running it under `$CMD` from standard input", found[0][1])
        found = defects("curl -fsSLo i.sh %si.sh\nsh < i.sh\n" % URL)
        self.assertEqual(1, len(found), found)
        self.assertIn("running it under `sh` from standard input", found[0][1])
        # A `-c` string is the program; the redirected download remains its data. Its existing
        # dynamic-program sentence stays, without a second redirected-program sentence.
        found = defects("curl -fsSLo i.sh %si.sh\nCMD=$(echo sh)\n$CMD -c 'cat' < i.sh\n" % URL)
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0][1].startswith("runs `$CMD` with `-c`"), found)


class TestAnOptionalWrapperSpelledByVariable(unittest.TestCase):
    """#2472: an unquoted `$` word in front of a name the reader knows -- a shell,
    an interpreter, a wrapper, a fetcher -- is an optional wrapper spelled by
    variable. Empty or unset, bash drops the word and the next one is the
    command; set to `sudo`, the next one runs too; so `shell_reader._optional`
    reads the rest of the statement as the command (fail-closed where the value
    runs nothing of it), and a quoted `"$SUDO"` keeps its word. Each row's
    comment carries its truth, b5 b3 dash gh (bash 5.2.21, bash 3.2.57, dash, a
    GitHub runner's bash with `sh` = dash), measured with `SUDO`, `CMD`, `X` and
    `x` unset, a recording `curl` and a `sudo` that runs its arguments: FR
    fetched and ran, F- fetched only, -- neither.
    """

    STREAM = "hands %si.sh straight to `sh`" % URL
    USE = "fetches %stool -> tool and running it under `sh`" % URL

    def test_the_pipeline_behind_the_word_is_reported(self):
        # FR FR FR FR on every row; main CLEAN on every row but the `${X:-sudo}
        # sh tool` one, which main's value table already read.
        for script in ("$SUDO sh -c '%s'\n" % PIPE,                      # the issue's step
                       "${SUDO:-} sh -c '%s'\n" % PIPE,                  # an empty default
                       "$SUDO $SHELLX sh -c '%s'\n" % PIPE,              # two words drop
                       "$SUDO env sh -c '%s'\n" % PIPE,                  # a wrapper after it
                       "${X:-sudo} sh -c '%s'\n" % PIPE,                 # a default that hands on
                       "SUDO=sudo\n$SUDO sh -c '%s'\n" % PIPE,           # the must-trip control
                       "$SUDO %s\n" % PIPE,                              # in front of the fetcher
                       "SUDO=\ncurl -fsSL %si.sh | $SUDO sh\n" % URL,    # the stream's consumer
                       "CMD=\n$CMD sh <<'EOF'\n%s\nEOF\n" % PIPE):      # a certain empty value
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertIn(self.STREAM, found[0][1])
        for script in (GET + "${X:-sudo} sh tool\n", GET + 'bash -c "\\$x sh tool"\n',
                       "$SUDO " + GET + "sh tool\n"):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertIn(self.USE, found[0][1])

    def test_a_kept_word_and_a_value_that_runs_nothing_read_as_before(self):
        # -- -- -- -- on every row (rc 127 where bash finds no command): the quoted word is
        # the command bash runs (`''`, `$SUDO` literally), a literal value the step assigns
        # that is no wrapper is `kept` by `workflow_annotate._mark` (`echo` prints, `true`
        # runs nothing, `apt-get` takes `sh` as its word), a default no wrapper is #2337's
        # word, and a `-c 'echo hi'` fetches nothing. Main CLEAN on every row, and so here.
        for script in ('"$SUDO" sh -c \'%s\'\n' % PIPE, "'$SUDO' sh -c '%s'\n" % PIPE,
                       "\\$SUDO sh -c '%s'\n" % PIPE, "CMD=\n\"$CMD\" sh <<'EOF'\n%s\nEOF\n" % PIPE,
                       "SUDO=echo\n$SUDO sh -c '%s'\n" % PIPE, "SUDO=true\n$SUDO sh -c '%s'\n" % PIPE,
                       "SUDO=apt-get\n$SUDO sh -c '%s'\n" % PIPE, "${X:-echo} sh -c '%s'\n" % PIPE,
                       "$SUDO sh -c 'echo hi'\n", "$SUDO apt-get install -y x\n"):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))

    def test_the_fail_closed_readings_around_it_are_unchanged(self):
        # A `$` word BEHIND a wrapper stays the unread wrapper report (#2227); a checksum
        # behind one is still not credited (FR FR FR FR with the check passing: the
        # over-report main gave, fail-closed, since the value may run nothing); and a
        # value naming a runner the guard does not list keeps the hand-off (#2792).
        found = defects("sudo $X sh -c '%s'\n" % PIPE)
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0][1].startswith("cannot read command behind wrapper"), found)
        found = defects(GET + "echo 'x  tool' > sums\n$SUDO sha256sum -c sums\nsh tool\n")
        self.assertEqual(1, len(found), found)
        self.assertIn(self.USE, found[0][1])
        found = defects("SUDO=csh\n$SUDO <<'EOF'\n%s\nEOF\n" % PIPE)
        self.assertTrue(any("`$SUDO`, a command word this guard does not" in why
                            for _name, why in found), found)

    def test_the_known_names_cover_the_tables_they_mirror(self):
        # `shell_reader` sits under the modules that own these tables, so it spells its own
        # copies; this pin keeps them equal.
        import shell_reader
        import shell_wrappers
        import workflow_fetch
        import workflow_programs
        known = set(shell_reader.OPTIONAL_NEXT)
        self.assertEqual(set(shell_reader._FETCHERS), set(workflow_fetch.FETCHERS))
        self.assertEqual(set(shell_reader._INTERPRETERS), set(workflow_programs._FOREIGN))
        for table in (shell_reader._SHELLS, shell_wrappers.WRAPPERS,
                      workflow_fetch.FETCHERS, workflow_programs._FOREIGN):
            self.assertTrue(set(table) <= known, table)


class TestADynamicWordWhereTheProgramMayBe(unittest.TestCase):
    """#2344 and #2337 (review N2 of #2331): a `$` word after a value in a shell's
    options, or after a `$` command word's `-c`, may be the program. The guard
    reads it as a `-c` string (re-review R1-N1); one that reads as no program
    (`"$Y"`) or holds a `$(...)` is weighed as a literal `'echo hi'` is there,
    `Idle`, kept where the job holds a fetch the guard reports (#2481), not
    dropped. One that carries a download (`"$x"`) is #2341's, which names
    the use (#2479)."""

    def test_it_is_reported_where_the_job_holds_a_reported_fetch(self):
        # Bash 3.2.57, 5.2.21 and dash run the download in each once `$X`
        # is `-c` (`tool` beside `'echo hi'`), `$CMD` is `sh`, and `$Y` and
        # `$P` are `sh tool`.
        for script in (GET + 'sh $X "$Y"\n', GET + '$CMD -c "$P"\n', GET + 'sh $X "$(cat tool)"\n',
                       GET + "sh $X 'echo hi'\n"):
            with self.subTest(script=script):
                self.assertTrue(defects(script))
        # All three run these too. A download a variable carries gets #2341's
        # sentence, naming the consumer as `carried` writes it: `carried`
        # finds it through `candidates` too (#2479), and the value's `Idle`
        # is dropped beside that louder reason (#2490).
        carries = "carries %si.sh in `$x` and hands it to `%s`"
        for script, head in (('x=$(curl -fsSL %si.sh)\nX=-c\nsh $X "$x"\n' % URL,
                              carries % (URL, "sh $X")),
                             ('x=$(curl -fsSL %si.sh)\nCMD=sh\n$CMD -c "$x"\n' % URL,
                              carries % (URL, "$CMD -c"))):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith(head), found)

    def test_a_carried_download_is_named_only_where_it_is_handed_over(self):
        # #2479's edges. A name no fetch assigned carries nothing: `"$y"`
        # after the value reads as the value's unread word, `Idle` -- CLEAN
        # with no download, alone beside one -- and bash 3.2.57, 5.2.21 and
        # dash run nothing of it (`$y` is empty). `sh -c -e "$x"` reached
        # `carried` already, through `_past_options`. Behind `sudo` a `$CMD`
        # is a command the reader reports unresolved, and only that is said,
        # never a carried sentence beside it (all three run the download
        # through a passwordless sudo). The control: `sh -c "$x"`, which all
        # three run.
        fetch = "x=$(curl -fsSL %si.sh)\n" % URL
        carries = "carries %si.sh in `$x` and hands it to `%s`"
        self.assertEqual([], defects('X=-c\nsh $X "$y"\n'))
        for script, head in ((GET + 'X=-c\nsh $X "$y"\n', "passes `sh` `$X` where it reads its options"),
                             (fetch + 'sh -c -e "$x"\n', carries % (URL, "sh -c -e")),
                             (fetch + 'CMD=sh\nsudo $CMD -c "$x"\n', "cannot read command behind wrapper"),
                             (fetch + 'sh -c "$x"\n', carries % (URL, "sh -c"))):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith(head), found)

    def test_it_is_not_reported_where_the_job_fetches_nothing(self):
        for script in ('sh $X "$Y"\n', '$CMD -c "$P"\n', 'sh $X "$(cat notes.txt)"\n'):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))

    def test_a_word_with_a_dollar_is_read_as_a_dash_c_string_is(self):
        # Re-review R1-N1 of #2331: a word with a `$` but no `$(...)` or
        # pattern in it is read as `sh -c` reads its string, as bash hands it
        # (`spelled`). Bash 3.2.57, 5.2.21 and dash run the download in each.
        for script, head in (('URL=%si.sh\nX=-c\nsh $X "curl -fsSL $URL | sh"\n' % URL, "passes `sh` `$X`"),
                             ("export URL=%si.sh\nX=-c\nsh $X 'curl -fsSL $URL | sh'\n" % URL,
                              "passes `sh` `$X`"),
                             ('URL=%si.sh\nCMD=sh\n$CMD -c "curl -fsSL $URL | sh"\n' % URL,
                              "runs `$CMD` with `-c`"),
                             ('X=-c\nsh $X "echo \\`curl -fsSL %si.sh | sh\\`"\n' % URL, "passes `sh` `$X`")):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith(head), found)
        # Read, these fetch nothing: CLEAN with no download, `Idle` beside one.
        for script in ('X=-c\nsh $X "echo $HOME"\n', 'X=-c\nsh $X "$P"\n', 'X=-c\nsh $X "echo \\`date\\`"\n'):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))
        self.assertTrue(defects(GET + 'sh $X "$P"\n'))

    def test_what_the_gap_list_keeps_reads_nothing(self):
        # With no word after the value nothing is handed on: `sh $X` runs
        # `tool` where `$X` names it, the value gap the gap list keeps, CLEAN
        # before this fix too. The literal shell's own `sh -c "$P"` was the
        # other half of that entry and is read now (#2483, below).
        self.assertEqual([], defects(GET + "sh $X\n"))


class TestAProgramWordContainingASubstitution(unittest.TestCase):
    """#2482: a candidate program keeps substitutions opaque while its visible
    outer text is read; the literal `-c` path is read so too since #2486."""

    def test_the_outer_program_is_read(self):
        scripts = (
            'X=-c\nsh $X "curl -fsSL $(echo %si.sh) | sh"\n' % URL,
            'X=-ec\nsh "$X" "curl -fsSL $(echo $(echo %si.sh)) | sh"\n' % URL,
            'X=-c\nsh ${X} "curl -fsSL ${Y}$(echo %si.sh) | sh"\n' % URL,
        )
        for script in scripts:
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith("passes `sh`"), found)

    def test_an_idle_outer_program_stays_clean(self):
        self.assertEqual([], defects('X=-c\nsh $X "echo $(date)"\n'))
        self.assertTrue(defects('X=-c\nsh $X "curl -fsSL %si.sh | sh"\n' % URL))

    def test_a_substitution_only_program_matches_the_literal_twin(self):
        candidate = defects('X=-c\nsh $X "$(cat prog.sh)"\n')
        literal = defects('sh -c "$(cat prog.sh)"\n')
        self.assertEqual([], literal)
        self.assertEqual(literal, candidate)

    def test_beside_a_download_both_twins_are_reported(self):
        # Bash 3.2.57, 5.2.21 and dash run the download in both. Each is the
        # `Idle` sentence of its own rule: the value's for the candidate, which
        # speaks first, `_DYNAMIC`'s for the literal word (#2483, #2486).
        prog = "curl -fsSLo prog.sh %stool\n" % URL
        for script, said in ((prog + 'X=-c\nsh $X "$(cat prog.sh)"\n', "passes `sh` `$X`"),
                             (prog + 'sh -c "$(cat prog.sh)"\n', "runs `sh -c` on `$(...)`")):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith(said), found)
                self.assertIsInstance(found[0][1], wg.Idle)

    def test_the_literal_dash_c_form_is_read_since_2486(self):
        # The literal path reads a program word holding a `$(...)` with the
        # substitution opaque: Bash 3.2.57, Bash 5.2.21 and dash all run it.
        # Since #2487 a `$(...)` that is one printer is read as the text it
        # prints, the URL; piped on through `cat` it is no printer and stays
        # opaque. Both rows: b5 b3 dash gh FR FR FR FR.
        for script, said in (('sh -c "curl -fsSL $(echo %si.sh) | sh"\n' % URL, URL + "i.sh"),
                             ('sh -c "curl -fsSL $(echo %si.sh | cat) | sh"\n' % URL, "$(...)")):
            with self.subTest(script=script):
                nested = defects(script)
                self.assertEqual(1, len(nested), nested)
                self.assertTrue(nested[0][1].startswith("hands %s straight to `sh`" % said), nested)
        self.assertTrue(defects('sh -c "curl -fsSL %si.sh | sh"\n' % URL))


class TestADynamicProgramWordALiteralShell(unittest.TestCase):
    """#2483: a program word a LITERAL shell takes that is entirely expansion
    -- `sh -c "$P"`, `eval "$P"` -- spells no command, so `flattened` read it
    as nothing at all and the step read CLEAN while bash runs the download
    once `$P` is `sh tool`. One rule now for such a word wherever a shell
    takes one: `Idle`, kept where the job holds a fetch the guard reports,
    exactly as the `$CMD -c "$P"` twin is. A word of lifted `$(...)` or
    backquotes, `$` words beside them or not, is one too (#2486):
    `sh -c "$(cat prog.sh)"` runs the download it prints, unread (#2487)."""

    def test_each_spelling_is_reported_beside_a_reported_fetch(self):
        # Bash 3.2.57 and 5.2.21 run `tool` in each once `$P` is `sh tool`;
        # the reader rewrites `${X:-sh}` to its default, so that shell is
        # literal here and the same rule reads it.
        for script, said in ((GET + 'sh -c "$P"\n', 'runs `sh -c` on `$P`'),
                             (GET + 'bash -c "${P}"\n', 'runs `bash -c` on `${P}`'),
                             (GET + 'eval "$P"\n', 'runs `eval` on `$P`'),
                             (GET + '${X:-sh} -c "$P"\n', 'runs `sh -c` on `$P`'),
                             (GET + 'sh -ec "$P"\n', 'runs `sh -c` on `$P`')):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith(said), found)

    def test_it_is_not_reported_where_no_fetch_of_the_job_is(self):
        # #2481's predicate decides it, as it decides the twin's: no fetch at
        # all, and a download a checksum credits, leave it standing nowhere.
        check = "echo '%s  tool' | sha256sum -c -\n" % ("a" * 64)
        for script in ('sh -c "$P"\n', 'eval "$P"\n', 'bash -c "${P}"\n',
                       GET + check + 'sh -c "$P"\n', 'sh -c "$(cat prog.sh)"\n',
                       GET + check + 'eval "$(ssh-agent -s)"\nsh tool\n'):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))

    def test_a_download_the_word_carries_keeps_its_own_sentence(self):
        # #2341's `carried` says it louder, in the same statement: one
        # sentence, not two (`kept` drops the quiet one beside a loud one).
        for use in ('sh -c "$x"\n', 'eval "$x"\n', 'bash -c "${x}"\n'):
            with self.subTest(use=use):
                found = defects('x=$(curl -fsSL %si.sh)\n' % URL + use)
                self.assertEqual(1, len(found), found)
                self.assertIn("carries", found[0][1])

    def test_the_dynamic_shell_twin_is_unchanged(self):
        found = defects(GET + '$CMD -c "$P"\n')
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0][1].startswith("runs `$CMD` with `-c`"), found)

    def test_a_value_in_the_options_keeps_its_louder_reason(self):
        # Round-0 review finding 1: a shell carrying BOTH a value where it
        # reads its options and a `-c` whose operand is all expansion is
        # #2344's defect, not this one. `candidates` weighs every word after
        # the value, so one that fetches makes THAT reason loud, where this
        # rule's is a droppable `_Quiet`; the value rule speaks first. Bash
        # 3.2.57 and 5.2.21 run the fetching word with `X=-c` and `$P` empty.
        fetch = "'curl -fsSL %si.sh | sh'" % URL
        for script in ('sh $X -c "$P" %s\n' % fetch, 'sh ${X} -c "$P" %s\n' % fetch,
                       'sh $X -c "$P" arg %s\n' % fetch,
                       'sh $(echo -c) -c "$P" %s\n' % fetch,
                       '${S:-sh} $X -c "$P" %s\n' % fetch,
                       'sudo sh $X -c "$P" %s\n' % fetch,
                       'sh $X -c "$P" \'curl -fsSLo t %st && sh t\'\n' % URL):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith("passes `sh`"), found)
        # Beside a reported fetch, where no word after the value fetches, the
        # value reason is `Idle` and this rule still does not speak over it.
        found = defects(GET + 'sh $X -c "$P"\n')
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0][1].startswith("passes `sh`"), found)
        # Inside a substitution a `-c` string past the first operand -- `$0` and `$1` once `$X` is
        # `-c` -- is handed too (`substitution_script`), read opaque where a `$(...)` or backquote
        # is among its text (#2486), and its answer is `Idle` (`echo` fetches nothing): it does not
        # speak over the value's loud reason, a literal string's no more than an opaque one's. Bash
        # 5.2.21, 3.2.57 and dash run the first operand's download in each (rc 0).
        for script in ("X=-c\ny=$(sh $X %s -c \"echo $(date)\")\n" % fetch,
                       "X=-c\ny=`sh $X %s -c \"echo $(date)\"`\n" % fetch,
                       "X=-c\ny=$(sh $X %s -c \"echo `date`\")\n" % fetch,
                       "X=-c\ny=$(sh $X %s -c 'echo hi')\n" % fetch):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith(
                    "passes `sh` `$X` where it reads its options"), found)
                self.assertNotIsInstance(found[0][1], wg.Idle)
        # Where the value's reason is `Idle` too, or there is no value, nothing is said, and all
        # three run no download: #2484's row (the string after the second `-c` is the program, the
        # download `$0`), the opaque string alone, and a first operand that fetches nothing.
        for script in ("X=-c\ny=$(sh $X -c 'echo hi' %s)\n" % fetch,
                       "y=$(sh -c \"echo $(date)\" x)\n",
                       "X=-c\ny=$(sh $X 'echo hi' -c \"echo $(date)\")\n"):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))

    def test_a_value_in_the_options_speaks_before_a_stdin_no_shell_is_sure_to_read(self):
        # Fix round 2's review (#2485): past a value where a shell reads its options no shell is
        # sure to read its stdin, so neither the script it is handed inside a `$(...)` nor a
        # printer piping it one -- each `Idle`, as `echo hi` fetches nothing -- speaks before the
        # value's reason, loud as the word after the value fetches: `main`'s sentence, `main`
        # reading no such stdin. With `X=-c` bash 3.2.57 and 5.2.21 (each `-e` and `-eo pipefail`)
        # and dash run that word's download in every row, bar dash at a here-string, which it
        # refuses (rc 2).
        sh = "sh $X -s '%s'" % PIPE
        echo, printf = 'echo "$Y" | %s', "printf '%%s %%s' \"$Y\" | %s"
        # Inside a substitution: a quoted heredoc, a here-string, a spelled printer and an unspelled
        # one; and the heredoc inside backquotes and inside `"$(...)"`.
        rows = [("x=$(%s <<'EOF'\necho hi\nEOF\n)" % sh, "sh"),
                ("x=$(%s <<< 'echo hi'\n)" % sh, "sh"),
                ("x=$(echo 'echo hi' | %s\n)" % sh, "sh"), ("x=$(%s\n)" % (echo % sh), "sh"),
                ("x=`%s <<'EOF'\necho hi\nEOF\n`" % sh, "sh"),
                ('echo "$(%s <<\'EOF\'\necho hi\nEOF\n)"' % sh, "sh")]
        # An unspelled printer at the step's own level, after `true &&`, in a function body, in
        # `( … )`, in a literal shell's quoted heredoc body, in a `-c` string, in an `eval` string.
        for printer in (echo, printf):
            piped, bare = printer % sh, printer.replace('"$Y"', "$Y") % sh
            rows += [(text, "sh") for text in (
                piped, "true && " + piped, "f() {\n%s\n}\nf" % piped, "(\n%s\n)" % piped,
                "bash -s <<'OUTER'\n%s\nOUTER" % piped, 'bash -c "%s"' % bare, 'eval "%s"' % bare)]
        # The word after the value as `- '…'`; the value as `"$X"`, `${X:--c}`, `${X}` and
        # `$(echo $X)`; `bash` and `dash`.
        for command, shell in (("sh $X - '%s'", "sh"), ('sh "$X" -s \'%s\'', "sh"),
                               ("sh ${X:--c} -s '%s'", "sh"), ("sh ${X} -s '%s'", "sh"),
                               ("sh $(echo $X) -s '%s'", "sh"), ("bash $X -s '%s'", "bash"),
                               ("dash $X -s '%s'", "dash")):
            rows += [(echo % (command % PIPE), shell),
                     ("x=$(%s <<'EOF'\necho hi\nEOF\n)" % (command % PIPE), shell)]
        for text, shell in rows:
            with self.subTest(script=text):
                found = defects("export X=-c\n%s\n" % text)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith("passes `%s`" % shell), found)
        # A bare word after the value reads as the program FILE, so the stdin was never a program
        # and the value's reason always spoke; it still does (every shell runs the word, rc 0).
        for text in (echo % ("sh $X '%s'" % PIPE),
                     "x=$(sh $X '%s' <<'EOF'\necho hi\nEOF\n)" % PIPE):
            with self.subTest(script=text):
                found = defects("export X=-c\n%s\n" % text)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith("passes `sh`"), found)

    def test_a_stdin_some_shell_reads_still_speaks_first(self):
        # The order the rule above leaves alone, each answer as it was. Where the word after the
        # value fetches nothing, the value's reason is `Idle` and the printer's speaks: CLEAN
        # alone, and kept beside a reported fetch (every shell runs `tool`, rc 0).
        quiet = 'X=-c\necho "$Y" | sh $X -s \'echo hi\'\n'
        with self.subTest(script=quiet):
            self.assertEqual([], defects(quiet))
        with self.subTest(script=GET + quiet + USE):
            found = defects(GET + quiet + USE)
            self.assertEqual(2, len(found), found)
            self.assertTrue(found[0][1].startswith("pipes `sh` its program from `echo`"), found)
        # A body no shell is sure to read that fetches, where the words after the value do not:
        # #2485's catch past an unset `X` (every shell runs the download, rc 0), and round 1's
        # behind `eval` (rc 0 likewise).
        for script, runner in (("x=$(sh $X -s 'echo hi' <<'EOF'\n%s\nEOF\n)\n" % PIPE, "sh"),
                               ("x=$(eval 'bash -s' <<'EOF'\n%s\nEOF\n)\n" % PIPE, "eval")):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith("hands a script to `%s` inside" % runner),
                                found)
        # Where a shell reads the stdin -- `-s` before the value -- or the handed script holds a
        # `-c` string, that script or the printer speaks first, as it always has: each answers as
        # on `main`, which reads them. CLEAN: `-s` before the value, inside `$(...)` and through a
        # printer, though with `X=-c` every shell runs the word (rc 0) -- `main`'s reading, a gap
        # filed under #2608; and a `-c` string whose word after it no shell runs (rc 0, nothing
        # downloaded).
        for script in ("X=-c\nx=$(sh -s $X '%s' <<'EOF'\necho hi\nEOF\n)\n" % PIPE,
                       "X=-c\necho \"$Y\" | sh -s $X '%s'\n" % PIPE,
                       "X=-c\nx=$(sh $X -c 'echo hi' '%s')\n" % PIPE):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))
        # The `-c` string's own reason where it fetches, `main`'s sentence (bash 5.2.21 runs it,
        # rc 0; bash 3.2.57 refuses `${X,}`, rc 1; dash too, rc 2); and a `$` command word's `-c`,
        # at the step's own level and inside `$(...)`, whose stdin no shell reads (every shell runs
        # the word, rc 0).
        for script, said in (("X=-c\nx=$(bash ${X,} -c '%s')\n" % PIPE,
                              "hands a script to `bash` inside a command substitution"),
                             ("CMD=$(echo sh)\n$CMD -c '%s' <<'EOF'\necho hi\nEOF\n" % PIPE,
                              "runs `$CMD` with `-c`"),
                             ("CMD=$(echo sh)\nx=$($CMD -c '%s' <<'EOF'\necho hi\nEOF\n)\n" % PIPE,
                              "runs `$CMD` with `-c`")):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith(said), found)

    def test_the_positional_parameters_read_alike(self):
        # Finding 2: `$@`, `${@}` and `$*` are one thing spelled three ways,
        # and `set --` gives a `run:` step positionals -- both bashes run
        # `tool` through `set -- 'sh tool'; sh -c "$@"`. `$*` holds a `*`, so
        # the reader's pattern reason already reports that statement and the
        # quiet one is dropped beside it.
        for script, said in ((GET + "set -- 'sh tool'\nsh -c \"$@\"\n",
                              "runs `sh -c` on `$@`"),
                             (GET + "set -- 'sh tool'\nsh -c \"${@}\"\n",
                              "runs `sh -c` on `${@}`"),
                             (GET + 'eval "$@"\n', "runs `eval` on `$@`")):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith(said), found)
        # `$*` holds a `*`: the script `flattened` inlines from it is a word
        # bash expands where a command starts, so #2294 reports THAT statement
        # (as on main) and this rule reports the shell's own -- two statements,
        # so no dedup, and the verdict was already FLAGGED.
        found = defects(GET + 'sh -c "$*"\n')
        self.assertEqual(2, len(found), found)
        self.assertIn("is a pattern", found[0][1])
        self.assertTrue(found[1][1].startswith("runs `sh -c` on `$*`"), found)

    def test_a_nested_expansion_is_still_all_expansion(self):
        # Finding 3: `${A:-${B}}` is entirely expansion, and both bashes run
        # `tool` through it where `$B` is `sh tool`. Braces are counted, not
        # matched by pattern, so the depth is not capped.
        for word in ('${A:-${B}}', '${A:-${B:-${C}}}', '${A:-${B}}${C}'):
            with self.subTest(word=word):
                found = defects(GET + 'sh -c "%s"\n' % word)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith("runs `sh -c` on `%s`" % word), found)
        # A word holding text of its own is not this rule, nested or not, and
        # an unbalanced brace is no expansion at all.
        for word in ('${A}x', 'x${A}', '${A:-${B}}x', '${A', '$', '${A:-${B}} ${C}'):
            with self.subTest(word=word):
                self.assertEqual([], defects(GET + 'sh -c "%s"\n' % word))
        # A blank BETWEEN substitutions is text of the word's own too, as between expansions above,
        # though bash 5.2.21, 3.2.57 and dash run the download through it: a known gap.
        self.assertEqual([], defects(GET + 'sh -c "$(cat a) $(cat tool)"\n'))

    def test_eval_set_is_the_declared_over_report(self):
        # Finding 4: `eval set -- "$OPTS"` is the getopt idiom, and bash runs
        # none of the value as a command -- unless it holds a `;`, which
        # `eval` does run, so reporting it is the fail-closed answer and
        # `dynamic_program`'s docstring declares it.
        found = defects(GET + 'eval set -- "$P"\n')
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0][1].startswith("runs `eval` on `$P`"), found)

    def test_a_string_that_mixes_text_and_expansion_is_read_as_written(self):
        # Not this rule: the string spells a command, and the reader reads it
        # as it always has -- `echo` fetches nothing, and `echo $(date)` is
        # read `Opaque`, its `$(...)` text where the guard's own walk reads it.
        for script in (GET + 'sh -c "echo $X"\n', GET + 'sh -c "echo $(date)"\n'):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))
        found = defects(GET + 'sh -c "curl -fsSL $U | sh"\n')
        self.assertEqual(1, len(found), found)
        self.assertIn("straight to `sh`", found[0][1])

    def test_a_word_that_is_all_substitution_is_one(self):
        # #2486's fifth row and its spellings, each CLEAN until now: bash
        # 3.2.57, 5.2.21 and dash run the download in every one (dash prints
        # nothing for `$(< f)`, so there only the bashes do; zsh runs its
        # own). `sudo` is a stub here, never the real one.
        # The row itself is pinned in `test_beside_a_download_both_twins_are_reported`.
        prog = "curl -fsSLo prog.sh %stool\n" % URL
        sh_c, on = "runs `sh -c` on `$(...)`", "runs `%s` on `%s`"
        for script, said in ((prog + 'eval "$(cat prog.sh)"\n', on % ("eval", "$(...)")),
                             (prog + 'sh -c "`cat prog.sh`"\n', sh_c),
                             (prog + 'sh -c "$(cat prog.sh)" x\n', sh_c),
                             (prog + 'bash -c "$(< prog.sh)"\n', on % ("bash -c", "$(...)")),
                             (GET + 'sh -c "$(cat tool)"\n', sh_c),
                             (GET + 'sh -c "$P$(cat tool)"\n', on % ("sh -c", "$P$(...)")),
                             (GET + 'sh -c "$(cat a)$(cat tool)"\n', on % ("sh -c", "$(...)$(...)")),
                             (GET + 'sudo sh -c "$(cat tool)"\n', sh_c),
                             (GET + 'zsh -c "$(cat tool)"\n', on % ("zsh -c", "$(...)")),
                             (GET + '${SHELL:-sh} -c "$(cat tool)"\n', sh_c),
                             (GET + 'y=$(sh -c "$(cat tool)")\n', sh_c)):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith(said), found)
                self.assertIsInstance(found[0][1], wg.Idle)
        # The control: the download run by its name, loud.
        found = defects(GET + "sh tool\n")
        self.assertEqual(1, len(found), found)
        self.assertNotIsInstance(found[0][1], wg.Idle)

    def test_blanks_around_the_word_and_a_trailing_semicolon_are_no_text_of_its_own(self):
        # Every shell runs `"$(cat tool) "` as it runs `"$(cat tool)"`, and a `run: |` block wraps
        # the word in newlines (`_all_expansion`). Bash 5.2.21, 3.2.57 and dash run the download
        # in every row, each CLEAN until now. The sentence quotes the word without its blanks.
        sh_c, on_eval = "runs `sh -c` on `$(...)`", "runs `eval` on `$(...)`"
        for script, said in ((GET + 'sh -c "$(cat tool) "\n', sh_c),
                             (GET + 'sh -c " $(cat tool)"\n', sh_c),
                             (GET + 'sh -c "$(cat tool);"\n', "runs `sh -c` on `$(...);`"),
                             (GET + 'eval "$(cat tool) "\n', on_eval),
                             (GET + 'sh -c "\n  $(cat tool)\n"\n', sh_c),
                             (GET + 'eval "\n$(cat tool)\n"\n', on_eval),
                             (GET + 'sh -c "\t$(cat tool)"\n', sh_c),
                             (GET + 'sh -c "`cat tool` "\n', sh_c)):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith(said), found)
                self.assertIsInstance(found[0][1], wg.Idle)
        # A leading `;`, or a second trailing one, is text: every shell refuses the string (rc 2)
        # and runs none of the download.
        for script in (GET + 'sh -c ";$(cat tool)"\n', GET + 'sh -c "$(cat tool);;"\n'):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))

    def test_a_stream_it_runs_keeps_its_own_sentence(self):
        # The stream the substitution prints is reported loud on the same
        # statement, so the word's `Idle` is dropped beside it (#2490).
        for script, how in (('sh -c "$(curl -fsSL %si.sh)"\n' % URL, "sh -c"),
                            ('eval "$(curl -fsSL %si.sh)"\n' % URL, "eval")):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith(
                    "hands %si.sh straight to `%s`" % (URL, how)), found)

    def test_what_it_prints_is_unread_whatever_it_runs(self):
        # The price, #2483's: beside an unverified download a word that runs
        # none of it is reported too -- in all three, `$(date)` names no
        # command (rc 127) and `ssh-agent -s` prints assignments. And a
        # printer piped on through `cat`, which `rendered` does not read as
        # one printer: the sentence is the unread one, though each runs the
        # download (b5 b3 dash gh: FR FR FR FR).
        for script, how in ((GET + 'sh -c "$(date)"\n', "sh -c"),
                            (GET + 'eval "$(ssh-agent -s)"\n', "eval"),
                            (GET + "eval \"$(echo 'sh tool' | cat)\"\n", "eval"),
                            (GET + "sh -c \"$(echo 'sh tool' | cat)\"\n", "sh -c")):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith("runs `%s` on `$(...)`" % how), found)
        # #2487's string rows (b5 b3 dash gh: FR FR FR FR) are read through
        # now: the one printer's text, `sh tool`, is the program. Fix round 1
        # (C-1 to C-3): the catch-all row stands beside that read, as it did
        # at the base (main / base / 19423415: UR / UR / FX), so each reports
        # both -- the price of a read that may miss what bash runs.
        for script, how in ((GET + "eval \"$(echo 'sh tool')\"\n", "eval"),
                            (GET + "sh -c \"$(echo 'sh tool')\"\n", "sh -c")):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(2, len(found), found)
                self.assertTrue(found[0][1].startswith("runs `%s` on `$(...)`" % how), found)
                self.assertTrue(found[1][1].startswith(
                    "fetches %stool -> tool and running it under `sh`" % URL), found)


class TestALiteralStringHoldingASubstitution(unittest.TestCase):
    """#2486's acceptance as its reviewer widened it (2026-10-02), row by row: a `-c` or
    `eval` string a LITERAL shell takes, with a `$(...)` the step's own shell runs among its text,
    is read with the substitution opaque (`Opaque`), or with the text it prints where it is one
    printer (#2487) -- inside the fetch, after it or before it, behind `sh`, `bash`, `zsh`, `eval`
    or a shell a default spells -- so the download the text around it spells is reported, once. A
    program word that is all expansion is reported beside a download, `Idle` (`_DYNAMIC`); alone,
    one a literal assignment fills still reads CLEAN (row 6). Under bash 3.2.57, 5.2.21 and dash
    every row fetches and runs the download, row 6 alone too."""

    def test_each_row_is_reported(self):
        sub, prog = "curl -fsSL $(echo %s)i.sh | sh" % URL, "curl -o prog.sh %si.sh\n" % URL
        piped = "hands %s straight to `sh`"
        # Rows 1 and 4 (b5 b3 dash gh: FR FR FR FR each): since #2487 the `$(echo …)` the step's
        # own shell runs is one printer, read as the URL it prints; piped on through `cat` it is
        # no printer, and the substitution stays opaque (FR FR FR FR too).
        rows = [
            # 1: the `$(...)` inside the fetch's URL, and the must-trip: its single-quoted twin,
            # whose `$(...)` the inner `sh` runs, read as a plain string before #2486 too.
            (1, 'sh -c "%s"\n' % sub, piped % (URL + "i.sh")),
            (1, 'sh -c "%s"\n' % sub.replace(")i.sh", " | cat)i.sh"), piped % "$(...)i.sh"),
            (1, "sh -c '%s'\n" % sub, piped % "$(...)i.sh"),
            # 2 and 3: an incidental `$(date)` after the fetch, and before it.
            (2, 'sh -c "%s; echo $(date)"\n' % PIPE, piped % (URL + "i.sh")),
            (3, 'sh -c "echo $(date); %s"\n' % PIPE, piped % (URL + "i.sh")),
            # 4: each other shell that takes such a string.
            (4, 'bash -c "%s"\n' % sub, piped % (URL + "i.sh")),
            (4, 'zsh -c "%s"\n' % sub, piped % (URL + "i.sh")),
            (4, 'eval "%s"\n' % sub, piped % (URL + "i.sh")),
            (4, '${X:-sh} -c "%s"\n' % sub, piped % (URL + "i.sh")),
            # 5: a program word all substitution, `_DYNAMIC`'s; the file run by its name; and the
            # value twin, whose `Idle` sentence speaks first.
            (5, prog + 'sh -c "$(cat prog.sh)"\n', "runs `sh -c` on `$(...)`"),
            (5, prog + "sh prog.sh\n", "fetches %si.sh -> prog.sh and running it" % URL),
            (5, prog + 'X=-c\nsh $X "$(cat prog.sh)"\n', "passes `sh` `$X` where it reads"),
            # 6 beside a download no checksum clears: `_DYNAMIC`'s, as `sh -c "$P"` is above.
            (6, GET + "P='%s'\nsh -c \"$P\"\n" % PIPE, "runs `sh -c` on `$P`")]
        for row, script, said in rows:
            with self.subTest(row=row, script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith(said), found)

    def test_row_6_alone_is_a_known_gap(self):
        # CLEAN, though all three fetch and run the download: the dynamic twin of #2486, filed
        # as #2682. `flattened` reads `"$P"` as no command, and `_DYNAMIC`'s `Idle` stands only
        # beside a fetch the guard reports; `carried` follows a DOWNLOAD a variable keeps
        # (`_assigned`), and a literal assignment's text handed to `-c`/`eval` is never a program.
        self.assertEqual([], defects("P='%s'\nsh -c \"$P\"\n" % PIPE))


class TestWhichProgramAStdinReadingCommandRuns(unittest.TestCase):
    """#2331 batch V-b: three true spellings escape `stdin_program`'s operand
    walk, so the heredoc, here-string or pipe each runs on its own stdin is
    taken for data instead of the program it is (#2500, #2485, #2473); and
    under a `$` command word a shell's `-s`, a vanishing operand or an
    option's value ended the walk at a FILE (`CMD=bash; $CMD -s -- "$V"`,
    `$CMD $X` with `X` unset, `$CMD -oe pipefail`), until the word took a
    shell's rules (the final review's F2, and its fix round 2); and an option
    owed a value took a stdin operand for it (`$PYTHON -Ou - file.py`,
    `python3 -O - file.py`), until the walk answered there for all but a
    literal shell (fix round 3); and a check counted in a body read past a
    value, and behind a string under the enclosing command's `-e`, until it
    counted nowhere (review round 1 and its fix); and another statement of
    such a body could clear a step `main` reports, until the job was read
    without those bodies too (fix round 2). Every step below was run in
    bash 3.2.57, 5.2.21 and dash, every checksum failing: a DEFECT is a
    download they run (bar a dash step, which refuses its own syntax only --
    `<<<`, `<(...)` -- and runs the `--` of `eval -- bash -s` as a command: an
    option word goes to the shell the step names, so `bash -o pipefail`,
    `bash -oe pipefail` and `bash -O extglob` run the heredoc under a dash
    step too, and `sh -o pipefail` wherever `sh` is bash, as on macOS -- a
    Linux `sh` is dash and refuses it), a CLEAN a step that runs none --
    except these readings, which contradict them, each accepted for its
    reason:

    * fail-closed over-reports: `X=script.sh; sh $X` and its `X=-n` and bare
      `X=-c` twins, which run nothing (#2485), and `CMD=$(echo sh)` whose body
      ends in the check (#2473), where the reader cannot tell the word from one
      that runs the body (`X=-s`) or skips it (`true`), and `$CMD "$X"` with
      `X` empty and `$PYTHON -Ou file.py` with a download body, whose walks
      now read on as a shell's, and `$CMD -o -` and `$CMD -oe - x.sh`, whose
      `-` is read as stdin though a shell refuses it as `-o`'s value (#2473);
      `$NODE -e "$CODE"` and `$PYTHON -m "$MOD"` with a download body, alone
      and beside GET, whose own option value spelled `$` the walk reads past
      as a vanishing operand, though neither reads the heredoc (#2473);
      a letter bash and dash refuse, read on as the operand walk reads `sh -K`
      (#2475 stops only a `-c` cluster): behind a value (`X=-K; sh $X`,
      #2485), a `$` word (`CMD=$(echo sh); $CMD -K`, #2473) or an inner shell
      (`eval 'bash -K -s'`, `bash -c 'sh -K'`, #2500); `eval -- bash -s`,
      whose `--` dash runs as a command; seventy `eval`s before `echo hi`,
      read as a stdin shell past the reading's 64-deep bound (#2500);
      `bash -c "sh $(echo tool)"`, read as `sh $(...)` (#2486), whose
      `$(...)` may vanish (#2485), so its heredoc is read as a body no shell
      is sure to read and a download in it reported by the job's first
      reading (#2500), though it runs `sh tool` and the heredoc is that
      program's data; and a
      non-shell body under a `$` word whose string spells a shell download,
      quoted or expanding (`print("$(curl ... | sh)")` under `$PYTHON -`, a
      `$CAT <<'EOF' > i.sh` body), read as shell and reported loud, filed
      under #2331; a check read
      past a value or a word that may vanish (`X=-s`, `X=-e`, `X` unset,
      `$(true)`), where the guard cannot tell the word from `X=/dev/null`
      (#2485); behind a string no check counts (#2500), so a body ending in
      its check (`eval 'bash -s'`, `bash -c 'sh'`, `bash -s -c 'sh'`) and a
      self-contained `-e` body (`eval 'bash -e -s'`) are reported though every
      shell stops at the check, what the inner shell is, what it reads and
      what becomes of its failure being the step's to change;
      `eval 'bash -s &'` and `eval 'bash -s < /dev/null'` around a body no
      shell runs (round 1); a step that a statement of a body no shell is sure
      to read would clear -- the `exit 1` of a rescue, a call of the step's
      function or of one the body defines, a `> sums`, a `cp` -- reported, the
      job being read without that body too, though the inner shell runs the
      `exit 1`, a shell lacks the function it calls or the check fails (round
      2): each with `main`'s sentence, bar the call of a function the body
      defines, which keeps the first reading's (its check "is inside the
      script `<holder>` runs, and the step does not stop when that script
      fails", where `main` says nothing verifies what arrived); a body no
      shell is sure to read that the reader refuses (such as a `)` in a
      substitution heredoc body), which refuses its step whole though under
      `CMD=$(echo true)` or past `X=/dev/null` no shell reads it (#2668; a
      literal `CMD=true` reads as `true` since #2468);
      `eval` words the reader refuses joined, though each reads alone
      (`eval 'echo $(cat <<A' 'x' 'A)'`), which refuse their step, as bash
      runs the join -- nothing in it downloads (fix round 3); and, as before
      round 1, the body of `builtin eval`, which the guard does not take for
      `eval`;
    * `Idle` hand-offs beside a download that never runs (`$CMD` with
      `echo hi`, `$PYTHON -`, `python3 -` and `${X:-/usr/bin/python3} -` with
      `print(1)`, `$PYTHON -s file.py`, `$PYTHON -Ou file.py` and
      `$PYTHON -O file.py` with `print(1)`, whose `-s` and `O` read as a
      shell's, `x=$(echo hi | $CMD)` and its `$(echo sh)` twin, and the
      `$CMD -c "$P"` candidate (#2337), each beside GET): a report of a
      program the guard cannot read, kept beside a fetch it reports (#2499),
      not a claim that a download runs;
    * fail-open readings: `$PYTHON -`, `python3 -`, `$PYTHON -Ou - file.py`
      or `python3 -O - file.py` running
      `os.system`, beside no reported fetch (option b's price, #2499); and,
      each filed under #2331, `eval 'bash -s | cat'` (#2500),
      `echo "$Y" | $CMD` with values no table places (literal ones read
      since #2468), and `eval "$CMD"` or an
      exported `bash -c '$CMD'` handed a heredoc alone -- beside a reported
      fetch #2483 reports the word, never the body (#2473). Round 1 leaves
      `main`'s own gaps for a literal stdin shell, read as `main` reads them,
      each filed under #2331 too and reported behind a string: options that
      keep it from running its program (`bash -n -s`, `bash -t -s`,
      `bash -s -c true`, `bash --version`, `bash -o $X -s` with `X=noexec`,
      and `SHELLOPTS=noexec bash -s` under a dash step); a subshell's
      `|| true`; a check in a function called under `|| true` or never called,
      or ahead of `&&` in a `-e` body; a body that reads the rest of itself
      away (`cat >/dev/null`); `<>` on descriptor 0, and `&>` under a dash
      step; `((bash -s))` with `bash` set; `bash - /dev/null`; and a name made
      to run something else (`sh() { :; }`, `alias sh=:`, a fake `sh` first on
      `PATH`), which the step's own `sha256sum` meets too. Round 2 leaves two,
      each filed under #2608: a `}` in a body a literal shell reads --
      `bash -s`, or the holder's own `-s` (`bash -s -c 'sh'`) -- closing the
      step's own group, as on `main` (an `exit`, a call or a write there is
      taken for the step's own too, and the twins pinned here run them); and
      a statement of one body no shell is sure to read giving credit for a
      download only another such body holds.

    `python3 $S` with S unset reads its heredoc as data, where python takes
    it as its program; here that is a SyntaxError, so CLEAN is still true
    (#2485, filed under #2331)."""

    def test_2500_eval_or_dash_c_behind_a_stdin_reading_shell_inherits_the_heredoc(self):
        # `eval`'s or `-c`'s STRING is one statement whose own command is
        # itself a stdin-reading shell (`bash -s`, `sh`): the enclosing
        # `eval`/`-c` command answers SHELL_PROGRAM too, so its heredoc,
        # here-string or pipe is read as that inner shell's program.
        for script in ("eval 'bash -s' <<'EOF'\n%s\nEOF\n" % PIPE,
                       "bash -c 'sh' <<'EOF'\n%s\nEOF\n" % PIPE,
                       "eval 'bash -s' <<< '%s'\n" % PIPE, "bash -c 'sh' <<< '%s'\n" % PIPE,
                       "echo '%s' | eval 'bash -s'\n" % PIPE,
                       "echo '%s' | bash -c 'sh'\n" % PIPE):
            with self.subTest(script=script):
                found = defects(script)
                self.assertTrue(any("straight to `sh`" in w for _, w in found), found)
        # Inside a `$(...)` the same inheritance still answers SHELL_PROGRAM
        # (`stdin_scripts` depends on it too), but `substitution_script`
        # weighs anything handed to a shell there with its OWN, more
        # conservative sentence -- no download is FOLLOWED into a
        # substitution, not that none was found.
        for script in ("x=$(eval 'bash -s' <<'EOF'\n%s\nEOF\n)\n" % PIPE,
                       "x=$(bash -c 'sh' <<'EOF'\n%s\nEOF\n)\n" % PIPE):
            with self.subTest(script=script):
                found = defects(script)
                self.assertTrue(any("inside a command substitution" in w for _, w in found), found)
        # The must-trip control: the literal spelling this already flagged.
        self.assertTrue(defects("bash -s <<'EOF'\n%s\nEOF\n" % PIPE))
        # An EXPANDING body is reported unread, as a bare shell's is.
        found = defects("eval 'bash -s' <<EOF\n%s\nEOF\n" % PIPE)
        self.assertEqual(1, len(found), found)
        self.assertIn("EXPANDING", found[0][1])
        # `echo hi` and `cat` do not read their own program from stdin, so
        # the heredoc stays `eval`'s or `-c`'s DATA: CLEAN.
        for script in ("eval 'echo hi' <<'EOF'\n%s\nEOF\n" % PIPE,
                       "bash -c 'cat' <<'EOF'\n%s\nEOF\n" % PIPE):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))
        # r0's N-4 (d13): `eval`'s own several words join into the ONE
        # string bash runs before this check, never read one at a time.
        # `eval bash script.sh` is `bash script.sh` -- a FILE, not bare
        # `bash` alone reading stdin -- and `eval set -- "$ARGS"` is not
        # `set` alone either: both stay CLEAN. The quoted and unquoted
        # spellings of `eval bash -s` agree (DEFECT), as they did before.
        for script in ("eval bash script.sh <<'EOF'\n%s\nEOF\n" % PIPE,
                       'eval set -- "$ARGS" <<\'EOF\'\n%s\nEOF\n' % PIPE):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))
        for script in ("eval bash -s <<'EOF'\n%s\nEOF\n" % PIPE,
                       "eval 'bash -s' <<'EOF'\n%s\nEOF\n" % PIPE):
            with self.subTest(script=script):
                found = defects(script)
                self.assertTrue(any("straight to `sh`" in w for _, w in found), found)
        # Review R1-I2: the join must be bash's OWN join, every word eval
        # was given, not `scripts()`'s (which drops every `-`-prefixed word
        # for ITS callers) -- dropping a `-s`/`-c`/`--` here silently turns
        # the inner shell's OWN stdin-reading form into a bare name or a
        # FILE instead, and reads CLEAN where bash RAN x3 (must-trip:
        # reverting to `scripts()`'s filtered words reads all four CLEAN).
        for script in ("eval bash -s x.sh <<'EOF'\n%s\nEOF\n" % PIPE,
                       "eval bash -c sh <<'EOF'\n%s\nEOF\n" % PIPE,
                       "eval sh -c 'bash -s' <<'EOF'\n%s\nEOF\n" % PIPE,
                       "eval bash -s -- x <<'EOF'\n%s\nEOF\n" % PIPE):
            with self.subTest(script=script):
                found = defects(script)
                self.assertTrue(any("straight to `sh`" in w for _, w in found), found)
        # eval's OWN leading `--` ends ITS options and is not joined either
        # (bash-true: `eval -- bash -s` still reads the heredoc as `bash
        # -s`'s); must-trip against the plainer "join argv[1:] outright"
        # fix, which would join it as the literal command `-- bash -s` and
        # read this CLEAN instead (neither bash nor a known shell is named
        # `--`).
        found = defects("eval -- bash -s <<'EOF'\n%s\nEOF\n" % PIPE)
        self.assertTrue(any("straight to `sh`" in w for _, w in found), found)
        # Review I-1, closed in round 1 and its fix round: no check in this
        # inherited body counts, under the enclosing command's `-e` or the
        # inner shell's, so a check gated only by `-e` is reported, naming the
        # command that holds the string, and the literal twin names its reader:
        # `bash tool` runs in all three shells past `sha256sum -c -`'s failure.
        check = "echo '%s  tool' | sha256sum -c -\nbash tool\n" % ("a" * 64)
        gated_body = GET + check
        for script, said in (("eval 'bash -s' <<'EOF'\n%sEOF\n" % gated_body, UNGATED % "eval"),
                             ("bash -ec 'sh' <<'EOF'\n%sEOF\n" % gated_body, UNGATED % "bash"),
                             ("bash -s <<'EOF'\n%sEOF\n" % gated_body, RUNS_ON % "bash"),
                             ("bash -c 'sh' <<'EOF'\n%sEOF\n" % gated_body, UNGATED % "bash")):
            with self.subTest(script=script):
                found = defects(script)
                self.assertTrue(any(said in w for _, w in found), found)
        # N-5's documented, filed gap: a pipeline whose FIRST stage reads
        # stdin is never reached here (the recursive check keeps to a single
        # STAGE, `len(parsed[0].stages) == 1`) -- bash runs `bash -s` as that
        # first stage with `eval`'s own heredoc as ITS stdin regardless, so
        # this CLEAN is a known false negative, not a claim nothing downloads.
        self.assertEqual([], defects("eval 'bash -s | cat' <<'EOF'\n%s\nEOF\n" % PIPE))
        # Where #2475's letter table meets this reading (#2551, the third
        # fold): a `-c` cluster the OUTER shell refuses hands over no string
        # (`_past_options`), so `bash -c -K 'sh'` reads CLEAN -- bash 3.2.57,
        # 5.2.21 and dash exit 2 and run nothing; before the fold it was read.
        # An INNER shell's refused letter is read on, as the operand walk
        # reads a literal `sh -K <<'EOF'`, so `eval 'bash -K -s'` and `bash -c
        # 'sh -K'` are still read and report the stream though all three
        # shells exit 2 at `-K` and run nothing: a fail-closed price, named in
        # `stdin_program`'s docstring. The controls are the first loop's.
        self.assertEqual([], defects("bash -c -K 'sh' <<'EOF'\n%s\nEOF\n" % PIPE))
        for script in ("eval 'bash -K -s' <<'EOF'\n%s\nEOF\n" % PIPE,
                       "bash -c 'sh -K' <<'EOF'\n%s\nEOF\n" % PIPE):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertIn("straight to `sh`", found[0][1])

    def test_2500_a_deep_eval_chain_is_read_bounded_and_fail_closed(self):
        # The final review's F1: `flattened` asked `stdin_program` once per
        # script an `eval` chain hands on, and each ask re-parsed the chain at
        # every level -- two hundred `eval`s took 37 s, and 1,600 raised an
        # uncaught RecursionError. The reading now looks at most 64 strings
        # deep and is asked once per stage, so the call returns. Three or two
        # hundred `eval`s before `bash -s` hand it the heredoc, and bash
        # 3.2.57, 5.2.21 and dash run it through both chains. Past the bound
        # the answer is SHELL_PROGRAM unlooked, fail-closed: seventy `eval`s
        # before `echo hi` read as a stdin shell though nothing runs (rc 0 in
        # all three), where three read CLEAN.
        for count, inner in ((3, "bash -s"), (200, "bash -s"), (70, "echo hi")):
            with self.subTest(count=count, inner=inner):
                found = defects("eval " * count + "%s <<'EOF'\n%s\nEOF\n" % (inner, PIPE))
                self.assertEqual(1, len(found), found)
                self.assertIn("straight to `sh`", found[0][1])
        self.assertEqual([], defects("eval eval eval echo hi <<'EOF'\n%s\nEOF\n" % PIPE))

    def test_2485_a_value_or_a_vanishing_word_does_not_end_a_shells_walk(self):
        # A value form (`$X`, quoted the same once the reader sees it) or a
        # word bash may drop outright does not end the walk at a FILE
        # operand, so the heredoc past it reads as the shell's program --
        # fail-closed, same as `sh -s` already was.
        for script in ("X=-s\nsh $X <<'EOF'\n%s\nEOF\n" % PIPE,
                       "sh $X <<'EOF'\n%s\nEOF\n" % PIPE,  # X unset: the empty word drops
                       "X=-s\nsh \"$X\" <<'EOF'\n%s\nEOF\n" % PIPE,
                       "bash <<'EOF' $(true)\n%s\nEOF\n" % PIPE):
            with self.subTest(script=script):
                found = defects(script)
                self.assertTrue(any("straight to `sh`" in w for _, w in found), found)
        # A clean body stays clean: nothing about the value matters here.
        self.assertEqual([], defects("X=-s\nsh $X <<'EOF'\necho hi\nEOF\n"))
        # Fail-closed over-report, named in the guard's gap list: bash runs
        # the FILE `$X` names, not the heredoc, but the reader cannot tell
        # `X=script.sh` from `X=-s` -- both are just `$X` by the time this
        # walk sees them.
        # The same over-report where the value is an option nothing runs
        # under, the class the guard's gap list names beside `X=script.sh`:
        # with `X=-K` bash 3.2.57, 5.2.21 and dash exit 2 at a letter they
        # refuse (#2475's table, #2551), with `X=-n` they read the heredoc
        # and run none of it (rc 0), and a bare `X=-c` hands them no string
        # (rc 2) -- but `$X` is a value this walk reads on. One subtest each,
        # so a copy without the rule still runs all four.
        for value in ("script.sh", "-K", "-n", "-c"):
            with self.subTest(value=value):
                found = defects("X=%s\nsh $X <<'EOF'\n%s\nEOF\n" % (value, PIPE))
                self.assertEqual(1, len(found), found)
                self.assertIn("straight to `sh`", found[0][1])
        # The must-trip control and the unaffected FOREIGN form.
        self.assertTrue(defects("sh -s <<'EOF'\n%s\nEOF\n" % PIPE))
        self.assertEqual([], defects("python3 $S <<EOF\n%s\nEOF\n" % PIPE))
        # A `<(...)` is `_value`-shaped too (every substitution reads back as
        # `$(...)`), but it never vanishes, so it is NOT such a word: found
        # via the corpus differential, `echo "$X" | bash <(curl ...)` must
        # answer exactly the one genuine finding `bash <(curl ...)` alone
        # already does, not a spurious SECOND one claiming `bash`'s program
        # instead pipes in unseen from `echo` (stdin was never its program;
        # the process substitution FILE always is). Review I-3: the body
        # must be UNPRINTED (`$X`) -- a literal `echo hi` is spelled out by
        # `printed()`, so it passes whether or not this exclusion exists and
        # never actually exercises the fix.
        piped = defects('echo "$X" | bash <(curl -fsSL %si.sh)\n' % URL)
        bare = defects("bash <(curl -fsSL %si.sh)\n" % URL)
        self.assertEqual(bare, piped)
        self.assertEqual(1, len(piped), piped)

    def test_2605_a_file_after_a_value_option_does_not_hide_stdin(self):
        # Bash 3.2.57, 5.2.21 and dash run every body: `$X` may be `-s`, or
        # `--rcfile`, whose `/dev/null` argument is not the program file.
        rows = ("X=-s\nsh $X file.sh",
                "X=-s\nbash $X file.sh arg",
                "CMD=bash\nX=-s\n$CMD $X file.sh",
                "X=--rcfile\nbash $X /dev/null",
                "X=--rcfile\nbash $X /dev/null -s arg")
        for command in rows:
            script = "%s <<'EOF'\n%s\nEOF\n" % (command, PIPE)
            with self.subTest(command=command):
                found = defects(script)
                self.assertTrue(any("straight to `sh`" in why for _step, why in found), found)
        # Literal file and ended-options controls run no body and stay CLEAN.
        for command in ("sh file.sh", "X=-s\nsh -- $X file.sh"):
            with self.subTest(command=command):
                self.assertEqual([], defects("%s <<'EOF'\n%s\nEOF\n" % (command, PIPE)))
        # Literal `-s` is the must-trip. A value that is really `-e` runs the
        # file, not the body, but pays the issue's named fail-closed price.
        for command in ("sh -s file.sh", "X=-e\nsh $X file.sh"):
            with self.subTest(command=command):
                found = defects("%s <<'EOF'\n%s\nEOF\n" % (command, PIPE))
                self.assertTrue(any("straight to `sh`" in why for _step, why in found), found)

    def test_2486_an_opaque_dash_c_string_may_be_a_stdin_reading_shell(self):
        # #2486 reads a `-c` string holding a `$(...)` among its text with the
        # substitution opaque, and #2500's join reads that string here too:
        # `bash -c "sh $(echo -s | cat)"` runs `sh -s`, which bash 3.2.57,
        # 5.2.21 and dash hand the heredoc as its program (b5 b3 dash gh: FR
        # FR FR FR), and `sh $(...)` is a shell whose `$(...)` may vanish
        # (#2485), so the body is read as one. The inner `sh $(...)` is weighed
        # beside the stream as at the top level. Its twin runs `sh tool` in
        # all three, the body that program's data (-- -- -- --): the
        # over-report the gap list names for a word naming a file.
        value = "passes `sh` `$(...)` where it reads its options"
        for word in ("-s", "tool"):
            with self.subTest(word=word):
                found = defects("bash -c \"sh $(echo %s | cat)\" <<'EOF'\n%s\nEOF\n" % (word, PIPE))
                self.assertEqual(2, len(found), found)
                self.assertTrue(found[0][1].startswith(value), found)
                self.assertIn("straight to `sh`", found[1][1])
        # Without the `cat` the `$(...)` is one printer, read as the word it prints (#2487):
        # `sh -s` reads the body, the stream reported alone (FR FR FR FR), and `sh tool` reads a
        # file, the body its data, and nothing runs (-- -- -- --): CLEAN, the over-report gone.
        found = defects("bash -c \"sh $(echo -s)\" <<'EOF'\n%s\nEOF\n" % PIPE)
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0][1].startswith("hands %si.sh straight to `sh`" % URL), found)
        self.assertEqual([], defects("bash -c \"sh $(echo tool)\" <<'EOF'\n%s\nEOF\n" % PIPE))
        # The control: V-b's literal string, credited as it was.
        found = defects("eval 'bash -s' <<'EOF'\n%s\nEOF\n" % PIPE)
        self.assertEqual(1, len(found), found)
        self.assertIn("straight to `sh`", found[0][1])

    def test_2473_a_dollar_command_words_body_is_read_as_shell_and_its_hand_off_weighed(self):
        # A value-form command word (`$CMD`, `"$CMD"`, `${CMD}`, `$(echo sh)`,
        # `$PYTHON -`) is a name no table places: `stdin_program` answers
        # VALUE_PROGRAM. Its body is read as shell, additively -- a
        # download there is the defect it is at the top level -- and the
        # hand-off is `Idle`, under its own sentence, which `kept` stands only
        # beside a fetch the guard reports (#2499).
        def to(word):
            return ("hands a heredoc body or here-string to `%s`, a command word this guard "
                    "does not follow -- its body is read as shell" % word)

        def reasons(script):
            return [why for _step, why in defects(script)]

        streamed = "straight to `sh`"
        # (a) The issue's own pin: both reasons stand and do not contradict --
        # the stream, found by reading the body, and the hand-off, kept since
        # the job now holds a fetch the guard reports.
        for script, word in (("CMD=$(echo sh)\n$CMD <<'EOF'\n%s\nEOF\n" % PIPE, "$CMD"),
                             ('CMD=$(echo sh)\n"$CMD" <<\'EOF\'\n%s\nEOF\n' % PIPE, "$CMD"),
                             ("CMD=$(echo sh)\n${CMD} <<'EOF'\n%s\nEOF\n" % PIPE, "${CMD}")):
            with self.subTest(script=script):
                found = reasons(script)
                self.assertEqual(2, len(found), found)
                self.assertTrue(any(streamed in w for w in found), found)
                self.assertTrue(any(w.startswith(to(word)) for w in found), found)
        # #2475's per-shell scoping (#2551) reads no option word behind a `$`
        # word as a refusal -- `CMD` may hold zsh, which runs `-K` -- so
        # `CMD=$(echo sh); $CMD -K <<'EOF'` reads as (a) does, both reasons kept,
        # though bash 3.2.57, 5.2.21 and dash exit 2 at `-K` and run nothing:
        # this rule's fail-closed price, named in `stdin_program`'s docstring.
        # A `${X:-sh}` default is the shell it spells (`shell_wrappers.
        # Defaulted`), never a VALUE: its body is read and no hand-off said.
        script = "CMD=$(echo sh)\n$CMD -K <<'EOF'\n%s\nEOF\n" % PIPE
        with self.subTest(script=script):
            found = reasons(script)
            self.assertEqual(2, len(found), found)
            self.assertTrue(any(streamed in w for w in found), found)
            self.assertTrue(any(w.startswith(to("$CMD")) for w in found), found)
        script = "${X:-sh} <<'EOF'\n%s\nEOF\n" % PIPE
        with self.subTest(script=script):
            found = reasons(script)
            self.assertEqual(1, len(found), found)
            self.assertIn(streamed, found[0])
        # (b) A clean body alone is CLEAN, the issue's pin; beside a download
        # no checksum clears, the hand-off is the one reason.
        self.assertEqual([], reasons("CMD=$(echo sh)\n$CMD <<'EOF'\necho hi\nEOF\n"))
        found = reasons(GET + "CMD=$(echo sh)\n$CMD <<'EOF'\necho hi\nEOF\n")
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0].startswith(to("$CMD")), found)
        # (c) #2597: an EXPANDING body under a `$` word is read as shell too.
        # Its download and the hand-off stand together, alone or beside GET;
        # the hand-off remains `Idle`, never the literal-shell EXPANDING one.
        expanding = "CMD=$(echo sh)\n$CMD <<EOF\n%s\nEOF\n" % PIPE
        for script in (expanding, GET + expanding):
            with self.subTest(script=script):
                found = reasons(script)
                self.assertEqual(2, len(found), found)
                self.assertTrue(any(streamed in w for w in found), found)
                self.assertTrue(any(w.startswith(to("$CMD")) for w in found), found)
                self.assertFalse(any("EXPANDING" in w for w in found), found)
        # A command substitution in that expanding body was already lifted by
        # the outer read. In the added body read its output is only a value, so
        # neither `$()` nor backquotes duplicates the one real stream defect.
        for syntax in ('$(%s)' % PIPE, '`%s`' % PIPE):
            script = 'CMD=$(echo sh)\n$CMD <<EOF\necho "%s"\nEOF\n' % syntax
            with self.subTest(syntax=syntax):
                found = reasons(script)
                self.assertEqual(1, len(found), found)
                self.assertIn(streamed, found[0])
        # The owner's innocent foreign-language control remains CLEAN. A
        # literal shell's existing loud EXPANDING answer remains unchanged.
        python = 'PYTHON=$(echo python3)\n$PYTHON - <<EOF\nprint("$VAR")\nEOF\n'
        self.assertEqual([], reasons(python))
        found = reasons("bash <<EOF\n%s\nEOF\n" % PIPE)
        self.assertEqual(1, len(found), found)
        self.assertIn("EXPANDING", found[0])
        # (d) `$PYTHON - <<'EOF'` is kept and dropped where `python3 - <<'EOF'`
        # is -- CLEAN alone, an innocuous body or an `os.system` download alike
        # (option b's price again: python runs that download) -- under its own
        # sentence: the literal gets the foreign-language one, `$PYTHON` the
        # hand-off naming it.
        for body in ("print(1)\n", "import os\nos.system('%s')\n" % PIPE):
            dollar = "PYTHON=$(echo python3)\n$PYTHON - <<'EOF'\n%sEOF\n" % body
            literal = "python3 - <<'EOF'\n%sEOF\n" % body
            with self.subTest(body=body):
                self.assertEqual([], reasons(dollar))
                self.assertEqual([], reasons(literal))
                found = reasons(GET + dollar)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0].startswith(to("$PYTHON")), found)
                found = reasons(GET + literal)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0].startswith(
                    "hands a heredoc body or here-string to `python3` as the program to run, "
                    "which this guard does not parse"), found)
        # The hand-off names the word whole, as `shell_reader.readable` renders
        # it: a basename would cut `${X:-/usr/bin/python3}` to `python3}`.
        found = reasons(GET + "${X:-/usr/bin/python3} - <<'EOF'\nprint(1)\nEOF\n")
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0].startswith(to("${X:-/usr/bin/python3}")), found)
        # The price of reading as shell a body that may not be (T25-M1, filed
        # under #2331): a non-shell body whose string spells a shell download
        # is reported loud, though nothing runs it -- python prints the text,
        # `cat` writes it to a file -- where the literal twins read CLEAN.
        printing = "print(\"$(%s)\")" % PIPE
        for script, word in (("PYTHON=$(echo python3)\n$PYTHON - <<'EOF'\n%s\nEOF\n" % printing,
                              "$PYTHON"),
                             ("CAT=$(echo cat)\n$CAT <<'EOF' > i.sh\n%s\nEOF\n" % PIPE, "$CAT")):
            with self.subTest(script=script):
                found = reasons(script)
                self.assertEqual(2, len(found), found)
                self.assertTrue(any(streamed in w for w in found), found)
                self.assertTrue(any(w.startswith(to(word)) for w in found), found)
        for script in ("python3 - <<'EOF'\n%s\nEOF\n" % printing,
                       "cat <<'EOF' > i.sh\n%s\nEOF\n" % PIPE):
            with self.subTest(script=script):
                self.assertEqual([], reasons(script))
        # (e) Review R1-I1: a `$(...)` or backquote command word is LIFTED
        # before the sentence is built; naming it by the raw marker
        # (`@@shell-<hex>@@`, fresh every parse) made the guard's own text
        # differ from run to run. It reads `$(...)`, the same in two runs.
        for script in ("$(echo sh) <<'EOF'\n%s\nEOF\n" % PIPE,
                       "`echo sh` <<'EOF'\n%s\nEOF\n" % PIPE):
            with self.subTest(script=script):
                first, second = defects(script), defects(script)
                self.assertEqual(first, second)
                found = [w for _step, w in first]
                self.assertEqual(2, len(found), found)
                self.assertTrue(any(streamed in w for w in found), found)
                self.assertTrue(any(w.startswith(to("$(...)")) for w in found), found)
                self.assertFalse(any("@@" in w for w in found), found)
        # (f) The must-trip control: a LITERAL `sh`, which `_value` never
        # matches, flagged on every tree. Mutation, on a copy: with
        # `stdin_scripts` yielding no body for VALUE_PROGRAM, (a) loses its
        # stream sentence and, with no fetch left to keep it, its hand-off.
        found = reasons("sh <<'EOF'\n%s\nEOF\n" % PIPE)
        self.assertEqual(1, len(found), found)
        self.assertIn(streamed, found[0])
        # A printer's text piped into a `$` command word is read as a shell's
        # is (#2333), with no hand-off sentence. `echo "$Y" | $CMD` with both
        # values literal read CLEAN, though the shells run its download (b5 b3
        # dash gh: FR FR FR FR) -- the gap the guard's list filed under #2331,
        # closed by #2468's annotation: `$Y` is spelled as its text and `$CMD`
        # read as `sh`, so the stream sentence stands.
        found = reasons("CMD=$(echo sh)\necho '%s' | $CMD\n" % PIPE)
        self.assertEqual(1, len(found), found)
        self.assertIn(streamed, found[0])
        self.assertEqual([], reasons("CMD=$(echo sh)\necho hi | $CMD\n"))
        found = reasons("CMD=sh\nY='%s'\necho \"$Y\" | $CMD\n" % PIPE)
        self.assertEqual(1, len(found), found)
        self.assertIn(streamed, found[0])
        # A literal name's FILE operand is unaffected: #2473 only reaches a
        # value-form command word, never a literal one.
        self.assertEqual([], reasons("python3 x.py\n"))

    def test_2607_a_value_command_bound_to_the_download_owns_its_stdin(self):
        # `$T` is not an unknown interpreter here: the job has already fetched
        # the command it runs. Bash 3.2.57, 5.2.21 and dash run the payload
        # with `chmod`; without it they return 1, 126 and 126, and none reads
        # the heredoc as shell. The existing run sentence stands alone.
        get = 'T="$PWD/tool"\ncurl -fsSLo "$T" %stool\n' % URL
        body = "$T <<'EOF'\n%s\nEOF\n"

        for prepare in ('chmod +x "$T"\n', ""):
            with self.subTest(prepare=prepare, body="innocent"):
                found = defects(get + prepare + body % "echo hi")
                self.assertEqual(1, len(found), found)
                self.assertIn("fetches https://example.test/tool -> $T", found[0][1])
                self.assertNotIn("hands a heredoc", found[0][1])
            with self.subTest(prepare=prepare, body="stream"):
                found = defects(get + prepare + body % PIPE)
                self.assertEqual(1, len(found), found)
                self.assertIn("fetches https://example.test/tool -> $T", found[0][1])
                self.assertNotIn("i.sh", found[0][1])

        # A checksum naming that bound destination clears the only real use.
        # Its unverified twin above is the must-trip control. The failed check
        # stops all three shells before the payload runs (rc 1, marker curl).
        check = 'echo "%s  $T" | sha256sum -c -\n' % ("a" * 64)
        with self.subTest(case="bound checksum"):
            self.assertEqual([], defects(get + check + 'chmod +x "$T"\n' + body % PIPE))
        # The payload's text cannot change the outer shell's static cwd. Removing the synthetic
        # body therefore recomputes #2427's directory state before the checksum and use are bound.
        with self.subTest(case="bound checksum after payload cd"):
            script = "mkdir -p d\ncd d\n" + get + check + 'chmod +x "$T"\n'
            self.assertEqual([], defects(script + body % ("cd /\n" + PIPE)))

        # The literal twin remains CLEAN with its check and FLAGGED without
        # it; a mixed literal/value path keeps its one run finding. Neither
        # body is shell input, so neither gains the body's stream sentence.
        literal_use = "chmod +x tool\n./tool <<'EOF'\n%s\nEOF\n" % PIPE
        literal = GET + CHECK + "\n" + literal_use
        self.assertEqual([], defects(literal))
        literal_control = GET + literal_use
        self.assertEqual(1, len(defects(literal_control)), defects(literal_control))
        mixed = ('curl -fsSLo "$PWD/tool" %stool\nchmod +x "$PWD/tool"\n'
                 '"$PWD/tool" <<\'EOF\'\n%s\nEOF\n' % (URL, PIPE))
        found = defects(mixed)
        self.assertEqual(1, len(found), found)
        self.assertNotIn("i.sh", found[0][1])

        # A different fetch binds nothing to `$CMD`: its existing hand-off is
        # retained, and a stream in the possible shell body is retained too.
        unrelated = "curl -fsSLo other %sother\nCMD=$(echo sh)\n" % URL
        found = defects(unrelated + "$CMD <<'EOF'\necho hi\nEOF\n")
        self.assertEqual(1, len(found), found)
        self.assertIn("hands a heredoc", found[0][1])
        found = defects(unrelated + "$CMD <<'EOF'\n%s\nEOF\n" % PIPE)
        self.assertEqual(2, len(found), found)
        self.assertTrue(any("hands a heredoc" in why for _step, why in found), found)
        self.assertTrue(any("i.sh" in why for _step, why in found), found)

        # Binding is job-wide, as fetch-and-execute credit already is. The
        # repeated assignment models a job environment value in separate
        # shell invocations; the defect remains attributed to the fetch step.
        split = wg.job_defects([
            ("fetch", get),
            ("run", 'T="$PWD/tool"\n' + body % PIPE),
        ])
        self.assertEqual(1, len(split), split)
        self.assertEqual("fetch", split[0][0])
        self.assertNotIn("i.sh", split[0][1])

    def test_2473_a_check_inside_a_dollar_command_words_body_clears_no_download(self):
        # `$CMD` may run its body as shell, or not at all -- `true` ignores it,
        # `cat` prints it -- so a checksum written there clears nothing:
        # `flattened` reads the body with its gates off. Bash 3.2.57 and
        # 5.2.21 run each download below unverified (dash too, bar the
        # here-string it refuses); a body read with its gates on cleared all
        # four.
        check = "echo '%s  tool' | sha256sum -c -" % ("a" * 64)
        use = "chmod +x tool\n./tool\n"
        ungated = "inside the script `%s` runs, and the step does not stop when that script fails"
        for script in (GET + "CMD=$(echo true)\n$CMD <<'EOF'\n%s\nEOF\n" % check + use,
                       GET + "CMD=$(echo cat)\n$CMD <<'EOF'\n%s\nEOF\n" % check + use,
                       GET + 'CMD=$(echo true)\necho "%s" | $CMD\n' % check + use,
                       GET + 'CMD=$(echo true)\n$CMD <<< "%s"\n' % check + use):
            with self.subTest(script=script):
                found = [w for _step, w in defects(script)]
                self.assertTrue(any(ungated % "$CMD" in w for w in found), found)
        # The controls: with no check the step is FLAGGED, and a literal `sh`
        # whose body ends in the check is CLEAN -- its failure stops `sh`, and
        # `-e` the step, in all three shells. Behind `CMD=$(echo sh)` the same
        # body is FLAGGED: a fail-closed over-report, since the reader cannot
        # tell that value from `CMD=$(echo true)`.
        found = [w for _step, w in defects(GET + use)]
        self.assertEqual(1, len(found), found)
        self.assertIn("nothing verifying what arrived", found[0])
        self.assertEqual([], defects(GET + "sh <<'EOF'\n%s\nEOF\n" % check + use))
        script = GET + "CMD=$(echo sh)\n$CMD <<'EOF'\n%s\nEOF\n" % check + use
        found = [w for _step, w in defects(script)]
        self.assertTrue(any(ungated % "$CMD" in w for w in found), found)
        # A `$(...)` runner is named so in this sentence too (R1-I1): the same
        # in two runs, never a raw marker. Its body runs on past the failed
        # check, and the shells run the download.
        script = GET + "$(echo sh) <<'EOF'\n%s\ntrue\nEOF\n" % check + use
        first, second = defects(script), defects(script)
        self.assertEqual(first, second)
        found = [w for _step, w in first]
        self.assertTrue(any(ungated % "$(...)" in w for w in found), found)
        self.assertFalse(any("@@" in w for w in found), found)

    def test_2598_a_dollar_command_words_body_inside_a_substitution_is_read_first(self):
        # Inside a `$(...)`, the script reader speaks before the hand-off's
        # `Idle`: both value-form words run the body in bash 3.2.57, 5.2.21
        # and dash, and its download is reported under the stable runner name.
        inside = "hands a script to `%s` inside a command substitution"
        for script, runner in (
                ("CMD=sh\nx=$($CMD <<'EOF'\n%s\nEOF\n)\n" % PIPE, "$CMD"),
                ("x=$($(echo sh) <<'EOF'\n%s\nEOF\n)\n" % PIPE, "$(...)")):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith(inside % runner), found)
        # The literal control keeps the same sentence.
        found = defects("x=$(sh <<'EOF'\n%s\nEOF\n)\n" % PIPE)
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0][1].startswith(inside % "sh"), found)
        # An innocuous body remains CLEAN alone. Beside GET, the same script
        # sentence is `Idle` and replaces today's hand-off sentence.
        clean = "CMD=sh\nx=$($CMD <<'EOF'\necho hi\nEOF\n)\n"
        self.assertEqual([], defects(clean))
        found = defects(GET + clean)
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0][1].startswith(inside % "$CMD"), found)

    def test_2473_a_printed_pipe_into_a_dollar_word_inside_a_substitution_is_weighed(self):
        # T25-M2: `stdin_scripts` yields a printer's spelled-out text for a `$`
        # command word too, so inside a `$(...)` `substitution_script` weighs
        # it as it weighs a literal `sh`'s (the control): a download in it is
        # reported (bash 3.2.57, 5.2.21 and dash run it), and an innocuous one
        # is `Idle`, kept only beside a fetch the guard reports. T25-I1: the
        # runner is named as `flattened` names it, so a `$(...)` word reads
        # `$(...)`, never the lifted marker it was, the same in two runs, and
        # `${X:-/opt/tools/runner}` reads whole, never its basename `runner}`.
        inside = "hands a script to `%s` inside a command substitution"
        found = defects("x=$(echo '%s' | sh)\n" % PIPE)
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0][1].startswith(inside % "sh"), found)
        for script, word in (("CMD=sh\nx=$(echo '%s' | $CMD)\n" % PIPE, "$CMD"),
                             (GET + "CMD=sh\nx=$(echo hi | $CMD)\n", "$CMD"),
                             ("x=$(echo '%s' | $(echo sh))\n" % PIPE, "$(...)"),
                             (GET + "x=$(echo hi | $(echo sh))\n", "$(...)"),
                             ("X=sh\nx=$(echo '%s' | ${X:-/opt/tools/runner})\n" % PIPE,
                              "${X:-/opt/tools/runner}")):
            with self.subTest(script=script):
                first, second = defects(script), defects(script)
                self.assertEqual(first, second)
                self.assertEqual(1, len(first), first)
                self.assertTrue(first[0][1].startswith(inside % word), first)
                self.assertNotIn("@@", first[0][1])
        self.assertEqual([], defects("CMD=sh\nx=$(echo hi | $CMD)\n"))
        # A realistic shape: a version probe beside an unverified download is
        # weighed and named `$(...)`, beside the download's own reason.
        script = (GET + "chmod +x tool\n./tool\n"
                  "PYV=$(echo 'import sys; print(sys.version)' | $(command -v python3))\n")
        first, second = defects(script), defects(script)
        self.assertEqual(first, second)
        found = [w for _step, w in first]
        self.assertEqual(2, len(found), found)
        self.assertTrue(any(w.startswith(inside % "$(...)") for w in found), found)
        self.assertTrue(any("nothing verifying what arrived" in w for w in found), found)
        self.assertFalse(any("@@" in w for w in found), found)

    def test_2599_a_dollar_word_an_eval_or_dash_c_string_runs_inherits_stdin(self):
        # #2599: a `-c` or `eval` string whose one statement is a `$`
        # command word inherits VALUE_PROGRAM. Its body and hand-off are read
        # like the direct `$CMD` spelling, naming the inner word, in all three
        # shells. The literal `eval 'bash -s'` remains the must-trip control.
        def to(word):
            return ("hands a heredoc body or here-string to `%s`, a command word this guard "
                    "does not follow" % word)

        streamed = "straight to `sh`"
        found = defects("eval 'bash -s' <<'EOF'\n%s\nEOF\n" % PIPE)
        self.assertTrue(any("straight to `sh`" in w for _step, w in found), found)
        for runs in ("CMD=sh\neval \"$CMD\"", "export CMD=sh\nbash -c '$CMD'"):
            script = "%s <<'EOF'\n%s\nEOF\n" % (runs, PIPE)
            with self.subTest(script=script):
                found = [w for _step, w in defects(script)]
                self.assertEqual(2, len(found), found)
                self.assertTrue(any(streamed in w for w in found), found)
                self.assertTrue(any(w.startswith(to("$CMD")) for w in found), found)
            clean = "%s <<'EOF'\necho hi\nEOF\n" % runs
            with self.subTest(clean=clean):
                self.assertEqual([], defects(clean))
                found = [w for _step, w in defects(GET + clean)]
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0].startswith(to("$CMD")), found)
        # A dynamic `-c` word with no stdin keeps #2483's answer. With a
        # heredoc it inherits VALUE_PROGRAM and is read fail-closed, though
        # every measured shell runs nothing when P is unset.
        self.assertEqual([], defects('sh -c "$P"\n'))
        found = [w for _step, w in defects(GET + 'sh -c "$P"\n')]
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0].startswith("runs `sh -c` on `$P`"), found)
        found = [w for _step, w in defects('sh -c "$P" <<\'EOF\'\n%s\nEOF\n' % PIPE)]
        self.assertEqual(2, len(found), found)
        self.assertTrue(any(streamed in w for w in found), found)
        self.assertTrue(any(w.startswith(to("$P")) for w in found), found)
        # A `$` command word handed `-c` takes its program from the string
        # (`stdin_program` answers None), so the heredoc is that program's
        # input: #2337's `candidates` speaks, and no hand-off is said.
        found = defects(GET + "CMD=sh\n$CMD -c \"$P\" <<'EOF'\n%s\nEOF\n" % PIPE)
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0][1].startswith("runs `$CMD` with `-c`"), found)

    def test_2473_a_dollar_word_takes_a_shells_dash_s_dash_c_and_vanishing_operand(self):
        # The final review's F2: under a `$` command word the walk took a
        # foreign interpreter's rules, so a shell's `-s` or a vanishing
        # operand ended it at a FILE, and each step below read CLEAN alone and
        # beside a fetch, though bash 3.2.57, 5.2.21 and dash run its heredoc.
        # The word may be a shell, so its walk takes a shell's `-c`, `-s` and
        # vanishing-operand rules: the stream and the hand-off, as `$CMD
        # <<'EOF'` reads.
        def to(word):
            return ("hands a heredoc body or here-string to `%s`, a command word this guard "
                    "does not follow -- its body is read as shell" % word)

        def reasons(script):
            return [why for _step, why in defects(script)]

        streamed = "straight to `sh`"
        for script in ("CMD=$(echo bash)\n$CMD -s -- \"$V\" <<'EOF'\n%s\nEOF\n" % PIPE,
                       "CMD=$(echo bash)\n$CMD -s arg <<'EOF'\n%s\nEOF\n" % PIPE,
                       "CMD=$(echo bash)\n$CMD -x -s x <<'EOF'\n%s\nEOF\n" % PIPE,
                       "CMD=$(echo sh)\n$CMD $X <<'EOF'\n%s\nEOF\n" % PIPE):     # X unset
            for fetched in ("", GET):
                with self.subTest(script=fetched + script):
                    found = reasons(fetched + script)
                    self.assertEqual(2, len(found), found)
                    self.assertTrue(any(streamed in w for w in found), found)
                    self.assertTrue(any(w.startswith(to("$CMD")) for w in found), found)
        # The controls read as they did. `-c` ends the walk, its string being
        # the program: `$CMD -c "$P"` keeps #2337's candidate sentence beside a
        # fetch and says no hand-off, and a `-c` with no string, which all
        # three shells refuse (rc 2), reads CLEAN. A literal FILE ends it too,
        # `python3 $S` keeps its FILE reading, `$PYTHON -` its hand-off, and
        # the literal `bash -s -- "$V"` is the must-trip control.
        script = GET + "CMD=$(echo sh)\n$CMD -c \"$P\" <<'EOF'\n%s\nEOF\n" % PIPE
        with self.subTest(script=script):
            found = reasons(script)
            self.assertEqual(1, len(found), found)
            self.assertTrue(found[0].startswith("runs `$CMD` with `-c`"), found)
        for script in ("CMD=$(echo sh)\n$CMD -c \"$P\" <<'EOF'\n%s\nEOF\n" % PIPE,
                       "CMD=$(echo bash)\n$CMD -c <<'EOF'\n%s\nEOF\n" % PIPE,
                       "CMD=$(echo sh)\n$CMD -- x.sh <<'EOF'\n%s\nEOF\n" % PIPE,
                       "CMD=$(echo sh)\n$CMD file <<'EOF'\n%s\nEOF\n" % PIPE,
                       "python3 $S <<'EOF'\n%s\nEOF\n" % PIPE,
                       "PYTHON=$(echo python3)\n$PYTHON - <<'EOF'\nprint(1)\nEOF\n"):
            with self.subTest(script=script):
                self.assertEqual([], reasons(script))
        script = "bash -s -- \"$V\" <<'EOF'\n%s\nEOF\n" % PIPE
        with self.subTest(script=script):
            found = reasons(script)
            self.assertEqual(1, len(found), found)
            self.assertIn(streamed, found[0])
        # The price, named in `stdin_program`'s docstring: the walk cannot tell
        # a quoted empty value from one the shell drops, nor a foreign
        # interpreter's `-s` from a shell's. `$CMD "$X"` with `X` empty runs
        # nothing (rc 127, 127 and 2: the shell is handed an empty file name),
        # and python runs `file.py`, never the body; yet each reads the
        # heredoc as `$CMD`'s program -- loud where the body spells a
        # download, its hand-off `Idle` beside a reported fetch otherwise.
        script = "CMD=$(echo sh)\n$CMD \"$X\" <<'EOF'\n%s\nEOF\n" % PIPE
        with self.subTest(script=script):
            found = reasons(script)
            self.assertEqual(2, len(found), found)
            self.assertTrue(any(streamed in w for w in found), found)
        python = "PYTHON=$(echo python3)\n$PYTHON -s file.py <<'EOF'\nprint(1)\nEOF\n"
        with self.subTest(script=python):
            self.assertEqual([], reasons(python))
        with self.subTest(script=GET + python):
            found = reasons(GET + python)
            self.assertEqual(1, len(found), found)
            self.assertTrue(found[0].startswith(to("$PYTHON")), found)
        # The same price where an interpreter's own option takes a value
        # spelled `$` (the Task 27 review's L2): node runs its `-e` string and
        # python looks for the module (rc 0 and rc 1 in all three shells),
        # neither reading the heredoc, yet the walk reads past `"$CODE"` and
        # `"$MOD"` as past a vanishing operand -- the stream and the hand-off,
        # alone and beside a fetch. Their literal twins end the walk at that
        # word, the program being elsewhere: CLEAN.
        for word, step in (("$NODE", "NODE=$(echo /usr/local/bin/node)\n$NODE -e \"$CODE\""),
                           ("$PYTHON", "PYTHON=$(echo python3)\n$PYTHON -m \"$MOD\"")):
            for fetched in ("", GET):
                script = "%s%s <<'EOF'\n%s\nEOF\n" % (fetched, step, PIPE)
                with self.subTest(script=script):
                    found = reasons(script)
                    self.assertEqual(2, len(found), found)
                    self.assertTrue(any(streamed in w for w in found), found)
                    self.assertTrue(any(w.startswith(to(word)) for w in found), found)
        for step in ("node -e \"$CODE\"", "python3 -m mod"):
            for fetched in ("", GET):
                script = "%s%s <<'EOF'\n%s\nEOF\n" % (fetched, step, PIPE)
                with self.subTest(script=script):
                    self.assertEqual([], reasons(script))

    def test_2473_a_dollar_word_counts_option_values_as_a_shell_does(self):
        # Fix round 2: under a `$` command word the walk still counted option
        # values a foreign interpreter's way, one where the option word ENDS
        # in `o` or `O`, so `-oe` took none and `pipefail` ended the walk as a
        # FILE: `CMD=bash; $CMD -oe pipefail <<'EOF'` read CLEAN alone and
        # beside a fetch, though bash 3.2.57 and 5.2.21 run its heredoc (dash
        # refuses `-o pipefail`, rc 2). The word may be a shell, so it owes a
        # value for each `o` or `O`, as a shell's does (#2344): the stream and
        # the hand-off. `-o pipefail` and `-O extglob`, which end in their
        # letter, read as they did.
        def to(word):
            return ("hands a heredoc body or here-string to `%s`, a command word this guard "
                    "does not follow -- its body is read as shell" % word)

        def reasons(script):
            return [why for _step, why in defects(script)]

        streamed = "straight to `sh`"
        for script in ("CMD=$(echo bash)\n$CMD -oe pipefail <<'EOF'\n%s\nEOF\n" % PIPE,
                       "CMD=$(echo sh)\n$CMD -o pipefail <<'EOF'\n%s\nEOF\n" % PIPE,
                       "CMD=$(echo bash)\n$CMD -O extglob <<'EOF'\n%s\nEOF\n" % PIPE):
            for fetched in ("", GET):
                with self.subTest(script=fetched + script):
                    found = reasons(fetched + script)
                    self.assertEqual(2, len(found), found)
                    self.assertTrue(any(streamed in w for w in found), found)
                    self.assertTrue(any(w.startswith(to("$CMD")) for w in found), found)
        # The price, named in `stdin_program`'s docstring: a foreign
        # interpreter's option word owes a value for an `o` or `O` before its
        # end too, so `$PYTHON -Ou file.py` reads its heredoc as `$PYTHON -O
        # file.py` does, though python runs `file.py` and the body is its data
        # (rc 2 here, in all three shells: there is no `file.py`) -- loud where
        # the body spells a download, its hand-off `Idle` beside a reported
        # fetch otherwise. A literal `python3 -Ou file.py` keeps its FILE
        # reading, fetch and download body or not.
        for flags in ("-Ou", "-O"):
            python = "PYTHON=$(echo python3)\n$PYTHON %s file.py <<'EOF'\nprint(1)\nEOF\n" % flags
            with self.subTest(script=python):
                self.assertEqual([], reasons(python))
            with self.subTest(script=GET + python):
                found = reasons(GET + python)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0].startswith(to("$PYTHON")), found)
        script = "PYTHON=$(echo python3)\n$PYTHON -Ou file.py <<'EOF'\n%s\nEOF\n" % PIPE
        with self.subTest(script=script):
            found = reasons(script)
            self.assertEqual(2, len(found), found)
            self.assertTrue(any(streamed in w for w in found), found)
        script = GET + "python3 -Ou file.py <<'EOF'\n%s\nEOF\n" % PIPE
        with self.subTest(script=script):
            self.assertEqual([], reasons(script))
        # Fix round 3 (the final review's F5): past an option owed a value, a
        # stdin operand ends the walk, but for a literal shell's. python's `-O`
        # takes no value, so the `-` in `$PYTHON -Ou - file.py` and in the
        # literal `python3 -O - file.py` is the program, whose `os.system`
        # download ran in all three shells: beside a fetch each reads its
        # hand-off, the foreign one where `main` read CLEAN; alone each is
        # option b's price, CLEAN. `$PYTHON -OO -` reads as it did.
        program = "import os\nos.system('%s')" % PIPE
        foreign = ("hands a heredoc body or here-string to `python3` as the program to run, "
                   "which this guard does not parse")
        for step, why in (("PYTHON=$(echo python3)\n$PYTHON -Ou - file.py", to("$PYTHON")),
                          ("python3 -O - file.py", foreign),
                          ("PYTHON=$(echo python3)\n$PYTHON -OO -", to("$PYTHON"))):
            script = "%s <<'EOF'\n%s\nEOF\n" % (step, program)
            with self.subTest(script=GET + script):
                found = reasons(GET + script)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0].startswith(why), found)
            if "-OO" not in step:
                with self.subTest(script=script):
                    self.assertEqual([], reasons(script))
        # A literal shell's `-o` does take the `-`, as an option name it
        # refuses (bash and dash exit 2): `bash -o - x.sh` reads CLEAN as on
        # `main`, and `bash -o pipefail -`, which both bashes run, the stream.
        # Under a `$` word, which may be python, the walk answers at the `-`,
        # fail-closed: `$CMD -o -` reads as before and `$CMD -oe - x.sh` is
        # read too, though a shell there runs nothing.
        script = "bash -o - x.sh <<'EOF'\n%s\nEOF\n" % PIPE
        with self.subTest(script=script):
            self.assertEqual([], reasons(script))
        script = "bash -o pipefail - <<'EOF'\n%s\nEOF\n" % PIPE
        with self.subTest(script=script):
            found = reasons(script)
            self.assertEqual(1, len(found), found)
            self.assertIn(streamed, found[0])
        for script in ("CMD=$(echo bash)\n$CMD -o - <<'EOF'\n%s\nEOF\n" % PIPE,
                       "CMD=$(echo bash)\n$CMD -oe - x.sh <<'EOF'\n%s\nEOF\n" % PIPE):
            with self.subTest(script=script):
                found = reasons(script)
                self.assertEqual(2, len(found), found)
                self.assertTrue(any(streamed in w for w in found), found)
                self.assertTrue(any(w.startswith(to("$CMD")) for w in found), found)

    # Round 1 of the review and its fix round: behind a string no check in a stdin program counts
    # (`workflow_programs.Stdin`). Each step hands a shell a body holding the check of `tool`
    # (`stdin_step`), run by bash 5.2.21 and 3.2.57 under `-e` and `-eo pipefail` and by dash under
    # `-e`. A method that pins a step reported behind a string also asserts its LITERAL twin CLEAN
    # -- `bash -s`, `sh` or `bash -e -s` at the step's own level, which every shell stops at the
    # check, as `main` credits it: the must-trip control.
    ECHOED = CHECK + "\necho done"
    USED = CHECK + "\n" + USE.rstrip("\n")
    # `_DYNAMIC`'s sentence for an `eval` word all substitution (#2483, #2486).
    EVAL_ON = "runs `eval` on `$(...)`"

    def assert_reported(self, rows):
        """Each (step, how many defects it has, what one of them says[, how another begins])."""
        for script, count, said, *begins in rows:
            with self.subTest(script=script):
                found = [why for _step, why in defects(script)]
                self.assertEqual(count, len(found), found)
                self.assertTrue(any(said in why for why in found), found)
                for head in begins:
                    self.assertTrue(any(why.startswith(head) for why in found), found)

    def assert_clean(self, scripts):
        for script in scripts:
            with self.subTest(script=script):
                self.assertEqual([], defects(script))

    def test_2500_a_check_the_inner_shell_carries_on_past_is_reported(self):
        # The review's blocker: the inner shell has no `-e`, so every shell
        # carries on past the failed check and runs the download (rc 0).
        runners = (("eval 'bash -s'", "eval"), ("eval bash -s", "eval"), ("eval 'sh'", "eval"),
                   ("bash -ec 'sh'", "bash"))
        self.assert_reported((stdin_step(runner, body), count, UNGATED % holder)
                             for runner, holder in runners
                             for body, count in ((self.ECHOED, 1), (self.USED, 1),
                                                 (GET + self.USED, 2)))
        # The same in a here-string and in an `echo` piped in: every shell runs
        # the download, bar dash at the here-string, which it refuses (rc 2).
        self.assert_reported([
            (stdin_step("eval 'bash -s'", self.ECHOED, "here-string"), 1, UNGATED % "eval"),
            (stdin_step("eval 'bash -s'", self.ECHOED, "piped"), 1, UNGATED % "eval"),
            (stdin_step("bash -ec 'sh'", self.ECHOED, "piped"), 1, UNGATED % "bash"),
            (stdin_step("eval 'sh'", self.USED, "piped"), 1, UNGATED % "eval")])
        # The check alone, or under the inner shell's own `-e`: every shell stops at it (rc 1;
        # dash refuses a here-string, rc 2), reported deliberately, as the next method says.
        self.assert_reported([(stdin_step(runner), 1, UNGATED % holder)
                              for runner, holder in runners] + [
            (stdin_step("eval 'bash -s'", CHECK, "here-string"), 1, UNGATED % "eval"),
            (stdin_step("eval 'bash -s'", CHECK, "piped"), 1, UNGATED % "eval"),
            (stdin_step("bash -ec 'sh'", CHECK, "piped"), 1, UNGATED % "bash"),
            (stdin_step("eval 'sh'", CHECK, "piped"), 1, UNGATED % "eval"),
            (stdin_step("eval 'bash -e -s'", self.ECHOED), 1, UNGATED % "eval"),
            (stdin_step("bash -ec 'sh -e'", self.ECHOED), 1, UNGATED % "bash")])
        # The controls: their literal twins, CLEAN as on `main`.
        self.assert_clean([stdin_step("bash -s"), stdin_step("sh"),
                           stdin_step("bash -s", CHECK, "here-string"),
                           stdin_step("bash -s", CHECK, "piped"), stdin_step("sh", CHECK, "piped"),
                           stdin_step("bash -e -s", self.ECHOED)])

    def test_2500_a_check_alone_behind_a_string_is_reported_deliberately(self):
        # Reported DELIBERATELY: every shell stops each step at the check (rc 1; dash refuses a
        # here-string, rc 2) and `main` reports each, but class 3 or class 4 makes a credit unsafe.
        self.assert_reported([
            # class 3 (inside `( ... ) || true`) and class 4 (after `bash() { :; }`)
            (stdin_step("eval 'bash -s'"), 1, UNGATED % "eval"),
            # class 4 (after `bash() { :; }`)
            (stdin_step("eval 'bash -s'", CHECK, "here-string"), 1, UNGATED % "eval"),
            # class 4 (after `bash() { :; }`)
            (stdin_step("eval 'bash -s'", CHECK, "piped"), 1, UNGATED % "eval"),
            # class 3 (inside `( ... ) || true`) and class 4 (after `bash() { :; }`)
            (stdin_step("eval bash -s"), 1, UNGATED % "eval"),
            # class 4 (after `bash() { :; }`)
            (stdin_step("eval bash -s", CHECK, "here-string"), 1, UNGATED % "eval"),
            # class 4 (after `bash() { :; }`)
            (stdin_step("eval bash -s", CHECK, "piped"), 1, UNGATED % "eval"),
            # class 3 (inside `( ... ) || true`) and class 4 (after `sh() { :; }`)
            (stdin_step("eval 'sh'"), 1, UNGATED % "eval"),
            # class 4 (after `sh() { :; }`)
            (stdin_step("eval 'sh'", CHECK, "here-string"), 1, UNGATED % "eval"),
            # class 4 (after `sh() { :; }`)
            (stdin_step("eval 'sh'", CHECK, "piped"), 1, UNGATED % "eval"),
            # class 3 (inside `( ... ) || true`) and class 4 (after `bash() { :; }`)
            (stdin_step("bash -c 'sh'"), 1, UNGATED % "bash"),
            # class 4 (after `bash() { :; }`)
            (stdin_step("bash -c 'sh'", CHECK, "here-string"), 1, UNGATED % "bash"),
            # class 4 (after `bash() { :; }`)
            (stdin_step("bash -c 'sh'", CHECK, "piped"), 1, UNGATED % "bash"),
            # class 3 (inside `( ... ) || true`) and class 4 (after `bash() { :; }`)
            (stdin_step("bash -ec 'sh'"), 1, UNGATED % "bash"),
            # class 4 (after `bash() { :; }`)
            (stdin_step("bash -ec 'sh'", CHECK, "here-string"), 1, UNGATED % "bash"),
            # class 4 (after `bash() { :; }`)
            (stdin_step("bash -ec 'sh'", CHECK, "piped"), 1, UNGATED % "bash")])
        # The map's proof: each twin runs the download in every shell (rc 0; dash refuses a
        # here-string, rc 2). The other three twins are pinned in the Class 3 and Class 4 methods.
        self.assert_reported([
            (stdin_step("eval 'bash -s'", CHECK, "here-string", pre="bash() { :; }\n"), 1,
             UNGATED % "eval"),
            (stdin_step("eval bash -s", CHECK, "piped", pre="bash() { :; }\n"), 1,
             UNGATED % "eval"),
            (stdin_step("bash -ec 'sh'", pre="bash() { :; }\n"), 1, UNGATED % "bash"),
            (stdin_step("( eval bash -s", end=") || true\n"), 1, UNGATED % "eval"),
            (stdin_step("( eval 'sh'", end=") || true\n"), 1, UNGATED % "eval"),
            (stdin_step("( bash -c 'sh'", end=") || true\n"), 1, UNGATED % "bash"),
            (stdin_step("( bash -ec 'sh'", end=") || true\n"), 1, UNGATED % "bash")])
        # The controls: the literal twins of the fifteen, CLEAN as on `main`.
        self.assert_clean(stdin_step(runner, CHECK, form) for runner in ("bash -s", "sh")
                          for form in ("heredoc", "here-string", "piped"))

    def test_2500_what_stands_around_the_inner_command_voids_its_check(self):
        # `!` makes the check's failure success, `&`, `<` and `<&-` keep the body from the inner
        # shell, past `sudo` or `X=1` it runs on: rc 0 in every shell, bar bash under `SHELLOPTS`.
        rows = [(stdin_step(runner, body), 1, UNGATED % name) for runner, body, name in (
            ("eval '! bash -s'", CHECK, "eval"), ("bash -c '! sh'", CHECK, "bash"),
            ("eval '! bash -e -s'", CHECK, "eval"), ("eval 'bash -s &'", CHECK, "eval"),
            ("eval 'bash -s < /dev/null'", CHECK, "eval"), ("eval 'bash -s <&-'", CHECK, "eval"),
            ("eval 'SHELLOPTS=noexec bash -s'", CHECK, "eval"),
            ("eval 'sudo bash -s'", self.ECHOED, "eval"),
            ("eval 'X=1 bash -s'", self.ECHOED, "eval"),
            ("eval 'bash -s' '</dev/null'", CHECK, "eval"))]
        # Alone, in a subshell or with another descriptor redirected, every shell
        # stops at the check (rc 1): reported all the same.
        self.assert_reported(rows + [(stdin_step(runner, body), 1, UNGATED % name)
                                     for runner, body, name in (
            ("eval 'bash -s'", CHECK, "eval"), ("bash -c 'sh'", CHECK, "bash"),
            ("eval '(bash -s)'", CHECK, "eval"), ("eval 'bash -s 2>/dev/null'", CHECK, "eval"),
            ("eval 'bash -e -s'", self.ECHOED, "eval"))])
        self.assert_clean([stdin_step("bash -s"), stdin_step("sh"),
                           stdin_step("bash -e -s", self.ECHOED)])

    def test_2500_an_inner_option_that_keeps_the_program_from_running_voids_its_check(self):
        # `-n` and `-o noexec` run nothing, `-t` one command, `-s -c true` the
        # string, `--version` no program: every shell runs the download (rc 0).
        rows = [(stdin_step(runner, body), 1, UNGATED % name) for runner, body, name in (
            ("eval 'bash -n -s'", CHECK, "eval"), ("bash -c 'sh -n'", CHECK, "bash"),
            ("eval 'bash -s -c true'", CHECK, "eval"), ("eval 'bash --version'", CHECK, "eval"),
            ("eval 'bash -o noexec -s'", CHECK, "eval"), ("eval bash -n -s", CHECK, "eval"),
            ("eval 'bash -t -s'", "echo start\n" + CHECK, "eval"))]
        # With no option, `-x` or `-e`, every shell stops at the check that ends
        # the body or runs under that `-e` (rc 1): reported all the same.
        self.assert_reported(rows + [(stdin_step(runner, body), 1, UNGATED % name)
                                     for runner, body, name in (
            ("eval 'bash -s'", CHECK, "eval"), ("eval 'bash -x -s'", CHECK, "eval"),
            ("eval 'bash -eu -s'", self.ECHOED, "eval"), ("bash -c 'sh -e'", self.ECHOED, "bash"),
            ("eval 'bash -s'", "echo start\n" + CHECK, "eval"))])
        self.assert_clean([stdin_step("bash -s"), stdin_step("bash -e -s", self.ECHOED),
                           stdin_step("bash -s", "echo start\n" + CHECK)])

    def test_2500_a_word_the_join_drops_or_bash_expands_voids_its_check(self):
        # A `$(...)`, backquote or `$N` that comes to `-n` hands the inner shell
        # that option, so it runs nothing: every shell runs the download (rc 0;
        # b5 b3 dash gh: FR FR FR FR for each substitution row). One that is a
        # printer is read as the `-n` it prints (#2487); piped on through `cat`
        # it is no printer. Either is a program `eval` runs that is all
        # expansion, whose `Idle` sentence stands beside the download too
        # (#2483, #2486) -- beside the printer's read since fix round 1's
        # catch-all (main / base / 19423415: 2 / 2 / 1 rows).
        self.assert_reported([
            (stdin_step("eval 'bash -s' $(printf %s -n)"), 2, UNGATED % "eval", self.EVAL_ON),
            (stdin_step("eval 'bash -s' \"$(printf %s -n)\""), 2, UNGATED % "eval",
             self.EVAL_ON),
            (stdin_step("eval 'bash -s' `printf %s -n`"), 2, UNGATED % "eval", self.EVAL_ON),
            (stdin_step("eval 'bash -s' $(printf %s -n | cat)"), 2, UNGATED % "eval",
             self.EVAL_ON),
            (stdin_step("eval 'bash -s' $N", pre="N=-n\n"), 2, UNGATED % "eval"),
            (stdin_step('eval "bash -s $N"', pre="N=-n\n"), 1, UNGATED % "eval"),
            (stdin_step('bash -c "sh $N"', pre="N=-n\n"), 1, UNGATED % "bash"),
            # With no such word, or one a comment in the string swallows, every
            # shell stops at the check (rc 1): reported all the same.
            (stdin_step("eval 'bash -s'"), 1, UNGATED % "eval"),
            (stdin_step("eval 'bash -s #' -n"), 1, UNGATED % "eval"),
            (stdin_step("bash -c 'sh'"), 1, UNGATED % "bash")])
        self.assert_clean([stdin_step("bash -s"), stdin_step("sh")])

    def test_2485_no_check_past_a_word_that_may_name_a_file_counts(self):
        # A word that may vanish may name a FILE (`sh /dev/null` reads no body),
        # and `X=-s` hands `sh` no `-e`: every shell runs the download (rc 0).
        self.assert_reported([
            (stdin_step("sh $X", pre="X=/dev/null\n"), 1, UNGATED % "sh"),
            (stdin_step("sh ${X:-/dev/null}"), 1, UNGATED % "sh"),
            (stdin_step('sh "$@"', pre="set -- /dev/null\n"), 1, UNGATED % "sh"),
            (stdin_step("bash $(echo /dev/null)"), 2, UNGATED % "bash"),
            (stdin_step("sh $X -s", pre="X=/dev/null\n"), 2, UNGATED % "sh"),
            (stdin_step("bash -c 'sh $X'", pre="export X=/dev/null\n"), 1, UNGATED % "bash"),
            (stdin_step("eval 'sh $X'", self.ECHOED, pre="X=-s\n"), 1, UNGATED % "eval")])
        # Reported DELIBERATELY: past `X=-s` every shell stops at the check (rc 1;
        # dash refuses the here-string, rc 2), but `X=/dev/null` spells the same.
        self.assert_reported((stdin_step("sh $X", CHECK, form, pre="X=-s\n"), 1, UNGATED % "sh")
                             for form in ("heredoc", "here-string", "piped"))
        # Behind a string with no value in it every shell stops at the check
        # (rc 1), reported all the same; the literal shells read CLEAN.
        self.assert_reported([(stdin_step("bash -c 'sh'"), 1, UNGATED % "bash"),
                              (stdin_step("eval 'sh'"), 1, UNGATED % "eval")])
        self.assert_clean([stdin_step("sh"), stdin_step("bash -s"),
                           stdin_step("bash -e -s", self.ECHOED)])

    def test_2500_the_holders_own_command_line_voids_its_check(self):
        # A holder given `-n`, `--version` or `-o noexec` runs nothing of its string, and `-c -e`'s
        # `-e` is not `sh`'s: rc 0 in every shell, bar bash refusing `SHELLOPTS=noexec` (rc 1).
        self.assert_reported([(stdin_step(runner), 1, UNGATED % name) for runner, name in (
            ("bash -nc 'sh'", "bash"), ("bash -n -c 'sh'", "bash"),
            ("bash --version -c 'sh'", "bash"), ("SHELLOPTS=noexec bash -c 'sh'", "bash"),
            ("bash -o noexec -c 'sh'", "bash"), ("sh -c 'bash -nc \"sh\"'", "sh"))]
            + [(stdin_step("bash -c -e 'sh'", self.ECHOED), 1, UNGATED % "bash")])
        # A holder of `-c`, `-e`, `-u` and `-x` alone, nested or not: every shell
        # stops at the check that is the whole body (rc 1), reported all the same.
        self.assert_reported([(stdin_step(runner), 1, UNGATED % name) for runner, name in (
            ("bash -c 'sh'", "bash"), ("bash -euxc 'sh'", "bash"), ("bash -c -e 'sh'", "bash"),
            ("sh -c 'bash -c \"sh\"'", "sh"))])
        self.assert_clean([stdin_step("sh"), stdin_step("bash -s"),
                           stdin_step("bash -e -s", self.ECHOED)])

    def test_2500_no_check_behind_a_string_counts_under_the_inner_shells_own_e(self):
        # Every shell stops at the check under the inner shell's `-e` or a `set -e`, or ending
        # the body (rc 1), and each step is reported: behind a string no check counts.
        self.assert_reported([(script, 1, UNGATED % name) for script, name in (
            (stdin_step("eval 'bash -e -s'", self.ECHOED), "eval"),
            (stdin_step("bash -c 'sh -e'", self.ECHOED), "bash"),
            (stdin_step("bash -ec 'sh -e'", self.ECHOED), "bash"),
            (stdin_step("eval 'bash -x -s'"), "eval"),
            (stdin_step("eval 'bash -eu -s'", self.ECHOED), "eval"),
            (stdin_step("eval '(bash -s)'"), "eval"),
            (stdin_step("eval '(bash -e -s)'", self.ECHOED), "eval"),
            (stdin_step("sh -c 'bash -c \"sh\"'"), "sh"),
            (stdin_step("eval 'eval \"bash -s\"'"), "eval"),
            (stdin_step("eval 'eval \"bash -es\"'", self.ECHOED), "eval"),
            (stdin_step("sh -c 'bash -c \"sh -e\"'", self.ECHOED), "sh"),
            (stdin_step("bash -euxc 'sh'"), "bash"), (stdin_step("bash -c -e 'sh'"), "bash"),
            (stdin_step("bash -c 'sh' -n"), "bash"),
            (stdin_step("{ eval 'bash -s'", end="}\n"), "eval"),
            (stdin_step("eval 'bash -s #' -n"), "eval"),
            (stdin_step("eval 'bash -s'", "echo start\n" + CHECK), "eval"),
            (stdin_step("eval 'bash -s'", "set -e\n" + self.ECHOED), "eval"),
            (stdin_step("eval 'bash -s 2>/dev/null'"), "eval"))])
        self.assert_clean([stdin_step("bash -e -s", self.ECHOED), stdin_step("bash -s"),
                           stdin_step("sh"), stdin_step("bash -s", "echo start\n" + CHECK),
                           stdin_step("bash -s", "set -e\n" + self.ECHOED)])

    def test_2500_the_prices_of_no_check_counting_behind_a_string_or_a_value(self):
        # Reported though no shell runs the download: each stops at the check (rc 1; dash's `time`
        # finds no program `eval`, 127) or, behind `&` or `<`, runs nothing of the body (no fetch).
        rows = [(stdin_step(runner, body), 1, UNGATED % name) for runner, body, name in (
            ("eval 'exec bash -s'", CHECK, "eval"), ("eval 'env bash -s'", CHECK, "eval"),
            ("eval 'time bash -s'", CHECK, "eval"), ("eval 'sudo bash -s'", CHECK, "eval"),
            ("eval 'X=1 bash -s'", CHECK, "eval"), ("eval 'bash --norc -s'", CHECK, "eval"),
            ("eval 'bash -o errexit -s'", self.ECHOED, "eval"),
            ("eval 'bash -s arg'", CHECK, "eval"),
            ("eval 'bash -s -- arg'", CHECK, "eval"), ("eval '! bash -s'", self.ECHOED, "eval"),
            ("bash +e -c 'sh'", CHECK, "bash"), ("command eval 'bash -s'", CHECK, "eval"),
            ("time eval 'bash -s'", CHECK, "eval"), ("env bash -c 'sh'", CHECK, "bash"),
            ("sudo bash -c 'sh'", CHECK, "bash"), ("X=1 eval 'bash -s'", CHECK, "eval"),
            ("sh $X", CHECK, "sh"),
            ("eval 'bash -s'", CHECK, "eval"), ("eval '(bash -s)'", CHECK, "eval"),
            ("eval 'bash -e -s'", self.ECHOED, "eval"), ("bash -c 'sh'", CHECK, "bash"),
            ("bash -euxc 'sh'", CHECK, "bash"), ("eval " * 3 + "bash -s", CHECK, "eval"),
            ("eval 'bash -s'", CHECK + " || exit 1\necho done", "eval"))]
        self.assert_reported(rows + [
            (stdin_step("sh $X", pre="X=-e\n"), 1, UNGATED % "sh"),
            (stdin_step("bash $(true)"), 2, UNGATED % "bash"),
            (stdin_step("eval 'bash -s &'", GET + self.USED, fetched=False), 1, UNGATED % "eval"),
            (stdin_step("eval 'bash -s < /dev/null'", GET + self.USED, fetched=False), 1,
             UNGATED % "eval"),
            (stdin_step("eval 'bash -s'", pre="if true; then\n", end="fi\n"), 1, UNGATED % "eval"),
            # A function header: each shell stops at the check (rc 1), and `main` reports it too.
            (stdin_step("f() { eval 'bash -s'", end="}\nf\n"), 1, UNGATED % "eval"),
            (stdin_step("eval " * 70 + "bash -s"), 1, UNGATED % "eval")])
        self.assert_clean([stdin_step("sh"), stdin_step("bash -s"),
                           stdin_step("bash -e -s", self.ECHOED)])
        # Its literal twin: every shell stops at the check (rc 1); `main` reads it CLEAN, as here.
        self.assert_clean([stdin_step("f() { bash -s", end="}\nf\n")])

    def test_2500_a_literal_stdin_shell_reads_as_on_main(self):
        # Every shell stops at a check that ends the body or runs under its `-e`
        # (rc 1), and runs the download past one that does neither (rc 0).
        self.assert_clean([stdin_step("bash -s"), stdin_step("sh"),
                           stdin_step("bash -e -s", self.ECHOED)])
        self.assert_reported([
            (stdin_step("bash -s", self.ECHOED), 1, RUNS_ON % "bash"),
            (stdin_step("bash -s", GET + self.USED, fetched=False), 1, RUNS_ON % "bash")])

    def test_2473_a_dollar_word_and_builtin_eval_read_as_before(self):
        # A `$` word credits nothing (`CMD=$(echo sh)` stops at the check, rc 1; `CMD=$(echo true)`
        # runs the download); `builtin eval`'s body is unread, as on `main` (bash: rc 1; dash: 127).
        for command in ("sh", "true"):
            script = stdin_step("$CMD", pre="CMD=$(echo %s)\n" % command)
            with self.subTest(script=script):
                found = [why for _step, why in defects(script)]
                self.assertEqual(2, len(found), found)
                self.assertTrue(any(UNGATED % "$CMD" in why for why in found), found)
                self.assertTrue(any(why.startswith("hands a heredoc body or here-string to `$CMD`")
                                    for why in found), found)
        self.assert_reported([
            (stdin_step("builtin eval 'bash -s'"), 1, "with nothing verifying what arrived")])
        self.assert_clean([stdin_step("bash -s")])

    def test_2500_mains_own_gaps_read_as_on_main(self):
        # `main`'s gaps, filed under #2331: CLEAN, as on `main`, though every shell runs the
        # download (rc 0), bar bash under `SHELLOPTS=noexec`, a variable it refuses (rc 1).
        self.assert_clean([stdin_step("bash -n -s"), stdin_step("bash -o noexec -s"),
                           stdin_step("bash -t -s", "echo start\n" + CHECK),
                           stdin_step("bash --version"), stdin_step("bash -s -c true"),
                           stdin_step("SHELLOPTS=noexec bash -s"),
                           stdin_step("sh", pre="sh() { :; }\n")])

    def test_2500_a_name_made_to_run_something_else_is_reported_behind_a_string(self):
        # Class 4: a function (`eval() { :; }` too), an alias, a fake `sh` first on `PATH`, a
        # sourced file or `BASH_ENV` runs in the shell's place, and nothing reads the body.
        def looked_up(pre, runner=None):
            step = CHECK + "\n" if runner is None else "%s <<'EOF'\n%s\nEOF\n" % (runner, CHECK)
            return pre + GET + step + "chmod +x tool; ./tool\n"
        fake = "mkdir -p fake; ln -s /usr/bin/true fake/%s; PATH=$PWD/fake:$PATH\n"
        # Every shell runs the download (rc 0) but where `eval() { :; }` is refused (dash, rc 2)
        # or an alias unexpanded (bash bar `expand_aliases`, rc 1; dash has no `shopt`, 127).
        self.assert_reported([
            (stdin_step("eval 'sh'", pre="sh() { :; }\n"), 1, UNGATED % "eval"),
            (stdin_step("bash -c 'sh'", pre="bash() { :; }\n"), 1, UNGATED % "bash"),
            # A word all substitution is a program `eval` runs, unread: its `Idle` sentence
            # stands beside the download too (#2486) -- piped on through `cat`, and since fix
            # round 1's catch-all beside one printer read as the function it prints (#2487;
            # main / base / 19423415: 2 / 2 / 1 rows). b5 b3 dash gh: FR FR FR FR for both.
            (looked_up("eval \"$(printf 'sh() { :; }' | cat)\"\n", "eval 'sh'"), 2,
             UNGATED % "eval", self.EVAL_ON),
            (looked_up("eval \"$(printf 'sh() { :; }')\"\n", "eval 'sh'"), 2, UNGATED % "eval",
             self.EVAL_ON)] + [
            (looked_up(pre, runner), 1, UNGATED % runner.split()[0]) for pre, runner in (
                ("sh() { :; }\n", "eval 'sh'"), ("bash() { :; }\n", "bash -c 'sh'"),
                ("eval() { :; }\n", "eval 'bash -s'"), ("alias sh=:\n", "eval 'sh'"),
                ("shopt -s expand_aliases\nalias sh=:\n", "eval 'sh'"),
                (fake % "sh", "eval 'sh'"),
                ("printf 'sh() { :; }\\n' > defs.sh\n. ./defs.sh\n", "eval 'sh'"),
                ("printf 'sh() { :; }\\n' > rc.sh\nexport BASH_ENV=$PWD/rc.sh\n", "bash -c 'sh'"))])
        # `main`'s own gap, filed under #2331: the literal twins, and the step's own `sha256sum`
        # made to run something else, read CLEAN though a shell runs the download (an alias: dash).
        self.assert_clean([looked_up(pre, runner) for pre, runner in (
            ("sh() { :; }\n", "sh"), ("alias sh=:\n", "sh"), ("bash() { :; }\n", "bash -s"),
            (fake % "sh", "sh"), ("sha256sum(){ :; }\n", None), (fake % "sha256sum", None))])
        self.assert_clean([stdin_step("sh"), stdin_step("bash -s")])

    def test_2500_a_value_for_the_inner_commands_stdin_is_reported(self):
        # Class 1: the inner shell reads its stdin from a value, here `/dev/null`,
        # not the body: every shell runs the download (rc 0).
        self.assert_reported([
            (stdin_step("eval 'bash -s < $F'", pre="F=/dev/null\n"), 1, UNGATED % "eval"),
            (stdin_step("bash -c 'sh < $0' /dev/null"), 1, UNGATED % "bash"),
            (stdin_step("eval '(bash -s) < $F'", pre="F=/dev/null\n"), 1, UNGATED % "eval"),
            (stdin_step("bash -c 'sh -e < $F'", self.ECHOED, pre="export F=/dev/null\n"), 1,
             UNGATED % "bash")])
        self.assert_clean([stdin_step("bash -s"), stdin_step("bash -e -s", self.ECHOED)])

    def test_2500_a_word_ahead_of_the_holders_dash_c_or_a_lone_dash_is_reported(self):
        # Class 2: `-n` or a FILE ahead of the holder's `-c` keeps its string from
        # running, and `bash - /dev/null` runs that FILE: every shell runs the download.
        self.assert_reported([
            (stdin_step("bash $X -c 'sh'", pre="X=-n\n"), 2, UNGATED % "bash"),
            (stdin_step("bash /dev/null -c 'sh'"), 1, UNGATED % "bash"),
            (stdin_step("bash x.sh -ec 'sh -e'", self.ECHOED, pre=": > x.sh\n"), 1,
             UNGATED % "bash"),
            (stdin_step("eval 'bash - /dev/null'"), 1, UNGATED % "eval")])
        # `main`'s gap, filed under #2331: the literal `bash - /dev/null` reads CLEAN.
        self.assert_clean([stdin_step("bash - /dev/null")])
        self.assert_clean([stdin_step("bash -s"), stdin_step("bash -e -s", self.ECHOED)])

    def test_2500_mains_literal_shell_gaps_are_reported_behind_a_string(self):
        # Class 3: each string row is reported. #2421 also closes the three function
        # literal gaps; the remaining literal twins stay filed under #2331.
        reported, fixed, group_handoffs, gaps = [], [], [], []
        for string, literal, body, pre, end, function_gap in (
                # `|| true` swallows the subshell's failure (rc 0, every shell)
                ("( eval 'bash -s'", "( bash -s", CHECK, "", ") || true\n", False),
                # a function called under `|| true`: `-e` off in it, its failure swallowed (rc 0)
                ("eval 'bash -e -s'", "bash -e -s",
                 "f() { %s; echo inner; }\nf || true\necho done" % CHECK, "", "", True),
                ("f() { eval 'bash -s'", "f() { bash -s", CHECK, "", "}\nf || true\n",
                 True),
                # a function never called runs no check (rc 0, every shell)
                ("f() { eval 'bash -s'", "f() { bash -s", CHECK, "", "}\n", True),
                # `-e` is off ahead of `&&` (rc 0, every shell)
                ("eval 'bash -e -s'", "bash -e -s", CHECK + " && echo ok\necho done", "", "",
                 False),
                # the body reads the rest of itself away (rc 0, every shell)
                ("eval 'bash -s'", "bash -s", "cat >/dev/null\n" + CHECK, "", "", False),
                # `&>` is `&` and `>` to dash, which backgrounds the reader (rc 0 there)
                ("eval 'bash -s &>/dev/null'", "bash -s &>/dev/null", CHECK, "", "", False),
                # `((bash -s))` is arithmetic to bash (rc 0 in the bashes)
                ("eval '((bash -s))'", "((bash -s))", CHECK, "bash=1\n", "", False),
                # `-o noexec` runs nothing (rc 0, every shell)
                ("eval 'bash -o $X -s'", "bash -o $X -s", CHECK, "X=noexec\n", "", False)):
            reported.append((stdin_step(string, body, pre=pre, end=end), 1, UNGATED % "eval"))
            literal_step = stdin_step(literal, body, pre=pre, end=end)
            if literal == "( bash -s":
                group_handoffs.append(literal_step)
            else:
                (fixed if function_gap else gaps).append(literal_step)
        # `<>` on descriptor 0 gives the reader `/dev/null` (rc 0, every shell)
        reported.append((stdin_step("eval 'bash -s <>/dev/null'"), 1, UNGATED % "eval"))
        gaps.append(GET + "bash -s <<'EOF' <>/dev/null\n%s\nEOF\n" % CHECK + USE)
        self.assert_reported(reported)
        self.assert_reported((script, 1, "inside a function") for script in fixed)
        self.assert_reported((script, 1, "ends a group that hands its failure")
                             for script in group_handoffs)
        self.assert_clean(gaps)
        self.assert_clean([stdin_step("bash -s"), stdin_step("bash -e -s", self.ECHOED)])

    # Fix round 2: nothing else in a body no shell is sure to read is the step's own
    # either. Each channel method pins one statement of such a body that cleared a step `main`
    # reports: the job is read with those bodies and without them, and a defect of either reading
    # is reported. Its table is the three holders, heredoc form, then `$CMD` with a here-string and
    # a printed pipe, each with `main`'s sentence; its must-trip control is the statement at the
    # step's own level, alone and beside such a body; its literal twin is the body under `bash -s`.
    HOLDERS = (("eval 'bash -s'", ""), ("sh $X", "X=/dev/null\n"), ("$CMD", "CMD=$(echo true)\n"))
    UNSURE = "eval 'bash -s' <<'EOF'\necho hi\nEOF\n"
    HANDED = ("hands a heredoc body or here-string to `$CMD`, a command word this guard does not"
              " follow -- its body is read as shell, which it may not be; name the interpreter"
              " (`bash -s`, `python3 -`), or exempt the step with a reason")
    RESCUED = ("making it executable; the checksum that names tool hands its failure to a `||`"
               " branch that does not fail the step")
    UNCHECKED = "making it executable with nothing verifying what arrived"
    IN_PIPELINE = ("running it under `sh`; the checksum that names tool runs in the same pipeline"
                   " as that use, so the shell may start both before the checksum's failure is"
                   " known")
    OTHER_FILE = ("making it executable; no checksum in the job names %s, and a checksum of a"
                  " different file verifies nothing")
    STREAM = ("hands %si.sh straight to `sh`, so there is no file to check -- download it to a"
              " file, `sha256sum -c` that file, then run it" % URL)

    @staticmethod
    def said(how, name="tool"):
        """`main`'s sentence for the download of `name`, used `how`."""
        return ("fetches %s%s -> %s and %s -- verify it first: `echo \"<sha256>  %s\" | sha256sum"
                " -c -` between the download and that use" % (URL, name, name, how, name))

    def assert_said(self, rows):
        """Each (step, a sentence): reported, that sentence among its defects."""
        for script, said in rows:
            with self.subTest(script=script):
                self.assertIn(said, [why for _step, why in defects(script)])

    def channel(self, step, how):
        """`step(holder, pre, form)` behind each holder as a heredoc, and under `$CMD` as a
        here-string and a printed pipe: each reported with `main`'s sentence."""
        rows = [step(holder, pre, "heredoc") for holder, pre in self.HOLDERS]
        rows += [step("$CMD", "CMD=$(echo true)\n", form) for form in ("here-string", "piped")]
        self.assert_said((script, self.said(how)) for script in rows)

    def test_2500_a_brace_in_a_body_no_shell_is_sure_to_read_closes_no_group_of_the_steps(self):
        # The body's `}` closed the group the check stands in, which lost its "same pipeline"
        # reason: every shell runs the download (rc 0, 1 under `-eo pipefail`; dash refuses `<<<`).
        def step(holder, pre, form):
            return GET + stdin_step(holder, "}", form, pre=pre + "{ %s\n" % CHECK,
                                    end="} | sh tool\n", fetched=False)
        self.channel(step, self.IN_PIPELINE)
        # Must-trip: the step's own `}`, alone and beside such a body (rc 1 in every shell).
        own = GET + "{ %s\n}\nsh tool\n" % CHECK
        self.assert_clean([own, self.UNSURE + own])
        # The literal twin, CLEAN though every shell runs the download (rc 0, 1 under
        # `-eo pipefail`): `main`'s own gap, filed under #2608.
        self.assert_clean([step("bash -s", "", "heredoc")])

    def test_2500_an_exit_in_a_body_no_shell_is_sure_to_read_rescues_no_check_of_the_steps(self):
        # `CHECK || <holder>` with `exit 1` in the body read as a rescue that stops the job: past
        # `X=/dev/null` and under `CMD=$(echo true)` every shell runs the download (rc 0; dash
        # refuses `<<<`); `eval 'bash -s'` runs the `exit 1` (rc 1). `main` reports all five.
        def step(holder, pre, form):
            if form == "piped":
                return GET + pre + "%s || echo 'exit 1' | %s\n" % (CHECK, holder) + USE
            return stdin_step("%s || %s" % (CHECK, holder), "exit 1", form, pre=pre)
        self.channel(step, self.RESCUED)
        # A literal `bash -s` inside the `$CMD` body is no surer: every shell runs the download
        # (rc 0).
        self.assert_said([(step("$CMD", "CMD=$(echo true)\n", "heredoc").replace(
            "exit 1", "bash -s <<'IN'\nexit 1\nIN"), self.said(self.RESCUED))])
        # Must-trip: the step's own `|| exit 1`, alone and beside such a body (rc 1 in every shell).
        own = GET + CHECK + " || exit 1\n" + USE
        self.assert_clean([own, self.UNSURE + own])
        # The literal twin, CLEAN as on `main` and right: `bash -s` runs the `exit 1` (rc 1).
        self.assert_clean([step("bash -s", "", "heredoc")])

    def test_2500_a_call_in_a_body_no_shell_is_sure_to_read_is_no_call_of_the_steps(self):
        # The step's `verify` called in the body read as the step's call: past `X=/dev/null` and
        # under `CMD=$(echo true)` every shell runs the download (rc 0; dash refuses `<<<`); the
        # shell `eval 'bash -s'` starts has no `verify` (rc 127). `main` reports all five.
        verify = "verify() {\n  ( %s || exit 1 )\n}\n" % CHECK
        self.channel(lambda holder, pre, form: stdin_step(holder, "verify", form, pre=pre + verify),
                     self.RESCUED)
        # Must-trip: the step's own call, alone and beside such a body (rc 1 in every shell).
        own = GET + verify + "verify\n" + USE
        self.assert_clean([own, self.UNSURE + own])
        # The literal twin, CLEAN as on `main` and right: the new shell has no `verify` (rc 127).
        self.assert_clean([stdin_step("bash -s", "verify", pre=verify)])
        # A function DEFINED in the body and called by the step (rc 127 in every shell): reported,
        # its check counting for nothing, as before this round; `main`, reading no body, says
        # nothing verifies what arrived, and one sentence is kept for the download.
        defined = "verify() { %s; }" % CHECK
        self.assert_reported((stdin_step(holder, defined, pre=pre, end="verify\n"), count,
                              UNGATED % holder.split()[0]) for (holder, pre), count in zip(
                                  self.HOLDERS, (1, 1, 2)))

    def test_2500_a_write_in_a_body_no_shell_is_sure_to_read_binds_no_check_of_the_steps(self):
        # `> sums` in the body bound the step's `sha256sum -c sums` to a digest: every shell stops
        # at the check (rc 1; dash refuses `<<<`), and `main`, reading no body, reports all five.
        sums = 'echo "%s  tool" > sums' % ("a" * 64)
        self.channel(lambda holder, pre, form: stdin_step(holder, sums, form, pre=pre,
                                                          end="sha256sum -c sums\n"),
                     self.UNCHECKED)
        # Must-trip: the step's own `> sums`, alone and beside such a body (rc 1 in every shell).
        own = GET + sums + "\nsha256sum -c sums\n" + USE
        self.assert_clean([own, self.UNSURE + own])
        # The literal twin, CLEAN as on `main` and right: `bash -s` writes the file (rc 1).
        self.assert_clean([stdin_step("bash -s", sums, end="sha256sum -c sums\n")])

    def test_2500_a_copy_in_a_body_no_shell_is_sure_to_read_names_no_file_for_the_step(self):
        # `cp tool other` in the body made the step's check of `other` name `tool`: every shell
        # stops at the check (rc 1; dash refuses `<<<`), and `main`, reading no body, reports all
        # five.
        other = 'echo "%s  other" | sha256sum -c -\n' % ("a" * 64)
        self.channel(lambda holder, pre, form: stdin_step(holder, "cp tool other", form, pre=pre,
                                                          end=other),
                     self.OTHER_FILE % "tool")
        # Must-trip: the step's own `cp`, alone and beside such a body (rc 1 in every shell).
        own = GET + "cp tool other\n" + other + USE
        self.assert_clean([own, self.UNSURE + own])
        # The literal twin, CLEAN as on `main` and right: `bash -s` copies the file (rc 1).
        self.assert_clean([stdin_step("bash -s", "cp tool other", end=other)])

    def test_2500_a_body_the_holders_own_options_read_is_the_steps_with_no_check_counting(self):
        # The holder's own options read stdin, so `main` reads the body as the holder's program,
        # statement for statement, and so do both readings here (the reader `()`); only the credit
        # of a check in it goes.
        sums = 'echo "%s  tool" > sums' % ("a" * 64)
        rescue = "CMD=$(echo true)\n%s || $CMD <<'EOF'\nexit 1\nEOF\n" % CHECK
        for holder in ("bash -s -c 'sh'", "bash -e -s -c 'sh'", "sh -s -c 'bash -s'"):
            body = "%s <<'B1'\n%%sB1\n" % holder
            self.assert_said([
                # The download in it, the group or the rescue in a `$CMD` body, or the use in it:
                # every shell runs the download (rc 0, 1 under `-eo pipefail` past the group).
                (body % GET + "CMD=$(echo true)\n{ %s\n$CMD <<'EOF'\n}\nEOF\n} | sh tool\n" % CHECK,
                 self.said(self.IN_PIPELINE)),
                (body % GET + rescue + USE, self.said(self.RESCUED)),
                (GET + rescue + body % USE, self.said(self.RESCUED)),
                # The download in it, the write in a `$CMD` body: every shell stops at the check
                # (rc 1), and `main` reports it.
                (body % GET + "CMD=$(echo true)\n$CMD <<'EOF'\n%s\nEOF\nsha256sum -c sums\n" % sums
                 + USE,
                 self.said(self.UNCHECKED)),
                # A stream in it: every shell runs it (rc 0).
                (body % (PIPE + "\n"), self.STREAM)])
            # Reported DELIBERATELY: a check alone in it, which every shell stops at (rc 1) and
            # `main` credits, counts for nothing behind a string.
            self.assert_reported([(GET + body % (CHECK + "\n") + USE, 1,
                                   UNGATED % holder.split()[0])])
            # A `}` in it closes the step's group, as on `main`: CLEAN though every shell runs the
            # download (rc 0, 1 under `-eo pipefail`) -- the literal twin's gap, filed under #2608.
            self.assert_clean([GET + "{ %s\n%s <<'EOF'\n}\nEOF\n} | sh tool\n" % (CHECK, holder)])

    def test_2500_a_download_in_one_body_and_a_channel_in_another(self):
        # The download or its use in a body a literal `bash -s` reads, the rescue or the group in a
        # `$CMD2` body: every shell runs the download (rc 0, 1 under `-eo pipefail` past the group),
        # and `main` reports each.
        def fetched(runner, value="true"):
            return "%s <<'EOF'\n%sEOF\nCMD2=%s\n" % (runner, GET, value)
        rescue = "%s || $CMD2 <<'EOF'\nexit 1\nEOF\n" % CHECK
        group = "{ %s\n$CMD2 <<'EOF'\n}\nEOF\n} | sh tool\n" % CHECK
        self.assert_said([
            (fetched("bash -s") + rescue + USE, self.said(self.RESCUED)),
            (fetched("bash -s") + group, self.said(self.IN_PIPELINE)),
            (GET + "CMD2=true\n" + rescue + "bash -s <<'EOF'\n%sEOF\n" % USE,
             self.said(self.RESCUED))])
        # Every shell runs the download (b5 b3 dash gh: FR+sha FR+sha FR+sha FR) -- fail-open on
        # `main` (CLEAN) and here, a literal value or a `$(...)` one: a statement of one unsure
        # body still gives credit for a fetch only another holds, filed as #2667 (under #2608).
        for value in ("true", "$(echo true)"):
            self.assert_clean([fetched("eval 'bash -s'", value) + rescue + USE,
                               fetched("eval 'bash -s'", value) + group])

    def test_2500_each_download_is_reported_once_whichever_reading_finds_it(self):
        # The first download runs unchecked (reported in both readings); the check of the second is
        # rescued through a `$CMD` body's `exit 1` (cleared in the first reading only). Every shell
        # runs both (rc 0). A defect is kept per download and statement: the second reading adds the
        # second download's, and never another sentence for the first -- a different download, the
        # same one twice, or two in one statement (a pipeline of two `curl`s).
        second = stdin_step(CHECK + " || $CMD", "exit 1", pre="CMD=true\n")
        one = "curl -fsSLo one %sone" % URL
        first = self.said(self.OTHER_FILE % "one", "one")
        again = ("verifies tool only AFTER making it executable -- fetches %stool -> tool, so"
                 " verify it first: `echo \"<sha256>  tool\" | sha256sum -c -` between the download"
                 " and that use" % URL)
        piped = one + " | " + GET + "chmod +x one\n./one\n" + second[len(GET):]
        for script, said in ((one + "\nchmod +x one\n./one\n" + second, first),
                             (GET + USE + second, again), (piped, first)):
            with self.subTest(script=script):
                self.assertEqual([self.HANDED, said, self.said(self.RESCUED)],
                                 [why for _step, why in defects(script)])

    def test_2500_a_write_in_one_steps_body_binds_no_check_of_the_next(self):
        # Step A's body writes `sums`; step B downloads, checks `sums` and uses the download. The
        # check fails in every shell (step A rc 0, step B rc 1), and `main`, reading no body,
        # reports step B.
        sums = 'echo "%s  tool" > sums' % ("a" * 64)
        self.assertEqual([("B", self.said(self.UNCHECKED))],
                         wg.job_defects([("A", "eval 'bash -s' <<'EOF'\n%s\nEOF\n" % sums),
                                         ("B", GET + "sha256sum -c sums\n" + USE)]))

    def test_2500_a_step_the_reader_refuses_raises_alone_and_is_named_once_in_a_job(self):
        # A `)` in a substitution heredoc body: bash runs the stream (rc 0), dash refuses the step
        # (rc 2). `fetch_exec_defects` raises, beside a `$CMD` body or not, and `job_defects`
        # names the step once -- also second in a job read twice for its first step's body.
        refused = "echo $(cat <<EOF\n$(%s)\nEOF)\n" % PIPE
        body = "CMD=true\n$CMD <<'EOF'\necho hi\nEOF\n"
        for script in (refused, body + refused, refused + body):
            with self.subTest(script=script):
                with self.assertRaises(shell_lex.Unreadable):
                    wg.fetch_exec_defects(script)
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith("cannot read this step: "), found)
        found = wg.job_defects([("A", self.UNSURE), ("B", refused)])
        self.assertEqual(["B"], [name for name, _why in found])
        self.assertTrue(found[0][1].startswith("cannot read this step: "), found)

    def test_2500_a_refused_body_no_shell_is_sure_to_read_refuses_its_step(self):
        # The same `)` in a body no shell is sure to read: the body is read, so the step is refused
        # whole, in both readings. Behind `eval 'bash -s'` and `bash -c 'sh'` every shell runs the
        # stream (rc 0); past `X=/dev/null` and under `CMD=$(echo true)` none reads the body (rc 0)
        # -- an over-report, filed as #2668 (under #2608).
        refused = "echo $(cat <<E2\n$(%s)\nE2)" % PIPE
        for holder, pre in self.HOLDERS + (("bash -c 'sh'", ""),):
            script = stdin_step(holder, refused, pre=pre, fetched=False)
            with self.subTest(script=script):
                with self.assertRaises(shell_lex.Unreadable):
                    wg.fetch_exec_defects(script)
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith("cannot read this step: "), found)
        # The over-report #2668 names is closed for a literal by #2468's annotation (b5 b3 dash
        # gh: -- -- -- --): under `CMD=true`, `$CMD` reads as `true`, which reads no body, so
        # nothing is refused -- CLEAN. The holder above keeps a value no table sees, and the price.
        script = stdin_step("$CMD", refused, pre="CMD=true\n", fetched=False)
        with self.subTest(script=script):
            self.assertEqual([], defects(script))
        # In a job, a refused step's own statements leave the fold with it, as those of any step
        # the reader refuses: step B's download, which step A makes executable, is reported at B
        # where A's body is read and at A where it is refused -- the job is reported either way.
        for body, named in (("echo hi", "B"), (refused, "A")):
            with self.subTest(body=body):
                step = stdin_step("eval 'bash -s'", body, fetched=False) + USE
                found = wg.job_defects([("B", GET), ("A", step)])
                self.assertEqual([named], [name for name, _why in found])

    def test_2500_a_job_handed_as_an_iterator_is_read_twice_as_its_list_is(self):
        # The fold read its argument once per reading, so an iterator or a generator lost the
        # second reading and the reports only it makes: here the rescue under `CMD=true` and the
        # two-step job whose step A's body writes `sums`, both pinned above.
        sums = 'echo "%s  tool" > sums' % ("a" * 64)
        rescue = [("step", stdin_step(CHECK + " || $CMD", "exit 1", pre="CMD=true\n"))]
        job = [("A", "eval 'bash -s' <<'EOF'\n%s\nEOF\n" % sums),
               ("B", GET + "sha256sum -c sums\n" + USE)]
        for steps, report in ((rescue, ("step", self.said(self.RESCUED))),
                              (job, ("B", self.said(self.UNCHECKED)))):
            with self.subTest(steps=steps):
                found = wg.job_defects(steps)
                self.assertIn(report, found)
                self.assertEqual(found, wg.job_defects(iter(steps)))
                self.assertEqual(found, wg.job_defects(step for step in steps))

    def test_2500_eval_s_words_are_read_joined_so_a_join_the_reader_refuses_refuses_the_step(self):
        # `_stdin` asks whether `eval`'s words JOINED, as bash runs them, are one stdin-reading
        # shell, and the reader refuses this join (a heredoc whose substitution closes before its
        # body), though each word reads alone, as on `main` -- kept: a text the
        # guard cannot read is refused. Bash 3.2.57, 5.2.21 and dash run the join (rc 0: `echo`
        # runs, nothing is downloaded), so alone the step is an over-report; in a job whose step A
        # makes step B's download executable and runs it (every shell runs it, rc 0), the report
        # names A, where `main` names B.
        join = "eval 'echo $(cat <<A' 'x' 'A)'\n"
        found = defects(join)
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0][1].startswith("cannot read this step: "), found)
        with self.assertRaises(shell_lex.Unreadable):
            wg.fetch_exec_defects(join)
        found = wg.job_defects([("B", GET), ("A", join + USE)])
        self.assertEqual(["A"], [name for name, _why in found])
        self.assertTrue(found[0][1].startswith("cannot read this step: "), found)


class TestDoubleQuoteEscapes(unittest.TestCase):
    """#2342: the program a double-quoted `-c` or `eval` string hands a shell
    is the text bash makes of it, `\\$` and `` \\` `` without their backslash."""

    def test_the_program_bash_hands_the_shell_is_read(self):
        fetch = "curl -fsSL %si.sh" % URL
        for script in ('bash -c "x=\\$(%s); eval \\"\\$x\\""\n' % fetch,
                       'eval "x=\\$(%s); eval \\"\\$x\\""\n' % fetch,
                       'bash -c "x=\\`%s\\`; eval \\"\\$x\\""\n' % fetch):
            with self.subTest(script=script):
                self.assertTrue(defects(script))

    def test_the_controls_read_as_they_did(self):
        self.assertTrue(defects('sh -c "%s"\n' % PIPE))
        self.assertTrue(defects('bash -c "curl -fsSL \\"$URL\\" | sh"\n'))
        for script in ('bash -c "echo \\$HOME"\n', "eval 'x=\\$(curl -fsSL %si.sh)'\n" % URL):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))

    def test_a_string_with_another_dollar_in_it_is_read_as_bash_hands_it(self):
        # The gap list's entry until #2466: bash runs both (b5 b3 dash gh: FR FR FR FR), and a
        # live `$URL` -- or a single-quoted `$` in the same word -- left the text as written.
        # Now the live word is carried as the value it is and the structure around it reads;
        # `TestALiveExpansionBesideAnEscape` pins the sentence and the controls.
        for script in ('URL=%si.sh\nbash -c "x=\\$(curl -fsSL $URL); eval \\"\\$x\\""\n' % URL,
                       'bash -c "x=\\$(curl -fsSL %si.sh)"\'; eval "$x"\'\n' % URL):
            with self.subTest(script=script):
                self.assertTrue(defects(script))


class TestALiveExpansionBesideAnEscape(unittest.TestCase):
    """#2466: a double-quoted `-c`/`eval` string with a LIVE expansion beside its `\\$` or `` \\` ``
    escapes is read as bash hands it on -- the backslashes gone, the live `$` word carried as the
    value it already is at top level, a lifted `$(...)` as its marker -- where #2342 read it as
    written, `\\$` and all, so `x=\\$(curl …)` was text and the download it carries into `eval`
    ran unreported. Bash evidence per row: each step from its own file under bash 5.2.21 and
    3.2.57 with `-e` and `-eo pipefail`, dash with `-e`, and 5.2.21 with `sh` = dash (b5 b3 dash
    gh), a mark-first `curl` stub whose payload marks when it RUNS and a `sha256sum` that fails."""

    LIVE = 'URL=%si.sh\nbash -c "x=\\$(curl -fsSL $URL); eval \\"\\$x\\""\n' % URL
    MIXED = 'bash -c "x=\\$(curl -fsSL %si.sh)"\'; eval "$x"\'\n' % URL
    CARRIED = "carries %s in `$x` and hands it to `eval`"
    IN_STRING = CHECK.replace('"', '\\"')

    def test_the_two_spellings_of_the_issue_are_reported(self):
        # FR FR FR FR each; `main` CLEAN (the fail-open). #2341's carried sentence, as the issue
        # asked: the structure is an assignment from `$(curl …)` and an `eval` of it, whatever
        # `URL` holds.
        for script, named in ((self.LIVE, "$URL"), (self.MIXED, URL + "i.sh")):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith(self.CARRIED % named), found)

    def test_the_twins_read_the_same_way(self):
        # `eval`, a backquote, `sh -c` and `dash -c` (FR FR FR FR each; `main` CLEAN), the string
        # behind `|| true` (FR x4; `main` CLEAN) and one holding a check of another file before
        # the `eval` (FR+sha x4: the check names `tool`, not the carried download; `main` CLEAN).
        for script in ('URL=%si.sh\neval "x=\\$(curl -fsSL $URL); eval \\"\\$x\\""\n' % URL,
                       'URL=%si.sh\nbash -c "x=\\`curl -fsSL $URL\\`; eval \\"\\$x\\""\n' % URL,
                       'URL=%si.sh\nsh -c "x=\\$(curl -fsSL $URL); eval \\"\\$x\\""\n' % URL,
                       'URL=%si.sh\ndash -c "x=\\$(curl -fsSL $URL); eval \\"\\$x\\""\n' % URL,
                       self.LIVE.rstrip("\n") + " || true\n",
                       'URL=%si.sh\nbash -c "x=\\$(curl -fsSL $URL); %s; eval \\"\\$x\\""\n'
                       % (URL, self.IN_STRING)):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith(self.CARRIED % "$URL"), found)

    def test_a_printer_piping_the_same_text_into_a_shell_is_read(self):
        # `echo "x=\$(curl … $URL); eval \"\$x\"" | sh` (FR FR FR FR): `main` reported it too,
        # but as a printer whose words it does not spell out; the spelled text now reads as the
        # program it is. A printer's word that also holds a lifted `$(...)` stays unspelled
        # (`echo "\$x $(true)" | sh` beside a download: F- x4, `main`'s own sentence kept).
        found = defects('URL=%si.sh\necho "x=\\$(curl -fsSL $URL); eval \\"\\$x\\"" | sh\n' % URL)
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0][1].startswith(self.CARRIED % "$URL"), found)
        found = defects(GET + 'echo "\\$x $(true)" | sh\n')
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0][1].startswith("pipes `sh` its program from `echo`"), found)

    def test_the_neighbour_of_2681_reads_as_its_escape_only_twin(self):
        # `curl -fsSLo tool …` then `bash -c "sh \$(echo tool) $(true)"` (FR FR FR FR): the live
        # `$(true)` made the string `Opaque`, and its `\$` kept its backslash in the rendering, so
        # `main` reported the download by the FETCH sentence (right verdict, one level off, noted
        # on #2466). Rendered as bash hands it on, `sh $(echo tool) $(...)`, it reads as
        # `bash -c "sh \$(echo tool)"` does (`TestAShellsSoleSubstitutionOperand`): the `Idle`
        # hand-off, kept beside the reported fetch.
        for script in (GET + 'bash -c "sh \\$(echo tool) $(true)"\n',
                       GET + 'bash -c "sh \\$(echo tool)"\n'):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith("passes `sh` `$(...)`"), found)
                self.assertIsInstance(found[0][1], wg.Idle)

    def test_the_controls_read_as_they_did(self):
        # CLEAN, as on `main` (-- -- -- --, or F- x4 for a download fetched and never run).
        for script in ('bash -c "echo $HOME"\n',
                       'bash -c "cd $GITHUB_WORKSPACE && echo \\$PWD"\n',
                       'bash -c "for f in $DIR/*; do echo \\$f; done"\n',
                       'URL=%si.sh\nbash -c "x=\\$(curl -fsSL $URL); echo \\"\\$x\\" > f"\n' % URL,
                       'URL=%si.sh\nbash -c "x=\\$(curl -fsSL $URL); echo \\"\\$x\\""\n' % URL):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))
        # DEFECT with the sentence `main` gives (FR FR FR FR): the pipe hands its live `$URL`
        # straight to `sh` (#2341), and a check inside the string that does not gate (FR+sha x4).
        found = defects('URL=%si.sh\nbash -c "curl -fsSL $URL | sh"\n' % URL)
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0][1].startswith("hands $URL straight to `sh`"), found)
        found = defects('URL=%si.sh\nbash -c "curl -fsSLo tool $URL; %s; sh tool"\n'
                        % (URL, self.IN_STRING))
        self.assertEqual(1, len(found), found)
        self.assertIn("inside the script `bash` runs, where no `-e` holds", found[0][1])

    def test_an_inner_assignment_read_as_the_steps_own_is_the_documented_price(self):
        # `bash -c "x=\$(curl … $URL)"` then the STEP's own `eval "$x"`: the child's `x` never
        # reaches the step (F- F- F- F-, nothing runs), but the gap list reads a child shell's
        # assignments as the step's, and the literal twin `bash -c 'x=$(curl …)'; eval "$x"`
        # reports on `main` the same way -- so this reports, named as the conservative reading.
        for script in ('URL=%si.sh\nbash -c "x=\\$(curl -fsSL $URL)"\neval "$x"\n' % URL,
                       "bash -c 'x=$(curl -fsSL %si.sh)'\neval \"$x\"\n" % URL):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertIn("in this guard's conservative reading", found[0][1])


class TestAShellsSoleSubstitutionOperand(unittest.TestCase):
    """#2342 handed the reader bash's text, so `eval "sh \\$(echo tool)"` is
    `sh $(echo tool)`: a shell whose only operand is a value whose OUTPUT
    becomes its words, the program among them (C1 of #2331's final review).
    That value is the candidate, weighed `Idle`, kept where the job holds a
    fetch the guard reports and nothing louder reports its statement (#2490).
    A `<(...)` hands the shell a file to read instead, and is not one.
    Unescaped, `eval "sh $(cat f)"` hands on the text the substitution prints:
    its string is read with that text opaque, as `sh $(...)`, and no check in
    it counts (#2486); `eval "sh $(echo tool)"`, whose substitution is one
    printer, is read as `sh tool`, the text it prints (#2487)."""

    def test_it_is_reported_where_the_job_holds_a_reported_fetch(self):
        # Bash 3.2.57, 5.2.21 and dash run the download in each, the strings
        # holding an unescaped `$(cat f)` too (#2486; b5 b3 dash gh: FR FR FR FR,
        # `f` holding `tool`). `sh $(echo tool)` and `eval "sh \$(echo tool)"`
        # live in `test_a_louder_reason_at_its_statement_speaks_alone`.
        named = GET + "echo tool > f\n"
        for script in (GET + 'bash -c "sh \\$(echo tool)"\n', GET + "sh `echo tool`\n",
                       named + 'eval "sh $(cat f)"\n', named + 'bash -c "sh $(cat f)"\n'):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith("passes `sh` `$(...)`"), found)
        # Unescaped `$(echo tool)` is one printer, read as `tool` (#2487): the string is
        # `sh tool`, and the download it runs is reported as such (FR FR FR FR each).
        for script in (GET + 'eval "sh $(echo tool)"\n', GET + 'bash -c "sh $(echo tool)"\n'):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith(
                    "fetches %stool -> tool and running it under `sh`" % URL), found)

    def test_it_is_not_reported_where_the_job_fetches_nothing(self):
        for script in ("sh $(echo tool)\n", 'eval "sh \\$(echo x.sh)"\n', "sh `echo tool`\n",
                       'eval "sh $(echo tool)"\n'):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))

    def test_a_string_holding_one_among_its_text_is_read_with_it_opaque(self):
        # #2486: the substitution's own text stays where the guard's walk
        # reads it, and what it prints is not read; `eval "echo $(date)"`
        # hands no shell a program. Bash 3.2.57, 5.2.21 and dash run the
        # download in each of the rest, every one CLEAN until now: `eval`
        # runs what the inner `sh $(...)` is handed, the string pipes it into
        # `sh`, and the substitution runs `tool`, where no download is
        # followed.
        value = "passes `sh` `$(...)` where it reads its options"
        self.assertEqual([], defects(GET + 'eval "echo $(date)"\n'))
        # Two sentences, each true and on a statement of its own, as the guard's gap list says:
        # `eval "sh $(curl …)"` reports the inner `sh $(...)` beside `eval`'s stream.
        found = defects('eval "sh $(curl -fsSL %si.sh)"\n' % URL)
        self.assertEqual(2, len(found), found)
        self.assertTrue(found[0][1].startswith(value), found)
        self.assertTrue(found[1][1].startswith("hands %si.sh straight to `eval`" % URL), found)
        found = defects(GET + 'x=$(bash -c "sh $(echo tool)")\n')
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0][1].startswith(
            "hands a script to `bash` inside a command substitution"), found)
        # The URL a one-printer `$(...)` prints is read as that text since #2487 (FR FR FR FR).
        found = defects('sh -c "curl -fsSL $(echo %si.sh) | sh"\n' % URL)
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0][1].startswith("hands %si.sh straight to `sh`" % URL), found)
        self.assertNotIn("@@", found[0][1])
        # #2486's rows 1-3 (2026-10-02) are pinned in `TestALiteralStringHoldingASubstitution`.
        # Row 2's `$(date)` after the fetch, behind each other shell that takes such a string:
        # bash 3.2.57, 5.2.21, dash and zsh run every one.
        for script in ('bash -c "%s; echo $(date)"\n' % PIPE, 'zsh -c "%s; echo $(date)"\n' % PIPE,
                       'eval "%s; echo $(date)"\n' % PIPE, '${X:-sh} -c "%s; echo $(date)"\n' % PIPE):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith("hands %si.sh straight to `sh`" % URL), found)
        # The controls: the string's literal twin and the stream at the top.
        for script in ("sh -c '%s'\n" % PIPE, "sh $(curl -fsSL %si.sh)\n" % URL):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertIn("straight to `sh`", found[0][1])
        # `eval`'s words are scripts one at a time, and a lone `$(...)` is
        # none: `dynamic_program` reports it, `Idle`, beside the download all
        # run as `tool` (b5 b3 dash gh: FR FR FR FR, `f` holding `tool`) --
        # what `cat f` prints unread. One printer's text is read (#2487):
        # `eval sh "$(echo tool)"` runs `tool` too (FR FR FR FR), reported so,
        # and since fix round 1 the catch-all `Idle` stands beside that read
        # (main / base / 19423415: UR / UR / FX).
        found = defects(GET + "echo tool > f\n" + 'eval sh "$(cat f)"\n')
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0][1].startswith("runs `eval` on `$(...)`"), found)
        self.assertIsInstance(found[0][1], wg.Idle)
        found = defects(GET + 'eval sh "$(echo tool)"\n')
        self.assertEqual(2, len(found), found)
        self.assertTrue(found[0][1].startswith("runs `eval` on `$(...)`"), found)
        self.assertIsInstance(found[0][1], wg.Idle)
        self.assertTrue(found[1][1].startswith(
            "fetches %stool -> tool and running it" % URL), found)

    def test_no_check_in_such_a_string_counts(self):
        # Bash re-reads the string with what the `$(...)` printed, so a check
        # in it may never run: here it does not, and bash 3.2.57 and 5.2.21
        # run `./tool` under `-e`. Its twin with no substitution stops at the
        # failing check in both, and reads CLEAN as it did (#2486).
        check = "echo '%s  tool' | sha256sum -c -" % ("a" * 64)
        run = "\nchmod +x tool\n./tool\n"
        found = defects(GET + "bash -ec \"$(echo 'true ||') %s\"" % check + run)
        self.assertEqual(1, len(found), found)
        self.assertIn("the checksum that names tool is inside the script `bash` runs with what "
                      "a `$(...)` prints, which may skip the check", found[0][1])
        self.assertEqual([], defects(GET + 'bash -ec "%s"' % check + run))

    def test_a_string_the_reader_refuses_so_read_is_unread_as_before(self):
        # `cat <<$(...)` names no line to end the body at -- bash takes the
        # delimiter from what the `$(...)` prints -- so that string is no
        # script, as before #2486, and the step is read, not refused whole.
        # Bash 3.2.57, 5.2.21 and dash run the stream, then fail the `eval`
        # (`a b` prints nothing); alone, the `eval` runs nothing.
        refused = 'eval "cat <<$(a b)\nit\'s\n$(a b)\n"\n'
        found = defects(PIPE + "\n" + refused)
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0][1].startswith("hands %si.sh straight to `sh`" % URL), found)
        self.assertEqual([], defects(refused))
        # The control: written out, the text is refused, fail-closed, as it was.
        found = defects(PIPE + "\ncat <<$(a b)\nit's\n$(a b)\n")
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0][1].startswith("cannot read this step"), found)
        # The residual (the gap list): all run the stream after the body,
        # which its literal twin reports, where the delimiter comes from a
        # `$(...)` that is no printer (b5 b3 dash gh: FR FR FR FR). One that
        # is (#2487) is read as the `E` it prints: the stream is reported
        # (FR FR FR FR).
        residual = 'sh -c "cat <<$(cat d) >/dev/null\nE\n%s"\n' % PIPE
        self.assertEqual([], defects("echo E > d\n" + residual))
        self.assertTrue(defects("sh -c 'cat <<E >/dev/null\nE\n%s'\n" % PIPE))
        found = defects('sh -c "cat <<$(echo E) >/dev/null\nE\n%s"\n' % PIPE)
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0][1].startswith("hands %si.sh straight to `sh`" % URL), found)

    def test_a_louder_reason_at_its_statement_speaks_alone(self):
        # #2490: where a fetch's own defect -- the stream `sh $(curl …)` hands
        # the shell -- or #2341's carried download reports the same statement,
        # the value's `Idle` is dropped and the loud sentence stands alone.
        # Bash 3.2.57, 5.2.21 and dash hand the downloaded words to `sh` as
        # its operands and run none of them; the controls, the stream piped
        # and the download handed whole, run in all three.
        stream = "hands %si.sh straight to `sh`" % URL
        carried = "carries %si.sh in `$x` and hands it to `%s`"
        fetch = "x=$(curl -fsSL %si.sh)\n" % URL
        for script, said in (("sh $(curl -fsSL %si.sh)\n" % URL, stream), (PIPE + "\n", stream),
                             (fetch + 'sh $(echo "$x")\n', carried % (URL, "sh")),
                             (fetch + 'eval "sh \\$(echo \\"\\$x\\")"\n', carried % (URL, "sh")),
                             (fetch + 'sh -c "$x"\n', carried % (URL, "sh -c"))):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith(said), found)
        # Where nothing louder speaks, the value's `Idle` is the one sentence
        # beside the download `sh tool` runs in all three: the must-trip
        # against dropping too much. The drop is per statement, not per job:
        # beside a stream on a statement of its own, both stand, in order.
        value = "passes `sh` `$(...)` where it reads its options"
        for script in (GET + "sh $(echo tool)\n", GET + 'eval "sh \\$(echo tool)"\n'):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith(value), found)
        found = defects(PIPE + "\nsh $(echo tool)\n")
        self.assertEqual(2, len(found), found)
        self.assertTrue(found[0][1].startswith(value), found)
        self.assertTrue(found[1][1].startswith(stream), found)
        self.assertEqual([], defects("sh $(echo tool)\n"))

    def test_a_process_substitution_hands_a_file_not_words(self):
        # Beside a download nothing is handed on; a `<(...)` that fetches is
        # read where it runs, once.
        for script in (GET + "sh <(echo 'echo hi')\n", GET + "bash <(echo true)\n"):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))
        found = defects("bash <(curl -fsSL %si.sh)\n" % URL)
        self.assertEqual(1, len(found), found)
        self.assertIn("straight to `bash`", found[0][1])

    def test_a_string_or_program_word_holding_a_process_substitution_is_unread(self):
        # #2486 keeps a `<(...)` out (`shell_reader.yields_words`): a string
        # holding one beside a `$(...)` is a script since #2684 -- the file rendered as an
        # operand, `sh tool $(...)` -- so the first two report the run of `tool` (FR FR FR FR for
        # `bash -c`; the `sh -c` twin runs it only where `sh` is bash 5.1 or later, read the
        # same, fail-closed); a program word that is all of one is still not `dynamic_program`'s.
        for script in (
                # runs `tool` where `sh` is bash 5.2.21; a 3.2.57 or dash `sh` exits 2 on the `(`
                GET + 'sh -c "sh $(echo tool) <(echo x)"\n',
                # bash 5.2.21 and 3.2.57 run it (`sh tool /dev/fd/63`), under a dash step too
                GET + 'bash -c "sh $(echo tool) <(echo x)"\n'):
            with self.subTest(script=script):
                found = defects(script)
                self.assertTrue(any("running it under `sh`" in w for _, w in found), found)
        for script in (
                # nothing of `tool` runs: a bash cannot execute `/dev/fd/63`, the others exit 2
                GET + 'sh -c "<(cat tool)"\n',
                # nothing of `tool` runs: the same in the step's own shell (dash's `eval` exits 2)
                GET + 'eval "<(cat tool)"\n'):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))
        # The `$(...)` twins are reported, two in `test_a_word_that_is_all_substitution_is_one`.
        # And these run `tool` (b5 b3 dash gh: FR FR FR FR, `f` holding `tool`): the string read
        # opaque, its `sh $(...)` the value's `Idle`; one printer's is read as `sh tool` (#2487),
        # the run reported as such (FR FR FR FR).
        value = "passes `sh` `$(...)` where it reads its options"
        found = defects(GET + "echo tool > f\n" + 'sh -c "sh $(cat f)"\n')
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0][1].startswith(value), found)
        self.assertIsInstance(found[0][1], wg.Idle)
        found = defects(GET + 'sh -c "sh $(echo tool)"\n')
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0][1].startswith(
            "fetches %stool -> tool and running it under `sh`" % URL), found)


class TestAProgramPipedFromAPrinter(unittest.TestCase):
    """#2333: the program an `echo` or `printf` pipes into a shell."""

    def test_a_program_a_printer_spells_out_is_read(self):
        for script in (GET + "echo 'sh tool' | sh\n", GET + "printf '%s\\n' 'sh tool' | bash\n",
                       "echo '%s' | sh\n" % PIPE, GET + "printf 'sh tool\\n' | sh -s\n",
                       GET + "echo sh tool | sudo bash\n"):
            with self.subTest(script=script):
                self.assertTrue(defects(script))
        # A check in front of it clears it as it clears `sh tool` written out.
        check = "echo '%s  tool' | sha256sum -c -%s\necho 'sh tool' | sh\n"
        self.assertEqual([], defects(GET + check % ("a" * 64, "")))
        self.assertTrue(defects(GET + check % ("a" * 64, " || true")))

    def test_a_program_it_does_not_spell_out_is_reported_unread(self):
        # Where the job holds a reported fetch, or its words, read as
        # written, fetch; else it is `Idle`, as a substitution's script is.
        for script in (GET + 'X="sh tool"\necho "$X" | sh\n', GET + "printf '%s %s\\n' sh tool | sh\n",
                       'echo "curl -fsSL $URL | sh" | sh\n', GET + 'echo "$(cat tool)" | sh\n',
                       'echo "$(curl -fsSL %si.sh)" | sh\n' % URL):
            with self.subTest(script=script):
                self.assertTrue(defects(script))
        for script in ('echo "$X" | sh\n', "printf '%s %s\\n' echo hi | sh\n"):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))
        # #2341 reads the download a variable carries: one sentence, not two.
        found = defects('x=$(curl -fsSL %si.sh)\necho "$x" | sh\n' % URL)
        self.assertEqual(1, len(found), found)
        self.assertIn("carries", found[0][1])

    def test_the_controls_read_as_they_did(self):
        for script in (GET + "echo hi > notes.txt\ncat notes.txt | sh\n",
                       GET + "echo 'sh tool' | sh -c 'echo hi'\n",
                       GET + "echo y | sh -c 'read a; echo $a'\n", "echo y | sh install.sh\n"):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))
        self.assertTrue(defects(GET + "cat tool | sh\n"))

    def test_a_producers_literal_value_is_read_as_the_stream_it_spells(self):
        # Bash runs this row, and `cat <<'EOF' | sh` (the other half of this test before #2467) is
        # a printer flipped in `test_workflow_printers.py`. This row was the documented gap -- a
        # `$` producer in a job with no download was `Idle`, though bash runs it (b5 b3 dash gh: FR
        # FR FR FR), as #2333 weighed a producer's `$X` as written and no table placed it (#2468)
        # -- closed by the annotation, which spells `$X` as the literal it holds: the #2333 stream
        # sentence.
        found = defects("X='%s'\necho \"$X\" | sh\n" % PIPE)
        self.assertEqual(1, len(found), found)
        said = "hands %si.sh straight to `sh`" % URL
        self.assertTrue(found[0][1].startswith(said), found)


if __name__ == "__main__":
    unittest.main()


class TestWhatAnEvalOrDashCStringHandsOn(unittest.TestCase):
    """#2673, #2683, #2684, #2764 (and #2669's refusal, #2685 proven closed): what `eval`'s words
    and a `-c` string hand on. Each row's comment carries its truth, b5 b3 dash gh (bash 5.2.21,
    bash 3.2.57, dash, a GitHub runner's bash with `sh` = dash), measured with a recording `curl`
    that hands back a marker program and the step run as GitHub runs it: FR fetched and ran, F-
    fetched only, -- neither. The four columns agree unless a comment says otherwise."""

    STREAM = "hands %si.sh straight to `sh`" % URL
    USE = "fetches %stool -> tool and running it under `sh`" % URL

    def test_evals_words_join_where_a_statement_is_split_across_them(self):
        # #2673, FR FR FR FR on each: bash joins its words with a space and runs the result.
        for script in ("eval 'curl -fsSL %si.sh |' 'sh'\n" % URL, "eval 'curl -fsSL %si.sh' '| sh'\n" % URL,
                       "eval 'curl -fsSL %si.sh' '|' 'sh'\n" % URL,
                       "command eval 'curl -fsSL %si.sh |' 'sh'\n" % URL,
                       "eval -- 'curl -fsSL %si.sh |' 'sh'\n" % URL):     # FR FR -- FR: dash runs `--`
            with self.subTest(script=script):
                self.assertTrue(any(self.STREAM in w for _, w in defects(script)), script)
        # FR FR FR FR: the split falls inside a `$(...)` of the joined text, handed to `sh -c`.
        found = defects("eval 'sh -c \"$(curl -fsSL %si.sh' ')\"'\n" % URL)
        self.assertTrue(any("straight to `sh -c`" in w for _, w in found), found)
        # -- -- -- --: a join that fetches nothing is CLEAN; the controls read as they did -- one
        # word, a split at a statement boundary, unquoted words.
        self.assertEqual([], defects("eval 'echo a |' 'cat'\n"))
        for script in ("eval 'curl -fsSL %si.sh | sh'\n" % URL, "eval curl -fsSL %si.sh '|' sh\n" % URL):
            with self.subTest(script=script):
                self.assertTrue(any(self.STREAM in w for _, w in defects(script)), script)
        found = defects("eval 'curl -fsSLo tool %stool;' 'sh tool'\n" % URL)
        self.assertTrue(any(self.USE in w for _, w in found), found)

    def test_words_with_no_split_statement_still_read_one_by_one(self):
        # The join is made only where a word begins or ends with an operator: `eval sh
        # "./cuda_*.run"` keeps its own reading (the operand reader re-parses its words with their
        # quoting), and `eval sh "$(echo tool)"` its two sentences (#2486, #2487).
        found = defects("curl -fsSLo cuda_1.run %scuda_1.run\neval sh \"./cuda_*.run\"\n" % URL)
        self.assertTrue(any("cuda_1.run" in w for _, w in found), found)
        found = defects(GET + 'eval sh "$(echo tool)"\n')
        self.assertEqual(2, len(found), found)
        self.assertTrue(found[0][1].startswith("runs `eval` on `$(...)`"), found)

    def test_a_join_the_reader_refuses_is_refused_on_both_paths(self):
        # #2669, -- -- -- -- (rc 0, nothing fetched): `eval 'echo $(cat <<A' 'x' 'A)'` joins to a
        # heredoc inside a substitution the reader cannot end; it is refused whole, fail-closed,
        # on the string path as on the stdin walk's -- one answer, naming the text bash runs.
        found = defects("eval 'echo $(cat <<A' 'x' 'A)'\n")
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0][1].startswith("cannot read this step"), found)
        self.assertEqual([], defects("eval 'echo \"a' 'b\"'\n"))      # a join the reader reads

    def test_a_word_holding_a_substitution_reaches_the_stdin_walk_rendered(self):
        # #2683, FR FR FR FR: `"sh $(echo -s)"` is `sh -s` (one printer spells it) and `"sh $(cat
        # f)"` is `sh $(...)`, a word that may vanish -- either way `sh` reads the heredoc. The
        # price, F-+chk x4: `"sh $(echo -n)"` runs nothing, but a check in its body counts for
        # nothing and the use after is reported.
        for script in ("eval \"sh $(echo -s)\" <<'EOF'\n%s\nEOF\n" % PIPE, "eval \"sh $(cat f)\" <<'EOF'\n%s\nEOF\n" % PIPE):
            with self.subTest(script=script):
                self.assertTrue(any(self.STREAM in w for _, w in defects(script)), script)
        found = defects(GET + "eval \"sh $(echo -n)\" <<'EOF'\n%s\nEOF\nchmod +x tool; ./tool\n" % CHECK)
        self.assertTrue(any(UNGATED % "eval" in w for _, w in found), found)
        # `eval "$(cat x)" <<'EOF'`: a word all expansion still names no shell; #2483's word stands.
        self.assertEqual([], defects("eval \"$(cat x)\" <<'EOF'\n%s\nEOF\n" % PIPE))

    def test_a_rendered_shell_reaches_the_heredoc(self):
        # #2764, FR FR FR FR: `eval "$(echo 'sh')"` is `sh`, and the heredoc its program.
        found = defects("eval \"$(echo 'sh')\" <<'EOF'\n%s\nEOF\n" % PIPE)
        self.assertTrue(any(self.STREAM in w for _, w in found), found)
        # FR FR -- FR (dash refuses `<(`): the FILE is the program, and where it is a shell reading
        # stdin the heredoc is that shell's; `echo hi` as the FILE reads nothing (-- -- -- --).
        for script in ("bash <(echo 'sh') <<'EOF'\n%s\nEOF\n" % PIPE, "source <(echo 'sh') <<'EOF'\n%s\nEOF\n" % PIPE):
            with self.subTest(script=script):
                self.assertTrue(any(self.STREAM in w for _, w in defects(script)), script)
        self.assertEqual([], defects("bash <(echo 'echo hi') <<'EOF'\n%s\nEOF\n" % PIPE))
        self.assertEqual([], defects("eval \"$(echo 'cat')\" <<'EOF'\n%s\nEOF\n" % PIPE))
        # No check in such a body counts (reader None): F-+chk x4, the use after is reported.
        found = defects(GET + "bash <(echo 'sh') <<'EOF'\n%s\nEOF\nchmod +x tool; ./tool\n" % CHECK)
        self.assertTrue(any(UNGATED % "bash" in w for _, w in found), found)

    def test_a_process_substitution_in_a_string_hands_a_file_not_nothing(self):
        # #2684, FR FR FR FR for `bash -c`; the `sh -c` twin runs only where `sh` is bash 5.1 or
        # later (F- F- F- F- here, rc 2) and is read the same, fail-closed: the string is
        # `sh tool $(...)`, `tool` its program, the file an operand `tool` ignores.
        for script in (GET + 'bash -c "sh $(echo tool) <(echo x)"\n', GET + 'sh -c "sh $(echo tool) <(echo x)"\n'):
            with self.subTest(script=script):
                self.assertTrue(any(self.USE in w for _, w in defects(script)), script)
        # F- F- F- F- (rc 2): no shell, no fetch -- CLEAN; `bash <(curl …)` at the top is #2495's.
        self.assertEqual([], defects(GET + 'sh -c "cat <(echo x)"\n'))
        self.assertTrue(any("straight to `bash`" in w for _, w in defects("bash <(curl -fsSL %si.sh)\n" % URL)))

    def test_2685_is_closed_on_main(self):
        # #2685, FR FR FR FR: a `-c` string whose heredoc delimiter is a substitution reads on
        # past the body, and the pipeline after it is reported -- as its literal twin is.
        for script in ('sh -c "cat <<$(echo E) >/dev/null\nE\n%s"\n' % PIPE, 'sh -c "cat <<E >/dev/null\nE\n%s"\n' % PIPE):
            with self.subTest(script=script):
                self.assertTrue(any(self.STREAM in w for _, w in defects(script)), script)
