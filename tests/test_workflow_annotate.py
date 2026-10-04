"""#2468, #2600, #2601: a step's own literal values read into a printer's `$X` and a `$CMD`.

`workflow_annotate.annotate` marks the raw statements once, in `workflow_guard.read`, before
`flattened` reads them: a printer's whole-reference word gets the reader's `spelled` text, and a
command word that is one becomes `shell_wrappers.Defaulted`, each only where the step's own table
holds one literal for the name. Unit pins first -- what is marked and what stays as written --
then the guard's rows. A guard row's comment carries its truth, b5 b3 dash gh (bash 5.2.21, bash
3.2.57, dash, a GitHub runner's bash with `sh` = dash, each `-e`; FR fetched and ran the download,
F- fetched only, -- neither, `+sha` the checksum ran, and failed), and the answer of the base
the module lands on.
"""
import unittest
from unittest import mock

import shell_reader
import workflow_annotate as wa
import workflow_guard as wg
from shell_wrappers import Defaulted

URL = "https://example.test/"
PIPE = "curl -fsSL %si.sh | sh" % URL
GET = "curl -fsSLo tool %stool\n" % URL
CHECK = "echo '%s  tool' | sha256sum -c -" % ("a" * 64)
USE = "chmod +x tool; ./tool\n"
STREAM = ("hands %si.sh straight to `sh`, so there is no file to check -- download it to a file, "
          "`sha256sum -c` that file, then run it" % URL)
UNVERIFIED = ("fetches %stool -> tool and making it executable with nothing verifying what "
              "arrived" % URL)
HANDED = ("hands a heredoc body or here-string to `%s`, a command word this guard does not "
          "follow -- its body is read as shell")
INSIDE = ("fetches %stool -> tool and making it executable; the checksum that names tool is "
          "inside the script `$CMD` runs, and the step does not stop when that script fails" % URL)
UNSPELLED = "pipes `%s` its program from `echo`, whose words this guard does not spell out"


def annotated(script):
    """The statements of `script` as `annotate` leaves them."""
    return wa.annotate(shell_reader.statements(script))


def stage_of(script, position=0):
    """A stage of the last statement of the annotated `script`, its first by default."""
    return annotated(script)[-1].stages[position]


def body(command, text=PIPE, end="", redirect=""):
    """`command` handed `text` as a quoted heredoc body, then `end`."""
    return "%s <<'EOF'%s\n%s\nEOF\n%s" % (command, redirect, text, end)


def defects(script):
    """The guard's sentences for a job of one step."""
    return [why for _name, why in wg.job_defects([("step", script)])]


class TestAPrintersWord(unittest.TestCase):
    """#2468: an `echo` or `printf` word that is ONE whole reference gets `spelled`."""

    def test_one_literal_is_spelled_on_the_word_as_written(self):
        rows = {'echo "$X" | sh': 1, "echo $X | sh": 1, 'echo "${X}" | sh': 1,
                "printf '%s\\n' \"$X\" | sh": 2, 'echo -n "$X" > f': 2}
        for use, at in rows.items():
            with self.subTest(use=use):
                word = stage_of("X='%s'\n%s\n" % (PIPE, use)).argv[at]
                self.assertEqual(PIPE, word.spelled)
                self.assertIn(word, ("$X", "${X}"))     # every other reader sees the word
                self.assertFalse(shell_reader.is_marker(word))

    def test_every_other_word_stays_as_written(self):
        # Two candidates, the stand-in of a lifted `$(...)`, `""`, a name never assigned; a value
        # a shell or the runner expands -- a reference, an operator expansion, a GitHub
        # expression, a quoted `$(...)`, a backquote, a process substitution; a reference with
        # text.
        for script in ("X='%s'\nif c; then X=other; fi\necho \"$X\" | sh\n" % PIPE,
                       'X=$(cat f)\necho "$X" | sh\n', 'X=\necho "$X" | sh\n',
                       'echo "$X" | sh\n', 'X="$Y"\necho "$X" | sh\n',
                       'X=${Y//a/b}\necho "$X" | sh\n', "X='${{ inputs.cmd }}'\necho \"$X\" | sh\n",
                       "X='echo $(%s)'\necho \"$X\" | sh\n" % PIPE,
                       "X='`echo sh` tool'\necho \"$X\" | sh\n",
                       "X='sh <(cat tool)'\necho \"$X\" | bash\n",
                       "X='%s'\necho \"$X\"/bin | sh\n" % PIPE,
                       "X='%s'\necho \"pre $X\" | sh\n" % PIPE):
            with self.subTest(script=script):
                word = stage_of(script).argv[1]
                self.assertFalse(hasattr(word, "spelled"), word)
                self.assertIn("$", word)

    def test_a_word_that_is_no_reference_is_untouched(self):
        argv = stage_of("X='%s'\necho hi \"$X\" | sh\n" % PIPE).argv
        self.assertEqual(["echo", "hi", "$X"], argv)
        self.assertFalse(hasattr(argv[1], "spelled"))
        self.assertEqual(PIPE, argv[2].spelled)

    def test_a_printer_a_command_word_resolves_to_is_read_too(self):
        argv = stage_of("P=echo\nX='%s'\n$P \"$X\" | sh\n" % PIPE).argv
        self.assertIsInstance(argv[0], Defaulted)
        self.assertEqual(["echo", "$X"], argv)
        self.assertEqual(PIPE, argv[1].spelled)


class TestACommandWord(unittest.TestCase):
    """#2600, #2601: the command word `command()` keeps, ONE whole reference, becomes
    `Defaulted` -- any name it holds, a shell or not."""

    def test_one_literal_becomes_the_name_it_holds(self):
        rows = (("CMD=sh\n" + body("$CMD"), 0, 0, "sh"),
                ("CMD=sh\n" + body('"$CMD"'), 0, 0, "sh"),
                ("CMD=sh\n" + body("${CMD}"), 0, 0, "sh"),
                ("CMD=true\n" + body("$CMD"), 0, 0, "true"),
                ("PYTHON=python3\n" + body("$PYTHON -", "print(1)"), 0, 0, "python3"),
                ("CAT=cat\n" + body("$CAT", redirect=" > i.sh"), 0, 0, "cat"),
                ("NODE=node\n" + body("$NODE -", "1"), 0, 0, "node"),
                ("CMD=sh\n" + body("X=1 $CMD"), 0, 1, "sh"),          # its prefix off
                ("CMD=sh\n" + body("env $CMD"), 0, 1, "sh"),          # behind a wrapper
                ("CMD=sh\ncurl -fsSL %si.sh | $CMD\n" % URL, 1, 0, "sh"))
        for script, position, at, name in rows:
            with self.subTest(script=script):
                stage = stage_of(script, position)
                word = stage.argv[at]
                self.assertIsInstance(word, Defaulted)
                self.assertEqual(name, word)
                self.assertIs(word, shell_reader.command(stage.argv)[0])

    def test_every_other_command_word_stays_as_written(self):
        # Two candidates, the stand-in, `""`, a name never assigned, a value holding a
        # reference; a blank or a pattern bash splits or globs, and any other text no plain
        # name; a text `command()` reads past -- an assignment's, a wrapper's, a keyword's; a
        # reference with text; and a `${X:-sh}` default, which `command()` reads as #2337's
        # shell before any value.
        for script in ("CMD=sh\nif c; then CMD=true; fi\n" + body("$CMD"),
                       "CMD=$(command -v sh)\n" + body("$CMD"), "CMD=\n" + body("$CMD"),
                       body("$CMD"), 'CMD="$SHELL"\n' + body("$CMD"),
                       "CMD='sh -e'\n" + body("$CMD"), "CMD='s*'\n" + body("$CMD"),
                       "CMD='`sh`'\n" + body("$CMD"), "CMD='sh;'\n" + body("$CMD"),
                       "A=X=1\n$A sh tool\n", "W=env\n$W sh tool\n", "K=if\n$K true\n",
                       "CMD=sh\n" + body("$CMD/x"), "CMD=true\n" + body("${CMD:-sh}")):
            with self.subTest(script=script):
                argv = stage_of(script).argv
                self.assertFalse(any(isinstance(word, Defaulted) for word in argv), argv)
                self.assertIn("$", argv[0])

    def test_a_word_bash_runs_no_command_at_is_never_marked(self):
        # The reader keeps each as a command word, but bash runs none there: a `case` subject,
        # and a word of an array literal it left unfolded in a `case` arm (#2348), which bash
        # assigns -- marked, either would be read as a command, or change the literal's word.
        for script in ("CMD=sh\ncase $CMD in\n  sh) echo hi ;;\nesac\n",
                       "X=sh\ncase $P in\n  a) A=(\"$X\") ;;\nesac\n",
                       "X='%s'\ncase $P in\n  a) A=(echo \"$X\") ;;\nesac\n" % PIPE):
            with self.subTest(script=script):
                words = [word for statement in annotated(script)
                         for stage in statement.stages for word in stage.argv]
                self.assertFalse([w for w in words if isinstance(w, Defaulted)
                                  or hasattr(w, "spelled") and w.startswith("$")], words)

    def test_the_statements_are_marked_in_place(self):
        stmts = shell_reader.statements("CMD=sh\n" + body("$CMD"))
        self.assertIs(stmts, wa.annotate(stmts))
        self.assertIsInstance(stmts[-1].stages[0].argv[0], Defaulted)

    def test_a_step_with_no_whole_reference_builds_no_table(self):
        # The cost: the table is built only at a statement one of whose words asks for it.
        with mock.patch.object(wa, "static_values", side_effect=AssertionError):
            wa.annotate(shell_reader.statements("X=1\necho hi | sh\nsh -c 'echo $X'\n"))


class TestAProducersValueIsWeighedAsItsText(unittest.TestCase):
    """#2468: `echo "$X" | sh` after `X='curl … | sh'` reads as the literal printer does."""

    def test_a_value_that_fetches_and_runs_is_reported_as_its_literal_twin(self):
        # FR FR FR FR on each; the base CLEAN on each. The twin `echo 'curl … | sh' | sh` gets
        # the #2333 sentence, and so does each: `echo`, `printf`, an unquoted `$X` (the same to
        # the reader), `bash -s`, and a printer reached through `P=echo`.
        self.assertEqual([STREAM], defects("echo '%s' | sh\n" % PIPE))
        for use in ('echo "$X" | sh\n', "printf '%s\\n' \"$X\" | sh\n", "echo $X | sh\n",
                    'echo "$X" | bash -s\n', 'P=echo\n$P "$X" | sh\n'):
            with self.subTest(use=use):
                self.assertEqual([STREAM], defects("X='%s'\n%s" % (PIPE, use)))

    def test_a_value_that_runs_nothing_reads_clean(self):
        # -- -- -- -- on both: nothing is fetched -- `sh` runs `echo hi`, or `other`, which is
        # not found. The base CLEAN on both, and so here, the value read.
        for script in ("X='echo hi'\necho \"$X\" | sh\n",
                       "X='%s'\nX=other\necho \"$X\" | sh\n" % PIPE):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))

    def test_a_value_the_table_cannot_place_reads_as_the_base(self):
        # The base's answer, CLEAN, on each, byte for byte: `X` never assigned (-- -- -- --); the
        # stand-in of a `$(...)` (-- -- -- --); and FR FR FR FR where `c` is no command, so `X`
        # keeps the download -- read as written because `if c` may assign `other`: two
        # candidates, the table's named limit, `Idle` in a job with no fetch, the base's gap.
        for script in ('echo "$X" | sh\n', 'X=$(cat f)\necho "$X" | sh\n',
                       "X='%s'\nif c; then X=other; fi\necho \"$X\" | sh\n" % PIPE):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))

    def test_a_value_that_expands_reads_as_the_base(self):
        # FR FR FR FR on each. The first value holds a `$(...)`, so it is no literal: the word
        # stays as written and the base's `Idle` CLEAN stands, its gap kept (the literal twin
        # `echo 'echo $(…)' | sh` is reported, unspelled). After a download, `$(echo sh) tool`,
        # a backquoted `echo sh` and `sh <(cat tool)` keep the base's unspelled-printer
        # sentence; spelled, each program would read CLEAN -- the reader reads the substitution
        # as text.
        self.assertEqual([], defects("X='echo $(%s)'\necho \"$X\" | sh\n" % PIPE))
        for value, shell in (("$(echo sh) tool", "sh"), ("`echo sh` tool", "sh"),
                             ("sh <(cat tool)", "bash")):
            with self.subTest(value=value):
                found = defects(GET + "X='%s'\necho \"$X\" | %s\n" % (value, shell))
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0].startswith(UNSPELLED % shell), found)

    def test_a_stream_that_goes_nowhere_moves_no_answer(self):
        # -- -- -- -- on both, the base CLEAN on both: the word is spelled, and `printed` is asked
        # only where a shell reads a program.
        for use in ('echo "$X" > f\n', 'echo "$X"\n'):
            with self.subTest(use=use):
                self.assertEqual([], defects("X='%s'\n%s" % (PIPE, use)))


class TestACommandWordReadsAsItsValue(unittest.TestCase):
    """#2600: `CMD=sh; $CMD <<'EOF'` reads as `sh <<'EOF'`, its check gated under its `-e`."""

    def step(self, command, assign="CMD=sh\n"):
        return GET + assign + body(command, CHECK, USE)

    def test_a_check_in_a_resolved_shells_body_credits(self):
        # F-+sha F-+sha F-+sha F-: every shell stops at the failed check. The base reported
        # the hand-off and the check as inside a script that does not stop the step; its
        # literal control `sh <<'EOF'` reads CLEAN, and so does the step, byte for byte.
        self.assertEqual([], defects(self.step("$CMD")))
        self.assertEqual(defects(self.step("sh")), defects(self.step("$CMD")))

    def test_a_value_that_skips_the_body_is_an_unverified_run(self):
        # FR FR FR FR on both: `true` and `cat` never run the check, and `./tool` runs. The
        # base: the hand-off and the check inside `$CMD`'s script; here, the literal twin's
        # unverified run.
        for value in ("true", "cat"):
            with self.subTest(value=value):
                found = defects(self.step("$CMD", "CMD=%s\n" % value))
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0].startswith(UNVERIFIED), found)
                self.assertEqual(defects(self.step(value, "CMD=%s\n" % value)), found)

    def test_a_word_the_table_cannot_place_reads_as_the_base(self):
        # FR FR FR FR (an unset `$CMD` runs nothing, then `./tool` runs) and F-+sha F-+sha F-+sha
        # F- (`c` is no command, so `CMD` stays `sh`): read as written -- a name never
        # assigned, and two candidates, the named limit. The base's answer on both, byte for
        # byte: the hand-off, then the check inside `$CMD`'s script.
        for assign in ("", "CMD=sh\nif c; then CMD=true; fi\n"):
            with self.subTest(assign=assign):
                found = defects(self.step("$CMD", assign))
                self.assertEqual(2, len(found), found)
                self.assertTrue(found[0].startswith(HANDED % "$CMD"), found)
                self.assertTrue(found[1].startswith(INSIDE), found)

    def test_a_word_behind_a_wrapper_is_resolved(self):
        # FR FR FR FR. The base: `env` holds a command operand it cannot read, and the stream;
        # here, `env sh <<'EOF'`'s answer, the stream alone.
        found = defects("CMD=sh\n" + body("env $CMD"))
        self.assertEqual([STREAM], found)
        self.assertEqual(defects("CMD=sh\n" + body("env sh")), found)


class TestAForeignOrWritingCommandWord(unittest.TestCase):
    """#2601: `$PYTHON -`, `$CAT <<'EOF' > f` and `$NODE -` read as their literal twins."""

    def test_each_reads_as_its_literal_twin(self):
        # -- -- -- -- on each: python prints the text, `cat` writes the body to a file, node
        # prints the template literal (measured with node on PATH, as the harness has none and
        # stops at rc 127). The base reported each: the hand-off, and the stream it read in the
        # body as shell. CLEAN, as the literal twin is.
        rows = (("PYTHON=python3\n", "$PYTHON -", "python3 -", 'print("$(%s)")' % PIPE, ""),
                ("CAT=cat\n", "$CAT", "cat", PIPE, " > i.sh"),
                ("NODE=node\n", "$NODE -", "node -", "console.log(`%s`)" % PIPE, ""))
        for assign, word, literal, text, redirect in rows:
            with self.subTest(word=word):
                found = defects(assign + body(word, text, redirect=redirect))
                self.assertEqual([], found)
                self.assertEqual(defects(assign + body(literal, text, redirect=redirect)), found)


class TestThePricesAndLimits(unittest.TestCase):
    """What `annotate` reads past bash, and what it leaves as the base read it."""

    def test_a_single_quoted_reference_over_reports(self):
        # -- -- -- --, the base CLEAN: bash prints `$X` for a child that holds no `X`; the reader
        # has lost the quotes and spells the value (the table's quoting price).
        self.assertEqual([STREAM], defects("X='%s'\necho '$X' | sh\n" % PIPE))

    def test_a_resolved_word_reads_as_its_literal_twin_prices_and_all(self):
        # -- -- -- -- on both. `$CMD -c "$P"`, the base CLEAN: `sh -c "$P"` hands its heredoc to
        # `$P` (#2599's named price), so the resolved word over-reports as its twin does. `$CMD
        # -K`, the base the hand-off and the stream: every shell refuses `-K`, and the twin
        # `sh -K` reads the stream alone, as `Defaulted` reads no letter as a refusal.
        for command, literal, count in (('$CMD -c "$P"', 'sh -c "$P"', 2),
                                        ("$CMD -K", "sh -K", 1)):
            with self.subTest(command=command):
                found = defects("CMD=sh\n" + body(command))
                self.assertEqual(count, len(found), found)
                self.assertEqual(defects("CMD=sh\n" + body(literal)), found)

    def test_the_defaulted_markers_rules_over_report_as_the_base_did(self):
        # -- -- -- -- and F- F- F- F-; the base reported both, and so here, where the literal twins
        # read CLEAN: `Defaulted` reads no option letter as a refusal (`sh -cK` runs nothing), and
        # a printer in its body both ways (bash's `echo` prints `sh\ttool`, which runs nothing).
        runs = "fetches %stool -> tool and running it under `sh` with nothing verifying" % URL
        for script, twin, said in (
                ("X=sh\n$X -cK '%s'\n" % PIPE, "X=sh\nsh -cK '%s'\n" % PIPE, STREAM),
                (GET + "CMD=bash\n" + body("$CMD", "echo 'sh\\ttool' | sh"),
                 GET + "CMD=bash\n" + body("bash", "echo 'sh\\ttool' | sh"), runs)):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0].startswith(said), found)
                self.assertEqual([], defects(twin))

    def test_a_value_bash_splits_reads_as_the_base(self):
        # `sh -e` FR FR FR FR and, before a check, F-+sha F-+sha F-+sha F-: bash splits the
        # value, so the word stays as written -- the base's answer byte for byte, the second an
        # over-report (the check is in a body read with gates off).
        found = defects("CMD='sh -e'\n" + body("$CMD"))
        self.assertEqual(2, len(found), found)
        self.assertTrue(found[0].startswith(HANDED % "$CMD"), found)
        self.assertEqual(STREAM, found[1])
        found = defects(GET + "CMD='sh -e'\n" + body("$CMD", CHECK, USE))
        self.assertEqual(2, len(found), found)
        self.assertTrue(found[1].startswith(INSIDE), found)

    def test_a_default_command_word_stays_the_shell_it_spells(self):
        # -- -- -- -- (`true` runs nothing), the base the stream: `${CMD:-sh}` is #2337's `sh`,
        # read before any value, so it over-reports as before.
        self.assertEqual([STREAM], defects("CMD=true\n" + body("${CMD:-sh}")))

    def test_an_empty_value_stays_as_written(self):
        # FR FR FR FR (the empty `$CMD` vanishes and `sh` reads the body), the base CLEAN, and so
        # here: the rule reads no empty value -- the base's gap (a FILE `sh` to the reader).
        self.assertEqual([], defects("CMD=\n" + body("$CMD sh")))

    def test_a_child_or_a_handed_script_inherits_no_mark(self):
        # FR FR FR FR on each, the base CLEAN on each, and so here: a `$(...)` child `_walk`
        # parses, and a `-c` string or a heredoc `flattened` parses (`X` exported), are read
        # after `annotate` -- the first cut's named limit, a follow-up.
        for script in ("X='%s'\ny=$(echo \"$X\" | sh)\n" % PIPE,
                       "export X='%s'\nbash -c 'echo \"$X\" | sh'\n" % PIPE,
                       "export X='%s'\n" % PIPE + body("sh", 'echo "$X" | sh')):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))


if __name__ == "__main__":
    unittest.main()
