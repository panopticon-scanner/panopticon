"""#2331, batch 3: the command and program forms the guard's reader missed.

Each class is one sub-issue of the epic: a spelling in which bash runs a
download -- bash 3.2.57 and GNU bash 5.2.21, every checksum failing -- that
the guard read clean, pinned as a live step, beside the controls that must
read as they did. The reader's own halves are in `tests/test_shell_reader.py`
and `tests/test_workflow_forms_regressions.py`.
"""
import unittest

import workflow_guard as wg

URL = "https://example.test/"
PIPE = "curl -fsSL %si.sh | sh" % URL
GET = "curl -fsSLo tool %stool\n" % URL


def defects(script):
    """The guard's answer for a job of one step running `script`."""
    return wg.job_defects([("step", script)])


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
    value from the middle of an option word."""

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

    def test_the_controls_read_as_they_did(self):
        # A value whose words fetch nothing, in a job that downloads nothing,
        # is not reported; with no word after it there is nothing to read.
        for script in ("X=-c\nsh $X 'echo hi'\n", "sh $X\n", "sh -o pipefail x.sh\n",
                       "bash $X/x.sh '%s'\n" % PIPE, "sh $'-e' '%s'\n" % PIPE):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))
        self.assertTrue(defects("sh -c '%s'\n" % PIPE))


class TestADynamicCommandWord(unittest.TestCase):
    """#2337: a command word that may expand to a shell."""

    def test_each_is_read(self):
        # A default that spells a shell is that shell; another dynamic word
        # handed `-c` makes the program after it a candidate (`candidates`).
        for script in ("${X:-sh} -c '%s'\n" % PIPE, '"${X:-bash}" -c \'%s\'\n' % PIPE,
                       "$CMD -c '%s'\n" % PIPE, "${X:-[s]h} -c '%s'\n" % PIPE,
                       GET + "${X:-sh} tool\n", GET + "CMD=sh\n$CMD -c 'sh tool'\n"):
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


class TestADynamicWordWhereTheProgramMayBe(unittest.TestCase):
    """#2344 and #2337 (review N2 of #2331): a `$` word after a value in a shell's
    options, or after a `$` command word's `-c`, may be the program. The guard
    reads it as a `-c` string (re-review R1-N1); one that reads as no program
    (`"$Y"`) or holds a `$(...)` is weighed as a literal `'echo hi'` is there,
    `Idle`, kept where the job holds a fetch the guard reports (#2481), not
    dropped."""

    def test_it_is_reported_where_the_job_fetches(self):
        # Bash 3.2.57, 5.2.21 and dash run the download in each once `$X`
        # is `-c` (`tool` beside `'echo hi'`), `$CMD` is `sh`, and `$Y` and
        # `$P` are `sh tool`.
        for script in (GET + 'sh $X "$Y"\n', GET + '$CMD -c "$P"\n', GET + 'sh $X "$(cat tool)"\n',
                       GET + "sh $X 'echo hi'\n"):
            with self.subTest(script=script):
                self.assertTrue(defects(script))
        # All three run these too. A download a variable carries gets that
        # `Idle` sentence, not #2341's: `carried` follows no value and no `$`
        # command word.
        for script, head in (('x=$(curl -fsSL %si.sh)\nX=-c\nsh $X "$x"\n' % URL, "passes `sh` `$X`"),
                             ('x=$(curl -fsSL %si.sh)\nCMD=sh\n$CMD -c "$x"\n' % URL,
                              "runs `$CMD` with `-c`")):
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
        # before this fix too; and the gap list's `sh -c "$P"` reads nothing,
        # though bash 3.2.57, 5.2.21 and dash run `tool` where `$P` is `sh tool`.
        for script in (GET + "sh $X\n", GET + 'sh -c "$P"\n'):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))


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

    def test_a_string_with_another_dollar_in_it_is_read_as_written(self):
        # The gap list's entry: bash runs both, but a live `$URL` makes the
        # text the shell gets one the reader does not know, and a single-
        # quoted `$` in the same word is counted as one.
        for script in ('URL=%si.sh\nbash -c "x=\\$(curl -fsSL $URL); eval \\"\\$x\\""\n' % URL,
                       'bash -c "x=\\$(curl -fsSL %si.sh)"\'; eval "$x"\'\n' % URL):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))


class TestAShellsSoleSubstitutionOperand(unittest.TestCase):
    """#2342 handed the reader bash's text, so `eval "sh \\$(echo tool)"` is
    `sh $(echo tool)`: a shell whose only operand is a value whose OUTPUT
    becomes its words, the program among them (C1 of #2331's final review).
    That value is the candidate, weighed `Idle`, kept where the job holds a
    fetch the guard reports.
    A `<(...)` hands the shell a file to read instead, and is not one."""

    def test_it_is_reported_where_the_job_fetches(self):
        # Bash 3.2.57, 5.2.21 and dash run the download in each.
        for script in (GET + 'eval "sh \\$(echo tool)"\n', GET + 'bash -c "sh \\$(echo tool)"\n',
                       GET + "sh $(echo tool)\n", GET + "sh `echo tool`\n"):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith("passes `sh` `$(...)`"), found)

    def test_it_is_not_reported_where_the_job_fetches_nothing(self):
        for script in ("sh $(echo tool)\n", 'eval "sh \\$(echo x.sh)"\n', "sh `echo tool`\n"):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))

    def test_a_process_substitution_hands_a_file_not_words(self):
        # Beside a download nothing is handed on; a `<(...)` that fetches is
        # read where it runs, once.
        for script in (GET + "sh <(echo 'echo hi')\n", GET + "bash <(echo true)\n"):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))
        found = defects("bash <(curl -fsSL %si.sh)\n" % URL)
        self.assertEqual(1, len(found), found)
        self.assertIn("straight to `bash`", found[0][1])


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

    def test_what_the_gap_list_leaves_is_read_as_before(self):
        # Bash runs both: another printer is not read, and a `$` producer in
        # a job with no download is `Idle`.
        for script in ("cat <<'EOF' | sh\n%s\nEOF\n" % PIPE, "X='%s'\necho \"$X\" | sh\n" % PIPE):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))


if __name__ == "__main__":
    unittest.main()
