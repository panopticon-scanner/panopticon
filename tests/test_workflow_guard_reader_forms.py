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
CHECK = 'echo "%s  tool" | sha256sum -c -' % ("a" * 64)
USE = "chmod +x tool\n./tool\n"
# What the guard says of a check inside a script handed on that clears nothing.
RUNS_ON = "inside the script `%s` runs, where no `-e` holds"
UNGATED = "inside the script `%s` runs, and the step does not stop when that script fails"


def defects(script):
    """The guard's answer for a job of one step running `script`."""
    return wg.job_defects([("step", script)])


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

    def test_numeric_ansi_c_escapes_spell_the_shells_c_option(self):
        # #2470: Bash 3.2 and 5.2 decode the hex and octal forms; Bash 5.2
        # also decodes both Unicode forms. Any supported shell can run the
        # program, so each spelling must expose its fetch-and-execute.
        for option in (r"$'-\x63'", r"$'-\143'", r"$'-\u0063'", r"$'-\U00000063'"):
            with self.subTest(option=option):
                found = defects("sh %s '%s'\n" % (option, PIPE))
                self.assertEqual(1, len(found), found)
                self.assertIn("hands %si.sh straight to `sh`" % URL, found[0][1])

    def test_an_ansi_c_code_point_outside_ascii_fails_closed(self):
        found = defects("sh $'-\\u00e9' '%s'\n" % PIPE)
        self.assertEqual(1, len(found), found)
        self.assertIn("cannot read this step", found[0][1])
        self.assertIn("outside ASCII", found[0][1])

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
                       "sh $'-\\x63' 'echo hi'\n"):
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

    def test_it_is_reported_where_the_job_holds_a_reported_fetch(self):
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
        # before this fix too. The literal shell's own `sh -c "$P"` was the
        # other half of that entry and is read now (#2483, below).
        self.assertEqual([], defects(GET + "sh $X\n"))


class TestADynamicProgramWordALiteralShell(unittest.TestCase):
    """#2483: a program word a LITERAL shell takes that is entirely expansion
    -- `sh -c "$P"`, `eval "$P"` -- spells no command, so `flattened` read it
    as nothing at all and the step read CLEAN while bash runs the download
    once `$P` is `sh tool`. One rule now for such a word wherever a shell
    takes one: `Idle`, kept where the job holds a fetch the guard reports,
    exactly as the `$CMD -c "$P"` twin is."""

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
                       GET + check + 'sh -c "$P"\n'):
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
        # as it always has -- `echo` fetches nothing, and a `$(...)` marker is
        # text the guard's own walk reads.
        for script in (GET + 'sh -c "echo $X"\n', GET + 'sh -c "$(cat tool)"\n'):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))
        found = defects(GET + 'sh -c "curl -fsSL $U | sh"\n')
        self.assertEqual(1, len(found), found)
        self.assertIn("straight to `sh`", found[0][1])


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
    counted only under the `-e` of the shell sure to read the body, behind a
    bare command line (round 1 of the review). Every step below was run in
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
      `X=-c` twins, which run nothing (#2485), and `CMD=sh` whose body ends in
      the check (#2473), where the reader cannot tell the word from one that
      runs the body (`X=-s`) or skips it (`CMD=true`), and `$CMD "$X"` with
      `X` empty and `$PYTHON -Ou file.py` with a download body, whose walks
      now read on as a shell's, and `$CMD -o -` and `$CMD -oe - x.sh`, whose
      `-` is read as stdin though a shell refuses it as `-o`'s value (#2473);
      `$NODE -e "$CODE"` and `$PYTHON -m "$MOD"` with a download body, alone
      and beside GET, whose own option value spelled `$` the walk reads past
      as a vanishing operand, though neither reads the heredoc (#2473);
      a letter bash and dash refuse, read on as the operand walk reads `sh -K`
      (#2475 stops only a `-c` cluster): behind a value (`X=-K; sh $X`,
      #2485), a `$` word (`CMD=sh; $CMD -K`, #2473) or an inner shell
      (`eval 'bash -K -s'`, `bash -c 'sh -K'`, #2500); `eval -- bash -s`,
      whose `--` dash runs as a command; seventy `eval`s before `echo hi`,
      read as a stdin shell past the credit's 64-deep bound (#2500); and a
      non-shell body under a `$` word whose string spells a shell download
      (`print("$(curl ... | sh)")` under `$PYTHON -`, a `$CAT <<'EOF' > i.sh`
      body), read as shell and reported loud, filed under #2331; a check read
      past a value or a word that may vanish (`X=-s`, `X=-e`, `X` unset,
      `$(true)`), where the guard cannot tell the word from `X=/dev/null`
      (#2485), or behind a string whose command line is not bare -- `exec`,
      `env`, `time`, `sudo`, `command`, an assignment or `!` in front,
      `--norc`, `-o errexit`, `+e` or an operand on it -- or seventy `eval`s
      deep, past that 64-deep bound, or ahead of `|| exit 1`, which is no `-e`
      (#2500), each counting for nothing since round 1, though no shell runs
      the download; `eval 'bash -s &'` and `eval 'bash -s < /dev/null'` around
      a body no shell runs (round 1); and, as before round 1, a check in an
      `if` branch, which clears no use outside it, and the body of
      `builtin eval`, which the guard does not take for `eval`;
    * `Idle` hand-offs beside a download that never runs (`$CMD` with
      `echo hi`, `$PYTHON -`, `python3 -` and `${X:-/usr/bin/python3} -` with
      `print(1)`, `$PYTHON -s file.py`, `$PYTHON -Ou file.py` and
      `$PYTHON -O file.py` with `print(1)`, whose `-s` and `O` read as a
      shell's, `x=$(echo hi | $CMD)` and its `$(echo sh)` twin, and the
      `$CMD -c "$P"` candidate (#2337), each beside GET): a report of a
      program the guard cannot read, kept beside a fetch it reports (#2499),
      not a claim that a download runs;
    * fail-open readings: `$CMD <<EOF` expanding, and `$PYTHON -`,
      `python3 -`, `$PYTHON -Ou - file.py` or `python3 -O - file.py` running
      `os.system`, beside no reported fetch (option b's price, #2499); and,
      each filed under #2331, `eval 'bash -s | cat'` (#2500),
      `echo "$Y" | $CMD`, `x=$($CMD <<'EOF' ...)`, and `eval "$CMD"` or an
      exported `bash -c '$CMD'` handed a heredoc alone -- beside a reported
      fetch #2483 reports the word, never the body (#2473). Round 1 leaves two
      more, each filed under #2331 too: a literal stdin shell whose options
      keep it from running its program (`bash -n -s`, `bash -t -s`,
      `bash -s -c true`, `bash --version`, and `SHELLOPTS=noexec bash -s`
      under a dash step), which `main` reads the same way, and a function that
      shadows the shell's name (`sh() { :; }` before `eval 'sh'`).

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
        # Review I-1, closed in round 1: this inherited body is read under the
        # `-e` of its READER, the inner `bash -s` or `sh` -- which has none --
        # not the enclosing command's, so a check gated only by `-e` is
        # reported, naming the inner shell, as in the literal twins:
        # `bash tool` runs in all three shells past `sha256sum -c -`'s failure.
        check = "echo '%s  tool' | sha256sum -c -\nbash tool\n" % ("a" * 64)
        gated_body = GET + check
        for script, reader in (("eval 'bash -s' <<'EOF'\n%sEOF\n" % gated_body, "bash"),
                               ("bash -ec 'sh' <<'EOF'\n%sEOF\n" % gated_body, "sh"),
                               ("bash -s <<'EOF'\n%sEOF\n" % gated_body, "bash"),
                               ("bash -c 'sh' <<'EOF'\n%sEOF\n" % gated_body, "sh")):
            with self.subTest(script=script):
                found = defects(script)
                self.assertTrue(any(RUNS_ON % reader in w for _, w in found), found)
        # N-5's documented, filed gap: a pipeline whose FIRST stage reads
        # stdin is never reached here (the recursive check keeps to a single
        # STAGE, `len(parsed[0].stages) == 1`) -- bash runs `bash -s` as that
        # first stage with `eval`'s own heredoc as ITS stdin regardless, so
        # this CLEAN is a known false negative, not a claim nothing downloads.
        self.assertEqual([], defects("eval 'bash -s | cat' <<'EOF'\n%s\nEOF\n" % PIPE))
        # Where #2475's letter table meets this credit (#2551, the third
        # fold): a `-c` cluster the OUTER shell refuses hands over no string
        # (`_past_options`), so `bash -c -K 'sh'` reads CLEAN -- bash 3.2.57,
        # 5.2.21 and dash exit 2 and run nothing; before the fold it was read.
        # An INNER shell's refused letter is read on, as the operand walk
        # reads a literal `sh -K <<'EOF'`, so `eval 'bash -K -s'` and `bash -c
        # 'sh -K'` stay credited and report the stream though all three
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
        # uncaught RecursionError. The credit now looks at most 64 strings
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

    def test_2473_a_dollar_command_words_body_is_read_as_shell_and_its_hand_off_weighed(self):
        # A value-form command word (`$CMD`, `"$CMD"`, `${CMD}`, `$(echo sh)`,
        # `$PYTHON -`) is a name no table places: `stdin_program` answers
        # VALUE_PROGRAM. Its QUOTED body is read as shell, additively -- a
        # download there is the defect it is at the top level -- and the
        # hand-off is `Idle`, under its own sentence, which `kept` stands only
        # beside a fetch the guard reports (#2499).
        def to(word):
            return ("hands a heredoc body or here-string to `%s`, a command word this guard "
                    "does not follow -- a quoted body is read as shell" % word)

        def reasons(script):
            return [why for _step, why in defects(script)]

        streamed = "straight to `sh`"
        # (a) The issue's own pin: both reasons stand and do not contradict --
        # the stream, found by reading the body, and the hand-off, kept since
        # the job now holds a fetch the guard reports.
        for script, word in (("CMD=sh\n$CMD <<'EOF'\n%s\nEOF\n" % PIPE, "$CMD"),
                             ('CMD=sh\n"$CMD" <<\'EOF\'\n%s\nEOF\n' % PIPE, "$CMD"),
                             ("CMD=sh\n${CMD} <<'EOF'\n%s\nEOF\n" % PIPE, "${CMD}")):
            with self.subTest(script=script):
                found = reasons(script)
                self.assertEqual(2, len(found), found)
                self.assertTrue(any(streamed in w for w in found), found)
                self.assertTrue(any(w.startswith(to(word)) for w in found), found)
        # #2475's per-shell scoping (#2551) reads no option word behind a `$`
        # word as a refusal -- `CMD` may hold zsh, which runs `-K` -- so
        # `CMD=sh; $CMD -K <<'EOF'` reads as (a) does, both reasons kept,
        # though bash 3.2.57, 5.2.21 and dash exit 2 at `-K` and run nothing:
        # this rule's fail-closed price, named in `stdin_program`'s docstring.
        # A `${X:-sh}` default is the shell it spells (`shell_wrappers.
        # Defaulted`), never a VALUE: its body is read and no hand-off said.
        script = "CMD=sh\n$CMD -K <<'EOF'\n%s\nEOF\n" % PIPE
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
        self.assertEqual([], reasons("CMD=sh\n$CMD <<'EOF'\necho hi\nEOF\n"))
        found = reasons(GET + "CMD=sh\n$CMD <<'EOF'\necho hi\nEOF\n")
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0].startswith(to("$CMD")), found)
        # (c) An EXPANDING body is read nowhere: alone it is CLEAN though the
        # shells run its download -- option b's price, the one `python3 -
        # <<EOF` pays on main. Beside a reported fetch the hand-off is kept,
        # under its own sentence, never the EXPANDING one.
        self.assertEqual([], reasons("CMD=sh\n$CMD <<EOF\n%s\nEOF\n" % PIPE))
        found = reasons(GET + "CMD=sh\n$CMD <<EOF\n%s\nEOF\n" % PIPE)
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0].startswith(to("$CMD")), found)
        self.assertNotIn("EXPANDING", found[0])
        # (d) `$PYTHON - <<'EOF'` is kept and dropped where `python3 - <<'EOF'`
        # is -- CLEAN alone, an innocuous body or an `os.system` download alike
        # (option b's price again: python runs that download) -- under its own
        # sentence: the literal gets the foreign-language one, `$PYTHON` the
        # hand-off naming it.
        for body in ("print(1)\n", "import os\nos.system('%s')\n" % PIPE):
            dollar = "PYTHON=python3\n$PYTHON - <<'EOF'\n%sEOF\n" % body
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
        for script, word in (("PYTHON=python3\n$PYTHON - <<'EOF'\n%s\nEOF\n" % printing, "$PYTHON"),
                             ("CAT=cat\n$CAT <<'EOF' > i.sh\n%s\nEOF\n" % PIPE, "$CAT")):
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
        # is (#2333), with no hand-off sentence. Text no printer spells out is
        # not read: `echo "$Y" | $CMD` reads CLEAN though the shells run its
        # download, the gap the guard's list files under #2331.
        found = reasons("CMD=sh\necho '%s' | $CMD\n" % PIPE)
        self.assertEqual(1, len(found), found)
        self.assertIn(streamed, found[0])
        self.assertEqual([], reasons("CMD=sh\necho hi | $CMD\n"))
        self.assertEqual([], reasons("CMD=sh\nY='%s'\necho \"$Y\" | $CMD\n" % PIPE))
        # A literal name's FILE operand is unaffected: #2473 only reaches a
        # value-form command word, never a literal one.
        self.assertEqual([], reasons("python3 x.py\n"))

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
        for script in (GET + "CMD=true\n$CMD <<'EOF'\n%s\nEOF\n" % check + use,
                       GET + "CMD=cat\n$CMD <<'EOF'\n%s\nEOF\n" % check + use,
                       GET + 'CMD=true\necho "%s" | $CMD\n' % check + use,
                       GET + 'CMD=true\n$CMD <<< "%s"\n' % check + use):
            with self.subTest(script=script):
                found = [w for _step, w in defects(script)]
                self.assertTrue(any(ungated % "$CMD" in w for w in found), found)
        # The controls: with no check the step is FLAGGED, and a literal `sh`
        # whose body ends in the check is CLEAN -- its failure stops `sh`, and
        # `-e` the step, in all three shells. Behind `CMD=sh` the same body is
        # FLAGGED: a fail-closed over-report, since the reader cannot tell
        # `CMD=sh` from `CMD=true`.
        found = [w for _step, w in defects(GET + use)]
        self.assertEqual(1, len(found), found)
        self.assertIn("nothing verifying what arrived", found[0])
        self.assertEqual([], defects(GET + "sh <<'EOF'\n%s\nEOF\n" % check + use))
        found = [w for _step, w in defects(GET + "CMD=sh\n$CMD <<'EOF'\n%s\nEOF\n" % check + use)]
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

    def test_2473_a_dollar_command_words_body_inside_a_substitution_is_unread(self):
        # A documented gap, filed under #2331: `_walk` asks `_unread_stdin`
        # before `unread_program`, so inside a `$(...)` the hand-off's `Idle`
        # answers first and `substitution_script`, which would read the body
        # and report its download, is never asked. Beside no reported fetch
        # the step reads CLEAN though bash 3.2.57, 5.2.21 and dash run that
        # download; the literal `sh` there is reported (the control).
        for script in ("CMD=sh\nx=$($CMD <<'EOF'\n%s\nEOF\n)\n" % PIPE,
                       "x=$($(echo sh) <<'EOF'\n%s\nEOF\n)\n" % PIPE):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))
        found = defects("x=$(sh <<'EOF'\n%s\nEOF\n)\n" % PIPE)
        self.assertEqual(1, len(found), found)
        self.assertIn("inside a command substitution", found[0][1])

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

    def test_2473_a_dollar_word_an_eval_or_dash_c_string_runs_is_unread(self):
        # A documented gap, filed under #2331: #2500's credit stays
        # SHELL_PROGRAM's, so a `-c` or `eval` string whose one statement is a
        # `$` command word makes no stdin shell of the command around it, and
        # its body is never read, though bash 3.2.57, 5.2.21 and dash run it.
        # Alone the step reads CLEAN; beside a reported fetch #2483 reports
        # the WORD (`dynamic_program`, `Idle`), never the stream in the body.
        # The literal `eval 'bash -s'` is caught (the control).
        found = defects("eval 'bash -s' <<'EOF'\n%s\nEOF\n" % PIPE)
        self.assertTrue(any("straight to `sh`" in w for _step, w in found), found)
        for runs, said in (("CMD=sh\neval \"$CMD\"", "runs `eval` on `$CMD`"),
                           ("export CMD=sh\nbash -c '$CMD'", "runs `bash -c` on `$CMD`")):
            script = "%s <<'EOF'\n%s\nEOF\n" % (runs, PIPE)
            with self.subTest(script=script):
                self.assertEqual([], defects(script))
                found = [w for _step, w in defects(GET + script)]
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0].startswith(said), found)
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
                    "does not follow -- a quoted body is read as shell" % word)

        def reasons(script):
            return [why for _step, why in defects(script)]

        streamed = "straight to `sh`"
        for script in ("CMD=bash\n$CMD -s -- \"$V\" <<'EOF'\n%s\nEOF\n" % PIPE,
                       "CMD=bash\n$CMD -s arg <<'EOF'\n%s\nEOF\n" % PIPE,
                       "CMD=bash\n$CMD -x -s x <<'EOF'\n%s\nEOF\n" % PIPE,
                       "CMD=sh\n$CMD $X <<'EOF'\n%s\nEOF\n" % PIPE):     # X unset
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
        script = GET + "CMD=sh\n$CMD -c \"$P\" <<'EOF'\n%s\nEOF\n" % PIPE
        with self.subTest(script=script):
            found = reasons(script)
            self.assertEqual(1, len(found), found)
            self.assertTrue(found[0].startswith("runs `$CMD` with `-c`"), found)
        for script in ("CMD=sh\n$CMD -c \"$P\" <<'EOF'\n%s\nEOF\n" % PIPE,
                       "CMD=bash\n$CMD -c <<'EOF'\n%s\nEOF\n" % PIPE,
                       "CMD=sh\n$CMD -- x.sh <<'EOF'\n%s\nEOF\n" % PIPE,
                       "CMD=sh\n$CMD file <<'EOF'\n%s\nEOF\n" % PIPE,
                       "python3 $S <<'EOF'\n%s\nEOF\n" % PIPE,
                       "PYTHON=python3\n$PYTHON - <<'EOF'\nprint(1)\nEOF\n"):
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
        script = "CMD=sh\n$CMD \"$X\" <<'EOF'\n%s\nEOF\n" % PIPE
        with self.subTest(script=script):
            found = reasons(script)
            self.assertEqual(2, len(found), found)
            self.assertTrue(any(streamed in w for w in found), found)
        python = "PYTHON=python3\n$PYTHON -s file.py <<'EOF'\nprint(1)\nEOF\n"
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
        for word, step in (("$NODE", "NODE=/usr/local/bin/node\n$NODE -e \"$CODE\""),
                           ("$PYTHON", "PYTHON=python3\n$PYTHON -m \"$MOD\"")):
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
                    "does not follow -- a quoted body is read as shell" % word)

        def reasons(script):
            return [why for _step, why in defects(script)]

        streamed = "straight to `sh`"
        for script in ("CMD=bash\n$CMD -oe pipefail <<'EOF'\n%s\nEOF\n" % PIPE,
                       "CMD=sh\n$CMD -o pipefail <<'EOF'\n%s\nEOF\n" % PIPE,
                       "CMD=bash\n$CMD -O extglob <<'EOF'\n%s\nEOF\n" % PIPE):
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
            python = "PYTHON=python3\n$PYTHON %s file.py <<'EOF'\nprint(1)\nEOF\n" % flags
            with self.subTest(script=python):
                self.assertEqual([], reasons(python))
            with self.subTest(script=GET + python):
                found = reasons(GET + python)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0].startswith(to("$PYTHON")), found)
        script = "PYTHON=python3\n$PYTHON -Ou file.py <<'EOF'\n%s\nEOF\n" % PIPE
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
        for step, why in (("PYTHON=python3\n$PYTHON -Ou - file.py", to("$PYTHON")),
                          ("python3 -O - file.py", foreign),
                          ("PYTHON=python3\n$PYTHON -OO -", to("$PYTHON"))):
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
        for script in ("CMD=bash\n$CMD -o - <<'EOF'\n%s\nEOF\n" % PIPE,
                       "CMD=bash\n$CMD -oe - x.sh <<'EOF'\n%s\nEOF\n" % PIPE):
            with self.subTest(script=script):
                found = reasons(script)
                self.assertEqual(2, len(found), found)
                self.assertTrue(any(streamed in w for w in found), found)
                self.assertTrue(any(w.startswith(to("$CMD")) for w in found), found)

    # Round 1 of the review: WHOSE program a stdin text is decides whether a
    # check in it counts (`workflow_programs.Stdin`). Each step below hands a
    # shell a body holding the check of `tool` (`stdin_step`); the shells are
    # bash 5.2.21 and 3.2.57 under `-e` and `-eo pipefail`, and dash under `-e`.
    # A method that pins a reading reported also asserts the credit that
    # stands where its mechanism is absent: the must-trip control.
    ECHOED = CHECK + "\necho done"
    USED = CHECK + "\n" + USE.rstrip("\n")

    def assert_reported(self, rows):
        """Each (step, how many defects it has, what one of them says)."""
        for script, count, said in rows:
            with self.subTest(script=script):
                found = [why for _step, why in defects(script)]
                self.assertEqual(count, len(found), found)
                self.assertTrue(any(said in why for why in found), found)

    def assert_clean(self, scripts):
        for script in scripts:
            with self.subTest(script=script):
                self.assertEqual([], defects(script))

    def test_2500_a_check_the_inner_shell_carries_on_past_is_reported(self):
        # The review's blocker: behind `eval` or `-c` the body is the INNER
        # shell's program, which has no `-e`. Every shell carries on past the
        # failed check, exits 0, and the step runs the download (rc 0).
        runners = (("eval 'bash -s'", "bash"), ("eval bash -s", "bash"), ("eval 'sh'", "sh"),
                   ("bash -ec 'sh'", "sh"))
        self.assert_reported((stdin_step(runner, body), count, RUNS_ON % reader)
                             for runner, reader in runners
                             for body, count in ((self.ECHOED, 1), (self.USED, 1),
                                                 (GET + self.USED, 2)))
        # The same in a here-string and in an `echo` piped in: every shell runs
        # the download, bar dash at the here-string, which it refuses (rc 2).
        self.assert_reported([
            (stdin_step("eval 'bash -s'", self.ECHOED, "here-string"), 1, RUNS_ON % "bash"),
            (stdin_step("eval 'bash -s'", self.ECHOED, "piped"), 1, RUNS_ON % "bash"),
            (stdin_step("bash -ec 'sh'", self.ECHOED, "piped"), 1, RUNS_ON % "sh"),
            (stdin_step("eval 'sh'", self.USED, "piped"), 1, RUNS_ON % "sh")])
        # The controls: with the check as the whole body, or under the inner
        # shell's own `-e`, every shell stops at it (rc 1; dash at a
        # here-string, which it refuses, rc 2).
        self.assert_clean([stdin_step(runner) for runner, _reader in runners] + [
            stdin_step("eval 'bash -s'", CHECK, "here-string"),
            stdin_step("eval 'bash -s'", CHECK, "piped"),
            stdin_step("bash -ec 'sh'", CHECK, "piped"), stdin_step("eval 'sh'", CHECK, "piped"),
            stdin_step("eval 'bash -e -s'", self.ECHOED),
            stdin_step("bash -ec 'sh -e'", self.ECHOED)])

    def test_2500_a_check_that_ends_a_bare_inner_shells_body_is_credited(self):
        # The check is the inner shell's last command, so its failure is that
        # shell's status and the `eval`'s or `-c`'s: every shell stops the step
        # there (rc 1), bar dash at a here-string, which it refuses (rc 2).
        self.assert_clean(stdin_step(runner, CHECK, form)
                          for runner in ("eval 'bash -s'", "eval bash -s", "eval 'sh'",
                                         "bash -c 'sh'", "bash -ec 'sh'")
                          for form in ("heredoc", "here-string", "piped"))

    def test_2500_what_stands_around_the_inner_command_voids_its_check(self):
        # `!` turns the check's failure into success; behind `sudo` or an
        # assignment the body carries on past it; `&` hands the inner shell
        # `/dev/null`, `<` another file and `<&-` no stdin, so it never reads
        # the body. Every shell runs the download (rc 0) -- under
        # `SHELLOPTS=noexec` dash only: the bashes refuse that readonly
        # variable (rc 1).
        rows = [(stdin_step(runner, body), 1, UNGATED % name) for runner, body, name in (
            ("eval '! bash -s'", CHECK, "eval"), ("bash -c '! sh'", CHECK, "bash"),
            ("eval '! bash -e -s'", CHECK, "eval"), ("eval 'bash -s &'", CHECK, "eval"),
            ("eval 'bash -s < /dev/null'", CHECK, "eval"), ("eval 'bash -s <&-'", CHECK, "eval"),
            ("eval 'SHELLOPTS=noexec bash -s'", CHECK, "eval"),
            ("eval 'sudo bash -s'", self.ECHOED, "eval"),
            ("eval 'X=1 bash -s'", self.ECHOED, "eval"),
            ("eval 'bash -s' '</dev/null'", CHECK, "eval"))]
        self.assert_reported(rows)
        # The controls: the bare command, a subshell around it and another
        # descriptor's redirection behind it keep the credit, and so does the
        # inner shell's own `-e` without the `!`: every shell stops (rc 1).
        self.assert_clean([stdin_step("eval 'bash -s'"), stdin_step("bash -c 'sh'"),
                           stdin_step("eval '(bash -s)'"), stdin_step("eval 'bash -s 2>/dev/null'"),
                           stdin_step("eval 'bash -e -s'", self.ECHOED)])

    def test_2500_an_inner_option_that_keeps_the_program_from_running_voids_its_check(self):
        # `-n` and `-o noexec` run nothing, `-t` one command, `-s -c true` the
        # string and `--version` no program: the inner shell exits 0 without the
        # check, and every shell runs the download (rc 0).
        rows = [(stdin_step(runner, body), 1, UNGATED % name) for runner, body, name in (
            ("eval 'bash -n -s'", CHECK, "eval"), ("bash -c 'sh -n'", CHECK, "bash"),
            ("eval 'bash -s -c true'", CHECK, "eval"), ("eval 'bash --version'", CHECK, "eval"),
            ("eval 'bash -o noexec -s'", CHECK, "eval"), ("eval bash -n -s", CHECK, "eval"),
            ("eval 'bash -t -s'", "echo start\n" + CHECK, "eval"))]
        self.assert_reported(rows)
        # The controls: options of `-e`, `-u` and `-x` alone keep the credit,
        # and with no option the check that ends a body after an `echo` is
        # credited: every shell stops at it (rc 1).
        self.assert_clean([stdin_step("eval 'bash -s'"), stdin_step("eval 'bash -x -s'"),
                           stdin_step("eval 'bash -eu -s'", self.ECHOED),
                           stdin_step("bash -c 'sh -e'", self.ECHOED),
                           stdin_step("eval 'bash -s'", "echo start\n" + CHECK)])

    def test_2500_a_word_the_join_drops_or_bash_expands_voids_its_check(self):
        # A `$(...)`, backquote or `$N` that comes to `-n` hands the inner shell
        # that option -- `eval` joins its words, and a double-quoted string is
        # expanded first -- so it runs nothing, and every shell runs the
        # download (rc 0).
        self.assert_reported([
            (stdin_step("eval 'bash -s' $(printf %s -n)"), 1, UNGATED % "eval"),
            (stdin_step("eval 'bash -s' \"$(printf %s -n)\""), 1, UNGATED % "eval"),
            (stdin_step("eval 'bash -s' `printf %s -n`"), 1, UNGATED % "eval"),
            (stdin_step("eval 'bash -s' $N", pre="N=-n\n"), 2, UNGATED % "eval"),
            (stdin_step('eval "bash -s $N"', pre="N=-n\n"), 1, UNGATED % "eval"),
            (stdin_step('bash -c "sh $N"', pre="N=-n\n"), 1, UNGATED % "bash")])
        # The controls: with no such word, or one a comment in the string
        # swallows, the credit stands: every shell stops at the check (rc 1).
        self.assert_clean([stdin_step("eval 'bash -s'"), stdin_step("eval 'bash -s #' -n"),
                           stdin_step("bash -c 'sh'")])

    def test_2485_no_check_past_a_word_that_may_name_a_file_counts(self):
        # A word that may vanish may name a FILE instead: `sh /dev/null` runs
        # that file and no shell reads the body, so every shell runs the
        # download (rc 0); with `X=-s` behind a string, `sh -s` carries on past
        # the check, with no `-e`.
        self.assert_reported([
            (stdin_step("sh $X", pre="X=/dev/null\n"), 1, UNGATED % "sh"),
            (stdin_step("sh ${X:-/dev/null}"), 1, UNGATED % "sh"),
            (stdin_step('sh "$@"', pre="set -- /dev/null\n"), 1, UNGATED % "sh"),
            (stdin_step("bash $(echo /dev/null)"), 2, UNGATED % "bash"),
            (stdin_step("sh $X -s", pre="X=/dev/null\n"), 2, UNGATED % "sh"),
            (stdin_step("bash -c 'sh $X'", pre="export X=/dev/null\n"), 1, UNGATED % "bash"),
            (stdin_step("eval 'sh $X'", self.ECHOED, pre="X=-s\n"), 1, UNGATED % "eval")])
        # The price: `X=-s` reads the body and every shell stops at the check
        # (rc 1; dash refuses the here-string, rc 2), but the guard cannot tell
        # it from `X=/dev/null`.
        self.assert_reported((stdin_step("sh $X", CHECK, form, pre="X=-s\n"), 1, UNGATED % "sh")
                             for form in ("heredoc", "here-string", "piped"))
        # The controls: a literal shell, and one behind a string with no value
        # in it, keep the credit: every shell stops at the check (rc 1).
        self.assert_clean([stdin_step("sh"), stdin_step("bash -s"), stdin_step("bash -c 'sh'"),
                           stdin_step("eval 'sh'")])

    def test_2500_the_holders_own_command_line_voids_its_check(self):
        # A `-c` shell given `-n`, `--version` or `-o noexec` runs nothing of
        # its string, so no inner shell reads the body and every shell runs the
        # download (rc 0) -- under `SHELLOPTS=noexec` dash only, the bashes
        # refusing that readonly variable (rc 1); `bash -c -e`'s `-e` is the
        # holder's, and the inner `sh` carries on past the check.
        self.assert_reported([(stdin_step(runner), 1, UNGATED % name) for runner, name in (
            ("bash -nc 'sh'", "bash"), ("bash -n -c 'sh'", "bash"),
            ("bash --version -c 'sh'", "bash"), ("SHELLOPTS=noexec bash -c 'sh'", "bash"),
            ("bash -o noexec -c 'sh'", "bash"), ("sh -c 'bash -nc \"sh\"'", "sh"))]
            + [(stdin_step("bash -c -e 'sh'", self.ECHOED), 1, RUNS_ON % "sh")])
        # The controls: a holder of `-c`, `-e`, `-u` and `-x` alone keeps the
        # credit, nested or not, and so does `bash -c -e` with the check as the
        # whole body: every shell stops at it (rc 1).
        self.assert_clean([stdin_step("bash -c 'sh'"), stdin_step("bash -euxc 'sh'"),
                           stdin_step("bash -c -e 'sh'"), stdin_step("sh -c 'bash -c \"sh\"'")])

    def test_2500_a_check_counts_under_a_bare_inner_shells_own_e(self):
        # Credits kept: the inner shell's own `-e`, its `-u` or `-x`, a
        # subshell, a string in a string, the holder's `-e`, `-u`, `-x` or a
        # `$0` after its string, a `{` in front at the step's level, a comment,
        # a check that ends the body, a `set -e`, another descriptor's
        # redirection. Every shell stops the step at the check (rc 1).
        self.assert_clean([
            stdin_step("eval 'bash -e -s'", self.ECHOED),
            stdin_step("bash -c 'sh -e'", self.ECHOED),
            stdin_step("bash -ec 'sh -e'", self.ECHOED), stdin_step("eval 'bash -x -s'"),
            stdin_step("eval 'bash -eu -s'", self.ECHOED), stdin_step("eval '(bash -s)'"),
            stdin_step("eval '(bash -e -s)'", self.ECHOED), stdin_step("sh -c 'bash -c \"sh\"'"),
            stdin_step("eval 'eval \"bash -s\"'"),
            stdin_step("eval 'eval \"bash -es\"'", self.ECHOED),
            stdin_step("sh -c 'bash -c \"sh -e\"'", self.ECHOED), stdin_step("bash -euxc 'sh'"),
            stdin_step("bash -c -e 'sh'"), stdin_step("bash -c 'sh' -n"),
            stdin_step("{ eval 'bash -s'", end="}\n"), stdin_step("eval 'bash -s #' -n"),
            stdin_step("eval 'bash -s'", "echo start\n" + CHECK),
            stdin_step("eval 'bash -s'", "set -e\n" + self.ECHOED),
            stdin_step("eval 'bash -s 2>/dev/null'")])

    def test_2500_the_prices_of_a_check_counting_only_behind_a_bare_command_line(self):
        # Reported though no shell runs the download: every shell stops the
        # step at the check (rc 1 -- under dash `time eval` runs the program
        # `time`, which finds no `eval`, rc 127), and nothing of a body the
        # inner shell reads in the background or from `/dev/null` runs at all
        # (rc 0, no fetch). A wrapper, an assignment or `!` in front, an option
        # outside `-c -e -u -s -x`, an operand, a word that may vanish, `&`, `<`
        # and the 64-string bound (seventy `eval`s) each leave the check
        # counting for nothing, and an `|| exit 1` in the body is no `-e`.
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
            ("sh $X", CHECK, "sh"))]
        self.assert_reported(rows + [
            (stdin_step("sh $X", pre="X=-e\n"), 1, UNGATED % "sh"),
            (stdin_step("bash $(true)"), 2, UNGATED % "bash"),
            (stdin_step("eval 'bash -s &'", GET + self.USED, fetched=False), 1, UNGATED % "eval"),
            (stdin_step("eval 'bash -s < /dev/null'", GET + self.USED, fetched=False), 1,
             UNGATED % "eval"),
            (stdin_step("eval 'bash -s'", CHECK + " || exit 1\necho done"), 1, RUNS_ON % "bash"),
            (stdin_step("eval " * 70 + "bash -s"), 1, UNGATED % "eval")])
        # The controls: each command line made bare, and the check made the
        # whole body or put under the reader's own `-e`, keeps the credit:
        # every shell stops at the check (rc 1).
        self.assert_clean([stdin_step("eval 'bash -s'"), stdin_step("eval '(bash -s)'"),
                           stdin_step("eval 'bash -e -s'", self.ECHOED), stdin_step("bash -c 'sh'"),
                           stdin_step("bash -euxc 'sh'"), stdin_step("sh"), stdin_step("bash -s"),
                           stdin_step("eval " * 3 + "bash -s")])

    def test_2500_a_literal_stdin_shell_reads_as_on_main(self):
        # The must-trip controls: at the step's own level the shell reading
        # stdin is the reader, as on `main`. Every shell stops at a check that
        # ends the body or runs under its `-e` (rc 1), and runs the download
        # past one that does neither (rc 0).
        self.assert_clean([stdin_step("bash -s"), stdin_step("sh"),
                           stdin_step("bash -e -s", self.ECHOED)])
        self.assert_reported([
            (stdin_step("bash -s", self.ECHOED), 1, RUNS_ON % "bash"),
            (stdin_step("bash -s", GET + self.USED, fetched=False), 1, RUNS_ON % "bash")])

    def test_2473_a_dollar_word_a_branch_and_builtin_eval_read_as_before(self):
        # A `$` command word credits nothing, whether the shells stop at the
        # check (`CMD=sh`, rc 1) or run the download (`CMD=true`, rc 0); a check
        # in a branch clears no use outside it, though they stop there (rc 1);
        # and `builtin eval` is no `eval` to the guard, its body unread as on
        # `main` (the bashes stop at the check, rc 1; dash has no `builtin`, 127).
        for command in ("sh", "true"):
            script = stdin_step("$CMD", pre="CMD=%s\n" % command)
            with self.subTest(script=script):
                found = [why for _step, why in defects(script)]
                self.assertEqual(2, len(found), found)
                self.assertTrue(any(UNGATED % "$CMD" in why for why in found), found)
                self.assertTrue(any(why.startswith("hands a heredoc body or here-string to `$CMD`")
                                    for why in found), found)
        self.assert_reported([
            (stdin_step("eval 'bash -s'", pre="if true; then\n", end="fi\n"), 1,
             "written inside an `if`/`while` branch the use is not in"),
            (stdin_step("builtin eval 'bash -s'"), 1, "with nothing verifying what arrived")])

    def test_2500_mains_own_gaps_read_as_on_main(self):
        # Gaps of `main`'s own, each filed under #2331: CLEAN though a shell
        # runs the download -- every shell where an option keeps the literal
        # shell from running its program or a function stands in for `sh`
        # (rc 0), dash alone under `SHELLOPTS=noexec` (the bashes, rc 1).
        # `main` reads each of these literal steps CLEAN too.
        self.assert_clean([stdin_step("bash -n -s"), stdin_step("bash -o noexec -s"),
                           stdin_step("bash -t -s", "echo start\n" + CHECK),
                           stdin_step("bash --version"), stdin_step("bash -s -c true"),
                           stdin_step("SHELLOPTS=noexec bash -s"),
                           stdin_step("sh", pre="sh() { :; }\n")])

    def test_2500_a_function_that_shadows_the_shell_is_mains_limit(self):
        # `main`'s limit, filed under #2331, reached through the new reading: a
        # function named `sh` or `bash` runs instead of the shell, nothing reads
        # the body, and every shell runs the download (rc 0) -- CLEAN, as
        # `main` reads the literal twin (`sh() { :; }` before `sh <<'EOF'`).
        self.assert_clean([stdin_step("eval 'sh'", pre="sh() { :; }\n"),
                           stdin_step("bash -c 'sh'", pre="bash() { :; }\n")])

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

    def test_it_is_reported_where_the_job_holds_a_reported_fetch(self):
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
