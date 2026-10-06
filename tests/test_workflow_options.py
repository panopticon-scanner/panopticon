"""#2331, the PROGRAMS lane: the stdin operand walk reads a shell's options as the shell does.

One class per mechanism of the cluster, each a spelling in which bash runs a download -- or runs
nothing -- that the guard read the other way, pinned as a live step beside the controls that must
read as they did. A row's comment carries its truth, b5 b3 dash gh (bash 5.2.21, bash 3.2.57, dash,
a GitHub runner's bash with `sh` = dash), measured with a recording `curl` that hands back a marker
program, a `sha256sum` whose `-c` fails, and the step run as GitHub runs it (`-e`, bash also
`-o pipefail`): FR fetched and ran, F- fetched only, -- neither, +chk the check ran. Every row's four
columns agree unless a comment says otherwise.
"""
import unittest

import workflow_guard as wg
import workflow_options as wo
import workflow_programs as wp

URL = "https://example.test/"
PIPE = "curl -fsSL %si.sh | sh" % URL
GET = "curl -fsSLo tool %stool\n" % URL
CHECK = "echo '%s  tool' | sha256sum -c -" % ("a" * 64)
USE = "chmod +x tool; ./tool\n"
STREAM = "hands %si.sh straight to `sh`" % URL
UNVERIFIED = "with nothing verifying what arrived"


def defects(script):
    return [why for _name, why in wg.job_defects([("step", script)])]


def body(command, text):
    return "%s <<'EOF'\n%s\nEOF\n" % (command, text)


class TestTheOptionsAfterDashS(unittest.TestCase):
    """#2647: bash keeps reading options after `-s`, and a `-c` among them puts the program in
    the string; the heredoc is that program's DATA. `--`, `-` or an operand ends the options,
    and the words after them are parameters, so the body is the program."""

    def test_a_dash_c_after_dash_s_wins(self):
        # FR FR FR FR: the check in the body is never read, and `./tool` runs unverified.
        found = defects(GET + body("bash -s -c true", CHECK) + USE)
        self.assertEqual(1, len(found), found)
        self.assertIn(UNVERIFIED, found[0])
        # -- -- -- --: `bash -s -c 'echo hi'` runs the string alone; the pipe in the body never.
        self.assertEqual([], defects(body("bash -s -c 'echo hi'", PIPE)))

    def test_a_dash_c_that_is_a_parameter_leaves_the_body_the_program(self):
        # F-+chk x4 on each: the check runs and stops the step (rc 1) -- CLEAN, as before.
        for command in ("bash -s -- -c x", "bash -s arg -c x", "bash -", "bash -s"):
            with self.subTest(command=command):
                self.assertEqual([], defects(GET + body(command, CHECK) + USE))

    def test_a_value_option_word_after_dash_s_is_read_fail_closed(self):
        # FR FR FR FR: bash expands `-$X` to `-c sh` before it reads its options, so `sh` reads
        # the body; the later literal `-c` is not trusted past such a word (the must-trip).
        found = defects(GET + "X='c sh'\nbash -s + -$X -c - + <<'EOF'\necho 'sh\\ttool' | sh\nEOF\n")
        self.assertTrue(found and "running it under `sh`" in found[-1], found)
        # F- F- F- F- (rc 127, bash runs `x`): the body is data -- CLEAN now, as the string wins.
        self.assertEqual([], defects(GET + "X='-c sh'\nbash -s -c x \"$X\" x <<'EOF'\necho 'sh\\ttool' | sh\nEOF\n"))

    def test_the_holder_whose_dash_c_names_a_stdin_shell_keeps_its_reader(self):
        # FR FR FR FR: `bash -s -c 'sh'` runs `sh`, which reads the body -- reported, as before,
        # with the body the holder's own (`()`), so a use inside it is still bound to its fetch.
        self.assertTrue(any(STREAM in why for why in defects(body("bash -s -c 'sh'", PIPE))))
        found = defects(GET + "bash -s -c 'sh' <<'B1'\nchmod +x tool\n./tool\nB1\n")
        self.assertTrue(any(UNVERIFIED in why for why in found), found)


class TestALoneDashBeforeAFile(unittest.TestCase):
    """#2654: a lone `-` ends a shell's options as `--` does; the word after it, if any, is the
    script FILE, and standard input is that program's data."""

    def test_the_file_after_a_lone_dash_is_the_program(self):
        # FR FR FR FR on each: the file (`/dev/null`) runs, the check is never read.
        for command in ("bash - /dev/null", "sh - /dev/null", "bash -e - /dev/null"):
            with self.subTest(command=command):
                found = defects(GET + body(command, CHECK) + USE)
                self.assertEqual(1, len(found), found)
                self.assertIn(UNVERIFIED, found[0])
        # -- -- -- --: the pipe in the body is never run -- the over-report is gone.
        self.assertEqual([], defects(body("bash - /dev/null", PIPE)))

    def test_a_lone_dash_with_nothing_after_it_is_still_stdin(self):
        # F-+chk x4: the body is the program, the check runs and stops the step.
        self.assertEqual([], defects(GET + body("bash -", CHECK) + USE))
        self.assertTrue(any(STREAM in why for why in defects(body("bash -", PIPE))))


class TestALongOptionOfTheShell(unittest.TestCase):
    """#2616: a shell's long options have a table now. `--rcfile FILE` and `--init-file FILE`
    take the file and read on; a word outside the table, or one spelled `--name=value`, is one
    bash refuses (rc 2, no stdin read), and dash refuses every long option."""

    def test_the_file_a_long_option_takes_is_no_script(self):
        # FR FR FR FR on each: the heredoc is the program after the file is skipped.
        for script in (body("bash --rcfile /dev/null", PIPE), body("bash --init-file /dev/null -s", PIPE),
                       body("bash --norc", PIPE)):
            with self.subTest(script=script):
                self.assertTrue(any(STREAM in why for why in defects(script)), script)
        # FR FR FR FR: the use inside the body is read.
        found = defects(GET + body("bash --rcfile /dev/null", "sh tool"))
        self.assertTrue(any("running it under `sh`" in why for why in found), found)

    def test_a_value_in_the_option_slot_after_the_file_is_still_weighed(self):
        # FR FR FR FR on each: `$X` (or `xargs`'s `{}`) spells `-c`, and the string runs.
        for script in ("X=-c\nbash --rcfile /dev/null $X '%s'\n" % PIPE,
                       "echo -c | xargs -I{} bash --rcfile /dev/null {} '%s'\n" % PIPE):
            with self.subTest(script=script):
                self.assertTrue(any("where it reads its options" in why for why in defects(script)), script)

    def test_a_refused_long_option_runs_nothing(self):
        # -- -- -- -- (rc 2) on each: bash answers `invalid option`, dash `Illegal option --`.
        for command in ("bash --bogus", "bash --rcfile=/dev/null", "dash --norc"):
            with self.subTest(command=command):
                self.assertEqual([], defects(body(command, PIPE)))
        # Controls that read as they did: a FILE operand after the option's file, and a `-c`
        # found wherever it stands.
        self.assertEqual([], defects("printf 'true\\n' > script.sh\n" + body("bash --rcfile /dev/null script.sh", PIPE)))
        self.assertTrue(any(STREAM in why for why in defects("bash --rcfile /dev/null -c '%s'\n" % PIPE)))

    def test_the_tables_are_the_union_bash_5_2_21_and_3_2_57_print(self):
        # `bash --help` on each: 5.2 adds `--pretty-print`, 3.2 `--protected` and `--wordexp`.
        # The four that print and exit run nothing (`bash --version <<'EOF'` reads no stdin).
        self.assertEqual(("--rcfile", "--init-file"), wo.LONG_VALUE_OPTIONS)
        self.assertEqual(set(wo.LONG_OPTIONS), {
            "--debug", "--debugger", "--dump-po-strings", "--dump-strings", "--help", "--login",
            "--noediting", "--noprofile", "--norc", "--posix", "--pretty-print", "--protected",
            "--restricted", "--verbose", "--version", "--wordexp"})
        self.assertEqual({"--help", "--version", "--dump-strings", "--dump-po-strings"}, set(wo.LONG_EXITS))
        self.assertTrue(wo._refused_long(["bash", "--bogus"], 1))
        self.assertTrue(wo._refused_long(["bash", "--version"], 1))
        self.assertTrue(wo._refused_long(["bash", "-rcfile=/dev/null"], 1))
        self.assertTrue(wo._refused_long(["dash", "--norc"], 1))
        self.assertFalse(wo._refused_long(["bash", "--norc"], 1))
        self.assertFalse(wo._refused_long(["bash", "-norc"], 1))
        self.assertFalse(wo._refused_long(["zsh", "--bogus"], 1))
        self.assertFalse(wo._refused_long(["bash", "--"], 1))
        # Both spellings bash takes; the one-dash one only for `bash` and `sh`.
        self.assertEqual("--login", wo.long_option("--login", "bash"))
        self.assertEqual("--login", wo.long_option("-login", "bash"))
        self.assertEqual("--login", wo.long_option("-login", "/bin/sh"))
        self.assertIsNone(wo.long_option("-login", "dash"))
        self.assertIsNone(wo.long_option("-login", "zsh"))
        self.assertEqual("--login", wo.long_option("--login", "dash"))
        for word in ("-bogus", "-e", "-rcfile=/dev/null", "-", "--", "--rcfile=f"):
            self.assertIsNone(wo.long_option(word, "bash"), word)
        self.assertFalse(wo._refused(["bash", "-login"], 1))
        self.assertFalse(wo._refused_name(["bash", "-noediting"], 1))

    def test_bash_takes_its_long_options_with_one_dash_too(self):
        # #2864 and the round-1 pre-check of PR #2858: bash reads `-login` as `--login`, and the
        # refusal reading took it for a letter cluster with a letter outside the table. FR FR FR
        # FR on each row below (the login-shell rows measured on the forge, where a login shell
        # keeps its PATH; on a Mac `/etc/profile` resets it), reported now; six of them (#2864:
        # `-norc`, `-restricted`, `-rcfile FILE`, `-init-file FILE`, and the two `-c` forms) read
        # CLEAN on main before this batch too.
        for script in (body("bash -login", PIPE), body("bash -noediting", PIPE), body("bash -debugger", PIPE),
                       body("sh -login", PIPE),                       # FR where `sh` is bash; dash refuses
                       "bash -login -c '%s'\n" % PIPE, "bash -posix -c '%s'\n" % PIPE,
                       body("bash -norc", PIPE), body("bash -restricted", PIPE),
                       body("bash -rcfile /dev/null", PIPE), body("bash -init-file /dev/null", PIPE),
                       "bash -norc -c '%s'\n" % PIPE, "bash -rcfile /dev/null -c '%s'\n" % PIPE):
            with self.subTest(script=script):
                self.assertTrue(any(STREAM in why for why in defects(script)), script)
        found = defects("X=-c\nbash -rcfile /dev/null $X '%s'\n" % PIPE)
        self.assertTrue(any("where it reads its options" in why for why in found), found)
        # -- -- -- -- (rc 2) on each: a one-dash word that spells no long option is a letter
        # cluster (`-bogus` fails at `g`), dash reads every one-dash word so (`dash -login` fails
        # at `-g`), a value glued on is refused (rc 1), and a long option after a `-c` cluster is
        # refused by both bashes (`- : invalid option`).
        for script in (body("bash -bogus", PIPE), body("dash -login", PIPE), body("bash -rcfile=/dev/null", PIPE),
                       "bash -c -login '%s'\n" % PIPE, "bash -c --login '%s'\n" % PIPE):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))

    def test_a_long_option_that_prints_and_exits_reads_no_stdin_and_runs_no_string(self):
        # `--version`, `--help`, `--dump-strings` and `--dump-po-strings` (`LONG_EXITS`) print
        # and exit before bash reads stdin or a `-c` string, in either spelling: with a check in
        # the heredoc and a use after, FR FR FR FR and rc 0 -- the use runs, the check never read
        # -- where `bash --norc <<'EOF'` reads the check and stops (F-+chk, rc 1). main read the
        # heredoc as the shell's program and credited the check: its own gap, closed with the
        # table. `sh --version` is read the same, fail-closed: FR where `sh` is bash, F- and rc 2
        # where it is dash.
        for runner in ("bash --version", "bash -version", "bash --help", "bash -help",
                       "bash --dump-strings", "bash --dump-po-strings", "bash --version -c 'sh'",
                       "bash -version -c 'sh'", "sh --version"):
            with self.subTest(runner=runner):
                found = defects(GET + body(runner, CHECK) + USE)
                self.assertTrue(any(UNVERIFIED in why for why in found), (runner, found))
        # -- -- -- -- (rc 0): a download in the heredoc or the string is never run.
        for script in (body("bash --version", PIPE), body("bash -version", PIPE), body("bash -help", PIPE),
                       "bash --help -c '%s'\n" % PIPE, "bash --dump-strings -c '%s'\n" % PIPE):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))
        self.assertEqual([], defects(GET + body("bash --norc", CHECK) + USE))     # the check counts


class TestAnOptionValueTheShellRefuses(unittest.TestCase):
    """#2606 (and #2603's letter half in the same walk): a measured shell exits 2 before it reads
    stdin at a `-o` name outside its table, at a `-o` value that is no name at all, and at a
    letter it refuses -- in the stdin walk and in the option words before a `-c` cluster."""

    def test_a_refused_name_or_value_runs_nothing(self):
        # -- -- -- -- (rc 2) on each.
        for script in (body("bash -o pipefial", PIPE), body("sh -o -", PIPE), body("bash -o /dev/stdin", PIPE),
                       body("bash -oo pipefail -", PIPE), "bash -o pipefial -c '%s'\n" % PIPE,
                       "sh -c -o - '%s'\n" % PIPE, body("bash -K", PIPE)):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))

    def test_the_controls_read_as_they_did(self):
        # FR FR FR FR: a name the shell takes; a value in an expansion is read ON, fail-closed.
        for script in (body("bash -o pipefail", PIPE), body("bash -o $X", PIPE), body("bash -s", PIPE)):
            with self.subTest(script=script):
                self.assertTrue(any(STREAM in why for why in defects(script)), script)
        # `-O` takes a shopt name, and a table of those is not kept: `bash -O nosuchopt -s` is
        # still reported though both bashes refuse it (rc 2) -- the price #2606 names.
        self.assertTrue(any(STREAM in why for why in defects(body("bash -O nosuchopt -s", PIPE))))
        # Behind a string an inner shell's refused letter is read ON, as before (#2500's price):
        # -- -- -- -- (rc 2) on each, reported all the same.
        for script in (body("eval 'bash -K -s'", PIPE), body("bash -c 'sh -K'", PIPE)):
            with self.subTest(script=script):
                self.assertTrue(any(STREAM in why for why in defects(script)), script)

    def test_a_literal_value_that_is_no_name_is_a_refusal_and_an_expansion_is_not(self):
        self.assertTrue(wo._refused_name(["bash", "-o", "pipefial"], 1))
        self.assertTrue(wo._refused_name(["sh", "-o", "-"], 1))
        self.assertTrue(wo._refused_name(["bash", "-o", "/dev/stdin"], 1))
        self.assertFalse(wo._refused_name(["bash", "-o", "pipefail"], 1))
        self.assertFalse(wo._refused_name(["bash", "-o", "$X"], 1))
        self.assertFalse(wo._refused_name(["zsh", "-o", "pipefial"], 1))


class TestAWordHoldingAProcessSubstitution(unittest.TestCase):
    """#2592: a word holding ANY `<(...)` or `>(...)` never vanishes -- bash substitutes a real
    path for it whatever else it holds -- so it is a FILE operand, not a vanishing one."""

    def test_a_mixed_word_is_no_vanishing_operand(self):
        # -- -- rc2 --: bash runs the `<(...)` path (dash refuses `<(`); the piped text is never
        # bash's program, so the stream sentence is gone.
        found = defects("echo '%s' | bash $(true)<(echo 'echo x')\n" % PIPE)
        self.assertFalse(any(STREAM in why for why in found), found)
        # FR FR FR FR: a command substitution alone may vanish, and the body is read.
        self.assertTrue(any(STREAM in why for why in defects(body("bash $(true)", PIPE))))
        self.assertTrue(wp._hands_file(wg.shell_reader.statements("bash $(true)<(echo x)")[0].stages[0].argv[1]))
        self.assertFalse(wp._hands_file(wg.shell_reader.statements("bash $(true)")[0].stages[0].argv[1]))


class TestTheOptionGrammarLivesInWorkflowOptions(unittest.TestCase):
    """#2331 (PR #2850): the option tables, the refusal readers and the option-slot word readers
    moved out of `workflow_programs` into `workflow_options`, byte for byte; `workflow_programs`
    re-exports every name, so each is the same object through either module."""

    def test_every_moved_name_is_the_same_object_through_either_module(self):
        for name in ("SET_OPTIONS", "SHELL_OPTIONS", "VALUE_OPTIONS", "SET_OPTION_NAMES",
                     "SHELL_OPTION_NAMES", "_MEASURED_SHELLS", "_refused", "_refused_name",
                     "_past_options", "_VALUE", "_value", "_BARE", "_before_operand",
                     "_may_spell_option"):
            with self.subTest(name=name):
                self.assertIs(getattr(wp, name), getattr(wo, name))
