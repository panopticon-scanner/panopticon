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

import shell_reader
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
        self.assertEqual({"--help", "--version", "--dump-strings", "--dump-po-strings", "--wordexp"},
                         set(wo.LONG_EXITS))
        self.assertTrue(wo._refused_long(["bash", "--bogus"], 1))
        self.assertTrue(wo._refused_long(["bash", "--version"], 1))
        self.assertTrue(wo._refused_long(["bash", "-rcfile"], 1))          # no FILE after it
        self.assertFalse(wo._refused_long(["bash", "-rcfile", "/dev/null"], 1))
        self.assertTrue(wo._refused_long(["bash", "-rcfile=/dev/null"], 1))
        self.assertTrue(wo._refused_long(["dash", "--norc"], 1))
        self.assertFalse(wo._refused_long(["bash", "--norc"], 1))
        self.assertFalse(wo._refused_long(["bash", "-norc"], 1))
        self.assertFalse(wo._refused_long(["zsh", "--bogus"], 1))
        self.assertFalse(wo._refused_long(["bash", "--"], 1))
        # Both spellings bash takes; the one-dash one only for `bash` and `sh`, in the leading run.
        self.assertEqual("--login", wo.long_option(["bash", "--login"], 1))
        self.assertEqual("--login", wo.long_option(["bash", "-login"], 1))
        self.assertEqual("--login", wo.long_option(["/bin/sh", "-login"], 1))
        self.assertEqual("--login", wo.long_option(["bash", "--norc", "-login"], 2))
        self.assertEqual("--login", wo.long_option(["bash", "-rcfile", "/dev/null", "-login"], 3))
        self.assertIsNone(wo.long_option(["bash", "-e", "-help"], 2))          # the letters `-h -e -l -p`
        self.assertIsNone(wo.long_option(["bash", "-c", "-help"], 2))
        self.assertEqual("--help", wo.long_option(["bash", "-e", "--help"], 2))  # refused after `-e`
        self.assertIsNone(wo.long_option(["dash", "-login"], 1))
        self.assertIsNone(wo.long_option(["zsh", "-login"], 1))
        self.assertEqual("--login", wo.long_option(["dash", "--login"], 1))
        for word in ("-bogus", "-e", "-rcfile=/dev/null", "-", "--", "--rcfile=f"):
            self.assertIsNone(wo.long_option(["bash", word], 1), word)
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
                       "bash -norc -c '%s'\n" % PIPE, "bash -rcfile /dev/null -c '%s'\n" % PIPE,
                       # the round-1 seat's extent: more names, the `o`-bearing ones before a `-c`
                       # (no value owed), a two-dash word after, wrappers, a path, `sh`
                       body("bash -debug", PIPE), "bash -noprofile -c '%s'\n" % PIPE,
                       "bash -verbose -c '%s'\n" % PIPE, body("bash -login --norc", PIPE),
                       body("sudo bash -norc", PIPE), "env bash -posix -c '%s'\n" % PIPE,
                       body("/bin/bash -norc", PIPE), body("sh -norc", PIPE), "sh -posix -c '%s'\n" % PIPE):
            with self.subTest(script=script):
                self.assertTrue(any(STREAM in why for why in defects(script)), script)
        for script in ("X=-c\nbash -rcfile /dev/null $X '%s'\n" % PIPE, "X=-c\nbash -login $X '%s'\n" % PIPE):
            with self.subTest(script=script):
                found = defects(script)
                self.assertTrue(any("where it reads its options" in why for why in found), found)
        # -- -- -- -- (rc 2) on each: a one-dash word that spells no long option is a letter
        # cluster (`-bogus` fails at `g`), dash reads every one-dash word so (`dash -login` fails
        # at `-g`), a value glued on is refused (rc 1), and a long option after a `-c` cluster is
        # refused by both bashes (`- : invalid option`).
        for script in (body("bash -bogus", PIPE), body("dash -login", PIPE), body("bash -rcfile=/dev/null", PIPE),
                       "bash -c -login '%s'\n" % PIPE, "bash -c --login '%s'\n" % PIPE):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))

    def test_the_one_dash_spelling_holds_in_the_leading_run_alone(self):
        # #2858 round 2 (B1): bash parses one-dash long names only while every word before is a
        # long option (or its FILE); after a short-option word the word is a letter cluster, and
        # `-help` is `-h -e -l -p`, all valid, so the heredoc or the string runs: FR on bash
        # 5.2.21 and 3.2.57 (forge, gt2.sh), rc 0. `sh -e -help`: FR where `sh` is bash, dash rc 2.
        for runner in ("bash -e -help", "bash -s -help", "bash -o errexit -help", "bash -ehelp",
                       "bash -e -s -help", "bash --norc -e -help", "bash -rcfile /dev/null -e -help",
                       "sh -e -help", "bash -e -posix", "bash -e -verbose",
                       "bash --norc -login", "bash -login -norc", "bash -rcfile /dev/null -login"):
            with self.subTest(runner=runner):
                self.assertTrue(any(STREAM in why for why in defects(body(runner, PIPE))), runner)
        for script in ("bash -c -help '%s'\n" % PIPE, "bash -x -help -c '%s'\n" % PIPE,
                       "bash -s -c -help '%s'\n" % PIPE, "X=-e\nbash $X -help <<'EOF'\n%s\nEOF\n" % PIPE):
            with self.subTest(script=script):
                self.assertTrue(defects(script), script)
        # -- -- -- --: `-help` alone prints and exits; a two-dash word off the leading run is an
        # error (rc 1); `-login` after `-c` is letters bash refuses (rc 2); a value glued on (rc 2).
        for script in (body("bash -help", PIPE), body("bash -e --help", PIPE), "bash -c -login '%s'\n" % PIPE,
                       body("bash --rcfile=/dev/null -e", PIPE)):
            with self.subTest(script=script):
                self.assertEqual([], defects(script), script)
        # Fail-closed, reported though nothing runs: `bash -e -login` (`-o gin`, rc 1), `bash -e
        # -norc` (rc 1), `bash -e -noediting` (rc 1) -- the letters' own refusals are not all in
        # the table, and a check behind them is never credited.

    def test_the_last_noexec_state_wins_and_a_cluster_o_takes_the_next_word(self):
        # #2858 round 3 (B1): bash, sh and dash keep reading options, so a later `+n` / `+o
        # noexec` turns noexec back off and the body runs: FR FR FR FR (forge, gt2.sh, both
        # bashes and dash) on each -- `-n -s +n` too (`+n` after `-s` is still an option).
        for runner in ("bash -n +n -s", "bash -o noexec +o noexec -s", "bash -n -s +n", "bash -n +o noexec -s",
                       "sh -n +n -s", "dash -n +n -s", "dash -n -s +n"):
            with self.subTest(runner=runner):
                self.assertTrue(any(STREAM in why for why in defects(body(runner, PIPE))), runner)
        # -- -- -- --: noexec on at the end (`+n -n`), `-D` undone by nothing (`-D +D`), and a
        # cluster's `o` takes the next word as its name (`-eo noexec`, `-oe noexec`: finding 1).
        for runner in ("bash +n -n -s", "bash -D +D -s", "bash -eo noexec -s", "bash -oe noexec -s"):
            with self.subTest(runner=runner):
                self.assertEqual([], defects(body(runner, PIPE)), runner)
                found = defects(GET + body(runner, CHECK) + USE)
                self.assertTrue(any(UNVERIFIED in why for why in found), (runner, found))
        # `-n +n -s` with a check in the body: the body is the program again, the check counts.
        self.assertEqual([], defects(GET + body("bash -n +n -s", CHECK) + USE))
        # Each `o` takes a word (`-oo errexit noexec`: the second is `noexec`), and `D` runs
        # nothing whatever `+n` says (`+nD`): -T rc 0, the use after unverified (the seat's matrix).
        for runner in ("bash -oo errexit noexec", "sh -oo errexit noexec", "dash -oo errexit noexec", "bash +nD"):
            with self.subTest(runner=runner):
                self.assertEqual([], defects(body(runner, PIPE)), runner)
                found = defects(GET + body(runner, CHECK) + USE)
                self.assertTrue(any(UNVERIFIED in why for why in found), (runner, found))

    def test_a_word_that_may_expand_to_nothing_holds_the_leading_run(self):
        # #2858 round 3 (B2): `$X`, `${X:-}`, `$(true)` may expand to nothing or to a long
        # option, and bash then takes the one-dash word after as leading: FR FR FR FR with `X=`,
        # `X=--norc`, `X=-norc` (forge, both bashes). The word is never read as a short option.
        for pre, runner in (("X=\n", "bash $X -login"), ("X=--norc\n", "bash $X -login"), ("X=-norc\n", "bash $X -login"),
                            ("X=\n", "bash ${X:-} -noprofile"), ("", "bash $(true) -login"), ("X=\n", "bash $X $X -login")):
            with self.subTest(runner=pre + runner):
                self.assertTrue(any(STREAM in why for why in defects(pre + body(runner, PIPE))), runner)
        self.assertTrue(defects("X=\nbash $X -norc -c '%s'\n" % PIPE))
        # Where `$X` may spell a short option instead, the one-dash word after may be LETTERS
        # that run (`X=-e; bash $X -help`: FR): an exit after such a word is read as the step's
        # own text with no check credited, reported either way (`X=` alone: nothing runs, -- --,
        # the fail-closed price). Round 4 (B1, shape C): nothing after an expansion clears, since
        # it may be `--rcfile` and take the next word as its FILE -- `X=--rcfile; bash $X -version`
        # runs the heredoc (FR on both bashes) -- so `X=; bash $X -version` (-- --, rc 0) and
        # `X=; bash -e $X -login` (-- --, rc 1) are reported too, fail-closed.
        self.assertTrue(any(STREAM in why for why in defects("X=-e\n" + body("bash $X -help", PIPE))))
        self.assertTrue(any(STREAM in why for why in defects("X=\n" + body("bash $X -help", PIPE))))
        for script in ("X=\n" + body("bash $X -version", PIPE), "X=\n" + body("bash -e $X -login", PIPE)):
            with self.subTest(script=script):
                self.assertTrue(any(STREAM in why for why in defects(script)), script)
        # With a check and a use: -T (`X=`: the version printed, the use unverified) -- reported by
        # the value's own sentence, since any word after `$X` may be the program.
        found = defects("X=\n" + GET + body("bash $X -version", CHECK) + USE)
        self.assertTrue(found and found[0].startswith("passes `bash` `$X`"), found)

    def test_after_an_expansion_in_the_option_run_nothing_is_sure(self):
        # #2858 round 4 (B1): a word that may expand -- an option word, a long option's FILE or an
        # `-o` name -- may vanish, so the NEXT word is the FILE, or spell `+n`, a `+o` name or
        # `--rcfile` itself; nothing at or after it clears, and no check in the body is credited.
        # Every row runs the heredoc: FR on bash 5.2.21 and 3.2.57 (forge, gt2.sh) unless noted.
        rows = (
            # (A) an expansion as a FILE option's value: with `X=` the next word is the rc file
            ("X=\n", "bash --rcfile $X --version"), ("X=\n", "bash -rcfile $X -help"),
            ("X=\n", "bash --norc --rcfile $X -n -s"), ("X=\n", "bash --rcfile $X -K -s"),
            ("X=\n", "bash --init-file $X --bogus"), ("X=\n", "bash --rcfile ${X:-} -D"),
            ("", "bash --rcfile $(true) -n"),
            ("X=\n", "sh --rcfile $X --version"),            # FR where `sh` is bash; dash rc 2 (seat)
            ("X=\n", "sudo bash --rcfile $X --version"),     # the seat's matrix, `sudo` stubbed
            ("X=\n", "env bash --rcfile $X -n -s"), ("X=\n", "timeout 5 bash --rcfile $X -K -s"),
            # (B) an expansion that may be `+n` or a `+o` name after noexec (dash too)
            ("X=+n\n", "bash -n $X -s"), ("X=noexec\n", "bash -n +o $X -s"), ("X=+n\n", "dash -n $X -s"),
            ("X=+n\n", "sh -n $X -s"), ("X=+n\n", "env bash -n $X -s"), ("X=+n\n", "bash -eo noexec $X -help"),
            # (C) an expansion that may itself be `--rcfile`, taking the next word as its FILE
            ("X=--rcfile\n", "bash $X -K -s"), ("X=--rcfile\n", "bash $X -version"), ("X=--rcfile\n", "bash $X +D"),
            ("X=--init-file\n", "sh $X -dump-strings"),      # FR where `sh` is bash; dash rc 2 (seat)
            ("X=--rcfile\n", "env bash $X -K -s"), ("X=--rcfile\n", "timeout 5 bash $X -version"))
        for pre, runner in rows:
            with self.subTest(runner=pre + runner):
                self.assertTrue(any(STREAM in why for why in defects(pre + body(runner, PIPE))), runner)
        # The `-c` path: with `X=` the next word is the rc file and the string runs (FR, both
        # bashes) -- `-help`, and the words that would take `-c` as a value were nothing shifted
        # (`-nor`'s `o`, `--rcfile`, `--`), or end the leading run (`-e`, then `-login` is long).
        for words in ("--rcfile $X -help", "--rcfile $X -nor", "--rcfile $X -- ", "--rcfile $X --rcfile",
                      "--rcfile $X -e -login", "--init-file $X -no", "--rcfile $X -e -rcfile /dev/null"):
            with self.subTest(words=words):
                script = "X=\nbash %s -c '%s'\n" % (words, PIPE)
                self.assertTrue(any(STREAM in why for why in defects(script)), script)
        # Every cluster carrying `c` after an expansion hands its operand on, a long name's letters
        # too: `X=-e; bash $X -rcfile 'P'` runs `P` (`-r -c -f ...` after `-e`: FR, both bashes).
        with self.subTest(script="X=-e; bash $X -rcfile P"):
            self.assertTrue(any(STREAM in why for why in defects("X=-e\nbash $X -rcfile '%s'\n" % PIPE)))
        # A `-c` cluster after an expansion clears nothing in the stdin walk: with `X=` the `-e` is
        # the rc file and `-norc` / `-rcfile /dev/null` are long options, so bash reads the heredoc
        # (FR); and `X=-s; sh $X -c true` runs the string THEN the heredoc under dash (FR, F4).
        for pre, runner in (("X=\n", "bash --rcfile $X -e -norc"), ("X=\n", "bash --rcfile $X -e -rcfile /dev/null"),
                            ("X=-s\n", "sh $X -c true"), ("X=-s\n", "dash $X -c true")):
            with self.subTest(runner=pre + runner):
                self.assertTrue(any(STREAM in why for why in defects(pre + body(runner, PIPE))), runner)
        # With a check in the body and a use after, -T on every shell (the use runs unverified):
        # `-rcfile /dev/null` is the rc file and `/dev/null` the script, `-n` stays on with `X=`,
        # `-o` takes `noexec` (F3, the seat's round 4), the `O` and `o` of `-Oo` take a word each (F1).
        for pre, runner in (("X=\n", "bash --rcfile $X -rcfile /dev/null"), ("X=\n", "bash -n $X -s"),
                            ("X=noexec\n", "bash -o $X -s"), ("", "bash -o ${X:-noexec}"),
                            ("", "bash -Oo extglob noexec")):
            with self.subTest(runner=pre + runner):
                found = defects(pre + GET + body(runner, CHECK) + USE)
                self.assertTrue(found, (runner, found))
        # Honest clears, nothing expands: -- -- on each (rc 0, 2, 0, 0).
        for script in (body("bash --rcfile /dev/null --version", PIPE), body("bash -K -s", PIPE),
                       body("bash -n -s", PIPE), body("bash -Oo extglob noexec", PIPE)):
            with self.subTest(script=script):
                self.assertEqual([], defects(script), script)
        # The price, fail-closed: bash runs only the string here in every reading measured (`X=`,
        # `X=-s`: -- --, rc 0), but after `$X` the `-c` may be a FILE with an `-s` to follow.
        for pre in ("X=\n", "X=-s\n"):
            with self.subTest(pre=pre):
                self.assertTrue(any(STREAM in why for why in defects(pre + body("bash $X -c true", PIPE))))

    def test_a_dash_c_string_after_a_file_is_read_since_the_file_may_hand_it_on(self):
        # #2858 round 5 (the coordinator's pre-check): bash hands `-c P` to the FILE as its
        # parameters, and a FILE may hand them to a shell -- `exec bash "$@"` and `eval "$2"` run
        # `P` (FR on bash 5.2.21 and 3.2.57, forge); a FILE that does not (`true`) runs nothing
        # (-- --), but its text is not the guard's to know, written in the step or not, so the
        # string is read as `main` reads it, fail-closed.
        for body_text in ('exec bash "$@"', 'eval "$2"', "true"):
            with self.subTest(file=body_text):
                script = "printf '%s\\n' > w.sh\nbash w.sh -c '%s'\n" % (body_text, PIPE)
                self.assertTrue(any(STREAM in why for why in defects(script)), script)
        self.assertTrue(any(STREAM in why for why in defects("bash ./deploy.sh -c '%s'\n" % PIPE)))
        # Past the FILE every word is its parameter, so nothing bash would refuse or exit on clears
        # (the coordinator's pre-check of 3f19a0a1): with the FILE handing on the word after `-c`,
        # each runs `P` (FR on both bashes, forge) -- a bad `-o`/`+o`/`-O` name, `--version`,
        # `--help`, `--dump-strings`, `--rcfile` (no value owed), and `--`, which `main` read as
        # the end of the options. `exec bash "$@"` with `--version` runs nothing (-- --), but the
        # FILE is not the guard's to know: reported, fail-closed, as `main` reports it.
        for body_text, words in (('eval "$4"', "-o pipefial"), ('eval "$4"', "+o pipefial"),
                                 ('eval "$4"', "-O nosuchopt"), ('eval "$3"', "--version"),
                                 ('eval "$3"', "--help"), ('eval "$3"', "--dump-strings"),
                                 ('eval "$3"', "--rcfile"), ('eval "$3"', "--"),
                                 ('exec bash "$@"', "--version")):
            with self.subTest(file=body_text, words=words):
                script = "echo '%s' > w.sh\nbash w.sh %s -c '%s'\n" % (body_text, words, PIPE)
                self.assertTrue(any(STREAM in why for why in defects(script)), script)

    def test_a_run_of_one_dash_long_options_costs_what_the_walk_does(self):
        # #2858 round 3 (B3): `_run` is one pass per argv, kept by identity -- twenty and ten
        # thousand one-dash words cost within 2x of the same run of two-dash words (the seat
        # measured 7.7 s at sixteen and a timeout at twenty on the round-3 head).
        import time
        for n in (20, 2000):
            runs = {}
            for opt in ("--norc", "-norc"):
                t0 = time.perf_counter()
                self.assertTrue(defects(body("bash " + " ".join([opt] * n), PIPE)))
                runs[opt] = time.perf_counter() - t0
            self.assertLess(runs["-norc"], max(2 * runs["--norc"], 0.5), (n, runs))

    def test_a_shell_that_reads_its_program_and_runs_none_of_it(self):
        # #2858 round 3: `-n` (noexec) and `-o noexec` read the heredoc and run nothing of it,
        # rc 0 -- and after a short option `-version` and `-noprofile` are letters with `n` among
        # them (a mid-cluster `o` with no word after it is accepted silently; with one, that word
        # is its name: `bash -e -version -c P` -> `-c: invalid option name`, rc 2). With a check in
        # the body and a use after: -T (the use runs unverified) on both bashes -- reported;
        # with a download in the body: -- -- (nothing runs) -- CLEAN. `-D` prints strings, same.
        for runner in ("bash -n -s", "bash -o noexec -s", "bash -s -version", "bash -e -version",
                       "bash -e -noprofile", "bash -D", "bash -Ds", "sh -n", "dash -n"):
            with self.subTest(runner=runner):
                found = defects(GET + body(runner, CHECK) + USE)
                self.assertTrue(any(UNVERIFIED in why for why in found), (runner, found))
                self.assertEqual([], defects(body(runner, PIPE)), runner)
        self.assertEqual([], defects("bash -e -version -c '%s'\n" % PIPE))     # `-c` is no name
        # `-t` runs ONE command, so a download first in the body runs: read on, reported.
        self.assertTrue(any(STREAM in why for why in defects(body("bash -t -s", PIPE))))

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
        # `--wordexp` expands stdin as words (bash 3.2) or is refused (5.2); `-rcfile` as the
        # last word wants a FILE (rc 2): nothing runs under either.
        for script in (body("bash --version", PIPE), body("bash -version", PIPE), body("bash -help", PIPE),
                       "bash --help -c '%s'\n" % PIPE, "bash --dump-strings -c '%s'\n" % PIPE,
                       body("bash -wordexp", PIPE), "bash --wordexp -c '%s'\n" % PIPE, body("bash -rcfile", PIPE)):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))
        self.assertEqual([], defects(GET + body("bash --norc", CHECK) + USE))     # the check counts


class TestDashReadsStdinAfterItsDashCString(unittest.TestCase):
    """#2647, round 1 (B2): bash's `-c` beside `-s` puts the program in the string alone, but dash
    runs the string and THEN reads stdin as a program, so under `dash`, and under `sh`, which may
    be dash, the heredoc is the program after all."""

    def test_an_s_among_dashs_options_keeps_stdin_as_a_program(self):
        # FR FR FR FR where `sh` is dash, rc 0 (where `sh` is bash: -- -- -- --, the string alone):
        # before, after or in the `-c` cluster, with other options between, with parameters after.
        for runner in ("sh -s -c true", "sh -s -e -c true", "dash -s -c true", "dash -s -e -c true",
                       "sh -sc true", "sh -cs true", "sh -c -s true", "dash -c -s true",
                       "sh -c -o pipefail -s true", "dash -s -c 'echo x' arg0"):
            with self.subTest(runner=runner):
                self.assertTrue(any(STREAM in why for why in defects(body(runner, PIPE))), runner)
        # -- -- -- --: bash runs the string alone, and an `-s` AFTER the string is a parameter
        # to dash too (`sh -c true -s`); `-c` alone reads no stdin.
        for runner in ("bash -s -c true", "bash -sc true", "bash -cs true", "bash -c -s true",
                       "sh -c true -s", "dash -c true -s", "sh -c true"):
            with self.subTest(runner=runner):
                self.assertEqual([], defects(body(runner, PIPE)), runner)

    def test_the_body_is_read_but_no_check_in_it_counts(self):
        # `dash -s -c true <<'EOF' CHECK EOF; USE`: dash reads the check and stops (F-+chk, rc 1);
        # but `dash -s -c 'cat' <<'EOF' CHECK EOF; USE` runs the use unverified (FR, rc 0: the
        # string ate stdin first), and under `sh`, where it is bash, the body is never read (FR).
        # So the body is the step's own text, read, with no check in it credited -- the
        # fail-closed price, as #2485's: the `true` row is over-reported, the others closed.
        for runner in ("dash -s -c true", "dash -s -c 'cat'", "sh -s -c true", "sh -s -c 'cat'"):
            with self.subTest(runner=runner):
                found = defects(GET + body(runner, CHECK) + USE)
                self.assertTrue(any("is inside the script" in why for why in found), (runner, found))
        # A stdin shell the string names reads the body as the holder's, as before: `()`.
        stage = shell_reader.statements("sh -s -c 'bash -s' <<'EOF'\necho hi\nEOF")[0].stages[-1]
        argv = shell_reader.command(stage.argv)
        self.assertEqual(wp.SHELL_PROGRAM, wp.stdin_program(argv))
        self.assertEqual((), wp.stdin_scripts(argv, stage)[0].reader)


class TestADashCStringTheShellIsNotSureToRun(unittest.TestCase):
    """#2858 round 6: past the FILE operand no word refuses or exits, after the cluster carrying `c`
    too; a `-c` string found past an operand, after a word that may expand, or under noexec is read
    for what it runs and no check in it counts; after a word that may expand a lone `-` keeps stdin.
    Truth from the round-5 seat's quick table (q-numbers: touch marks under bash 5.2.21 and 3.2.57
    with `sh` as dash, and `sh` as each bash) and its matrix (row ids), or the forge (`gt2.sh`, both
    child bashes) where a comment says so: P the payload ran, T the unverified tool ran."""

    UNGATED = "inside the script `bash` runs, and the step does not stop when that script fails"
    EVAL_LAST = "echo 'for a; do :; done; eval \"$a\"' > w.sh\n"

    def test_past_the_file_no_word_after_the_cluster_refuses_or_exits(self):
        # P x4 on each (q01, q02, q05-q10, q19c, q82, q83): the words after the cluster are the
        # FILE's parameters, which bash never parses, and the FILE evaluates the last.
        for tail in ("-c -o -", "-co x1", "-c -e -o /dev/stdin", "-c -o ''", "-c -o pipefial", "-c -K",
                     "-c --version"):
            with self.subTest(tail=tail):
                found = defects(self.EVAL_LAST + "bash w.sh %s '%s'\n" % (tail, PIPE))
                self.assertTrue(any(STREAM in why for why in found), found)
        for script in ("echo 'eval \"$4\"' > w.sh\nbash w.sh -c -o - '%s'\n" % PIPE,
                       self.EVAL_LAST + "sh w.sh -c +o 1 '%s'\n" % PIPE,
                       self.EVAL_LAST + body("bash w.sh -c -o - 'sh'", PIPE),
                       body("bash -s x -c -o - '%s'" % PIPE, 'for a; do :; done; eval "$a"'),
                       # -- x4 (rc 2): the FILE is not the guard's to know -- REPORTED, as on `main`.
                       "echo 'exec bash \"$@\"' > w.sh\nbash w.sh -c -o - '%s'\n" % PIPE,
                       "echo 'exec sh \"$@\"' > w.sh\nbash w.sh -c -o - '%s'\n" % PIPE):
            with self.subTest(script=script):
                self.assertTrue(any(STREAM in why for why in defects(script)), script)

    def test_a_check_in_a_string_no_shell_is_sure_to_run_counts_for_nothing(self):
        # T x4 on each (q20-q27, q30-q32, q86): the check never runs, and `./tool` runs unverified
        # -- past an operand, after a word that may expand, or after a FILE option's misread FILE.
        for runner in ("bash /dev/null -- -c", ": > w.sh\nbash w.sh -- -c", "bash -s x -- -c",
                       "X=-s\nbash $X -- -c", "X=/dev/null\nbash $X -c -K", "X=--version\nbash $X -- -c",
                       ": > w.sh\nbash --rcfile -c w.sh -c", "X=--rcfile\nbash $X -rcfile /dev/null -c",
                       "X=\nbash $X --version -c", "bash /dev/null --version -c", "bash /dev/null -c",
                       "X=\nbash $X -help -c",
                       # Under noexec the shell reads the string and runs none of it: the tool runs
                       # in every shell, both child bashes (forge) -- credited before round 6.
                       "bash -n -c", "bash -o noexec -c", "bash -D -c", "bash -nc", "sh -n -c"):
            with self.subTest(runner=runner):
                found = defects(GET + '%s "%s"\n' % (runner, CHECK) + USE)
                self.assertTrue(any("tool" in why and ("inside the script" in why or UNVERIFIED in why)
                                    for why in found), found)
        self.assertTrue(any(self.UNGATED in why for why in defects(GET + 'bash /dev/null -c "%s"\n' % CHECK + USE)))
        # +chk x4 (rc 1, q28; forge for the others): the shell surely runs it, and the step stops.
        for runner in ("bash -c", "bash -e -c", "bash -n +n -c", "bash --norc -c"):
            with self.subTest(runner=runner):
                self.assertEqual([], defects(GET + '%s "%s"\n' % (runner, CHECK) + USE))
        # The price (q29, +chk x4): a FILE that runs its last parameter runs the check, but the
        # guard cannot see the FILE, so the use is reported.
        self.assertTrue(defects(GET + self.EVAL_LAST + 'bash w.sh -- -c "%s"\n' % CHECK + USE))

    def test_after_an_expansion_a_lone_dash_keeps_stdin_the_program(self):
        # P x4 on each (q40-q43, q46-q48, q49d-h): `X` may be `-s`, and the words after the `-` are
        # its parameters; quoted, `"$X"` is the same one word (forge).
        for script in ("X=-s\n" + body("bash $X - -c true", PIPE), "X=-s\n" + body("sh $X - -c true", PIPE),
                       "X=-s\n" + body("dash $X - -c true", PIPE), "X=s\n" + body("bash -$X - -c true", PIPE),
                       "X=-s\n" + body("bash $X - /dev/null", PIPE), "X=-s\n" + body("bash $X - x.sh", PIPE),
                       "X=-s\n" + body("sh $X - /dev/null", PIPE), "X=-s\n" + body("bash $X -e - x.sh", PIPE),
                       "X=-s\n" + body("bash -e $X - x.sh", PIPE), "X=-s\n" + body("bash $X -o errexit - x.sh", PIPE),
                       "X=-s\n" + body("bash --norc $X - x.sh", PIPE), "X=-s\n" + body("bash ${X:-} - x.sh", PIPE),
                       "X=-s\n" + body('bash "$X" - -c true', PIPE),
                       # The control (q44): the literal `-s` reports, as before.
                       body("bash -s - -c true", PIPE),
                       # The price, fail-closed (q45, rc 127): `X=` runs the FILE `-c`, nothing else.
                       "X=\n" + body("bash $X - -c true", PIPE)):
            with self.subTest(script=script):
                self.assertTrue(any(STREAM in why for why in defects(script)), script)

    def test_each_reading_and_an_operand_after_an_expansion_decide_a_row(self):
        # The `--rcfile` reading alone finds the string (matrix 49014, 49049: P x4; 66849: dash
        # refuses `-rcfile`, rc 2, and `sh` as bash runs P).
        for script in ("X='-rcfile'\nbash -$X -nor -c '%s'\n" % PIPE, "X='-rcfile'\nbash -$X -- -c '%s'\n" % PIPE,
                       "X='-rcfile'\nsh -$X -nor -c '%s'\n" % PIPE):
            with self.subTest(script=script):
                self.assertTrue(any(STREAM in why for why in defects(script)), script)
        # An operand after a word that may expand keeps stdin (matrix 22908, 48836, 48846: P x4).
        for script in ("X=\n" + body("bash --rcfile $X -e -init-file /dev/null", PIPE),
                       "X='s'\n" + body("bash -$X x.sh -c true", PIPE), "X='s'\n" + body("bash -$X -- -c true", PIPE)):
            with self.subTest(script=script):
                self.assertTrue(any(STREAM in why for why in defects(script)), script)

    def test_a_quoted_expansion_is_one_word_and_never_vanishes(self):
        # -- x4 (matrix 21652, 28132: rc 2; forge: `--version`, rc 0): `"$X"` is `--rcfile`'s FILE
        # whatever it holds, so `-rcfile` wants a FILE and `--version` prints and exits.
        for script in ("X=\n" + body('bash --rcfile "$X" -rcfile', PIPE), "X=\n" + body('sh --rcfile "$X" -rcfile', PIPE),
                       "X=\n" + body('bash --rcfile "$X" --version', PIPE)):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))
        # P x4 (forge): the string after it runs.
        self.assertTrue(any(STREAM in why for why in defects("X=\nbash --rcfile \"$X\" -c '%s'\n" % PIPE)))


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
