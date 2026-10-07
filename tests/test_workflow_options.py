"""#2331, the PROGRAMS lane: the stdin operand walk reads a shell's options as the shell does.

One class per mechanism of the cluster, each a spelling in which bash runs a download -- or runs
nothing -- that the guard read the other way, pinned as a live step beside the controls that must
read as they did. A row's comment carries its truth, b5 b3 dash gh (bash 5.2.21, bash 3.2.57, dash,
a GitHub runner's bash with `sh` = dash), measured with a recording `curl` that hands back a marker
program, a `sha256sum` whose `-c` fails, and the step run as GitHub runs it (`-e`, bash also
`-o pipefail`): FR fetched and ran, F- fetched only, -- neither, +chk the check ran. Every row's four
columns agree unless a comment says otherwise.
"""
import collections
import contextlib
import itertools
import os
import tempfile
import time
import unittest
from unittest import mock

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
# `main`'s sentence for a body the step reads as its own with no check in it counted (#2858 round 10).
WITHHELD = "and the step does not stop when that script fails"


def defects(script):
    return [why for _name, why in wg.job_defects([("step", script)])]


def as_main(test, scripts, what=STREAM):
    """#2858 round 10, the monotone ruling: rows an earlier round CLEARED, read again as `main` reads
    them -- reported, `what` in a sentence -- each a pin that fails if its row moves."""
    for script in scripts:
        with test.subTest(as_main=script):
            found = defects(script)
            test.assertTrue(any(what in why for why in found), (script, found))


def over_reported(test, scripts, what=STREAM):
    """#2858 round 10: rows `main` reads CLEAN, which this walk reads on past a long option's FILE
    (#2616) or a one-dash long word (#2864) to one that refuses, prints or exits -- nothing runs,
    and the row is reported: the named over-report of reading on with no clear."""
    for script in scripts:
        with test.subTest(over_reported=script):
            found = defects(script)
            test.assertTrue(any(what in why for why in found), (script, found))


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
        self.assertIn(WITHHELD, found[0])
        # -- -- -- --: `bash -s -c 'echo hi'` runs the string alone; the pipe in the body never --
        # reported all the same, as on `main` (#2647's over-report half; round 10 clears nothing).
        as_main(self, [body("bash -s -c 'echo hi'", PIPE)])

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
        # F- F- F- F- (rc 127, bash runs `x`): the body is data -- reported all the same, as on
        # `main`, which reads `-s` and the body (round 10 clears nothing).
        as_main(self, [GET + "X='-c sh'\nbash -s -c x \"$X\" x <<'EOF'\necho 'sh\\ttool' | sh\nEOF\n"], "tool")

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
                self.assertIn(WITHHELD, found[0])
        # -- -- -- --: the pipe in the body is never run -- reported all the same, as on `main`
        # (#2654's over-report half; round 10 clears nothing).
        as_main(self, [body("bash - /dev/null", PIPE)])

    def test_a_lone_dash_with_nothing_after_it_is_still_stdin(self):
        # F-+chk x4: the body is the program, the check runs and stops the step.
        self.assertEqual([], defects(GET + body("bash -", CHECK) + USE))
        self.assertTrue(any(STREAM in why for why in defects(body("bash -", PIPE))))


class TestALongOptionOfTheShell(unittest.TestCase):
    """#2616: a shell's long options have a table now. `--rcfile FILE` and `--init-file FILE`
    take the file and read on; a word outside the table, or one spelled `--name=value`, is one
    bash refuses (rc 2, no stdin read), and dash refuses every long option -- read on, as `main`
    reads it (#2858 round 10: no clear), and no check counted where the shell prints and exits."""

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

    def test_a_refused_long_option_reads_as_main(self):
        # -- -- -- -- (rc 2) on each: bash answers `invalid option`, dash `Illegal option --` --
        # reported, as on `main` (round 10 withdraws the refusal clear).
        as_main(self, [body(command, PIPE) for command in ("bash --bogus", "bash --rcfile=/dev/null", "dash --norc")])
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
        # The leading run's exits count no check (`_runs_none`, round 10); an rc FILE is no exit, and a
        # two-dash word after a short one is refused (rc 1), which an `-e` step stops at, as on main.
        for argv, none in ((["bash", "--version"], True), (["bash", "-version"], True), (["bash", "--norc", "--help"], True),
                           (["bash", "--rcfile", "f", "-version"], True), (["bash", "--rcfile", "--version"], False),
                           (["bash", "-e", "--version"], False), (["bash", "--norc"], False), (["bash", "-n"], True),
                           (["bash", "-n", "+n"], False), (["bash", "-D"], True)):
            with self.subTest(argv=argv):
                self.assertEqual(none, wo._runs_none(argv))
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
        # `main`'s readers, byte for byte (round 10), take `-login` for letters and refuse its `g`; the
        # string reader never asks them about a long word, which ends its search first (`_operand_past`).
        self.assertTrue(wo._refused(["bash", "-login"], 1))
        self.assertEqual("--login", wo.long_option(["bash", "-login"], 1))

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
        # refused by both bashes (`- : invalid option`). `main` reads the first two on, and so does
        # round 10 (no refusal clear); the rest `main` reads CLEAN too.
        as_main(self, [body("bash -bogus", PIPE), body("dash -login", PIPE)])
        for script in (body("bash -rcfile=/dev/null", PIPE), "bash -c -login '%s'\n" % PIPE,
                       "bash -c --login '%s'\n" % PIPE):
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
        # Reported as on `main` (round 10), bar the `-c` row, which `main` reads CLEAN too.
        as_main(self, [body("bash -help", PIPE), body("bash -e --help", PIPE), body("bash --rcfile=/dev/null -e", PIPE)])
        self.assertEqual([], defects("bash -c -login '%s'\n" % PIPE))
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
        # The body is read as `main` reads it -- the download reported (round 10: no clear) -- and
        # no check in it counts.
        for runner in ("bash +n -n -s", "bash -D +D -s", "bash -eo noexec -s", "bash -oe noexec -s"):
            with self.subTest(runner=runner):
                as_main(self, [body(runner, PIPE)])
                found = defects(GET + body(runner, CHECK) + USE)
                self.assertTrue(any(WITHHELD in why for why in found), (runner, found))
        # `-n +n -s` with a check in the body: the body is the program again, the check counts.
        self.assertEqual([], defects(GET + body("bash -n +n -s", CHECK) + USE))
        # Each `o` takes a word (`-oo errexit noexec`: the second is `noexec`), and `D` runs
        # nothing whatever `+n` says (`+nD`): -T rc 0, the use after unverified (the seat's matrix).
        for runner in ("bash -oo errexit noexec", "sh -oo errexit noexec", "dash -oo errexit noexec", "bash +nD"):
            with self.subTest(runner=runner):
                as_main(self, [body(runner, PIPE)])
                found = defects(GET + body(runner, CHECK) + USE)
                self.assertTrue(any(WITHHELD in why for why in found), (runner, found))

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
        # Nothing expands, nothing runs: -- -- on each (rc 0, 2, 0, 0) -- reported as on `main`
        # (round 10 withdraws these clears; no check in the first, third or fourth counts).
        as_main(self, [body("bash -K -s", PIPE), body("bash -n -s", PIPE), body("bash -Oo extglob noexec", PIPE)])
        over_reported(self, [body("bash --rcfile /dev/null --version", PIPE)])
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
        # #2858 round 3 (B3): `_run` is one pass per argv, kept by identity -- twenty and two
        # thousand one-dash words cost within 2x of the same run of two-dash words (the seat
        # measured 7.7 s at sixteen and a timeout at twenty on the round-3 head). Round 10: `main`
        # reads the two-dash run's heredoc itself, and the one-dash run's only through this walk, as
        # no shell's sure program -- which the guard folds twice (`job_defects`). So the pair keeps
        # its 2x bound like for like, both runs ending in a one-dash word `main` reads as a `-c`
        # cluster (each folded twice: 0.9x measured on the Mac), and the plain pair carries that
        # second fold (1.6x-1.8x on the Mac, 2.15x on GitHub's 3.13 runner before `long_option` was
        # kept per argv): a 3x bound.
        import time
        for n in (20, 2000):
            for tail, bound in ((" -norc", 2), ("", 3)):
                runs = {}
                for opt in ("--norc", "-norc"):
                    t0 = time.perf_counter()
                    self.assertTrue(defects(body("bash " + " ".join([opt] * n) + tail, PIPE)))
                    runs[opt] = time.perf_counter() - t0
                self.assertLess(runs["-norc"], max(bound * runs["--norc"], 0.5), (n, tail, runs))

    def test_a_shell_that_reads_its_program_and_runs_none_of_it(self):
        # #2858 round 3: `-n` (noexec) and `-o noexec` read the heredoc and run nothing of it,
        # rc 0 -- and after a short option `-version` and `-noprofile` are letters with `n` among
        # them (a mid-cluster `o` with no word after it is accepted silently; with one, that word
        # is its name: `bash -e -version -c P` -> `-c: invalid option name`, rc 2). With a check in
        # the body and a use after: -T (the use runs unverified) on both bashes -- reported, no
        # check counted; with a download in the body: -- -- (nothing runs) -- reported as on
        # `main` (round 10 withdraws the clear). `-D` prints strings, same.
        for runner in ("bash -n -s", "bash -o noexec -s", "bash -s -version", "bash -e -version",
                       "bash -e -noprofile", "bash -D", "bash -Ds", "sh -n", "dash -n"):
            with self.subTest(runner=runner):
                found = defects(GET + body(runner, CHECK) + USE)
                self.assertTrue(any(WITHHELD in why for why in found), (runner, found))
                as_main(self, [body(runner, PIPE)])
        as_main(self, ["bash -e -version -c '%s'\n" % PIPE])     # `-c` is no name: rc 2, as main reads it
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
                self.assertTrue(any(WITHHELD in why or UNVERIFIED in why for why in found), (runner, found))
        # -- -- -- -- (rc 0): a download in the heredoc or the string is never run.
        # `--wordexp` expands stdin as words (bash 3.2) or is refused (5.2); `-rcfile` as the
        # last word wants a FILE (rc 2): nothing runs under either -- reported as on `main`
        # (round 10 withdraws the clear).
        as_main(self, [body("bash --version", PIPE), body("bash -version", PIPE), body("bash -help", PIPE),
                       "bash --help -c '%s'\n" % PIPE, "bash --dump-strings -c '%s'\n" % PIPE,
                       body("bash -wordexp", PIPE), "bash --wordexp -c '%s'\n" % PIPE])
        over_reported(self, [body("bash -rcfile", PIPE)])
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
        # to dash too (`sh -c true -s`); `-c` alone reads no stdin. `bash -s -c true` is reported
        # all the same, as on `main` (#2647's over-report half, round 10).
        as_main(self, [body("bash -s -c true", PIPE)])
        for runner in ("bash -sc true", "bash -cs true", "bash -c -s true", "sh -c true -s", "dash -c true -s", "sh -c true"):
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
        with self.subTest(row="bash /dev/null -c, the sentence"):
            self.assertTrue(any(self.UNGATED in why for why in defects(GET + 'bash /dev/null -c "%s"\n' % CHECK + USE)))
        # +chk x4 (rc 1, q28; the round-6 seat for `-c --`, its S5; forge for the others): the shell
        # surely runs it, and the step stops.
        for runner in ("bash -c", "bash -e -c", "bash -n +n -c", "bash --norc -c", "bash -c --"):
            with self.subTest(runner=runner):
                self.assertEqual([], defects(GET + '%s "%s"\n' % (runner, CHECK) + USE))
        # The price (q29, +chk x4): a FILE that runs its last parameter runs the check, but the
        # guard cannot see the FILE, so the use is reported.
        with self.subTest(row="q29, the price"):
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
        # whatever it holds, so `-rcfile` wants a FILE and `--version` prints and exits -- reported
        # as on `main` (round 10 withdraws the clear).
        as_main(self, ["X=\n" + body('bash --rcfile "$X" --version', PIPE)])
        over_reported(self, ["X=\n" + body('bash --rcfile "$X" -rcfile', PIPE), "X=\n" + body('sh --rcfile "$X" -rcfile', PIPE)])
        # P x4 (forge): the string after it runs.
        self.assertTrue(any(STREAM in why for why in defects("X=\nbash --rcfile \"$X\" -c '%s'\n" % PIPE)))


class TestWhatMainReportsStaysReported(unittest.TestCase):
    """#2858 round 7, the coordinator's corrected bar: a row main REPORTS while a shell runs the
    payload or the unverified use stays reported, named or not. Two classes the earlier rounds
    named close, each by a general rule. Truth from the round-5 seat's matrix (row ids: bash 5.2.21
    and 3.2.57 with `sh` as dash and as each bash) or the forge (`gt2.sh`, both child bashes)."""

    PRETTY = ("-norc -pretty-print", "-rcfile /dev/null -pretty-print", "--rcfile /dev/null -pretty-print",
              "-rcfile -e -pretty-print", "-rcfile -- -pretty-print", "-rcfile -login -pretty-print",
              "-init-file /dev/null -pretty-print", "-restricted -pretty-print")

    def test_pretty_print_runs_none_of_the_stdin_program_but_a_dash_c_string_still_runs(self):
        # 5.2's `--pretty-print` prints the heredoc and runs none of it, and 3.2 refuses it (rc 1):
        # the use after runs past a check never run where the step's bash is 5.2 (T, rc 0; matrix
        # 07031-07967 and the `sh` twins 10415-11351, 21646 and 28126) -- reported, as on main.
        # The round-6 seat's hunt adds a quoted FILE before it (112956, 113056, 115068, 115708,
        # 116348, 113788: T under 5.2): one word (`"$X"`, `"$*"`, `"${A[*]}"`) or an `@` form.
        for runner in ["%s %s" % (shell, words) for shell in ("bash", "sh") for words in self.PRETTY] + [
                'X=\nbash --rcfile "$X" -pretty-print', 'X=\nsh --rcfile "$X" -pretty-print',
                'X=\nbash -rcfile "$X" -pretty-print', 'X=\nbash --init-file "$X" -pretty-print',
                'set --\nbash --rcfile "$*" -pretty-print', 'A=()\nbash --rcfile "${A[*]}" -pretty-print',
                'set -- /dev/null\nbash --rcfile "$@" -pretty-print',
                'A=(/dev/null)\nbash --rcfile "${A[@]}" -pretty-print']:
            with self.subTest(runner=runner):
                found = defects(GET + body(runner, CHECK) + USE)
                self.assertTrue(any("tool" in why for why in found), found)
        # -- x4 with bash 5.2.21 and 3.2.57 each as the child (forge, `gt2.sh`): a download in the
        # heredoc never runs -- the stdin program is uncredited, and reported as on `main` (round 10).
        as_main(self, [body("bash --pretty-print", PIPE)])
        over_reported(self, [body("bash -norc -pretty-print", PIPE)])
        # A `-c` string after it runs: FR x4 with bash 5.2.21 as the child, -- (rc 2) with 3.2.57
        # (forge) -- so no string reader refuses it, and a check in it keeps its credit: +chk, rc 1,
        # with either child bash.
        for script in ("bash --pretty-print -c '%s'\n" % PIPE, "bash -pretty-print -c '%s'\n" % PIPE):
            with self.subTest(script=script):
                self.assertTrue(any(STREAM in why for why in defects(script)), script)
        self.assertEqual([], defects(GET + 'bash --pretty-print -c "%s"\n' % CHECK + USE))

    def test_a_parameter_expansion_right_after_dash_c_stands_where_the_shell_reads_options(self):
        # P x4 (matrix 04570, 04574, 04910, 04914, which main reports; the forge for the rest):
        # `Y=-c` makes it an option word, as `Y=` (it vanishes) and `Y=-e` do, so the word after it
        # is the string. `Y=x` runs `x` (rc 127) and the download is `$0`: the price, fail-closed.
        for script in ("Y=-c\nbash -login -c $Y '%s'\n", "Y=-c\nbash -posix -c $Y '%s'\n",
                       "Y=-c\nsh -login -c $Y '%s'\n", "Y=-c\nsh -posix -c $Y '%s'\n", "Y=-c\nbash -c $Y '%s'\n",
                       "Y=-c\nbash -c \"$Y\" '%s'\n", "Y=\nbash -c $Y '%s'\n", "Y=-e\nbash -c $Y '%s'\n",
                       "Y=x\nbash -c $Y '%s'\n"):
            with self.subTest(script=script):
                found = defects(script % PIPE)
                self.assertTrue(any("`$Y` where it reads its options" in why for why in found), found)
        # -- (forge): in every reading the string is `echo hi`, and the download a parameter.
        self.assertEqual([], defects("Y=-c\nbash -c $Y 'echo hi' '%s'\n" % PIPE))


class TestAQuotedExpansionThatMayBeNoWordOrMany(unittest.TestCase):
    """#2858 round 7, the round-6 seat's B2 and B3: only a quoted expansion that is always ONE word --
    `"$X"`, `"$*"`, `"${A[*]}"` -- is a long option's FILE as written and never vanishes; an `@` form
    (`"$@"`, `"${A[@]}"`) may be no word or several, an expansion like `$X`. And the word after a lone
    `-` is the script FILE only where it is literal or one word. Truth from the round-6 seat's
    direct probes (r-, k- and q-numbers: touch marks under bash 5.2.21 and 3.2.57, `sh` as dash and
    as each bash)."""

    def test_an_at_form_as_a_long_options_file_may_be_no_word(self):
        # P x4 (r01-r05, r11; r08 where `sh` is bash): with no words, the next word is the rc FILE
        # and the shell runs on -- `-nor` then `-c P`, or past `-K`/`--version`/`-n` the heredoc.
        for script in ("bash --rcfile \"$@\" -nor -c '%s'\n" % PIPE, body('bash --rcfile "$@" -K', PIPE),
                       body('bash --rcfile "$@" --version', PIPE), "A=()\n" + body('bash --rcfile "${A[@]}" -K', PIPE),
                       body('bash --rcfile "$@" -n -s', PIPE), body('sh --rcfile "$@" -K', PIPE),
                       body('bash -rcfile "$@" -version', PIPE),
                       # Beside a `$X` (k02373, k02374): the "gone" reading holds for the `@` form too.
                       "X=\n" + body('bash --rcfile "$@" -K $X', PIPE),
                       "X=\nbash --rcfile \"$@\" --version $X -c '%s'\n" % PIPE):
            with self.subTest(script=script):
                self.assertTrue(any(STREAM in why for why in defects(script)), script)
        # T x4 (r06, r07): `-n` lands in the option run, the check never runs, the use does.
        for script in ("set -- /dev/null -n\n" + GET + 'bash --rcfile "$@" -c "%s"\n' % CHECK + USE,
                       "A=(/dev/null -n)\n" + GET + body('bash --rcfile "${A[@]}"', CHECK) + USE):
            with self.subTest(script=script):
                self.assertTrue(any("tool" in why for why in defects(script)), script)
        # -- x4 (r09, r10: rc 2; k02412, k02616: rc 0): a one-word form is the FILE, and nothing runs
        # -- reported as on `main` (round 10 withdraws the clear).
        as_main(self, ["X=\n" + body('bash --rcfile "$X" -K', PIPE), "A=()\n" + body('bash --rcfile "${A[*]}" -K', PIPE),
                       "X=\nY=\nbash --rcfile \"$Y\" --version $X -c '%s'\n" % PIPE])
        over_reported(self, ["X=\nY=\nbash -rcfile \"$Y\" --version $X -c '%s'\n" % PIPE])
        # The price, accepted (r12: rc 127 for every value the seat ran; main reports it too): after
        # an `@` form nothing is sure, so a refusal there no longer clears.
        self.assertTrue(any(STREAM in why for why in defects("bash --rcfile \"$@\" -o pipefial -c '%s'\n" % PIPE)))

    def test_a_word_after_a_lone_dash_that_may_vanish_leaves_stdin_the_program(self):
        # P x4 (r20-r23, r26, r27): with no word there, the shell reads the heredoc.
        for script in ("X=\n" + body("bash - $X", PIPE), body('bash - "$@"', PIPE), "X=\n" + body("sh - $X", PIPE),
                       "X=\n" + body("dash - $X", PIPE), "X=\n" + body("bash -e - $X", PIPE), body("bash - $(true)", PIPE),
                       # The control (r24): `--` keeps stdin, as before.
                       "X=\n" + body("bash -- $X", PIPE)):
            with self.subTest(script=script):
                self.assertTrue(any(STREAM in why for why in defects(script)), script)
        # -- x4 (r28, rc 127): a one-word `"$X"` is the FILE, and nothing runs -- reported as on
        # `main` (round 10 withdraws the clear).
        as_main(self, ["X=x.sh\n" + body('bash - "$X"', PIPE)])


class TestAClearingRuleFiresOnlyOnSureInput(unittest.TestCase):
    """#2858 round 8, the coordinator's ruling on the round-7 seat: a rule that CLEARS fires only on
    input proven sure -- an allowlist, never a denylist. Round 10 withdraws every clear, so what is
    left is the CREDIT side: `--pretty-print` counts no check in the stdin program where nothing in
    the option run makes the shell interactive (`_printed`); `_one_word` allows only the quoted
    forms proven to be one word. Truth from the round-7 seat's hunt (row ids) and direct probes (z,
    w, a, n): touch marks under bash 5.2.21 and 3.2.57, `sh` as dash and as each bash."""

    def test_pretty_print_runs_the_heredoc_where_the_shell_may_be_interactive(self):
        # P on 5.2 (b5, sh5; 3.2 refuses the option, rc 2): bash 5.2 ignores `--pretty-print` under
        # `-i` and runs the heredoc -- 121640 (z01), z12 `-il`, z13 `-s -i`, w18 `-ri`, w19 `-o posix
        # -i`, z06 `sh` where sh is bash 5.2, w01 `sudo`, and an `-i` an expansion may spell (z03,
        # 121700).
        for script in (body("bash --pretty-print -i", PIPE), body("bash --pretty-print -il", PIPE),
                       body("bash --pretty-print -s -i", PIPE), body("bash --pretty-print -ri", PIPE),
                       body("bash --pretty-print -o posix -i", PIPE), body("sh --pretty-print -i", PIPE),
                       body("sudo bash --pretty-print -i", PIPE), "X=-i\n" + body("bash --pretty-print $X", PIPE),
                       "Y=-i\n" + body('bash --pretty-print "$Y"', PIPE)):
            with self.subTest(script=script):
                self.assertTrue(any(STREAM in why for why in defects(script)), script)
        # +chk, rc 1 on 5.2 (z19, 121641): the check runs and stops the step -- credited, as on main.
        with self.subTest(row="z19"):
            self.assertEqual([], defects(GET + body("bash --pretty-print -i", CHECK) + USE))
        # -- (121638 rc 0/2, 121654 `+i` rc 0/2, z02 rc 2): nothing interactive after it, or the
        # option refused after a short one, and the heredoc never runs -- reported as on `main`
        # (round 10 withdraws the clear), and with a check, no check counted where 5.2 prints it.
        as_main(self, [body("bash --pretty-print", PIPE), body("bash --pretty-print +i", PIPE),
                       body("bash -i --pretty-print", PIPE)])
        for runner in ("bash --pretty-print", "bash --pretty-print +i", "bash --pretty-print -i +i"):
            with self.subTest(withheld=runner):
                self.assertTrue(any(WITHHELD in why for why in defects(GET + body(runner, CHECK) + USE)), runner)

    def test_one_word_is_an_allowlist(self):
        # P x4 (120923, 120949, 127438, a11): `"${!X}"` with `X=@` or `X='A[@]'` is no word or
        # several, as `"$@"` is, and so is any form the allowlist does not name.
        for script in ("X=@\nset --\nbash --rcfile \"${!X}\" -nor -c '%s'\n" % PIPE,
                       "A=()\nX='A[@]'\nbash --rcfile \"${!X}\" -nor -c '%s'\n" % PIPE,
                       "X=@\nset --\n" + body('bash - "${!X}"', PIPE),
                       "X=@\nset --\n" + body('bash --rcfile "${!X%x}" -K', PIPE)):
            with self.subTest(script=script):
                self.assertTrue(any(STREAM in why for why in defects(script)), script)
        # T x4 (z09): `-n` lands in the run, the check never runs, the use does.
        with self.subTest(row="z09"):
            self.assertTrue(any("tool" in why for why in defects(
                "X=@\nset -- /dev/null -n\n" + GET + body('bash --rcfile "${!X}"', CHECK) + USE)))
        # The price, fail-closed (z29 rc 2, a03 rc 127, n11 rc 127): a form outside the allowlist,
        # or a quoted `"$(...)"` after a lone `-`, is read as `$X` even where it is one word.
        for script in ("X=*\nset --\n" + body('bash --rcfile "${!X}" -K', PIPE), "set --\n" + body('bash - "${#@}"', PIPE),
                       body('bash - "$(true)"', PIPE)):
            with self.subTest(script=script):
                self.assertTrue(defects(script), script)

    def test_the_one_word_scan_is_linear(self):
        # CodeQL on eb6da4e0 (high): `_ONE_WORD` could split a `$NAME` beside text two ways inside a
        # default, so a failing match backtracked exponentially -- `'${X:-' + '0$A' * 24 + '@}'` took
        # 1.2 s and doubled with each repetition. The scan reads each token once: CodeQL's shape, with
        # and without `}`, and the defaults that blew up return at once at 10,000 repetitions.
        class Kept(str):
            kept = True
        for shape, one in (("${{A-$A" + "0$A" * 10000, False), ("${{A-$A" + "0$A" * 10000 + "}", False),
                           ("${X:-" + "0$A" * 10000 + "@}", False), ("${X:-" + "0$A" * 10000, False),
                           ("${X:-" + "0$A" * 10000 + "}", True)):
            with self.subTest(shape=shape[:8], end=shape[-2:]):
                start = time.perf_counter()
                self.assertEqual(one, wo._one_word(Kept(shape)))
                self.assertLess(time.perf_counter() - start, 1.0)

    def test_a_literal_after_a_lone_dash_is_the_file_and_a_value_after_dash_c_dash_dash_may_vanish(self):
        # -- (127346, rc 127 x4): a literal `-` after a lone `-` is the FILE named `-` -- reported
        # as on `main` (round 10 withdraws the clear).
        as_main(self, [body("bash - -", PIPE)])
        # P x4 (135648, 131856, 132172; main CLEAN too): with `Y` empty the next word is the string.
        for script in ("Y=\nsh -c -- $Y '%s'\n" % PIPE, "Y=\nbash -c -- $Y '%s'\n" % PIPE,
                       "Y=\nbash -c - $Y '%s'\n" % PIPE):
            with self.subTest(script=script):
                self.assertTrue(defects(script), script)


class TestAClearOrACreditNeedsASureShell(unittest.TestCase):
    """#2858 round 9, the coordinator's literal-only ruling on the round-8 seat: a clear or a check
    credit this guard's stdin and string walks add fires only for (1) a shell written as itself and
    named as one (`bash`, `sh`, `dash`, by PATH or in `/bin` or `/usr/bin`), reached through literal
    words; (2) an option run literal up to the deciding word; (3) a step that leaves the shell its
    own name -- no function or alias of a shell's or a wrapper's name, no sourced file, no `eval` of
    a word it does not spell, no `BASH_ENV`/`ENV`; (4) the state the shell itself computes, startup
    files included. Anything else reads as main read it. Round 10 (the monotone ruling) withdraws
    every clear and the certificate with it: each row below reads as `main` reads it or adds a
    report, and its clean controls are reported as `main` reports them. Truth: the round-8 seat's
    hunts (row ids) and direct cases (y..), touch marks under bash 5.2.21 and 3.2.57, `sh` as dash
    and as each bash; and the round-9 forge probes, cited where they stand."""

    def assert_reported(self, scripts):
        for script in scripts:
            with self.subTest(script=script):
                self.assertTrue(defects(script), script)

    def assert_clean(self, scripts):
        for script in scripts:
            with self.subTest(script=script):
                self.assertEqual([], defects(script), script)

    def test_rule_1_a_shell_written_as_itself(self):
        # P x4 (yh01 147164, yh03, yh09; main REPORTS): `SH='bash --rcfile'` makes `--pretty-print` the
        # rc FILE and bash runs the heredoc -- no clear behind a command word that is not literal.
        self.assert_reported(["SH='bash --rcfile'\n" + body("${SH:-bash} --pretty-print", PIPE),
                              "SH='sudo bash --rcfile'\n" + body("${SH:-bash} --pretty-print", PIPE),
                              "SH='bash --rcfile'\n" + body("${SH-/bin/bash} --pretty-print", PIPE)])
        # T on b5 sh5 (147153; main CLEAN): behind such a word no check counts either.
        self.assert_reported([GET + body("${SH:-bash} --pretty-print", CHECK) + USE])
        # P x2 (bash 5.2.21, 3.2.57, this round: `S='bash -s'` runs `bash -s bash --version`, reading
        # the heredoc): an optional `$S` the reader looks through is no literal wrapper; nor is a
        # wrapper's word that may expand. A shell named by a path the step may write (`./bash`, the
        # named price: rc 127 here) is not one either.
        self.assert_reported([body("$S bash --version", PIPE), body('sudo -u "$U" bash -K', PIPE),
                              body("./bash --version", PIPE), body("zsh --pretty-print", PIPE)])
        # -- (rc 0, 2): the controls, literal, through a literal wrapper or an assignment -- round 9
        # cleared them; reported as on `main` now (round 10).
        as_main(self, [body(c, PIPE) for c in ("bash --version", "sudo bash --version", "env bash -K",
                                              "/usr/bin/bash --version", "X=1 bash --version", "sh -o pipefial")])

    def test_rule_2_a_literal_run(self):
        # P x4 (160000 ym01, ym06, ym16, yk11, yl08; main REPORTS): after a lone `-` a word that may be
        # no word -- a nested `${…}` the reader leaves plain, a pattern under `nullglob` -- leaves
        # stdin the program; so does a `~` (`HOME=-i`, F5's tilde rows: main CLEAN too).
        self.assert_reported(["X=\nY=\n" + body("bash - ${X:-${Y}}", PIPE), "A=()\ni=\n" + body("bash - ${A[${i}]}", PIPE),
                              "set --\n" + body("bash - ${1:-${2}}", PIPE),
                              "shopt -s nullglob\n" + body("bash - /nonexistent*", PIPE),
                              "shopt -s nullglob\n" + body("dash - /nonexistent*", PIPE),
                              "HOME=-i\n" + body("bash --pretty-print ~", PIPE)])
        # The price (yl09, rc 127 x4): without `nullglob` the pattern stays the FILE, read as `$X` all the same.
        self.assert_reported([body("bash - /nonexistent*", PIPE)])
        # -- (ym09 rc 127, 127346): a quoted one-word form, and a literal word, are the FILE -- round 9
        # cleared them; reported as on `main` now (round 10).
        as_main(self, ["X=\nY=\n" + body('bash - "${X:-${Y}}"', PIPE), body("bash - x.sh", PIPE)])

    def test_rule_3_a_step_that_leaves_the_shell_its_name(self):
        # P x4 (yg01 147490, yg04, yg02, yg07, yg08, yg09; main REPORTS): a function or alias of the
        # shell's or a wrapper's name runs the heredoc whatever the words after it say.
        shadows = ["bash() { command bash; }\n", "function sh { command sh; }\n",
                   "alias bash='command bash -s --'\nshopt -s expand_aliases\n", "sudo() { bash; }\n",
                   "env() { bash; }\n", "command() { bash; }\n", "eval 'bash() { command bash; }'\n",
                   "printf 'bash() { command bash; }' > lib.sh\n. ./lib.sh\n",
                   "printf 'exec env -u BASH_ENV bash -s' > e.sh\nexport BASH_ENV=$PWD/e.sh\n"]
        runners = {"sudo() { bash; }\n": "sudo bash --version", "env() { bash; }\n": "env bash --version",
                   "command() { bash; }\n": "command bash --version", "function sh { command sh; }\n": "sh --version"}
        self.assert_reported([pre + body(runners.get(pre, "bash --version"), PIPE) for pre in shadows])
        # P on b5 (this round: `BASH_ENV` runs before `--pretty-print` prints, and may read stdin).
        self.assert_reported([shadows[-1] + body("bash --pretty-print", PIPE)])
        # The marked inner parse: a string `eval` reads, and a `$(…)` the guard parses apart, are no
        # surer than the step around them; without the function the `eval`'s string clears.
        self.assert_reported([shadows[0] + "eval \"bash --version <<'EOF'\n%s\nEOF\"\n" % PIPE,
                              shadows[0] + "x=$(bash --version <<'EOF'\n%s\nEOF\n)\n" % PIPE])
        # The string #2500's walk parses itself takes the holder's certificate (`inner_command`): `eval
        # 'bash -s -c true'` runs `true` and leaves the heredoc unread (-- x4), unless a `bash()` reads
        # it (P x4); an `eval` of a word the guard does not spell may define anything.
        self.assert_reported([shadows[0] + body("eval 'bash -s -c true'", PIPE), 'eval "$X"\n' + body("bash --version", PIPE)])
        # Without the function round 9 cleared these; reported as on `main` now (round 10).
        as_main(self, ["eval \"bash --version <<'EOF'\n%s\nEOF\"\n" % PIPE, body("eval 'bash -s -c true'", PIPE)])
        # The named over-report (yg03, -- x4): a function that hands its words on runs nothing here.
        self.assert_reported(['bash() { command bash "$@"; }\n' + body("bash --version", PIPE)])

    def test_rule_3_what_may_change_the_name_in_the_step_or_the_job(self):
        # The coordinator's widened scope: a step that sets `PATH`, `SHELLOPTS` or `BASHOPTS`, exports a
        # `BASH_FUNC_…` function, or uses `hash` or `enable` may change what `bash` names or runs before
        # its options -- it reads as main, and main REPORTS each.
        self.assert_reported([pre + body("bash --version", PIPE) for pre in (
            'export PATH="$PWD/bin:$PATH"\n', "SHELLOPTS=xtrace\n", "export BASHOPTS=extglob\n",
            "export 'BASH_FUNC_bash%%=() { command bash; }'\n", 'hash -p "$PWD/x" bash\n', "enable -n echo\n")])
        # A job's earlier step that writes `$GITHUB_ENV` or `$GITHUB_PATH` sets `BASH_ENV` or `PATH` for
        # every later one (`workflow_sure.uncertified`): no clear after it.
        def job(*scripts):
            return [why for _name, why in wg.job_defects([("s%d" % n, s) for n, s in enumerate(scripts)])]
        later = body("bash --pretty-print", PIPE)
        for before in ('echo "BASH_ENV=$PWD/e.sh" >> "$GITHUB_ENV"\n', 'echo "$PWD/bin" >> "$GITHUB_PATH"\n'):
            with self.subTest(before=before):
                self.assertTrue(job(before, later), before)
        # (c) A write that may plant a shell or a wrapper where a later bare word finds it -- in the step
        # or a step before it: a target named like one (a PATH directory main does not bind, `cp` to
        # `/snap/bin`, a decompressed `bash.gz`), one not written as itself, an archive unpacked.
        planted = ["curl -fsSLo ~/.cargo/bin/bash %sb\n" % URL, "cp tool /snap/bin/sh\n", "gunzip -f bash.gz\n",
                   'curl -fsSLo "$OUT" %sb\n' % URL, "echo 'exec bash -s' > ~/.local/bin/sudo\n", "tar -xzf tools.tgz -C ~/bin\n"]
        self.assert_reported([pre + body("bash --version", PIPE) for pre in planted])
        for before in planted:
            with self.subTest(job=before):
                self.assertTrue(job(before, body("bash --version", PIPE)), before)
        # The controls round 9 cleared -- a literal target named like no shell, before or in the step
        # -- reported as on `main` now (round 10).
        as_main(self, ["curl -fsSLo tool %stool\n" % URL + body("bash --version", PIPE)])
        self.assertTrue(job("echo hi > notes.txt\n", body("bash --version", PIPE)))
        # The same step text in two jobs, in either order: reported in each, as on `main`.
        writer = 'echo "BASH_ENV=$PWD/e.sh" >> "$GITHUB_ENV"\n'
        for order in ((False, True, False), (True, False, True)):
            for tainted in order:
                with self.subTest(order=order, tainted=tainted):
                    self.assertTrue(job(writer, later) if tainted else job("echo hi\n", later))

    def test_rule_4_the_state_the_shell_computes(self):
        # T on b5 sh5 (yf08 141005, yf01, 140309, yj08, this round's `--rcfile -i`; main REPORTS on
        # yf08's kin): `+i` after `-i`, an rc FILE spelled `-i`, an `-i` past `--` and a one-dash
        # `-login` leave 5.2 printing the check, and the use runs.
        self.assert_reported([GET + body("bash %s" % run, CHECK) + USE for run in (
            "-norc --pretty-print -i +i", "--pretty-print -i +i", "--pretty-print --rcfile -i",
            "--pretty-print --init-file -i", "--pretty-print -s -- -i", "--pretty-print -login")])
        # +chk rc 1 on b5 sh5, rc 2 on b3 (yf12, yf13): interactive, the check runs -- credited, as on main.
        self.assert_clean([GET + body("bash --pretty-print -i", CHECK) + USE,
                           GET + body("bash --pretty-print +i -i", CHECK) + USE])
        # P on b5 (this round): a login run sources a `~/.bash_profile` the step may have written,
        # which may read stdin itself -- no clear; the named price where it is the runner's own.
        self.assert_reported([body("bash --login --pretty-print", PIPE), body("bash --pretty-print -l", PIPE)])
        # -- (bash 5.2.21 and 3.2.57, round 9: `--: invalid option`, rc 1/2): a two-dash option after a
        # short one is refused, and nothing runs -- reported as on `main` now (round 10).
        as_main(self, [body("bash -e --version", PIPE), body("bash -i --pretty-print", PIPE),
                       body("bash -o pipefail --norc", PIPE)])
        # The state `_printed` reads (round 10: a reason to count no check, never a clear).
        for argv, printed in ((["bash", "--pretty-print", "+i", "-i"], False), (["bash", "--pretty-print", "-i", "+i"], True),
                              (["bash", "--pretty-print", "--rcfile", "-i"], True), (["bash", "--pretty-print", "-s", "--", "-i"], True),
                              (["bash", "--pretty-print", "-login"], True), (["bash", "--pretty-print", "-o", "interactive"], False),
                              (["bash", "-e", "--pretty-print"], False)):
            with self.subTest(argv=argv):
                self.assertEqual(printed, wo._printed(argv))

    def test_a_mixed_word_a_member_after_dash_c_dash_dash_and_the_floor(self):
        # P x2 (bash 5.2.21, 3.2.57, this round): `$(echo '-s ')<(…)` is `-s /dev/fd/63`, so bash
        # reads the heredoc -- a mixed word is no sure FILE (#2592's clear is gone; its own
        # `$(true)<(…)` row is the named over-report, as on main).
        self.assert_reported([body("bash $(echo '-s ')<(echo 'echo x')", PIPE),
                              "echo '%s' | bash $(true)<(echo 'echo x')\n" % PIPE])
        # -- x4 (yeb; main CLEAN): a member after `-c --` is the string, never an option or nothing (F3).
        self.assert_clean(["Y=\nbash -c -- \"$Y\" '%s'\n" % PIPE, "Y=\nsh -c - \"$Y\" '%s'\n" % PIPE])
        # main's floor for a shell no certificate covers (`_main_walk`, `_dash_c_strings`,
        # `_floor_candidates`): no less read than main read, and no check counted it did not count --
        # main REPORTS each of these. P x4: `command bash` reads the heredoc whatever `-login -c` says;
        # T x4: `bash() { :; }` runs nothing and the use runs unverified (main never counted the check:
        # `-norc` is `-c` to it, `/dev/null` its FILE); `SH=true` does the same.
        self.assert_reported(["bash() { command bash; }\n" + body("bash -login -c", PIPE),
                              "bash() { :; }\n" + GET + body("bash -norc", CHECK) + USE,
                              "bash() { :; }\n" + GET + body("bash --rcfile /dev/null", CHECK) + USE,
                              GET + body("${SH:-bash} --rcfile /dev/null", CHECK) + USE,
                              "${SH:-bash} -o -c '%s'\n" % PIPE, "${SH:-bash} --rcfile $X '%s'\n" % PIPE])
        # The walk's own answer for a word no certificate covers, as a `$(…)`'s statement or a direct
        # call sees it: main's -- the heredoc read, and no check counted.
        self.assertEqual(wp.SHELL_PROGRAM, wp._stdin(["bash", "-login", "-c"], 0)[0])
        self.assertIsNone(wp._stdin(["bash", "--rcfile", "/dev/null"], 0)[1])


class TestAnOptionValueTheShellRefuses(unittest.TestCase):
    """#2606 (and #2603's letter half in the same walk): a measured shell exits 2 before it reads
    stdin at a `-o` name outside its table, at a `-o` value that is no name at all, and at a
    letter it refuses -- in the stdin walk and in the option words before a `-c` cluster."""

    def test_a_refused_name_or_value_reads_as_main(self):
        # -- -- -- -- (rc 2) on each -- reported as on `main` (#2606 and #2603's over-reports; round
        # 10 withdraws the refusal clear, and both issues move to Refs).
        as_main(self, [body("bash -o pipefial", PIPE), body("sh -o -", PIPE), body("bash -o /dev/stdin", PIPE),
                       body("bash -oo pipefail -", PIPE), "bash -o pipefial -c '%s'\n" % PIPE,
                       "sh -c -o - '%s'\n" % PIPE, body("bash -K", PIPE)])

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
        # `main`'s reader, byte for byte (round 10): a value of letters outside the table refuses; a
        # value that is not all letters is read on, fail-closed, as `main` reads it.
        self.assertTrue(wo._refused_name(["bash", "-o", "pipefial"], 1))
        self.assertFalse(wo._refused_name(["sh", "-o", "-"], 1))
        self.assertFalse(wo._refused_name(["bash", "-o", "/dev/stdin"], 1))
        self.assertFalse(wo._refused_name(["bash", "-o", "pipefail"], 1))
        self.assertFalse(wo._refused_name(["bash", "-o", "$X"], 1))
        self.assertFalse(wo._refused_name(["zsh", "-o", "pipefial"], 1))


class TestAWordHoldingAProcessSubstitution(unittest.TestCase):
    """#2592 read a word holding any `<(...)` as the FILE it names, since bash always substitutes a
    real path for it. But a command substitution beside it may split an option off first --
    `$(echo '-s ')<(…)` is `-s /dev/fd/63`, and bash reads the heredoc (#2858 round 9) -- so a mixed
    word is no literal and reads as one that may vanish, as on main."""

    def test_a_mixed_word_may_vanish(self):
        # P x2 (bash 5.2.21, 3.2.57; dash has no `<(`): the heredoc is bash's program.
        found = defects(body("bash $(echo '-s ')<(echo 'echo x')", PIPE))
        self.assertTrue(any(STREAM in why for why in found), found)
        # -- -- rc2 -- (the named over-report, as on main): #2592's own row runs the path.
        self.assertTrue(any(STREAM in why for why in defects("echo '%s' | bash $(true)<(echo 'echo x')\n" % PIPE)))
        # FR FR FR FR: a command substitution alone may vanish, and the body is read.
        self.assertTrue(any(STREAM in why for why in defects(body("bash $(true)", PIPE))))


class TestTheWalkJoinsMains(unittest.TestCase):
    """#2858 round 10, the monotone ruling: this walk's answer JOINS `main`'s -- a body is read where
    either reads it, a check counts only where both count it, the body or string `main` reads stays
    the step's own as `main` reads it, a body or string only this walk finds is no shell's sure
    program (the guard's second fold leaves it out), and the `-c` strings and the candidates are
    the union. One pin per join; each mutant that drops a join fails one (truth: the rows' own
    classes above, and the round-10 probes `r10_probe.py` / `r10_fold1.py`, main CLEAN where noted)."""

    IN_PIPELINE = "runs in the same pipeline as that use"

    @staticmethod
    def argv(text):
        return shell_reader.command(shell_reader.statements(text)[0].stages[-1].argv)

    def test_a_body_only_this_walk_reads_is_read_as_no_shells_sure_program(self):
        # Read where either reads it: #2616 and #2864 (FR x4; main CLEAN), with no reader -- `Unsure`.
        for runner in ("bash --rcfile /dev/null", "bash -norc", "bash -rcfile /dev/null"):
            with self.subTest(runner=runner):
                self.assertTrue(any(STREAM in why for why in defects(body(runner, PIPE))), runner)
                argv = self.argv(body(runner, PIPE))
                self.assertEqual((wp.SHELL_PROGRAM, None), (wp.stdin_program(argv), wp.stdin_reader(argv)))
        # A `}` in a body `main` never reads is no group's end (main RRRRR; read as the step's own, it
        # closed the group and the step read CLEAN): `sh -sc true`, where dash reads stdin after the string.
        group = GET + "{ %s\nsh -sc true <<'B1'\n}\nB1\n} | sh tool\n" % CHECK
        self.assertTrue(defects(group), group)

    def test_a_check_counts_only_where_both_walks_count_it(self):
        # #2647, #2654, and a shell that runs none of its program: `main` counted the check (CCCRR).
        for runner in ("bash -s -c true", "bash - /dev/null", "bash --version", "bash -n -s", "bash -o $X -s"):
            with self.subTest(runner=runner):
                found = defects(GET + body(runner, CHECK) + USE)
                self.assertTrue(any(WITHHELD in why for why in found), (runner, found))
                self.assertEqual((), wp.stdin_reader(self.argv(body(runner, CHECK))))
        # Both count it: CLEAN, as on main, the reader the shell's own argv.
        for runner in ("bash -s", "bash -", "bash -e -s", "bash --norc"):
            with self.subTest(runner=runner):
                self.assertEqual([], defects(GET + body(runner, CHECK) + USE), runner)
                argv = self.argv(body(runner, CHECK))
                self.assertIs(argv, wp.stdin_reader(argv))

    def test_the_body_main_reads_stays_the_steps_own(self):
        # A check withheld keeps `main`'s statements the step's own (`()`, never None): a download
        # in the body then a group whose check runs in the use's pipeline -- main RRRRR, and CCCRR
        # when the body was made no shell's sure program (the round-10 probe's 30 cells).
        for holder in ("bash -o $X -s", "bash -s $X", "bash -O $X -s"):
            with self.subTest(holder=holder):
                step = "%s <<'B1'\n%sB1\nCMD=$(echo true)\n{ %s\n$CMD <<'EOF'\n}\nEOF\n} | sh tool\n" % (holder, GET, CHECK)
                self.assertTrue(any(self.IN_PIPELINE in why for why in defects(step)), holder)
        # So with a string `main` reads and this walk withholds (`bash -o $X -c`, `Handed` with `()`).
        step = "bash -o $X -c '%s'\nCMD=$(echo true)\n{ %s\n$CMD <<'EOF'\n}\nEOF\n} | sh tool\n" % (GET.strip(), CHECK)
        self.assertTrue(any(self.IN_PIPELINE in why for why in defects(step)), step)

    def test_the_strings_are_the_union(self):
        # A string only this walk finds (main CLEAN): read for what it runs, with no reader.
        for script in ("bash -norc -c '%s'\n" % PIPE, "bash -rcfile /dev/null -c '%s'\n" % PIPE,
                       body("bash -rcfile /dev/null -c 'sh'", PIPE)):
            with self.subTest(script=script):
                self.assertTrue(any(STREAM in why for why in defects(script)), script)
        # A dynamic string only this walk finds speaks as `main`'s would (`dynamic_program`): bash runs
        # the download's text (FR x4; main CLEAN, reading `-norc` as a `-c` cluster it refuses).
        self.assertTrue(defects(GET + 'bash -norc -c "$(cat tool)"\n'))
        handed = wp.scripts(self.argv("bash -norc -c 'echo hi'"))
        self.assertEqual((["echo hi"], [None]), ([str(s) for s in handed], [s.reader for s in handed]))
        # One of `main`'s, a check in it counted only where the shell surely runs it.
        self.assertTrue(any(WITHHELD in why for why in defects("X=-e\n" + GET + 'bash $X -c "%s"\n' % CHECK + USE)))
        self.assertEqual([], defects(GET + 'bash -c "%s"\n' % CHECK + USE))

    def test_the_candidates_are_the_union(self):
        # `bash -rcfile FILE $X '…'`: main stops at `-rcfile`'s `c`; this walk skips the FILE and
        # weighs the words after the value (FR x4 with `X=-c`; main CLEAN).
        self.assertTrue(any("where it reads its options" in why
                            for why in defects("X=-c\nbash -rcfile /dev/null $X '%s'\n" % PIPE)))
        self.assertEqual(["P"], [str(w) for w in wp.candidates(self.argv("bash -rcfile /dev/null $X P"))[1]])
        # `main`'s answer stands first where it has one.
        self.assertEqual(["P"], [str(w) for w in wp.candidates(self.argv("sh $X P"))[1]])

    def test_an_added_body_beside_mains_own_unsure_body_hides_nothing(self):
        # The guard's first fold reads both bodies; a `cd`, an `exit` or a function in the added one
        # does not hide the download `main` reports behind `eval 'bash -s'` (the fold-1 probe, 240 rows).
        for inside in ("cd /tmp", "exit 0", "chmod() { :; }", "rm -f tool"):
            with self.subTest(inside=inside):
                step = "eval 'bash -s' <<'B0'\n%sB0\nbash -norc <<'B1'\n%s\nB1\n" % (GET, inside) + USE
                self.assertTrue(defects(step), step)


class TestTheGuardReturnsMainsFindingsThenTheWalks(unittest.TestCase):
    """#2858 round 11, the coordinator's ruling on round 10's seat: monotone at the OUTPUT.
    `job_defects` returns `main`'s findings -- a pass in which every join answers as `main` does
    (`mains_answer`), nothing of this walk feeding it -- then this walk's not among them. Round 10's
    seat found four consumers that read LESS when an added reading reached them: B1 `_on_stdin` and
    annotate's `_complete`, B2 `substitution_script`, B3 a `()` reader's printers, B4 an added body's
    `}` regrouping the first fold. Each row below is the seat's (`hunt.jsonl`, ids given; round 11's
    `mfd`/`mfd2`: B4's shape behind a holder whose `-c` string only this walk finds): `main` reports
    it RRRRR, this walk's own pass reads a cell CLEAN, and the job keeps `main`'s findings."""

    # Round 10's B4 shape: `main`'s own Unsure fetch, then a brace group whose holder's heredoc body is `}`.
    B4 = "eval 'bash -s' <<'B0'\n%sB0\n{ %s\n%%s <<'B1'\n}\nB1\n} | sh tool\n" % (GET, CHECK)
    SEAT = {"os000 (B1)": GET + "CMD=bash\n$CMD x -- -c cat < tool\n",
            "su00 (B2)": "X='%s'\nout=$(bash -s x -- -c 'echo hi' <<EOF\n$X\nEOF\n)\n" % PIPE,
            "nr02 (B3)": "bash x.sh -c \"echo 'curl -fsSLo tool %stool\\t' | sh\"\nCMD=$(echo true)\n"
                         "{ %s\n$CMD <<'EOF'\n}\nEOF\n} | sh tool\n" % (URL, CHECK),
            "cf00432 (B4)": B4 % "sh -sc true",
            # Round 11's seat, B1: the walk fed into the main pass through `_stdin_details` (MF5 MF7 MF8
            # MF9) read each of these CLEAN under the first three settings, and no pin failed.
            "mfd2 (an outermost one-dash holder)": B4 % "bash -norc -c 'sh'",
            "mfd (a one-dash holder's FILE)": B4 % "bash -rcfile /dev/null -c 'sh'",
            "mfd (a nested holder)": B4 % "bash -c \"sh -rcfile /dev/null -c 'sh'\""}
    SHELLS = (None, "bash", "sh", "bash {0}", "sh {0}")
    # Round 12's seat, B1 and F1: the walk's tables are read, never called, so no watcher sees one fed
    # into the main pass (MX13: `_details`' recursion reading an inner argv less its one-dash long
    # options), nor one of `main`'s own readers changed (MX3 `_after_dash_c`, MX4 `SHELL_OPTIONS`).
    # The family carries them: B4 behind each holder -- outermost, a stdin string, nested, in `eval`,
    # an inner shell behind a FILE holder, a string or `eval`, bare -- for each spelling of the walk's
    # tables `main` reports there: all 71 rows of that grid's 225 that `main` (e9e6e1fd) reports RRRRR.
    # A one-dash word holding a `c` (a `-c` cluster to `main`: `_after_dash_c`), alone or paired, under
    # every holder; a FILE word `main` reads as no cluster under the four holders whose shell has no
    # `-c` (the walk's `LONG_VALUE_OPTIONS`: an MX13 on them moves those); `-login -restricted` under
    # the five whose shell has one.
    HOLDERS = ("bash %s -c 'sh'", "sh %s -c 'sh'", "bash %s -c 'bash -s'", "bash -c \"bash %s -c 'sh'\"",
               "eval \"bash %s -c 'sh'\"", "bash --rcfile /dev/null -c 'bash %s'", "bash -c 'bash %s'",
               "eval 'bash %s'", "bash %s")
    SPELLED = tuple("-" + name[2:] for name in wo.LONG_OPTIONS) + tuple(
        spelled + " /dev/null" for name in wo.LONG_VALUE_OPTIONS for spelled in (name[1:], name))
    CLUSTERS = tuple(words for words in SPELLED if not words.startswith("--") and "c" in words.split()[0])
    FILES = tuple(words for words in SPELLED if words.endswith(" /dev/null") and (words.startswith("--") or "c" not in words))
    FAMILY = tuple(holder % words for holder, words in itertools.chain(
        itertools.product(HOLDERS, CLUSTERS + ("-norc -login", "--noprofile -norc")),
        itertools.product(HOLDERS[5:], FILES), itertools.product(HOLDERS[:5], ("-login -restricted",))))
    # This walk's own readers and helpers -- every function #2858 added that only the walk calls (round
    # 12's seat, F3) -- each where it is looked up; `_WALK`'s pair is bound when the module loads, so it
    # is watched as a pair too, and its two names are TRIPWIRES: nothing looks either up by name (round
    # 12's seat, F2), so neither may run in the main pass, and neither need run in the walk's.
    WALK_ONLY = ((wp, ("_walk", "_walk_scripts", "_added_strings", "_shell_candidates", "_dash_c_strings",
                       "_stdin_walk", "_counted", "_sure_string", "Handed")),
                 (wo, ("long_option", "_run", "_after_value", "_dash_c_operand", "_dash_s", "_in_every_reading",
                       "_literal", "_long_name", "_long_word", "_one_word", "_operand_past", "_printed",
                       "_runs_none", "_value_after_dash_c")))
    TRIPWIRES = ("_walk", "_walk_scripts")
    # Rows past the seat's for the structural pin: a long option's FILE, one-dash words, a value in the
    # option slot, `-c --`, a string in a string, `eval`, a `$` command word, a dynamic string.
    WALKED = (body("bash --rcfile /dev/null", PIPE), body("bash -norc", PIPE), "bash -norc -c '%s'\n" % PIPE,
              GET + body("bash -s -c true", CHECK) + USE, GET + 'bash -norc -c "$(cat tool)"\n',
              "X=\nbash -norc $X '%s'\n" % PIPE, body("bash -o $X -s", PIPE), body("bash -c -- $X 'P' sh", PIPE),
              body("bash -c \"bash -norc -c 'sh'\"", PIPE), body("eval \"bash -norc -c 'sh'\"", PIPE),
              "CMD=bash\n" + body("$CMD -norc", PIPE), "echo '%s' | bash -norc -c 'sh'\n" % PIPE)

    @staticmethod
    def argv(text):
        return shell_reader.command(shell_reader.statements(text)[0].stages[-1].argv)

    def test_the_main_pass_reads_as_main(self):
        # Rows `main` reads CLEAN that this walk reports (#2616, #2864, #2647, a dynamic string only
        # this walk finds): CLEAN in the main pass, nothing of the walk feeding it.
        for script in (body("bash --rcfile /dev/null", PIPE), body("bash -norc", PIPE), "bash -norc -c '%s'\n" % PIPE,
                       GET + body("bash -s -c true", CHECK) + USE, GET + 'bash -norc -c "$(cat tool)"\n'):
            with self.subTest(script=script), wo.mains_answer():
                self.assertEqual([], wg._job_defects([("step", script)]))
        # The four joins answer as `main`'s code does there ...
        with wo.mains_answer():
            self.assertEqual([], wp.scripts(self.argv("bash -norc -c 'echo hi'")))
            self.assertEqual((None, None), wp.dynamic_program(self.argv('bash -norc -c "$(cat tool)"')))
            self.assertEqual((None, []), wp.candidates(self.argv("bash -rcfile /dev/null $X P")))
            self.assertIsNone(wp.stdin_program(self.argv(body("bash --rcfile /dev/null", PIPE))))
            argv = self.argv(body("bash -s -c true", CHECK))
            self.assertIs(argv, wp.stdin_reader(argv))
        # ... and the seat's rows keep `main`'s findings in it.
        for name, script in self.SEAT.items():
            with self.subTest(row=name), wo.mains_answer():
                self.assertTrue(all(wg._job_defects([wg.Step("step", script, s)]) for s in self.SHELLS))

    def test_the_main_pass_reports_every_holder_of_the_family(self):
        # Round 12's seat, B1 and F1: MX13, MX3 and MX4 each read some row of the family CCCRR, and the
        # whole suite passed each of them.
        for holder in self.FAMILY:
            with self.subTest(holder=holder), wo.mains_answer():
                self.assertTrue(all(wg._job_defects([wg.Step("step", self.B4 % holder, s)]) for s in self.SHELLS))

    def test_the_job_holds_every_finding_of_mains(self):
        for name, script in self.SEAT.items():
            # The walk's own pass alone reads a cell CLEAN (round 10's blockers) ...
            with self.subTest(row=name, walk_alone=True):
                self.assertFalse(all(wg._job_defects([wg.Step("step", script, s)]) for s in self.SHELLS))
            # ... the job holds every finding of `main`'s, under every setting.
            for shell in self.SHELLS:
                with self.subTest(row=name, shell=shell):
                    with wo.mains_answer():
                        mains = wg._job_defects([wg.Step("step", script, shell)])
                    found = wg.job_defects([wg.Step("step", script, shell)])
                    self.assertTrue(mains)
                    self.assertEqual([], [finding for finding in mains if finding not in found])
                    self.assertEqual(found[:len(mains)], mains)

    def test_the_cached_readers_see_only_lists_no_statement_holds(self):
        # F1 of round 10's review: `_run` and `long_option` keep their answers per argv object, so no
        # list either reads may be rewritten after. None is: each is a copy -- `command()`'s, a
        # reading's, the inner parse's -- never a statement's own `argv`, the list
        # `workflow_annotate` rewrites in place. Every list the two read is checked against every
        # statement's the job parsed, by identity.
        seen, held = [], []
        run, long_option, read, parsed = wo._run, wo.long_option, wg.read, wp._parsed

        def seen_run(argv):
            seen.append(argv)
            return run(argv)

        def seen_long(argv, at):
            seen.append(argv)
            return long_option(argv, at)

        def held_statements(stmts):
            held.extend(stage.argv for statement in stmts for stage in statement.stages)
            return stmts

        steps = ["CMD=bash\n" + body("$CMD -norc", PIPE), "SH=sh\n$SH -norc -c '%s'\n" % PIPE,
                 'bash -c "bash -norc -s" <<\'EOF\'\n%s\nEOF\n' % PIPE, "eval 'eval bash --rcfile /dev/null' <<'EOF'\n%s\nEOF\n" % PIPE,
                 body("bash " + " ".join(["-norc"] * 40), PIPE), "X=\nbash --rcfile $X -norc -c '%s'\n" % PIPE]
        with mock.patch.object(wo, "_run", seen_run), mock.patch.object(wo, "long_option", seen_long), \
                mock.patch.object(wg, "read", lambda script, shell=None: held_statements(read(script, shell))), \
                mock.patch.object(wp, "_parsed", lambda text: held_statements(parsed(text))):
            for step in steps:
                wg.job_defects([("step", step)])
        self.assertTrue(seen and held)
        held_ids = {id(argv) for argv in held}
        self.assertEqual([], [argv for argv in seen if id(argv) in held_ids])

    def test_nothing_of_the_walk_runs_in_the_main_pass(self):
        # Round 11's seat, B1: the ruling's "nothing of the walk feeds the main pass", as a test. Each
        # reader and helper of this walk's own is watched where it is looked up, and none may run while
        # `_MAINS` is set; each watcher but the two tripwires must also see its reader run in the walk's
        # pass, counted per watcher (round 12's seat, F2), or it watches nothing. This pins NAMED calls:
        # the walk's tables are read, not called, and `FAMILY`'s rows carry them (round 12's seat, B1).
        calls = collections.Counter()

        def watched(label, reader):
            def call(*args, **kwargs):
                calls[label, bool(wo._MAINS.get())] += 1
                return reader(*args, **kwargs)
            return call

        self.assertEqual((wp._options, wp._main_scripts), wp._MAIN)
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(wp, "_WALK", tuple(watched("_WALK[%d]" % at, reader)
                                                                     for at, reader in enumerate(wp._WALK))))
            for module, names in self.WALK_ONLY:
                for name in names:
                    stack.enter_context(mock.patch.object(module, name, watched(name, getattr(module, name))))
            for script in self.WALKED + tuple(self.SEAT.values()):
                for shell in self.SHELLS:
                    wg.job_defects([wg.Step("step", script, shell)])
        watchers = ["_WALK[0]", "_WALK[1]"] + [name for _module, names in self.WALK_ONLY for name in names]
        self.assertEqual([], [label for label in watchers if calls[label, True]])
        self.assertEqual([], [label for label in watchers if label not in self.TRIPWIRES and not calls[label, False]])

    def test_a_raise_in_the_main_pass_resets_the_switch(self):
        # Round 11's seat, F1: `mains_answer` resets `_MAINS` on a raise too, pinned here and not by
        # the order the tests run in.
        with self.assertRaises(LookupError):
            with wo.mains_answer():
                self.assertTrue(wo._MAINS.get())
                raise LookupError("in the main pass")
        self.assertFalse(wo._MAINS.get())

    def test_a_raise_in_the_main_pass_leaves_the_job(self):
        # Round 11's seat, F2: a raise in the main pass is never read as a CLEAN `main` -- nothing
        # catches it, no walk's pass runs after it, and the switch is off.
        passes, real = [], wg._job_defects

        def failing(steps, strict=False):
            passes.append(wo._MAINS.get())
            if wo._MAINS.get():
                raise LookupError("in the main pass")
            return real(steps, strict)

        with mock.patch.object(wg, "_job_defects", failing), self.assertRaises(LookupError):
            wg.job_defects([("step", PIPE + "\n")])
        self.assertEqual([True], passes)
        self.assertFalse(wo._MAINS.get())

    def test_mains_findings_come_first(self):
        # Round 11's seat, F3: the order. `$X` is empty and `-norc` bash's own: this walk reports the
        # `$X` in the option slot before the stream both passes report, and the job keeps `main`'s
        # findings first, then the walk's not among them.
        script = "X=\nbash -norc $X '%s'\n" % PIPE
        for shell in self.SHELLS:
            with self.subTest(shell=shell):
                step = [wg.Step("step", script, shell)]
                with wo.mains_answer():
                    mains = wg._job_defects(step)
                walked = wg._job_defects(step)
                self.assertNotEqual(mains[0], walked[0])
                self.assertEqual(mains + [entry for entry in walked if entry not in mains], wg.job_defects(step))

    def test_the_union_keeps_a_walk_finding_under_another_name(self):
        # Round 12's seat, F4 (MU10): a walk's finding is among `main`'s only under its own name. Both
        # passes report the first step's stream, only the walk the second's, under one `why`: the job
        # keeps both, for a name the union keys and for one it compares.
        for first, second in (("a", "b"), (["a"], ["b"])):
            steps = [wg.Step(first, PIPE + "\n"), wg.Step(second, "bash -norc -c '%s'\n" % PIPE)]
            with self.subTest(names=(first, second)):
                with wo.mains_answer():
                    mains = wg._job_defects(steps)
                walked = wg._job_defects(steps)
                self.assertEqual([first], [name for name, _why in mains])
                self.assertEqual([first, second], [name for name, _why in walked])
                self.assertEqual(1, len({why for _name, why in walked}))
                self.assertEqual(walked, wg.job_defects(steps))

    def test_the_union_keys_a_hashable_name_and_compares_the_rest(self):
        # Round 11's seat, F4, and round 12's, B2 and F5: a hashable name -- every name the workflow schema
        # takes -- is looked up with its `why`, so n entries make n comparisons whether their `why`s
        # differ (D1) or are one (D2: round 12's union made 2n^2 there). A step's name is the workflow's
        # own YAML value, a list or a mapping maybe: no key, it is compared with the names its `why`
        # holds, never hashed (a set of the pairs raises on it) -- linear where those `why`s differ,
        # quadratic in such names under one `why` (round 13's E2: a name the workflow schema refuses).
        script = "X=\nbash -norc $X '%s'\n" % PIPE
        for name in (["a", "b"], {"k": "v"}):
            with self.subTest(name=name):
                found = wg.job_defects([wg.Step(name, script)])
                self.assertEqual([name, name], [named for named, _why in found])
        compared = []

        class Name(str):
            __hash__ = None             # unhashable, as a list is

            def __eq__(self, other):
                compared.append(other)
                return str.__eq__(self, other)

        class Hashed(Name):
            __hash__ = str.__hash__     # hashable, as a string is

        n = 500
        for label, kind, why, new in (("D1", Name, "why %d", "new %d"), ("D2", Hashed, "why", "why")):
            mains = [(kind("s%d" % k), why.replace("%d", str(k))) for k in range(n)]
            walked = ([(kind("s%d" % k), why.replace("%d", str(k))) for k in range(n)]
                      + [(kind("t%d" % k), new.replace("%d", str(k))) for k in range(n)])
            del compared[:]
            with self.subTest(distribution=label), mock.patch.object(
                    wg, "_job_defects", lambda steps, strict=False: list(mains if wo._MAINS.get() else walked)):
                found = wg.job_defects([])
                count = len(compared)
                self.assertEqual(mains + walked[n:], found)
                self.assertLessEqual(count, 2 * n)      # n in each; 2n^2 by round 11's scan, and round 12's D2

    def test_a_name_that_holds_itself_is_compared_by_identity(self):
        # Round 13's E1: an anchor can make a step's name hold itself (`&a [*a]`), and `==` cannot finish
        # between two such names, so the union compares them by identity -- where round 12's raised
        # `RecursionError` and `main` printed every defect. Under `pwsh` both passes report each step;
        # in the second job only the walk reports the second step's stream, under the first's `why`.
        # The job keeps every finding, and the CLI prints each step's defect.
        held, holds, mapped, maps = [], [], {}, {}
        held.append(held)
        holds.append(holds)
        mapped["k"], maps["k"] = mapped, maps
        for first, second in ((held, holds), (mapped, maps)):
            for steps in ([wg.Step(first, "echo hi\n", "pwsh"), wg.Step(second, "echo hi\n", "pwsh")],
                          [wg.Step(first, PIPE + "\n"), wg.Step(second, "bash -norc -c '%s'\n" % PIPE)]):
                with self.subTest(name=type(first).__name__, shell=steps[0].shell):
                    found = wg.job_defects(steps)
                    self.assertEqual([id(first), id(second)], [id(name) for name, _why in found])
                    self.assertEqual(1, len({why for _name, why in found}))
        lines: list[str] = []
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "held.yml")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("jobs:\n  j:\n    steps:\n" + "".join(
                    "      - {name: %s, shell: pwsh, run: echo %d}\n" % (name, at)
                    for at, name in enumerate(("&a [*a]", "&b [*b]", "&c {k: *c}", "&d {k: *d}"))))
            self.assertEqual(1, wg.main([path], out=lines.append))
        self.assertEqual(5, len(lines))         # each step's defect, then the count


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
