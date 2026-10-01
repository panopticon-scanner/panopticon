"""#2331, batch 4: the heredocs the shell lexer reads inside a substitution.

Each class is one sub-issue of the epic: a spelling in which bash runs a
download -- GNU bash 5.2.21, and bash 3.2.57 unless a test says otherwise,
every checksum failing -- that the guard read clean, pinned as a live step,
beside the controls that must read as they did. The `python3 -` rows pin the
fail-closed report a program in a language the guard has no grammar for gets,
which #2499 keeps only beside a fetch the guard reports. The reader's and the
lexer's own halves are in `tests/test_shell_reader.py`.
"""
import unittest

import workflow_guard as wg

URL = "https://example.test/"
PIPE = "curl -fsSL %si.sh | sh" % URL
GET = "curl -fsSLo t.sh %si.sh\n" % URL


def defects(script):
    """The guard's answer for a job of one step running `script`."""
    return wg.job_defects([("step", script)])


def twins(opener, body, close="EOF"):
    """`opener`'s heredoc inside `x=$(...)`, its terminator and `)` on lines of
    their own, and its one-line twin, whose terminator line is `EOF)`."""
    return ("x=$(%s\n%s\n%s\n)\n" % (opener, body, close),
            "x=$(%s\n%s\n%s)\n" % (opener, body, close))


class TestAHeredocBodyTheEnclosingParseLifts(unittest.TestCase):
    """#2336: a heredoc inside `$(...)` whose terminator and `)` stand on lines
    of their own. The enclosing parse read its body and left a marker in the
    substitution's text, which meant nothing to the parse that read that text
    again: the program a shell there runs was read by nobody. Each one now
    gets the answer of its one-line twin, which bash runs the same way."""

    def test_a_program_a_shell_reads_there_is_reported(self):
        for opener, body, close, shell in (("bash <<'EOF'", PIPE, "EOF", "bash"),
                                           ("sh <<'EOF'", PIPE, "EOF", "sh"),
                                           ("bash -s <<'EOF'", PIPE, "EOF", "bash"),
                                           ("bash <<-'EOF'", "\t" + PIPE, "\tEOF", "bash")):
            multi, one = twins(opener, body, close)
            with self.subTest(script=multi):
                found = defects(multi)
                self.assertEqual(1, len(found), found)
                self.assertIn("hands a script to `%s` inside a command substitution" % shell,
                              found[0][1])
                self.assertEqual(defects(one), found)
        # Deeper in, and in a process substitution, the body goes along.
        for script in ("x=$(echo \"$(bash <<'EOF'\n%s\nEOF\n)\")\n" % PIPE,
                       "cat <(bash <<'EOF'\n%s\nEOF\n)\n" % PIPE):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertIn("hands a script to `bash` inside a command substitution",
                              found[0][1])

    def test_a_body_not_read_as_written_is_reported(self):
        # An unquoted delimiter: a shell runs what bash expands the body to,
        # and a `$(...)` in it runs as bash expands it, whoever reads it. A
        # program in a language the guard has no grammar for is reported, as
        # it is at the top level.
        # The foreign program stands beside `GET`'s download, which no
        # checksum clears: #2499's predicate, pinned below in full.
        for head, opener, body, named in (
                ("", "bash <<EOF", PIPE, "EXPANDING heredoc body"),
                ("", "cat <<EOF", "$(%s)" % PIPE, "straight to `sh`"),
                (GET, "python3 - <<'EOF'", "print(1)", "to `python3` as the program")):
            multi, one = twins(opener, body)
            with self.subTest(script=multi):
                found = defects(head + multi)
                self.assertEqual(1, len(found), found)
                self.assertIn(named, found[0][1])
                self.assertEqual(defects(head + one), found)

    def test_the_controls_read_as_their_twins_do(self):
        # `cat` reads data; a script that neither fetches nor runs anything is
        # weighed `Idle` where the job reports no fetch; a body on descriptor
        # 3, or one `x.sh` reads, is no program. Each twin reads clean too.
        for opener, body in (("cat <<'EOF'", "hi"), ("bash <<'EOF'", "echo hi"),
                             ("bash 3<<'EOF'", PIPE), ("bash x.sh <<'EOF'", PIPE)):
            multi, one = twins(opener, body)
            with self.subTest(script=multi):
                self.assertEqual([], defects(multi))
                self.assertEqual([], defects(one))

    def test_a_script_there_may_run_what_the_job_downloaded(self):
        # The guard follows no download into a substitution, so where the job
        # downloads, a script a shell runs there is reported however idle.
        multi, one = twins("bash <<'EOF'", "bash t.sh")
        found = defects(GET + multi)
        self.assertEqual(1, len(found), found)
        self.assertIn("hands a script to `bash` inside a command substitution", found[0][1])
        self.assertEqual(defects(GET + one), found)


class TestABodyEndsWhereBash52EndsItInASubstitution(unittest.TestCase):
    """#2343: bash 5.2 ends a heredoc body inside a substitution at a line its
    delimiter starts with a `)` after it -- `EOF)` -- and reads the rest of
    that line as code. The lexer ended one only at a line that IS the
    delimiter, so a later heredoc's `EOF` ended it, and every statement
    between went into the body: a fetch piped into a shell there was read by
    nobody. Each body now ends where 5.2 ends it."""

    EARLIER = "echo $(cat <<'EOF'\nhi\nEOF)\n"
    LATER = "%s | echo \"$(cat <<EOF)\"\nbody\nEOF\n" % PIPE
    # The differential row it was found in (i-sub:12057).
    ROW = ("echo $(eval \"echo \\\"%s  t\\\" | sha256sum -c -\") | echo $(bash -s <<'EOF'\n%s\n"
           "EOF) && sudo -u x %s | env sh | echo \"$(cat <<EOF)\"\nit's\nEOF || bash -s <<'EOF'\n"
           "%s\nEOF; python3 - <<'EOF'\nprint(1)\nEOF\n" % ("a" * 64, PIPE, PIPE[:-5], PIPE))

    def test_the_statement_after_an_earlier_heredoc_is_read(self):
        # Without the earlier heredoc the later one is refused by name; with
        # it the step read clean, and is now refused in the same words.
        alone = defects(self.LATER)
        self.assertEqual(1, len(alone), alone)
        self.assertIn("cannot read this step: a heredoc inside a `$(...)`", alone[0][1])
        self.assertEqual(alone, defects(self.EARLIER + self.LATER))
        # With no later one, the fetch is flagged as it was.
        found = defects(self.EARLIER + PIPE + "\n")
        self.assertEqual(1, len(found), found)
        self.assertIn("hands %si.sh straight to `sh`" % URL, found[0][1])

    def test_the_row_it_was_found_in_is_refused(self):
        # Both bashes run its payload. Its `EOF)` ends the body `bash -s`
        # reads, and the `"$(cat <<EOF)"` after it is refused as above.
        self.assertEqual(defects(self.LATER), defects(self.ROW))

    def test_each_of_three_heredocs_keeps_the_fetch_after_it(self):
        # One-line, multi-line, one-line: a fetch after each is read, wherever
        # it stands, and a later heredoc ends no earlier body.
        three = ("echo $(cat <<'EOF'\nhi\nEOF)\n{}\ny=$(cat <<'EOF'\nbody\nEOF\n)\n{}\n"
                 "z=$(cat <<'EOF'\nmore\nEOF)\n{}\ncat <<'EOF'\ndata\nEOF\n")
        for pipes in ((PIPE, PIPE, PIPE), (PIPE, "", ""), ("", PIPE, ""), ("", "", PIPE)):
            with self.subTest(pipes=pipes):
                found = defects(three.format(*pipes))
                self.assertEqual(sum(map(bool, pipes)), len(found), found)
        self.assertEqual([], defects(three.format("", "", "")))

    def test_a_quote_or_a_subshell_there_reads_as_bash_reads_it(self):
        # An apostrophe in a one-line body was read as code, its quote open
        # to the end of the step; `EOF (...)` is a subshell 5.2 runs, not a
        # body line. Both run in 5.2 only: 3.2 finds the `)` by counting
        # parentheses and quotes, so it errors on the first and hands `cat`
        # the second as its body. At the top, as in bash, an `EOF)` line is a
        # body line.
        for script in ("x=$(cat <<'EOF'\nit's\nEOF)\n%s\n" % PIPE,
                       "x=$(cat <<EOF\nEOF (%s)\nEOF\n)\n" % PIPE):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertIn("hands %si.sh straight to `sh`" % URL, found[0][1])
        self.assertEqual([], defects("x=$(cat <<'EOF'\nit's\nEOF)\necho done\n"))
        self.assertEqual([], defects("(cat <<EOF\nhi\nEOF)\n%s\nEOF\n)\n" % PIPE))


class TestAForeignProgramOnStandardInput(unittest.TestCase):
    """#2499 (owner ruling 2026-10-01, option b): a heredoc body handed to an
    interpreter this guard has no grammar for -- `python3 - <<'EOF'`,
    `node <<'NODE'` -- is reported only beside a fetch the guard reports, the
    same predicate as #2481's `Idle` rule for shells, decided once for both
    (`workflow_forms.kept`). The four calibration-pool jobs #2499 named clear,
    and 26 more the `realwf` differential found, every one of them a program
    that parses a `pom.xml`, YAML, HTML or JSON and fetches nothing; the report
    stays wherever a download could reach the program.

    #2491 (#2336) handed such a body back to the substitution that reads it,
    so the rule reaches `MODULES=$(python3 - <<'EOF' ... )` too, and the
    predicate governs it there in the same words."""

    CHECKED = "echo '%s  t.sh' | sha256sum -c -\n" % ("a" * 64)
    SAID = "to `python3` as the program to run"

    def body(self, opener, close="EOF"):
        return "%s\nprint(1)\n%s\n" % (opener, close)

    def test_a_program_in_a_job_that_reports_no_fetch_is_not_reported(self):
        for opener in ("python3 - <<'EOF'", "python <<'EOF'"):
            with self.subTest(opener=opener):
                self.assertEqual([], defects(self.body(opener)))
                multi, one = twins(opener, "print(1)")
                self.assertEqual([], defects(multi))
                self.assertEqual([], defects(one))
        # `node`'s twin, and a credited download beside each: cleared too.
        self.assertEqual([], defects("node <<'NODE'\nconsole.log(1)\nNODE\n"))
        for script in (self.body("python3 - <<'EOF'"),
                       "node <<'NODE'\nconsole.log(1)\nNODE\n",
                       twins("python3 - <<'EOF'", "print(1)")[0]):
            with self.subTest(script=script):
                self.assertEqual([], defects(GET + self.CHECKED + script))

    def test_a_program_beside_a_fetch_the_guard_reports_is_reported(self):
        for script in (GET + self.body("python3 - <<'EOF'"),
                       GET + twins("python3 - <<'EOF'", "print(1)")[0],
                       GET + twins("python3 - <<'EOF'", "print(1)")[1]):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertIn(self.SAID, found[0][1])
        # A stream into a shell, and a download a variable carries, report a
        # fetch too: the program stands beside each.
        for fetch in ("%s\n" % PIPE, "x=$(curl -fsSL %si.sh)\nsh -c \"$x\"\n" % URL):
            with self.subTest(fetch=fetch):
                found = defects(fetch + self.body("python3 - <<'EOF'"))
                self.assertEqual(2, len(found), found)
                self.assertTrue(any(self.SAID in why for _n, why in found), found)
        # An OIDC-token `curl | jq` is no download, and keeps none of them.
        self.assertEqual([], defects("curl -fsSL %sx | jq .tag\n" % URL
                                     + self.body("python3 - <<'EOF'")))

    def test_an_enclosing_reason_is_idle_where_its_only_unread_form_is_one(self):
        # Review r0 NIT 7: `_weighed` reads "an inner `Idle` is not unread",
        # so a wrapper whose handed script holds no unread form BUT a foreign
        # stdin program is `Idle` too, and #2499's predicate governs it as it
        # governs the program itself. 13 of the differential's reasons-only
        # sentences are this shape; a handed script that FETCHES stays loud.
        inner = "python3 - <<'PY'\nprint(1)\nPY\n"
        for script in ('V=$(sh -c "%s")\n' % inner, '$CMD -c "%s"\n' % inner):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))
                self.assertTrue(defects(GET + script))
        self.assertTrue(defects('V=$(sh -c \'%s\')\n' % PIPE))

    def test_an_expanding_shell_body_is_reported_with_no_fetch_at_all(self):
        # The EXPANDING branch is untouched by the ruling: a shell body bash
        # expands runs what this guard never sees, fetch or no fetch.
        for opener in ("bash -s <<EOF", "sh <<EOF"):
            with self.subTest(opener=opener):
                found = defects("%s\necho $(date)\nEOF\n" % opener)
                self.assertEqual(1, len(found), found)
                self.assertIn("EXPANDING heredoc body", found[0][1])
        # A foreign body reaches that branch for no interpreter: `python3 -`
        # is answered by the rule above it, so #2499's predicate governs it
        # (the deviation #2499's pin list did not foresee). A `$(...)` lifted
        # out of the body is still read where bash runs it, and reported.
        self.assertEqual([], defects("python3 - <<EOF\nprint($(date))\nEOF\n"))
        found = defects("python3 - <<EOF\nprint(\"$(%s)\")\nEOF\n" % PIPE)
        self.assertEqual(2, len(found), found)
        self.assertIn(self.SAID, found[0][1])
        self.assertIn("straight to `python3 -`", found[1][1])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
