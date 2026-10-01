"""#2331, batch 4: the heredocs the shell lexer reads inside a substitution.

Each class is one sub-issue of the epic: a spelling in which bash runs a
download -- bash 3.2.57 and GNU bash 5.2.21, every checksum failing -- that
the guard read clean, pinned as a live step, beside the controls that must
read as they did. The reader's and the lexer's own halves are in
`tests/test_shell_reader.py`.
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
        for opener, body, named in (("bash <<EOF", PIPE, "EXPANDING heredoc body"),
                                    ("cat <<EOF", "$(%s)" % PIPE, "straight to `sh`"),
                                    ("python3 - <<'EOF'", "print(1)", "to `python3` as the program")):
            multi, one = twins(opener, body)
            with self.subTest(script=multi):
                found = defects(multi)
                self.assertEqual(1, len(found), found)
                self.assertIn(named, found[0][1])
                self.assertEqual(defects(one), found)

    def test_the_controls_read_as_their_twins_do(self):
        # `cat` reads data; a script that neither fetches nor runs anything is
        # weighed `Idle` where the job downloads nothing; a body on descriptor
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
        # body line. At the top, as in bash, an `EOF)` line is a body line.
        for script in ("x=$(cat <<'EOF'\nit's\nEOF)\n%s\n" % PIPE,
                       "x=$(cat <<EOF\nEOF (%s)\nEOF\n)\n" % PIPE):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertIn("hands %si.sh straight to `sh`" % URL, found[0][1])
        self.assertEqual([], defects("x=$(cat <<'EOF'\nit's\nEOF)\necho done\n"))
        self.assertEqual([], defects("(cat <<EOF\nhi\nEOF)\n%s\nEOF\n)\n" % PIPE))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
