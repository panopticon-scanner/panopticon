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
import time
import unittest

import shell_reader


def stage(script):
    """The one stage of the one statement `script` parses to."""
    stmts = shell_reader.statements(script)
    assert len(stmts) == 1, stmts
    assert len(stmts[0].stages) == 1, stmts[0].stages
    return stmts[0].stages[0]


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


class TestTheCaseHeaderProbeIsNotQuadratic(unittest.TestCase):
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
    """

    def test_a_50kb_single_statement_parses_in_well_under_a_second(self):
        script = "echo " + "a " * 26000 + "\n"
        self.assertGreater(len(script), 50 * 1024, len(script))
        start = time.monotonic()
        stmts = shell_reader.statements(script)
        elapsed = time.monotonic() - start
        self.assertEqual(1, len(stmts), stmts)
        self.assertEqual(26001, len(stmts[0].stages[0].argv))
        self.assertLess(elapsed, 2.0, elapsed)

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
        script = "case " + "a" * (50 * 1024) + " in x) :; esac\n"
        start = time.monotonic()
        stmts = shell_reader.statements(script)
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, 2.0, elapsed)
        self.assertTrue(any(st.stages[0].argv[:1] == ["esac"] for st in stmts),
                        stmts)


if __name__ == "__main__":
    unittest.main()


class TestOrderedRedirects(unittest.TestCase):
    def test_descriptor_snapshots_and_opened_files(self):
        cases = (
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
