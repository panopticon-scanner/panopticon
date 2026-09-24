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
