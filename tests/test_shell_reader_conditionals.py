"""#2441 (COD-C2C): `[[ ... ]]` is one word list, and its `&&`/`||` do not split it.

`shell_reader._split` turns the lexed text into statements at `;`, `&`, `&&`, `||` and
newlines. Bash reads `[[ ... ]]` as ONE compound command whose inner `&&`, `||`, `(`, `)`,
`<` and `>` are the conditional expression's operators -- not list separators, subshells or
redirections -- so the split reached the workflow guard with

    CHECK && [[ -f a || -f b ]] || exit 1

as the three statements `CHECK && [[ -f a`, `-f b ]]` and `exit 1`. The `|| exit 1` that
ends the real list was therefore never attributed to the check, and the gating model --
which credits a checksum only where the shell would stop on its failure -- refused a step
bash stops dead. Bash 3.2.57 and 5.2.21 agree, with a failing `CHECK` and `set -e`:
`CHECK && [[ -f a || -f b ]] || exit 1` never reaches the use, and the same list WITHOUT
the `|| exit 1` runs it (the must-trip control beside every clean pin below). dash has no
`[[` at all and answers `[[: not found`.

The lexer (`shell_lex`) already knew the construct -- it escapes the pattern characters
inside one -- but it hands the reader TEXT, so the reader has to know it too. This file is
that reading's spec; `tests/test_shell_reader.py` stays the redirect parser's.
"""
import unittest

import shell_reader
import workflow_guard as wg

HEX = "a" * 64
FETCH = "curl -fsSLo /tmp/payload https://example.test/payload\n"
CHECK = 'echo "%s  /tmp/payload" | sha256sum -c -' % HEX
USE = "chmod +x /tmp/payload && /tmp/payload\n"


def read(script):
    """`script` as `[([argv per stage], separator), ...]`, markers as written."""
    return [([[str(word) for word in stage.argv] for stage in statement.stages],
             statement.separator)
            for statement in shell_reader.statements(script)]


def one(script):
    """The argv of the one stage of the FIRST statement `script` parses to."""
    first = shell_reader.statements(script)[0]
    assert len(first.stages) == 1, first.stages
    return [str(word) for word in first.stages[0].argv]


def defects(body, shell=None):
    """The guard's reasons for a step that fetches, runs `body`, then uses."""
    return [why for _step, why in
            wg.job_defects([wg.Step("step", FETCH + body % CHECK + USE, shell)])]


class TestTheTestIsOneStatement(unittest.TestCase):
    """Its `&&` and `||` join the expressions of one command, so the statement
    they are written in runs to the separator OUTSIDE the `]]`."""

    def test_the_issues_shape_is_one_statement_for_the_test(self):
        self.assertEqual(
            [(([["CHECK"]]), "&&"),
             ([["[[", "-f", "a", "||", "-f", "b", "]]"]], "||"),
             ([["exit", "1"]], "\n")],
            read("CHECK && [[ -f a || -f b ]] || exit 1\n"))

    def test_an_and_inside_an_if_test_stays_inside_it(self):
        self.assertEqual(["if", "[[", "-f", "a", "&&", "-n", "$b", "]]"],
                         one('if [[ -f a && -n "$b" ]]; then USE; fi\n'))

    def test_a_while_head_keeps_both_of_its_expressions(self):
        self.assertEqual(["while", "[[", "!", "-f", "a", "||", "!", "-f", "b", "]]"],
                         one("while [[ ! -f a || ! -f b ]]; do sleep 1; done\n"))

    def test_a_negated_test_is_still_one_statement(self):
        self.assertEqual([(["!", "[[", "-f", "a", "]]"], "||"), (["exit", "1"], "\n")],
                         [(st[0][0], st[1]) for st in read("! [[ -f a ]] || exit 1\n")])

    def test_a_test_written_across_a_continuation_is_one_statement(self):
        # `lex` folds the `\`-newline away before `_split` ever sees the text.
        self.assertEqual(["[[", "-f", "a", "||", "-f", "b", "]]"],
                         one("[[ -f a \\\n   || -f b ]] || exit 1\n"))

    def test_a_case_arms_test_is_one_statement_too(self):
        # The arm's token closes with its own `)`, so the command after it
        # still stands where a command starts -- as it does for `curl`.
        statements = read("case $x in a) [[ -f p || -f q ]] || exit 1 ;; esac\n")
        self.assertEqual(["[[", "-f", "p", "||", "-f", "q", "]]"],
                         statements[1][0][0][1:])
        self.assertEqual("||", statements[1][1])


class TestTheTestsOtherOperatorsAreItsOwn(unittest.TestCase):
    """`(`, `)`, `<` and `>` inside `[[ ... ]]` open no subshell and redirect
    no descriptor: bash 3.2.57 and 5.2.21 write no file named `bbb` for
    `[[ aaa < bbb ]]`, and `[[ ( -f a || -f b ) && -n $c ]]` is one command."""

    def test_parens_inside_the_test_are_not_a_subshell(self):
        statement = shell_reader.statements("[[ ( -f a || -f b ) && -n $c ]] || exit 1\n")[0]
        self.assertEqual(["[[", "(", "-f", "a", "||", "-f", "b", ")", "&&", "-n", "$c", "]]"],
                         [str(word) for word in statement.stages[0].argv])
        self.assertEqual((0, 0), (statement.stages[0].group_open,
                                  statement.stages[0].group_close))

    def test_a_string_comparison_is_not_a_redirection(self):
        for script, which in (("[[ $a < $b ]] || exit 1\n", "reads"),
                              ("[[ $a > $b ]] || exit 1\n", "writes")):
            with self.subTest(script=script):
                stage = shell_reader.statements(script)[0].stages[0]
                self.assertEqual([], getattr(stage, which), which)
                self.assertIn("$b", [str(word) for word in stage.argv])

    def test_a_subshell_around_a_test_still_balances(self):
        stage = shell_reader.statements("( [[ -f a || -f b ]] ) || exit 1\n")[0].stages[0]
        self.assertEqual((1, 1), (stage.group_open, stage.group_close))

    def test_a_regex_alternation_leaves_no_group_the_count_cannot_close(self):
        # `^(a|b)` is ONE word to bash (`[[ abc =~ ^(a|b) ]]` is true on 3.2.57
        # and 5.2.21). The reader still ends the STAGE at the `|`, but the test
        # outlives the stage, so its `)` closes no group the count never opened
        # -- the unbalanced count #2334 reads as a list whose end was lost.
        statement = shell_reader.statements("[[ $x =~ ^(a|b) ]] || exit 1\n")[0]
        self.assertEqual((0, 0), (sum(s.group_open for s in statement.stages),
                                  sum(s.group_close for s in statement.stages)))


class TestWhatIsNotTheConditional(unittest.TestCase):
    """A `[[` bash reads as an ordinary word, and a `]]` that ends the test."""

    def test_a_bracket_pair_among_the_arguments_is_an_ordinary_word(self):
        # bash 3.2.57 and 5.2.21 print `[[ a` and run no second command here.
        self.assertEqual([([["echo", "[[", "a"]], "||"), ([["b"]], "\n")],
                         read("echo [[ a || b\n"))

    def test_a_quoted_bracket_pair_never_enters_the_test(self):
        # `"[[" a || b` answers `[[: command not found` and takes the `||`
        # branch on both bashes: a quoted `[[` is a command NAME.
        self.assertEqual([([["[[", "a"]], "||"), ([["b"]], "\n")], read('"[[" a || b\n'))

    def test_the_operators_between_two_tests_still_separate_them(self):
        self.assertEqual([(["[[", "-f", "a", "]]"], "&&"),
                          (["[[", "-f", "b", "]]"], "||"),
                          (["exit", "1"], "\n")],
                         [(st[0][0], st[1]) for st in
                          read("[[ -f a ]] && [[ -f b ]] || exit 1\n")])

    def test_an_operator_attached_to_the_closing_bracket_still_separates(self):
        # `[[ -f A ]]&& USE` runs the use on both bashes: the `&&` closes `]]`.
        self.assertEqual([(["[[", "-f", "a", "]]"], "&&"), (["echo", "yes"], "\n")],
                         [(st[0][0], st[1]) for st in read("[[ -f a ]]&& echo yes\n")])

    def test_a_case_pattern_spelled_with_brackets_is_still_a_pattern(self):
        statements = read("case $x in [[) echo odd ;; esac\n")
        self.assertEqual(3, len(statements), statements)
        self.assertEqual(["echo", "odd"], statements[1][0][0][1:])

    def test_an_unclosed_test_ends_with_its_statement(self):
        # Nothing below the syntax error bash would stop on is swallowed.
        self.assertEqual([([["[[", "-f", "a", "||", "-f", "b"]], "\n"),
                          ([["echo", "after"]], "||"), ([["echo", "more"]], "\n")],
                         read("[[ -f a || -f b\necho after || echo more\n"))


class TestCaseHeadersAcrossGrammarBoundaries(unittest.TestCase):
    """#2429: bash permits a nested header directly after an outer arm's `)`
    and permits the header's literal `in` after a newline. Both boundaries must
    reach the statement reader instead of hiding an arm's commands in argv."""

    PIPE = "curl -fsSL https://example.test/i.sh | sh"

    def reasons(self, script):
        return [why for _step, why in wg.job_defects([wg.Step("case", script)])]

    def assert_pipe_is_reported(self, script):
        found = self.reasons(script)
        self.assertEqual(1, len(found), found)
        self.assertIn("hands https://example.test/i.sh straight to `sh`", found[0])

    def test_a_nested_case_can_start_on_its_outer_arms_line(self):
        script = ('case "$X" in\n'
                  '  a) case "$Y" in b) %s;; esac;;\n'
                  'esac\n') % self.PIPE
        parsed = read(script)
        self.assertIn([["case", "$Y", "in"]], [stages for stages, _separator in parsed])
        self.assert_pipe_is_reported(script)

    def test_the_literal_in_can_start_the_line_after_the_subject(self):
        for gap in ("\nin\n", "\n  in\n", "\n\nin\n", "\n# comment\nin\n"):
            with self.subTest(gap=gap):
                script = ('case "$X"%s'
                          '  a) %s;;\n'
                          'esac\n') % (gap, self.PIPE)
                self.assertEqual([["case", "$X", "in"]], read(script)[0][0])
                self.assert_pipe_is_reported(script)

    def test_tight_spaced_and_next_line_arm_controls_stay_read(self):
        controls = (
            'case "$X" in a) %s;; esac\n' % self.PIPE,
            'case "$X" in ( a | b ) %s;; esac\n' % self.PIPE,
            ('case "$X" in\n'
             '  a)\n'
             '    case "$Y" in b) %s;; esac;;\n'
             'esac\n') % self.PIPE,
            ('case "$X" in\n'
             '  a)case "$Y" in b) %s;; esac;;\n'
             'esac\n') % self.PIPE,
        )
        for script in controls:
            with self.subTest(script=script):
                self.assert_pipe_is_reported(script)


class TestTheGuardCreditsTheRescueThatEndsTheList(unittest.TestCase):
    """The step-level reading, with the must-trip control beside each clean
    one: dropping the `|| exit 1` is what bash needs to run the use, and it is
    what the guard needs to report the step."""

    def test_the_issues_step_is_accepted_and_the_control_is_reported(self):
        for shell in (None, "sh", "bash"):
            with self.subTest(shell=shell):
                self.assertEqual([], defects("%s && [[ -f a || -f b ]] || exit 1\n", shell))
                found = defects("%s && [[ -f a || -f b ]]\n", shell)
                self.assertEqual(1, len(found), found)
                self.assertIn("runs ahead of `&&`, where the shell suspends `-e`", found[0])

    def test_the_other_conditional_shapes_are_accepted_with_their_rescue(self):
        for body in ("%s && [[ ( -f a || -f b ) && -n $c ]] || exit 1\n",
                     "%s && [[ $a < $b ]] || exit 1\n",
                     "%s && [[ -f a ]] && [[ -f b ]] || exit 1\n",
                     "%s && [[ -f a \\\n   || -f b ]] || exit 1\n",
                     "%s && ! [[ -f a ]] || exit 1\n"):
            with self.subTest(body=body):
                self.assertEqual([], defects(body))
                self.assertEqual(1, len(defects(body.replace(" || exit 1", ""))), body)

    def test_a_check_before_a_conditional_branch_still_clears_the_use(self):
        self.assertEqual([], defects('%s\nif [[ -f a && -n "$b" ]]; then echo ok; fi\n'))
        self.assertEqual([], defects("while [[ ! -f a || ! -f b ]]; do sleep 1; done\n%s\n"))
        # The control: a check that IS the `if` test decides a branch, so
        # errexit never applies to it and the guard refuses it as before.
        found = defects("if %s; then echo ok; fi\n")
        self.assertEqual(1, len(found), found)
        self.assertIn("is an `if`/`while` test", found[0])

    def test_a_check_in_an_or_branch_reads_as_its_plain_spelling_does(self):
        # NOT a pin on the verdict: `X || CHECK` runs the use unverified when
        # `X` succeeds (bash 3.2.57 and 5.2.21, with the file present), and the
        # guard credits the check anyway -- a gap in the `||`-branch model that
        # predates this change and is none of the reader's doing. What this
        # change owns is that the conditional spelling is read as the plain one.
        plain = defects("test -f a || %s\n")
        for body in ("[[ -f a ]] || %s\n", "[[ -f a || -f b ]] || %s\n"):
            with self.subTest(body=body):
                self.assertEqual(plain, defects(body))


class TestWhatThisDoesNotWiden(unittest.TestCase):
    """Two spellings bash reads as one command that the reader still splits.
    Both are recorded rather than fixed: the first is a continuation only bash
    takes, and the second is a syntax error on every shell."""

    def test_a_newline_after_an_inner_operator_still_ends_the_statement(self):
        # Bash 3.2.57 and 5.2.21 read the newline after `&&` inside `[[ ]]` as
        # a continuation and run the use; the reader ends the statement there,
        # which leaves the test's halves in two statements -- fail-closed, as
        # neither half is a check, a fetch or a use.
        self.assertEqual([(["[[", "-f", "a", "&&"], "\n"), (["-f", "b", "]]"], "\n")],
                         [(st[0][0], st[1]) for st in read("[[ -f a &&\n -f b ]]\n")])

    def test_a_lone_pipe_inside_the_test_still_ends_the_stage(self):
        # `[[ -f a | -f b ]]` is a syntax error on bash 3.2.57 and 5.2.21, so
        # nothing in the step runs; the reader keeps its pipeline reading.
        statement = shell_reader.statements("[[ -f a | -f b ]]\n")[0]
        self.assertEqual(2, len(statement.stages), statement.stages)


if __name__ == "__main__":
    unittest.main()
