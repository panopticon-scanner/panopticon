"""#3141: the understood subset. A step a download reaches -- the one that fetches and every one after it in the job --
that reads outside the small subset this repo's own workflows use there is UNVERIFIED in the fleet lint
(`job_defects(steps, subset=True)`, `tests/test_workflow_pins.py`): "step not fully read: <construct> at line N; review
by hand". A step the guard reports keeps that finding alone, and every other caller reads as before."""
import unittest

import pytest

import workflow_guard as wg
import workflow_subset
from tests.test_shell_reader import LinearGrowth

FETCH = "curl -fsSLo t https://example.test/t\n"
CHECK = 'echo "%s  t" | sha256sum -c -\n' % ("a" * 64)


def findings(*scripts, subset=True):
    return [why for _name, why in wg.job_defects([wg.Step("s%d" % n, text) for n, text in enumerate(scripts)],
                                                 subset=subset)]


def unverified(construct, line):
    return "step not fully read: %s at line %d; review by hand" % (construct, line)


class TestTheUnderstoodSubset(unittest.TestCase):

    def test_a_step_inside_the_subset_reads_clean(self):
        # What the fleet's download-reachable steps use: the commands, wrappers taken off, `if` and `case` with their
        # arms, `{ }` groups, assignments, a command substitution of a command in the subset, pipes and lists.
        self.assertEqual([], findings(
            "set -euo pipefail\n" + FETCH + CHECK + "sudo mkdir -p d\nrc=0\ntimeout 5 test -f t || rc=$?\n"
            'case "$rc" in\n  0) ;;\n  *) echo "rc=$rc"; exit 1 ;;\nesac\n'
            'if [ -f t ]; then chmod +x t; fi\ntest -f t || { echo none; exit 1; }\nsize="$(stat -c%s t)"\n'))

    def test_a_step_outside_it_is_unverified_at_its_line(self):
        for tail, construct in (
                ("awk x t\n", "the command `awk`"),
                ('n="$(awk -c x t)"\n', "the command `awk`"),
                ('eval "echo ok"\n', "the command `eval`"),
                ("$RUN t\n", "the command `$RUN`"),     # a value command word, the download checked
                ("while true; do echo ok; done\n", "the keyword `while`"),
                ("f() { echo ok; }\n", "a function definition"),
                ("echo <(echo ok)\n", "a process substitution")):
            with self.subTest(tail=tail):
                self.assertEqual([unverified(construct, 3)], findings(FETCH + CHECK + tail))

    def test_a_private_use_character_comes_first(self):
        # Wherever it stands: here on line 4, after a command outside the subset on line 3.
        text = FETCH + CHECK + "awk x t\n# " + chr(0xE004) + "\n"
        self.assertEqual([unverified("a private-use character", 4)], findings(text))
        self.assertEqual(workflow_subset.Unread("a private-use character", 4),
                         workflow_subset.fully_read(wg.read(text), text))

    def test_java_on_the_list_still_may_not_run_a_download(self):
        # #3251: a name on the list is not a pass for what it runs. Each form is still reported, not read clean.
        for name, run in (("a.jar", "java -jar a.jar"), ("a.jar", "java -cp a.jar Main"), ("A.java", "java A.java")):
            with self.subTest(run=run):
                self.assertIn("running it under `java`", " ".join(
                    findings("curl -fsSL https://example.test/f -o %s\n%s\n" % (name, run))))
        self.assertIn("`java /dev/stdin`", " ".join(findings("curl -fsSL https://example.test/f | java /dev/stdin\n")))

    def test_java_on_a_checked_download_reads_clean(self):
        self.assertEqual([], findings(FETCH + CHECK + "java -jar t\n"))

    def test_a_reported_step_keeps_its_report_alone(self):
        found = findings(FETCH + "sh t\n")
        self.assertEqual(1, len(found))
        self.assertIn("running it under `sh` with nothing verifying what arrived", found[0])

    def test_a_download_reaches_the_steps_after_it_and_not_those_before(self):
        self.assertEqual([unverified("the command `awk`", 1)], findings(FETCH + CHECK, "awk x t\n"))
        self.assertEqual([], findings("awk x t\n", FETCH + CHECK))
        self.assertEqual([], findings("awk x t\n"))

    def test_a_step_the_lexer_refuses_is_outside_the_subset(self):
        # The guard names such a step itself ("cannot read this step"), and that finding stands alone; the gate's
        # own reading of it, without that finding, is UNVERIFIED rather than skipped.
        refused = "cat <<$(a b)\nit's\n$(a b)\n"
        found = findings(FETCH + CHECK, refused)
        self.assertEqual(1, len(found))
        self.assertTrue(found[0].startswith("cannot read this step: "))
        self.assertEqual([("s1", "step not fully read: a step the reader cannot read; review by hand")],
                         wg._unverified([wg.Step("s0", FETCH + CHECK), wg.Step("s1", refused)], []))

    def test_the_gate_is_the_fleet_lints_alone(self):
        # Every other caller of `job_defects` reads as `main` does.
        self.assertEqual([], findings(FETCH + CHECK + "awk x t\n", subset=False))

    def test_the_line_follows_the_statements(self):
        # The word first stands where it is not the command: in a comment, then as an argument.
        text = "# awk here\n" + FETCH + CHECK + "echo awk\nawk x t\n"
        self.assertEqual([unverified("the command `awk`", 5)], findings(text))


class TestFullyReadIsLinear(LinearGrowth, unittest.TestCase):

    @staticmethod
    def make(n):
        return FETCH + CHECK + "mkdir -p d\n" * n + "awk x t\n"

    @pytest.mark.serial
    def test_one_pass_over_the_step(self):
        # Growth, not speed: `read` and the walk at 500 and 2,000 statements, the construct found on the last line.
        self.assert_linear_growth(500, self.make, lambda n, found: self.assertEqual(
            workflow_subset.Unread("the command `awk`", n + 3), found),
            parser=lambda text: workflow_subset.fully_read(wg.read(text), text))


if __name__ == "__main__":
    unittest.main()
