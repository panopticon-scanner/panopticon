"""#2439: option-on state from shell branches that are sure to run.

The guard deliberately treats an option enabled in a branch of unknown outcome
as still off after that branch.  It can be more precise for the three bounded
control-flow forms here: a literal ``if true`` body, the first case arm that a
literal subject is sure to match (or an initial ``*`` arm), and a ``for`` body
over a literal non-empty list. Static ``eval`` and ``command`` spellings run
the same ``set`` in the step's shell and carry the same state.
"""
import unittest

import workflow_guard as wg


HEX = "0" * 64


class TestAnOptionTurnedOnInAProvedBranch(unittest.TestCase):
    FETCH = "curl -fsSLo /tmp/payload https://example.test/payload\n"
    CHECK = 'echo "%s  /tmp/payload" | sha256sum -c -' % HEX
    PIPED = CHECK + " | cat"
    USE = "chmod +x /tmp/payload && /tmp/payload\n"

    def job(self, before, shell=None, check=CHECK):
        run = self.FETCH + before + check + "\n" + self.USE
        return wg.job_defects([wg.Step("step", run, shell)])

    def assertClean(self, before, shell=None, check=CHECK):
        found = self.job(before, shell, check)
        self.assertEqual([], found, found)

    def assertReported(self, before, shell=None, check=CHECK):
        found = self.job(before, shell, check)
        self.assertEqual(1, len(found), found)
        return found[0][1]

    def test_set_e_in_each_proved_branch_arms_the_later_check(self):
        forms = (
            "set +e\nif true; then set -e; fi\n",
            "set +e\nif true\nthen\n  set -e\nfi\n",
            "set +e\ncase x in x) set -e;; esac\n",
            'set +e\ncase "$unknown" in *) set -e;; esac\n',
            "set +e\nfor item in one; do set -e; done\n",
            "set +e\nfor item in one two; do\n  set -e\ndone\n",
            "set +e\nif true; then case x in x) set -e;; esac; fi\n",
            'set +e\nfor item in one; do case "$unknown" in *) set -e;; esac; done\n',
        )
        for shell in (None, "bash", "sh", "bash {0}", "sh {0}"):
            for form in forms:
                with self.subTest(shell=shell, form=form):
                    self.assertClean(form, shell)

    def test_shopt_in_a_proved_branch_arms_errexit_in_bash(self):
        for shell in (None, "bash", "bash {0}"):
            for form in (
                "set +e\nif true; then shopt -so errexit; fi\n",
                "set +e\ncase x in x) shopt -s -o errexit;; esac\n",
                "set +e\nfor item in one; do shopt -os errexit; done\n",
            ):
                with self.subTest(shell=shell, form=form):
                    self.assertClean(form, shell)

    def test_set_and_shopt_in_proved_branches_arm_pipefail(self):
        for form in (
            "set +o pipefail\nif true; then set -o pipefail; fi\n",
            "set +o pipefail\ncase x in x) set -o pipefail;; esac\n",
            "set +o pipefail\nfor item in one; do set -o pipefail; done\n",
            "set +o pipefail\nif true; then shopt -so pipefail; fi\n",
        ):
            with self.subTest(form=form):
                self.assertClean(form, check=self.PIPED)

    def test_static_setter_wrappers_carry_option_on_state(self):
        portable = (
            "set +e\neval set -e\n",
            "set +e\neval 'set -e'\n",
            'set +e\neval "set -e"\n',
            "set +e\ncommand set -e\n",
            "set +e\nif true; then command set -e; fi\n",
        )
        for shell in (None, "bash", "sh", "bash {0}", "sh {0}"):
            for form in portable:
                with self.subTest(shell=shell, form=form):
                    self.assertClean(form, shell)

    def test_static_setter_wrappers_carry_pipefail_state(self):
        for form in (
            "set +o pipefail\neval 'set -o pipefail'\n",
            "set +o pipefail\ncommand set -o pipefail\n",
        ):
            with self.subTest(form=form):
                self.assertClean(form, check=self.PIPED)

    def test_a_branch_or_eval_the_guard_cannot_decide_stays_fail_closed(self):
        for form in (
            'set +e\nif [ -n "$unknown" ]; then set -e; fi\n',
            "set +e\nif command true; then set -e; fi\n",
            'set +e\ncase "$unknown" in x) set -e;; esac\n',
            "set +e\ncase x in '*') set -e;; esac\n",
            "set +e\ncase x in \\*) set -e;; esac\n",
            "set +e\ncase x in 'x|y') set -e;; esac\n",
            "set +e\ncase ~ in '~') set -e;; esac\n",
            'set +e\ncase "$unknown" in x) :;; *) set -e;; esac\n',
            "set +e\nshopt -s nocasematch\ncase X in x) :;; X) set -e;; esac\n",
            "set +e\nif true; false; then set -e; fi\n",
            "set +e\nif true < /definitely/missing; then set -e; fi\n",
            "set +e\nif true; then case x in y) set -e;; esac; fi\n",
            "set +e\nfalse && if true; then set -e; fi\n",
            "set +e\nfalse && case x in x) set -e;; esac\n",
            "set +e\nfalse && for item in one; do set -e; done\n",
            "set +e\nif true; then set -e; fi < /definitely/missing\n",
            "set +e\ncase x in x) set -e;; esac < /definitely/missing\n",
            "set +e\nfor item in one; do set -e; done < /definitely/missing\n",
            "set +e\nif true; then set -e; fi & wait\n",
            "set +e\nif true; then set -e; fi | cat\n",
            "set +e\nfor item in; do set -e; done\n",
            "set +e\nfor item in $unknown; do set -e; done\n",
            "set +e\nfor item in *.txt; do set -e; done\n",
        ):
            with self.subTest(form=form):
                self.assertReported(form)
        found = self.job("set +e\nvalue='set -e'\neval \"$value\"\n")
        self.assertTrue(any("program this guard does not follow" in reason for _step, reason in found), found)
        self.assertTrue(any("runs after a `set +e`" in reason for _step, reason in found), found)

    def test_a_setter_that_may_be_skipped_by_a_list_stays_fail_closed(self):
        for form in (
            "set +e\ntrue && set -e\n",
            "set +e\nfalse || set -e\n",
            "set +e\nif true; then false && set -e; fi\n",
            "set +e\nif true; then set -e & wait; fi\n",
            "set +e\nfor item in one; do break; set -e; done\n",
            "set +e\nfor item in one; do continue; set -e; done\n",
            "set +e\nfor item in one; do eval break; set -e; done\n",
            "set +e\nf() { break; }\nfor item in one; do f; set -e; done\n",
        ):
            with self.subTest(form=form):
                self.assertReported(form)

    def test_bash_only_shopt_is_not_credited_to_sh(self):
        for form in (
            "set +e\nif true; then shopt -so errexit; fi\n",
            "set +e\ncommand shopt -so errexit\n",
            "set +e\nbuiltin set -e\n",
        ):
            with self.subTest(form=form):
                self.assertReported(form, "sh")

    def test_builtin_and_wrapped_shopt_keep_their_named_fail_closed_reading(self):
        for form, check in (
            ("set +e\nbuiltin set -e\n", self.CHECK),
            ("set +e\ncommand shopt -so errexit\n", self.CHECK),
            ("set +e\neval shopt -so errexit\n", self.CHECK),
            ("set +e\ncommand command set -e\n", self.CHECK),
            ("set +e\ncommand eval 'set -e'\n", self.CHECK),
            ("set +e\neval 'command set -e'\n", self.CHECK),
            ("set +o pipefail\nbuiltin set -o pipefail\n", self.PIPED),
            ("set +o pipefail\neval 'shopt -so pipefail'\n", self.PIPED),
        ):
            with self.subTest(form=form):
                self.assertReported(form, check=check)


if __name__ == "__main__":
    unittest.main()
