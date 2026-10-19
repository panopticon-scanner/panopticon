"""A function's checksum gate counts only when a stopping call precedes the use."""

import unittest

import workflow_guard as wg


URL = "https://example.test/t"
FETCH = f"curl -fsSLo t {URL}"
SUMS = "echo '%s  t' > sums" % ("a" * 64)
CHECK = "sha256sum -c sums"
SHELLS = (None, "bash", "sh", "bash {0}", "sh {0}")
BASH_SHELLS = (None, "bash", "bash {0}")


def reported(body, shell):
    """Whether the guard reports the downloaded `t` used by ``body``."""
    script = f"{FETCH}\n{SUMS}\n{body}\necho done\n"
    return bool(wg.job_defects([wg.Step("step", script, shell)]))


class TestAFunctionGateOnlyCreditsItsCalls(unittest.TestCase):
    """#2949: defining a rescued check does not run or credit the check."""

    FAIL_OPEN_ROWS = {
        "never called": f"f() {{ {CHECK} || exit 1; }}\nsh t",
        "called after use": f"f() {{ {CHECK} || exit 1; }}\nsh t\nf",
        "one-line definition": f"f() {{ {CHECK} || exit 1; }}; sh t",
        "find cannot call a function": (
            f"f() {{ {CHECK} || exit 1; }}\nfind /dev/null -exec f \\;\nsh t"
        ),
        "nested unreachable call": (
            f"f() {{ {CHECK} || return 1; }}\n"
            "g() { find /dev/null -exec f \\; || return 1; }\n"
            "g || exit 1\nsh t"
        ),
    }

    def test_an_uncalled_or_late_function_gate_does_not_clear_the_use(self):
        for name, row in self.FAIL_OPEN_ROWS.items():
            for shell in SHELLS:
                with self.subTest(name=name, shell=shell):
                    self.assertTrue(reported(row, shell))

    def test_the_function_keyword_has_the_same_rule_where_the_shell_accepts_it(self):
        row = f"function f {{ {CHECK} || exit 1; }}\nsh t"
        for shell in BASH_SHELLS:
            with self.subTest(shell=shell):
                self.assertTrue(reported(row, shell))

    def test_the_function_keyword_keeps_the_sh_dialect_fail_closed(self):
        # dash refuses Bash's `function` keyword before reaching the payload.
        # The guard still reports it under an explicit `sh`: that is the
        # bounded fail-closed price of recognizing the same body for Bash.
        row = f"function f {{ {CHECK} || exit 1; }}\nsh t"
        for shell in ("sh", "sh {0}"):
            with self.subTest(shell=shell):
                self.assertTrue(reported(row, shell))

    def test_the_neighboring_controls_keep_their_existing_answers(self):
        rows = {
            # A bare check in an uncalled body already refuses the use.
            "bare check": (f"f() {{ {CHECK}; }}\nsh t", True),
            # A stopping call before the use really gates the downloaded file.
            "called before use": (f"f() {{ {CHECK} || exit 1; }}\nf\nsh t", False),
            # The same rescue at the step level really gates the downloaded file.
            "inline rescue": (f"{CHECK} || exit 1\nsh t", False),
        }
        for name, (row, expected) in rows.items():
            for shell in SHELLS:
                with self.subTest(name=name, shell=shell):
                    self.assertEqual(expected, reported(row, shell))


class TestAStrayCloserBoundsAPipedFunctionCall(unittest.TestCase):
    """#3128: the function index keeps the legacy fail-closed depth bound."""

    def test_an_unmatched_closer_does_not_reach_the_outer_piped_group(self):
        rows = {
            "source closer": f"set -eo pipefail\nf() {{ {CHECK} || exit 1; }}\n)\n"
                             "{ { f; }; } | cat\nsh t",
            "handed closer": f"set -eo pipefail\nf() {{ {CHECK} || exit 1; }}\n"
                             "echo ')' | sh || true\n{ { f; }; } | cat\nsh t",
        }
        for name, row in rows.items():
            for shell in SHELLS:
                with self.subTest(name=name, shell=shell):
                    self.assertTrue(reported(row, shell))


if __name__ == "__main__":
    unittest.main()
