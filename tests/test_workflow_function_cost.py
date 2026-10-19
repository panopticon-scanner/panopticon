"""Function-call gating indexes a step once instead of scanning it per body."""

import random
import unittest
from unittest import mock

import shell_reader
import workflow_failure_contexts
import workflow_function_calls
import workflow_gating
import workflow_guard as wg


FETCH = "curl -fsSLo t https://example.test/t"
SUMS = "echo '%s  t' > sums" % ("a" * 64)
RESCUED = "f() { sha256sum -c sums || exit 1; }"
RESCUED_LINES = "f() {\n  sha256sum -c sums || exit 1\n}"
PLAIN_LINES = "f() {\n  sha256sum -c sums\n}"


def _script(*lines):
    return "\n".join(lines) + "\n"


# The review seat's complete div*/hp* differential, including controls.  hp0-
# hp4 are valid parent scripts whose handed child contributes the stray close.
STRAY_CLOSER_ROWS = {
    "div0": _script(FETCH, SUMS, RESCUED_LINES, ")", "{ { f; }; } | cat", "sh t"),
    "div1": _script(FETCH, SUMS, "set -e", RESCUED_LINES, ")", "{ { f; }; } | cat", "sh t"),
    "div2": _script(FETCH, SUMS, "set -eo pipefail", RESCUED_LINES, ")",
                    "{ { f; }; } | cat", "sh t"),
    "div3": _script(FETCH, SUMS, RESCUED_LINES, "}", "{ { f; }; } | cat", "sh t"),
    "div4": _script(FETCH, SUMS, RESCUED, ")", "{", "{", "f", "}", "} | cat", "sh t"),
    "div5": _script(FETCH, SUMS, ")", RESCUED, "{ { f; }; } | cat", "sh t"),
    "div6": _script(FETCH, SUMS, RESCUED, "{ { f; }; } | cat", "sh t"),
    "div7": _script(FETCH, SUMS, RESCUED, ")", "{ { f; }; } | cat", "sh t"),
    "div8": _script(FETCH, SUMS, RESCUED, ")", "{ { f; }; }", "sh t"),
    "div9": _script(FETCH, SUMS, RESCUED, ") | cat", "{ { f; }; } | cat", "sh t"),
    "div10": _script(FETCH, SUMS, "set -o pipefail", RESCUED, ")",
                     "{ { f; }; } | cat", "sh t"),
    "div11": _script(FETCH, SUMS, PLAIN_LINES, ")", "{ { f; }; } | cat", "sh t"),
    "div12": _script(FETCH, SUMS, "set -e", PLAIN_LINES, ")", "{ { f; }; } | cat", "sh t"),
    "div13": _script(FETCH, SUMS, "set -eo pipefail", PLAIN_LINES, ")",
                     "{ { f; }; } | cat", "sh t"),
    "div14": _script(FETCH, SUMS, "set -eo pipefail", PLAIN_LINES, "}",
                     "{ { f; } | cat; }", "sh t"),
    "hp0": _script("set -eo pipefail", FETCH, SUMS, RESCUED, "echo ')' | sh || true",
                   "{ { f; }; } | cat", "sh t"),
    "hp1": _script("set -eo pipefail", FETCH, SUMS, RESCUED, "sh -c ')' || true",
                   "{ { f; }; } | cat", "sh t"),
    "hp2": _script("set -eo pipefail", FETCH, SUMS, RESCUED, "bash -c 'echo )' || true",
                   "{ { f; }; } | cat", "sh t"),
    "hp3": _script("set -eo pipefail", FETCH, SUMS, RESCUED,
                   "printf '%s\\n' ')' | sh || :", "{ { f; }; } | cat", "sh t"),
    "hp4": _script("set -eo pipefail", FETCH, SUMS, RESCUED, "sh -c '}' || true",
                   "{ { f; }; } | cat", "sh t"),
    "hp5": _script("set -eo pipefail", FETCH, SUMS, RESCUED, "{ { f; }; } | cat", "sh t"),
    "hp6": _script(FETCH, SUMS, RESCUED, "echo ')' | sh || true",
                   "{ { f; }; } | cat", "sh t"),
}


# The three generated review rows that changed text without changing verdict.
GENERATED_STRAY_CLOSER_ROWS = {
    "gen2130": _script(
        "wget -qO t https://example.test/t", SUMS, "command f",
        "verify() { sha256sum -c sums || exit 1; }", "{ { f; }; } | tee log", "}",
        "verify() {", "  eval ':'", "  ( sha256sum -c sums || exit 1 )",
        "  shopt -s expand_aliases", "  { if ! sha256sum -c sums; then exit 1; fi; } | cat",
        "} | cat", "{ { verify; }; } | tee log", "./t", "! verify", "chmod +x t && ./t"),
    "gen2733": _script(
        FETCH, SUMS, "}", "verify() (", "  command set +e", ") | cat", "verify; echo after",
        "if true; then", "g () {", "  { sha256sum -c sums; }", "  sha256sum -c sums",
        "} >log", "fi", "{ { verify; }; } | tee log", "{ { h; }; } | tee log",
        "chmod +x t && ./t"),
    "gen2924": _script(
        FETCH, SUMS, "} } | cat", "(", "verify() (", "  x=$(verify)", "  function h() {",
        "    sha256sum -c sums || return 1", "    unset -f g", "    f () {", "      true",
        "    } >log", "  } >log", "  sha256sum -c sums || return 1", "  source ./lib.sh",
        ") >log", ")", "f; echo after", "g() (", "  set +e", ") >log",
        'verify() { echo "%s  t" | sha256sum -c -; { { h; }; } | tee log; echo hi; }'
        % ("a" * 64), "./t", "g | cat", "chmod +x t && ./t"),
}


def _sampled_function_rows():
    """A fixed draw of malformed and balanced function-call boundaries."""
    draw = random.Random(3158)
    rows = {}
    for number in range(128):
        name = draw.choice(("f", "g", "verify"))
        definition = draw.choice((
            f"{name}() {{ sha256sum -c sums || exit 1; }}",
            f"{name}() {{\n  sha256sum -c sums\n}}",
            f"{name}() (\n  sha256sum -c sums || return 1\n)",
        ))
        lines = [FETCH, SUMS]
        posture = draw.choice((None, None, "set -e", "set -o pipefail", "set -eo pipefail"))
        if posture is not None:
            lines.append(posture)
        lines.append(definition)
        closer = draw.choice((None, None, None, ")", "}", ") | cat", "} } | cat"))
        if closer is not None:
            lines.append(closer)
        depth = draw.randint(1, 4)
        lines.extend("{" for _level in range(depth))
        lines.append(name)
        piped = draw.randrange(depth + 1)
        for level in range(depth):
            lines.append("}" + (" | cat" if level == piped else ""))
        lines.extend(("sh t", draw.choice(("true", f"{name} || true", "echo done"))))
        rows[f"sample{number}"] = _script(*lines)
    return rows


class TestFunctionGatingIsIndexed(unittest.TestCase):
    """#3128: adding definitions doubles the two forward searches' work."""

    FETCH = "curl -fsSLo t https://example.test/t\n"
    PRINT = "echo 'echo ok' | sh\n"
    CHECK = "sha256sum -c t.sha || exit 1\n"

    @classmethod
    def nested_uses(cls, n):
        return (cls.FETCH + "".join("f%d() {\n" % i for i in range(n))
                + "sh t\n" + "}\n" * n + "f0\n")

    @classmethod
    def sibling_gates(cls, n):
        return "".join(
            "f%d() {\n%s%s}\nf%d\n" % (i, cls.PRINT, cls.CHECK, i)
            for i in range(n)
        )

    def barrier_calls(self, make, n):
        with mock.patch.object(
                workflow_function_calls, "_posture_barrier",
                wraps=workflow_function_calls._posture_barrier) as calls:
            with mock.patch.object(
                    workflow_gating, "_posture_barrier",
                    wraps=workflow_gating._posture_barrier) as pipelines:
                findings = wg.job_defects([wg.Step("step", make(n), None)])
        return calls.call_count + pipelines.call_count, findings

    def closer_calls(self, n):
        with mock.patch.object(
                workflow_function_calls, "_closes",
                wraps=workflow_function_calls._closes) as closes:
            findings = wg.job_defects([wg.Step("step", self.nested_uses(n), None)])
        return closes.call_count, findings

    def test_each_statement_is_examined_once_for_function_call_events(self):
        shapes = ((self.nested_uses, 1), (self.sibling_gates, 0))
        for make, expected_findings in shapes:
            with self.subTest(shape=make.__name__):
                small, small_findings = self.barrier_calls(make, 16)
                large, large_findings = self.barrier_calls(make, 32)
                self.assertEqual(expected_findings, len(small_findings))
                self.assertEqual(expected_findings, len(large_findings))
                self.assertLessEqual(large, 2 * small + 32, (small, large))

    def test_each_closing_run_is_indexed_once(self):
        small, small_findings = self.closer_calls(16)
        large, large_findings = self.closer_calls(32)
        self.assertEqual(1, len(small_findings))
        self.assertEqual(1, len(large_findings))
        self.assertLessEqual(large, 2 * small + 32, (small, large))

    def test_indexed_pipeline_answers_match_a_deterministic_legacy_sample(self):
        # The exact review rows are joined by a seeded sample so the O(1)
        # lookup stays equivalent beyond the one reported nesting depth.
        rows = {**STRAY_CLOSER_ROWS, **GENERATED_STRAY_CLOSER_ROWS,
                **_sampled_function_rows()}
        groups = functions = 0
        for name, script in rows.items():
            statement_lists = (
                ("source", list(shell_reader.statements(script))),
                ("handed", list(wg.read(script))),
            )
            for reading, stmts in statement_lists:
                analysis = workflow_failure_contexts.statement_analysis(stmts)
                indexed = workflow_function_calls._function_index(stmts, analysis)
                for position in range(len(stmts)):
                    legacy = workflow_gating._piped_group_stage(stmts, position)
                    start = indexed.piped_group(position)
                    answer = (workflow_gating._pipeline_end(stmts, *start)
                              if start is not None else None)
                    with self.subTest(row=name, reading=reading, position=position,
                                      helper="piped_group"):
                        self.assertEqual(legacy, answer)
                    groups += 1

                    legacy = workflow_gating._piped_function_end(stmts, position)
                    answer = workflow_gating._piped_function_end(
                        stmts, position, analysis)
                    with self.subTest(row=name, reading=reading, position=position,
                                      helper="piped_function_end"):
                        self.assertEqual(legacy, answer)
                    functions += 1
        self.assertGreater(groups, 2500)
        self.assertEqual(groups, functions)


if __name__ == "__main__":
    unittest.main()
