"""Function-call gating indexes a step once instead of scanning it per body."""

import unittest
from unittest import mock

import workflow_function_calls
import workflow_gating
import workflow_guard as wg


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


if __name__ == "__main__":
    unittest.main()
