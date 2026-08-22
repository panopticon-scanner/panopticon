"""Tests for the _run_adapter helper script."""
import io
import sys
import unittest
from unittest import mock

import scripts._run_adapter as ra


class TestRunAdapterHelper(unittest.TestCase):
    def test_main_runs_named_adapter_and_returns_rc(self):
        class FakeAdapter:
            name = "fake"
            def invoke(self, target): return (b'{"ok":true}', 0)

        with mock.patch.dict(ra.ADAPTERS, {"fake": FakeAdapter()}, clear=False):
            stdout = io.BytesIO()
            class FakeOut:
                buffer = stdout
            old_stdout = sys.stdout
            sys.stdout = FakeOut()
            try:
                rc = ra.main(["_run_adapter.py", "fake", "/tmp/target"])
            finally:
                sys.stdout = old_stdout
            self.assertEqual(rc, 0)
            self.assertEqual(stdout.getvalue(), b'{"ok":true}')

    def test_main_fails_closed_on_unregistered_adapter(self):
        # #1051: an unregistered adapter must exit non-zero (was 0 == "ran clean")
        rc = ra.main(["_run_adapter.py", "not-a-real-adapter", "/tmp/target"])
        self.assertEqual(rc, ra.FAIL_RC)

    def test_main_fails_closed_on_adapter_that_crashes(self):
        # #1051 / SEC-G2B: a crash must exit non-zero, never a silent rc 0
        class CrashingAdapter:
            name = "crash"
            def invoke(self, target):
                raise RuntimeError("boom")

        with mock.patch.dict(ra.ADAPTERS, {"crash": CrashingAdapter()}, clear=False):
            rc = ra.main(["_run_adapter.py", "crash", "/tmp/target"])
            self.assertEqual(rc, ra.FAIL_RC)

    def test_adapter_helper_registry_not_leaked(self):
        # Regression: _run_adapter helper tests must restore ra.ADAPTERS.
        original = dict(ra.ADAPTERS)
        self.test_main_runs_named_adapter_and_returns_rc()
        self.assertEqual(dict(ra.ADAPTERS), original)
