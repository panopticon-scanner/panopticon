import io
import os
import sys
import unittest
from contextlib import redirect_stderr

ROOT = os.path.join(os.path.dirname(__file__), os.pardir)
sys.path.insert(0, os.path.join(ROOT, "skill"))

import scripts._run_adapter as ra  # noqa: E402


class _Raises:
    name = "boom"

    def invoke(self, target):
        raise RuntimeError("adapter exploded")


class _EmitFails:
    """Adapter returns a stdout object whose bytes cannot be written."""
    name = "emit"

    def invoke(self, target):
        class _Bad:
            def __len__(self):  # truthy, so we reach the write path
                return 1
        return _Bad(), 0


class TestRunAdapterFailClosed(unittest.TestCase):
    # #1051 / SEC-G2B: a crash, an emit failure, or an unregistered adapter must
    # exit NON-ZERO so the caller (run_tools._capture_run) treats it as a skip
    # and the manifest lands it in `missing` -- never a clean rc 0 that reads as
    # "ran clean".

    def _with_adapter(self, name, adapter):
        ra.ADAPTERS[name] = adapter
        self.addCleanup(lambda: ra.ADAPTERS.pop(name, None))

    def test_crash_returns_nonzero(self):
        self._with_adapter("boom", _Raises())
        with redirect_stderr(io.StringIO()) as err:
            rc = ra.main(["_run_adapter.py", "boom", "/src"])
        self.assertNotEqual(rc, 0)
        self.assertIn("crashed", err.getvalue())

    def test_unregistered_adapter_returns_nonzero(self):
        with redirect_stderr(io.StringIO()) as err:
            rc = ra.main(["_run_adapter.py", "does-not-exist", "/src"])
        self.assertNotEqual(rc, 0)
        self.assertIn("not registered", err.getvalue())

    def test_emit_failure_returns_nonzero(self):
        self._with_adapter("emit", _EmitFails())
        with redirect_stderr(io.StringIO()) as err:
            rc = ra.main(["_run_adapter.py", "emit", "/src"])
        self.assertNotEqual(rc, 0)
        self.assertIn("failed to emit", err.getvalue())

    def test_clean_adapter_passes_through_returncode(self):
        class _Ok:
            name = "ok"
            def invoke(self, target):
                return b'{"findings":[]}', 0
        self._with_adapter("ok", _Ok())
        rc = ra.main(["_run_adapter.py", "ok", "/src"])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
