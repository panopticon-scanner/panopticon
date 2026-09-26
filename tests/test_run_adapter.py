import io
import os
import unittest
from contextlib import redirect_stderr
from unittest import mock


import scripts._run_adapter as ra


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
        # #run7 TST-D1A: patch.dict restores the prior mapping on cleanup; the old
        # `pop(name, None)` DELETED the key even if it had pre-existed (a latent
        # harness bug if a synthetic name ever collided with a real adapter).
        p = mock.patch.dict(ra.ADAPTERS, {name: adapter}, clear=False)
        p.start()
        self.addCleanup(p.stop)

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


class _ModeReader:
    """An adapter that DECLARES it reads the security mode, like the real
    `LegacySarifAdapter` (#1839)."""

    name = "mode-reader"
    reads_security_mode = True

    def __init__(self):
        self.seen = []

    def invoke(self, target, security_mode=ra.STANDARD):
        self.seen.append(security_mode)
        return b"{}", 0


class _ModeBlind:
    """An adapter that declares nothing: it must be called exactly as before."""

    name = "mode-blind"

    def __init__(self):
        self.calls = []

    def invoke(self, target):
        self.calls.append(target)
        return b"{}", 0


class TestSecurityModeReachesTheAdapter(unittest.TestCase):
    """#1839 (run-14 SEC-284952751): an inline suppression COMMENT in the
    target's source is neutralised under `--security redteam` and honoured
    under `standard`, so the adapter that builds the scanner's argv inside the
    container has to know which mode this run is. The dispatcher tells it on
    the argv -- an explicit `--security <mode>` pair rather than an environment
    variable, which is a channel the reviewed repository's own hooks could set.
    """

    def _with_adapter(self, name, adapter):
        p = mock.patch.dict(ra.ADAPTERS, {name: adapter}, clear=False)
        p.start()
        self.addCleanup(p.stop)
        return adapter

    def test_the_mode_reaches_an_adapter_that_declares_it(self):
        adapter = self._with_adapter("mode-reader", _ModeReader())
        rc = ra.main(["_run_adapter.py", ra.SECURITY_FLAG, "redteam",
                      "mode-reader", "/src"])
        self.assertEqual(rc, 0)
        self.assertEqual(adapter.seen, ["redteam"])

    def test_an_adapter_that_declares_nothing_is_called_unchanged(self):
        # Every other adapter's `invoke` takes one argument; passing the
        # keyword to all of them would be a TypeError -> FAIL_RC, i.e. the
        # whole tool axis lost on a plumbing change.
        adapter = self._with_adapter("mode-blind", _ModeBlind())
        rc = ra.main(["_run_adapter.py", ra.SECURITY_FLAG, "redteam",
                      "mode-blind", "/src"])
        self.assertEqual(rc, 0)
        self.assertEqual(adapter.calls, [os.path.abspath("/src")])

    def test_the_flag_pair_is_not_read_as_the_target(self):
        # `target` is positional (argv[2]); the pair is stripped BEFORE that
        # read, or the scan root becomes the string "--security".
        adapter = self._with_adapter("mode-reader", _ModeReader())
        rc = ra.main(["_run_adapter.py", ra.SECURITY_FLAG, "standard",
                      "mode-reader"])
        self.assertEqual(rc, 0)
        self.assertEqual(adapter.seen, [ra.STANDARD])

    def test_the_default_is_standard_when_no_mode_is_named(self):
        adapter = self._with_adapter("mode-reader", _ModeReader())
        rc = ra.main(["_run_adapter.py", "mode-reader", "/src"])
        self.assertEqual(rc, 0)
        self.assertEqual(adapter.seen, [ra.STANDARD])

    def test_an_unrecognised_mode_fails_closed(self):
        # The argv is machine-generated, so an unknown token is a bug -- and
        # the fail-OPEN reading of one (treat it as `standard`) is a run that
        # silently honours the target's suppression comments under redteam.
        adapter = self._with_adapter("mode-reader", _ModeReader())
        with redirect_stderr(io.StringIO()) as err:
            rc = ra.main(["_run_adapter.py", ra.SECURITY_FLAG, "redteem",
                          "mode-reader", "/src"])
        self.assertEqual(rc, ra.FAIL_RC)
        self.assertEqual(adapter.seen, [])
        self.assertIn("security mode", err.getvalue())

    def test_a_mode_flag_with_no_value_fails_closed(self):
        adapter = self._with_adapter("mode-reader", _ModeReader())
        with redirect_stderr(io.StringIO()) as err:
            rc = ra.main(["_run_adapter.py", "mode-reader", ra.SECURITY_FLAG])
        self.assertEqual(rc, ra.FAIL_RC)
        self.assertEqual(adapter.seen, [])
        self.assertIn("security mode", err.getvalue())

    def test_every_mode_aware_invoke_declares_itself(self):
        # The declaration is what `main` dispatches on, so an adapter that
        # GREW the keyword without declaring it would be handed `standard` for
        # ever -- suppression comments honoured on a redteam run, silently.
        import inspect
        declared, takes = [], []
        for name, adapter in sorted(ra.ADAPTERS.items()):
            params = inspect.signature(adapter.invoke).parameters
            if "security_mode" in params:
                takes.append(name)
            if getattr(adapter, "reads_security_mode", False):
                declared.append(name)
        self.assertEqual(takes, declared)
        self.assertTrue(declared, "no adapter reads the mode: the pin is vacuous")

    def test_the_modes_are_the_ones_the_dispatcher_can_send(self):
        # ONE definition of the two names (`tools/base`), read by the
        # dispatcher that writes the token and the entry point that parses it.
        import scripts.run_tools as rt
        self.assertEqual(tuple(ra.SECURITY_MODES), tuple(rt.SECURITY_MODES))
        self.assertIn(rt.REDTEAM, ra.SECURITY_MODES)


if __name__ == "__main__":
    unittest.main()
