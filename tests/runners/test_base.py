import importlib
import os
import sys
import threading
import time
import unittest
from unittest import mock

import scripts.runners.base as base
import scripts.runners.session as session_runner


class FakeRunner(base.HostRunner):
    host = "fake"; mode = "headless"; default_concurrency = 3
    def __init__(self):
        self.calls = []
    def run_entry(self, entry, env):
        self.calls.append((entry["id"], dict(env)))
        if entry["id"] == "boom":
            raise RuntimeError("launch failed")
        return base.RunResult(entry_id=entry["id"], ok=True, text="{}", usage={},
                              cost_usd=0.0, model=None, session_id=None, denials=[], error=None)


class TestRunBatch(unittest.TestCase):
    def test_results_come_back_in_entry_order_and_an_exception_is_a_failed_result(self):
        r = FakeRunner()
        entries = [{"id": "a"}, {"id": "boom"}, {"id": "c"}]
        out = r.run_batch(entries, 2, env_for=lambda e: {"E": e["id"]})
        self.assertEqual([x.entry_id for x in out], ["a", "boom", "c"])
        self.assertTrue(out[0].ok and out[2].ok)
        self.assertFalse(out[1].ok)
        self.assertIn("launch failed", out[1].error)
        self.assertEqual(sorted(c[0] for c in r.calls), ["a", "boom", "c"])
        self.assertEqual(next(c[1] for c in r.calls if c[0] == "a"), {"E": "a"})

    def test_run_entry_is_abstract(self):
        with self.assertRaises(NotImplementedError):
            base.HostRunner().run_entry({"id": "x"}, {})


class TestIterBatch(unittest.TestCase):
    """P07 (#1636): the loop has to be handed each entry the MOMENT it
    finishes, not when its slowest peer does. `run_batch` joined every future
    before returning anything, so a 42-minute 85-panel batch persisted and
    ledgered nothing until the last entry came back -- and an interruption
    before that lost every completed reply and its usage. `iter_batch` is that
    seam: completion order, with the timing measured around `run_entry`
    itself, which is also where the ledger's duration_ms now comes from (it
    was hard-coded None at the one call site)."""

    def _gated(self):
        """A runner whose "slow" entry blocks until `released` is set, and
        which announces on `entered` that it is really inside `run_entry` --
        the consumer needs that to time anything, because `iter_batch` is a
        generator and its pool does not exist until the first `next()`."""
        released, entered = threading.Event(), threading.Event()

        class Gated(base.HostRunner):
            host = "fake"; mode = "headless"; default_concurrency = 2

            def run_entry(self, entry, env):
                if entry["id"] == "slow":
                    entered.set()
                    released.wait(10)
                return base.RunResult(entry_id=entry["id"], ok=True, text="", usage={},
                                      cost_usd=None, model=None, session_id=None,
                                      denials=[], error=None)

        return Gated(), released, entered

    def test_a_finished_entry_is_yielded_while_its_peer_is_still_running(self):
        r, released, _entered = self._gated()
        entries = [{"id": "slow"}, {"id": "fast"}]
        stream = r.iter_batch(entries, 2, env_for=lambda e: {})
        self.addCleanup(released.set)
        self.addCleanup(stream.close)
        entry, result, timing = next(stream)
        # entry order says "slow" first; completion order says otherwise, and
        # completion order is the one the loop persists in.
        self.assertEqual("fast", entry["id"])
        self.assertEqual("fast", result.entry_id)
        self.assertFalse(released.is_set(), "the slow entry is still inside run_entry")
        self.assertEqual({"started_at", "finished_at", "duration_ms"}, set(timing))
        self.assertIsInstance(timing["duration_ms"], int)
        self.assertGreaterEqual(timing["duration_ms"], 0)
        # same fixed-width UTC format the ledger's own `ts` uses, so the two
        # sort together and finished never precedes started
        for stamp in (timing["started_at"], timing["finished_at"]):
            self.assertRegex(stamp, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        self.assertLessEqual(timing["started_at"], timing["finished_at"])
        released.set()
        self.assertEqual(["slow"], [e["id"] for e, _r, _t in stream])

    def test_the_slow_entrys_timing_covers_the_time_it_blocked(self):
        # The 50 ms window opens only once the worker is provably inside
        # `run_entry`: a bare `threading.Timer` starts counting before the
        # generator has even built its pool, so any stall longer than the
        # window (a loaded CI runner, a CPU-quota'd container) would release
        # the entry before it blocked and collapse duration_ms to 0.
        r, released, entered = self._gated()
        stream = r.iter_batch([{"id": "slow"}, {"id": "fast"}], 2, lambda e: {})
        self.addCleanup(released.set)
        self.addCleanup(stream.close)
        first = next(stream)                       # "fast"; the pool now exists
        self.assertTrue(entered.wait(10), "the slow entry never entered run_entry")
        time.sleep(0.05)
        released.set()
        timings = {e["id"]: t for e, _r, t in [first] + list(stream)}
        self.assertGreaterEqual(timings["slow"]["duration_ms"], 40)
        self.assertLess(timings["fast"]["duration_ms"], timings["slow"]["duration_ms"])

    def test_run_batch_drains_iter_batch_and_keeps_entry_order(self):
        r, released, _entered = self._gated()
        released.set()
        out = r.run_batch([{"id": "slow"}, {"id": "fast"}], 2, env_for=lambda e: {})
        self.assertEqual(["slow", "fast"], [x.entry_id for x in out])

    def test_a_family_inherits_it_without_overriding_anything(self):
        # docs/FAMILY-PR-GUARDRAILS.md §3: `run_entry` is the only method a
        # family implements; the pool -- both shapes of it -- is inherited.
        # This is what made dropping the `results is None` branch safe, and it
        # matters more now: headless calls `iter_batch`, so a family that
        # overrode `run_batch` -- the documented seam until this PR -- would
        # have its override silently ignored rather than failing loudly.
        #
        # Discovered from the package directory, the way
        # tests/test_layout.py::_package_dirs does, so the NEXT family is
        # enrolled by existing rather than by being listed here.
        pkg_dir = os.path.dirname(os.path.abspath(base.__file__))
        names = sorted(f[:-3] for f in os.listdir(pkg_dir)
                       if f.endswith(".py") and f not in ("__init__.py", "base.py"))
        self.assertIn("claude", names)                  # the directory really was read
        for name in names:
            mod = importlib.import_module("scripts.runners.%s" % name)
            runner = getattr(mod, "Runner", None) or getattr(mod, "SessionRunner", None)
            self.assertIsNotNone(runner, name)
            self.assertNotIn("iter_batch", vars(runner), name)
            if name != "session":       # the one documented override: it launches nothing
                self.assertNotIn("run_batch", vars(runner), name)


class TestRunnerFor(unittest.TestCase):
    def test_session_mode_is_always_available(self):
        r = base.runner_for("gemini", "session")
        self.assertIsInstance(r, session_runner.SessionRunner)
        self.assertEqual(r.mode, "session")

    def test_headless_resolves_the_host_module_or_refuses(self):
        self.assertTrue(base.headless_available("claude"))
        self.assertEqual(base.runner_for("claude", "headless").mode, "headless")
        self.assertFalse(base.headless_available("gemini"))
        with self.assertRaises(ValueError) as cm:
            base.runner_for("gemini", "headless")
        self.assertIn("--mode session", str(cm.exception))

    def test_unknown_mode_is_refused(self):
        with self.assertRaises(ValueError):
            base.runner_for("claude", "batch")


class TestBrokenHeadlessModule(unittest.TestCase):
    def test_a_broken_runner_module_raises_instead_of_reading_as_absent(self):
        pkg_dir = os.path.dirname(os.path.abspath(base.__file__))
        modname = "scripts.runners.brokenhost"
        path = os.path.join(pkg_dir, "brokenhost.py")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("import scripts.runners.does_not_exist_xyz\n")

        def _cleanup():
            if os.path.exists(path):
                os.remove(path)
            sys.modules.pop(modname, None)
            sys.modules.pop("scripts.runners.does_not_exist_xyz", None)
            cache_dir = os.path.join(pkg_dir, "__pycache__")
            if os.path.isdir(cache_dir):
                for f in os.listdir(cache_dir):
                    if f.startswith("brokenhost."):
                        os.remove(os.path.join(cache_dir, f))

        self.addCleanup(_cleanup)

        with self.assertRaises(ModuleNotFoundError) as cm:
            base.runner_for("brokenhost", "headless")
        self.assertEqual(cm.exception.name, "scripts.runners.does_not_exist_xyz")

        with self.assertRaises(ModuleNotFoundError):
            base.headless_available("brokenhost")


class TestGuardFileNameConstants(unittest.TestCase):
    """M5 (final review): the allowlist/scope file NAMES have ONE owner here,
    read by module attribute everywhere else. Two writers have to agree on
    them byte-for-byte -- `runners/claude.py`'s `prepare`, which bakes them
    into the hook commands it writes into host-settings.json, and
    `orchestrate.Guards`, which writes the files themselves -- and they used
    to spell both strings separately in three places. A rename that missed
    one would arm a hook against a file nothing ever writes: fail-closed, so
    every guarded Read and Write in the fan-out would be denied."""

    def test_the_names_are_owned_by_base_and_read_by_attribute(self):
        import tempfile
        from unittest import mock
        import scripts.orchestrate as orchestrate
        import scripts.runners.claude as claude_runner
        self.assertEqual(base.ALLOWLIST_FILE, "write-allowlist.json")
        self.assertEqual(base.SCOPE_FILE, "read-scope.json")
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.object(base, "ALLOWLIST_FILE", "renamed-allowlist.json"), \
             mock.patch.object(base, "SCOPE_FILE", "renamed-scope.json"):
            runner = claude_runner.Runner("claude")
            runner.prepare(d, review_root=d)
            guards = orchestrate.Guards("headless", run_dir=d)
            for path in (runner.allowlist_path, guards.allowlist_path):
                self.assertEqual(path, os.path.join(d, "renamed-allowlist.json"))
            for path in (runner.scope_path, guards.scope_path):
                self.assertEqual(path, os.path.join(d, "renamed-scope.json"))


class TestLaunchEnv(unittest.TestCase):
    """#1626 I2: ONE env preparation per runner, reachable by the probes.

    `Runner.run_entry` built its child environment inline, so
    `probes.common._cli_advertises` -- which launches the SAME binary to ask
    what it advertises -- had no way to use it and passed no `env` at all.
    The interrogation therefore ran under an environment the runner never
    uses. `launch_env` is that preparation named once; `run_entry` calls it,
    the usage probe calls it, and a family override changes both together.
    """

    def test_the_default_is_the_process_environment_plus_the_overlay(self):
        with mock.patch.dict(os.environ, {"PATH": "/p", "HOME": "/h"}, clear=True):
            self.assertEqual({"PATH": "/p", "HOME": "/h", "E": "1"},
                             base.HostRunner().launch_env({"E": "1"}))

    def test_no_overlay_is_just_the_process_environment(self):
        with mock.patch.dict(os.environ, {"PATH": "/p"}, clear=True):
            self.assertEqual({"PATH": "/p"}, base.HostRunner().launch_env())

    def test_it_is_a_copy_the_caller_may_mutate(self):
        # The probes and the loop both hand the result straight to a
        # subprocess call; returning os.environ itself would let one launch's
        # preparation leak into this process and into every later one.
        env = base.HostRunner().launch_env()
        env["PANOPTICON_ONLY_IN_THE_CHILD"] = "1"
        self.assertNotIn("PANOPTICON_ONLY_IN_THE_CHILD", os.environ)


class TestTheUsageProbesSeamAttributes(unittest.TestCase):
    """#1626 I3: `probes.claude._headless_usage_source` reads three attributes
    off a claiming host's runner -- `CLI`, `ENVELOPE_FLAGS` and `runner` --
    and `HostRunner` declared none of them. A family had to learn they exist
    from an `except Exception` whose detail then named the wrong thing.
    """

    def test_the_contract_declares_the_two_the_usage_probe_reads(self):
        self.assertEqual("", base.HostRunner.CLI)
        self.assertEqual((), base.HostRunner.ENVELOPE_FLAGS)

    def test_a_family_that_leaves_them_empty_inherits_the_empty_defaults(self):
        # The point of declaring them: a runner that says nothing about its
        # CLI reads `unknown` for usage_ledger with a detail saying exactly
        # that, instead of raising AttributeError into a detail about a
        # missing module.
        class Bare(base.HostRunner):
            host = "bare"
        self.assertEqual("", Bare().CLI)
        self.assertEqual((), Bare().ENVELOPE_FLAGS)
