import contextlib
import importlib
import io
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import scripts.runners.base as base
import scripts.runners.batch as batch_mod
import scripts.runners.schema as schema_rules
import scripts._version as version
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
        #
        # `base.py` is the seam itself, `batch.py` (#1662) the loop's
        # rollback manifest, `children.py` (#1575) the seam's own launcher and
        # child registry mixed into HostRunner, `outage.py` (#1623) its
        # host-outage verdict, `schema.py` (#1732) the output-schema argv
        # rules split out of `base.py`, `resume.py` (#1732) the resume command
        # split out of `outage.py`, and `kimi_home.py` the sandboxed
        # `$KIMI_CODE_HOME` the kimi family's children run under: none is a
        # family, none launches a HOST, and none has a Runner. A shared module
        # added to this package costs one line here, which is the visible
        # decision it should be -- the alternative, skipping any module that
        # happens to have no `Runner`, would silently excuse the family that
        # forgot one.
        pkg_dir = os.path.dirname(os.path.abspath(base.__file__))
        names = sorted(f[:-3] for f in os.listdir(pkg_dir)
                       if f.endswith(".py")
                       and f not in ("__init__.py", "base.py", "batch.py",
                                     "children.py", "outage.py", "resume.py",
                                     "schema.py", "kimi_home.py"))
        self.assertIn("claude", names)                  # the directory really was read
        for name in names:
            mod = importlib.import_module("scripts.runners.%s" % name)
            runner = getattr(mod, "Runner", None) or getattr(mod, "SessionRunner", None)
            self.assertIsNotNone(runner, name)
            self.assertNotIn("iter_batch", vars(runner), name)
            if name != "session":       # the one documented override: it launches nothing
                self.assertNotIn("run_batch", vars(runner), name)


class TestTheCooperativeStop(unittest.TestCase):
    """#1721: a host outage that begins mid-batch had to drain the WHOLE
    checkpoint before the loop could ask whether the host was down -- 78 review
    cells at one launch each, every one of them charged at dispatch. `stop` is
    the seam that lets the consumer say "no more": what is still QUEUED is
    cancelled, what is already IN FLIGHT is drained and yielded exactly as
    usual, and no child is terminated (that is the interrupt path -- an
    in-flight launch during an outage fails fast on its own)."""

    def _runner(self, seen):
        """A runner whose first two entries are fast, and whose entry `ei`
        (i >= 2) does not come back until the consumer has handled `i` results.

        That chain is what makes the launch bound a FACT rather than a race.
        Two workers answering instantly outrun a consumer that does real work
        per result, so a fixture that merely released everything at the moment
        `stop` fires leaves a window in which both workers pull another entry
        before the cancel lands. Here the pool is pinned to the consumer's own
        progress: at the moment `stop` returns true the consumer has handled 2,
        so `e2` may be free but `e3` (which waits for 3) cannot be, and at most
        one further entry can start. The chain always makes progress -- `ei`
        waits on results that arrive from entries launched before it -- so it
        cannot deadlock, and every wait is deadlined.
        """
        launched, terminated = [], []

        def await_consumer(n):
            deadline = time.monotonic() + 10
            while len(seen) < n:
                if time.monotonic() > deadline:
                    raise AssertionError("the consumer never handled %d results" % n)
                time.sleep(0.002)

        class Stopping(base.HostRunner):
            host = "fake"; mode = "headless"; default_concurrency = 2

            def run_entry(self, entry, env):
                launched.append(entry["id"])
                index = int(entry["id"][1:])
                if index >= 2:
                    await_consumer(index)
                return base.RunResult(entry_id=entry["id"], ok=True, text="", usage={},
                                      cost_usd=None, model=None, session_id=None,
                                      denials=[], error=None)

            def terminate_children(self, grace=None):
                terminated.append(grace)
                return []

        return Stopping(), launched, terminated

    def _drain(self, runner, seen, entries, **kw):
        with contextlib.closing(runner.iter_batch(entries, 2, lambda e: {}, **kw)) as stream:
            for entry, _result, _timing in stream:
                seen.append(entry["id"])

    def test_a_stop_that_says_yes_cancels_what_is_still_queued(self):
        seen, calls = [], []
        runner, launched, terminated = self._runner(seen)

        def stop():
            calls.append(len(seen))
            return len(seen) >= 2

        self._drain(runner, seen, [{"id": "e%d" % i} for i in range(8)], stop=stop)
        self.assertLess(len(launched), 8, launched)
        # 2 handled + the pool: `e2`/`e3` were already running and at most one
        # worker can turn over between the second result and the cancel
        self.assertLessEqual(len(launched), 5, launched)
        # every entry that really launched came back to the consumer -- the
        # in-flight ones included -- and nothing cancelled was yielded
        self.assertEqual(sorted(launched), sorted(seen))
        self.assertEqual([], terminated, "an outage is not the interrupt path")
        # asked once per yield at most, and never before the first result
        self.assertLessEqual(len(calls), len(seen))
        self.assertTrue(calls and calls[0] >= 1)

    def test_a_stop_that_raises_is_not_the_interrupt_path(self):
        # A consumer's predicate is not a Ctrl-C. Unwrapped it fell into the
        # `except BaseException` arm, which terminates this batch's children --
        # the one thing the stop path promises never to do -- and re-raised
        # into the loop. It means "carry on".
        seen = []
        runner, launched, terminated = self._runner(seen)

        def stop():
            raise RuntimeError("the tally blew up")

        self._drain(runner, seen, [{"id": "e%d" % i} for i in range(8)], stop=stop)
        self.assertEqual(8, len(launched), launched)
        self.assertEqual(sorted(seen), sorted(launched))
        self.assertEqual([], terminated, "a raising stop terminated the children")

    def test_no_stop_at_all_launches_the_whole_batch(self):
        seen = []
        runner, launched, terminated = self._runner(seen)
        self._drain(runner, seen, [{"id": "e%d" % i} for i in range(8)])
        self.assertEqual(8, len(launched), launched)
        self.assertEqual(sorted(seen), sorted(launched))
        self.assertEqual([], terminated)

    def test_a_stop_that_stays_false_launches_the_whole_batch(self):
        seen = []
        runner, launched, _terminated = self._runner(seen)
        self._drain(runner, seen, [{"id": "e%d" % i} for i in range(8)],
                    stop=lambda: False)
        self.assertEqual(8, len(launched), launched)
        self.assertEqual(sorted(seen), sorted(launched))


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
    """`_headless_module` must tell "no runner for this host" apart from "this
    host's runner is broken", so the test needs a module that fails to import.

    #1616 item 4: it used to write `brokenhost.py` into `skill/scripts/runners/`
    -- the LIVE source tree -- and rely on `addCleanup` to take it away again.
    A crash, a Ctrl-C or a `-x` exit between the two left a stray module in the
    shipped package, where `_seams()` in tests/test_host_launch_guard.py and
    `_package_files()` in tests/test_layout.py would both then find it.

    A temp directory APPENDED TO THE PACKAGE'S `__path__` instead. A package
    path is a list and the import system reads it per lookup, so
    `scripts.runners.brokenhost` resolves out of the temp directory while the
    real package keeps its own files; a plain `sys.path` entry could not do
    this, because `scripts.runners` is already imported and its submodule
    search never consults `sys.path` again. Nothing is written inside the
    repository at any point, so there is nothing a crash can leave behind:
    `mkdtemp` is the only place this test writes, `__pycache__` included.
    """

    def _temp_package_dir(self, name, source):
        """`name` importable from `scripts.runners`, out of a temp directory."""
        import scripts.runners as runners_pkg
        root = tempfile.mkdtemp(prefix="panopticon-runners-")
        self.addCleanup(shutil.rmtree, root, True)
        with open(os.path.join(root, name + ".py"), "w", encoding="utf-8") as fh:
            fh.write(source)
        runners_pkg.__path__.append(root)
        self.addCleanup(lambda: runners_pkg.__path__.remove(root))
        self.addCleanup(sys.modules.pop, "scripts.runners." + name, None)
        # The finder for a directory is cached by path, and this one was
        # created after the last cache build.
        importlib.invalidate_caches()
        return root

    def test_a_broken_runner_module_raises_instead_of_reading_as_absent(self):
        pkg_dir = os.path.dirname(os.path.abspath(base.__file__))
        self.addCleanup(sys.modules.pop, "scripts.runners.does_not_exist_xyz", None)
        self._temp_package_dir("brokenhost",
                               "import scripts.runners.does_not_exist_xyz\n")
        self.assertFalse(os.path.exists(os.path.join(pkg_dir, "brokenhost.py")),
                         "the live runners package holds a test's fixture module")

        with self.assertRaises(ModuleNotFoundError) as cm:
            base.runner_for("brokenhost", "headless")
        self.assertEqual(cm.exception.name, "scripts.runners.does_not_exist_xyz")

        with self.assertRaises(ModuleNotFoundError):
            base.headless_available("brokenhost")

    def test_the_temp_package_is_really_what_the_import_resolves(self):
        # Otherwise the test above could pass on a module that was never
        # found at all -- both halves of it expect an exception.
        root = self._temp_package_dir("workinghost", "class Runner:\n    pass\n")
        self.assertTrue(base.headless_available("workinghost"))
        mod = importlib.import_module("scripts.runners.workinghost")
        self.assertEqual(os.path.dirname(os.path.abspath(mod.__file__)), root)


class TestGuardFileNameConstants(unittest.TestCase):
    """M5 (final review): the allowlist/scope file NAMES have ONE owner here,
    read by module attribute everywhere else. Two readers have to agree on
    them byte-for-byte -- `runners/claude.py`'s `prepare`, which resolves the
    paths the launch is built around, and `orchestrate.Guards`, which writes
    those files and bakes their absolute paths into the hook commands -- and
    they used to spell both strings separately in three places. A rename that
    missed one would arm a hook against a file nothing ever writes:
    fail-closed, so every guarded Read and Write in the fan-out would be
    denied.

    Two READERS, not two writers, since #1616 item 5: `prepare` no longer
    writes host-settings.json at all (`arm` did it again immediately after),
    which is why this test asserts the resolved PATHS on both sides rather
    than the file either of them produced."""

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


def _published():
    """One of the schemas panopticon publishes under skill/reference/."""
    return os.path.abspath(version.reference_path("advisor-verdict-schema.json"))


class TestTheOutputSchemaSeam(unittest.TestCase):
    """D10 ruling 3: ONE optional class attribute (docs/FAMILY-PR-GUARDRAILS.md
    section 3). A family whose CLI takes a constrained-output schema names its
    flag; a family that leaves it empty is unaffected."""

    def test_the_contract_declares_it_empty(self):
        self.assertEqual((), base.HostRunner.OUTPUT_SCHEMA_FLAG)

        class Bare(base.HostRunner):
            host = "bare"
        self.assertEqual((), Bare().OUTPUT_SCHEMA_FLAG)
        self.assertEqual([], schema_rules.schema_argv(Bare().OUTPUT_SCHEMA_FLAG,
                                              {"output_schema": _published()}))

    def test_a_declared_flag_takes_the_entrys_published_schema(self):
        self.assertEqual(["--x", _published()],
                         schema_rules.schema_argv(("--x",), {"output_schema": _published()}))

    def test_an_entry_naming_no_schema_gets_no_flag(self):
        for entry in ({}, {"output_schema": None}, {"output_schema": ""}, None):
            with self.subTest(entry=entry):
                self.assertEqual([], schema_rules.schema_argv(("--x",), entry))

    def test_a_path_outside_the_published_reference_dir_is_refused(self):
        # The entry travels through `.panopticon/dispatch-request.json`, inside
        # the reviewed tree. Nothing else on the argv is a path the target
        # could have named, and this one must not become the exception: only
        # the schemas panopticon publishes are ever passed to a host CLI.
        for path in ("/etc/passwd", os.path.join(os.path.dirname(_published()), "nope.json"),
                     os.path.join(os.path.dirname(_published()), os.pardir, "SKILL.md")):
            with self.subTest(path=path):
                self.assertEqual([], schema_rules.schema_argv(("--x",), {"output_schema": path}))

    def test_inline_hands_the_cli_the_schema_text_not_its_path(self):
        # MEASURED 2026-09-20 on claude 2.1.276: `--json-schema <schema>` takes
        # the JSON itself ("--json-schema is not valid JSON: JSON Parse error:
        # Unrecognized token '/'" on a path), while codex's `--output-schema
        # <FILE>` takes a path. Run 14 burned 3 x 103 tool-verify launches on
        # the path form before the driver gave up.
        argv = schema_rules.schema_argv(("--x",), {"output_schema": _published()}, inline=True)
        self.assertEqual("--x", argv[0])
        self.assertEqual(2, len(argv))
        self.assertNotEqual(_published(), argv[1])
        with open(_published(), encoding="utf-8") as fh:
            self.assertEqual(json.load(fh), json.loads(argv[1]))
        self.assertNotIn("\n", argv[1])

    def test_inline_still_refuses_an_unpublished_path(self):
        self.assertEqual([], schema_rules.schema_argv(("--x",), {"output_schema": "/etc/passwd"},
                                              inline=True))

    def test_inline_schema_applies_the_containment_rule_itself(self):
        # Not only via schema_argv: a helper that opened whatever it was handed
        # would turn the one target-chosen argv value into an arbitrary-file
        # read that reaches the CLI (review round 1, item 1).
        self.assertIsNone(schema_rules.inline_schema("/etc/passwd"))
        self.assertIsNone(schema_rules.inline_schema(None))
        self.assertIsNotNone(schema_rules.inline_schema(_published()))

    def test_inline_refuses_a_published_file_too_large_for_one_argv_token(self):
        # skill/reference/ also publishes ocrdb-0.5.0.json (176 KB compacted),
        # over Linux MAX_ARG_STRLEN: execve would answer E2BIG and the runner
        # would burn three launches per entry -- the run-14 failure mode by a
        # second road (review round 1, item 2).
        self.assertLess(0, schema_rules.INLINE_SCHEMA_MAX)
        tmp = tempfile.mkdtemp()
        try:
            big = os.path.join(tmp, "big-schema.json")
            with open(big, "w", encoding="utf-8") as fh:
                json.dump({"type": "object", "pad": "x" * (schema_rules.INLINE_SCHEMA_MAX + 1)}, fh)
            with mock.patch.object(schema_rules.version, "reference_path", return_value=tmp):
                self.assertIsNone(schema_rules.inline_schema(big))
                self.assertEqual([], schema_rules.schema_argv(("--x",), {"output_schema": big},
                                                      inline=True))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        published = os.path.join(os.path.dirname(_published()), "ocrdb-0.5.0.json")
        if os.path.isfile(published):
            self.assertIsNone(schema_rules.inline_schema(published))

    def test_inline_treats_an_unparsable_published_file_as_no_schema(self):
        # The persist layer validates the reply against the schema either way;
        # a launch without the flag is the fail-safe, a launch the CLI refuses
        # is three burned attempts per entry.
        tmp = tempfile.mkdtemp()
        try:
            bad = os.path.join(tmp, "broken-schema.json")
            with open(bad, "w", encoding="utf-8") as fh:
                fh.write("{not json")
            with mock.patch.object(schema_rules.version, "reference_path", return_value=tmp):
                self.assertEqual([], schema_rules.schema_argv(("--x",), {"output_schema": bad},
                                                      inline=True))
                # The path form is untouched: it hands over the (resolved)
                # file and lets the CLI be the one to choke on it.
                self.assertEqual(["--x", os.path.realpath(bad)],
                                 schema_rules.schema_argv(("--x",), {"output_schema": bad}))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestAFailedResultKeepsWhatTheLaunchProduced(unittest.TestCase):
    """D10 ruling 5: a timed-out entry is the most expensive kind of failure,
    and it used to be the one that kept nothing -- `usage={}` and the partial
    stdout discarded inside the `except`."""

    def test_failed_defaults_to_no_usage_and_no_text(self):
        res = base.RunResult.failed("e1", "boom")
        self.assertEqual(({}, "", False), (res.usage, res.text, res.ok))

    def test_failed_carries_the_usage_and_partial_output_it_is_given(self):
        res = base.RunResult.failed("e1", "timed out after 5s",
                                    usage={"input_tokens": 9}, text="partial")
        self.assertEqual({"input_tokens": 9}, res.usage)
        self.assertEqual("partial", res.text)
        self.assertFalse(res.ok)

    def test_partial_output_reads_a_killed_childs_stdout_however_it_arrives(self):
        # TimeoutExpired carries stdout UNDECODED even from a text-mode launch
        # (CPython translates newlines only after communicate() returns, and
        # the timeout raises before that), so bytes is the normal case.
        cases = {b"half a line": "half a line", "half a line": "half a line",
                 None: "", b"": "", b"\xff bad": "� bad"}
        for stdout, expected in cases.items():
            with self.subTest(stdout=stdout):
                exc = subprocess.TimeoutExpired(["x"], 1, output=stdout)
                self.assertEqual(expected, base.partial_output(exc))


class FakeChild:
    """A `subprocess.Popen`-shaped handle for `terminate_children` (#1662):
    `terminate` then, for one that will not die, `kill`. No real process: the
    suite never launches a host binary, and this path is about what the runner
    SENDS, not about what a child does with it."""

    def __init__(self, stubborn=False):
        self.stubborn = stubborn
        self.sent = []

    def terminate(self):
        self.sent.append("TERM")

    def kill(self):
        self.sent.append("KILL")

    def wait(self, timeout=None):
        if self.stubborn:
            raise subprocess.TimeoutExpired(["child"], timeout or 0)
        return 0


class TestAnInterruptStopsTheBatch(unittest.TestCase):
    """#1662: Ctrl-C means complete stoppage. `shutdown(wait=True)` queued its
    stop sentinel BEHIND every work item, so every entry the batch had queued
    -- running or not yet started -- was still launched and allowed to finish,
    none of them persisted, and the interrupt did not return until the last
    child exited. On a wide batch of slow entries that is minutes of work paid
    for and thrown away."""

    def _stoppable(self, terminate_releases=True):
        """A runner whose entries (bar the first) block until the interrupt
        path terminates them -- which is what a SIGTERM does to a real child:
        the worker holding it stops blocking and returns."""
        released, started, terminated = threading.Event(), [], []

        class Stoppable(base.HostRunner):
            host = "fake"; mode = "headless"; default_concurrency = 2
            INTERRUPT_GRACE = 0.25

            def run_entry(self, entry, env):
                started.append(entry["id"])
                if entry["id"] != "e0":
                    released.wait(10)
                return base.RunResult(entry_id=entry["id"], ok=True, text="", usage={},
                                      cost_usd=None, model=None, session_id=None,
                                      denials=[], error=None)

            def terminate_children(self, grace=None):
                terminated.append(grace)
                if terminate_releases:
                    released.set()

        self.addCleanup(released.set)
        return Stoppable(), started, terminated

    def _interrupt_after_the_first_completion(self, runner, entries, width=2):
        stream = runner.iter_batch(entries, width, lambda e: {})
        began = time.monotonic()
        with self.assertRaises(KeyboardInterrupt):
            with contextlib.closing(stream):
                for _entry, _result, _timing in stream:
                    raise KeyboardInterrupt          # the operator's Ctrl-C
        return time.monotonic() - began

    def test_the_entries_still_queued_are_never_launched(self):
        # Six entries, concurrency two, interrupted after the first
        # completion. A worker that finishes an entry takes the next queued
        # item straight away and nothing the consumer does can beat it, so up
        # to `width` entries can still launch after the interrupt -- here only
        # `e0` completes, so exactly one slot turns over and `e1` plus at most
        # `e2` run. e3..e5 were queued and must never launch; the test above
        # pins the general bound. On the base every one of the six ran.
        r, started, _terminated = self._stoppable()
        entries = [{"id": "e%d" % i} for i in range(6)]
        self._interrupt_after_the_first_completion(r, entries)
        self.assertIn("e0", started)
        self.assertEqual([], [x for x in ("e3", "e4", "e5") if x in started],
                         "queued entries launched after the interrupt: %r" % started)
        self.assertLessEqual(len(started), 3, started)

    def test_the_launches_after_the_interrupt_are_bounded_by_the_pool_width(self):
        # "One worker slot turns over" is only true when ONE entry completes.
        # Every worker that finishes an entry pulls the next queued item
        # before the consumer's interrupt can reach the generator, so the real
        # bound is the POOL, not a single slot: with four fast entries at
        # width four, four workers each start one more -- eight launches out
        # of twenty, and never a ninth. The test above is what pins the
        # cancellation itself; this one pins how much can still get out, which
        # is the number the seam's docstring now quotes. On the base, whose
        # `shutdown(wait=True)` queued its sentinel behind every work item, all
        # twenty ran.
        released, started = threading.Event(), []
        self.addCleanup(released.set)

        class Wide(base.HostRunner):
            host = "fake"; INTERRUPT_GRACE = 0.25

            def run_entry(self, entry, env):
                started.append(entry["id"])
                if int(entry["id"][1:]) >= 4:          # only the first four are fast
                    released.wait(10)
                return base.RunResult(entry_id=entry["id"], ok=True, text="", usage={},
                                      cost_usd=None, model=None, session_id=None,
                                      denials=[], error=None)

        self._interrupt_after_the_first_completion(
            Wide(), [{"id": "e%d" % i} for i in range(20)], width=4)
        self.assertLessEqual(len(started), 8, started)     # 2 x width, exactly
        self.assertEqual([], [x for x in started if int(x[1:]) >= 8], started)

    def test_the_in_flight_entry_is_terminated_rather_than_awaited(self):
        r, _started, terminated = self._stoppable()
        self._interrupt_after_the_first_completion(
            r, [{"id": "e%d" % i} for i in range(6)])
        self.assertEqual(1, len(terminated), "terminate_children was not called once")

    def test_a_child_that_ignores_the_terminate_is_not_waited_out(self):
        # The grace is a BOUND, not a promise: a runner whose terminate does
        # not end the child still returns from the interrupt, instead of
        # blocking for the entry's full 10s.
        r, _started, terminated = self._stoppable(terminate_releases=False)
        elapsed = self._interrupt_after_the_first_completion(
            r, [{"id": "e%d" % i} for i in range(6)])
        self.assertEqual(1, len(terminated))
        self.assertLess(elapsed, 5, "the interrupt waited the blocked entry out")

    def test_a_terminate_that_raises_does_not_replace_the_interrupt(self):
        # A family's teardown must never become the exception the operator
        # sees instead of their own Ctrl-C.
        released = threading.Event()
        self.addCleanup(released.set)

        class Angry(base.HostRunner):
            host = "angry"; INTERRUPT_GRACE = 0.05

            def run_entry(self, entry, env):
                if entry["id"] != "e0":
                    released.wait(10)
                return base.RunResult(entry_id=entry["id"], ok=True, text="", usage={},
                                      cost_usd=None, model=None, session_id=None,
                                      denials=[], error=None)

            def terminate_children(self, grace=None):
                raise RuntimeError("teardown exploded")

        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self._interrupt_after_the_first_completion(
                Angry(), [{"id": "e%d" % i} for i in range(4)])
        self.assertIn("teardown exploded", err.getvalue())
        self.assertIn("angry", err.getvalue())

    def test_terminate_children_sends_sigterm_then_sigkill(self):
        r = base.HostRunner()
        quick, stubborn = FakeChild(), FakeChild(stubborn=True)
        r.register_child(quick)
        r.register_child(stubborn)
        self.assertEqual([quick, stubborn], r.terminate_children(grace=0))
        self.assertEqual(["TERM"], quick.sent)
        self.assertEqual(["TERM", "KILL"], stubborn.sent)
        # ...and the registry is emptied, so a second call is a no-op rather
        # than a second SIGKILL at a pid the OS has since reused.
        self.assertEqual([], r.terminate_children(grace=0))

    def test_a_runner_that_registered_nothing_terminates_nothing(self):
        self.assertEqual([], base.HostRunner().terminate_children(grace=0))

    def test_the_interrupt_path_installs_no_signal_handler(self):
        # The rollback must CALL THROUGH a family's handler, never replace it:
        # runners/kimi.py chains a SIGTERM secret-stripper onto whatever was
        # there, and an interrupt path that installed its own would unlink it.
        before = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
        r, _started, _terminated = self._stoppable()
        self._interrupt_after_the_first_completion(
            r, [{"id": "e%d" % i} for i in range(4)])
        self.assertEqual(before, {s: signal.getsignal(s)
                                  for s in (signal.SIGINT, signal.SIGTERM)})


class TestTheBatchManifest(unittest.TestCase):
    """#1662: the list a Ctrl-C rolls back, written before the batch's first
    launch. Its own module (`runners/batch.py`) but not its own test file:
    when this was written the host leaf of the review matrix was one file
    short of its cap, and a file past the cap chunks the leaf into a name the
    matrix has no entry for (the #1638 P13 defect). #1718 has since split the
    runner seam into its own `Orchestration:Runners` layer, so a
    `test_batch.py` would fit today; this class stays here by inertia only."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)

    def _artifact(self, name, body="{}"):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
        return path

    def _batch(self, *names):
        entries = [{"id": n, "out_file": self._artifact(n + ".json")} for n in names]
        return batch_mod.Batch(self.dir, 3, "review", entries).open(), entries

    def test_the_manifest_lists_the_entry_ids_and_the_files_they_will_write(self):
        batch, entries = self._batch("review-app-SEC", "review-app-ACC")
        self.assertEqual(batch.path,
                         os.path.join(self.dir, "batch-3.json"))
        with open(batch.path, encoding="utf-8") as fh:
            doc = json.load(fh)
        self.assertEqual(1, doc["schema_version"])
        self.assertEqual((3, "review"), (doc["batch"], doc["checkpoint"]))
        self.assertRegex(doc["opened_at"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        self.assertEqual(["review-app-SEC", "review-app-ACC"],
                         [row["id"] for row in doc["entries"]])
        self.assertEqual([[e["out_file"]] for e in entries],
                         [row["artifacts"] for row in doc["entries"]])

    def test_roll_back_deletes_what_it_lists_and_nothing_else(self):
        # The "never a glob" rule: a prior phase's output sits in the same
        # folder, and on a redteam target so does whatever the tree planted
        # with a matching name.
        batch, entries = self._batch("review-app-SEC")
        bystander = self._artifact("coverage-app.json")
        removed, problems = batch.roll_back()
        self.assertEqual(([entries[0]["out_file"]], []), (removed, problems))
        self.assertFalse(os.path.exists(entries[0]["out_file"]))
        self.assertTrue(os.path.isfile(bystander))
        self.assertFalse(os.path.exists(batch.path), "the manifest goes with it")

    def test_an_artifact_that_was_never_written_is_not_a_problem(self):
        # Most of a cancelled batch never got that far.
        batch, entries = self._batch("review-app-SEC")
        os.remove(entries[0]["out_file"])
        self.assertEqual(([], []), batch.roll_back())

    def test_a_record_the_batch_wrote_later_is_rolled_back_too(self):
        # `persist.retain_rejected` names the file only once it has written
        # it, so the manifest gains it mid-batch rather than at open.
        batch, entries = self._batch("review-app-SEC")
        kept = self._artifact("rejected-review-app-SEC-1.json")
        batch.add_artifact("review-app-SEC", kept)
        batch.add_artifact("review-app-SEC", kept)          # idempotent
        with open(batch.path, encoding="utf-8") as fh:
            self.assertEqual([entries[0]["out_file"], kept],
                             json.load(fh)["entries"][0]["artifacts"])
        removed, _problems = batch.roll_back()
        self.assertEqual({entries[0]["out_file"], kept}, set(removed))

    def test_a_record_for_an_entry_not_in_the_batch_is_ignored(self):
        batch, _entries = self._batch("review-app-SEC")
        batch.add_artifact("review-app-ACC", self._artifact("stray.json"))
        batch.add_artifact("review-app-SEC", None)
        self.assertEqual(1, len(batch.artifacts()))

    def test_an_artifact_planted_as_a_symlink_loses_the_link_not_the_target(self):
        batch, entries = self._batch("review-app-SEC")
        target = self._artifact("elsewhere.json", "precious")
        os.remove(entries[0]["out_file"])
        os.symlink(target, entries[0]["out_file"])
        batch.roll_back()
        self.assertFalse(os.path.lexists(entries[0]["out_file"]))
        self.assertTrue(os.path.isfile(target))

    def test_a_path_that_cannot_be_removed_is_reported_not_raised(self):
        # The loop is already on its way out with an interrupt to explain; a
        # rollback that could not finish is something the operator is TOLD,
        # not something that replaces the interrupt's own message.
        batch, entries = self._batch("review-app-SEC")
        os.remove(entries[0]["out_file"])
        os.makedirs(os.path.join(entries[0]["out_file"], "child"))
        removed, problems = batch.roll_back()
        self.assertEqual([], removed)
        self.assertEqual(1, len(problems))
        self.assertIn(entries[0]["out_file"], problems[0])

    def test_close_removes_the_manifest_and_a_second_close_is_quiet(self):
        batch, _entries = self._batch("review-app-SEC")
        self.assertEqual([], batch.close())
        self.assertFalse(os.path.exists(batch.path))
        self.assertEqual([], batch.close())

    def test_an_empty_batch_lists_nothing(self):
        batch = batch_mod.Batch(self.dir, 1, "scout", []).open()
        self.assertEqual(([], []), (batch.entry_ids(), batch.artifacts()))
        self.assertEqual(([], []), batch.roll_back())

    def test_registration_refuses_paths_outside_the_run_before_manifest_creation(self):
        sibling = self.dir + "-sibling"
        os.mkdir(sibling)
        self.addCleanup(shutil.rmtree, sibling, True)
        outside = os.path.join(sibling, "keep.json")
        with open(outside, "w", encoding="utf-8") as fh:
            fh.write("keep")
        paths = (outside, os.path.join(self.dir, "..", os.path.basename(sibling), "keep.json"))
        for path in paths:
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "escapes the run folder"):
                batch_mod.Batch(self.dir, 3, "review", [{"id": "e", "out_file": path}]).open()
            self.assertFalse(os.path.lexists(batch_mod.manifest_path(self.dir, 3)))
        with open(outside, encoding="utf-8") as fh:
            self.assertEqual("keep", fh.read())

    def test_registration_refuses_a_linked_parent_even_when_it_points_inside(self):
        real = os.path.join(self.dir, "real")
        os.mkdir(real)
        link = os.path.join(self.dir, "linked")
        os.symlink(real, link)
        for destination in (real, self.dir + "-outside"):
            with self.subTest(destination=destination):
                os.unlink(link)
                os.symlink(destination, link)
                with self.assertRaisesRegex(ValueError, "symlink"):
                    batch_mod.Batch(self.dir, 3, "review", [
                        {"id": "e", "out_file": os.path.join(link, "keep.json")}]).open()
                self.assertFalse(os.path.lexists(batch_mod.manifest_path(self.dir, 3)))

    def test_add_artifact_refuses_outside_and_linked_parent_without_changing_record(self):
        batch, _entries = self._batch("review-app-SEC")
        with open(batch.path, "rb") as fh:
            before = fh.read()
        outside = os.path.join(os.path.dirname(self.dir), "outside.json")
        link = os.path.join(self.dir, "linked")
        os.symlink(self.dir, link)
        for path in (outside, os.path.join(link, "keep.json"), None):
            if path is None:
                with self.assertRaises(ValueError):
                    batch.add_artifact("review-app-SEC", 42)
            else:
                with self.assertRaises(ValueError):
                    batch.add_artifact("review-app-SEC", path)
            with open(batch.path, "rb") as fh:
                self.assertEqual(before, fh.read())
            self.assertEqual(1, len(batch.artifacts()))

    def test_rollback_validates_all_artifacts_before_deleting_any(self):
        batch, entries = self._batch("review-app-SEC")
        outside = os.path.join(os.path.dirname(self.dir), "keep-outside.json")
        with open(outside, "w", encoding="utf-8") as fh:
            fh.write("keep")
        self.addCleanup(lambda: os.path.exists(outside) and os.remove(outside))
        batch.entries[0]["artifacts"].append(outside)
        removed, problems = batch.roll_back()
        self.assertEqual([], removed)
        self.assertTrue(problems)
        self.assertIn("unsafe batch artifact", problems[0])
        self.assertTrue(os.path.isfile(entries[0]["out_file"]))
        self.assertTrue(os.path.isfile(batch.path))
        with open(outside, encoding="utf-8") as fh:
            self.assertEqual("keep", fh.read())

    def test_rollback_refuses_a_parent_replaced_with_a_link(self):
        parent = os.path.join(self.dir, "owned")
        other = os.path.join(self.dir, "other")
        os.mkdir(parent)
        os.mkdir(other)
        owned = os.path.join(parent, "keep.json")
        with open(owned, "w", encoding="utf-8") as fh:
            fh.write("original")
        batch = batch_mod.Batch(self.dir, 3, "review", [{"id": "e", "out_file": owned}]).open()
        os.rename(parent, parent + "-moved")
        with open(os.path.join(other, "keep.json"), "w", encoding="utf-8") as fh:
            fh.write("keep")
        os.symlink(other, parent)
        removed, problems = batch.roll_back()
        self.assertEqual([], removed)
        self.assertTrue(problems)
        self.assertTrue(os.path.isfile(batch.path))
        with open(os.path.join(other, "keep.json"), encoding="utf-8") as fh:
            self.assertEqual("keep", fh.read())

    def test_rollback_refuses_a_parent_replaced_with_another_directory(self):
        parent = os.path.join(self.dir, "owned")
        os.mkdir(parent)
        owned = os.path.join(parent, "keep.json")
        with open(owned, "w", encoding="utf-8") as fh:
            fh.write("original")
        batch = batch_mod.Batch(self.dir, 3, "review", [{"id": "e", "out_file": owned}]).open()
        os.rename(parent, parent + "-moved")
        os.mkdir(parent)
        with open(owned, "w", encoding="utf-8") as fh:
            fh.write("keep")
        removed, problems = batch.roll_back()
        self.assertEqual([], removed)
        self.assertTrue(problems)
        self.assertTrue(os.path.isfile(batch.path))
        with open(owned, encoding="utf-8") as fh:
            self.assertEqual("keep", fh.read())

    def test_rollback_refuses_malformed_recovered_artifacts(self):
        for bad in (42, "bad\0path", {"path": "bad"}):
            with self.subTest(bad=bad):
                batch, entries = self._batch("review-app-SEC")
                batch.entries[0]["artifacts"].append(bad)
                removed, problems = batch.roll_back()
                self.assertEqual([], removed)
                self.assertTrue(problems)
                self.assertTrue(os.path.isfile(entries[0]["out_file"]))
                self.assertTrue(os.path.isfile(batch.path))
                batch.entries[0]["artifacts"].pop()
                self.assertEqual([], batch.close())

    def test_system_alias_above_the_run_folder_is_accepted(self):
        if not os.path.islink("/tmp") or not self.dir.startswith("/private/tmp/"):
            self.skipTest("no /tmp to /private/tmp alias")
        aliased = os.path.join("/tmp", os.path.relpath(self.dir, "/private/tmp"))
        batch = batch_mod.Batch(aliased, 3, "review", [
            {"id": "e", "out_file": os.path.join(aliased, "owned.json")}]).open()
        with open(os.path.join(self.dir, "owned.json"), "w", encoding="utf-8") as fh:
            fh.write("owned")
        removed, problems = batch.roll_back()
        self.assertEqual(([os.path.join(aliased, "owned.json")], []), (removed, problems))
        self.assertFalse(os.path.lexists(os.path.join(self.dir, "owned.json")))

    def test_replaced_run_directory_refuses_close_and_manifest_rewrite(self):
        batch, _entries = self._batch("review-app-SEC")
        moved = self.dir + "-moved"
        self.addCleanup(shutil.rmtree, moved, True)
        os.rename(self.dir, moved)
        os.mkdir(self.dir)
        planted = batch_mod.manifest_path(self.dir, 3)
        with open(planted, "w", encoding="utf-8") as fh:
            fh.write("keep")
        self.assertTrue(batch.close())
        with self.assertRaises(ValueError):
            batch.begin_recovery()
        with open(planted, encoding="utf-8") as fh:
            self.assertEqual("keep", fh.read())
        self.assertTrue(os.path.isfile(batch_mod.manifest_path(moved, 3)))



class TestTheRegisteredAgentAllowlist(unittest.TestCase):
    """#1720: `entry["agent"]` arrives through
    `.panopticon/dispatch-request.json`, a file inside the REVIEWED TREE, and
    every family puts it on a launch's argv (kimi joins it into a filesystem
    path). The allowlist is the same containment idea `schema.published_schema`
    applies to the one other entry-derived argv value -- and it is DERIVED
    from `dispatch.ROLE_FILES`, so a role added or renamed there cannot leave
    a second, stale spelling here.
    """

    def test_the_allowlist_is_exactly_the_four_dispatch_role_shells(self):
        import scripts.dispatch as dispatch
        self.assertEqual(
            base.REGISTERED_AGENT_NAMES,
            frozenset(dispatch.registered_agent_name(role_file)
                      for role_file in dispatch.ROLE_FILES.values()))
        self.assertIn("panopticon-scout", base.REGISTERED_AGENT_NAMES)

    def test_registered_agent_answers_the_name_or_none(self):
        self.assertEqual("panopticon-scout",
                         base.registered_agent({"agent": "panopticon-scout"}))
        for value in ("panopticon-scout-evil", "../../tmp/evil", "/tmp/x", "", None, 7):
            self.assertIsNone(base.registered_agent({"agent": value}), value)
        self.assertIsNone(base.registered_agent({}))
        self.assertIsNone(base.registered_agent(None))

    def test_an_unhashable_agent_is_answered_none_and_never_raises(self):
        # Fix round 1, item 1. The request is JSON from inside the reviewed
        # tree, so `agent` can perfectly well be an array or an object --
        # and `value in <frozenset>` on one raises `TypeError: unhashable
        # type`, straight out of `run_entry`, which never raises (spec 4.4).
        # A type check that only a str reaches, before the membership test.
        for value in ([], {}, {"a": {"b": "panopticon-scout"}},
                      ["panopticon-scout"], set()):
            self.assertIsNone(base.registered_agent({"agent": value}), repr(value))

    def test_the_refusal_names_the_value_and_never_downgrades(self):
        result = base.refuse_unregistered_agent({"id": "review-app-SEC",
                                                 "agent": "../../tmp/evil"})
        self.assertFalse(result.ok)
        self.assertEqual("review-app-SEC", result.entry_id)
        self.assertIn("not a registered panopticon shell", result.error)
        self.assertIn(repr("../../tmp/evil"), result.error)

    def test_the_refusal_neutralises_a_value_that_is_trying_to_write_the_log(self):
        # Fix round 1, item 6: the value is the TARGET's, and it lands in the
        # operator's stderr and in the ledger row. `%r` renders a control
        # character, an ANSI escape or a newline as its escape sequence, so a
        # value cannot forge a second log line or repaint the terminal.
        result = base.refuse_unregistered_agent(
            {"id": "e", "agent": "panopticon-scout\x1b[2J\ndriver loop: all good"})
        self.assertNotIn("\x1b", result.error)
        self.assertNotIn("\n", result.error)
        self.assertIn("\\x1b", result.error)

    def test_the_refusal_still_truncates_and_redacts(self):
        long_value = "a" * 500
        result = base.refuse_unregistered_agent({"id": "e", "agent": long_value})
        self.assertIn(repr("a" * 200), result.error)
        self.assertNotIn("a" * 201, result.error)


class TestTheAgentIsBoundToItsCheckpointsRole(unittest.TestCase):
    """#1727: the allowlist alone lets any of the four shells stand in for any
    other -- a `verify` entry naming `panopticon-domain-panel` is a registered
    shell, so it launched, under a WRITE-granting charter the verify round
    never dispatches. The loop hands the runner the roles its checkpoint
    dispatches, and the same check narrows to them."""

    def test_roles_none_is_the_whole_allowlist(self):
        self.assertEqual("panopticon-scout",
                         base.registered_agent({"agent": "panopticon-scout"}, roles=None))
        self.assertEqual("panopticon-domain-panel",
                         base.registered_agent({"agent": "panopticon-domain-panel"}))

    def test_roles_narrows_to_exactly_those_shells(self):
        entry = {"agent": "panopticon-advisor"}
        self.assertEqual("panopticon-advisor",
                         base.registered_agent(entry, roles=("advisor",)))
        self.assertEqual("panopticon-advisor",
                         base.registered_agent(entry, roles=("advisor", "domain_advisor")))
        for roles in (("scout",), ("domain_panel",), ("domain_advisor",)):
            self.assertIsNone(base.registered_agent(entry, roles=roles), roles)

    def test_an_empty_role_tuple_accepts_nothing(self):
        # The `scan` checkpoint: its one entry is dispatched shell-less by
        # design, so NO name is right for it -- and an empty tuple must not
        # read as "unconstrained".
        for name in ("panopticon-scout", "panopticon-advisor",
                     "panopticon-domain-panel", "panopticon-domain-advisor"):
            self.assertIsNone(base.registered_agent({"agent": name}, roles=()), name)

    def test_an_unknown_role_key_narrows_rather_than_widens(self):
        self.assertIsNone(base.registered_agent({"agent": "panopticon-scout"},
                                                roles=("not_a_role",)))

    def test_the_refusal_names_the_shells_this_checkpoint_allows(self):
        result = base.refuse_unregistered_agent(
            {"id": "verify-app-SEC-primary", "agent": "panopticon-domain-panel"},
            roles=("advisor", "domain_advisor"))
        self.assertFalse(result.ok)
        self.assertEqual("verify-app-SEC-primary", result.entry_id)
        self.assertIn("not a registered panopticon shell for this checkpoint",
                      result.error)
        self.assertIn("allowed: panopticon-advisor, panopticon-domain-advisor",
                      result.error)
        self.assertIn(repr("panopticon-domain-panel"), result.error)

    def test_the_refusal_without_roles_is_word_for_word_what_it_was(self):
        for kwargs in ({}, {"roles": None}):
            result = base.refuse_unregistered_agent({"id": "e", "agent": "x"}, **kwargs)
            self.assertEqual(base.UNREGISTERED_AGENT % "x", result.error)

    def test_the_refusal_still_neutralises_a_hostile_value_with_roles_given(self):
        result = base.refuse_unregistered_agent(
            {"id": "e", "agent": "panopticon-scout\x1b[2J\ndriver loop: all good"},
            roles=("advisor",))
        self.assertNotIn("\x1b", result.error)
        self.assertNotIn("\n", result.error)

    def test_a_runner_carries_no_roles_until_the_loop_says_so(self):
        self.assertIsNone(base.HostRunner("claude").roles)


class TestTheOneConcurrencyCeiling(unittest.TestCase):
    """#1576 (OPS-2112448973): the headless runner accepted unbounded process
    concurrency. `--concurrency` is a `_positive_int` with no upper bound, and
    `default_concurrency` is whatever a family declares, so `driver loop
    --concurrency 500` opened a 500-wide pool of host CLIs -- each one a real
    process tree, each one charged.

    ONE ceiling, applied in ONE place: `batch_width`. The flag keeps accepting
    any positive int (a clamp in the parser AND here would be two ceilings
    that can disagree), and every caller that needs the number -- `iter_batch`
    for its pool, `orchestrate.loop` for its outage tally -- asks this method
    rather than re-deriving the expression.
    """

    def test_the_ceiling_is_the_largest_shipped_family_default(self):
        # A flat number, not a cpu count: these children are network-bound
        # CLIs, and a 2-core CI runner running 8 of them is the shape the
        # suite already assumes.
        self.assertEqual(8, base.MAX_CONCURRENCY)

    def test_every_shipped_family_fits_under_it(self):
        pkg_dir = os.path.dirname(os.path.abspath(base.__file__))
        names = sorted(f[:-3] for f in os.listdir(pkg_dir)
                       if f.endswith(".py")
                       and f not in ("__init__.py", "base.py", "batch.py",
                                     "children.py", "outage.py", "resume.py",
                                     "schema.py", "kimi_home.py"))
        for name in names:
            mod = importlib.import_module("scripts.runners.%s" % name)
            runner = getattr(mod, "Runner", None) or getattr(mod, "SessionRunner")
            with self.subTest(family=name):
                self.assertLessEqual(
                    runner.default_concurrency, base.MAX_CONCURRENCY,
                    "%s ships a default above the ceiling, so its ordinary run "
                    "would print a clamp warning on every batch" % name)

    def test_an_absent_or_zero_request_falls_back_to_the_family_default(self):
        runner = FakeRunner()                       # default_concurrency = 3
        for asked in (None, 0):
            with self.subTest(asked=asked):
                self.assertEqual(3, runner.batch_width(asked))

    def test_a_request_under_the_ceiling_is_what_was_asked_for(self):
        self.assertEqual(2, FakeRunner().batch_width(2))

    def test_a_request_over_the_ceiling_is_clamped_and_says_so_once(self):
        runner, err = FakeRunner(), io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(base.MAX_CONCURRENCY, runner.batch_width(500))
            self.assertEqual(base.MAX_CONCURRENCY, runner.batch_width(500))
        # ONE line, not one per caller: `iter_batch` and `orchestrate.loop`
        # both ask for the same width on every batch.
        self.assertEqual(["concurrency 500 clamped to the ceiling 8"],
                         err.getvalue().splitlines())

    def test_a_clamp_at_a_different_width_is_still_reported(self):
        runner, err = FakeRunner(), io.StringIO()
        with contextlib.redirect_stderr(err):
            runner.batch_width(500)
            runner.batch_width(64)
        self.assertEqual(2, len(err.getvalue().splitlines()))

    def test_a_width_under_the_ceiling_prints_nothing(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            FakeRunner().batch_width(base.MAX_CONCURRENCY)
        self.assertEqual("", err.getvalue())

    def test_a_negative_request_is_still_a_pool_of_one(self):
        # `max(1, ...)` was already there and stays: a ThreadPoolExecutor
        # refuses max_workers <= 0, so a bad number must degrade, not crash.
        self.assertEqual(1, FakeRunner().batch_width(-5))

    def test_the_pool_itself_is_bounded_by_the_ceiling(self):
        # The guarantee, not the arithmetic: `iter_batch` asks for 500 and
        # never has more than the ceiling in flight.
        runner, peak, live, lock = FakeRunner(), [0], [0], threading.Lock()

        def one(entry, env):
            with lock:
                live[0] += 1
                peak[0] = max(peak[0], live[0])
            time.sleep(0.02)
            with lock:
                live[0] -= 1
            return base.RunResult(entry_id=entry["id"], ok=True, text="", usage={},
                                  cost_usd=None, model=None, session_id=None,
                                  denials=[], error=None)

        entries = [{"id": "e%d" % i} for i in range(40)]
        err = io.StringIO()
        with contextlib.redirect_stderr(err), mock.patch.object(runner, "run_entry", one):
            list(runner.iter_batch(entries, 500, lambda e: {}))
        self.assertLessEqual(peak[0], base.MAX_CONCURRENCY)
        self.assertGreater(peak[0], 1, "the pool never ran anything in parallel")
