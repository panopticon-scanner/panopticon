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
        # `base.py` is the seam itself and `batch.py` (#1662) the loop's
        # rollback manifest: neither is a family, neither launches anything,
        # and neither has a Runner. A shared module added to this package
        # costs one line here, which is the visible decision it should be --
        # the alternative, skipping any module that happens to have no
        # `Runner`, would silently excuse the family that forgot one.
        pkg_dir = os.path.dirname(os.path.abspath(base.__file__))
        names = sorted(f[:-3] for f in os.listdir(pkg_dir)
                       if f.endswith(".py")
                       and f not in ("__init__.py", "base.py", "batch.py"))
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
        self.assertEqual([], base.schema_argv(Bare().OUTPUT_SCHEMA_FLAG,
                                              {"output_schema": _published()}))

    def test_a_declared_flag_takes_the_entrys_published_schema(self):
        self.assertEqual(["--x", _published()],
                         base.schema_argv(("--x",), {"output_schema": _published()}))

    def test_an_entry_naming_no_schema_gets_no_flag(self):
        for entry in ({}, {"output_schema": None}, {"output_schema": ""}, None):
            with self.subTest(entry=entry):
                self.assertEqual([], base.schema_argv(("--x",), entry))

    def test_a_path_outside_the_published_reference_dir_is_refused(self):
        # The entry travels through `.panopticon/dispatch-request.json`, inside
        # the reviewed tree. Nothing else on the argv is a path the target
        # could have named, and this one must not become the exception: only
        # the schemas panopticon publishes are ever passed to a host CLI.
        for path in ("/etc/passwd", os.path.join(os.path.dirname(_published()), "nope.json"),
                     os.path.join(os.path.dirname(_published()), os.pardir, "SKILL.md")):
            with self.subTest(path=path):
                self.assertEqual([], base.schema_argv(("--x",), {"output_schema": path}))


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


class TestTheHostOutageClassifier(unittest.TestCase):
    """#1623: 243 of the 247 failed launches in the Kimi evidence run were ONE
    403 -- the host, not the entries -- and the loop charged every one of them
    to the entry that happened to be holding it.

    The classifier is host-agnostic on purpose: it reads the failure TEXT, and
    all three shipped families compose `RunResult.error` out of the host's own
    exit line and message (`claude -p exited 1: ...`, `kimi -p exited 1: ...`,
    codex's `turn.failed` error), so there is one place that decides and every
    family is free to override it at its own construction.
    """

    HOST = (
        # the three families' shipped failure text, verbatim in shape
        "kimi -p exited 1: Error: 403 Forbidden",
        "claude -p exited 1: API Error: 401 {\"type\":\"authentication_error\"}",
        "claude -p reported is_error: Invalid API key - please run /login",
        "codex exited with status 1: stream error: unexpected status 429 Too Many Requests",
        "kimi -p exited 1: quota exceeded for this organization",
        "claude -p exited 1: Your credit balance is too low",
        "codex exited with status 1: 503 Service Unavailable",
        "kimi -p exited 1: upstream connect error",
        "claude -p exited 1: Overloaded",
    )
    ENTRY = (
        # every OTHER failure this suite and the three families produce
        "always", "flaky", "concurrency cap", "is_error",
        "persist refused: shape check failed",
        "claude -p timed out after 300s",
        "codex timed out after 500s",
        "kimi -p timed out after 403s",          # the number is a duration, not a status
        "could not launch kimi: [Errno 2] No such file or directory",
        "claude -p printed no JSON envelope (exit 2)",
        "codex returned no final message",
        "enforcement shell not registered at /tmp/x/panopticon-domain-panel.sh",
        "ValueError: Codex requires delivery: return_json; it cannot self-write",
    )

    def test_the_provider_side_symptoms_read_as_a_host_failure(self):
        for error in self.HOST:
            with self.subTest(error=error):
                self.assertEqual(base.HOST_FAILURE, base.classify_failure(error))

    def test_every_other_failure_stays_the_entrys_own(self):
        for error in self.ENTRY:
            with self.subTest(error=error):
                self.assertEqual(base.ENTRY_FAILURE, base.classify_failure(error))

    def test_no_error_at_all_is_an_entry_failure(self):
        self.assertEqual(base.ENTRY_FAILURE, base.classify_failure(None))
        self.assertEqual(base.ENTRY_FAILURE, base.classify_failure(""))

    def test_a_failed_result_carries_the_classification(self):
        self.assertEqual(base.HOST_FAILURE,
                         base.RunResult.failed("e1", "kimi -p exited 1: 403 Forbidden").failure_class)
        self.assertEqual(base.ENTRY_FAILURE, base.RunResult.failed("e1", "always").failure_class)

    def test_a_family_may_refine_it_at_its_own_construction(self):
        # The seam's ruling: the default classifier covers the shipped text and
        # a family that knows better says so, rather than patching this module.
        res = base.RunResult.failed("e1", "always", failure_class=base.HOST_FAILURE)
        self.assertEqual(base.HOST_FAILURE, res.failure_class)
        direct = base.RunResult(entry_id="e1", ok=False, text="", usage={}, cost_usd=None,
                                model=None, session_id=None, denials=[],
                                error="claude -p exited 1: 429 rate limit",
                                failure_class=base.ENTRY_FAILURE)
        self.assertEqual(base.ENTRY_FAILURE, direct.failure_class)

    def test_a_direct_construction_is_classified_too(self):
        # `claude.parse_envelope` builds its non-zero-exit failure through the
        # plain constructor, not through `failed` -- which is exactly the
        # shape a 403 arrives in on that host.
        res = base.RunResult(entry_id="e1", ok=False, text="", usage={}, cost_usd=None,
                             model=None, session_id=None, denials=[],
                             error="claude -p exited 1: 403 Forbidden")
        self.assertEqual(base.HOST_FAILURE, res.failure_class)

    def test_a_successful_result_is_not_a_failure_of_either_kind(self):
        res = base.RunResult(entry_id="e1", ok=True, text="{}", usage={}, cost_usd=None,
                             model=None, session_id=None, denials=[], error=None)
        self.assertEqual(base.ENTRY_FAILURE, res.failure_class)


class TestTheFailureTally(unittest.TestCase):
    """#1623: the loop's per-entry streaks, and the host-outage verdict read
    off them. Here rather than in orchestrate.py because the classification and
    everything decided from it have one owner (and orchestrate.py is an entry
    script at its size ceiling)."""

    def _args(self, **kw):
        return type("Args", (), dict({"target": "/tmp/repo", "mode": "headless",
                                      "pr": None, "base": None, "setup": False}, **kw))()

    def _fail(self, error):
        return base.RunResult.failed("e", error)

    def _ok(self):
        return base.RunResult(entry_id="e", ok=True, text="{}", usage={}, cost_usd=None,
                              model=None, session_id=None, denials=[], error=None)

    def test_an_entry_failure_charges_that_entry_and_nothing_else(self):
        tally = base.FailureTally("claude", self._args())
        tally.record("a", self._fail("always"))
        tally.record("b", self._ok())
        self.assertIsNone(tally.settle())
        self.assertEqual({"a": 1}, tally.streaks)

    def test_a_clean_launch_clears_the_streak(self):
        tally = base.FailureTally("claude", self._args())
        for _ in range(2):
            tally.record("a", self._fail("always"))
            tally.settle()
        tally.record("a", self._ok())
        tally.settle()
        self.assertEqual({}, tally.streaks)

    def test_a_refused_reply_is_the_entrys_failure_whatever_the_host_said(self):
        # persist refusing a reply is panopticon's own verdict: the launch
        # itself came back fine, so nothing about it can be the host's fault.
        tally = base.FailureTally("claude", self._args())
        tally.record("a", self._ok(), refusal="persist refused: 403 findings were not adjudicated")
        self.assertIsNone(tally.settle())
        self.assertEqual({"a": 1}, tally.streaks)

    def test_a_whole_batch_of_host_failures_charges_nobody_and_pauses(self):
        tally = base.FailureTally("kimi", self._args())
        for eid in ("a", "b", "c", "d"):
            tally.record(eid, self._fail("kimi -p exited 1: Error: 403 Forbidden"))
        message = tally.settle()
        self.assertEqual({}, tally.streaks)
        self.assertTrue(message.startswith("paused:"), message)
        self.assertIn("kimi", message)                       # the host
        self.assertIn(base.HOST_FAILURE, message)            # the failure class
        self.assertIn("4", message)                          # the count
        self.assertIn("driver.py loop", message)             # the exact resume command
        self.assertIn("--host kimi", message)

    def test_a_mixed_batch_charges_only_the_entry_class_failures(self):
        tally = base.FailureTally("claude", self._args())
        tally.record("a", self._fail("claude -p exited 1: 403 Forbidden"))
        tally.record("b", self._fail("always"))
        self.assertIsNone(tally.settle())                    # not an outage
        self.assertEqual({"b": 1}, tally.streaks)

    def test_a_batch_with_no_failures_at_all_is_not_an_outage(self):
        tally = base.FailureTally("claude", self._args())
        tally.record("a", self._ok())
        self.assertIsNone(tally.settle())

    def test_settling_closes_the_batch(self):
        tally = base.FailureTally("claude", self._args())
        tally.record("a", self._fail("403 Forbidden"))
        self.assertIsNotNone(tally.settle())
        self.assertIsNone(tally.settle())                    # the next batch is empty

    def test_the_cap_message_names_the_entry_the_count_and_its_last_error(self):
        tally = base.FailureTally("claude", self._args())
        for _ in range(3):
            tally.record("a", self._fail("always"))
            tally.settle()
        self.assertIsNone(tally.exhausted([{"id": "a"}], 4))
        message = tally.exhausted([{"id": "a"}, {"id": "b"}], 3)
        self.assertIn("entry a failed 3 consecutive launches", message)
        self.assertIn("last: always", message)

    def test_an_entry_the_host_failed_never_reaches_the_cap(self):
        tally = base.FailureTally("kimi", self._args())
        for _ in range(9):
            tally.record("a", self._fail("kimi -p exited 1: 429 rate limit"))
            tally.settle()
        self.assertIsNone(tally.exhausted([{"id": "a"}], 3))

    def test_the_resume_command_carries_the_flags_that_resolve_the_same_run(self):
        tally = base.FailureTally("codex", self._args(target="/tmp/repo", pr=7, mode="headless"))
        tally.record("a", self._fail("codex exited with status 1: 503 Service Unavailable"))
        message = tally.settle()
        self.assertIn("--pr 7", message)
        self.assertIn("/tmp/repo", message)
        self.assertIn("--mode headless", message)


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
    `Orchestration:Hosts` is at 47 of its 48-file cap, and a 49th file chunks
    the leaf into a name the review matrix has no entry for (the #1638 P13
    defect). Same parking reasoning as `money.py`/`ledger.py` in groups.yml."""

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

