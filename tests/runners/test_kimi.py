import dataclasses
import json
import os
import subprocess
import tempfile
import unittest
from unittest import mock

import scripts.hosts as hosts
import scripts.runners.base as base
import scripts.runners.kimi as kimi_runner
import scripts.runners.outage as outage
from tests._test_helpers import (kimi_fixture_home as _fixture_home,
                           prepared_kimi as _prepared)

from tests.runners.kimi_support import CONFIGURED, STREAM, _entry

class TestCommand(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.r = _prepared(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.r.teardown, "complete")   # C1: the home is a temp dir now

    def test_enforced_entry_passes_agent_file_and_model(self):
        cmd = self.r.command(_entry(True), "kimi-code/k3")
        self.assertEqual(cmd[0], "kimi")
        self.assertIn("--output-format", cmd)
        agent_flags = [a for a in cmd if a.startswith("--agent-file=")]
        self.assertEqual(len(agent_flags), 1)
        self.assertTrue(agent_flags[0].endswith("panopticon-domain-panel.md"))
        self.assertIn("-m", cmd)
        self.assertIn("kimi-code/k3", cmd)
        self.assertEqual(cmd[-1], _entry(True)["prompt"])     # the prompt is the last argv, inline

    def test_unenforced_entry_passes_no_agent_file(self):
        cmd = self.r.command(_entry(False), "kimi-code/k3")
        self.assertFalse(any(a.startswith("--agent-file=") for a in cmd))
        self.assertIn("kimi-code/k3", cmd)

    def test_no_model_means_no_model_flag(self):
        cmd = self.r.command(_entry(False, model=None), None)
        self.assertNotIn("-m", cmd)

    def test_this_family_takes_no_output_schema(self):
        # D10 ruling 3: the installed Kimi CLI advertises no constrained-output
        # flag, so the family leaves the seam attribute empty -- and an entry
        # that names a schema (every review cell does) must still reach the
        # argv without one, rather than picking up another family's flag.
        self.assertEqual((), kimi_runner.Runner.OUTPUT_SCHEMA_FLAG)
        entry = dict(_entry(True), output_schema="/any/schema.json")
        self.assertEqual(self.r.command(entry, "kimi-code/k3"),
                         self.r.command(_entry(True), "kimi-code/k3"))


class TestParseEnvelope(unittest.TestCase):
    def test_the_last_assistant_content_and_the_session_id_win(self):
        text, session_id = kimi_runner.Runner("kimi").parse_envelope("e1", STREAM, 0)
        self.assertEqual(text, "the final reply")
        self.assertEqual(session_id, "session_test-1")

    def test_a_nonzero_exit_is_a_failure(self):
        res = kimi_runner.Runner("kimi").parse_envelope("e1", STREAM, 2)
        self.assertFalse(res.ok)
        self.assertIn("exited 2", res.error)

    def test_partial_output_never_masks_the_host_reason(self):
        res = kimi_runner.Runner("kimi").parse_envelope(
            "e1", STREAM, 1, stderr="provider.auth_error: 403 weekly usage limit")
        self.assertIn("403 weekly usage limit", res.error)
        self.assertNotIn("the final reply", res.error)
        self.assertEqual("the final reply", res.text)
        self.assertEqual("session_test-1", res.session_id)
        self.assertEqual(outage.HOST_FAILURE, res.failure_class)

    def test_missing_host_reason_is_explicit_and_partial_reply_is_separate(self):
        text = "API Error: 403 Forbidden"
        stream = json.dumps({"role": "assistant", "content": text})
        res = kimi_runner.Runner("kimi").parse_envelope("e1", stream, 1)
        self.assertIn("host provided no failure reason", res.error)
        self.assertIn("retained separately", res.error)
        self.assertNotIn(text, res.error)
        self.assertEqual(text, res.text)
        self.assertIsNone(res.host_error)
        self.assertEqual(outage.ENTRY_FAILURE, res.failure_class)

    def test_a_failed_launch_reports_stderr_not_an_empty_tail(self):
        # 2026-09-13: an 8-wide burst hit the gateway rate limit and every
        # entry read 'kimi -p exited 1: ' -- stdout empty, the reason on
        # stderr, invisible. stderr is the failure detail of record.
        res = kimi_runner.Runner("kimi").parse_envelope(
            "e1", "", 1, stderr="Error: rate limit exceeded\n")
        self.assertFalse(res.ok)
        self.assertIn("rate limit", res.error)

    def test_the_host_surface_is_stderr_never_the_assistants_content(self):
        # #1623 C1: `detail` prefers the assistant's own text, so a cell whose
        # reply names src/billing/quota.py would otherwise read as a quota
        # outage and stop the whole run.
        r = kimi_runner.Runner("kimi")
        res = r.parse_envelope(
            "e1", json.dumps({"role": "assistant",
                              "content": "no such file or directory: src/billing/quota.py"}),
            1, stderr="")
        self.assertIsNone(res.host_error)
        self.assertEqual(outage.ENTRY_FAILURE, res.failure_class)
        res = r.parse_envelope("e1", "", 1, stderr="provider.auth_error: 403\n")
        self.assertEqual("provider.auth_error: 403", res.host_error)
        self.assertEqual(outage.HOST_FAILURE, res.failure_class)

    def test_a_failed_launch_also_keeps_stderr_on_the_result(self):
        # #1732 part 3: `error` already folds up to 200 characters of stderr
        # (or of the agent's tail) into an operator sentence; the ROW needs
        # the CLI's own words as a field, redacted and bounded, so the ledger
        # is diagnosable without re-reading a composed message.
        res = kimi_runner.Runner("kimi").parse_envelope(
            "e1", "", 1, stderr="Error: rate limit exceeded key sk-ant-api03-AAAABBBBCCCC\n")
        self.assertIn("rate limit exceeded", res.stderr)
        self.assertNotIn("sk-ant-", res.stderr)
        self.assertLessEqual(len(res.stderr), base.STDERR_HEAD)

    def test_a_successful_launch_carries_no_stderr(self):
        r = kimi_runner.Runner("kimi")
        text, _session = r.parse_envelope("e1", STREAM, 0, stderr="a warning")
        self.assertEqual("the final reply", text)

    def test_garbage_lines_are_tolerated(self):
        text, session_id = kimi_runner.Runner("kimi").parse_envelope(
            "e1", "not json\n" + STREAM + "\n{broken", 0)
        self.assertEqual(text, "the final reply")


class TestAliases(unittest.TestCase):
    def test_tiers_resolve_through_the_profile_aliases(self):
        self.assertEqual(kimi_runner.resolve_cli_alias("secondary", CONFIGURED), "kimi-code/k3")
        self.assertEqual(kimi_runner.resolve_cli_alias("primary", CONFIGURED), "kimi-code/kimi-for-coding")

    def test_full_and_short_aliases_resolve_when_configured(self):
        self.assertEqual(kimi_runner.resolve_cli_alias("k3", CONFIGURED), "kimi-code/k3")
        self.assertEqual(kimi_runner.resolve_cli_alias("kimi-code/k3", CONFIGURED), "kimi-code/k3")

    def test_an_unresolvable_model_is_none_never_a_guess(self):
        self.assertIsNone(kimi_runner.resolve_cli_alias("bogus", CONFIGURED))
        self.assertIsNone(kimi_runner.resolve_cli_alias(None, CONFIGURED))
        self.assertIsNone(kimi_runner.resolve_cli_alias("secondary", frozenset()))

    def test_tier_aliases_derive_from_model_resolver(self):
        tiers = kimi_runner._tier_aliases()
        self.assertEqual(tiers.get("primary"), "kimi-for-coding")
        self.assertEqual(tiers.get("secondary"), "k3")


class TestRunEntry(unittest.TestCase):
    def _env(self):
        return {base.ENV_ENTRY_ID: "review-app-SEC",
                base.ENV_WRITE_ALLOWLIST: "/w.json", base.ENV_READ_SCOPE: "/s.json"}

    def _fake_run(self, seen):
        def fake(cmd, **kw):
            seen["cmd"], seen["kw"] = cmd, kw
            class P:
                returncode = 0
                stdout = STREAM
                stderr = ""
            return P()
        return fake

    def test_run_entry_overlays_bindings_sets_home_and_drops_session_markers(self):
        seen = {}
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.dict(os.environ, {"PATH": "/p", "HOME": "/h",
                                          "KIMI_CODE_HOME": _fixture_home(d),
                                          "KIMI_SESSION_ID": "s1", "KIMI_CODE_VERSION": "0.42.0"},
                             clear=True):
            r = kimi_runner.Runner("kimi", runner=self._fake_run(seen))
            r.prepare(os.path.join(d, "run"), review_root=d)
            self.addCleanup(r.teardown, "complete")
            r.max_turns = 12
            res = r.run_entry(_entry(False), self._env())
        self.assertTrue(res.ok)
        self.assertEqual(res.text, "the final reply")
        self.assertEqual(res.session_id, "session_test-1")
        child_env = seen["kw"]["env"]
        self.assertEqual(child_env["PATH"], "/p")            # inherited, never in `env`
        self.assertEqual(child_env["HOME"], "/h")            # inherited, never in `env`
        self.assertNotIn("KIMI_SESSION_ID", child_env)       # nested-session markers dropped
        self.assertNotIn("KIMI_CODE_VERSION", child_env)
        self.assertEqual(child_env["KIMI_CODE_HOME"], r.kimi_home)
        self.assertEqual(child_env["KIMI_LOOP_MAX_STEPS_PER_TURN"], "12")
        self.assertEqual(child_env[base.ENV_ENTRY_ID], "review-app-SEC")
        self.assertEqual(seen["kw"]["cwd"], os.path.abspath(d))
        self.assertEqual(seen["kw"]["timeout"], r.entry_timeout)

    def test_run_entry_prepares_its_environment_through_launch_env(self):
        # #1626 I2: ONE env preparation per runner. Kimi's discipline -- the
        # per-run KIMI_CODE_HOME, the step cap, and dropping the nested-session
        # markers -- moved into `launch_env` unchanged (the test above still
        # asserts every one of them on the child), and `run_entry` calls it.
        seen = {}
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
            r = kimi_runner.Runner("kimi", runner=self._fake_run(seen))
            r.prepare(os.path.join(d, "run"), review_root=d)
            self.addCleanup(r.teardown, "complete")
            with mock.patch.object(r, "launch_env", wraps=r.launch_env) as prepared:
                r.run_entry(_entry(False), self._env())
        self.assertEqual(1, prepared.call_count)

    def test_usage_and_model_come_back_from_the_wire_file(self):
        seen = {}
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
            r = kimi_runner.Runner("kimi", runner=self._fake_run(seen))
            r.prepare(os.path.join(d, "run"), review_root=d)
            self.addCleanup(r.teardown, "complete")
            wire = os.path.join(r.kimi_home, "sessions", "wd_x_1", "session_test-1",
                                "agents", "main", "wire.jsonl")
            os.makedirs(os.path.dirname(wire))
            with open(wire, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(
                    {"type": "usage.record", "model": "kimi-code/k3", "usageScope": "turn",
                     "usage": {"inputOther": 42, "output": 7,
                               "inputCacheRead": 100, "inputCacheCreation": 3}}) + "\n")
            res = r.run_entry(_entry(False), self._env())
        self.assertTrue(res.ok)
        self.assertEqual(res.usage["input_tokens"], 42)
        self.assertEqual(res.usage["cache_read_input_tokens"], 100)
        self.assertEqual(res.model, "kimi-code/k3")
        self.assertIsNone(res.cost_usd)                       # no USD metering on OAuth

    def test_an_enforced_entry_without_a_registered_shell_fails_closed(self):
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
            row = dataclasses.replace(hosts.HOSTS["kimi"], registration_dir=os.path.join(d, "nowhere"))
            with mock.patch.dict(hosts.HOSTS, {"kimi": row}):
                r = kimi_runner.Runner("kimi", runner=self._fake_run({}))
                r.prepare(os.path.join(d, "run"), review_root=d)
                self.addCleanup(r.teardown, "complete")
                res = r.run_entry(_entry(True), self._env())
        self.assertFalse(res.ok)
        self.assertIn("not registered", res.error)

    def test_an_unresolvable_entry_model_fails_closed(self):
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
            r = kimi_runner.Runner("kimi", runner=self._fake_run({}))
            r.prepare(os.path.join(d, "run"), review_root=d)
            self.addCleanup(r.teardown, "complete")
            res = r.run_entry(_entry(False, model="bogus-tier"), self._env())
        self.assertFalse(res.ok)
        self.assertIn("does not resolve", res.error)

    def test_a_timed_out_launch_keeps_the_stream_it_had_printed(self):
        # D10 ruling 5. Kimi's usage comes from the session wire file, not from
        # stdout, so a killed launch has no usage to recover -- but the
        # stream-json it did print is what the loop retains as evidence.
        partial = STREAM.split("\n")[0]

        def slow(cmd, **kw):
            raise subprocess.TimeoutExpired(cmd, kw.get("timeout"), output=partial.encode())

        with tempfile.TemporaryDirectory() as d, \
             mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
            r = kimi_runner.Runner("kimi", runner=slow)
            r.prepare(os.path.join(d, "run"), review_root=d)
            self.addCleanup(r.teardown, "complete")
            res = r.run_entry(_entry(False), {})
        self.assertFalse(res.ok)
        self.assertIn("timed out after", res.error)
        self.assertEqual(partial, res.text)
        self.assertEqual({}, res.usage)

    def test_a_timed_out_launch_carries_the_killed_childs_stderr(self):
        # #1732 fix round 2: the `TimeoutExpired` path kept the partial stream
        # and dropped stderr, so the failure that costs a whole entry timeout
        # ledgered no diagnosis. `TimeoutExpired` carries both streams UNDECODED
        # even from a text-mode launch (see `base.partial_output`).
        noisy = "kimi: auth failed for key sk-ant-api03-AAAABBBBCCCCDDDDEEEEFFFF"

        def slow(cmd, **kw):
            raise subprocess.TimeoutExpired(cmd, kw.get("timeout"), stderr=noisy.encode())

        with tempfile.TemporaryDirectory() as d, \
             mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
            r = kimi_runner.Runner("kimi", runner=slow)
            r.prepare(os.path.join(d, "run"), review_root=d)
            self.addCleanup(r.teardown, "complete")
            res = r.run_entry(_entry(False), {})
        self.assertFalse(res.ok)
        self.assertIn("timed out after", res.error)
        self.assertIn("auth failed", res.stderr)
        self.assertNotIn("sk-ant-", res.stderr)
        self.assertLessEqual(len(res.stderr), base.STDERR_HEAD)

    def test_a_timeout_or_launch_failure_is_a_failed_result(self):
        def boom(cmd, **kw):
            raise subprocess.TimeoutExpired(cmd, kw.get("timeout"))
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
            r = kimi_runner.Runner("kimi", runner=boom)
            r.prepare(os.path.join(d, "run"), review_root=d)
            self.addCleanup(r.teardown, "complete")
            res = r.run_entry(_entry(False), {})
        self.assertFalse(res.ok)
        self.assertIn("timed out", res.error)

        def missing(cmd, **kw):
            raise FileNotFoundError("kimi")
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
            r = kimi_runner.Runner("kimi", runner=missing)
            r.prepare(os.path.join(d, "run"), review_root=d)
            self.addCleanup(r.teardown, "complete")
            res = r.run_entry(_entry(False), {})
        self.assertFalse(res.ok)
        self.assertIn("kimi", res.error)

    def test_any_other_launch_exception_is_a_failed_result(self):
        def bad_args(cmd, **kw):
            raise ValueError("bad args")
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
            r = kimi_runner.Runner("kimi", runner=bad_args)
            r.prepare(os.path.join(d, "run"), review_root=d)
            self.addCleanup(r.teardown, "complete")
            res = r.run_entry(_entry(False), {})
        self.assertFalse(res.ok)
        self.assertIn("ValueError", res.error)


class TestRegistration(unittest.TestCase):
    def test_the_headless_runner_is_discoverable_by_name(self):
        self.assertTrue(base.headless_available("kimi"))
        runner = base.runner_for("kimi", "headless")
        self.assertEqual(runner.host, "kimi")
        self.assertEqual(runner.mode, "headless")
