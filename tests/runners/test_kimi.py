import atexit
import contextlib
import dataclasses
import datetime
import glob
import io
import json
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import tomllib
import unittest
from unittest import mock

import scripts.hosts as hosts
import scripts.kimi_guard_hook as kimi_guard_hook
import scripts.runners.base as base
import scripts.kimi_toml as kimi_toml
import scripts.runners.kimi as kimi_runner
import scripts.runners.kimi_home as kimi_home
import scripts.runners.outage as outage

STREAM = "\n".join([
    json.dumps({"role": "meta", "type": "system.version", "version": "0.42.0"}),
    json.dumps({"role": "assistant", "content": "intermediate thought"}),
    json.dumps({"role": "tool", "tool_call_id": "t1", "content": "file contents"}),
    json.dumps({"role": "assistant", "content": "the final reply"}),
    json.dumps({"role": "meta", "type": "session.resume_hint",
                "session_id": "session_test-1", "command": "kimi -r session_test-1"}),
])
CONFIGURED = frozenset({"kimi-code/k3", "kimi-code/kimi-for-coding"})


def _entry(enforced, model="secondary"):
    return {"id": "review-app-SEC", "agent": "panopticon-domain-panel" if enforced else None,
            "enforced": enforced, "model": model, "prompt": "panopticon-entry: review-app-SEC\nReview.",
            "out_file": "/r/.panopticon/runs/t/findings-app-SEC.json"}


def _fixture_home(d):
    """A minimal real-home fixture: a config with two model aliases and a
    credentials file to symlink. Never the operator's real home."""
    home = os.path.join(d, "real-home")
    os.makedirs(home)
    with open(os.path.join(home, "config.toml"), "w", encoding="utf-8") as fh:
        fh.write('default_model = "kimi-code/k3"\n\n'
                 '[models."kimi-code/k3"]\nmodel = "k3"\n\n'
                 '[models."kimi-code/kimi-for-coding"]\nmodel = "kimi-for-coding"\n')
    with open(os.path.join(home, "credentials"), "w", encoding="utf-8") as fh:
        fh.write("fixture")
    return home


@contextlib.contextmanager
def _narrowed_temp_root():
    """Yield (root, outside): a directory the runner will treat as THE temp
    root, and a sibling that is therefore outside it.

    Both are real temp directories -- tests write nowhere else -- but the
    runner's idea of the root is narrowed to the first, so a path can be
    prefix-matching and still outside the root. That combination is what the
    root half of `is_temp_home` exists for, and there is no other way to build
    it without writing outside the temp directory the test owns.
    """
    with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
        with mock.patch.object(tempfile, "gettempdir", return_value=root), \
             mock.patch.dict(os.environ):
            os.environ.pop("XDG_RUNTIME_DIR", None)
            yield root, outside


def _prepared(d, runner=None):
    with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
        r = kimi_runner.Runner("kimi", runner=runner or subprocess.run)
        r.prepare(os.path.join(d, "run"), review_root=d)
    return r


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


class TestPrepare(unittest.TestCase):
    def test_prepare_builds_the_per_run_home_and_it_is_idempotent(self):
        with tempfile.TemporaryDirectory() as d:
            fixture = _fixture_home(d)
            with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": fixture}):
                r = kimi_runner.Runner("kimi")
                run_dir = os.path.join(d, "run")
                r.prepare(run_dir, review_root=d)
                self.addCleanup(r.teardown, "complete")
                home = r.kimi_home
                # C1: the home is a temp dir outside the reviewed tree; the run
                # folder keeps only the pointer file that names it.
                self.assertTrue(kimi_home.is_temp_home(home))
                self.assertNotIn(os.path.realpath(d), os.path.realpath(home))
                self.assertTrue(os.path.islink(os.path.join(home, "credentials")))
                self.assertEqual(os.readlink(os.path.join(home, "credentials")),
                                 os.path.join(fixture, "credentials"))
                with open(os.path.join(home, "config.toml"), "rb") as fh:
                    config = tomllib.load(fh)
                self.assertFalse(config["merge_all_available_skills"])
                self.assertFalse(config["builtin_product_skills"])
                for tool in ("Bash", "Agent", "AgentSwarm", "FetchURL", "WebSearch"):
                    self.assertIn(tool, config["tools"]["disabled"])   # I1
                hooks = config["hooks"]
                self.assertEqual(len(hooks), 2)
                matchers = sorted(h["matcher"] for h in hooks)
                # I1 widened the read matcher to carry ReadMediaFile.
                self.assertEqual(matchers, [kimi_home.READ_MATCHER,
                                            kimi_home.WRITE_MATCHER])
                for h in hooks:
                    self.assertIn(os.path.abspath(kimi_guard_hook.__file__), h["command"])
                self.assertIn(os.path.join(run_dir, "read-scope.json"),
                              [h["command"] for h in hooks
                               if h["matcher"] == kimi_home.READ_MATCHER][0])
                self.assertIn(os.path.join(run_dir, "write-allowlist.json"),
                              [h["command"] for h in hooks
                               if h["matcher"] == kimi_home.WRITE_MATCHER][0])
                # the fixture's own values survive the merge
                self.assertEqual(config["models"]["kimi-code/k3"]["model"], "k3")
                self.assertEqual(r.configured, {"kimi-code/k3", "kimi-code/kimi-for-coding"})
                # Idempotent in the sense that survived N2: a second prepare
                # arms the same configuration. It does so in a FRESH home --
                # reuse would have to trust the pointer file -- so the first
                # one is this runner's to drop.
                first_home = r.kimi_home
                r.prepare(run_dir, review_root=d)
                self.addCleanup(shutil.rmtree, first_home, True)
                self.assertNotEqual(first_home, r.kimi_home)
                with open(os.path.join(r.kimi_home, "config.toml"), "rb") as fh:
                    self.assertEqual(config, tomllib.load(fh))

    def test_a_source_config_with_hooks_keeps_them(self):
        with tempfile.TemporaryDirectory() as d:
            fixture = _fixture_home(d)
            with open(os.path.join(fixture, "config.toml"), "a", encoding="utf-8") as fh:
                fh.write('\n[[hooks]]\nevent = "Stop"\ncommand = "true"\n')
            with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": fixture}):
                r = kimi_runner.Runner("kimi")
                r.prepare(os.path.join(d, "run"), review_root=d)
                self.addCleanup(r.teardown, "complete")
                with open(os.path.join(r.kimi_home, "config.toml"), "rb") as fh:
                    config = tomllib.load(fh)
            self.assertEqual(len(config["hooks"]), 3)
            self.assertIn("Stop", [h["event"] for h in config["hooks"]])


class TestTomlEmission(unittest.TestCase):
    def test_dump_toml_round_trips_nested_tables_and_arrays(self):
        config = {"top": "value", "n": 3, "f": 1.5, "flag": True,
                  "arr": ["a", "b"],
                  "providers": {"managed:kimi-code": {"type": "kimi", "api_key": "",
                                                      "oauth": {"storage": "file"}}},
                  "hooks": [{"event": "PreToolUse", "matcher": "Read", "timeout": 30}]}
        back = tomllib.loads(kimi_toml.dump_toml(config))
        self.assertEqual(back, config)

    def test_keys_that_are_not_bare_are_quoted(self):
        back = tomllib.loads(kimi_toml.dump_toml({"models": {"kimi-code/k3": {"model": "k3"}}}))
        self.assertEqual(back["models"]["kimi-code/k3"]["model"], "k3")


class TestWire(unittest.TestCase):
    def _wire(self, d, records):
        path = os.path.join(d, "wire.jsonl")
        with open(path, "w", encoding="utf-8") as fh:
            for record in records:
                fh.write(json.dumps(record) + "\n")
        return path

    def test_turn_records_sum_and_other_scopes_are_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            path = self._wire(d, [
                {"type": "usage.record", "model": "kimi-code/k3", "usageScope": "turn",
                 "usage": {"inputOther": 10, "output": 2, "inputCacheRead": 4, "inputCacheCreation": 1}},
                {"type": "usage.record", "model": "kimi-code/k3", "usageScope": "turn",
                 "usage": {"inputOther": 5, "output": 3, "inputCacheRead": 0, "inputCacheCreation": 0}},
                {"type": "usage.record", "usageScope": "session",
                 "usage": {"inputOther": 999, "output": 999, "inputCacheRead": 999, "inputCacheCreation": 999}},
            ])
            usage, model = kimi_runner.parse_wire(path)
        self.assertEqual(usage, {"input_tokens": 15, "output_tokens": 5,
                                 "cache_read_input_tokens": 4, "cache_creation_input_tokens": 1})
        self.assertEqual(model, "kimi-code/k3")

    def test_no_turn_records_is_empty_usage_not_a_figure(self):
        with tempfile.TemporaryDirectory() as d:
            path = self._wire(d, [{"type": "usage.record", "usageScope": "session",
                                   "usage": {"inputOther": 9}}])
            usage, model = kimi_runner.parse_wire(path)
        self.assertEqual(usage, {})
        self.assertIsNone(model)

    def test_a_missing_wire_is_empty(self):
        self.assertEqual(kimi_runner.parse_wire("/nonexistent/wire.jsonl"), ({}, None))

    def test_wire_path_globs_the_session_layout_and_rejects_pathy_ids(self):
        with tempfile.TemporaryDirectory() as d:
            home = os.path.join(d, "kimi-home")
            wire = os.path.join(home, "sessions", "wd_x_1", "session_abc", "agents", "main", "wire.jsonl")
            os.makedirs(os.path.dirname(wire))
            with open(wire, "w") as fh:
                fh.write("")
            self.assertEqual(kimi_runner.wire_path(home, "session_abc"), wire)
            self.assertIsNone(kimi_runner.wire_path(home, "../escape"))
            self.assertIsNone(kimi_runner.wire_path(home, "session_missing"))


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


if __name__ == "__main__":
    unittest.main()


class TestHomeLocation(unittest.TestCase):
    """C1 (gate review): the per-run Kimi home carries the operator's
    credential surface -- symlinked OAuth stores and a config.toml holding any
    plaintext api_key -- so it must not live inside the tree being reviewed,
    where a prompt-injected reviewer's in-scope Read and a `zip -r` of the run
    folder both reach it."""

    def _prepare(self, d):
        with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
            r = kimi_runner.Runner("kimi")
            r.prepare(os.path.join(d, ".panopticon", "runs", "t"), review_root=d)
        self.addCleanup(r.teardown, "complete")
        return r

    def test_the_home_is_outside_the_reviewed_tree(self):
        with tempfile.TemporaryDirectory() as d:
            r = self._prepare(d)
            review_root = os.path.realpath(d)
            home = os.path.realpath(r.kimi_home)
            self.assertFalse(home == review_root or home.startswith(review_root + os.sep),
                             "the kimi home is inside the reviewed tree: %s" % home)
            self.assertTrue(os.path.basename(r.kimi_home).startswith("panopticon-kimi-"))
            self.assertTrue(os.path.isfile(os.path.join(r.kimi_home, "config.toml")))

    def test_the_run_dir_keeps_only_a_pointer_file(self):
        with tempfile.TemporaryDirectory() as d:
            r = self._prepare(d)
            run_dir = os.path.join(d, ".panopticon", "runs", "t")
            self.assertEqual(sorted(os.listdir(run_dir)), ["kimi-home-path"])
            with open(os.path.join(run_dir, "kimi-home-path"), encoding="utf-8") as fh:
                self.assertEqual(fh.read().strip(), r.kimi_home)

    def test_the_home_is_0700_and_the_config_0600(self):
        with tempfile.TemporaryDirectory() as d:
            r = self._prepare(d)
            self.assertEqual(0o700, os.stat(r.kimi_home).st_mode & 0o777)
            self.assertEqual(0o600, os.stat(os.path.join(r.kimi_home, "config.toml")).st_mode & 0o777)

    def test_credentials_are_still_symlinked_never_copied(self):
        with tempfile.TemporaryDirectory() as d:
            r = self._prepare(d)
            link = os.path.join(r.kimi_home, "credentials")
            self.assertTrue(os.path.islink(link))

    def test_teardown_removes_the_home_on_complete_and_keeps_it_on_error(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
                r = kimi_runner.Runner("kimi")
                r.prepare(os.path.join(d, "run"), review_root=d)
            home = r.kimi_home
            r.teardown("error")
            self.assertTrue(os.path.isdir(home), "an errored run keeps its home for debugging")
            r.teardown("complete")
            self.assertFalse(os.path.exists(home))

    def test_an_errored_teardown_keeps_the_home_but_strips_its_secrets(self):
        # N6: a kept home holds a config.toml carrying the operator's api_key
        # verbatim and live symlinks into their OAuth stores, and nothing ever
        # prunes it -- on a machine that errors regularly (the PR's own
        # evidence run errored 247 launches) that is a growing set of
        # credential handles, path-visible to every process of that uid. The
        # debugging value is in the wire files, not the secrets.
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
                r = kimi_runner.Runner("kimi")
                r.prepare(os.path.join(d, "run"), review_root=d)
            home = r.kimi_home
            self.addCleanup(shutil.rmtree, home, True)
            wire = os.path.join(home, "sessions", "w", "s", "agents", "main", "wire.jsonl")
            os.makedirs(os.path.dirname(wire))
            with open(wire, "w", encoding="utf-8") as fh:
                fh.write("{}\n")
            with contextlib.redirect_stderr(io.StringIO()) as err:
                r.teardown("error")
            self.assertTrue(os.path.isdir(home))                       # kept
            self.assertTrue(os.path.isfile(wire))                      # and useful
            self.assertFalse(os.path.exists(os.path.join(home, "config.toml")))
            for item in ("credentials", "oauth"):
                self.assertFalse(os.path.islink(os.path.join(home, item)))
            line = err.getvalue()
            self.assertIn(home, line)
            self.assertIn("its config.toml and credential links were removed, so nothing "
                          "left there carries a credential", line)
            # R3-6: the names strip_secrets returned are never echoed (CodeQL
            # read the interpolated list as clear-text logging of a credential).
            for name in kimi_home._CREDENTIAL_ITEMS:
                self.assertNotIn(name, line.replace(home, ""))

    def test_an_errored_teardown_after_a_strip_says_it_held_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
                r = kimi_runner.Runner("kimi")
                r.prepare(os.path.join(d, "run"), review_root=d)
            home = r.kimi_home
            self.addCleanup(shutil.rmtree, home, True)
            r._strip_on_exit()                                     # a handler ran first
            with contextlib.redirect_stderr(io.StringIO()) as err:
                r.teardown("error")
            line = err.getvalue()
            self.assertIn(home, line)
            self.assertIn("; it held no credential files", line)
            for name in kimi_home._CREDENTIAL_ITEMS:
                self.assertNotIn(name, line.replace(home, ""))

    def test_a_removed_home_takes_its_pointer_file_with_it(self):
        with tempfile.TemporaryDirectory() as d:
            run_dir = os.path.join(d, "run")
            with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
                r = kimi_runner.Runner("kimi")
                r.prepare(run_dir, review_root=d)
            r.teardown("complete")
            self.assertFalse(os.path.exists(r.home_pointer))
            self.assertEqual([], os.listdir(run_dir))

    def test_a_hard_kill_strips_the_secrets_through_the_exit_handler(self):
        # R2-2: `teardown` runs from orchestrate._finish, which a SIGKILL, an
        # OOM kill or a power loss never reaches -- and since N2 removed reuse,
        # nothing ever adopts a crashed run's home again. The exit and signal
        # handlers are what stand between a crash and a permanent orphan
        # holding the api_key and live OAuth symlinks. Exercised through the
        # handler itself: the suite sends no signals.
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
                r = kimi_runner.Runner("kimi")
                r.prepare(os.path.join(d, "run"), review_root=d)
            home = r.kimi_home
            self.addCleanup(shutil.rmtree, home, True)
            self.addCleanup(r.teardown, "error")
            wire = os.path.join(home, "sessions", "w", "s", "agents", "main", "wire.jsonl")
            os.makedirs(os.path.dirname(wire))
            with open(wire, "w", encoding="utf-8") as fh:
                fh.write("{}\n")
            r._strip_on_exit()
            self.assertFalse(os.path.exists(os.path.join(home, "config.toml")))
            for item in ("credentials", "oauth"):
                self.assertFalse(os.path.islink(os.path.join(home, item)))
            self.assertTrue(os.path.isfile(wire))       # the transcripts survive
            r._strip_on_exit()                          # idempotent

    def test_the_signal_handler_strips_then_chains_to_the_previous_one(self):
        seen = []
        previous = signal.getsignal(signal.SIGTERM)
        signal.signal(signal.SIGTERM, lambda signum, frame: seen.append(signum))
        self.addCleanup(signal.signal, signal.SIGTERM, previous)
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
                r = kimi_runner.Runner("kimi")
                r.prepare(os.path.join(d, "run"), review_root=d)
            home = r.kimi_home
            self.addCleanup(shutil.rmtree, home, True)
            installed = signal.getsignal(signal.SIGTERM)
            self.assertNotEqual(installed, previous)
            installed(signal.SIGTERM, None)             # no real signal is sent
            self.assertEqual([signal.SIGTERM], seen)    # chained
            self.assertFalse(os.path.exists(os.path.join(home, "config.toml")))
            r.teardown("complete")
            # the run is over: the handlers come back off, so a suite that
            # prepares many runners does not stack wrappers on SIGTERM.
            self.assertIsNone(r._crash_strip)

    def test_an_interrupt_mid_batch_terminates_before_the_guards_come_down(self):
        # R3-1, as amended by #1662. A Ctrl-C raises KeyboardInterrupt in the
        # main thread inside the pool. `config.toml` is the ONLY place this
        # host's guard hooks and derived deny-list are registered, so any
        # child still running when it is stripped runs fail-open -- which is
        # why the ORDER is: cancel what has not started, terminate what is
        # running, and only then let `orchestrate._finish` call
        # teardown("error"). Every entry that did launch must therefore have
        # seen the config; the ones still queued must not have launched at
        # all (before #1662 the pool's `with` drained all four). `prepare`
        # must still leave SIGINT alone: the loop routes the interrupt, and a
        # handler that stripped secrets would strip them before the
        # termination rather than after. Real Runner, real run_batch, fake
        # run_entry; the interrupt is raised the way the driver's own handler
        # raises it -- no signal is sent.
        with tempfile.TemporaryDirectory() as d:
            before = signal.getsignal(signal.SIGINT)
            with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
                r = kimi_runner.Runner("kimi")
                r.prepare(os.path.join(d, "run"), review_root=d)
            home = r.kimi_home
            self.addCleanup(shutil.rmtree, home, True)
            self.addCleanup(r.teardown, "error")
            self.assertIs(before, signal.getsignal(signal.SIGINT),
                          "prepare must not install a SIGINT handler")
            config = os.path.join(home, "config.toml")
            seen, released = [], threading.Event()
            self.addCleanup(released.set)
            # The in-flight entry stays in flight until the interrupt has been
            # through, so "still queued" means still queued: a fake that
            # returned the moment the Ctrl-C landed would free its worker to
            # pull the next item and the assertion would be a race.
            r.INTERRUPT_GRACE = 0.05          # ...and the bounded wait is short

            def fake_run_entry(entry, env):
                seen.append((entry["id"], os.path.isfile(config)))
                if entry["id"] == "e0":
                    handler = signal.getsignal(signal.SIGINT)
                    if callable(handler):
                        handler(signal.SIGINT, None)      # what a Ctrl-C would run
                    raise KeyboardInterrupt
                released.wait(5)
                return base.RunResult(entry_id=entry["id"], ok=True, text="", usage={},
                                      cost_usd=None, model=None, session_id=None,
                                      denials=[], error=None)

            entries = [{"id": "e%d" % i} for i in range(4)]
            with mock.patch.object(r, "run_entry", fake_run_entry), \
                 self.assertRaises(KeyboardInterrupt):
                base.HostRunner.run_batch(r, entries, 2, lambda e: {})
            released.set()
            launched = [eid for eid, _present in seen]
            self.assertIn("e0", launched)
            self.assertLess(len(seen), 4,
                            "the queued entries were launched anyway: %r" % seen)
            self.assertNotIn("e3", launched,
                             "an entry still queued at the interrupt launched: %r" % seen)
            self.assertEqual([], [eid for eid, present in seen if not present],
                             "an entry ran after the config was stripped: %r" % seen)
            self.assertTrue(os.path.isfile(config),
                            "config.toml must outlive the termination")
            r.teardown("error")        # the loop's path: strip AFTER the termination
            self.assertFalse(os.path.exists(config))

    def test_a_prepare_that_rejects_the_operator_config_leaves_no_home_behind(self):
        # R3-2: build_kimi_home mints the directory and links the two
        # credential stores BEFORE build_merged_config can refuse the
        # operator's config, and prepare assigns self.kimi_home only on
        # success -- so an ordinary operator typo used to leave a
        # panopticon-kimi-* holding live OAuth symlinks that no teardown, exit
        # handler or later run ever reclaimed.
        with _narrowed_temp_root() as (root, _outside), tempfile.TemporaryDirectory() as d:
            fixture = _fixture_home(d)
            config = os.path.join(fixture, "config.toml")
            with open(config, encoding="utf-8") as fh:
                body = fh.read()
            with open(config, "w", encoding="utf-8") as fh:
                fh.write("hooks = [1, 2]\n" + body)      # top level, before any table
            pattern = os.path.join(root, kimi_home.HOME_PREFIX + "*")
            self.assertEqual([], glob.glob(pattern))
            with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": fixture}):
                r = kimi_runner.Runner("kimi")
                with self.assertRaises(ValueError) as caught:
                    r.prepare(os.path.join(d, "run"), review_root=d)
            self.assertIn("expected an array of tables at `hooks`, found int in it",
                          str(caught.exception))
            self.assertIsNone(r.kimi_home)
            r.teardown("error")
            self.assertEqual([], glob.glob(pattern),
                             "prepare orphaned a home holding credential links")

    def test_runners_torn_down_in_arming_order_leave_the_baseline_handler(self):
        # R3-3: the disarm used to restore its `previous` only when the CURRENT
        # handler was its own wrapper. Two runners armed without a teardown in
        # between, then torn down in arming order, left the first one's wrapper
        # installed for good -- pinning a dead Runner (and its home path) from
        # the process's SIGTERM handler. tests/runners/conftest.py guards the
        # same invariant around every test; this is the case that trips it.
        baseline = signal.getsignal(signal.SIGTERM)
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
                first = kimi_runner.Runner("kimi")
                first.prepare(os.path.join(d, "run-1"), review_root=d)
                self.addCleanup(shutil.rmtree, first.kimi_home, True)
                second = kimi_runner.Runner("kimi")
                second.prepare(os.path.join(d, "run-2"), review_root=d)
                self.addCleanup(shutil.rmtree, second.kimi_home, True)
            self.assertIsNot(baseline, signal.getsignal(signal.SIGTERM))   # armed
            armed = [first._crash_strip, second._crash_strip]
            # The atexit side, measured by the call: `atexit._ncallbacks()`
            # never shrinks on an unregister before 3.13 (the slot is NULLed,
            # not compacted), so a count is not a portable measure of it.
            with mock.patch.object(atexit, "unregister", wraps=atexit.unregister) as unregister:
                first.teardown("complete")
                second.teardown("complete")
            self.assertIs(baseline, signal.getsignal(signal.SIGTERM),
                          "a wrapper is still installed after both teardowns")
            self.assertEqual([mock.call(cb) for cb in armed], unregister.call_args_list)
            self.assertEqual([None, None], [first._crash_strip, second._crash_strip])

    def test_an_interrupt_mid_strip_leaves_the_exit_stripper_armed(self):
        # #1662 re-review: `teardown` took the crash strippers off FIRST and
        # only then stripped the home, so a Ctrl-C landing between the two
        # left config.toml (api_key verbatim) behind with no atexit net --
        # a window the base never had, because a second interrupt never
        # reached teardown there. The strippers come off LAST: an interrupt
        # anywhere above leaves the atexit stripper armed to finish the job.
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
                r = kimi_runner.Runner("kimi")
                r.prepare(os.path.join(d, "run-1"), review_root=d)
                self.addCleanup(shutil.rmtree, r.kimi_home, True)
                self.addCleanup(r._disarm_crash_strippers)
            armed = r._crash_strip
            self.assertIsNotNone(armed)
            with mock.patch.object(kimi_home, "strip_secrets", side_effect=KeyboardInterrupt), \
                 mock.patch.object(atexit, "unregister", wraps=atexit.unregister) as unregister:
                with self.assertRaises(KeyboardInterrupt):
                    r.teardown("error")
            self.assertIs(armed, r._crash_strip, "the exit stripper was taken off before the strip ran")
            unregister.assert_not_called()
            self.assertTrue(os.path.isfile(os.path.join(r.kimi_home, "config.toml")))

    def test_a_c_installed_previous_handler_is_treated_as_the_default(self):
        # R3-4: `signal.getsignal` reports a handler installed from C as None.
        # The chain handled a callable and SIG_DFL and let None fall through,
        # so under an embedding host the wrapper stripped the home and then
        # RETURNED: the SIGTERM that would have ended the process did nothing.
        # None must behave as SIG_DFL: restore the default and re-raise the
        # signal. Measured on the wrapper directly, with the two calls that
        # would end the process replaced -- nothing is sent to the test process.
        r = kimi_runner.Runner("kimi")                 # no home: the strip is a no-op
        handler = r._signal_stripper(None)
        with mock.patch.object(signal, "signal") as install, \
             mock.patch.object(os, "kill") as kill:
            handler(signal.SIGTERM, None)
        install.assert_called_once_with(signal.SIGTERM, signal.SIG_DFL)
        kill.assert_called_once_with(os.getpid(), signal.SIGTERM)

    def test_a_disarm_restores_the_default_for_a_c_installed_previous_handler(self):
        # NEW-6 (round-4 re-review): the disarm handed `ours.previous` straight
        # to `signal.signal`, and for the C-installed case R3-4 exists for that
        # value is None, which `signal.signal` rejects with a TypeError the
        # except tuple does not catch -- so `teardown` aborted BEFORE stripping
        # the home. None means "the default" here exactly as it does in the
        # wrapper's own chain. The real `signal.signal` is not touched: the
        # fake mirrors only its documented refusal of None.
        r = kimi_runner.Runner("kimi")
        ours = r._signal_stripper(None)
        r._signal_handlers = {signal.SIGTERM: ours}
        installed = []

        def fake_signal(signum, handler):
            if handler is None:
                raise TypeError("signal handler must be signal.SIG_IGN, "
                                "signal.SIG_DFL, or a callable object")
            installed.append((signum, handler))

        with mock.patch.object(signal, "getsignal", return_value=ours), \
             mock.patch.object(signal, "signal", side_effect=fake_signal):
            r._disarm_crash_strippers()
        self.assertEqual([(signal.SIGTERM, signal.SIG_DFL)], installed)
        self.assertEqual({}, r._signal_handlers)

    def test_teardown_refuses_a_path_that_is_not_a_temp_home(self):
        with tempfile.TemporaryDirectory() as d:
            planted = os.path.join(d, "not-a-temp-home")
            os.makedirs(planted)
            r = kimi_runner.Runner("kimi")
            r.kimi_home = planted
            r.teardown("complete")
            self.assertTrue(os.path.isdir(planted), "teardown deleted a path outside the temp root")

    def test_every_prepare_mints_a_fresh_home_even_on_a_resume(self):
        # N2: nothing is reused. The only record of a previous home is the
        # pointer file, which lives in the reviewed tree, and reading it back
        # would make an attacker's file an input to where this run's
        # credential surface gets written.
        with tempfile.TemporaryDirectory() as d:
            run_dir = os.path.join(d, "run")
            with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
                first = kimi_runner.Runner("kimi")
                first.prepare(run_dir, review_root=d)
                self.addCleanup(first.teardown, "complete")
                second = kimi_runner.Runner("kimi")
                second.prepare(run_dir, review_root=d)         # resume: same run dir
                self.addCleanup(second.teardown, "complete")
            self.assertNotEqual(first.kimi_home, second.kimi_home)
            self.assertTrue(kimi_home.is_temp_home(second.kimi_home))
            self.assertTrue(os.path.isfile(os.path.join(second.kimi_home, "config.toml")))
            with open(os.path.join(run_dir, "kimi-home-path"), encoding="utf-8") as fh:
                self.assertEqual(second.kimi_home, fh.read().strip())

    def test_prepare_never_reads_the_pointer_file(self):
        # The hostile target is prefix-matching AND pre-created OUTSIDE the
        # temp root, so nothing about it can be waved through by a name check.
        with _narrowed_temp_root() as (_root, outside), \
             tempfile.TemporaryDirectory() as d:
            hostile = os.path.join(outside, "panopticon-kimi-EVIL")
            os.makedirs(hostile)
            run_dir = os.path.join(d, "run")
            os.makedirs(run_dir)
            with open(os.path.join(run_dir, "kimi-home-path"), "w", encoding="utf-8") as fh:
                fh.write(hostile)
            with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
                r = kimi_runner.Runner("kimi")
                r.prepare(run_dir, review_root=d)
                self.addCleanup(r.teardown, "complete")
            self.assertNotEqual(os.path.realpath(hostile), os.path.realpath(r.kimi_home))
            self.assertEqual([], os.listdir(hostile))       # no config, no credential links

    def test_teardown_refuses_a_prefix_matching_path_outside_the_temp_root(self):
        # The root half of `is_temp_home`, which the round-1 test did not
        # reach: its "hostile" path was inside a TemporaryDirectory, i.e.
        # under the temp root, so the NAME refused it.
        with _narrowed_temp_root() as (_root, outside):
            planted = os.path.join(outside, "panopticon-kimi-PLANTED")
            os.makedirs(planted)
            with open(os.path.join(planted, "keep-me"), "w", encoding="utf-8") as fh:
                fh.write("x")
            self.assertFalse(kimi_home.is_temp_home(planted))
            r = kimi_runner.Runner("kimi")
            r.kimi_home = planted
            r.teardown("complete")
            self.assertTrue(os.path.isfile(os.path.join(planted, "keep-me")))


class TestHardenedWrites(unittest.TestCase):
    """I2: `<run_dir>` is inside the scanned tree and the home is a path a
    resume re-derives, so every file this runner writes goes out through a
    staging writer that refuses to follow a planted symlink -- the same rule
    runners/claude.py states for `host-settings.json`."""

    def test_a_symlinked_home_is_refused_rather_than_chmodded_through(self):
        with tempfile.TemporaryDirectory() as d:
            elsewhere = os.path.join(d, "elsewhere")
            os.makedirs(elsewhere)
            os.chmod(elsewhere, 0o755)
            home = os.path.join(d, "kimi-home")
            os.symlink(elsewhere, home)
            with self.assertRaises(OSError) as caught:
                kimi_home.build_kimi_home(home, os.path.join(d, "s.json"),
                                          os.path.join(d, "a.json"),
                                          real_home=_fixture_home(d))
            self.assertIn(home, str(caught.exception))
            self.assertEqual(0o755, os.stat(elsewhere).st_mode & 0o777)
            self.assertFalse(os.path.exists(os.path.join(elsewhere, "config.toml")))

    def test_a_symlink_planted_at_the_staging_name_is_not_written_through(self):
        with tempfile.TemporaryDirectory() as d:
            home = os.path.join(d, "kimi-home")
            os.makedirs(home)
            victim = os.path.join(d, "victim")
            with open(victim, "w", encoding="utf-8") as fh:
                fh.write("untouched")
            os.symlink(victim, os.path.join(home, "config.toml.tmp"))
            kimi_home.build_kimi_home(home, os.path.join(d, "s.json"),
                                      os.path.join(d, "a.json"),
                                      real_home=_fixture_home(d))
            with open(victim, encoding="utf-8") as fh:
                self.assertEqual("untouched", fh.read())
            self.assertEqual(0o600, os.stat(os.path.join(home, "config.toml")).st_mode & 0o777)

    def test_the_pointer_file_is_written_through_the_same_writer(self):
        with tempfile.TemporaryDirectory() as d:
            run_dir = os.path.join(d, "run")
            os.makedirs(run_dir)
            victim = os.path.join(d, "victim")
            with open(victim, "w", encoding="utf-8") as fh:
                fh.write("untouched")
            os.symlink(victim, os.path.join(run_dir, "kimi-home-path.tmp"))
            with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
                r = kimi_runner.Runner("kimi")
                r.prepare(run_dir, review_root=d)
            self.addCleanup(r.teardown, "complete")
            with open(victim, encoding="utf-8") as fh:
                self.assertEqual("untouched", fh.read())
            with open(os.path.join(run_dir, "kimi-home-path"), encoding="utf-8") as fh:
                self.assertEqual(r.kimi_home, fh.read().strip())


class TestTomlEmissionRoundTrips(unittest.TestCase):
    """C2: the armed `config.toml` is the ONLY place Kimi's confinement lives,
    and this writer produces it from whatever the operator's own config holds.
    A shape it cannot emit is not a cosmetic bug: a config Kimi will not load
    is a run with the two `[[hooks]]` entries missing."""

    def test_a_nested_array_of_tables_round_trips(self):
        # `[[mcp.servers]]` is the standard MCP shape. The old writer emitted
        # the PARENT's path -- `[[mcp]]` -- which tomllib refuses with
        # "Cannot overwrite a value".
        config = {"mcp": {"servers": [{"name": "s1", "command": "a"},
                                      {"name": "s2", "command": "b"}]}}
        self.assertEqual(config, tomllib.loads(kimi_toml.dump_toml(config)))

    def test_a_scalar_after_an_array_of_tables_stays_in_its_own_table(self):
        # The old writer emitted array-of-tables headers from INSIDE the scalar
        # loop, so `y` was swallowed into the last `[[...]]`.
        config = {"a": {"list": [{"x": 1}], "y": 2}}
        self.assertEqual(config, tomllib.loads(kimi_toml.dump_toml(config)))

    def test_datetimes_dates_and_times_round_trip(self):
        config = {"last_update_check": datetime.datetime(2026, 9, 13, 12, 30, 5,
                                                         tzinfo=datetime.timezone.utc),
                  "naive": datetime.datetime(2026, 9, 13, 12, 30, 5),
                  "day": datetime.date(2026, 9, 13),
                  "clock": datetime.time(7, 5, 1)}
        self.assertEqual(config, tomllib.loads(kimi_toml.dump_toml(config)))

    def test_tables_three_deep_round_trip(self):
        config = {"providers": {"managed:kimi-code": {"oauth": {"storage": "file",
                                                                "key": "x"},
                                                      "api_key": "k"}},
                  "top": 1}
        self.assertEqual(config, tomllib.loads(kimi_toml.dump_toml(config)))

    def test_a_none_value_names_the_key_it_came_from(self):
        with self.assertRaises(TypeError) as caught:
            kimi_toml.dump_toml({"tools": {"disabled": None}})
        self.assertIn("disabled", str(caught.exception))

    def test_the_real_merged_config_drops_the_operators_mcp_servers(self):
        # #1640 (run-13 AGT-3297306866). This used to assert the OPPOSITE --
        # that two `[[mcp.servers]]` and `enabled = true` round-tripped into
        # the armed home -- which was true and was the defect: the per-run
        # home's confinement is `tools.disabled` plus two PreToolUse hooks,
        # and both adjudicate the CLI's own tool names. An MCP server's tools
        # are supplied at runtime by another process, under names neither has
        # heard, reaching the filesystem and the network through that process.
        # The writer's ability to emit the nested shape is still covered, by
        # `test_a_nested_array_of_tables_round_trips` above.
        with tempfile.TemporaryDirectory() as d:
            fixture = _fixture_home(d)
            with open(os.path.join(fixture, "config.toml"), "a", encoding="utf-8") as fh:
                fh.write('\n[[mcp.servers]]\nname = "s1"\n\n[[mcp.servers]]\nname = "s2"\n'
                         '\n[mcp]\nenabled = true\n')
            home = os.path.join(d, "home")
            with contextlib.redirect_stderr(io.StringIO()) as err:
                kimi_home.build_kimi_home(home, os.path.join(d, "s.json"),
                                          os.path.join(d, "a.json"), real_home=fixture)
            with open(os.path.join(home, "config.toml"), "rb") as fh:
                armed = tomllib.load(fh)
        self.assertEqual([], armed["mcp"]["servers"])
        self.assertFalse(armed["mcp"]["enabled"])
        self.assertEqual(2, len(armed["hooks"]))
        # The disclosure is a COUNT on one line, never a list: it shares the
        # operator's stderr with the run's own progress output, and a line
        # that grows with the operator's config would crowd it out.
        self.assertIn("2 operator MCP servers disabled in the per-run home",
                      err.getvalue())
        self.assertNotIn("s1", err.getvalue())

    def test_an_operator_config_with_no_mcp_block_discloses_nothing(self):
        # Nothing was dropped, so there is nothing to say; a line printed on
        # every run teaches the operator to skip the ones that matter.
        with tempfile.TemporaryDirectory() as d:
            home = os.path.join(d, "home")
            with contextlib.redirect_stderr(io.StringIO()) as err:
                kimi_home.build_kimi_home(home, os.path.join(d, "s.json"),
                                          os.path.join(d, "a.json"),
                                          real_home=_fixture_home(d))
            with open(os.path.join(home, "config.toml"), "rb") as fh:
                armed = tomllib.load(fh)
        self.assertEqual("", err.getvalue())
        self.assertEqual({"enabled": False, "servers": []}, armed["mcp"])

    def test_every_shape_it_scrubs_is_disclosed_exactly_once(self):
        # Fix round 1, F4. `dropped` counted only a real list, and the line
        # printed only when that count was truthy -- so a scalar `mcp`, a
        # hostile `servers`, and an `enabled = true` with no servers listed
        # were all replaced in TOTAL SILENCE. Those are the shapes an operator
        # is least likely to notice, and their MCP configuration is being
        # removed. One line each, naming the shape and the count; never two,
        # never none.
        shapes = (
            ({"enabled": True, "servers": [{"name": "s1"}, {"name": "s2"}]},
             "2 operator MCP servers disabled in the per-run home"),
            ({"enabled": True, "servers": [{"name": "s1"}]},
             "1 operator MCP server disabled in the per-run home"),
            ({"enabled": True, "servers": []},
             "`mcp.enabled` was set with no servers listed"),
            ({"enabled": True}, "`mcp.enabled` was set with no servers listed"),
            ({"enabled": False, "servers": "hostile"},
             "`mcp.servers` was a str, not an array"),
            ({"servers": {"a": 1}}, "`mcp.servers` was a dict, not an array"),
            ("whatever the operator put here", "`mcp` was a str, not a table"),
            ([1, 2, 3], "`mcp` was a list, not a table"),
        )
        for block, phrase in shapes:
            with self.subTest(block=repr(block)[:40]):
                stream = io.StringIO()
                self.assertEqual({"enabled": False, "servers": []},
                                 kimi_toml.mediated_mcp({"mcp": block}, disclose=stream))
                lines = stream.getvalue().splitlines()
                self.assertEqual(1, len(lines), lines)
                self.assertIn(phrase, lines[0])
                self.assertTrue(lines[0].startswith("driver loop: "), lines[0])
                self.assertNotIn("s1", lines[0])

    def test_nothing_to_scrub_says_nothing(self):
        # Two no-ops, and both must stay silent: an operator with no `[mcp]`
        # at all, and one whose block is already exactly what the per-run home
        # writes. A line on every run teaches its reader to skip the ones that
        # matter.
        for source in ({}, {"mcp": {"enabled": False, "servers": []}}):
            with self.subTest(source=source):
                stream = io.StringIO()
                kimi_toml.mediated_mcp(source, disclose=stream)
                self.assertEqual("", stream.getvalue())

    def test_the_inert_block_is_a_value_no_importer_can_move(self):
        # Every armed config gets its OWN dict and its OWN list: one config
        # mutating the block it was handed must not reach the next.
        #
        # Fix round 2 (N3): this used to be a module-level dict, and the guard
        # probes compare the armed file against it. A shared mutable bar is
        # one any importer could move for the rest of the process without
        # touching the probe or the runner -- so it is a function now. A
        # MappingProxyType would not have been enough: the `servers` list
        # inside it stays mutable, which is the same hazard one level down,
        # and it is exactly the key a planted server would go into.
        first, second = kimi_toml.inert_mcp(), kimi_toml.inert_mcp()
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["servers"], second["servers"])
        first["enabled"] = True
        first["servers"].append("planted")
        first["extra"] = "planted"
        self.assertEqual({"enabled": False, "servers": []}, kimi_toml.inert_mcp())
        self.assertEqual(kimi_toml.inert_mcp(), kimi_toml.mediated_mcp())
        self.assertIsNot(kimi_toml.mediated_mcp()["servers"],
                         kimi_toml.mediated_mcp()["servers"])

    def test_the_block_is_constructed_not_filtered(self):
        # Whatever the operator's `[mcp]` holds -- a scalar, a table this
        # writer could not emit, a per-server `enabled` flag -- the armed home
        # carries the same two keys. Preferring the block-level switch over a
        # per-server one is deliberate: it is one fact, and the probes refute
        # it by reading two keys rather than walking a list.
        merged = kimi_home.build_merged_config(
            {"mcp": "whatever the operator put here"}, "s.json", "a.json")
        self.assertEqual({"enabled": False, "servers": []}, merged["mcp"])


class TestDefaultAgentSurface(unittest.TestCase):
    """I1: `tools.disabled` is what confines an UNENFORCED entry -- the
    setup-scan is always unenforced, so this is the default path of every
    `driver setup`, not a corner. A three-name deny-list left 21 of 24 tools
    live, including an unguarded read tool and two egress tools."""

    def test_the_disabled_set_is_derived_as_the_complement_of_the_templates(self):
        vocabulary = set().union(*kimi_home.TOOL_VOCABULARY.values())
        allowed = kimi_home.allowed_tool_union()
        self.assertEqual(sorted(vocabulary - allowed), kimi_home.disabled_tools())
        self.assertEqual({"Read", "Grep", "Glob", "Write"}, allowed)

    def test_the_egress_persistence_and_unguarded_read_tools_are_closed(self):
        disabled = set(kimi_home.disabled_tools())
        for tool in ("FetchURL", "WebSearch", "CronCreate", "CronDelete",
                     "ReadMediaFile", "Skill", "Agent", "AgentSwarm", "Bash"):
            self.assertIn(tool, disabled)
        for tool in ("Read", "Grep", "Glob", "Write"):
            self.assertNotIn(tool, disabled)

    def test_the_armed_config_disables_everything_no_template_grants(self):
        with tempfile.TemporaryDirectory() as d:
            home = os.path.join(d, "home")
            kimi_home.build_kimi_home(home, os.path.join(d, "s.json"),
                                      os.path.join(d, "a.json"),
                                      real_home=_fixture_home(d))
            with open(os.path.join(home, "config.toml"), "rb") as fh:
                config = tomllib.load(fh)
        vocabulary = set().union(*kimi_home.TOOL_VOCABULARY.values())
        self.assertEqual(vocabulary,
                         set(config["tools"]["disabled"]) | kimi_home.allowed_tool_union())

    def test_the_read_matcher_covers_every_read_tool_the_hook_adjudicates(self):
        for tool in kimi_guard_hook._READ_TOOLS:
            self.assertIn(tool, kimi_home.READ_MATCHER.split("|"))


class TestOperatorConfigShape(unittest.TestCase):
    """M3: `~/.kimi-code/config.toml` is the operator's file, not ours. A shape
    the merge does not expect used to surface as a bare ValueError/TypeError
    from `dict()` -- loud (orchestrate reports it as an error status) but
    reading as a crash rather than as "your config has an unexpected shape"."""

    def _fixture(self, d, body):
        home = os.path.join(d, "real-home")
        os.makedirs(home, exist_ok=True)
        with open(os.path.join(home, "config.toml"), "w", encoding="utf-8") as fh:
            fh.write(body)
        return home

    def _build(self, d, body):
        return kimi_home.build_kimi_home(os.path.join(d, "home"),
                                         os.path.join(d, "s.json"),
                                         os.path.join(d, "a.json"),
                                         real_home=self._fixture(d, body))

    def test_a_tools_array_names_the_file_the_key_and_the_shape(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError) as caught:
                self._build(d, 'tools = ["Read"]\n')
        message = str(caught.exception)
        self.assertIn("config.toml", message)
        self.assertIn("`tools`", message)
        self.assertIn("expected a table", message)
        self.assertIn("list", message)

    def test_a_disabled_string_is_named(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError) as caught:
                self._build(d, '[tools]\ndisabled = "Bash"\n')
        self.assertIn("`tools.disabled`", str(caught.exception))
        self.assertIn("expected an array", str(caught.exception))

    def test_a_disabled_list_holding_non_strings_is_named(self):
        # N5: `_expect` checked that `tools.disabled` was an ARRAY, not what
        # was in it, so `[1, 2]` reached `sorted(set(...) | set(...))` and
        # raised "'<' not supported between instances of 'str' and 'int'" --
        # the unnamed crash M3 exists to remove.
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError) as caught:
                self._build(d, '[tools]\ndisabled = [1, 2]\n')
        message = str(caught.exception)
        self.assertIn("config.toml", message)
        self.assertIn("`tools.disabled`", message)
        self.assertIn("an array of strings", message)
        self.assertIn("int", message)

    def test_a_hooks_table_is_named_rather_than_silently_dropped(self):
        # `[hooks]` instead of `[[hooks]]`: the old filter iterated the dict's
        # KEYS, discarded them all as non-dicts, and armed a config whose
        # operator hooks had vanished without a word.
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError) as caught:
                self._build(d, '[hooks]\nevent = "Stop"\n')
        self.assertIn("`hooks`", str(caught.exception))

    def test_a_hooks_array_holding_non_tables_is_named(self):
        # R2-3: N5's `items=` went to `tools.disabled` and not to its twin.
        # `hooks = [1, 2]` passed the array check and was then silently
        # discarded by `[h for h in ... if isinstance(h, dict)]` -- the
        # operator's own hooks gone without a word, which is the failure M3
        # exists to remove, one level down.
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError) as caught:
                self._build(d, 'hooks = [1, 2]\n')
        message = str(caught.exception)
        self.assertIn("config.toml", message)
        self.assertIn("`hooks`", message)
        self.assertIn("an array of tables", message)
        self.assertIn("int", message)

    def test_a_config_with_the_expected_shapes_still_builds(self):
        with tempfile.TemporaryDirectory() as d:
            home = self._build(d, '[tools]\ndisabled = ["Something"]\n\n'
                                  '[[hooks]]\nevent = "Stop"\ncommand = "true"\n')
            with open(os.path.join(home, "config.toml"), "rb") as fh:
                config = tomllib.load(fh)
        self.assertIn("Something", config["tools"]["disabled"])
        self.assertEqual(3, len(config["hooks"]))


class TestAgentFileChildrenAreBoundGlobally(unittest.TestCase):
    """The PR claimed, unverified, that `tools.disabled` binds an
    `--agent-file=` child as well as the default agent. What can be settled
    without launching the CLI is the half that is ours: the config the runner
    writes puts the deny-list at the TOP level of the per-run home -- not under
    any agent-scoped table -- and that home is the one the enforced child is
    launched with. Whether kimi honours it there is the CLI's half, and stays
    recorded as unverified."""

    def test_an_enforced_launch_points_at_a_home_whose_deny_list_is_global(self):
        seen = {}

        def fake(cmd, **kw):
            seen["cmd"], seen["env"] = cmd, kw["env"]
            class P:
                returncode, stdout, stderr = 0, STREAM, ""
            return P()
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
            row = dataclasses.replace(hosts.HOSTS["kimi"], registration_dir=d)
            with open(os.path.join(d, "panopticon-domain-panel.md"), "w", encoding="utf-8") as fh:
                fh.write("---\nname: panopticon-domain-panel\n---\n")
            with mock.patch.dict(hosts.HOSTS, {"kimi": row}):
                r = kimi_runner.Runner("kimi", runner=fake)
                r.prepare(os.path.join(d, "run"), review_root=d)
                self.addCleanup(r.teardown, "complete")
                res = r.run_entry(_entry(True), {})
            self.assertTrue(res.ok)
            self.assertTrue(any(a.startswith("--agent-file=") for a in seen["cmd"]))
            with open(os.path.join(seen["env"]["KIMI_CODE_HOME"], "config.toml"), "rb") as fh:
                config = tomllib.load(fh)
        self.assertIn("Bash", config["tools"]["disabled"])          # top-level table
        self.assertNotIn("agents", config)                          # no per-agent override


class TestTheEntryAgentIsAllowlistedAndContained(unittest.TestCase):
    """#1720. `entry["agent"]` reaches this runner through
    `.panopticon/dispatch-request.json` -- a file inside the REVIEWED TREE --
    and `_shell_path` joined it into a filesystem path that `--agent-file=`
    then hands the CLI as the reviewer's GOVERNING INSTRUCTIONS. An absolute
    or `../` value loaded an attacker-chosen markdown file; a registered name
    symlinked out of the registration directory did the same thing one step
    later. Two rules, both fail-closed: the name must be one of the four
    registered shells, and the path it resolves to must stay inside the
    registration directory (`runners.schema.published_schema`'s containment rule,
    second application).
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.registration_dir = os.path.join(self.tmp.name, "kimi-agents")
        os.makedirs(self.registration_dir)
        self.launched = []
        self.r = _prepared(self.tmp.name, runner=self._fake())
        self.addCleanup(self.r.teardown, "complete")

    def _fake(self):
        def fake(cmd, **kw):
            self.launched.append(cmd)
            class P:
                returncode = 0
                stdout = STREAM
                stderr = ""
            return P()
        return fake

    def _run(self, agent):
        row = dataclasses.replace(hosts.HOSTS["kimi"],
                                  registration_dir=self.registration_dir)
        with mock.patch.dict(hosts.HOSTS, {"kimi": row}):
            return self.r.run_entry(dict(_entry(True), agent=agent), {})

    def _shell(self, name="panopticon-domain-panel"):
        return os.path.join(self.registration_dir, name + ".md")

    def test_a_traversal_or_foreign_agent_never_reaches_a_launch(self):
        for agent in ("../../tmp/evil", "/tmp/x", "panopticon-domain-panel-evil"):
            res = self._run(agent)
            self.assertFalse(res.ok, agent)
            self.assertIn("not a registered panopticon shell", res.error)
            self.assertIn(repr(agent), res.error)
        self.assertEqual([], self.launched)

    def test_an_enforced_entry_with_no_agent_is_refused_not_downgraded(self):
        res = self._run(None)
        self.assertFalse(res.ok)
        self.assertIn("not a registered panopticon shell", res.error)
        self.assertEqual([], self.launched)

    def test_a_json_array_or_object_agent_is_refused_rather_than_raising(self):
        # Fix round 1, item 1. The request is JSON, so `agent` can be an array
        # or an object -- and the membership test used to raise `TypeError:
        # unhashable type` out of `run_entry`, which never raises (spec 4.4).
        # It is a SECURITY refusal, not a crash.
        for agent in ([], {}, {"a": {"b": "panopticon-domain-panel"}},
                      ["panopticon-domain-panel"]):
            res = self._run(agent)
            self.assertFalse(res.ok, agent)
            self.assertIn("not a registered panopticon shell", res.error)
            self.assertIn(repr(str(agent)), res.error)
        self.assertEqual([], self.launched)

    def test_a_registered_name_whose_shell_escapes_the_directory_is_refused(self):
        outside = os.path.join(self.tmp.name, "planted.md")
        with open(outside, "w", encoding="utf-8") as fh:
            fh.write("# whatever the target wanted the reviewer to be told\n")
        os.symlink(outside, self._shell())
        res = self._run("panopticon-domain-panel")
        self.assertFalse(res.ok)
        self.assertIn("outside", res.error)
        self.assertEqual([], self.launched)

    def test_a_registered_shell_inside_the_directory_still_launches(self):
        with open(self._shell(), "w", encoding="utf-8") as fh:
            fh.write("# the registered shell\n")
        res = self._run("panopticon-domain-panel")
        self.assertTrue(res.ok, res.error)
        self.assertEqual(1, len(self.launched))
        self.assertIn("--agent-file=%s" % os.path.realpath(self._shell()),
                      self.launched[0])


class TestTheRolesTheLoopSetsReachTheKimiCheck(TestTheEntryAgentIsAllowlistedAndContained):
    """#1727, kimi's half: the name is also joined into `--agent-file=`, which
    IS the reviewer's governing instructions -- so a registered shell the
    checkpoint does not dispatch is a charter swap, refused before launch."""

    def test_a_registered_but_misrouted_shell_is_refused(self):
        self.r.roles = ("advisor", "domain_advisor")
        res = self._run("panopticon-domain-panel")
        self.assertFalse(res.ok)
        self.assertIn("not a registered panopticon shell for this checkpoint", res.error)
        self.assertIn("panopticon-advisor", res.error)
        self.assertEqual([], self.launched)

    def test_the_shell_path_refuses_a_misrouted_name_too(self):
        # `_shell_path` is the second application of the same allowlist; it
        # must narrow with the roles or the argv and the check disagree.
        self.r.roles = ("advisor",)
        self.assertIsNone(self.r._shell_path({"agent": "panopticon-domain-panel"}))
