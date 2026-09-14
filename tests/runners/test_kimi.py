import dataclasses
import json
import os
import subprocess
import tempfile
import tomllib
import unittest
from unittest import mock

import scripts.hosts as hosts
import scripts.kimi_guard_hook as kimi_guard_hook
import scripts.runners.base as base
import scripts.runners.kimi as kimi_runner

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
                home = r.kimi_home
                self.assertEqual(home, os.path.join(run_dir, "kimi-home"))
                self.assertTrue(os.path.islink(os.path.join(home, "credentials")))
                self.assertEqual(os.readlink(os.path.join(home, "credentials")),
                                 os.path.join(fixture, "credentials"))
                with open(os.path.join(home, "config.toml"), "rb") as fh:
                    config = tomllib.load(fh)
                self.assertFalse(config["merge_all_available_skills"])
                self.assertFalse(config["builtin_product_skills"])
                for tool in ("Bash", "Agent", "AgentSwarm"):
                    self.assertIn(tool, config["tools"]["disabled"])
                hooks = config["hooks"]
                self.assertEqual(len(hooks), 2)
                matchers = sorted(h["matcher"] for h in hooks)
                self.assertEqual(matchers, ["Read|Grep|Glob", "Write|Edit"])
                for h in hooks:
                    self.assertIn(os.path.abspath(kimi_guard_hook.__file__), h["command"])
                self.assertIn(os.path.join(run_dir, "read-scope.json"),
                              [h["command"] for h in hooks if h["matcher"] == "Read|Grep|Glob"][0])
                self.assertIn(os.path.join(run_dir, "write-allowlist.json"),
                              [h["command"] for h in hooks if h["matcher"] == "Write|Edit"][0])
                # the fixture's own values survive the merge
                self.assertEqual(config["models"]["kimi-code/k3"]["model"], "k3")
                self.assertEqual(r.configured, {"kimi-code/k3", "kimi-code/kimi-for-coding"})
                r.prepare(run_dir, review_root=d)                 # idempotent
                with open(os.path.join(home, "config.toml"), "rb") as fh:
                    self.assertEqual(config, tomllib.load(fh))

    def test_a_source_config_with_hooks_keeps_them(self):
        with tempfile.TemporaryDirectory() as d:
            fixture = _fixture_home(d)
            with open(os.path.join(fixture, "config.toml"), "a", encoding="utf-8") as fh:
                fh.write('\n[[hooks]]\nevent = "Stop"\ncommand = "true"\n')
            with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": fixture}):
                r = kimi_runner.Runner("kimi")
                r.prepare(os.path.join(d, "run"), review_root=d)
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
        back = tomllib.loads(kimi_runner.dump_toml(config))
        self.assertEqual(back, config)

    def test_keys_that_are_not_bare_are_quoted(self):
        back = tomllib.loads(kimi_runner.dump_toml({"models": {"kimi-code/k3": {"model": "k3"}}}))
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

    def test_usage_and_model_come_back_from_the_wire_file(self):
        seen = {}
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
            r = kimi_runner.Runner("kimi", runner=self._fake_run(seen))
            r.prepare(os.path.join(d, "run"), review_root=d)
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
                res = r.run_entry(_entry(True), self._env())
        self.assertFalse(res.ok)
        self.assertIn("not registered", res.error)

    def test_an_unresolvable_entry_model_fails_closed(self):
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
            r = kimi_runner.Runner("kimi", runner=self._fake_run({}))
            r.prepare(os.path.join(d, "run"), review_root=d)
            res = r.run_entry(_entry(False, model="bogus-tier"), self._env())
        self.assertFalse(res.ok)
        self.assertIn("does not resolve", res.error)

    def test_a_timeout_or_launch_failure_is_a_failed_result(self):
        def boom(cmd, **kw):
            raise subprocess.TimeoutExpired(cmd, kw.get("timeout"))
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
            r = kimi_runner.Runner("kimi", runner=boom)
            r.prepare(os.path.join(d, "run"), review_root=d)
            res = r.run_entry(_entry(False), {})
        self.assertFalse(res.ok)
        self.assertIn("timed out", res.error)

        def missing(cmd, **kw):
            raise FileNotFoundError("kimi")
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
            r = kimi_runner.Runner("kimi", runner=missing)
            r.prepare(os.path.join(d, "run"), review_root=d)
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
