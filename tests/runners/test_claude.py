import json
import os
import tempfile
import unittest
from unittest import mock

import scripts.read_guard_hook as read_guard_hook
import scripts.runners.base as base
import scripts.runners.claude as claude_runner
import scripts.write_guard_hook as write_guard_hook

ENVELOPE = {"type": "result", "subtype": "success", "is_error": False,
            "result": "```json\n{\"domains\": []}\n```", "session_id": "sess-1",
            "num_turns": 3, "duration_ms": 1234, "total_cost_usd": 0.019,
            "usage": {"input_tokens": 10, "output_tokens": 5,
                      "cache_read_input_tokens": 100, "cache_creation_input_tokens": 0},
            "modelUsage": {"claude-haiku-4-5-20251001": {"inputTokens": 10}},
            "permission_denials": [{"tool_name": "Glob", "reason": "denied"}]}


def _entry(enforced, model="claude-sonnet-5"):
    return {"id": "review-app-SEC", "agent": "panopticon-domain-panel" if enforced else None,
            "enforced": enforced, "model": model, "prompt": "panopticon-entry: review-app-SEC\nReview.",
            "out_file": "/r/.panopticon/runs/t/findings-app-SEC.json"}


class TestCommand(unittest.TestCase):
    def setUp(self):
        self.r = claude_runner.Runner("claude")

    def test_enforced_entry_passes_agent_and_never_model(self):
        cmd = self.r.command(_entry(True), "/run/host-settings.json", max_turns=40)
        self.assertEqual(cmd[:2], ["claude", "-p"])
        for flag in ("--settings", "/run/host-settings.json", "--output-format", "json",
                     "--no-session-persistence", "--max-turns", "40", "--agent", "panopticon-domain-panel"):
            self.assertIn(flag, cmd)
        self.assertNotIn("--model", cmd)
        self.assertEqual(cmd[-1], _entry(True)["prompt"])         # the prompt is the last argv, inline

    def test_unenforced_entry_passes_model_and_no_agent(self):
        cmd = self.r.command(_entry(False), "/run/host-settings.json", max_turns=40)
        self.assertIn("--model", cmd); self.assertIn("claude-sonnet-5", cmd)
        self.assertNotIn("--agent", cmd)

    def test_unbound_model_passes_neither(self):
        cmd = self.r.command(_entry(False, model=None), "/run/host-settings.json", max_turns=40)
        self.assertNotIn("--model", cmd); self.assertNotIn("--agent", cmd)

    def test_the_envelope_flags_are_on_every_argv(self):
        # ENVELOPE_FLAGS is the runner's own spelling of what makes a launch
        # print the envelope, read by the usage probe; a flag listed there
        # that `command` does not put on the argv would have the probe
        # proving a launch shape nothing uses.
        for enforced in (True, False):
            cmd = self.r.command(_entry(enforced), "/s.json", max_turns=40)
            for flag in claude_runner.Runner.ENVELOPE_FLAGS:
                with self.subTest(enforced=enforced, flag=flag):
                    self.assertIn(flag, cmd)
        self.assertEqual(("-p", "--output-format"), claude_runner.Runner.ENVELOPE_FLAGS)

    def test_no_per_entry_budget_arm_exists(self):
        # M3 (final review): `--max-budget-usd` is a WHOLE-RUN knob the loop
        # enforces off its own ledger (spec 4.3). `command` carried a
        # per-entry budget parameter nothing ever set, so the flag it built
        # could never reach a real launch -- dead weight that reads like a
        # live per-entry cap.
        cmd = self.r.command(_entry(True), "/s.json", max_turns=40)
        self.assertNotIn("--max-budget-usd", cmd)
        self.assertFalse(hasattr(self.r, "per_entry_budget_usd"))


class TestEnvelope(unittest.TestCase):
    def test_a_success_envelope_becomes_an_ok_result(self):
        res = claude_runner.Runner("claude").parse_envelope("e1", json.dumps(ENVELOPE), 0)
        self.assertTrue(res.ok)
        self.assertEqual(res.text, ENVELOPE["result"])
        self.assertEqual(res.usage["input_tokens"], 10)
        self.assertEqual(res.cost_usd, 0.019)
        self.assertEqual(res.model, "claude-haiku-4-5-20251001")
        self.assertEqual(res.session_id, "sess-1")
        self.assertEqual(res.denials, ENVELOPE["permission_denials"])
        self.assertIsNone(res.error)

    def test_is_error_and_nonzero_exit_and_non_json_are_failures(self):
        r = claude_runner.Runner("claude")
        bad = dict(ENVELOPE, is_error=True, result="quota exhausted")
        self.assertFalse(r.parse_envelope("e1", json.dumps(bad), 0).ok)
        self.assertIn("quota", r.parse_envelope("e1", json.dumps(bad), 0).error)
        self.assertFalse(r.parse_envelope("e1", json.dumps(ENVELOPE), 2).ok)
        res = r.parse_envelope("e1", "not json at all", 0)
        self.assertFalse(res.ok); self.assertIn("JSON", res.error)


class TestRunEntry(unittest.TestCase):
    def test_run_entry_inherits_the_process_environment_and_overlays_the_bindings(self):
        # C1 (final review): `env_for` is a three-key OVERLAY, not a whole
        # environment. A runner that only FILTERED it launched `claude` with
        # no PATH and no HOME -- FileNotFoundError on every entry, for the
        # whole run. The previous version of this test hand-supplied HOME in
        # `env` and then asserted HOME came back, so it asserted a mock
        # against itself and stayed green with the filter-only line. This one
        # clears os.environ to a known fixture and requires the inherited
        # keys -- which are NOT in `env` -- to reach the child.
        seen = {}
        def fake_run(cmd, **kw):
            seen["cmd"], seen["kw"] = cmd, kw
            class P: returncode = 0; stdout = json.dumps(ENVELOPE); stderr = ""
            return P()
        env = {base.ENV_ENTRY_ID: "review-app-SEC",
               base.ENV_WRITE_ALLOWLIST: "/w.json", base.ENV_READ_SCOPE: "/s.json"}
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.dict(os.environ, {"PATH": "/p", "HOME": "/h", "CLAUDECODE": "1"},
                             clear=True):
            r = claude_runner.Runner("claude", runner=fake_run)
            r.prepare(d, review_root=d)
            r.max_turns = 12
            res = r.run_entry(_entry(True), env)
        self.assertTrue(res.ok)
        self.assertEqual(seen["kw"]["cwd"], d)
        child_env = seen["kw"]["env"]
        self.assertEqual(child_env["PATH"], "/p")        # inherited, never in `env`
        self.assertEqual(child_env["HOME"], "/h")        # inherited, never in `env`
        self.assertNotIn("CLAUDECODE", child_env)        # a nested `claude -p` refuses to start
        self.assertEqual(child_env[base.ENV_ENTRY_ID], "review-app-SEC")
        self.assertEqual(child_env[base.ENV_WRITE_ALLOWLIST], "/w.json")
        self.assertEqual(child_env[base.ENV_READ_SCOPE], "/s.json")
        self.assertIn("--max-turns", seen["cmd"]); self.assertIn("12", seen["cmd"])
        self.assertEqual(seen["kw"]["timeout"], r.entry_timeout)

    def test_a_timeout_or_launch_failure_is_a_failed_result(self):
        import subprocess
        def boom(cmd, **kw):
            raise subprocess.TimeoutExpired(cmd, kw.get("timeout"))
        with tempfile.TemporaryDirectory() as d:
            r = claude_runner.Runner("claude", runner=boom); r.prepare(d, review_root=d)
            res = r.run_entry(_entry(True), {})
        self.assertFalse(res.ok); self.assertIn("timed out", res.error)
        def missing(cmd, **kw):
            raise FileNotFoundError("claude")
        with tempfile.TemporaryDirectory() as d:
            r = claude_runner.Runner("claude", runner=missing); r.prepare(d, review_root=d)
            res = r.run_entry(_entry(True), {})
        self.assertFalse(res.ok); self.assertIn("claude", res.error)

    def test_any_other_launch_exception_is_a_failed_result(self):
        def bad_args(cmd, **kw):
            raise ValueError("bad args")
        with tempfile.TemporaryDirectory() as d:
            r = claude_runner.Runner("claude", runner=bad_args); r.prepare(d, review_root=d)
            res = r.run_entry(_entry(True), {})
        self.assertFalse(res.ok)
        self.assertIn("ValueError", res.error)


class TestPrepare(unittest.TestCase):
    def test_prepare_writes_both_guard_hooks_with_absolute_paths_and_nothing_else(self):
        with tempfile.TemporaryDirectory() as d:
            r = claude_runner.Runner("claude")
            r.prepare(d, review_root=d)
            path = os.path.join(d, base.SETTINGS_FILE)
            with open(path, encoding="utf-8") as fh:
                settings = json.load(fh)
            self.assertEqual(sorted(settings), ["hooks"])
            pre = settings["hooks"]["PreToolUse"]
            self.assertEqual(len(pre), 2)
            self.assertIn(write_guard_hook._hook_entry(os.path.join(d, "write-allowlist.json")), pre)
            self.assertIn(read_guard_hook._hook_entry(os.path.join(d, "read-scope.json")), pre)
            self.assertEqual(r.settings_path, path)
            self.assertEqual(r.allowlist_path, os.path.join(d, "write-allowlist.json"))
            self.assertEqual(r.scope_path, os.path.join(d, "read-scope.json"))
            r.prepare(d, review_root=d)                              # idempotent
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(settings, json.load(fh))

    def test_prepare_never_writes_through_a_symlinked_tmp(self):
        # I7 (plan 6 final review): `prepare` staged host-settings.json at
        # `<path>.tmp` with a plain open(), INSIDE the scanned tree. A redteam
        # target can commit that exact name as a symlink to anything the
        # invoking user can write, and the runner would have written the
        # settings JSON straight through it.
        with tempfile.TemporaryDirectory() as d:
            outside = os.path.join(d, "outside.txt")
            with open(outside, "w", encoding="utf-8") as fh:
                fh.write("PRECIOUS")
            settings = os.path.join(d, base.SETTINGS_FILE)
            os.symlink(outside, settings + ".tmp")
            claude_runner.Runner("claude").prepare(d, review_root=d)
            with open(outside, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "PRECIOUS")
            self.assertFalse(os.path.islink(settings))
            self.assertTrue(os.path.isfile(settings))
            with open(settings, encoding="utf-8") as fh:
                self.assertEqual(len(json.load(fh)["hooks"]["PreToolUse"]), 2)
            self.assertFalse(os.path.exists(settings + ".tmp"))


class TestTheSuiteNeverLaunchesTheRealCli(unittest.TestCase):
    def test_a_runner_built_without_a_fake_refuses_to_launch(self):
        # Structural, not per-test discipline (family guardrails section 3,
        # #1616): conftest swaps the module's DEFAULT_RUNNER for a refusal, so a
        # Runner that nobody handed a fake fails its launch loudly instead of
        # spending money -- and run_entry's never-raise contract turns that
        # refusal into a failed RunResult naming the rule.
        with tempfile.TemporaryDirectory() as d:
            r = claude_runner.Runner("claude")
            r.prepare(d, review_root=d)
            res = r.run_entry(_entry(True), {})
        self.assertFalse(res.ok)
        self.assertIn("never launch the real", res.error)

    def test_an_injected_runner_is_used_verbatim(self):
        def fake(cmd, **kw):
            raise AssertionError("unreachable")
        self.assertIs(fake, claude_runner.Runner("claude", runner=fake).runner)
