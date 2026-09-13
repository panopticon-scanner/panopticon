import json
import os
import tempfile
import unittest

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

    def test_per_entry_budget_is_passed_when_set(self):
        cmd = self.r.command(_entry(True), "/s.json", max_turns=40, budget_usd=0.5)
        self.assertIn("--max-budget-usd", cmd); self.assertIn("0.5", cmd)


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
    def test_run_entry_invokes_the_cli_in_the_review_root_with_the_bindings_and_without_claudecode(self):
        seen = {}
        def fake_run(cmd, **kw):
            seen["cmd"], seen["kw"] = cmd, kw
            class P: returncode = 0; stdout = json.dumps(ENVELOPE); stderr = ""
            return P()
        with tempfile.TemporaryDirectory() as d:
            r = claude_runner.Runner("claude", runner=fake_run)
            r.prepare(d, review_root=d)
            r.max_turns = 12
            env = {"CLAUDECODE": "1", "HOME": "/h", base.ENV_ENTRY_ID: "review-app-SEC",
                   base.ENV_WRITE_ALLOWLIST: "/w.json", base.ENV_READ_SCOPE: "/s.json"}
            res = r.run_entry(_entry(True), env)
        self.assertTrue(res.ok)
        self.assertEqual(seen["kw"]["cwd"], d)
        self.assertNotIn("CLAUDECODE", seen["kw"]["env"])
        self.assertEqual(seen["kw"]["env"][base.ENV_ENTRY_ID], "review-app-SEC")
        self.assertEqual(seen["kw"]["env"]["HOME"], "/h")
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
