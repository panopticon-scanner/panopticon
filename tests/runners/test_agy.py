import dataclasses
import json
import os
import subprocess
import tempfile
import unittest
from unittest import mock

import scripts.dispatch as dispatch
import scripts.hosts as hosts
import scripts.runners.agy as agy_runner
import scripts.runners.agy_home as agy_home
import scripts.runners.base as base
import scripts.runners.outage as outage


ENVELOPE = json.dumps({
    "session_id": "2c8d8cf2-070f-416c-90bf-5a1983debf98",
    "response": "the final reply",
    "stats": {
        "models": {
            "gemini-4-argon-high": {
                "api": {"totalRequests": 1, "totalErrors": 0, "totalLatencyMs": 420},
                "tokens": {"input": 100, "prompt": 140, "candidates": 25,
                           "total": 180, "cached": 40, "thoughts": 15, "tool": 0},
            }
        }
    },
})


def _entry(enforced=True, model="gemini-4-argon-high", **extra):
    out = {
        "id": "review-app-SEC",
        "role": "domain_panel",
        "agent": "panopticon-domain-panel" if enforced else None,
        "enforced": enforced,
        "model": model,
        "prompt": "<!-- panopticon-entry: review-app-SEC -->\nreview the cell",
    }
    out.update(extra)
    return out


def _fixture_user_home(root):
    home = os.path.join(root, "operator-home")
    cli_dir = os.path.join(home, ".gemini", "antigravity-cli")
    os.makedirs(cli_dir, exist_ok=True)
    with open(os.path.join(cli_dir, "antigravity-oauth-token"), "w", encoding="utf-8") as fh:
        fh.write("oauth-token-fixture")
    # Sensitive / polluting user directories that MUST NEVER be linked into run_home.
    for forbidden in ("mcp", "brain", "knowledge", "implicit", "annotations"):
        os.makedirs(os.path.join(cli_dir, forbidden), exist_ok=True)
    with open(os.path.join(cli_dir, "settings.json"), "w", encoding="utf-8") as fh:
        json.dump({"userSetting": "must-not-leak"}, fh)
    agents_dir = os.path.join(home, ".gemini", "config", "agents")
    dispatch.emit_host_agents("agy", agents_dir)
    return home, agents_dir


class TestAgyModelCatalogue(unittest.TestCase):
    def test_known_models_cover_current_catalogue_and_pending_retirements(self):
        current = {
            "gemini-4-carbon", "gemini-4-argon", "gemini-3.8-flash",
            "gemini-3.7-flash", "gemini-3.6-flash", "gemini-3.1-pro-preview",
            "claude-sonnet-5-5", "claude-opus-5-5",
            *("claude-sonnet-5-5-%s" % level for level in ("low", "medium", "high", "max")),
            *("claude-opus-5-5-%s" % level for level in ("low", "medium", "high", "max")),
        }
        self.assertTrue(current.issubset(agy_runner.KNOWN_MODELS))
        self.assertTrue({"claude-sonnet-4-6", "claude-opus-4-6-thinking",
                         "gpt-oss-120b-medium"}.issubset(agy_runner.KNOWN_MODELS))


class TestAgyHomeIsolationAndGitCeiling(unittest.TestCase):
    """Changes 1, 2, and 3: minimal auth link, Git ceiling in <run_home>/workspace,
    and single '*' PreToolUse matcher."""

    def test_build_links_only_oauth_token_and_agents_and_creates_git_ceiling(self):
        with tempfile.TemporaryDirectory() as d:
            user_home, agents_dir = _fixture_user_home(d)
            run_home = agy_home.build(
                "/s.json", "/w.json",
                user_home=user_home, registration_dir=agents_dir)
            workspace_dir = agy_home.workspace_dir(run_home)
            self.addCleanup(agy_home.teardown, run_home, "complete")

            cli_dir = os.path.join(run_home, ".gemini", "antigravity-cli")
            self.assertEqual(sorted(os.listdir(cli_dir)),
                             ["antigravity-oauth-token", "settings.json"])
            self.assertTrue(os.path.islink(os.path.join(cli_dir, "antigravity-oauth-token")))
            self.assertFalse(os.path.islink(os.path.join(cli_dir, "settings.json")))
            with open(os.path.join(cli_dir, "settings.json"), encoding="utf-8") as fh:
                self.assertEqual(
                    {"agentMode": "accept-edits", "allowNonWorkspaceAccess": True},
                    json.load(fh))

            config_dir = os.path.join(run_home, ".gemini", "config")
            self.assertEqual(sorted(os.listdir(config_dir)), ["agents", "hooks.json"])
            self.assertTrue(os.path.islink(os.path.join(config_dir, "agents")))
            with open(os.path.join(config_dir, "hooks.json"), encoding="utf-8") as fh:
                hooks_doc = json.load(fh)
            pre = hooks_doc["panopticon-guard"]["PreToolUse"]
            self.assertEqual(len(pre), 1)
            self.assertEqual(pre[0]["matcher"], "*")
            self.assertEqual(pre[0]["hooks"][0]["timeout"], 30)

            git_dir = os.path.join(workspace_dir, ".git")
            self.assertTrue(os.path.isdir(os.path.join(git_dir, "objects")))
            self.assertTrue(os.path.isdir(os.path.join(git_dir, "refs")))
            with open(os.path.join(git_dir, "HEAD"), encoding="utf-8") as fh:
                self.assertEqual("ref: refs/heads/main\n", fh.read())

    def test_prepare_creates_git_ceiling_and_teardown_strips_secrets_on_failure(self):
        with tempfile.TemporaryDirectory() as d:
            user_home, agents_dir = _fixture_user_home(d)
            runner = agy_runner.Runner("agy")
            with mock.patch.dict(os.environ, {"HOME": user_home}):
                runner.prepare(d, os.path.join(d, "run"), registration_dir=agents_dir)
            run_home = runner.run_home
            self.assertTrue(os.path.isfile(os.path.join(runner.workspace_dir, ".git", "HEAD")))

            runner.teardown("failed")
            self.assertTrue(os.path.isdir(run_home))
            cli_dir = os.path.join(run_home, ".gemini", "antigravity-cli")
            self.assertFalse(os.path.lexists(os.path.join(cli_dir, "antigravity-oauth-token")))
            self.assertFalse(os.path.lexists(os.path.join(run_home, ".gemini", "config", "agents")))
            self.assertTrue(os.path.isfile(os.path.join(run_home, ".gemini", "config", "hooks.json")))
            agy_home.teardown(run_home, "complete")
            self.assertFalse(os.path.exists(run_home))


class TestCommand(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        user_home, agents_dir = _fixture_user_home(self.tmp.name)
        self.r = agy_runner.Runner("agy")
        with mock.patch.dict(os.environ, {"HOME": user_home}):
            self.r.prepare(self.tmp.name, os.path.join(self.tmp.name, "run"),
                           registration_dir=agents_dir)
        self.addCleanup(self.r.teardown, "complete")

    def test_enforced_entry_passes_agent_model_and_disable_slash_commands(self):
        cmd = self.r.command(_entry(True), "gemini-4-argon-high")
        self.assertEqual(cmd[0], "agy")
        self.assertIn("--output-format", cmd)
        self.assertIn("json", cmd)
        self.assertIn("--disable-slash-commands", cmd)
        self.assertIn("--agent", cmd)
        self.assertIn("panopticon-domain-panel", cmd)
        self.assertIn("--model", cmd)
        self.assertIn("gemini-4-argon-high", cmd)
        self.assertEqual(cmd[-2:], ["-p", _entry(True)["prompt"]])

    def test_unenforced_entry_omits_agent_flag(self):
        cmd = self.r.command(_entry(False), "gemini-4-argon-high")
        self.assertNotIn("--agent", cmd)
        self.assertIn("gemini-4-argon-high", cmd)

    def test_carbon_at_high_passes_effort_as_its_own_argument(self):
        # #3564: the exact argv, `--effort` right after `--model`, never a `-high` slug.
        entry = _entry(True, model="gemini-4-carbon", effort="high")
        self.assertEqual(self.r.command(entry, "gemini-4-carbon"), [
            "agy", "--output-format", "json", "--disable-slash-commands",
            "--agent", "panopticon-domain-panel", "--model", "gemini-4-carbon",
            "--effort", "high", "-p", entry["prompt"]])

    def test_every_documented_level_is_passed(self):
        for level in agy_runner.AGY_EFFORTS:
            with self.subTest(level=level):
                cmd = self.r.command(_entry(True, model="gemini-4-carbon", effort=level),
                                     "gemini-4-carbon")
                self.assertEqual(["--effort", level],
                                 cmd[cmd.index("--effort"):cmd.index("--effort") + 2])

    def test_no_effort_means_no_flag_even_on_an_effort_named_slug(self):
        # The scout/advisor default ends in `-medium`; with no effort it still passes.
        for model in ("gemini-3.8-flash-medium", "gemini-4-carbon", "gemini-4-argon-high"):
            with self.subTest(model=model):
                self.assertNotIn("--effort", self.r.command(_entry(True, model=model), model))

    def test_a_bad_effort_is_refused(self):
        for model, effort, why in (
                ("gemini-4-carbon", "turbo", "is not one of"),
                ("gemini-4-carbon", "High", "is not one of"),
                ("gemini-4-carbon", "", "is not one of"),
                ("gemini-4-carbon", "--help", "is not one of"),
                ("gemini-4-carbon", 3, "is not one of"),
                ("gemini-4-argon-high", "high", "already names an effort"),
                ("gemini-3.8-flash-medium", "low", "already names an effort"),
                ("gemini-4-carbon-xhigh", "high", "already names an effort")):
            with self.subTest(model=model, effort=effort):
                with self.assertRaisesRegex(ValueError, why):
                    self.r.command(_entry(True, model=model, effort=effort), model)

    def test_an_effort_with_no_model_is_refused(self):
        with self.assertRaisesRegex(ValueError, "has no model to apply to"):
            self.r.command(_entry(True, model=None, effort="high"), None)

    def test_output_schema_flag_passed_when_present(self):
        schema_path = os.path.abspath(os.path.join(
            os.path.dirname(agy_runner.__file__),
            "..", "..", "reference", "probe-output-schema.json"))
        entry = _entry(True, output_schema=schema_path)
        cmd = self.r.command(entry, "gemini-4-argon-high")
        idx = cmd.index("--json-schema")
        self.assertTrue(cmd[idx + 1].startswith("{"))


class TestParseEnvelope(unittest.TestCase):
    def test_extracts_response_session_id_usage_and_model(self):
        r = agy_runner.Runner("agy")
        res = r.parse_envelope("e1", ENVELOPE, 0)
        self.assertTrue(res.ok)
        self.assertEqual(res.text, "the final reply")
        self.assertEqual(res.session_id, "2c8d8cf2-070f-416c-90bf-5a1983debf98")
        self.assertEqual(res.model, "gemini-4-argon-high")
        self.assertIsNone(res.cost_usd)
        self.assertEqual(res.usage, {
            "input_tokens": 100,
            "output_tokens": 25,
            "cache_read_input_tokens": 40,
            "cache_creation_input_tokens": 0,
            "cache_read_tokens": 40,
            "thinking_tokens": 15,
            "total_tokens": 180,
        })

    def test_nonzero_exit_reports_stderr_and_redacts_secrets(self):
        r = agy_runner.Runner("agy")
        res = r.parse_envelope(
            "e1", "", 1, stderr="Error: 429 rate limit exceeded sk-ant-api03-AAAABBBBCCCC\n")
        self.assertFalse(res.ok)
        self.assertIn("429 rate limit", res.error)
        self.assertNotIn("sk-ant-", res.stderr)
        self.assertEqual(outage.HOST_FAILURE, res.failure_class)


class TestRunEntry(unittest.TestCase):
    def _env(self):
        return {base.ENV_ENTRY_ID: "review-app-SEC",
                base.ENV_WRITE_ALLOWLIST: "/w.json",
                base.ENV_READ_SCOPE: "/s.json"}

    def _fake_run(self, seen):
        def fake(cmd, **kw):
            seen["cmd"], seen["kw"] = cmd, kw
            return subprocess.CompletedProcess(cmd, 0, stdout=ENVELOPE, stderr="")
        return fake

    def test_run_entry_uses_isolated_home_and_workspace_cwd(self):
        seen = {}
        with tempfile.TemporaryDirectory() as d:
            user_home, agents_dir = _fixture_user_home(d)
            with mock.patch.dict(os.environ, {"PATH": "/p", "HOME": user_home,
                                              "ANTIGRAVITY_CLI": "1",
                                              "ANTIGRAVITY_CLI_ALIAS": "agy"},
                                 clear=True):
                r = agy_runner.Runner("agy", runner=self._fake_run(seen))
                r.prepare(d, os.path.join(d, "run"), registration_dir=agents_dir)
                self.addCleanup(r.teardown, "complete")
                res = r.run_entry(_entry(True), self._env())
        self.assertTrue(res.ok)
        self.assertEqual(res.text, "the final reply")
        self.assertEqual(res.model, "gemini-4-argon-high")
        self.assertEqual(res.usage["input_tokens"], 100)
        child_env = seen["kw"]["env"]
        self.assertEqual(child_env["HOME"], r.run_home)
        self.assertNotIn("ANTIGRAVITY_CLI", child_env)
        self.assertNotIn("ANTIGRAVITY_CLI_ALIAS", child_env)
        self.assertEqual(child_env[base.ENV_ENTRY_ID], "review-app-SEC")
        self.assertEqual(seen["kw"]["cwd"], r.workspace_dir)

    def test_enforced_entry_without_registered_shell_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            user_home, _ = _fixture_user_home(d)
            empty_reg = os.path.join(d, "empty-agents")
            os.makedirs(empty_reg, exist_ok=True)
            row = dataclasses.replace(hosts.HOSTS["agy"], registration_dir=empty_reg)
            with mock.patch.dict(hosts.HOSTS, {"agy": row}), \
                    mock.patch.dict(os.environ, {"HOME": user_home}):
                r = agy_runner.Runner("agy", runner=self._fake_run({}))
                r.prepare(d, os.path.join(d, "run"), registration_dir=empty_reg)
                self.addCleanup(r.teardown, "complete")
                res = r.run_entry(_entry(True), self._env())
        self.assertFalse(res.ok)
        self.assertIn("not registered", res.error)

    def test_unresolvable_model_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            user_home, agents_dir = _fixture_user_home(d)
            with mock.patch.dict(os.environ, {"HOME": user_home}):
                r = agy_runner.Runner("agy", runner=self._fake_run({}))
                r.prepare(d, os.path.join(d, "run"), registration_dir=agents_dir)
                self.addCleanup(r.teardown, "complete")
                res = r.run_entry(_entry(False, model="bogus-model"), self._env())
        self.assertFalse(res.ok)
        self.assertIn("not in agy's known model catalogue", res.error)

    def test_a_bad_effort_fails_the_entry_before_any_launch(self):
        # #3564: refused by name in run_entry, not as a "launch raised" crash.
        for model, effort, why in (("gemini-4-carbon", "turbo", "is not one of"),
                                   ("gemini-4-argon-high", "high", "already names an effort")):
            with self.subTest(effort=effort), tempfile.TemporaryDirectory() as d:
                user_home, agents_dir = _fixture_user_home(d)
                seen = {}
                with mock.patch.dict(os.environ, {"HOME": user_home}):
                    r = agy_runner.Runner("agy", runner=self._fake_run(seen))
                    r.prepare(d, os.path.join(d, "run"), registration_dir=agents_dir)
                    self.addCleanup(r.teardown, "complete")
                    res = r.run_entry(_entry(False, model=model, effort=effort), self._env())
                self.assertFalse(res.ok)
                self.assertIn(why, res.error)
                self.assertNotIn("launch raised", res.error)
                self.assertEqual({}, seen)

    def test_run_entry_launches_carbon_with_its_effort(self):
        seen = {}
        with tempfile.TemporaryDirectory() as d:
            user_home, agents_dir = _fixture_user_home(d)
            with mock.patch.dict(os.environ, {"HOME": user_home}):
                r = agy_runner.Runner("agy", runner=self._fake_run(seen))
                r.prepare(d, os.path.join(d, "run"), registration_dir=agents_dir)
                self.addCleanup(r.teardown, "complete")
                r.run_entry(_entry(False, model="gemini-4-carbon", effort="high"), self._env())
        cmd = seen["cmd"]
        self.assertEqual(["--model", "gemini-4-carbon", "--effort", "high"],
                         cmd[cmd.index("--model"):cmd.index("--model") + 4])

    def test_timeout_returns_failed_result_with_partial_output(self):
        def slow(cmd, **kw):
            raise subprocess.TimeoutExpired(
                cmd, kw.get("timeout"), output=b"partial reply", stderr=b"timeout err")

        with tempfile.TemporaryDirectory() as d:
            user_home, agents_dir = _fixture_user_home(d)
            with mock.patch.dict(os.environ, {"HOME": user_home}):
                r = agy_runner.Runner("agy", runner=slow)
                r.prepare(d, os.path.join(d, "run"), registration_dir=agents_dir)
                self.addCleanup(r.teardown, "complete")
                res = r.run_entry(_entry(False), self._env())
        self.assertFalse(res.ok)
        self.assertIn("timed out after", res.error)
        self.assertEqual("partial reply", res.text)
        self.assertIn("timeout err", res.stderr)
        self.assertIsNone(res.model)

    def test_run_entry_leaves_model_none_when_envelope_reports_no_model(self):
        no_model_envelope = json.dumps({
            "conversation_id": "conv-no-model",
            "status": "SUCCESS",
            "response": "ok",
            "usage": {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
        })

        def fake(cmd, **kw):
            return subprocess.CompletedProcess(cmd, 0, stdout=no_model_envelope, stderr="")

        with tempfile.TemporaryDirectory() as d:
            user_home, agents_dir = _fixture_user_home(d)
            with mock.patch.dict(os.environ, {"HOME": user_home}):
                r = agy_runner.Runner("agy", runner=fake)
                r.prepare(d, os.path.join(d, "run"), registration_dir=agents_dir)
                self.addCleanup(r.teardown, "complete")
                res = r.run_entry(_entry(True, model="gemini-4-argon-high"), self._env())
        self.assertTrue(res.ok)
        self.assertIsNone(res.model)
        self.assertEqual(res.usage["total_tokens"], 15)


if __name__ == "__main__":
    unittest.main()
