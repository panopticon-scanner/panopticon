import contextlib
import dataclasses
import io
import json
import os
import re
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

import scripts.dispatch as dispatch
import scripts.hosts as hosts
import scripts.ledger as ledger
import scripts.runners.base as base
import scripts.runners.gemini as gemini_runner
import scripts.runners.gemini_home as gemini_home
import scripts.runners.outage as outage


ENVELOPE = json.dumps({
    "session_id": "2c8d8cf2-070f-416c-90bf-5a1983debf98",
    "response": "the final reply",
    "stats": {
        "models": {
            "gemini-3.6-flash": {
                "api": {"totalRequests": 1, "totalErrors": 0, "totalLatencyMs": 420},
                "tokens": {"input": 100, "prompt": 140, "candidates": 25,
                           "total": 180, "cached": 40, "thoughts": 15, "tool": 0},
            }
        }
    },
})


def _entry(enforced=True, model="gemini-3.6-flash", **extra):
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
    gemini_dir = os.path.join(home, ".gemini")
    os.makedirs(gemini_dir, exist_ok=True)
    with open(os.path.join(gemini_dir, "oauth_creds.json"), "w", encoding="utf-8") as fh:
        json.dump({"refresh_token": "SECRET_REFRESH_TOKEN_VALUE_12345"}, fh)
    with open(os.path.join(gemini_dir, "google_accounts.json"), "w", encoding="utf-8") as fh:
        json.dump({"active": "operator@example.com"}, fh)
    # Non-auth / ambient files and directories that MUST NEVER be copied into run_home (P5).
    for non_auth in ("state.json", "installation_id", "GEMINI.md"):
        with open(os.path.join(gemini_dir, non_auth), "w", encoding="utf-8") as fh:
            fh.write("must-not-seed-%s" % non_auth)
    for forbidden_dir in ("mcp", "extensions", "skills", "agents", "policies"):
        os.makedirs(os.path.join(gemini_dir, forbidden_dir), exist_ok=True)
    with open(os.path.join(gemini_dir, "settings.json"), "w", encoding="utf-8") as fh:
        json.dump({
            "userSetting": "must-not-leak",
            "security": {"auth": {"selectedType": "oauth-personal"}},
        }, fh)
    agents_dir = os.path.join(home, ".gemini", "cli-agents")
    dispatch.emit_host_agents("gemini", agents_dir)
    return home, agents_dir


class TestGeminiHomeCredentialSeedHygiene(unittest.TestCase):
    """P5: Credential-seed hygiene in `gemini_home.py`."""

    def test_run_home_is_outside_review_root_and_outside_panopticon_with_0700_mode(self):
        with tempfile.TemporaryDirectory() as d:
            review_root = os.path.join(d, "target-repo")
            os.makedirs(review_root, exist_ok=True)
            user_home, _agents_dir = _fixture_user_home(d)
            run_home = gemini_home.build(
                "/s.json", "/w.json",
                user_home=user_home,
                review_root=review_root)
            self.addCleanup(gemini_home.teardown, run_home, "complete")

            self.assertFalse(gemini_home._inside(run_home, review_root))
            self.assertNotIn(".panopticon", run_home)
            self.assertEqual(0o700, stat.S_IMODE(os.stat(run_home).st_mode))
            gemini_dir = os.path.join(run_home, ".gemini")
            self.assertEqual(0o700, stat.S_IMODE(os.stat(gemini_dir).st_mode))

    def test_copies_only_oauth_creds_and_google_accounts_with_0600_mode_and_excludes_state_and_installation_id(self):
        with tempfile.TemporaryDirectory() as d:
            user_home, _agents_dir = _fixture_user_home(d)
            with mock.patch.dict(os.environ, {}, clear=True):
                run_home = gemini_home.build(
                    "/s.json", "/w.json",
                    user_home=user_home)
            self.addCleanup(gemini_home.teardown, run_home, "complete")

            gemini_dir = os.path.join(run_home, ".gemini")
            self.assertEqual(
                sorted(os.listdir(gemini_dir)),
                ["google_accounts.json", "oauth_creds.json", "policies", "settings.json"],
            )
            for excluded in ("state.json", "installation_id", "GEMINI.md",
                             "mcp", "extensions", "skills", "agents"):
                self.assertFalse(
                    os.path.lexists(os.path.join(gemini_dir, excluded)),
                    "%s must not be seeded into <run_home>/.gemini" % excluded)
            for cred in gemini_home.CREDENTIAL_FILES:
                cred_path = os.path.join(gemini_dir, cred)
                self.assertFalse(os.path.islink(cred_path))
                self.assertEqual(0o600, stat.S_IMODE(os.stat(cred_path).st_mode))
            settings_path = os.path.join(gemini_dir, "settings.json")
            self.assertEqual(0o600, stat.S_IMODE(os.stat(settings_path).st_mode))
            with open(settings_path, encoding="utf-8") as fh:
                settings_doc = json.load(fh)
            self.assertNotIn("userSetting", settings_doc)
            self.assertEqual(settings_doc["mcpServers"], {})
            self.assertEqual(settings_doc["mcp"]["allowed"], [])
            self.assertIs(False, settings_doc["skills"]["enabled"])
            self.assertNotIn("fileName", settings_doc["context"])
            self.assertEqual(
                settings_doc["security"]["auth"]["selectedType"], "oauth-personal")
            before = settings_doc["hooks"]["BeforeTool"]
            self.assertEqual(len(before), 1)
            self.assertEqual(before[0]["matcher"], "*")

    def test_refuses_symlinked_and_fifo_credential_files(self):
        with tempfile.TemporaryDirectory() as d:
            user_home, _agents_dir = _fixture_user_home(d)
            oauth_path = os.path.join(user_home, ".gemini", "oauth_creds.json")
            os.unlink(oauth_path)
            target_secret = os.path.join(d, "outside-secret.json")
            with open(target_secret, "w", encoding="utf-8") as fh:
                fh.write("{}")
            os.symlink(target_secret, oauth_path)

            acct_path = os.path.join(user_home, ".gemini", "google_accounts.json")
            os.unlink(acct_path)
            if hasattr(os, "mkfifo"):
                os.mkfifo(acct_path)

            run_home = gemini_home.build(
                "/s.json", "/w.json",
                user_home=user_home)
            self.addCleanup(gemini_home.teardown, run_home, "complete")
            self.assertFalse(
                os.path.lexists(os.path.join(run_home, ".gemini", "oauth_creds.json")))
            self.assertFalse(
                os.path.lexists(os.path.join(run_home, ".gemini", "google_accounts.json")))

    def test_teardown_removes_run_home_on_complete_and_wipes_all_runtime_secrets_on_failure(self):
        with tempfile.TemporaryDirectory() as d:
            user_home, agents_dir = _fixture_user_home(d)
            runner = gemini_runner.Runner("gemini")
            with mock.patch.dict(os.environ, {"HOME": user_home}):
                runner.prepare(os.path.join(d, "run"), review_root=d,
                               registration_dir=agents_dir)
            run_home = runner.run_home
            self.assertTrue(os.path.isfile(os.path.join(runner.workspace_dir, ".git", "HEAD")))
            gemini_dir = os.path.join(run_home, ".gemini")
            for extra_secret in ("gemini-credentials.json", "mcp-oauth-tokens.json", "tmp-token.json"):
                with open(os.path.join(gemini_dir, extra_secret), "w", encoding="utf-8") as fh:
                    fh.write("secret")
            os.makedirs(os.path.join(gemini_dir, "runtime_cache"), exist_ok=True)

            runner.teardown("failed")
            self.assertTrue(os.path.isdir(run_home))
            self.assertEqual(
                sorted(os.listdir(gemini_dir)),
                ["policies", "settings.json"],
            )

            gemini_home.teardown(run_home, "complete")
            self.assertFalse(os.path.exists(run_home))

    def test_no_credential_path_or_value_appears_in_run_result_or_ledger(self):
        with tempfile.TemporaryDirectory() as d:
            user_home, agents_dir = _fixture_user_home(d)
            run_dir = os.path.join(d, ".panopticon", "runs", "t1")
            os.makedirs(run_dir, exist_ok=True)

            def fake(cmd, **kw):
                return subprocess.CompletedProcess(cmd, 0, stdout=ENVELOPE, stderr="")

            with mock.patch.dict(os.environ, {"HOME": user_home}):
                r = gemini_runner.Runner("gemini", runner=fake)
                r.prepare(run_dir, review_root=d, registration_dir=agents_dir)
                self.addCleanup(r.teardown, "complete")
                res = r.run_entry(_entry(True), {
                    base.ENV_ENTRY_ID: "review-app-SEC",
                    base.ENV_WRITE_ALLOWLIST: "/w.json",
                    base.ENV_READ_SCOPE: "/s.json",
                })
                led = ledger.Ledger(run_dir)
                led.record(_entry(True), "review", res, "headless", "gemini",
                           timing={"started_at": "2026-11-08T00:00:00Z",
                                   "finished_at": "2026-11-08T00:00:01Z",
                                   "duration_ms": 1000})
                serialized_res = json.dumps(dataclasses.asdict(res))
                with open(led.path, encoding="utf-8") as fh:
                    ledger_text = fh.read()

            for forbidden in ("oauth_creds.json", "google_accounts.json",
                              "SECRET_REFRESH_TOKEN_VALUE_12345",
                              "operator@example.com", r.run_home):
                self.assertNotIn(forbidden, serialized_res)
                self.assertNotIn(forbidden, ledger_text)


class TestCommand(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        user_home, self.agents_dir = _fixture_user_home(self.tmp.name)
        self.r = gemini_runner.Runner("gemini")
        self.r.system_config_dir = os.path.join(self.tmp.name, "empty-sys")
        os.makedirs(self.r.system_config_dir, exist_ok=True)
        with mock.patch.dict(os.environ, {"HOME": user_home}):
            self.r.prepare(os.path.join(self.tmp.name, "run"),
                           review_root=self.tmp.name,
                           registration_dir=self.agents_dir)
        self.addCleanup(self.r.teardown, "complete")

    def test_enforced_entry_passes_yolo_admin_policy_include_directories_and_model(self):
        cmd = self.r.command(_entry(True), "gemini-3.6-flash")
        self.assertEqual(cmd[0], "gemini")
        self.assertIn("--output-format", cmd)
        self.assertIn("json", cmd)
        self.assertIn("--approval-mode", cmd)
        self.assertEqual(cmd[cmd.index("--approval-mode") + 1], "yolo")
        self.assertIn("--admin-policy", cmd)
        expected_policy = os.path.realpath(
            os.path.join(self.agents_dir, "panopticon-domain-panel.toml"))
        self.assertEqual(cmd[cmd.index("--admin-policy") + 1], expected_policy)
        self.assertIn("--include-directories", cmd)
        self.assertIn("-m", cmd)
        self.assertEqual(cmd[cmd.index("-m") + 1], "gemini-3.6-flash")
        self.assertEqual(cmd[-2:], ["-p", _entry(True)["prompt"]])

    def test_command_escapes_all_at_tokens_in_prompt(self):
        entry = _entry(
            True,
            prompt=(
                "<!-- panopticon-entry: review-app-SEC -->\n"
                "Check @/etc/passwd, @src/auth.py, @login_required, "
                "user@corp.com, and already-escaped \\@literal."
            ),
        )
        cmd = self.r.command(entry, "gemini-3.6-flash")
        prompt_arg = cmd[cmd.index("-p") + 1]
        self.assertIsNone(re.search(r"(?<!\\)@", prompt_arg), prompt_arg)
        self.assertIn(r"\@/etc/passwd", prompt_arg)
        self.assertIn(r"\@src/auth.py", prompt_arg)
        self.assertIn(r"\@login_required", prompt_arg)
        self.assertIn(r"user\@corp.com", prompt_arg)
        self.assertIn(r"\@literal", prompt_arg)
        self.assertNotIn(r"\\@literal", prompt_arg)

    def test_unenforced_entry_uses_unenforced_admin_policy(self):
        cmd = self.r.command(_entry(False), "gemini-3.6-flash")
        self.assertIn("--admin-policy", cmd)
        self.assertEqual(
            cmd[cmd.index("--admin-policy") + 1],
            gemini_home.unenforced_policy_path(self.r.run_home))

    def test_command_refuses_when_system_policy_hazard_appears_after_probe(self):
        with tempfile.TemporaryDirectory() as sys_dir:
            pol_dir = os.path.join(sys_dir, "policies")
            os.makedirs(pol_dir, exist_ok=True)
            with open(os.path.join(pol_dir, "late.toml"), "w", encoding="utf-8") as fh:
                fh.write('[[rule]]\ntoolName = "*"\ndecision = "allow"\npriority = 999\n')
            self.r.system_config_dir = sys_dir
            try:
                with self.assertRaisesRegex(RuntimeError, "system policy hazard"):
                    self.r.command(_entry(True), "gemini-3.6-flash")
            finally:
                self.r.system_config_dir = None

    def test_known_models_excludes_retired_gemini_2_5_models(self):
        for retired in ("gemini-2.5-pro", "gemini-2.5-flash",
                        "gemini-2.5-flash-lite", "auto-gemini-2.5"):
            self.assertNotIn(retired, gemini_runner.KNOWN_MODELS)
        for current in ("gemini-3.6-flash", "gemini-3.8-flash",
                        "gemini-3.5-flash-lite", "gemini-4-argon", "gemini-4-carbon"):
            self.assertIn(current, gemini_runner.KNOWN_MODELS)


class TestParseEnvelope(unittest.TestCase):
    """P6: Disjoint `input_tokens`, `cache_read_input_tokens = cached`, and
    `output_tokens = candidates + thoughts`."""

    def test_extracts_disjoint_input_cached_and_combined_candidates_plus_thoughts_output(self):
        r = gemini_runner.Runner("gemini")
        res = r.parse_envelope("e1", ENVELOPE, 0)
        self.assertTrue(res.ok)
        self.assertEqual(res.text, "the final reply")
        self.assertEqual(res.session_id, "2c8d8cf2-070f-416c-90bf-5a1983debf98")
        self.assertEqual(res.model, "gemini-3.6-flash")
        self.assertIsNone(res.cost_usd)
        self.assertEqual(res.usage, {
            "input_tokens": 100,
            "output_tokens": 40,
            "cache_read_input_tokens": 40,
            "cache_creation_input_tokens": 0,
            "cache_read_tokens": 40,
            "thinking_tokens": 15,
            "total_tokens": 180,
        })

    def test_fallback_when_input_absent_subtracts_cached_from_prompt(self):
        env_no_input = json.dumps({
            "session_id": "s2",
            "response": "ok",
            "stats": {
                "models": {
                    "gemini-3.5-flash-lite": {
                        "tokens": {"prompt": 140, "cached": 40, "candidates": 25,
                                   "thoughts": 15, "total": 180},
                    }
                }
            },
        })
        r = gemini_runner.Runner("gemini")
        res = r.parse_envelope("e1", env_no_input, 0)
        self.assertEqual(res.usage["input_tokens"], 100)
        self.assertEqual(res.usage["cache_read_input_tokens"], 40)
        self.assertEqual(res.usage["output_tokens"], 40)

    def test_cache_read_only_envelope_preserves_nonzero_cache_read_and_zero_input(self):
        env_cache_only = json.dumps({
            "session_id": "s3",
            "response": "ok",
            "stats": {
                "models": {
                    "gemini-3.5-flash-lite": {
                        "tokens": {"input": 0, "prompt": 80, "cached": 80,
                                   "candidates": 0, "thoughts": 0, "total": 80},
                    }
                }
            },
        })
        r = gemini_runner.Runner("gemini")
        res = r.parse_envelope("e1", env_cache_only, 0)
        self.assertEqual(res.usage["input_tokens"], 0)
        self.assertEqual(res.usage["cache_read_input_tokens"], 80)
        self.assertEqual(res.usage["output_tokens"], 0)
        self.assertEqual(res.usage["total_tokens"], 80)

    def test_extracts_structured_error_object_and_redacts_secrets(self):
        r = gemini_runner.Runner("gemini")
        err_env = json.dumps({
            "session_id": "s-err",
            "error": {
                "type": "FatalAuthenticationError",
                "message": "429 rate limit exceeded sk-ant-api03-AAAABBBBCCCC",
                "code": 41,
            },
        })
        res = r.parse_envelope("e1", err_env, 1)
        self.assertFalse(res.ok)
        self.assertIn("429 rate limit", res.error)
        self.assertNotIn("sk-ant-", res.error)
        self.assertEqual(outage.HOST_FAILURE, res.failure_class)

    def test_non_json_failure_path_redacts_raw_stdout(self):
        r = gemini_runner.Runner("gemini")
        raw_out = "fatal crash with token sk-ant-api03-AAAABBBBCCCCDDDDEEEEFFFF"
        res = r.parse_envelope("e1", raw_out, 1, stderr="boom")
        self.assertFalse(res.ok)
        self.assertNotIn("sk-ant-", res.text)
        self.assertIn("[REDACTED_KEY]", res.text)

    def test_exit_codes_41_and_173_classify_as_host_failure_and_name_exit_codes(self):
        r = gemini_runner.Runner("gemini")
        res_41 = r.parse_envelope(
            "scout", "", 41,
            stderr=(
                "YOLO mode is enabled. All tool calls will be automatically approved.\n"
                "When using Gemini API, you must specify the GEMINI_API_KEY environment variable.\n"
            ),
        )
        self.assertFalse(res_41.ok)
        self.assertEqual(outage.HOST_FAILURE, res_41.failure_class)
        self.assertIn("41 (FatalAuthenticationError)", res_41.error)
        self.assertIn("GEMINI_API_KEY", res_41.error)

        res_173 = r.parse_envelope("scout", "", 173, stderr="GaxiosError: limit reached")
        self.assertFalse(res_173.ok)
        self.assertEqual(outage.HOST_FAILURE, res_173.failure_class)
        self.assertIn("173 (HTTP 429 rate-limit/quota (429 mod 256))", res_173.error)

        for code, expected_name in ((42, "FatalInputError"),
                                    (52, "FatalConfigError"),
                                    (53, "FatalTurnLimitedError")):
            res_code = r.parse_envelope("scout", "", code, stderr="fatal")
            self.assertIn("%d (%s)" % (code, expected_name), res_code.error)

    def test_auth_and_ineligible_tier_errors_pause_tally_after_one_launch_without_retries(self):
        r = gemini_runner.Runner("gemini")
        stderr_run2 = (
            "YOLO mode is enabled. All tool calls will be automatically approved.\n"
            "Loaded cached credentials.\n"
            "IneligibleTierError: This client is no longer supported for Gemini Code Assist for individuals.\n"
            "    at UserContentGenerator.doOnboarding (/bundle/chunk.js:123:45)\n"
            "[ERROR] {\n"
            '  "error": {\n'
            '    "message": "This client is no longer supported for Gemini Code Assist for individuals.",\n'
            '    "code": 400\n'
            "  }\n"
            "}\n"
        )
        res = r.parse_envelope("scout", "", 1, stderr=stderr_run2)
        self.assertEqual(outage.HOST_FAILURE, res.failure_class)
        self.assertIn("This client is no longer supported", res.stderr)
        tally = outage.FailureTally("gemini")
        tally.record("scout", res, seq=0)
        paused = tally.settle(unlaunched=0)
        self.assertIsNotNone(paused)
        self.assertIn("paused: the gemini host failed 1 of this batch's 1 launches", paused)
        self.assertEqual({}, tally.streaks)

    def test_long_stderr_preserves_tail_reason_instead_of_startup_banner(self):
        r = gemini_runner.Runner("gemini")
        long_stderr = "\n".join([
            "YOLO mode is enabled. All tool calls will be automatically approved.",
            "Loaded cached credentials.",
            "Ripgrep is not available, falling back to basic search (slower, less accurate)",
            "Attempt 1 failed with status 429. Retrying with backoff...",
            "    at stackFrameOne (/usr/local/lib/node_modules/@google/gemini-cli/bundle/chunk.js:100:10)",
            "    at stackFrameTwo (/usr/local/lib/node_modules/@google/gemini-cli/bundle/chunk.js:200:20)",
            "    at stackFrameThree (/usr/local/lib/node_modules/@google/gemini-cli/bundle/chunk.js:300:30)",
            "    at stackFrameFour (/usr/local/lib/node_modules/@google/gemini-cli/bundle/chunk.js:400:40)",
            "FINAL_ROOT_CAUSE: Quota exceeded for metric generate_content_requests",
        ])
        res = r.parse_envelope("scout", "", 1, stderr=long_stderr)
        self.assertFalse(res.ok)
        self.assertIn("FINAL_ROOT_CAUSE: Quota exceeded", res.stderr)
        self.assertIn("FINAL_ROOT_CAUSE: Quota exceeded", res.error)
        self.assertNotIn("YOLO mode is enabled", res.stderr)


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

    def test_run_entry_uses_isolated_gemini_cli_home_workspace_cwd_and_scrubs_gemini_env(self):
        seen = {}
        with tempfile.TemporaryDirectory() as d:
            user_home, agents_dir = _fixture_user_home(d)
            ambient_env = {
                "PATH": "/p",
                "HOME": user_home,
                "GEMINI_CLI": "1",
                "GEMINI_API_KEY": "allowed-key",
                "GEMINI_CLI_SYSTEM_SETTINGS_PATH": "/evil/settings.json",
                "GEMINI_CLI_SYSTEM_DEFAULTS_PATH": "/evil/defaults.json",
                "GEMINI_CLI_TRUSTED_FOLDERS_PATH": "/evil/trusted.json",
                "GEMINI_SYSTEM_MD": "/evil/system.md",
                "GEMINI_TELEMETRY_OUTFILE": "/evil/telemetry.log",
            }
            with mock.patch.dict(os.environ, ambient_env, clear=True):
                r = gemini_runner.Runner("gemini", runner=self._fake_run(seen))
                r.prepare(os.path.join(d, "run"), review_root=d,
                          registration_dir=agents_dir)
                self.addCleanup(r.teardown, "complete")
                res = r.run_entry(_entry(True), self._env())
        self.assertTrue(res.ok)
        self.assertEqual(res.text, "the final reply")
        self.assertEqual(res.model, "gemini-3.6-flash")
        self.assertEqual(res.usage["input_tokens"], 100)
        child_env = seen["kw"]["env"]
        self.assertEqual(child_env["GEMINI_CLI_HOME"], r.run_home)
        self.assertEqual(child_env["HOME"], r.run_home)
        self.assertEqual(child_env["GEMINI_API_KEY"], "allowed-key")
        for scrubbed in ("GEMINI_CLI", "GEMINI_CLI_SYSTEM_SETTINGS_PATH",
                         "GEMINI_CLI_SYSTEM_DEFAULTS_PATH",
                         "GEMINI_CLI_TRUSTED_FOLDERS_PATH",
                         "GEMINI_SYSTEM_MD", "GEMINI_TELEMETRY_OUTFILE"):
            self.assertNotIn(scrubbed, child_env)
        self.assertEqual(child_env[base.ENV_ENTRY_ID], "review-app-SEC")
        self.assertEqual(seen["kw"]["cwd"], r.workspace_dir)

    def test_enforced_entry_without_registered_policy_shell_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            user_home, _ = _fixture_user_home(d)
            empty_reg = os.path.join(d, "empty-agents")
            os.makedirs(empty_reg, exist_ok=True)
            row = dataclasses.replace(hosts.HOSTS["gemini"], registration_dir=empty_reg)
            with mock.patch.dict(hosts.HOSTS, {"gemini": row}), \
                    mock.patch.dict(os.environ, {"HOME": user_home}):
                r = gemini_runner.Runner("gemini", runner=self._fake_run({}))
                r.prepare(os.path.join(d, "run"), review_root=d,
                          registration_dir=empty_reg)
                self.addCleanup(r.teardown, "complete")
                res = r.run_entry(_entry(True), self._env())
        self.assertFalse(res.ok)
        self.assertIn("not registered", res.error)

    def test_unresolvable_model_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            user_home, agents_dir = _fixture_user_home(d)
            with mock.patch.dict(os.environ, {"HOME": user_home}):
                r = gemini_runner.Runner("gemini", runner=self._fake_run({}))
                r.prepare(os.path.join(d, "run"), review_root=d,
                          registration_dir=agents_dir)
                self.addCleanup(r.teardown, "complete")
                res = r.run_entry(_entry(False, model="bogus-model"), self._env())
        self.assertFalse(res.ok)
        self.assertIn("not in gemini's known model catalogue", res.error)

    def test_timeout_returns_failed_result_with_partial_output(self):
        def slow(cmd, **kw):
            raise subprocess.TimeoutExpired(
                cmd, kw.get("timeout"), output=b"partial reply", stderr=b"timeout err")

        with tempfile.TemporaryDirectory() as d:
            user_home, agents_dir = _fixture_user_home(d)
            with mock.patch.dict(os.environ, {"HOME": user_home}):
                r = gemini_runner.Runner("gemini", runner=slow)
                r.prepare(os.path.join(d, "run"), review_root=d,
                          registration_dir=agents_dir)
                self.addCleanup(r.teardown, "complete")
                res = r.run_entry(_entry(False), self._env())
        self.assertFalse(res.ok)
        self.assertIn("timed out after", res.error)
        self.assertEqual("partial reply", res.text)
        self.assertIn("timeout err", res.stderr)
        self.assertIsNone(res.model)

    def test_run_entry_leaves_model_none_when_envelope_reports_no_model(self):
        no_model_envelope = json.dumps({
            "session_id": "sess-no-model",
            "status": "SUCCESS",
            "response": "ok",
            "usage": {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
        })

        def fake(cmd, **kw):
            return subprocess.CompletedProcess(cmd, 0, stdout=no_model_envelope, stderr="")

        with tempfile.TemporaryDirectory() as d:
            user_home, agents_dir = _fixture_user_home(d)
            with mock.patch.dict(os.environ, {"HOME": user_home}):
                r = gemini_runner.Runner("gemini", runner=fake)
                r.prepare(os.path.join(d, "run"), review_root=d,
                          registration_dir=agents_dir)
                self.addCleanup(r.teardown, "complete")
                res = r.run_entry(_entry(True, model="gemini-3.6-flash"), self._env())
        self.assertTrue(res.ok)
        self.assertIsNone(res.model)
        self.assertEqual(res.usage["total_tokens"], 15)

    def test_run_entry_fails_early_when_selected_type_is_gemini_api_key_and_env_var_unset(self):
        launched = []

        def should_not_launch(cmd, **kw):
            launched.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, stdout=ENVELOPE, stderr="")

        with tempfile.TemporaryDirectory() as d:
            user_home, agents_dir = _fixture_user_home(d)
            with open(os.path.join(user_home, ".gemini", "settings.json"), "w",
                      encoding="utf-8") as fh:
                json.dump({"security": {"auth": {"selectedType": "gemini-api-key"}}}, fh)
            with mock.patch.dict(os.environ, {"HOME": user_home}, clear=True):
                r = gemini_runner.Runner("gemini", runner=should_not_launch)
                r.prepare(os.path.join(d, "run"), review_root=d,
                          registration_dir=agents_dir)
                self.addCleanup(r.teardown, "complete")
                res = r.run_entry(_entry(True, model="gemini-3.6-flash"), self._env())
        self.assertFalse(res.ok)
        self.assertEqual([], launched)
        self.assertEqual(outage.HOST_FAILURE, res.failure_class)
        self.assertIn(gemini_home.MISSING_API_KEY_REMEDY, res.error)

    def test_rerouted_envelope_records_requested_model_in_ledger_and_discloses_on_stderr(self):
        rerouted_env = json.dumps({
            "session_id": "sess-reroute",
            "response": "ok",
            "stats": {
                "models": {
                    "gemini-3.5-flash-lite": {
                        "tokens": {"input": 10, "prompt": 10, "candidates": 5,
                                   "cached": 0, "thoughts": 0, "total": 15},
                    }
                }
            },
        })

        def fake(cmd, **kw):
            return subprocess.CompletedProcess(cmd, 0, stdout=rerouted_env, stderr="")

        with tempfile.TemporaryDirectory() as d:
            user_home, agents_dir = _fixture_user_home(d)
            run_dir = os.path.join(d, "run")
            with mock.patch.dict(os.environ, {"HOME": user_home}):
                r = gemini_runner.Runner("gemini", runner=fake)
                r.prepare(run_dir, review_root=d, registration_dir=agents_dir)
                self.addCleanup(r.teardown, "complete")
                entry = _entry(True, model="gemini-3.6-flash")
                res = r.run_entry(entry, self._env())
                led = ledger.Ledger(run_dir)
                stderr_buf = io.StringIO()
                with contextlib.redirect_stderr(stderr_buf):
                    led.record(entry, "review", res, "headless", "gemini",
                               timing={"started_at": "2026-11-10T00:00:00Z",
                                       "finished_at": "2026-11-10T00:00:01Z",
                                       "duration_ms": 1000})
                with open(led.path, encoding="utf-8") as fh:
                    row = json.loads(fh.readline())
        self.assertEqual("gemini-3.6-flash", row.get("requested_model"))
        self.assertEqual("gemini-3.5-flash-lite", row.get("model"))
        self.assertIn("model rerouted by host 'gemini'", stderr_buf.getvalue())
        self.assertIn("bound 'gemini-3.6-flash'", stderr_buf.getvalue())
        self.assertIn("envelope reported 'gemini-3.5-flash-lite'", stderr_buf.getvalue())


if __name__ == "__main__":
    unittest.main()
