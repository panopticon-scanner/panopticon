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
import scripts.runners.children as children
import scripts.runners.outage as outage


# #3550: agy's DOCUMENTED `--output-format json` envelope (field table at
# https://antigravity.google/docs/cli/headless/, read 2026-11-11). It carries no model:
# the old fixture here was Gemini CLI's shape, which is how every real ledger row's
# `model: null` passed every test.
ENVELOPE = json.dumps({
    "conversation_id": "2c8d8cf2-070f-416c-90bf-5a1983debf98",
    "status": "SUCCESS",
    "response": "the final reply",
    "duration_seconds": 7.16,
    "num_turns": 1,
    "usage": {"input_tokens": 100, "output_tokens": 25, "thinking_tokens": 15,
              "cache_read_tokens": 40, "total_tokens": 180},
})
# Not agy's shape: Gemini CLI's `stats.models`, kept as a tolerant fallback only.
GEMINI_SHAPED_ENVELOPE = json.dumps({
    "session_id": "2c8d8cf2-070f-416c-90bf-5a1983debf98",
    "response": "the final reply",
    "stats": {"models": {"gemini-4-argon-high": {
        "tokens": {"input": 100, "prompt": 140, "candidates": 25,
                   "total": 180, "cached": 40, "thoughts": 15, "tool": 0}}}},
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

    def test_the_levels_are_the_captured_set(self):
        self.assertEqual(("low", "medium", "high"), agy_runner.AGY_EFFORTS)

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
                ("gemini-4-carbon", "xhigh", "is not one of"),
                ("gemini-4-carbon", "max", "is not one of"),
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
        self.assertIsNone(res.model)       # #3550: agy reports no answering model
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


class TestTheDocumentedEnvelope(unittest.TestCase):
    """#3550: what agy's real envelope yields, and the tolerant fallbacks."""

    def test_the_documented_envelope_maps_usage_and_reports_no_model(self):
        res = agy_runner.parse_envelope(ENVELOPE, 0, entry_id="e")
        self.assertTrue(res.ok)
        self.assertIsNone(res.model)
        self.assertEqual("2c8d8cf2-070f-416c-90bf-5a1983debf98", res.session_id)
        self.assertEqual({"input_tokens": 100, "output_tokens": 25, "thinking_tokens": 15,
                          "cache_read_input_tokens": 40, "cache_read_tokens": 40,
                          "cache_creation_input_tokens": 0, "total_tokens": 180}, res.usage)

    def test_a_future_model_field_is_still_picked_up(self):
        for raw, model in ((GEMINI_SHAPED_ENVELOPE, "gemini-4-argon-high"),
                           (json.dumps(dict(json.loads(ENVELOPE), model="gemini-4-carbon")),
                            "gemini-4-carbon")):
            with self.subTest(model=model):
                self.assertEqual(model, agy_runner.parse_envelope(raw, 0, entry_id="e").model)

    def test_the_disclosure_cites_the_documented_envelope(self):
        self.assertIn("reports no answering model", agy_runner.NO_ANSWERING_MODEL)
        self.assertIn("https://antigravity.google/docs/cli/headless/",
                      agy_runner.NO_ANSWERING_MODEL)

    def test_the_carbon_effort_slugs_are_known_but_not_defaults(self):
        for slug in ("gemini-4-carbon-low", "gemini-4-carbon-medium", "gemini-4-carbon-high"):
            self.assertIn(slug, agy_runner.KNOWN_MODELS)


class TestTheLedgerRowForAgy(unittest.TestCase):
    """#3550: an agy row names what was bound; `model` stays null and is never invented."""

    TIMING = {"started_at": "2026-11-11T00:00:00Z", "finished_at": "2026-11-11T00:00:01Z",
              "duration_ms": 1000}

    def _row(self, entry, raw=ENVELOPE):
        import contextlib
        import io
        import scripts.ledger as ledger
        res = agy_runner.parse_envelope(raw, 0, entry_id=entry["id"])
        with tempfile.TemporaryDirectory() as d:
            led = ledger.Ledger(d)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                led.record(entry, "review", res, "headless", "agy", timing=self.TIMING)
            with open(led.path, encoding="utf-8") as fh:
                row = json.loads(fh.readline())
            usage = led.usage_document()
        return row, err.getvalue(), usage

    def test_the_row_carries_the_bound_model_and_effort_with_model_null(self):
        row, err, usage = self._row(_entry(False, model="gemini-4-carbon", effort="high"))
        self.assertIsNone(row["model"])
        self.assertEqual("gemini-4-carbon", row["requested_model"])
        self.assertEqual("high", row["requested_effort"])
        self.assertEqual(100, row["usage"]["input_tokens"])
        self.assertEqual("", err)
        self.assertEqual({}, usage["by_model"])          # no split is claimed

    def test_no_effort_means_no_requested_effort(self):
        row, _err, _usage = self._row(_entry(False, model="gemini-3.8-flash-medium"))
        self.assertEqual("gemini-3.8-flash-medium", row["requested_model"])
        self.assertNotIn("requested_effort", row)

    def test_an_unbound_entry_writes_neither(self):
        row, _err, _usage = self._row(_entry(False, model=None))
        self.assertNotIn("requested_model", row)
        self.assertNotIn("requested_effort", row)

    def test_a_reported_model_that_differs_is_said_loudly(self):
        raw = json.dumps(dict(json.loads(ENVELOPE), model="gemini-3.8-flash-lite"))
        row, err, _usage = self._row(_entry(False, model="gemini-4-carbon", effort="high"), raw)
        self.assertEqual("gemini-3.8-flash-lite", row["model"])
        self.assertIn("host 'agy' reported model 'gemini-3.8-flash-lite', "
                      "bound 'gemini-4-carbon'", err)

    def test_a_reported_model_that_matches_is_quiet(self):
        raw = json.dumps(dict(json.loads(ENVELOPE), model="gemini-4-carbon"))
        _row, err, _usage = self._row(_entry(False, model="gemini-4-carbon"), raw)
        self.assertEqual("", err)


class TestAgyAuthFailsClosed(unittest.TestCase):
    """#3576: no agy child may reach a browser sign-in, and no run starts without auth.
    Fixture homes only: nothing here reads the real ~/.gemini or the Keychain."""

    # The owner's live log lines (agy 1.5.6, 2026-11-11), in order.
    LOG = ("Print mode: not authenticated, trying silent auth\n"
           "Print mode: silent auth failed\n"
           "Print mode: triggering interactive OAuth\n"
           "consumerOAuth: starting OAuth flow\n")

    def _env(self):
        return {base.ENV_ENTRY_ID: "review-app-SEC",
                base.ENV_WRITE_ALLOWLIST: "/w.json", base.ENV_READ_SCOPE: "/s.json"}

    def _home_without_token(self, d, dangling=False):
        user_home, agents_dir = _fixture_user_home(d)
        token = os.path.join(user_home, ".gemini", "antigravity-cli",
                             agy_home.OAUTH_TOKEN_FILE)
        os.unlink(token)
        if dangling:
            os.symlink(os.path.join(d, "gone"), token)
        return user_home, agents_dir

    def test_build_refuses_when_the_token_is_missing_or_dangling(self):
        for dangling in (False, True):
            with self.subTest(dangling=dangling), tempfile.TemporaryDirectory() as d:
                user_home, agents_dir = self._home_without_token(d, dangling)
                before = set(agy_home._LIVE_HOMES)
                with self.assertRaises(agy_home.AgyAuthUnreachable) as caught:
                    agy_home.build("/s.json", "/w.json", user_home=user_home,
                                   registration_dir=agents_dir)
                self.assertEqual(before, agy_home._LIVE_HOMES)   # no home was made
                message = str(caught.exception)
                self.assertIn("agy auth not reachable from the isolated HOME", message)
                self.assertIn("antigravity-oauth-token is missing", message)
                self.assertIn("#3576", message)
                self.assertNotIn(user_home, message)

    def test_build_links_a_present_token(self):
        with tempfile.TemporaryDirectory() as d:
            user_home, agents_dir = _fixture_user_home(d)
            home = agy_home.build("/s.json", "/w.json", user_home=user_home,
                                  registration_dir=agents_dir)
            self.addCleanup(agy_home.teardown, home, "complete")
            self.assertTrue(os.path.islink(os.path.join(
                home, ".gemini", "antigravity-cli", agy_home.OAUTH_TOKEN_FILE)))

    def test_prepare_refuses_before_any_launch(self):
        seen = {}
        with tempfile.TemporaryDirectory() as d:
            user_home, agents_dir = self._home_without_token(d)
            with mock.patch.dict(os.environ, {"HOME": user_home}):
                r = agy_runner.Runner("agy", runner=lambda cmd, **kw: seen.setdefault("cmd", cmd))
                with self.assertRaises(agy_home.AgyAuthUnreachable):
                    r.prepare(d, os.path.join(d, "run"), registration_dir=agents_dir)
        self.assertEqual({}, seen)
        self.assertIsNone(r.agy_home)

    def test_the_stop_pattern_names_the_lines_after_silent_auth_fails(self):
        lines = self.LOG.splitlines()
        self.assertIsNone(agy_runner.INTERACTIVE_AUTH.search(lines[0].encode()))
        for line in lines[1:]:
            self.assertIsNotNone(agy_runner.INTERACTIVE_AUTH.search(line.encode()), line)

    def _run(self, fake):
        with tempfile.TemporaryDirectory() as d:
            user_home, agents_dir = _fixture_user_home(d)
            with mock.patch.dict(os.environ, {"HOME": user_home}):
                r = agy_runner.Runner("agy", runner=fake)
                r.prepare(d, os.path.join(d, "run"), registration_dir=agents_dir)
                self.addCleanup(r.teardown, "complete")
                return r.run_entry(_entry(True), self._env())

    def _assert_auth_failure(self, res):
        self.assertFalse(res.ok)
        self.assertIn("stopped before it could open a browser sign-in", res.error)
        self.assertEqual(agy_home.AUTH_UNREACHABLE, res.host_error)
        self.assertEqual(outage.HOST_FAILURE, res.failure_class)

    def test_a_stopped_child_is_a_typed_host_failure(self):
        seen = {}

        def fake(cmd, **kw):
            seen.update(kw)
            raise children.HostStopped(cmd, output="", stderr=self.LOG)
        self._assert_auth_failure(self._run(fake))
        self.assertIs(agy_runner.INTERACTIVE_AUTH, seen["stop_on"])

    def test_a_child_that_finished_on_the_line_is_the_same_failure(self):
        def fake(cmd, **kw):
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr=self.LOG)
        self._assert_auth_failure(self._run(fake))

    def test_silent_auth_alone_is_not_an_auth_failure(self):
        def fake(cmd, **kw):
            return subprocess.CompletedProcess(
                cmd, 0, stdout=ENVELOPE, stderr=self.LOG.splitlines()[0] + "\n")
        self.assertTrue(self._run(fake).ok)


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
        self.assertIsNone(res.model)       # #3550: agy reports no answering model
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
