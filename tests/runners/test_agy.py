import dataclasses
import io
import json
import os
import subprocess
import tempfile
import unittest
from unittest import mock

import scripts.dispatch as dispatch
import scripts.hosts as hosts
import scripts.model_resolver as model_resolver
import scripts.redact as redact
import scripts.runners.agy as agy_runner
import scripts.runners.agy_home as agy_home
import scripts.runners.base as base
import scripts.runners.children as children
import scripts.runners.outage as outage


# #3576: these tests choose agy's auth route themselves; an operator's exported key or
# route choice must not leak in.
_ENV_PATCH = None


def setUpModule():
    global _ENV_PATCH
    _ENV_PATCH = mock.patch.dict(os.environ)
    _ENV_PATCH.start()
    for name in ("GEMINI_API_KEY", "PANOPTICON_AGY_AUTH"):
        os.environ.pop(name, None)


def tearDownModule():
    _ENV_PATCH.stop()


# The owner's `agy models` on the API-key route (2026-11-12), names then display names.
KEY_ROUTE_MODELS = "\n".join(
    ["Available models:"]
    + ["%s\t%s" % (slug, slug.replace("-", " ").title()) for slug in (
        "gemini-4-argon-high", "gemini-4-argon-medium", "gemini-4-argon-low",
        "gemini-3.8-flash-high", "gemini-3.8-flash-medium", "gemini-3.8-flash-low",
        "gemini-3.7-flash-high", "gemini-3.7-flash-medium", "gemini-3.7-flash-low",
        "gemini-3.6-flash-high", "gemini-3.6-flash-medium", "gemini-3.6-flash-low",
        "gemini-3.1-pro-high", "gemini-3.1-pro-low")]) + "\n"
FAKE_KEY = "AIza" + "K" * 35  # a real key's shape, built like the test_redact sentinels

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


def _args(cmd):
    """An agy argv after its leading `--gemini_dir <dir>` (#3613)."""
    return list(cmd[3:]) if len(cmd) > 2 and cmd[1] == agy_home.GEMINI_DIR_FLAG else list(cmd[1:])


def _answers_preflight(fake=None, *, agents_rc=0, agents_extra=(), hook_log=True, turn=None):
    """Wrap `fake` so the #3613 preflight is answered as a signed-in agy answers it:
    `agy agents` lists exactly the run's shells and agy's log under the run records
    the hook load; the minimal turn returns the documented envelope. Any other
    launch goes to `fake` (and is refused when there is none)."""
    def wrapped(cmd, **kw):
        if _args(cmd) == ["agents"]:
            gdir = cmd[2]
            names = sorted(agy_home.expected_agents(os.path.dirname(gdir))) + list(agents_extra)
            if hook_log:
                log_dir = os.path.join(gdir, "antigravity-cli", "log")
                os.makedirs(log_dir, exist_ok=True)
                with open(os.path.join(log_dir, "cli-20261113_000000.log"), "w",
                          encoding="utf-8") as fh:
                    fh.write("I1113 hooks_manager.go:54] %s\n" % agy_home.HOOK_LOAD_PROOF)
            return subprocess.CompletedProcess(cmd, agents_rc, stdout="\n".join(names) + "\n",
                                               stderr="")
        if _args(cmd)[-2:] == ["-p", agy_runner.PREFLIGHT_PROMPT]:
            if turn is not None:
                return turn(cmd, **kw)
            return subprocess.CompletedProcess(cmd, 0, stdout=ENVELOPE, stderr="")
        if fake is None:
            raise AssertionError("unexpected agy launch: %r" % (cmd,))
        return fake(cmd, **kw)
    return wrapped


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

    def test_build_writes_only_the_runs_gemini_dir_and_creates_git_ceiling(self):
        # #3613: nothing is copied or linked from ~/.gemini; the run's gemini dir
        # holds settings, the shells link, our hook and an empty MCP list.
        with tempfile.TemporaryDirectory() as d:
            user_home, agents_dir = _fixture_user_home(d)
            run_home = agy_home.build(
                "/s.json", "/w.json",
                user_home=user_home, registration_dir=agents_dir)
            workspace_dir = agy_home.workspace_dir(run_home)
            self.addCleanup(agy_home.teardown, run_home, "complete")
            self.assertEqual(["gemini", "workspace"], sorted(os.listdir(run_home)))
            gdir = agy_home.gemini_dir(run_home)

            cli_dir = os.path.join(gdir, "antigravity-cli")
            self.assertEqual(["settings.json"], sorted(os.listdir(cli_dir)))
            self.assertFalse(os.path.islink(os.path.join(cli_dir, "settings.json")))
            with open(os.path.join(cli_dir, "settings.json"), encoding="utf-8") as fh:
                self.assertEqual(
                    {"agentMode": "accept-edits", "allowNonWorkspaceAccess": True},
                    json.load(fh))

            config_dir = os.path.join(gdir, "config")
            self.assertEqual(["agents", "hooks.json", "mcp_config.json"],
                             sorted(os.listdir(config_dir)))
            self.assertEqual(os.path.realpath(agents_dir),
                             os.path.realpath(os.path.join(config_dir, "agents")))
            with open(os.path.join(config_dir, "mcp_config.json"), encoding="utf-8") as fh:
                self.assertEqual({"mcpServers": {}}, json.load(fh))
            with open(os.path.join(config_dir, "hooks.json"), encoding="utf-8") as fh:
                hooks_doc = json.load(fh)
            pre = hooks_doc["panopticon-guard"]["PreToolUse"]
            self.assertEqual(len(pre), 1)
            self.assertEqual(pre[0]["matcher"], "*")
            self.assertEqual(pre[0]["hooks"][0]["timeout"], 30)
            for root, dirs, files in os.walk(run_home):
                for name in dirs + files:
                    target = os.path.realpath(os.path.join(root, name))
                    if os.path.islink(os.path.join(root, name)):
                        with self.subTest(link=name):
                            self.assertEqual(os.path.realpath(agents_dir), target)

            git_dir = os.path.join(workspace_dir, ".git")
            self.assertTrue(os.path.isdir(os.path.join(git_dir, "objects")))
            self.assertTrue(os.path.isdir(os.path.join(git_dir, "refs")))
            with open(os.path.join(git_dir, "HEAD"), encoding="utf-8") as fh:
                self.assertEqual("ref: refs/heads/main\n", fh.read())

    def test_prepare_creates_git_ceiling_and_teardown_strips_the_agents_link_on_failure(self):
        with tempfile.TemporaryDirectory() as d:
            user_home, agents_dir = _fixture_user_home(d)
            runner = agy_runner.Runner("agy", runner=_answers_preflight())
            with mock.patch.dict(os.environ, {"HOME": user_home}):
                runner.prepare(d, os.path.join(d, "run"), registration_dir=agents_dir)
            run_home = runner.run_home
            self.assertTrue(os.path.isfile(os.path.join(runner.workspace_dir, ".git", "HEAD")))

            runner.teardown("failed")
            self.assertTrue(os.path.isdir(run_home))
            self.assertFalse(os.path.lexists(agy_home.agents_dir(run_home)))
            self.assertTrue(os.path.isfile(os.path.join(
                agy_home.gemini_dir(run_home), "config", "hooks.json")))
            agy_home.teardown(run_home, "complete")
            self.assertFalse(os.path.exists(run_home))


class TestCommand(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        user_home, agents_dir = _fixture_user_home(self.tmp.name)
        self.r = agy_runner.Runner("agy", runner=_answers_preflight())
        with mock.patch.dict(os.environ, {"HOME": user_home}):
            self.r.prepare(self.tmp.name, os.path.join(self.tmp.name, "run"),
                           registration_dir=agents_dir)
        self.addCleanup(self.r.teardown, "complete")

    def test_enforced_entry_passes_agent_model_and_disable_slash_commands(self):
        cmd = self.r.command(_entry(True), "gemini-4-argon-high")
        self.assertEqual(cmd[:3], ["agy", "--gemini_dir", agy_home.gemini_dir(self.r.agy_home)])
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
            "agy", "--gemini_dir", agy_home.gemini_dir(self.r.agy_home),
            "--output-format", "json", "--disable-slash-commands",
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

    def test_the_stop_pattern_names_the_lines_after_silent_auth_fails(self):
        lines = self.LOG.splitlines()
        self.assertIsNone(agy_runner.INTERACTIVE_AUTH.search(lines[0].encode()))
        for line in lines[1:]:
            self.assertIsNotNone(agy_runner.INTERACTIVE_AUTH.search(line.encode()), line)

    def _run(self, fake):
        with tempfile.TemporaryDirectory() as d:
            user_home, agents_dir = _fixture_user_home(d)
            with mock.patch.dict(os.environ, {"HOME": user_home}):
                r = agy_runner.Runner("agy", runner=_answers_preflight(fake))
                r.prepare(d, os.path.join(d, "run"), registration_dir=agents_dir)
                self.addCleanup(r.teardown, "complete")
                return r.run_entry(_entry(True), self._env())

    def _assert_auth_failure(self, res):
        self.assertFalse(res.ok)
        self.assertIn("stopped before it could open a browser sign-in", res.error)
        self.assertEqual(agy_home.AUTH_UNREACHABLE, res.host_error)
        self.assertEqual(outage.HOST_FAILURE, res.failure_class)

    def test_the_message_alone_classifies_as_a_host_failure(self):
        # Belt and braces with the explicit class: the outage pause reads it either way.
        self.assertEqual(outage.HOST_FAILURE,
                         outage.classify_failure(agy_home.AUTH_UNREACHABLE))

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


class TestThePreflightFailsClosed(unittest.TestCase):
    """#3613: `prepare()` proves --gemini_dir took effect and that the route signs in,
    with one minimal real turn, before any entry launches. Every failure is loud,
    names its cause, leaves no run directory, and never falls back."""

    LOG = TestAgyAuthFailsClosed.LOG

    def _prepare(self, runner, env=None):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, True))
        user_home, agents_dir = _fixture_user_home(d)
        with mock.patch.dict(os.environ, dict({"HOME": user_home}, **(env or {}))):
            r = agy_runner.Runner("agy", runner=runner)
            self.addCleanup(r.teardown, "complete")
            r.prepare(d, os.path.join(d, "run"), registration_dir=agents_dir)
        return r

    def _assert_refused(self, runner, exc, text, env=None):
        before = set(agy_home._LIVE_HOMES)
        with self.assertRaises(exc) as caught:
            self._prepare(runner, env)
        self.assertIn(text, str(caught.exception))
        self.assertEqual(before, agy_home._LIVE_HOMES)          # no run left behind
        return caught.exception

    def test_a_signed_in_run_passes_with_exactly_two_preflight_launches(self):
        calls = []

        def turn(cmd, **kw):
            calls.append(("turn", list(cmd), kw))
            return subprocess.CompletedProcess(cmd, 0, stdout=ENVELOPE, stderr="")
        r = self._prepare(_answers_preflight(turn=turn))
        self.assertEqual("signin", r.auth_route)
        self.assertEqual(1, len(calls))
        _tag, cmd, kw = calls[0]
        # R3: the default model, no effort, no agent, so no tools.
        self.assertEqual(["agy", "--gemini_dir", agy_home.gemini_dir(r.agy_home),
                          "--output-format", "json", "--disable-slash-commands",
                          "-p", agy_runner.PREFLIGHT_PROMPT], cmd)
        self.assertIs(agy_runner.INTERACTIVE_AUTH, kw["stop_on"])
        self.assertEqual("/usr/bin/false", kw["env"]["BROWSER"])

    def test_agents_that_are_not_exactly_ours_refuse(self):
        for kwargs, text in (({"agents_extra": ("panopticon-scout-shadow",)}, "expected exactly"),
                             ({"agents_extra": ("someone-elses-agent",)}, "expected exactly"),
                             ({"agents_rc": 3}, "exited 3")):
            with self.subTest(**{k: str(v) for k, v in kwargs.items()}):
                self._assert_refused(_answers_preflight(**kwargs),
                                     agy_runner.AgyPreflightRefused, text)

    def test_a_project_scoped_agent_refuses_even_under_our_own_name(self):
        # A project shell that shadows one of ours prints OUR name, tagged [project]:
        # the listed set still matches, so only the [project] check refuses it.
        def agents(cmd, **kw):
            wrapped(cmd, **kw)                       # writes the hook-load log line
            names = sorted(agy_home.expected_agents(os.path.dirname(cmd[2])))
            lines = ["Available subagents:"] + ["  - %s [user]" % n for n in names[:-1]]
            lines.append("  - %s [project]" % names[-1])
            return subprocess.CompletedProcess(cmd, 0, stdout="\n".join(lines) + "\n", stderr="")
        wrapped = _answers_preflight()

        def fake(cmd, **kw):
            return agents(cmd, **kw) if _args(cmd) == ["agents"] else wrapped(cmd, **kw)
        self._assert_refused(fake, agy_runner.AgyPreflightRefused, "did not isolate the shells")

    def test_a_missing_hook_load_line_refuses_with_its_own_message(self):
        exc = self._assert_refused(_answers_preflight(hook_log=False),
                                   agy_runner.AgyPreflightRefused, "agy hook-load proof missing")
        self.assertIn(agy_home.HOOK_LOAD_PROOF, str(exc))
        self.assertIn("log format may have changed", str(exc))

    def test_the_hook_load_line_is_the_measured_text(self):
        self.assertEqual("loaded 1 named hooks from 1 hooks.json file(s)", agy_home.HOOK_LOAD_PROOF)

    def test_auth_trouble_in_the_turn_is_agy_auth_unreachable(self):
        def stopped(cmd, **kw):
            raise children.HostStopped(cmd, output="", stderr=self.LOG)

        def interactive(cmd, **kw):
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr=self.LOG)

        def not_signed_in(cmd, **kw):
            return subprocess.CompletedProcess(
                cmd, 1, stdout="", stderr="error getting token source: %s.\n"
                % agy_runner.NOT_SIGNED_IN)
        for turn in (stopped, interactive, not_signed_in):
            with self.subTest(turn=turn.__name__):
                exc = self._assert_refused(_answers_preflight(turn=turn),
                                           agy_home.AgyAuthUnreachable, "agy is not authenticated")
                self.assertNotIn("runs only when you choose it", str(exc))

    def test_a_failed_sign_in_with_a_key_set_names_the_key_route_and_does_not_take_it(self):
        def interactive(cmd, **kw):
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr=self.LOG)
        seen = []

        def models(cmd, **kw):
            seen.append(list(cmd))
            return subprocess.CompletedProcess(cmd, 0, stdout=KEY_ROUTE_MODELS, stderr="")
        exc = self._assert_refused(_answers_preflight(models, turn=interactive),
                                   agy_home.AgyAuthUnreachable, "PANOPTICON_AGY_AUTH=key",
                                   env={"GEMINI_API_KEY": FAKE_KEY})
        self.assertIn("runs only when you choose it", str(exc))
        self.assertEqual([], seen)                    # the key route was never tried

    def test_other_turn_failures_refuse_as_preflight(self):
        def bad_envelope(cmd, **kw):
            return subprocess.CompletedProcess(
                cmd, 0, stdout=json.dumps({"status": "ERROR", "error": "quota exhausted"}),
                stderr="")

        def timeout(cmd, **kw):
            raise subprocess.TimeoutExpired(cmd, agy_runner.PREFLIGHT_TIMEOUT)

        def no_json(cmd, **kw):
            return subprocess.CompletedProcess(cmd, 2, stdout="", stderr="crashed\n")
        for turn, text in ((bad_envelope, "quota exhausted"), (timeout, "timed out"),
                           (no_json, "exited 2")):
            with self.subTest(turn=turn.__name__):
                self._assert_refused(_answers_preflight(turn=turn),
                                     agy_runner.AgyPreflightRefused, text)

    # #3620: each AgyAuthUnreachable / AgyPreflightRefused ends with the step that refused,
    # so the next owner capture says where it stopped.
    def test_each_turn_and_agents_path_names_its_step(self):
        log = self.LOG

        def stopped(cmd, **kw):
            raise children.HostStopped(cmd, output="", stderr=log)

        def timeout(cmd, **kw):
            raise subprocess.TimeoutExpired(cmd, 1)

        def reply(rc, out, err):
            return lambda cmd, **kw: subprocess.CompletedProcess(cmd, rc, stdout=out, stderr=err)
        bad = json.dumps({"status": "ERROR", "error": "x"})
        wrapped = _answers_preflight()

        def on_agents(behaviour):
            return lambda cmd, **kw: (behaviour(cmd, **kw) if _args(cmd) == ["agents"]
                                      else wrapped(cmd, **kw))
        unreachable, refused = agy_home.AgyAuthUnreachable, agy_runner.AgyPreflightRefused
        for runner, exc, step in (
                (on_agents(stopped), unreachable, "agents: interactive auth"),
                (on_agents(timeout), refused, "agents: timeout"),
                (_answers_preflight(agents_rc=3), refused, "agents: shells"),
                (_answers_preflight(hook_log=False), refused, "agents: hook-load proof"),
                (_answers_preflight(turn=stopped), unreachable, "turn: interactive auth (stopped)"),
                (_answers_preflight(turn=timeout), refused, "turn: timeout"),
                (_answers_preflight(turn=reply(1, "", log)), unreachable,
                 "turn: interactive auth on stderr"),
                (_answers_preflight(turn=reply(0, agy_runner.NOT_SIGNED_IN, "")), unreachable,
                 "turn: not-logged-in on stdout"),
                (_answers_preflight(turn=reply(0, "", agy_runner.NOT_SIGNED_IN)), unreachable,
                 "turn: not-logged-in on stderr"),
                (_answers_preflight(turn=reply(0, bad, "")), refused, "turn: envelope")):
            with self.subTest(step=step):
                caught = self._assert_refused(runner, exc, "")
                self.assertTrue(str(caught).endswith("[preflight step: %s]" % step), str(caught))

    def test_each_models_path_names_its_step(self):
        key = {"GEMINI_API_KEY": FAKE_KEY, "PANOPTICON_AGY_AUTH": "key"}

        def models(behaviour):
            return _answers_preflight(lambda cmd, **kw: behaviour(cmd, **kw))

        def stopped(cmd, **kw):
            raise children.HostStopped(cmd, output="", stderr=self.LOG)

        def timeout(cmd, **kw):
            raise subprocess.TimeoutExpired(cmd, 1)
        for runner, exc, step in (
                (models(stopped), agy_home.AgyAuthUnreachable, "models: interactive auth"),
                (models(timeout), agy_runner.AgyPreflightRefused, "models: timeout"),
                (models(lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, stdout="",
                                                                      stderr="")),
                 agy_home.AgyAuthUnreachable, "models: listing"),
                (models(lambda cmd, **kw: subprocess.CompletedProcess(
                    cmd, 0, stdout="gemini-3.8-flash-medium Flash\n", stderr="")),
                 agy_runner.AgyPreflightRefused, "turn: key-route default")):
            with self.subTest(step=step):
                caught = self._assert_refused(runner, exc, "", env=key)
                self.assertTrue(str(caught).endswith("[preflight step: %s]" % step), str(caught))

    def test_the_auth_message_still_classifies_as_an_outage(self):
        import scripts.runners.outage as outage_mod
        msg = str(agy_home.unreachable({}, "turn: not-logged-in on stderr"))
        self.assertTrue(msg.startswith(agy_home.AUTH_UNREACHABLE))
        self.assertEqual(outage_mod.classify_failure(msg),
                         outage_mod.classify_failure(agy_home.AUTH_UNREACHABLE))


class TestTheSigninRouteNeverHoldsTheKey(unittest.TestCase):
    """#3617 review N1-N4: R2 enforced in the child environment, the key-route hint
    on every failed sign-in turn, timeouts as refusals, and the hook proof read from
    any of the run's logs."""

    LOG = TestAgyAuthFailsClosed.LOG

    def _prepare(self, runner, env):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, True))
        user_home, agents_dir = _fixture_user_home(d)
        patch = mock.patch.dict(os.environ, dict({"HOME": user_home}, **env))
        patch.start()
        self.addCleanup(patch.stop)
        for name in ("GEMINI_API_KEY", "PANOPTICON_AGY_AUTH"):   # only what this call names
            if name not in env:
                os.environ.pop(name, None)
        r = agy_runner.Runner("agy", runner=runner)
        self.addCleanup(r.teardown, "complete")
        r.prepare(d, os.path.join(d, "run"), registration_dir=agents_dir)
        return r

    def test_no_signin_child_holds_the_key_and_a_key_route_child_does(self):
        envs = []

        def record(cmd, **kw):
            envs.append((_args(cmd)[-1:], kw["env"]))
            return subprocess.CompletedProcess(cmd, 0, stdout=ENVELOPE, stderr="")

        def tracked(fake):
            inner = _answers_preflight(fake, turn=record)

            def wrapped(cmd, **kw):
                if _args(cmd) == ["agents"]:
                    envs.append((["agents"], kw["env"]))
                return inner(cmd, **kw)
            return wrapped
        r = self._prepare(tracked(record), {"GEMINI_API_KEY": FAKE_KEY})
        r.run_entry(_entry(True), {base.ENV_ENTRY_ID: "review-app-SEC"})
        self.assertEqual("signin", r.auth_route)
        self.assertEqual(3, len(envs))                     # agents, turn, entry
        for argv, env in envs:
            with self.subTest(launch=argv):
                self.assertNotIn("GEMINI_API_KEY", env)
        envs.clear()

        def models(cmd, **kw):
            if _args(cmd) == ["models"]:
                return subprocess.CompletedProcess(cmd, 0, stdout=KEY_ROUTE_MODELS, stderr="")
            return record(cmd, **kw)
        r = self._prepare(tracked(models), {"GEMINI_API_KEY": FAKE_KEY,
                                            "PANOPTICON_AGY_AUTH": "key"})
        self.assertEqual("key", r.auth_route)
        for argv, env in envs:
            with self.subTest(launch=argv, route="key"):
                self.assertEqual(FAKE_KEY, env["GEMINI_API_KEY"])

    def test_every_failed_signin_turn_names_the_key_route_when_a_key_is_set(self):
        def bad(cmd, **kw):
            return subprocess.CompletedProcess(
                cmd, 0, stdout=json.dumps({"status": "ERROR", "error": "quota exhausted"}),
                stderr="")

        def timeout(cmd, **kw):
            raise subprocess.TimeoutExpired(cmd, agy_runner.PREFLIGHT_TIMEOUT)
        for turn in (bad, timeout):
            for env, hinted in (({"GEMINI_API_KEY": FAKE_KEY}, True), ({}, False)):
                with self.subTest(turn=turn.__name__, key=hinted):
                    with self.assertRaises(agy_runner.AgyPreflightRefused) as caught:
                        self._prepare(_answers_preflight(turn=turn), env)
                    self.assertEqual(hinted, "runs only when you choose it" in str(caught.exception))
                    self.assertNotIn(FAKE_KEY, str(caught.exception))

    def _agents_log_says_not_signed_in(self, turn):
        """#3620: the owner's measured sequence -- `agy agents` exits 0 and writes BOTH the
        hook-load line and the not-logged-in line into one cli-*.log, which the turn reuses."""
        wrapped = _answers_preflight(turn=turn)

        def fake(cmd, **kw):
            proc = wrapped(cmd, **kw)
            if _args(cmd) == ["agents"]:
                log = os.path.join(cmd[2], "antigravity-cli", "log", "cli-20261113_000000.log")
                with open(log, "a", encoding="utf-8") as fh:
                    fh.write("E1113 errorreport.go:273] error getting token source: %s.\n"
                             % agy_runner.NOT_SIGNED_IN)
            return proc
        return fake

    def test_a_signed_in_turn_passes_though_agents_logged_not_signed_in(self):
        # #3620 regression: the run log is never read for auth, so this run is NOT refused.
        def turn(cmd, **kw):
            log_dir = os.path.join(cmd[2], "antigravity-cli", "log")
            self.assertEqual(["cli-20261113_000000.log"], os.listdir(log_dir))   # one log
            return subprocess.CompletedProcess(cmd, 0, stdout=ENVELOPE, stderr="")
        r = self._prepare(self._agents_log_says_not_signed_in(turn),
                          {"GEMINI_API_KEY": FAKE_KEY})
        self.assertEqual("signin", r.auth_route)

    def test_a_failed_turn_after_that_log_still_names_the_key_route(self):
        # N2 as intended: the hint comes with every failed sign-in turn, not from the log.
        def turn(cmd, **kw):
            return subprocess.CompletedProcess(
                cmd, 0, stdout=json.dumps({"status": "ERROR", "error": "no session"}), stderr="")
        with self.assertRaises(agy_runner.AgyPreflightRefused) as caught:
            self._prepare(self._agents_log_says_not_signed_in(turn), {"GEMINI_API_KEY": FAKE_KEY})
        self.assertIn("runs only when you choose it", str(caught.exception))
        self.assertTrue(str(caught.exception).endswith("[preflight step: turn: envelope]"))

    def test_agents_and_models_timeouts_refuse(self):
        def agents_timeout(cmd, **kw):
            raise subprocess.TimeoutExpired(cmd, agy_runner.MODELS_TIMEOUT)
        wrapped = _answers_preflight()

        def slow_agents(cmd, **kw):
            return agents_timeout(cmd, **kw) if _args(cmd) == ["agents"] else wrapped(cmd, **kw)
        with self.assertRaisesRegex(agy_runner.AgyPreflightRefused, "`agy agents` timed out"):
            self._prepare(slow_agents, {})

        def slow_models(cmd, **kw):
            if _args(cmd) == ["models"]:
                raise subprocess.TimeoutExpired(cmd, agy_runner.MODELS_TIMEOUT)
            raise AssertionError("nothing after a refused listing: %r" % (cmd,))
        with self.assertRaisesRegex(agy_runner.AgyPreflightRefused, "`agy models` timed out"):
            self._prepare(slow_models, {"GEMINI_API_KEY": FAKE_KEY, "PANOPTICON_AGY_AUTH": "key"})

    def test_the_hook_proof_is_read_from_any_of_the_runs_logs(self):
        with tempfile.TemporaryDirectory() as d:
            home = agy_home.build("/s.json", "/w.json", registration_dir=os.path.join(d, "none"),
                                  route="signin")
            self.addCleanup(agy_home.teardown, home, "complete")
            self.assertFalse(agy_home.hook_load_proven(home)[0])
            log_dir = os.path.join(agy_home.gemini_dir(home), "antigravity-cli", "log")
            os.makedirs(log_dir)
            for name, text in (("cli-20261113_000000.log", agy_home.HOOK_LOAD_PROOF),
                               ("cli-20261113_000009.log", "models listed")):
                with open(os.path.join(log_dir, name), "w", encoding="utf-8") as fh:
                    fh.write("I1113 x.go:1] %s\n" % text)
            self.assertEqual((True, ""), agy_home.hook_load_proven(home))
            os.unlink(os.path.join(log_dir, "cli-20261113_000000.log"))
            proven, why = agy_home.hook_load_proven(home)
            self.assertFalse(proven)
            self.assertIn("agy hook-load proof missing", why)


class TestTheKeyRoute(unittest.TestCase):
    """#3576 step 2 and #3613: the Gemini API key as agy's auth, beside agy's own
    sign-in. Fixture homes and environments only; FAKE_KEY is a sentinel, not a key."""

    def _homes(self, d):
        return _fixture_user_home(d)

    def test_the_route_choice(self):
        # #3613 (R2): the sign-in is the default and a key alone never chooses the
        # key route; only PANOPTICON_AGY_AUTH=key does.
        key = {"GEMINI_API_KEY": FAKE_KEY}
        for env, route in (
                ({}, "signin"),
                (key, "signin"),
                (dict(key, PANOPTICON_AGY_AUTH="key"), "key"),
                (dict(key, PANOPTICON_AGY_AUTH="signin"), "signin"),
                ({"PANOPTICON_AGY_AUTH": " "}, "signin"),
                ({"GEMINI_API_KEY": "  "}, "signin")):
            with self.subTest(env=sorted(env), route=route):
                self.assertEqual(route, agy_home.auth_route(env))

    def test_the_route_refusals(self):
        for env, why in (
                ({"PANOPTICON_AGY_AUTH": "key"}, "GEMINI_API_KEY is not set"),
                ({"PANOPTICON_AGY_AUTH": "key", "GEMINI_API_KEY": "  "},
                 "GEMINI_API_KEY is not set"),
                ({"PANOPTICON_AGY_AUTH": "token"}, "PANOPTICON_AGY_AUTH must be one of signin, key"),
                ({"PANOPTICON_AGY_AUTH": "secret-sentinel"},
                 "PANOPTICON_AGY_AUTH must be one of signin, key")):
            with self.subTest(why=why[:40], env=sorted(env)):
                with self.assertRaises(agy_home.AgyAuthUnreachable) as caught:
                    agy_home.auth_route(env)
                self.assertIn(why, str(caught.exception))
                self.assertNotIn("secret-sentinel", str(caught.exception))

    def test_the_message_names_both_routes_and_never_the_keychain_item(self):
        for part in ("Sign in with an interactive `agy` session", "PANOPTICON_AGY_AUTH=key",
                     "GEMINI_API_KEY", "gemini-4-argon-high in place of Carbon",
                     "panopticon never reads it", "#3613"):
            self.assertIn(part, agy_home.AUTH_UNREACHABLE)
        self.assertNotIn("antigravity-oauth-token", agy_home.AUTH_UNREACHABLE)

    def test_a_set_key_that_was_not_chosen_is_named_never_used(self):
        # #3613 (R2): a failed sign-in with a key in the environment says how to
        # choose the key route; it does not choose it.
        with_key = str(agy_home.unreachable({"GEMINI_API_KEY": FAKE_KEY}))
        without = str(agy_home.unreachable({}))
        self.assertTrue(with_key.startswith(agy_home.AUTH_UNREACHABLE))
        self.assertIn("runs only when you choose it", with_key)
        self.assertEqual(agy_home.AUTH_UNREACHABLE, without)
        self.assertNotIn(FAKE_KEY, with_key)

    def test_a_key_route_home_sets_the_provider_and_never_holds_the_key(self):
        with tempfile.TemporaryDirectory() as d:
            user_home, agents_dir = self._homes(d)
            with mock.patch.dict(os.environ, {"GEMINI_API_KEY": FAKE_KEY}):
                home = agy_home.build("/s.json", "/w.json", user_home=user_home,
                                      registration_dir=agents_dir, route="key")
            self.addCleanup(agy_home.teardown, home, "complete")
            with open(os.path.join(agy_home.gemini_dir(home), "antigravity-cli", "settings.json"),
                      encoding="utf-8") as fh:
                self.assertEqual("gemini", json.load(fh)["modelProvider"])
            for root, _dirs, files in os.walk(home):
                for name in files:
                    with open(os.path.join(root, name), "rb") as fh:
                        self.assertNotIn(FAKE_KEY.encode(), fh.read(), name)

    def test_a_signin_route_home_has_no_provider(self):
        with tempfile.TemporaryDirectory() as d:
            user_home, agents_dir = self._homes(d)
            home = agy_home.build("/s.json", "/w.json", user_home=user_home,
                                  registration_dir=agents_dir, route="signin")
            self.addCleanup(agy_home.teardown, home, "complete")
            with open(os.path.join(agy_home.gemini_dir(home), "antigravity-cli", "settings.json"),
                      encoding="utf-8") as fh:
                self.assertNotIn("modelProvider", json.load(fh))

    def test_the_key_is_redacted_wherever_it_could_be_logged(self):
        for text in ("GEMINI_API_KEY=%s" % FAKE_KEY, 'export GEMINI_API_KEY="%s"' % FAKE_KEY,
                     '{"GEMINI_API_KEY": "%s"}' % FAKE_KEY, "key %s in an error" % FAKE_KEY):
            self.assertNotIn(FAKE_KEY, redact.redact(text))

    def test_the_listed_models_parse_from_the_owner_capture(self):
        names = agy_runner.listed_models(KEY_ROUTE_MODELS)
        self.assertEqual(14, len(names))
        self.assertIn("gemini-4-argon-high", names)
        self.assertNotIn("Available", names)
        self.assertFalse(any(n.startswith("gemini-4-carbon") for n in names))
        self.assertEqual(frozenset({"gemini-4-argon-high"}), agy_runner.listed_models(
            "gemini-4-argon-high Gemini 4 Argon (High)\n\n  \n"))

    def test_the_key_route_binding(self):
        listed = agy_runner.listed_models(KEY_ROUTE_MODELS)
        ladder = ("gemini-4-argon-high",)
        for model, effort, explicit, bound in (
                ("gemini-3.8-flash-medium", None, False, "gemini-3.8-flash-medium"),
                ("gemini-4-argon", "high", False, "gemini-4-argon-high"),
                ("gemini-3.1-pro", "low", True, "gemini-3.1-pro-low")):
            with self.subTest(model=model, effort=effort, explicit=explicit):
                # A listed model runs as asked, ladder or not, and records nothing.
                self.assertEqual((bound, None), agy_runner.key_route_model(
                    model, effort, listed, explicit=explicit, ladder=ladder))
        for effort in ("high", "low"):
            with self.subTest(fallback=effort):
                self.assertEqual(
                    ("gemini-4-argon-high",
                     {"requested": "gemini-4-carbon-%s" % effort, "bound": "gemini-4-argon-high",
                      "route": "key", "rung": 1, "reason": "not listed on route key"}),
                    agy_runner.key_route_model("gemini-4-carbon", effort, listed, ladder=ladder))
        # The first LISTED rung wins; an unlisted rung is skipped and the rung number says so.
        self.assertEqual(("gemini-3.8-flash-medium", 2), (lambda r: (r[0], r[1]["rung"]))(
            agy_runner.key_route_model("gemini-4-carbon", "high", listed,
                                       ladder=("gemini-9-unlisted", "gemini-3.8-flash-medium"))))
        for model, effort, explicit, lad, why in (
                ("gemini-4-carbon", "high", True, ladder, "never substituted"),
                ("gemini-4-carbon", "high", False, (), "no fallback ladder applies"),
                ("gemini-3.1-pro", "medium", False, (), "lists no model 'gemini-3.1-pro-medium'"),
                (None, None, False, ladder, "needs a model")):
            with self.subTest(model=model, effort=effort, explicit=explicit, ladder=lad):
                with self.assertRaisesRegex(ValueError, why):
                    agy_runner.key_route_model(model, effort, listed, explicit=explicit,
                                               ladder=lad)
        # A rung the route does not list is not used either.
        with self.assertRaisesRegex(ValueError, r"nor any fallback \(gemini-4-argon-high\)"):
            agy_runner.key_route_model("gemini-4-carbon", "high",
                                       frozenset({"gemini-3.8-flash-medium"}), ladder=ladder)

    def test_the_preflight_default_is_the_carbon_roles_first_key_rung(self):
        # #3582: #3576's hard-coded choice is now the profile ladder; the preflight's
        # key-route default must stay the rung the Carbon roles would bind.
        for role in ("domain_panel", "domain_advisor"):
            with self.subTest(role=role):
                self.assertEqual(agy_runner.KEY_ROUTE_DEFAULT,
                                 model_resolver.registration_config("agy", role)
                                 ["fallbacks"]["key"][0])

    def _key_runner(self, d, seen, models_rc=0, models_out=KEY_ROUTE_MODELS, turns=None):
        def fake(cmd, **kw):
            seen.append((list(cmd), kw))
            if _args(cmd) == ["models"]:
                return subprocess.CompletedProcess(cmd, models_rc, stdout=models_out, stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout=ENVELOPE, stderr="")

        def turn(cmd, **kw):
            if turns is not None:
                turns.append(list(cmd))
            return subprocess.CompletedProcess(cmd, 0, stdout=ENVELOPE, stderr="")
        user_home, agents_dir = self._homes(d)
        patch = mock.patch.dict(os.environ, {"HOME": user_home, "GEMINI_API_KEY": FAKE_KEY,
                                             "PANOPTICON_AGY_AUTH": "key"})
        patch.start()
        self.addCleanup(patch.stop)
        r = agy_runner.Runner("agy", runner=_answers_preflight(fake, turn=turn))
        self.addCleanup(r.teardown, "complete")
        r.prepare(d, os.path.join(d, "run"), registration_dir=agents_dir)
        return r

    def _env(self):
        return {base.ENV_ENTRY_ID: "review-app-SEC",
                base.ENV_WRITE_ALLOWLIST: "/w.json", base.ENV_READ_SCOPE: "/s.json"}

    def test_prepare_lists_the_models_once(self):
        seen = []
        with tempfile.TemporaryDirectory() as d:
            r = self._key_runner(d, seen)
            self.assertEqual("key", r.auth_route)
            self.assertIn("gemini-4-argon-high", r.key_models)
        self.assertEqual([["models"]], [_args(c) for c, _kw in seen])
        self.assertEqual("--gemini_dir", seen[0][0][1])
        self.assertIs(agy_runner.INTERACTIVE_AUTH, seen[0][1]["stop_on"])
        self.assertEqual(FAKE_KEY, seen[0][1]["env"]["GEMINI_API_KEY"])

    def test_prepare_refuses_when_the_listing_fails_or_is_empty(self):
        for rc, out, why in ((1, "", "exited 1"), (2, KEY_ROUTE_MODELS, "exited 2"),
                             (0, "Available models:\n", "listed no models")):
            with self.subTest(why=why), tempfile.TemporaryDirectory() as d:
                with self.assertRaisesRegex(agy_home.AgyAuthUnreachable, why):
                    self._key_runner(d, [], models_rc=rc, models_out=out)

    LADDER = {"key": ["gemini-4-argon-high"]}

    def test_a_carbon_entry_runs_argon_high_with_no_effort_flag(self):
        seen = []
        with tempfile.TemporaryDirectory() as d:
            r = self._key_runner(d, seen)
            with mock.patch("sys.stderr", new_callable=io.StringIO) as err:
                res = r.run_entry(_entry(True, model="gemini-4-carbon", effort="high",
                                         fallbacks=self.LADDER), self._env())
        self.assertTrue(res.ok)
        cmd = seen[-1][0]
        self.assertEqual("gemini-4-argon-high", cmd[cmd.index("--model") + 1])
        self.assertNotIn("--effort", cmd)
        self.assertEqual("gemini-4-argon-high", res.bound_model)
        self.assertEqual({"requested": "gemini-4-carbon-high", "bound": "gemini-4-argon-high",
                          "route": "key", "rung": 1, "reason": "not listed on route key"},
                         res.model_substitution)
        self.assertIn("agy: entry review-app-SEC: gemini-4-carbon-high not listed on route key; "
                      "bound fallback gemini-4-argon-high (rung 1)", err.getvalue())
        self.assertEqual(FAKE_KEY, seen[-1][1]["env"]["GEMINI_API_KEY"])

    def test_a_carbon_entry_with_no_ladder_is_refused_before_launch(self):
        # A strict run's entries carry no ladder: refuse-on-unlisted, as before #3582.
        seen = []
        with tempfile.TemporaryDirectory() as d:
            r = self._key_runner(d, seen)
            res = r.run_entry(_entry(True, model="gemini-4-carbon", effort="high"), self._env())
        self.assertFalse(res.ok)
        self.assertIn("no fallback ladder applies", res.error)
        self.assertEqual(1, len(seen))                          # only `agy models`

    def test_a_strict_run_walks_no_ladder_even_if_the_entry_carries_one(self):
        # #3627 review 1: belt and braces at the runner.
        seen = []
        with tempfile.TemporaryDirectory() as d:
            r = self._key_runner(d, seen)
            with mock.patch.dict(os.environ, {"PANOPTICON_MODEL_STRICT": "1"}):
                res = r.run_entry(_entry(True, model="gemini-4-carbon", effort="high",
                                         fallbacks=self.LADDER), self._env())
        self.assertFalse(res.ok)
        self.assertIn("no fallback ladder applies", res.error)
        self.assertIsNone(res.model_substitution)

    def test_a_quota_failure_on_a_fallback_tries_no_other_rung(self):
        # #3582: quota is never a fallback trigger -- the entry fails typed, once.
        seen = []
        quota = json.dumps({"status": "ERROR", "error": "RESOURCE_EXHAUSTED: quota exceeded"})
        with tempfile.TemporaryDirectory() as d:
            r = self._key_runner(d, seen)
            r.runner = _answers_preflight(lambda cmd, **kw: (
                seen.append((list(cmd), kw)),
                subprocess.CompletedProcess(cmd, 1, stdout=quota, stderr=""))[1])
            res = r.run_entry(_entry(True, model="gemini-4-carbon", effort="high",
                                     fallbacks={"key": ["gemini-4-argon-high",
                                                        "gemini-3.8-flash-medium"]}),
                              self._env())
        self.assertFalse(res.ok)
        self.assertEqual(outage.HOST_FAILURE, res.failure_class)
        launches = [c for c, _kw in seen if "-p" in c]
        self.assertEqual(1, len(launches))
        self.assertEqual("gemini-4-argon-high", launches[0][launches[0].index("--model") + 1])

    def test_a_listed_default_runs_as_is(self):
        seen = []
        with tempfile.TemporaryDirectory() as d:
            r = self._key_runner(d, seen)
            res = r.run_entry(_entry(True, model="gemini-3.8-flash-medium"), self._env())
        cmd = seen[-1][0]
        self.assertEqual("gemini-3.8-flash-medium", cmd[cmd.index("--model") + 1])
        self.assertEqual("gemini-3.8-flash-medium", res.bound_model)

    def test_an_explicit_unlisted_model_is_refused_before_launch(self):
        seen = []
        with tempfile.TemporaryDirectory() as d:
            r = self._key_runner(d, seen)
            entry = dict(_entry(True, model="gemini-4-carbon", effort="high"),
                         model_override=True)
            res = r.run_entry(entry, self._env())
        self.assertFalse(res.ok)
        self.assertIn("lists no model 'gemini-4-carbon-high'", res.error)
        self.assertEqual(outage.HOST_FAILURE, res.failure_class)
        self.assertEqual(1, len(seen))                          # only `agy models`

    def test_the_preflight_turn_on_the_key_route_runs_its_default(self):
        turns = []
        with tempfile.TemporaryDirectory() as d:
            self._key_runner(d, [], turns=turns)
        self.assertEqual(1, len(turns))
        self.assertEqual(["--output-format", "json", "--disable-slash-commands",
                          "--model", agy_runner.KEY_ROUTE_DEFAULT,
                          "-p", agy_runner.PREFLIGHT_PROMPT], _args(turns[0]))

    def test_a_key_route_without_its_default_is_refused_and_leaves_no_run(self):
        listed = "Available models:\ngemini-3.8-flash-medium\tFlash\n"
        with tempfile.TemporaryDirectory() as d:
            before = set(agy_home._LIVE_HOMES)
            with self.assertRaisesRegex(agy_runner.AgyPreflightRefused,
                                        "does not list gemini-4-argon-high"):
                self._key_runner(d, [], models_out=listed)
            self.assertEqual(before, agy_home._LIVE_HOMES)

    def test_the_signin_route_is_the_default_even_with_a_key_exported(self):
        seen = {}
        with tempfile.TemporaryDirectory() as d:
            user_home, agents_dir = _fixture_user_home(d)
            with mock.patch.dict(os.environ, {"HOME": user_home, "GEMINI_API_KEY": FAKE_KEY}):
                def fake(cmd, **kw):
                    seen["cmd"] = cmd
                    return subprocess.CompletedProcess(cmd, 0, stdout=ENVELOPE, stderr="")
                r = agy_runner.Runner("agy", runner=_answers_preflight(fake))
                r.prepare(d, os.path.join(d, "run"), registration_dir=agents_dir)
                self.addCleanup(r.teardown, "complete")
                res = r.run_entry(_entry(True, model="gemini-4-carbon", effort="high"),
                                  self._env())
        self.assertEqual("signin", r.auth_route)
        cmd = seen["cmd"]
        self.assertEqual(["--model", "gemini-4-carbon", "--effort", "high"],
                         cmd[cmd.index("--model"):cmd.index("--model") + 4])
        self.assertIsNone(res.bound_model)

    def test_the_ledger_row_says_what_was_bound(self):
        import scripts.ledger as ledger
        seen = []
        with tempfile.TemporaryDirectory() as d:
            r = self._key_runner(d, seen)
            entry = _entry(False, model="gemini-4-carbon", effort="high",
                           fallbacks=self.LADDER)
            res = r.run_entry(entry, self._env())
            led = ledger.Ledger(os.path.join(d, "ledger"))
            led.record(entry, "review", res, "headless", "agy",
                       timing={"started_at": "2026-11-12T00:00:00Z",
                               "finished_at": "2026-11-12T00:00:01Z", "duration_ms": 1000})
            with open(led.path, encoding="utf-8") as fh:
                row = json.loads(fh.readline())
        self.assertEqual(("gemini-4-carbon", "high", "gemini-4-argon-high"),
                         (row["requested_model"], row["requested_effort"], row["bound_model"]))
        self.assertIsNone(row["model"])
        self.assertEqual({"requested": "gemini-4-carbon-high", "bound": "gemini-4-argon-high",
                          "route": "key", "rung": 1, "reason": "not listed on route key"},
                         row["model_substitution"])


class TestRunEntry(unittest.TestCase):
    def _env(self):
        return {base.ENV_ENTRY_ID: "review-app-SEC",
                base.ENV_WRITE_ALLOWLIST: "/w.json",
                base.ENV_READ_SCOPE: "/s.json"}

    def _fake_run(self, seen):
        def fake(cmd, **kw):
            seen["cmd"], seen["kw"] = cmd, kw
            return subprocess.CompletedProcess(cmd, 0, stdout=ENVELOPE, stderr="")
        return _answers_preflight(fake)

    def test_run_entry_keeps_the_operators_home_and_leads_with_gemini_dir(self):
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
        # #3613: the operator's HOME, so agy reads its own sign-in; the run's
        # configuration comes from --gemini_dir, and no child may open a browser.
        self.assertEqual(user_home, child_env["HOME"])
        self.assertEqual("/usr/bin/false", child_env["BROWSER"])
        self.assertEqual(["agy", "--gemini_dir", os.path.join(r.run_home, "gemini")],
                         seen["cmd"][:3])
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
                r = agy_runner.Runner("agy", runner=_answers_preflight(slow))
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
                r = agy_runner.Runner("agy", runner=_answers_preflight(fake))
                r.prepare(d, os.path.join(d, "run"), registration_dir=agents_dir)
                self.addCleanup(r.teardown, "complete")
                res = r.run_entry(_entry(True, model="gemini-4-argon-high"), self._env())
        self.assertTrue(res.ok)
        self.assertIsNone(res.model)
        self.assertEqual(res.usage["total_tokens"], 15)


if __name__ == "__main__":
    unittest.main()
