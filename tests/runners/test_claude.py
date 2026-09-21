import json
import os
import tempfile
import unittest
from unittest import mock

import pytest

import scripts.read_guard_hook as read_guard_hook
import scripts.runners.base as base
import scripts.runners.claude as claude_runner
import scripts.runners.outage as outage
import scripts._version as version
import scripts.write_guard_hook as write_guard_hook

# #1616 item 8: this file IS the family's launch behaviour, so it is the one
# that opts out of conftest's `run_entry` refusal. Every launch below still
# goes through an injected `runner=<fake>` -- except the one test that exists
# to prove an un-injected Runner refuses.
pytestmark = pytest.mark.claude_runner

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

    def test_every_launch_drops_the_targets_project_and_local_discovery(self):
        # #1657 step 2: the child runs in the REVIEWED TREE, which is where
        # claude discovers `.claude/settings.json`, `.claude/settings.local
        # .json`, `.mcp.json`, `.claude/skills` and `.claude/commands`. A
        # hostile target plants any of those and they load as configuration.
        # `--setting-sources user` drops the project and local settings (and
        # the hooks they declare); `--strict-mcp-config` leaves a launch that
        # passes no `--mcp-config` with no MCP at all; `--disable-slash-
        # commands` is "Disable all skills" (`claude --help`), so it is what
        # closes a planted `.claude/skills/*/SKILL.md` as well as
        # `.claude/commands/**`, and it costs nothing because reviewers run
        # registered `--agent` shells. All three are `claude --help`-attested.
        for enforced in (True, False):
            with self.subTest(enforced=enforced):
                cmd = self.r.command(_entry(enforced), "/run/host-settings.json", max_turns=40)
                self.assertEqual(cmd[cmd.index("--setting-sources") + 1], "user")
                self.assertIn("--strict-mcp-config", cmd)
                self.assertIn("--disable-slash-commands", cmd)
                # `--settings` is a SEPARATE channel that still applies under
                # `--setting-sources user`, which is the only reason the guard
                # hooks in that file still arm.
                self.assertLess(cmd.index("--settings"), cmd.index("--setting-sources"))
                self.assertEqual(cmd[cmd.index("--settings") + 1], "/run/host-settings.json")

    def test_no_launch_ever_unarms_the_guard_hooks(self):
        # `--bare` and `--safe-mode` both DISABLE hooks. Passing either would
        # silently un-arm the read and write guards -- the confinement this
        # host's whole posture rests on -- while looking like hardening.
        for enforced in (True, False):
            cmd = self.r.command(_entry(enforced), "/s.json", max_turns=40)
            for flag in ("--bare", "--safe-mode"):
                with self.subTest(enforced=enforced, flag=flag):
                    self.assertNotIn(flag, cmd)

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

    def test_the_host_surface_is_the_envelopes_own_error_not_the_agents_text(self):
        # #1623 C1: `error` carries 200 characters of the AGENT's reply, so a
        # cell whose finding is about a 403 handler must not read as a 403.
        r = claude_runner.Runner("claude")
        finding = dict(ENVELOPE, is_error=True,
                       result='{"findings": [{"title": "/admin returns 403 Forbidden"}]}')
        res = r.parse_envelope("e1", json.dumps(finding), 0)
        self.assertIsNone(res.host_error)
        self.assertEqual(outage.ENTRY_FAILURE, res.failure_class)
        # ...while the CLI's OWN rendering of a provider refusal does.
        refused = dict(ENVELOPE, is_error=True, result="API Error: 403 Forbidden")
        res = r.parse_envelope("e1", json.dumps(refused), 0)
        self.assertEqual("API Error: 403 Forbidden", res.host_error)
        self.assertEqual(outage.HOST_FAILURE, res.failure_class)
        # ...and so does an envelope that carries a provider error object.
        envelope = dict(ENVELOPE, is_error=True, result="",
                        error={"type": "rate_limit_error", "message": "slow down"})
        self.assertEqual(outage.HOST_FAILURE,
                         r.parse_envelope("e1", json.dumps(envelope), 0).failure_class)

    def test_the_subscription_limit_line_is_host_class_with_no_error_object(self):
        # #1729, tool-confirmed on run 14: the envelope carries NO `error`
        # object at all -- only the CLI's own `result` string -- so
        # `host_error` must come from `outage.cli_error(text)` alone.
        r = claude_runner.Runner("claude")
        line = "You've hit your session limit · resets 10:10am (America/Chicago)"
        envelope = {"type": "result", "subtype": "success", "is_error": True,
                    "result": line, "session_id": "x", "total_cost_usd": 0, "usage": {}}
        res = r.parse_envelope("e1", json.dumps(envelope), 1)
        self.assertFalse(res.ok)
        self.assertEqual(line, res.host_error)
        self.assertEqual(outage.HOST_FAILURE, res.failure_class)
        # ...and the same envelope reported through a clean exit is still
        # host-class: `is_error` is the CLI's own verdict on the turn,
        # independent of the process's exit code.
        res0 = r.parse_envelope("e1", json.dumps(dict(envelope)), 0)
        self.assertFalse(res0.ok)
        self.assertEqual(line, res0.host_error)
        self.assertEqual(outage.HOST_FAILURE, res0.failure_class)

    def test_an_agents_own_opening_words_are_never_the_host(self):
        # N1: `result` is the AGENT's reply, and the gate used to accept
        # anything that merely STARTED with one of its prefixes -- so a review
        # cell whose finding opens "Authentication error handling is missing"
        # read as an auth outage, stopped the run, and took the per-entry cap
        # off itself on the way (for a verify entry that cap is the ONLY bound).
        r = claude_runner.Runner("claude")
        import tests.runners.test_outage as outage_tests
        for text in outage_tests.TestTheHostOutageClassifier.AGENT_OPENERS:
            with self.subTest(text=text):
                for envelope in (dict(ENVELOPE, is_error=True, result=text),
                                 dict(ENVELOPE, result=text)):
                    res = r.parse_envelope("e1", json.dumps(envelope), 1)
                    self.assertIsNone(res.host_error)
                    self.assertEqual(outage.ENTRY_FAILURE, res.failure_class)
        for text in outage_tests.TestTheHostOutageClassifier.CLI_ERRORS:
            with self.subTest(text=text):
                res = r.parse_envelope("e1", json.dumps(
                    dict(ENVELOPE, is_error=True, result=text)), 0)
                self.assertEqual(outage.HOST_FAILURE, res.failure_class)

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

    def test_run_entry_prepares_its_environment_through_launch_env(self):
        # #1626 I2: ONE env preparation. `run_entry` built the child
        # environment inline, so `probes.common._cli_advertises` -- which
        # launches the SAME binary to read its `--help` -- could not reuse it
        # and passed no env at all. The CLAUDECODE pop now lives in
        # `launch_env`, `run_entry` calls it, and the usage probe calls it, so
        # the interrogation and the launch cannot diverge.
        def fake_run(cmd, **kw):
            class P: returncode = 0; stdout = json.dumps(ENVELOPE); stderr = ""
            return P()
        with tempfile.TemporaryDirectory() as d:
            r = claude_runner.Runner("claude", runner=fake_run)
            r.prepare(d, review_root=d)
            with mock.patch.object(r, "launch_env", wraps=r.launch_env) as prepared:
                r.run_entry(_entry(True), {base.ENV_ENTRY_ID: "review-app-SEC"})
        self.assertEqual(1, prepared.call_count)

    def test_launch_env_drops_the_nested_session_marker_with_no_entry_at_all(self):
        # The probe calls it with no overlay and no entry: there is no entry
        # to launch, only a `--help` to read. The pop still has to happen.
        with mock.patch.dict(os.environ, {"PATH": "/p", "CLAUDECODE": "1"}, clear=True):
            env = claude_runner.Runner("claude", runner=lambda *a, **k: None).launch_env()
        self.assertEqual({"PATH": "/p"}, env)

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
    """#1616 item 5: `prepare` resolves the run folder's three paths and
    creates the folder. It does NOT write host-settings.json -- `Guards.arm`
    rewrites that file, through the hooks' own installers, before the first
    launch of every batch, so the content `prepare` used to put there was
    never read by anything."""

    def _run_dir(self, d):
        run_dir = os.path.join(d, ".panopticon", "runs", "t")
        os.makedirs(os.path.dirname(run_dir), exist_ok=True)
        return run_dir

    def test_prepare_resolves_the_paths_and_creates_the_run_folder(self):
        with tempfile.TemporaryDirectory() as d:
            run_dir = self._run_dir(d)
            r = claude_runner.Runner("claude")
            r.prepare(run_dir, review_root=d)
            self.assertTrue(os.path.isdir(run_dir))
            self.assertEqual(r.settings_path, os.path.join(run_dir, base.SETTINGS_FILE))
            self.assertEqual(r.allowlist_path, os.path.join(run_dir, "write-allowlist.json"))
            self.assertEqual(r.scope_path, os.path.join(run_dir, "read-scope.json"))
            self.assertEqual(r.review_root, os.path.abspath(d))
            self.assertFalse(
                os.path.exists(r.settings_path),
                "prepare wrote a settings file that Guards.arm immediately rewrites")
            r.prepare(run_dir, review_root=d)                        # idempotent

    def test_arming_writes_the_settings_file_the_launch_is_pointed_at(self):
        # The contract itself, where it really lives. Both PreToolUse entries,
        # with the absolute allowlist/scope paths baked into the commands, and
        # `command()` pointing `claude -p --settings` at that same file.
        import scripts.orchestrate as orchestrate
        with tempfile.TemporaryDirectory() as d:
            run_dir = self._run_dir(d)
            r = claude_runner.Runner("claude")
            r.prepare(run_dir, review_root=d)
            entry = dict(_entry(True),
                         out_file=os.path.join(run_dir, "findings-app-SEC.json"),
                         scope={"files": [], "dirs": [os.path.abspath(d)]})
            orchestrate.Guards("headless", run_dir=run_dir).arm([entry])
            with open(r.settings_path, encoding="utf-8") as fh:
                settings = json.load(fh)
            self.assertEqual(sorted(settings), ["hooks"])
            pre = settings["hooks"]["PreToolUse"]
            self.assertEqual(len(pre), 2)
            self.assertIn(write_guard_hook._hook_entry(r.allowlist_path), pre)
            self.assertIn(read_guard_hook._hook_entry(r.scope_path), pre)
            self.assertIn(r.settings_path,
                          r.command(entry, r.settings_path, max_turns=40))


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


class TestOutputSchema(unittest.TestCase):
    """D10 ruling 3: `claude -p --json-schema <schema>` constrains the reply
    to the role's published envelope. The CLI takes the schema TEXT, not a
    path -- MEASURED 2026-09-20 on claude 2.1.276, which answers a path with
    "--json-schema is not valid JSON: JSON Parse error: Unrecognized token
    '/'" and exit 1, no envelope, in ~120 ms. Run 14's tool-verify batch
    burned 3 x 103 launches on it before the driver gave up."""

    def setUp(self):
        self.r = claude_runner.Runner("claude")
        self.schema = os.path.abspath(version.reference_path("findings-envelope-schema.json"))

    def test_the_flag_the_family_declares_is_the_one_on_the_argv(self):
        self.assertEqual(("--json-schema",), claude_runner.Runner.OUTPUT_SCHEMA_FLAG)
        entry = dict(_entry(True), output_schema=self.schema)
        cmd = self.r.command(entry, "/s.json", max_turns=40)
        self.assertEqual(cmd[-3], "--json-schema")
        self.assertEqual(cmd[-1], entry["prompt"])
        # The token is the published file's JSON, one line, never its path.
        self.assertNotEqual(self.schema, cmd[-2])
        with open(self.schema, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh), json.loads(cmd[-2]))
        self.assertNotIn("\n", cmd[-2])

    def test_an_entry_with_no_schema_carries_no_flag(self):
        cmd = self.r.command(_entry(True), "/s.json", max_turns=40)
        self.assertNotIn("--json-schema", cmd)

    def test_a_schema_outside_the_published_reference_dir_never_reaches_the_cli(self):
        entry = dict(_entry(True), output_schema="/tmp/mine.json")
        self.assertNotIn("--json-schema", self.r.command(entry, "/s.json", max_turns=40))

    def test_structured_output_is_preferred_over_result_when_present(self):
        # With --json-schema the CLI may return the object in
        # `structured_output` alongside (or instead of) the `result` text.
        # Whichever it does, the loop has to persist the OBJECT.
        body = {"findings": [], "_panopticon": {"run_id": "RID", "role": "domain_panel"}}
        envelope = dict(ENVELOPE, structured_output=body, result="here you go")
        res = self.r.parse_envelope("e1", json.dumps(envelope), 0)
        self.assertEqual(json.loads(res.text), body)

    def test_an_absent_or_empty_structured_output_falls_back_to_result(self):
        for envelope in (ENVELOPE, dict(ENVELOPE, structured_output=None),
                         dict(ENVELOPE, structured_output={})):
            with self.subTest(envelope=sorted(envelope)):
                res = self.r.parse_envelope("e1", json.dumps(envelope), 0)
                self.assertEqual(res.text, ENVELOPE["result"])


class TestATimedOutLaunchKeepsWhatItPrinted(unittest.TestCase):
    """D10 ruling 5: a timed-out entry is often the most expensive one in the
    run, and everything it produced used to be discarded inside the `except`."""

    def test_the_partial_stdout_survives_as_the_results_text(self):
        import subprocess
        partial = '{"type": "result", "result": "```json\\n{\\"findings\\": ['

        def slow(cmd, **kw):
            raise subprocess.TimeoutExpired(cmd, kw.get("timeout"), output=partial.encode())

        with tempfile.TemporaryDirectory() as d:
            r = claude_runner.Runner("claude", runner=slow)
            r.prepare(d, review_root=d)
            res = r.run_entry(_entry(True), {})
        self.assertFalse(res.ok)
        self.assertIn("timed out after", res.error)
        self.assertEqual(partial, res.text)
        # ...and no usage: claude -p prints its envelope only at the end, so a
        # killed launch's stdout carries no figure to read. Recorded as the
        # empty truth rather than a fabricated zero-cost success.
        self.assertEqual({}, res.usage)


class TestTheEntryAgentIsAllowlisted(unittest.TestCase):
    """#1720. `entry["agent"]` arrives through
    `.panopticon/dispatch-request.json`, inside the REVIEWED TREE, and goes
    on the argv as `--agent <name>`. It resolves only among the operator's own
    user-scope agents, so this family's exposure is a SWAP, not a traversal --
    but a swapped shell is still a reviewer running under instructions and
    tool grants nobody in this run chose. And an enforced entry carrying no
    agent at all used to fall through to the bare `--model` branch: an
    unenforced launch reported as an enforced one.
    """

    def _refuse(self, agent):
        launched = []

        def fake_run(cmd, **kw):
            launched.append(cmd)
            class P: returncode = 0; stdout = json.dumps(ENVELOPE); stderr = ""
            return P()

        with tempfile.TemporaryDirectory() as d:
            r = claude_runner.Runner("claude", runner=fake_run)
            r.prepare(d, review_root=d)
            res = r.run_entry(dict(_entry(True), agent=agent), {})
        return res, launched

    def test_a_wrong_but_plausible_agent_is_refused_before_any_launch(self):
        for agent in ("panopticon-scout-evil", "some-operator-agent"):
            res, launched = self._refuse(agent)
            self.assertFalse(res.ok, agent)
            self.assertIn("not a registered panopticon shell", res.error)
            self.assertIn(repr(agent), res.error)
            self.assertEqual([], launched)

    def test_an_enforced_entry_with_no_agent_is_refused_not_downgraded(self):
        res, launched = self._refuse(None)
        self.assertFalse(res.ok)
        self.assertIn("not a registered panopticon shell", res.error)
        self.assertEqual([], launched)

    def test_a_json_array_or_object_agent_is_refused_rather_than_raising(self):
        # Fix round 1, item 1: `run_entry` never raises (spec 4.4), and an
        # array or object `agent` used to escape it as a TypeError.
        for agent in ([], {}, {"a": {"b": "panopticon-domain-panel"}},
                      ["panopticon-domain-panel"]):
            res, launched = self._refuse(agent)
            self.assertFalse(res.ok, agent)
            self.assertIn("not a registered panopticon shell", res.error)
            self.assertIn(repr(str(agent)), res.error)
            self.assertEqual([], launched)

    def test_command_gives_an_enforced_foreign_agent_neither_agent_nor_model(self):
        # Fix round 1, item 2. `command()` is latent behind `run_entry`'s
        # refusal today, but its fall-through still BUILT a bare `--model`
        # argv for an enforced entry -- an unenforced launch one caller away.
        # An enforced entry gets the registered shell or no launch at all.
        r = claude_runner.Runner("claude")
        for agent in ("panopticon-scout-evil", None):
            cmd = r.command(dict(_entry(True), agent=agent),
                            "/run/host-settings.json", max_turns=40)
            self.assertNotIn("--agent", cmd, agent)
            self.assertNotIn("--model", cmd, agent)
        # ...and an UNENFORCED entry is untouched: it still binds its model.
        cmd = r.command(_entry(False), "/run/host-settings.json", max_turns=40)
        self.assertIn("--model", cmd)

    def test_a_registered_agent_still_launches(self):
        res, launched = self._refuse("panopticon-domain-panel")
        self.assertTrue(res.ok, res.error)
        self.assertEqual(1, len(launched))
        self.assertIn("panopticon-domain-panel", launched[0])


class TestTheRolesTheLoopSetsReachTheCheck(unittest.TestCase):
    """#1727: `runner.roles` is the checkpoint's own role set. A REGISTERED
    shell that this checkpoint does not dispatch must be refused exactly as a
    foreign name is -- before any launch."""

    def test_a_registered_but_misrouted_shell_is_refused(self):
        launched = []

        def fake_run(cmd, **kw):
            launched.append(cmd)
            class P: returncode = 0; stdout = json.dumps(ENVELOPE); stderr = ""
            return P()

        with tempfile.TemporaryDirectory() as d:
            r = claude_runner.Runner("claude", runner=fake_run)
            r.prepare(d, review_root=d)
            r.roles = ("advisor", "domain_advisor")
            res = r.run_entry(dict(_entry(True), agent="panopticon-domain-panel"), {})
        self.assertFalse(res.ok)
        self.assertIn("not a registered panopticon shell for this checkpoint", res.error)
        self.assertIn("panopticon-domain-advisor", res.error)
        self.assertEqual([], launched)

    def test_the_right_shell_for_the_roles_still_launches(self):
        launched = []

        def fake_run(cmd, **kw):
            launched.append(cmd)
            class P: returncode = 0; stdout = json.dumps(ENVELOPE); stderr = ""
            return P()

        with tempfile.TemporaryDirectory() as d:
            r = claude_runner.Runner("claude", runner=fake_run)
            r.prepare(d, review_root=d)
            r.roles = ("domain_panel",)
            res = r.run_entry(dict(_entry(True), agent="panopticon-domain-panel"), {})
        self.assertTrue(res.ok, res.error)
        self.assertIn("panopticon-domain-panel", launched[0])

    def test_command_binds_no_agent_for_a_misrouted_shell(self):
        # `command` is the argv builder behind the refusal: it must not put a
        # misrouted shell on the launch line either, or a second caller would.
        r = claude_runner.Runner("claude")
        r.roles = ("advisor",)
        cmd = r.command(dict(_entry(True), agent="panopticon-domain-panel"),
                        "/run/host-settings.json", max_turns=40)
        self.assertNotIn("--agent", cmd)


class TestTheFailedLaunchesStderr(unittest.TestCase):
    """#1732 part 3: what the CLI said on stderr reaches the ledger row.

    Run 14's tool-verify checkpoint failed all 103 launches in ~120 ms with
    `claude -p printed no JSON envelope (exit 1)` -- a message that names the
    symptom and diagnoses nothing. The diagnosis was on stderr the whole time
    (`--json-schema is not valid JSON: JSON Parse error: Unrecognized token
    '/'`) and this runner never read `proc.stderr` at all, so 309 launches and
    ~35 minutes bought one sentence nobody could see.
    """

    SECRET = ("--json-schema is not valid JSON: JSON Parse error: "
              "Unrecognized token '/' (key sk-ant-api03-AAAABBBBCCCCDDDDEEEEFFFF)")

    def _run(self, stdout, returncode, stderr):
        def fake_run(cmd, **kw):
            class P:
                pass
            P.returncode, P.stdout, P.stderr = returncode, stdout, stderr
            return P()
        with tempfile.TemporaryDirectory() as d:
            r = claude_runner.Runner("claude", runner=fake_run)
            r.prepare(d, review_root=d)
            return r.run_entry(_entry(True), {base.ENV_ENTRY_ID: "review-app-SEC"})

    def test_a_failed_launch_carries_the_redacted_head_of_stderr(self):
        res = self._run("", 1, self.SECRET)
        self.assertFalse(res.ok)
        # the error stays exactly what it was -- the row's `stderr` is the
        # diagnosis, not a replacement for the symptom
        self.assertEqual("claude -p printed no JSON envelope (exit 1)", res.error)
        self.assertIn("Unrecognized token", res.stderr)
        self.assertNotIn("sk-ant-", res.stderr)
        self.assertLessEqual(len(res.stderr), base.STDERR_HEAD)

    def test_it_is_bounded_at_the_seams_own_constant(self):
        res = self._run("", 1, "x" * (base.STDERR_HEAD * 3))
        self.assertEqual("x" * base.STDERR_HEAD, res.stderr)

    def test_a_successful_launch_carries_none(self):
        res = self._run(json.dumps(ENVELOPE), 0, self.SECRET)
        self.assertTrue(res.ok)
        self.assertIsNone(res.stderr)

    def test_an_empty_stderr_is_none_not_an_empty_string(self):
        res = self._run("", 1, "   \n")
        self.assertFalse(res.ok)
        self.assertIsNone(res.stderr)
