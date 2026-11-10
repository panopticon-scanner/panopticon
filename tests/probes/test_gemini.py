"""Unit tests for the `gemini` (`@google/gemini-cli`) capability probes (`scripts/probes/gemini.py`)."""
import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts import dispatch, hosts
import scripts.gemini_guard_hook as gemini_guard_hook
import scripts.model_resolver as model_resolver
import scripts.probes.common as probes_common
import scripts.probes.gemini as gemini_probes
import scripts.read_guard_hook as read_guard_hook
import scripts.runners.base as runners_base
import scripts.runners.gemini as gemini_runner
import scripts.runners.gemini_home as gemini_home


HELP_STDOUT = (
    "Usage: gemini [options]\n"
    "  -m, --model <model>\n"
    "  -p, --prompt <prompt>\n"
    "  -o, --output-format <format>\n"
    "  --approval-mode <mode>\n"
    "  --admin-policy <path>\n"
    "  --include-directories <dirs>\n"
)


def _emit_gemini_shells(directory):
    dispatch.emit_host_agents("gemini", directory)


class TestGeminiShellSurfaceProbe(unittest.TestCase):
    def _runner(self, version_out="0.55.1\n", help_out=HELP_STDOUT, rc=0):
        seen = []

        def fake(cmd, **kw):
            seen.append((cmd, kw))
            out = version_out if "--version" in cmd else help_out
            return subprocess.CompletedProcess(cmd, rc, stdout=out, stderr="")

        return fake, seen

    def test_emitted_policy_shells_and_settings_locks_prove_surface(self):
        runner, _seen = self._runner()
        with tempfile.TemporaryDirectory() as d, \
                tempfile.TemporaryDirectory() as sys_dir:
            _emit_gemini_shells(d)
            state, by, detail = gemini_probes.probe_gemini_shell_surface(
                "gemini", registration_dir=d, runner=runner,
                env={}, system_config_dir=sys_dir)
        self.assertEqual(hosts.PROVEN, state, detail)
        self.assertEqual(gemini_probes.GEMINI_SHELL_SURFACE, by)
        self.assertIn("0.55", detail)
        self.assertIn("5/5", detail)

    def test_missing_shells_refute(self):
        runner, _ = self._runner()
        with tempfile.TemporaryDirectory() as d, \
                tempfile.TemporaryDirectory() as sys_dir:
            state, _by, detail = gemini_probes.probe_gemini_shell_surface(
                "gemini", registration_dir=d, runner=runner,
                env={}, system_config_dir=sys_dir)
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("no policy shell", detail)

    def test_policy_allowing_forbidden_tool_refutes(self):
        runner, _ = self._runner()
        with tempfile.TemporaryDirectory() as d, \
                tempfile.TemporaryDirectory() as sys_dir:
            _emit_gemini_shells(d)
            scout = os.path.join(d, "panopticon-scout.toml")
            with open(scout, encoding="utf-8") as fh:
                text = fh.read()
            text = text.replace(
                'toolName = "run_shell_command"\ndecision = "deny"\npriority = 950',
                'toolName = "run_shell_command"\ndecision = "allow"\npriority = 900',
            )
            with open(scout, "w", encoding="utf-8") as fh:
                fh.write(text)
            state, _by, detail = gemini_probes.probe_gemini_shell_surface(
                "gemini", registration_dir=d, runner=runner,
                env={}, system_config_dir=sys_dir)
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("run_shell_command", detail)

    def test_policy_missing_catchall_deny_refutes(self):
        runner, _ = self._runner()
        with tempfile.TemporaryDirectory() as d, \
                tempfile.TemporaryDirectory() as sys_dir:
            _emit_gemini_shells(d)
            scout = os.path.join(d, "panopticon-scout.toml")
            with open(scout, encoding="utf-8") as fh:
                text = fh.read()
            text = text.replace(
                '[[rule]]\ntoolName = "*"\ndecision = "deny"\npriority = 100\n',
                "",
            )
            with open(scout, "w", encoding="utf-8") as fh:
                fh.write(text)
            state, _by, detail = gemini_probes.probe_gemini_shell_surface(
                "gemini", registration_dir=d, runner=runner,
                env={}, system_config_dir=sys_dir)
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("catch-all deny", detail)

    def test_policy_missing_mcp_wildcard_deny_refutes(self):
        runner, _ = self._runner()
        with tempfile.TemporaryDirectory() as d, \
                tempfile.TemporaryDirectory() as sys_dir:
            _emit_gemini_shells(d)
            scout = os.path.join(d, "panopticon-scout.toml")
            with open(scout, encoding="utf-8") as fh:
                text = fh.read()
            text = text.replace(
                '[[rule]]\nmcpName = "*"\ntoolName = "*"\ndecision = "deny"\npriority = 950\n',
                "",
            )
            with open(scout, "w", encoding="utf-8") as fh:
                fh.write(text)
            state, _by, detail = gemini_probes.probe_gemini_shell_surface(
                "gemini", registration_dir=d, runner=runner,
                env={}, system_config_dir=sys_dir)
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("MCP wildcard deny", detail)

    def test_policy_with_extra_rule_keys_or_top_level_table_refutes(self):
        runner, _ = self._runner()
        with tempfile.TemporaryDirectory() as d, \
                tempfile.TemporaryDirectory() as sys_dir:
            _emit_gemini_shells(d)
            scout = os.path.join(d, "panopticon-scout.toml")
            with open(scout, encoding="utf-8") as fh:
                orig = fh.read()
            for mutated, expected_fragment in (
                ('modes = ["plan"]\n' + orig, "unexpected top-level key"),
                (orig.replace('priority = 900', 'priority = 900\nmodes = ["plan"]'),
                 "unsupported or missing rule keys"),
                (orig.replace('priority = 900', 'priority = 900\nargsPattern = ".*"'),
                 "unsupported or missing rule keys"),
                (orig.replace('priority = 900', 'priority = 900\ninteractive = false'),
                 "unsupported or missing rule keys"),
            ):
                with self.subTest(expected=expected_fragment):
                    with open(scout, "w", encoding="utf-8") as fh:
                        fh.write(mutated)
                    state, _by, detail = gemini_probes.probe_gemini_shell_surface(
                        "gemini", registration_dir=d, runner=runner,
                        env={}, system_config_dir=sys_dir)
                    self.assertEqual(hosts.REFUTED, state)
                    self.assertIn(expected_fragment, detail)

    def test_system_policies_or_system_settings_or_env_overrides_refute(self):
        runner, _ = self._runner()
        with tempfile.TemporaryDirectory() as d:
            _emit_gemini_shells(d)
            with tempfile.TemporaryDirectory() as sys_dir:
                pol_dir = os.path.join(sys_dir, "policies")
                os.makedirs(pol_dir, exist_ok=True)
                with open(os.path.join(pol_dir, "corp.toml"), "w", encoding="utf-8") as fh:
                    fh.write('[[rule]]\ntoolName = "*"\ndecision = "allow"\npriority = 999\n')
                state, _by, detail = gemini_probes.probe_gemini_shell_surface(
                    "gemini", registration_dir=d, runner=runner,
                    env={}, system_config_dir=sys_dir)
                self.assertEqual(hosts.REFUTED, state)
                self.assertIn("corp.toml", detail)

            with tempfile.TemporaryDirectory() as sys_dir:
                with open(os.path.join(sys_dir, "settings.json"), "w", encoding="utf-8") as fh:
                    fh.write("{}")
                state, _by, detail = gemini_probes.probe_gemini_shell_surface(
                    "gemini", registration_dir=d, runner=runner,
                    env={}, system_config_dir=sys_dir)
                self.assertEqual(hosts.REFUTED, state)
                self.assertIn("settings.json is present", detail)

            with tempfile.TemporaryDirectory() as sys_dir:
                state, _by, detail = gemini_probes.probe_gemini_shell_surface(
                    "gemini", registration_dir=d, runner=runner,
                    env={"GEMINI_CLI_SYSTEM_SETTINGS_PATH": "/etc/custom.json"},
                    system_config_dir=sys_dir)
                self.assertEqual(hosts.REFUTED, state)
                self.assertIn("GEMINI_CLI_SYSTEM_SETTINGS_PATH", detail)

    def test_gemini_api_key_selected_type_without_env_var_refutes_with_remedy(self):
        runner, _ = self._runner()
        with tempfile.TemporaryDirectory() as d, \
                tempfile.TemporaryDirectory() as sys_dir, \
                tempfile.TemporaryDirectory() as home:
            _emit_gemini_shells(d)
            os.makedirs(os.path.join(home, ".gemini"), exist_ok=True)
            with open(os.path.join(home, ".gemini", "settings.json"), "w", encoding="utf-8") as fh:
                json.dump({"security": {"auth": {"selectedType": "gemini-api-key"}}}, fh)
            with mock.patch.dict(os.environ, {"HOME": home}, clear=True):
                state, _by, detail = gemini_probes.probe_gemini_shell_surface(
                    "gemini", registration_dir=d, runner=runner,
                    env={}, system_config_dir=sys_dir)
            self.assertEqual(hosts.REFUTED, state)
            self.assertIn(gemini_home.MISSING_API_KEY_REMEDY, detail)

            with mock.patch.dict(os.environ, {"HOME": home, "GEMINI_API_KEY": "secret-val"}, clear=True):
                state_ok, _by, detail_ok = gemini_probes.probe_gemini_shell_surface(
                    "gemini", registration_dir=d, runner=runner,
                    env={"GEMINI_API_KEY": "secret-val"}, system_config_dir=sys_dir)
            self.assertEqual(hosts.PROVEN, state_ok, detail_ok)
            self.assertNotIn("secret-val", detail_ok)

    def test_unescaped_at_in_runner_command_refutes(self):
        runner, _ = self._runner()
        with tempfile.TemporaryDirectory() as d, \
                tempfile.TemporaryDirectory() as sys_dir:
            _emit_gemini_shells(d)
            with mock.patch.object(gemini_runner, "escape_prompt_at_tokens",
                                   side_effect=lambda p: p):
                state, _by, detail = gemini_probes.probe_gemini_shell_surface(
                    "gemini", registration_dir=d, runner=runner,
                    env={}, system_config_dir=sys_dir)
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("unescaped '@'", detail)

    def test_narrowed_tool_vocabulary_refutes(self):
        runner, _ = self._runner()
        with tempfile.TemporaryDirectory() as d, \
                tempfile.TemporaryDirectory() as sys_dir:
            _emit_gemini_shells(d)
            narrow = {"0.55": gemini_home.TOOL_VOCABULARY["0.55"] - {"read_file"}}
            with mock.patch.dict(gemini_home.TOOL_VOCABULARY, narrow):
                state, _by, detail = gemini_probes.probe_gemini_shell_surface(
                    "gemini", registration_dir=d, runner=runner,
                    env={}, system_config_dir=sys_dir)
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("match nothing", detail)

    def test_uncovered_version_is_unknown(self):
        runner, _ = self._runner(version_out="9.99.0\n")
        with tempfile.TemporaryDirectory() as d, \
                tempfile.TemporaryDirectory() as sys_dir:
            _emit_gemini_shells(d)
            state, _by, detail = gemini_probes.probe_gemini_shell_surface(
                "gemini", registration_dir=d, runner=runner,
                env={}, system_config_dir=sys_dir)
        self.assertEqual(hosts.UNKNOWN, state)
        self.assertIn("9.99", detail)

    def test_shadow_shell_in_user_gemini_agents_refutes(self):
        with tempfile.TemporaryDirectory() as home, \
                tempfile.TemporaryDirectory() as target:
            shadow_dir = os.path.join(home, ".gemini", "agents")
            os.makedirs(shadow_dir, exist_ok=True)
            with open(os.path.join(shadow_dir, "panopticon-scout.md"), "w",
                      encoding="utf-8") as fh:
                fh.write("---\nname: panopticon-scout\n---\n")
            with mock.patch.dict(os.environ, {"HOME": home}):
                state, by, detail = probes_common.probe_shadow_shells("gemini", target)
        self.assertEqual(hosts.REFUTED, state)
        self.assertEqual(probes_common.SHADOW_SHELL_SCAN, by)
        self.assertIn(".gemini/agents/panopticon-scout.md", detail)

    def test_settings_locks_drift_or_context_filename_present_refutes(self):
        runner, _ = self._runner()
        with tempfile.TemporaryDirectory() as d, \
                tempfile.TemporaryDirectory() as sys_dir:
            _emit_gemini_shells(d)
            unlocked = gemini_home.settings_document("/s.json", "/w.json")
            unlocked["experimental"]["enableAgents"] = True
            with mock.patch.object(gemini_home, "settings_document",
                                   return_value=unlocked):
                state, _by, detail = gemini_probes.probe_gemini_shell_surface(
                    "gemini", registration_dir=d, runner=runner,
                    env={}, system_config_dir=sys_dir)
            self.assertEqual(hosts.REFUTED, state)
            self.assertIn("experimental.enableAgents", detail)

            with_filename = gemini_home.settings_document("/s.json", "/w.json")
            with_filename["context"]["fileName"] = "CUSTOM.md"
            with mock.patch.object(gemini_home, "settings_document",
                                   return_value=with_filename):
                state2, _by2, detail2 = gemini_probes.probe_gemini_shell_surface(
                    "gemini", registration_dir=d, runner=runner,
                    env={}, system_config_dir=sys_dir)
            self.assertEqual(hosts.REFUTED, state2)
            self.assertIn("context.fileName must be omitted", detail2)


class TestGeminiReadAndWriteGuardProbes(unittest.TestCase):
    def test_read_guard_proven_with_wildcard_matcher_and_armed_payloads(self):
        state, by, detail = gemini_probes.probe_gemini_read_guard("gemini")
        self.assertEqual(hosts.PROVEN, state, detail)
        self.assertEqual(gemini_probes.GEMINI_READ_GUARD, by)
        self.assertIn("23/23 payloads", detail)
        self.assertIn("BeforeTool (*)", detail)

    def test_read_guard_refutes_when_matcher_narrowed_from_wildcard(self):
        state, _by, detail = gemini_probes.probe_gemini_read_guard(
            "gemini", matcher="read_file|write_file")
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("expected '*'", detail)

    def test_write_guard_proven_with_wildcard_matcher_and_content_sanitization(self):
        state, by, detail = gemini_probes.probe_gemini_write_guard("gemini")
        self.assertEqual(hosts.PROVEN, state, detail)
        self.assertEqual(gemini_probes.GEMINI_WRITE_GUARD, by)
        self.assertIn("12/12 payloads", detail)
        self.assertIn("BeforeTool (*)", detail)

    def test_write_guard_refutes_when_matcher_narrowed_from_wildcard(self):
        state, _by, detail = gemini_probes.probe_gemini_write_guard(
            "gemini", matcher="write_file")
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("expected '*'", detail)

    def test_relative_and_dotdot_paths_are_denied_before_resolution(self):
        with tempfile.TemporaryDirectory() as sandbox:
            real_box = os.path.realpath(sandbox)
            ws_dir = os.path.join(real_box, "workspace")
            cfg_dir = os.path.join(real_box, "config")
            os.makedirs(ws_dir, exist_ok=True)
            os.makedirs(cfg_dir, exist_ok=True)
            in_file = os.path.join(ws_dir, "allowed.py")
            out_json = os.path.join(ws_dir, "findings.json")
            with open(in_file, "w", encoding="utf-8") as fh:
                fh.write("x = 1\n")
            scope_path = os.path.join(real_box, "read-scope.json")
            allowlist_path = os.path.join(real_box, "write-allowlist.json")
            scopes = read_guard_hook.scope_from_plan([
                {"id": "e1", "scope": {"files": [in_file], "dirs": [ws_dir], "reads": []}}
            ])
            with open(scope_path, "w", encoding="utf-8") as fh:
                json.dump(read_guard_hook.stamp_rows(scopes), fh)
            with open(allowlist_path, "w", encoding="utf-8") as fh:
                json.dump({"version": 2, "entries": {"e1": [out_json]}, "paths": [out_json]}, fh)

            env = {"PANOPTICON_ENTRY_ID": "e1"}
            old_cwd = os.getcwd()
            try:
                os.chdir(cfg_dir)
                cases = (
                    ("read_file", {"file_path": "allowed.py"}),
                    ("read_file", {"file_path": "../workspace/allowed.py"}),
                    ("grep_search", {"dir_path": "allowed.py", "pattern": "x"}),
                    ("grep_search", {"dir_path": "../workspace/allowed.py", "pattern": "x"}),
                    ("list_directory", {"dir_path": "."}),
                    ("list_directory", {"dir_path": "../workspace"}),
                    ("glob", {"dir_path": ".", "pattern": "*.py"}),
                    ("glob", {"dir_path": "../workspace", "pattern": "*.py"}),
                    ("write_file", {"file_path": "findings.json", "content": "{}"}),
                    ("write_file", {"file_path": "../workspace/findings.json", "content": "{}"}),
                )
                for tool_name, args in cases:
                    with self.subTest(tool=tool_name, args=args):
                        allow, reason = gemini_guard_hook.adjudicate(
                            {"tool_name": tool_name, "tool_input": args},
                            scope_path, allowlist_path, env=env)
                        self.assertFalse(allow, reason)
                        self.assertIn("absolute", reason)
            finally:
                os.chdir(old_cwd)

    def test_grep_search_include_pattern_climb_git_magic_and_unknown_keys_are_denied(self):
        with tempfile.TemporaryDirectory() as sandbox:
            real_box = os.path.realpath(sandbox)
            in_dir = os.path.join(real_box, "granted")
            os.makedirs(in_dir, exist_ok=True)
            in_file = os.path.join(in_dir, "allowed.py")
            with open(in_file, "w", encoding="utf-8") as fh:
                fh.write("x = 1\n")
            scope_path = os.path.join(real_box, "read-scope.json")
            allowlist_path = os.path.join(real_box, "write-allowlist.json")
            scopes = read_guard_hook.scope_from_plan([
                {"id": "e1", "scope": {"files": [in_file], "dirs": [in_dir], "reads": []}}
            ])
            with open(scope_path, "w", encoding="utf-8") as fh:
                json.dump(read_guard_hook.stamp_rows(scopes), fh)
            with open(allowlist_path, "w", encoding="utf-8") as fh:
                json.dump({"version": 2, "entries": {}, "paths": []}, fh)

            bound_env = {"PANOPTICON_ENTRY_ID": "e1"}

            allow_ok, reason_ok = gemini_guard_hook.adjudicate(
                {"tool_name": "grep_search",
                 "tool_input": {"dir_path": in_dir, "pattern": "x",
                                "include_pattern": "allowed.py"}},
                scope_path, allowlist_path, env=bound_env)
            self.assertTrue(allow_ok, reason_ok)

            for label, bad_input, fragment in (
                ("ungranted_dir", {"dir_path": real_box, "pattern": "x"},
                 "grep_search over a directory is denied"),
                ("include_pattern_climb",
                 {"dir_path": in_dir, "pattern": "x", "include_pattern": "../outside.py"},
                 "denied"),
                ("include_pattern_git_magic",
                 {"dir_path": in_dir, "pattern": "x", "include_pattern": ":(top)**"},
                 "git pathspec magic"),
                ("exclude_pattern_git_magic",
                 {"dir_path": in_dir, "pattern": "x", "exclude_pattern": ":(glob)**"},
                 "git pathspec magic"),
                ("dead_include_key",
                 {"dir_path": in_dir, "pattern": "x", "include": "allowed.py"},
                 "unsupported tool_input key(s): include"),
            ):
                with self.subTest(case=label):
                    allow, reason = gemini_guard_hook.adjudicate(
                        {"tool_name": "grep_search", "tool_input": bad_input},
                        scope_path, allowlist_path, env=bound_env)
                    self.assertFalse(allow, reason)
                    self.assertIn(fragment, reason)

    def test_argv_is_authoritative_and_env_policy_paths_never_override(self):
        with tempfile.TemporaryDirectory() as sandbox:
            real_box = os.path.realpath(sandbox)
            in_file = os.path.join(real_box, "allowed.py")
            other_file = os.path.join(real_box, "other.py")
            for p in (in_file, other_file):
                with open(p, "w", encoding="utf-8") as fh:
                    fh.write("x = 1\n")
            argv_scope = os.path.join(real_box, "argv-scope.json")
            env_scope = os.path.join(real_box, "env-scope.json")
            allowlist_path = os.path.join(real_box, "write-allowlist.json")
            with open(argv_scope, "w", encoding="utf-8") as fh:
                json.dump(read_guard_hook.stamp_rows(read_guard_hook.scope_from_plan([
                    {"id": "e1", "scope": {"files": [in_file], "dirs": [], "reads": []}}
                ])), fh)
            with open(env_scope, "w", encoding="utf-8") as fh:
                json.dump(read_guard_hook.stamp_rows(read_guard_hook.scope_from_plan([
                    {"id": "e1", "scope": {"files": [other_file], "dirs": [], "reads": []}}
                ])), fh)
            with open(allowlist_path, "w", encoding="utf-8") as fh:
                json.dump({"version": 2, "entries": {}, "paths": []}, fh)

            allow, reason = gemini_guard_hook.adjudicate(
                {"tool_name": "read_file", "tool_input": {"file_path": other_file}},
                argv_scope, allowlist_path,
                env={"PANOPTICON_ENTRY_ID": "e1",
                     "PANOPTICON_READ_SCOPE": env_scope})
            self.assertFalse(allow)
            self.assertIn("outside your cell's scope", reason)

            stdin = io.StringIO(json.dumps({
                "tool_name": "read_file",
                "tool_input": {"file_path": other_file},
            }))
            stdout = io.StringIO()
            with mock.patch("sys.stdin", stdin), contextlib.redirect_stdout(stdout):
                rc = gemini_guard_hook.main(
                    [],
                    env={"PANOPTICON_ENTRY_ID": "e1",
                         "PANOPTICON_READ_SCOPE": env_scope,
                         "PANOPTICON_WRITE_ALLOWLIST": allowlist_path})
            self.assertEqual(0, rc)
            verdict = json.loads(stdout.getvalue())
            self.assertEqual("deny", verdict["decision"])
            self.assertIn("bad hook invocation", verdict["reason"])

    def test_main_crash_handler_denies_fail_closed(self):
        stdin = io.StringIO(json.dumps({
            "tool_name": "read_file",
            "tool_input": {"file_path": "/abs/a.py"},
        }))
        stdout = io.StringIO()
        with mock.patch("sys.stdin", stdin), \
                contextlib.redirect_stdout(stdout), \
                mock.patch.object(gemini_guard_hook, "adjudicate",
                                  side_effect=RuntimeError("unexpected crash")):
            rc = gemini_guard_hook.main(["/s.json", "/w.json"],
                                        env={"PANOPTICON_ENTRY_ID": "e1"})
        self.assertEqual(0, rc)
        verdict = json.loads(stdout.getvalue())
        self.assertEqual("deny", verdict["decision"])
        self.assertIn("gemini guard crashed: unexpected crash", verdict["reason"])

    def test_denial_log_drops_write_file_content_and_logs_path_and_length_only(self):
        with tempfile.TemporaryDirectory() as sandbox:
            real_box = os.path.realpath(sandbox)
            scope_path = os.path.join(real_box, "read-scope.json")
            allowlist_path = os.path.join(real_box, "write-allowlist.json")
            denial_log = os.path.join(real_box, "denials.jsonl")
            with open(scope_path, "w", encoding="utf-8") as fh:
                json.dump({}, fh)
            with open(allowlist_path, "w", encoding="utf-8") as fh:
                json.dump({"version": 2, "entries": {"e1": ["/abs/allowed.json"]},
                           "paths": ["/abs/allowed.json"]}, fh)
            secret_body = "SECRET_WRITE_CONTENT_PAYLOAD_999"
            stdin = io.StringIO(json.dumps({
                "tool_name": "write_file",
                "tool_input": {"file_path": "/abs/forbidden.json",
                               "content": secret_body},
            }))
            stdout = io.StringIO()
            with mock.patch("sys.stdin", stdin), contextlib.redirect_stdout(stdout):
                rc = gemini_guard_hook.main(
                    [scope_path, allowlist_path],
                    env={"PANOPTICON_ENTRY_ID": "e1",
                         gemini_guard_hook.ENV_DENIAL_LOG: denial_log})
            self.assertEqual(0, rc)
            with open(denial_log, encoding="utf-8") as fh:
                raw_log = fh.read()
            self.assertNotIn(secret_body, raw_log)
            rec = json.loads(raw_log.strip())
            self.assertEqual("write_file", rec["tool"])
            self.assertEqual(
                {"file_path": "/abs/forbidden.json", "content_length": len(secret_body)},
                rec["args"])


class TestGeminiModelBoundProbe(unittest.TestCase):
    def _help_runner(self, text=HELP_STDOUT, rc=0):
        def fake(cmd, **kw):
            return subprocess.CompletedProcess(cmd, rc, stdout=text, stderr="")
        return fake

    def test_emitted_policy_metadata_and_argv_prove_binding(self):
        with tempfile.TemporaryDirectory() as d:
            _emit_gemini_shells(d)
            state, by, detail = gemini_probes.probe_gemini_model_bound(
                "gemini", registration_dir=d, runner=self._help_runner())
        self.assertEqual(hosts.PROVEN, state, detail)
        self.assertEqual(gemini_probes.GEMINI_MODEL_BOUND, by)
        self.assertIn("gemini-3.6-flash", detail)

    def test_policy_model_header_drift_refutes(self):
        with tempfile.TemporaryDirectory() as d:
            _emit_gemini_shells(d)
            panel = os.path.join(d, "panopticon-domain-panel.toml")
            with open(panel, encoding="utf-8") as fh:
                text = fh.read().replace(
                    "# panopticon-model: gemini-3.6-flash",
                    "# panopticon-model: gemini-3.5-flash-lite")
            with open(panel, "w", encoding="utf-8") as fh:
                fh.write(text)
            state, _by, detail = gemini_probes.probe_gemini_model_bound(
                "gemini", registration_dir=d, runner=self._help_runner())
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("declares model 'gemini-3.5-flash-lite'", detail)

    def test_silent_model_reroute_in_ledger_refutes_model_binding(self):
        with tempfile.TemporaryDirectory() as d:
            _emit_gemini_shells(d)
            settings = os.path.join(d, "host-settings.json")
            ledger_path = os.path.join(d, runners_base.LEDGER_FILE)
            with open(ledger_path, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({
                    "entry_id": "scout",
                    "host": "gemini",
                    "checkpoint": "scout",
                    "requested_model": "gemini-3.6-flash",
                    "model": "gemini-3.5-flash-lite",
                    "ok": True,
                }) + "\n")
            state, by, detail = gemini_probes.probe_gemini_model_bound(
                "gemini", registration_dir=d, settings_path=settings,
                runner=self._help_runner())
        self.assertEqual(hosts.REFUTED, state)
        self.assertEqual(gemini_probes.GEMINI_MODEL_BOUND, by)
        self.assertIn("silent model reroute", detail)
        self.assertIn("gemini-3.6-flash", detail)
        self.assertIn("gemini-3.5-flash-lite", detail)

    def test_unknown_catalogue_model_refutes(self):
        with tempfile.TemporaryDirectory() as d:
            _emit_gemini_shells(d)
            with mock.patch.object(model_resolver, "resolve_model",
                                   return_value={"model": "not-in-catalogue"}):
                state, _by, detail = gemini_probes.probe_gemini_model_bound(
                    "gemini", registration_dir=d, runner=self._help_runner())
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("not in runners.gemini.KNOWN_MODELS", detail)

    def test_all_roles_unbound_returns_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            _emit_gemini_shells(d)
            for name in os.listdir(d):
                p = os.path.join(d, name)
                with open(p, encoding="utf-8") as fh:
                    text = fh.read()
                text = text.replace(
                    "# panopticon-model: gemini-3.6-flash",
                    "# panopticon-model: inherit"
                )
                with open(p, "w", encoding="utf-8") as fh:
                    fh.write(text)
            with mock.patch.object(model_resolver, "registration_model",
                                   return_value=None), \
                    mock.patch.object(model_resolver, "resolve_model",
                                      return_value={"model": None}):
                state, _by, detail = gemini_probes.probe_gemini_model_bound(
                    "gemini", registration_dir=d, runner=self._help_runner())
        self.assertEqual(hosts.UNKNOWN, state)
        self.assertIn("no role carries an entry model", detail)


class TestGeminiUsageEnvelopeProbe(unittest.TestCase):
    def _help_runner(self, text=HELP_STDOUT, rc=0):
        def fake(cmd, **kw):
            return subprocess.CompletedProcess(cmd, rc, stdout=text, stderr="")
        return fake

    def test_no_ledger_is_unknown(self):
        state, by, detail = gemini_probes.probe_gemini_usage_envelope(
            "gemini", runner=self._help_runner())
        self.assertEqual(hosts.UNKNOWN, state, detail)
        self.assertEqual(gemini_probes.GEMINI_USAGE_ENVELOPE, by)
        self.assertIn("no run ledger path", detail)

        with tempfile.TemporaryDirectory() as d:
            settings = os.path.join(d, "host-settings.json")
            state, _by, detail = gemini_probes.probe_gemini_usage_envelope(
                "gemini", settings_path=settings, runner=self._help_runner())
            self.assertEqual(hosts.UNKNOWN, state, detail)
            self.assertIn("no dispatch-ledger.jsonl exists", detail)

    def test_empty_ledger_is_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            settings = os.path.join(d, "host-settings.json")
            ledger = os.path.join(d, runners_base.LEDGER_FILE)
            with open(ledger, "w", encoding="utf-8") as fh:
                fh.write("")
            state, _by, detail = gemini_probes.probe_gemini_usage_envelope(
                "gemini", settings_path=settings, runner=self._help_runner())
            self.assertEqual(hosts.UNKNOWN, state, detail)
            self.assertIn("no completed gemini entries yet", detail)

    def test_non_gemini_rows_only_is_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            settings = os.path.join(d, "host-settings.json")
            ledger = os.path.join(d, runners_base.LEDGER_FILE)
            with open(ledger, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({
                    "entry_id": "e1", "host": "claude", "ok": True,
                    "usage": {"input_tokens": 100, "output_tokens": 20},
                }) + "\n")
            state, _by, detail = gemini_probes.probe_gemini_usage_envelope(
                "gemini", settings_path=settings, runner=self._help_runner())
            self.assertEqual(hosts.UNKNOWN, state, detail)
            self.assertIn("no completed gemini entries yet", detail)

    def test_gemini_row_with_usage_proves_and_row_without_usage_refutes(self):
        with tempfile.TemporaryDirectory() as d:
            settings = os.path.join(d, "host-settings.json")
            ledger = os.path.join(d, runners_base.LEDGER_FILE)
            with open(ledger, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({
                    "entry_id": "e1", "host": "gemini", "ok": True,
                    "usage": {"input_tokens": 10, "output_tokens": 5},
                }) + "\n")
            state, _by, detail = gemini_probes.probe_gemini_usage_envelope(
                "gemini", settings_path=settings, runner=self._help_runner())
            self.assertEqual(hosts.PROVEN, state, detail)
            self.assertIn("1 gemini entries carry usage", detail)

            with open(ledger, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({
                    "entry_id": "e1", "host": "gemini", "ok": True, "usage": {},
                }) + "\n")
            state, _by, detail = gemini_probes.probe_gemini_usage_envelope(
                "gemini", settings_path=settings, runner=self._help_runner())
            self.assertEqual(hosts.REFUTED, state)
            self.assertIn("carries no token counts", detail)

    def test_cache_read_only_ledger_row_proves_usage(self):
        with tempfile.TemporaryDirectory() as d:
            settings = os.path.join(d, "host-settings.json")
            ledger = os.path.join(d, runners_base.LEDGER_FILE)
            with open(ledger, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({
                    "entry_id": "e1", "host": "gemini", "ok": True,
                    "usage": {
                        "input_tokens": 0,
                        "output_tokens": 0,
                        "cache_read_input_tokens": 80,
                        "total_tokens": 0,
                    },
                }) + "\n")
            state, _by, detail = gemini_probes.probe_gemini_usage_envelope(
                "gemini", settings_path=settings, runner=self._help_runner())
            self.assertEqual(hosts.PROVEN, state, detail)
            self.assertIn("1 gemini entries carry usage", detail)

    def test_broken_parse_envelope_mapping_refutes(self):
        broken = runners_base.RunResult(
            entry_id="probe", ok=True, text="", usage={},
            cost_usd=None, model=None, session_id=None, denials=[], error=None)
        with mock.patch.object(gemini_runner.Runner, "parse_envelope", return_value=broken):
            state, _by, detail = gemini_probes.probe_gemini_usage_envelope(
                "gemini", runner=self._help_runner())
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("failed standard usage self-test", detail)


class TestGeminiLiveCanary(unittest.TestCase):
    def test_simulated_runner_exercises_live_canary_path(self):
        def fake_gemini(cmd, **kw):
            self.assertIn("--approval-mode", cmd)
            self.assertEqual(cmd[cmd.index("--approval-mode") + 1], "yolo")
            self.assertIn("--admin-policy", cmd)
            policy_path = cmd[cmd.index("--admin-policy") + 1]
            self.assertTrue(os.path.isfile(policy_path))
            env = kw.get("env") or {}
            log_path = env.get(gemini_guard_hook.ENV_DENIAL_LOG)
            if log_path:
                with open(log_path, "w", encoding="utf-8") as fh:
                    fh.write(json.dumps({
                        "tool": "read_file",
                        "args": {"file_path": "/outside"},
                        "reason": "outside scope",
                    }) + "\n")
            out = json.dumps({
                "session_id": "canary-sess",
                "response": "allowed_value = 42",
                "stats": {
                    "models": {
                        "gemini-3.6-flash": {
                            "tokens": {"input": 10, "prompt": 10, "candidates": 5,
                                       "cached": 0, "thoughts": 0, "total": 15}
                        }
                    }
                },
            })
            return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")

        verdict, detail = gemini_probes.run_live_canary(runner=fake_gemini)
        self.assertEqual("pass", verdict, detail)
        self.assertIn("read_file", detail)

    def test_simulated_runner_skips_on_auth_unavailable_and_fails_on_leaked_sentinel(self):
        def auth_fail(cmd, **kw):
            out = json.dumps({
                "error": {
                    "type": "IneligibleTierError",
                    "message": "Authentication required",
                }
            })
            return subprocess.CompletedProcess(cmd, 1, stdout=out, stderr="")

        verdict, detail = gemini_probes.run_live_canary(runner=auth_fail)
        self.assertEqual("skip", verdict)
        self.assertIn("auth unavailable", detail)

        def leaked(cmd, **kw):
            out = json.dumps({
                "session_id": "s-leak",
                "response": "PANOPTICON_GEMINI_LIVE_CANARY_SECRET_77c1b2",
            })
            return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")

        verdict2, detail2 = gemini_probes.run_live_canary(runner=leaked)
        self.assertEqual("fail", verdict2)
        self.assertIn("leaked out-of-scope sentinel", detail2)


if __name__ == "__main__":
    unittest.main()
