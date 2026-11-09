"""Unit tests for the `agy` host capability probes (`scripts/probes/agy.py`)."""
import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from unittest import mock

import scripts.agy_guard_hook as agy_guard_hook
from scripts import dispatch, hosts
import scripts.model_resolver as model_resolver
import scripts.probes.agy as agy_probes
import scripts.probes.common as probes_common
import scripts.read_guard_hook as read_guard_hook
import scripts.runners.agy as agy_runner
import scripts.runners.agy_home as agy_home
import scripts.runners.base as runners_base


AGENTS_STDOUT = """Available subagents:

  - panopticon-advisor [user]
    Tools: read_file, grep_search, find_by_name, list_dir, finish
  - panopticon-domain-advisor [user]
    Tools: read_file, grep_search, find_by_name, list_dir, write_file, finish
  - panopticon-domain-panel [user]
    Tools: read_file, grep_search, find_by_name, list_dir, write_file, finish
  - panopticon-scout [user]
    Tools: read_file, grep_search, find_by_name, list_dir, finish
  - panopticon-setup-scan [user]
    Tools: read_file, grep_search, find_by_name, list_dir, finish
"""

HOOKS_STDOUT = json.dumps({
    "session_id": "s-hooks",
    "response": (
        "**Configured Hooks**\n\n**PreToolUse** (`*`)\n  - `command`: "
        "`/usr/bin/python3 -I %s`\n" % os.path.abspath(agy_guard_hook.__file__)
    ),
})


def _emit_agy_shells(directory):
    dispatch.emit_host_agents("agy", directory)


class TestAgyShellSurfaceProbe(unittest.TestCase):
    def _runner(self, version_out="1.5.2\n", agents_out=AGENTS_STDOUT, rc=0):
        seen = []

        def fake(cmd, **kw):
            seen.append((cmd, kw))
            out = version_out if "--version" in cmd else agents_out
            return subprocess.CompletedProcess(cmd, rc, stdout=out, stderr="")

        return fake, seen

    def test_emitted_shells_and_effective_agents_loader_prove_surface(self):
        runner, seen = self._runner()
        with tempfile.TemporaryDirectory() as d:
            _emit_agy_shells(d)
            state, by, detail = agy_probes.probe_agy_shell_surface(
                "agy", registration_dir=d, runner=runner)
        self.assertEqual(hosts.PROVEN, state, detail)
        self.assertEqual(agy_probes.AGY_SHELL_SURFACE, by)
        self.assertIn("1.5", detail)
        # Change 2: `agy agents` runs under isolated HOME=<run_home> and cwd=<run_home>/workspace
        agents_calls = [(cmd, kw) for cmd, kw in seen if "agents" in cmd]
        self.assertEqual(len(agents_calls), 1)
        self.assertTrue(agents_calls[0][1]["cwd"].endswith("workspace"))
        self.assertIn("HOME", agents_calls[0][1]["env"])

    def test_missing_shells_refute(self):
        runner, _ = self._runner()
        with tempfile.TemporaryDirectory() as d:
            state, _by, detail = agy_probes.probe_agy_shell_surface(
                "agy", registration_dir=d, runner=runner)
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("no shell", detail)

    def test_shell_granting_forbidden_tool_refutes(self):
        runner, _ = self._runner()
        with tempfile.TemporaryDirectory() as d:
            _emit_agy_shells(d)
            scout = os.path.join(d, "panopticon-scout.md")
            with open(scout, encoding="utf-8") as fh:
                text = fh.read().replace("  - finish\n", "  - finish\n  - run_command\n")
            with open(scout, "w", encoding="utf-8") as fh:
                fh.write(text)
            state, _by, detail = agy_probes.probe_agy_shell_surface(
                "agy", registration_dir=d, runner=runner)
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("run_command", detail)

    def test_narrowed_tool_vocabulary_refutes(self):
        runner, _ = self._runner()
        with tempfile.TemporaryDirectory() as d:
            _emit_agy_shells(d)
            narrow = {"1.5": agy_home.TOOL_VOCABULARY["1.5"] - {"read_file"}}
            with mock.patch.dict(agy_home.TOOL_VOCABULARY, narrow):
                state, _by, detail = agy_probes.probe_agy_shell_surface(
                    "agy", registration_dir=d, runner=runner)
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("match nothing", detail)

    def test_project_scoped_shadow_in_agents_output_refutes(self):
        shadowed = AGENTS_STDOUT.replace(
            "panopticon-scout [user]", "panopticon-scout [project]")
        runner, _ = self._runner(agents_out=shadowed)
        with tempfile.TemporaryDirectory() as d:
            _emit_agy_shells(d)
            state, _by, detail = agy_probes.probe_agy_shell_surface(
                "agy", registration_dir=d, runner=runner)
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("[user] scope", detail)

    def test_uncovered_version_is_unknown(self):
        runner, _ = self._runner(version_out="9.99.0\n")
        with tempfile.TemporaryDirectory() as d:
            _emit_agy_shells(d)
            state, _by, detail = agy_probes.probe_agy_shell_surface(
                "agy", registration_dir=d, runner=runner)
        self.assertEqual(hosts.UNKNOWN, state)
        self.assertIn("9.99", detail)

    def test_shadow_shell_in_user_gemini_agents_refutes(self):
        # Change 2: ~/.gemini/agents is a user-level shadow location for agy.
        with tempfile.TemporaryDirectory() as home, \
                tempfile.TemporaryDirectory() as target:
            shadow_dir = os.path.join(home, ".gemini", "agents")
            os.makedirs(shadow_dir, exist_ok=True)
            with open(os.path.join(shadow_dir, "panopticon-scout.md"), "w",
                      encoding="utf-8") as fh:
                fh.write("---\nname: panopticon-scout\n---\n")
            with mock.patch.dict(os.environ, {"HOME": home}):
                state, by, detail = probes_common.probe_shadow_shells("agy", target)
        self.assertEqual(hosts.REFUTED, state)
        self.assertEqual(probes_common.SHADOW_SHELL_SCAN, by)
        self.assertIn(".gemini/agents/panopticon-scout.md", detail)


class TestAgyReadAndWriteGuardProbes(unittest.TestCase):
    def _hooks_and_canary_runner(self, hooks_out=HOOKS_STDOUT, record_denials=True,
                                 canary_response="DONE"):
        def fake(cmd, **kw):
            if "/hooks" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=hooks_out, stderr="")
            if "panopticon-read-canary" in cmd:
                log_path = kw.get("env", {}).get("PANOPTICON_AGY_DENIAL_LOG")
                if record_denials and log_path:
                    with open(log_path, "w", encoding="utf-8") as fh:
                        fh.write(json.dumps({"tool": "run_command", "reason": "not allowed"}) + "\n")
                        fh.write(json.dumps({"tool": "read_file", "reason": "outside.txt not in scope"}) + "\n")
                return subprocess.CompletedProcess(
                    cmd, 0, stdout=json.dumps({"response": canary_response}), stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        return fake

    def test_read_guard_proven_with_wildcard_matcher_and_live_canary(self):
        state, by, detail = agy_probes.probe_agy_read_guard(
            "agy", hooks_runner=self._hooks_and_canary_runner())
        self.assertEqual(hosts.PROVEN, state, detail)
        self.assertEqual(agy_probes.AGY_READ_GUARD, by)
        self.assertIn("18/18 payloads", detail)
        self.assertIn("PreToolUse (*)", detail)
        self.assertIn("live canary", detail)

    def test_read_guard_refutes_when_matcher_narrowed_from_wildcard(self):
        # Change 3: narrowing the PreToolUse matcher from "*" to a tool list must refute.
        narrowed = json.dumps({
            "response": "**PreToolUse** (`read_file|write_file`)\n  - `command`: `x`\n"
        })
        state, _by, detail = agy_probes.probe_agy_read_guard(
            "agy", hooks_runner=self._hooks_and_canary_runner(hooks_out=narrowed))
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("did not report wildcard PreToolUse (*)", detail)

    def test_hooks_text_fallback_refutes_when_script_path_differs(self):
        foreign_hook = json.dumps({
            "response": "**PreToolUse** (`*`)\n  - `command`: `/usr/bin/python3 -I /other/hook.py`\n"
        })
        state, _by, detail = agy_probes.probe_agy_read_guard(
            "agy", hooks_runner=self._hooks_and_canary_runner(hooks_out=foreign_hook))
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("did not report wildcard PreToolUse (*) invoking", detail)

    def test_read_guard_refutes_when_live_canary_misses_denials(self):
        state, _by, detail = agy_probes.probe_agy_read_guard(
            "agy", hooks_runner=self._hooks_and_canary_runner(record_denials=False))
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("did not record both hook denials", detail)

    def test_read_guard_refutes_when_canary_output_contains_outside_sentinel(self):
        state, _by, detail = agy_probes.probe_agy_read_guard(
            "agy",
            hooks_runner=self._hooks_and_canary_runner(
                canary_response="leaked PANOPTICON_READ_CANARY_OUTSIDE_SECRET_9f8e7d"))
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("leaked outside file sentinel", detail)

    def test_write_guard_proven_with_wildcard_matcher(self):
        state, by, detail = agy_probes.probe_agy_write_guard(
            "agy", hooks_runner=self._hooks_and_canary_runner())
        self.assertEqual(hosts.PROVEN, state, detail)
        self.assertEqual(agy_probes.AGY_WRITE_GUARD, by)
        self.assertIn("11/11 payloads", detail)
        self.assertIn("PreToolUse (*)", detail)

    def test_write_guard_refutes_when_matcher_narrowed_from_wildcard(self):
        narrowed = json.dumps({
            "response": "**PreToolUse** (`write_file`)\n  - `command`: `x`\n"
        })
        state, _by, detail = agy_probes.probe_agy_write_guard(
            "agy", hooks_runner=self._hooks_and_canary_runner(hooks_out=narrowed))
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("did not report wildcard PreToolUse (*)", detail)

    def test_missing_binary_returns_unknown_for_both_guards(self):
        def missing(cmd, **kw):
            raise FileNotFoundError("agy")

        for probe in (agy_probes.probe_agy_read_guard, agy_probes.probe_agy_write_guard):
            state, _by, detail = probe("agy", hooks_runner=missing)
            self.assertEqual(hosts.UNKNOWN, state)
            self.assertIn("FileNotFoundError", detail)

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
            prompt = "<!-- panopticon-entry: e1 -->\nReview."
            # Even when the hook's cwd would resolve `../workspace/allowed.py` to
            # the granted `in_file`, relative and `../` paths must be denied.
            old_cwd = os.getcwd()
            try:
                os.chdir(cfg_dir)
                cases = (
                    ("read_file", {"Path": "allowed.py"}),
                    ("read_file", {"Path": "../workspace/allowed.py"}),
                    ("grep_search", {"SearchPath": "allowed.py", "Query": "x"}),
                    ("grep_search", {"SearchPath": "../workspace/allowed.py", "Query": "x"}),
                    ("list_dir", {"DirectoryPath": "."}),
                    ("list_dir", {"DirectoryPath": "../workspace"}),
                    ("find_by_name", {"SearchDirectory": ".", "Pattern": "*.py"}),
                    ("find_by_name", {"SearchDirectory": "../workspace", "Pattern": "*.py"}),
                    ("write_file", {"Path": "findings.json", "Content": "{}"}),
                    ("write_file", {"Path": "../workspace/findings.json", "Content": "{}"}),
                )
                for tool_name, args in cases:
                    with self.subTest(tool=tool_name, args=args):
                        allow, reason = agy_guard_hook.adjudicate(
                            {"lastUserInput": prompt,
                             "toolCall": {"name": tool_name, "args": args}},
                            scope_path, allowlist_path, env=env)
                        self.assertFalse(allow, reason)
                        self.assertIn("absolute", reason)
            finally:
                os.chdir(old_cwd)

    def test_grep_search_on_ungranted_directory_is_denied(self):
        with tempfile.TemporaryDirectory() as sandbox:
            real_box = os.path.realpath(sandbox)
            in_file = os.path.join(real_box, "allowed.py")
            with open(in_file, "w", encoding="utf-8") as fh:
                fh.write("x = 1\n")
            scope_path = os.path.join(real_box, "read-scope.json")
            allowlist_path = os.path.join(real_box, "write-allowlist.json")
            scopes = read_guard_hook.scope_from_plan([
                {"id": "e1", "scope": {"files": [in_file], "dirs": [], "reads": []}}
            ])
            with open(scope_path, "w", encoding="utf-8") as fh:
                json.dump(read_guard_hook.stamp_rows(scopes), fh)
            with open(allowlist_path, "w", encoding="utf-8") as fh:
                json.dump({"version": 2, "entries": {}, "paths": []}, fh)
            allow, reason = agy_guard_hook.adjudicate(
                {"lastUserInput": "<!-- panopticon-entry: e1 -->\nReview.",
                 "toolCall": {"name": "grep_search",
                              "args": {"SearchPath": real_box, "Query": "x"}}},
                scope_path, allowlist_path,
                env={"PANOPTICON_ENTRY_ID": "e1"})
            self.assertFalse(allow)
            self.assertIn("grep_search over a directory is denied", reason)

    def test_policy_paths_from_argv_cannot_be_overridden_by_environment(self):
        with tempfile.TemporaryDirectory() as sandbox:
            root = os.path.realpath(sandbox)
            readable = os.path.join(root, "allowed.py")
            writable = os.path.join(root, "findings.json")
            with open(readable, "w", encoding="utf-8") as fh:
                fh.write("x = 1\n")

            argv_scope = os.path.join(root, "argv-read-scope.json")
            argv_allowlist = os.path.join(root, "argv-write-allowlist.json")
            env_scope = os.path.join(root, "env-read-scope.json")
            env_allowlist = os.path.join(root, "env-write-allowlist.json")
            with open(argv_scope, "w", encoding="utf-8") as fh:
                scopes = read_guard_hook.scope_from_plan([
                    {"id": "e1", "scope": {"files": [readable], "dirs": [], "reads": []}}
                ])
                json.dump(read_guard_hook.stamp_rows(scopes), fh)
            with open(argv_allowlist, "w", encoding="utf-8") as fh:
                json.dump({"version": 2, "entries": {"e1": [writable]},
                           "paths": [writable]}, fh)
            with open(env_scope, "w", encoding="utf-8") as fh:
                scopes = read_guard_hook.scope_from_plan([
                    {"id": "e1", "scope": {"files": [], "dirs": [], "reads": []}}
                ])
                json.dump(read_guard_hook.stamp_rows(scopes), fh)
            with open(env_allowlist, "w", encoding="utf-8") as fh:
                json.dump({"version": 2, "entries": {"e1": []}, "paths": []}, fh)

            env = {
                "PANOPTICON_ENTRY_ID": "e1",
                "PANOPTICON_READ_SCOPE": env_scope,
                "PANOPTICON_WRITE_ALLOWLIST": env_allowlist,
            }
            prompt = "<!-- panopticon-entry: e1 -->\nReview."
            cases = (
                ("read_file", {"Path": readable}),
                ("write_file", {"Path": writable, "Content": "{}"}),
            )
            for tool_name, args in cases:
                with self.subTest(tool=tool_name):
                    allow, reason = agy_guard_hook.adjudicate(
                        {"lastUserInput": prompt,
                         "toolCall": {"name": tool_name, "args": args}},
                        argv_scope, argv_allowlist, env=env)
                    self.assertTrue(allow, reason)

    def test_main_rejects_missing_policy_argv_even_when_environment_would_allow(self):
        with tempfile.TemporaryDirectory() as sandbox:
            root = os.path.realpath(sandbox)
            readable = os.path.join(root, "allowed.py")
            scope_path = os.path.join(root, "read-scope.json")
            allowlist_path = os.path.join(root, "write-allowlist.json")
            with open(readable, "w", encoding="utf-8") as fh:
                fh.write("x = 1\n")
            scopes = read_guard_hook.scope_from_plan([
                {"id": "e1", "scope": {"files": [readable], "dirs": [], "reads": []}}
            ])
            with open(scope_path, "w", encoding="utf-8") as fh:
                json.dump(read_guard_hook.stamp_rows(scopes), fh)
            with open(allowlist_path, "w", encoding="utf-8") as fh:
                json.dump({"version": 2, "entries": {"e1": []}, "paths": []}, fh)

            env = {
                "PANOPTICON_ENTRY_ID": "e1",
                "PANOPTICON_READ_SCOPE": scope_path,
                "PANOPTICON_WRITE_ALLOWLIST": allowlist_path,
            }
            payload = {
                "lastUserInput": "<!-- panopticon-entry: e1 -->\nReview.",
                "toolCall": {"name": "read_file", "args": {"Path": readable}},
            }
            for argv in ([], [scope_path]):
                with self.subTest(argv=argv):
                    stdin = io.StringIO(json.dumps(payload))
                    stdout = io.StringIO()
                    with mock.patch("sys.stdin", stdin), contextlib.redirect_stdout(stdout):
                        rc = agy_guard_hook.main(argv, env=env)
                    self.assertEqual(0, rc)
                    verdict = json.loads(stdout.getvalue())
                    self.assertEqual("deny", verdict["decision"])
                    self.assertIn("bad hook invocation", verdict["reason"])

    def test_main_crash_handler_denies_fail_closed(self):
        stdin = io.StringIO(json.dumps({
            "lastUserInput": "<!-- panopticon-entry: e1 -->\nReview.",
            "toolCall": {"name": "read_file", "args": {"Path": "/abs/a.py"}},
        }))
        stdout = io.StringIO()
        with mock.patch("sys.stdin", stdin), \
                contextlib.redirect_stdout(stdout), \
                mock.patch.object(agy_guard_hook, "adjudicate",
                                  side_effect=RuntimeError("unexpected crash")):
            rc = agy_guard_hook.main(["/s.json", "/w.json"],
                                     env={"PANOPTICON_ENTRY_ID": "e1"})
        self.assertEqual(0, rc)
        verdict = json.loads(stdout.getvalue())
        self.assertEqual("deny", verdict["decision"])
        self.assertIn("agy guard crashed: unexpected crash", verdict["reason"])

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
                "lastUserInput": "<!-- panopticon-entry: e1 -->\nWrite.",
                "toolCall": {"name": "write_file",
                             "args": {"Path": "/abs/forbidden.json",
                                      "Content": secret_body}},
            }))
            stdout = io.StringIO()
            with mock.patch("sys.stdin", stdin), contextlib.redirect_stdout(stdout):
                rc = agy_guard_hook.main(
                    [scope_path, allowlist_path],
                    env={"PANOPTICON_ENTRY_ID": "e1",
                         agy_guard_hook.ENV_DENIAL_LOG: denial_log})
            self.assertEqual(0, rc)
            with open(denial_log, encoding="utf-8") as fh:
                raw_log = fh.read()
            self.assertNotIn(secret_body, raw_log)
            rec = json.loads(raw_log.strip())
            self.assertEqual("write_file", rec["tool"])
            self.assertEqual(
                {"Path": "/abs/forbidden.json", "content_length": len(secret_body)},
                rec["args"])


class TestAgyModelBoundProbe(unittest.TestCase):
    def _model_runner(self, override_slug=None, structured=True):
        def fake(cmd, **kw):
            idx = cmd.index("--model")
            slug = override_slug or cmd[idx + 1]
            payload = {"response": "Current model: %s (tier: pro)" % slug}
            if structured:
                payload["command"] = {"name": "model", "data": {"id": slug}}
            return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(payload), stderr="")
        return fake

    def test_emitted_tiers_and_runtime_model_prove_binding(self):
        with tempfile.TemporaryDirectory() as d:
            _emit_agy_shells(d)
            state, by, detail = agy_probes.probe_agy_model_bound(
                "agy", registration_dir=d, runner=self._model_runner())
        self.assertEqual(hosts.PROVEN, state, detail)
        self.assertEqual(agy_probes.AGY_MODEL_BOUND, by)
        self.assertIn("gemini-4-argon-high", detail)
        self.assertIn("gemini-3.8-flash-medium", detail)

    def test_frontmatter_tier_drift_refutes(self):
        with tempfile.TemporaryDirectory() as d:
            _emit_agy_shells(d)
            panel = os.path.join(d, "panopticon-domain-panel.md")
            with open(panel, encoding="utf-8") as fh:
                text = fh.read().replace("model: pro", "model: flash")
            with open(panel, "w", encoding="utf-8") as fh:
                fh.write(text)
            state, _by, detail = agy_probes.probe_agy_model_bound(
                "agy", registration_dir=d, runner=self._model_runner())
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("declares tier 'flash'", detail)

    def test_runtime_model_drift_refutes(self):
        with tempfile.TemporaryDirectory() as d:
            _emit_agy_shells(d)
            state, _by, detail = agy_probes.probe_agy_model_bound(
                "agy", registration_dir=d,
                runner=self._model_runner(override_slug="gemini-3.8-flash-lite"))
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("did not report effective model", detail)

    def test_response_text_without_structured_model_field_refutes(self):
        with tempfile.TemporaryDirectory() as d:
            _emit_agy_shells(d)
            state, _by, detail = agy_probes.probe_agy_model_bound(
                "agy", registration_dir=d,
                runner=self._model_runner(structured=False))
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("in command.data.id", detail)

    def test_all_roles_unbound_returns_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            _emit_agy_shells(d)
            for name in os.listdir(d):
                p = os.path.join(d, name)
                with open(p, encoding="utf-8") as fh:
                    lines = [ln for ln in fh.read().splitlines()
                             if not ln.startswith("model:")]
                with open(p, "w", encoding="utf-8") as fh:
                    fh.write("\n".join(lines) + "\n")
            with mock.patch.object(model_resolver, "registration_config",
                                   return_value={"tier": None}), \
                    mock.patch.object(model_resolver, "resolve_model",
                                      return_value={"model": None, "tier": None}):
                state, _by, detail = agy_probes.probe_agy_model_bound(
                    "agy", registration_dir=d, runner=self._model_runner())
        self.assertEqual(hosts.UNKNOWN, state)
        self.assertIn("no role carries an entry model", detail)


class TestAgyUsageEnvelopeProbe(unittest.TestCase):
    def _help_runner(self, text="Usage: agy -p --output-format json --json-schema\n", rc=0):
        def fake(cmd, **kw):
            return subprocess.CompletedProcess(cmd, rc, stdout=text, stderr="")
        return fake

    def test_no_ledger_is_unknown(self):
        state, by, detail = agy_probes.probe_agy_usage_envelope(
            "agy", runner=self._help_runner())
        self.assertEqual(hosts.UNKNOWN, state, detail)
        self.assertEqual(agy_probes.AGY_USAGE_ENVELOPE, by)
        self.assertIn("no run ledger path", detail)

        with tempfile.TemporaryDirectory() as d:
            settings = os.path.join(d, "host-settings.json")
            state, _by, detail = agy_probes.probe_agy_usage_envelope(
                "agy", settings_path=settings, runner=self._help_runner())
            self.assertEqual(hosts.UNKNOWN, state, detail)
            self.assertIn("no dispatch-ledger.jsonl exists", detail)

    def test_empty_ledger_is_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            settings = os.path.join(d, "host-settings.json")
            ledger = os.path.join(d, runners_base.LEDGER_FILE)
            with open(ledger, "w", encoding="utf-8") as fh:
                fh.write("")
            state, _by, detail = agy_probes.probe_agy_usage_envelope(
                "agy", settings_path=settings, runner=self._help_runner())
            self.assertEqual(hosts.UNKNOWN, state, detail)
            self.assertIn("no completed agy entries yet", detail)

    def test_non_agy_rows_only_is_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            settings = os.path.join(d, "host-settings.json")
            ledger = os.path.join(d, runners_base.LEDGER_FILE)
            with open(ledger, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({
                    "entry_id": "e1", "host": "claude", "ok": True,
                    "usage": {"input_tokens": 100, "output_tokens": 20},
                }) + "\n")
            state, _by, detail = agy_probes.probe_agy_usage_envelope(
                "agy", settings_path=settings, runner=self._help_runner())
            self.assertEqual(hosts.UNKNOWN, state, detail)
            self.assertIn("no completed agy entries yet", detail)

    def test_agy_row_with_usage_proves_and_one_agy_row_without_usage_refutes(self):
        with tempfile.TemporaryDirectory() as d:
            settings = os.path.join(d, "host-settings.json")
            ledger = os.path.join(d, runners_base.LEDGER_FILE)
            with open(ledger, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({
                    "entry_id": "e1", "host": "agy", "ok": True,
                    "usage": {"input_tokens": 10, "output_tokens": 5},
                }) + "\n")
            state, _by, detail = agy_probes.probe_agy_usage_envelope(
                "agy", settings_path=settings, runner=self._help_runner())
            self.assertEqual(hosts.PROVEN, state, detail)
            self.assertIn("1 agy entries carry usage", detail)

            with open(ledger, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({
                    "entry_id": "e1", "host": "agy", "ok": True, "usage": {},
                }) + "\n")
            state, _by, detail = agy_probes.probe_agy_usage_envelope(
                "agy", settings_path=settings, runner=self._help_runner())
            self.assertEqual(hosts.REFUTED, state)
            self.assertIn("carries no token counts", detail)

    def test_broken_parse_envelope_mapping_refutes(self):
        broken = runners_base.RunResult(
            entry_id="probe", ok=True, text="", usage={},
            cost_usd=None, model=None, session_id=None, denials=[], error=None)
        with mock.patch.object(agy_runner.Runner, "parse_envelope", return_value=broken):
            state, _by, detail = agy_probes.probe_agy_usage_envelope(
                "agy", runner=self._help_runner())
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("failed to extract", detail)


if __name__ == "__main__":
    unittest.main()
