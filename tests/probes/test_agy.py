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
import scripts.runners.children as children


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


# #3613: agy children keep the operator's HOME and take their configuration from
# `--gemini_dir`. Every test here runs under a fixture HOME, so none reads the real
# ~/.gemini, and no sign-in is staged anywhere: panopticon never stages one.
_HOME_PATCH = None
_HOME_DIR = None


def setUpModule():
    global _HOME_PATCH, _HOME_DIR
    _HOME_DIR = tempfile.TemporaryDirectory()
    _HOME_PATCH = mock.patch.dict(os.environ, {"HOME": _HOME_DIR.name})
    _HOME_PATCH.start()
    for name in ("GEMINI_API_KEY", "PANOPTICON_AGY_AUTH"):        # #3576: chosen per test
        os.environ.pop(name, None)


def tearDownModule():
    _HOME_PATCH.stop()
    _HOME_DIR.cleanup()


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
        # #3613: `agy agents` keeps the operator's HOME, takes the run's --gemini_dir
        # as its first argument, and runs in <run>/workspace.
        agents_calls = [(cmd, kw) for cmd, kw in seen if "agents" in cmd]
        self.assertEqual(len(agents_calls), 1)
        cmd, kw = agents_calls[0]
        self.assertTrue(kw["cwd"].endswith("workspace"))
        self.assertEqual(_HOME_DIR.name, kw["env"]["HOME"])
        self.assertEqual("/usr/bin/false", kw["env"]["BROWSER"])
        self.assertEqual("--gemini_dir", cmd[1])
        self.assertEqual(os.path.join(os.path.dirname(kw["cwd"]), "gemini"), cmd[2])

    def test_version_and_help_carry_an_empty_gemini_dir(self):
        # #3617 review N5: no agy launch reads ~/.gemini, not even --version/--help.
        seen = []

        def fake(cmd, **kw):
            seen.append(list(cmd))
            return subprocess.CompletedProcess(cmd, 0, stdout="1.5.2\n-p --output-format\n",
                                               stderr="")
        with tempfile.TemporaryDirectory() as d:
            _emit_agy_shells(d)
            agy_probes.probe_agy_shell_surface("agy", registration_dir=d, runner=fake)
        agy_probes.probe_agy_usage_envelope("agy", runner=fake)
        for flag in ("--version", "--help"):
            with self.subTest(flag=flag):
                cmd = next(c for c in seen if c[-1] == flag)
                self.assertEqual(["agy", "--gemini_dir"], cmd[:2])
                self.assertEqual(4, len(cmd))

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

    def test_a_real_home_gemini_agents_shell_shadows_gemini_but_not_agy(self):
        # #3613: every agy launch passes --gemini_dir, which replaces ~/.gemini
        # (#3605 P1), so ~/.gemini/agents shadows nothing for agy. gemini still
        # reads it, and still refutes on it.
        with tempfile.TemporaryDirectory() as home, \
                tempfile.TemporaryDirectory() as target:
            shadow_dir = os.path.join(home, ".gemini", "agents")
            os.makedirs(shadow_dir, exist_ok=True)
            with open(os.path.join(shadow_dir, "panopticon-scout.md"), "w",
                      encoding="utf-8") as fh:
                fh.write("---\nname: panopticon-scout\n---\n")
            with mock.patch.dict(os.environ, {"HOME": home}):
                agy = probes_common.probe_shadow_shells("agy", target)
                gemini = probes_common.probe_shadow_shells("gemini", target)
        self.assertNotEqual(hosts.REFUTED, agy[0], agy[2])
        self.assertEqual(hosts.REFUTED, gemini[0])
        self.assertEqual(probes_common.SHADOW_SHELL_SCAN, gemini[1])
        self.assertIn(".gemini/agents/panopticon-scout.md", gemini[2])


class TestTheProbesFailClosedOnAuth(unittest.TestCase):
    """#3576: a probe whose child would reach a browser sign-in is UNKNOWN, with the
    operator message, and no probe builds a home without a reachable sign-in."""

    LOG = ("Print mode: not authenticated, trying silent auth\n"
           "Print mode: silent auth failed\n"
           "Print mode: triggering interactive OAuth\n")

    def test_a_stopped_child_reads_as_the_auth_message(self):
        seen = {}

        def stopped(cmd, **kw):
            seen.update(kw)
            raise children.HostStopped(cmd, output="", stderr=self.LOG)
        with tempfile.TemporaryDirectory() as d:
            _emit_agy_shells(d)
            state, _by, detail = agy_probes.probe_agy_model_bound(
                "agy", registration_dir=d, runner=stopped)
        self.assertEqual(hosts.UNKNOWN, state)
        self.assertIn(agy_home.AUTH_UNREACHABLE, detail)
        self.assertIs(agy_runner.INTERACTIVE_AUTH, seen["stop_on"])

    def test_a_child_that_finished_on_the_line_reads_the_same(self):
        def finished(cmd, **kw):
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr=self.LOG)
        with tempfile.TemporaryDirectory() as d:
            _emit_agy_shells(d)
            state, _by, detail = agy_probes.probe_agy_model_bound(
                "agy", registration_dir=d, runner=finished)
        self.assertEqual(hosts.UNKNOWN, state)
        self.assertIn(agy_home.AUTH_UNREACHABLE, detail)

    def test_no_sign_in_is_staged_and_the_launch_keeps_the_operators_home(self):
        # #3613 (R1): no token file is linked or required. The guard probes build
        # the run and launch under the operator's HOME with the run's --gemini_dir;
        # whether agy is signed in is agy's to answer (the tests above).
        launched = []

        def fake(cmd, **kw):
            launched.append((list(cmd), kw["env"].get("HOME")))
            return subprocess.CompletedProcess(cmd, 0, stdout=HOOKS_STDOUT, stderr="")

        with tempfile.TemporaryDirectory() as empty, \
                mock.patch.dict(os.environ, {"HOME": empty}):
            agy_probes.probe_agy_read_guard("agy", hooks_runner=fake)
        self.assertTrue(launched)
        for cmd, home in launched:
            with self.subTest(cmd=cmd[3:5]):
                self.assertEqual(["agy", "--gemini_dir"], cmd[:2])
                self.assertEqual(empty, home)


class TestTheModelProbeOnTheKeyRoute(unittest.TestCase):
    """#3576 step 2: on the API-key route the probe binds what the runner binds."""

    FAKE_KEY = "AIza" + "K" * 35
    LISTED = "\n".join(["Available models:", "gemini-4-argon-high\tGemini 4 Argon (High)",
                        "gemini-3.8-flash-medium\tGemini 3.8 Flash (Medium)"]) + "\n"

    def _run(self, models_rc=0, extra_env=None):
        seen = []

        def fake(cmd, **kw):
            seen.append(list(cmd))
            if cmd[3:] == ["models"]:
                return subprocess.CompletedProcess(cmd, models_rc, stdout=self.LISTED, stderr="")
            slug = cmd[cmd.index("--model") + 1]
            return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(
                {"command": {"name": "model", "data": {"id": slug}}}), stderr="")
        with tempfile.TemporaryDirectory() as home, tempfile.TemporaryDirectory() as d:
            # #3613 (R2): the key route runs only when the operator names it.
            env = dict({"HOME": home, "GEMINI_API_KEY": self.FAKE_KEY,
                        "PANOPTICON_AGY_AUTH": "key"}, **(extra_env or {}))
            with mock.patch.dict(os.environ, env):
                _emit_agy_shells(d)
                result = agy_probes.probe_agy_model_bound("agy", registration_dir=d, runner=fake)
        return result, seen

    def test_carbon_roles_are_proven_bound_to_argon_high(self):
        (state, _by, detail), seen = self._run()
        self.assertEqual(hosts.PROVEN, state, detail)
        self.assertIn("on the API-key route", detail)
        self.assertIn("(gemini-3.8-flash-medium, gemini-4-argon-high) on the API-key route", detail)
        # #3582: the proof names each fallback, then proves the bound model, never Carbon.
        for role in ("domain_advisor", "domain_panel"):
            self.assertIn("%s: requested gemini-4-carbon-high -> bound gemini-4-argon-high "
                          "(fallback rung 1: not listed on route key)" % role, detail)
        self.assertFalse(any(c[c.index("--model") + 1].startswith("gemini-4-carbon")
                             for c in seen if "--model" in c))
        self.assertEqual(["models"], seen[0][3:])
        self.assertEqual("--gemini_dir", seen[0][1])
        self.assertFalse(any("--effort" in c for c in seen))
        self.assertFalse(any(c[-1] == "/effort" for c in seen))

    def test_a_strict_run_refutes_carbon_on_the_key_route(self):
        (state, _by, detail), _seen = self._run(extra_env={"PANOPTICON_MODEL_STRICT": "1"})
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("domain_panel: agy key route lists no model 'gemini-4-carbon-high'", detail)
        self.assertIn("no fallback ladder applies", detail)

    def test_an_explicit_unlisted_override_refutes(self):
        (state, _by, detail), _seen = self._run(extra_env={
            "PANOPTICON_MODEL_DOMAIN_PANEL": '{"model": "gemini-4-carbon", "effort": "high"}'})
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("never substituted", detail)

    def test_only_a_key_route_probe_child_holds_the_key(self):
        # #3617 review N1: the probes enforce R2 in the child environment too.
        for extra, held in (({}, True), ({"PANOPTICON_AGY_AUTH": ""}, False)):
            envs = []
            with self.subTest(route="key" if held else "signin"), \
                    mock.patch.object(agy_probes, "DEFAULT_RUNNER", None):
                def fake(cmd, **kw):
                    envs.append(kw["env"])
                    if cmd[3:] == ["models"]:
                        return subprocess.CompletedProcess(cmd, 0, stdout=self.LISTED, stderr="")
                    return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(
                        {"command": {"name": "model", "data": {"id": "x"}}}), stderr="")
                with tempfile.TemporaryDirectory() as home, tempfile.TemporaryDirectory() as d:
                    env = dict({"HOME": home, "GEMINI_API_KEY": self.FAKE_KEY,
                                "PANOPTICON_AGY_AUTH": "key"}, **extra)
                    with mock.patch.dict(os.environ, env):
                        _emit_agy_shells(d)
                        agy_probes.probe_agy_model_bound("agy", registration_dir=d, runner=fake)
                self.assertTrue(envs)
                for child in envs:
                    self.assertEqual(held, child.get("GEMINI_API_KEY") == self.FAKE_KEY)
                    if not held:
                        self.assertNotIn("GEMINI_API_KEY", child)

    def test_a_key_alone_does_not_choose_the_key_route(self):
        # #3613 (R2): with no PANOPTICON_AGY_AUTH the probe stays on the sign-in
        # route and never asks for the key route's model list.
        (_state, _by, detail), seen = self._run(extra_env={"PANOPTICON_AGY_AUTH": ""})
        self.assertNotIn("on the API-key route", detail)
        self.assertFalse(any(c[3:] == ["models"] for c in seen))

    def test_a_failed_listing_is_unknown(self):
        (state, _by, detail), _seen = self._run(models_rc=2)
        self.assertEqual(hosts.UNKNOWN, state)
        self.assertIn("`agy models` on the API-key route exited 2", detail)


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
                json.dump(scopes, fh)
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
                json.dump(scopes, fh)
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
                json.dump(scopes, fh)
            with open(argv_allowlist, "w", encoding="utf-8") as fh:
                json.dump({"version": 2, "entries": {"e1": [writable]},
                           "paths": [writable]}, fh)
            with open(env_scope, "w", encoding="utf-8") as fh:
                scopes = read_guard_hook.scope_from_plan([
                    {"id": "e1", "scope": {"files": [], "dirs": [], "reads": []}}
                ])
                json.dump(scopes, fh)
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
                json.dump(scopes, fh)
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
    # #3564: the owner's captures (2026-11-11) of `agy --model gemini-4-carbon --effort high
    # --output-format json`, trimmed, field shapes exact.
    CAPTURED_MODEL = {"command": {"name": "model", "data": {
        "id": "gemini-4-carbon-high", "label": "Gemini 4 Carbon (High)", "effort": "high",
        "is_default": False}}, "response": "gemini-4-carbon-high\tGemini 4 Carbon (High)"}
    CAPTURED_EFFORT = {"command": {"name": "effort", "data": {
        "adjustable": True, "current": "high", "available": ["low", "medium", "high"]}}}

    def _model_runner(self, override_slug=None, structured=True, effort_rc=0,
                      effort_data=None, effort_stdout=None, model_data=None, seen=None):
        """A fake agy answering as the captures do: `/model` names `<model>-<effort>`
        with `data.effort` when an effort is passed, and `/effort` reports it current."""
        def fake(cmd, **kw):
            if seen is not None:
                seen.append(list(cmd))
            level = cmd[cmd.index("--effort") + 1] if "--effort" in cmd else None
            if cmd[-1] == "/effort":
                if effort_stdout is not None:
                    out = effort_stdout
                else:
                    data = (effort_data if effort_data is not None else
                            dict(self.CAPTURED_EFFORT["command"]["data"], current=level))
                    out = json.dumps({"command": {"name": "effort", "data": data}})
                return subprocess.CompletedProcess(cmd, effort_rc, stdout=out, stderr="")
            slug = override_slug or cmd[cmd.index("--model") + 1]
            data = {"id": slug + ("-" + level if level else ""), "is_default": False}
            if level:
                data["effort"] = level
            if model_data is not None and level:
                data = model_data           # only the effort roles, so flash stays bound
            payload = {"response": "%s\t%s" % (data.get("id"), data.get("id"))}
            if structured:
                payload["command"] = {"name": "model", "data": data}
            return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(payload), stderr="")
        return fake

    def test_carbon_at_high_is_proven_on_the_captured_shapes(self):
        seen = []
        with tempfile.TemporaryDirectory() as d:
            _emit_agy_shells(d)
            state, by, detail = agy_probes.probe_agy_model_bound(
                "agy", registration_dir=d, runner=self._model_runner(seen=seen))
        self.assertEqual(hosts.PROVEN, state, detail)
        self.assertEqual(agy_probes.AGY_MODEL_BOUND, by)
        self.assertIn("gemini-4-carbon high", detail)
        self.assertIn("gemini-3.8-flash-medium", detail)
        model_calls = [c for c in seen if c[-1] == "/model"]
        effort_calls = [c for c in seen if c[-1] == "/effort"]
        carbon = [c for c in model_calls if "gemini-4-carbon" in c]
        flash = [c for c in model_calls if "gemini-3.8-flash-medium" in c]
        self.assertTrue(carbon and flash)
        for call in carbon + effort_calls:
            self.assertEqual(["--model", "gemini-4-carbon", "--effort", "high"],
                             call[call.index("--model"):call.index("--model") + 4])
        for call in flash:
            self.assertNotIn("--effort", call)
        self.assertEqual(len(carbon), len(effort_calls))

    def test_the_captured_payloads_verbatim_prove_the_carbon_roles(self):
        def fake(cmd, **kw):
            if "--effort" not in cmd:
                slug = cmd[cmd.index("--model") + 1]
                out = {"command": {"name": "model", "data": {"id": slug}}}
            else:
                out = self.CAPTURED_EFFORT if cmd[-1] == "/effort" else self.CAPTURED_MODEL
            return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(out), stderr="")
        with tempfile.TemporaryDirectory() as d:
            _emit_agy_shells(d)
            state, _by, detail = agy_probes.probe_agy_model_bound(
                "agy", registration_dir=d, runner=fake)
        self.assertEqual(hosts.PROVEN, state, detail)

    def test_the_model_leg_refutes_what_the_capture_rules_out(self):
        for name, data in (
                ("bare id with effort mismatch",
                 {"id": "gemini-4-carbon-high", "effort": "low"}),
                ("combined id with no effort field", {"id": "gemini-4-carbon-high"}),
                ("other level's slug", {"id": "gemini-4-carbon-medium", "effort": "medium"}),
                ("other model", {"id": "gemini-4-argon-high", "effort": "high"}),
                ("id not a string", {"id": None, "effort": "high"})):
            with self.subTest(name), tempfile.TemporaryDirectory() as d:
                _emit_agy_shells(d)
                state, _by, detail = agy_probes.probe_agy_model_bound(
                    "agy", registration_dir=d, runner=self._model_runner(model_data=data))
                self.assertEqual(hosts.REFUTED, state, detail)
                self.assertIn("did not report effective model", detail)

    def test_the_bare_model_id_still_matches_with_an_effort(self):
        def bare(cmd, **kw):
            if cmd[-1] == "/effort":
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(
                    self.CAPTURED_EFFORT), stderr="")
            slug = cmd[cmd.index("--model") + 1]
            return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(
                {"command": {"name": "model", "data": {"id": slug}}}), stderr="")
        with tempfile.TemporaryDirectory() as d:
            _emit_agy_shells(d)
            state, _by, detail = agy_probes.probe_agy_model_bound(
                "agy", registration_dir=d, runner=bare)
        self.assertEqual(hosts.PROVEN, state, detail)

    def test_the_effort_leg_refutes_what_the_capture_rules_out(self):
        base = self.CAPTURED_EFFORT["command"]["data"]
        for name, data, why in (
                ("not adjustable", dict(base, adjustable=False), "is not adjustable"),
                ("adjustable missing", {"current": "high", "available": ["high"]},
                 "is not adjustable"),
                ("other level current", dict(base, current="medium"),
                 "did not report effort 'high' as current and available"),
                ("level not available", dict(base, available=["low", "medium"]),
                 "did not report effort 'high' as current and available"),
                ("available not a list", dict(base, available="low,medium,high"),
                 "did not report effort 'high' as current and available")):
            with self.subTest(name), tempfile.TemporaryDirectory() as d:
                _emit_agy_shells(d)
                state, _by, detail = agy_probes.probe_agy_model_bound(
                    "agy", registration_dir=d, runner=self._model_runner(effort_data=data))
                self.assertEqual(hosts.REFUTED, state, detail)
                self.assertIn(why, detail)

    def test_an_effort_payload_without_command_data_refutes(self):
        with tempfile.TemporaryDirectory() as d:
            _emit_agy_shells(d)
            state, _by, detail = agy_probes.probe_agy_model_bound(
                "agy", registration_dir=d, runner=self._model_runner(effort_stdout="{}"))
        self.assertEqual(hosts.REFUTED, state, detail)
        self.assertIn("carried no command.data", detail)

    def test_roles_with_no_effort_prove_binding(self):
        real = model_resolver.entry_policy

        def no_effort(host, role):
            policy = real(host, role)
            policy.pop("effort", None)
            return policy
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(model_resolver, "entry_policy", no_effort):
            _emit_agy_shells(d)
            seen = []
            state, by, detail = agy_probes.probe_agy_model_bound(
                "agy", registration_dir=d, runner=self._model_runner(seen=seen))
        self.assertEqual(hosts.PROVEN, state, detail)
        self.assertIn("gemini-4-carbon", detail)
        self.assertIn("gemini-3.8-flash-medium", detail)
        self.assertIn(agy_runner.NO_ANSWERING_MODEL, detail)        # #3550
        self.assertFalse(any(c[-1] == "/effort" or "--effort" in c for c in seen))

    def test_a_failed_effort_readback_refutes(self):
        for kwargs, expected in (({"effort_rc": 3}, "`agy -p /effort` exited 3"),
                                 ({"effort_stdout": "high"}, "returned non-JSON stdout")):
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as d:
                _emit_agy_shells(d)
                state, _by, detail = agy_probes.probe_agy_model_bound(
                    "agy", registration_dir=d, runner=self._model_runner(**kwargs))
                self.assertEqual(hosts.REFUTED, state)
                self.assertIn(expected, detail)

    def test_an_effort_beside_a_combined_slug_refutes_before_any_launch(self):
        real = model_resolver.entry_policy

        def combined(host, role):
            policy = real(host, role)
            if policy.get("effort"):
                policy["model"] = "gemini-4-argon-high"
            return policy
        seen = []
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(model_resolver, "entry_policy", combined):
            _emit_agy_shells(d)
            state, _by, detail = agy_probes.probe_agy_model_bound(
                "agy", registration_dir=d, runner=self._model_runner(seen=seen))
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("already names an effort", detail)
        self.assertEqual([], seen)

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
        self.assertIn("in command.data", detail)

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
            self.assertIn(agy_runner.NO_ANSWERING_MODEL, detail)    # #3550

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
