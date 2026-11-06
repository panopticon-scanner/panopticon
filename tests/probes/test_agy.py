"""Unit tests for the `agy` host capability probes (`scripts/probes/agy.py`)."""
import json
import os
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts import dispatch, hosts
import scripts.probes.agy as agy_probes
import scripts.probes.common as probes_common
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
    "response": "**Configured Hooks**\n\n**PreToolUse** (`*`)\n  - `command`: `/usr/bin/python3 -I /x/agy_guard_hook.py`\n",
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
    def _hooks_and_canary_runner(self, hooks_out=HOOKS_STDOUT, record_denials=True):
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
                    cmd, 0, stdout=json.dumps({"response": "DONE"}), stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        return fake

    def test_read_guard_proven_with_wildcard_matcher_and_live_canary(self):
        state, by, detail = agy_probes.probe_agy_read_guard(
            "agy", hooks_runner=self._hooks_and_canary_runner())
        self.assertEqual(hosts.PROVEN, state, detail)
        self.assertEqual(agy_probes.AGY_READ_GUARD, by)
        self.assertIn("15/15 payloads", detail)
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

    def test_read_guard_refutes_when_live_canary_misses_denials(self):
        state, _by, detail = agy_probes.probe_agy_read_guard(
            "agy", hooks_runner=self._hooks_and_canary_runner(record_denials=False))
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("did not record both hook denials", detail)

    def test_write_guard_proven_with_wildcard_matcher(self):
        state, by, detail = agy_probes.probe_agy_write_guard(
            "agy", hooks_runner=self._hooks_and_canary_runner())
        self.assertEqual(hosts.PROVEN, state, detail)
        self.assertEqual(agy_probes.AGY_WRITE_GUARD, by)
        self.assertIn("9/9 payloads", detail)
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


class TestAgyModelBoundProbe(unittest.TestCase):
    def _model_runner(self, override_slug=None):
        def fake(cmd, **kw):
            idx = cmd.index("--model")
            slug = override_slug or cmd[idx + 1]
            out = json.dumps({"response": "Current model: %s (tier: pro)" % slug})
            return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")
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


class TestAgyUsageEnvelopeProbe(unittest.TestCase):
    def _help_runner(self, text="Usage: agy -p --output-format json --json-schema\n", rc=0):
        def fake(cmd, **kw):
            return subprocess.CompletedProcess(cmd, rc, stdout=text, stderr="")
        return fake

    def test_help_flags_and_envelope_parser_prove_usage(self):
        state, by, detail = agy_probes.probe_agy_usage_envelope(
            "agy", runner=self._help_runner())
        self.assertEqual(hosts.PROVEN, state, detail)
        self.assertEqual(agy_probes.AGY_USAGE_ENVELOPE, by)
        self.assertIn("parse_envelope", detail)

    def test_ledger_with_usage_proves_and_empty_ledger_refutes(self):
        with tempfile.TemporaryDirectory() as d:
            settings = os.path.join(d, "host-settings.json")
            ledger = os.path.join(d, runners_base.LEDGER_FILE)
            with open(ledger, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({
                    "entry_id": "e1", "ok": True,
                    "usage": {"input_tokens": 10, "output_tokens": 5},
                }) + "\n")
            state, _by, detail = agy_probes.probe_agy_usage_envelope(
                "agy", settings_path=settings, runner=self._help_runner())
            self.assertEqual(hosts.PROVEN, state, detail)
            self.assertIn("dispatch-ledger.jsonl", detail)

            with open(ledger, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({"entry_id": "e1", "ok": True, "usage": {}}) + "\n")
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
