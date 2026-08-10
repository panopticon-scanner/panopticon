import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "skill"))
import scripts.codex_runner as cr
import scripts.dispatch as dispatch
import scripts.group_runner as gr


class TestCodexCommand(unittest.TestCase):
    def _entry(self, root, **updates):
        entry = {
            "role": "panel_review",
            "agent": "panopticon-panel-review",
            "enforced": True,
            "execution": "codex_exec",
            "delivery": "return_json",
            "run_id": "run-123",
            "model": {"model": "gpt-5.6-terra", "model_reasoning_effort": "high"},
            "panel": "security",
            "lens": None,
            "group": "g1",
            "prompt": "review safely",
            "out_file": os.path.join(root, ".panopticon", "findings-g1-security-panel_review.json"),
        }
        entry.update(updates)
        return entry

    def test_command_is_isolated_and_structured(self):
        with tempfile.TemporaryDirectory() as root:
            entry = self._entry(root)
            output = os.path.join(root, ".panopticon", ".result.json")
            command = cr.build_command(entry, root, output, codex="codex-test")
        self.assertEqual(command[:2], ["codex-test", "exec"])
        self.assertIn("--ephemeral", command)
        self.assertIn("--strict-config", command)
        self.assertIn("--ignore-user-config", command)
        self.assertIn("--ignore-rules", command)
        self.assertEqual(command[command.index("--sandbox") + 1], "read-only")
        self.assertEqual(command[command.index("--ask-for-approval") + 1], "never")
        self.assertEqual(command[command.index("--model") + 1], "gpt-5.6-terra")
        joined = "\n".join(command)
        for override in (
                "features.hooks=false", "features.multi_agent=false",
                'web_search="disabled"', 'history.persistence="none"',
                'shell_environment_policy.inherit="core"'):
            self.assertIn(override, joined)
        self.assertEqual(command[-1], "-")

    def test_rejects_output_outside_artifact_directory(self):
        with tempfile.TemporaryDirectory() as root:
            entry = self._entry(root, out_file=os.path.join(root, "source.py"))
            with self.assertRaisesRegex(ValueError, "escapes"):
                cr.validate_entry(entry, root)

    def test_rejects_non_codex_plan_entry(self):
        with tempfile.TemporaryDirectory() as root:
            entry = self._entry(root, execution=None)
            with self.assertRaisesRegex(ValueError, "not a codex_exec"):
                cr.validate_entry(entry, root)


class TestCodexExecution(unittest.TestCase):
    def _profile(self):
        return {
            "group": "g1", "files": ["app.py"], "depth": "standard",
            "panels": ["security"], "security_mode": "standard",
            "lenses": {"security": []},
        }

    def _valid_finding(self):
        return {
            "id": "SEC-001",
            "severity": "HIGH",
            "panel": "security",
            "category": "injection",
            "location": {"file": "app.py", "line_start": 1},
            "title": "Unsafe query",
            "description": "A query is built unsafely.",
            "impact": "Data exposure.",
            "remediation": "Parameterize the query.",
            "references": [],
            "source_role": "panel_review",
            "depth": "standard",
            "provenance": {"discovered_by": "agent:panel_review"},
            "citations": {"cwe": ["CWE-89"]},
        }

    def test_valid_response_is_stamped_and_published(self):
        with tempfile.TemporaryDirectory() as root:
            open(os.path.join(root, "app.py"), "w").close()
            entry = dispatch.build_plan(
                self._profile(), host="codex", codex_exec=True,
                root=root, run_id="run-123")[0]

            def fake_runner(command, **kwargs):
                output = command[command.index("--output-last-message") + 1]
                with open(output, "w", encoding="utf-8") as fh:
                    json.dump({"findings": [self._valid_finding()]}, fh)
                return subprocess.CompletedProcess(command, 0, "", "")

            written = cr.run_entry(entry, root, runner=fake_runner)
            with open(written, encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertEqual(data["_panopticon"]["producer"], "codex_exec")
            self.assertEqual(data["_panopticon"]["run_id"], "run-123")
            self.assertTrue(gr.entry_is_done(written, entry))

    def test_invalid_response_does_not_replace_existing_output(self):
        with tempfile.TemporaryDirectory() as root:
            open(os.path.join(root, "app.py"), "w").close()
            entry = dispatch.build_plan(
                self._profile(), host="codex", codex_exec=True,
                root=root, run_id="run-123")[0]
            os.makedirs(os.path.dirname(entry["out_file"]))
            with open(entry["out_file"], "w", encoding="utf-8") as fh:
                fh.write("sentinel")

            def fake_runner(command, **kwargs):
                output = command[command.index("--output-last-message") + 1]
                with open(output, "w", encoding="utf-8") as fh:
                    json.dump({"findings": [{"panel": "code"}]}, fh)
                return subprocess.CompletedProcess(command, 0, "", "")

            with self.assertRaises(ValueError):
                cr.run_entry(entry, root, runner=fake_runner)
            with open(entry["out_file"], encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "sentinel")

    def test_response_location_cannot_escape_target(self):
        with tempfile.TemporaryDirectory() as root:
            entry = dispatch.build_plan(
                self._profile(), host="codex", codex_exec=True,
                root=root, run_id="run-123")[0]
            finding = self._valid_finding()
            finding["location"]["file"] = "../secret.txt"
            with self.assertRaisesRegex(ValueError, "escapes"):
                cr.validate_envelope({"findings": [finding]}, entry, root)

    def test_run_id_prevents_stale_resume(self):
        with tempfile.TemporaryDirectory() as root:
            entry = dispatch.build_plan(
                self._profile(), host="codex", codex_exec=True,
                root=root, run_id="new-run")[0]
            os.makedirs(os.path.dirname(entry["out_file"]))
            with open(entry["out_file"], "w", encoding="utf-8") as fh:
                json.dump({"findings": [], "_panopticon": {
                    "producer": "codex_exec", "run_id": "old-run",
                    "role": entry["role"], "panel": entry["panel"],
                    "lens": entry["lens"], "group": entry["group"]}}, fh)
            self.assertFalse(gr.entry_is_done(entry["out_file"], entry))
            self.assertEqual(gr.pending_entries([entry]), [entry])

    def test_build_plan_rejects_path_bearing_lens(self):
        profile = self._profile()
        profile["lenses"] = {"security": [{
            "name": "../../write-allowlist", "spawn": True,
            "priority": 1, "depth_threshold": "shallow"}]}
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(ValueError, "unsafe lens"):
                dispatch.build_plan(profile, host="codex", codex_exec=True, root=root)


if __name__ == "__main__":
    unittest.main()
