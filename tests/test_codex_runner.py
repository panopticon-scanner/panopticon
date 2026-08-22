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
        self.assertIn("--skip-git-repo-check", command)
        self.assertNotIn("--add-dir", command)
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
                self.assertNotEqual(kwargs["cwd"], root)
                self.assertIn(os.path.join(root, "app.py"), kwargs["input"])
                output = command[command.index("--output-last-message") + 1]
                with open(output, "w", encoding="utf-8") as fh:
                    json.dump({
                        "findings": [self._valid_finding()],
                        "_panopticon": {"run_id": "run-123", "role": "panel_review"},
                    }, fh)
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

    def test_response_location_must_be_assigned(self):
        with tempfile.TemporaryDirectory() as root:
            entry = dispatch.build_plan(self._profile(), host="codex", root=root)[0]
            finding = self._valid_finding()
            finding["location"]["file"] = "other.py"
            with self.assertRaisesRegex(ValueError, "outside the assigned files"):
                cr.validate_envelope({"findings": [finding]}, entry, root)

    def test_symlinked_artifact_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
            os.symlink(outside, os.path.join(root, ".panopticon"))
            with self.assertRaisesRegex(ValueError, "not a symlink"):
                dispatch.build_plan(self._profile(), host="codex", root=root)

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

    def test_codex_host_automatically_builds_runner_entries(self):
        with tempfile.TemporaryDirectory() as root:
            entry = dispatch.build_plan(self._profile(), host="codex", root=root)[0]
        self.assertEqual(entry["execution"], "codex_exec")
        self.assertEqual(entry["delivery"], "return_json")
        self.assertTrue(entry["run_id"])

    def test_run_plan_validates_done_entries_before_resume(self):
        with tempfile.TemporaryDirectory() as root:
            out = os.path.join(root, ".panopticon", "findings.json")
            os.makedirs(os.path.dirname(out))
            with open(out, "w", encoding="utf-8") as fh:
                json.dump({"findings": []}, fh)
            bad = [{"role": "unknown", "group": "g", "panel": "code",
                    "out_file": out}]
            with self.assertRaisesRegex(ValueError, "invalid dispatch plan"):
                cr.run_plan(bad, root)


class TestSchemaValidationWarning(unittest.TestCase):
    """#1088: validate_schema must not SILENTLY skip when jsonschema is absent."""

    def test_warns_when_jsonschema_missing(self):
        import builtins, io, contextlib
        from unittest import mock
        real = builtins.__import__
        def fake(name, *a, **k):
            if name == "jsonschema":
                raise ImportError("simulated missing jsonschema")
            return real(name, *a, **k)
        cr._jsonschema_missing_warned = False
        buf = io.StringIO()
        with mock.patch("builtins.__import__", side_effect=fake), \
             contextlib.redirect_stderr(buf):
            cr.validate_schema({"x": 1}, "unused-path")   # hits the ImportError branch
        self.assertIn("jsonschema not installed", buf.getvalue())


class TestCodexAdvisors(unittest.TestCase):
    def _verdict(self, finding_id="SEC-001", run_id="run-test"):
        return {"run_id": run_id, "finding_id": finding_id,
                "verdict": "CONFIRMED",
                "confidence": "CERTAIN", "reasoning": "verified",
                "explored": ["app.py"], "references": [],
                "citations": {"cwe": [], "owasp": [], "cve": []}}

    def test_advisor_verdict_is_validated_and_published(self):
        with tempfile.TemporaryDirectory() as root:
            pan = os.path.join(root, ".panopticon")
            prompts = os.path.join(pan, "advisor-prompts")
            verdicts = os.path.join(pan, "verdicts")
            os.makedirs(prompts)
            queue_id = "4f2a9c1e7b30d85a"
            prompt = os.path.join(prompts, queue_id + ".md")
            with open(prompt, "w", encoding="utf-8") as fh:
                fh.write("verify claim")
            entry = {"queue_id": queue_id,
                     "finding": {"id": "SEC-001"}}

            def fake_runner(command, **kwargs):
                self.assertNotEqual(kwargs["cwd"], root)
                self.assertIn("UNTRUSTED DATA", kwargs["input"])
                output = command[command.index("--output-last-message") + 1]
                with open(output, "w", encoding="utf-8") as fh:
                    json.dump(self._verdict(), fh)
                return subprocess.CompletedProcess(command, 0, "", "")

            path = cr.run_advisor_entry(
                entry, prompt, verdicts, root, runner=fake_runner,
                run_id="run-test")
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["verdict"], "CONFIRMED")

    def test_advisor_wrong_echo_is_not_published(self):
        with tempfile.TemporaryDirectory() as root:
            pan = os.path.join(root, ".panopticon")
            prompts = os.path.join(pan, "advisor-prompts")
            verdicts = os.path.join(pan, "verdicts")
            os.makedirs(prompts)
            queue_id = "4f2a9c1e7b30d85a"
            prompt = os.path.join(prompts, queue_id + ".md")
            with open(prompt, "w") as fh:
                fh.write("verify")
            entry = {"queue_id": queue_id,
                     "finding": {"id": "SEC-001"}}

            def fake_runner(command, **kwargs):
                output = command[command.index("--output-last-message") + 1]
                with open(output, "w") as fh:
                    json.dump(self._verdict("WRONG"), fh)
                return subprocess.CompletedProcess(command, 0, "", "")

            with self.assertRaisesRegex(ValueError, "echoes"):
                cr.run_advisor_entry(entry, prompt, verdicts, root,
                                     runner=fake_runner, run_id="run-test")
            self.assertFalse(os.path.exists(os.path.join(verdicts, queue_id + ".json")))

    def test_advisor_paths_are_confined_to_artifacts(self):
        with tempfile.TemporaryDirectory() as root:
            entry = {"queue_id": "4f2a9c1e7b30d85a",
                     "finding": {"id": "SEC-001"}}
            with self.assertRaisesRegex(ValueError, "escapes"):
                cr.run_advisor_entry(entry, os.path.join(root, "prompt.md"),
                                     os.path.join(root, "verdicts"), root)


if __name__ == "__main__":
    unittest.main()
