import json
import os
import subprocess
import tempfile
import unittest

from scripts.runners import gemini

class TestGeminiRunner(unittest.TestCase):
    def test_prepare_writes_hooks_json(self):
        with tempfile.TemporaryDirectory() as run_dir, tempfile.TemporaryDirectory() as review_root:
            runner = gemini.Runner()
            runner.prepare(run_dir, review_root)

            hooks_path = os.path.join(run_dir, ".agents", "hooks.json")
            self.assertTrue(os.path.isfile(hooks_path))

            with open(hooks_path, "r", encoding="utf-8") as f:
                hooks_data = json.load(f)

            self.assertIn("panopticon-guard", hooks_data)
            hooks = hooks_data["panopticon-guard"].get("PreToolUse", [])
            self.assertEqual(1, len(hooks))

            cmd = hooks[0]["hooks"][0]["command"]
            self.assertIn("gemini_guard.py", cmd)

    def test_run_entry_env(self):
        with tempfile.TemporaryDirectory() as run_dir, tempfile.TemporaryDirectory() as review_root:
            calls = []
            def spy_runner(cmd, cwd, env, **kwargs):
                calls.append((cmd, cwd, env))
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout='{"status": "SUCCESS", "response": "ok", "usage": {}}')

            runner = gemini.Runner(runner=spy_runner)
            runner.prepare(run_dir, review_root)

            env = {"PANOPTICON_ENTRY_ID": "entry-123", "PANOPTICON_READ_SCOPE": os.path.join(review_root, ".panopticon", "read-scope.json"), "PANOPTICON_WRITE_ALLOWLIST": os.path.join(review_root, ".panopticon", "write-allowlist.json")}
            entry = {"id": "entry-123", "prompt": "test"}

            result = runner.run_entry(entry, env)
            self.assertTrue(result.ok)

            self.assertEqual(1, len(calls))
            cmd, out_cwd, out_env = calls[0]

            self.assertEqual(run_dir, out_cwd)
            self.assertEqual("entry-123", out_env.get("PANOPTICON_ENTRY_ID"))
            self.assertNotIn("AGY_SESSION", out_env)
            self.assertIn("PANOPTICON_READ_SCOPE", out_env)
            self.assertIn("PANOPTICON_WRITE_ALLOWLIST", out_env)

            self.assertEqual(os.path.join(review_root, ".panopticon", "read-scope.json"), out_env["PANOPTICON_READ_SCOPE"])
            self.assertEqual(os.path.join(review_root, ".panopticon", "write-allowlist.json"), out_env["PANOPTICON_WRITE_ALLOWLIST"])

if __name__ == "__main__":
    unittest.main()
    def test_shadow_hooks_check(self):
        with tempfile.TemporaryDirectory() as run_dir, tempfile.TemporaryDirectory() as review_root:
            pano_dir = os.path.join(review_root, ".panopticon")
            os.makedirs(pano_dir)

            # Plant a shadow hook
            agent_dir = os.path.join(pano_dir, ".agents")
            os.makedirs(agent_dir)
            with open(os.path.join(agent_dir, "hooks.json"), "w") as f:
                f.write("{}")

            runner = gemini.Runner()
            with self.assertRaises(ValueError) as ctx:
                runner.prepare(run_dir, review_root)
            self.assertIn("Shadow hook discovered", str(ctx.exception))
