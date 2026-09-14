import json
import os
import subprocess
import tempfile
import unittest
import sys

class TestGeminiGuard(unittest.TestCase):
    def setUp(self):
        self.guard = os.path.abspath("skill/scripts/gemini_guard.py")

    def run_guard(self, payload, env=None):
        test_env = os.environ.copy()
        if env:
            test_env.update(env)
        proc = subprocess.run([sys.executable, self.guard], input=json.dumps(payload), text=True, capture_output=True, env=test_env)
        if proc.stdout:
            try:
                return json.loads(proc.stdout)
            except Exception as e:
                print('JSON ERROR:', e, repr(proc.stdout))
                pass
                pass
        return {}

    def test_allow_unknown_tool(self):
        payload = {"toolCall": {"name": "other_tool"}}
        res = self.run_guard(payload)
        self.assertEqual(res.get("decision"), "allow")

    def test_deny_out_of_scope_read(self):
        with tempfile.TemporaryDirectory() as d:
            scope = os.path.join(d, "read-scope.json")
            with open(scope, "w") as f:
                json.dump({"entry-1": {"files": [os.path.join(d, "in.py")]}}, f)
            env = {"PANOPTICON_ENTRY_ID": "entry-1", "PANOPTICON_READ_SCOPE": scope}
            payload = {"toolCall": {"name": "view_file", "args": {"AbsolutePath": os.path.join(d, "out.py")}}}
            res = self.run_guard(payload, env)
            self.assertEqual(res.get("decision"), "deny")

    def test_unbound_identity_deny(self):
        payload = {"toolCall": {"name": "view_file", "args": {"AbsolutePath": "foo"}}, "context": {"agentName": "panopticon-scout"}}
        env = {"PANOPTICON_ENTRY_ID": ""}
        res = self.run_guard(payload, env)
        self.assertEqual(res.get("decision"), "deny")

if __name__ == "__main__":
    unittest.main()
