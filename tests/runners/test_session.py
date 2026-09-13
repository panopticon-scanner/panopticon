import contextlib
import io
import json
import unittest

import scripts.runners.session as session_runner


class TestSessionRunner(unittest.TestCase):
    def test_run_batch_prints_the_batch_and_returns_none(self):
        r = session_runner.SessionRunner("claude")
        entries = [{"id": "scout-app", "out_file": "/r/.panopticon/runs/t/scout-app.json",
                    "delivery": "return_json", "prompt_file": "/r/p.txt"},
                   {"id": "review-app-SEC", "out_file": "/r/.panopticon/runs/t/findings-app-SEC.json"}]
        with contextlib.redirect_stdout(io.StringIO()) as out:
            got = r.run_batch(entries, 1, env_for=lambda e: {})
        self.assertIsNone(got)
        printed = json.loads(out.getvalue())
        self.assertEqual(printed["status"], "dispatch")
        self.assertEqual(printed["pending"], ["scout-app", "review-app-SEC"])
        self.assertEqual(printed["return_persist"], ["scout-app"])
        self.assertIn("driver persist scout-app", printed["persist"])
        self.assertIn("driver loop --mode session", printed["then"])
