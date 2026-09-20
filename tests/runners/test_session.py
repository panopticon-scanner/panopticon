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

    def test_the_printed_batch_names_the_request_hash(self):
        # #1727: a session HOST reads dispatch-request.json itself, out of the
        # reviewed tree, so it is told what that file must hash to. The loop
        # sets the attribute exactly as it sets `dispatch_request`.
        r = session_runner.SessionRunner("claude")
        r.dispatch_request = "/r/.panopticon/runs/t/dispatch-request.json"
        r.request_sha256 = "b" * 64
        with contextlib.redirect_stdout(io.StringIO()) as out:
            r.run_batch([{"id": "review-app-SEC", "out_file": "/r/x.json"}], 1,
                        env_for=lambda e: {})
        printed = json.loads(out.getvalue())
        self.assertEqual(printed["request_sha256"], "b" * 64)

    def test_the_request_hash_defaults_to_none(self):
        r = session_runner.SessionRunner("claude")
        with contextlib.redirect_stdout(io.StringIO()) as out:
            r.run_batch([{"id": "e", "out_file": "/r/x.json"}], 1, env_for=lambda e: {})
        self.assertIsNone(json.loads(out.getvalue())["request_sha256"])
