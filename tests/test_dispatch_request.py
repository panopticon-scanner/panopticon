import os
import tempfile
import unittest

import scripts.driver as driver


class TestLoadDispatchRequest(unittest.TestCase):
    def test_reads_request_entries_for_guard_allowlist(self):
        with tempfile.TemporaryDirectory() as root:
            entries = [{"id": "review-app-SEC", "out_file": "/abs/findings-app-SEC.json"},
                       {"id": "review-app-COD", "out_file": "/abs/findings-app-COD.json"}]
            driver.write_dispatch_request(root, "RID", "review", "app", entries)
            req = driver.load_dispatch_request(root)
            self.assertEqual(req["checkpoint"], "review")
            self.assertEqual([e["out_file"] for e in req["entries"]],
                             ["/abs/findings-app-SEC.json", "/abs/findings-app-COD.json"])

    def test_absent_request_returns_none(self):
        with tempfile.TemporaryDirectory() as root:
            self.assertIsNone(driver.load_dispatch_request(root))

    def test_malformed_request_returns_none(self):
        # load_dispatch_request delegates to _load_json, which swallows parse
        # errors so the engine can proceed without a stale request (#1196).
        with tempfile.TemporaryDirectory() as root:
            pano = os.path.join(root, ".panopticon")
            os.makedirs(pano)
            with open(os.path.join(pano, "dispatch-request.json"), "w") as fh:
                fh.write("{not valid json")
            self.assertIsNone(driver.load_dispatch_request(root))

    def test_empty_entries_roundtrip(self):
        with tempfile.TemporaryDirectory() as root:
            driver.write_dispatch_request(root, "RID", "review", "app", [])
            req = driver.load_dispatch_request(root)
            self.assertEqual(req["entries"], [])

    def test_unknown_checkpoint_raises(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(ValueError, "unknown checkpoint kind"):
                driver.write_dispatch_request(root, "RID", "not-a-checkpoint", "app", [])
