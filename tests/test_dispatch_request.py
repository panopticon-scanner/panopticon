import tempfile, unittest
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
