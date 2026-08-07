import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "scripts"))
import reconcile_apply


class TestLedger(unittest.TestCase):
    def test_load_missing_ledger_returns_empty_dict(self):
        self.assertEqual(reconcile_apply.load_ledger(path="/nonexistent/x.json"), {})

    def test_load_ledger_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "filed-issues.json")
            data = {"fp|F-1|app.py|finding": "https://github.com/o/r/issues/1"}
            with open(p, "w") as fh:
                json.dump(data, fh)
            self.assertEqual(reconcile_apply.load_ledger(path=p), data)

    def test_ledger_key_matches_file_issues_key_for_format(self):
        record = {"stored_fingerprint": "deadbeefdeadbeef", "id": "F-TOOL-1",
                 "location_file": "app/config.py", "kind": "finding"}
        self.assertEqual(reconcile_apply.ledger_key(record),
                         "deadbeefdeadbeef|F-TOOL-1|app/config.py|finding")

    def test_ledger_key_handles_missing_stored_fingerprint(self):
        record = {"stored_fingerprint": None, "id": "F-1",
                 "location_file": "x.py", "kind": "rejected"}
        self.assertEqual(reconcile_apply.ledger_key(record), "|F-1|x.py|rejected")
