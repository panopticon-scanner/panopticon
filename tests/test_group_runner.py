import json, os, tempfile, unittest
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "skill"))
import scripts.group_runner as gr


class TestEntryIsDone(unittest.TestCase):
    def _write(self, d, name, text):
        p = os.path.join(d, name)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(text)
        return p

    def test_valid_findings_file_is_done(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, "f.json", json.dumps({"findings": [{"id": "A"}]}))
            self.assertTrue(gr.entry_is_done(p))

    def test_empty_findings_list_is_done(self):
        # A legitimately clean reviewer still produced a valid document.
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, "f.json", json.dumps({"findings": []}))
            self.assertTrue(gr.entry_is_done(p))

    def test_missing_file_is_not_done(self):
        self.assertFalse(gr.entry_is_done("/nonexistent/f.json"))

    def test_truncated_json_is_not_done(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, "f.json", '{"findings": [{"id":')  # truncated
            self.assertFalse(gr.entry_is_done(p))

    def test_object_without_findings_list_is_not_done(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, "f.json", json.dumps({"notfindings": 1}))
            self.assertFalse(gr.entry_is_done(p))


class TestPendingEntries(unittest.TestCase):
    def test_pending_excludes_done_entries(self):
        with tempfile.TemporaryDirectory() as d:
            done = os.path.join(d, "done.json")
            with open(done, "w") as fh:
                json.dump({"findings": []}, fh)
            plan = [{"out_file": done}, {"out_file": os.path.join(d, "todo.json")}]
            pending = gr.pending_entries(plan)
            self.assertEqual([e["out_file"] for e in pending],
                             [os.path.join(d, "todo.json")])
