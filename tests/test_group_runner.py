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


class TestFanOutCoverage(unittest.TestCase):
    def _plan_entry(self, d, group, panel, done):
        out = os.path.join(d, "findings-%s-%s-panel_review.json" % (group, panel))
        if done:
            with open(out, "w") as fh:
                json.dump({"findings": []}, fh)
        return {"role": "panel_review", "out_file": out,
                "group": group, "panel": panel}

    def test_planned_vs_executed_and_group_status(self):
        with tempfile.TemporaryDirectory() as d:
            plan = [
                self._plan_entry(d, "g1", "code", True),
                self._plan_entry(d, "g1", "security", True),
                self._plan_entry(d, "g2", "code", True),
                self._plan_entry(d, "g2", "security", False),  # not run
            ]
            cov = gr.fan_out_coverage(plan)
            self.assertEqual(cov["planned"], {"code": 2, "security": 2})
            self.assertEqual(cov["executed"], {"code": 2, "security": 1})
            self.assertEqual(cov["groups_complete"], ["g1"])
            self.assertEqual(cov["groups_partial"], ["g2"])

    def test_zero_done_group_is_partial_not_dropped(self):
        # A group that was planned but had NO entries run must be disclosed as
        # partial (a fully-missed group), never silently dropped.
        with tempfile.TemporaryDirectory() as d:
            plan = [
                self._plan_entry(d, "g3", "code", False),
                self._plan_entry(d, "g3", "security", False),
            ]
            cov = gr.fan_out_coverage(plan)
            self.assertEqual(cov["planned"], {"code": 1, "security": 1})
            self.assertEqual(cov["executed"], {})
            self.assertEqual(cov["groups_complete"], [])
            self.assertEqual(cov["groups_partial"], ["g3"])

    def test_unresolvable_entry_is_skipped_not_fatal(self):
        # An entry with no group/panel keys and an out_file that doesn't match
        # the findings-{group}-{panel}- pattern is skipped, not crashed on.
        plan = [{"role": "panel_review", "out_file": "/tmp/whatever.json"}]
        cov = gr.fan_out_coverage(plan)  # must not raise
        self.assertEqual(cov["planned"], {})
        self.assertEqual(cov["executed"], {})
        self.assertEqual(cov["groups_complete"], [])
        self.assertEqual(cov["groups_partial"], [])
