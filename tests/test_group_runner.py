import json
import os
import tempfile
import unittest

import scripts.group_runner as gr
import scripts.evidence as ev


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
        out = os.path.join(d, "findings-%s-%s-domain_panel.json" % (group, panel))
        if done:
            with open(out, "w") as fh:
                json.dump({"findings": []}, fh)
        return {"role": "domain_panel", "out_file": out,
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

    def _driver_entry(self, d, group, domain, done):
        # 5.1 driver cell: group+domain, out_file findings-<group>-<domain>.json
        out = os.path.join(d, "findings-%s-%s.json" % (group, domain))
        if done:
            with open(out, "w") as fh:
                json.dump({"findings": []}, fh)
        return {"enforced": True, "out_file": out, "group": group, "domain": domain}

    def test_driver_domain_cells_counted_by_domain_axis(self):
        # #run7: the 5.1 driver plan entries carry group+domain (NOT the 4.x
        # group+panel), and their out_file is findings-<group>-<domain>.json with
        # no trailing panel segment -- so _group_panel returned (None, None) for
        # every driver cell and meta.coverage.fan_out came back {} on every 5.1 run.
        with tempfile.TemporaryDirectory() as d:
            plan = [
                self._driver_entry(d, "Auth", "SEC", True),
                self._driver_entry(d, "Auth", "COD", True),
                self._driver_entry(d, "Api", "SEC", False),   # not run
            ]
            cov = gr.fan_out_coverage(plan)
            self.assertEqual(cov["planned"], {"SEC": 2, "COD": 1})   # keyed by domain
            self.assertEqual(cov["executed"], {"SEC": 1, "COD": 1})
            self.assertEqual(cov["groups_complete"], ["Auth"])
            self.assertEqual(cov["groups_partial"], ["Api"])

    def test_group_panel_accepts_driver_domain_shape(self):
        self.assertEqual(
            gr._group_panel({"group": "Auth", "domain": "SEC",
                             "out_file": "/x/findings-Auth-SEC.json"}),
            ("Auth", "SEC"))

    def test_group_panel_regex_fallback_when_no_structured_fields(self):
        # #run7 TST-A2C: the legacy 4.x fallback branch -- an entry with NO
        # group/panel/domain keys is resolved purely from the
        # findings-<group>-<panel>- filename. Every other test supplies the
        # structured fields, so this success branch was never exercised.
        self.assertEqual(
            gr._group_panel({"role": "domain_panel",
                             "out_file": "/x/findings-g1-code-domain_panel.json"}),
            ("g1", "code"))

    def test_unresolvable_entry_is_skipped_not_fatal(self):
        # An entry with no group/panel keys and an out_file that doesn't match
        # the findings-{group}-{panel}- pattern is skipped, not crashed on.
        plan = [{"role": "panel_review", "out_file": "/tmp/whatever.json"}]
        cov = gr.fan_out_coverage(plan)  # must not raise
        self.assertEqual(cov["planned"], {})
        self.assertEqual(cov["executed"], {})
        self.assertEqual(cov["groups_complete"], [])
        self.assertEqual(cov["groups_partial"], [])

    def test_non_dict_plan_entry_is_tolerated(self):
        # A shape-valid JSON list can contain a non-dict element (corrupt plan);
        # neither fan_out_coverage nor pending_entries may raise — tolerant by
        # design, so a malformed plan never aborts synthesis after fan-out ran.
        plan = [{"role": "panel_review", "group": "g1", "panel": "code",
                 "out_file": "x.json"}, "not-a-dict", 42, None]
        cov = gr.fan_out_coverage(plan)  # must not raise
        self.assertEqual(cov["planned"], {"code": 1})
        self.assertEqual(gr.pending_entries(plan),
                         [plan[0]])  # only the real (not-done) entry, junk skipped


class TestVerifyResume(unittest.TestCase):
    def _vd(self, d, qid, body):
        vdir = os.path.join(d, "verdicts")
        os.makedirs(vdir, exist_ok=True)
        with open(os.path.join(vdir, qid + ".json"), "w", encoding="utf-8") as fh:
            fh.write(body)
        return vdir

    def test_verdict_is_done_matches_load_verdicts(self):
        with tempfile.TemporaryDirectory() as d:
            vdir = self._vd(d, "q1", '{"finding_id":"F","verdict":"CONFIRMED"}')
            self._vd(d, "q2", '```json\n{"verdict":"REJECTED"}\n```')  # fenced -> strict parse rejects
            self._vd(d, "q3", '{"finding_id":"F"}')                    # no verdict -> not done
            self._vd(d, "q4", '{ truncated')                           # unparseable -> not done
            self._vd(d, "q5", '{"verdict":"CONFIRMED"}')               # missing finding_id -> not done
            self.assertTrue(gr.verdict_is_done("q1", vdir))
            self.assertFalse(gr.verdict_is_done("q2", vdir))
            self.assertFalse(gr.verdict_is_done("q3", vdir))
            self.assertFalse(gr.verdict_is_done("q4", vdir))
            self.assertFalse(gr.verdict_is_done("q5", vdir))
            self.assertFalse(gr.verdict_is_done("nope", vdir))
            self.assertFalse(gr.verdict_is_done("q1", None))
            # consistency: done-set == load_verdicts keys
            self.assertEqual({"q1"}, set(ev.load_verdicts(vdir)))

    def test_pending_verdicts_is_the_resume_set(self):
        with tempfile.TemporaryDirectory() as d:
            vdir = self._vd(d, "q1", '{"finding_id":"F1","verdict":"CONFIRMED"}')
            queue = {"entries": [{"queue_id": "q1"}, {"queue_id": "q2"},
                                 {"queue_id": "q3"}, "junk"]}
            self.assertEqual([e["queue_id"] for e in gr.pending_verdicts(queue, vdir)],
                             ["q2", "q3"])                 # q1 done, "junk" skipped
            self.assertEqual(gr.pending_verdicts(None, vdir), [])

    def test_pending_verdicts_retries_wrong_echo(self):
        with tempfile.TemporaryDirectory() as d:
            vdir = self._vd(d, "q1", '{"finding_id":"WRONG","verdict":"REJECTED"}')
            queue = {"entries": [{"queue_id": "q1", "finding": {"id": "SEC-001"}}]}
            self.assertEqual(gr.pending_verdicts(queue, vdir), queue["entries"])

    def test_non_list_entries_is_tolerated(self):
        # A verify queue with a truthy non-list `entries` (e.g. an int) is a
        # valid JSON dict, so it passes synthesize.main's isinstance(dict)
        # load guard; pending_verdicts/resume_stats must treat it as empty
        # rather than raising when iterating it.
        self.assertEqual(gr.pending_verdicts({"entries": 42}, None), [])
        self.assertEqual(gr.resume_stats([], {"entries": 42}, None)["verify"],
                         {"total": 0, "done": 0, "pending": 0})

    def test_resume_stats_counts_both_phases(self):
        with tempfile.TemporaryDirectory() as d:
            done_out = os.path.join(d, "f1.json")
            with open(done_out, "w") as fh:
                fh.write('{"findings":[]}')
            plan = [{"out_file": done_out}, {"out_file": os.path.join(d, "missing.json")}]
            vdir = self._vd(d, "q1", '{"finding_id":"F","verdict":"CONFIRMED"}')
            queue = {"entries": [{"queue_id": "q1"}, {"queue_id": "q2"}]}
            st = gr.resume_stats(plan, queue, vdir)
            self.assertEqual(st["fan_out"], {"total": 2, "done": 1, "pending": 1})
            self.assertEqual(st["verify"], {"total": 2, "done": 1, "pending": 1})
            self.assertEqual(gr.resume_stats(None, None, None)["fan_out"],
                             {"total": 0, "done": 0, "pending": 0})


class TestOutFileContentHashes(unittest.TestCase):
    """#493 R4: fan-out-time snapshot + synthesis-time verification."""

    def test_snapshot_and_verify_roundtrip_then_tamper(self):
        import tempfile, os, json as _json
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "findings-g1-code-panel_review.json")
            with open(out, "w") as fh:
                _json.dump({"findings": []}, fh)
            hashes_path = os.path.join(d, "out-file-hashes.json")
            plan = [{"out_file": out}]
            recorded = gr.snapshot_out_files(plan, out_path=hashes_path)
            self.assertEqual(len(recorded), 1)
            checked, mismatched, unreadable = gr.verify_out_file_hashes(
                [out], hashes_path=hashes_path)
            self.assertEqual((checked, mismatched, unreadable), (1, [], False))
            with open(out, "w") as fh:                    # substitute content
                _json.dump({"findings": [{"id": "EVIL-1"}]}, fh)
            checked, mismatched, unreadable = gr.verify_out_file_hashes(
                [out], hashes_path=hashes_path)
            self.assertEqual(checked, 1)
            self.assertEqual(mismatched, [out])
            self.assertFalse(unreadable)

    def test_no_snapshot_reads_as_not_measured(self):
        checked, mismatched, unreadable = gr.verify_out_file_hashes(
            ["x.json"], hashes_path="/nonexistent/h.json")
        self.assertIsNone(checked)
        self.assertEqual(mismatched, [])
        self.assertFalse(unreadable)               # genuinely absent, not tamper

    def test_corrupt_snapshot_is_a_detected_tamper_not_no_snapshot(self):
        # #run7 #1208: snapshot_out_files only writes when non-empty, so a
        # PRESENT-but-corrupt hashes file is a tamper signal, not "no snapshot" --
        # an attacker who substitutes a findings file could otherwise truncate the
        # snapshot to erase the evidence and keep integrity green.
        import tempfile, os
        with tempfile.TemporaryDirectory() as d:
            for payload in ("{ this is not json", "[]", "{}", "null"):
                hp = os.path.join(d, "out-file-hashes.json")
                with open(hp, "w") as fh:
                    fh.write(payload)
                checked, mismatched, unreadable = gr.verify_out_file_hashes(
                    ["x.json"], hashes_path=hp)
                self.assertTrue(unreadable, payload)   # present+corrupt -> tamper
                self.assertIsNone(checked)


class TestVerifyPlanEntries(unittest.TestCase):
    def _plan(self, enforced=True):
        return [{
            "role": "domain_panel",
            "agent": "panopticon-domain-panel",
            "enforced": enforced,
            "panel": "security",
            "lens": None,
            "files": ["app.py"],
            "group": "test_repo",
            "depth": "standard",
            "security_mode": "standard",
            "lenses": [],
            "out_file": os.path.join(tempfile.mkdtemp(), "out.json"),
            "prompt": "review",
            "run_id": "abc123",
            "scope_bound": True,
        }]

    def test_enforced_without_registration_is_caught(self):
        plan = self._plan(enforced=True)
        problems = gr.verify_plan_entries(plan, host="claude", agents_dir=tempfile.mkdtemp())
        self.assertTrue(problems)
        self.assertIn("enforced:true but no registered shell", " ".join(problems))

    def test_enforced_with_registration_is_ok(self):
        reg = tempfile.mkdtemp()
        with open(os.path.join(reg, "panopticon-domain-panel.md"), "w") as fh:
            fh.write("---\nname: test\n---\nbody\n")
        plan = self._plan(enforced=True)
        problems = gr.verify_plan_entries(plan, host="claude", agents_dir=reg)
        self.assertFalse(problems)

    def test_codex_exec_entries_are_exempt(self):
        plan = self._plan(enforced=True)
        plan[0]["execution"] = "codex_exec"
        plan[0]["delivery"] = "return_json"
        problems = gr.verify_plan_entries(plan, host="claude", agents_dir=tempfile.mkdtemp())
        self.assertFalse(problems)
