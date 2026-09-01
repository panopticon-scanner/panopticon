import json
import os
import tempfile
import unittest

import scripts.collect_usage as cu

# NOTE: scripts.synthesize is imported lazily inside the one test that needs it.
# Importing it at module scope prepends skill/scripts to sys.path[0]
# (score_gate.py:11), where skill/scripts/tools/ then shadows tests/tools/ and
# breaks collection of every test that does `from tools.git_repo import ...`.
# This file sorts early enough alphabetically to trigger that for the whole run.


def _rec(role="assistant", usage=None, model="claude-opus-5", ts=None,
         content=None, rtype=None):
    msg = {"role": role, "model": model}
    if usage is not None:
        msg["usage"] = usage
    if content is not None:
        msg["content"] = content
    rec = {"type": rtype or ("user" if role == "user" else "assistant"),
           "message": msg}
    if ts:
        rec["timestamp"] = ts
    return rec


def _u(i=0, o=0, cc=0, cr=0):
    return {"input_tokens": i, "output_tokens": o,
            "cache_creation_input_tokens": cc, "cache_read_input_tokens": cr}


def _write(path, records):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    return path


class TestProjectSlug(unittest.TestCase):
    def test_non_alphanumerics_collapse_to_dashes(self):
        # Spaces and underscores both become '-', which is how the real
        # transcript directory for this repo is named.
        self.assertEqual(
            cu.project_slug("/Volumes/Mini Vault/untitled_folder/projects/panopticon"),
            "-Volumes-Mini-Vault-untitled-folder-projects-panopticon")


class TestScan(unittest.TestCase):
    def test_sums_every_usage_field(self):
        with tempfile.TemporaryDirectory() as d:
            p = _write(os.path.join(d, "t.jsonl"), [
                _rec(usage=_u(1, 2, 3, 4)),
                _rec(usage=_u(10, 20, 30, 40)),
                _rec(),                       # no usage -> ignored
            ])
            totals, n, models = cu.scan(p)
        self.assertEqual(totals, _u(11, 22, 33, 44))
        self.assertEqual(n, 2)
        self.assertEqual(models, {"claude-opus-5": 2})

    def test_since_excludes_earlier_messages(self):
        # A session transcript spans more than one run; usage from before the
        # run started must not be billed to it.
        with tempfile.TemporaryDirectory() as d:
            p = _write(os.path.join(d, "t.jsonl"), [
                _rec(usage=_u(o=100), ts="2026-08-29T00:00:00Z"),   # prior run
                _rec(usage=_u(o=7), ts="2026-08-30T00:00:00Z"),     # this run
            ])
            totals, n, _ = cu.scan(p, since="2026-08-29T12:00:00Z")
        self.assertEqual(totals["output_tokens"], 7)
        self.assertEqual(n, 1)

    def test_malformed_and_scalar_lines_are_tolerated(self):
        # Task output files interleave bare scalars and partial lines with
        # records; neither may abort collection.
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "t.jsonl")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write("42\n")                       # bare scalar
                fh.write('{"message": {"usage":\n')    # truncated
                fh.write(json.dumps(_rec(usage=_u(o=5))) + "\n")
                fh.write('"a string"\n')
            totals, n, _ = cu.scan(p)
        self.assertEqual(totals["output_tokens"], 5)
        self.assertEqual(n, 1)


class TestPhaseAttribution(unittest.TestCase):
    def _agent(self, d, name, prompt):
        return _write(os.path.join(d, name),
                      [_rec(role="user", content=prompt),
                       _rec(usage=_u(o=1))])

    def test_verify_wins_over_findings_mentioned_in_its_prompt(self):
        # THE bug this ordering exists for: an advisor prompt EMBEDS the cell's
        # findings to adjudicate, so it names findings-<g>-<d>.json too. Testing
        # review first would file every advisor under review and report the
        # verify round as costing nothing.
        with tempfile.TemporaryDirectory() as d:
            p = self._agent(d, "adv.jsonl",
                            "Adjudicate the findings in findings-Auth-SEC.json. "
                            "Write your bundle to /r/.panopticon/verdicts/"
                            "verdicts-Auth-SEC.json")
            self.assertEqual(cu.classify_transcript(p), "verify")

    def test_review_and_scout_are_recognised(self):
        with tempfile.TemporaryDirectory() as d:
            rev = self._agent(d, "rev.jsonl",
                              "Write your findings to /r/.panopticon/"
                              "findings-Auth-SEC.json")
            sct = self._agent(d, "sct.jsonl",
                              "Return your profile; out_file /r/.panopticon/"
                              "scout-Auth.json")
            self.assertEqual(cu.classify_transcript(rev), "review")
            self.assertEqual(cu.classify_transcript(sct), "scout")

    def test_prompt_file_path_decides_the_phase(self):
        # #run10 B2 hands agents a prompt_file PATH, so a real dispatch prompt
        # names _prompts/<entry-id>.txt and never mentions the findings file.
        # On the first real target scan this put 100% of subagent tokens in
        # `unattributed` -- two of our own features interacting.
        with tempfile.TemporaryDirectory() as d:
            for entry, want in (("review-UI_2-COD", "review"),
                                ("scout-Auth", "scout"),
                                ("verify-Auth-SEC-primary", "verify")):
                p = self._agent(d, entry + ".jsonl",
                                "Read your full instructions from this file:\n"
                                "/r/.panopticon/runs/tag/_prompts/%s.txt\n"
                                "Repo root: /r" % entry)
                self.assertEqual(cu.classify_transcript(p), want, entry)

    def test_unrecognised_prompt_is_unattributed_not_guessed(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._agent(d, "x.jsonl", "Summarise the release notes.")
            self.assertEqual(cu.classify_transcript(p), "unattributed")

    def test_classification_ignores_later_turns(self):
        # A scout that READS a findings file must stay a scout: only the
        # dispatched prompt decides.
        with tempfile.TemporaryDirectory() as d:
            p = _write(os.path.join(d, "s.jsonl"), [
                _rec(role="user", content="write /r/.panopticon/scout-Api.json"),
                _rec(usage=_u(o=1), content="I read findings-Api-COD.json"),
            ])
            self.assertEqual(cu.classify_transcript(p), "scout")


class TestTranscriptDiscovery(unittest.TestCase):
    """#run10: the first release counted only the `tasks/` directory."""

    def _session(self, root):
        proj = os.path.join(root, "-Some-Project")
        sess = "sess-1"
        ctl = _write(os.path.join(proj, sess + ".jsonl"), [_rec(usage=_u(o=1))])
        return proj, sess, ctl

    def test_workflow_agent_transcripts_are_discovered(self):
        # The documented Claude-host fan-out IS a Workflow, and its agents write
        # under subagents/workflows/wf_*/. Missing them dropped more tokens than
        # the collector reported in total on the first real target scan.
        with tempfile.TemporaryDirectory() as d:
            proj, sess, ctl = self._session(d)
            wf = os.path.join(proj, sess, "subagents", "workflows", "wf_abc")
            _write(os.path.join(wf, "agent-aaa.jsonl"), [_rec(usage=_u(o=5))])
            _write(os.path.join(wf, "agent-bbb.jsonl"), [_rec(usage=_u(o=6))])
            found = cu.find_task_transcripts(ctl)
        self.assertEqual({cu._agent_id(p) for p in found}, {"aaa", "bbb"})

    def test_same_agent_in_two_locations_is_counted_once(self):
        # subagents/<id>.jsonl and tasks/<id>.output are the SAME agent. Adding
        # both would double-count the run -- worse than the under-count it fixes.
        with tempfile.TemporaryDirectory() as d:
            proj, sess, ctl = self._session(d)
            _write(os.path.join(proj, sess, "subagents", "dup.jsonl"),
                   [_rec(usage=_u(o=9))])
            wf = os.path.join(proj, sess, "subagents", "workflows", "wf_x")
            _write(os.path.join(wf, "agent-dup.jsonl"), [_rec(usage=_u(o=9))])
            found = cu.find_task_transcripts(ctl)
        self.assertEqual(len(found), 1, found)
        self.assertEqual(cu._agent_id(found[0]), "dup")

    def test_agent_id_strips_prefix_and_suffixes(self):
        self.assertEqual(cu._agent_id("/x/agent-a1b2.jsonl"), "a1b2")
        self.assertEqual(cu._agent_id("/x/a1b2.output"), "a1b2")
        self.assertEqual(cu._agent_id("/x/a1b2.jsonl"), "a1b2")


class TestControllerSelection(unittest.TestCase):
    """#calibration-2: a machine running more than one session in the same
    project has several transcripts, and the most-recently-TOUCHED one is not
    necessarily the one that ran the scan."""

    def _proj(self, root):
        d = os.path.join(root, ".claude", "projects",
                         cu.project_slug("/some/project"))
        os.makedirs(d, exist_ok=True)
        return d

    def test_picks_the_session_that_worked_in_the_window(self):
        with tempfile.TemporaryDirectory() as home:
            d = self._proj(home)
            # `idle` is touched LAST, so newest-by-mtime would pick it -- but it
            # did no work inside the window.
            _write(os.path.join(d, "busy.jsonl"), [
                _rec(usage=_u(o=10), ts="2026-08-30T20:00:00Z"),
                _rec(usage=_u(o=10), ts="2026-08-30T20:01:00Z")])
            idle = _write(os.path.join(d, "idle.jsonl"), [
                _rec(usage=_u(o=99), ts="2026-08-01T00:00:00Z")])
            os.utime(idle, (2 << 30, 2 << 30))
            got = cu.find_controller_transcript(
                "/some/project", home=home, since="2026-08-30T19:00:00Z")
        self.assertEqual(os.path.basename(got), "busy.jsonl")

    def test_without_a_window_falls_back_to_newest(self):
        with tempfile.TemporaryDirectory() as home:
            d = self._proj(home)
            _write(os.path.join(d, "old.jsonl"), [_rec(usage=_u(o=1))])
            new = _write(os.path.join(d, "new.jsonl"), [_rec(usage=_u(o=1))])
            os.utime(new, (2 << 30, 2 << 30))
            got = cu.find_controller_transcript("/some/project", home=home)
        self.assertEqual(os.path.basename(got), "new.jsonl")

    def test_all_silent_in_window_falls_back_rather_than_asserting_one(self):
        with tempfile.TemporaryDirectory() as home:
            d = self._proj(home)
            _write(os.path.join(d, "a.jsonl"),
                   [_rec(usage=_u(o=1), ts="2026-01-01T00:00:00Z")])
            b = _write(os.path.join(d, "b.jsonl"),
                       [_rec(usage=_u(o=1), ts="2026-01-01T00:00:00Z")])
            os.utime(b, (2 << 30, 2 << 30))
            got = cu.find_controller_transcript(
                "/some/project", home=home, since="2026-08-30T00:00:00Z")
        self.assertEqual(os.path.basename(got), "b.jsonl")


class TestCollect(unittest.TestCase):
    def _session(self, d):
        ctl = _write(os.path.join(d, "ctl.jsonl"), [_rec(usage=_u(1, 2, 3, 4))])
        tasks = os.path.join(d, "tasks")
        _write(os.path.join(tasks, "a.output"),
               [_rec(role="user", content="write /r/.panopticon/findings-G-SEC.json"),
                _rec(usage=_u(o=10))])
        _write(os.path.join(tasks, "b.output"),
               [_rec(role="user", content="write /r/.panopticon/verdicts/verdicts-G-SEC.json"),
                _rec(usage=_u(o=20))])
        return ctl, tasks

    def test_totals_reconcile_with_the_parts(self):
        with tempfile.TemporaryDirectory() as d:
            ctl, tasks = self._session(d)
            doc = cu.collect(d, d, transcript=ctl, tasks_dir=tasks)
        self.assertEqual(doc["total"], sum(doc["by_field"].values()))
        # phases cover every subagent token; the controller is the remainder
        self.assertEqual(
            sum(doc["by_phase"].values())
            + sum(doc["by_source"]["controller"].values()),
            doc["total"])
        self.assertEqual(doc["by_phase"]["review"], 10)
        self.assertEqual(doc["by_phase"]["verify"], 20)
        self.assertEqual(doc["subagent_transcripts"], 2)

    def test_no_transcript_yields_none_not_zero(self):
        # An absent number must stay absent. A usage.json of zeros would be a
        # false ledger, which is the failure mode D4 exists to avoid.
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(
                cu.collect(d, d, transcript=None,
                           tasks_dir=os.path.join(d, "empty")))

    def test_main_writes_nothing_when_no_transcript(self):
        with tempfile.TemporaryDirectory() as d:
            rc = cu.main(["--run-dir", d, "--project-dir", d,
                          "--tasks-dir", os.path.join(d, "none")])
        self.assertEqual(rc, 1)
        self.assertFalse(os.path.exists(os.path.join(d, "usage.json")))

    def test_since_defaults_to_the_run_manifest(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "run-manifest.json"), "w",
                      encoding="utf-8") as fh:
                json.dump({"run_id": "r", "created": "2026-08-30T00:00:00Z"}, fh)
            self.assertEqual(cu.run_started_at(d), "2026-08-30T00:00:00Z")
            self.assertIsNone(cu.run_started_at(os.path.join(d, "nope")))


class TestEndToEndIntoTheReport(unittest.TestCase):
    def test_written_usage_is_what_synthesize_surfaces(self):
        # The whole point of the channel: what the collector writes is what
        # meta.cost.tokens reports, verbatim.
        import scripts.synthesize as syn
        with tempfile.TemporaryDirectory() as d:
            ctl = _write(os.path.join(d, "ctl.jsonl"), [_rec(usage=_u(o=99))])
            rc = cu.main(["--run-dir", d, "--project-dir", d,
                          "--transcript", ctl,
                          "--tasks-dir", os.path.join(d, "none"), "--since", "none"])
            self.assertEqual(rc, 0)
            written = json.load(open(os.path.join(d, "usage.json"), encoding="utf-8"))
            surfaced = syn.load_run_usage(d)
        self.assertEqual(surfaced, written)
        self.assertEqual(surfaced["total"], 99)




class TestSourcesIsASummary(unittest.TestCase):
    """`sources` must stay O(1), not O(transcripts).

    It was one entry per transcript, each with an absolute path: 700 entries and
    190 KB on gotify -- 99% of meta.cost, and ~99% of the report BASE. synthesize
    splits a report once its base (everything but the findings) passes max_bytes,
    so that made the split trigger a function of how many agents ran rather than
    how much was found: a 2-finding fixture produced an 888 KB base and split
    into report.json + report_part2.json. Nothing was lost, but a consumer
    reading report.json alone saw half the findings.
    """

    def _usage(self, n_subagents):
        with tempfile.TemporaryDirectory() as d:
            tasks = os.path.join(d, "tasks")
            os.makedirs(tasks)
            rec = json.dumps({"message": {"usage": {"input_tokens": 1,
                                                    "output_tokens": 1},
                                          "model": "m"}}) + "\n"
            ctl = os.path.join(d, "controller.jsonl")
            with open(ctl, "w", encoding="utf-8") as fh:
                fh.write(rec)
            for i in range(n_subagents):
                with open(os.path.join(tasks, "review-g%d-SEC.jsonl" % i), "w",
                          encoding="utf-8") as fh:
                    fh.write(rec)
            return cu.collect(d, d, transcript=ctl, tasks_dir=tasks)

    def test_sources_does_not_grow_with_transcript_count(self):
        small = self._usage(3)
        large = self._usage(300)
        if small is None or large is None:
            self.skipTest("collect() found no usage records in the fixture")
        s_bytes = len(json.dumps(small["sources"]))
        l_bytes = len(json.dumps(large["sources"]))
        self.assertLess(
            l_bytes, s_bytes * 2,
            "sources grew with transcript count (%d -> %d bytes): it must be a "
            "summary, or meta.cost drives the report split" % (s_bytes, l_bytes))
        self.assertLess(l_bytes, 2000, "sources should stay small; got %d bytes" % l_bytes)

    def test_sources_still_reports_the_counts(self):
        u = self._usage(5)
        if u is None:
            self.skipTest("collect() found no usage records in the fixture")
        self.assertEqual(u["sources"]["subagent_transcripts"], 5)
        self.assertEqual(u["subagent_transcripts"], 5)


if __name__ == "__main__":
    unittest.main()
