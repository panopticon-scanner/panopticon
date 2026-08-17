"""#5.0-03: tool findings are routed into the driver's verify phase.

The certification core. Proves end-to-end that a deterministic (tool) finding
now gets a per-finding advisor dispatched by the DRIVER, its verdict matched by
(unchanged) synthesize, and `tool_confirmed` reached -- so a base PASS is no
longer flipped to INCONCLUSIVE just because a scanner fired.

Style mirrors test_driver_verify.py / TestVerifyMatrixEndToEnd: drives state on
disk and runs a REAL synthesize.py subprocess via driver.synthesize_execute.
"""
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

import scripts.driver as driver
import scripts.evidence as evidence

RUN_ID = "RID"


def _semgrep_sarif(results):
    return {"runs": [{"tool": {"driver": {"name": "semgrep", "rules": []}},
                      "results": results}]}


def _result(rule, uri, line, level="error", text=None):
    return {"ruleId": rule, "level": level,
            "message": {"text": text or rule},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": line}}}]}


class _ToolVerifyBase(unittest.TestCase):
    def _repo(self, results, floor=None, agent_findings=None):
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        os.makedirs(os.path.join(d, "src"))
        with open(os.path.join(d, "src", "app.py"), "w") as fh:
            fh.write("import os\nx = 1\ny = 2\nz = 3\npw = 'secret'\n")
        os.makedirs(driver._pano(d, "tools"))
        with open(driver._pano(d, "tools", "semgrep.sarif"), "w") as fh:
            json.dump(_semgrep_sarif(results), fh)
        driver._write_json(driver._pano(d, "tools-ran.json"),
                           {"ran": True, "run_id": RUN_ID})
        driver._write_json(driver._pano(d, "groups.json"),
                           {"groups": [{"name": "app", "files": ["src/app.py"]}]})
        driver._write_json(driver._pano(d, "coverage-app.json"),
                           {"group": "app", "floor": floor or [],
                            "effective": floor or [], "run_id": RUN_ID})
        if agent_findings:
            driver._write_json(driver._pano(d, "findings-app-SEC.json"), {
                "findings": agent_findings,
                "_panopticon": {"run_id": RUN_ID, "role": "domain_panel",
                                "domain": "SEC", "group": "app"}})
        return d

    def _manifest(self, **flags):
        f = {"fail_on": "high"}
        f.update(flags)
        return {"run_id": RUN_ID, "host": "claude", "security_mode": "standard",
                "flags": f}

    def _bundle(self):
        # verify_execute loads the ocrdb bundle for the (empty) cell rounds; the
        # tool round never touches it. Stub it out for speed/isolation.
        return mock.patch("scripts.driver.ocrdb.load_bundle",
                          return_value={"domains": {}})


class TestToolQueueParity(_ToolVerifyBase):
    """The crux: the driver's tool-finding queue_ids AND finding ids equal
    synthesize's for the same .panopticon/tools/ fixture."""

    def _report_tool_pairs(self, d, manifest):
        driver.synthesize_execute(d, manifest)
        report = driver._load_json(driver._pano(d, "report.json"))
        return {(f["fingerprint"], f["id"]) for f in report["findings"]
                if evidence.is_tool_sourced(f)}

    def test_queue_ids_and_ids_match_synthesize(self):
        d = self._repo([_result("r1", "src/app.py", 1),
                        _result("r2", "src/app.py", 9)])
        m = self._manifest()
        driver_pairs = {(qid, f["id"]) for qid, f in driver._tool_verify_queue(d, m)}
        self.assertTrue(driver_pairs)                       # non-empty
        # queue_id == exported fingerprint, and the finding id round-trips too.
        self.assertEqual(driver_pairs, self._report_tool_pairs(d, m))

    def test_parity_survives_agent_overlap_on_aggregate_group(self):
        # Two hits of ONE rule in ONE file form an aggregate group; an agent
        # finding at the SECOND hit's line makes aggregate_tool_findings keep the
        # SECOND hit as the survivor (agent-corroborated locus). A tool-only
        # pipeline (no agent findings) would keep the FIRST -> a different finding
        # id than synthesize -> its verdict would fail synthesize's finding_id
        # echo. The driver runs synthesize's full combined pipeline precisely so
        # this stays byte-identical.
        d = self._repo(
            [_result("r1", "src/app.py", 1), _result("r1", "src/app.py", 5)],
            agent_findings=[{"domain": "SEC", "code": "SEC-A1A", "severity": "LOW",
                             "title": "authz gap", "category": "authz",
                             "location": {"file": "src/app.py", "line_start": 5}}])
        m = self._manifest()
        queue = driver._tool_verify_queue(d, m)
        driver_pairs = {(qid, f["id"]) for qid, f in queue}
        # survivor is the SECOND hit (SG-002), NOT the first -- proves the
        # full-pipeline survivor selection.
        self.assertEqual({f["id"] for _q, f in queue}, {"SG-002"})
        self.assertEqual(driver_pairs, self._report_tool_pairs(d, m))

    def test_empty_queue_when_tools_did_not_run(self):
        d = self._repo([_result("r1", "src/app.py", 1)])
        driver._write_json(driver._pano(d, "tools-ran.json"),
                           {"ran": False, "run_id": RUN_ID})
        self.assertEqual(driver._tool_verify_queue(d, self._manifest()), [])


class TestToolVerifyDispatch(_ToolVerifyBase):
    def test_entry_is_return_persist_advisor(self):
        d = self._repo([_result("r1", "src/app.py", 1, level="note")])
        m = self._manifest()
        qid, _f = driver._tool_verify_queue(d, m)[0]
        with self._bundle():
            result = driver.verify_execute(d, m)
        self.assertEqual((result.checkpoint, result.group), ("verify", "tools"))
        entry = driver._load_json(driver._pano(d, "dispatch-request.json"))["entries"][0]
        self.assertEqual(entry["agent"], "panopticon-advisor")   # advisor.md shell
        self.assertTrue(entry["enforced"])
        self.assertEqual(entry["delivery"], "return_json")       # host persists
        self.assertEqual(os.path.basename(entry["out_file"]), "%s.json" % qid)
        self.assertEqual(os.path.dirname(entry["out_file"]),
                         os.path.abspath(driver._pano(d, "verdicts")))
        self.assertEqual(entry["out_file"], os.path.abspath(entry["out_file"]))
        self.assertIn("Repo root:", entry["prompt"])             # advisor root pin

    def test_generic_host_unenforced_entry(self):
        d = self._repo([_result("r1", "src/app.py", 1, level="note")])
        m = self._manifest()
        m["host"] = "generic"
        with self._bundle():
            driver.verify_execute(d, m)
        entry = driver._load_json(driver._pano(d, "dispatch-request.json"))["entries"][0]
        self.assertIsNone(entry["agent"])
        self.assertFalse(entry["enforced"])


class TestToolVerifyEndToEnd(_ToolVerifyBase):
    """The money test: without a verdict a tool finding forces INCONCLUSIVE
    (pre-fix behavior, now reachable only WITHOUT a verdict); with a CONFIRMED
    verdict from the driver's tool-advisor it reaches tool_confirmed and does NOT
    force INCONCLUSIVE."""

    def _persist(self, out_file, verdict, finding_id):
        with open(out_file, "w") as fh:
            json.dump({"finding_id": finding_id, "verdict": verdict,
                       "reasoning": "adjudicated"}, fh)

    def test_no_verdict_leaves_tool_finding_unanswered_inconclusive(self):
        d = self._repo([_result("r1", "src/app.py", 1, level="note")])
        m = self._manifest()
        with self._bundle():
            result = driver.verify_execute(d, m)
            self.assertEqual(result.checkpoint, "verify")
            self.assertFalse(driver.verify_done(d, m))          # verdict owed
        driver.synthesize_execute(d, m)
        report = driver._load_json(driver._pano(d, "report.json"))
        self.assertEqual(report["summary"]["gate"], "INCONCLUSIVE")
        self.assertEqual(report["meta"]["coverage"]["verdicts"]["unanswered"], 1)

    def test_confirmed_verdict_reaches_tool_confirmed_no_inconclusive(self):
        d = self._repo([_result("r1", "src/app.py", 1, level="note")])
        m = self._manifest()
        qid, finding = driver._tool_verify_queue(d, m)[0]
        with self._bundle():
            driver.verify_execute(d, m)
        entry = driver._load_json(driver._pano(d, "dispatch-request.json"))["entries"][0]
        # simulate the host persisting the advisor's RETURNED verdict JSON
        self._persist(entry["out_file"], "CONFIRMED", finding["id"])
        with self._bundle():
            self.assertTrue(driver.verify_done(d, m))
            self.assertEqual(driver.verify_execute(d, m).kind, "advanced")
        driver.synthesize_execute(d, m)
        report = driver._load_json(driver._pano(d, "report.json"))
        tf = next(f for f in report["findings"] if evidence.is_tool_sourced(f))
        self.assertEqual(tf["evidence"]["status"], "tool_confirmed")
        self.assertNotEqual(report["summary"]["gate"], "INCONCLUSIVE")
        self.assertEqual(report["meta"]["coverage"]["verdicts"]["unanswered"], 0)
        self.assertEqual(report["meta"]["coverage"]["tool_axis"]["confirmed"], 1)
        self.assertEqual(qid + ".json", os.path.basename(entry["out_file"]))


class TestToolVerifyResume(_ToolVerifyBase):
    def test_existing_verdict_not_redispatched_and_verify_done_waits(self):
        d = self._repo([_result("r1", "src/app.py", 1, level="note"),
                        _result("r2", "app/db.py", 2, level="note")])
        m = self._manifest()
        queue = driver._tool_verify_queue(d, m)
        self.assertEqual(len(queue), 2)
        self.assertFalse(driver.verify_done(d, m))              # both owed

        # answer exactly one
        qid0, f0 = queue[0]
        os.makedirs(driver._pano(d, "verdicts"), exist_ok=True)
        with open(driver._tool_verdict_out_file(d, qid0), "w") as fh:
            json.dump({"finding_id": f0["id"], "verdict": "REJECTED",
                       "reasoning": "not reachable"}, fh)
        self.assertFalse(driver.verify_done(d, m))              # one still owed

        # re-dispatch names ONLY the still-undone entry
        with self._bundle():
            result = driver.verify_execute(d, m)
        self.assertEqual(result.checkpoint, "verify")
        outs = [os.path.basename(e["out_file"]) for e in
                driver._load_json(driver._pano(d, "dispatch-request.json"))["entries"]]
        self.assertEqual(outs, ["%s.json" % queue[1][0]])
        self.assertNotIn("%s.json" % qid0, outs)

        # answer the second -> verify phase drains
        qid1, f1 = queue[1]
        with open(driver._tool_verdict_out_file(d, qid1), "w") as fh:
            json.dump({"finding_id": f1["id"], "verdict": "CONFIRMED",
                       "reasoning": "reachable"}, fh)
        self.assertTrue(driver.verify_done(d, m))
        with self._bundle():
            self.assertEqual(driver.verify_execute(d, m).kind, "advanced")

    def test_garbled_verdict_is_not_done(self):
        d = self._repo([_result("r1", "src/app.py", 1, level="note")])
        m = self._manifest()
        qid, _f = driver._tool_verify_queue(d, m)[0]
        os.makedirs(driver._pano(d, "verdicts"), exist_ok=True)
        with open(driver._tool_verdict_out_file(d, qid), "w") as fh:
            fh.write("{ not valid json")
        self.assertFalse(driver._tool_verdict_done(d, qid))
        self.assertFalse(driver.verify_done(d, m))


class TestSynthesizeFixtureParityWiring(_ToolVerifyBase):
    """synthesize_execute must ingest the SAME tool set the tool-verify queue
    does -- so it forwards --include-fixtures exactly when _tool_verify_queue
    keeps fixtures."""

    def _cmd_for(self, manifest):
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            with open(cmd[cmd.index("--out") + 1], "w") as fh:
                json.dump({"findings": []}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")
        d = self._repo([_result("r1", "src/app.py", 1)])
        with mock.patch("scripts.driver.subprocess.run", side_effect=fake_run):
            driver.synthesize_execute(d, manifest)
        return captured["cmd"]

    def test_redteam_forwards_include_fixtures(self):
        m = self._manifest()
        m["security_mode"] = "redteam"
        self.assertIn("--include-fixtures", self._cmd_for(m))

    def test_flag_forwards_include_fixtures(self):
        m = self._manifest()
        m["flags"]["include_fixtures"] = True
        self.assertIn("--include-fixtures", self._cmd_for(m))

    def test_standard_omits_include_fixtures(self):
        self.assertNotIn("--include-fixtures", self._cmd_for(self._manifest()))


if __name__ == "__main__":
    unittest.main()
