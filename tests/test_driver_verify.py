import json, os, tempfile, unittest
from unittest import mock
from conftest import write_host_evidence
from scripts import hosts
import scripts.phases.runio as runio
import scripts.phases.review as review
import scripts.phases.verify as verify
import scripts.phases.requests as requests
import scripts.model_resolver as model_resolver

def _manifest(root):
    return {"run_id": "RID", "host": "claude", "security_mode": "standard"}

def _write(root, name, obj):
    os.makedirs(os.path.join(root, ".panopticon"), exist_ok=True)
    with open(os.path.join(root, ".panopticon", name), "w") as fh:
        json.dump(obj, fh)

def _cell(root, group, domain, findings):
    _write(root, "findings-%s-%s.json" % (group, domain),
           {"findings": findings,
            "_panopticon": {"run_id": "RID", "role": "domain_panel",
                            "domain": domain, "group": group}})

class TestVerifyPrimary(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        self.manifest = _manifest(self.root)
        _write(self.root, "groups.json", {"groups": [{"name": "app", "files": ["a.py"]}]})
        _write(self.root, "coverage-app.json", {"effective": ["SEC", "QAL"]})
        # #1344 F4 (a): _verify_entry now derives `delivery` from the host's
        # PROVEN write guard, not an absent-evidence UNKNOWN -- prove it here
        # so this fixture keeps exercising the enforced/self-write path it was
        # written for. test_an_enforced_advisor_with_no_write_guard_is_return_persist
        # and test_a_guarded_advisor_self_writes_with_no_preamble below overwrite
        # this with the MIXED fixture to show the guard varying.
        write_host_evidence(self.root, {hosts.TOOL_POLICY_ENFORCED: hosts.PROVEN,
                                        hosts.ARTIFACT_WRITE_GUARD: hosts.PROVEN})
    def tearDown(self):
        self.tmp.cleanup()

    def test_engages_cell_at_or_above_fp_skips_below(self):
        # SEC: a HIGH -> score 5*conf*1 >= 1.5 -> engaged. QAL: a LOW -> 0 -> below.
        _cell(self.root, "app", "SEC", [{"domain": "SEC", "code": "SEC-A1A",
              "severity": "HIGH", "title": "t", "category": "x",
              "location": {"file": "a.py", "line_start": 1}}])
        _cell(self.root, "app", "QAL", [{"domain": "QAL", "code": "QAL-A1A",
              "severity": "LOW", "title": "t", "category": "x",
              "location": {"file": "a.py", "line_start": 2}}])
        with (
            mock.patch("scripts.dispatch.render_prompt", return_value="BODY"),
            mock.patch("scripts.dispatch.registered_agent_name",
                       return_value="panopticon-domain-advisor"),
            mock.patch("scripts.ocrdb.load_bundle", return_value={"domains": {}})
        ):
            result = verify.verify_execute(self.root, self.manifest)
        self.assertEqual(result.checkpoint, "verify")
        req = runio._load_json(runio._pano(self.root, "dispatch-request.json"))
        outs = [os.path.basename(e["out_file"]) for e in req["entries"]]
        self.assertEqual(outs, ["verdicts-app-SEC.json"])          # only engaged
        e = req["entries"][0]
        self.assertNotIn("write_mode", e)
        self.assertTrue(e["out_file"].endswith(".json"))
        self.assertEqual(e["out_file"], os.path.abspath(e["out_file"]))
        self.assertNotIn("delivery", e)                            # host-agnostic

    def test_an_enforced_advisor_with_no_write_guard_is_return_persist(self):
        # enforced stays True (the shell exists); delivery flips (nothing
        # confines its Write). Both facts on one entry -- an all-refuted or
        # all-proven fixture cannot show this.
        write_host_evidence(self.root, {hosts.TOOL_POLICY_ENFORCED: hosts.PROVEN,
                                        hosts.ARTIFACT_WRITE_GUARD: hosts.REFUTED})
        _cell(self.root, "app", "SEC", [{"domain": "SEC", "code": "SEC-A1A",
              "severity": "HIGH", "title": "t", "category": "x",
              "location": {"file": "a.py", "line_start": 1}}])
        with (
            mock.patch("scripts.dispatch.render_prompt", return_value="BODY"),
            mock.patch("scripts.dispatch.registered_agent_name",
                       return_value="panopticon-domain-advisor"),
            mock.patch("scripts.ocrdb.load_bundle", return_value={"domains": {}})
        ):
            verify.verify_execute(self.root, self.manifest)
        req = runio._load_json(runio._pano(self.root, "dispatch-request.json"))
        outs = [os.path.basename(e["out_file"]) for e in req["entries"]]
        self.assertEqual(outs, ["verdicts-app-SEC.json"])          # only engaged
        e = req["entries"][0]
        self.assertTrue(e["enforced"])
        self.assertEqual("return_json", e["delivery"])
        self.assertTrue(e["prompt"].startswith(
            requests.RETURN_PERSIST_PREAMBLE % {"out_file": e["out_file"]}))

    def test_a_guarded_advisor_self_writes_with_no_preamble(self):
        # setUp already proves ARTIFACT_WRITE_GUARD -- restated for clarity.
        write_host_evidence(self.root, {hosts.TOOL_POLICY_ENFORCED: hosts.PROVEN,
                                        hosts.ARTIFACT_WRITE_GUARD: hosts.PROVEN})
        _cell(self.root, "app", "SEC", [{"domain": "SEC", "code": "SEC-A1A",
              "severity": "HIGH", "title": "t", "category": "x",
              "location": {"file": "a.py", "line_start": 1}}])
        with (
            mock.patch("scripts.dispatch.render_prompt", return_value="BODY"),
            mock.patch("scripts.dispatch.registered_agent_name",
                       return_value="panopticon-domain-advisor"),
            mock.patch("scripts.ocrdb.load_bundle", return_value={"domains": {}})
        ):
            verify.verify_execute(self.root, self.manifest)
        req = runio._load_json(runio._pano(self.root, "dispatch-request.json"))
        outs = [os.path.basename(e["out_file"]) for e in req["entries"]]
        self.assertEqual(outs, ["verdicts-app-SEC.json"])          # only engaged
        e = req["entries"][0]
        self.assertNotIn("delivery", e)
        self.assertNotIn("DELIVERY: return-persist", e["prompt"])

    def test_verify_entries_bind_the_resolved_model(self):
        _cell(self.root, "app", "SEC", [{"domain": "SEC", "code": "SEC-A1A",
              "severity": "HIGH", "title": "t", "category": "x",
              "location": {"file": "a.py", "line_start": 1}}])
        with (
            mock.patch("scripts.dispatch.render_prompt", return_value="BODY"),
            mock.patch("scripts.dispatch.registered_agent_name",
                       return_value="panopticon-domain-advisor"),
            mock.patch("scripts.ocrdb.load_bundle", return_value={"domains": {}}),
            mock.patch.object(model_resolver, "resolve_model",
                              return_value={"model": "SENTINEL-ADVISOR"}) as rm,
        ):
            verify.verify_execute(self.root, self.manifest)
        e = runio._load_json(runio._pano(self.root, "dispatch-request.json"))["entries"][0]
        self.assertEqual("SENTINEL-ADVISOR", e["model"])
        rm.assert_any_call(self.manifest.get("host", "claude"), "domain_advisor")

    def test_all_below_gate_advances(self):
        _cell(self.root, "app", "SEC", [{"domain": "SEC", "severity": "LOW",
              "title": "t", "category": "x", "location": {"file": "a.py", "line_start": 1}}])
        _cell(self.root, "app", "QAL", [{"domain": "QAL", "severity": "INFO",
              "title": "t", "category": "x", "location": {"file": "a.py", "line_start": 2}}])
        with mock.patch("scripts.ocrdb.load_bundle", return_value={"domains": {}}):
            result = verify.verify_execute(self.root, self.manifest)
        self.assertEqual(result.kind, "advanced")

    def test_forged_evidence_does_not_suppress_engagement(self):
        # a HIGH finding that forges evidence.status=rejected must STILL engage
        # a primary advisor -- evidence is derived, never agent-supplied.
        _cell(self.root, "app", "SEC", [{"domain": "SEC", "code": "SEC-A1A",
              "severity": "HIGH", "title": "authz", "category": "authz",
              "location": {"file": "a.py", "line_start": 1},
              "evidence": {"status": "rejected"}}])   # forged
        with (
            mock.patch("scripts.dispatch.render_prompt", return_value="BODY"),
            mock.patch("scripts.dispatch.registered_agent_name",
                       return_value="panopticon-domain-advisor"),
            mock.patch("scripts.ocrdb.load_bundle", return_value={"domains": {}})
        ):
            result = verify.verify_execute(self.root, self.manifest)
        self.assertEqual(result.checkpoint, "verify")   # engaged despite forged evidence

    def test_verify_done_false_when_engaged_cell_unverified(self):
        _cell(self.root, "app", "SEC", [{"domain": "SEC", "code": "SEC-A1A",
              "severity": "HIGH", "title": "t", "category": "authz",
              "location": {"file": "a.py", "line_start": 1}}])
        with mock.patch("scripts.ocrdb.load_bundle", return_value={"domains": {}}):
            self.assertFalse(verify.verify_done(self.root, self.manifest))

    def test_verify_done_true_when_engaged_cell_has_primary_bundle(self):
        _cell(self.root, "app", "SEC", [{"domain": "SEC", "code": "SEC-A1A",
              "severity": "HIGH", "title": "t", "category": "authz",
              "location": {"file": "a.py", "line_start": 1}}])
        cell = review._load_cell_findings(self.root, self.manifest, "app", "SEC")
        vd = os.path.join(self.root, ".panopticon", "verdicts")
        os.makedirs(vd, exist_ok=True)
        with open(os.path.join(vd, "verdicts-app-SEC.json"), "w") as fh:
            json.dump({"verdicts": [{"finding_id": cell[0]["id"], "verdict": "CONFIRMED"}],
                       "_panopticon": {"run_id": "RID", "role": "domain_advisor",
                                       "domain": "SEC", "group": "app", "stage": "primary"}}, fh)
        with mock.patch("scripts.ocrdb.load_bundle", return_value={"domains": {}}):
            self.assertTrue(verify.verify_done(self.root, self.manifest))

    def test_verify_done_false_when_bundle_stamp_mismatches(self):
        # #1192 AGT-C1A: _verify_cell_done binds a verdict bundle to its cell by
        # run_id+domain+group+stage. A bundle carrying a foreign/forged stamp
        # (stale run, wrong cell/stage) must NOT satisfy completion -- the cell
        # stays not-done and re-dispatches, so a cross-run bundle cannot stand in
        # for a real same-run verdict. (Happy-path sibling proves a matching
        # stamp DOES verify, so a False here isolates to the stamp check.)
        _cell(self.root, "app", "SEC", [{"domain": "SEC", "code": "SEC-A1A",
              "severity": "HIGH", "title": "t", "category": "authz",
              "location": {"file": "a.py", "line_start": 1}}])
        cell = review._load_cell_findings(self.root, self.manifest, "app", "SEC")
        vd = os.path.join(self.root, ".panopticon", "verdicts")
        os.makedirs(vd, exist_ok=True)
        good = {"run_id": "RID", "role": "domain_advisor",
                "domain": "SEC", "group": "app", "stage": "primary"}
        for bad in ({**good, "run_id": "STALE"},   # foreign run
                    {**good, "domain": "QAL"},      # wrong domain
                    {**good, "group": "other"},     # wrong group
                    {**good, "stage": "backup"}):   # wrong stage
            with open(os.path.join(vd, "verdicts-app-SEC.json"), "w") as fh:
                json.dump({"verdicts": [{"finding_id": cell[0]["id"],
                                         "verdict": "CONFIRMED"}],
                           "_panopticon": bad}, fh)
            with mock.patch("scripts.ocrdb.load_bundle",
                            return_value={"domains": {}}):
                self.assertFalse(
                    verify.verify_done(self.root, self.manifest),
                    "bundle with mismatched stamp %r must not verify" % bad)

    # --- A2 (run-9): 1:1 finding<->verdict reconciliation, bounded re-dispatch ---
    def _two_finding_cell(self):
        _cell(self.root, "app", "SEC", [
            {"domain": "SEC", "code": "SEC-A1A", "severity": "HIGH", "title": "one",
             "category": "authz", "location": {"file": "a.py", "line_start": 1}},
            {"domain": "SEC", "code": "SEC-B1A", "severity": "HIGH", "title": "two",
             "category": "output", "location": {"file": "b.py", "line_start": 2}}])
        return review._load_cell_findings(self.root, self.manifest, "app", "SEC")

    def _write_primary_bundle(self, fids):
        vd = os.path.join(self.root, ".panopticon", "verdicts")
        os.makedirs(vd, exist_ok=True)
        with open(os.path.join(vd, "verdicts-app-SEC.json"), "w") as fh:
            json.dump({"verdicts": [{"finding_id": f, "verdict": "CONFIRMED"} for f in fids],
                       "_panopticon": {"run_id": "RID", "role": "domain_advisor",
                                       "domain": "SEC", "group": "app", "stage": "primary"}}, fh)

    def test_incomplete_primary_bundle_reconciles_not_done(self):
        # A2: a labeled, parseable bundle that adjudicated only 1 of 2 findings is
        # NOT done -- the dropped finding must re-dispatch, not slip through as a
        # silent verdicts.unanswered:1 that sinks certification (the run-9 cause).
        cell = self._two_finding_cell()
        self._write_primary_bundle([cell[0]["id"]])                    # 1 of 2
        self.assertFalse(verify._verify_cell_done(
            self.root, self.manifest, "app", "SEC", "primary"))
        self._write_primary_bundle([cell[0]["id"], cell[1]["id"]])     # both -> done
        self.assertTrue(verify._verify_cell_done(
            self.root, self.manifest, "app", "SEC", "primary"))

    def test_extra_unknown_verdict_does_not_block_done(self):
        # A phantom extra verdict (surfaces as unknown at synthesis) must not force
        # re-dispatch as long as every finding IS covered.
        cell = self._two_finding_cell()
        self._write_primary_bundle([cell[0]["id"], cell[1]["id"], "phantom"])
        self.assertTrue(verify._verify_cell_done(
            self.root, self.manifest, "app", "SEC", "primary"))

    def test_incomplete_bundle_accepted_after_max_attempts(self):
        # Bounded: once the re-dispatch budget is spent, an incomplete bundle is
        # accepted so the run PROCEEDS and the gap surfaces as unanswered ->
        # INCONCLUSIVE, rather than wedging forever on a systematic re-coder.
        cell = self._two_finding_cell()
        self._write_primary_bundle([cell[0]["id"]])                    # stays incomplete
        for _ in range(verify._MAX_VERIFY_ATTEMPTS):
            self.assertFalse(verify._verify_cell_done(
                self.root, self.manifest, "app", "SEC", "primary"))
            verify._bump_verify_attempts(self.root, "app", "SEC", "primary")
        self.assertTrue(verify._verify_cell_done(                      # budget spent
            self.root, self.manifest, "app", "SEC", "primary"))

    def test_execute_charges_an_attempt_only_on_redispatch(self):
        # The bump counts a RE-dispatch (a labeled-but-incomplete bundle already on
        # disk), never the first dispatch (no bundle yet).
        cell = self._two_finding_cell()
        with (
            mock.patch("scripts.dispatch.render_prompt", return_value="B"),
            mock.patch("scripts.dispatch.registered_agent_name",
                       return_value="panopticon-domain-advisor"),
            mock.patch("scripts.ocrdb.load_bundle", return_value={"domains": {}}),
        ):
            verify.verify_execute(self.root, self.manifest)            # first dispatch
            self.assertEqual(verify._verify_attempts(self.root, "app", "SEC", "primary"), 0)
            self._write_primary_bundle([cell[0]["id"]])               # incomplete return
            verify.verify_execute(self.root, self.manifest)           # re-dispatch
            self.assertEqual(verify._verify_attempts(self.root, "app", "SEC", "primary"), 1)


class TestVerifyBackup(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = self.tmp.name
        self.manifest = _manifest(self.root)
        _write(self.root, "groups.json", {"groups": [{"name": "app", "files": ["a.py"]}]})
        _write(self.root, "coverage-app.json", {"effective": ["SEC"]})
        # a confirmed CRITICAL clears F_b (20*0.8*1.5 = 24 >= 8)
        _cell(self.root, "app", "SEC", [{"domain": "SEC", "code": "SEC-A1A",
              "severity": "CRITICAL", "title": "t", "category": "authz",
              "location": {"file": "a.py", "line_start": 1}}])
    def tearDown(self):
        self.tmp.cleanup()

    def _primary_confirm(self, fid):
        os.makedirs(os.path.join(self.root, ".panopticon", "verdicts"), exist_ok=True)
        with open(os.path.join(self.root, ".panopticon", "verdicts",
                               "verdicts-app-SEC.json"), "w") as fh:
            json.dump({"verdicts": [{"finding_id": fid, "verdict": "CONFIRMED"}],
                       "_panopticon": {"run_id": "RID", "role": "domain_advisor",
                                       "domain": "SEC", "group": "app",
                                       "stage": "primary"}}, fh)

    def test_backup_summoned_after_primary_confirm(self):
        cell = review._load_cell_findings(self.root, self.manifest, "app", "SEC")
        self._primary_confirm(cell[0]["id"])
        with (
            mock.patch("scripts.dispatch.render_prompt", return_value="BODY"),
            mock.patch("scripts.dispatch.registered_agent_name",
                       return_value="panopticon-domain-advisor"),
            mock.patch("scripts.ocrdb.load_bundle", return_value={"domains": {}})
        ):
            result = verify.verify_execute(self.root, self.manifest)
        self.assertEqual(result.checkpoint, "verify")
        e = runio._load_json(runio._pano(self.root, "dispatch-request.json"))["entries"][0]
        self.assertTrue(e["out_file"].endswith("verdicts-app-SEC-backup.json"))
        self.assertNotIn("write_mode", e)

    def test_backup_round_batches_all_groups_in_one_checkpoint(self):
        # #20: the backup round must batch every pending backup cell across ALL
        # groups into one checkpoint (group=None), like review + verify-primary --
        # not one round trip per group (run-7: 19 backup groups serialized).
        root = self.root
        _write(root, "groups.json", {"groups": [{"name": "app", "files": ["a.py"]},
                                                 {"name": "api", "files": ["b.py"]}]})
        _write(root, "coverage-api.json", {"effective": ["SEC"]})
        _cell(root, "api", "SEC", [{"domain": "SEC", "code": "SEC-A1A",
              "severity": "CRITICAL", "title": "t", "category": "authz",
              "location": {"file": "b.py", "line_start": 1}}])
        # primary CONFIRMED for BOTH cells so the primary round is complete and
        # verify_execute proceeds to the (batched) backup round.
        os.makedirs(os.path.join(root, ".panopticon", "verdicts"), exist_ok=True)
        for g in ("app", "api"):
            cell = review._load_cell_findings(root, self.manifest, g, "SEC")
            with open(os.path.join(root, ".panopticon", "verdicts",
                                   "verdicts-%s-SEC.json" % g), "w") as fh:
                json.dump({"verdicts": [{"finding_id": cell[0]["id"],
                                         "verdict": "CONFIRMED"}],
                           "_panopticon": {"run_id": "RID", "role": "domain_advisor",
                                           "domain": "SEC", "group": g,
                                           "stage": "primary"}}, fh)
        with (
            mock.patch("scripts.dispatch.render_prompt", return_value="BODY"),
            mock.patch("scripts.dispatch.registered_agent_name",
                       return_value="panopticon-domain-advisor"),
            mock.patch("scripts.ocrdb.load_bundle", return_value={"domains": {}})
        ):
            result = verify.verify_execute(root, self.manifest)
        self.assertEqual(result.checkpoint, "verify")
        self.assertIsNone(result.group)                 # batched, not per-group
        entries = runio._load_json(runio._pano(root, "dispatch-request.json"))["entries"]
        self.assertTrue(all(e["out_file"].endswith("-backup.json") for e in entries))
        groups = {os.path.basename(e["out_file"]).split("-")[1] for e in entries}
        self.assertEqual(groups, {"app", "api"})        # both groups, ONE checkpoint

    def test_rejected_category_never_summons_backup(self):
        cell = review._load_cell_findings(self.root, self.manifest, "app", "SEC")
        os.makedirs(os.path.join(self.root, ".panopticon", "verdicts"), exist_ok=True)
        with open(os.path.join(self.root, ".panopticon", "verdicts",
                               "verdicts-app-SEC.json"), "w") as fh:
            json.dump({"verdicts": [{"finding_id": cell[0]["id"], "verdict": "REJECTED"}],
                       "_panopticon": {"run_id": "RID", "role": "domain_advisor",
                                       "domain": "SEC", "group": "app",
                                       "stage": "primary"}}, fh)
        with mock.patch("scripts.ocrdb.load_bundle", return_value={"domains": {}}):
            result = verify.verify_execute(self.root, self.manifest)
        self.assertEqual(result.kind, "advanced")     # nothing to back up

    def test_confirmed_high_alone_below_fb_no_backup(self):
        _cell(self.root, "app", "SEC", [{"domain": "SEC", "code": "SEC-A1A",
              "severity": "HIGH", "title": "t", "category": "authz",
              "location": {"file": "a.py", "line_start": 1}}])
        cell = review._load_cell_findings(self.root, self.manifest, "app", "SEC")
        self._primary_confirm(cell[0]["id"])   # or inline-write the CONFIRMED primary bundle
        with mock.patch("scripts.ocrdb.load_bundle", return_value={"domains": {}}):
            result = verify.verify_execute(self.root, self.manifest)
        self.assertEqual(result.kind, "advanced")   # HIGH alone below F_b -> no backup round

    def test_verify_done_gates_on_backup_round(self):
        # setUp already writes a CRITICAL cell (clears F_b); if your setUp differs, write one here
        cell = review._load_cell_findings(self.root, self.manifest, "app", "SEC")
        self._primary_confirm(cell[0]["id"])       # primary CONFIRMED bundle only
        with mock.patch("scripts.ocrdb.load_bundle", return_value={"domains": {}}):
            self.assertFalse(verify.verify_done(self.root, self.manifest))   # backup owed
        # now write the -backup bundle
        vd = os.path.join(self.root, ".panopticon", "verdicts")
        with open(os.path.join(vd, "verdicts-app-SEC-backup.json"), "w") as fh:
            json.dump({"verdicts": [{"finding_id": cell[0]["id"], "verdict": "CONFIRMED"}],
                       "_panopticon": {"run_id": self.manifest["run_id"], "role": "domain_advisor",
                                       "domain": "SEC", "group": "app", "stage": "backup"}}, fh)
        with mock.patch("scripts.ocrdb.load_bundle", return_value={"domains": {}}):
            self.assertTrue(verify.verify_done(self.root, self.manifest))


class TestOversizedCellIsChunked(unittest.TestCase):
    """#1521: an oversized cell must reach the advisor as SEVERAL bounded
    dispatches, not one unbounded prompt -- and not as a truncated one, since
    _verify_cell_done demands a verdict for every claim."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        self.manifest = _manifest(self.root)
        _write(self.root, "groups.json",
               {"groups": [{"name": "app", "files": ["a.py"]}]})
        _write(self.root, "coverage-app.json", {"effective": ["SEC"]})
        self.addCleanup(self.tmp.cleanup)

    def _dispatch(self, n):
        _cell(self.root, "app", "SEC",
              [{"domain": "SEC", "code": "SEC-A1A", "severity": "HIGH",
                "title": "t%d" % i, "category": "x",
                "location": {"file": "a.py", "line_start": i + 1}}
               for i in range(n)])
        with (
            mock.patch("scripts.dispatch.render_prompt", return_value="BODY"),
            mock.patch("scripts.dispatch.registered_agent_name",
                       return_value="panopticon-domain-advisor"),
            mock.patch("scripts.ocrdb.load_bundle", return_value={"domains": {}})
        ):
            verify.verify_execute(self.root, self.manifest)
        with open(runio._pano(self.root, "dispatch-request.json"),
                  encoding="utf-8") as fh:
            return json.load(fh)["entries"]

    def test_a_small_cell_still_dispatches_exactly_one_advisor(self):
        self.assertEqual(len(self._dispatch(3)), 1)

    def test_an_oversized_cell_dispatches_one_advisor_per_chunk(self):
        entries = self._dispatch(verify._CELL_CLAIMS_CAP * 2 + 1)
        self.assertEqual(len(entries), 3)

    def test_each_chunk_gets_a_distinct_id_and_out_file(self):
        # Colliding ids would collide their prompt files; colliding out_files
        # would have each advisor overwrite the last one's verdicts.
        entries = self._dispatch(verify._CELL_CLAIMS_CAP * 2 + 1)
        self.assertEqual(len({e["id"] for e in entries}), len(entries))
        self.assertEqual(len({e["out_file"] for e in entries}), len(entries))

    def test_the_first_chunk_keeps_the_established_out_file(self):
        entries = self._dispatch(verify._CELL_CLAIMS_CAP * 2 + 1)
        self.assertTrue(entries[0]["out_file"].endswith("verdicts-app-SEC.json"))
