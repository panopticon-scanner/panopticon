import json, os, tempfile, unittest
from unittest import mock
import scripts.driver as driver

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
            mock.patch("scripts.driver.dispatch.render_prompt", return_value="BODY"),
            mock.patch("scripts.driver.dispatch.registered_agent_name",
                       return_value="panopticon-domain-advisor"),
            mock.patch("scripts.driver.ocrdb.load_bundle", return_value={"domains": {}})
        ):
            result = driver.verify_execute(self.root, self.manifest)
        self.assertEqual(result.checkpoint, "verify")
        req = driver._load_json(driver._pano(self.root, "dispatch-request.json"))
        outs = [os.path.basename(e["out_file"]) for e in req["entries"]]
        self.assertEqual(outs, ["verdicts-app-SEC.json"])          # only engaged
        e = req["entries"][0]
        self.assertNotIn("write_mode", e)
        self.assertTrue(e["out_file"].endswith(".json"))
        self.assertEqual(e["out_file"], os.path.abspath(e["out_file"]))
        self.assertNotIn("delivery", e)                            # host-agnostic

    def test_all_below_gate_advances(self):
        _cell(self.root, "app", "SEC", [{"domain": "SEC", "severity": "LOW",
              "title": "t", "category": "x", "location": {"file": "a.py", "line_start": 1}}])
        _cell(self.root, "app", "QAL", [{"domain": "QAL", "severity": "INFO",
              "title": "t", "category": "x", "location": {"file": "a.py", "line_start": 2}}])
        with mock.patch("scripts.driver.ocrdb.load_bundle", return_value={"domains": {}}):
            result = driver.verify_execute(self.root, self.manifest)
        self.assertEqual(result.kind, "advanced")

    def test_forged_evidence_does_not_suppress_engagement(self):
        # a HIGH finding that forges evidence.status=rejected must STILL engage
        # a primary advisor -- evidence is derived, never agent-supplied.
        _cell(self.root, "app", "SEC", [{"domain": "SEC", "code": "SEC-A1A",
              "severity": "HIGH", "title": "authz", "category": "authz",
              "location": {"file": "a.py", "line_start": 1},
              "evidence": {"status": "rejected"}}])   # forged
        with (
            mock.patch("scripts.driver.dispatch.render_prompt", return_value="BODY"),
            mock.patch("scripts.driver.dispatch.registered_agent_name",
                       return_value="panopticon-domain-advisor"),
            mock.patch("scripts.driver.ocrdb.load_bundle", return_value={"domains": {}})
        ):
            result = driver.verify_execute(self.root, self.manifest)
        self.assertEqual(result.checkpoint, "verify")   # engaged despite forged evidence

    def test_verify_done_false_when_engaged_cell_unverified(self):
        _cell(self.root, "app", "SEC", [{"domain": "SEC", "code": "SEC-A1A",
              "severity": "HIGH", "title": "t", "category": "authz",
              "location": {"file": "a.py", "line_start": 1}}])
        with mock.patch("scripts.driver.ocrdb.load_bundle", return_value={"domains": {}}):
            self.assertFalse(driver.verify_done(self.root, self.manifest))

    def test_verify_done_true_when_engaged_cell_has_primary_bundle(self):
        _cell(self.root, "app", "SEC", [{"domain": "SEC", "code": "SEC-A1A",
              "severity": "HIGH", "title": "t", "category": "authz",
              "location": {"file": "a.py", "line_start": 1}}])
        cell = driver._load_cell_findings(self.root, self.manifest, "app", "SEC")
        vd = os.path.join(self.root, ".panopticon", "verdicts")
        os.makedirs(vd, exist_ok=True)
        with open(os.path.join(vd, "verdicts-app-SEC.json"), "w") as fh:
            json.dump({"verdicts": [{"finding_id": cell[0]["id"], "verdict": "CONFIRMED"}],
                       "_panopticon": {"run_id": "RID", "role": "domain_advisor",
                                       "domain": "SEC", "group": "app", "stage": "primary"}}, fh)
        with mock.patch("scripts.driver.ocrdb.load_bundle", return_value={"domains": {}}):
            self.assertTrue(driver.verify_done(self.root, self.manifest))


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
        cell = driver._load_cell_findings(self.root, self.manifest, "app", "SEC")
        self._primary_confirm(cell[0]["id"])
        with (
            mock.patch("scripts.driver.dispatch.render_prompt", return_value="BODY"),
            mock.patch("scripts.driver.dispatch.registered_agent_name",
                       return_value="panopticon-domain-advisor"),
            mock.patch("scripts.driver.ocrdb.load_bundle", return_value={"domains": {}})
        ):
            result = driver.verify_execute(self.root, self.manifest)
        self.assertEqual(result.checkpoint, "verify")
        e = driver._load_json(driver._pano(self.root, "dispatch-request.json"))["entries"][0]
        self.assertTrue(e["out_file"].endswith("verdicts-app-SEC-backup.json"))
        self.assertNotIn("write_mode", e)

    def test_rejected_category_never_summons_backup(self):
        cell = driver._load_cell_findings(self.root, self.manifest, "app", "SEC")
        os.makedirs(os.path.join(self.root, ".panopticon", "verdicts"), exist_ok=True)
        with open(os.path.join(self.root, ".panopticon", "verdicts",
                               "verdicts-app-SEC.json"), "w") as fh:
            json.dump({"verdicts": [{"finding_id": cell[0]["id"], "verdict": "REJECTED"}],
                       "_panopticon": {"run_id": "RID", "role": "domain_advisor",
                                       "domain": "SEC", "group": "app",
                                       "stage": "primary"}}, fh)
        with mock.patch("scripts.driver.ocrdb.load_bundle", return_value={"domains": {}}):
            result = driver.verify_execute(self.root, self.manifest)
        self.assertEqual(result.kind, "advanced")     # nothing to back up

    def test_confirmed_high_alone_below_fb_no_backup(self):
        _cell(self.root, "app", "SEC", [{"domain": "SEC", "code": "SEC-A1A",
              "severity": "HIGH", "title": "t", "category": "authz",
              "location": {"file": "a.py", "line_start": 1}}])
        cell = driver._load_cell_findings(self.root, self.manifest, "app", "SEC")
        self._primary_confirm(cell[0]["id"])   # or inline-write the CONFIRMED primary bundle
        with mock.patch("scripts.driver.ocrdb.load_bundle", return_value={"domains": {}}):
            result = driver.verify_execute(self.root, self.manifest)
        self.assertEqual(result.kind, "advanced")   # HIGH alone below F_b -> no backup round

    def test_verify_done_gates_on_backup_round(self):
        # setUp already writes a CRITICAL cell (clears F_b); if your setUp differs, write one here
        cell = driver._load_cell_findings(self.root, self.manifest, "app", "SEC")
        self._primary_confirm(cell[0]["id"])       # primary CONFIRMED bundle only
        with mock.patch("scripts.driver.ocrdb.load_bundle", return_value={"domains": {}}):
            self.assertFalse(driver.verify_done(self.root, self.manifest))   # backup owed
        # now write the -backup bundle
        vd = os.path.join(self.root, ".panopticon", "verdicts")
        with open(os.path.join(vd, "verdicts-app-SEC-backup.json"), "w") as fh:
            json.dump({"verdicts": [{"finding_id": cell[0]["id"], "verdict": "CONFIRMED"}],
                       "_panopticon": {"run_id": self.manifest["run_id"], "role": "domain_advisor",
                                       "domain": "SEC", "group": "app", "stage": "backup"}}, fh)
        with mock.patch("scripts.driver.ocrdb.load_bundle", return_value={"domains": {}}):
            self.assertTrue(driver.verify_done(self.root, self.manifest))
