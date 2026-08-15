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
        with mock.patch("scripts.driver.dispatch.render_prompt", return_value="BODY"), \
             mock.patch("scripts.driver.dispatch.registered_agent_name",
                        return_value="panopticon-domain-advisor"), \
             mock.patch("scripts.driver.ocrdb.load_bundle", return_value={"domains": {}}):
            result = driver.verify_execute(self.root, self.manifest)
        self.assertEqual(result.checkpoint, "verify")
        req = driver._load_json(driver._pano(self.root, "dispatch-request.json"))
        outs = [os.path.basename(e["out_file"]) for e in req["entries"]]
        self.assertEqual(outs, ["verdicts-app-SEC.json"])          # only engaged
        e = req["entries"][0]
        self.assertEqual(e["write_mode"], "return")
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
        with mock.patch("scripts.driver.dispatch.render_prompt", return_value="BODY"), \
             mock.patch("scripts.driver.dispatch.registered_agent_name",
                        return_value="panopticon-domain-advisor"), \
             mock.patch("scripts.driver.ocrdb.load_bundle", return_value={"domains": {}}):
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


class TestPersistReturnedVerdict(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = os.path.join(self.tmp.name, ".panopticon", "verdicts",
                                "verdicts-app-SEC.json")
    def tearDown(self):
        self.tmp.cleanup()

    def _entry(self):
        return {"id": "verify-app-SEC-primary", "write_mode": "return",
                "out_file": self.out}

    def test_persists_valid_bundle(self):
        text = ('{"verdicts": [{"finding_id": "SEC-1", "verdict": "CONFIRMED"}], '
                '"_panopticon": {"run_id": "RID", "role": "domain_advisor", '
                '"domain": "SEC", "group": "app", "stage": "primary"}}')
        assert driver.persist_returned_verdict(self._entry(), text) is True
        with open(self.out) as fh:
            assert json.load(fh)["verdicts"][0]["finding_id"] == "SEC-1"

    def test_fenced_json_is_tolerated(self):
        text = "```json\n{\"verdicts\": []}\n```"
        assert driver.persist_returned_verdict(self._entry(), text) is True

    def test_malformed_return_persists_nothing(self):
        assert driver.persist_returned_verdict(self._entry(), "not json {") is False
        assert not os.path.exists(self.out)

    def test_non_bundle_rejected(self):
        assert driver.persist_returned_verdict(self._entry(),
                                               '{"verdict": "CONFIRMED"}') is False
