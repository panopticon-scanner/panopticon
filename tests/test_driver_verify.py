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
