"""phases.persist: the ONLY place a return-persist reply becomes a file."""
import json
import os
import shutil
import tempfile
import unittest

import scripts.phases.persist as persist
import scripts.phases.verify as verify
import scripts.ocrdb as ocrdb


def _entry(out_file, delivery="return_json", **extra):
    e = {"id": extra.pop("id", "x"), "out_file": out_file}
    if delivery:
        e["delivery"] = delivery
    e.update(extra)
    return e


class TestRoleOf(unittest.TestCase):
    def test_roles_are_keyed_on_the_out_file_name(self):
        cases = {
            "/r/.panopticon/runs/t/scout-app.json": "scout",
            "/r/.panopticon/setup-proposal.json": "setup-scan",
            "/r/.panopticon/runs/t/findings-app-SEC.json": "review-cell",
            "/r/.panopticon/runs/t/verdicts/verdicts-app-SEC.json": "verify-cell",
            "/r/.panopticon/runs/t/verdicts/verdicts-app-SEC-backup-part1.json": "verify-cell",
            "/r/.panopticon/runs/t/verdicts/q-0001.json": "tool-advisor",
            "/r/.panopticon/runs/t/report.json": None,
        }
        self.assertTrue(cases)
        for out_file, role in cases.items():
            with self.subTest(out_file=out_file):
                self.assertEqual(role, persist.role_of(_entry(out_file)))
        self.assertEqual(sorted(set(cases.values()) - {None}), sorted(persist.ROLES))


class TestWriteReply(unittest.TestCase):
    def setUp(self):
        self.d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.d, ignore_errors=True))
        os.makedirs(os.path.join(self.d, ".panopticon", "runs", "t", "verdicts"))

    def _out(self, *parts):
        return os.path.join(self.d, ".panopticon", "runs", "t", *parts)

    def test_fence_wrapped_scout_reply_is_accepted_and_written_as_clean_json(self):
        e = _entry(self._out("scout-app.json"), id="scout-app")
        ok, reason = persist.write_reply(e, "Here you go:\n```json\n"
                                         + json.dumps({"domains": ["SEC"], "files": [], "tools": []})
                                         + "\n```\n")
        self.assertTrue(ok, reason)
        with open(e["out_file"], encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["domains"], ["SEC"])   # strict json: fence gone
        self.assertFalse(os.path.exists(e["out_file"] + ".tmp"))

    def test_a_non_return_persist_entry_is_refused(self):
        e = _entry(self._out("findings-app-SEC.json"), delivery=None)
        ok, reason = persist.write_reply(e, "{}")
        self.assertFalse(ok)
        self.assertIn("return_json", reason)
        self.assertFalse(os.path.exists(e["out_file"]))

    def test_an_already_done_entry_is_refused(self):
        e = _entry(self._out("scout-app.json"))
        persist.write_reply(e, json.dumps({"domains": [], "files": [], "tools": []}))
        ok, reason = persist.write_reply(e, json.dumps({"domains": ["X"]}))
        self.assertFalse(ok)
        self.assertIn("already", reason)

    def test_an_unparseable_reply_writes_nothing(self):
        e = _entry(self._out("scout-app.json"))
        ok, reason = persist.write_reply(e, "sorry, I could not")
        self.assertFalse(ok)
        self.assertIn("parse", reason)
        self.assertFalse(os.path.exists(e["out_file"]))

    def test_a_scout_reply_failing_the_shape_check_is_refused_with_the_reason(self):
        e = _entry(self._out("scout-app.json"))
        ok, reason = persist.write_reply(e, json.dumps({"domains": [["SEC"]]}))
        self.assertFalse(ok)
        self.assertIn("domains", reason)
        self.assertFalse(os.path.exists(e["out_file"]))

    def test_a_review_cell_reply_must_carry_the_entry_stamp(self):
        e = _entry(self._out("findings-app-SEC.json"), run_id="RID", group="app", domain="SEC")
        body = {"findings": [], "_panopticon": {"run_id": "OTHER", "group": "app", "domain": "SEC"}}
        ok, reason = persist.write_reply(e, json.dumps(body))
        self.assertFalse(ok)
        self.assertIn("_panopticon", reason)
        body["_panopticon"]["run_id"] = "RID"
        ok, reason = persist.write_reply(e, json.dumps(body))
        self.assertTrue(ok, reason)

    def test_a_verify_cell_reply_needs_a_verdict_list_and_its_stamp(self):
        e = _entry(self._out("verdicts", "verdicts-app-SEC.json"),
                   run_id="RID", group="app", domain="SEC", stage="primary")
        ok, reason = persist.write_reply(e, json.dumps({"verdicts": "no"}))
        self.assertFalse(ok)
        ok, reason = persist.write_reply(e, json.dumps(
            {"verdicts": [], "_panopticon": {"run_id": "RID", "group": "app",
                                             "domain": "SEC", "stage": "primary"}}))
        self.assertTrue(ok, reason)

    def test_a_verify_cell_reply_with_a_wrong_stamp_is_refused_for_a_real_shaped_entry(self):
        # fix round 1: the entry comes from verify._verify_entry itself -- the
        # only builder of verify-cell entries -- not a hand-picked subset of
        # keys, so a regression in what that function stamps on the entry
        # fails HERE as well as in test_verify.py's own pin.
        manifest = {"run_id": "RID", "host": "claude",
                    "security_mode": "standard", "flags": {}}
        files = ["src/pay.py"]
        cell = [{"id": "F1", "code": "SEC-A1A", "severity": "HIGH",
                 "title": "t", "category": "SEC",
                 "location": {"file": files[0], "line": 1},
                 "description": "d"}]
        bundle = ocrdb.load_bundle()
        e = verify._verify_entry(self.d, manifest, "app", "SEC", files, cell,
                                 "claude", bundle, "primary")
        body = {"verdicts": [], "_panopticon": {"run_id": "OTHER", "group": "app",
                                                "domain": "SEC", "stage": "primary"}}
        ok, reason = persist.write_reply(e, json.dumps(body))
        self.assertFalse(ok)
        self.assertIn("_panopticon", reason)
        body["_panopticon"]["run_id"] = "RID"
        ok, reason = persist.write_reply(e, json.dumps(body))
        self.assertTrue(ok, reason)

    def test_a_tool_advisor_reply_needs_a_valid_verdict_value(self):
        e = _entry(self._out("verdicts", "q-0001.json"))
        ok, _ = persist.write_reply(e, json.dumps({"verdict": "MAYBE"}))
        self.assertFalse(ok)
        ok, reason = persist.write_reply(e, json.dumps({"verdict": "confirmed"}))
        self.assertTrue(ok, reason)

    def test_an_unknown_out_file_family_is_refused(self):
        e = _entry(self._out("report.json"))
        ok, reason = persist.write_reply(e, "{}")
        self.assertFalse(ok)
        self.assertIn("role", reason)

    def test_the_write_is_confined_to_the_artifact_tree(self):
        e = _entry(os.path.join(self.d, "elsewhere.json"))
        ok, reason = persist.write_reply(e, "{}")
        self.assertFalse(ok)
        self.assertFalse(os.path.exists(e["out_file"]))
