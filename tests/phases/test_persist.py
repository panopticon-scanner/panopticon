"""phases.persist: the ONLY place a return-persist reply becomes a file."""
import json
import os
import shutil
import tempfile
import unittest

import scripts.phases.persist as persist
import scripts.phases.review as review
import scripts.phases.runio as runio
import scripts.phases.verify as verify
import scripts.ocrdb as ocrdb


def _entry(out_file, delivery="return_json", **extra):
    e = {"id": extra.pop("id", "x"), "out_file": out_file}
    if delivery:
        e["delivery"] = delivery
    e.update(extra)
    return e


def _verify_cell(review_root, findings=2):
    """A production-shaped primary verify-cell entry, WITH its review cell on
    disk -- the state `verify_execute` actually dispatches in (review_done
    gates the verify phase, so the findings file always exists by then).

    Returns the entry, the claim ids the advisor was handed, and a verdict-list
    builder, so a test can hand `write_reply` a bundle that adjudicates any
    subset of them.
    """
    manifest = {"run_id": "RID", "host": "claude",
                "security_mode": "standard", "flags": {}}
    files = ["src/pay.py"]
    raw = [{"id": "F%d" % i, "code": "SEC-A1A", "severity": "HIGH",
            "title": "t%d" % i, "category": "SEC",
            "location": {"file": files[0], "line": i},
            "description": "d%d" % i} for i in range(1, findings + 1)]
    runio._write_json(runio._pano(review_root, "findings-app-SEC.json"),
                      {"findings": raw,
                       "_panopticon": {"run_id": "RID", "group": "app", "domain": "SEC"}})
    cell = review._load_cell_findings(review_root, manifest, "app", "SEC")
    entry = verify._verify_entry(review_root, manifest, "app", "SEC", files, cell,
                                 "claude", ocrdb.load_bundle(), "primary")
    return {"entry": entry, "cell": cell, "ids": [f["id"] for f in cell],
            "verdicts": lambda ids: [{"finding_id": i, "verdict": "CONFIRMED",
                                      "reasoning": "r"} for i in ids]}


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
        env = _verify_cell(self.d)
        body = {"verdicts": [], "_panopticon": {"run_id": "OTHER", "group": "app",
                                                "domain": "SEC", "stage": "primary"}}
        ok, reason = persist.write_reply(env["entry"], json.dumps(body))
        self.assertFalse(ok)
        self.assertIn("_panopticon", reason)
        body["_panopticon"]["run_id"] = "RID"
        body["verdicts"] = env["verdicts"](env["ids"])
        ok, reason = persist.write_reply(env["entry"], json.dumps(body))
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


class TestVerifyCellCompleteness(unittest.TestCase):
    """I3 (final review): persist's verify-cell acceptance is the verify
    PHASE's own done predicate (`verify._verify_cell_done`), not the looser
    "a `verdicts` list carrying the right stamp".

    A2 (run-9) is the reason the phase asks more: an advisor RE-CODED a cell's
    findings and returned 9 verdicts for 10 claims, and a bundle accepted on
    shape alone left two claims silently unadjudicated. persist inherited the
    laxity, so `orchestrate._pending` dropped a cell the engine still wanted
    -- `run_batch([])`, zero launches, while each `driver.run` spent one of
    the cell's three re-dispatch attempts on nothing at all.
    """

    def setUp(self):
        self.d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.d, ignore_errors=True))
        self.env = _verify_cell(self.d, findings=2)

    def _reply(self, ids):
        return json.dumps({"verdicts": self.env["verdicts"](ids),
                           "_panopticon": {"run_id": "RID", "group": "app",
                                           "domain": "SEC", "stage": "primary"}})

    def test_a_bundle_that_leaves_a_dispatched_claim_unadjudicated_is_refused(self):
        entry = self.env["entry"]
        for ids in ([], self.env["ids"][:1]):
            ok, reason = persist.write_reply(entry, self._reply(ids))
            self.assertFalse(ok, "accepted a bundle covering %d of 2 claims" % len(ids))
            self.assertIn("adjudicate", reason)
            self.assertFalse(os.path.exists(entry["out_file"]))

    def test_a_complete_bundle_is_accepted_and_reads_back_done(self):
        entry = self.env["entry"]
        self.assertFalse(persist.is_done(entry))
        ok, reason = persist.write_reply(entry, self._reply(self.env["ids"]))
        self.assertTrue(ok, reason)
        self.assertTrue(persist.is_done(entry))

    def test_a_short_bundle_on_disk_does_not_read_back_done(self):
        # the SELF-WRITE path: the advisor wrote the bundle itself, under the
        # write guard, so `write_reply` never saw it. `is_done` is the only
        # thing standing between a short bundle and a dropped re-dispatch.
        entry = self.env["entry"]
        runio._write_json(entry["out_file"],
                          {"verdicts": self.env["verdicts"](self.env["ids"][:1]),
                           "_panopticon": {"run_id": "RID", "group": "app",
                                           "domain": "SEC", "stage": "primary"}})
        self.assertFalse(persist.is_done(entry))
