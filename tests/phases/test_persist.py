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


class TestRetainRejected(unittest.TestCase):
    """D10 ruling 1: a refused reply is EVIDENCE, not litter.

    Run-13: 7 of 8 failed attempts were replies missing `_panopticon`, and
    `write_reply` refused each one writing nothing at all -- so the reply text
    was gone, every rerun started from scratch, and nobody could see what the
    agent had actually returned. The record under `runs/<tag>/rejected/` keeps
    it, redacted, with the reason; ruling 2 reads it back into the retry.
    """

    def setUp(self):
        self.d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.d, ignore_errors=True))
        self.run_dir = os.path.join(self.d, ".panopticon", "runs", "t")
        os.makedirs(self.run_dir)
        self.entry = _entry(os.path.join(self.run_dir, "findings-app-SEC.json"),
                            id="review-app-SEC", run_id="RID", group="app", domain="SEC")

    def _record(self, attempt):
        with open(os.path.join(self.run_dir, "rejected",
                               "review-app-SEC-%d.json" % attempt), encoding="utf-8") as fh:
            return json.load(fh)

    def test_a_refused_reply_is_kept_redacted_with_its_reason(self):
        secret = "ghp_" + "A" * 36
        path = persist.retain_rejected(self.run_dir, self.entry,
                                       '{"findings": [], "token": "%s"}' % secret,
                                       "reply carries no _panopticon stamp")
        self.assertEqual(path, os.path.join(self.run_dir, "rejected", "review-app-SEC-1.json"))
        rec = self._record(1)
        self.assertEqual(rec["schema_version"], 1)
        self.assertEqual(rec["entry_id"], "review-app-SEC")
        self.assertEqual(rec["attempt"], 1)
        self.assertIn("_panopticon", rec["reason"])
        self.assertTrue(rec["recorded_at"].endswith("Z"), rec["recorded_at"])
        self.assertNotIn(secret, rec["reply"])
        self.assertIn("[REDACTED_TOKEN]", rec["reply"])
        self.assertNotIn("truncated", rec)

    def test_the_second_refusal_of_one_entry_is_a_second_record(self):
        persist.retain_rejected(self.run_dir, self.entry, "first", "no")
        persist.retain_rejected(self.run_dir, self.entry, "second", "still no")
        self.assertEqual(1, self._record(1)["attempt"])
        self.assertEqual("second", self._record(2)["reply"])
        self.assertEqual(2, self._record(2)["attempt"])

    def test_an_oversized_reply_is_capped_and_says_so(self):
        persist.retain_rejected(self.run_dir, self.entry, "x" * (400 * 1024), "too big")
        rec = self._record(1)
        self.assertTrue(rec["truncated"])
        self.assertEqual(len(rec["reply"].encode("utf-8")), persist.REJECTED_CAP)

    def test_a_reply_with_nothing_in_it_is_not_a_record(self):
        self.assertIsNone(persist.retain_rejected(self.run_dir, self.entry, "", "empty"))
        self.assertFalse(os.path.exists(os.path.join(self.run_dir, "rejected")))

    def test_an_entry_id_can_never_steer_the_write_out_of_the_folder(self):
        entry = _entry(self.entry["out_file"], id="../../escape")
        path = persist.retain_rejected(self.run_dir, entry, "text", "no")
        self.assertEqual(os.path.dirname(path), os.path.join(self.run_dir, "rejected"))

    def test_nothing_under_rejected_is_a_persist_role(self):
        # "Nothing under `rejected/` is ever read by a done predicate": the
        # records sit in the run folder beside the artifacts, so the role map
        # -- which keys on the out_file NAME -- must not claim one.
        persist.retain_rejected(self.run_dir, self.entry, '{"findings": []}', "no")
        kept = os.path.join(self.run_dir, "rejected", "review-app-SEC-1.json")
        self.assertIsNone(persist.role_of(_entry(kept)))


class TestRoleSchema(unittest.TestCase):
    """D10 ruling 3: the published schema a role's reply is accepted against,
    for the CLIs that can constrain their output to one."""

    def test_each_returning_role_names_its_published_schema(self):
        cases = {
            "/r/.panopticon/runs/t/findings-app-SEC.json": "findings-envelope-schema.json",
            "/r/.panopticon/runs/t/verdicts/verdicts-app-SEC.json": "verdict-bundle-schema.json",
            "/r/.panopticon/runs/t/verdicts/q-0001.json": "advisor-verdict-schema.json",
        }
        for out_file, name in cases.items():
            with self.subTest(out_file=out_file):
                path = persist.role_schema(_entry(out_file))
                self.assertEqual(os.path.basename(path), name)
                self.assertEqual(path, os.path.abspath(path))
                self.assertTrue(os.path.isfile(path), path)
                self.assertEqual(os.path.basename(os.path.dirname(path)), "reference")

    def test_a_role_with_no_published_schema_names_none(self):
        # scout / setup-scan shapes live in code (coverage._scout_shape_errors,
        # "a JSON object"); there is no file to point a CLI at, and inventing
        # one would be a second definition of a shape the code already owns.
        for out_file in ("/r/.panopticon/runs/t/scout-app.json",
                         "/r/.panopticon/setup-proposal.json",
                         "/r/.panopticon/runs/t/report.json"):
            with self.subTest(out_file=out_file):
                self.assertIsNone(persist.role_schema(_entry(out_file)))
