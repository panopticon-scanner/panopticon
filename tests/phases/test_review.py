"""Tests for scripts.phases.review: matrix-cell fan-out and cell artifacts.
"""
import os
import tempfile
import unittest
from unittest import mock

from scripts import hosts
from conftest import write_host_evidence
import scripts.phases.runio as runio
import scripts.phases.review as review
import scripts.phases.requests as requests

import scripts.ocrdb as ocrdb
import scripts.model_resolver as model_resolver


class TestCellFanOut(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        os.makedirs(runio._pano(self.root))
        self.addCleanup(self._t.cleanup)
        self.manifest = {"run_id": "R", "security_mode": "standard", "host": "claude"}
        # #1344 F3: review_execute's driver-plan write gates on PROVEN evidence
        # now, not the bare claim -- prove everything claude claims so this
        # claude-host fixture keeps exercising the enforced/guarded path it
        # was written for.
        write_host_evidence(self.root, {c: hosts.PROVEN for c in hosts.CAPABILITIES})
        runio._write_json(runio._pano(self.root, "groups.json"),
                           {"groups": [{"name": "Auth", "files": ["a.py"]}]})
        with open(runio._pano(self.root, "groups.yml"), "w") as fh:
            fh.write("groups:\n  Auth:\n    match: ['a.py']\n")   # #1092 healthy resume
        runio._write_json(runio._pano(self.root, "coverage-Auth.json"),
                           {"group": "Auth", "effective": ["SEC", "DAT"], "run_id": "R"})

    def _menu_stub(self):
        return mock.patch("scripts.ocrdb.domain_menu",
                          return_value=[{"code": "SEC-A1A", "name": "x", "severity": "HIGH", "cwe": []}])

    def test_review_emits_cell_entries_per_effective_domain(self):
        with self._menu_stub(), \
             mock.patch("scripts.dispatch.render_prompt", return_value="BODY"), \
             mock.patch("scripts.dispatch.registered_agent_name",
                        return_value="panopticon-domain-panel"), \
             mock.patch("scripts.ocrdb.load_bundle", return_value={"domains": {}}):
            result = review.review_execute(self.root, self.manifest)
        self.assertEqual(result.kind, "checkpoint")
        self.assertEqual(result.checkpoint, "review")
        req = runio._load_json(runio._pano(self.root, "dispatch-request.json"))
        outs = sorted(e["out_file"].split("/")[-1] for e in req["entries"])
        self.assertEqual(outs, ["findings-Auth-DAT.json", "findings-Auth-SEC.json"])
        for e in req["entries"]:
            self.assertEqual(e["out_file"], os.path.abspath(e["out_file"]))
            self.assertNotIn("delivery", e)   # host-agnostic

    def test_cell_entries_bind_the_resolved_model(self):
        with self._menu_stub(), \
             mock.patch("scripts.dispatch.render_prompt", return_value="BODY"), \
             mock.patch("scripts.dispatch.registered_agent_name",
                        return_value="panopticon-domain-panel"), \
             mock.patch("scripts.ocrdb.load_bundle", return_value={"domains": {}}), \
             mock.patch.object(model_resolver, "resolve_model",
                               return_value={"model": "SENTINEL-PANEL"}) as rm:
            review.review_execute(self.root, self.manifest)
        req = runio._load_json(runio._pano(self.root, "dispatch-request.json"))
        for e in req["entries"]:
            with self.subTest(entry=e["id"]):
                self.assertEqual("SENTINEL-PANEL", e["model"])
        rm.assert_any_call(self.manifest.get("host", "claude"), "domain_panel")

    def test_review_done_requires_all_cells(self):
        self.assertFalse(review.review_done(self.root, self.manifest))
        for dom in ("SEC", "DAT"):
            runio._write_json(runio._pano(self.root, "findings-Auth-%s.json" % dom),
                               {"findings": [], "_panopticon": {"run_id": "R",
                                "role": "domain_panel", "domain": dom, "group": "Auth"}})
        self.assertTrue(review.review_done(self.root, self.manifest))

    def test_stale_run_id_cell_is_not_done(self):
        runio._write_json(runio._pano(self.root, "findings-Auth-SEC.json"),
                           {"findings": [], "_panopticon": {"run_id": "OLD",
                            "role": "domain_panel", "domain": "SEC", "group": "Auth"}})
        self.assertFalse(review.review_done(self.root, self.manifest))

    def test_cell_prompt_names_the_out_file(self):
        # a real render (no render_prompt mock): the dispatched reviewer must be
        # TOLD where to write, or its findings file never appears and the cell
        # never completes.
        entry = review._cell_entry(self.root, self.manifest, "Auth", "SEC",
                                    ["a.py"], [], "claude", ocrdb.load_bundle())
        self.assertIn(entry["out_file"], entry["prompt"])

    def _run_review_with_guard(self, guard):
        write_host_evidence(self.root, {hosts.TOOL_POLICY_ENFORCED: hosts.PROVEN,
                                        hosts.ARTIFACT_WRITE_GUARD: guard})
        # require_unenforced_ack (#1519) runs on every review_execute call,
        # independent of delivery -- a REFUTED guard with no override would
        # refuse the whole checkpoint before a single cell entry is built,
        # which is a DIFFERENT test (test_unenforced_ack.py). Accepting the
        # risk here isolates the thing THIS test is about: the shape of the
        # entry the bridge produces once dispatch is allowed to proceed.
        manifest = dict(self.manifest, flags={"allow_unenforced": True})
        with self._menu_stub(), \
             mock.patch("scripts.dispatch.render_prompt", return_value="BODY"), \
             mock.patch("scripts.dispatch.registered_agent_name",
                        return_value="panopticon-domain-panel"), \
             mock.patch("scripts.ocrdb.load_bundle", return_value={"domains": {}}):
            review.review_execute(self.root, manifest)
        return runio._load_json(runio._pano(self.root, "dispatch-request.json"))["entries"]

    def test_an_enforced_cell_with_no_write_guard_is_return_persist(self):
        # enforced stays True (the shell exists); delivery flips (nothing
        # confines its Write). Both facts on one entry -- an all-refuted or
        # all-proven fixture cannot show this.
        for e in self._run_review_with_guard(hosts.REFUTED):
            with self.subTest(entry=e["id"]):
                self.assertTrue(e["enforced"])
                self.assertEqual("return_json", e["delivery"])
                self.assertTrue(e["prompt"].startswith(
                    requests.entry_marker(e["id"])
                    + requests.RETURN_PERSIST_PREAMBLE % {"out_file": e["out_file"]}))

    def test_a_guarded_cell_self_writes_with_no_preamble(self):
        for e in self._run_review_with_guard(hosts.PROVEN):
            with self.subTest(entry=e["id"]):
                self.assertNotIn("delivery", e)
                self.assertNotIn("DELIVERY: return-persist", e["prompt"])

    def test_every_cell_entry_carries_marker_and_scope(self):
        entries = self._run_review_with_guard(hosts.PROVEN)
        self.assertTrue(entries)
        for e in entries:
            with self.subTest(entry=e["id"]):
                self.assertEqual(requests.entry_marker(e["id"]).rstrip("\n"), e["marker"])
                self.assertTrue(e["prompt"].startswith(e["marker"] + "\n"))
                # `reads` is the prompt's own pointer set -- the SEC checklist
                # (Claude family PR; test_the_sec_cell_may_read_the_checklist_
                # its_prompt_points_at covers the grant) plus the prompt file
                # that write_dispatch_request stamps and grants on every entry.
                self.assertEqual(requests.scope(files=e["files"],
                                                reads=review._cell_reads(e["domain"]) + [e["prompt_file"]]),
                                 e["scope"])
                self.assertTrue(e["scope"]["files"])
                self.assertTrue(all(os.path.isabs(p) for p in e["scope"]["files"]))

    def test_the_sec_cell_may_read_the_checklist_its_prompt_points_at(self):
        # Surfaced by the Claude family PR's first real headless run: the SEC
        # prompt hands the reviewer an absolute checklist path
        # (_render_security_checklist) and the read guard denied it -- the
        # scope granted the cell's files and nothing else, so the pointer was a
        # dead end. The grant and the pointer now share one spelling, and a
        # non-SEC cell is granted nothing extra.
        bundle = ocrdb.load_bundle()
        with self._menu_stub():
            sec = review._cell_entry(self.root, self.manifest, "Auth", "SEC", ["a.py"], [], "claude", bundle)
            dat = review._cell_entry(self.root, self.manifest, "Auth", "DAT", ["a.py"], [], "claude", bundle)
        path = review._security_checklist_path()
        self.assertTrue(os.path.isfile(path), path)
        self.assertEqual([path], sec["scope"]["reads"])
        self.assertIn("Read `%s`" % path, sec["prompt"])
        self.assertEqual([], dat["scope"]["reads"])
        self.assertNotIn("security-checklists", dat["prompt"])

    def test_cell_entries_carry_their_scope_as_absolute_paths(self):
        # spec 7.2: machine-readable, exactly as out_file is for the write
        # guard. Same resolution the prose list uses, so the two cannot name
        # different trees.
        with self._menu_stub(), \
             mock.patch("scripts.dispatch.render_prompt", return_value="BODY"), \
             mock.patch("scripts.dispatch.registered_agent_name",
                        return_value="panopticon-domain-panel"), \
             mock.patch("scripts.ocrdb.load_bundle", return_value={"domains": {}}):
            review.review_execute(self.root, self.manifest)
        req = runio._load_json(runio._pano(self.root, "dispatch-request.json"))
        expected = [os.path.abspath(os.path.join(self.root, "a.py"))]
        for e in req["entries"]:
            with self.subTest(entry=e["id"]):
                self.assertEqual(expected, e["files"])
                for f in e["files"]:
                    self.assertTrue(f.startswith(os.path.abspath(self.root) + os.sep))


class TestPanelsRecordWhetherTheySawScannerEvidence(unittest.TestCase):
    """#1637 P08 ruling 5: a panel that reviewed with no tool output on disk
    is a materially weaker review, and until now the report said nothing about
    it. Each dispatch entry records the fact as it renders the prompt, and the
    run keeps a durable per-cell tally so a resume cannot lose the batches it
    already dispatched."""

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        os.makedirs(runio._pano(self.root))
        self.addCleanup(self._t.cleanup)
        self.manifest = {"run_id": "R", "security_mode": "standard", "host": "claude"}
        write_host_evidence(self.root, {c: hosts.PROVEN for c in hosts.CAPABILITIES})
        runio._write_json(runio._pano(self.root, "groups.json"),
                          {"groups": [{"name": "Auth", "files": ["a.py"]}]})
        with open(runio._pano(self.root, "groups.yml"), "w") as fh:
            fh.write("groups:\n  Auth:\n    match: ['a.py']\n")
        runio._write_json(runio._pano(self.root, "coverage-Auth.json"),
                          {"group": "Auth", "effective": ["SEC"], "run_id": "R"})

    def _dispatch(self):
        with mock.patch("scripts.ocrdb.domain_menu", return_value=[]), \
             mock.patch("scripts.dispatch.render_prompt", return_value="BODY"), \
             mock.patch("scripts.dispatch.registered_agent_name",
                        return_value="panopticon-domain-panel"), \
             mock.patch("scripts.ocrdb.load_bundle", return_value={"domains": {}}):
            review.review_execute(self.root, self.manifest)
        return runio._load_json(runio._pano(self.root, "dispatch-request.json"))

    def _marker(self, ran):
        runio._write_json(runio._pano(self.root, "tools-ran.json"),
                          {"schema_version": 1, "ran": ran, "skipped": not ran,
                           "crashed": False, "note": "", "returncode": 0,
                           "run_id": "R"})

    def test_an_entry_records_that_no_tool_output_existed(self):
        req = self._dispatch()
        self.assertEqual([e["tools_context"] for e in req["entries"]], [False])

    def test_an_entry_records_tool_output_that_did_exist(self):
        self._marker(True)
        req = self._dispatch()
        self.assertEqual([e["tools_context"] for e in req["entries"]], [True])

    def test_a_skipped_scan_is_not_scanner_context(self):
        self._marker(False)
        req = self._dispatch()
        self.assertEqual([e["tools_context"] for e in req["entries"]], [False])

    def test_the_tally_is_durable_across_batches(self):
        self._dispatch()                       # dispatched without evidence
        self._marker(True)
        runio._write_json(runio._pano(self.root, "coverage-Auth.json"),
                          {"group": "Auth", "effective": ["SEC", "DAT"],
                           "run_id": "R"})
        self._dispatch()                       # second cell, with evidence
        cells = runio._load_json(
            runio._pano(self.root, "panel-tools-context.json"))["cells"]
        self.assertEqual(cells, {"Auth/SEC": True, "Auth/DAT": True})


class TestTestInventoryNote(unittest.TestCase):
    """#1638 P13: the cell's `Tests:` inventory comes from the CLAIMING
    group's `tests:` axis, and a reviewer's reads are confined to its own
    cell -- so an empty inventory is indistinguishable, from inside the cell,
    from a repository with no tests. Run-13 published the wrong one of those
    two readings. The driver knows which it is (it assigned every file to a
    group), so it says so on the prompt instead of leaving the reviewer to
    guess.

    Three states, computed from the run's OWN assignment (groups.json) and
    the committed matrix `review_execute` already loads:

    * complete -- the group has a `tests:` inventory and nothing is missing;
    * empty    -- no test is assigned to it at all;
    * split    -- test files NAMED after this group's modules exist, and
                  another group claims them. This is run-13's case, and the
                  only one that can name where the tests went.
    """

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        os.makedirs(runio._pano(self.root))
        self.addCleanup(self._t.cleanup)
        self.manifest = {"run_id": "R", "security_mode": "standard",
                         "host": "claude"}
        write_host_evidence(self.root, {c: hosts.PROVEN for c in hosts.CAPABILITIES})
        # `Code` owns src/a.py; its test lives in `Other`, exactly the
        # matrix defect P06 described and P13 is the visible consequence of.
        runio._write_json(runio._pano(self.root, "groups.json"),
                          {"groups": [
                              {"name": "Code", "files": ["src/a.py"]},
                              {"name": "Other", "files": ["tests/test_a.py"]},
                              {"name": "Lonely", "files": ["src/z.py"]}]})
        with open(runio._pano(self.root, "groups.yml"), "w") as fh:
            fh.write("groups:\n"
                     "  Code:\n    match: ['src/a.py']\n"
                     "  Other:\n    match: ['other/**']\n"
                     "    tests: ['tests/**']\n"
                     "  Lonely:\n    match: ['src/z.py']\n")
        for g in ("Code", "Other", "Lonely"):
            runio._write_json(runio._pano(self.root, "coverage-%s.json" % g),
                              {"group": g, "effective": ["TST"], "run_id": "R"})

    def _prompts(self):
        review.review_execute(self.root, self.manifest)
        req = runio._load_json(runio._pano(self.root, "dispatch-request.json"))
        return {e["group"]: e for e in req["entries"]}

    def test_a_group_whose_tests_another_group_claims_is_split(self):
        entry = self._prompts()["Code"]
        self.assertEqual("split", entry["inventory_note"])
        self.assertIn("Inventory: split", entry["prompt"])
        self.assertIn("Other", entry["prompt"])
        self.assertIn("tests/test_a.py", entry["prompt"])

    def test_a_group_with_its_own_tests_is_complete(self):
        entry = self._prompts()["Other"]
        self.assertEqual("complete", entry["inventory_note"])
        self.assertIn("Inventory: complete", entry["prompt"])

    def test_a_group_with_no_tests_anywhere_is_empty(self):
        entry = self._prompts()["Lonely"]
        self.assertEqual("empty", entry["inventory_note"])
        self.assertIn("Inventory: empty", entry["prompt"])

    def test_a_test_the_other_group_owns_the_module_for_is_not_split(self):
        # `dispatch.py` in one group and `workflows/dispatch.js` in another:
        # `tests/test_dispatch.py` belongs to whoever owns the module it is
        # named after, and must not flag the other as split. Basename matching
        # is what makes this cheap; this is the filter that keeps it usable.
        runio._write_json(runio._pano(self.root, "groups.json"),
                          {"groups": [
                              {"name": "Code", "files": ["src/a.py"]},
                              {"name": "Other", "files": ["other/a.py",
                                                          "tests/test_a.py"]}]})
        self.assertEqual("empty", self._prompts()["Code"]["inventory_note"])

    def test_the_split_line_caps_the_paths_it_names(self):
        many = ["tests/test_m%d.py" % i for i in range(9)]
        runio._write_json(runio._pano(self.root, "groups.json"),
                          {"groups": [
                              {"name": "Code",
                               "files": ["src/m%d.py" % i for i in range(9)]},
                              {"name": "Other", "files": many}]})
        prompt = self._prompts()["Code"]["prompt"]
        self.assertIn("9 test file(s)", prompt)
        self.assertIn("(and 4 more)", prompt)
        self.assertNotIn("tests/test_m8.py", prompt)

    def test_the_state_is_persisted_per_group_for_synthesis(self):
        self._prompts()
        body = runio._load_json(
            runio._pano(self.root, "panel-test-inventory.json"))
        self.assertEqual({"Code": "split", "Other": "complete",
                          "Lonely": "empty"}, body["groups"])
