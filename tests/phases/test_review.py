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
                    requests.RETURN_PERSIST_PREAMBLE % {"out_file": e["out_file"]}))

    def test_a_guarded_cell_self_writes_with_no_preamble(self):
        for e in self._run_review_with_guard(hosts.PROVEN):
            with self.subTest(entry=e["id"]):
                self.assertNotIn("delivery", e)
                self.assertNotIn("DELIVERY: return-persist", e["prompt"])
