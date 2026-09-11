"""Tests for scripts.phases.requests: dispatch-request.json, the driver plan and the
prompt file lists every checkpoint emits.
"""
import json
import os
import tempfile
import unittest
from unittest import mock

from scripts import hosts
from conftest import write_host_evidence
import scripts.phases.runio as runio
import scripts.phases.requests as requests
import scripts.phases.coverage as coverage
import scripts.phases.review as review
import scripts.phases.verify as verify

import scripts.ocrdb as ocrdb
import scripts.model_resolver as model_resolver


class TestWriteDispatchRequest(unittest.TestCase):
    def test_writes_host_agnostic_request(self):
        with tempfile.TemporaryDirectory() as root:
            entries = [{"id": "e1", "agent": "panopticon-scout", "enforced": True,
                        "model": None, "prompt": "…", "out_file": "/abs/scout-Auth.json"}]
            path = requests.write_dispatch_request(root, "RID", "scout", "Auth", entries)
            self.assertTrue(path.endswith(".panopticon/dispatch-request.json"))
            self.assertEqual(path, os.path.abspath(path))
            with open(path, encoding="utf-8") as fh:
                req = json.load(fh)
            self.assertEqual(req["checkpoint"], "scout")
            self.assertEqual(req["run_id"], "RID")
            self.assertEqual(req["group"], "Auth")
            self.assertEqual(req["entries"][0]["out_file"], "/abs/scout-Auth.json")
            # host-agnostic: no per-host delivery block
            self.assertNotIn("delivery", req["entries"][0])

    def test_unknown_checkpoint_kind_raises(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(ValueError):
                requests.write_dispatch_request(root, "RID", "bogus", "Auth", [])

class TestReviewerFileListsAreAbsolute(unittest.TestCase):
    """#975-class regression: the reviewer subagent inherits the HOST's cwd
    (the user's checkout), never the --pr worktree/review_root. A relative
    file list in the checkpoint prompt resolves against the wrong checkout —
    silent wrong-tree review. review_root here is deliberately NOT cwd (a
    dedicated tmp dir distinct from the test process's cwd), so a prompt that
    still carries a bare-relative entry would resolve to nothing/the wrong
    file under the old code, exactly like a real --pr run."""

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        os.makedirs(runio._pano(self.root))
        self.addCleanup(self._t.cleanup)
        self.manifest = {"run_id": "R", "security_mode": "standard", "host": "claude"}
        # #1344 F4 (a): _cell_entry/_verify_entry now derive `delivery` from
        # the host's proven write guard -- this class is about the #975 file
        # list/repo-root pin, not the bridge, so prove it PROVEN and keep
        # exercising the enforced/self-write path these tests were written for.
        write_host_evidence(self.root, {c: hosts.PROVEN for c in hosts.CAPABILITIES})
        self.assertNotEqual(self.root, os.path.realpath(os.getcwd()))
        self.files = ["src/checkout/pay.py"]
        self.abs_file = os.path.abspath(os.path.join(self.root, self.files[0]))
        self.cell = [{"id": "F1", "code": "SEC-A1A", "severity": "HIGH", "title": "t",
                      "category": "SEC", "location": {"file": self.files[0], "line": 1},
                      "description": "d"}]

    def _make_verify_entry(self):
        return verify._verify_entry(self.root, self.manifest, "Auth", "SEC",
                                    self.files, self.cell, "claude",
                                    ocrdb.load_bundle(), "primary")

    def _assert_absolute_not_relative(self, prompt):
        self.assertIn("- %s" % self.abs_file, prompt)
        # no bare-relative remnant: "- src/checkout/pay.py" is not a substring
        # of "- /tmp/.../src/checkout/pay.py" (the dash-space precedes the
        # absolute root, not "src"), so this is a real, precise negative.
        self.assertNotIn("- %s" % self.files[0], prompt)

    def test_scout_entry_file_list_is_absolute(self):
        entry = coverage._scout_entry(self.root, self.manifest, "Auth", self.files, "claude")
        self._assert_absolute_not_relative(entry["prompt"])

    def test_cell_entry_file_list_is_absolute(self):
        entry = review._cell_entry(self.root, self.manifest, "Auth", "SEC",
                                    self.files, [], "claude", ocrdb.load_bundle())
        self._assert_absolute_not_relative(entry["prompt"])

    def test_verify_entry_file_list_is_absolute(self):
        self._assert_absolute_not_relative(self._make_verify_entry()["prompt"])

    def test_verify_entry_prompt_carries_repo_root_header(self):
        # The advisor also adjudicates the findings JSON's `location` fields,
        # which stay repo-relative on disk (Part A can't reach into that
        # payload) -- so the prompt itself must tell the advisor the absolute
        # root those relative locations resolve against (mirrors the retired
        # dispatch.render_advisor_prompts' #975 "Repo root:" prepend).
        expected_header = "Repo root: %s" % os.path.abspath(self.root)
        # startswith is strictly stronger than assertIn (present AND at pos 0).
        self.assertTrue(self._make_verify_entry()["prompt"].startswith(expected_header))


class TestBoundModel(unittest.TestCase):
    """#1344 F4 (b): the entry's model comes from model_resolver, not a literal.

    One helper so five builders cannot resolve five ways. The value is the
    STRING model id, not resolve_model's whole config dict: docs/PANOPTICON.md
    defines entry["model"] as "the model named by entry['model'] (omit when
    null)". Kimi's max_context_size/alias extras are that family's PR to carry.
    """

    def test_returns_the_resolved_model_string(self):
        with mock.patch.object(model_resolver, "resolve_model",
                               return_value={"model": "SENTINEL", "alias": "x"}) as rm:
            self.assertEqual("SENTINEL", requests.bound_model("claude", "domain_panel"))
        rm.assert_called_once_with("claude", "domain_panel")

    def test_a_host_with_no_model_policy_binds_none(self):
        # gemini/generic: registry row, no profile table, no fallback table.
        # None means "inherit the session's model" and is what those hosts
        # dispatch with today -- unchanged by this plan (R-F4-1).
        for host in ("gemini", "generic"):
            with self.subTest(host=host):
                self.assertIsNone(requests.bound_model(host, "domain_panel"))

    def test_claude_binds_the_profile_model_not_the_session_default(self):
        # Oracle is resolve_model itself, not a literal: model-profiles.yml is
        # the owner of the value and this test must not become a second copy.
        expected = model_resolver.resolve_model("claude", "domain_panel")["model"]
        self.assertIsNotNone(expected, "fixture precondition: claude has a profile")
        self.assertEqual(expected, requests.bound_model("claude", "domain_panel"))


class TestDelivery(unittest.TestCase):
    """#1344 F4 (a): delivery is DERIVED from the role's Write grant and the
    host's proven write guard, in one place. It used to be a literal set at
    exactly one builder (the tool-advisor) while the two write-capable
    builders never set it -- so a host with no write guard got unguarded
    self-write.
    """

    def _evidence(self, guard):
        # MIXED, and specifically tool_policy PROVEN with the guard varying:
        # an enforced shell with no write guard is the case the bridge is for.
        return {hosts.TOOL_POLICY_ENFORCED: {"state": hosts.PROVEN, "by": "x", "detail": "x"},
                hosts.ARTIFACT_WRITE_GUARD: {"state": guard, "by": "x", "detail": "x"},
                hosts.USAGE_LEDGER: {"state": hosts.UNKNOWN, "by": None, "detail": "x"}}

    def test_a_write_role_on_a_guarded_host_self_writes(self):
        mode, prefix = requests.delivery("claude", self._evidence(hosts.PROVEN),
                                         "domain-panel.md", "/abs/out.json")
        self.assertIsNone(mode)
        self.assertEqual("", prefix)

    def test_a_write_role_on_an_unguarded_host_is_bridged_with_the_preamble(self):
        for guard in (hosts.REFUTED, hosts.UNKNOWN):
            with self.subTest(guard=guard):
                mode, prefix = requests.delivery("claude", self._evidence(guard),
                                                 "domain-panel.md", "/abs/out.json")
                self.assertEqual("return_json", mode)
                self.assertEqual(requests.RETURN_PERSIST_PREAMBLE
                                 % {"out_file": "/abs/out.json"}, prefix)

    def test_a_read_only_role_is_return_persist_with_no_preamble(self):
        # advisor.md grants no Write: there is nothing to override, so the
        # template's own "return" instruction stands and no preamble is added
        # -- on a guarded host AND an unguarded one.
        for guard in (hosts.PROVEN, hosts.REFUTED):
            with self.subTest(guard=guard):
                mode, prefix = requests.delivery("claude", self._evidence(guard),
                                                 "advisor.md", "/abs/v.json")
                self.assertEqual(("return_json", ""), (mode, prefix))

    def test_a_host_that_claims_no_guard_is_bridged(self):
        # gemini/generic: driver-selectable today, prove nothing. R-F4-4.
        for host in ("gemini", "generic"):
            with self.subTest(host=host):
                mode, _prefix = requests.delivery(host, {}, "domain-advisor.md", "/abs/o")
                self.assertEqual("return_json", mode)

    def test_the_preamble_names_the_out_file_and_forbids_the_write(self):
        prefix = requests.RETURN_PERSIST_PREAMBLE % {"out_file": "/abs/out.json"}
        self.assertIn("/abs/out.json", prefix)
        self.assertIn("do NOT write", prefix)
        self.assertIn("final message", prefix)
        self.assertTrue(prefix.endswith("\n\n"), "preamble must separate from the body")
