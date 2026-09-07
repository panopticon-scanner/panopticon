"""Tests for scripts.phases.requests: dispatch-request.json, the driver plan and the
prompt file lists every checkpoint emits.
"""
import json
import os
import tempfile
import unittest

import scripts.phases.runio as runio
import scripts.phases.requests as requests
import scripts.phases.coverage as coverage
import scripts.phases.review as review
import scripts.phases.verify as verify

import scripts.ocrdb as ocrdb


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
