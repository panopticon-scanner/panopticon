"""Tests for scripts.phases.verify: cell, backup and tool verification.
"""
import json
import os
import tempfile
import unittest

import scripts.phases.runio as runio
import scripts.phases.requests as requests
import scripts.phases.review as review
import scripts.phases.verify as verify

import scripts.ocrdb as ocrdb


class TestVerifyCreatesDir(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        os.makedirs(runio._pano(self.root))
        self.addCleanup(self._t.cleanup)
        self.manifest = {"run_id": "R"}

    def test_verify_execute_creates_verdicts_dir(self):
        verify.verify_execute(self.root, self.manifest)
        self.assertTrue(os.path.isdir(runio._pano(self.root, "verdicts")))
        self.assertTrue(verify.verify_done(self.root, self.manifest))

class TestVerifyBackupNarrowing(unittest.TestCase):
    """#1029: the backup adversary re-reads only the files its scoped
    (advisor-confirmed, >= F_b) claims cite, not the whole cell -- a
    coverage-preserving cost cut (the advisor is claim-driven, reads unconfined)."""

    RUN_ID = "run-backup-narrow"

    def test_backup_scope_files_narrows_to_cited_files(self):
        scope = [{"location": {"file": "src/a.py", "line_start": 3}},
                 {"location": {"file": "src/b.py", "line_start": 9}}]
        self.assertEqual(
            verify._backup_scope_files("/repo", ["src/a.py", "src/b.py", "src/c.py"], scope),
            ["src/a.py", "src/b.py"])   # c.py (uncited) dropped

    def test_backup_scope_files_dedups_preserving_order(self):
        scope = [{"location": {"file": "src/a.py"}},
                 {"location": {"file": "src/a.py"}},
                 {"location": {"file": "src/b.py"}}]
        self.assertEqual(
            verify._backup_scope_files("/repo", ["src/a.py", "src/b.py"], scope),
            ["src/a.py", "src/b.py"])

    def test_backup_scope_files_falls_back_when_location_missing(self):
        # a scoped claim with no resolvable file -> the full group list; never
        # refute blind.
        full = ["src/a.py", "src/b.py", "src/c.py"]
        for bad in ({"location": {"file": ""}}, {"location": None}, {},
                    {"location": {}}):
            scope = [{"location": {"file": "src/a.py"}}, bad]
            self.assertEqual(verify._backup_scope_files("/repo", full, scope), full)

    def test_backup_scope_files_falls_back_on_escaping_claim_path(self):
        # #1096: an LLM/panel-supplied location.file that escapes review_root
        # (absolute or ../) must NOT reach the advisor's file list -- it forces
        # the safe full-group fallback, never an out-of-tree read.
        full = ["src/a.py", "src/b.py"]
        for evil in ("/etc/passwd", "../../../etc/shadow",
                     "src/../../outside.py"):
            scope = [{"location": {"file": "src/a.py"}},
                     {"location": {"file": evil}}]
            self.assertEqual(
                verify._backup_scope_files("/repo", full, scope), full, evil)
        # a confined relative path is still used verbatim
        self.assertEqual(
            verify._backup_scope_files(
                "/repo", full, [{"location": {"file": "src/a.py"}}]),
            ["src/a.py"])

    def test_confined_to_root_rejects_symlink_escape(self):
        # #run7 ARC-F2A: a committed in-tree symlink whose lexical path is inside
        # the tree but RESOLVES outside (src/evil -> /etc/passwd) passed the old
        # abspath check; realpath now catches it. A legit path -- including one not
        # yet written -- still confines.
        with tempfile.TemporaryDirectory() as outside, \
             tempfile.TemporaryDirectory() as root:
            root = os.path.realpath(root)
            secret = os.path.join(os.path.realpath(outside), "secret.txt")
            open(secret, "w").close()
            os.makedirs(os.path.join(root, "src"))
            os.symlink(secret, os.path.join(root, "src", "evil"))
            self.assertFalse(runio._confined_to_root(root, "src/evil"))    # escapes
            open(os.path.join(root, "src", "real.py"), "w").close()
            self.assertTrue(runio._confined_to_root(root, "src/real.py"))  # in-tree
            self.assertTrue(runio._confined_to_root(root, "src/new.py"))   # not-yet-written

    def test_confine_claim_location_redacts_escaping_file(self):
        # #run8 ARC-F2A: a claim location.file that escapes review_root is
        # neutralized before it reaches the unconfined advisor; in-tree paths and
        # other location fields pass through untouched.
        root = "/repo"
        esc = verify._confine_claim_location(
            root, {"file": "../../../.ssh/id_rsa", "line_start": 3})
        self.assertEqual(esc["file"], verify._REDACTED_CLAIM_PATH)
        self.assertEqual(esc["line_start"], 3)                 # siblings preserved
        keep = verify._confine_claim_location(root, {"file": "src/auth.py", "line_start": 9})
        self.assertEqual(keep["file"], "src/auth.py")
        self.assertIsNone(verify._confine_claim_location(root, None))   # no location
        self.assertEqual(verify._confine_claim_location(root, {}), {})  # no file key

    def test_render_findings_confines_location_in_claims(self):
        # #run8 ARC-F2A: the claims JSON handed to the domain-advisor must carry a
        # redacted location for an escaping path, in-tree ones verbatim.
        cell = [
            {"id": "A-001", "severity": "HIGH", "title": "x",
             "location": {"file": "../../etc/shadow", "line_start": 1}},
            {"id": "A-002", "severity": "LOW", "title": "y",
             "location": {"file": "app/db.py", "line_start": 5}},
        ]
        blob = json.loads(verify._render_findings("/repo", cell))
        self.assertEqual(blob[0]["location"]["file"], verify._REDACTED_CLAIM_PATH)
        self.assertEqual(blob[1]["location"]["file"], "app/db.py")

    def test_tool_verify_entry_confines_finding_location(self):
        # #run8 ARC-F2A: _tool_verify_entry embeds the whole tool finding into the
        # unconfined advisor's claim -- its location.file is confined too.
        finding = {"id": "T-1", "severity": "HIGH",
                   "location": {"file": "../../../root/.ssh/id_rsa", "line_start": 2}}
        with tempfile.TemporaryDirectory() as root:
            entry = verify._tool_verify_entry(
                root, {"run_id": "r"}, "q1", finding, "kimi")
        self.assertIn(verify._REDACTED_CLAIM_PATH, entry["prompt"])
        self.assertNotIn("id_rsa", entry["prompt"])

    def _manifest(self):
        return {"run_id": self.RUN_ID, "host": "claude",
                "security_mode": "standard", "flags": {}}

    def test_verify_backup_execute_narrows_file_list(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(runio._pano(d, "verdicts"), exist_ok=True)
            manifest = self._manifest()
            # group G spans 3 files; two CONFIRMED CRIT claims cite a.py + b.py.
            runio._write_json(runio._pano(d, "groups.json"),
                {"groups": [{"name": "G",
                             "files": ["src/a.py", "src/b.py", "src/c.py"]}]})
            runio._write_json(runio._pano(d, "coverage-G.json"),
                {"effective": ["SEC"]})
            runio._write_json(runio._pano(d, "findings-G-SEC.json"), {
                "findings": [
                    {"title": "authz bypass A", "severity": "CRITICAL",
                     "domain": "SEC", "code": "SEC-A2A", "category": "authz",
                     "location": {"file": "src/a.py", "line_start": 10}},
                    {"title": "authz bypass B", "severity": "CRITICAL",
                     "domain": "SEC", "code": "SEC-A2A", "category": "authz",
                     "location": {"file": "src/b.py", "line_start": 20}}],
                "_panopticon": {"run_id": self.RUN_ID, "role": "domain_panel",
                                "domain": "SEC", "group": "G"}})
            # load the cell for its synthesize-assigned ids, then CONFIRM both
            # (primary) so the authz category clears F_b and a backup is summoned.
            cell = review._load_cell_findings(d, manifest, "G", "SEC")
            self.assertEqual(len(cell), 2)
            runio._write_json(
                verify._verify_out_file(d, "G", "SEC", "primary"), {
                    "verdicts": [{"finding_id": f["id"], "verdict": "CONFIRMED",
                                  "reasoning": "real"} for f in cell],
                    "_panopticon": {"run_id": self.RUN_ID, "role": "domain_advisor",
                                    "domain": "SEC", "group": "G",
                                    "stage": "primary"}})
            res = verify._verify_backup_execute(d, manifest, "claude",
                                                ocrdb.load_bundle())
            self.assertIsNotNone(res)
            self.assertEqual(res.checkpoint, "verify")
            entry = requests.load_dispatch_request(d)["entries"][0]
            self.assertTrue(entry["out_file"].endswith("-backup.json"))
            prompt = entry["prompt"]
            self.assertIn("src/a.py", prompt)
            self.assertIn("src/b.py", prompt)
            self.assertNotIn("src/c.py", prompt)   # uncited group file excluded
