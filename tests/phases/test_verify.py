"""Tests for scripts.phases.verify: cell, backup and tool verification.
"""
import contextlib
import io
import json
import os
import tempfile
import unittest

import scripts.phases.runio as runio
import scripts.phases.requests as requests
import scripts.phases.review as review
import scripts.phases.verify as verify
import scripts.phases.persist as persist
import scripts.phases.evidence_scope as evidence_scope

import scripts.ocrdb as ocrdb
import scripts.evidence as evidence


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
    coverage-preserving cost cut (the advisor is claim-driven, reads unconfined).

    The fixture builds a REAL tree (it used to pass the string "/repo"): since
    #1638 P16 fix round 3 D2 a claim file must resolve to an EXISTING in-root
    file to bound the grant, because a grant of one path the advisor cannot open
    is a deny-all fence in everything but name. The narrowing semantics these
    tests are about are unchanged."""

    RUN_ID = "run-backup-narrow"

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        self.addCleanup(self._t.cleanup)
        os.makedirs(os.path.join(self.root, "src"))
        for name in ("a.py", "b.py", "c.py"):
            with open(os.path.join(self.root, "src", name), "w",
                      encoding="utf-8") as fh:
                fh.write("import os\n")

    def test_backup_scope_files_narrows_to_cited_files(self):
        scope = [{"location": {"file": "src/a.py", "line_start": 3}},
                 {"location": {"file": "src/b.py", "line_start": 9}}]
        self.assertEqual(
            verify._backup_scope_files(self.root,
                                       ["src/a.py", "src/b.py", "src/c.py"], scope),
            ["src/a.py", "src/b.py"])   # c.py (uncited) dropped

    def test_backup_scope_files_dedups_preserving_order(self):
        scope = [{"location": {"file": "src/a.py"}},
                 {"location": {"file": "src/a.py"}},
                 {"location": {"file": "src/b.py"}}]
        self.assertEqual(
            verify._backup_scope_files(self.root, ["src/a.py", "src/b.py"], scope),
            ["src/a.py", "src/b.py"])

    def test_backup_scope_files_falls_back_when_location_missing(self):
        # a scoped claim with no resolvable file -> the full group list; never
        # refute blind. `src/ghost.py` is the D2 addition: in-root and confined,
        # but not there to be read.
        full = ["src/a.py", "src/b.py", "src/c.py"]
        for bad in ({"location": {"file": ""}}, {"location": None}, {},
                    {"location": {}}, {"location": {"file": "./"}},
                    {"location": {"file": "  "}},
                    {"location": {"file": "src/ghost.py"}}):
            scope = [{"location": {"file": "src/a.py"}}, bad]
            self.assertEqual(verify._backup_scope_files(self.root, full, scope),
                             full, bad)

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
                verify._backup_scope_files(self.root, full, scope), full, evil)
        # a confined relative path is still used verbatim
        self.assertEqual(
            verify._backup_scope_files(
                self.root, full, [{"location": {"file": "src/a.py"}}]),
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

    def test_verify_entry_carries_the_stamp_keys_persist_checks(self):
        # Cross-module contract (fix round 1): persist._stamp_matches reads
        # run_id/group/domain/stage off the ENTRY (mirroring review._cell_entry),
        # so the only builder of verify-cell entries must actually set them.
        manifest = {"run_id": "R", "host": "claude",
                    "security_mode": "standard", "flags": {}}
        files = ["src/pay.py"]
        cell = [{"id": "F1", "code": "SEC-A1A", "severity": "HIGH",
                 "title": "t", "category": "SEC",
                 "location": {"file": files[0], "line": 1},
                 "description": "d"}]
        bundle = ocrdb.load_bundle()
        with tempfile.TemporaryDirectory() as root:
            entry = verify._verify_entry(root, manifest, "Auth", "SEC", files,
                                         cell, "claude", bundle, "primary")
        self.assertTrue(set(persist._STAMP_KEYS) <= set(entry))
        self.assertEqual(entry["run_id"], manifest["run_id"])
        self.assertEqual(entry["group"], "Auth")
        self.assertEqual(entry["domain"], "SEC")
        self.assertEqual(entry["stage"], "primary")

    def _manifest(self):
        return {"run_id": self.RUN_ID, "host": "claude",
                "security_mode": "standard", "flags": {}}

    def test_verify_backup_execute_narrows_file_list(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(runio._pano(d, "verdicts"), exist_ok=True)
            manifest = self._manifest()
            # group G spans 3 files; two CONFIRMED CRIT claims cite a.py + b.py.
            os.makedirs(os.path.join(d, "src"), exist_ok=True)
            for name in ("a.py", "b.py", "c.py"):    # D2: claim files must exist
                with open(os.path.join(d, "src", name), "w",
                          encoding="utf-8") as fh:
                    fh.write("import os\n")
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


class TestBackupEvidenceClosure(unittest.TestCase):
    """#1638 P16 (owner ruling D4): the backup advisor is granted a BOUNDED
    EVIDENCE CLOSURE -- the claim's file, the producers its own evidence names,
    and a one-hop in-repo import neighbourhood -- and the grant is recorded in
    the prompt so the verdict can echo it. Run-13 granted the claim file alone,
    so a cross-file defect the primary CONFIRMED came back NEEDS_MORE_INFO."""

    RUN_ID = "run-backup-closure"

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        self.addCleanup(self._t.cleanup)

    def _write(self, rel, text="import os\n"):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path) or self.root, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return rel

    def _run13_repo(self):
        self._write("synth/__init__.py", "")
        self._write("synth/render.py")
        self._write("synth/grading.py")
        self._write("synthesize.py", "import synth.render as render_mod\n")
        return ["synth/render.py", "synth/grading.py", "synthesize.py"]

    def _claim(self):
        return {"id": "F1", "code": "SEC-A1A", "severity": "HIGH",
                "title": "redaction runs after the render", "category": "SEC",
                "location": {"file": "synth/render.py", "line_start": 12},
                "description": "the call order in synth/grading.py and "
                               "synthesize.py runs redact last"}

    def test_backup_scope_files_grants_the_named_producers(self):
        files = self._run13_repo()
        self.assertEqual(
            verify._backup_scope_files(self.root, files, [self._claim()]),
            ["synth/render.py", "synth/grading.py", "synthesize.py"])

    def test_backup_grant_records_the_cap_and_truncation(self):
        files = self._run13_repo()
        self.assertEqual(
            verify._backup_grant(self.root, files, [self._claim()]),
            {"granted": ["synth/render.py", "synth/grading.py",
                         "synthesize.py"],
             "cap": evidence_scope.CAP, "truncated": False,
             "entry_cap": evidence_scope.ENTRY_CAP, "entry_truncated": False,
             "omitted": 0, "floor_count": 1})

    def test_backup_entry_prompt_lists_the_granted_evidence(self):
        files = self._run13_repo()
        grant = verify._backup_grant(self.root, files, [self._claim()])
        entry = verify._verify_entry(
            self.root, {"run_id": self.RUN_ID, "host": "claude",
                        "security_mode": "standard", "flags": {}},
            "G", "SEC", grant["granted"], [self._claim()], "claude",
            ocrdb.load_bundle(), "backup", grant=grant)
        prompt = entry["prompt"]
        self.assertIn("Evidence granted for this check (bounded closure)",
                      prompt)
        for rel in grant["granted"]:
            self.assertIn(os.path.join(self.root, rel), prompt)
        self.assertIn("missing_evidence", prompt)

    def test_backup_entry_read_scope_is_exactly_the_granted_list(self):
        # Family guardrails section 3: nothing is widened beyond the recorded
        # list, and every granted path stays inside review_root.
        files = self._run13_repo()
        grant = verify._backup_grant(self.root, files, [self._claim()])
        entry = verify._verify_entry(
            self.root, {"run_id": self.RUN_ID, "host": "claude",
                        "security_mode": "standard", "flags": {}},
            "G", "SEC", grant["granted"], [self._claim()], "claude",
            ocrdb.load_bundle(), "backup", grant=grant)
        want = [os.path.join(self.root, rel) for rel in grant["granted"]]
        self.assertEqual(entry["files"], want)
        self.assertEqual(entry["scope"]["files"], want)
        self.assertEqual(entry["scope"]["dirs"], [])
        self.assertEqual(entry["scope"]["reads"], [])
        for path in entry["scope"]["files"]:
            self.assertTrue(runio._confined_to_root(self.root, path), path)

    def test_granted_list_is_prompt_sanitized(self):
        # #1190: a control character in a target-tree filename must not be able
        # to inject prompt lines through the grant block.
        rel = self._write("src/we\x07ird.py")
        grant = {"granted": [rel], "cap": 12, "truncated": False}
        entry = verify._verify_entry(
            self.root, {"run_id": self.RUN_ID, "host": "claude",
                        "security_mode": "standard", "flags": {}},
            "G", "SEC", [rel], [self._claim()], "claude",
            ocrdb.load_bundle(), "backup", grant=grant)
        self.assertNotIn("\x07", entry["prompt"])
        self.assertIn("we\\x07ird.py", entry["prompt"])

    def test_primary_entry_carries_no_grant_block(self):
        files = self._run13_repo()
        entry = verify._verify_entry(
            self.root, {"run_id": self.RUN_ID, "host": "claude",
                        "security_mode": "standard", "flags": {}},
            "G", "SEC", files, [self._claim()], "claude",
            ocrdb.load_bundle(), "primary")
        # The TEMPLATE names the heading (it tells a backup advisor what to do
        # with the section); what a primary entry must not carry is the driver's
        # rendered grant.
        self.assertNotIn("These files are the WHOLE of what", entry["prompt"])
        self.assertNotIn(verify._GRANT_HEADING + "\n", entry["prompt"])


class TestBackupGrantBlockPlacement(unittest.TestCase):
    """Fix round 1, F4: the grant block sits BETWEEN the repo-root pin and the
    template, so the advisor reads the root, then its fence, then the claims --
    which is what `_verify_entry`'s comment says. It was prepended ahead of the
    pin. And F3: an entry-ceiling truncation is stated in the prompt, not left
    for the advisor to discover a file at a time."""

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        self.addCleanup(self._t.cleanup)

    def _entry(self, grant):
        claim = {"id": "F1", "code": "SEC-A1A", "severity": "HIGH",
                 "title": "t", "category": "SEC",
                 "location": {"file": "a.py", "line_start": 1},
                 "description": "d"}
        return verify._verify_entry(
            self.root, {"run_id": "R", "host": "claude",
                        "security_mode": "standard", "flags": {}},
            "G", "SEC", grant["granted"], [claim], "claude",
            ocrdb.load_bundle(), "backup", grant=grant)

    def test_the_grant_block_sits_between_the_pin_and_the_template(self):
        prompt = self._entry({"granted": ["a.py"], "cap": 12,
                              "truncated": False, "entry_cap": 48,
                              "entry_truncated": False})["prompt"]
        pin = prompt.index("Repo root: ")
        heading = prompt.index(verify._GRANT_HEADING)
        template = prompt.index("You are an independent")
        self.assertLess(pin, heading, "the repo-root pin must come first")
        self.assertLess(heading, template)

    def test_an_entry_ceiling_truncation_is_stated_in_the_prompt(self):
        prompt = self._entry({"granted": ["a.py"], "cap": 12,
                              "truncated": False, "entry_cap": 48,
                              "entry_truncated": True, "omitted": 7})["prompt"]
        self.assertIn("7 further files omitted by the entry ceiling", prompt)

    def test_no_omission_line_when_the_ceiling_did_not_bite(self):
        prompt = self._entry({"granted": ["a.py"], "cap": 12,
                              "truncated": False, "entry_cap": 48,
                              "entry_truncated": False})["prompt"]
        # (the TEMPLATE mentions the ceiling to say what it means; what must be
        # absent is the driver's counted sentence.)
        self.assertNotIn("further files omitted by the entry ceiling", prompt)

    def _floor_sentence(self, floor_count):
        prompt = self._entry({"granted": ["a.py"], "cap": 12,
                              "truncated": False, "entry_cap": 48,
                              "entry_truncated": False,
                              "floor_count": floor_count})["prompt"]
        return prompt

    def test_one_claim_file_is_said_in_the_singular(self):
        # Fix round 4, N5. The single-claim entry is the COMMON case (a backup
        # chunk is often one finding), so "1 of the files below are claim files"
        # is the sentence most advisors actually read.
        self.assertIn("1 of the files below is a claim file, which no cap "
                      "bounds.", self._floor_sentence(1))

    def test_several_claim_files_stay_plural(self):
        self.assertIn("3 of the files below are claim files, which no cap "
                      "bounds.", self._floor_sentence(3))


class TestPlantedCarrierCannotSuppressTheBackupRound(unittest.TestCase):
    """Fix round 2, N1. `_cell_verdicts` was the THIRD reader of an agent-written
    verdict bundle and the one the F1 strip missed. Its output picks the backup
    round's scope (`advisor_confirmed` only), so a PRIMARY advisor that plants
    `_backup_missing_evidence` on its own verdicts flips them to
    `backup_scope_limited`, empties the scope, and `_verify_backup_execute`
    dispatches no adversarial round for the cell at all -- cheaper than the
    exploit F1 closed, and invisible in the report."""

    RUN_ID = "run-carrier-suppression"

    def _cell(self, root, planted):
        os.makedirs(runio._pano(root, "verdicts"), exist_ok=True)
        manifest = {"run_id": self.RUN_ID, "host": "claude",
                    "security_mode": "standard", "flags": {}}
        runio._write_json(runio._pano(root, "groups.json"),
                          {"groups": [{"name": "G", "files": ["src/a.py"]}]})
        runio._write_json(runio._pano(root, "coverage-G.json"),
                          {"effective": ["SEC"]})
        runio._write_json(runio._pano(root, "findings-G-SEC.json"), {
            "findings": [{"title": "injection %d" % i, "severity": "CRITICAL",
                          "domain": "SEC", "code": "SEC-A3A",
                          "category": "injection",
                          "location": {"file": "src/a.py", "line_start": 10 + i}}
                         for i in range(3)],
            "_panopticon": {"run_id": self.RUN_ID, "role": "domain_panel",
                            "domain": "SEC", "group": "G"}})
        cell = review._load_cell_findings(root, manifest, "G", "SEC")
        verdict = lambda f: dict(                                  # noqa: E731
            {"finding_id": f["id"], "verdict": "CONFIRMED",
             "reasoning": "real"},
            **({"_backup_missing_evidence": ["elsewhere.py"]} if planted else {}))
        runio._write_json(
            verify._verify_out_file(root, "G", "SEC", "primary"),
            {"verdicts": [verdict(f) for f in cell],
             "_panopticon": {"run_id": self.RUN_ID, "role": "domain_advisor",
                             "domain": "SEC", "group": "G", "stage": "primary"}})
        return manifest

    def _scope(self, planted):
        with tempfile.TemporaryDirectory() as d:
            root = os.path.realpath(d)
            manifest = self._cell(root, planted)
            return verify._cell_backup_findings(root, manifest, "G", "SEC")

    def test_a_planted_carrier_does_not_shrink_the_backup_scope(self):
        self.assertEqual(len(self._scope(planted=False)), 3)
        self.assertEqual(len(self._scope(planted=True)), 3)

    def test_the_backup_round_is_still_dispatched(self):
        with tempfile.TemporaryDirectory() as d:
            root = os.path.realpath(d)
            manifest = self._cell(root, planted=True)
            res = verify._verify_backup_execute(root, manifest, "claude",
                                                ocrdb.load_bundle())
            self.assertIsNotNone(res, "no adversarial backup entry dispatched")
            self.assertEqual(res.checkpoint, "verify")

    def test_cell_verdicts_strips_agent_private_keys(self):
        with tempfile.TemporaryDirectory() as d:
            root = os.path.realpath(d)
            self._cell(root, planted=True)
            got = verify._cell_verdicts(root, "G", "SEC", "primary")
            self.assertEqual(len(got), 3)
            for v in got:
                self.assertEqual([k for k in v if k.startswith("_")], [], v)


class TestBackupCellFixture(unittest.TestCase):
    """Shared fixture: one cell whose primary bundle this test decides."""

    RUN_ID = "run-fix3"

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        self.addCleanup(self._t.cleanup)
        os.makedirs(runio._pano(self.root, "verdicts"), exist_ok=True)
        self.manifest = {"run_id": self.RUN_ID, "host": "claude",
                         "security_mode": "standard", "flags": {}}

    def _cell(self, loc_file="src/a.py", verdicts_for=None, files=None):
        # `files=[]` is a deliberate value, not "unset" -- N2's group.
        files = ["src/a.py", "src/b.py"] if files is None else files
        for rel in files:
            path = os.path.join(self.root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("import os\n")
        runio._write_json(runio._pano(self.root, "groups.json"),
                          {"groups": [{"name": "G", "files": files}]})
        runio._write_json(runio._pano(self.root, "coverage-G.json"),
                          {"effective": ["SEC"]})
        runio._write_json(runio._pano(self.root, "findings-G-SEC.json"), {
            "findings": [{"title": "injection %d" % i, "severity": "CRITICAL",
                          "domain": "SEC", "code": "SEC-A3A",
                          "category": "injection",
                          "location": {"file": loc_file, "line_start": 10 + i}}
                         for i in range(3)],
            "_panopticon": {"run_id": self.RUN_ID, "role": "domain_panel",
                            "domain": "SEC", "group": "G"}})
        cell = review._load_cell_findings(self.root, self.manifest, "G", "SEC")
        verdicts = []
        for f in cell:
            verdicts.extend((verdicts_for or (lambda fid: [
                {"finding_id": fid, "verdict": "CONFIRMED",
                 "reasoning": "real"}]))(f["id"]))
        runio._write_json(
            verify._verify_out_file(self.root, "G", "SEC", "primary"),
            {"verdicts": verdicts,
             "_panopticon": {"run_id": self.RUN_ID, "role": "domain_advisor",
                             "domain": "SEC", "group": "G",
                             "stage": "primary"}})
        return cell


class TestDuplicatePrimariesResolveTheSameWayEverywhere(TestBackupCellFixture):
    """Fix round 3, D1. `_cell_backup_findings` built its finding_id map with a
    dict comprehension -- LAST-wins -- while `evidence.match_verdict_by_id` is
    FIRST-wins. A primary bundle emitting CONFIRMED then REJECTED for one
    finding therefore made the DRIVER see `rejected` (scope 0, no adversarial
    round dispatched) while SYNTHESIS saw `advisor_confirmed` (factor 1.5,
    gate-eligible) -- the N1 outcome with no private key and no `stage`, and a
    direct contradiction of this PR's own stated policy."""

    def _dupes(self, fid):
        return [{"finding_id": fid, "verdict": "CONFIRMED", "reasoning": "yes"},
                {"finding_id": fid, "verdict": "REJECTED", "reasoning": "no"}]

    def test_the_driver_keeps_the_first_verdict_like_synthesis_does(self):
        self._cell(verdicts_for=self._dupes)
        scope = verify._cell_backup_findings(self.root, self.manifest, "G", "SEC")
        self.assertEqual(len(scope), 3)
        self.assertEqual({f["evidence"]["status"] for f in scope},
                         {"advisor_confirmed"})

    def test_the_backup_round_is_still_dispatched(self):
        self._cell(verdicts_for=self._dupes)
        res = verify._verify_backup_execute(self.root, self.manifest, "claude",
                                            ocrdb.load_bundle())
        self.assertIsNotNone(res, "no adversarial backup entry dispatched")

    def test_driver_and_synthesis_agree_on_the_winner(self):
        cell = self._cell(verdicts_for=self._dupes)
        verdicts = verify._cell_verdicts(self.root, "G", "SEC", "primary")
        by_fid = {}
        for v in verdicts:
            by_fid.setdefault(str(v["finding_id"]), []).append(v)
        for f in cell:
            # run_id=None: `_cell_verdicts` reads a per-cell FILE, so it never
            # stamps one, and the driver path passes none either.
            synthesis = evidence.match_verdict_by_id(f, by_fid)
            driver = evidence.by_finding_id(verdicts, "primary")[str(f["id"])]
            self.assertEqual(driver["verdict"], synthesis["verdict"])
            self.assertEqual(driver["verdict"], "CONFIRMED")


class TestNoBackupEntryIsEverDispatchedWithAnEmptyGrant(TestBackupCellFixture):
    """Fix round 3, D2, at the layer the invariant is about: the dispatch
    REQUEST. An empty `files` list is a deny-all read fence (the guard refuses
    every Read, Grep and Glob), so an entry carrying one asks an advisor to
    adjudicate with nothing."""

    def _entries(self, loc_file):
        self._cell(loc_file=loc_file)
        res = verify._verify_backup_execute(self.root, self.manifest, "claude",
                                            ocrdb.load_bundle())
        self.assertIsNotNone(res)
        return requests.load_dispatch_request(self.root)["entries"]

    def test_every_dispatched_entry_has_a_non_empty_read_grant(self):
        for loc in ("src/a.py", "./", " ", "", "."):
            for entry in self._entries(loc):
                self.assertTrue(entry["files"], (loc, entry["id"]))
                self.assertTrue(entry["scope"]["files"], (loc, entry["id"]))


class TestAGroupWithNoFilesGetsNoBackupEntry(TestBackupCellFixture):
    """Fix round 4, N2. The never-empty invariant was enforced inside `grant()`,
    which guarantees it by falling back to the GROUP's file list -- so the
    guarantee was conditional on that list being non-empty. A group carrying
    `files: []` fell back to nothing and an entry shipped a deny-all fence.

    Unreachable through the pipeline (`discovery.assign_scoped` never writes an
    empty group), so this is defence in depth. The invariant is made
    unconditional at the layer it is about: a group with no files has nothing to
    verify, so no backup entry is BUILT for it -- and the done-predicate agrees,
    because a cell nobody will ever dispatch must not hold the phase open."""

    def _no_files(self):
        self._cell(files=[])

    def test_no_entry_is_dispatched_for_a_group_with_no_files(self):
        self._no_files()
        res = verify._verify_backup_execute(self.root, self.manifest, "claude",
                                            ocrdb.load_bundle())
        self.assertIsNone(res, "a backup entry was built for an empty group")

    def test_the_skip_is_recorded_not_silent(self):
        self._no_files()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            verify._verify_backup_execute(self.root, self.manifest, "claude",
                                          ocrdb.load_bundle())
        self.assertIn("G", err.getvalue())
        self.assertIn("no files", err.getvalue())

    def test_the_phase_does_not_hang_on_the_skipped_cell(self):
        # A cell that will never be dispatched must not leave `verify` waiting
        # on a verdict file that can never arrive.
        self._no_files()
        self.assertTrue(verify._verify_backup_done(self.root, self.manifest))

    def test_a_group_with_files_still_gets_its_entry(self):
        self._cell()
        res = verify._verify_backup_execute(self.root, self.manifest, "claude",
                                            ocrdb.load_bundle())
        self.assertIsNotNone(res)
        for entry in requests.load_dispatch_request(self.root)["entries"]:
            self.assertTrue(entry["files"])
