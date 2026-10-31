"""#3231 part A: the tool advisor's read fence is its claim's cell PLUS the backup
round's bounded closure (A1), and a NEEDS_MORE_INFO that names the files it could
not reach earns one re-dispatch with them, charged to the item's own budget (A2)."""
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

import jsonschema

import scripts.evidence as evidence
import scripts.loop_batch as loop_batch
import scripts.phases.persist as persist
import scripts.phases.evidence_scope as evidence_scope
import scripts.phases.runio as runio
import scripts.phases.verify as verify
import scripts.phases.verify_tools as verify_tools
import scripts.run_manifest as run_manifest
import scripts.runners.schema as schema_rules

QID = "0123456789abcdef"
RUN = "run-3231"


def _finding(file="synth/render.py", **kw):
    f = {"id": "SG-1", "severity": "HIGH", "source": "tool:semgrep",
         "title": "hooks path traversal", "category": "x",
         "location": {"file": file, "line_start": 3}}
    f.update(kw)
    return f


class _Tree(unittest.TestCase):
    """`Synth` holds render.py, which reaches `reconcile` through a FUNCTION-LEVEL
    import (the issue's first example); `Core` holds reconcile.py; `Phases` holds
    child.py, whose callers live in `Driver` (the second example)."""

    FILES = {
        "synth/render.py": "def f():\n    import reconcile\n    return reconcile.g()\n",
        "synth/other.py": "X = 1\n",
        "reconcile.py": "def g():\n    return 1\n",
        "phases/child.py": "import subprocess\n",
        "driver/caller.py": "from phases import child\n",
        "driver/second.py": "Y = 2\n",
    }
    GROUPS = [{"name": "Synth", "files": ["synth/render.py", "synth/other.py", "reconcile_alias.py"]},
              {"name": "Core", "files": ["reconcile.py"]},
              {"name": "Phases", "files": ["phases/child.py"]},
              {"name": "Driver", "files": ["driver/caller.py", "driver/second.py"]}]

    def setUp(self):
        self.root = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        os.makedirs(runio._pano(self.root), exist_ok=True)
        for rel, text in self.FILES.items():
            path = os.path.join(self.root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        groups = [dict(g, files=[f for f in g["files"] if f in self.FILES]) for g in self.GROUPS]
        # Stamped for this run, as `discovery_execute` writes it: the listing a
        # `missing_evidence` name must be in to be granted (F4).
        runio._write_json(run_manifest.manifest_path(self.root), {"run_id": RUN, "host": "claude"})
        runio._write_json(runio._pano(self.root, "groups.json"), {"groups": groups, "run_id": RUN})

    def _abs(self, rel):
        return os.path.join(self.root, rel)

    def _list(self, files, name="Extra"):
        """Add `files` to this run's discovered listing as one more group."""
        path = runio._pano(self.root, "groups.json")
        doc = runio._load_json(path)
        doc["groups"].append({"name": name, "files": list(files)})
        runio._write_json(path, doc)

    def _entry(self, finding=None, lift=None):
        return verify_tools._tool_verify_entry(self.root, {"run_id": "r"}, QID,
                                               finding or _finding(), "claude", lift)

    def _verdict(self, verdict="NEEDS_MORE_INFO", missing=None):
        body = {"finding_id": "SG-1", "verdict": verdict, "confidence": "POSSIBLE",
                "reasoning": "r", "explored": [], "references": [], "citations": {}}
        if missing is not None:
            body["missing_evidence"] = missing
        os.makedirs(os.path.dirname(verify_tools._tool_verdict_out_file(self.root, QID)),
                    exist_ok=True)
        runio._write_json(verify_tools._tool_verdict_out_file(self.root, QID), body)

    def _spent(self, n):
        for _ in range(n):
            verify._charge_verify_dispatch(self.root, [{"id": verify_tools.TOOL_ENTRY_PREFIX + QID}])

    def _attempts(self):
        return verify._verify_attempts_key(self.root, "tool/%s" % QID)


class ClosureTest(_Tree):
    def test_the_fence_is_the_cell_plus_the_one_hop_closure(self):
        entry = self._entry()
        files = set(entry["scope"]["files"])
        self.assertTrue({self._abs("synth/render.py"), self._abs("synth/other.py"),
                         self._abs("reconcile.py")} <= files)
        self.assertNotIn(self._abs("driver/caller.py"), files)
        self.assertIn(verify_tools._CLOSURE_HEADING, entry["prompt"])
        self.assertIn(self._abs("reconcile.py"), entry["prompt"])

    def test_a_named_path_outside_the_root_is_never_granted(self):
        entry = self._entry(_finding(description="see ../../outside.py and /etc/passwd.py"))
        self.assertFalse([f for f in entry["scope"]["files"]
                          if not f.startswith(self.root + os.sep)])

    def test_a_claim_with_nothing_outside_its_cell_carries_no_block(self):
        entry = self._entry(_finding(file="synth/other.py"))
        self.assertNotIn(verify_tools._CLOSURE_HEADING, entry["prompt"])
        self.assertEqual(sorted([self._abs("synth/other.py"), self._abs("synth/render.py")]),
                         sorted(entry["scope"]["files"]))

    def test_an_escaping_cited_file_still_confines_to_nothing(self):
        entry = self._entry(_finding(file="../../etc/shadow"))
        self.assertEqual([], entry["scope"]["files"])


class LiftTest(_Tree):
    def _child(self):
        return _finding(file="phases/child.py", title="Popen audit")

    def test_a_needs_more_info_naming_a_file_earns_one_re_dispatch_with_it(self):
        self._spent(1)
        self._verdict(missing=[self._abs("driver/caller.py")])
        self.assertEqual([self._abs("driver/caller.py")],
                         verify_tools._lift_owed(self.root, QID, self._child()))
        with mock.patch.object(verify_tools, "_tool_verify_queue",
                               return_value=[(QID, self._child())]):
            self.assertFalse(verify_tools._verify_tools_done(self.root, {"run_id": "r"}))
        captured = []
        with mock.patch.object(verify_tools, "_tool_verify_queue",
                               return_value=[(QID, self._child())]), \
                mock.patch.object(verify_tools.requests, "write_dispatch_request_bound",
                                  side_effect=lambda *a: captured.append(a[4]) or ("req", "sha")):
            result = verify_tools._verify_tools_execute(self.root, {"run_id": "r"}, "claude")
        self.assertEqual("checkpoint", result.kind)
        (entry,) = captured[0]
        self.assertIn(self._abs("driver/caller.py"), entry["scope"]["files"])
        self.assertIn(verify_tools._LIFTED, entry["prompt"])
        self.assertEqual(2, self._attempts())           # charged to the item's own budget

    def test_the_lift_is_owed_once(self):
        self._spent(2)
        self._verdict(missing=[self._abs("driver/caller.py")])
        self.assertIsNone(verify_tools._lift_owed(self.root, QID, self._child()))
        with mock.patch.object(verify_tools, "_tool_verify_queue",
                               return_value=[(QID, self._child())]):
            self.assertTrue(verify_tools._verify_tools_done(self.root, {"run_id": "r"}))

    def test_an_interrupted_lift_is_owed_again(self):
        self._spent(2)
        verify._give_back_verify_dispatch(self.root, [{"id": verify_tools.TOOL_ENTRY_PREFIX + QID}])
        self._verdict(missing=[self._abs("driver/caller.py")])
        self.assertIsNotNone(verify_tools._lift_owed(self.root, QID, self._child()))

    def test_names_that_grant_nothing_new_earn_nothing(self):
        self._spent(1)
        for missing in ([self._abs("phases/child.py")],          # already in the cell
                        ["does/not/exist.py"],                    # resolves to nothing
                        ["/etc/passwd"],                          # outside the root
                        []):
            with self.subTest(missing=missing):
                self._verdict(missing=missing)
                self.assertIsNone(verify_tools._lift_owed(self.root, QID, self._child()))

    def test_a_decided_verdict_is_never_lifted(self):
        self._spent(1)
        for verdict in ("CONFIRMED", "REJECTED"):
            with self.subTest(verdict=verdict):
                self._verdict(verdict, missing=[self._abs("driver/caller.py")])
                self.assertIsNone(verify_tools._lift_owed(self.root, QID, self._child()))

    def test_the_lift_is_capped_like_any_closure(self):
        names = []
        for n in range(evidence_scope.CAP + 8):
            rel = "extra/m%02d.py" % n
            path = self._abs(rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("Z = %d\n" % n)
            names.append(rel)
        self._list(names)
        cell = [self._abs("phases/child.py")]
        base, _ = verify_tools._tool_closure(self.root, self._child(), cell)
        lifted, _ = verify_tools._tool_closure(self.root, self._child(), cell, names)
        self.assertEqual(evidence_scope.CAP, len(set(lifted) - set(base)))

    def test_the_report_says_what_a_tool_advisor_could_not_see(self):
        verdict = {"verdict": "NEEDS_MORE_INFO", "reasoning": "r",
                   "missing_evidence": ["driver/caller.py"]}
        tool = evidence.derive_evidence(_finding(), verdict)
        self.assertEqual(("needs_more_info", ["driver/caller.py"]),
                         (tool["status"], tool.get("missing_evidence")))
        agent = evidence.derive_evidence(_finding(source="agent:sr"), verdict)
        self.assertNotIn("missing_evidence", agent)
        many = dict(verdict, missing_evidence=["f%d.py" % n for n in range(40)])
        self.assertEqual(evidence.SCOPE_NAMES_SHOWN,
                         len(evidence.derive_evidence(_finding(), many)["missing_evidence"]))


class LoopSurfacesTest(_Tree):
    """One item through the real loop surfaces (change request F1/F2): the lift entry
    as the round builds it, `loop_batch._pending`, `persist.write_reply`, the round's
    own done predicate, and the evidence synthesize derives. Only the queue is fixed,
    because recomputing it runs synthesize's whole ingest and is not what is tested."""

    def setUp(self):
        super().setUp()
        self.finding = _finding(file="phases/child.py", title="Popen audit")
        self._spent(1)
        self._verdict(missing=[self._abs("driver/caller.py")])
        self.queue = mock.patch.object(verify_tools, "_tool_verify_queue",
                                       return_value=[(QID, self.finding)])
        self.queue.start()
        self.addCleanup(self.queue.stop)

    def _lift_entry(self):
        captured = []
        with mock.patch.object(verify_tools.requests, "write_dispatch_request_bound",
                               side_effect=lambda *a: captured.append(a[4]) or ("r", "s")):
            verify_tools._verify_tools_execute(self.root, {"run_id": "r"}, "claude")
        (entry,) = captured[0]
        return entry

    def _reply(self, verdict, missing=None):
        body = {"finding_id": "SG-1", "verdict": verdict, "confidence": "LIKELY",
                "reasoning": "traced the caller", "explored": [], "references": [],
                "citations": {}}
        if missing is not None:
            body["missing_evidence"] = missing
        return json.dumps(body)

    def _evidence(self):
        verdicts, unloadable = evidence.load_verdicts_detailed(
            runio._pano(self.root, "verdicts"))
        self.assertEqual(([], [QID]), (unloadable, sorted(verdicts)))
        return evidence.derive_evidence(self.finding, verdicts[QID])

    def _finish(self):
        done = verify_tools._verify_tools_done(self.root, {"run_id": "r"})
        if not done:
            self.assertIsNone(verify_tools._verify_tools_execute(self.root, {"run_id": "r"}, "claude"))
        self.assertTrue(verify_tools._verify_tools_done(self.root, {"run_id": "r"}))

    def test_the_lift_launches_and_a_confirmed_second_answer_lands(self):
        entry = self._lift_entry()
        self.assertEqual([entry], loop_batch._pending([entry]))     # not born done
        self.assertEqual((True, ""), persist.write_reply(entry, self._reply("CONFIRMED")))
        self.assertFalse(verify_tools._verify_tools_done(self.root, {"run_id": "r"}))
        self._finish()
        self.assertEqual("tool_confirmed", self._evidence()["status"])
        self.assertFalse(os.path.exists(entry["out_file"]))          # promoted, not left over

    def test_a_second_needs_more_info_stands(self):
        entry = self._lift_entry()
        persist.write_reply(entry, self._reply("NEEDS_MORE_INFO", ["driver/second.py"]))
        self._finish()
        ev = self._evidence()
        self.assertEqual(("needs_more_info", ["driver/second.py"]),
                         (ev["status"], ev.get("missing_evidence")))
        self.assertIsNone(verify_tools._lift_owed(self.root, QID, self.finding))   # once

    def test_a_failed_lift_keeps_the_first_answer(self):
        entry = self._lift_entry()
        ok, _reason = persist.write_reply(entry, "not json at all")
        self.assertFalse(ok)
        self._finish()
        ev = self._evidence()
        self.assertEqual(("needs_more_info", [self._abs("driver/caller.py")]),
                         (ev["status"], ev.get("missing_evidence")))

    def test_an_interrupt_on_the_real_rollback_path_leaves_the_lift_owed(self):
        import scripts.ledger as ledger_mod
        import scripts.runners.batch as batch_mod
        entry = self._lift_entry()
        self.assertEqual(2, self._attempts())
        run_dir = runio._pano(self.root)
        batch = batch_mod.Batch(run_dir, 1, "verify", [entry]).open()
        self.assertEqual([[entry["out_file"]]], [r["artifacts"] for r in batch.entries])
        ledger = ledger_mod.Ledger(run_dir)
        ledger.mark_batch()
        runner = mock.Mock(host="claude")
        message = loop_batch.rolled_back(self.root, batch, [entry], {"checkpoint": "verify"},
                                         ledger, "headless", runner, None)
        self.assertNotIn("rollback incomplete", message)
        self.assertEqual(1, self._attempts())                        # refunded
        self.assertTrue(verify_tools._tool_verdict_done(self.root, QID))   # first stands
        self.assertIsNotNone(verify_tools._lift_owed(self.root, QID, self.finding))


class NamesInAnyLanguageTest(_Tree):
    FILES = dict(_Tree.FILES, **{"web/src/App.tsx": "export {}\n",
                                 "web/app/User.php": "<?php\n"})
    GROUPS = _Tree.GROUPS + [{"name": "Web", "files": ["web/src/App.tsx", "web/app/User.php"]}]

    def test_missing_evidence_names_resolve_whole_whatever_the_extension(self):
        cell = [self._abs("phases/child.py")]
        extras, _ = verify_tools._tool_closure(
            self.root, _finding(file="phases/child.py"), cell,
            [self._abs("web/src/App.tsx"), "web/app/User.php"])
        self.assertEqual({"web/src/App.tsx", "web/app/User.php"}, set(extras))


class StrictGenerationTest(_Tree):
    """#3241 constrains a Codex tool advisor to a projection. Without the field there,
    it could never name a file, and the lift would silently never fire on Codex."""

    def _child(self):
        return _finding(file="phases/child.py", title="Popen audit")

    def test_a_lift_entry_selects_the_projection_and_it_can_name_a_file(self):
        self._spent(1)
        entry = self._entry(self._child(), lift=["driver/caller.py"])
        self.assertEqual(verify_tools._tool_lift_out_file(self.root, QID), entry["out_file"])
        path = persist.generation_schema(entry)
        self.assertEqual("tool-advisor-generation-schema.json", os.path.basename(path))
        with open(path, encoding="utf-8") as fh:
            schema = json.load(fh)
        self.assertIn("missing_evidence", schema["required"])

    def test_a_codex_shaped_reply_goes_through_the_projection_write_reply_and_the_lift(self):
        # The whole path on the strict host: what the provider may return, what the
        # receipt accepts after stamping, and what the round then owes.
        finding = self._child()
        with open(persist.launch_schema(self._entry(finding), "codex"), encoding="utf-8") as fh:
            projection = json.load(fh)
        self.assertEqual(persist.generation_schema(self._entry(finding)),
                         schema_rules.strict_output_schema(
                             persist.generation_schema(self._entry(finding))))

        def reply(verdict, missing):
            body = {"finding_id": "SG-1", "verdict": verdict, "confidence": "LIKELY",
                    "reasoning": "r", "explored": [], "references": [],
                    "citations": {"cwe": [], "owasp": [], "cve": []},
                    "missing_evidence": missing}
            jsonschema.validate(body, projection)
            return json.dumps(body)

        self._spent(1)
        first = self._entry(finding)
        self.assertEqual((True, ""), persist.write_reply(
            first, reply("NEEDS_MORE_INFO", ["driver/caller.py"])))
        self.assertEqual(["driver/caller.py"],
                         verify_tools._lift_owed(self.root, QID, finding))
        lift = self._entry(finding, lift=["driver/caller.py"])
        self.assertEqual("tool-advisor-generation-schema.json",
                         os.path.basename(persist.launch_schema(lift, "codex")))
        self.assertEqual("advisor-verdict-schema.json",
                         os.path.basename(persist.launch_schema(lift, "claude")))
        self.assertEqual((True, ""), persist.write_reply(lift, reply("CONFIRMED", [])))
        verify_tools._promote_lifts(self.root, [QID])
        with open(verify_tools._tool_verdict_out_file(self.root, QID), encoding="utf-8") as fh:
            landed = json.load(fh)
        self.assertEqual(("CONFIRMED", []), (landed["verdict"], landed["missing_evidence"]))
        jsonschema.validate(landed, self._receipt())

    def _receipt(self):
        with open(persist.role_schema({"out_file": "verdicts/" + QID + ".json"}),
                  encoding="utf-8") as fh:
            return json.load(fh)

    def test_the_empty_list_the_projection_forces_means_nothing_was_named(self):
        self._spent(1)
        for verdict in ("CONFIRMED", "REJECTED", "NEEDS_MORE_INFO"):
            with self.subTest(verdict):
                self._verdict(verdict, missing=[])
                self.assertIsNone(verify_tools._lift_owed(self.root, QID, self._child()))
                self.assertEqual([], evidence.scope_limited_paths(
                    {"verdict": verdict, "missing_evidence": []}))


class RunDiscoveredOnlyTest(_Tree):
    """F4: a `missing_evidence` name is granted only if this run discovered the file.
    F4b: `.git` and `.panopticon` are never evidence, by any path."""

    SECRETS = {".env": "K=v\n", ".git/config": "[core]\n",
               ".git/info/x.json": "{}\n",
               ".panopticon/host-settings.json": "{}\n",
               ".panopticon/runs/t/verdicts/other.json": "{}\n",
               "terraform.tfstate": "{}\n", "deploy/id_rsa": "k\n"}
    FILES = dict(_Tree.FILES, **SECRETS)

    def _child(self, **kw):
        return _finding(file="phases/child.py", title="Popen audit", **kw)

    def _refused(self, name, target=None):
        """Neither owed, nor in the fence of an entry that was handed the name anyway."""
        target = self._abs(target or name)
        self._verdict(missing=[name])
        self.assertIsNone(verify_tools._lift_owed(self.root, QID, self._child()))
        entry = self._entry(self._child(), lift=[name])
        self.assertNotIn(target, entry["scope"]["files"])

    def test_a_file_on_disk_the_run_did_not_discover_is_never_granted(self):
        self._spent(1)
        for name, target in ((".env", None), (".git/config", None),
                             (".panopticon/host-settings.json", None),
                             (".panopticon/runs/t/verdicts/other.json", None),
                             ("terraform.tfstate", None), ("id_rsa", "deploy/id_rsa")):
            with self.subTest(name):
                self._refused(name, target)

    def test_a_run_discovered_file_still_lifts(self):
        self._spent(1)
        self._verdict(missing=["driver/caller.py"])
        self.assertEqual(["driver/caller.py"],
                         verify_tools._lift_owed(self.root, QID, self._child()))
        entry = self._entry(self._child(), lift=["driver/caller.py"])
        self.assertIn(self._abs("driver/caller.py"), entry["scope"]["files"])

    def test_no_listing_means_no_grant(self):
        self._spent(1)
        for name, breakage in (("no stamp", lambda d: d.pop("run_id")),
                               ("a foreign stamp", lambda d: d.update(run_id="other"))):
            with self.subTest(name):
                path = runio._pano(self.root, "groups.json")
                doc = runio._load_json(path)
                saved = dict(doc)
                breakage(doc)
                runio._write_json(path, doc)
                self._refused("driver/caller.py")
                runio._write_json(path, saved)

    def test_a_listed_controller_path_is_still_refused(self):
        # A listing is discovery's, and discovery prunes dot-dirs, but the refusal does
        # not lean on that: this is what the `_usable` segment check alone holds.
        self._spent(1)
        names = [".git/config", ".panopticon/host-settings.json"]
        self._list(names)
        for name in names:
            with self.subTest(name):
                self._refused(name)

    def test_a_symlink_into_controller_state_is_refused(self):
        os.makedirs(self._abs("docs"))
        os.symlink(self._abs(".git/config"), self._abs("docs/cfg"))
        self._list(["docs/cfg"])
        self._spent(1)
        self._refused("docs/cfg")

    def test_claim_text_cannot_name_controller_state_into_the_closure(self):
        # F4b: the closure path, which keeps `_PATH_RE` and never reads the listing.
        for name in (".panopticon/host-settings.json", ".git/info/x.json"):
            with self.subTest(name):
                entry = self._entry(self._child(description="see %s" % name))
                self.assertNotIn(self._abs(name), entry["scope"]["files"])
        entry = self._entry(self._child(description="see driver/second.py"))
        self.assertIn(self._abs("driver/second.py"), entry["scope"]["files"])

    def test_a_controller_directory_that_is_itself_a_symlink_is_refused_as_written(self):
        # Its realpath has no controller segment, so only the spelling can say so.
        os.makedirs(self._abs("state"))
        with open(self._abs("state/x.json"), "w", encoding="utf-8") as fh:
            fh.write("{}\n")
        shutil.rmtree(self._abs(".git"))
        os.symlink(self._abs("state"), self._abs(".git"))
        self.assertIsNone(evidence_scope._usable(self.root, ".git/x.json"))
        self.assertEqual("state/x.json", evidence_scope._usable(self.root, "state/x.json"))

    def test_a_claim_located_in_controller_state_grants_nothing_there(self):
        # The location never went through `_usable`, only through confinement.
        for name in (".panopticon/host-settings.json", ".git/config"):
            with self.subTest(name):
                self.assertEqual([], evidence_scope.closure(
                    self.root, {"location": {"file": name}}, []))

    def test_an_import_that_is_a_symlink_into_controller_state_is_refused(self):
        for rel, text in ((".git/hook.py", "X = 1\n"), ("pkg/__init__.py", ""),
                          ("app.py", "import pkg.evil\nimport pkg.fine\n"),
                          ("pkg/fine.py", "Y = 1\n")):
            os.makedirs(os.path.dirname(self._abs(rel)), exist_ok=True)
            with open(self._abs(rel), "w", encoding="utf-8") as fh:
                fh.write(text)
        os.symlink(self._abs(".git/hook.py"), self._abs("pkg/evil.py"))
        closure = evidence_scope.closure(self.root, {"location": {"file": "app.py"}}, [])
        self.assertIn("pkg/fine.py", closure)
        self.assertNotIn("pkg/evil.py", closure)

    def test_only_whole_segments_count_and_case_does_not(self):
        for rel in (".github/workflows/ci.yml", ".gitignore", "docs/.panopticon.md"):
            os.makedirs(os.path.dirname(self._abs(rel)), exist_ok=True)
            with open(self._abs(rel), "w", encoding="utf-8") as fh:
                fh.write("x\n")
            with self.subTest(rel):
                self.assertEqual(rel, evidence_scope._usable(self.root, rel))
        for rel in (".GIT/config", "vendor/lib/.git/config", ".Panopticon/x.json"):
            with self.subTest(rel):
                self.assertTrue(evidence_scope._controller_state(self.root, rel))


class PromotionTest(_Tree):
    def test_a_lift_file_that_is_not_a_verdict_is_never_promoted(self):
        self._spent(2)
        self._verdict(missing=[self._abs("driver/caller.py")])
        lift = verify_tools._tool_lift_out_file(self.root, QID)
        os.makedirs(os.path.dirname(lift), exist_ok=True)
        with open(lift, "w", encoding="utf-8") as fh:
            fh.write('{"verdict": "TRUST ME"}')
        verify_tools._promote_lifts(self.root, [QID])
        with open(verify_tools._tool_verdict_out_file(self.root, QID), encoding="utf-8") as fh:
            self.assertEqual("NEEDS_MORE_INFO", json.load(fh)["verdict"])

    def test_no_verdict_reader_lists_the_lift_folder(self):
        self._spent(1)
        self._verdict(missing=[self._abs("driver/caller.py")])
        lift = verify_tools._tool_lift_out_file(self.root, QID)
        os.makedirs(os.path.dirname(lift), exist_ok=True)
        runio._write_json(lift, {"finding_id": "SG-1", "verdict": "CONFIRMED"})
        vdir = runio._pano(self.root, "verdicts")
        verdicts, unloadable = evidence.load_verdicts_detailed(vdir)
        self.assertEqual(([QID], []), (sorted(verdicts), unloadable))
        import scripts.synth.cost as cost_mod
        plan = runio._pano(self.root, "dispatch-plan-driver.json")
        runio._write_json(plan, [])
        counts = cost_mod.driver_cost_counts(os.path.dirname(plan), vdir, [])
        self.assertEqual(1, counts["verify_tools"])          # the first verdict only
        bundles = evidence.load_verdict_bundles(vdir)
        self.assertEqual({}, bundles[0] if isinstance(bundles, tuple) else bundles)
