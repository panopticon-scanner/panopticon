"""Driver delta and integrity integration tests."""
import contextlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import scripts.phases.runio as runio
import scripts.phases.engine as engine
import scripts.phases.requests as requests
import scripts.phases.discovery as discovery
import scripts.phases.coverage as coverage
import scripts.phases.review as review
import scripts.phases.verify as verify
import scripts.phases.synthesize as synthesize
import scripts.phases.validate as validate_phase

from tests._test_helpers import write_host_evidence
import scripts.driver as driver
import scripts.diff_map as diff_map
import scripts.groups_schema as groups_schema
import scripts.run_manifest as run_manifest



from tests.driver_helpers import _ALL_PROVEN, start_module_patches

def setUpModule():
    global _run_probes_patch, _readiness_docker_patch
    _run_probes_patch, _readiness_docker_patch = start_module_patches()


def tearDownModule():
    _run_probes_patch.stop()
    _readiness_docker_patch.stop()


class TestDriverDeltaEndToEnd(unittest.TestCase):
    """P6.3: the LAST 5.0 driver e2e -- proves the delta (`-c`) + `--pr` paths
    against a REAL git repo, no live `gh`. Mirrors
    TestDriverSingleScopeEndToEnd's real-git-repo + self-write harness
    (P6.2), scoped to `changed` instead of `group`:

    - `-c` delta: the real `discovery.py --repo-scan --scope-changed
      --base` subprocess restricts groups.json to the one changed file and
      emits `.panopticon/diff-hunks.json`; the run-loop reaches a graded
      report whose delta block is populated and whose gate is scoped to the
      on-diff findings only (a pre-existing off-diff HIGH that would flip
      `fail_on: high` to FAIL never reaches the gate).
    - `--pr` resume: `resolve_review_root(pr=...)` is idempotent over the
      deterministic worktree (diff_map._worktree_dir, P6.1) and
      `validate_execute` releases it -- function-level, mocking
      diff_map.acquire_pr/release_worktree since a live `gh` PR isn't
      available in tests.
    - requires-setup: `-c` on a repo with no committed groups.yml fails
      loudly, same as P6.2's group-scope case.
    """

    RUN_ID = "RID"

    def _repo_with_changed_file(self):
        """A committed two-group matrix repo (Auth untouched; Checkout's
        cart.py untouched too) plus one UNCOMMITTED edit to Checkout/pay.py --
        the `-c` delta's changed file. Returns (repo_dir, base_sha): base_sha
        anchors `--scope-changed --base`; HEAD stays pinned there (the edit is
        uncommitted, like a live `-c` invocation), so diff-hunks.json's
        includes_uncommitted comes back True.

        pay.py is padded to 60 lines: the edit lands at line 2 (an on-diff
        finding is placed there), and a pre-existing finding is placed at
        line 58 -- well outside the default +/-5 diff-context tolerance
        window around the line-2 hunk, so it classifies off-diff.
        """
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        for p in ("src/auth/login.py", "src/checkout/cart.py"):
            full = os.path.join(d, *p.split("/"))
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w") as fh:
                fh.write("def f():\n    return 1\n")
        pay_lines = ["def charge(amount):", "    return amount", "",
                     "def refund(amount):", "    return -amount"]
        pay_lines += ["# pad line %d" % i for i in range(6, 61)]
        pay_path = os.path.join(d, "src", "checkout", "pay.py")
        os.makedirs(os.path.dirname(pay_path), exist_ok=True)
        with open(pay_path, "w") as fh:
            fh.write("\n".join(pay_lines) + "\n")
        os.makedirs(os.path.join(d, ".panopticon"))
        write_host_evidence(d, _ALL_PROVEN)
        with open(os.path.join(d, "panopticon.yml"), "w") as fh:
            fh.write("version: 1\n")
            # #5.0-11: GLOBAL_FLOOR folds ARC/COD/DAT/TST into every group's
            # effective panel set. Deliberately NOT excluded here (unlike the
            # other two matrix e2e fixtures): audit_floor_cells checks the
            # DISCLOSED floor (declared | GLOBAL_FLOOR), not the exclude-netted
            # effective set, so excluding a global-floor domain leaves it
            # "on the floor" with no findings file -> missing_floor -> the
            # gate downgrades PASS to INCONCLUSIVE, which would defeat this
            # test's on-diff-vs-all gate-scope comparison (its whole point).
            # Instead Checkout's review cell fires all 5 floor domains and
            # _self_write_review_two_findings below services all of them
            # (SEC real, the other 4 empty) so every floor cell is present.
            fh.write(
                "groups:\n"
                "  Auth:\n    match: ['src/auth/**']\n    panels: [SEC]\n"
                "  Checkout:\n    match: ['src/checkout/**']\n    panels: [SEC]\n")
        subprocess.run(["git", "init", "-q"], cwd=d, check=True, timeout=30)
        subprocess.run(["git", "add", "-A"], cwd=d, check=True, timeout=30)
        subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t",
                        "commit", "-qm", "x"], cwd=d, check=True, timeout=30)
        base_sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=d,
                                  capture_output=True, text=True,
                                  check=True, timeout=30).stdout.strip()
        # Uncommitted edit -- the -c delta's live-tree change.
        pay_lines[1] = "    return amount * 2  # bumped"
        with open(pay_path, "w") as fh:
            fh.write("\n".join(pay_lines) + "\n")
        return d, base_sha

    def _manifest(self, base):
        return {"run_id": self.RUN_ID, "host": "claude", "security_mode": "standard",
                "flags": {"fail_on": "high"},
                "scope": {"mode": "changed", "target": None}, "base": base}

    def _self_write_scout(self, entry):
        runio._write_json(entry["out_file"], {"group": "Checkout", "domains": ["SEC"]})

    def _self_write_review_two_findings(self, entries):
        """SEC gets one on-diff LOW (pay.py's edited line 2) and one
        pre-existing HIGH (line 58, far outside the diff-context window).
        Combined cell score (0 + 5*0.8 = 4.0) stays under F_b (8.0), so no
        backup round is summoned. #5.0-11: GLOBAL_FLOOR also fires
        ARC/COD/DAT/TST for this group -- service those with empty cells (no
        findings) so every floor cell is present (audit_floor_cells) without
        adding score-engaging noise (they never reach F_p, so verify only
        ever dispatches for SEC)."""
        for e in entries:
            domain = e["id"].rsplit("-", 1)[-1]
            if domain == "SEC":
                findings = [
                    {"title": "on-diff nit", "severity": "LOW", "domain": "SEC",
                     "code": "SEC-A1A", "category": "authz",
                     "location": {"file": "src/checkout/pay.py", "line_start": 2}},
                    {"title": "pre-existing gap", "severity": "HIGH", "domain": "SEC",
                     "code": "SEC-A2A", "category": "authz",
                     "location": {"file": "src/checkout/pay.py", "line_start": 58}},
                ]
            else:
                findings = []
            runio._write_json(e["out_file"], {
                "findings": findings,
                "_panopticon": {"run_id": self.RUN_ID, "role": "domain_panel",
                                "domain": domain, "group": "Checkout"}})

    def _self_write_verify_all(self, d, manifest, entry):
        cell = review._load_cell_findings(d, manifest, "Checkout", "SEC")
        runio._write_json(entry["out_file"], {
            "verdicts": [{"finding_id": f["id"], "verdict": "CONFIRMED",
                          "reasoning": "verified"} for f in cell],
            "_panopticon": {"run_id": self.RUN_ID, "role": "domain_advisor",
                            "domain": "SEC", "group": "Checkout", "stage": "primary"}})

    def test_changed_scope_restricts_matrix_emits_diff_hunks_and_report_has_delta(self):
        d, base_sha = self._repo_with_changed_file()
        manifest = self._manifest(base_sha)

        # discovery: the real discovery.py --repo-scan --scope-changed
        # --base subprocess -- restricts groups.json to the one changed file.
        result = discovery.discovery_execute(d, manifest)
        self.assertEqual(result.kind, "advanced")
        groups_json = runio._load_json(runio._pano(d, "groups.json"))
        names = {g["name"] for g in groups_json["groups"]}
        files = sorted(f for g in groups_json["groups"] for f in g["files"])
        self.assertEqual(names, {"Checkout"})            # Auth excluded entirely
        self.assertEqual(files, ["src/checkout/pay.py"])  # cart.py unchanged, excluded

        # discovery.py's on-diff hunk map, alongside groups.json.
        hunks_path = runio._pano(d, "diff-hunks.json")
        self.assertTrue(os.path.isfile(hunks_path))
        hunks = runio._load_json(hunks_path)
        self.assertEqual(hunks["base"], base_sha)
        self.assertEqual(hunks["base_commit"], base_sha)
        self.assertTrue(hunks["includes_uncommitted"])
        self.assertIn("src/checkout/pay.py", hunks["hunks"])

        # coverage: scout checkpoint then floor+scout (SEC as committed, plus
        # #5.0-11's GLOBAL_FLOOR ARC/COD/DAT/TST on every group)
        cov = coverage.coverage_execute(d, manifest)
        self.assertEqual(cov.checkpoint, "scout")
        self.assertIsNone(cov.group)                 # #1056: scouts batched, group=None
        req = requests.load_dispatch_request(d)
        for e in req["entries"]:
            self._self_write_scout(e)
        self.assertEqual(coverage.coverage_execute(d, manifest).kind, "advanced")
        self.assertTrue(coverage.coverage_done(d, manifest))

        # review checkpoint -- 2 cells (Checkout/SEC committed + universal COD).
        # #5.0-19: pay.py is a single, surfaceless file, so the global floor's
        # ARC/DAT/TST are surface-gated off; self-write both findings into SEC
        # (scoped to pay.py) and an empty cell into COD.
        r = review.review_execute(d, manifest)
        self.assertEqual(r.checkpoint, "review")
        req = requests.load_dispatch_request(d)
        self.assertEqual(len(req["entries"]), 2)
        self._self_write_review_two_findings(req["entries"])
        self.assertTrue(review.review_done(d, manifest))

        # verify checkpoint -- primary only (combined score < F_b, no backup)
        v = verify.verify_execute(d, manifest)
        self.assertEqual(v.checkpoint, "verify")
        req = requests.load_dispatch_request(d)
        self.assertEqual(len(req["entries"]), 1)
        self._self_write_verify_all(d, manifest, req["entries"][0])
        self.assertEqual(verify.verify_execute(d, manifest).kind, "advanced")
        self.assertTrue(verify.verify_done(d, manifest))

        # synthesize -> a graded report with a populated delta block.
        self.assertEqual(synthesize.synthesize_execute(d, manifest).kind, "advanced")
        report = runio._load_json(runio._pano(d, "report.json"))

        delta_meta = report["meta"]["coverage"]["delta"]
        self.assertIsNotNone(delta_meta)
        self.assertEqual(delta_meta["base"], base_sha)
        self.assertTrue(delta_meta["includes_uncommitted"])
        self.assertEqual(delta_meta["files_changed"], 1)
        self.assertEqual(delta_meta["on_diff_total"], 1)
        self.assertEqual(delta_meta["pre_existing_total"], 1)

        delta_summary = report["summary"]["delta"]
        self.assertIsNotNone(delta_summary)
        self.assertEqual(delta_summary["on_diff"]["low"], 1)
        self.assertEqual(delta_summary["pre_existing"]["high"], 1)

        on_diff_f = next(f for f in report["findings"] if f["severity"] == "LOW")
        pre_existing_f = next(f for f in report["findings"] if f["severity"] == "HIGH")
        self.assertTrue(on_diff_f["delta"]["on_diff"])
        self.assertFalse(pre_existing_f["delta"]["on_diff"])
        self.assertEqual(on_diff_f["evidence"]["status"], "advisor_confirmed")
        self.assertEqual(pre_existing_f["evidence"]["status"], "advisor_confirmed")

        # gate scoped on-diff (the default --gate-scope): fail_on=high WOULD
        # FAIL on the pre-existing HIGH if it leaked into the gate -- it
        # doesn't, only the on-diff LOW is gate-eligible, so the gate stays
        # clean of it.
        self.assertEqual(report["summary"]["gate"], "PASS")

        # Item 7 (load-bearing proof): flip --gate-scope to "all" on the SAME
        # artifacts and the pre-existing off-diff HIGH now reaches the gate ->
        # FAIL. This proves the default on-diff scoping is what produced the PASS
        # (not a vacuous pass), i.e. gate scope actually changes the outcome.
        manifest["flags"]["gate_scope"] = "all"
        self.assertEqual(synthesize.synthesize_execute(d, manifest).kind, "advanced")
        report_all = runio._load_json(runio._pano(d, "report.json"))
        self.assertEqual(report_all["summary"]["gate"], "FAIL")

    def test_changed_scope_without_committed_groups_yml_raises_loud_setup_error(self):
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        os.makedirs(os.path.join(d, ".panopticon"))   # no groups.yml -- un-setup repo
        manifest = self._manifest(base="deadbeef")
        with self.assertRaises(runio.DriverError) as cm:
            discovery.discovery_execute(d, manifest)
        self.assertIn("panopticon setup", str(cm.exception))

    def test_pr_resolve_review_root_worktree_is_idempotent(self):
        """resolve_review_root(pr=...) acquires the deterministic per-(repo,
        PR) worktree (diff_map._worktree_dir, P6.1); a second acquire for the
        SAME (repo, PR) resumes the SAME path without a second underlying
        create. `diff_map.acquire_pr` is mocked (no live `gh`) with a fake
        that mirrors the REAL function's own idempotency contract: reuse an
        already-materialized deterministic worktree rather than recreating
        it, using the real (un-mocked) `_worktree_dir` to compute the path."""
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        subprocess.run(["git", "init", "-q"], cwd=d, check=True, timeout=30)
        wt = diff_map._worktree_dir(d, 7)
        self.addCleanup(lambda: shutil.rmtree(wt, ignore_errors=True))
        created = {"count": 0}

        def fake_acquire_pr(pr_number, repo=".", runner=subprocess.run):
            path = diff_map._worktree_dir(repo, pr_number)
            if not os.path.isdir(path):
                created["count"] += 1
                os.makedirs(path)
            return {"worktree": path, "base": "main", "head_sha": "deadbeef"}

        with mock.patch.object(diff_map, "acquire_pr",
                               side_effect=fake_acquire_pr) as m:
            root1, worktree1, base1 = runio.resolve_review_root(d, pr=7)
            root2, worktree2, base2 = runio.resolve_review_root(d, pr=7)

        self.assertEqual(m.call_count, 2)
        self.assertEqual(m.call_args_list[0].args[0], 7)
        self.assertEqual(m.call_args_list[0].kwargs["repo"], d)
        self.assertEqual(root1, wt)
        self.assertEqual(worktree1, wt)
        self.assertEqual(base1, "main")
        self.assertEqual(root2, wt)
        self.assertEqual(worktree2, wt)
        self.assertEqual(base2, "main")
        self.assertEqual(created["count"], 1)   # 2nd acquire reused, no re-create

    def test_validate_does_not_release_pr_worktree(self):
        """Ruling A: validate_execute does NOT release manifest["worktree"] --
        the PR worktree IS the review root, so releasing here would delete
        report.json + the manifest mid-machine. It still writes validate.json and
        advances on a clean tree; release-on-complete is covered at the run()
        level (test_run_finalizes_worktree_only_on_complete)."""
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        subprocess.run(["git", "init", "-q"], cwd=d, check=True, timeout=30)
        validate_phase.capture_tree_baseline(d)   # real git status --porcelain, clean
        wt = diff_map._worktree_dir(d, 7)
        manifest = {"run_id": self.RUN_ID, "worktree": wt}

        with mock.patch.object(diff_map, "release_worktree") as rel:
            result = validate_phase.validate_execute(d, manifest)

        self.assertEqual(result.kind, "advanced")
        rel.assert_not_called()
        validate = runio._load_json(runio._pano(d, "validate.json"))
        self.assertTrue(validate["tree_clean"])
        self.assertEqual(validate["unexpected_changes"], [])


class TestDriverIntegrityWiring(unittest.TestCase):
    """#5.0-16: the driver emits dispatch-plan-driver.json (H2, reconcile) and
    out-file-hashes.json (H3, content snapshot) so both anti-tampering controls
    -- dead on the driver path when neither artifact was written -- actually
    run. Drives review->verify->synthesize via self-writes (like
    TestDriverRunLoopEndToEnd) and asserts on the graded report's
    meta.integrity."""

    RUN_ID = "RID"

    def _repo(self, effective):
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        os.makedirs(os.path.join(d, "src"))
        with open(os.path.join(d, "src", "app.py"), "w") as fh:
            fh.write("def f():\n    return 1\n")
        os.makedirs(os.path.join(d, ".panopticon"))
        # #1511 BR-06: PERSIST the manifest before writing any run artifact.
        # These tests used an in-memory manifest dict that was never written, so
        # `_run_tag` found nothing and every `_pano` call resolved the flat
        # top-level layout -- the class asserted the two anti-tamper controls
        # worked on a code path production never takes, and the per-run wiring
        # bug (#1511) sailed through a suite that appeared to cover it.
        self._m = run_manifest.build_manifest(
            target=d, review_root=d, host="claude", security_mode="standard",
            run_id=self.RUN_ID, flags={"fail_on": "high"})
        run_manifest.write_manifest(d, self._m)
        self._run_dir = os.path.join(d, ".panopticon", "runs",
                                     run_manifest.run_tag(self._m))
        # #1344 F3: host-capabilities.json is itself a per-run artifact once a
        # manifest is on disk -- write it AFTER write_manifest above, or it
        # lands beside the run folder instead of inside it, same as #1511.
        write_host_evidence(d, _ALL_PROVEN)
        runio._write_json(runio._pano(d, "groups.json"),
                           {"groups": [{"name": "app", "files": ["src/app.py"]}]})
        with open(os.path.join(d, "panopticon.yml"), "w") as fh:
            fh.write("version: 1\n")
            fh.write("groups:\n  app:\n    match: ['src/**']\n")   # #1092 healthy resume
        runio._write_json(runio._pano(d, "coverage-app.json"),
                           {"group": "app", "floor": effective,
                            "effective": effective, "run_id": self.RUN_ID})
        # Run artifacts must land INSIDE the run folder, not beside it.
        self.assertTrue(os.path.isfile(os.path.join(self._run_dir, "groups.json")),
                        "fixture wrote run artifacts to the flat layout")
        # A stale top-level snapshot from an earlier run: if any of this class's
        # assertions can be satisfied by reading it, the wiring is wrong.
        runio._write_json(
            os.path.join(d, ".panopticon", "out-file-hashes.json"),
            {os.path.join(self._run_dir, "findings-app-QAL.json"): "0" * 64})
        return d

    def _manifest(self):
        return self._m

    def _cell_payload(self, domain, title="nit"):
        # QAL LOW scores below F_p, so verify engages nothing -- the only reason
        # a gate could go INCONCLUSIVE is the integrity signal under test.
        return {"findings": [{"title": title, "severity": "LOW", "domain": domain,
                              "code": domain + "-A1A", "category": "style",
                              "location": {"file": "src/app.py", "line_start": 1}}],
                "_panopticon": {"run_id": self.RUN_ID, "role": "domain_panel",
                                "domain": domain, "group": "app"}}

    def _drive_review(self, d, m, domain="QAL"):
        r = review.review_execute(d, m)
        self.assertEqual(r.checkpoint, "review")
        for e in requests.load_dispatch_request(d)["entries"]:
            runio._write_json(e["out_file"], self._cell_payload(domain))
        self.assertTrue(review.review_done(d, m))

    def test_clean_run_integrity_not_inconclusive(self):
        d = self._repo(["QAL"])
        m = self._manifest()
        self._drive_review(d, m)
        # verify engages nothing -> advances, but snapshots at its top first
        self.assertEqual(verify.verify_execute(d, m).kind, "advanced")
        self.assertTrue(verify.verify_done(d, m))
        self.assertTrue(os.path.isfile(runio._pano(d, "dispatch-plan-driver.json")))
        self.assertTrue(os.path.isfile(runio._pano(d, "out-file-hashes.json")))
        self.assertEqual(synthesize.synthesize_execute(d, m).kind, "advanced")
        report = runio._load_json(runio._pano(d, "report.json"))
        integ = report["meta"]["integrity"]
        self.assertGreaterEqual(integ["plans_seen"], 1)
        self.assertEqual(integ["unexpected_findings_files"], [])
        self.assertEqual(integ["missing_planned_files"], [])
        self.assertEqual(integ["invalid_dispatch_plans"], [])
        self.assertEqual(integ["content_mismatched_files"], [])
        self.assertEqual(integ["empty_dispatch_plans"], 0)
        self.assertGreaterEqual(integ["content_hashes_checked"], 1)
        self.assertNotEqual(report["summary"]["gate"], "INCONCLUSIVE")

    def test_h2_injected_undeclared_findings_file_forces_inconclusive(self):
        d = self._repo(["QAL"])
        m = self._manifest()
        self._drive_review(d, m)
        verify.verify_execute(d, m)   # snapshot taken over the DECLARED cells
        # a rogue reviewer writes a cell the plan never declared
        runio._write_json(runio._pano(d, "findings-app-BOGUS.json"),
                           {"findings": [], "_panopticon": {
                               "run_id": self.RUN_ID, "role": "domain_panel",
                               "domain": "BOGUS", "group": "app"}})
        synthesize.synthesize_execute(d, m)
        report = runio._load_json(runio._pano(d, "report.json"))
        integ = report["meta"]["integrity"]
        self.assertTrue(any("findings-app-BOGUS.json" in p
                            for p in integ["unexpected_findings_files"]),
                        integ["unexpected_findings_files"])
        self.assertEqual(report["summary"]["gate"], "INCONCLUSIVE")

    def test_h3_content_substitution_after_snapshot_forces_inconclusive(self):
        d = self._repo(["QAL"])
        m = self._manifest()
        self._drive_review(d, m)
        verify.verify_execute(d, m)   # snapshot the ORIGINAL bytes now
        self.assertTrue(os.path.isfile(runio._pano(d, "out-file-hashes.json")))
        # substitute the DECLARED cell's bytes after the snapshot
        cell = runio._pano(d, "findings-app-QAL.json")
        runio._write_json(cell, self._cell_payload("QAL", title="INJECTED"))
        synthesize.synthesize_execute(d, m)
        report = runio._load_json(runio._pano(d, "report.json"))
        integ = report["meta"]["integrity"]
        # still a DECLARED file -> not unexpected; only the content check fires
        self.assertEqual(integ["unexpected_findings_files"], [])
        self.assertTrue(any("findings-app-QAL.json" in p
                            for p in integ["content_mismatched_files"]),
                        integ["content_mismatched_files"])
        self.assertEqual(report["summary"]["gate"], "INCONCLUSIVE")

    def test_resume_is_idempotent_snapshot_one_way_plan_stable(self):
        d = self._repo(["QAL"])
        m = self._manifest()
        self._drive_review(d, m)
        plan_path = runio._pano(d, "dispatch-plan-driver.json")
        plan1 = runio._load_json(plan_path)
        review.review_execute(d, m)   # second pass: plan write is a no-op
        self.assertEqual(runio._load_json(plan_path), plan1)
        verify.verify_execute(d, m)   # first snapshot
        hashes_path = runio._pano(d, "out-file-hashes.json")
        snap1 = runio._load_json(hashes_path)
        # substitute a declared cell, then a SECOND verify_execute must NOT
        # re-hash -- re-hashing would silently mask the substitution
        with open(runio._pano(d, "findings-app-QAL.json"), "a") as fh:
            fh.write("\n")
        verify.verify_execute(d, m)
        self.assertEqual(runio._load_json(hashes_path), snap1)


class TestDriverHardening(unittest.TestCase):
    """#1033: small driver robustness residuals from the P3 tail."""

    def _pano_dir(self):
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        os.makedirs(runio._pano(d))
        return d

    def test_phase_result_rejects_unknown_kind(self):   # #5
        for kind in ("advanced", "checkpoint"):
            self.assertEqual(engine.PhaseResult(kind=kind).kind, kind)
        for bad in ("advance", "complete", "error", ""):
            with self.assertRaises(ValueError):
                engine.PhaseResult(kind=bad)

    def test_next_verb_is_removed(self):   # #10
        with self.assertRaises(SystemExit):
            driver.build_parser().parse_args(["next", "."])
        self.assertEqual(driver.build_parser().parse_args(["run", "."]).verb, "run")

    def test_committed_groups_parsed_once_per_version(self):   # #7
        d = self._pano_dir()
        with open(os.path.join(d, "panopticon.yml"), "w", encoding="utf-8") as fh:
            fh.write("version: 1\n")
            fh.write("groups:\n  Auth:\n    match: ['src/auth/**']\n")
        runio._parse_committed_groups.cache_clear()
        self.addCleanup(runio._parse_committed_groups.cache_clear)
        calls = []
        real = groups_schema.parse_groups
        with mock.patch("scripts.groups_schema.parse_groups",
                        side_effect=lambda doc: calls.append(1) or real(doc)):
            runio.load_committed_groups(d)
            runio.load_committed_groups(d)      # same file -> cache hit
        self.assertEqual(len(calls), 1)

    def test_phase_driver_error_is_status_error(self):   # #9 (run level)
        d = self._pano_dir()

        def boom_exec(r, m):
            raise runio.DriverError("kaboom")
        boom = engine.Phase(name="discovery", kind="deterministic",
                            done=lambda r, m: False, execute=boom_exec)
        args = driver.build_parser().parse_args(["run", d])
        status = driver.run(args, phases=(boom,))
        self.assertEqual(status["status"], "error")
        self.assertIn("kaboom", status["message"])

    def test_main_driver_error_prints_status_and_exits_1(self):   # #9 (CLI level)
        # no committed groups.yml -> discovery raises DriverError -> main() prints
        # ONE status:error JSON line (no traceback) and returns exit code 1.
        d = self._pano_dir()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = driver.main(["run", d])
        self.assertEqual(rc, 1)
        status = json.loads(buf.getvalue().strip().splitlines()[-1])
        self.assertEqual(status["status"], "error")

    def test_spawn_oserror_becomes_driver_error(self):   # #6
        d = self._pano_dir()
        with open(os.path.join(d, "panopticon.yml"), "w", encoding="utf-8") as fh:
            fh.write("version: 1\n")
            fh.write("groups:\n  Auth:\n    match: ['**/*.py']\n")
        with mock.patch("scripts.phases.child._run_child",
                        side_effect=runio.DriverError("could not spawn: ENOENT")):
            with self.assertRaises(runio.DriverError) as ctx:
                discovery.discovery_execute(d, {"security_mode": "standard",
                                             "scope": {"mode": "repo"}})
        self.assertIn("could not spawn", str(ctx.exception))

    def test_load_ocrdb_bundle_wraps_valueerror(self):   # #1034/#1
        # a malformed OCRDb bundle on the driver path becomes a DriverError
        # (clean status:error), not a raw traceback crashing the phase.
        with mock.patch("scripts.ocrdb.load_bundle",
                        side_effect=ValueError("bundle malformed")):
            with self.assertRaises(runio.DriverError):
                runio._load_ocrdb_bundle()

    def test_render_criteria_gates_and_falls_back(self):   # #1035
        b = {"domains": {"SEC": {"entries": {
            "SEC-A1A": {"name": "cmd-inj", "criteria": "qualifies when unsanitized"},
            "SEC-A1B": {"name": "nocrit"}}}}}
        out = review._render_criteria(b, "SEC")
        self.assertIn("SEC-A1A", out)
        self.assertIn("qualifies when unsanitized", out)
        self.assertNotIn("SEC-A1B", out)              # no criteria -> omitted
        none = review._render_criteria(
            {"domains": {"SEC": {"entries": {"SEC-A1B": {"name": "nocrit"}}}}}, "SEC")
        self.assertIn("no explicit OCRDb criteria", none)   # never blank

    def test_verify_entry_carries_the_criteria_lens(self):   # #1035
        b = {"domains": {"SEC": {"entries": {
            "SEC-A1A": {"name": "cmd-inj", "default_severity": "HIGH",
                        "criteria": "CRITSENTINEL when the sink is reached"}}}}}
        cell = [{"id": "SEC-1", "title": "t", "severity": "HIGH", "domain": "SEC",
                 "category": "x", "location": {"file": "a.py", "line_start": 1}}]
        entry = verify._verify_entry("/repo", {"run_id": "R", "host": "claude"},
                                     "app", "SEC", ["a.py"], cell, "claude", b,
                                     "primary")
        self.assertIn("CRITSENTINEL", entry["prompt"])

