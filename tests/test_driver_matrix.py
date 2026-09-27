"""Matrix review, verify, loop, and scope integration tests."""
import argparse
import json
import os
import shutil
import subprocess
import tempfile
import unittest

import scripts.phases.runio as runio
import scripts.phases.requests as requests
import scripts.phases.discovery as discovery
import scripts.phases.coverage as coverage
import scripts.phases.review as review
import scripts.phases.verify as verify
import scripts.phases.synthesize as synthesize

from tests._test_helpers import write_host_evidence
import scripts.driver as driver
import scripts.run_manifest as run_manifest

from tests.tools.git_repo import make_git_repo


from tests.driver_helpers import _ALL_PROVEN, start_module_patches

def setUpModule():
    global _run_probes_patch, _readiness_docker_patch
    _run_probes_patch, _readiness_docker_patch = start_module_patches()


def tearDownModule():
    _run_probes_patch.stop()
    _readiness_docker_patch.stop()


class TestReviewMatrixEndToEnd(unittest.TestCase):
    """Task 6: the whole 5.0 review matrix, end to end, against the real
    driver + discovery + synthesize subprocesses -- discovery -> coverage
    (+scout domains) -> tools -> review (cells fire) -> verify (no-op) ->
    synthesize -> a real report.json with (domain, code) findings."""

    def _repo(self):
        # #5.0-11: GLOBAL_FLOOR folds ARC/COD/DAT/TST into every group's
        # effective panel set; exclude the three non-COD floor members so
        # this fixture keeps its original single-cell (COD-only) shape.
        return make_git_repo(
            test_case=self,
            files={"src/app.py": "def f():\n    return 1\n"},
            groups_yml=("groups:\n"
                        "  Core:\n"
                        "    match: ['src/**']\n"
                        "    panels: [COD]\n"
                        "    exclude: [ARC, DAT, TST]\n"),
            branch=None,
            user_email="t@t",
            user_name="t",
        )

    def _args(self, d):
        # --no-tools: this fixture services scout + review checkpoints only; with
        # a tools image present the tool scan would emit the #5.0-03 tool-advisor
        # verify round, which has no servicer here (that path is covered by
        # test_driver_tool_verify.py). Keeps the run deterministic across envs.
        return driver.build_parser().parse_args(
            ["run", d, "--host", "claude", "--no-tools"])

    def _service(self, d, status, run_id):
        # emulate the orchestrator dispatching whatever the checkpoint asked for
        if status.get("checkpoint") == "scout":
            for g, _ in coverage._discovered_groups(d):
                p = runio._pano(d, "scout-%s.json" % g)
                if not os.path.exists(p):
                    runio._write_json(p, {"group": g, "domains": ["COD"]})
        elif status.get("checkpoint") == "review":
            req = runio._load_json(runio._pano(d, "dispatch-request.json"))
            for e in req["entries"]:
                # #5: review cells are batched (group=None on the request); each
                # entry is self-describing -- id == "review-<group>-<domain>".
                grp, dom = e["id"][len("review-"):].rsplit("-", 1)
                runio._write_json(e["out_file"], {
                    "findings": [{"title": "t", "severity": "LOW",
                                  "domain": dom, "code": dom + "-X0X",
                                  "location": {"file": "src/app.py", "line": 1}}],
                    "_panopticon": {"run_id": run_id, "role": "domain_panel",
                                    "domain": dom, "group": grp}})

    def test_review_matrix_reaches_report_with_coded_findings(self):
        d = self._repo()
        args = self._args(d)
        status = driver.run(args)
        run_id = run_manifest.load_manifest(d)["run_id"]
        for _ in range(40):
            if status["status"] == "checkpoint":
                self._service(d, status, run_id)
            status = driver.run(args)
            self.assertNotEqual(status["status"], "error", status.get("message"))
            if status["status"] == "complete":
                break
        self.assertEqual(status["status"], "complete")
        report = runio._load_json(runio._pano(d, "report.json"))
        codes = [f.get("code") for f in report.get("findings", [])]
        self.assertTrue(any(c and c.startswith("COD") for c in codes))
        self.assertEqual(report["meta"]["ocrdb_version"], "0.5.0")


class TestVerifyMatrixEndToEnd(unittest.TestCase):
    """5.0-P5 Slice B Task 5: verify is no longer a no-op. Against the real
    driver functions (verify_execute/verify_done) and
    a real synthesize.py subprocess (phases.synthesize.synthesize_execute) -- mirrors
    TestReviewMatrixEndToEnd's real-artifact style, but drives review/verify
    state directly on disk (as TestVerifyPrimary/TestVerifyBackup in
    test_driver_verify.py do) rather than through the full driver.run()
    checkpoint loop, since a withheld verdict would otherwise re-emit the verify
    checkpoint forever."""

    RUN_ID = "RID"

    def _repo(self, floor):
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        os.makedirs(os.path.join(d, "src"))
        with open(os.path.join(d, "src", "app.py"), "w") as fh:
            fh.write("def f():\n    return 1\n")
        os.makedirs(os.path.join(d, ".panopticon"))
        write_host_evidence(d, _ALL_PROVEN)
        runio._write_json(runio._pano(d, "groups.json"),
                           {"groups": [{"name": "app", "files": ["src/app.py"]}]})
        with open(os.path.join(d, "panopticon.yml"), "w") as fh:
            fh.write("version: 1\n")
            fh.write("groups:\n  app:\n    match: ['src/**']\n")   # #1092 healthy resume
        runio._write_json(runio._pano(d, "coverage-app.json"),
                           {"group": "app", "floor": floor, "effective": floor,
                            "run_id": self.RUN_ID})
        return d

    def _manifest(self):
        return {"run_id": self.RUN_ID, "host": "claude", "security_mode": "standard",
                "flags": {"fail_on": "high"}}

    def _write_cell(self, d, domain, severity="HIGH"):
        # A HIGH finding at the default (POSSIBLE) confidence scores 5*0.8*1 =
        # 4.0 -- above F_p (1.5, engages the primary advisor) but, even once
        # advisor_confirmed (x1.5 -> 6.0), below F_b (8.0, summons a backup) --
        # so the primary round alone settles the cell.
        runio._write_json(runio._pano(d, "findings-app-%s.json" % domain), {
            "findings": [{"title": "issue in %s" % domain, "severity": severity,
                          "domain": domain, "code": domain + "-A1A", "category": "authz",
                          "location": {"file": "src/app.py", "line_start": 1}}],
            "_panopticon": {"run_id": self.RUN_ID, "role": "domain_panel",
                            "domain": domain, "group": "app"}})

    def _confirm_bundle(self, d, manifest, domain, group="app"):
        cell = review._load_cell_findings(d, manifest, group, domain)
        fid = cell[0]["id"]   # driver's own id assignment -- what an advisor echoes
        return json.dumps({"verdicts": [{"finding_id": fid, "verdict": "CONFIRMED",
                                         "reasoning": "verified by advisor"}],
                           "_panopticon": {"run_id": manifest["run_id"],
                                           "role": "domain_advisor", "domain": domain,
                                           "group": group, "stage": "primary"}})

    def _self_write(self, entry, text):
        """Simulate the advisor self-writing its bundle to entry['out_file']."""
        os.makedirs(os.path.dirname(entry["out_file"]), exist_ok=True)
        with open(entry["out_file"], "w") as fh:
            fh.write(text)

    def test_confirmed_verdict_reaches_advisor_confirmed_report(self):
        d = self._repo(["SEC"])
        self._write_cell(d, "SEC")
        manifest = self._manifest()

        result = verify.verify_execute(d, manifest)
        self.assertEqual(result.kind, "checkpoint")
        self.assertEqual(result.checkpoint, "verify")
        req = runio._load_json(runio._pano(d, "dispatch-request.json"))
        entry = req["entries"][0]

        text = self._confirm_bundle(d, manifest, "SEC")
        self._self_write(entry, text)

        result2 = verify.verify_execute(d, manifest)   # drains the (empty) backup round
        self.assertEqual(result2.kind, "advanced")
        self.assertTrue(verify.verify_done(d, manifest))

        synth = synthesize.synthesize_execute(d, manifest)
        self.assertEqual(synth.kind, "advanced")
        report = runio._load_json(runio._pano(d, "report.json"))
        finding = next(f for f in report["findings"] if f.get("domain") == "SEC")
        self.assertEqual(finding["evidence"]["status"], "advisor_confirmed")
        # verify actually resolved the cell -- not left as an unanswered gap.
        self.assertNotEqual(report["summary"]["gate"], "INCONCLUSIVE")

    def test_withheld_engaged_cell_yields_inconclusive(self):
        d = self._repo(["SEC"])
        self._write_cell(d, "SEC")
        manifest = self._manifest()

        result = verify.verify_execute(d, manifest)   # engages SEC, dispatches, never answered
        self.assertEqual(result.checkpoint, "verify")
        self.assertFalse(verify.verify_done(d, manifest))

        synth = synthesize.synthesize_execute(d, manifest)
        self.assertEqual(synth.kind, "advanced")
        report = runio._load_json(runio._pano(d, "report.json"))
        self.assertEqual(report["summary"]["gate"], "INCONCLUSIVE")
        self.assertIn(["app", "SEC"],
                      report["meta"]["coverage"]["verify_matrix"]["unverified_engaged"])

    def test_resume_checkpoint_names_only_the_undone_cell(self):
        d = self._repo(["SEC", "QAL"])
        self._write_cell(d, "SEC")
        self._write_cell(d, "QAL")
        manifest = self._manifest()

        result = verify.verify_execute(d, manifest)   # both cells pending, one dispatch
        self.assertEqual(result.checkpoint, "verify")
        req = runio._load_json(runio._pano(d, "dispatch-request.json"))
        outs = sorted(os.path.basename(e["out_file"]) for e in req["entries"])
        self.assertEqual(outs, ["verdicts-app-QAL.json", "verdicts-app-SEC.json"])
        sec_entry = next(e for e in req["entries"]
                         if e["out_file"].endswith("verdicts-app-SEC.json"))

        text = self._confirm_bundle(d, manifest, "SEC")
        self._self_write(sec_entry, text)

        result2 = verify.verify_execute(d, manifest)
        self.assertEqual(result2.kind, "checkpoint")
        req2 = runio._load_json(runio._pano(d, "dispatch-request.json"))
        outs2 = [os.path.basename(e["out_file"]) for e in req2["entries"]]
        self.assertEqual(outs2, ["verdicts-app-QAL.json"])   # SEC is done; only QAL remains


class TestDriverRunLoopEndToEnd(unittest.TestCase):
    """P6.1: the controller run-loop drives review + verify to a graded report
    purely by self-writing each checkpoint's entries' out_files between driver
    invocations (no persist_returned_verdict, no write_mode)."""

    RUN_ID = "RID"

    def _repo(self, floor):
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        os.makedirs(os.path.join(d, "src"))
        with open(os.path.join(d, "src", "app.py"), "w") as fh:
            fh.write("def f():\n    return 1\n")
        os.makedirs(os.path.join(d, ".panopticon"))
        write_host_evidence(d, _ALL_PROVEN)
        runio._write_json(runio._pano(d, "groups.json"),
                           {"groups": [{"name": "app", "files": ["src/app.py"]}]})
        with open(os.path.join(d, "panopticon.yml"), "w") as fh:
            fh.write("version: 1\n")
            fh.write("groups:\n  app:\n    match: ['src/**']\n")   # #1092 healthy resume
        runio._write_json(runio._pano(d, "coverage-app.json"),
                           {"group": "app", "floor": floor, "effective": floor,
                            "run_id": self.RUN_ID})
        return d

    def _manifest(self):
        return {"run_id": self.RUN_ID, "host": "claude", "security_mode": "standard",
                "flags": {"fail_on": "high"}}

    def _self_write_review(self, d, entry, domain, group="app"):
        runio._write_json(entry["out_file"], {
            "findings": [{"title": "issue in %s" % domain, "severity": "HIGH",
                          "domain": domain, "code": domain + "-A1A", "category": "authz",
                          "location": {"file": "src/app.py", "line_start": 1}}],
            "_panopticon": {"run_id": self.RUN_ID, "role": "domain_panel",
                            "domain": domain, "group": group}})

    def _self_write_verify(self, d, manifest, entry, domain, group="app"):
        cell = review._load_cell_findings(d, manifest, group, domain)
        fid = cell[0]["id"]
        stage = "backup" if entry["out_file"].endswith("-backup.json") else "primary"
        runio._write_json(entry["out_file"], {
            "verdicts": [{"finding_id": fid, "verdict": "CONFIRMED",
                          "reasoning": "verified"}],
            "_panopticon": {"run_id": self.RUN_ID, "role": "domain_advisor",
                            "domain": domain, "group": group, "stage": stage}})

    def test_loop_reaches_graded_report_via_self_writes(self):
        d = self._repo(["SEC"])
        manifest = self._manifest()
        # review checkpoint
        r = review.review_execute(d, manifest)
        self.assertEqual(r.checkpoint, "review")
        req = requests.load_dispatch_request(d)
        for e in req["entries"]:
            self.assertNotIn("write_mode", e)          # unified self-write shape
            self._self_write_review(d, e, "SEC")
        self.assertTrue(review.review_done(d, manifest))
        # verify checkpoint (primary; SEC HIGH is < F_b so no backup)
        v = verify.verify_execute(d, manifest)
        self.assertEqual(v.checkpoint, "verify")
        req = requests.load_dispatch_request(d)
        for e in req["entries"]:
            self._self_write_verify(d, manifest, e, "SEC")
        v2 = verify.verify_execute(d, manifest)
        self.assertEqual(v2.kind, "advanced")
        self.assertTrue(verify.verify_done(d, manifest))
        # synthesize → graded report, advisor_confirmed, not INCONCLUSIVE
        self.assertEqual(synthesize.synthesize_execute(d, manifest).kind, "advanced")
        report = runio._load_json(runio._pano(d, "report.json"))
        finding = next(f for f in report["findings"] if f.get("domain") == "SEC")
        self.assertEqual(finding["evidence"]["status"], "advisor_confirmed")
        self.assertNotEqual(report["summary"]["gate"], "INCONCLUSIVE")

    def test_below_gate_cell_needs_no_verify(self):
        d = self._repo(["QAL"])
        manifest = self._manifest()
        review.review_execute(d, manifest)
        for e in requests.load_dispatch_request(d)["entries"]:
            runio._write_json(e["out_file"], {
                "findings": [{"title": "nit", "severity": "LOW", "domain": "QAL",
                              "code": "QAL-A1A", "category": "style",
                              "location": {"file": "src/app.py", "line_start": 1}}],
                "_panopticon": {"run_id": self.RUN_ID, "role": "domain_panel",
                                "domain": "QAL", "group": "app"}})
        # QAL LOW scores 0 < F_p → verify engages nothing → advances
        self.assertEqual(verify.verify_execute(d, manifest).kind, "advanced")
        self.assertTrue(verify.verify_done(d, manifest))

    def test_scout_checkpoint_is_read_only_return_persist(self):
        # The run's FIRST checkpoint (scout) is the opposite shape from
        # review/verify: the scout agent is read-only and cannot self-write,
        # so the host must capture its RETURNED ScopeProfile JSON and write it
        # to the entry's out_file itself (no write-guard involved). Drive that
        # live — no pre-seeded coverage-<group>.json — through coverage_execute.
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        os.makedirs(os.path.join(d, "src"))
        with open(os.path.join(d, "src", "app.py"), "w") as fh:
            fh.write("def f():\n    return 1\n")
        os.makedirs(os.path.join(d, ".panopticon"))
        runio._write_json(runio._pano(d, "groups.json"),
                           {"groups": [{"name": "app", "files": ["src/app.py"]}]})
        with open(os.path.join(d, "panopticon.yml"), "w") as fh:
            fh.write("version: 1\n")
            fh.write("groups:\n  app:\n    match: ['src/**']\n")   # #1091 healthy resume
        manifest = self._manifest()

        result = coverage.coverage_execute(d, manifest)
        self.assertEqual(result.kind, "checkpoint")
        self.assertEqual(result.checkpoint, "scout")
        self.assertFalse(coverage.coverage_done(d, manifest))

        req = requests.load_dispatch_request(d)
        self.assertEqual(req["checkpoint"], "scout")
        for entry in req["entries"]:
            # host-side return-persist: no self-write, the host writes what
            # the read-only scout returned.
            runio._write_json(entry["out_file"],
                               {"group": "app", "domains": ["SEC"]})

        result2 = coverage.coverage_execute(d, manifest)
        self.assertEqual(result2.kind, "advanced")
        self.assertTrue(coverage.coverage_done(d, manifest))


class TestCliFlagsResolveTheCommittedConfig(unittest.TestCase):
    """#1681 Plan 2: the flags resolve CLI > the config's EFFECTIVE
    contribution > the engine's default, and only what the trust classes let
    through can reach a flag at all. The manifest's anti-drift keys record the
    EFFECTIVE value, so a config edit between resumes is caught the same way a
    flag edit is."""

    def test_flags_take_the_grain_knobs_from_settings_when_the_cli_is_silent(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "panopticon.yml"), "w", encoding="utf-8") as fh:
                fh.write("version: 1\ngroups: {}\nsettings:\n  max_per_group: 12\n"
                         "  fail_on: high\n  gate_scope: all\n")
            args = argparse.Namespace(max_per_group=None, max_verify=None,
                                      fail_on=None, gate_scope=None)
            flags = driver._cli_flags(args, review_root=d)
            self.assertEqual(flags["max_per_group"], 12)
            self.assertEqual(flags["fail_on"], "high")
            self.assertEqual(flags["gate_scope"], "all")
            args = argparse.Namespace(max_per_group=3, max_verify=None,
                                      fail_on="critical", gate_scope=None)
            flags = driver._cli_flags(args, review_root=d)
            self.assertEqual((flags["max_per_group"], flags["fail_on"]), (3, "critical"))

    def test_a_committed_max_verify_no_longer_reaches_the_flags(self):
        # #1681 Plan 2: max_verify is a GATE key now, and the built-in default
        # (uncapped) is stricter than any number -- so the file cannot set it.
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "panopticon.yml"), "w", encoding="utf-8") as fh:
                fh.write("version: 1\ngroups: {}\nsettings:\n  max_verify: 9\n")
            args = argparse.Namespace(max_per_group=None, max_verify=None)
            self.assertIsNone(driver._cli_flags(args, review_root=d)["max_verify"])
            res = driver._resolve_config(args, review_root=d)
            self.assertEqual(res.refused[0]["key"], "max_verify")

    def test_an_operator_only_key_is_refused_and_never_reaches_the_flags(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "panopticon.yml"), "w", encoding="utf-8") as fh:
                fh.write("version: 1\ngroups: {}\nsettings:\n  allow_unenforced: true\n"
                         "  diff_context: 40\n")
            args = argparse.Namespace(max_per_group=None, max_verify=None)
            flags = driver._cli_flags(args, review_root=d)
            self.assertIsNone(flags["allow_unenforced"])
            self.assertIsNone(flags["diff_context"])
            self.assertEqual(sorted(r["key"] for r in
                                    driver._resolve_config(args, review_root=d).refused),
                             ["allow_unenforced", "diff_context"])

    def test_a_committed_tools_false_cannot_switch_the_scanners_off(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "panopticon.yml"), "w", encoding="utf-8") as fh:
                fh.write("version: 1\ngroups: {}\nsettings:\n  tools: false\n")
            args = argparse.Namespace(max_per_group=None, max_verify=None)
            self.assertIsNone(driver._cli_flags(args, review_root=d)["tools"])

    def test_no_review_root_means_no_config_and_no_crash(self):
        args = argparse.Namespace(max_per_group=7, max_verify=None)
        self.assertEqual(driver._cli_flags(args)["max_per_group"], 7)
        self.assertEqual(driver._resolve_config(args, review_root=None), driver.config_schema.EMPTY)


class TestDriverSingleScopeEndToEnd(unittest.TestCase):
    """P6.2: a committed multi-group matrix + `manifest["scope"]` restricts
    the REAL `discovery.py --repo-scan --scope-group` subprocess to the
    target group's files, and the run-loop reaches a graded report from that
    restricted matrix -- mirrors TestDriverRunLoopEndToEnd's self-write
    harness (P6.1), starting one phase earlier at discovery. A repo with no
    committed groups.yml fails discovery loudly (run `panopticon setup`
    first) rather than silently reviewing everything."""

    RUN_ID = "RID"

    def _repo_with_two_groups(self):
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        for p in ("src/auth/login.py", "src/checkout/pay.py", "src/checkout/cart.py"):
            full = os.path.join(d, *p.split("/"))
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w") as fh:
                fh.write("def f():\n    return 1\n")
        os.makedirs(os.path.join(d, ".panopticon"))
        write_host_evidence(d, _ALL_PROVEN)
        with open(os.path.join(d, "panopticon.yml"), "w") as fh:
            fh.write("version: 1\n")
            # #5.0-11: GLOBAL_FLOOR folds ARC/COD/DAT/TST into every group's
            # effective panel set; exclude all four so each group's fixture
            # keeps its original single-cell (SEC-only) shape.
            fh.write(
                "groups:\n"
                "  Auth:\n    match: ['src/auth/**']\n    panels: [SEC]\n"
                "    exclude: [ARC, COD, DAT, TST]\n"
                "  Checkout:\n    match: ['src/checkout/**']\n    panels: [SEC]\n"
                "    exclude: [ARC, COD, DAT, TST]\n")
        # discovery_execute subprocesses the REAL discovery.py --repo-scan,
        # which discovers via `git ls-files` -- commit the fixture so it's seen.
        subprocess.run(["git", "init", "-q"], cwd=d, check=True, timeout=30)
        subprocess.run(["git", "add", "-A"], cwd=d, check=True, timeout=30)
        subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t",
                        "commit", "-qm", "x"], cwd=d, check=True, timeout=30)
        return d

    def _manifest(self):
        return {"run_id": self.RUN_ID, "host": "claude", "security_mode": "standard",
                "flags": {"fail_on": "high"},
                "scope": {"mode": "group", "target": "Checkout"}}

    def _self_write_review(self, entry, domain, group):
        runio._write_json(entry["out_file"], {
            "findings": [{"title": "issue in %s" % domain, "severity": "HIGH",
                          "domain": domain, "code": domain + "-A1A", "category": "authz",
                          "location": {"file": "src/checkout/pay.py", "line_start": 1}}],
            "_panopticon": {"run_id": self.RUN_ID, "role": "domain_panel",
                            "domain": domain, "group": group}})

    def _self_write_verify(self, d, manifest, entry, domain, group):
        cell = review._load_cell_findings(d, manifest, group, domain)
        fid = cell[0]["id"]
        stage = "backup" if entry["out_file"].endswith("-backup.json") else "primary"
        runio._write_json(entry["out_file"], {
            "verdicts": [{"finding_id": fid, "verdict": "CONFIRMED",
                          "reasoning": "verified"}],
            "_panopticon": {"run_id": self.RUN_ID, "role": "domain_advisor",
                            "domain": domain, "group": group, "stage": stage}})

    def test_single_scope_restricts_matrix_and_reaches_graded_report(self):
        d = self._repo_with_two_groups()
        manifest = self._manifest()

        # discovery: the real discovery.py --repo-scan --scope-group Checkout
        # subprocess -- single-scope restricts the matrix to the target group.
        result = discovery.discovery_execute(d, manifest)
        self.assertEqual(result.kind, "advanced")
        groups_json = runio._load_json(runio._pano(d, "groups.json"))
        names = {g["name"] for g in groups_json["groups"]}
        files = sorted(f for g in groups_json["groups"] for f in g["files"])
        self.assertEqual(names, {"Checkout"})              # Auth excluded entirely
        self.assertEqual(files, ["src/checkout/cart.py", "src/checkout/pay.py"])

        # coverage: scout checkpoint (read-only return-persist) then floor+scout
        cov = coverage.coverage_execute(d, manifest)
        self.assertEqual(cov.checkpoint, "scout")
        self.assertIsNone(cov.group)                 # #1056: scouts batched, group=None
        req = requests.load_dispatch_request(d)
        for e in req["entries"]:
            runio._write_json(e["out_file"], {"group": "Checkout", "domains": ["SEC"]})
        self.assertEqual(coverage.coverage_execute(d, manifest).kind, "advanced")
        self.assertTrue(coverage.coverage_done(d, manifest))

        # review checkpoint -- self-write cell findings, scoped to Checkout's files
        r = review.review_execute(d, manifest)
        self.assertEqual(r.checkpoint, "review")
        self.assertIsNone(r.group)                          # #5: review cells batched, group=None
        req = requests.load_dispatch_request(d)
        for e in req["entries"]:
            self.assertNotIn("write_mode", e)               # unified self-write shape
            self._self_write_review(e, "SEC", "Checkout")
        self.assertTrue(review.review_done(d, manifest))

        # verify checkpoint -- primary only (SEC HIGH is < F_b, so no backup)
        v = verify.verify_execute(d, manifest)
        self.assertEqual(v.checkpoint, "verify")
        req = requests.load_dispatch_request(d)
        for e in req["entries"]:
            self._self_write_verify(d, manifest, e, "SEC", "Checkout")
        self.assertEqual(verify.verify_execute(d, manifest).kind, "advanced")
        self.assertTrue(verify.verify_done(d, manifest))

        # synthesize -> graded report, every finding confined to Checkout's files
        self.assertEqual(synthesize.synthesize_execute(d, manifest).kind, "advanced")
        report = runio._load_json(runio._pano(d, "report.json"))
        self.assertTrue(report["findings"])
        for f in report["findings"]:
            self.assertTrue(f["location"]["file"].startswith("src/checkout/"))
        finding = next(f for f in report["findings"] if f.get("domain") == "SEC")
        self.assertEqual(finding["evidence"]["status"], "advisor_confirmed")
        self.assertNotEqual(report["summary"]["gate"], "INCONCLUSIVE")

    def test_discovery_without_committed_groups_yml_raises_loud_setup_error(self):
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        os.makedirs(os.path.join(d, ".panopticon"))   # no groups.yml -- un-setup repo
        manifest = self._manifest()
        with self.assertRaises(runio.DriverError) as cm:
            discovery.discovery_execute(d, manifest)
        self.assertIn("panopticon setup", str(cm.exception))

