import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import scripts.driver as driver


def _fake_phase(name, *, done_after=1, result_kind="advanced", checkpoint=None):
    """A fake phase backed by an execute counter (stands in for disk state).
    done() flips True once execute has run `done_after` times."""
    state = {"executes": 0}

    def done(root, manifest):
        return state["executes"] >= done_after

    def execute(root, manifest):
        state["executes"] += 1
        if result_kind == "checkpoint":
            return driver.PhaseResult(kind="checkpoint", checkpoint=checkpoint,
                                      group="G", dispatch_request="/abs/req.json",
                                      message="stop")
        return driver.PhaseResult(kind="advanced")

    return driver.Phase(name=name, kind="deterministic", done=done,
                        execute=execute), state


class TestRunEngine(unittest.TestCase):
    def test_advances_deterministic_to_complete(self):
        a, _ = _fake_phase("a")
        b, _ = _fake_phase("b")
        c, _ = _fake_phase("c")
        status = driver.run_engine("/root", {}, [a, b, c])
        self.assertEqual(status["status"], "complete")
        self.assertEqual(status["advanced"], ["a", "b", "c"])

    def test_stops_at_first_checkpoint(self):
        a, _ = _fake_phase("a")
        b, _ = _fake_phase("b", done_after=99, result_kind="checkpoint",
                           checkpoint="scout")
        c, _ = _fake_phase("c")
        status = driver.run_engine("/root", {}, [a, b, c])
        self.assertEqual(status["status"], "checkpoint")
        self.assertEqual(status["phase"], "b")
        self.assertEqual(status["checkpoint"], "scout")
        self.assertEqual(status["group"], "G")
        self.assertEqual(status["advanced"], ["a"])   # c never reached

    def test_skips_done_phases_on_resume(self):
        a, sa = _fake_phase("a", done_after=0)   # already done
        b, sb = _fake_phase("b", done_after=0)   # already done
        c, _ = _fake_phase("c")
        status = driver.run_engine("/root", {}, [a, b, c])
        self.assertEqual(status["status"], "complete")
        self.assertEqual(status["advanced"], ["c"])
        self.assertEqual(sa["executes"], 0)      # not re-executed
        self.assertEqual(sb["executes"], 0)

    def test_mixed_phase_reselected_until_done(self):
        # one phase that needs 3 executes (advances one "unit" each) then done
        m, state = _fake_phase("coverage", done_after=3)
        status = driver.run_engine("/root", {}, [m])
        self.assertEqual(status["status"], "complete")
        self.assertEqual(state["executes"], 3)
        self.assertEqual(status["advanced"], ["coverage"])   # deduped

    def test_progress_guard_raises_on_no_progress(self):
        stuck, _ = _fake_phase("stuck", done_after=99)   # never satisfied
        with self.assertRaises(RuntimeError):
            driver.run_engine("/root", {}, [stuck], max_steps=5)


class TestEmitStatus(unittest.TestCase):
    def test_error_status_returns_exit_1(self):
        buf = io.StringIO()
        rc = driver.emit_status({"status": "error", "message": "boom"}, stream=buf)
        self.assertEqual(rc, 1)
        self.assertIn("boom", buf.getvalue())

    def test_checkpoint_and_complete_return_exit_0(self):
        self.assertEqual(driver.emit_status({"status": "checkpoint"},
                                            stream=io.StringIO()), 0)
        self.assertEqual(driver.emit_status({"status": "complete"},
                                            stream=io.StringIO()), 0)

    def test_emits_valid_json(self):
        buf = io.StringIO()
        driver.emit_status({"status": "complete", "phase": None}, stream=buf)
        self.assertEqual(json.loads(buf.getvalue())["status"], "complete")


class TestWriteDispatchRequest(unittest.TestCase):
    def test_writes_host_agnostic_request(self):
        with tempfile.TemporaryDirectory() as root:
            entries = [{"id": "e1", "agent": "panopticon-scout", "enforced": True,
                        "model": None, "prompt": "…", "out_file": "/abs/scout-Auth.json"}]
            path = driver.write_dispatch_request(root, "RID", "scout", "Auth", entries)
            self.assertTrue(path.endswith(".panopticon/dispatch-request.json"))
            self.assertEqual(path, os.path.abspath(path))
            with open(path) as fh:
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
                driver.write_dispatch_request(root, "RID", "bogus", "Auth", [])


class TestResolveReviewRoot(unittest.TestCase):
    def _git_repo(self):
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        subprocess.run(["git", "init", "-q", d], check=True)
        return d

    def test_resolves_repo_root_from_subdir(self):
        d = self._git_repo()
        sub = os.path.join(d, "pkg")
        os.makedirs(sub)
        root, wt = driver.resolve_review_root(sub)
        self.assertEqual(root, d)
        self.assertIsNone(wt)

    def test_resolves_repo_root_from_file_target(self):
        d = self._git_repo()
        f = os.path.join(d, "a.py")
        open(f, "w").close()
        root, wt = driver.resolve_review_root(f)
        self.assertEqual(root, d)

    def test_non_git_dir_returns_target(self):
        with tempfile.TemporaryDirectory() as d:
            d = os.path.realpath(d)
            root, wt = driver.resolve_review_root(d)
            self.assertEqual(root, d)
            self.assertIsNone(wt)

    def test_pr_uses_diff_map_worktree(self):
        with mock.patch("scripts.driver.diff_map.acquire_pr",
                        return_value={"worktree": "/tmp/pr-wt", "base": "main",
                                      "head_sha": "abc"}) as acq:
            root, wt = driver.resolve_review_root(".", pr=7)
        self.assertEqual(root, "/tmp/pr-wt")
        self.assertEqual(wt, "/tmp/pr-wt")
        acq.assert_called_once()


class TestDiscoveryPhase(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        os.makedirs(os.path.join(self.root, ".panopticon"))
        self.addCleanup(self._t.cleanup)
        self.manifest = {"run_id": "R", "security_mode": "standard"}

    def _write_groups_yml(self, body):
        with open(driver._pano(self.root, "groups.yml"), "w") as fh:
            fh.write(body)

    def test_missing_groups_yml_raises(self):
        with self.assertRaises(driver.DriverError):
            driver.discovery_execute(self.root, self.manifest)

    def test_discovery_subprocesses_orchestrator_and_marks_done(self):
        self._write_groups_yml("groups:\n  Auth:\n    match: ['src/auth/**']\n")

        def fake_run(cmd, **kw):   # tolerant: driver passes cwd/env/capture_output
            out = cmd[cmd.index("--out") + 1]
            with open(out, "w") as fh:
                json.dump({"groups": [{"name": "Auth", "files": ["src/auth/a.py"]}]}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("scripts.driver.subprocess.run", side_effect=fake_run):
            result = driver.discovery_execute(self.root, self.manifest)
        self.assertEqual(result.kind, "advanced")
        self.assertTrue(driver.discovery_done(self.root, self.manifest))

    def test_discovery_raises_when_no_groups_json_produced(self):
        self._write_groups_yml("groups:\n  Auth:\n    match: ['src/auth/**']\n")
        with mock.patch("scripts.driver.subprocess.run",
                        return_value=mock.Mock(returncode=1, stdout="", stderr="boom")):
            with self.assertRaises(driver.DriverError):
                driver.discovery_execute(self.root, self.manifest)


class TestCoveragePhase(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        os.makedirs(driver._pano(self.root))
        self.addCleanup(self._t.cleanup)
        self.manifest = {"run_id": "R", "security_mode": "standard", "host": "claude"}

    def _groups_json(self, groups):
        driver._write_json(driver._pano(self.root, "groups.json"), {"groups": groups})

    def _groups_yml(self, body):
        with open(driver._pano(self.root, "groups.yml"), "w") as fh:
            fh.write(body)

    def test_emits_scout_checkpoint_when_scout_absent(self):
        self._groups_json([{"name": "Auth", "files": ["a.py"]}])
        self._groups_yml("groups:\n  Auth:\n    match: ['a.py']\n    panels: [SEC]\n")
        with mock.patch("scripts.driver.dispatch.render_prompt",
                        return_value="SCOUT-BODY"), \
             mock.patch("scripts.driver.dispatch.registered_agent_name",
                        return_value="panopticon-scout"):
            result = driver.coverage_execute(self.root, self.manifest)
        self.assertEqual(result.kind, "checkpoint")
        self.assertEqual(result.checkpoint, "scout")
        self.assertEqual(result.group, "Auth")
        req = driver._load_json(driver._pano(self.root, "dispatch-request.json"))
        self.assertEqual(req["checkpoint"], "scout")
        entry = req["entries"][0]
        self.assertTrue(entry["out_file"].endswith("scout-Auth.json"))
        self.assertEqual(entry["out_file"], os.path.abspath(entry["out_file"]))
        self.assertTrue(entry["enforced"])              # claude host
        self.assertNotIn("delivery", entry)             # host-agnostic

    def test_generic_host_scout_entry_not_enforced(self):
        self._groups_json([{"name": "Auth", "files": ["a.py"]}])
        self._groups_yml("groups:\n  Auth:\n    match: ['a.py']\n")
        m = dict(self.manifest, host="generic")
        with mock.patch("scripts.driver.dispatch.render_prompt", return_value="B"), \
             mock.patch("scripts.driver.dispatch.registered_agent_name",
                        return_value="panopticon-scout"):
            driver.coverage_execute(self.root, m)
        entry = driver._load_json(driver._pano(self.root, "dispatch-request.json"))["entries"][0]
        self.assertFalse(entry["enforced"])
        self.assertIsNone(entry["agent"])

    def test_computes_floor_coverage_after_scout_lands(self):
        self._groups_json([{"name": "Auth", "files": ["a.py"]}])
        self._groups_yml(
            "groups:\n  Auth:\n    match: ['a.py']\n    panels: [SEC, DAT]\n"
            "    exclude: [OPS]\n")
        driver._write_json(driver._pano(self.root, "scout-Auth.json"),
                           {"group": "Auth", "panels": ["code"]})
        result = driver.coverage_execute(self.root, self.manifest)
        self.assertEqual(result.kind, "advanced")
        cov = driver._load_json(driver._pano(self.root, "coverage-Auth.json"))
        self.assertEqual(cov["floor"], ["DAT", "SEC"])        # disclosure sorts
        self.assertEqual(cov["excluded"], ["OPS"])
        self.assertEqual(cov["effective"], ["DAT", "SEC"])    # exclude ∉ floor
        self.assertEqual(cov["scout_added"], [])              # bridge deferred to P4
        self.assertTrue(cov["scout_file"].endswith("scout-Auth.json"))

    def test_group_absent_from_matrix_gets_empty_floor(self):
        # a split group (e.g. Auth_1) not present in groups.yml -> empty floor
        self._groups_json([{"name": "Auth_1", "files": ["a.py"]}])
        self._groups_yml("groups:\n  Auth:\n    match: ['a.py']\n    panels: [SEC]\n")
        driver._write_json(driver._pano(self.root, "scout-Auth_1.json"), {"g": 1})
        driver.coverage_execute(self.root, self.manifest)
        cov = driver._load_json(driver._pano(self.root, "coverage-Auth_1.json"))
        self.assertEqual(cov["effective"], [])

    def test_coverage_done_only_when_all_groups_covered(self):
        self._groups_json([{"name": "A", "files": []}, {"name": "B", "files": []}])
        self._groups_yml("groups:\n  A:\n    match: ['*']\n  B:\n    match: ['*']\n")
        self.assertFalse(driver.coverage_done(self.root, self.manifest))
        for g in ("A", "B"):
            driver._write_json(driver._pano(self.root, "coverage-%s.json" % g), {"g": g})
        self.assertTrue(driver.coverage_done(self.root, self.manifest))


class TestCoverageBridge(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        os.makedirs(driver._pano(self.root))
        self.addCleanup(self._t.cleanup)
        self.manifest = {"run_id": "R", "security_mode": "standard", "host": "claude"}

    def _setup(self, floor_yaml, scout_domains):
        driver._write_json(driver._pano(self.root, "groups.json"),
                           {"groups": [{"name": "Auth", "files": ["a.py"]}]})
        with open(driver._pano(self.root, "groups.yml"), "w") as fh:
            fh.write(floor_yaml)
        driver._write_json(driver._pano(self.root, "scout-Auth.json"),
                           {"group": "Auth", "domains": scout_domains})

    def test_scout_widens_coverage(self):
        self._setup("groups:\n  Auth:\n    match: ['a.py']\n    panels: [SEC]\n",
                    ["SEC", "DAT"])
        driver.coverage_execute(self.root, self.manifest)
        cov = driver._load_json(driver._pano(self.root, "coverage-Auth.json"))
        self.assertEqual(cov["scout_added"], ["DAT"])          # SEC already floor
        self.assertEqual(cov["effective"], ["DAT", "SEC"])

    def test_invalid_scout_domain_dropped_and_disclosed(self):
        self._setup("groups:\n  Auth:\n    match: ['a.py']\n    panels: [SEC]\n",
                    ["DAT", "BOGUS"])
        driver.coverage_execute(self.root, self.manifest)
        cov = driver._load_json(driver._pano(self.root, "coverage-Auth.json"))
        self.assertEqual(cov["scout_added"], ["DAT"])
        self.assertEqual(cov["scout_invalid"], ["BOGUS"])

    def test_scout_cannot_override_exclude(self):
        self._setup("groups:\n  Auth:\n    match: ['a.py']\n    panels: [SEC]\n"
                    "    exclude: [DAT]\n", ["DAT"])
        driver.coverage_execute(self.root, self.manifest)
        cov = driver._load_json(driver._pano(self.root, "coverage-Auth.json"))
        self.assertNotIn("DAT", cov["effective"])              # exclude wins


class TestToolsPhase(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        os.makedirs(driver._pano(self.root))
        self.addCleanup(self._t.cleanup)
        self.manifest = {"run_id": "R", "flags": {}}

    def test_produced_output_marks_ran(self):
        def fake_run(cmd, **kw):
            out = cmd[cmd.index("--out") + 1]
            os.makedirs(out, exist_ok=True)
            open(os.path.join(out, "trivy.json"), "w").close()
            return mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch("scripts.driver.subprocess.run", side_effect=fake_run):
            result = driver.tools_execute(self.root, self.manifest)
        self.assertEqual(result.kind, "advanced")
        marker = driver._load_json(driver._pano(self.root, "tools-ran.json"))
        self.assertTrue(marker["ran"])
        self.assertTrue(driver.tools_done(self.root, self.manifest))

    def test_docker_absent_is_disclosed_skip_that_advances(self):
        def fake_run(cmd, **kw):   # produces nothing, exits 0 (docker missing)
            return mock.Mock(returncode=0, stdout="",
                             stderr="panopticon-tools image not available; skipping")
        with mock.patch("scripts.driver.subprocess.run", side_effect=fake_run):
            result = driver.tools_execute(self.root, self.manifest)
        self.assertEqual(result.kind, "advanced")
        marker = driver._load_json(driver._pano(self.root, "tools-ran.json"))
        self.assertFalse(marker["ran"])
        self.assertTrue(marker["skipped"])
        self.assertIn("image not available", marker["note"])

    def test_no_tools_flag_skips_subprocess(self):
        m = {"run_id": "R", "flags": {"tools": False}}
        with mock.patch("scripts.driver.subprocess.run") as run_mock:
            result = driver.tools_execute(self.root, m)
        run_mock.assert_not_called()
        self.assertEqual(result.kind, "advanced")
        self.assertTrue(driver._load_json(driver._pano(self.root, "tools-ran.json"))["skipped"])


class TestNoopPhases(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        os.makedirs(driver._pano(self.root))
        self.addCleanup(self._t.cleanup)
        self.manifest = {"run_id": "R"}

    def test_review_noop_advances_and_marks(self):
        result = driver.review_execute(self.root, self.manifest)
        self.assertEqual(result.kind, "advanced")
        self.assertTrue(driver.review_done(self.root, self.manifest))

    def test_verify_noop_creates_verdicts_dir(self):
        driver.verify_execute(self.root, self.manifest)
        self.assertTrue(os.path.isdir(driver._pano(self.root, "verdicts")))
        self.assertTrue(driver.verify_done(self.root, self.manifest))

    def test_marker_from_other_run_is_not_done(self):
        driver.review_execute(self.root, {"run_id": "OLD"})
        self.assertFalse(driver.review_done(self.root, {"run_id": "NEW"}))


class TestSynthesizePhase(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        os.makedirs(driver._pano(self.root))
        self.addCleanup(self._t.cleanup)
        self.manifest = {"run_id": "R", "security_mode": "standard",
                         "flags": {"fail_on": "high"}}

    def test_builds_report_via_verdicts_dir_form(self):
        captured = {}
        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            with open(cmd[cmd.index("--out") + 1], "w") as fh:
                json.dump({"grade": "A", "findings": []}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch("scripts.driver.subprocess.run", side_effect=fake_run):
            result = driver.synthesize_execute(self.root, self.manifest)
        self.assertEqual(result.kind, "advanced")
        self.assertTrue(driver.synthesize_done(self.root, self.manifest))
        cmd = captured["cmd"]
        self.assertIn("--verdicts-dir", cmd)
        self.assertNotIn("--emit-verify-queue", cmd)
        self.assertIn("--fail-on", cmd)
        self.assertEqual(cmd[cmd.index("--out") + 1],
                         driver._pano(self.root, "report.json"))

    def test_tools_dir_added_only_when_tools_ran(self):
        driver._write_json(driver._pano(self.root, "tools-ran.json"),
                           {"ran": True, "run_id": "R"})
        def fake_run(cmd, **kw):
            with open(cmd[cmd.index("--out") + 1], "w") as fh:
                json.dump({"findings": []}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch("scripts.driver.subprocess.run", side_effect=fake_run) as rm_:
            driver.synthesize_execute(self.root, self.manifest)
        self.assertIn("--tools-dir", rm_.call_args[0][0])

    def test_gate_fail_nonzero_still_advances_when_report_present(self):
        def fake_run(cmd, **kw):
            with open(cmd[cmd.index("--out") + 1], "w") as fh:
                json.dump({"grade": "F", "findings": []}, fh)
            return mock.Mock(returncode=2, stdout="", stderr="gate failed")  # non-zero
        with mock.patch("scripts.driver.subprocess.run", side_effect=fake_run):
            result = driver.synthesize_execute(self.root, self.manifest)
        self.assertEqual(result.kind, "advanced")

    def test_absent_report_raises(self):
        with mock.patch("scripts.driver.subprocess.run",
                        return_value=mock.Mock(returncode=1, stdout="", stderr="boom")):
            with self.assertRaises(driver.DriverError):
                driver.synthesize_execute(self.root, self.manifest)


class TestValidatePhase(unittest.TestCase):
    def _git_repo(self):
        import shutil as _sh
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: _sh.rmtree(d, ignore_errors=True))
        subprocess.run(["git", "init", "-q", d], check=True)
        subprocess.run(["git", "-C", d, "config", "user.email", "t@t"], check=True)
        subprocess.run(["git", "-C", d, "config", "user.name", "t"], check=True)
        open(os.path.join(d, "a.py"), "w").close()
        subprocess.run(["git", "-C", d, "add", "-A"], check=True)
        subprocess.run(["git", "-C", d, "commit", "-qm", "init"], check=True)
        os.makedirs(os.path.join(d, ".panopticon"))
        return d

    def test_clean_tree_advances(self):
        d = self._git_repo()
        driver.capture_tree_baseline(d)
        m = {"run_id": "R", "worktree": None}
        result = driver.validate_execute(d, m)
        self.assertEqual(result.kind, "advanced")
        self.assertTrue(driver.validate_done(d, m))

    def test_reviewer_side_effect_outside_panopticon_raises(self):
        d = self._git_repo()
        driver.capture_tree_baseline(d)
        open(os.path.join(d, "leaked.py"), "w").close()   # NEW file outside .panopticon
        m = {"run_id": "R", "worktree": None}
        with self.assertRaises(driver.DriverError):
            driver.validate_execute(d, m)
        self.assertFalse(driver.validate_done(d, m))   # dirty tree != validated

    def test_panopticon_changes_are_ignored(self):
        d = self._git_repo()
        driver.capture_tree_baseline(d)
        open(os.path.join(d, ".panopticon", "report.json"), "w").close()
        result = driver.validate_execute(d, {"run_id": "R", "worktree": None})
        self.assertEqual(result.kind, "advanced")

    def test_releases_pr_worktree(self):
        d = self._git_repo()
        driver.capture_tree_baseline(d)
        with mock.patch("scripts.driver.diff_map.release_worktree") as rel:
            driver.validate_execute(d, {"run_id": "R", "worktree": "/tmp/pr-wt"})
        rel.assert_called_once()

    def test_non_git_target_has_no_baseline_and_advances(self):
        with tempfile.TemporaryDirectory() as d:
            d = os.path.realpath(d)
            os.makedirs(os.path.join(d, ".panopticon"))
            self.assertIsNone(driver.capture_tree_baseline(d))
            result = driver.validate_execute(d, {"run_id": "R", "worktree": None})
            self.assertEqual(result.kind, "advanced")

    def test_panopticon_prefix_sibling_is_flagged(self):
        # a repo-root file sharing the '.panopticon' prefix WITHOUT a '/' boundary
        # is a reviewer side effect, not an in-.panopticon artifact -> must raise.
        d = self._git_repo()
        driver.capture_tree_baseline(d)
        open(os.path.join(d, ".panopticon-evil.py"), "w").close()
        with self.assertRaises(driver.DriverError):
            driver.validate_execute(d, {"run_id": "R", "worktree": None})

    def test_rename_out_of_panopticon_is_flagged(self):
        # a rename moving a tracked file OUT of .panopticon/ must be caught on
        # its DESTINATION path.
        d = self._git_repo()
        os.makedirs(os.path.join(d, ".panopticon"), exist_ok=True)
        inside = os.path.join(d, ".panopticon", "x.py")
        open(inside, "w").close()
        subprocess.run(["git", "-C", d, "add", "-A"], check=True)
        subprocess.run(["git", "-C", d, "commit", "-qm", "add pano file"], check=True)
        driver.capture_tree_baseline(d)
        subprocess.run(["git", "-C", d, "mv", ".panopticon/x.py", "leaked.py"], check=True)
        with self.assertRaises(driver.DriverError):
            driver.validate_execute(d, {"run_id": "R", "worktree": None})


import scripts.run_manifest as run_manifest  # noqa: E402


class TestDriverCLIAndEndToEnd(unittest.TestCase):
    def _repo(self):
        import shutil as _sh
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: _sh.rmtree(d, ignore_errors=True))
        g = ["git", "-C", d]
        subprocess.run(["git", "init", "-q", d], check=True)
        subprocess.run(g + ["config", "user.email", "t@t"], check=True)
        subprocess.run(g + ["config", "user.name", "t"], check=True)
        os.makedirs(os.path.join(d, "src"))
        with open(os.path.join(d, "src", "app.py"), "w") as fh:
            fh.write("def f():\n    return 1\n")
        os.makedirs(os.path.join(d, ".panopticon"))
        with open(os.path.join(d, ".panopticon", "groups.yml"), "w") as fh:
            fh.write("groups:\n  Core:\n    match: ['src/**']\n    panels: [COD]\n")
        subprocess.run(g + ["add", "-A"], check=True)
        subprocess.run(g + ["commit", "-qm", "init"], check=True)
        return d

    def _args(self, target, *extra):
        return driver.build_parser().parse_args(["run", target, *extra])

    def _inject_scouts(self, root):
        for g, _ in driver._discovered_groups(root):
            p = driver._pano(root, "scout-%s.json" % g)
            if not os.path.exists(p):
                driver._write_json(p, {"group": g, "panels": ["code"]})

    def test_first_run_writes_manifest_and_baseline(self):
        d = self._repo()
        driver.run(self._args(d))
        self.assertIsNotNone(run_manifest.load_manifest(d))
        self.assertTrue(os.path.isfile(driver._pano(d, "tree-baseline.txt")))

    def test_end_to_end_reaches_report(self):
        d = self._repo()
        args = self._args(d)
        status = driver.run(args)
        self.assertEqual(status["status"], "checkpoint")
        self.assertEqual(status["checkpoint"], "scout")
        for _ in range(30):
            if status["status"] == "checkpoint":
                self._inject_scouts(d)
            status = driver.run(args)
            self.assertNotEqual(status["status"], "error", status.get("message"))
            if status["status"] == "complete":
                break
        self.assertEqual(status["status"], "complete")
        self.assertTrue(os.path.isfile(driver._pano(d, "report.json")))
        # idempotent: a completed run stays complete
        self.assertEqual(driver.run(args)["status"], "complete")

    def test_resume_reemits_same_checkpoint_before_dispatch(self):
        d = self._repo()
        args = self._args(d)
        s1 = driver.run(args)
        s2 = driver.run(args)   # nothing serviced -> identical checkpoint
        self.assertEqual((s1["checkpoint"], s1["group"]),
                         (s2["checkpoint"], s2["group"]))

    def test_flag_drift_is_refused(self):
        d = self._repo()
        driver.run(self._args(d))                       # manifest = standard
        status = driver.run(self._args(d, "--security", "redteam"))
        self.assertEqual(status["status"], "error")
        self.assertIn("drift", status["message"])

    def test_reset_restarts_from_scratch(self):
        d = self._repo()
        args = self._args(d)
        driver.run(args)
        self._inject_scouts(d)
        driver.run(args)                                # advance past scout
        status = driver.run(self._args(d, "--reset"))   # wipe + restart
        self.assertEqual(status["status"], "checkpoint")
        self.assertEqual(status["checkpoint"], "scout")
        # reset never deletes the committed matrix
        self.assertTrue(os.path.isfile(driver._pano(d, "groups.yml")))

    def test_main_prints_status_and_returns_exit_code(self):
        d = self._repo()
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = driver.main(["run", d])
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(buf.getvalue())["status"], "checkpoint")

    def test_pr_is_refused_without_acquiring_worktree(self):
        # C1: driver --pr must refuse loudly and must NOT call acquire_pr
        # (which would leak a worktree).
        d = self._repo()
        args = driver.build_parser().parse_args(["run", d, "--pr", "7"])
        with mock.patch("scripts.driver.diff_map.acquire_pr") as acq:
            status = driver.run(args)
        acq.assert_not_called()
        self.assertEqual(status["status"], "error")
        self.assertIn("pr", status["message"].lower())

    def test_fresh_manifest_clears_stale_artifacts(self):
        # I1: a stale report.json with no manifest must be cleared on the first
        # run, not resumed as "synthesize done".
        d = self._repo()
        stale = driver._pano(d, "report.json")
        driver._write_json(stale, {"stale": True})
        status = driver.run(self._args(d))     # first run -> manifest built
        self.assertNotEqual(status["status"], "error", status.get("message"))
        self.assertFalse(os.path.exists(stale))  # stale artifact cleared

    def test_missing_baseline_self_heals_on_resume(self):
        # I2: a manifest written without a baseline (interrupt window) must get
        # the baseline captured on the next invocation.
        d = self._repo()
        m = run_manifest.build_manifest(
            target=d, review_root=d, host="claude", security_mode="standard")
        run_manifest.write_manifest(d, m)        # manifest, but NO baseline
        self.assertFalse(os.path.exists(driver._pano(d, "tree-baseline.txt")))
        driver.run(self._args(d))                # resume -> should self-heal
        self.assertTrue(os.path.exists(driver._pano(d, "tree-baseline.txt")))


if __name__ == "__main__":
    unittest.main()
