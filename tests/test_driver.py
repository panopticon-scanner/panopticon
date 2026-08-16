import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import scripts.driver as driver
import scripts.ocrdb as ocrdb


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
        root, wt, pr_base = driver.resolve_review_root(sub)
        self.assertEqual(root, d)
        self.assertIsNone(wt)
        self.assertIsNone(pr_base)

    def test_resolves_repo_root_from_file_target(self):
        d = self._git_repo()
        f = os.path.join(d, "a.py")
        open(f, "w").close()
        root, wt, pr_base = driver.resolve_review_root(f)
        self.assertEqual(root, d)

    def test_non_git_dir_returns_target(self):
        with tempfile.TemporaryDirectory() as d:
            d = os.path.realpath(d)
            root, wt, pr_base = driver.resolve_review_root(d)
            self.assertEqual(root, d)
            self.assertIsNone(wt)
            self.assertIsNone(pr_base)

    def test_pr_uses_diff_map_worktree(self):
        with mock.patch("scripts.driver.diff_map.acquire_pr",
                        return_value={"worktree": "/tmp/pr-wt", "base": "main",
                                      "head_sha": "abc"}) as acq:
            root, wt, pr_base = driver.resolve_review_root(".", pr=7)
        self.assertEqual(root, "/tmp/pr-wt")
        self.assertEqual(wt, "/tmp/pr-wt")
        self.assertEqual(pr_base, "main")
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

    def test_discovery_threads_scope_group_to_repo_scan(self):
        self._write_groups_yml("groups:\n  Auth:\n    match: ['src/auth/**']\n")
        manifest = dict(self.manifest, scope={"mode": "group", "target": "Auth"})

        def fake_run(cmd, **kw):
            out = cmd[cmd.index("--out") + 1]
            with open(out, "w") as fh:
                json.dump({"groups": [{"name": "Auth", "files": ["src/auth/a.py"]}]}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("scripts.driver.subprocess.run", side_effect=fake_run) as run:
            result = driver.discovery_execute(self.root, manifest)
        self.assertEqual(result.kind, "advanced")
        cmd = run.call_args.args[0]
        self.assertIn("--scope-group", cmd)
        self.assertIn("Auth", cmd)

    def test_discovery_repo_scope_appends_no_scope_arg(self):
        self._write_groups_yml("groups:\n  Auth:\n    match: ['src/auth/**']\n")
        manifest = dict(self.manifest, scope={"mode": "repo"})

        def fake_run(cmd, **kw):
            out = cmd[cmd.index("--out") + 1]
            with open(out, "w") as fh:
                json.dump({"groups": [{"name": "Auth", "files": ["src/auth/a.py"]}]}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("scripts.driver.subprocess.run", side_effect=fake_run) as run:
            driver.discovery_execute(self.root, manifest)
        cmd = run.call_args.args[0]
        self.assertNotIn("--scope-file", cmd)
        self.assertNotIn("--scope-dir", cmd)
        self.assertNotIn("--scope-group", cmd)

    def test_discovery_threads_changed_scope_with_base_and_diff_context(self):
        self._write_groups_yml("groups:\n  Auth:\n    match: ['src/auth/**']\n")
        manifest = dict(self.manifest, scope={"mode": "changed", "target": None},
                        base="main", flags={"diff_context": 5})

        def fake_run(cmd, **kw):
            out = cmd[cmd.index("--out") + 1]
            with open(out, "w") as fh:
                json.dump({"groups": [{"name": "Auth", "files": ["src/auth/a.py"]}]}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("scripts.driver.subprocess.run", side_effect=fake_run) as run:
            result = driver.discovery_execute(self.root, manifest)
        self.assertEqual(result.kind, "advanced")
        cmd = run.call_args.args[0]
        self.assertIn("--scope-changed", cmd)
        self.assertIn("--base", cmd)
        self.assertEqual(cmd[cmd.index("--base") + 1], "main")
        self.assertIn("--diff-context", cmd)
        self.assertEqual(cmd[cmd.index("--diff-context") + 1], "5")
        self.assertNotIn("--scope-file", cmd)
        self.assertNotIn("--scope-dir", cmd)
        self.assertNotIn("--scope-group", cmd)
        self.assertNotIn("--scope-files", cmd)

    def test_discovery_threads_files_scope_with_target_list(self):
        self._write_groups_yml("groups:\n  Auth:\n    match: ['src/auth/**']\n")
        manifest = dict(self.manifest,
                        scope={"mode": "files", "target": ["a.py", "b.py"]})

        def fake_run(cmd, **kw):
            out = cmd[cmd.index("--out") + 1]
            with open(out, "w") as fh:
                json.dump({"groups": [{"name": "Auth", "files": ["src/auth/a.py"]}]}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("scripts.driver.subprocess.run", side_effect=fake_run) as run:
            result = driver.discovery_execute(self.root, manifest)
        self.assertEqual(result.kind, "advanced")
        cmd = run.call_args.args[0]
        self.assertIn("--scope-files", cmd)
        i = cmd.index("--scope-files")
        self.assertEqual(cmd[i + 1:i + 3], ["a.py", "b.py"])
        self.assertNotIn("--base", cmd)
        self.assertNotIn("--diff-context", cmd)

    def test_discovery_threads_pr_base_when_present(self):
        # Finding B: a --pr manifest carries the gh-detected base in `pr_base`
        # (not `base`) so orchestrator resolves it with origin/<base> preference.
        self._write_groups_yml("groups:\n  Auth:\n    match: ['src/auth/**']\n")
        manifest = dict(self.manifest, scope={"mode": "changed", "target": None},
                        base=None, pr_base="main")

        def fake_run(cmd, **kw):
            out = cmd[cmd.index("--out") + 1]
            with open(out, "w") as fh:
                json.dump({"groups": [{"name": "Auth", "files": ["src/auth/a.py"]}]}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("scripts.driver.subprocess.run", side_effect=fake_run) as run:
            result = driver.discovery_execute(self.root, manifest)
        self.assertEqual(result.kind, "advanced")
        cmd = run.call_args.args[0]
        self.assertIn("--scope-changed", cmd)
        self.assertIn("--pr-base", cmd)
        self.assertEqual(cmd[cmd.index("--pr-base") + 1], "main")
        self.assertNotIn("--base", cmd)   # base is None -> not threaded

    def test_discovery_omits_pr_base_when_absent(self):
        # A -c/--files manifest (no PR) carries no pr_base -> orchestrator gets
        # no --pr-base and its byte-identical behavior is preserved.
        self._write_groups_yml("groups:\n  Auth:\n    match: ['src/auth/**']\n")
        manifest = dict(self.manifest, scope={"mode": "changed", "target": None},
                        base="main")

        def fake_run(cmd, **kw):
            out = cmd[cmd.index("--out") + 1]
            with open(out, "w") as fh:
                json.dump({"groups": [{"name": "Auth", "files": ["src/auth/a.py"]}]}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("scripts.driver.subprocess.run", side_effect=fake_run) as run:
            driver.discovery_execute(self.root, manifest)
        cmd = run.call_args.args[0]
        self.assertNotIn("--pr-base", cmd)
        self.assertIn("--base", cmd)


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


class TestVerifyNoop(unittest.TestCase):
    # verify_* stays a wired no-op in P4 (P5 wires advisor + score_gate); review_*
    # was the P3 no-op here but is now the real cell fan-out (see TestCellFanOut).
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        os.makedirs(driver._pano(self.root))
        self.addCleanup(self._t.cleanup)
        self.manifest = {"run_id": "R"}

    def test_verify_noop_creates_verdicts_dir(self):
        driver.verify_execute(self.root, self.manifest)
        self.assertTrue(os.path.isdir(driver._pano(self.root, "verdicts")))
        self.assertTrue(driver.verify_done(self.root, self.manifest))


class TestCellFanOut(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        os.makedirs(driver._pano(self.root))
        self.addCleanup(self._t.cleanup)
        self.manifest = {"run_id": "R", "security_mode": "standard", "host": "claude"}
        driver._write_json(driver._pano(self.root, "groups.json"),
                           {"groups": [{"name": "Auth", "files": ["a.py"]}]})
        driver._write_json(driver._pano(self.root, "coverage-Auth.json"),
                           {"group": "Auth", "effective": ["SEC", "DAT"], "run_id": "R"})

    def _menu_stub(self):
        return mock.patch("scripts.driver.ocrdb.domain_menu",
                          return_value=[{"code": "SEC-A1A", "name": "x", "severity": "HIGH", "cwe": []}])

    def test_review_emits_cell_entries_per_effective_domain(self):
        with self._menu_stub(), \
             mock.patch("scripts.driver.dispatch.render_prompt", return_value="BODY"), \
             mock.patch("scripts.driver.dispatch.registered_agent_name",
                        return_value="panopticon-domain-panel"), \
             mock.patch("scripts.driver.ocrdb.load_bundle", return_value={"domains": {}}):
            result = driver.review_execute(self.root, self.manifest)
        self.assertEqual(result.kind, "checkpoint")
        self.assertEqual(result.checkpoint, "review")
        req = driver._load_json(driver._pano(self.root, "dispatch-request.json"))
        outs = sorted(e["out_file"].split("/")[-1] for e in req["entries"])
        self.assertEqual(outs, ["findings-Auth-DAT.json", "findings-Auth-SEC.json"])
        for e in req["entries"]:
            self.assertEqual(e["out_file"], os.path.abspath(e["out_file"]))
            self.assertNotIn("delivery", e)   # host-agnostic

    def test_review_done_requires_all_cells(self):
        self.assertFalse(driver.review_done(self.root, self.manifest))
        for dom in ("SEC", "DAT"):
            driver._write_json(driver._pano(self.root, "findings-Auth-%s.json" % dom),
                               {"findings": [], "_panopticon": {"run_id": "R",
                                "role": "domain_panel", "domain": dom, "group": "Auth"}})
        self.assertTrue(driver.review_done(self.root, self.manifest))

    def test_stale_run_id_cell_is_not_done(self):
        driver._write_json(driver._pano(self.root, "findings-Auth-SEC.json"),
                           {"findings": [], "_panopticon": {"run_id": "OLD",
                            "role": "domain_panel", "domain": "SEC", "group": "Auth"}})
        self.assertFalse(driver.review_done(self.root, self.manifest))

    def test_cell_prompt_names_the_out_file(self):
        # a real render (no render_prompt mock): the dispatched reviewer must be
        # TOLD where to write, or its findings file never appears and the cell
        # never completes.
        entry = driver._cell_entry(self.root, self.manifest, "Auth", "SEC",
                                    ["a.py"], [], "claude", ocrdb.load_bundle())
        self.assertIn(entry["out_file"], entry["prompt"])


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

    def test_diff_context_forwarded_when_set(self):
        manifest = dict(self.manifest,
                        flags={"fail_on": "high", "diff_context": 5})
        captured = {}
        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            with open(cmd[cmd.index("--out") + 1], "w") as fh:
                json.dump({"grade": "A", "findings": []}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch("scripts.driver.subprocess.run", side_effect=fake_run):
            driver.synthesize_execute(self.root, manifest)
        cmd = captured["cmd"]
        self.assertIn("--diff-context", cmd)
        self.assertEqual(cmd[cmd.index("--diff-context") + 1], "5")

    def test_diff_context_absent_when_unset(self):
        def fake_run(cmd, **kw):
            with open(cmd[cmd.index("--out") + 1], "w") as fh:
                json.dump({"grade": "A", "findings": []}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch("scripts.driver.subprocess.run", side_effect=fake_run) as run:
            driver.synthesize_execute(self.root, self.manifest)
        self.assertNotIn("--diff-context", run.call_args.args[0])


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

    def test_validate_does_not_release_pr_worktree(self):
        # Ruling A: validate must NOT release the worktree -- when review_root IS
        # the worktree, releasing here would delete report.json + the manifest and
        # break cursor derivation. Release happens in run() on completion instead.
        d = self._git_repo()
        driver.capture_tree_baseline(d)
        with mock.patch("scripts.driver.diff_map.release_worktree") as rel:
            result = driver.validate_execute(d, {"run_id": "R", "worktree": "/tmp/pr-wt"})
        rel.assert_not_called()
        self.assertEqual(result.kind, "advanced")
        self.assertTrue(driver.validate_done(d, {"run_id": "R", "worktree": "/tmp/pr-wt"}))

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


class TestFinalizeWorktree(unittest.TestCase):
    """Ruling A: on a completed --pr run, review_root IS the disposable worktree.
    _finalize_worktree surfaces report.json to the caller's target BEFORE
    releasing the worktree, and no-ops when there is no worktree."""

    def _dir(self):
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        return d

    def test_surfaces_report_then_releases_with_target_repo(self):
        worktree = self._dir()
        target = self._dir()
        driver._write_json(driver._pano(worktree, "report.json"),
                           {"summary": {"gate": "PASS"}})
        manifest = {"run_id": "R", "worktree": worktree, "target": target}
        with mock.patch.object(driver.diff_map, "release_worktree") as rel:
            driver._finalize_worktree(worktree, manifest)
        # report surfaced to the OWNING checkout's .panopticon/
        surfaced = driver._load_json(driver._pano(target, "report.json"))
        self.assertEqual(surfaced, {"summary": {"gate": "PASS"}})
        # released against the owning repo (target), not review_root (==worktree)
        rel.assert_called_once_with(worktree, repo=target)

    def test_no_worktree_is_a_noop(self):
        target = self._dir()
        with mock.patch.object(driver.diff_map, "release_worktree") as rel:
            driver._finalize_worktree(target, {"run_id": "R", "worktree": None})
        rel.assert_not_called()


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
        # Pin the branch to `main` so it is deterministic regardless of the
        # runner's git `init.defaultBranch` (CI defaults to `master`). The --pr
        # test mocks a gh pr_base of "main"; resolve_base(pr_base="main") does
        # NOT fall through to master (the #947 loud-fail for a given-but-
        # unresolvable base), so the repo must actually carry a `main` ref.
        subprocess.run(g + ["branch", "-M", "main"], check=True)
        return d

    def _args(self, target, *extra):
        return driver.build_parser().parse_args(["run", target, *extra])

    def _inject_scouts(self, root):
        for g, _ in driver._discovered_groups(root):
            p = driver._pano(root, "scout-%s.json" % g)
            if not os.path.exists(p):
                driver._write_json(p, {"group": g, "panels": ["code"]})

    def _inject_review(self, root):
        # Simulates the dispatched domain-panel reviewers landing their
        # findings files, so the E2E loop can progress past the review
        # checkpoint (P4 cell fan-out) the same way _inject_scouts simulates
        # the scout checkpoint.
        req = driver._load_json(driver._pano(root, "dispatch-request.json"))
        if not (isinstance(req, dict) and req.get("checkpoint") == "review"):
            return
        run_id = run_manifest.load_manifest(root)["run_id"]
        for e in req["entries"]:
            stem = os.path.basename(e["out_file"])[len("findings-"):-len(".json")]
            group, domain = stem.rsplit("-", 1)
            driver._write_json(e["out_file"], {"findings": [],
                "_panopticon": {"run_id": run_id, "role": "domain_panel",
                                 "domain": domain, "group": group}})

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
                self._inject_review(d)
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

    def test_scope_group_flag_parses(self):
        args = driver.build_parser().parse_args(["run", "x", "-g", "Auth"])
        self.assertEqual(args.scope_group, "Auth")
        self.assertIsNone(args.scope_file)
        self.assertIsNone(args.scope_dir)

    def test_scope_flags_are_mutually_exclusive(self):
        with self.assertRaises(SystemExit):
            driver.build_parser().parse_args(
                ["run", "x", "-g", "Auth", "-f", "src/app.py"])

    def test_scope_changed_flag_parses(self):
        args = driver.build_parser().parse_args(["run", "x", "-c"])
        self.assertTrue(args.scope_changed)
        self.assertEqual(driver._scope_from_args(args),
                         {"mode": "changed", "target": None})

    def test_scope_files_flag_parses(self):
        args = driver.build_parser().parse_args(
            ["run", "x", "--files", "a.py", "b.py"])
        self.assertEqual(args.scope_files, ["a.py", "b.py"])
        self.assertEqual(driver._scope_from_args(args),
                         {"mode": "files", "target": ["a.py", "b.py"]})

    def test_scope_changed_is_mutually_exclusive_with_group(self):
        with self.assertRaises(SystemExit):
            driver.build_parser().parse_args(["run", "x", "-g", "Auth", "-c"])

    def test_scope_recorded_on_manifest(self):
        d = self._repo()
        driver.run(self._args(d, "-g", "Auth"))
        manifest = run_manifest.load_manifest(d)
        self.assertEqual(manifest["scope"], {"mode": "group", "target": "Auth"})

    def test_scope_drift_is_refused(self):
        d = self._repo()
        driver.run(self._args(d, "-g", "Auth"))          # manifest scoped to Auth
        status = driver.run(self._args(d, "-g", "Checkout"))
        self.assertEqual(status["status"], "error")
        self.assertIn("drift", status["message"])
        self.assertIn("scope", status["message"])

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

    def test_pr_acquires_worktree_and_records_manifest(self):
        # C1 flip: driver --pr now acquires the deterministic PR worktree via
        # resolve_review_root, rather than refusing. Finding B: with NO explicit
        # --base, manifest["base"] stays None (anti-drift key -- a bare resume
        # passes base=None -> no false drift) and the gh-detected PR base lands
        # in manifest["pr_base"], the origin-preference channel.
        d = self._repo()
        args = driver.build_parser().parse_args(["run", d, "--pr", "7"])
        with mock.patch(
                "scripts.driver.resolve_review_root",
                return_value=(d, d, "main")) as resolve:
            status = driver.run(args)
        resolve.assert_called_once()
        _call_args, call_kwargs = resolve.call_args
        self.assertEqual(call_kwargs.get("pr"), 7)
        self.assertNotEqual(status["status"], "error", status.get("message"))
        manifest = run_manifest.load_manifest(d)
        self.assertEqual(manifest["pr"], 7)
        self.assertEqual(manifest["worktree"], d)
        self.assertIsNone(manifest["base"])          # explicit-only; none given
        self.assertEqual(manifest["pr_base"], "main")  # gh base -> pr_base channel
        self.assertEqual(manifest["scope"], {"mode": "changed", "target": None})

    def test_run_finalizes_worktree_only_on_complete(self):
        # Ruling A wiring: run() surfaces+releases the worktree via
        # _finalize_worktree ONLY when the engine returns status=="complete" --
        # never on a mid-run checkpoint (which must leave the worktree in place so
        # the resume can re-enter it).
        d = self._repo()
        complete = {"status": "complete", "phase": None, "checkpoint": None,
                    "group": None, "dispatch_request": None, "advanced": [],
                    "message": "all phases complete"}
        checkpoint = dict(complete, status="checkpoint", checkpoint="scout")

        with mock.patch("scripts.driver.run_engine", return_value=complete), \
                mock.patch("scripts.driver._finalize_worktree") as fin:
            status = driver.run(self._args(d))
        self.assertEqual(status["status"], "complete")
        fin.assert_called_once()

        d2 = self._repo()
        with mock.patch("scripts.driver.run_engine", return_value=checkpoint), \
                mock.patch("scripts.driver._finalize_worktree") as fin2:
            status2 = driver.run(self._args(d2))
        self.assertEqual(status2["status"], "checkpoint")
        fin2.assert_not_called()

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


class TestReviewMatrixEndToEnd(unittest.TestCase):
    """Task 6: the whole 5.0 review matrix, end to end, against the real
    driver + orchestrator + synthesize subprocesses -- discovery -> coverage
    (+scout domains) -> tools -> review (cells fire) -> verify (no-op) ->
    synthesize -> a real report.json with (domain, code) findings."""

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

    def _args(self, d):
        return driver.build_parser().parse_args(["run", d, "--host", "claude"])

    def _service(self, d, status, run_id):
        # emulate the orchestrator dispatching whatever the checkpoint asked for
        if status.get("checkpoint") == "scout":
            for g, _ in driver._discovered_groups(d):
                p = driver._pano(d, "scout-%s.json" % g)
                if not os.path.exists(p):
                    driver._write_json(p, {"group": g, "domains": ["COD"]})
        elif status.get("checkpoint") == "review":
            req = driver._load_json(driver._pano(d, "dispatch-request.json"))
            for e in req["entries"]:
                dom = e["id"].rsplit("-", 1)[-1]
                driver._write_json(e["out_file"], {
                    "findings": [{"title": "t", "severity": "LOW",
                                  "domain": dom, "code": dom + "-X0X",
                                  "location": {"file": "src/app.py", "line": 1}}],
                    "_panopticon": {"run_id": run_id, "role": "domain_panel",
                                    "domain": dom, "group": req["group"]}})

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
        report = driver._load_json(driver._pano(d, "report.json"))
        codes = [f.get("code") for f in report.get("findings", [])]
        self.assertTrue(any(c and c.startswith("COD") for c in codes))
        self.assertEqual(report["meta"]["ocrdb_version"], "0.3.1")


class TestVerifyMatrixEndToEnd(unittest.TestCase):
    """5.0-P5 Slice B Task 5: verify is no longer a no-op. Against the real
    driver functions (verify_execute/verify_done) and
    a real synthesize.py subprocess (driver.synthesize_execute) -- mirrors
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
        driver._write_json(driver._pano(d, "groups.json"),
                           {"groups": [{"name": "app", "files": ["src/app.py"]}]})
        driver._write_json(driver._pano(d, "coverage-app.json"),
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
        driver._write_json(driver._pano(d, "findings-app-%s.json" % domain), {
            "findings": [{"title": "issue in %s" % domain, "severity": severity,
                          "domain": domain, "code": domain + "-A1A", "category": "authz",
                          "location": {"file": "src/app.py", "line_start": 1}}],
            "_panopticon": {"run_id": self.RUN_ID, "role": "domain_panel",
                            "domain": domain, "group": "app"}})

    def _confirm_bundle(self, d, manifest, domain, group="app"):
        cell = driver._load_cell_findings(d, manifest, group, domain)
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

        result = driver.verify_execute(d, manifest)
        self.assertEqual(result.kind, "checkpoint")
        self.assertEqual(result.checkpoint, "verify")
        req = driver._load_json(driver._pano(d, "dispatch-request.json"))
        entry = req["entries"][0]

        text = self._confirm_bundle(d, manifest, "SEC")
        self._self_write(entry, text)

        result2 = driver.verify_execute(d, manifest)   # drains the (empty) backup round
        self.assertEqual(result2.kind, "advanced")
        self.assertTrue(driver.verify_done(d, manifest))

        synth = driver.synthesize_execute(d, manifest)
        self.assertEqual(synth.kind, "advanced")
        report = driver._load_json(driver._pano(d, "report.json"))
        finding = next(f for f in report["findings"] if f.get("domain") == "SEC")
        self.assertEqual(finding["evidence"]["status"], "advisor_confirmed")
        # verify actually resolved the cell -- not left as an unanswered gap.
        self.assertNotEqual(report["summary"]["gate"], "INCONCLUSIVE")

    def test_withheld_engaged_cell_yields_inconclusive(self):
        d = self._repo(["SEC"])
        self._write_cell(d, "SEC")
        manifest = self._manifest()

        result = driver.verify_execute(d, manifest)   # engages SEC, dispatches, never answered
        self.assertEqual(result.checkpoint, "verify")
        self.assertFalse(driver.verify_done(d, manifest))

        synth = driver.synthesize_execute(d, manifest)
        self.assertEqual(synth.kind, "advanced")
        report = driver._load_json(driver._pano(d, "report.json"))
        self.assertEqual(report["summary"]["gate"], "INCONCLUSIVE")
        self.assertIn(["app", "SEC"],
                      report["meta"]["coverage"]["verify_matrix"]["unverified_engaged"])

    def test_resume_checkpoint_names_only_the_undone_cell(self):
        d = self._repo(["SEC", "QAL"])
        self._write_cell(d, "SEC")
        self._write_cell(d, "QAL")
        manifest = self._manifest()

        result = driver.verify_execute(d, manifest)   # both cells pending, one dispatch
        self.assertEqual(result.checkpoint, "verify")
        req = driver._load_json(driver._pano(d, "dispatch-request.json"))
        outs = sorted(os.path.basename(e["out_file"]) for e in req["entries"])
        self.assertEqual(outs, ["verdicts-app-QAL.json", "verdicts-app-SEC.json"])
        sec_entry = next(e for e in req["entries"]
                         if e["out_file"].endswith("verdicts-app-SEC.json"))

        text = self._confirm_bundle(d, manifest, "SEC")
        self._self_write(sec_entry, text)

        result2 = driver.verify_execute(d, manifest)
        self.assertEqual(result2.kind, "checkpoint")
        req2 = driver._load_json(driver._pano(d, "dispatch-request.json"))
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
        driver._write_json(driver._pano(d, "groups.json"),
                           {"groups": [{"name": "app", "files": ["src/app.py"]}]})
        driver._write_json(driver._pano(d, "coverage-app.json"),
                           {"group": "app", "floor": floor, "effective": floor,
                            "run_id": self.RUN_ID})
        return d

    def _manifest(self):
        return {"run_id": self.RUN_ID, "host": "claude", "security_mode": "standard",
                "flags": {"fail_on": "high"}}

    def _self_write_review(self, d, entry, domain, group="app"):
        driver._write_json(entry["out_file"], {
            "findings": [{"title": "issue in %s" % domain, "severity": "HIGH",
                          "domain": domain, "code": domain + "-A1A", "category": "authz",
                          "location": {"file": "src/app.py", "line_start": 1}}],
            "_panopticon": {"run_id": self.RUN_ID, "role": "domain_panel",
                            "domain": domain, "group": group}})

    def _self_write_verify(self, d, manifest, entry, domain, group="app"):
        cell = driver._load_cell_findings(d, manifest, group, domain)
        fid = cell[0]["id"]
        stage = "backup" if entry["out_file"].endswith("-backup.json") else "primary"
        driver._write_json(entry["out_file"], {
            "verdicts": [{"finding_id": fid, "verdict": "CONFIRMED",
                          "reasoning": "verified"}],
            "_panopticon": {"run_id": self.RUN_ID, "role": "domain_advisor",
                            "domain": domain, "group": group, "stage": stage}})

    def test_loop_reaches_graded_report_via_self_writes(self):
        d = self._repo(["SEC"])
        manifest = self._manifest()
        # review checkpoint
        r = driver.review_execute(d, manifest)
        self.assertEqual(r.checkpoint, "review")
        req = driver.load_dispatch_request(d)
        for e in req["entries"]:
            self.assertNotIn("write_mode", e)          # unified self-write shape
            self._self_write_review(d, e, "SEC")
        self.assertTrue(driver.review_done(d, manifest))
        # verify checkpoint (primary; SEC HIGH is < F_b so no backup)
        v = driver.verify_execute(d, manifest)
        self.assertEqual(v.checkpoint, "verify")
        req = driver.load_dispatch_request(d)
        for e in req["entries"]:
            self._self_write_verify(d, manifest, e, "SEC")
        v2 = driver.verify_execute(d, manifest)
        self.assertEqual(v2.kind, "advanced")
        self.assertTrue(driver.verify_done(d, manifest))
        # synthesize → graded report, advisor_confirmed, not INCONCLUSIVE
        self.assertEqual(driver.synthesize_execute(d, manifest).kind, "advanced")
        report = driver._load_json(driver._pano(d, "report.json"))
        finding = next(f for f in report["findings"] if f.get("domain") == "SEC")
        self.assertEqual(finding["evidence"]["status"], "advisor_confirmed")
        self.assertNotEqual(report["summary"]["gate"], "INCONCLUSIVE")

    def test_below_gate_cell_needs_no_verify(self):
        d = self._repo(["QAL"])
        manifest = self._manifest()
        driver.review_execute(d, manifest)
        for e in driver.load_dispatch_request(d)["entries"]:
            driver._write_json(e["out_file"], {
                "findings": [{"title": "nit", "severity": "LOW", "domain": "QAL",
                              "code": "QAL-A1A", "category": "style",
                              "location": {"file": "src/app.py", "line_start": 1}}],
                "_panopticon": {"run_id": self.RUN_ID, "role": "domain_panel",
                                "domain": "QAL", "group": "app"}})
        # QAL LOW scores 0 < F_p → verify engages nothing → advances
        self.assertEqual(driver.verify_execute(d, manifest).kind, "advanced")
        self.assertTrue(driver.verify_done(d, manifest))

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
        driver._write_json(driver._pano(d, "groups.json"),
                           {"groups": [{"name": "app", "files": ["src/app.py"]}]})
        manifest = self._manifest()

        result = driver.coverage_execute(d, manifest)
        self.assertEqual(result.kind, "checkpoint")
        self.assertEqual(result.checkpoint, "scout")
        self.assertFalse(driver.coverage_done(d, manifest))

        req = driver.load_dispatch_request(d)
        self.assertEqual(req["checkpoint"], "scout")
        for entry in req["entries"]:
            # host-side return-persist: no self-write, the host writes what
            # the read-only scout returned.
            driver._write_json(entry["out_file"],
                               {"group": "app", "domains": ["SEC"]})

        result2 = driver.coverage_execute(d, manifest)
        self.assertEqual(result2.kind, "advanced")
        self.assertTrue(driver.coverage_done(d, manifest))


class TestDriverSingleScopeEndToEnd(unittest.TestCase):
    """P6.2: a committed multi-group matrix + `manifest["scope"]` restricts
    the REAL `orchestrator.py --repo-scan --scope-group` subprocess to the
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
        with open(driver._pano(d, "groups.yml"), "w") as fh:
            fh.write(
                "groups:\n"
                "  Auth:\n    match: ['src/auth/**']\n    panels: [SEC]\n"
                "  Checkout:\n    match: ['src/checkout/**']\n    panels: [SEC]\n")
        # discovery_execute subprocesses the REAL orchestrator.py --repo-scan,
        # which discovers via `git ls-files` -- commit the fixture so it's seen.
        subprocess.run(["git", "init", "-q"], cwd=d, check=True)
        subprocess.run(["git", "add", "-A"], cwd=d, check=True)
        subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t",
                        "commit", "-qm", "x"], cwd=d, check=True)
        return d

    def _manifest(self):
        return {"run_id": self.RUN_ID, "host": "claude", "security_mode": "standard",
                "flags": {"fail_on": "high"},
                "scope": {"mode": "group", "target": "Checkout"}}

    def _self_write_review(self, entry, domain, group):
        driver._write_json(entry["out_file"], {
            "findings": [{"title": "issue in %s" % domain, "severity": "HIGH",
                          "domain": domain, "code": domain + "-A1A", "category": "authz",
                          "location": {"file": "src/checkout/pay.py", "line_start": 1}}],
            "_panopticon": {"run_id": self.RUN_ID, "role": "domain_panel",
                            "domain": domain, "group": group}})

    def _self_write_verify(self, d, manifest, entry, domain, group):
        cell = driver._load_cell_findings(d, manifest, group, domain)
        fid = cell[0]["id"]
        stage = "backup" if entry["out_file"].endswith("-backup.json") else "primary"
        driver._write_json(entry["out_file"], {
            "verdicts": [{"finding_id": fid, "verdict": "CONFIRMED",
                          "reasoning": "verified"}],
            "_panopticon": {"run_id": self.RUN_ID, "role": "domain_advisor",
                            "domain": domain, "group": group, "stage": stage}})

    def test_single_scope_restricts_matrix_and_reaches_graded_report(self):
        d = self._repo_with_two_groups()
        manifest = self._manifest()

        # discovery: the real orchestrator.py --repo-scan --scope-group Checkout
        # subprocess -- single-scope restricts the matrix to the target group.
        result = driver.discovery_execute(d, manifest)
        self.assertEqual(result.kind, "advanced")
        groups_json = driver._load_json(driver._pano(d, "groups.json"))
        names = {g["name"] for g in groups_json["groups"]}
        files = sorted(f for g in groups_json["groups"] for f in g["files"])
        self.assertEqual(names, {"Checkout"})              # Auth excluded entirely
        self.assertEqual(files, ["src/checkout/cart.py", "src/checkout/pay.py"])

        # coverage: scout checkpoint (read-only return-persist) then floor+scout
        cov = driver.coverage_execute(d, manifest)
        self.assertEqual(cov.checkpoint, "scout")
        self.assertEqual(cov.group, "Checkout")
        req = driver.load_dispatch_request(d)
        for e in req["entries"]:
            driver._write_json(e["out_file"], {"group": "Checkout", "domains": ["SEC"]})
        self.assertEqual(driver.coverage_execute(d, manifest).kind, "advanced")
        self.assertTrue(driver.coverage_done(d, manifest))

        # review checkpoint -- self-write cell findings, scoped to Checkout's files
        r = driver.review_execute(d, manifest)
        self.assertEqual(r.checkpoint, "review")
        self.assertEqual(r.group, "Checkout")
        req = driver.load_dispatch_request(d)
        for e in req["entries"]:
            self.assertNotIn("write_mode", e)               # unified self-write shape
            self._self_write_review(e, "SEC", "Checkout")
        self.assertTrue(driver.review_done(d, manifest))

        # verify checkpoint -- primary only (SEC HIGH is < F_b, so no backup)
        v = driver.verify_execute(d, manifest)
        self.assertEqual(v.checkpoint, "verify")
        req = driver.load_dispatch_request(d)
        for e in req["entries"]:
            self._self_write_verify(d, manifest, e, "SEC", "Checkout")
        self.assertEqual(driver.verify_execute(d, manifest).kind, "advanced")
        self.assertTrue(driver.verify_done(d, manifest))

        # synthesize -> graded report, every finding confined to Checkout's files
        self.assertEqual(driver.synthesize_execute(d, manifest).kind, "advanced")
        report = driver._load_json(driver._pano(d, "report.json"))
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
        with self.assertRaises(driver.DriverError) as cm:
            driver.discovery_execute(d, manifest)
        self.assertIn("panopticon setup", str(cm.exception))


class TestDriverDeltaEndToEnd(unittest.TestCase):
    """P6.3: the LAST 5.0 driver e2e -- proves the delta (`-c`) + `--pr` paths
    against a REAL git repo, no live `gh`. Mirrors
    TestDriverSingleScopeEndToEnd's real-git-repo + self-write harness
    (P6.2), scoped to `changed` instead of `group`:

    - `-c` delta: the real `orchestrator.py --repo-scan --scope-changed
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
        with open(driver._pano(d, "groups.yml"), "w") as fh:
            fh.write(
                "groups:\n"
                "  Auth:\n    match: ['src/auth/**']\n    panels: [SEC]\n"
                "  Checkout:\n    match: ['src/checkout/**']\n    panels: [SEC]\n")
        subprocess.run(["git", "init", "-q"], cwd=d, check=True)
        subprocess.run(["git", "add", "-A"], cwd=d, check=True)
        subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t",
                        "commit", "-qm", "x"], cwd=d, check=True)
        base_sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=d,
                                  capture_output=True, text=True,
                                  check=True).stdout.strip()
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
        driver._write_json(entry["out_file"], {"group": "Checkout", "domains": ["SEC"]})

    def _self_write_review_two_findings(self, entry):
        """One on-diff LOW (pay.py's edited line 2) and one pre-existing HIGH
        (line 58, far outside the diff-context window) -- both SEC/Checkout.
        Combined cell score (0 + 5*0.8 = 4.0) stays under F_b (8.0), so no
        backup round is summoned."""
        driver._write_json(entry["out_file"], {
            "findings": [
                {"title": "on-diff nit", "severity": "LOW", "domain": "SEC",
                 "code": "SEC-A1A", "category": "authz",
                 "location": {"file": "src/checkout/pay.py", "line_start": 2}},
                {"title": "pre-existing gap", "severity": "HIGH", "domain": "SEC",
                 "code": "SEC-A2A", "category": "authz",
                 "location": {"file": "src/checkout/pay.py", "line_start": 58}},
            ],
            "_panopticon": {"run_id": self.RUN_ID, "role": "domain_panel",
                            "domain": "SEC", "group": "Checkout"}})

    def _self_write_verify_all(self, d, manifest, entry):
        cell = driver._load_cell_findings(d, manifest, "Checkout", "SEC")
        driver._write_json(entry["out_file"], {
            "verdicts": [{"finding_id": f["id"], "verdict": "CONFIRMED",
                          "reasoning": "verified"} for f in cell],
            "_panopticon": {"run_id": self.RUN_ID, "role": "domain_advisor",
                            "domain": "SEC", "group": "Checkout", "stage": "primary"}})

    def test_changed_scope_restricts_matrix_emits_diff_hunks_and_report_has_delta(self):
        d, base_sha = self._repo_with_changed_file()
        manifest = self._manifest(base_sha)

        # discovery: the real orchestrator.py --repo-scan --scope-changed
        # --base subprocess -- restricts groups.json to the one changed file.
        result = driver.discovery_execute(d, manifest)
        self.assertEqual(result.kind, "advanced")
        groups_json = driver._load_json(driver._pano(d, "groups.json"))
        names = {g["name"] for g in groups_json["groups"]}
        files = sorted(f for g in groups_json["groups"] for f in g["files"])
        self.assertEqual(names, {"Checkout"})            # Auth excluded entirely
        self.assertEqual(files, ["src/checkout/pay.py"])  # cart.py unchanged, excluded

        # the orchestrator's on-diff hunk map, alongside groups.json.
        hunks_path = driver._pano(d, "diff-hunks.json")
        self.assertTrue(os.path.isfile(hunks_path))
        hunks = driver._load_json(hunks_path)
        self.assertEqual(hunks["base"], base_sha)
        self.assertEqual(hunks["base_commit"], base_sha)
        self.assertTrue(hunks["includes_uncommitted"])
        self.assertIn("src/checkout/pay.py", hunks["hunks"])

        # coverage: scout checkpoint then floor+scout (SEC only, as committed)
        cov = driver.coverage_execute(d, manifest)
        self.assertEqual(cov.checkpoint, "scout")
        self.assertEqual(cov.group, "Checkout")
        req = driver.load_dispatch_request(d)
        for e in req["entries"]:
            self._self_write_scout(e)
        self.assertEqual(driver.coverage_execute(d, manifest).kind, "advanced")
        self.assertTrue(driver.coverage_done(d, manifest))

        # review checkpoint -- one cell (Checkout/SEC); self-write both
        # findings into it, scoped to pay.py (the only file in play).
        r = driver.review_execute(d, manifest)
        self.assertEqual(r.checkpoint, "review")
        req = driver.load_dispatch_request(d)
        self.assertEqual(len(req["entries"]), 1)
        self._self_write_review_two_findings(req["entries"][0])
        self.assertTrue(driver.review_done(d, manifest))

        # verify checkpoint -- primary only (combined score < F_b, no backup)
        v = driver.verify_execute(d, manifest)
        self.assertEqual(v.checkpoint, "verify")
        req = driver.load_dispatch_request(d)
        self.assertEqual(len(req["entries"]), 1)
        self._self_write_verify_all(d, manifest, req["entries"][0])
        self.assertEqual(driver.verify_execute(d, manifest).kind, "advanced")
        self.assertTrue(driver.verify_done(d, manifest))

        # synthesize -> a graded report with a populated delta block.
        self.assertEqual(driver.synthesize_execute(d, manifest).kind, "advanced")
        report = driver._load_json(driver._pano(d, "report.json"))

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
        self.assertEqual(driver.synthesize_execute(d, manifest).kind, "advanced")
        report_all = driver._load_json(driver._pano(d, "report.json"))
        self.assertEqual(report_all["summary"]["gate"], "FAIL")

    def test_changed_scope_without_committed_groups_yml_raises_loud_setup_error(self):
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        os.makedirs(os.path.join(d, ".panopticon"))   # no groups.yml -- un-setup repo
        manifest = self._manifest(base="deadbeef")
        with self.assertRaises(driver.DriverError) as cm:
            driver.discovery_execute(d, manifest)
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
        subprocess.run(["git", "init", "-q"], cwd=d, check=True)
        wt = driver.diff_map._worktree_dir(d, 7)
        self.addCleanup(lambda: shutil.rmtree(wt, ignore_errors=True))
        created = {"count": 0}

        def fake_acquire_pr(pr_number, repo=".", runner=subprocess.run):
            path = driver.diff_map._worktree_dir(repo, pr_number)
            if not os.path.isdir(path):
                created["count"] += 1
                os.makedirs(path)
            return {"worktree": path, "base": "main", "head_sha": "deadbeef"}

        with mock.patch.object(driver.diff_map, "acquire_pr",
                               side_effect=fake_acquire_pr) as m:
            root1, worktree1, base1 = driver.resolve_review_root(d, pr=7)
            root2, worktree2, base2 = driver.resolve_review_root(d, pr=7)

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
        subprocess.run(["git", "init", "-q"], cwd=d, check=True)
        driver.capture_tree_baseline(d)   # real git status --porcelain, clean
        wt = driver.diff_map._worktree_dir(d, 7)
        manifest = {"run_id": self.RUN_ID, "worktree": wt}

        with mock.patch.object(driver.diff_map, "release_worktree") as rel:
            result = driver.validate_execute(d, manifest)

        self.assertEqual(result.kind, "advanced")
        rel.assert_not_called()
        validate = driver._load_json(driver._pano(d, "validate.json"))
        self.assertTrue(validate["tree_clean"])
        self.assertEqual(validate["unexpected_changes"], [])


class TestDriverSetup(unittest.TestCase):
    def _repo(self):
        import shutil as _sh
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: _sh.rmtree(d, ignore_errors=True))
        g = ["git", "-C", d]
        subprocess.run(["git", "init", "-q", d], check=True)
        subprocess.run(g + ["config", "user.email", "t@t"], check=True)
        subprocess.run(g + ["config", "user.name", "t"], check=True)
        os.makedirs(os.path.join(d, "src", "checkout"))
        with open(os.path.join(d, "src", "checkout", "pay.py"), "w") as fh:
            fh.write("x = 1\n")
        subprocess.run(g + ["add", "-A"], check=True)
        subprocess.run(g + ["commit", "-qm", "init"], check=True)
        subprocess.run(g + ["branch", "-M", "main"], check=True)
        return d

    def test_setup_verb_parses(self):
        args = driver.build_parser().parse_args(["setup", "."])
        self.assertEqual(args.verb, "setup")

    def test_scan_emits_setup_scan_checkpoint_when_vocab_present(self):
        d = self._repo()
        args = driver.build_parser().parse_args(["setup", d])
        status = driver.run_setup_flow(args)
        self.assertEqual(status["status"], "checkpoint")
        self.assertEqual(status["checkpoint"], "scan")
        req = driver._load_json(driver._pano(d, "dispatch-request.json"))
        self.assertEqual(req["checkpoint"], "scan")
        entry = req["entries"][0]
        self.assertEqual(entry["id"], "setup-scan")
        self.assertTrue(entry["out_file"].endswith("setup-proposal.json"))
        self.assertTrue(os.path.isfile(driver._pano(d, "setup-scan-brief.md")))

    def test_ingest_writes_draft_then_completes(self):
        d = self._repo()
        args = driver.build_parser().parse_args(["setup", d])
        driver.run_setup_flow(args)                       # scan checkpoint
        proposal = {"groups": [{"capability": "Checkout",
                                "match": ["src/checkout/**"], "tests": []}]}
        with open(driver._pano(d, "setup-proposal.json"), "w") as fh:
            json.dump(proposal, fh)
        status = driver.run_setup_flow(args)              # re-invoke -> ingest
        self.assertEqual(status["status"], "complete")
        self.assertTrue(os.path.isfile(driver._pano(d, "groups.yml.draft")))
        self.assertFalse(os.path.isfile(driver._pano(d, "groups.yml")))


if __name__ == "__main__":
    unittest.main()
