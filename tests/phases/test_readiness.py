"""#1637 P08: scanner readiness is an orchestrator CHECKPOINT, not a flag.

Run-13 paid for 12 scouts, then skipped the tool scan (the image was absent
while Docker itself was up), then dispatched 85 panels with no scanner context
-- and the `skipped: true` marker cached that skip for the rest of the run. The
answer (owner ruling D7) is a deterministic `readiness` phase at the HEAD of
`driver.PHASES`, ahead of `discovery` and therefore ahead of the first paid
dispatch, which fails CLOSED on a missing tools image unless `--no-tools` was
passed and prints the exact, copy-pasteable remedy.

Everything here is asserted through `driver.run` / `orchestrate.loop` rather
than by calling the phase directly: "no scout checkpoint was emitted" is the
property that matters, and it is only true of the whole engine.

No real Docker. The docker probe is reached through `readiness_checks.DOCKER_RUNNER`,
a module-level seam the tests swap for a fake -- `tests/conftest.py`'s autouse
`_refuse_setup_docker` delegates an INJECTED runner to the real check and
refuses only the un-injected default, so a test that wants "image present"
states it and one that states nothing reaches nothing.
"""
import json
import os
import tempfile
import unittest
from unittest import mock

from _test_helpers import all_proven_artifact as _all_proven_artifact
import scripts.driver as driver
import scripts.phases.readiness as readiness
import scripts.phases.runio as runio
import scripts.run_manifest as run_manifest

from tools.git_repo import make_git_repo


_READINESS = "scripts.phases.readiness"
_READINESS_CHECKS = "scripts.phases.readiness_checks"

# The one spelling of the pull remedy the operator is supposed to be able to
# paste. Pinned here as a literal, not imported from the module under test: a
# remedy that drifts is a remedy that does not work, and importing it would
# make the test agree with whatever it became.
PULL_REMEDY = ("docker pull ghcr.io/panopticon-scanner/panopticon-tools:latest "
               "&& docker tag ghcr.io/panopticon-scanner/panopticon-tools:latest "
               "panopticon-tools:latest")


class _Probe:
    def __init__(self, returncode):
        self.returncode, self.stdout, self.stderr = returncode, "", ""


def _docker_runner(*, daemon=0, image=0):
    """A fake `subprocess.run` answering only the two argv readiness probes."""
    def runner(cmd, **_kw):
        if list(cmd[:3]) == ["docker", "image", "inspect"]:
            return _Probe(image)
        return _Probe(daemon)
    return runner


_run_probes_patch = None


def setUpModule():
    # Same reason as tests/test_driver.py: driver.run() probes the host for
    # real on every invocation, and this file is about phase ORDER, not about
    # what happens to be registered on the developer's machine.
    global _run_probes_patch
    _run_probes_patch = mock.patch(
        "scripts.host_probes.run_probes",
        side_effect=lambda host, target, **kw: _all_proven_artifact(host))
    _run_probes_patch.start()


def tearDownModule():
    _run_probes_patch.stop()


class _ReadinessCase(unittest.TestCase):
    def _repo(self):
        return make_git_repo(
            test_case=self,
            files={"src/app.py": "def f():\n    return 1\n"},
            groups_yml="groups:\n  Core:\n    match: ['src/**']\n    panels: [COD]\n",
            branch="main", user_email="t@t", user_name="t")

    def _args(self, target, *extra):
        return driver.build_parser().parse_args(["run", target, *extra])

    def _readiness_json(self, root):
        return runio._load_json(runio._pano(root, "readiness.json"))

    def _rows(self, root):
        return {c["name"]: c for c in self._readiness_json(root)["checks"]}


class TestFailsClosedBeforeAnyPaidScouting(_ReadinessCase):

    def test_online_sidecar_warning_precedes_scouting_and_names_the_pull(self):
        from scripts.tools import egress
        d = self._repo()
        def runner(cmd, **kw):
            return _Probe(1 if cmd[-1] == egress.PROXY_IMAGE else 0)
        with mock.patch(_READINESS_CHECKS + ".DOCKER_RUNNER", runner):
            status = driver.run(self._args(d, "--online"))
        self.assertEqual(status["checkpoint"], "scout", status)
        row = self._rows(d)["egress-proxy"]
        self.assertIsNone(row["ok"])
        self.assertEqual(row["level"], "warn")
        self.assertIn("docker pull " + egress.PROXY_IMAGE, row["detail"])
        self.assertTrue(self._readiness_json(d)["flags"]["online"])

    def test_offline_cached_readiness_is_not_valid_for_an_online_run(self):
        d = self._repo()
        with mock.patch(_READINESS_CHECKS + ".DOCKER_RUNNER", _docker_runner()):
            driver.run(self._args(d))
        manifest = run_manifest.load_manifest(d)
        manifest["flags"]["online"] = True
        self.assertFalse(readiness.readiness_done(d, manifest))

    def test_image_absent_with_tools_enabled_refuses_before_the_scout(self):
        d = self._repo()
        with mock.patch(_READINESS_CHECKS + ".DOCKER_RUNNER",
                        _docker_runner(daemon=0, image=1)):
            status = driver.run(self._args(d))
        self.assertEqual(status["status"], "error", status)
        self.assertIsNone(status.get("checkpoint"))
        self.assertIn(PULL_REMEDY, status["message"])
        self.assertIn("docker build -t panopticon-tools", status["message"])
        self.assertIn("--no-tools", status["message"])
        # The whole point: nothing was dispatched. No request file, and no
        # scout artifact, because `coverage` was never reached.
        self.assertFalse(os.path.exists(runio._pano(d, "dispatch-request.json")))
        self.assertFalse(os.path.exists(runio._pano(d, "groups.json")))

    def test_the_refusal_writes_a_ready_false_artifact_naming_the_row(self):
        d = self._repo()
        with mock.patch(_READINESS_CHECKS + ".DOCKER_RUNNER",
                        _docker_runner(daemon=0, image=1)):
            driver.run(self._args(d))
        body = self._readiness_json(d)
        self.assertIs(body["ready"], False)
        rows = self._rows(d)
        self.assertIs(rows["docker"]["ok"], True)
        self.assertIs(rows["tools-image"]["ok"], False)
        self.assertIn(PULL_REMEDY, rows["tools-image"]["detail"])

    def test_a_missing_python_dependency_refuses_before_the_scout(self):
        # #1639 P15 fix round 2, F7: the dependencies row existed only in the
        # `driver readiness` VERB. `driver loop` goes through this PHASE, which
        # exists precisely to stop a run before the first paid dispatch, and it
        # had the answer available and did not ask -- so a machine without
        # `jsonschema` paid for the whole review and then exited `artifact
        # invalid`, because the completion path's validation is (correctly)
        # fail-closed.
        d = self._repo()
        with mock.patch(_READINESS_CHECKS + ".DOCKER_RUNNER",
                        _docker_runner(daemon=0, image=0)), \
                mock.patch(_READINESS_CHECKS + "._installed",
                           side_effect=lambda name: name != "jsonschema"):
            status = driver.run(self._args(d))
        self.assertEqual(status["status"], "error", status)
        self.assertIn("pip install jsonschema", status["message"])
        self.assertFalse(os.path.exists(runio._pano(d, "dispatch-request.json")))
        rows = self._rows(d)
        self.assertIs(rows["dependencies"]["ok"], False)
        self.assertIn("pip install", rows["dependencies"]["detail"])

    def test_a_complete_install_leaves_the_row_green(self):
        d = self._repo()
        with mock.patch(_READINESS_CHECKS + ".DOCKER_RUNNER",
                        _docker_runner(daemon=0, image=0)):
            driver.run(self._args(d))
        rows = self._rows(d)
        self.assertIs(rows["dependencies"]["ok"], True)
        self.assertIn("installed", rows["dependencies"]["detail"])

    def test_a_dead_daemon_refuses_too_and_names_its_own_remedy(self):
        d = self._repo()
        with mock.patch(_READINESS_CHECKS + ".DOCKER_RUNNER",
                        _docker_runner(daemon=1, image=1)):
            status = driver.run(self._args(d))
        self.assertEqual(status["status"], "error", status)
        self.assertIn("docker unavailable", status["message"])
        self.assertIn("--no-tools", status["message"])

    def test_driver_loop_surfaces_the_refusal_as_its_error_status(self):
        import scripts.orchestrate as orchestrate
        d = self._repo()
        args = driver.build_parser().parse_args(
            ["loop", d, "--mode", "session", "--host", "claude"])
        with mock.patch(_READINESS_CHECKS + ".DOCKER_RUNNER",
                        _docker_runner(daemon=0, image=1)):
            status = orchestrate.loop(args)
        self.assertEqual(status["status"], "error", status)
        self.assertIn(PULL_REMEDY, status["message"])


class TestTheDisclosedOptOut(_ReadinessCase):

    def test_no_tools_passes_with_null_docker_rows_and_the_run_proceeds(self):
        d = self._repo()
        # No DOCKER_RUNNER stub at all: --no-tools must not probe anything.
        status = driver.run(self._args(d, "--no-tools"))
        self.assertEqual(status["status"], "checkpoint", status)
        self.assertEqual(status["checkpoint"], "scout")
        body = self._readiness_json(d)
        self.assertIs(body["ready"], True)
        rows = self._rows(d)
        for name in ("docker", "tools-image"):
            self.assertIsNone(rows[name]["ok"], rows[name])
            self.assertIn("not applicable (--no-tools)", rows[name]["detail"])

    def test_the_artifact_pins_its_shape(self):
        d = self._repo()
        driver.run(self._args(d, "--no-tools"))
        body = self._readiness_json(d)
        self.assertEqual(body["schema_version"], 1)
        self.assertEqual(body["run_id"], run_manifest.load_manifest(d)["run_id"])
        self.assertIsInstance(body["checked_at"], str)
        self.assertEqual(body["flags"], {"tools": False, "online": False})
        self.assertIsInstance(body["checks"], list)
        for row in body["checks"]:
            # `level` is optional -- readiness_execute only adds it (always
            # "warn", alongside `ok: None`) to a row whose raw check answered
            # "warn" rather than True/False/None. This run's rows do not
            # (--no-tools takes every check off the warn-capable path), but
            # the shape pin has to allow the key a row CAN carry, not just
            # the keys these particular rows happen to have.
            self.assertLessEqual(set(row), {"detail", "name", "ok", "level"})
            self.assertGreaterEqual(set(row), {"detail", "name", "ok"})
            self.assertIsInstance(row["name"], str)
            self.assertIsInstance(row["detail"], str)
            self.assertIn(row["ok"], (True, False, None))
            if "level" in row:
                self.assertEqual(row["level"], "warn")
                self.assertIsNone(row["ok"])
        # The host posture is recorded, never re-derived and never gating.
        self.assertIsNone(self._rows(d)["host-capabilities"]["ok"])


class TestTheDonePredicateIsNotACachedPass(_ReadinessCase):

    def test_a_stale_artifact_whose_tools_flag_differs_is_re_evaluated(self):
        d = self._repo()
        self.assertEqual(driver.run(self._args(d, "--no-tools"))["status"],
                         "checkpoint")
        # The operator flips the run to tools-enabled. The artifact on disk
        # still says `ready` under `tools: false`; trusting it would walk
        # straight past the check the flip just made relevant.
        path = run_manifest.manifest_path(d)
        manifest = run_manifest.load_manifest(d)
        manifest["flags"]["tools"] = None
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh)
        with mock.patch(_READINESS_CHECKS + ".DOCKER_RUNNER",
                        _docker_runner(daemon=0, image=1)):
            status = driver.run(self._args(d))
        self.assertEqual(status["status"], "error", status)
        self.assertIn(PULL_REMEDY, status["message"])

    def test_a_pass_is_not_re_run_on_the_next_invocation(self):
        d = self._repo()
        driver.run(self._args(d, "--no-tools"))
        first = self._readiness_json(d)["checked_at"]
        driver.run(self._args(d, "--no-tools"))
        self.assertEqual(self._readiness_json(d)["checked_at"], first)


class TestReadinessIsWiredAsThePhase(_ReadinessCase):

    def test_readiness_is_the_first_phase(self):
        self.assertEqual([p.name for p in driver.PHASES][:2],
                         ["readiness", "discovery"])
        self.assertEqual(driver.PHASES[0].kind, "deterministic")

    def test_the_phase_cannot_reach_a_runner_or_a_host_probe(self):
        """Ruling 2: readiness establishes NOTHING about the host -- the
        posture is already established by `driver._establish_host_posture` on
        every invocation, and `setup_flow._check_host_shells` launches a CLI.
        Asserted on the module's own import graph, because the day someone
        reaches for `run_probes` here is the day readiness starts costing a
        host launch. BOTH halves of the phase: item 25e moved the environment
        checks -- the half that actually looks at the machine -- into
        `readiness_checks`, and a guard left pointing at only the assembler
        would watch the wrong file."""
        import ast
        import scripts.phases.readiness as readiness
        import scripts.phases.readiness_checks as readiness_checks
        for module in (readiness, readiness_checks):
            with open(module.__file__, encoding="utf-8") as fh:
                tree = ast.parse(fh.read(), module.__file__)
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(a.name for a in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.add(node.module)
            for banned in ("scripts.host_probes", "scripts.runners",
                           "scripts.probes.common", "scripts.dispatch"):
                self.assertFalse(any(m == banned or m.startswith(banned + ".")
                                     for m in imported),
                                 "%s imports %s" % (module.__name__, banned))

    def test_the_docker_runner_seam_is_none_in_production(self):
        """F4: `DOCKER_RUNNER` is a test-only injection point. A non-None value
        left behind in production code makes readiness answer off a fake --
        "ok" without ever probing Docker -- and that is the check gating every
        paid dispatch. Two halves: the shipped default, and nothing outside
        tests/ ever assigning it."""
        import ast
        import subprocess
        import sys
        from conftest import REPO_ROOT, SKILL_ROOT
        # Asserted in a FRESH interpreter: this process has patched the
        # attribute a dozen times by now, so reading it here proves nothing.
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(
            [SKILL_ROOT, os.path.join(SKILL_ROOT, "scripts")]
            + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else []))
        proc = subprocess.run(  # nosec B603
            [sys.executable, "-c",
             "import scripts.phases.readiness_checks as r; print(repr(r.DOCKER_RUNNER))"],
            capture_output=True, text=True, timeout=30, env=env, cwd=REPO_ROOT)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), "None")

        offenders = []
        for base in (os.path.join(SKILL_ROOT, "scripts"),
                     os.path.join(REPO_ROOT, "scripts")):
            for dirpath, dirnames, filenames in os.walk(base):
                dirnames[:] = [x for x in dirnames if x != "__pycache__"]
                for filename in sorted(filenames):
                    if not filename.endswith(".py"):
                        continue
                    path = os.path.join(dirpath, filename)
                    with open(path, encoding="utf-8") as fh:
                        tree = ast.parse(fh.read(), path)
                    for node in ast.walk(tree):
                        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                            continue
                        targets = (node.targets if isinstance(node, ast.Assign)
                                   else [node.target])
                        for target in targets:
                            name = (target.id if isinstance(target, ast.Name)
                                    else target.attr
                                    if isinstance(target, ast.Attribute) else None)
                            if name != "DOCKER_RUNNER":
                                continue
                            ok = (os.path.basename(path) == "readiness_checks.py"
                                  and isinstance(node.value, ast.Constant)
                                  and node.value.value is None)
                            if not ok:
                                offenders.append("%s:%d: %s" % (
                                    os.path.relpath(path, REPO_ROOT),
                                    node.lineno, ast.unparse(node)))
        self.assertEqual(offenders, [],
                         "DOCKER_RUNNER is a test-only seam; production code "
                         "must leave it None:\n" + "\n".join(offenders))

    def test_the_launch_guard_still_finds_exactly_the_known_seams(self):
        from test_host_launch_guard import _seams
        relatives = [relative for _, relative, _ in _seams()]
        for name in ("readiness.py", "readiness_checks.py"):
            self.assertNotIn(os.path.join("phases", name), relatives)


class TestMatrixRowNamesTheResolvedConfig(unittest.TestCase):
    """#1681 Task 7: `_matrix_row` reads through `repo_config`, so the
    resolved config path is part of the row -- and a refusal (a legacy-only
    tree, a symlinked config name) comes back as a failed ROW, never a
    traceback out of a preflight."""

    def test_matrix_row_names_the_resolved_config(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, ".panopticon.yml"), "w").write(
                "version: 1\ngroups:\n  A:\n    match: ['a/**']\n")
            row = readiness._matrix_row(d)
            self.assertEqual(row["config"], os.path.join(d, ".panopticon.yml"))
            self.assertTrue(row["ok"])

    def test_matrix_row_refuses_a_legacy_tree_with_the_remedy(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".panopticon"))
            open(os.path.join(d, ".panopticon", "groups.yml"), "w").write("groups: {}\n")
            row = readiness._matrix_row(d)
            self.assertFalse(row["ok"])
            self.assertIn("migrate-config", row["detail"])
            self.assertEqual(row["config"], "none")

    def test_matrix_row_reports_a_symlinked_config_as_a_refusal_not_the_no_groups_row(self):
        with tempfile.TemporaryDirectory() as d:
            os.symlink("elsewhere.yml", os.path.join(d, "panopticon.yml"))
            row = readiness._matrix_row(d)
            self.assertFalse(row["ok"])
            self.assertIn("symlink", row["detail"])
            self.assertEqual(row["config"], "none")


if __name__ == "__main__":
    unittest.main()


class TestTheExistingRunRowReadsTheRequestBound(unittest.TestCase):
    """#1727: the `existing_run` row's pending COUNT is read out of
    `dispatch-request.json`, a file in the reviewed tree. Once the run has
    recorded a hash for it, the row reads it bound -- a file that no longer
    matches reports NO count and says why, rather than a number derived from
    a request this run cannot vouch for. A run with no record (one written
    before the key existed) reads exactly as it did."""

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        self.addCleanup(self._t.cleanup)
        os.makedirs(os.path.join(self.root, ".panopticon"))
        run_manifest.write_manifest(self.root, {
            "schema_version": 1, "run_id": "0123456789abcdef", "host": "claude",
            "security_mode": "standard", "created": "2026-09-20T00:00:00Z",
            "review_root": self.root, "target": self.root})
        self.tag = run_manifest.run_tag(run_manifest.load_manifest(self.root))
        runs = os.path.join(self.root, ".panopticon", "runs")
        os.makedirs(os.path.join(runs, self.tag))
        os.symlink(self.tag, os.path.join(runs, "latest"))

    def _entries(self):
        import scripts.phases.requests as requests
        pending = os.path.join(self.root, ".panopticon", "runs", self.tag, "b.json")
        return requests.write_dispatch_request(
            self.root, "RID", "review", None,
            [{"id": "b", "prompt": "p", "out_file": pending}])

    def test_a_recorded_request_still_reports_its_pending_count(self):
        self._entries()
        row = readiness._existing_run_row(self.root)
        self.assertEqual(("checkpoint", 1), (row["status"], row["pending"]))
        self.assertEqual(self.tag, row["tag"])

    def test_a_request_that_no_longer_matches_reports_no_count(self):
        path = self._entries()
        with open(path, "ab") as fh:
            fh.write(b" ")
        row = readiness._existing_run_row(self.root)
        self.assertIsNone(row["pending"])
        self.assertIn("pending count unknown", row["detail"])
        self.assertIn("does not match the request this run wrote", row["detail"])
        self.assertEqual(self.tag, row["tag"])

    def test_a_run_with_no_recorded_hash_reads_as_it_always_did(self):
        path = self._entries()
        manifest = run_manifest.load_manifest(self.root)
        manifest.pop("dispatch_request")
        run_manifest._rewrite(self.root, manifest)
        with open(path, "ab") as fh:
            fh.write(b" ")
        row = readiness._existing_run_row(self.root)
        self.assertEqual(("checkpoint", 1), (row["status"], row["pending"]))
