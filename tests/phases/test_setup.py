"""Tests for scripts.phases.setup: the `driver setup` scan/ingest flow and its manifest.
"""
import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

import scripts.phases.runio as runio
import scripts.phases.setup as setup
import scripts.phases.setup as setup_phase
import scripts.phases.requests as requests

import scripts.driver as driver
import scripts.coverage_model as coverage_model
import scripts.host_disclosure as host_disclosure
import scripts.hosts as hosts
import scripts.setup_flow as setup_flow
import scripts.model_resolver as model_resolver

from tools.git_repo import make_git_repo


class TestDriverSetup(unittest.TestCase):
    def _repo(self):
        return make_git_repo(
            test_case=self,
            files={"src/checkout/pay.py": "x = 1\n"},
            branch="main",
            user_email="t@t",
            user_name="t",
        )

    def test_setup_verb_parses(self):
        args = driver.build_parser().parse_args(["setup", "."])
        self.assertEqual(args.verb, "setup")

    def test_scan_emits_setup_scan_checkpoint_when_vocab_present(self):
        d = self._repo()
        args = driver.build_parser().parse_args(["setup", d])
        status = setup.run_setup_flow(args)
        self.assertEqual(status["status"], "checkpoint")
        self.assertEqual(status["checkpoint"], "scan")
        req = runio._load_json(requests.request_path(d, namespace="setup"))
        self.assertEqual(req["checkpoint"], "scan")
        entry = req["entries"][0]
        self.assertEqual(entry["id"], "setup-scan")
        self.assertTrue(entry["out_file"].endswith("setup-proposal.json"))
        self.assertTrue(os.path.isfile(runio._pano(d, "setup-scan-brief.md")))

    def test_setup_scan_is_deliberately_not_model_bound(self):
        # R-F4-2. setup-scan has no role in dispatch.ROLE_FILES and no profile
        # entry; resolve_model would hand it the host's catch-all default and
        # silently move the one judgement-heavy, one-off `driver setup`
        # dispatch off the session's model. The exception is pinned so it
        # stays a decision rather than becoming an omission.
        d = self._repo()
        with mock.patch.object(model_resolver, "resolve_model",
                               return_value={"model": "SENTINEL"}) as rm:
            entry = setup._setup_scan_entry(d, "PROMPT")
        self.assertIsNone(entry["model"])
        rm.assert_not_called()

    def test_scan_leaves_blanket_gitignore_and_notes_forced_add(self):
        # #1135: a repo already blanket-ignoring .panopticon/ keeps its
        # .gitignore untouched (no migration to /*), and the scan surfaces that
        # groups.yml must be `git add -f`-ed.
        d = self._repo()
        with open(os.path.join(d, ".gitignore"), "w") as fh:
            fh.write(".panopticon/\n")
        args = driver.build_parser().parse_args(["setup", d])
        status = setup.run_setup_flow(args)
        self.assertIn("git add -f", status["message"])
        with open(os.path.join(d, ".gitignore"), encoding="utf-8") as fh:
            gi = fh.read()
        self.assertIn(".panopticon/", gi)
        self.assertNotIn(".panopticon/*", gi)   # not migrated in place

    def test_ingest_writes_draft_then_completes(self):
        d = self._repo()
        args = driver.build_parser().parse_args(["setup", d])
        setup.run_setup_flow(args)                       # scan checkpoint
        proposal = {"groups": [{"capability": "Checkout",
                                "match": ["src/checkout/**"], "tests": []}]}
        with open(runio._pano(d, "setup-proposal.json"), "w") as fh:
            json.dump(proposal, fh)
        status = setup.run_setup_flow(args)              # re-invoke -> ingest
        self.assertEqual(status["status"], "complete")
        self.assertTrue(os.path.isfile(runio._pano(d, "groups.yml.draft")))
        self.assertFalse(os.path.isfile(runio._pano(d, "groups.yml")))

    def test_vocab_absent_falls_back_to_seed_and_completes(self):
        # The bundled fixture is always present, so force absence at the loader
        # boundary to exercise the fallback path deterministically.
        d = self._repo()
        args = driver.build_parser().parse_args(["setup", d])
        with mock.patch("scripts.setup_flow.load_bundled_vocabulary",
                        return_value=({"names": []}, False)):
            status = setup.run_setup_flow(args)
        self.assertEqual(status["status"], "complete")
        self.assertTrue(runio._json_parses(runio._pano(d, "setup-complete.json")))
        self.assertTrue(os.path.isfile(runio._pano(d, "groups.yml")))   # flat seed
        # no scan checkpoint was emitted
        self.assertFalse(os.path.isfile(runio._pano(d, "setup-proposal.json")))

    def test_stale_fallback_marker_self_heals_when_vocab_returns(self):
        # First run: vocab absent -> fallback marker written, run completes
        # without a checkpoint.
        d = self._repo()
        args = driver.build_parser().parse_args(["setup", d])
        with mock.patch("scripts.setup_flow.load_bundled_vocabulary",
                        return_value=({"names": []}, False)):
            status1 = setup.run_setup_flow(args)
        self.assertEqual(status1["status"], "complete")
        marker = runio._load_json(runio._pano(d, "setup-complete.json"))
        self.assertEqual(marker["mode"], "fallback")

        # Re-invoke WITHOUT --reset, vocab now present (no mock => real bundled
        # fixture). Without the self-heal, scan_done/ingest_done would both
        # short-circuit on the stale marker and this would return "complete"
        # again, reusing the flat fallback seed instead of running a real scan.
        status2 = setup.run_setup_flow(args)
        self.assertEqual(status2["status"], "checkpoint")
        self.assertEqual(status2["checkpoint"], "scan")
        self.assertFalse(runio._json_parses(runio._pano(d, "setup-complete.json")))
        self.assertTrue(os.path.isfile(runio._pano(d, "setup-scan-brief.md")))

    def test_completion_message_branches_on_draft_vs_fallback(self):
        # vocab-absent fallback: flat groups.yml, no draft -> message must not
        # send the owner looking for a groups.yml.draft that was never written.
        d1 = self._repo()
        args1 = driver.build_parser().parse_args(["setup", d1])
        with mock.patch("scripts.setup_flow.load_bundled_vocabulary",
                        return_value=({"names": []}, False)):
            status1 = setup.run_setup_flow(args1)
        self.assertEqual(status1["status"], "complete")
        self.assertNotIn("draft", status1["message"])
        self.assertIn("groups.yml", status1["message"])

        # vocab-present path: ingest writes a real draft -> message should
        # point the owner at it.
        d2 = self._repo()
        args2 = driver.build_parser().parse_args(["setup", d2])
        setup.run_setup_flow(args2)                       # scan checkpoint
        proposal = {"groups": [{"capability": "Checkout",
                                "match": ["src/checkout/**"], "tests": []}]}
        with open(runio._pano(d2, "setup-proposal.json"), "w") as fh:
            json.dump(proposal, fh)
        status2 = setup.run_setup_flow(args2)              # re-invoke -> ingest
        self.assertEqual(status2["status"], "complete")
        self.assertIn("draft", status2["message"])

    def test_fallback_message_surfaces_readiness_gaps(self):
        # Force a deterministic readiness gap (a docker check that failed)
        # rather than relying on the real docker/tools-image state of the
        # machine running the tests -- that state varies by environment and
        # would make this assertion flaky.
        d = self._repo()
        args = driver.build_parser().parse_args(["setup", d])
        fake_checks = [("docker", False,
                        "docker unavailable -- install/start Docker or run with --no-tools")]
        with mock.patch("scripts.setup_flow.load_bundled_vocabulary",
                        return_value=({"names": []}, False)), \
             mock.patch("scripts.setup_flow.readiness", return_value=fake_checks):
            status = setup.run_setup_flow(args)
        self.assertEqual(status["status"], "complete")
        self.assertIn("readiness gaps", status["message"])
        self.assertIn("docker", status["message"])

    def test_ingest_malformed_proposal_errors(self):
        d = self._repo()
        args = driver.build_parser().parse_args(["setup", d])
        setup.run_setup_flow(args)
        with open(runio._pano(d, "setup-proposal.json"), "w") as fh:
            json.dump({"groups": [{"capability": "", "match": []}]}, fh)
        status = setup.run_setup_flow(args)
        self.assertEqual(status["status"], "error")
        self.assertFalse(os.path.isfile(runio._pano(d, "groups.yml.draft")))

    def test_reset_clears_setup_artifacts(self):
        d = self._repo()
        args = driver.build_parser().parse_args(["setup", d])
        setup.run_setup_flow(args)                        # scan checkpoint: brief + manifest
        self.assertTrue(os.path.isfile(runio._pano(d, "setup-scan-brief.md")))
        # Simulate a real returned proposal sitting on disk pre-reset (the host
        # wrote it back but it was never ingested) -- a genuine artifact for
        # --reset to clear, not one that never existed.
        proposal = {"groups": [{"capability": "Checkout",
                                "match": ["src/checkout/**"], "tests": []}]}
        with open(runio._pano(d, "setup-proposal.json"), "w") as fh:
            json.dump(proposal, fh)
        run_id_before = setup.load_setup_manifest(d)["run_id"]

        reset_args = driver.build_parser().parse_args(["setup", d, "--reset"])
        setup.run_setup_flow(reset_args)                  # clears, then re-scans

        # the pre-existing proposal was actually removed (not left for the
        # re-scan to trip over as a stale "already done" marker)
        self.assertFalse(os.path.isfile(runio._pano(d, "setup-proposal.json")))
        # the setup-manifest was regenerated, not reused -> a genuinely fresh run
        self.assertNotEqual(setup.load_setup_manifest(d)["run_id"], run_id_before)
        # a real re-scan happened (brief re-rendered under the fresh run)
        self.assertTrue(os.path.isfile(runio._pano(d, "setup-scan-brief.md")))

    def test_foreign_setup_manifest_is_discarded_and_rebuilt(self):
        # #run7 AGT-C1A: a target-committed setup-manifest stamped with a foreign
        # review_root (presetting a hostile vocabulary_path) must be discarded and
        # rebuilt from args, mirroring the run-manifest #1093 guard.
        import io, contextlib
        d = self._repo()
        os.makedirs(runio._pano(d), exist_ok=True)
        runio._write_json(runio._pano(d, "setup-manifest.json"),
                           {"schema_version": 1, "run_id": "FOREIGN",
                            "review_root": "/somewhere/else",
                            "vocabulary_path": "/etc/hostile-vocab.yml",
                            "host": "claude"})
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            setup.run_setup_flow(driver.build_parser().parse_args(["setup", d]))
        m = setup.load_setup_manifest(d)
        self.assertNotEqual(m["review_root"], "/somewhere/else")   # re-stamped to THIS tree
        self.assertNotEqual(m["run_id"], "FOREIGN")                # rebuilt, not reused
        self.assertIsNone(m["vocabulary_path"])                    # hostile path dropped
        self.assertIn("ignoring foreign setup-manifest", err.getvalue())

    def test_reset_preserves_committed_groups_yml(self):
        d = self._repo()
        os.makedirs(runio._pano(d), exist_ok=True)
        committed_path = runio._pano(d, "groups.yml")
        content = "groups:\n  checkout:\n    match:\n      - src/checkout/**\n"
        with open(committed_path, "w") as fh:
            fh.write(content)

        args = driver.build_parser().parse_args(["setup", d])
        setup.run_setup_flow(args)                        # scan checkpoint

        reset_args = driver.build_parser().parse_args(["setup", d, "--reset"])
        setup.run_setup_flow(reset_args)                  # clears setup artifacts only

        self.assertTrue(os.path.isfile(committed_path))
        with open(committed_path, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), content)

    def test_setup_end_to_end_loop(self):
        """scan checkpoint -> host persists proposal -> re-invoke ingests ->
        complete, draft present, committed groups.yml never written."""
        d = self._repo()
        args = driver.build_parser().parse_args(["setup", d])
        s1 = setup.run_setup_flow(args)
        self.assertEqual(s1["checkpoint"], "scan")
        entry = runio._load_json(
            requests.request_path(d, namespace="setup"))["entries"][0]
        # host return-persist: write the returned proposal to entry["out_file"]
        with open(entry["out_file"], "w") as fh:
            json.dump({"groups": [{"capability": "Checkout",
                                   "match": ["src/checkout/**"], "tests": []}]}, fh)
        s2 = setup.run_setup_flow(args)
        self.assertEqual(s2["status"], "complete")
        self.assertIn("groups.yml.draft", "".join(os.listdir(runio._pano(d))))
        self.assertFalse(os.path.isfile(runio._pano(d, "groups.yml")))

    def test_setup_size_flags_pin_the_manifest_and_reach_the_report(self):
        # 5.2: --max-per-group/--max-groups are pinned in setup-manifest.json at
        # scan time and honoured by ingest; the report artifacts are written
        # and the completion message points at the report.
        d = self._repo()
        args = driver.build_parser().parse_args(
            ["setup", d, "--max-per-group", "3", "--max-groups", "5"])
        setup.run_setup_flow(args)                       # scan checkpoint
        manifest = setup.load_setup_manifest(d)
        self.assertEqual((manifest["max_per_group"], manifest["max_groups"]), (3, 5))
        with open(runio._pano(d, "setup-proposal.json"), "w") as fh:
            json.dump({"groups": [{"capability": "Checkout",
                                   "match": ["src/checkout/**"], "tests": []}]}, fh)
        status = setup.run_setup_flow(args)              # re-invoke -> ingest
        self.assertEqual(status["status"], "complete")
        self.assertIn("setup-report.md", status["message"])
        report = runio._load_json(runio._pano(d, "setup-report.json"))["report"]
        self.assertEqual((report["cap"], report["ceiling"]), (3, 5))
        self.assertTrue(os.path.isfile(runio._pano(d, "setup-report.md")))
        # a bare re-invocation resumes the pinned manifest, not the (absent) flags
        status = setup.run_setup_flow(driver.build_parser().parse_args(["setup", d]))
        self.assertEqual(status["status"], "complete")
        self.assertEqual(setup.load_setup_manifest(d)["max_per_group"], 3)

    def test_setup_size_flags_must_be_positive(self):
        parser = driver.build_parser()
        for argv in (["setup", ".", "--max-per-group", "0"],
                     ["setup", ".", "--max-groups", "-3"],
                     ["setup", ".", "--max-per-group", "x"],
                     ["run", ".", "--max-per-group", "0"]):
            with self.subTest(argv=argv), self.assertRaises(SystemExit), \
                    contextlib.redirect_stderr(io.StringIO()):
                parser.parse_args(argv)
        self.assertEqual(parser.parse_args(["setup", ".", "--max-groups", "5"]).max_groups, 5)

    def test_setup_manifest_pins_the_config_numbers_at_creation(self):
        # config.json is resolved when the manifest is minted: an edit between
        # scan and ingest cannot move the cap or the ceiling under the brief.
        d = self._repo()
        os.makedirs(runio._pano(d), exist_ok=True)
        with open(os.path.join(runio._pano(d), "config.json"), "w") as fh:
            json.dump({"max_per_group": 7, "max_groups": 9}, fh)
        setup.run_setup_flow(driver.build_parser().parse_args(["setup", d]))
        manifest = setup.load_setup_manifest(d)
        self.assertEqual((manifest["max_per_group"], manifest["max_groups"]), (7, 9))
        with open(os.path.join(runio._pano(d), "config.json"), "w") as fh:
            json.dump({"max_per_group": 2, "max_groups": 4}, fh)
        with open(runio._pano(d, "setup-proposal.json"), "w") as fh:
            json.dump({"groups": [{"capability": "Checkout",
                                   "match": ["src/checkout/**"], "tests": []}]}, fh)
        status = setup.run_setup_flow(driver.build_parser().parse_args(["setup", d]))
        self.assertEqual(status["status"], "complete")
        report = runio._load_json(runio._pano(d, "setup-report.json"))["report"]
        self.assertEqual((report["cap"], report["ceiling"]), (7, 9))
        # the CLI still wins over config
        d2 = self._repo()
        os.makedirs(runio._pano(d2), exist_ok=True)
        with open(os.path.join(runio._pano(d2), "config.json"), "w") as fh:
            json.dump({"max_per_group": 7}, fh)
        setup.run_setup_flow(driver.build_parser().parse_args(
            ["setup", d2, "--max-per-group", "3"]))
        self.assertEqual(setup.load_setup_manifest(d2)["max_per_group"], 3)

    def test_scan_writes_the_spine_with_the_manifest_sizes(self):
        # 5.2 stage 1: the scan phase computes the spine ONCE with the sizes
        # the manifest pinned, persists it, and the brief carries the same
        # numbers -- what the agent plans against is what ingest applies.
        d = self._repo()
        args = driver.build_parser().parse_args(
            ["setup", d, "--max-per-group", "3", "--max-groups", "5"])
        status = setup.run_setup_flow(args)
        self.assertEqual(status["checkpoint"], "scan")
        spine = runio._load_json(runio._pano(d, "setup-spine.json"))
        self.assertEqual((spine["cap"], spine["ceiling"], spine["ceiling_source"]),
                         (3, 5, "cli"))
        self.assertEqual(setup_flow.read_spine(d), spine)
        with open(runio._pano(d, "setup-scan-brief.md"), encoding="utf-8") as fh:
            brief = fh.read()
        self.assertIn("## Size arithmetic", brief)
        self.assertIn("ceiling (CODE review groups this repo affords): 5 from --max-groups", brief)
        self.assertIn("setup-spine.json", runio._TOP_LEVEL)
        self.assertIn("setup-spine.json", setup._SETUP_ARTIFACTS)
        # --reset drops the pinned sizes and re-runs scan: the spine is rebuilt
        # with the defaults, not left over from the flagged run
        setup.run_setup_flow(driver.build_parser().parse_args(["setup", d, "--reset"]))
        spine = runio._load_json(runio._pano(d, "setup-spine.json"))
        self.assertEqual((spine["cap"], spine["ceiling_source"]), (48, "formula"))

    def test_scan_brief_carries_the_bundled_catalogs(self):
        # 5.2 §5.1: the scan phase renders BOTH shipped catalogs in full prose
        # (#1500) -- the capability entries with their definitions and the
        # layer entries the agent may name -- plus the surfaces enum.
        d = self._repo()
        setup.run_setup_flow(driver.build_parser().parse_args(["setup", d]))
        with open(runio._pano(d, "setup-scan-brief.md"), encoding="utf-8") as fh:
            brief = fh.read()
        self.assertIn("## Capability catalog", brief)
        self.assertIn("### Auth\nDefinition: ", brief)
        self.assertIn("## Layer catalog", brief)
        self.assertIn("### API\nDefinition: ", brief)
        self.assertNotIn("do not propose `layers`", brief)
        for surface in coverage_model.SURFACES:
            self.assertIn(surface, brief)

    def test_reset_clears_the_report_artifacts(self):
        d = self._repo()
        args = driver.build_parser().parse_args(["setup", d])
        setup.run_setup_flow(args)
        with open(runio._pano(d, "setup-proposal.json"), "w") as fh:
            json.dump({"groups": [{"capability": "Checkout",
                                   "match": ["src/checkout/**"], "tests": []}]}, fh)
        setup.run_setup_flow(args)
        for name in ("setup-report.md", "setup-report.json"):
            self.assertTrue(os.path.isfile(runio._pano(d, name)), name)
            self.assertIn(name, runio._TOP_LEVEL)
            self.assertIn(name, setup._SETUP_ARTIFACTS)
        setup.run_setup_flow(driver.build_parser().parse_args(["setup", d, "--reset"]))
        for name in ("setup-report.md", "setup-report.json", "groups.yml.draft"):
            self.assertFalse(os.path.isfile(runio._pano(d, name)), name)


class TestSetupOwnsItsDispatchNamespace(unittest.TestCase):
    """#1507: `driver setup` wrote its dispatch request and prompt through the
    per-run resolver, so they landed in whatever `.panopticon/runs/latest`
    pointed at -- an unrelated review run from a previous day, whose own
    `dispatch-request.json` was overwritten with a `scan` checkpoint carrying
    setup's run_id.

    A run folder is one run's artifacts (#1130). A later setup silently mutating
    an old one breaks that run's resume and its audit trail. Setup already has a
    top-level namespace (setup-manifest, setup-proposal, setup-report...); the
    dispatch request belongs beside them.
    """

    def _root(self):
        d = os.path.realpath(tempfile.mkdtemp())
        os.makedirs(os.path.join(d, ".panopticon"))
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        return d

    def _prior_run(self, root):
        """A previous review run's folder, exactly as a real one would look."""
        tag = "claude-redteam-repo-20260829-07b08094"
        folder = os.path.join(root, ".panopticon", "runs", tag)
        os.makedirs(os.path.join(folder, "_prompts"))
        with open(os.path.join(folder, "dispatch-request.json"), "w") as fh:
            json.dump({"schema_version": 1, "run_id": "07b08094",
                       "checkpoint": "review", "group": None, "entries": []}, fh)
        with open(os.path.join(root, ".panopticon", "run-manifest.json"), "w") as fh:
            json.dump({"schema_version": 1, "run_id": "07b08094",
                       "host": "claude", "created": "2026-08-29T00:00:00Z",
                       "tag": tag}, fh)
        return folder

    def _snapshot(self, folder):
        out = {}
        for base, _dirs, names in os.walk(folder):
            for name in names:
                path = os.path.join(base, name)
                with open(path, "rb") as fh:
                    out[os.path.relpath(path, folder)] = fh.read()
        return out

    def test_setup_writes_into_its_own_namespace(self):
        root = self._root()
        path = requests.write_dispatch_request(
            root, "RID", "scan", None,
            [{"id": "setup-scan", "agent": None, "enforced": False,
              "model": None, "prompt": "BRIEF", "out_file": "/abs/p.json"}],
            namespace="setup")
        self.assertTrue(path.endswith(".panopticon/setup-dispatch-request.json"),
                        path)
        self.assertNotIn("/runs/", path)

    def test_setup_leaves_a_previous_run_folder_byte_identical(self):
        root = self._root()
        folder = self._prior_run(root)
        before = self._snapshot(folder)
        requests.write_dispatch_request(
            root, "ea7a6402", "scan", None,
            [{"id": "setup-scan", "agent": None, "enforced": False,
              "model": None, "prompt": "BRIEF", "out_file": "/abs/p.json"}],
            namespace="setup")
        self.assertEqual(self._snapshot(folder), before)

    def test_the_setup_prompt_lands_beside_its_request(self):
        root = self._root()
        self._prior_run(root)
        requests.write_dispatch_request(
            root, "RID", "scan", None,
            [{"id": "setup-scan", "agent": None, "enforced": False,
              "model": None, "prompt": "BRIEF", "out_file": "/abs/p.json"}],
            namespace="setup")
        prompt = os.path.join(root, ".panopticon", "setup-prompts",
                              "setup-scan.txt")
        self.assertTrue(os.path.isfile(prompt))
        with open(prompt, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "BRIEF")

    def test_a_review_run_still_writes_into_its_run_folder(self):
        # The namespace is opt-in; the run loop's behaviour is unchanged.
        root = self._root()
        folder = self._prior_run(root)
        path = requests.write_dispatch_request(
            root, "07b08094", "review", None,
            [{"id": "review-G-SEC", "agent": None, "enforced": False,
              "model": None, "prompt": "P", "out_file": "/abs/f.json"}])
        self.assertEqual(os.path.dirname(path),
                         os.path.dirname(runio._pano(root, "dispatch-request.json")))
        self.assertIn(os.path.join(".panopticon", "runs"), path)
        self.assertNotIn("setup-dispatch-request", path)
        self.assertTrue(os.path.isdir(folder))

    def test_the_namespaced_request_reads_back(self):
        root = self._root()
        requests.write_dispatch_request(
            root, "RID", "scan", None,
            [{"id": "setup-scan", "agent": None, "enforced": False,
              "model": None, "prompt": "BRIEF", "out_file": "/abs/p.json"}],
            namespace="setup")
        req = requests.load_dispatch_request(root, namespace="setup")
        self.assertEqual(req["checkpoint"], "scan")
        self.assertEqual(req["run_id"], "RID")


class TestSetupScanExecuteUsesTheNamespace(unittest.TestCase):
    def test_scan_execute_points_at_the_setup_request(self):
        d = os.path.realpath(tempfile.mkdtemp())
        os.makedirs(os.path.join(d, ".panopticon"))
        os.makedirs(os.path.join(d, "src"))
        with open(os.path.join(d, "src", "app.py"), "w") as fh:
            fh.write("x = 1\n")
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        result = setup_phase.scan_execute(d, {"run_id": "RID", "host": "claude"})
        if result.kind != "checkpoint":
            self.skipTest("vocab-absent fallback path")
        self.assertTrue(result.dispatch_request.endswith(
            ".panopticon/setup-dispatch-request.json"), result.dispatch_request)


class TestReadinessLimitationsAreLoud(unittest.TestCase):
    """Spec §5.1: "If there are limitations by host then we should LOUDLY
    declare them", and "absence of warnings must mean 'measured and proven',
    never 'nobody looked'".

    Before #1344 F2, gemini's `enforced-shells` check was `False`, so it landed
    in `gaps` and the operator saw `readiness gaps: enforced-shells` -- loud,
    but wrong: the remedy it named (`--emit-host-agents gemini`) raises. Task 6
    made it `None`, which is right and was silent: `gaps` filters on `is
    False`, so the operator got a plain `readiness OK` on a host that cannot
    enforce anything, and the honest line reached `setup-complete.json` alone.
    A limitation is not a gap and it is not nothing.
    """

    def _repo(self):
        return make_git_repo(
            test_case=self, files={"src/checkout/pay.py": "x = 1\n"},
            branch="main", user_email="t@t", user_name="t")

    def _fallback(self, checks, host=None):
        """A vocab-absent `driver setup` whose readiness answers `checks`."""
        d = self._repo()
        argv = ["setup", d] + (["--host", host] if host else [])
        args = driver.build_parser().parse_args(argv)
        with mock.patch("scripts.setup_flow.load_bundled_vocabulary",
                        return_value=({"names": []}, False)), \
             mock.patch("scripts.setup_flow.readiness", return_value=checks):
            status = setup.run_setup_flow(args)
        self.assertEqual("complete", status["status"])
        marker = runio._load_json(runio._pano(d, "setup-complete.json"))
        return status["message"], marker

    # gemini's REAL answer, computed by the registry-backed check itself rather
    # than restated here, so a reworded detail cannot make this test pass on
    # prose that no longer matches what setup emits.
    GEMINI_CHECKS = setup_flow._check_host_shells("gemini", None)

    def test_the_gemini_limitation_reaches_the_operator(self):
        rows = {c[0]: c for c in self.GEMINI_CHECKS}
        self.assertEqual(("enforced-shells", None,
                          "gemini registers no enforcement shells; reviewers "
                          "run with a prompt-advisory tool policy"),
                         rows["enforced-shells"])
        msg, marker = self._fallback(self.GEMINI_CHECKS, host="gemini")
        self.assertIn("limitations", msg)
        self.assertIn("enforced-shells", msg)
        self.assertIn("gemini registers no enforcement shells", msg)
        self.assertIn(["enforced-shells", rows["enforced-shells"][2]],
                      marker["limitations"])

    def test_a_shell_less_host_still_discloses_its_capability_posture(self):
        # F3b: registering no enforcement shells is a fact about ONE check, not
        # an exemption from §5.1. gemini claims nothing, so five-of-five
        # unproven IS its whole story -- and the `enforced-shells` early return
        # used to end the check list right here, leaving the operator one line
        # that named the host and no capability, no probe and no remedy.
        rows = {c[0]: c for c in self.GEMINI_CHECKS}
        self.assertIn("host-capabilities", rows)
        for capability in hosts.CAPABILITIES:
            with self.subTest(capability=capability):
                row = rows["host-capability:" + capability]
                self.assertIn(host_disclosure.remedy(capability, "gemini"),
                              row[2])
        msg, marker = self._fallback(self.GEMINI_CHECKS, host="gemini")
        self.assertIn(["host-capabilities", rows["host-capabilities"][2]],
                      marker["limitations"])
        self.assertIn("host-capabilities", msg)

    def test_a_limitation_never_becomes_a_gap(self):
        # It must not gate READY: `gaps` stays empty and the readiness verdict
        # stays OK. Distinct clause, distinct key -- a consumer can tell "not
        # applicable" from "fine".
        msg, marker = self._fallback(self.GEMINI_CHECKS, host="gemini")
        self.assertEqual([], marker["gaps"])
        self.assertNotIn("readiness gaps", msg)

    def test_a_fully_registered_claude_run_reports_neither(self):
        checks = [("docker", True, "ok"), ("target-root", True, "ok"),
                  ("enforced-shells", True, "ok"),
                  ("groups-manifest", True, "1 group(s)")]
        msg, marker = self._fallback(checks, host="claude")
        self.assertNotIn("limitations", msg)
        self.assertNotIn("readiness gaps", msg)
        self.assertEqual([], marker["gaps"])
        self.assertEqual([], marker["limitations"])

    def test_a_real_gap_is_still_reported_as_a_gap(self):
        checks = [("docker", False, "docker unavailable -- install/start Docker"),
                  ("enforced-shells", None, "gemini registers no enforcement "
                                            "shells; reviewers run with a "
                                            "prompt-advisory tool policy")]
        msg, marker = self._fallback(checks, host="gemini")
        self.assertEqual(["docker"], marker["gaps"])
        self.assertIn("readiness gaps: docker", msg)
        self.assertIn("limitations", msg)
        self.assertIn("enforced-shells", msg)
