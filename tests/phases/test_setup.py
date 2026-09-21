"""Tests for scripts.phases.setup: the `driver setup` scan/ingest flow and its manifest.
"""
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import scripts.phases.engine as engine
import scripts.phases.runio as runio
import scripts.phases.setup as setup
import scripts.phases.setup as setup_phase
import scripts.phases.requests as requests

import scripts.driver as driver
import scripts.loop_batch as loop_batch
import scripts.coverage_model as coverage_model
import scripts.host_disclosure as host_disclosure
import scripts.host_probes as host_probes
import scripts.hosts as hosts
import scripts.setup_flow as setup_flow
import scripts.model_resolver as model_resolver
import scripts.probes.codex as codex_probes
import scripts.repo_config as repo_config
import scripts.runners.batch as batch_mod

from conftest import write_host_evidence
from test_orchestrate import _all_proven_artifact, _refuted_artifact
from tools.git_repo import make_git_repo


class TestDriverSetup(unittest.TestCase):
    def _repo(self, enforcement=None):
        """A target tree. `enforcement` seeds this host's capability evidence
        (#1737): PROVEN is the registered machine every scan test but the ack
        ones assumes, and None leaves the tree with no evidence at all -- the
        all-unknown posture, which gates as REFUTED and takes the ack path."""
        repo = make_git_repo(
            test_case=self,
            files={"src/checkout/pay.py": "x = 1\n"},
            branch="main",
            user_email="t@t",
            user_name="t",
        )
        if enforcement is not None:
            write_host_evidence(repo, {hosts.TOOL_POLICY_ENFORCED: enforcement})
        return repo

    def _registered_repo(self):
        """A machine that HAS emitted its enforcement shells and proved it.

        A UNIT fixture: it arranges the evidence and calls `run_setup_flow`
        with no posture step, so these tests exercise the flow against a given
        posture. The real verb PROBES for itself (#1737 fix round 1) and
        overwrites this artifact before any gate reads it --
        `TestStandaloneSetupProbesItsOwnPosture` drives `driver.main` end to
        end for that, including the planted-artifact case. Read the two
        together: a green fixture here proves nothing about the wiring.
        """
        return self._repo(enforcement=hosts.PROVEN)

    def _write_settings(self, repo, max_per_group, max_groups):
        """A root config carrying only `settings:` (#1681 retired config.json)."""
        body = "version: 1\ngroups: {}\nsettings:\n  max_per_group: %d\n" % max_per_group
        if max_groups is not None:
            body += "  max_groups: %d\n" % max_groups
        with open(os.path.join(repo, repo_config.CONFIG_NAMES[0]), "w") as fh:
            fh.write(body)

    def test_setup_verb_parses(self):
        args = driver.build_parser().parse_args(["setup", "."])
        self.assertEqual(args.verb, "setup")

    def test_scan_emits_setup_scan_checkpoint_when_vocab_present(self):
        # #1737: a machine that has emitted its shells -- the normal state for
        # every scan test below. The unregistered machine's path (refusal, or
        # the acknowledged shell-less dispatch) has its own tests above.
        d = self._registered_repo()
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
        self.assertEqual("return_json", entry["delivery"])

    def test_setup_refuses_a_shell_less_scan_without_the_operators_ack(self):
        # #1737 brief case (b). The one dispatch that reads the whole untrusted
        # tree now passes the acknowledgement every other unenforced dispatch
        # has required since #1519, and a refusal lands BEFORE anything is
        # dispatched.
        #
        # This is the UNIT shape: no posture step, so no probe ran and the
        # state is UNKNOWN -- for which the remedy is the invocation that
        # measures, never the emit command (fix round 2: a remedy that cannot
        # change the answer is the defect, not the wording). The real verb
        # probes, and a fresh machine with no registration directory measures
        # REFUTED and IS told to emit --
        # TestStandaloneSetupProbesItsOwnPosture covers that end to end.
        d = self._repo()
        args = driver.build_parser().parse_args(["setup", d])
        status = setup.run_setup_flow(args)
        self.assertEqual("error", status["status"], status)
        self.assertIn("tool_policy_enforced", status["message"])
        self.assertIn("driver loop --setup --host claude --mode headless",
                      status["message"])
        self.assertNotIn("--emit-host-agents", status["message"])
        self.assertIn("--allow-unenforced", status["message"])
        self.assertIn("setup-unenforced-ack.json", status["message"])
        # nothing was dispatched
        self.assertFalse(os.path.isfile(requests.request_path(d, namespace="setup")))

    def test_the_ack_lets_the_shell_less_scan_proceed_and_is_recorded(self):
        d = self._repo()
        args = driver.build_parser().parse_args(["setup", d, "--allow-unenforced"])
        status = setup.run_setup_flow(args)
        self.assertEqual("checkpoint", status["status"], status)
        entry = runio._load_json(requests.request_path(d, namespace="setup"))["entries"][0]
        self.assertFalse(entry["enforced"])
        self.assertIsNone(entry["agent"])
        ack = runio._load_json(runio._pano(d, setup.SETUP_UNENFORCED_ACK))
        self.assertTrue(ack["acknowledged"])
        self.assertEqual(["setup_scan"], ack["roles"])
        self.assertEqual("claude", ack["host"])
        self.assertTrue(ack["plan_sha256"])
        self.assertIn("tool_policy_enforced", ack)
        # ...and it lands FLAT, beside setup's other artifacts, never in a
        # review run's folder and never as the review ack's name (#1507/#493).
        self.assertTrue(os.path.isfile(os.path.join(
            d, ".panopticon", setup.SETUP_UNENFORCED_ACK)))
        self.assertFalse(os.path.exists(os.path.join(
            d, ".panopticon", requests.UNENFORCED_ACK)))

    def test_the_refusal_names_no_emit_command_on_a_host_with_no_shells(self):
        # `--host generic` is the permanent unenforced fallback (ruling D1) and
        # registers nothing, so `--emit-host-agents generic` is a command that
        # refuses. The refusal offers the two remedies that exist instead.
        d = self._repo()
        status = setup.run_setup_flow(driver.build_parser().parse_args(
            ["setup", d, "--host", "generic"]))
        self.assertEqual("error", status["status"], status)
        self.assertNotIn("--emit-host-agents", status["message"])
        self.assertIn("--allow-unenforced", status["message"])
        self.assertIn("--host claude", status["message"])

    def test_a_proven_host_needs_no_ack_at_all(self):
        # #1737 brief case (c): the shell is registered and the posture proves
        # it, so the entry is enforced and nothing is acknowledged.
        d = self._repo()
        write_host_evidence(d, {hosts.TOOL_POLICY_ENFORCED: hosts.PROVEN})
        args = driver.build_parser().parse_args(["setup", d])
        status = setup.run_setup_flow(args)
        self.assertEqual("checkpoint", status["status"], status)
        entry = runio._load_json(requests.request_path(d, namespace="setup"))["entries"][0]
        self.assertTrue(entry["enforced"])
        self.assertEqual("panopticon-setup-scan", entry["agent"])
        self.assertFalse(os.path.exists(runio._pano(d, setup.SETUP_UNENFORCED_ACK)))

        self.assertTrue(loop_batch.expected_enforced(d, "claude", "setup"))

    def test_a_stored_allow_unenforced_flag_grants_nothing(self):
        # `setup-manifest.json` sits at a `.panopticon` path a hostile target
        # can force-commit (`git add -f`), and it is written once and reused --
        # so the flag is read off THIS invocation's argv every time. A stored
        # acceptance is not an acceptance.
        d = self._repo()
        setup.run_setup_flow(driver.build_parser().parse_args(
            ["setup", d, "--allow-unenforced"]))
        manifest = setup.load_setup_manifest(d)
        manifest["flags"] = {"allow_unenforced": True}
        runio._write_json(setup._setup_manifest_path(d), manifest)
        setup._clear_setup_artifacts(d)         # keeps nothing but the tree
        runio._write_json(setup._setup_manifest_path(d), manifest)
        status = setup.run_setup_flow(driver.build_parser().parse_args(["setup", d]))
        self.assertEqual("error", status["status"], status)
        self.assertIn("--allow-unenforced", status["message"])
        self.assertFalse(os.path.exists(runio._pano(d, setup.SETUP_UNENFORCED_ACK)))

    def test_the_flag_the_operator_typed_reaches_the_phases(self):
        # `scan_execute` sees only the manifest, so the argv answer has to be
        # recorded on the in-memory one the engine is handed.
        d = self._repo()
        seen = {}
        real = setup.require_unenforced_scan_ack

        def spy(review_root, manifest, entries):
            seen.update(manifest.get("flags") or {})
            return real(review_root, manifest, entries)

        with mock.patch.object(setup, "require_unenforced_scan_ack", spy):
            setup.run_setup_flow(driver.build_parser().parse_args(
                ["setup", d, "--allow-unenforced"]))
        self.assertEqual({"allow_unenforced": True}, seen)

    def test_reset_discards_the_acceptance(self):
        d = self._repo()
        setup.run_setup_flow(driver.build_parser().parse_args(
            ["setup", d, "--allow-unenforced"]))
        self.assertTrue(os.path.isfile(runio._pano(d, setup.SETUP_UNENFORCED_ACK)))
        setup._clear_setup_artifacts(d)
        self.assertFalse(os.path.exists(runio._pano(d, setup.SETUP_UNENFORCED_ACK)))

    def test_setup_host_generic_prints_the_fallback_notice_once(self):
        # D1: run_setup_flow resolves `host` itself (a manifest field it pins
        # at creation, not driver.py's run() path), so the notice is printed
        # here rather than from driver.py. Pin the count, not presence: a
        # single `driver setup` invocation must not repeat it per phase.
        d = self._repo()
        args = driver.build_parser().parse_args(["setup", d, "--host", "generic"])
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            setup.run_setup_flow(args)
        self.assertEqual(1, err.getvalue().count(host_disclosure.GENERIC_FALLBACK_NOTICE))

    def test_setup_scan_is_deliberately_not_model_bound(self):
        # R-F4-2. `resolve_model` would hand setup-scan a role tier and
        # silently move the one judgement-heavy, one-off `driver setup`
        # dispatch off the session's model. #1737 registered the SHELL and
        # left the MODEL exactly here: the role now has a ROLE_FILES row and
        # an explicit `model: null` profile, and the entry still carries None,
        # so the exception stays a decision rather than becoming an omission.
        d = self._repo()
        with mock.patch.object(model_resolver, "resolve_model",
                               return_value={"model": "SENTINEL"}) as rm:
            entry = setup._setup_scan_entry(d, "PROMPT", "claude")
        self.assertIsNone(entry["model"])
        rm.assert_not_called()

    def test_setup_scan_names_its_registered_shell_on_a_proven_host(self):
        # #1737 (AGT-B1D): the one dispatch that reads the WHOLE untrusted
        # tree used to carry `agent: None, enforced: False` unconditionally,
        # so its tool grant was whatever the host gives a general-purpose
        # agent. It is a registered role now, and `enforced` is DERIVED from
        # this invocation's own posture the way the five phase sites are.
        d = self._repo()
        write_host_evidence(d, {hosts.TOOL_POLICY_ENFORCED: hosts.PROVEN})
        entry = setup._setup_scan_entry(d, "PROMPT", "claude")
        self.assertEqual("panopticon-setup-scan", entry["agent"])
        self.assertTrue(entry["enforced"])
        self.assertIsNone(entry["model"])          # R-F4-2, unchanged
        self.assertTrue(loop_batch.expected_enforced(d, "claude", "setup"))

    def test_setup_scan_falls_back_shell_less_when_the_host_cannot_enforce(self):
        # No evidence at all is the all-unknown posture, and UNKNOWN gates as
        # REFUTED: a machine that has not emitted its shells dispatches
        # shell-less -- and `scan_execute` makes the operator say so.
        d = self._repo()
        entry = setup._setup_scan_entry(d, "PROMPT", "claude")
        self.assertIsNone(entry["agent"])
        self.assertFalse(entry["enforced"])
        self.assertIsNone(entry["model"])

    def test_the_entry_agrees_with_what_the_loop_expects_either_way(self):
        # The #1720 request-integrity check, run against the builder: an entry
        # whose self-asserted `enforced` disagrees with the run's own evidence
        # stops the batch before anything launches.
        d = self._repo()
        for states in ({hosts.TOOL_POLICY_ENFORCED: hosts.PROVEN},
                       {hosts.TOOL_POLICY_ENFORCED: hosts.REFUTED}):
            with self.subTest(states=states):
                write_host_evidence(d, states)
                entry = setup._setup_scan_entry(d, "PROMPT", "claude")
                self.assertEqual([], loop_batch.refuse_disagreeing(
                    [entry], loop_batch.expected_enforced(d, "claude", "setup")))
                self.assertEqual([], loop_batch.refuse_misrouted([entry], "scan"))

    def test_setup_scan_entry_is_return_persist_and_says_so(self):
        # #1608. Its docstring always said "return-persist"; now the entry does.
        d = self._repo()
        with mock.patch.object(requests, "delivery",
                               return_value=("SENTINEL-MODE", "")) as dl:
            entry = setup._setup_scan_entry(d, "PROMPT", "claude")
        self.assertEqual("SENTINEL-MODE", entry["delivery"])
        # unenforced here because this repo has no capability evidence (#1737)
        self.assertFalse(entry["enforced"])
        self.assertIsNone(entry["model"])         # unchanged: R-F4-2
        (host, _evidence, role_file, out_file), _kw = dl.call_args
        self.assertEqual(("claude", "setup-scan.md", entry["out_file"]),
                         (host, role_file, out_file))

    def test_setup_scan_entry_unpatched_is_return_json_with_no_preamble(self):
        d = self._repo()
        entry = setup._setup_scan_entry(d, "PROMPT", "claude")
        self.assertEqual("return_json", entry["delivery"])
        self.assertEqual(requests.entry_marker("setup-scan") + "PROMPT", entry["prompt"])

    def test_setup_scan_entry_is_directory_scoped_to_the_review_root(self):
        d = self._repo()
        entry = setup._setup_scan_entry(d, "PROMPT", "claude")
        self.assertEqual("panopticon-entry: setup-scan", entry["marker"])
        self.assertEqual(requests.scope(dirs=[os.path.abspath(d)]), entry["scope"])

    def test_scan_leaves_a_blanket_gitignore_untouched(self):
        # #1135: a repo already blanket-ignoring .panopticon/ keeps its
        # .gitignore untouched (no migration to /*). #1681 retired the
        # `git add -f` note with it: the committed config is at the ROOT, so
        # nothing setup writes under .panopticon/ needs force-adding.
        d = self._registered_repo()
        with open(os.path.join(d, ".gitignore"), "w") as fh:
            fh.write(".panopticon/\n")
        args = driver.build_parser().parse_args(["setup", d])
        status = setup.run_setup_flow(args)
        self.assertEqual("setup-scan checkpoint", status["message"])
        with open(os.path.join(d, ".gitignore"), encoding="utf-8") as fh:
            gi = fh.read()
        self.assertIn(".panopticon/", gi)
        self.assertNotIn(".panopticon/*", gi)   # not migrated in place

    def test_scan_discloses_a_stale_config_json_on_stderr(self):
        # #1681 retired the JSON config. It is never read and never deleted for
        # the operator -- so the one thing setup owes them is saying so, once,
        # where they will see it. (`provision` returns the line; this is the
        # only place that prints it.)
        d = self._repo()
        os.makedirs(runio._pano(d), exist_ok=True)
        with open(os.path.join(d, ".panopticon", "config.json"), "w") as fh:
            json.dump({"max_per_group": 5}, fh)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            setup.run_setup_flow(driver.build_parser().parse_args(["setup", d]))
        self.assertIn("config.json", err.getvalue())
        self.assertIn("settings:", err.getvalue())

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
        self.assertTrue(os.path.isfile(repo_config.draft_path(d)))
        self.assertIsNone(repo_config.resolve(d).path)

    def test_vocab_absent_falls_back_to_seed_and_completes(self):
        # The bundled fixture is always present, so force absence at the loader
        # boundary to exercise the fallback path deterministically.
        d = self._registered_repo()
        args = driver.build_parser().parse_args(["setup", d])
        with mock.patch("scripts.setup_flow.load_bundled_vocabulary",
                        return_value=({"names": []}, False)):
            status = setup.run_setup_flow(args)
        self.assertEqual(status["status"], "complete")
        self.assertTrue(runio._json_parses(runio._pano(d, "setup-complete.json")))
        self.assertEqual(os.path.join(d, repo_config.CONFIG_NAMES[0]),
                         repo_config.resolve(d).path)                   # flat seed
        # no scan checkpoint was emitted
        self.assertFalse(os.path.isfile(runio._pano(d, "setup-proposal.json")))

    def test_stale_fallback_marker_self_heals_when_vocab_returns(self):
        # First run: vocab absent -> fallback marker written, run completes
        # without a checkpoint.
        d = self._registered_repo()
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
        # vocab-absent fallback: a flat root config, no draft -> the message
        # must not send the owner looking for a draft that was never written.
        d1 = self._repo()
        args1 = driver.build_parser().parse_args(["setup", d1])
        with mock.patch("scripts.setup_flow.load_bundled_vocabulary",
                        return_value=({"names": []}, False)):
            status1 = setup.run_setup_flow(args1)
        self.assertEqual(status1["status"], "complete")
        self.assertNotIn("draft", status1["message"])
        self.assertIn(repo_config.CONFIG_NAMES[0], status1["message"])

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
        self.assertFalse(os.path.isfile(repo_config.draft_path(d)))

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
        self.assertIn("stamped review_root '/somewhere/else' !=", err.getvalue())
        self.assertNotIn("git-tracked", err.getvalue())

    def test_tracked_setup_manifest_message_does_not_claim_the_stamp_differs(self):
        root = self._repo()
        args = driver.build_parser().parse_args(["setup", root])
        setup.run_setup_flow(args)
        self.assertEqual(root, setup.load_setup_manifest(root)["review_root"])
        err = io.StringIO()
        with mock.patch.object(runio, "_manifest_committed", return_value=True), \
                contextlib.redirect_stderr(err):
            setup.run_setup_flow(args)
        self.assertIn("ignoring foreign setup-manifest.json (the file is git-tracked", err.getvalue())
        self.assertNotIn("stamped review_root", err.getvalue())

    def test_reset_preserves_the_committed_root_config(self):
        d = self._repo()
        committed_path = os.path.join(d, repo_config.CONFIG_NAMES[0])
        content = ("version: 1\ngroups:\n  checkout:\n    match:\n"
                   "      - src/checkout/**\n")
        with open(committed_path, "w") as fh:
            fh.write(content)
        draft = repo_config.draft_path(d)
        with open(draft, "w") as fh:
            fh.write("version: 1\ngroups: {}\n")

        args = driver.build_parser().parse_args(["setup", d])
        setup.run_setup_flow(args)                        # scan checkpoint

        reset_args = driver.build_parser().parse_args(["setup", d, "--reset"])
        setup.run_setup_flow(reset_args)                  # clears setup artifacts only

        self.assertFalse(os.path.isfile(draft))           # the draft is derived
        self.assertTrue(os.path.isfile(committed_path))
        with open(committed_path, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), content)

    def test_reset_clears_the_capability_evidence_setup_writes(self):
        # Fix round 1, F2, the lifecycle half. `driver loop --setup` writes a
        # FLAT .panopticon/host-capabilities.json (its posture step, #1616
        # item 3). Nothing cleared it: it is not a review artifact, so
        # `driver.run`'s own `--reset` never reaches it, and the setup list
        # did not name it -- leaving a file the verb reads on every later
        # invocation with no way to discard it.
        d = self._repo()
        flat = os.path.join(d, ".panopticon", runio.HOST_CAPABILITIES)
        os.makedirs(os.path.dirname(flat), exist_ok=True)
        runio._write_json(flat, {"schema_version": 1, "host": "claude",
                                 "sentinel": True, "capabilities": {}})
        setup._clear_setup_artifacts(d)
        self.assertFalse(os.path.isfile(flat))

    def test_reset_does_not_reach_a_review_runs_evidence(self):
        # The trap in the line above: `host-capabilities.json` is NOT in
        # `runio._TOP_LEVEL`, so `runio._pano` resolves it into `runs/<tag>/`
        # whenever a review run-manifest is on the tree -- and that file is
        # that run's, not setup's. Clearing setup's must name the flat path.
        d = self._repo()
        runio._write_json(runio._pano(d, "run-manifest.json"),
                          {"schema_version": 1, "run_id": "r1", "host": "claude",
                           "review_root": os.path.abspath(d),
                           "created": "2026-09-17T00:00:00Z"})
        per_run = runio._pano(d, runio.HOST_CAPABILITIES)
        self.assertNotEqual(os.path.abspath(per_run),
                            os.path.join(d, ".panopticon", runio.HOST_CAPABILITIES))
        os.makedirs(os.path.dirname(per_run), exist_ok=True)
        runio._write_json(per_run, {"schema_version": 1, "host": "claude",
                                    "capabilities": {}})
        setup._clear_setup_artifacts(d)
        self.assertTrue(os.path.isfile(per_run),
                        "a --setup --reset deleted a review run's own evidence")

    def _dead_pid(self):
        """A pid that is certainly not running: a child spawned and reaped."""
        proc = subprocess.Popen([sys.executable, "-c", ""])
        proc.wait()
        return proc.pid

    def _batch_record(self, d, name, **fields):
        path = os.path.join(d, ".panopticon", name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        runio._write_json(path, {"schema_version": 1, "batch": 1, **fields})
        return path

    def test_reset_clears_a_leftover_batch_record(self):
        # #1698. `driver loop --setup`'s run folder is the FLAT .panopticon/,
        # and this list named only setup's own artifacts -- so a crashed setup
        # batch's `batch-<n>.json` survived `--reset`. Recovery is SKIPPED
        # under `--reset`, so the next run reached `Batch.open`'s O_EXCL and
        # raised FileExistsError at it: a traceback, from the very flag the
        # refusal it replaced told the operator to use.
        d = self._repo()
        flat = os.path.join(d, ".panopticon", "batch-1.json")
        os.makedirs(os.path.dirname(flat), exist_ok=True)
        runio._write_json(flat, {"schema_version": 1, "batch": 1})
        setup._clear_setup_artifacts(d)
        self.assertFalse(os.path.isfile(flat))

    def test_reset_leaves_a_batch_record_a_live_setup_loop_owns(self):
        # #1698 round 2: the sweep is unconditional no longer. Two concurrent
        # `driver loop --setup` runs share the flat `.panopticon/`, so a
        # `--reset` that deleted the other one's IN-FLIGHT record would hand
        # its own crash rollback nothing to roll back -- the same accident the
        # resume-side ownership check exists to prevent, arriving from the
        # other direction.
        d = self._repo()
        live = self._batch_record(d, "batch-1.json", pid=os.getpid(),
                                  host=batch_mod.host_id())
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            setup._clear_setup_artifacts(d)
        self.assertTrue(os.path.isfile(live))
        self.assertIn("batch-1.json", err.getvalue())
        self.assertIn("still running", err.getvalue())

    def test_reset_clears_a_record_whose_owner_is_dead_or_unstamped(self):
        # Everything the resume side would recover or refuse, `--reset` is
        # entitled to discard: it is the operator saying the run is over.
        d = self._repo()
        dead = self._batch_record(d, "batch-1.json", pid=self._dead_pid(),
                                  host=batch_mod.host_id())
        unstamped = self._batch_record(d, "batch-2.json")
        elsewhere = self._batch_record(d, "batch-3.json", pid=1,
                                       host="some-other-box")
        setup._clear_setup_artifacts(d)
        for path in (dead, unstamped, elsewhere):
            self.assertFalse(os.path.isfile(path), path)

    def test_reset_sweeps_by_the_same_name_shape_recovery_matches(self):
        # `batch-` + `.json` is not the record's name: `recover_stale` reads
        # the ITERATION number out of it, and a file that carries none is not
        # a record at all -- not one this sweep may delete on a prefix match.
        d = self._repo()
        record = self._batch_record(d, "batch-10.json", pid=self._dead_pid(),
                                    host=batch_mod.host_id())
        decoy = self._batch_record(d, "batch-foo.json")
        setup._clear_setup_artifacts(d)
        self.assertFalse(os.path.isfile(record))
        self.assertTrue(os.path.isfile(decoy),
                        "a --setup --reset deleted a file that is not a batch record")

    def test_reset_does_not_reach_a_review_runs_batch_record(self):
        # The trap next door, the same one `host-capabilities.json` has:
        # `batch-<n>.json` is not in `runio._TOP_LEVEL`, so `_pano` resolves it
        # into `runs/<tag>/` whenever a review run-manifest is on the tree --
        # and a record in there belongs to that run, which may be live.
        d = self._repo()
        runio._write_json(runio._pano(d, "run-manifest.json"),
                          {"schema_version": 1, "run_id": "r1", "host": "claude",
                           "review_root": os.path.abspath(d),
                           "created": "2026-09-17T00:00:00Z"})
        per_run = runio._pano(d, "batch-1.json")
        self.assertNotEqual(os.path.abspath(per_run),
                            os.path.join(d, ".panopticon", "batch-1.json"))
        os.makedirs(os.path.dirname(per_run), exist_ok=True)
        runio._write_json(per_run, {"schema_version": 1, "batch": 1})
        setup._clear_setup_artifacts(d)
        self.assertTrue(os.path.isfile(per_run),
                        "a --setup --reset deleted a review run's own batch record")

    def test_setup_end_to_end_loop(self):
        """scan checkpoint -> host persists proposal -> re-invoke ingests ->
        complete, draft present, the committed root config never written."""
        d = self._registered_repo()
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
        self.assertIn(repo_config.DRAFT_NAME, os.listdir(d))
        self.assertIsNone(repo_config.resolve(d).path)

    def test_setup_size_flags_pin_the_manifest_and_reach_the_report(self):
        # 5.2: --max-per-group/--max-groups are pinned in setup-manifest.json at
        # scan time and honoured by ingest; the report artifacts are written
        # and the completion message points at the report.
        d = self._registered_repo()
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

    def test_setup_manifest_pins_the_clamped_config_numbers_at_creation(self):
        # `settings:` is resolved when the manifest is minted: an edit between
        # scan and ingest cannot move the cap or the ceiling under the brief.
        # max_per_group: 7 is below the 8-48 band (#1681 Plan 2), so the
        # manifest pins the clamped 8 -- the number a run would actually use.
        d = self._repo()
        self._write_settings(d, 7, 9)
        setup.run_setup_flow(driver.build_parser().parse_args(["setup", d]))
        manifest = setup.load_setup_manifest(d)
        self.assertEqual((manifest["max_per_group"], manifest["max_groups"]), (8, 9))
        self._write_settings(d, 2, 4)
        with open(runio._pano(d, "setup-proposal.json"), "w") as fh:
            json.dump({"groups": [{"capability": "Checkout",
                                   "match": ["src/checkout/**"], "tests": []}]}, fh)
        status = setup.run_setup_flow(driver.build_parser().parse_args(["setup", d]))
        self.assertEqual(status["status"], "complete")
        report = runio._load_json(runio._pano(d, "setup-report.json"))["report"]
        self.assertEqual((report["cap"], report["ceiling"]), (8, 9))
        # the CLI still wins over config
        d2 = self._repo()
        self._write_settings(d2, 7, None)
        setup.run_setup_flow(driver.build_parser().parse_args(
            ["setup", d2, "--max-per-group", "3"]))
        self.assertEqual(setup.load_setup_manifest(d2)["max_per_group"], 3)

    def test_scan_writes_the_spine_with_the_manifest_sizes(self):
        # 5.2 stage 1: the scan phase computes the spine ONCE with the sizes
        # the manifest pinned, persists it, and the brief carries the same
        # numbers -- what the agent plans against is what ingest applies.
        d = self._registered_repo()
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
        for name in ("setup-report.md", "setup-report.json"):
            self.assertFalse(os.path.isfile(runio._pano(d, name)), name)
        self.assertFalse(os.path.isfile(repo_config.draft_path(d)))


class TestTheRefusalNamesARemedyThatCanWork(unittest.TestCase):
    """#1737 fix round 2. The round-1 Critical was an impotent remedy --
    `--emit-host-agents` named to an operator nothing would re-probe for. One
    host over, the same shape survived: codex maps `tool_policy_enforced` to
    `codex-effective-tools`, and that probe short-circuits to UNKNOWN whenever
    `settings_path` is None -- which `driver setup` always leaves it, having no
    `--mode`. So `driver setup --host codex` cannot reach PROVEN on any
    machine, however many times its operator emits shells.

    The rule is the state, and it is host-agnostic. REFUTED means the host
    measured and said no -- for every capability that maps to a registration
    probe, re-emitting is the fix, and the quoted detail names the specific
    fault. UNKNOWN means NOTHING measured it, and no amount of registering
    changes what was never read: the remedy is the invocation that can
    measure, which is the headless loop.
    """

    def _repo(self):
        return make_git_repo(test_case=self, files={"src/a.py": "x = 1\n"},
                             branch="main", user_email="t@t", user_name="t")

    def _refuse(self, d, host, row):
        """`driver setup --host <host>` against an artifact carrying `row` for
        tool_policy_enforced, returning the refusal message."""
        body = _all_proven_artifact(host)
        body["capabilities"][hosts.TOOL_POLICY_ENFORCED] = row
        out = io.StringIO()
        with mock.patch("scripts.host_probes.run_probes",
                        side_effect=lambda h, target, **kw: body), \
                contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(io.StringIO()):
            driver.main(["setup", d, "--host", host])
        status = json.loads(out.getvalue().splitlines()[-1])
        self.assertEqual("error", status["status"], status)
        return status["message"]

    def _codex_unmeasurable_row(self):
        """The row the REAL codex probe produces for `driver setup` -- taken
        from the production probe rather than retyped, and reached without
        launching anything: the short-circuit is before the launch."""
        with tempfile.TemporaryDirectory() as reg:
            state, by, detail = codex_probes.probe_codex_tool_policy(
                "codex", registration_dir=reg, settings_path=None)
        self.assertEqual(hosts.UNKNOWN, state)
        self.assertIn("--mode headless", detail)
        return {"state": state, "by": by, "detail": detail}

    def test_codex_is_pointed_at_the_invocation_that_can_measure_it(self):
        message = self._refuse(self._repo(), "codex", self._codex_unmeasurable_row())
        self.assertIn("driver loop --setup --host codex --mode headless", message)
        self.assertNotIn("--emit-host-agents", message)
        self.assertIn("--allow-unenforced", message)
        # ...and the probe's own reason is still quoted, so the operator can
        # see WHY this invocation could not answer.
        self.assertIn("measured for driver loop --mode headless only", message)

    def test_a_refuted_host_still_gets_the_emit_remedy(self):
        message = self._refuse(self._repo(), "claude",
                               {"state": hosts.REFUTED, "by": "registered-shell-tools",
                                "detail": "no registration directory at /nope"})
        self.assertIn("--emit-host-agents claude", message)
        self.assertNotIn("driver loop --setup", message)
        self.assertIn("--allow-unenforced", message)

    def test_an_unmeasured_claude_is_not_told_to_emit_either(self):
        # The same rule, on the host the round-1 fix was written for: an
        # unreadable registration directory is UNKNOWN, and emitting into a
        # directory that cannot be read changes nothing.
        message = self._refuse(self._repo(), "claude",
                               {"state": hosts.UNKNOWN, "by": "registered-shell-tools",
                                "detail": "cannot read /nope, so nothing could be checked"})
        self.assertNotIn("--emit-host-agents", message)
        self.assertIn("driver loop --setup --host claude --mode headless", message)

    def test_a_host_that_registers_nothing_is_offered_neither(self):
        message = self._refuse(self._repo(), "generic",
                               {"state": hosts.UNKNOWN, "by": None, "detail": "no shells"})
        self.assertNotIn("--emit-host-agents", message)
        self.assertNotIn("driver loop --setup", message)
        self.assertIn("--allow-unenforced", message)
        self.assertIn("--host claude", message)


class TestTheSetupAckDescribesThisInvocation(unittest.TestCase):
    """#1737 fix round 1, nit (a). The ack borrowed the review ack's
    never-overwrite rule, which exists there to protect a BINDING (#493 R2:
    `plan_sha256` must stay as first written so a changed plan reads stale).
    Setup's ack binds nothing downstream -- it is a record of what the
    operator accepted about THIS dispatch -- so never-overwrite only made it
    lie: an ack first written on one host kept that host's name, and one
    written while the posture was refuted went on saying `acknowledged: true`
    after the operator emitted their shells and the dispatch became enforced.
    """

    def _root(self):
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        os.makedirs(os.path.join(d, ".panopticon"))
        return d

    def _entry(self, out_file="/abs/p.json"):
        return {"id": "setup-scan", "agent": None, "enforced": False,
                "out_file": out_file, "prompt": "BRIEF"}

    def _manifest(self, host="claude"):
        return {"host": host, "flags": {"allow_unenforced": True}}

    def test_host_and_plan_hash_are_refreshed_on_every_write(self):
        d = self._root()
        setup.require_unenforced_scan_ack(d, self._manifest("claude"), [self._entry()])
        first = runio._load_json(runio._pano(d, setup.SETUP_UNENFORCED_ACK))
        setup.require_unenforced_scan_ack(
            d, self._manifest("generic"), [self._entry("/abs/other.json")])
        second = runio._load_json(runio._pano(d, setup.SETUP_UNENFORCED_ACK))
        self.assertEqual("claude", first["host"])
        self.assertEqual("generic", second["host"])
        self.assertNotEqual(first["plan_sha256"], second["plan_sha256"])

    def test_writing_the_same_acceptance_twice_changes_nothing(self):
        d = self._root()
        path = setup.require_unenforced_scan_ack(d, self._manifest(), [self._entry()])
        before = open(path, "rb").read()
        again = setup.require_unenforced_scan_ack(d, self._manifest(), [self._entry()])
        self.assertEqual(path, again)
        self.assertEqual(before, open(path, "rb").read())

    def test_an_enforced_dispatch_supersedes_and_removes_a_standing_ack(self):
        d = self._root()
        path = setup.require_unenforced_scan_ack(d, self._manifest(), [self._entry()])
        self.assertTrue(os.path.isfile(path))
        write_host_evidence(d, {hosts.TOOL_POLICY_ENFORCED: hosts.PROVEN})
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertIsNone(setup.require_unenforced_scan_ack(
                d, {"host": "claude"}, [self._entry()]))
        self.assertFalse(os.path.exists(path),
                         "a superseded acceptance stayed on the tree saying "
                         "acknowledged: true about an enforced dispatch")
        self.assertIn(setup.SETUP_UNENFORCED_ACK, err.getvalue())   # announced

    def test_removing_it_is_never_fatal(self):
        # The ack sits under `.panopticon`, which the target owns: a read-only
        # directory, or a planted directory at the name, must not take down
        # the enforced path -- the acknowledgement is not needed there.
        d = self._root()
        write_host_evidence(d, {hosts.TOOL_POLICY_ENFORCED: hosts.PROVEN})
        os.makedirs(runio._pano(d, setup.SETUP_UNENFORCED_ACK))
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertIsNone(setup.require_unenforced_scan_ack(
                d, {"host": "claude"}, [self._entry()]))


class TestStandaloneSetupProbesItsOwnPosture(unittest.TestCase):
    """#1737 fix round 1, Critical. `driver setup` -- the bootstrap verb, not
    `driver loop --setup` -- passed `posture=None`, so NOTHING wrote the setup
    namespace's `host-capabilities.json`. The ack gate reads exactly that
    artifact, so on a fresh target the verb refused with "probe none ran: no
    evidence", and the remedy it names first (`--emit-host-agents`) changed
    nothing at all, because nothing re-probed afterwards. The only route
    through the bootstrap verb became `--allow-unenforced` -- the silent
    unenforced dispatch #1737 exists to remove, now merely renamed.

    The verb probes for itself now, exactly as `driver loop --setup` does.
    These tests go through `driver.main` deliberately: the wiring IS the fix,
    and a test calling `run_setup_flow(posture=...)` by hand would pass with
    the wiring still missing.
    """

    def _repo(self):
        return make_git_repo(test_case=self, files={"src/a.py": "x = 1\n"},
                             branch="main", user_email="t@t", user_name="t")

    def _setup(self, d, *argv, probes):
        out = io.StringIO()
        with mock.patch("scripts.host_probes.run_probes",
                        side_effect=lambda host, target, **kw: probes(host)), \
                contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(io.StringIO()):
            code = driver.main(["setup", d, *argv])
        return code, json.loads(out.getvalue().splitlines()[-1])

    def _evidence(self, d):
        return runio._load_json(os.path.join(d, ".panopticon", runio.HOST_CAPABILITIES))

    def test_a_proven_host_dispatches_enforced_with_no_ack_and_no_fixture(self):
        d = self._repo()
        self.assertIsNone(self._evidence(d))          # a genuinely fresh target
        code, status = self._setup(d, probes=_all_proven_artifact)
        self.assertEqual(0, code, status)
        self.assertEqual("checkpoint", status["status"], status)
        # the run wrote its OWN evidence, flat, in setup's namespace
        written = self._evidence(d)
        self.assertEqual(hosts.PROVEN,
                         written["capabilities"][hosts.TOOL_POLICY_ENFORCED]["state"])
        entry = runio._load_json(requests.request_path(d, namespace="setup"))["entries"][0]
        self.assertTrue(entry["enforced"])
        self.assertEqual("panopticon-setup-scan", entry["agent"])
        self.assertFalse(os.path.exists(runio._pano(d, setup.SETUP_UNENFORCED_ACK)))

    def test_a_standing_ack_is_dropped_once_the_shells_are_registered(self):
        # The bootstrap sequence itself: accept the risk once, emit the
        # shells, re-run. The acceptance must not outlive the posture it was
        # about, saying `acknowledged: true` over an enforced dispatch.
        d = self._repo()
        self._setup(d, "--allow-unenforced", probes=_refuted_artifact)
        ack = runio._pano(d, setup.SETUP_UNENFORCED_ACK)
        self.assertTrue(os.path.isfile(ack))
        os.remove(requests.request_path(d, namespace="setup"))
        code, status = self._setup(d, probes=_all_proven_artifact)
        self.assertEqual(0, code, status)
        entry = runio._load_json(requests.request_path(d, namespace="setup"))["entries"][0]
        self.assertTrue(entry["enforced"])
        self.assertFalse(os.path.exists(ack))

    def test_an_unenforceable_host_is_refused_with_both_remedies(self):
        d = self._repo()
        code, status = self._setup(d, probes=_refuted_artifact)
        self.assertEqual(1, code, status)
        self.assertEqual("error", status["status"], status)
        self.assertIn("--emit-host-agents claude", status["message"])
        self.assertIn("--allow-unenforced", status["message"])
        # ...and the refusal quotes what the probe ACTUALLY found, not
        # "probe none ran: no evidence" -- the symptom of the unwired step.
        self.assertNotIn("none ran", status["message"])
        self.assertIn("fixture: tool policy deliberately refuted", status["message"])
        self.assertFalse(os.path.isfile(requests.request_path(d, namespace="setup")))

    def test_the_ack_carries_the_same_unenforceable_host_through(self):
        d = self._repo()
        code, status = self._setup(d, "--allow-unenforced", probes=_refuted_artifact)
        self.assertEqual(0, code, status)
        self.assertEqual("checkpoint", status["status"], status)
        entry = runio._load_json(requests.request_path(d, namespace="setup"))["entries"][0]
        self.assertFalse(entry["enforced"])
        self.assertIsNone(entry["agent"])
        ack = runio._load_json(runio._pano(d, setup.SETUP_UNENFORCED_ACK))
        self.assertEqual(hosts.REFUTED, ack[hosts.TOOL_POLICY_ENFORCED])

    def test_a_planted_evidence_artifact_is_overwritten_before_the_gate_reads_it(self):
        # Fix round 1, Important 2. `.panopticon/host-capabilities.json` is a
        # path a hostile target can force-commit past `.gitignore`, and before
        # the posture step was wired the gate simply believed it. The run's own
        # probe now rewrites the artifact BEFORE the gate reads it, so a
        # planted `proven` cannot buy an enforced dispatch.
        d = self._repo()
        os.makedirs(os.path.join(d, ".panopticon"), exist_ok=True)
        write_host_evidence(d, {hosts.TOOL_POLICY_ENFORCED: hosts.PROVEN})
        subprocess.run(["git", "add", "-f", ".panopticon/" + runio.HOST_CAPABILITIES],
                       cwd=d, check=True, capture_output=True)
        code, status = self._setup(d, probes=_refuted_artifact)
        self.assertEqual(1, code, status)
        self.assertIn("--allow-unenforced", status["message"])
        self.assertEqual(hosts.REFUTED,
                         self._evidence(d)["capabilities"][hosts.TOOL_POLICY_ENFORCED]["state"])


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
        # #1737: a registered machine, so the scan dispatches enforced rather
        # than being refused for want of the operator's acknowledgement.
        write_host_evidence(d, {hosts.TOOL_POLICY_ENFORCED: hosts.PROVEN})
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
    # prose that no longer matches what setup emits. Still gemini after the
    # retirement (#1621, 2026-09-13): `_check_host_shells` reads the REGISTRY,
    # which still knows the row, and a shell-less host's readiness answer is a
    # fact about that row. The setup RUN that carries these answers below is
    # driven under `generic`, because `driver setup --host gemini` is now an
    # argparse error -- the rows are the subject, the driven host is scaffold.
    #
    # #1598/#1599: a METHOD, not a module-level constant. As a constant it was
    # evaluated at COLLECTION time -- before any mock could be in place -- so
    # it reached the live probes with no repo_root and read whatever
    # `~/.claude/agents` held on the machine running the suite. It was also
    # the reason `repo_root` could not simply be made required. The posture is
    # pinned to a deterministic shell-less envelope and a real tree is named;
    # the REGISTRY rows above it are what these tests are about.
    GEMINI_POSTURE = {
        "schema_version": 1, "host": "gemini", "probed_at": "T",
        "capabilities": {
            capability: {"state": hosts.UNKNOWN, "by": None,
                         "detail": "no probe: gemini does not claim this "
                                   "capability, so there is nothing to prove"}
            for capability in hosts.CAPABILITIES},
    }

    @property
    def GEMINI_CHECKS(self):
        with mock.patch.object(host_probes, "run_probes",
                               return_value=self.GEMINI_POSTURE):
            return setup_flow._check_host_shells("gemini", None, ".")

    def test_the_gemini_limitation_reaches_the_operator(self):
        rows = {c[0]: c for c in self.GEMINI_CHECKS}
        self.assertEqual(("enforced-shells", None,
                          "gemini registers no enforcement shells; reviewers "
                          "run with a prompt-advisory tool policy"),
                         rows["enforced-shells"])
        msg, marker = self._fallback(self.GEMINI_CHECKS, host="generic")
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
        msg, marker = self._fallback(self.GEMINI_CHECKS, host="generic")
        self.assertIn(["host-capabilities", rows["host-capabilities"][2]],
                      marker["limitations"])
        self.assertIn("host-capabilities", msg)

    def test_a_limitation_never_becomes_a_gap(self):
        # It must not gate READY: `gaps` stays empty and the readiness verdict
        # stays OK. Distinct clause, distinct key -- a consumer can tell "not
        # applicable" from "fine".
        msg, marker = self._fallback(self.GEMINI_CHECKS, host="generic")
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

    def test_the_operator_message_lists_one_limitation_per_bounded_line(self):
        # #1601, end to end on the shipped gemini posture: seven limitations,
        # each carrying a full remedy, rendered as ONE 1847-character line on
        # the message the operator actually reads. One per line now, each
        # under the column bar, and one line per stored limitation -- so the
        # message and `setup-complete.json` still agree on the count.
        msg, marker = self._fallback(self.GEMINI_CHECKS, host="generic")
        body = msg.splitlines()
        self.assertIn("limitations:", body)
        head = body.index("limitations:")
        self.assertEqual(len(marker["limitations"]), len(body) - head - 1)
        over = ["%d: %s" % (len(ln), ln) for ln in body[head:] if len(ln) > 119]
        self.assertEqual([], over, "\n".join(over))

    def test_a_real_gap_is_still_reported_as_a_gap(self):
        checks = [("docker", False, "docker unavailable -- install/start Docker"),
                  ("enforced-shells", None, "gemini registers no enforcement "
                                            "shells; reviewers run with a "
                                            "prompt-advisory tool policy")]
        msg, marker = self._fallback(checks, host="generic")
        self.assertEqual(["docker"], marker["gaps"])
        self.assertIn("readiness gaps: docker", msg)
        self.assertIn("limitations", msg)
        self.assertIn("enforced-shells", msg)


class TestTheLimitationsClauseStaysReadable(unittest.TestCase):
    """#1601: `_limitations_clause` joined every limitation into ONE line.
    For `gemini` -- which claims nothing, so five-of-five-unproven plus two
    shell rows is its entire story, seven limitations each carrying a full
    remedy -- that line went from ~110 characters to 1847, and the same text
    is stored in `setup-complete.json`'s `limitations` array.

    Nothing gating changed (shell-less hosts produce 7 rows and 0 gaps), which
    is exactly why it needs a test: a completion message nobody can read is a
    disclosure in the letter and not in the fact, and 5.1's "LOUDLY declare
    them" is about being READ.
    """

    # A real remedy, verbatim from host_disclosure, so the fixture cannot be
    # quietly short enough to pass a length bar the shipped text fails.
    REMEDY = host_disclosure.remedy(hosts.MODEL_BINDING, "gemini")

    def _rows(self, n):
        return [("host-capability:capability_%02d" % i, self.REMEDY)
                for i in range(n)]

    def _lines(self, clause):
        return clause.splitlines()

    def test_twenty_remedies_render_as_twelve_lines_and_a_tail(self):
        body = self._lines(setup_phase._limitations_clause(self._rows(20)))
        self.assertEqual("limitations:", body[0])
        self.assertEqual(1 + setup_phase._LIMITATION_MAX + 1, len(body),
                         "expected a header, 12 remedies and one tail:\n"
                         + "\n".join(body))
        self.assertIn("and 8 more", body[-1])

    def test_no_rendered_line_is_over_the_column_bar(self):
        for count in (1, 7, 12, 20):
            with self.subTest(limitations=count):
                clause = setup_phase._limitations_clause(self._rows(count))
                over = [ln for ln in self._lines(clause) if len(ln) > 119]
                self.assertEqual([], over, "line over 119 characters:\n"
                                 + "\n".join("%d: %s" % (len(ln), ln)
                                              for ln in over))

    def test_every_line_carries_exactly_one_remedy(self):
        body = self._lines(setup_phase._limitations_clause(self._rows(3)))
        self.assertEqual(4, len(body))
        for name, line in zip(("capability_00", "capability_01", "capability_02"),
                              body[1:]):
            self.assertIn(name, line)
            # ...and only its own: the 1847-character line was every remedy
            # joined by ", ".
            self.assertEqual(1, sum(1 for c in ("capability_00", "capability_01",
                                                "capability_02") if c in line))

    def test_a_non_string_detail_is_rendered_not_raised(self):
        # Re-review of R1 Minor 4: slicing `detail` instead of the rendered
        # line made a list/dict/int detail raise where the base rendered it.
        # `detail` arrives from `_stored_limitations`, i.e. the untrusted
        # `.panopticon/setup-complete.json`, outside the status-protocol
        # try/except -- so it escaped as a traceback with no JSON status.
        for detail in (["a", "b"], {"k": 1}, 7, None):
            with self.subTest(detail=detail):
                line = setup_phase._limitation_line("host-capability:x", detail)
                self.assertIsInstance(line, str)
                self.assertIn(str(detail), line)
        long = ["remedy-%02d" % i for i in range(40)]
        line = setup_phase._limitation_line("host-capability:x", long)
        self.assertLessEqual(len(line), setup_phase._LIMITATION_LINE)
        self.assertTrue(line.endswith(setup_phase._TRUNCATED + ")"), line)

    def test_a_short_list_gets_no_tail(self):
        clause = setup_phase._limitations_clause(self._rows(setup_phase._LIMITATION_MAX))
        self.assertNotIn("more", clause)

    def test_a_name_longer_than_the_bar_survives_intact(self):
        # R1 Minor 4. The docstring promised "the NAME is never what gets cut"
        # while `_limitation_line` sliced the whole rendered line: a 156-char
        # name came back truncated mid-name, losing the one field
        # `setup-complete.json` keys the untruncated detail under and the one
        # an operator greps the readiness rows for. Unreachable with today's
        # check names (the longest is `host-capability:tool_policy_enforced`,
        # 36 characters) -- which is exactly why it was a comment claiming a
        # guarantee the code did not make.
        name = "host-capability:" + ("x" * 140)
        line = self._lines(setup_phase._limitations_clause(
            [(name, self.REMEDY)]))[1]
        self.assertIn(name, line)
        self.assertNotIn(self.REMEDY, line, "the detail must still be cut")

    def test_the_detail_is_the_only_field_ever_cut(self):
        name = "host-capability:model_binding"
        line = self._lines(setup_phase._limitations_clause(
            [(name, self.REMEDY)]))[1]
        self.assertIn(name, line)
        self.assertTrue(line.endswith(setup_phase._TRUNCATED + ")"), line)
        # ...and what survives of the detail is a PREFIX of the real one, not
        # a slice of something else.
        cut = line[len("  - %s (" % name):-len(setup_phase._TRUNCATED + ")")]
        self.assertTrue(self.REMEDY.startswith(cut), line)
        self.assertTrue(cut, "the detail was cut away entirely")

    def test_the_name_survives_truncation(self):
        # The check's NAME is what an operator greps for and what
        # setup-complete.json keys on; only the detail may be cut.
        line = self._lines(setup_phase._limitations_clause(
            [("host-capability:model_binding", self.REMEDY)]))[1]
        self.assertIn("host-capability:model_binding", line)


class TestSetupConvertsAStalledEngine(unittest.TestCase):
    """`driver run` turns the engine's progress guard into an `error` status
    (#1637 P08 F1b); `driver setup` drives the same engine and still let it
    escape as a traceback. One named class, two call sites, and only one of
    them converting is how the next person learns the guarantee is per-caller
    rather than per-engine."""

    def test_a_stalled_setup_engine_is_an_error_status(self):
        with tempfile.TemporaryDirectory() as d:
            root = os.path.realpath(d)
            os.makedirs(runio._pano(root), exist_ok=True)
            stuck = engine.Phase(
                name="scan", kind="deterministic", done=lambda r, m: False,
                execute=lambda r, m: engine.PhaseResult(kind="advanced"))
            args = mock.Mock(target=root, host="claude", reset=False,
                             max_per_group=None, max_groups=None)
            status = setup_phase.run_setup_flow(args, phases=(stuck,))
        self.assertEqual(status["status"], "error", status)
        self.assertIn("without satisfying its done() predicate",
                      status["message"])


class TestSetupConvertsAConfinementRefusal(unittest.TestCase):
    """Item 24 R1-1: #1577 routed the five `--setup` artifact writes through the
    confined no-follow writers, and the whole-path confinement refuses a planted
    component with a `ValueError` -- not a `DriverError`. `run_setup_flow`
    converted only `(DriverError, EngineStalled)`, so the refusal escaped
    `driver setup` as a traceback: the host asking for a status got no JSON at
    all, and the operator got a stack trace naming a file instead of a message
    naming the plant.

    A refusal is a RESULT of this verb -- the guard working -- so it speaks the
    same status protocol as every other outcome. `driver run` had the same gap
    around the engine's own artifact writes and is closed with it.
    """

    def _planted(self, root, victim_dir):
        victim = os.path.join(victim_dir, "loot")
        with open(victim, "w", encoding="utf-8") as fh:
            fh.write("KEEP")
        os.makedirs(runio._pano(root), exist_ok=True)
        os.symlink(victim, runio._pano(root, "setup-spine.json"))
        return victim

    def test_an_invalid_root_config_is_an_error_status_with_nothing_written(self):
        # I2: `driver run` fails loud on this tree and setup used to walk
        # straight past it -- the committed matrix reads as {} whenever the
        # document is unreadable, so the flow would have proposed a draft that
        # discards the operator's own groups and exclude_paths.
        d = make_git_repo(test_case=self, files={"src/checkout/pay.py": "x = 1\n"},
                          branch="main", user_email="t@t", user_name="t")
        with open(os.path.join(d, repo_config.CONFIG_NAMES[0]), "w",
                  encoding="utf-8") as fh:
            fh.write("groups:\n  Checkout:\n    match: ['src/checkout/**']\n")
        args = driver.build_parser().parse_args(["setup", d])
        status = setup_phase.run_setup_flow(args)
        self.assertEqual(status["status"], "error", status)
        self.assertIn("version: 1", status["message"])
        self.assertFalse(os.path.isfile(repo_config.draft_path(d)))
        self.assertFalse(os.path.isfile(runio._pano(d, "setup-report.md")))

    def test_a_planted_spine_is_an_error_status_not_a_traceback(self):
        d = make_git_repo(test_case=self, files={"src/checkout/pay.py": "x = 1\n"},
                          branch="main", user_email="t@t", user_name="t")
        with tempfile.TemporaryDirectory() as out:
            victim = self._planted(d, os.path.realpath(out))
            args = driver.build_parser().parse_args(["setup", d])
            status = setup_phase.run_setup_flow(args)
            self.assertEqual(status["status"], "error", status)
            self.assertIn("setup-spine.json", status["message"])
            with open(victim, encoding="utf-8") as fh:
                self.assertEqual("KEEP", fh.read())
