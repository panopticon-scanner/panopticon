"""#3367: a host reading `complete` learns where the artifacts are without a `stat`, a loop is not
told to tear down what it already tore down, `driver run` keeps every key it had, and the manifest
says when the run finished, without any reader depending on it."""
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

import scripts.first_contact as first_contact
import scripts.orchestrate as orchestrate
import scripts.phases.engine as engine
import scripts.phases.runio as runio
import scripts.phases.synthesize as synthesize
import scripts.run_manifest as run_manifest
import scripts.synth.render as render_mod
import scripts.x0x_report as x0x_report
from tests._test_helpers import adopt_panopticon, our_manifest
from tests.orchestrate_helpers import FakeRunner, _HeadlessLoopCase

TAG = "claude-standard-repo-00000000-abcd1234"


class _Reports(unittest.TestCase):
    def setUp(self):
        self.root = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.pano = os.path.join(self.root, ".panopticon")
        os.makedirs(self.pano)
        self.report = os.path.join(self.pano, TAG + "-report.json")

    def _touch(self, name):
        path = os.path.join(self.pano, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("{}")
        return path

    def _write(self, **meta):
        with open(self.report, "w", encoding="utf-8") as fh:
            json.dump({"meta": meta, "findings": []}, fh)


class ArtifactsTest(_Reports):
    def test_each_kind_is_named_by_its_absolute_path(self):
        part, discarded = self._touch(TAG + "-report_part1.json"), self._touch(TAG + "-report-discarded.json")
        x0x, html = self._touch(TAG + "-report-x0x.json"), self._touch(TAG + "-report.json.html")
        self._write(parts=[os.path.basename(part)], discarded_claims_file=os.path.basename(discarded))
        self.assertEqual({"report": self.report, "parts": [part], "discarded": discarded,
                          "x0x": x0x, "html": html},
                         synthesize.completion_artifacts(self.report))

    def test_a_real_split_report_is_named_whole(self):
        report = {"meta": {}, "summary": {}, "groups": [],
                  "findings": [{"id": "F-%d" % n, "title": "t" * 400} for n in range(40)],
                  "discarded_claims": [{"id": "D-%d" % n, "reasoning": "r" * 400} for n in range(40)]}
        render_mod.write_report(report, self.report, max_bytes=6000)
        out = synthesize.completion_artifacts(self.report)
        self.assertGreater(len(out["parts"]), 1)
        self.assertTrue(os.path.isfile(out["discarded"]))
        for path in out["parts"]:
            self.assertTrue(os.path.isfile(path), path)

    def test_a_clean_run_names_only_what_exists(self):
        self._write()
        self.assertEqual({"report": self.report}, synthesize.completion_artifacts(self.report))

    def test_a_file_planted_beside_the_report_is_not_named(self):
        self._touch(TAG + "-report_part9.json")
        self._touch(TAG + "-report-discarded.json")
        self._write(parts=[])
        self.assertEqual({"report": self.report}, synthesize.completion_artifacts(self.report))

    def test_a_malformed_part_name_is_left_out_never_resolved(self):
        outside = os.path.join(self.root, "outside.json")
        with open(outside, "w", encoding="utf-8") as fh:
            fh.write("{}")
        nested = os.path.join(self.pano, "sub")
        os.makedirs(nested)
        with open(os.path.join(nested, "p.json"), "w", encoding="utf-8") as fh:
            fh.write("{}")
        good = self._touch("good_part1.json")
        self._touch("back\\slash.json")        # a real file of that name, so only the name refuses it
        names = ["back\\slash.json", "../outside.json", outside, "sub/p.json", "sub\\p.json", "..", ".", "", 7, None,
                 ["good_part1.json"], "good_part1.json"]
        self._write(parts=names, discarded_claims_file="../outside.json")
        out = synthesize.completion_artifacts(self.report)
        self.assertEqual([good], out["parts"])
        self.assertNotIn("discarded", out)

    def test_a_meta_of_the_wrong_shape_names_nothing_more(self):
        for meta in ("text", ["a"], None, {"parts": "g"}, {"parts": {"g": 1}}, {"parts": 7}):
            with self.subTest(meta=meta):
                self._touch("g")               # so a string or a dict walked by item would name it
                with open(self.report, "w", encoding="utf-8") as fh:
                    json.dump({"meta": meta}, fh)
                self.assertEqual({"report": self.report}, synthesize.completion_artifacts(self.report))

    def test_an_unreadable_report_is_still_named_as_the_file_it_is(self):
        with open(self.report, "w", encoding="utf-8") as fh:
            fh.write("{torn")
        self.assertEqual({"report": self.report}, synthesize.completion_artifacts(self.report))

    def test_a_symlink_is_never_named_whatever_it_claims_to_be(self):
        target = os.path.join(self.root, "target.json")
        with open(target, "w", encoding="utf-8") as fh:
            fh.write("{}")
        for name in (TAG + "-report-x0x.json", TAG + "-report.json.html", "link_part1.json",
                     "link-discarded.json"):
            os.symlink(target, os.path.join(self.pano, name))
        self._write(parts=["link_part1.json"], discarded_claims_file="link-discarded.json")
        self.assertEqual({"report": self.report}, synthesize.completion_artifacts(self.report))

    def test_a_report_that_is_a_symlink_or_missing_names_nothing(self):
        self.assertEqual({}, synthesize.completion_artifacts(self.report))
        target = os.path.join(self.root, "target.json")
        with open(target, "w", encoding="utf-8") as fh:
            fh.write("{}")
        os.symlink(target, self.report)
        self.assertEqual({}, synthesize.completion_artifacts(self.report))

    def test_a_directory_is_not_a_file(self):
        self._write()
        os.mkdir(self.report + ".html")
        self.assertNotIn("html", synthesize.completion_artifacts(self.report))


class CompleteStatusTest(unittest.TestCase):
    def setUp(self):
        self.root = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        os.makedirs(os.path.join(self.root, ".panopticon"))
        adopt_panopticon(self.root)
        built = run_manifest.build_manifest(target=self.root, review_root=self.root, host="claude",
                                            security_mode="standard")
        run_manifest.write_manifest(self.root, our_manifest(self.root, built))
        self.manifest = run_manifest.load_manifest(self.root)

    def _on_disk(self):
        return run_manifest.load_manifest(self.root)

    def _complete(self):
        return {"status": "complete", "message": "all phases complete",
                "teardown": engine.TEARDOWN_DIRECTIVE}

    def test_it_records_completed_at_and_keeps_every_existing_key(self):
        status = synthesize.complete_status(self._complete(), self.root, self.manifest)
        self.assertEqual(engine.TEARDOWN_DIRECTIVE, status["teardown"])
        self.assertEqual("all phases complete", status["message"])
        self.assertIn("artifacts", status)
        self.assertRegex(self._on_disk()["completed_at"], r"^\d{4}-\d\d-\d\dT")

    def test_the_x0x_disclosure_still_rides_on_it(self):
        x0x = runio._report_out(self.root)[:-len(".json")] + "-x0x.json"
        log = x0x_report.failure_log_path(x0x)
        with open(log, "w", encoding="utf-8") as fh:
            json.dump({"discarded_findings": [{"id": "a"}, {"id": "b"}]}, fh)
        status = synthesize.complete_status(self._complete(), self.root, self.manifest)
        self.assertEqual((2, log), (status["x0x_discarded"], status["x0x_failure_log"]))
        self.assertIn("artifacts", status)

    def test_only_complete_gets_either(self):
        for kind in ("error", "paused", "checkpoint"):
            with self.subTest(kind):
                status = synthesize.complete_status({"status": kind}, self.root, self.manifest)
                self.assertEqual({"status": kind}, status)
                self.assertNotIn("completed_at", self._on_disk())

    def test_the_first_write_wins(self):
        self.manifest["completed_at"] = "2026-01-01T00:00:00Z"
        run_manifest._rewrite(self.root, self.manifest)
        synthesize.complete_status(self._complete(), self.root, self.manifest)
        self.assertEqual("2026-01-01T00:00:00Z", self._on_disk()["completed_at"])

    def test_a_failed_write_cannot_mask_the_status(self):
        for error in (OSError("disk full"), ValueError("refused")):
            with self.subTest(error=error), \
                    mock.patch.object(run_manifest, "_rewrite", side_effect=error):
                manifest = dict(self.manifest)
                status = synthesize.complete_status(self._complete(), self.root, manifest)
                self.assertEqual("complete", status["status"])
                self.assertIn("completed_at not recorded", status["message"])
                self.assertEqual(0, engine.emit_status(status, stream=mock.Mock()))

    def test_the_stamped_manifest_still_verifies_after_the_write(self):
        before = first_contact.assess_artifacts(self.root, read_only=True)["run-manifest.json"]
        self.assertNotIn("completed_at", before)
        synthesize.complete_status(self._complete(), self.root, self.manifest)
        after = first_contact.assess_artifacts(self.root, read_only=True)["run-manifest.json"]
        self.assertEqual(before["stamp"], after["stamp"])
        self.assertIn("completed_at", after)

    def test_it_is_no_anti_drift_key_on_a_resume(self):
        synthesize.complete_status(self._complete(), self.root, self.manifest)
        self.assertEqual([], run_manifest.conflicting_flags(self._on_disk(), host="claude",
                                                            security_mode="standard"))

    def test_a_manifest_with_no_completed_at_is_an_ordinary_one(self):
        self.assertNotIn("completed_at", self._on_disk())
        self.assertEqual([], run_manifest.conflicting_flags(self._on_disk(), host="claude",
                                                            security_mode="standard"))


class ThroughTheRealEntryPointsTest(_HeadlessLoopCase):
    def _run_to_complete(self):
        d, floor = self._repo()
        status = self._run(d, floor, FakeRunner())
        self.assertEqual("complete", status["status"], status)
        return d, status

    def test_a_loop_is_not_told_to_tear_down_what_it_tore_down(self):
        _d, status = self._run_to_complete()
        self.assertNotIn("teardown", status)

    def test_a_loop_names_real_artifacts_and_the_manifest_says_it_finished(self):
        d, status = self._run_to_complete()
        report = status["artifacts"]["report"]
        self.assertEqual(os.path.realpath(runio._report_out(d)), os.path.realpath(report))
        self.assertTrue(os.path.isabs(report))
        for key in ("x0x", "html"):
            self.assertTrue(os.path.isfile(status["artifacts"][key]), key)
        self.assertRegex(run_manifest.load_manifest(d)["completed_at"], r"^\d{4}-\d\d-\d\dT")

    def test_the_directive_stays_when_the_disarm_failed(self):
        status = {"status": "complete", "teardown": engine.TEARDOWN_DIRECTIVE}
        guards = mock.Mock(armed_entries=[])
        guards.disarm.side_effect = OSError("settings unwritable")
        with self.assertRaises(OSError):
            orchestrate._finish(status, "/nonexistent", guards, None, None, mode="session")
        self.assertIn("teardown", status)

    def test_with_no_guards_it_stays_too(self):
        status = {"status": "complete", "teardown": engine.TEARDOWN_DIRECTIVE}
        out = orchestrate._finish(status, "/nonexistent", None, None, None, mode="session")
        self.assertIn("teardown", out)

    def test_an_error_keeps_what_it_had(self):
        status = {"status": "error", "message": "m"}
        guards = mock.Mock(armed_entries=[])
        self.assertEqual({"status": "error", "message": "m"},
                         orchestrate._finish(dict(status), "/nonexistent", guards, None, None,
                                             mode="session"))

    def test_the_usage_write_still_runs_on_every_headless_terminal_status(self):
        for kind in ("complete", "error", "paused"):
            with self.subTest(kind), mock.patch.object(orchestrate.loop_batch, "write_usage") as write:
                orchestrate._finish({"status": kind}, "/nonexistent", None, mock.Mock(), None)
                write.assert_called_once()

    def test_a_setup_run_gets_no_artifacts(self):
        # `run_setup_flow` has its own `complete`, and never goes through `complete_status`.
        import inspect
        import scripts.phases.setup as setup
        self.assertNotIn("complete_status", inspect.getsource(setup))


class DriverRunKeepsItsContractTest(unittest.TestCase):
    def test_the_engine_still_says_teardown(self):
        marks = iter((True,))
        phase = engine.Phase("p", "deterministic", lambda *_a: next(marks), mock.Mock())
        self.assertEqual(engine.TEARDOWN_DIRECTIVE, engine.run_engine("r", {}, [phase])["teardown"])

    def test_the_one_call_site_is_driver_run(self):
        import scripts.driver as driver
        with open(driver.__file__, encoding="utf-8") as fh:
            self.assertEqual(1, fh.read().count("synthesize.complete_status(result, review_root, manifest)"))


if __name__ == "__main__":
    unittest.main()
