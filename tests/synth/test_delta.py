"""Tests for scripts.synth.delta: diff hunks and on-diff classification.
"""
import contextlib
import io
import os
import json
import tempfile
import unittest

import scripts.synth.delta as delta_mod

from tests.synth.helpers import _cli_args


class TestLoadDiffHunks(unittest.TestCase):
    """#449 Task 7: the orchestrator's diff-hunks.json artifact, tuple-ified."""

    def test_loads_and_converts_ranges_to_tuples(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "diff-hunks.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "base": "main",
                        "base_source": "explicit",
                        "diff_context": 5,
                        "files_changed": 1,
                        "hunks": {"a.py": [[10, 12], [20, 20]]},
                    },
                    fh,
                )
            data = delta_mod.load_diff_hunks(path)
            self.assertEqual(data["base"], "main")
            self.assertEqual(data["hunks"], {"a.py": [(10, 12), (20, 20)]})

    def test_missing_file_returns_empty_dict(self):
        self.assertEqual(delta_mod.load_diff_hunks("/does/not/exist/diff-hunks.json"), {})

    def test_malformed_json_returns_empty_dict(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "diff-hunks.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("{not json")
            self.assertEqual(delta_mod.load_diff_hunks(path), {})

    def test_non_dict_payload_returns_empty_dict(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "diff-hunks.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(["not", "a", "dict"], fh)
            self.assertEqual(delta_mod.load_diff_hunks(path), {})

    def test_missing_hunks_key_defaults_to_empty(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "diff-hunks.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"base": "main"}, fh)
            data = delta_mod.load_diff_hunks(path)
            self.assertEqual(data["hunks"], {})

class TestClassifyFindings(unittest.TestCase):
    """#449 Task 7: classify_findings stamps f['delta'] via diff_map.classify."""

    def test_stamps_delta_on_each_finding(self):
        findings = [
            {"id": "A-1", "location": {"file": "a.py", "line_start": 11}},
            {"id": "A-2", "location": {"file": "a.py", "line_start": 90}},
        ]
        hunks = {"a.py": [(10, 12)]}
        delta_mod.classify_findings(findings, hunks, 5)
        self.assertTrue(findings[0]["delta"]["on_diff"])
        self.assertFalse(findings[1]["delta"]["on_diff"])
        self.assertIn("hunk", findings[0]["delta"])
        self.assertIn("distance", findings[0]["delta"])

class DeltaLoaderTest(unittest.TestCase):
    def test_from_args_without_hunks_is_inactive(self):
        dc = delta_mod.DeltaContext.from_args(_cli_args(diff_context=3))
        self.assertIsNone(dc.diff_hunks)
        self.assertEqual(dc.diff_context, 3)
        self.assertFalse(dc.active)

    def test_from_args_loads_hunks_and_warns_without_fail_on(self):
        with tempfile.TemporaryDirectory() as d:
            hp = os.path.join(d, "diff-hunks.json")
            with open(hp, "w") as fh:
                json.dump({"base": "main", "hunks": {"a.py": [[1, 5]]}}, fh)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                dc = delta_mod.DeltaContext.from_args(_cli_args(diff_hunks=hp))
            self.assertTrue(dc.active)
            self.assertIn("DELTA REVIEW WITH Gate: OFF", err.getvalue())
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                delta_mod.DeltaContext.from_args(_cli_args(diff_hunks=hp, fail_on="high"))
            self.assertEqual(err.getvalue(), "")

class TestLoadDiffHunksReport(unittest.TestCase):
    """ARC-2340795244 (#1783): the loader is total, so every tolerance it
    applies has to be RECORDED. `load_diff_hunks` keeps its old contract for
    callers; the report form says what the payload cost."""

    def _write(self, d, payload, raw=None):
        path = os.path.join(d, "diff-hunks.json")
        with open(path, "w", encoding="utf-8") as fh:
            if raw is not None:
                fh.write(raw)
            else:
                json.dump(payload, fh)
        return path

    def test_unreadable_file_is_reported(self):
        data, report = delta_mod.load_diff_hunks_report("/does/not/exist/diff-hunks.json")
        self.assertEqual(data, {})
        self.assertEqual(report.payload_malformed, "unreadable")
        self.assertEqual((report.files, report.ranges, report.ranges_dropped), (0, 0, 0))

    def test_malformed_json_is_reported_as_unreadable(self):
        with tempfile.TemporaryDirectory() as d:
            path = self._write(d, None, raw="{not json")
            data, report = delta_mod.load_diff_hunks_report(path)
            self.assertEqual(data, {})
            self.assertEqual(report.payload_malformed, "unreadable")

    def test_non_dict_payload_is_reported(self):
        with tempfile.TemporaryDirectory() as d:
            path = self._write(d, ["not", "a", "dict"])
            data, report = delta_mod.load_diff_hunks_report(path)
            self.assertEqual(data, {})
            self.assertEqual(report.payload_malformed, "not an object")

    def test_non_dict_hunks_is_reported(self):
        with tempfile.TemporaryDirectory() as d:
            path = self._write(d, {"base": "main", "hunks": "nope"})
            data, report = delta_mod.load_diff_hunks_report(path)
            self.assertEqual(data["hunks"], {})
            self.assertEqual(report.payload_malformed, "hunks not an object")
            self.assertEqual((report.files, report.ranges), (0, 0))

    def test_missing_hunks_key_is_reported_the_same_way(self):
        # discovery.write_diff_hunks always emits a `hunks` key, so an artifact
        # without one is as broken as one carrying a non-object there.
        with tempfile.TemporaryDirectory() as d:
            path = self._write(d, {"base": "main"})
            _, report = delta_mod.load_diff_hunks_report(path)
            self.assertEqual(report.payload_malformed, "hunks not an object")

    def test_dropped_ranges_are_counted(self):
        with tempfile.TemporaryDirectory() as d:
            path = self._write(d, {"base": "main",
                                   "hunks": {"a.py": [[1, 5], [2], "x", [3, "4"]],
                                             "b.py": "not a list"}})
            data, report = delta_mod.load_diff_hunks_report(path)
            self.assertEqual(data["hunks"], {"a.py": [(1, 5)]})
            self.assertIsNone(report.payload_malformed)
            self.assertEqual((report.files, report.ranges), (1, 1))
            # three malformed ranges under a.py, plus b.py's whole entry
            self.assertEqual(report.ranges_dropped, 4)

    def test_a_well_formed_payload_reports_nothing_dropped(self):
        with tempfile.TemporaryDirectory() as d:
            path = self._write(d, {"base": "main",
                                   "hunks": {"a.py": [[1, 5], [9, 9]], "b.py": [[2, 3]]}})
            _, report = delta_mod.load_diff_hunks_report(path)
            self.assertIsNone(report.payload_malformed)
            self.assertEqual((report.files, report.ranges, report.ranges_dropped), (2, 3, 0))

    def test_load_diff_hunks_returns_the_same_data(self):
        with tempfile.TemporaryDirectory() as d:
            path = self._write(d, {"base": "main", "hunks": {"a.py": [[1, 5]]}})
            self.assertEqual(delta_mod.load_diff_hunks(path),
                             delta_mod.load_diff_hunks_report(path)[0])

class TestDeltaLoadDisclosure(unittest.TestCase):
    """ARC-2340795244 (#1783): from_args says on stderr what the artifact cost,
    in the #957 register. A green gate over a change with findings is the
    failure this disclosure exists to make visible."""

    NOTICE_957 = ("synthesize: DELTA REVIEW WITH Gate: OFF -- no --fail-on was "
                  "passed, so nothing can gate this change; pass --fail-on "
                  "{critical,high,medium,low} to arm the gate")

    def _from_args(self, payload, raw=None, **kw):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "diff-hunks.json")
            with open(path, "w", encoding="utf-8") as fh:
                if raw is not None:
                    fh.write(raw)
                else:
                    json.dump(payload, fh)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                ctx = delta_mod.DeltaContext.from_args(
                    _cli_args(diff_hunks=path, fail_on="high", **kw))
            return ctx, err.getvalue(), path

    def test_the_957_notice_is_unchanged(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "diff-hunks.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"base": "main", "hunks": {"a.py": [[1, 5]]}}, fh)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                delta_mod.DeltaContext.from_args(_cli_args(diff_hunks=path))
            self.assertEqual(err.getvalue(), self.NOTICE_957 + "\n")

    def test_the_context_carries_the_load_report(self):
        ctx, err, _ = self._from_args({"base": "main", "hunks": {"a.py": [[1, 5]]}})
        self.assertEqual(err, "")
        self.assertEqual((ctx.report.files, ctx.report.ranges), (1, 1))
        self.assertIsNone(ctx.report.payload_malformed)

    def test_an_unreadable_artifact_is_disclosed_with_its_path(self):
        ctx, err, path = self._from_args(None, raw="{not json")
        self.assertIn("DELTA ARTIFACT MALFORMED", err)
        self.assertIn("unreadable", err)
        self.assertIn(path, err)
        self.assertFalse(ctx.active)

    def test_a_non_object_hunks_map_is_disclosed(self):
        _, err, _ = self._from_args({"base": "main", "hunks": 7})
        self.assertIn("DELTA ARTIFACT MALFORMED", err)
        self.assertIn("hunks not an object", err)

    def test_an_active_delta_with_zero_hunks_is_disclosed(self):
        ctx, err, path = self._from_args({"base": "main", "hunks": {}})
        self.assertTrue(ctx.active)
        self.assertIn("DELTA REVIEW WITH ZERO HUNKS", err)
        self.assertIn("off-diff", err)
        self.assertIn("on-diff", err)      # the gate scope that has nothing to fail on
        self.assertIn("empty change", err)
        self.assertIn("regenerate", err)
        self.assertIn(path, err)

    def test_an_inactive_payload_gets_no_zero_hunk_warning(self):
        # No base: the review degrades to a full-repo one, which is the WIDER
        # gate. Nothing is scoped away, so there is nothing to warn about.
        _, err, _ = self._from_args({"hunks": {}})
        self.assertNotIn("ZERO HUNKS", err)

    def test_a_populated_delta_gets_no_zero_hunk_warning(self):
        _, err, _ = self._from_args({"base": "main", "hunks": {"a.py": [[1, 5]]}})
        self.assertEqual(err, "")

    def test_dropped_ranges_are_disclosed_as_a_count(self):
        _, err, _ = self._from_args({"base": "main",
                                     "hunks": {"a.py": [[1, 5], [2], "x"]}})
        self.assertIn("2 malformed hunk range(s) dropped", err)
        self.assertNotIn("ZERO HUNKS", err)

    def test_a_named_file_with_no_range_is_disclosed_as_the_fail_open_shape(self):
        # `diff_map.classify` fails OPEN for a lined finding in a file the map
        # NAMES but gives no range, so "zero ranges" has two consequences and
        # the warning has to say which one this artifact bought.
        _, err, _ = self._from_args({"base": "main", "hunks": {"a.py": []}})
        self.assertIn("DELTA REVIEW WITH ZERO HUNKS", err)
        self.assertIn("names 1 file(s)", err)
        self.assertIn("fails OPEN", err)

    def test_an_empty_map_is_disclosed_as_matching_nothing(self):
        _, err, _ = self._from_args({"base": "main", "hunks": {}})
        self.assertIn("the map is empty", err)
        self.assertNotIn("fails OPEN", err)
