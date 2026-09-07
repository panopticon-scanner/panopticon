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
