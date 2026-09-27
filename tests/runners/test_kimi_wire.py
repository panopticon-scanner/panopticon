import json
import os
import tempfile
import unittest
from unittest import mock

import scripts.runners.kimi as kimi_runner


class TestWire(unittest.TestCase):
    def test_malformed_records_do_not_hide_adjacent_turns(self):
        good = {"type": "usage.record", "usageScope": "turn", "model": "kimi-code/k3",
                "usage": {"inputOther": 7, "output": 2}}
        with tempfile.TemporaryDirectory() as directory:
            path = self._wire(directory, [good, None, [], "record", 3,
                                          {"type": "usage.record", "usageScope": "session"}])
            with open(path, "ab") as fh:
                fh.write(b'{unfinished\n\xff\n')
                fh.write((json.dumps(good) + "\n").encode())
            self.assertEqual(kimi_runner.parse_wire(path), (
                {"input_tokens": 14, "output_tokens": 4,
                 "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0}, "kimi-code/k3"))

    def test_invalid_usage_is_unknown_and_never_partially_added(self):
        good = {"type": "usage.record", "usageScope": "turn", "model": "kimi-code/k3",
                "usage": {"inputOther": 7, "output": 2}}
        bodies = [None, [], "usage", 42, {}, {"unknown": 100}]
        for field in ("inputOther", "output", "inputCacheRead", "inputCacheCreation"):
            bodies.extend({"inputOther": 999, field: bad}
                          for bad in (None, True, False, -1, 1.5, "3", [], {}, float("inf")))
        with tempfile.TemporaryDirectory() as directory:
            for body in bodies:
                with self.subTest(body=body):
                    bad = {"type": "usage.record", "usageScope": "turn",
                           "model": "invalid-record", "usage": body}
                    self.assertEqual(kimi_runner.parse_wire(self._wire(directory, [bad])), ({}, None))
                    path = self._wire(directory, [good, bad, good])
                    self.assertEqual(kimi_runner.parse_wire(path), (
                        {"input_tokens": 14, "output_tokens": 4,
                         "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0}, "kimi-code/k3"))

    def test_zero_usage_is_measured_and_only_string_models_replace_the_alias(self):
        with tempfile.TemporaryDirectory() as directory:
            records = [{"type": "llm.request", "modelAlias": "observed-model"}]
            for model in (None, "", [], {"name": "fake"}, 42, True):
                records.extend([{"type": "llm.request", "modelAlias": model},
                                {"type": "usage.record", "usageScope": "turn",
                                 "model": model, "usage": {"inputOther": 0}}])
            self.assertEqual(kimi_runner.parse_wire(self._wire(directory, records)), (
                {"input_tokens": 0, "output_tokens": 0,
                 "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0}, "observed-model"))

    def test_wire_path_refuses_non_string_traversal_and_glob_identifiers(self):
        with tempfile.TemporaryDirectory() as directory:
            home = os.path.join(directory, "kimi-[home]")
            wire = os.path.join(home, "sessions", "wd_x_1", "session_abc", "agents", "main", "wire.jsonl")
            os.makedirs(os.path.dirname(wire))
            with open(wire, "w", encoding="utf-8"):
                pass
            self.assertEqual(kimi_runner.wire_path(home, "session_abc"), wire)
            for session in (None, 1, True, [], {}, ["session_abc"], "", ".", "..",
                            "../session_abc", "..\\session_abc", "*", "session_?bc",
                            "session_[a]bc", "session_abc\n"):
                with self.subTest(session=session), mock.patch.object(
                        kimi_runner.glob, "glob") as search:
                    self.assertIsNone(kimi_runner.wire_path(home, session))
                    search.assert_not_called()

    def _wire(self, d, records):
        path = os.path.join(d, "wire.jsonl")
        with open(path, "w", encoding="utf-8") as fh:
            for record in records:
                fh.write(json.dumps(record) + "\n")
        return path

    def test_turn_records_sum_and_other_scopes_are_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            path = self._wire(d, [
                {"type": "usage.record", "model": "kimi-code/k3", "usageScope": "turn",
                 "usage": {"inputOther": 10, "output": 2, "inputCacheRead": 4, "inputCacheCreation": 1}},
                {"type": "usage.record", "model": "kimi-code/k3", "usageScope": "turn",
                 "usage": {"inputOther": 5, "output": 3, "inputCacheRead": 0, "inputCacheCreation": 0}},
                {"type": "usage.record", "usageScope": "session",
                 "usage": {"inputOther": 999, "output": 999, "inputCacheRead": 999, "inputCacheCreation": 999}},
            ])
            usage, model = kimi_runner.parse_wire(path)
        self.assertEqual(usage, {"input_tokens": 15, "output_tokens": 5,
                                 "cache_read_input_tokens": 4, "cache_creation_input_tokens": 1})
        self.assertEqual(model, "kimi-code/k3")

    def test_no_turn_records_is_empty_usage_not_a_figure(self):
        with tempfile.TemporaryDirectory() as d:
            path = self._wire(d, [{"type": "usage.record", "usageScope": "session",
                                   "usage": {"inputOther": 9}}])
            usage, model = kimi_runner.parse_wire(path)
        self.assertEqual(usage, {})
        self.assertIsNone(model)

    def test_a_missing_wire_is_empty(self):
        self.assertEqual(kimi_runner.parse_wire("/nonexistent/wire.jsonl"), ({}, None))

    def test_wire_path_globs_the_session_layout_and_rejects_pathy_ids(self):
        with tempfile.TemporaryDirectory() as d:
            home = os.path.join(d, "kimi-home")
            wire = os.path.join(home, "sessions", "wd_x_1", "session_abc", "agents", "main", "wire.jsonl")
            os.makedirs(os.path.dirname(wire))
            with open(wire, "w") as fh:
                fh.write("")
            self.assertEqual(kimi_runner.wire_path(home, "session_abc"), wire)
            self.assertIsNone(kimi_runner.wire_path(home, "../escape"))
            self.assertIsNone(kimi_runner.wire_path(home, "session_missing"))
