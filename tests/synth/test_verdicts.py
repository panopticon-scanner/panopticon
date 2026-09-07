"""Tests for scripts.synth.verdicts: the verify queue and verdict resolution.
"""
import contextlib
import io
import os
import json
import tempfile
import unittest

import scripts.synth.verdicts as verdicts_mod

from tests.synth.helpers import _make_finding


class EmitVerifyQueueTest(unittest.TestCase):
    """WS-0 S3: the --emit-verify-queue exit main() branches on."""

    def test_writes_the_queue_and_returns_true(self):
        f = _make_finding(severity="HIGH", id="CD-007")
        with tempfile.TemporaryDirectory() as d:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertTrue(verdicts_mod.emit_verify_queue([f], d, None))
            qp = os.path.join(d, "verify-queue.json")
            self.assertTrue(os.path.isfile(qp))
            with open(qp) as fh:
                self.assertEqual(len(json.load(fh)["entries"]), 1)
            self.assertIn("verify queue: 1 entries", out.getvalue())

    def test_nothing_to_queue_removes_a_stale_queue_and_returns_false(self):
        with tempfile.TemporaryDirectory() as d:
            qp = os.path.join(d, "verify-queue.json")
            with open(qp, "w") as fh:
                json.dump({"entries": [{"queue_id": "stale"}]}, fh)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertFalse(verdicts_mod.emit_verify_queue([], d, None))
            self.assertFalse(os.path.exists(qp))
            self.assertIn("verify queue empty; emitting final report", err.getvalue())

    def test_does_not_mutate_the_findings(self):
        f = _make_finding(severity="HIGH", id="CD-007")
        before = json.dumps(f, sort_keys=True)
        with tempfile.TemporaryDirectory() as d:
            with contextlib.redirect_stdout(io.StringIO()):
                verdicts_mod.emit_verify_queue([f], d, None)
        self.assertEqual(json.dumps(f, sort_keys=True), before)
