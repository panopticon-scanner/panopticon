import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(__file__), os.pardir)
SCRIPTS = os.path.join(ROOT, "skill", "scripts")

sys.path.insert(0, os.path.join(ROOT, "skill"))
import scripts.synthesize as syn  # noqa: E402


class TestEndToEnd(unittest.TestCase):
    def test_orchestrator_then_synthesize(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "src"))
            open(os.path.join(d, "src", "app.py"), "w").close()
            # 1. resolve target
            r = subprocess.run(
                [sys.executable, os.path.join(SCRIPTS, "orchestrator.py"),
                 "--repo", d, "--directory", "src"],
                capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            groups = json.loads(r.stdout)
            gname = groups["groups"][0]["name"]
            # 2. write a findings file as a panel agent would
            os.makedirs(os.path.join(d, ".panopticon"))
            fp = os.path.join(d, ".panopticon", "findings-%s-code.json" % gname)
            with open(fp, "w") as fh:
                json.dump({"findings": [{"id": "CD-001", "title": "smell",
                    "severity": "MEDIUM", "confidence": "POSSIBLE", "panel": "code",
                    "category": "structure",
                    "location": {"file": "src/app.py", "line_start": 1}}]}, fh)
            gj = os.path.join(d, "groups.json")
            with open(gj, "w") as fh:
                json.dump(groups, fh)
            out = os.path.join(d, ".panopticon", "report.json")
            # 3. synthesize
            # cwd=d: synthesize.py globs .panopticon/dispatch-plan*.json
            # relative to its cwd (#146/C1); without pinning cwd here, a
            # subprocess launched from the repo root would pick up THIS
            # repo's own leftover self-scan dispatch-plan-*.json artifacts
            # and reconcile this test's findings file against them.
            r2 = subprocess.run(
                [sys.executable, os.path.join(SCRIPTS, "synthesize.py"),
                 "--target", "src", "--groups", gj, "--out", out, fp],
                capture_output=True, text=True, cwd=d)
            self.assertEqual(r2.returncode, 0, r2.stderr)
            self.assertIn("Grade:", r2.stdout)
            with open(out) as _fh:
                report = json.load(_fh)
            # The panel-agent finding carries no verdict, so it is unverified
            # under the two-axis model and does not move the grade by default.
            self.assertEqual(report["summary"]["overall_grade"], "A")
            self.assertEqual(report["summary"]["evidence_stats"]["unverified"], 1)
            # opting unverified findings into the gate restores the old behavior
            r3 = subprocess.run(
                [sys.executable, os.path.join(SCRIPTS, "synthesize.py"),
                 "--target", "src", "--groups", gj, "--gate-unverified",
                 "--out", out, fp],
                capture_output=True, text=True, cwd=d)
            self.assertEqual(r3.returncode, 0, r3.stderr)
            with open(out) as _fh:
                report = json.load(_fh)
            self.assertEqual(report["summary"]["overall_grade"], "C")


class TestStrictGateEndToEnd(unittest.TestCase):
    # P2/#446, combined effect: derive_evidence now checks the advisor
    # verdict before the finding's source, and the verify queue (fingerprint-
    # keyed, queues every finding) can actually route a tool claim to that
    # verdict. Together: an unverified tool HIGH is `tool_reported`, which is
    # not gate-eligible, so it no longer fails the build on its own -- it
    # takes an advisor CONFIRMED to fail the gate. --gate-unverified remains
    # the escape hatch that restores the old "every non-rejected claim gates"
    # behavior.
    def _tool_high(self):
        return {"id": "T-1", "source": "tool:bandit", "severity": "HIGH",
                "panel": "security", "category": "secrets",
                "title": "hardcoded password", "confidence": "LIKELY",
                "description": "d",
                "location": {"file": "a.py", "line_start": 1},
                "provenance": {"confirmation_reasoning": "B105"}}

    def test_unverified_tool_high_no_longer_fails_the_gate(self):
        r = syn.build_report([self._tool_high()], [], "t", "high",
                             "2026-08-05T00:00:00Z")
        self.assertEqual(r["summary"]["gate"], "PASS")
        self.assertEqual(
            r["findings"][0]["evidence"]["status"], "tool_reported")

    def test_confirmed_tool_high_fails_the_gate(self):
        f = self._tool_high()
        prepared, _ = syn.prepare_for_queue([dict(f)])
        queue, _c = syn.evidence_mod.build_verify_queue(prepared)
        qid = queue[0]["queue_id"]
        verdicts = {qid: {"verdict": "CONFIRMED",
                          "finding_id": queue[0]["finding"]["id"],
                          "reasoning": "real credential"}}
        r = syn.build_report([f], [], "t", "high", "2026-08-05T00:00:00Z",
                             verdicts=verdicts, verdicts_supplied=True)
        self.assertEqual(r["summary"]["gate"], "FAIL")

    def test_gate_unverified_still_includes_tool_reported(self):
        r = syn.build_report([self._tool_high()], [], "t", "high",
                             "2026-08-05T00:00:00Z", gate_unverified=True)
        self.assertEqual(r["summary"]["gate"], "FAIL")
