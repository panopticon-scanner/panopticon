import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(__file__), os.pardir)
SCRIPTS = os.path.join(ROOT, "skill", "scripts")



class TestEndToEnd(unittest.TestCase):
    def test_discovery_then_synthesize(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "src"))
            open(os.path.join(d, "src", "app.py"), "w").close()
            # 1. resolve target (P6.5 Slice A: orchestrator.py --directory
            # retired; discovery.py --repo-scan is the sole surviving mode --
            # same groups.json shape, driven the way driver.py drives it)
            r = subprocess.run(
                [sys.executable, os.path.join(SCRIPTS, "discovery.py"),
                 "--repo-scan", d],
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


class TestX0XEmissionEndToEnd(unittest.TestCase):
    def test_synthesize_emits_x0x_report(self):
        # §5.1: a real synthesize run emits an X0X catalog-gap report sibling from
        # the <DOM>-X0X findings, stamped with the driver-supplied run_id.
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "src"))
            open(os.path.join(d, "src", "app.py"), "w").close()
            r = subprocess.run(
                [sys.executable, os.path.join(SCRIPTS, "discovery.py"),
                 "--repo-scan", d], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            groups = json.loads(r.stdout)
            gname = groups["groups"][0]["name"]
            os.makedirs(os.path.join(d, ".panopticon"))
            fp = os.path.join(d, ".panopticon", "findings-%s-code.json" % gname)
            with open(fp, "w") as fh:
                json.dump({"findings": [{
                    "id": "AR-001", "code": "ARC-X0X", "domain": "ARC",
                    "title": "ungated fixture provisioning",
                    "short_title": "ungated fixture provisioning",
                    "severity": "MEDIUM", "confidence": "POSSIBLE", "panel": "code",
                    "category": "general", "description": "runs on every start",
                    "location": {"file": "src/app.py", "line_start": 1,
                                 "line_end": 3}}]}, fh)
            gj = os.path.join(d, "groups.json")
            with open(gj, "w") as fh:
                json.dump(groups, fh)
            out = os.path.join(d, ".panopticon", "report.json")
            r2 = subprocess.run(
                [sys.executable, os.path.join(SCRIPTS, "synthesize.py"),
                 "--target", "src", "--groups", gj, "--run-id", "RID-123",
                 "--out", out, fp],
                capture_output=True, text=True, cwd=d)
            self.assertEqual(r2.returncode, 0, r2.stderr)
            x0x_path = os.path.join(d, ".panopticon", "report-x0x.json")
            self.assertTrue(os.path.isfile(x0x_path), r2.stdout + r2.stderr)
            x0x = json.load(open(x0x_path))
            self.assertEqual(x0x["generated_by"]["run_id"], "RID-123")
            self.assertEqual(len(x0x["candidates"]), 1, x0x)
            c = x0x["candidates"][0]
            self.assertEqual(c["domain"], "ARC")
            self.assertEqual(c["fallback_code"], "ARC-X0X")
            self.assertEqual(c["proposed_name"], "ungated-fixture-provisioning")
            # #1109: the occurrence id is the finding's CONTENT-derived id, not the
            # agent-supplied "AR-001" -- content-derived and ARC-domain-scoped.
            fid = c["occurrences"][0]["finding_id"]
            self.assertNotEqual(fid, "AR-001")
            self.assertRegex(fid, r"^ARC-\d{3,}$")
