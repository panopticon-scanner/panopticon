import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(__file__), os.pardir)
SCRIPTS = os.path.join(ROOT, "scripts")


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
            r2 = subprocess.run(
                [sys.executable, os.path.join(SCRIPTS, "synthesize.py"),
                 "--target", "src", "--groups", gj, "--out", out, fp],
                capture_output=True, text=True)
            self.assertEqual(r2.returncode, 0, r2.stderr)
            self.assertIn("Grade:", r2.stdout)
            with open(out) as _fh:
                report = json.load(_fh)
            # The panel-agent finding carries no verdict, so it is unverified
            # under the two-axis model and does not move the grade by default.
            self.assertEqual(report["summary"]["overall_grade"], "A")
