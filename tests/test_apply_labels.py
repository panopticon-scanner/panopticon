import os
import subprocess
import unittest

from conftest import REPO_ROOT   # #run7 TST-G1B: shared path anchor

SCRIPT = os.path.join(REPO_ROOT, ".github", "apply-labels.sh")
FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "labels.yml")


class TestApplyLabels(unittest.TestCase):
    def test_dry_run_lists_all_labels(self):
        proc = subprocess.run(
            ["bash", SCRIPT, "--dry-run"],
            cwd=REPO_ROOT,
            env={**os.environ, "CATALOG": FIXTURE},
            capture_output=True, text=True, timeout=60)   # #run7 TST-G3B: bound the shell-out
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = proc.stdout
        self.assertIn("severity:critical", out)
        self.assertIn("severity:high", out)
        self.assertIn('"quoted"', out)
        self.assertIn("evidence:advisor-confirmed", out)
        self.assertIn("would apply", out)

    def test_embedded_quote_parses_intact(self):
        proc = subprocess.run(
            ["bash", SCRIPT, "--dry-run"],
            cwd=REPO_ROOT,
            env={**os.environ, "CATALOG": FIXTURE},
            capture_output=True, text=True, timeout=60)   # #run7 TST-G3B: bound the shell-out
        self.assertEqual(proc.returncode, 0, proc.stderr)
        # The embedded quote must survive regex parsing, not be split/dropped.
        self.assertIn('Impact if true: high, including "quoted" text', proc.stdout)
