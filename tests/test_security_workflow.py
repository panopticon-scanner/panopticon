"""The security gate's process-status contract and workflow propagation."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

import yaml

from tests._test_helpers import semgrep_size_stamped


ROOT = os.path.join(os.path.dirname(__file__), os.pardir)
GATE_SCRIPT = os.path.join(ROOT, "skill", "scripts", "security_gate.py")
SECURITY = os.path.join(ROOT, ".github", "workflows", "security.yml")
FORK = os.path.join(ROOT, ".github", "workflows", "security-fork.yml")
GATE = "Gate on HIGH/CRITICAL tool findings (unverified-strict policy)"


def _load(path):
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _step(job, name):
    return next(step for step in job["steps"] if step.get("name") == name)


def _sarif(level=None):
    results = []
    if level:
        results.append({
            "ruleId": "test.rule",
            "level": level,
            "message": {"text": "test finding"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "/src/app.py"},
                "region": {"startLine": 1},
            }}],
        })
    run = semgrep_size_stamped({
        "tool": {"driver": {"name": "semgrep", "rules": []}},
        "results": results,
    })
    return {"version": "2.1.0", "runs": [run]}


class TestSecurityGateExitStatus(unittest.TestCase):
    def test_cli_distinguishes_clean_gated_and_incomplete_scans(self):
        cases = (
            (None, True, 0, "0 HIGH/CRITICAL"),
            ("error", True, 1, "1 HIGH/CRITICAL"),
            (None, False, 2, "scanner coverage incomplete"),
        )
        for level, produced, expected, message in cases:
            with self.subTest(level=level, produced=produced), \
                    tempfile.TemporaryDirectory() as root:
                tools = os.path.join(root, "tools")
                os.mkdir(tools)
                if produced:
                    with open(os.path.join(tools, "semgrep.sarif"), "w",
                              encoding="utf-8") as fh:
                        json.dump(_sarif(level), fh)
                manifest = os.path.join(root, "manifest.json")
                with open(manifest, "w", encoding="utf-8") as fh:
                    json.dump({
                        "selected": ["semgrep"],
                        "produced": ["semgrep"] if produced else [],
                        "missing": [] if produced else ["semgrep"],
                    }, fh)
                proc = subprocess.run(
                    [sys.executable, GATE_SCRIPT, "--tools-dir", tools,
                     "--manifest", manifest],
                    cwd=ROOT, capture_output=True, text=True, check=False)
                self.assertEqual(proc.returncode, expected, proc.stdout + proc.stderr)
                self.assertIn(message, proc.stdout + proc.stderr)

    def test_workflows_do_not_soften_gate_failures(self):
        routes = (
            (SECURITY, "scan", GATE),
            (SECURITY, "scan", "Strict full-tree gate"),
            (FORK, "fork-scan", GATE),
        )
        for path, job_name, step_name in routes:
            with self.subTest(workflow=os.path.basename(path), step=step_name):
                job = _load(path)["jobs"][job_name]
                step = _step(job, step_name)
                self.assertNotIn("continue-on-error", job)
                self.assertNotIn("continue-on-error", step)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
