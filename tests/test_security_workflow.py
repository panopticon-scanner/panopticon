"""The security gate's process-status contract and workflow propagation."""
import contextlib
import io
import json
import os
import re
import subprocess
import tempfile
import unittest

import yaml

import scripts.security_gate as security_gate
from tests._test_helpers import semgrep_size_stamped


ROOT = os.path.join(os.path.dirname(__file__), os.pardir)
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
                stdout, stderr = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    try:
                        status = security_gate.main(
                            ["--tools-dir", tools, "--manifest", manifest])
                    except SystemExit as exc:
                        status = exc.code
                output = stdout.getvalue() + stderr.getvalue()
                self.assertEqual(status, expected, output)
                self.assertIn(message, output)

    def test_workflows_do_not_soften_gate_failures(self):
        # The weekly strict verdict is reported, not gating (owner 2026-11-10),
        # so it is not here: see test_the_strict_verdict_reports_and_fails_only_unevaluated.
        routes = (
            (SECURITY, "scan", GATE),
            (FORK, "fork-scan", GATE),
        )
        for path, job_name, step_name in routes:
            with self.subTest(workflow=os.path.basename(path), step=step_name):
                job = _load(path)["jobs"][job_name]
                step = _step(job, step_name)
                self.assertNotIn("continue-on-error", job)
                self.assertNotIn("continue-on-error", step)

    def test_the_strict_verdict_reports_and_fails_only_unevaluated(self):
        # Owner 2026-11-10: findings (exit 1) warn and write the summary; any
        # other non-zero (the gate could not evaluate) still fails the step.
        # Runs the step's own body under GitHub's bash flags with `python`
        # stubbed to each status, so it pins what the step DOES.
        job = _load(SECURITY)["jobs"]["scan"]
        step = _step(job, "Strict full-tree verdict (reported, not gating)")
        self.assertNotIn("continue-on-error", job)
        self.assertNotIn("continue-on-error", step)
        self.assertIn("security_gate.py", step["run"])
        body = re.sub(r"\$\{\{[^}]*\}\}", "x", step["run"])
        cases = ((0, 0, "**pass**", None), (1, 0, "**fail** (reported, not gating)", "::warning "),
                 (2, 2, None, "::error::"), (3, 3, None, "::error::"))
        for gate_rc, step_rc, summary_text, annotation in cases:
            with self.subTest(gate_rc=gate_rc), tempfile.TemporaryDirectory() as tmp:
                summary = os.path.join(tmp, "summary.md")
                open(summary, "w").close()
                stub = "python() { return %d; }\n" % gate_rc
                proc = subprocess.run(
                    ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", stub + body],
                    env={"PATH": os.environ.get("PATH", ""), "RUNNER_TEMP": tmp,
                         "GITHUB_STEP_SUMMARY": summary},
                    capture_output=True, text=True, timeout=30)
                self.assertEqual(proc.returncode, step_rc, proc.stdout + proc.stderr)
                with open(summary, encoding="utf-8") as fh:
                    written = fh.read()
                if summary_text:
                    self.assertIn(summary_text, written)
                if annotation:
                    self.assertIn(annotation, proc.stdout)

if __name__ == "__main__":  # pragma: no cover
    unittest.main()
