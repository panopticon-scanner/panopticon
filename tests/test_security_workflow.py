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

CODEQL_STEP = "Ensure CodeQL has analysed this main SHA"
AUDIT_ROUTE = ("(github.event.schedule == '41 6 * * *' || "
               "(github.event_name == 'workflow_dispatch' && inputs.route == 'main-audit'))")
SCAN_NAME = ("${{ github.event_name == 'pull_request' && 'scan' || "
             "((github.event.schedule == '23 7 * * 1' || "
             "(github.event_name == 'workflow_dispatch' && inputs.route != 'main-audit')) "
             "&& 'strict-full-tree' || 'main-audit') }}")
# A stand-in `gh`: each API answers from its own queue file, one line per call
# ("ERR" fails the call); a dispatch is recorded. `sleep` is a no-op.
GH_STUB = r"""
pop() { local f="$STUB/$1" line; line="$(head -n 1 "$f")"; tail -n +2 "$f" > "$f.n"; mv "$f.n" "$f"
        [ "$line" != ERR ] || return 1; printf '%s\n' "$line"; }
gh() {
  case "$*" in
    "api repos/o/r/code-scanning/analyses"*) pop analyses ;;
    "api repos/o/r/commits/main"*) pop commits ;;
    "workflow run codeql.yml --repo o/r --ref main") echo x >> "$STUB/dispatched" ;;
    *) echo "unexpected gh $*" >&2; return 9 ;;
  esac
}
sleep() { :; }
"""


class TestCodeqlCurrentJob(unittest.TestCase):
    """#3581: main-audit dispatches CodeQL at its own SHA, and `scan` still runs."""

    def setUp(self):
        self.jobs = _load(SECURITY)["jobs"]

    def test_runs_on_the_audit_route_only(self):
        job = self.jobs["codeql-current"]
        self.assertEqual(" ".join(job["if"].split()),
                         "github.ref == 'refs/heads/main' && " + AUDIT_ROUTE)
        self.assertEqual(job["permissions"],
                         {"actions": "write", "contents": "read", "security-events": "read"})
        self.assertNotIn("uses", json.dumps(job["steps"]))

    def test_scan_keeps_its_name_and_runs_when_the_new_job_is_skipped(self):
        # Without `!cancelled()`, a skipped `needs` skips `scan`, and a skipped
        # required check reports green without scanning (#1900).
        scan = self.jobs["scan"]
        self.assertEqual(scan["needs"], "codeql-current")
        self.assertTrue(" ".join(scan["if"].split()).startswith("!cancelled() && ("))
        self.assertEqual(" ".join(scan["name"].split()), SCAN_NAME)

    def _run(self, analyses, commits):
        body = _step(self.jobs["codeql-current"], CODEQL_STEP)["run"]
        with tempfile.TemporaryDirectory() as stub:
            for name, lines in (("analyses", analyses), ("commits", commits)):
                with open(os.path.join(stub, name), "w", encoding="utf-8") as fh:
                    fh.write("".join(line + "\n" for line in lines))
            proc = subprocess.run(
                ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", GH_STUB + body],
                env={"PATH": os.environ.get("PATH", ""), "STUB": stub,
                     "REPO": "o/r", "SHA": "abc"},
                capture_output=True, text=True, timeout=30)
            dispatched = os.path.exists(os.path.join(stub, "dispatched"))
        return proc.returncode, proc.stdout + proc.stderr, dispatched

    def test_step_outcomes(self):
        cases = (
            ("already analysed", ["1"], [], 0, "already analysed", False),
            ("main moved first", ["0"], ["def"], 1, "main moved from abc to def", False),
            ("dispatched then analysed", ["0", "0", "1"], ["abc", "abc"], 0,
             "after 2 polls", True),
            ("main moved while waiting", ["0", "0"], ["abc", "def"], 1,
             "main moved from abc to def", True),
            ("analyses API error", ["ERR"], [], 1, "gave no count", False),
            ("API error while waiting", ["0", "ERR"], ["abc"], 1, "gave no count", True),
            ("never analysed", ["0"] * 71, ["abc"] * 71, 1, "within 35 minutes", True),
        )
        for label, analyses, commits, rc, text, dispatched in cases:
            with self.subTest(label):
                got_rc, out, got_dispatch = self._run(analyses, commits)
                self.assertEqual(got_rc, rc, out)
                self.assertIn(text, out)
                self.assertEqual(got_dispatch, dispatched, out)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
