"""Privilege-boundary checks for the ``pull_request_target`` fork route."""
import os
import re
import shlex
import unittest

import yaml


ROOT = os.path.join(os.path.dirname(__file__), os.pardir)
BASE = os.path.join(ROOT, ".github", "workflows", "security.yml")
FORK = os.path.join(ROOT, ".github", "workflows", "security-fork.yml")
GATE = "Gate on HIGH/CRITICAL tool findings (unverified-strict policy)"


def _load(path=FORK):
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _values(value):
    if isinstance(value, dict):
        for item in value.values():
            yield from _values(item)
    elif isinstance(value, list):
        for item in value:
            yield from _values(item)
    elif isinstance(value, str):
        yield value


def _checkouts(job):
    return [step for step in job.get("steps", [])
            if str(step.get("uses", "")).startswith("actions/checkout@")]


def _step(job, name):
    return next(step for step in job["steps"] if step.get("name") == name)


class TestForkPrivilegeBoundary(unittest.TestCase):
    def setUp(self):
        self.workflow = _load()
        self.scan = self.workflow["jobs"]["fork-scan"]
        self.unlabel = self.workflow["jobs"]["unlabel"]

    def test_the_privileged_trigger_and_jobs_are_closed_sets(self):
        # PyYAML 1.1 reads the unquoted ``on`` key as True.
        self.assertEqual(list(self.workflow.get(True, {})), ["pull_request_target"])
        self.assertEqual(set(self.workflow["jobs"]), {"fork-scan", "unlabel"})

    def test_the_scan_job_has_no_secret_or_write_grant(self):
        self.assertEqual(self.scan["permissions"], {
            "contents": "read", "packages": "read", "actions": "read",
        })
        inherited = {"env": self.workflow.get("env", {}), "job": self.scan}
        secret_values = [value for value in _values(inherited)
                         if re.search(r"\${{\s*secrets\s*(?:\.|\[)", value)]
        self.assertEqual(secret_values, [])

    def test_untrusted_checkout_is_after_the_label_gate_and_read_only(self):
        steps = self.scan["steps"]
        self.assertEqual(steps[0].get("name"), "Gate on the safe-to-scan label")
        checkouts = _checkouts(self.scan)
        self.assertEqual(len(checkouts), 2)
        by_path = {step["with"]["path"]: step for step in checkouts}
        self.assertEqual(set(by_path), {"controller", "target"})

        controller = by_path["controller"]
        self.assertEqual(controller["with"]["ref"],
                         "${{ github.event.pull_request.base.sha }}")
        self.assertIs(controller["with"]["persist-credentials"], False)

        target = by_path["target"]
        self.assertEqual(target["with"]["repository"],
                         "${{ github.event.pull_request.head.repo.full_name }}")
        self.assertEqual(target["with"]["ref"],
                         "${{ github.event.pull_request.head.sha }}")
        self.assertIs(target["with"]["persist-credentials"], False)
        self.assertLess(0, steps.index(target))
        self.assertLess(steps.index(controller), steps.index(target))

    def test_the_write_capable_unlabel_job_never_checks_out_pr_code(self):
        self.assertEqual(self.unlabel["permissions"], {"pull-requests": "write"})
        self.assertEqual(_checkouts(self.unlabel), [])


class TestTheLabelGateIsTheFirstThingThatRuns(unittest.TestCase):
    def setUp(self):
        self.gate = _load()["jobs"]["fork-scan"]["steps"][0]

    def test_the_event_bindings_name_this_label_and_only_event_data(self):
        self.assertEqual(self.gate.get("name"), "Gate on the safe-to-scan label")
        self.assertEqual(self.gate.get("env"), {
            "ACTION": "${{ github.event.action }}",
            "LABEL": "${{ github.event.label.name }}",
            "LABELLED": "${{ contains(github.event.pull_request.labels.*.name, "
                        "'safe-to-scan') }}",
        })

    def test_each_failed_binding_exits_nonzero(self):
        script = self.gate.get("run", "")
        for variable, expected in (
                ("ACTION", "labeled"),
                ("LABEL", "safe-to-scan"),
                ("LABELLED", "true")):
            with self.subTest(variable=variable):
                lhs = re.escape('"$%s"' % variable)
                rhs = re.escape('"%s"' % expected)
                block = re.search(
                    r"if\s+\[\s*%s\s+!=\s+%s\s*\]\s*;\s*then"
                    r"(?P<body>.*?)(?:^|\n)\s*fi\b" % (lhs, rhs),
                    script, flags=re.MULTILINE | re.DOTALL)
                self.assertIsNotNone(block, script)
                self.assertRegex(
                    block.group("body"),
                    r"(?:^|\n)\s*exit\s+[1-9][0-9]*\s*(?:;|$)")


class TestBothWorkflowsScanInRedteam(unittest.TestCase):
    ROUTES = (
        (BASE, "scan", "Run static-analysis tools", "run_tools.py"),
        (BASE, "scan", GATE, "security_gate.py"),
        (BASE, "scan", "Strict full-tree gate", "security_gate.py"),
        (FORK, "fork-scan", "Run static-analysis tools", "run_tools.py"),
        (FORK, "fork-scan", GATE, "security_gate.py"),
    )

    def test_scanners_and_gates_pass_the_counting_mode(self):
        for path, job_name, step_name, command in self.ROUTES:
            with self.subTest(workflow=os.path.basename(path), step=step_name):
                job = _load(path)["jobs"][job_name]
                tokens = shlex.split(_step(job, step_name)["run"], comments=True)
                self.assertTrue(any(token.endswith(command) for token in tokens), tokens)
                self.assertEqual(tokens.count("--security"), 1, tokens)
                index = tokens.index("--security")
                self.assertEqual(tokens[index + 1], "redteam", tokens)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
