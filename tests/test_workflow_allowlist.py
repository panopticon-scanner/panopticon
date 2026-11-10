"""Small structural rules for the workflow trust boundary."""

from pathlib import Path
import re
import unittest

import yaml

from tests._test_helpers import REPO_ROOT


WORKFLOWS = Path(REPO_ROOT, ".github", "workflows")
PINNED_ACTION = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")


def _defects(filename, document):
    defects = []
    jobs = document.get("jobs") or {}
    workflow_permissions = "permissions" in document
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        prefix = f"{filename}: jobs.{job_name}"
        if not workflow_permissions and "permissions" not in job:
            defects.append(f"{prefix} has no permissions declaration")
        references = []
        if "uses" in job:
            references.append((f"{prefix}.uses", job["uses"]))
        for index, step in enumerate(job.get("steps") or []):
            if isinstance(step, dict) and "uses" in step:
                references.append((f"{prefix}.steps[{index}].uses", step["uses"]))
        for location, reference in references:
            if not isinstance(reference, str) or not PINNED_ACTION.fullmatch(reference):
                defects.append(f"{location} is not pinned to a 40-hex SHA")

    # PyYAML 1.1 reads the plain key `on` as boolean true.
    events = document.get("on", document.get(True, {}))
    if isinstance(events, (str, list)):
        event_names = events
    elif isinstance(events, dict):
        event_names = events.keys()
    else:
        event_names = ()
    if "pull_request_target" in event_names and filename != "security-fork.yml":
        defects.append(
            f"{filename}: pull_request_target is allowed only in security-fork.yml"
        )
    return defects


class TestWorkflowAllowlist(unittest.TestCase):
    def test_repository_workflows_are_allowed(self):
        defects = []
        paths = sorted(WORKFLOWS.glob("*.y*ml"))
        self.assertGreater(len(paths), 5, "workflow allowlist matched almost nothing")
        for path in paths:
            document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            defects.extend(_defects(path.name, document))
        self.assertEqual([], defects)

    def test_mutable_action_reference_is_rejected(self):
        document = {
            "permissions": {"contents": "read"},
            "jobs": {"scan": {"steps": [{"uses": "actions/checkout@v7"}]}},
        }
        self.assertEqual(
            ["example.yml: jobs.scan.steps[0].uses is not pinned to a 40-hex SHA"],
            _defects("example.yml", document),
        )

    def test_every_job_needs_effective_permissions(self):
        document = {"jobs": {"declared": {"permissions": {}}, "missing": {}}}
        self.assertEqual(
            ["example.yml: jobs.missing has no permissions declaration"],
            _defects("example.yml", document),
        )

    def test_pull_request_target_is_confined_to_security_fork(self):
        document = {"on": {"pull_request_target": {}}, "permissions": {}, "jobs": {}}
        self.assertEqual(
            ["other.yml: pull_request_target is allowed only in security-fork.yml"],
            _defects("other.yml", document),
        )
        self.assertEqual([], _defects("security-fork.yml", document))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
