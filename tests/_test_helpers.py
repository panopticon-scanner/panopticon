"""Shared test helpers used across multiple test modules."""
import os

from conftest import FIXTURE_ROOT  # noqa: E402


def touch(root, rel, content=""):
    """Create a file at ``root/rel`` with optional content."""
    full = os.path.join(root, rel)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as fh:
        fh.write(content)


def assert_adapter_finds(test_case, adapter_name, target_name, group="g1",
                         ok_codes=(0, 1)):
    """Run an adapter against a fixture and assert it produces findings.

    Skips the test when the fixture directory is not present (the normal case
    outside the fixtures image). A non-applicable fixture or a tool crash is a
    real failure, not a skip that would leave coverage silently empty (#583).
    """
    from scripts.tools import ADAPTERS

    target = os.path.join(FIXTURE_ROOT, target_name)
    adapter = ADAPTERS[adapter_name]
    if not os.path.isdir(target):
        test_case.skipTest(
            f"{target_name} fixture not vendored (run inside the fixtures image)"
        )
    test_case.assertTrue(
        adapter.is_applicable(target),
        f"{adapter_name} should apply to the {target_name} project",
    )
    raw, rc = adapter.invoke(target)
    test_case.assertIn(
        rc, ok_codes, f"{adapter_name} errored (rc {rc}) on {target_name}"
    )
    findings = adapter.parse(raw, group)
    test_case.assertTrue(findings, f"expected {adapter_name} findings against {target_name}")
    return findings
