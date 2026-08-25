"""Shared test helpers used across multiple test modules."""
import os

from conftest import FIXTURE_ROOT  # noqa: E402


class FakeStream:
    """Iterable-chunk fake stdout/stderr for FakePopen."""

    def __init__(self, chunks):
        if chunks is None:
            chunks = []
        elif isinstance(chunks, bytes):
            chunks = [chunks]
        self._chunks = list(chunks)
        self._idx = 0

    def read(self, size=-1):
        if self._idx >= len(self._chunks):
            return b""
        chunk = self._chunks[self._idx]
        self._idx += 1
        return chunk

    def close(self):
        pass


class FakePopen:
    """A Popen-like stand-in for tests that exercise run_tool's bounded
    capture path. Supports both pre-built ``return_value=FakePopen(...)``
    patching and ``side_effect=FakePopen`` construction from run_tool's call
    arguments."""

    def __init__(self, cmd=None, stdout=None, stderr=None, returncode=0,
                 **kwargs):
        self.cmd = list(cmd) if cmd else []
        self._returncode = returncode
        self._killed = False
        # run_tool passes subprocess.PIPE for stdout/stderr; ignore those and
        # let the test provide the byte payload explicitly.
        self.stdout = FakeStream(stdout if stdout not in (None, -1) else None)
        self.stderr = FakeStream(stderr if stderr not in (None, -1) else None)
        self.kwargs = kwargs

    def wait(self, timeout=None):
        if self._killed and self._returncode == 0:
            self._returncode = -9
        return self._returncode

    def kill(self):
        self._killed = True

    def poll(self):
        return self._returncode if self._killed else None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


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
