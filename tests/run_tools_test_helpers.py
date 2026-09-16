"""Shared helpers for the split run_tools test modules."""
import json


class _FakeResult:
    def __init__(self, returncode=0, stdout=b"", stderr=b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class _Interrupted(BaseException):
    """Not an `Exception`: `_capture_run` catches those, and the point of the
    teardown test is an exception that ESCAPES the dispatch the way an operator
    interrupt does."""


class _DockerStub:
    """A runner stub that records every docker argv and answers the control
    calls the egress session makes, without a daemon anywhere near it.

    `fail` names control verbs (`"network create"`, `"run -d"`, ...) that
    should come back non-zero, which is how the fail-closed paths are driven.
    """

    SUBNET = "172.28.0.0/16"
    GATEWAY = "172.28.0.1"

    def __init__(self, fail=(), running=b"true\n"):
        self.calls = []
        self.fail = set(fail)
        self.running = running

    @staticmethod
    def verb(cmd):
        """The control verb a docker argv starts with: `network create`, `rm`,
        `run -d`, `inspect`, or `run` for a scanner dispatch."""
        rest = list(cmd[1:])
        if rest[:1] == ["network"]:
            return "network %s" % rest[1]
        if rest[:1] == ["run"]:
            return "run -d" if "-d" in rest[:4] else "run"
        if rest[:1] == ["container"]:
            return "container %s" % rest[1]
        return rest[0] if rest else ""

    def __call__(self, cmd, **_kw):
        cmd = list(cmd)
        self.calls.append(cmd)
        verb = self.verb(cmd)
        if verb in self.fail:
            return _FakeResult(returncode=1, stdout=b"", stderr=b"boom")
        if verb == "network inspect":
            body = json.dumps([{"Name": cmd[-1], "Internal": True, "IPAM": {
                "Config": [{"Subnet": self.SUBNET, "Gateway": self.GATEWAY}]}}])
            return _FakeResult(returncode=0, stdout=body.encode("utf-8"))
        if verb == "inspect":
            return _FakeResult(returncode=0, stdout=self.running)
        return _FakeResult(returncode=0, stdout=b'{"dependencies":[]}')

    def control(self):
        """Every call that is NOT a scanner dispatch, in order."""
        return [c for c in self.calls if self.verb(c) != "run"]

    def dispatches(self):
        """`{adapter name: argv}` for the scanner containers that ran."""
        return {c[-1]: c for c in self.calls if self.verb(c) == "run"}
