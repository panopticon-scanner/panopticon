"""Reusable setup fixtures and synthetic readiness artifacts."""

import contextlib
import json
import os
import subprocess
import tempfile
import unittest
from unittest import mock


import scripts.hosts as hosts
import scripts.probes.codex as codex_probes
import shutil


def _isolate_codex_probes(test_case):
    """Readiness assertions must never invoke a real Codex runtime probe."""
    for name, probe_id in (
        ("probe_codex_tool_policy", "codex-effective-tools"),
        ("probe_codex_read_scope", "codex-read-scope"),
    ):
        patcher = mock.patch.object(
            codex_probes, name,
            return_value=(hosts.UNKNOWN, probe_id, "isolated test fixture"))
        patcher.start()
        test_case.addCleanup(patcher.stop)

def _repo(test_case, with_committed=False):
    d = os.path.realpath(tempfile.mkdtemp())
    os.makedirs(os.path.join(d, "src", "checkout"))
    with open(os.path.join(d, "src", "checkout", "pay.py"), "w") as fh:
        fh.write("x = 1\n")
    os.makedirs(os.path.join(d, ".panopticon"))
    test_case.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
    if with_committed:
        body = "groups:\n  Checkout:\n    match: ['src/checkout/**']\n    panels: [SEC]\n"
        with open(os.path.join(d, "panopticon.yml"), "w") as fh:
            fh.write("version: 1\n" + body)
    return d

def _git_repo(test_case, gitignore):
    """A real git checkout whose .gitignore is exactly `gitignore`."""
    d = _repo(test_case)
    for argv in (["init", "-q"], ["config", "user.name", "T"],
                 ["config", "user.email", "t@example.com"]):
        subprocess.run(["git", "-C", d] + argv, check=True,
                       capture_output=True)
    with open(os.path.join(d, ".gitignore"), "w") as fh:
        fh.write(gitignore)
    subprocess.run(["git", "-C", d, "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", d, "commit", "-qm", "init"], check=True,
                   capture_output=True)
    return d

def _status(repo):
    return subprocess.run(["git", "-C", repo, "status", "--porcelain"],
                          capture_output=True, text=True).stdout

def _mixed_artifact(host):
    """A host-capabilities.json envelope with a genuinely MIXED posture: one
    proven, one refuted, three unknown -- each on a DIFFERENT capability, per
    the plan's Global Constraint. Same shape as
    tests/test_host_disclosure.py's module-level MIXED fixture, redefined
    locally rather than imported so this file does not reach into another
    test module for its data."""
    return {
        "schema_version": 1, "host": host, "probed_at": "T",
        "capabilities": {
            hosts.TOOL_POLICY_ENFORCED: {
                "state": hosts.REFUTED, "by": "shadow-shell-scan",
                "detail": "the reviewed tree ships .claude/agents/panopticon-scout.md"},
            hosts.ARTIFACT_WRITE_GUARD: {
                "state": hosts.PROVEN, "by": "write-guard-armed",
                "detail": "round-trip denied"},
            hosts.USAGE_LEDGER: {
                "state": hosts.UNKNOWN, "by": None,
                "detail": "no transcript directory"},
            hosts.READ_SCOPE_CONFINED: {
                "state": hosts.UNKNOWN, "by": None,
                "detail": "claude proves this since plan 5; other hosts do not claim it"},
            hosts.MODEL_BINDING: {
                "state": hosts.UNKNOWN, "by": None,
                "detail": "dispatch entries carry model=None until F4 binds them"},
        },
    }

def _all_proven_artifact(host):
    """Every capability PROVEN, for pairing with a host that CLAIMS all five
    (see test_an_all_proven_host_says_so_rather_than_reporting_nothing) -- an
    all-proven artifact alone is not enough: the synthetic fixture pins the
    shape; claude proves read_scope_confined since plan 5, other hosts do
    not claim it, so hosts.posture()'s claim-mask would still force that one
    to unknown on a host that does not claim it, and the NOT-PROVEN headline
    would fire regardless of what this fixture says."""
    return {
        "schema_version": 1, "host": host, "probed_at": "T",
        "capabilities": {cap: {"state": hosts.PROVEN, "by": "fixture",
                               "detail": "proven"} for cap in hosts.CAPABILITIES},
    }

def _shell_less_artifact(host):
    """What `run_probes` really returns for a host that registers no shells and
    claims nothing: five honest unknowns, each with its OWN reason.

    Not mixed across STATES, because gemini/generic cannot reach a mixed one --
    `hosts.posture()`'s claim-mask forces every non-refuted state to unknown
    for a host that claims nothing, so a proven entry here would be a fixture
    asserting something the registry cannot produce. Mixed where it can be:
    five different details, and one capability whose `by` names a probe that
    actually ran (the shadow scan runs for any host, claim or no claim), so a
    renderer that hard-codes one capability's shape fails on the other four.
    """
    return {
        "schema_version": 1, "host": host, "probed_at": "T",
        "capabilities": {
            hosts.TOOL_POLICY_ENFORCED: {
                "state": hosts.UNKNOWN, "by": "shadow-shell-scan",
                "detail": "host %r discovers no project-scoped agents" % host},
            hosts.ARTIFACT_WRITE_GUARD: {
                "state": hosts.UNKNOWN, "by": None,
                "detail": "no probe: host %r does not claim this capability, "
                          "so there is nothing to prove" % host},
            hosts.USAGE_LEDGER: {
                "state": hosts.UNKNOWN, "by": None,
                "detail": "no probe: host %r does not claim this capability, "
                          "so there is nothing to prove" % host},
            hosts.READ_SCOPE_CONFINED: {
                "state": hosts.UNKNOWN, "by": None,
                "detail": "no probe: host %r does not claim this capability, "
                          "so there is nothing to prove" % host},
            hosts.MODEL_BINDING: {
                "state": hosts.UNKNOWN, "by": None,
                "detail": "no probe in F3a: dispatch entries still carry "
                          "model=None (spec 8, F4)"},
        },
    }

def _runner_ok(cmd, **kwargs):
    """A `runner` that never touches a real process. The new host-capability
    probing code does not take `runner` at all (host_probes.run_probes is
    mocked directly in these tests); this only stands in for the codex-cli
    `_probe` call other hosts' checks make, which none of these tests reach."""
    return subprocess.CompletedProcess(cmd, 0, "", "")

class SetupFixtureBase(unittest.TestCase):
    """Shared setup fixtures with no collected test methods."""

    def setUp(self):
        _isolate_codex_probes(self)

    def _gitignore(self, repo):
        with open(os.path.join(repo, ".gitignore"), encoding="utf-8") as fh:
            return fh.read()

    def _legacy(self, d, body, mode="w"):
        os.makedirs(os.path.join(d, ".panopticon"), exist_ok=True)
        path = os.path.join(d, ".panopticon", "groups.yml")
        with open(path, mode) as fh:
            fh.write(body)
        return path

    @contextlib.contextmanager
    def _ingest_fixture(self):
        """A temp repo with a valid setup-proposal.json on disk, yielded as
        (repo, proposal_path). One proposal body, shared by every test that
        needs a successful ingest."""
        d = _repo(self)
        proposal = {"groups": [{"capability": "Checkout",
                                "match": ["src/checkout/**"], "tests": []}]}
        pp = os.path.join(d, ".panopticon", "setup-proposal.json")
        with open(pp, "w") as fh:
            json.dump(proposal, fh)
        yield d, pp

    def _spine_repo(self):
        # A small polyglot repo: a committed vertical, a second unclaimed one,
        # docs/CI/manifests for Commons, two test trees, two manifests that
        # name frameworks. Non-git, so discovery walks the tree.
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        files = {
            "src/checkout/pay.py": "x = 1\n",
            "src/checkout/api/routes.py": "x = 1\n",
            "src/search/a.go": "package s\n",
            "src/search/b.go": "package s\n",
            "src/search/deep/c.go": "package s\n",
            "docs/guide.md": "# g\n",
            "README.md": "# r\n",
            ".github/workflows/ci.yml": "on: push\n",
            "tests/checkout/test_pay.py": "def test(): pass\n",
            "tests/search/search_test.go": "package s\n",
            "package.json": '{"dependencies": {"react": "18"}}\n',
            "pyproject.toml": "[project]\ndependencies = ['django']\n",
        }
        for rel, body in files.items():
            os.makedirs(os.path.join(d, os.path.dirname(rel)) or d, exist_ok=True)
            with open(os.path.join(d, rel), "w") as fh:
                fh.write(body)
        os.makedirs(os.path.join(d, ".panopticon"))
        with open(os.path.join(d, "panopticon.yml"), "w") as fh:
            fh.write("version: 1\ngroups:\n  Checkout:\n    match: ['src/checkout/**']\n"
                     "    panels: [SEC]\n")
        return d

    def _settings(self, d, body):
        """Re-write the spine repo's root config with `settings:` appended."""
        with open(os.path.join(d, "panopticon.yml"), "w") as fh:
            fh.write("version: 1\ngroups:\n  Checkout:\n    match: ['src/checkout/**']\n"
                     "    panels: [SEC]\n" + body)

    def _write_proposal(self, d, proposal):
        pp = os.path.join(d, ".panopticon", "setup-proposal.json")
        with open(pp, "w") as fh:
            json.dump(proposal, fh)
        return pp

    def _root_settings(self, d, body):
        with open(os.path.join(d, "panopticon.yml"), "w") as fh:
            fh.write("version: 1\ngroups: {}\n" + body)

