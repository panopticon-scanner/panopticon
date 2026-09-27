"""Shared driver test constants and inert patch factories."""
from unittest import mock


from tests._test_helpers import all_proven_artifact as _all_proven_artifact
from tests._test_helpers import docker_probe_runner
from scripts import hosts



_ALL_PROVEN = {c: hosts.PROVEN for c in hosts.CAPABILITIES}


def start_module_patches():
    """Start deterministic host and readiness fakes for the calling test module."""
    run_probes_patch = mock.patch(
        "scripts.host_probes.run_probes",
        side_effect=lambda host, target, **kw: _all_proven_artifact(host))
    readiness_docker_patch = mock.patch(
        "scripts.phases.readiness_checks.DOCKER_RUNNER", docker_probe_runner())
    run_probes_patch.start()
    readiness_docker_patch.start()
    return run_probes_patch, readiness_docker_patch
