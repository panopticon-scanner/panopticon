"""Containment and environment tests for scripts.run_tools."""
import contextlib
import io
import os
import tempfile
import unittest
from unittest import mock

import scripts.run_tools as rt
import scripts.tools.egress as rt_egress

from run_tools_test_helpers import _DockerStub, _FakeResult, _Interrupted


class TestContainment(unittest.TestCase):
    def _calls(self, tools, online=False, env=None):
        calls = []
        fake = _FakeResult(returncode=0, stdout=b'{"runs":[]}', stderr=b'')
        def runner(cmd, **kw):
            calls.append(cmd); return fake
        with mock.patch.dict(os.environ, env or {}, clear=True):
            with tempfile.TemporaryDirectory() as d:
                rt.run_tools(d, tools, os.path.join(d, "out"),
                             runner=runner, online=online)
        return calls

    def test_every_dispatch_has_network_none(self):
        for cmd in self._calls(["semgrep", "cargo-audit"]):
            self.assertIn("--network", cmd)          # clear failure, not ValueError (#780)
            i = cmd.index("--network")
            self.assertLess(i + 1, len(cmd), "--network has no value argument")
            self.assertEqual(cmd[i + 1], "none")

    def test_every_dispatch_has_an_empty_working_directory(self):
        # #1877, the container half: the image ends `WORKDIR /src`, which is
        # the target mount, so a dispatch with no `-w` starts its scanner
        # inside the reviewed repo and reads whatever cwd-relative config the
        # target planted. Same iteration and the same "clear failure, not
        # ValueError" care as the network pin above.
        for cmd in self._calls(["semgrep", "cargo-audit"]):
            self.assertIn("-w", cmd)                # clear failure, not ValueError
            i = cmd.index("-w")
            self.assertLess(i + 1, len(cmd), "-w has no value argument")
            self.assertEqual(cmd[i + 1], rt.ADAPTER_EMPTY_CWD)

    def test_gosec_is_the_one_dispatch_that_starts_in_the_mount(self):
        # gosec's argv is the CWD-RELATIVE go package pattern `./...`, so its
        # container has to start at the module root. It is the one documented
        # exception, and it says so EXPLICITLY (`-w /src`) rather than leaning
        # on the image's WORKDIR, so the decision is greppable here rather
        # than implied by a Dockerfile line.
        for cmd in self._calls(["gosec"]):
            self.assertIn("-w", cmd)                # clear failure, not ValueError
            i = cmd.index("-w")
            self.assertLess(i + 1, len(cmd), "-w has no value argument")
            self.assertEqual(cmd[i + 1], "/src")

    def test_nvd_api_key_never_forwarded(self):
        for cmd in self._calls(["dependency-check"],
                               env={"NVD_API_KEY": "dummy"}):
            self.assertNotIn("-e", cmd)
            self.assertNotIn("NVD_API_KEY", cmd)

    def test_online_only_adapters_skipped_offline(self):
        calls = self._calls(["pip-audit", "npm-audit", "cargo-audit"])
        joined = [" ".join(c) for c in calls]
        self.assertEqual(len(calls), 1)
        self.assertIn("cargo-audit", joined[0])

    def test_online_flag_dispatches_online_only_with_network(self):
        # #1645: the online adapter is no longer given Docker's default bridge.
        # With no egress session established (this helper's stub answers the
        # control plane with an empty capture, so the network cannot come up)
        # it is not dispatched at all -- fail closed, never onto the bridge.
        calls = self._calls(["pip-audit"], online=True)
        self.assertEqual([c for c in calls if c[1] == "run" and "-d" not in c[:5]],
                         [])

    def test_roslyn_never_gets_network_even_online(self):
        calls = self._calls(["roslyn-secguard"], online=True)
        self.assertEqual(len(calls), 1)               # #run7 COD-A2C: clear fail if roslyn was skipped
        self.assertIn("--network", calls[0])          # clear failure, not ValueError (#781)
        i = calls[0].index("--network")
        self.assertLess(i + 1, len(calls[0]), "--network has no value argument")
        self.assertEqual(calls[0][i + 1], "none")

    def test_filter_online_helper(self):
        chosen = ["semgrep", "pip-audit", "npm-audit", "gosec"]
        self.assertEqual(rt.filter_online(chosen, online=False),
                         ["semgrep", "gosec"])
        self.assertEqual(rt.filter_online(chosen, online=True), chosen)

    def test_calls_helper_does_not_leak_environ(self):
        # Regression: _calls must restore os.environ after patching.
        original = dict(os.environ)
        self.test_nvd_api_key_never_forwarded()
        self.assertEqual(dict(os.environ), original)


class TestOnlineEgress(unittest.TestCase):
    """#1645 (SEC-C1A): an ONLINE_ONLY adapter reaches its advisory endpoints
    through a per-run proxy on a `--internal` network, never Docker's default
    bridge."""

    def _run(self, tools, stub=None, online=True, raise_on=None):
        stub = stub or _DockerStub()
        runner = stub
        if raise_on:
            def runner(cmd, **kw):                      # noqa: ANN001
                out = stub(cmd, **kw)
                if cmd[-1] == raise_on:
                    raise _Interrupted("the operator stopped the scan")
                return out
        with tempfile.TemporaryDirectory() as d:
            with contextlib.redirect_stderr(io.StringIO()) as err:
                with contextlib.ExitStack() as stack:
                    if raise_on:
                        stack.enter_context(self.assertRaises(_Interrupted))
                    rt.run_tools(d, tools, os.path.join(d, "out"),
                                 runner=runner, online=online, run_id="r1645")
        self.stderr = err.getvalue()
        return stub

    def _names(self, stub):
        create = [c for c in stub.calls if _DockerStub.verb(c) == "network create"]
        self.assertEqual(len(create), 1, stub.calls)
        network = create[0][-1]
        return network, network.replace(rt_egress.NETWORK_PREFIX,
                                        rt_egress.PROXY_PREFIX)

    def test_the_control_plane_sequence_is_create_start_connect_teardown(self):
        stub = self._run(["pip-audit"])
        network, proxy = self._names(stub)
        docker = stub.calls[0][0]
        conf = [c for c in stub.calls if _DockerStub.verb(c) == "run -d"][0]
        mounts = [conf[i + 1] for i, tok in enumerate(conf) if tok == "-v"]
        self.assertEqual([[docker] + c[1:] for c in stub.control()], [
            [docker, "container", "prune", "--force",
             "--filter", "label=%s" % rt_egress.EGRESS_LABEL,
             "--filter", "until=%s" % rt_egress.SWEEP_AGE],
            [docker, "network", "prune", "--force",
             "--filter", "label=%s" % rt_egress.EGRESS_LABEL,
             "--filter", "until=%s" % rt_egress.SWEEP_AGE],
            [docker, "network", "create", "--internal",
             "--label", rt_egress.EGRESS_LABEL, network],
            [docker, "network", "inspect", network],
            [docker, "run", "-d", "--rm", "--name", proxy,
             "--label", rt_egress.EGRESS_LABEL, "--network", "bridge",
             "--cap-drop=ALL", "--security-opt=no-new-privileges",
             "--memory", "256m", "--memory-swap", "256m",
             "--cpus", "1", "--pids-limit", "64",
             "-v", mounts[0], "-v", mounts[1], rt_egress.PROXY_IMAGE,
             "timeout", str(rt.TOOL_TIMEOUT + rt_egress.SIDECAR_SLACK),
             "/usr/bin/tinyproxy", "-d", "-c", "/etc/tinyproxy/tinyproxy.conf"],
            [docker, "network", "connect", "--ip", "172.28.0.2", network, proxy],
            [docker, "inspect", "--format", "{{.State.Running}}", proxy],
            [docker, "rm", "-f", proxy],
            [docker, "network", "rm", network],
        ])

    def test_the_sidecar_config_is_mounted_read_only(self):
        stub = self._run(["pip-audit"])
        conf = [c for c in stub.calls if _DockerStub.verb(c) == "run -d"][0]
        mounts = [conf[i + 1] for i, tok in enumerate(conf) if tok == "-v"]
        self.assertEqual([m.rsplit(":", 2)[1:] for m in mounts],
                         [["/etc/tinyproxy/tinyproxy.conf", "ro"],
                          ["/etc/tinyproxy/filter", "ro"]])

    def test_the_generated_config_is_deleted_when_the_scan_ends(self):
        stub = self._run(["pip-audit"])
        conf = [c for c in stub.calls if _DockerStub.verb(c) == "run -d"][0]
        for token in (conf[i + 1] for i, t in enumerate(conf) if t == "-v"):
            host_path = token.rsplit(":", 2)[0]
            self.assertFalse(os.path.exists(host_path), host_path)

    def test_the_online_adapter_runs_on_the_internal_network(self):
        stub = self._run(["pip-audit"])
        network, _proxy = self._names(stub)
        argv = stub.dispatches()["pip-audit"]
        self.assertEqual(argv[argv.index("--network") + 1], network)
        self.assertNotIn("bridge", argv)

    def test_the_online_adapter_is_pointed_at_the_sidecar(self):
        stub = self._run(["pip-audit"])
        argv = stub.dispatches()["pip-audit"]
        env = [argv[i + 1] for i, tok in enumerate(argv) if tok == "-e"]
        self.assertEqual(env, ["HTTP_PROXY=http://172.28.0.2:8888",
                               "HTTPS_PROXY=http://172.28.0.2:8888",
                               "NO_PROXY="])

    def test_no_other_environment_variable_reaches_a_tool_container(self):
        # The docker construction passed NO host environment into a scanner
        # container before this change, and the three proxy variables above are
        # the first -- set by the controller from the sidecar's address, never
        # read from the host. `-e NAME` (no `=`) is what forwards a host value;
        # every one of ours carries its own.
        stub = self._run(["pip-audit", "npm-audit", "osv-scanner",
                          "semgrep", "roslyn-secguard"])
        allowed = {"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"}
        for name, argv in sorted(stub.dispatches().items()):
            passed = [argv[i + 1] for i, tok in enumerate(argv) if tok == "-e"]
            self.assertTrue(all("=" in v for v in passed), (name, passed))
            self.assertLessEqual({v.split("=", 1)[0] for v in passed}, allowed,
                                 "%s: %s" % (name, passed))
            if name not in ("pip-audit", "npm-audit"):
                self.assertEqual(passed, [], name)

    def test_an_offline_adapter_still_gets_no_network_at_all(self):
        stub = self._run(["pip-audit", "osv-scanner"])
        argv = stub.dispatches()["osv-scanner"]
        self.assertEqual(argv[argv.index("--network") + 1], "none")

    def test_a_run_with_no_online_adapter_touches_no_control_plane(self):
        stub = self._run(["semgrep", "osv-scanner"], online=True)
        self.assertEqual(stub.control(), [])

    def test_teardown_runs_when_an_adapter_dispatch_raises(self):
        stub = self._run(["pip-audit"], raise_on="pip-audit")
        network, proxy = self._names(stub)
        self.assertEqual([c[1:] for c in stub.control()[-2:]],
                         [["rm", "-f", proxy], ["network", "rm", network]])

    def test_a_network_that_cannot_be_created_keeps_the_adapter_off_the_bridge(self):
        stub = self._run(["pip-audit", "osv-scanner"],
                         stub=_DockerStub(fail=["network create"]))
        self.assertNotIn("pip-audit", stub.dispatches())
        self.assertIn("osv-scanner", stub.dispatches())
        self.assertIn("online egress unavailable", self.stderr)
        # The remedy has to be runnable from the line it is printed on: this is
        # the first scan-time image pull panopticon has ever needed, so the
        # likeliest cause of a sidecar that would not start is a host that has
        # never pulled it.
        self.assertIn("docker pull %s" % rt_egress.PROXY_IMAGE, self.stderr)

    def test_a_sidecar_that_did_not_come_up_keeps_the_adapter_off_the_bridge(self):
        stub = self._run(["pip-audit"], stub=_DockerStub(running=b"false\n"))
        self.assertNotIn("pip-audit", stub.dispatches())
        self.assertIn("online egress unavailable", self.stderr)

    def test_a_failed_setup_still_removes_what_it_managed_to_create(self):
        stub = self._run(["pip-audit"], stub=_DockerStub(fail=["network connect"]))
        network, proxy = self._names(stub)
        self.assertEqual([c[1:] for c in stub.control()[-2:]],
                         [["rm", "-f", proxy], ["network", "rm", network]])

    def test_a_stale_sweep_can_never_reach_a_live_run(self):
        # `container prune` removes only STOPPED containers and `network prune`
        # only networks with nothing attached, both scoped to this label and to
        # things older than the sweep age -- so a concurrent scan's sidecar and
        # network are out of reach by construction, not by luck.
        stub = self._run(["pip-audit"])
        for cmd in stub.control()[:2]:
            self.assertIn("prune", cmd)
            self.assertIn("label=%s" % rt_egress.EGRESS_LABEL, cmd)
            self.assertIn("until=%s" % rt_egress.SWEEP_AGE, cmd)
            self.assertNotIn("-f", cmd[2:])

    def test_the_sidecar_cannot_outlive_the_scan_it_serves(self):
        # Started under `timeout`, so a controller that dies before its
        # teardown leaves a proxy that stops on its own rather than one running
        # until the host reboots. The ceiling is the LOOP's worst case -- every
        # selected tool hitting TOOL_TIMEOUT -- so it can never cut a scan that
        # is still running short.
        for tools in (["pip-audit"], ["pip-audit", "semgrep", "osv-scanner"]):
            with self.subTest(tools=tools):
                stub = self._run(tools)
                argv = [c for c in stub.calls
                        if _DockerStub.verb(c) == "run -d"][0]
                self.assertEqual(
                    argv[argv.index("timeout") + 1],
                    str(rt.TOOL_TIMEOUT * len(tools) + rt_egress.SIDECAR_SLACK))


class TestManifestNetworkPosture(unittest.TestCase):
    """#1645 ruling 3: the manifest discloses the egress posture per tool.

    "pip-audit: produced" says a scanner ran. It has never said what that
    scanner could reach while it ran, and until this field there was nowhere
    for the answer to go.
    """

    def _manifest(self, tools, stub=None, online=True):
        stub = stub or _DockerStub()
        with tempfile.TemporaryDirectory() as d:
            with contextlib.redirect_stderr(io.StringIO()):
                written = rt.run_tools(d, tools, os.path.join(d, "out"),
                                       runner=stub, online=online,
                                       run_id="r1645")
                return rt.write_manifest(os.path.join(d, "m.json"), tools,
                                         written)

    def test_an_offline_tool_is_recorded_as_having_no_network(self):
        payload = self._manifest(["semgrep", "osv-scanner"])
        self.assertEqual(payload["network"],
                         {"semgrep": "none", "osv-scanner": "none"})

    def test_an_online_adapter_names_the_allowlist_it_was_confined_to(self):
        payload = self._manifest(["pip-audit"])
        self.assertEqual(payload["network"]["pip-audit"],
                         "proxied:api.osv.dev,files.pythonhosted.org,pypi.org")

    def test_a_refused_adapter_leaves_selected_for_excluded_scope(self):
        # Ruling 2, as the artifact sees it: the adapter did not run, and the
        # manifest says so in the shape the gate already understands. It must
        # leave `selected` at the same time -- `security_gate` rejects a
        # manifest whose `excluded_scope` overlaps `selected`, and an adapter
        # left in both would read as a scanner that was required and missing.
        payload = self._manifest(["pip-audit", "semgrep"],
                                 stub=_DockerStub(fail=["network create"]))
        self.assertEqual(payload["network"]["pip-audit"],
                         "excluded:online egress unavailable")
        self.assertEqual(payload["excluded_scope"], ["pip-audit"])
        self.assertNotIn("pip-audit", payload["selected"])
        self.assertNotIn("pip-audit", payload["missing"])

    def test_a_manifest_written_without_a_scan_claims_no_posture(self):
        # Read off what the runner OBSERVED itself granting, the same
        # construction as `redacted`: the docker-absent path writes a manifest
        # without ever running the loop, and it must claim nothing rather than
        # assert a posture nobody established.
        rt._NETWORK_POSTURE.clear()
        with tempfile.TemporaryDirectory() as d:
            payload = rt.write_manifest(os.path.join(d, "m.json"),
                                        ["semgrep"], [])
        self.assertEqual(payload["network"], {})

    def test_a_caller_may_state_a_posture_the_loop_did_not_observe(self):
        with tempfile.TemporaryDirectory() as d:
            payload = rt.write_manifest(os.path.join(d, "m.json"), ["semgrep"],
                                        [], network={"semgrep": "none"})
        self.assertEqual(payload["network"], {"semgrep": "none"})
