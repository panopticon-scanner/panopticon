"""Containment and environment tests for scripts.run_tools."""
import contextlib
import io
import os
import tempfile
import unittest
from unittest import mock

import scripts.run_tools as rt
import scripts.tool_capture as tc
import scripts.tools_manifest as tm
import scripts.tools.egress as rt_egress

from tests.run_tools_test_helpers import _DockerStub, _FakeResult, _Interrupted


class TestContainment(unittest.TestCase):
    def _calls(self, tools, online=False, env=None, allow_target_build=False):
        calls = []
        fake = _FakeResult(returncode=0, stdout=b'{"runs":[]}', stderr=b'')
        def runner(cmd, **kw):
            calls.append(cmd); return fake
        with tempfile.TemporaryDirectory() as trusted:
            docker = os.path.join(trusted, "docker")
            with open(docker, "w", encoding="utf-8") as fh:
                fh.write("#!/bin/sh\nexit 99\n")
            os.chmod(docker, 0o700)
            child_env = dict(env or {})
            child_env["PATH"] = trusted
            with mock.patch.dict(os.environ, child_env, clear=True), \
                    tempfile.TemporaryDirectory() as d:
                rt.run_tools(d, tools, os.path.join(d, "out"), runner=runner,
                             online=online, allow_target_build=allow_target_build)
        return calls

    def test_every_dispatch_has_network_none(self):
        calls = self._calls(["semgrep", "cargo-audit"])
        self.assertEqual(len(calls), 2, "both selected scanners must dispatch")
        for cmd in calls:
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
        calls = self._calls(["semgrep", "cargo-audit"])
        self.assertEqual(len(calls), 2, "both selected scanners must dispatch")
        for cmd in calls:
            self.assertIn("-w", cmd)                # clear failure, not ValueError
            i = cmd.index("-w")
            self.assertLess(i + 1, len(cmd), "-w has no value argument")
            self.assertEqual(cmd[i + 1], rt.ADAPTER_EMPTY_CWD)

    def test_the_two_mount_cwd_dispatches_say_so_explicitly(self):
        # Two scanners take the mount as their working directory because for
        # them the cwd is a SCAN INPUT, not a config surface: gosec's argv is
        # the CWD-RELATIVE go package pattern `./...`, and eslint's cwd is
        # its flat config's base path (a scratch cwd scoped the whole target
        # out -- exit 2, no output, measured on eslint 10.9.0). Both say so
        # EXPLICITLY (`-w /src`) rather than leaning on the image's WORKDIR,
        # so the decision is greppable here rather than implied by a
        # Dockerfile line. Named literally, not read off the tuple, so this
        # cannot rubber-stamp a third entry.
        for tool in ("gosec", "eslint-security"):
            calls = self._calls([tool])
            self.assertEqual(len(calls), 1, "%s must dispatch" % tool)
            for cmd in calls:
                self.assertIn("-w", cmd)            # clear failure, not ValueError
                i = cmd.index("-w")
                self.assertLess(i + 1, len(cmd), "-w has no value argument")
                self.assertEqual(cmd[i + 1], "/src", "%s: wrong cwd" % tool)

    def test_exactly_two_tools_keep_the_target_as_their_cwd(self):
        # #1877 I3: the dispatcher's exception and the adapter-side one in
        # tests/tools/test_adapter_cwd_confinement.py::ALLOWED_TARGET_CWD now
        # name gosec INDEPENDENTLY -- the old `_is_inside` imported
        # run_tools' tuple precisely so the two could not drift. Without this
        # pin, adding a second name here would put another container back
        # inside the mount with a green suite, because the two tests above
        # iterate fixed tool lists. A new entry must be argued for in BOTH
        # places, with its own reason.
        self.assertEqual(tuple(rt.DISPATCH_KEEPS_TARGET_CWD),
                         ("gosec", "eslint-security"))

    def test_nvd_api_key_never_forwarded(self):
        calls = self._calls(["dependency-check"],
                            env={"NVD_API_KEY": "dummy"})
        self.assertEqual(len(calls), 1, "dependency-check must dispatch")
        for cmd in calls:
            self.assertNotIn("-e", cmd)
            self.assertNotIn("NVD_API_KEY", cmd)

    def test_empty_dispatch_cannot_pass_containment_checks(self):
        with mock.patch.object(rt, "run_tools", return_value=[]):
            for check in (self.test_every_dispatch_has_network_none,
                          self.test_every_dispatch_has_an_empty_working_directory,
                          self.test_the_two_mount_cwd_dispatches_say_so_explicitly,
                          self.test_nvd_api_key_never_forwarded):
                with self.subTest(check=check.__name__), self.assertRaises(AssertionError):
                    check()

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
        # #3265: the opt-in path -- without the flag roslyn is never dispatched.
        calls = self._calls(["roslyn-secguard"], online=True, allow_target_build=True)
        self.assertEqual(len(calls), 1)               # #run7 COD-A2C: clear fail if roslyn was skipped
        self.assertIn("--network", calls[0])          # clear failure, not ValueError (#781)
        i = calls[0].index("--network")
        self.assertLess(i + 1, len(calls[0]), "--network has no value argument")
        self.assertEqual(calls[0][i + 1], "none")

    def test_roslyn_is_never_dispatched_without_the_opt_in(self):
        # #3265: run_tools() itself withholds it, not only the CLI in front of it.
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual([], self._calls(["roslyn-secguard"], online=True))

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


class TestScannerContainerLifecycle(unittest.TestCase):
    """#3583: scanner containers belong to, and are reaped by, one run."""

    RUN_ID = "run-3583"
    ROLE_LABEL = "panopticon.role=scanner"
    RUN_LABEL = "panopticon.run=%s" % RUN_ID
    ORPHAN = "a" * 12

    @staticmethod
    def _ps(docker):
        return [docker, "ps", "-aq",
                "--filter", "label=panopticon.role=scanner",
                "--filter", "label=panopticon.run=run-3583"]

    def _run(self, stub, tools=("semgrep", "osv-scanner"), interrupt=None,
             run_id=RUN_ID):
        runner = stub
        if interrupt is not None:
            def runner(cmd, **kw):
                if _DockerStub.verb(cmd) == "run":
                    stub.calls.append(list(cmd))
                    raise interrupt("fixture interrupt")
                return stub(cmd, **kw)

        with tempfile.TemporaryDirectory() as trusted, \
                tempfile.TemporaryDirectory() as target:
            docker = os.path.join(trusted, "docker")
            with open(docker, "w", encoding="utf-8") as fh:
                fh.write("#!/bin/sh\nexit 99\n")
            os.chmod(docker, 0o700)
            with mock.patch.dict(os.environ, {"PATH": trusted}, clear=True), \
                    contextlib.redirect_stderr(io.StringIO()) as err:
                if interrupt is None:
                    rt.run_tools(target, list(tools), os.path.join(target, "out"),
                                 runner=runner, run_id=run_id)
                else:
                    with self.assertRaises(interrupt):
                        rt.run_tools(target, list(tools), os.path.join(target, "out"),
                                     runner=runner, run_id=run_id)
        self.stderr = err.getvalue()
        return os.path.realpath(docker)

    def test_every_scanner_launch_has_role_and_run_labels(self):
        stub = _DockerStub()
        self._run(stub)
        dispatches = [cmd for cmd in stub.calls if _DockerStub.verb(cmd) == "run"]
        self.assertEqual(len(dispatches), 2)
        for argv in dispatches:
            labels = [argv[index + 1] for index, token in enumerate(argv)
                      if token == "--label"]
            self.assertIn(self.ROLE_LABEL, labels, argv)
            self.assertIn(self.RUN_LABEL, labels, argv)

    def test_a_direct_scan_without_a_manifest_run_id_is_still_labelled(self):
        stub = _DockerStub()
        self._run(stub, tools=("semgrep",), run_id=None)
        launches = [cmd for cmd in stub.calls if _DockerStub.verb(cmd) == "run"]
        self.assertEqual(len(launches), 1)
        argv = launches[0]
        labels = [argv[index + 1] for index, token in enumerate(argv)
                  if token == "--label"]
        self.assertIn(self.ROLE_LABEL, labels)
        generated = [label for label in labels if label.startswith("panopticon.run=direct-")]
        self.assertEqual(len(generated), 1, labels)
        self.assertNotEqual(generated[0], "panopticon.run=direct-")

    def test_resume_reaps_only_this_runs_labelled_scanners_before_dispatch(self):
        stub = _DockerStub(listings=[(self.ORPHAN,)])
        docker = self._run(stub, tools=("semgrep",))
        self.assertEqual(stub.calls[:2], [
            self._ps(docker),
            [docker, "rm", "-f", self.ORPHAN],
        ])
        dispatch_index = next(index for index, cmd in enumerate(stub.calls)
                              if _DockerStub.verb(cmd) == "run")
        self.assertGreater(dispatch_index, 1)
        self.assertIn("reaped 1 scanner container", self.stderr)

    def test_sigint_and_sigterm_reap_the_run_before_the_interrupt_escapes(self):
        for interrupt in (KeyboardInterrupt, rt.procgroup.Terminated):
            with self.subTest(interrupt=interrupt.__name__):
                stub = _DockerStub(listings=[(), (self.ORPHAN,)])
                docker = self._run(stub, tools=("semgrep",), interrupt=interrupt)
                self.assertEqual(stub.calls[-2:], [
                    self._ps(docker),
                    [docker, "rm", "-f", self.ORPHAN],
                ])
                self.assertIn("reaped 1 scanner container", self.stderr)

    def test_unverified_cleanup_never_redispatches_a_scanner(self):
        cases = {
            "lookup failed": _DockerStub(fail=["ps"]),
            "removal failed": _DockerStub(
                fail=["rm"], listings=[(self.ORPHAN,)]),
            "invalid id": _DockerStub(listings=[("--all",)]),
        }
        for label, stub in cases.items():
            with self.subTest(case=label):
                self._run(stub, tools=("semgrep",))
                self.assertEqual(
                    [cmd for cmd in stub.calls if _DockerStub.verb(cmd) == "run"],
                    [])
                self.assertIn("cleanup could not be verified", self.stderr)


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
            [docker, "ps", "-aq",
             "--filter", "label=%s" % rt.SCANNER_LABEL,
             "--filter", "label=%s=r1645" % rt.SCANNER_RUN_LABEL],
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
             "timeout", str(tc.TOOL_TIMEOUT + rt_egress.SIDECAR_SLACK),
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
        # #3583's scanner-orphan lookup is the one control call every persisted
        # run makes. No egress network/sidecar control call is introduced.
        self.assertEqual([_DockerStub.verb(cmd) for cmd in stub.control()], ["ps"])
        self.assertNotIn(rt_egress.EGRESS_LABEL, " ".join(stub.control()[0]))

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
        prune = [cmd for cmd in stub.control() if "prune" in cmd]
        self.assertEqual(len(prune), 2)
        for cmd in prune:
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
                    str(tc.TOOL_TIMEOUT * len(tools) + rt_egress.SIDECAR_SLACK))


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
                return tm.write_manifest(os.path.join(d, "m.json"), tools,
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
        tm._NETWORK_POSTURE.clear()
        with tempfile.TemporaryDirectory() as d:
            payload = tm.write_manifest(os.path.join(d, "m.json"),
                                        ["semgrep"], [])
        self.assertEqual(payload["network"], {})

    def test_a_caller_may_state_a_posture_the_loop_did_not_observe(self):
        with tempfile.TemporaryDirectory() as d:
            payload = tm.write_manifest(os.path.join(d, "m.json"), ["semgrep"],
                                        [], network={"semgrep": "none"})
        self.assertEqual(payload["network"], {"semgrep": "none"})
