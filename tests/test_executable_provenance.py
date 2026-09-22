"""Executable provenance at the reviewed-tree process boundaries."""
import contextlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import scripts.diff_map as diff_map
import scripts.executable as executable
import scripts.phases.runio as runio
import scripts.run_tools as run_tools
import scripts.runners.base as runner_base
from conftest import REAL_DOCKER_AVAILABLE


def _program(path, body):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("#!/bin/sh\n" + body)
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
    return path


def _native_programs(compiler, trusted, target):
    """Build a native CLI and constructor library for this platform."""
    cli_source = os.path.join(trusted, "hostcli.c")
    library_source = os.path.join(target, "startup.c")
    cli = os.path.join(trusted, "hostcli")
    if sys.platform == "darwin":
        loader_var = "DYLD_INSERT_LIBRARIES"
        library = os.path.join(target, "startup.dylib")
        library_flags = ["-dynamiclib"]
    elif sys.platform.startswith("linux"):
        loader_var = "LD_PRELOAD"
        library = os.path.join(target, "startup.so")
        library_flags = ["-shared", "-fPIC"]
    else:
        raise unittest.SkipTest("native loader regression supports macOS and Linux")

    with open(cli_source, "w", encoding="utf-8") as fh:
        fh.write(
            "#include <stdio.h>\n"
            "#include <stdlib.h>\n"
            "int main(void) {\n"
            "  const char *auth = getenv(\"HOST_TOKEN\");\n"
            "  const char *config = getenv(\"HOST_CONFIG\");\n"
            "  const char *loader = getenv(\"%s\");\n"
            "  printf(\"NATIVE auth=%%s config=%%s loader=%%s\\n\",\n"
            "         auth ? auth : \"<unset>\", config ? config : \"<unset>\",\n"
            "         loader ? loader : \"<unset>\");\n"
            "  return 0;\n"
            "}\n" % loader_var)
    with open(library_source, "w", encoding="utf-8") as fh:
        fh.write(
            "#include <stdio.h>\n"
            "__attribute__((constructor)) static void startup(void) {\n"
            "  fputs(\"LOADER_STARTUP\\n\", stdout);\n"
            "  fflush(stdout);\n"
            "}\n")
    subprocess.run([compiler, "-o", cli, cli_source], check=True,
                   capture_output=True, text=True)
    subprocess.run([compiler, *library_flags, "-o", library, library_source],
                   check=True, capture_output=True, text=True)
    return cli, loader_var, library


class TestTrustedResolver(unittest.TestCase):
    def test_startup_environment_policy_removes_reserved_namespaces_only(self):
        supplied = {
            "PATH": "/trusted/bin",
            "BASH_ENV": "startup.sh",
            "ENV": "shell-startup.sh",
            "LD_PRELOAD": "startup.so",
            "LD_LIBRARY_PATH": "/reviewed/lib",
            "LD_AUDIT": "audit.so",
            "DYLD_INSERT_LIBRARIES": "startup.dylib",
            "DYLD_LIBRARY_PATH": "/reviewed/lib",
            "DYLD_FRAMEWORK_PATH": "/reviewed/frameworks",
            "HOST_LD_LIBRARY_PATH": "kept",
            "MY_DYLD_FRAMEWORK_PATH": "kept-too",
            "HOST_TOKEN": "auth-kept",
            "HOST_CONFIG": "config-kept",
        }
        original = dict(supplied)

        clean = executable.sanitize_startup_environment(supplied)

        self.assertEqual(supplied, original)
        for name in ("BASH_ENV", "ENV", "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
                     "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
                     "DYLD_FRAMEWORK_PATH"):
            self.assertNotIn(name, clean)
        self.assertEqual(clean["HOST_LD_LIBRARY_PATH"], "kept")
        self.assertEqual(clean["MY_DYLD_FRAMEWORK_PATH"], "kept-too")
        self.assertEqual(clean["HOST_TOKEN"], "auth-kept")
        self.assertEqual(clean["HOST_CONFIG"], "config-kept")

    def test_symlinked_directory_and_candidate_into_target_are_rejected(self):
        with tempfile.TemporaryDirectory() as parent:
            target = os.path.join(parent, "target")
            external = os.path.join(parent, "external")
            poison = os.path.join(parent, "poison")
            os.makedirs(target)
            marker = _program(os.path.join(target, "git"), "exit 99\n")
            os.makedirs(external)
            os.makedirs(poison)
            os.symlink(target, os.path.join(parent, "target-link"))
            os.symlink(marker, os.path.join(poison, "git"))
            trusted = _program(os.path.join(external, "git"), "exit 0\n")
            path = os.pathsep.join([os.path.join(parent, "target-link"), poison,
                                    external])
            got = executable.resolve("git", target, path)
            self.assertEqual(got.path, os.path.realpath(trusted))
            self.assertNotIn(os.path.realpath(target), got.path_env.split(os.pathsep))
            self.assertNotIn(os.path.realpath(poison), got.path_env.split(os.pathsep))

    def test_case_alias_of_target_is_rejected_when_filesystem_aliases_case(self):
        with tempfile.TemporaryDirectory() as parent:
            target = os.path.join(parent, "target")
            alias = os.path.join(parent, "TARGET")
            trusted = os.path.join(parent, "trusted")
            os.makedirs(target)
            target_cli = _program(os.path.join(target, "probe-cli"), "exit 99\n")
            trusted_cli = _program(os.path.join(trusted, "probe-cli"), "exit 0\n")
            if not os.path.exists(alias) or not os.path.samefile(alias, target):
                self.skipTest("filesystem distinguishes path case")

            got = executable.resolve(
                "probe-cli", target, os.pathsep.join([alias, trusted]))
            self.assertEqual(got.path, os.path.realpath(trusted_cli))
            with self.assertRaises(executable.ExecutableResolutionError):
                executable.resolve(os.path.join(alias, "probe-cli"), target, trusted)
            self.assertTrue(os.path.isfile(target_cli))


class TestHostCliBoundary(unittest.TestCase):
    def test_review_root_path_entries_and_relative_entries_cannot_supply_cli(self):
        with tempfile.TemporaryDirectory() as target, tempfile.TemporaryDirectory() as trusted, \
                tempfile.TemporaryDirectory() as scratch:
            marker = os.path.join(target, "host-ran")
            _program(os.path.join(target, "hostcli"), "printf bad > %s\n" % marker)
            _program(os.path.join(target, "bin", "hostcli"), "printf bad > %s\n" % marker)
            good = _program(os.path.join(trusted, "hostcli"),
                            "printf '%s' \"$PATH\"\n" % "%s")
            runner = runner_base.HostRunner()
            runner.review_root = target
            env = {"PATH": os.pathsep.join(["", ".", os.path.join(target, "bin"),
                                             trusted])}
            got = runner.launch(["hostcli"], cwd=scratch, env=env)
            self.assertEqual(got.returncode, 0)
            self.assertFalse(os.path.exists(marker))
            self.assertTrue(os.path.isfile(good))
            self.assertEqual(got.args[0], "hostcli")
            self.assertNotIn(os.path.realpath(target), got.stdout.split(os.pathsep))
            self.assertTrue(all(os.path.isabs(p) for p in got.stdout.split(os.pathsep)))

    def test_missing_trusted_cli_fails_closed_before_a_target_cli_runs(self):
        with tempfile.TemporaryDirectory() as target:
            marker = os.path.join(target, "host-ran")
            _program(os.path.join(target, "hostcli"), "printf bad > %s\n" % marker)
            runner = runner_base.HostRunner()
            runner.review_root = target
            with self.assertRaisesRegex(OSError, "trusted PATH"):
                runner.launch(["hostcli"], cwd=target, env={"PATH": "."})
            self.assertFalse(os.path.exists(marker))

    def test_probe_before_prepare_uses_its_cwd_as_the_review_boundary(self):
        with tempfile.TemporaryDirectory() as target, tempfile.TemporaryDirectory() as trusted:
            marker = os.path.join(target, "host-ran")
            _program(os.path.join(target, "hostcli"), "printf bad > %s\n" % marker)
            _program(os.path.join(trusted, "hostcli"), "printf trusted\n")
            runner = runner_base.HostRunner()  # no prepare(), no review_root binding
            got = runner.launch(["hostcli"], cwd=target,
                                env={"PATH": os.pathsep.join([".", trusted])})
            self.assertEqual(got.stdout, "trusted")
            self.assertFalse(os.path.exists(marker))

    def test_python_and_node_startup_injection_is_removed_but_auth_is_kept(self):
        with tempfile.TemporaryDirectory() as target, tempfile.TemporaryDirectory() as trusted, \
                tempfile.TemporaryDirectory() as scratch:
            marker = os.path.join(target, "startup-ran")
            with open(os.path.join(target, "sitecustomize.py"), "w", encoding="utf-8") as fh:
                fh.write("open(%r, 'w').write('python')\n" % marker)
            with open(os.path.join(target, "startup.cjs"), "w", encoding="utf-8") as fh:
                fh.write("require('fs').writeFileSync(%r, 'node')\n" % marker)
            cli = os.path.join(trusted, "hostcli")
            with open(cli, "w", encoding="utf-8") as fh:
                fh.write("#!%s\nimport os\nprint('trusted:' + os.environ['HOST_TOKEN'])\n"
                         % os.path.realpath(sys.executable))
            os.chmod(cli, 0o700)
            runner = runner_base.HostRunner()
            runner.review_root = target
            for pythonpath, cwd in ((".", target), (target, scratch)):
                with self.subTest(pythonpath=pythonpath):
                    env = {"PATH": trusted, "PYTHONPATH": pythonpath,
                           "PYTHONHOME": target, "PYTHONINSPECT": "1",
                           "NODE_OPTIONS": "--require ./startup.cjs",
                           "NODE_PATH": target, "HOST_TOKEN": "kept"}
                    got = runner.launch(["hostcli"], cwd=cwd, env=env)
                    self.assertEqual(got.returncode, 0, got.stderr)
                    self.assertEqual(got.stdout, "trusted:kept\n")
                    self.assertFalse(os.path.exists(marker))

    def test_bash_startup_injection_is_removed_without_mutating_environment(self):
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("bash is unavailable")
        with tempfile.TemporaryDirectory() as target, tempfile.TemporaryDirectory() as trusted:
            startup = os.path.join(target, "startup.sh")
            with open(startup, "w", encoding="utf-8") as fh:
                fh.write("printf 'SHELL_STARTUP\\n'\n")
            cli = os.path.join(trusted, "hostcli")
            with open(cli, "w", encoding="utf-8") as fh:
                fh.write(
                    "#!%s\n"
                    "printf 'WRAPPER auth=%%s config=%%s bash_env=%%s env=%%s\\n' "
                    "\"$HOST_TOKEN\" \"$HOST_CONFIG\" "
                    "\"${BASH_ENV-<unset>}\" \"${ENV-<unset>}\"\n"
                    % os.path.realpath(bash))
            os.chmod(cli, 0o700)
            runner = runner_base.HostRunner()
            runner.review_root = target
            cases = (
                ("control", {}),
                ("relative-bash-env", {"BASH_ENV": "startup.sh"}),
                ("absolute-bash-env", {"BASH_ENV": startup}),
                ("env-only", {"ENV": "startup.sh"}),
            )
            with mock.patch.dict(os.environ, {"BASH_ENV": "caller-startup",
                                               "CALLER_STATE": "kept"}, clear=False):
                caller_before = dict(os.environ)
                for name, startup_env in cases:
                    with self.subTest(name=name):
                        env = {"PATH": trusted, "HOST_TOKEN": "auth-kept",
                               "HOST_CONFIG": "config-kept", **startup_env}
                        supplied_before = dict(env)
                        got = runner.launch(["hostcli"], cwd=target, env=env)
                        self.assertEqual(got.returncode, 0, got.stderr)
                        self.assertEqual(
                            got.stdout,
                            "WRAPPER auth=auth-kept config=config-kept "
                            "bash_env=<unset> env=<unset>\n")
                        self.assertNotIn("SHELL_STARTUP", got.stdout)
                        self.assertEqual(env, supplied_before)
                        self.assertEqual(dict(os.environ), caller_before)

    def test_native_loader_injection_is_removed_without_mutating_environment(self):
        compiler = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
        if not compiler:
            self.skipTest("no C compiler is available")
        with tempfile.TemporaryDirectory() as target, tempfile.TemporaryDirectory() as trusted, \
                tempfile.TemporaryDirectory() as scratch:
            _cli, loader_var, library = _native_programs(compiler, trusted, target)
            runner = runner_base.HostRunner()
            runner.review_root = target
            env = {"PATH": trusted, loader_var: library, "HOST_TOKEN": "auth-kept",
                   "HOST_CONFIG": "config-kept"}
            supplied_before = dict(env)
            with mock.patch.dict(os.environ, {loader_var: "caller-library",
                                               "CALLER_STATE": "kept"}, clear=False):
                caller_before = dict(os.environ)
                got = runner.launch(["hostcli"], cwd=scratch, env=env)
                self.assertEqual(got.returncode, 0, got.stderr)
                self.assertEqual(
                    got.stdout,
                    "NATIVE auth=auth-kept config=config-kept loader=<unset>\n")
                self.assertNotIn("LOADER_STARTUP", got.stdout)
                self.assertEqual(env, supplied_before)
                self.assertEqual(dict(os.environ), caller_before)


class TestManifestGitBoundary(unittest.TestCase):
    @staticmethod
    def _git(root, *args):
        subprocess.run([shutil.which("git"), "-C", root, *args], check=True,
                       capture_output=True)

    def test_target_git_cannot_forge_the_manifest_trust_decision(self):
        git = shutil.which("git")
        self.assertTrue(git)
        with tempfile.TemporaryDirectory() as target:
            self._git(target, "init", "-q")
            manifest = os.path.join(target, "run-manifest.json")
            with open(manifest, "w", encoding="utf-8") as fh:
                fh.write("{}")
            self._git(target, "add", "run-manifest.json")
            marker = os.path.join(target, "git-ran")
            _program(os.path.join(target, "git"),
                     "printf forged > %s\nexit 0\n" % marker)
            hostile = os.pathsep.join(["", ".", target, os.path.dirname(git)])
            old_cwd = os.getcwd()
            try:
                os.chdir(target)
                with mock.patch.dict(os.environ, {"PATH": hostile}, clear=False):
                    self.assertTrue(runio._manifest_committed(target, manifest))
            finally:
                os.chdir(old_cwd)
            self.assertFalse(os.path.exists(marker))

    def test_manifest_check_refuses_when_only_target_git_exists(self):
        with tempfile.TemporaryDirectory() as target:
            manifest = os.path.join(target, "run-manifest.json")
            with open(manifest, "w", encoding="utf-8") as fh:
                fh.write("{}")
            marker = os.path.join(target, "git-ran")
            _program(os.path.join(target, "git"),
                     "printf forged > %s\nexit 1\n" % marker)
            with mock.patch.dict(os.environ, {"PATH": target}, clear=False):
                with self.assertRaisesRegex(runio.DriverError, "trusted git"):
                    runio._manifest_committed(target, manifest)
            self.assertFalse(os.path.exists(marker))


class TestDiffGitBoundary(unittest.TestCase):
    @staticmethod
    def _git(root, *args):
        subprocess.run([shutil.which("git"), "-C", root, *args], check=True,
                       capture_output=True)

    def test_hunk_map_ignores_target_git_and_uses_external_git(self):
        git = shutil.which("git")
        self.assertTrue(git)
        with tempfile.TemporaryDirectory() as target:
            self._git(target, "init", "-q")
            self._git(target, "config", "user.email", "t@example.com")
            self._git(target, "config", "user.name", "T")
            with open(os.path.join(target, "a.py"), "w", encoding="utf-8") as fh:
                fh.write("old\n")
            self._git(target, "add", "a.py")
            self._git(target, "commit", "-qm", "base")
            self._git(target, "branch", "base")
            with open(os.path.join(target, "a.py"), "w", encoding="utf-8") as fh:
                fh.write("new\n")
            marker = os.path.join(target, "git-ran")
            _program(os.path.join(target, "git"),
                     "printf forged > %s\nexit 0\n" % marker)
            path = os.pathsep.join([target, os.path.dirname(git)])
            with mock.patch.dict(os.environ, {"PATH": path}, clear=False):
                mapped = diff_map.hunk_map(target, "base")
            self.assertIn("a.py", mapped)
            self.assertFalse(os.path.exists(marker))

    def test_hunk_map_fails_loud_when_only_target_git_exists(self):
        with tempfile.TemporaryDirectory() as target:
            marker = os.path.join(target, "git-ran")
            _program(os.path.join(target, "git"),
                     "printf forged > %s\nexit 0\n" % marker)
            with mock.patch.dict(os.environ, {"PATH": target}, clear=False):
                with self.assertRaisesRegex(diff_map.DiffMapError, "trusted PATH"):
                    diff_map.hunk_map(target, "main")
            self.assertFalse(os.path.exists(marker))


class TestDockerBoundary(unittest.TestCase):
    def test_target_docker_is_skipped_and_child_path_is_sanitized(self):
        calls = []

        class Result:
            returncode, stdout, stderr = 0, b'{"runs":[]}', b""

        def runner(cmd, **kwargs):
            calls.append((list(cmd), dict(kwargs)))
            return Result()

        with tempfile.TemporaryDirectory() as parent:
            target = os.path.join(parent, "target")
            trusted = os.path.join(parent, "trusted")
            os.makedirs(target)
            marker = os.path.join(target, "docker-ran")
            _program(os.path.join(target, "docker"), "printf bad > %s\n" % marker)
            good = _program(os.path.join(trusted, "docker"), "exit 99\n")
            out = os.path.join(parent, "out")
            hostile = os.pathsep.join(["", ".", target, trusted])
            with mock.patch.dict(os.environ, {
                    "PATH": hostile, "PYTHONPATH": target,
                    "NODE_OPTIONS": "--require ./startup.cjs"}, clear=False):
                written = run_tools.run_tools(target, ["semgrep"], out, runner=runner,
                                              venv_dirs=[])
            self.assertEqual(len(written), 1)
            self.assertFalse(os.path.exists(marker))
            cmd, kwargs = calls[0]
            self.assertEqual(os.path.realpath(cmd[0]), os.path.realpath(good))
            child_path = kwargs["env"]["PATH"].split(os.pathsep)
            self.assertTrue(all(os.path.isabs(p) for p in child_path))
            self.assertNotIn(os.path.realpath(target), child_path)
            self.assertNotIn("PYTHONPATH", kwargs["env"])
            self.assertNotIn("NODE_OPTIONS", kwargs["env"])

    def test_symlinked_docker_with_different_target_name_keeps_cid_watchdog_identity(self):
        calls = []
        killed = []

        class Proc:
            def __init__(self):
                self.stdout = io.BytesIO(b'{"runs":[]}')
                self.stderr = io.BytesIO(b'')

            def wait(self):
                return 0

            def poll(self):
                return None

            def kill(self):
                killed.append("client")

        def runner(cmd, **kwargs):
            calls.append((list(cmd), dict(kwargs)))
            cid_index = cmd.index("--cidfile") + 1
            with open(cmd[cid_index], "w", encoding="utf-8") as fh:
                fh.write("container-id\n")
            return Proc()

        def docker_control(cmd, **kwargs):
            killed.append((list(cmd), dict(kwargs)))
            return subprocess.CompletedProcess(cmd, 0, stdout=b"", stderr=b"")

        with tempfile.TemporaryDirectory() as parent:
            target = os.path.join(parent, "target")
            trusted = os.path.join(parent, "trusted")
            os.makedirs(target)
            real = _program(os.path.join(trusted, "docker.real"), "exit 99\n")
            os.symlink("docker.real", os.path.join(trusted, "docker"))
            with mock.patch.dict(os.environ, {"PATH": trusted}, clear=False), \
                    mock.patch.object(run_tools.subprocess, "run",
                                      side_effect=docker_control):
                written = run_tools.run_tools(
                    target, ["semgrep"], os.path.join(parent, "out"),
                    runner=runner, venv_dirs=[])

        self.assertEqual(1, len(written))
        self.assertEqual(os.path.realpath(real), calls[0][0][0])
        self.assertEqual("--cidfile", calls[0][0][2])
        kill_calls = [item for item in killed if isinstance(item, tuple)]
        self.assertEqual([os.path.realpath(real), "kill", "container-id"],
                         kill_calls[0][0])
        self.assertEqual(calls[0][1]["env"], kill_calls[0][1]["env"])

    def test_docker_context_does_not_classify_an_unrelated_run_argv(self):
        calls = []

        class Result:
            returncode, stdout, stderr = 0, b'{"runs":[]}', b""

        with tempfile.TemporaryDirectory() as parent:
            docker = _program(os.path.join(parent, "docker.real"), "exit 0\n")
            other = _program(os.path.join(parent, "other"), "exit 0\n")
            context = run_tools._DockerContext(docker, {"PATH": parent})

            def runner(cmd, **kwargs):
                calls.append(list(cmd))
                return Result()

            run_tools._capture_run(
                "tool", "semgrep", [other, "run", "--rm"],
                os.path.join(parent, "out.sarif"), runner,
                docker_context=context)
        self.assertNotIn("--cidfile", calls[0])

    def test_main_probe_cannot_execute_target_docker(self):
        with tempfile.TemporaryDirectory() as target:
            marker = os.path.join(target, "docker-ran")
            _program(os.path.join(target, "docker"),
                     "printf forged > %s\nexit 0\n" % marker)
            with mock.patch.dict(os.environ, {"PATH": os.pathsep.join(["", ".", target])},
                                 clear=False), \
                    mock.patch.object(run_tools, "docker_available",
                                      new=REAL_DOCKER_AVAILABLE), \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(run_tools.main(["--target", target, "--tools", "semgrep",
                                                 "--out", os.path.join(target, "out")]), 0)
            self.assertFalse(os.path.exists(marker))

    def test_missing_external_docker_fails_before_the_injected_runner(self):
        called = []
        with tempfile.TemporaryDirectory() as target:
            _program(os.path.join(target, "docker"), "exit 0\n")
            with mock.patch.dict(os.environ, {"PATH": target}, clear=False):
                with self.assertRaisesRegex(executable.ExecutableResolutionError,
                                            "trusted PATH"):
                    run_tools.run_tools(
                        target, ["semgrep"], os.path.join(target, "out"),
                        runner=lambda *args, **kwargs: called.append((args, kwargs)),
                        venv_dirs=[])
        self.assertEqual(called, [])

    def test_egress_and_teardown_reuse_absolute_docker_and_sanitized_path(self):
        calls = []

        class Result:
            def __init__(self, stdout=b""):
                self.returncode, self.stdout, self.stderr = 0, stdout, b""

        def runner(cmd, **kwargs):
            calls.append((list(cmd), dict(kwargs)))
            if list(cmd[1:3]) == ["network", "inspect"]:
                body = [{"IPAM": {"Config": [
                    {"Subnet": "172.30.0.0/16", "Gateway": "172.30.0.1"}]}}]
                return Result(json.dumps(body).encode())
            if cmd[1] == "inspect":
                return Result(b"true\n")
            return Result(b'{"dependencies":[]}')

        with tempfile.TemporaryDirectory() as parent:
            target = os.path.join(parent, "target")
            trusted = os.path.join(parent, "trusted")
            os.makedirs(target)
            good = _program(os.path.join(trusted, "docker"), "exit 99\n")
            with mock.patch.dict(os.environ, {
                    "PATH": os.pathsep.join([".", target, trusted])}, clear=False):
                run_tools.run_tools(target, ["pip-audit"], os.path.join(parent, "out"),
                                    runner=runner, online=True, venv_dirs=[], run_id="r")
        self.assertGreater(len(calls), 4)
        for cmd, kwargs in calls:
            self.assertEqual(cmd[0], os.path.realpath(good))
            self.assertEqual(kwargs["env"]["PATH"], os.path.realpath(trusted))
        self.assertTrue(any(cmd[1:3] == ["rm", "-f"] for cmd, _kwargs in calls))


if __name__ == "__main__":
    unittest.main()
