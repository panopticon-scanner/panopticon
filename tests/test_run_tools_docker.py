"""Docker availability probe tests for scripts.run_tools."""
import contextlib
import hashlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

import scripts.run_tools as rt
import scripts.tools_image as tools_image

from tests.run_tools_test_helpers import FOUND_IMAGE, FOUND_IMAGE_ID, INSPECT_OK, _FakeResult

SCRIPTS_DIR = os.path.dirname(os.path.abspath(rt.__file__))


# #3270 (D2): the halt is asserted by BEHAVIOUR -- a ValueError carrying the
# fixed sentence -- so on a build without it the test fails on what happened.
HALTS = (r"inside the target; remove it \(deactivate the target's virtualenv or direnv\) "
         r"and re-run$")


class TestRunTools(unittest.TestCase):
    def test_docker_unavailable_when_runner_fails(self):
        def runner(cmd, **kw):
            raise FileNotFoundError("docker not installed")
        self.assertFalse(rt.docker_available(runner=runner))

    def test_docker_available_when_inspect_ok(self):
        found = rt.docker_available(
            runner=lambda cmd, **kw: _FakeResult(returncode=0, stdout=INSPECT_OK))
        self.assertEqual(FOUND_IMAGE_ID, found["id"])     # #3270: the identity, not True

    def test_docker_unavailable_when_image_missing(self):
        # Docker is installed (no exception) but `image inspect` returns non-zero
        # because the panopticon-tools image isn't built -> unavailable.
        self.assertFalse(rt.docker_available(runner=lambda cmd, **kw: _FakeResult(returncode=1)))

    def test_docker_available_probe_carries_timeout(self):
        # #1112: the gating probe must be bounded so a wedged daemon can't hang.
        seen = {}
        def runner(cmd, **kw):
            if "inspect" in cmd:
                seen.update(kw)
            return _FakeResult(returncode=0, stdout=INSPECT_OK)
        rt.docker_available(runner=runner)
        self.assertEqual(seen.get("timeout"), rt.DOCKER_PROBE_TIMEOUT)

    def test_docker_unavailable_when_probe_times_out(self):
        def runner(cmd, **kw):
            raise rt.subprocess.TimeoutExpired(cmd, kw.get("timeout"))
        self.assertFalse(rt.docker_available(runner=runner))  # bounded, no hang

    def test_docker_probe_fault_is_diagnosed_not_silent(self):
        # OPS-E1A: a real fault (wedged daemon, permission denial) must not be
        # swallowed silently -- print WHY on stderr before returning False, so the
        # whole tool-scan phase no-op is diagnosable instead of masquerading as
        # "no docker here". The genuinely-absent binary (FileNotFoundError) stays quiet.
        import io, contextlib
        def wedged(cmd, **kw):
            raise rt.subprocess.TimeoutExpired(cmd, kw.get("timeout"))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertFalse(rt.docker_available(runner=wedged))
        self.assertIn("docker probe", err.getvalue())

        def missing(cmd, **kw):
            raise FileNotFoundError("docker not installed")
        quiet = io.StringIO()
        with contextlib.redirect_stderr(quiet):
            self.assertFalse(rt.docker_available(runner=missing))
        self.assertEqual(quiet.getvalue(), "")   # benign absent binary -> no noise


class TestTheImageIsNamedAndDispatchedById(unittest.TestCase):
    """#3270 G1: the tools image is the unit of trust. A found image is named by
    its id, the scan is dispatched by that id, and the manifest records it
    with docker's own app record and the mounted adapter code's hash. An
    image whose id cannot be read halts; no image stays the disclosed skip."""

    VERSION = b"Docker version 27.1.1, build 6312585\n"

    def _docker(self, root):
        path = os.path.join(root, "docker")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("#!/bin/sh\nexit 0\n")
        os.chmod(path, 0o700)
        return path

    def _runner(self, inspect=INSPECT_OK, seen=None):
        def runner(cmd, **kw):
            if seen is not None:
                seen.append(list(cmd))
            if "--version" in cmd:
                return _FakeResult(returncode=0, stdout=self.VERSION)
            return _FakeResult(returncode=0, stdout=inspect)
        return runner

    def test_a_found_image_is_named_by_its_id_and_docker_is_traced(self):
        with tempfile.TemporaryDirectory() as bin_dir, tempfile.TemporaryDirectory() as target:
            docker = self._docker(bin_dir)
            seen = []
            with mock.patch.dict(os.environ, {"PATH": bin_dir}):
                found = rt.docker_available(runner=self._runner(seen=seen), target=target)
            with open(docker, "rb") as fh:
                body = fh.read()
        self.assertEqual([os.path.realpath(docker), "image", "inspect", "--format",
                          tools_image.INSPECT_FORMAT, "panopticon-tools"], seen[0])
        self.assertEqual({"ref": "panopticon-tools", "id": FOUND_IMAGE_ID, "repo_digests": [],
                          "apps": [{"name": "docker", "path": os.path.realpath(docker),
                                    "version": "Docker version 27.1.1, build 6312585",
                                    "sha256": hashlib.sha256(body).hexdigest(),
                                    "size": len(body)}]}, found)

    def test_registry_digests_ride_beside_the_id_and_a_local_build_has_none(self):
        digest = "ghcr.io/o/t@sha256:" + "b" * 64
        got = tools_image.identity("t", ("%s [\"%s\", \"not a digest\"]" % (FOUND_IMAGE_ID, digest)).encode())
        self.assertEqual([digest], got["repo_digests"])
        self.assertEqual([], tools_image.identity("t", ("%s null" % FOUND_IMAGE_ID).encode())["repo_digests"])

    def test_an_image_whose_id_cannot_be_read_halts(self):
        for stdout in (b"", b"latest []\n", b"sha256:" + b"A" * 64 + b" []", b"sha256:abc []"):
            with self.subTest(stdout=stdout), tempfile.TemporaryDirectory() as bin_dir, \
                    tempfile.TemporaryDirectory() as target:
                self._docker(bin_dir)
                with mock.patch.dict(os.environ, {"PATH": bin_dir}):
                    with self.assertRaisesRegex(ValueError,
                                                "^tools image panopticon-tools cannot be named"):
                        rt.docker_available(runner=self._runner(inspect=stdout), target=target)

    def test_the_cli_halts_with_one_fixed_line_and_the_halt_exit(self):
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(rt, "docker_available",
                                  side_effect=tools_image.ImageIdentityError(
                                      tools_image.UNNAMEABLE % "panopticon-tools")), \
                mock.patch.object(rt, "run_tools") as scan, contextlib.redirect_stderr(err):
            rc = tools_image.halting(rt.main)(["--tools", "semgrep", "--target", d,
                                               "--out", os.path.join(d, "out")])
        self.assertEqual(tools_image.HALT_EXIT, rc)
        scan.assert_not_called()
        self.assertIn("run_tools: HALT: tools image panopticon-tools cannot be named: docker "
                      "reported no image id; refusing to scan with an image nobody can identify\n",
                      err.getvalue())

    def test_a_path_entry_inside_the_target_halts_the_probe(self):
        with tempfile.TemporaryDirectory() as target:
            os.makedirs(os.path.join(target, "bin"))
            self._docker(os.path.join(target, "bin"))
            with mock.patch.dict(os.environ, {"PATH": os.path.join(target, "bin")}), \
                    contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaisesRegex(ValueError, HALTS):
                    rt.docker_available(runner=self._runner(), target=target)

    def test_main_dispatches_by_the_id_and_records_it(self):
        docker_app = {"name": "docker", "path": "/usr/bin/docker", "version": "Docker version 27.1.1",
                      "sha256": "c" * 64, "size": 3}
        found = dict(FOUND_IMAGE, apps=[docker_app])
        with tempfile.TemporaryDirectory() as d:
            manifest = os.path.join(d, "m", "tools-manifest.json")
            with mock.patch.object(rt, "docker_available", return_value=found), \
                    mock.patch.object(rt, "run_tools", return_value=[]) as scan, \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(0, rt.main(["--tools", "semgrep", "--target", d, "--out",
                                             os.path.join(d, "out"), "--manifest", manifest]))
            with open(manifest, encoding="utf-8") as fh:
                written = json.load(fh)
        self.assertEqual(FOUND_IMAGE_ID, scan.call_args.kwargs["image"])
        self.assertEqual({"ref": "panopticon-tools", "id": FOUND_IMAGE_ID, "repo_digests": [],
                          "adapter_code": tools_image.adapter_code(SCRIPTS_DIR)}, written["image"])
        self.assertEqual([docker_app], written["apps"])
        self.assertEqual([docker_app], found["apps"])       # the probe's answer is not mutated

    def test_a_skipped_scan_records_that_the_image_was_not_available(self):
        with tempfile.TemporaryDirectory() as d:
            manifest = os.path.join(d, "m", "tools-manifest.json")
            with mock.patch.object(rt, "docker_available", return_value=False), \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(0, rt.main(["--tools", "semgrep", "--target", d, "--out",
                                             os.path.join(d, "out"), "--manifest", manifest]))
            with open(manifest, encoding="utf-8") as fh:
                written = json.load(fh)
        self.assertEqual({"ref": "panopticon-tools", "id": None}, written["image"])
        self.assertNotIn("apps", written)


class TestTheAdapterCodeIsNamedByOneHash(unittest.TestCase):
    """#3270 C1: the checkout's `skill/scripts` is mounted over the image's baked
    copy, so the id does not cover our adapters; one sha256 over the mounted
    tree says which code ran."""

    def _tree(self, root):
        os.makedirs(os.path.join(root, "tools"))
        for rel, body in (("a.py", "A = 1\n"), ("tools/b.py", "B = 2\n")):
            with open(os.path.join(root, rel), "w", encoding="utf-8") as fh:
                fh.write(body)

    def test_it_changes_with_a_byte_or_a_name_and_ignores_bytecode(self):
        with tempfile.TemporaryDirectory() as root:
            self._tree(root)
            first = tools_image.adapter_code(root)
            self.assertRegex(first, r"^sha256:[0-9a-f]{64}$")
            os.makedirs(os.path.join(root, "tools", "__pycache__"))
            for rel in ("tools/__pycache__/b.cpython-314.pyc", "c.pyc"):
                with open(os.path.join(root, rel), "wb") as fh:
                    fh.write(b"\0")
            self.assertEqual(first, tools_image.adapter_code(root))
            with open(os.path.join(root, "a.py"), "a", encoding="utf-8") as fh:
                fh.write("# edit\n")
            edited = tools_image.adapter_code(root)
            self.assertNotEqual(first, edited)
            os.rename(os.path.join(root, "tools", "b.py"), os.path.join(root, "tools", "c.py"))
            self.assertNotEqual(edited, tools_image.adapter_code(root))
