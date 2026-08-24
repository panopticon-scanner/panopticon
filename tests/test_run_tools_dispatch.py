"""Adapter dispatch tests for scripts.run_tools."""
import contextlib
import io
import os
import tempfile
import unittest
from unittest import mock

import scripts.run_tools as rt

from run_tools_test_helpers import _FakeResult


class TestAdapterDispatch(unittest.TestCase):
    def test_main_tools_with_exclude_does_not_crash(self):
        # COD-X0X: `--tools ... --exclude ...` built a LIST of adapters and passed
        # it to partition_by_exclusion, which iterates .items() -> AttributeError
        # crashed the whole CLI before any scan. The combination is operator-facing
        # (documented in --exclude help), so it must resolve cleanly.
        class FakeAdapter:
            def applicable_files(self, target):
                return []
        with mock.patch.dict(rt.ADAPTERS, {"faketool": FakeAdapter()}, clear=False), \
             mock.patch("scripts.run_tools.docker_available", return_value=True), \
             mock.patch("scripts.run_tools.run_tools", return_value={}), \
             contextlib.redirect_stderr(io.StringIO()):
            rc = rt.main(["--tools", "faketool", "--exclude", "tests/fixtures/*",
                          "--target", ".", "--out", "/tmp/pano-x0x"])
        self.assertEqual(rc, 0)

    def test_select_adapters_by_ecosystem(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "requirements.txt"), "w").close()
            names = rt.select_adapters(d)
            self.assertIn("pip-audit", names)
            self.assertNotIn("npm-audit", names)

    def test_run_tools_dispatches_phase1_adapter_via_docker_helper(self):
        class FakeAdapter:
            name = "fake"
            def is_applicable(self, target): return True
            def invoke(self, target): return (b'{"findings":[]}', 0)

        calls = []
        fake = _FakeResult(returncode=0, stdout=b'{"findings":[]}', stderr=b'')
        def runner(cmd, **kw):
            calls.append(cmd); return fake

        with tempfile.TemporaryDirectory() as d:
            out_dir = os.path.join(d, "out")
            with mock.patch.dict(rt.ADAPTERS, {"fake": FakeAdapter()}, clear=False):
                rt.run_tools(d, ["fake"], out_dir, image="panopticon-tools", runner=runner)
            self.assertEqual(len(calls), 1)
            self.assertIn("/opt/panopticon/scripts/_run_adapter.py", calls[0])
            self.assertIn("fake", calls[0])
            with open(os.path.join(out_dir, "fake.json"), "rb") as fh:
                self.assertEqual(fh.read(), fake.stdout)

    def test_empty_adapter_output_fails_closed(self):
        # #1051: an adapter run that exits 0 with EMPTY stdout is a silent
        # failure, not a clean run. Fail closed: announce it, write NO file, and
        # drop it from the produced set so write_manifest lands it in `missing`
        # (-> INCONCLUSIVE) instead of certifying it as ran-clean.
        class FakeAdapter:
            name = "fake"
            def is_applicable(self, target): return True
        fake = _FakeResult(returncode=0, stdout=b'', stderr=b'')
        def runner(cmd, **kw):
            return fake
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "out")
            with mock.patch.dict(rt.ADAPTERS, {"fake": FakeAdapter()}, clear=False):
                with contextlib.redirect_stderr(io.StringIO()) as err:
                    paths = rt.run_tools(d, ["fake"], out, runner=runner)
            self.assertIn("produced no output", err.getvalue())
            self.assertEqual(paths, [])                                   # not produced
            self.assertFalse(os.path.exists(os.path.join(out, "fake.json")))  # no empty file

    def test_empty_adapter_output_lands_in_manifest_missing(self):
        # #1051, end-to-end: the empty-output adapter must show up in the
        # runner's coverage manifest as `missing`, never `produced` -- that is
        # the signal synthesize's #1031 gate turns into INCONCLUSIVE.
        class FakeAdapter:
            name = "fake"
            def is_applicable(self, target): return True
        fake = _FakeResult(returncode=0, stdout=b'', stderr=b'')
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "out")
            with mock.patch.dict(rt.ADAPTERS, {"fake": FakeAdapter()}, clear=False):
                written = rt.run_tools(d, ["fake"], out, runner=lambda cmd, **kw: fake)
            payload = rt.write_manifest(
                os.path.join(d, "m.json"), ["fake"], written)
            self.assertEqual(payload["produced"], [])
            self.assertEqual(payload["missing"], ["fake"])

    def test_run_tools_uses_readonly_src_mount_for_phase2_build_adapters(self):
        calls = []
        fake = _FakeResult(returncode=0, stdout=b'{"runs":[]}', stderr=b'')
        def runner(cmd, **kw):
            calls.append(cmd); return fake

        with tempfile.TemporaryDirectory() as d:
            out_dir = os.path.join(d, "out")
            for tool in ("spotbugs", "roslyn-secguard"):
                rt.run_tools(d, [tool], out_dir, image="panopticon-tools", runner=runner)
            expected_mount = "%s:/src:ro" % os.path.abspath(d)
            for cmd in calls:
                self.assertIn(expected_mount, cmd)


    def test_default_selection_includes_phase1_adapters(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "requirements.txt"), "w").close()
            open(os.path.join(d, "package-lock.json"), "w").close()
            chosen = rt.select_tools([], has_deps=False) + [
                name for name in rt.select_adapters(d) if name in rt.PHASE1_ADAPTERS
            ]
            self.assertIn("pip-audit", chosen)
            self.assertIn("npm-audit", chosen)

    def test_phase1_adapter_registry_not_leaked(self):
        # Regression: phase-1 adapter tests must restore rt.ADAPTERS.
        original = dict(rt.ADAPTERS)
        self.test_run_tools_dispatches_phase1_adapter_via_docker_helper()
        self.assertEqual(dict(rt.ADAPTERS), original)
