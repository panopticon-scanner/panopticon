"""Every `.panopticon`-resident writer refuses a symlink planted at its path.

#1735 (SEC-D1C) was `run_manifest._rewrite`; this is the rest of the sweep it
prompted. `.panopticon/` lives INSIDE the reviewed tree, so under redteam every
artifact path -- and every `<artifact>.tmp` staged beside it -- is a name the
target can pre-commit as a symlink to a file the invoking user can write. A
plain `open(path, "w")` follows it and replaces that file's contents.

Shape, once per site: plant the link at the exact path the writer will open,
pointing at a victim OUTSIDE `.panopticon` (the real attack -- a dotfile,
`authorized_keys`), call the writer, assert the victim's bytes survived. The
whole-path confinement answers that half LOUDLY, which is why most of these
assert a raise; `open_w_nofollow`'s O_NOFOLLOW answers a link that stays inside
the tree, and tests/test_safe_write.py covers that once for the primitive
rather than once per caller.

The sites with a uuid-named staging file (`synth/render`, `discovery`) have no
plantable leaf -- the name is unguessable and `os.replace` never dereferences
-- so what routing them through the helper buys is the INTERMEDIATE-component
confinement (`.panopticon/runs -> /elsewhere`). Their tests pin the uuid to
reach the same assertion.

Deliberately NOT here, because their paths are not `.panopticon`-resident: the
guard hooks' own `_atomic_write_json` (already O_EXCL|O_NOFOLLOW, and standalone
by necessity -- a hook subprocess has no package on sys.path), `setup_flow`'s
seed (already O_EXCL|O_NOFOLLOW), `dispatch.emit_host_agents` (the host's agent
registration directory), `tools/egress` (a scratch dir, by design), and
`strain_report.write_report` / `reconcile` (operator `--out` paths, no driver
caller). The #1735 report carries the full table.
"""
import json
import os
import tempfile
import types
import unittest
from unittest import mock

import scripts.citations as citations
import scripts.collect_usage as collect_usage
import scripts.discovery as discovery
import scripts.evidence as evidence
import scripts.group_runner as group_runner
import scripts.html_report as html_report
import scripts.run_tools as run_tools
import scripts.synthesize as synthesize
import scripts.synth.render as render_mod


class _Planted(unittest.TestCase):
    """A review root with a `.panopticon/` and a victim file outside it."""

    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.addCleanup(self._d.cleanup)
        self.root = self._d.name
        self.pano = os.path.join(self.root, ".panopticon")
        os.makedirs(self.pano)
        self.victim = os.path.join(self.root, "victim.txt")
        with open(self.victim, "w", encoding="utf-8") as fh:
            fh.write("PRECIOUS")

    def plant(self, *parts):
        """A symlink at `.panopticon/<parts>` pointing at the victim."""
        path = os.path.join(self.pano, *parts)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        os.symlink(self.victim, path)
        return path

    def assert_victim_intact(self):
        with open(self.victim, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "PRECIOUS")


class TestHtmlReport(_Planted):
    def test_write_html_refuses_a_planted_link(self):
        path = self.plant("run-report.json.html")
        with self.assertRaises(ValueError):
            html_report.write_html({"findings": [], "meta": {}}, path)
        self.assert_victim_intact()


class TestVerifyQueue(_Planted):
    def test_write_verify_queue_refuses_a_planted_link(self):
        path = self.plant("runs", "tag", "verify-queue.json")
        with self.assertRaises(ValueError):
            evidence.write_verify_queue([], 0, path)
        self.assert_victim_intact()


class TestEpssCache(_Planted):
    def test_save_cache_refuses_a_planted_link_without_taking_the_run_down(self):
        # The one best-effort writer here: an unwritable EPSS cache has always
        # been a shrug (`except OSError: pass`), and a refused one stays a
        # shrug -- the refusal already did its job by not clobbering the victim.
        path = self.plant("epss-cache.json")
        citations._save_cache(path, {"CVE-2020-1": 0.5})
        self.assert_victim_intact()
        self.assertTrue(os.path.islink(path))      # nothing written through it


class TestToolsManifest(_Planted):
    def test_run_tools_write_manifest_refuses_a_planted_link(self):
        path = self.plant("runs", "tag", "tools-manifest.json")
        with self.assertRaises(ValueError):
            run_tools.write_manifest(path, ["semgrep"], [])
        self.assert_victim_intact()


class TestUsageJson(_Planted):
    def test_collect_usage_refuses_a_planted_link(self):
        run_dir = os.path.join(self.pano, "runs", "tag")
        os.makedirs(run_dir)
        self.plant("runs", "tag", "usage.json")
        doc = {"total": 1, "subagent_transcripts": 0}
        with mock.patch.object(collect_usage, "collect", return_value=doc):
            with self.assertRaises(ValueError):
                collect_usage.main(["--run-dir", run_dir,
                                    "--project-dir", self.root,
                                    "--since", "none", "--until", "none"])
        self.assert_victim_intact()


class TestOutFileHashes(_Planted):
    def test_snapshot_out_files_refuses_a_planted_link(self):
        cell = os.path.join(self.pano, "findings-g1-security.json")
        with open(cell, "w", encoding="utf-8") as fh:
            json.dump({"findings": []}, fh)
        path = self.plant("runs", "tag", "out-file-hashes.json")
        with self.assertRaises(ValueError):
            group_runner.snapshot_out_files([{"out_file": cell}], out_path=path)
        self.assert_victim_intact()


class TestX0xArtifact(_Planted):
    """`synthesize.main` stages `<report>-x0x.json` at a `.tmp` beside it --
    the same fixed-name staging shape as the manifest this issue is about."""

    def setUp(self):
        super().setUp()
        cwd = os.getcwd()
        os.chdir(self.root)            # run_dir falls back to a cwd-relative .panopticon
        self.addCleanup(os.chdir, cwd)

    def test_the_x0x_staging_write_refuses_a_planted_link(self):
        findings = os.path.join(self.root, "findings-g1-security.json")
        with open(findings, "w", encoding="utf-8") as fh:
            json.dump({"findings": []}, fh)
        out = os.path.join(self.pano, "report.json")
        self.plant("report-x0x.json.tmp")
        with self.assertRaises(ValueError):
            synthesize.main(["--out", out, findings])
        self.assert_victim_intact()


class _PinnedUuid:
    """`uuid.uuid4().hex` with a name a test can plant a link at."""
    HEX = "0" * 32

    def __enter__(self):
        self._p = mock.patch.object(
            render_mod.uuid, "uuid4",
            return_value=types.SimpleNamespace(hex=self.HEX))
        self._p.start()
        return self

    def __exit__(self, *exc):
        self._p.stop()
        return False


class TestReportStaging(_Planted):
    """`synth/render.write_report` stages every part under a uuid name, so the
    leaf is unplantable; the confinement it gains covers the directory."""

    def test_single_report_staging_refuses_a_planted_link(self):
        out = os.path.join(self.pano, "report.json")
        with _PinnedUuid():
            self.plant(".report-%s.tmp" % _PinnedUuid.HEX)
            with self.assertRaises(ValueError):
                render_mod.write_report({"findings": [], "meta": {}}, out)
        self.assert_victim_intact()

    def test_chunked_report_staging_refuses_a_planted_link(self):
        out = os.path.join(self.pano, "report.json")
        report = {"meta": {}, "findings": [{"id": "A-1"}, {"id": "A-2"}]}
        with _PinnedUuid():
            self.plant(".part-%s.tmp" % _PinnedUuid.HEX)
            with self.assertRaises(ValueError):
                render_mod.write_report(report, out, max_bytes=10)
        self.assert_victim_intact()


class TestDiffHunks(_Planted):
    def test_diff_hunks_staging_refuses_a_planted_link(self):
        out = os.path.join(self.pano, "diff-hunks.json")
        with mock.patch.object(discovery.uuid, "uuid4",
                               return_value=types.SimpleNamespace(hex="1" * 32)):
            self.plant(".diff-hunks-%s.tmp" % ("1" * 32))
            with self.assertRaises(ValueError):
                discovery.write_diff_hunks(self.root, None, "none", out, 0, False)
        self.assert_victim_intact()


if __name__ == "__main__":
    unittest.main()
