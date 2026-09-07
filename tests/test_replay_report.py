"""`scripts/replay_report.py` -- the WS-0 behaviour-preservation oracle.

The tool is a consumer of the driver like any test, so the driver side is
mocked at the same seams the tool patches. The scrub is the point: two
replays of one folder into two out-dirs must compare IDENTICAL on stdout
and stderr as well as on the report files, or the stdout gate (spec §6.1)
has to be a hand-masked compare.
"""
import argparse
import json
import os
import subprocess
import tempfile
import unittest
from unittest import mock

import replay_report

MANIFEST = {"host": "codex", "security_mode": "redteam", "scope": {"mode": "repo"},
            "created": "2026-09-06T00:00:00Z", "run_id": "0123456789abcdef"}
TAG = "codex-redteam-repo-20260906-01234567"


def _run_folder(base):
    """A run folder that satisfies `replay`'s preflight (no usage.json: codex host)."""
    folder = os.path.join(base, "runs", TAG)
    os.makedirs(folder)
    for name in ("dispatch-plan-driver.json", "out-file-hashes.json"):
        with open(os.path.join(folder, name), "w", encoding="utf-8") as fh:
            fh.write("{}")
    with open(os.path.join(folder, "validate.json"), "w", encoding="utf-8") as fh:
        json.dump({"run_id": MANIFEST["run_id"]}, fh)
    return folder


def _fake_synthesize_execute(root, manifest):
    """Stand-in driver phase: asks `_run_child` for the synthesize argv exactly
    once, the way the real phase does, then reports the child wrote nothing."""
    import scripts.driver as driver
    driver._run_child(["python3", "/repo/skill/scripts/synthesize.py", "--out",
                       os.path.join(root, ".panopticon", "orig-report.json")],
                      root, "synthesize")
    raise driver.DriverError("no report")


def _fake_child(cmd, cwd, capture_output, text, env):
    """Stand-in synthesize child: writes the report at `--out` and talks about
    both per-replay paths on stdout and stderr, as the real one does."""
    out_path = cmd[cmd.index("--out") + 1]
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump({"meta": {"timestamp": "t"}, "summary": {"grade": "F"}}, fh)
    out_dir = os.path.dirname(out_path)
    return subprocess.CompletedProcess(
        cmd, 0,
        stdout=f"X0X artifact: {out_dir}/{TAG}-report-x0x.json (7 candidates)\n# report\n",
        stderr=f"ingest: path mismatch under {cwd}/.panopticon/runs/{TAG}\n")


def _replay_into(review_root, run_folder, out_dir):
    with mock.patch("scripts.driver.synthesize_execute", new=_fake_synthesize_execute), \
            mock.patch.object(replay_report.subprocess, "run", new=_fake_child), \
            mock.patch("sys.stdout"):
        replay_report.replay(argparse.Namespace(
            repo=None, review_root=review_root, run_folder=run_folder,
            out_dir=out_dir, manifest=os.path.join(review_root, "run-manifest.json")))


class ReplayScrubTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.review_root = os.path.join(self.tmp.name, "review")
        os.makedirs(self.review_root)
        with open(os.path.join(self.review_root, "run-manifest.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(MANIFEST, fh)
        self.run_folder = _run_folder(self.tmp.name)

    def _read(self, out_dir, name):
        with open(os.path.join(out_dir, name), encoding="utf-8") as fh:
            return fh.read()

    def test_replay_writes_stdout_with_out_dir_and_scratch_root_scrubbed(self):
        out_dir = os.path.join(self.tmp.name, "out-a")
        _replay_into(self.review_root, self.run_folder, out_dir)
        self.assertEqual(self._read(out_dir, "synthesize.stdout"),
                         f"X0X artifact: <out>/{TAG}-report-x0x.json (7 candidates)\n# report\n")

    def test_replay_writes_stderr_with_scratch_root_scrubbed(self):
        out_dir = os.path.join(self.tmp.name, "out-a")
        _replay_into(self.review_root, self.run_folder, out_dir)
        self.assertEqual(self._read(out_dir, "synthesize.stderr"),
                         f"ingest: path mismatch under <scratch>/.panopticon/runs/{TAG}\n")


class ScrubTest(unittest.TestCase):
    def test_scrub_replaces_scratch_root_and_out_dir_with_tokens(self):
        text = ("X0X artifact: /out/r11-a/tag-report-x0x.json\n"
                "findings: /tmp/replay-abc/root/.panopticon/runs/tag/findings.json\n")
        got = replay_report._scrub(text, "/tmp/replay-abc/root", "/out/r11-a")
        self.assertEqual(got, "X0X artifact: <out>/tag-report-x0x.json\n"
                              "findings: <scratch>/.panopticon/runs/tag/findings.json\n")

    def test_scrub_is_idempotent_and_leaves_clean_text_alone(self):
        clean = "HTML artifact: <out>/tag-report.json.html\n"
        self.assertEqual(replay_report._scrub(clean, "/tmp/replay-abc/root", "/out/r11-a"), clean)


def _out_dir(base, name, stdout, stderr=None):
    """A replay out-dir: one report plus the captured streams."""
    d = os.path.join(base, name)
    os.makedirs(d)
    with open(os.path.join(d, f"{TAG}-report.json"), "w", encoding="utf-8") as fh:
        json.dump({"meta": {"timestamp": name}, "summary": {"grade": "F"}}, fh)
    for stream, text in (("synthesize.stdout", stdout), ("synthesize.stderr", stderr)):
        if text is not None:
            with open(os.path.join(d, stream), "w", encoding="utf-8") as fh:
                fh.write(text)
    return d


def _diff(a, b):
    """Run `diff` and return (exit code, printed lines)."""
    printed = []
    with mock.patch("builtins.print", new=lambda *parts, **kw: printed.append(" ".join(map(str, parts)))):
        rc = replay_report.diff(argparse.Namespace(a=a, b=b, limit=50))
    return rc, printed


class DiffStreamsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_identical_streams_and_reports_are_identical(self):
        a = _out_dir(self.tmp.name, "a", "# report\n- HIGH: 14\n", "warn\n")
        b = _out_dir(self.tmp.name, "b", "# report\n- HIGH: 14\n", "warn\n")
        rc, printed = _diff(a, b)
        self.assertEqual(rc, 0)
        self.assertTrue(printed[-1].startswith("IDENTICAL: 0 difference(s)"), printed)

    def test_stdout_difference_is_reported_with_its_first_differing_line(self):
        a = _out_dir(self.tmp.name, "a", "# report\n- HIGH: 14\n", "warn\n")
        b = _out_dir(self.tmp.name, "b", "# report\n- HIGH: 15\n", "warn\n")
        rc, printed = _diff(a, b)
        self.assertEqual(rc, 1)
        self.assertIn("synthesize.stdout: differs at line 2", printed)

    def test_stderr_difference_is_reported(self):
        a = _out_dir(self.tmp.name, "a", "# report\n", "warn\n")
        b = _out_dir(self.tmp.name, "b", "# report\n", "warn\nSCHEMA: finding[3] missing cvss\n")
        rc, printed = _diff(a, b)
        self.assertEqual(rc, 1)
        self.assertIn("synthesize.stderr: differs at line 2", printed)

    def test_stream_present_on_one_side_only_is_reported(self):
        a = _out_dir(self.tmp.name, "a", "# report\n", "warn\n")
        b = _out_dir(self.tmp.name, "b", "# report\n")
        rc, printed = _diff(a, b)
        self.assertEqual(rc, 1)
        self.assertIn("synthesize.stderr: present on A only", printed)


if __name__ == "__main__":
    unittest.main()
