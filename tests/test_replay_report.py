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
import sys
import tempfile
import unittest
from unittest import mock
import pytest
import scripts.phases.child as child_mod
import scripts.phases.runio as runio
from scripts import hosts

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
    child_mod._run_child(["python3", "/repo/skill/scripts/synthesize.py", "--out",
                          os.path.join(root, ".panopticon", "orig-report.json")],
                         root, "synthesize")
    raise runio.DriverError("no report")


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
    with mock.patch("scripts.phases.synthesize.synthesize_execute", new=_fake_synthesize_execute), \
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

    def _args(self, name):
        return argparse.Namespace(repo=None, review_root=self.review_root,
                                  run_folder=self.run_folder,
                                  out_dir=os.path.join(self.tmp.name, name),
                                  manifest=os.path.join(self.review_root, "run-manifest.json"))

    def test_mismatched_run_id_refuses_before_child_or_source_change(self):
        path = os.path.join(self.run_folder, "validate.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"run_id": "different"}, fh)
        before = replay_report._listing(self.run_folder)
        with mock.patch.object(replay_report.subprocess, "run") as child:
            with self.assertRaisesRegex(SystemExit, "manifest run_id.*run folder"):
                replay_report.replay(self._args("mismatch"))
        child.assert_not_called()
        self.assertEqual(replay_report._listing(self.run_folder), before)

    def test_missing_standard_artifacts_refuse_before_child_or_source_change(self):
        for name in replay_report.REQUIRED:
            with self.subTest(name=name):
                path = os.path.join(self.run_folder, name)
                os.unlink(path)
                before = replay_report._listing(self.run_folder)
                with mock.patch.object(replay_report.subprocess, "run") as child, \
                        mock.patch("scripts.phases.synthesize.synthesize_execute") as phase:
                    with self.assertRaisesRegex(SystemExit, "lacks.*" + name):
                        replay_report.replay(self._args("missing-" + name))
                child.assert_not_called()
                phase.assert_not_called()
                self.assertEqual(replay_report._listing(self.run_folder), before)
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write("{}")

    def test_no_synthesize_command_refuses_before_child_or_source_change(self):
        before = replay_report._listing(self.run_folder)
        with mock.patch.object(replay_report.subprocess, "run") as child, \
                mock.patch("scripts.phases.synthesize.synthesize_execute"):
            with self.assertRaisesRegex(SystemExit, "did not build a synthesize command"):
                replay_report.replay(self._args("no-command"))
        child.assert_not_called()
        self.assertEqual(replay_report._listing(self.run_folder), before)

    def test_reference_mutation_is_refused(self):
        def mutate_reference(cmd, cwd, capture_output, text, env):
            with open(os.path.join(self.run_folder, "new-reference-file"), "w") as fh:
                fh.write("mutation probe")
            return _fake_child(cmd, cwd, capture_output, text, env)

        with mock.patch("scripts.phases.synthesize.synthesize_execute",
                        new=_fake_synthesize_execute), \
                mock.patch.object(replay_report.subprocess, "run", new=mutate_reference):
            with self.assertRaisesRegex(SystemExit, "REFERENCE RUN FOLDER MUTATED"):
                replay_report.replay(self._args("mutated"))

    def test_no_report_is_refused_after_child(self):
        def no_report(cmd, cwd, capture_output, text, env):
            return subprocess.CompletedProcess(cmd, 0, "", "")

        before = replay_report._listing(self.run_folder)
        with mock.patch("scripts.phases.synthesize.synthesize_execute",
                        new=_fake_synthesize_execute), \
                mock.patch.object(replay_report.subprocess, "run", new=no_report):
            with self.assertRaisesRegex(SystemExit, "no report written"):
                replay_report.replay(self._args("no-report"))
        self.assertEqual(replay_report._listing(self.run_folder), before)

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

    def test_replay_cannot_import_target_sitecustomize_before_trusted_script(self):
        marker = os.path.join(self.review_root, "sitecustomize-ran")
        with open(os.path.join(self.review_root, "sitecustomize.py"), "w",
                  encoding="utf-8") as fh:
            fh.write("open(%r, 'w').write('bad')\n" % marker)
        trusted = os.path.join(self.tmp.name, "trusted")
        os.makedirs(trusted)
        script = os.path.join(trusted, "synthesize.py")
        with open(script, "w", encoding="utf-8") as fh:
            fh.write("import json, os, sys\n"
                     "p = sys.argv[sys.argv.index('--out') + 1]\n"
                     "os.makedirs(os.path.dirname(p), exist_ok=True)\n"
                     "json.dump({'meta': {}, 'summary': {}}, open(p, 'w'))\n")

        def build_command(root, _manifest):
            child_mod._run_child([sys.executable, script, "--out",
                                  os.path.join(root, ".panopticon", "orig-report.json")],
                                 root, "synthesize")
            raise runio.DriverError("recorded")

        out = os.path.join(self.tmp.name, "out-startup")
        for pythonpath in (".", self.review_root):
            with self.subTest(pythonpath=pythonpath), \
                    mock.patch("scripts.phases.synthesize.synthesize_execute",
                               new=build_command), \
                    mock.patch.dict(os.environ, {"PYTHONPATH": pythonpath}, clear=False), \
                    mock.patch("sys.stdout"):
                replay_report.replay(argparse.Namespace(
                    repo=None, review_root=self.review_root, run_folder=self.run_folder,
                    out_dir=out, manifest=os.path.join(self.review_root,
                                                       "run-manifest.json")))
            self.assertFalse(os.path.exists(marker))


    def test_usage_preflight_matches_the_archived_runs_measured_posture(self):
        for host in (None, "claude", "codex"):
            for state in (hosts.PROVEN, hosts.UNKNOWN, hosts.REFUTED):
                with self.subTest(host=host, state=state):
                    manifest = dict(MANIFEST)
                    if host is None:
                        manifest.pop("host")
                    else:
                        manifest["host"] = host
                    with open(os.path.join(self.review_root, "run-manifest.json"), "w") as fh:
                        json.dump(manifest, fh)
                    with open(os.path.join(self.run_folder, "host-capabilities.json"), "w") as fh:
                        json.dump({"capabilities": {hosts.USAGE_LEDGER: {"state": state}}}, fh)
                    out = os.path.join(self.tmp.name, "out-%s-%s" % (host, state))
                    if host == "claude" and state == hosts.PROVEN:
                        with self.assertRaisesRegex(SystemExit, "lacks.*usage.json"):
                            _replay_into(self.review_root, self.run_folder, out)
                    else:
                        _replay_into(self.review_root, self.run_folder, out)
                    self.assertFalse(os.path.exists(os.path.join(self.run_folder, "usage.json")))


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


def _write_report(directory, suffix, value):
    path = os.path.join(directory, f"{TAG}-report{suffix}")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(value, fh)


def test_diff_nested_values_lists_and_key_order(tmp_path):
    a = _out_dir(tmp_path, "a", "")
    b = _out_dir(tmp_path, "b", "")
    _write_report(a, ".json", {"meta": {"timestamp": "a"},
                              "nested": {"items": [1, {"value": "old"}]}})
    _write_report(b, ".json", {"meta": {"timestamp": "b"},
                              "nested": {"items": [1, {"value": "new"}]}})
    rc, lines = _diff(a, b)
    assert rc == 1
    assert any("nested.items[1].value" in line for line in lines)
    _write_report(b, ".json", {"meta": {"timestamp": "b"},
                              "nested": {"items": [1]}})
    rc, lines = _diff(a, b)
    assert rc == 1
    assert any("nested.items: list length 2 != 1" in line for line in lines)
    _write_report(b, ".json", {"nested": {"items": [1, {"value": "old"}]},
                              "meta": {"timestamp": "b"}})
    rc, lines = _diff(a, b)
    assert rc == 1
    assert any("KEY ORDER" in line for line in lines)


@pytest.mark.parametrize("suffix", [".json", "_part2.json", "-discarded.json", "-x0x.json"])
def test_diff_each_json_artifact_content_and_presence(tmp_path, suffix):
    a = _out_dir(tmp_path, "a", "")
    b = _out_dir(tmp_path, "b", "")
    _write_report(a, suffix, {"nested": {"value": "old"}})
    _write_report(b, suffix, {"nested": {"value": "new"}})
    rc, lines = _diff(a, b)
    assert rc == 1
    if suffix == ".json":
        assert any("nested.value" in line for line in lines)
        os.unlink(os.path.join(b, f"{TAG}-report{suffix}"))
        assert any("present on A only" in line for line in _diff(a, b)[1])
        return
    assert any("nested.value" in line for line in lines)
    os.unlink(os.path.join(b, f"{TAG}-report{suffix}"))
    rc, lines = _diff(a, b)
    assert rc == 1
    assert any("present on A only" in line for line in lines)


def test_diff_masks_only_declared_json_timestamps(tmp_path):
    a = _out_dir(tmp_path, "a", "")
    b = _out_dir(tmp_path, "b", "")
    _write_report(a, ".json", {"meta": {"timestamp": "first"}, "other": "same"})
    _write_report(b, ".json", {"meta": {"timestamp": "second"}, "other": "same"})
    _write_report(a, "-x0x.json", {"generated_at": "first", "other": "same"})
    _write_report(b, "-x0x.json", {"generated_at": "second", "other": "same"})
    assert _diff(a, b)[0] == 0
    _write_report(b, ".json", {"meta": {"timestamp": "second"}, "other": "changed"})
    rc, lines = _diff(a, b)
    assert rc == 1
    assert any("other" in line for line in lines)
    _write_report(b, ".json", {"meta": {"timestamp": "second"}, "other": "same"})
    _write_report(b, "-x0x.json", {"generated_at": "second", "other": "changed"})
    rc, lines = _diff(a, b)
    assert rc == 1
    assert any("-x0x.json.other" in line for line in lines)


def test_diff_html_timestamp_content_and_presence(tmp_path):
    a = _out_dir(tmp_path, "a", "")
    b = _out_dir(tmp_path, "b", "")
    html = f"{TAG}-report.json.html"
    for folder, stamp in ((a, "2026-09-25T00:00:00Z"),
                          (b, "2026-09-26T00:00:00Z")):
        with open(os.path.join(folder, html), "w", encoding="utf-8") as fh:
            fh.write(f"<p>{stamp}</p><b>same</b>")
    assert _diff(a, b)[0] == 0
    with open(os.path.join(b, html), "w", encoding="utf-8") as fh:
        fh.write("<p>2026-09-26T00:00:00Z</p><b>changed</b>")
    assert any("differs" in line for line in _diff(a, b)[1])
    os.unlink(os.path.join(b, html))
    assert any("present on A only" in line for line in _diff(a, b)[1])


if __name__ == "__main__":
    unittest.main()
