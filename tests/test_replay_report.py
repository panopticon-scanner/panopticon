"""`scripts/replay_report.py` -- the WS-0 behaviour-preservation oracle.

The tool is a consumer of the driver like any test, so the driver side is
mocked at the same seams the tool patches. The scrub is the point: two
replays of one folder into two out-dirs must compare IDENTICAL on stdout
and stderr as well as on the report files, or the stdout gate (spec §6.1)
has to be a hand-masked compare.
"""
import argparse
import contextlib
import io
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
import scripts.run_manifest as run_manifest
from scripts import hosts

import replay_report
from tests._test_helpers import adopt_panopticon, our_manifest

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


_REAL_RUN = subprocess.run


@contextlib.contextmanager
def _child(fake=None):
    """Fake only the synthesize CHILD (#3332): replay's first-contact git probe
    goes through the same `subprocess.run` and must still run for real."""
    child = fake if fake is not None else mock.MagicMock()

    def run(cmd, *args, **kwargs):
        if len(cmd) > 1 and os.path.basename(str(cmd[1])) == "synthesize.py":
            return child(cmd, *args, **kwargs)
        return _REAL_RUN(cmd, *args, **kwargs)

    with mock.patch.object(replay_report.subprocess, "run", new=run):
        yield child


def _mpath(review_root):
    return os.path.join(review_root, ".panopticon", "run-manifest.json")


def _write_ours(review_root, manifest):
    """#3332: a run of OURS -- the tree adopted and the manifest stamped to it
    with the suite's key -- which replay's flag-less verification accepts."""
    if not os.path.isfile(os.path.join(review_root, ".panopticon", "owner.json")):
        adopt_panopticon(review_root)
    stamped = our_manifest(review_root, dict(manifest, review_root=os.path.abspath(review_root)))
    with open(_mpath(review_root), "w", encoding="utf-8") as fh:
        json.dump(stamped, fh)


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


def _replay_into(review_root, run_folder, out_dir, trust=False, child=_fake_child):
    with mock.patch("scripts.phases.synthesize.synthesize_execute", new=_fake_synthesize_execute), \
            _child(child), \
            mock.patch("sys.stdout"):
        replay_report.replay(argparse.Namespace(
            repo=None, review_root=review_root, run_folder=run_folder,
            out_dir=out_dir, manifest=_mpath(review_root), trust_archive=trust))


class ReplayScrubTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.review_root = os.path.join(self.tmp.name, "review")
        os.makedirs(self.review_root)
        _write_ours(self.review_root, MANIFEST)
        self.run_folder = _run_folder(self.tmp.name)

    def _read(self, out_dir, name):
        with open(os.path.join(out_dir, name), encoding="utf-8") as fh:
            return fh.read()

    def _args(self, name):
        return argparse.Namespace(repo=None, review_root=self.review_root,
                                  run_folder=self.run_folder,
                                  out_dir=os.path.join(self.tmp.name, name),
                                  manifest=_mpath(self.review_root))

    def test_mismatched_run_id_refuses_before_child_or_source_change(self):
        path = os.path.join(self.run_folder, "validate.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"run_id": "different"}, fh)
        before = replay_report._listing(self.run_folder)
        with _child() as child:
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
                with _child() as child, \
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
        with _child() as child, \
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
                _child(mutate_reference):
            with self.assertRaisesRegex(SystemExit, "REFERENCE RUN FOLDER MUTATED"):
                replay_report.replay(self._args("mutated"))

    def test_no_report_is_refused_after_child(self):
        def no_report(cmd, cwd, capture_output, text, env):
            return subprocess.CompletedProcess(cmd, 0, "", "")

        before = replay_report._listing(self.run_folder)
        with mock.patch("scripts.phases.synthesize.synthesize_execute",
                        new=_fake_synthesize_execute), \
                _child(no_report):
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
                    out_dir=out, manifest=_mpath(self.review_root)))
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
                    _write_ours(self.review_root, manifest)
                    with open(os.path.join(self.run_folder, "host-capabilities.json"), "w") as fh:
                        json.dump({"capabilities": {hosts.USAGE_LEDGER: {"state": state}}}, fh)
                    out = os.path.join(self.tmp.name, "out-%s-%s" % (host, state))
                    if host == "claude" and state == hosts.PROVEN:
                        with self.assertRaisesRegex(SystemExit, "lacks.*usage.json"):
                            _replay_into(self.review_root, self.run_folder, out)
                    else:
                        _replay_into(self.review_root, self.run_folder, out)
                    self.assertFalse(os.path.exists(os.path.join(self.run_folder, "usage.json")))

    def test_a_replay_keeps_the_runs_usage_and_never_reattributes_it(self):
        # #3373: attribution reads the prompt index, and a replay must not re-run it on an old run.
        manifest = dict(MANIFEST, host="claude")
        _write_ours(self.review_root, manifest)
        with open(os.path.join(self.run_folder, "host-capabilities.json"), "w") as fh:
            json.dump({"capabilities": {hosts.USAGE_LEDGER: {"state": hosts.PROVEN}}}, fh)
        usage = os.path.join(self.run_folder, "usage.json")
        with open(usage, "w", encoding="utf-8") as fh:
            json.dump({"total": 7, "by_phase": {"unattributed": 7}}, fh)
        os.makedirs(os.path.join(self.run_folder, "_prompts"), exist_ok=True)
        with open(os.path.join(self.run_folder, "_prompts", "index.json"), "w") as fh:
            json.dump({"review-A:B-SEC": "~" + "0" * 64 + ".txt"}, fh)
        with open(usage, "rb") as fh:
            before = fh.read()
        import scripts.collect_usage as collect_usage
        with mock.patch.object(collect_usage, "collect", side_effect=AssertionError("re-run")):
            _replay_into(self.review_root, self.run_folder, os.path.join(self.tmp.name, "out-u"))
        with open(usage, "rb") as fh:
            self.assertEqual(before, fh.read())


class ArchiveTrustTest(unittest.TestCase):
    """#3332: the scratch root is a new path, so the run's own stamp never
    verifies there. Without --trust-archive, replay re-binds it only after first
    contact's read-only assessment verified <review-root> with this machine's
    key; --trust-archive replays a foreign run, says so, and marks the report."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = tmp.name
        self.review_root = os.path.join(self.base, "review")
        os.makedirs(self.review_root)
        _write_ours(self.review_root, MANIFEST)
        self.run_folder = _run_folder(self.base)

    def _replay(self, name, trust=False, child=_fake_child):
        out = os.path.join(self.base, name)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            _replay_into(self.review_root, self.run_folder, out, trust=trust, child=child)
        with open(os.path.join(out, f"{TAG}-report.json"), encoding="utf-8") as fh:
            return json.load(fh), err.getvalue()

    def _foreign(self):
        # the stamp another machine's key made: well-formed, never ours
        with open(_mpath(self.review_root), encoding="utf-8") as fh:
            manifest = json.load(fh)
        manifest["stamp"] = "0" * 64
        with open(_mpath(self.review_root), "w", encoding="utf-8") as fh:
            json.dump(manifest, fh)

    def _refused(self, name):
        with _child() as child, self.assertRaises(SystemExit) as ctx, mock.patch("sys.stdout"):
            replay_report.replay(argparse.Namespace(
                repo=None, review_root=self.review_root, run_folder=self.run_folder,
                out_dir=os.path.join(self.base, name), manifest=_mpath(self.review_root),
                trust_archive=False))
        child.assert_not_called()
        return str(ctx.exception.code)

    def test_a_run_with_completed_at_replays_and_keeps_it_as_it_was(self):
        # #3367: #3328's replays depend on this. The key goes through a real stamped rewrite.
        with open(_mpath(self.review_root), encoding="utf-8") as fh:
            manifest = json.load(fh)
        manifest[run_manifest.COMPLETED_AT] = "2026-10-31T00:00:00Z"
        run_manifest._rewrite(self.review_root, manifest)
        with open(_mpath(self.review_root), "rb") as fh:
            before = fh.read()
        report, err = self._replay("out")
        self.assertNotIn("unverified_archive", report["meta"])
        self.assertNotIn("--trust-archive", err)
        with open(_mpath(self.review_root), "rb") as fh:
            self.assertEqual(before, fh.read())

    def test_a_replay_of_an_older_run_does_not_write_completed_at(self):
        with open(_mpath(self.review_root), "rb") as fh:
            before = fh.read()
        self.assertNotIn(b"completed_at", before)
        self._replay("out")
        with open(_mpath(self.review_root), "rb") as fh:
            self.assertEqual(before, fh.read())
        scratch = [os.path.join(folder, name) for folder, _d, names in os.walk(self.base)
                   for name in names if name == "run-manifest.json"]
        for path in scratch:
            with open(path, encoding="utf-8") as fh:
                self.assertNotIn("completed_at", fh.read(), path)

    def test_a_verified_run_replays_unmarked_and_silent(self):
        report, err = self._replay("out")
        self.assertNotIn("unverified_archive", report["meta"])
        self.assertNotIn("--trust-archive", err)

    def test_the_child_meets_a_scratch_root_its_first_contact_accepts(self):
        seen = []

        def child(cmd, cwd, capture_output, text, env):
            import scripts.first_contact as first_contact
            with mock.patch.dict(os.environ, env, clear=True):
                found = first_contact.assess_artifacts(cwd, read_only=True)
            seen.append((found.get("run-manifest.json") or {}).get("review_root") == cwd)
            return _fake_child(cmd, cwd, capture_output, text, env)

        for trust in (False, True):
            with self.subTest(trust=trust):
                self._replay("out-%s" % trust, trust=trust, child=child)
        self.assertEqual([True, True], seen)

    def test_an_unverified_run_refuses_without_the_flag_and_names_it(self):
        self._foreign()
        self.assertIn("--trust-archive", self._refused("foreign"))
        os.remove(os.path.join(self.review_root, ".panopticon", "owner.json"))
        self.assertIn("--trust-archive", self._refused("unmarked"))

    def test_a_manifest_other_than_the_verified_one_refuses(self):
        elsewhere = os.path.join(self.base, "elsewhere.json")
        with open(_mpath(self.review_root), encoding="utf-8") as fh:
            manifest = json.load(fh)
        manifest["security_mode"] = "standard"
        with open(elsewhere, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh)
        with _child() as child, self.assertRaises(SystemExit) as ctx, mock.patch("sys.stdout"):
            replay_report.replay(argparse.Namespace(
                repo=None, review_root=self.review_root, run_folder=self.run_folder,
                out_dir=os.path.join(self.base, "x"), manifest=elsewhere, trust_archive=False))
        child.assert_not_called()
        self.assertIn("--trust-archive", str(ctx.exception.code))

    def test_no_operator_key_refuses_and_creates_nothing(self):
        absent = os.path.join(self.base, "no-state")
        with mock.patch.dict(os.environ, {"PANOPTICON_STATE_DIR": absent}):
            self.assertIn("--trust-archive", self._refused("keyless"))
        self.assertFalse(os.path.lexists(absent))

    def test_trust_archive_replays_a_foreign_run_marked_and_says_so(self):
        self._foreign()
        report, err = self._replay("out", trust=True)
        self.assertIs(True, report["meta"]["unverified_archive"])
        self.assertIn("--trust-archive", err)
        self.assertIn("NOT verified", err)

    def test_the_operator_state_dir_is_never_written_and_trust_never_reads_it(self):
        from scripts import run_stamp
        operator = run_stamp.state_dir()
        key = os.path.join(operator, run_stamp.KEY_NAME)
        before = (os.stat(key).st_mtime_ns, os.stat(key).st_ino, sorted(os.listdir(operator)))
        self._replay("verified")
        self.assertEqual(before, (os.stat(key).st_mtime_ns, os.stat(key).st_ino,
                                  sorted(os.listdir(operator))))
        # --trust-archive never touches an operator dir: one with no key stays empty
        empty = os.path.join(self.base, "operator-empty")
        os.makedirs(empty)
        self._foreign()
        with mock.patch.dict(os.environ, {"PANOPTICON_STATE_DIR": empty}):
            self._replay("trusted", trust=True)
        self.assertEqual([], os.listdir(empty))

    def test_the_marker_is_a_declared_report_field(self):
        # meta is closed (additionalProperties: false): an undeclared marker
        # would fail every marked report's schema validation
        from scripts.synth import validate_schema
        doc = {"meta": {"timestamp": "t"}}
        plain = set(validate_schema.schema_errors(doc))
        self.assertEqual(plain, set(validate_schema.schema_errors(
            {"meta": {"timestamp": "t", "unverified_archive": True}})))
        self.assertNotEqual(plain, set(validate_schema.schema_errors(
            {"meta": {"timestamp": "t", "unverified_archive": False}})))

    def test_two_verified_replays_are_identical(self):
        self._replay("a")
        self._replay("b")
        with mock.patch("builtins.print"):
            self.assertEqual(0, replay_report.diff(argparse.Namespace(
                a=os.path.join(self.base, "a"), b=os.path.join(self.base, "b"), limit=50)))


class ScratchRootCopiesTest(unittest.TestCase):
    """#3332: the scratch root is COPIES. A linked `runs/<tag>` is refused by the
    artifact confinement, and the no-follow LOC count reads a symlink farm as 0
    lines -- a silent null health, not an error."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = os.path.realpath(tmp.name)
        self.review_root = os.path.join(self.base, "review")
        os.makedirs(os.path.join(self.review_root, "src"))
        with open(os.path.join(self.review_root, "src", "a.py"), "w", encoding="utf-8") as fh:
            fh.write("x = 1\n\ny = 2\nz = 3\n")
        os.symlink("a.py", os.path.join(self.review_root, "src", "alias.py"))
        os.makedirs(os.path.join(self.review_root, ".git"))
        self.run_folder = _run_folder(self.base)
        os.symlink("validate.json", os.path.join(self.run_folder, "linked.json"))
        self.scratch = os.path.join(self.base, "scratch")
        os.makedirs(self.scratch)
        self.root = replay_report._scratch_root(self.scratch, self.review_root, MANIFEST, TAG,
                                                self.run_folder)

    def test_the_run_folder_and_the_source_are_copied_never_linked(self):
        copied = os.path.join(self.root, ".panopticon", "runs", TAG)
        for path in (copied, os.path.join(self.root, "src")):
            with self.subTest(path=os.path.relpath(path, self.root)):
                self.assertFalse(os.path.islink(path))
                self.assertTrue(os.path.isdir(path))
        self.assertEqual(sorted(replay_report._listing(self.run_folder)),
                         sorted(replay_report._listing(copied)))
        # a link INSIDE a copied tree stays a link, never its target's bytes
        self.assertEqual("validate.json", os.readlink(os.path.join(copied, "linked.json")))
        self.assertEqual("a.py", os.readlink(os.path.join(self.root, "src", "alias.py")))
        self.assertFalse(os.path.lexists(os.path.join(self.root, ".git")))

    def test_the_loc_count_reads_the_source_through_the_copy(self):
        from scripts.synth import grading
        self.assertEqual(3, grading.nonblank_loc(self.root, [{"files": ["src/a.py"]}]))


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


@pytest.mark.parametrize(
    "suffix",
    [".json", "_part2.json", "-discarded.json", "-x0x.json",
     "-x0x-failures.json"],
)
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


@pytest.mark.parametrize(("suffix", "left", "right", "path"), [
    (".json", {"meta": {"timestamp": "first"}, "audit": {"timestamp": "first"}},
     {"meta": {"timestamp": "second"}, "audit": {"timestamp": "second"}},
     ".json.audit.timestamp"),
    ("_part2.json", {"timestamp": "first"}, {"timestamp": "second"},
     "_part2.json.timestamp"),
    ("-x0x.json", {"generated_at": "first", "timestamp": "first"},
     {"generated_at": "second", "timestamp": "second"},
     "-x0x.json.timestamp"),
])
def test_diff_reports_timestamp_outside_declared_mask(tmp_path, suffix, left, right, path):
    a = _out_dir(tmp_path, "a", "")
    b = _out_dir(tmp_path, "b", "")
    _write_report(a, suffix, left)
    _write_report(b, suffix, right)
    rc, lines = _diff(a, b)
    assert rc == 1
    assert any(path in line for line in lines)
    assert not any("meta.timestamp" in line or "generated_at" in line for line in lines)


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
