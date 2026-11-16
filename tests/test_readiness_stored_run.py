"""#3671: `driver readiness` reads a stored run only when a run in THIS checkout wrote it.

Everything under `.panopticon/` is in the reviewed tree, so the target can commit it: a run
folder holding a posture with every control PROVEN, a `runs/latest` symlink to it, a finished
report, a manifest of its own. Read through `latest`, readiness printed that posture as this
run's ("every control this run relies on was verified, not assumed") and called the planted run
"complete" -- for a run `driver loop` would halt on at first contact, or never resume.

Every row that describes a stored run now reads the folder this checkout's own manifest names,
and nothing else. Real git repositories throughout: "committed into the target" is the threat.
"""
import contextlib
import io
import json
import os
import shutil
import subprocess
import unittest
from unittest import mock

import scripts.driver as driver
import scripts.phases.readiness as readiness
import scripts.phases.readiness_checks as readiness_checks
import scripts.phases.runio as runio
import scripts.phases.verify_tools as verify_tools
import scripts.run_manifest as run_manifest
import scripts.safe_git as safe_git
from scripts import hosts
from tests._test_helpers import hard_link_or_skip, our_manifest
from tests.phases.test_readiness_verb import _docker_runner
from tests.tools.git_repo import make_git_repo

FILES = {"src/app.py": "def f():\n    return 1\n", "README.md": "# x\n"}
MATRIX = "version: 1\ngroups:\n  Core:\n    match: ['src/**']\n    panels: [COD]\n"
# Strings that exist only in what the target planted. None may reach the output.
PLANTED_TAG = "zz-planted-run-7c1e"
PLANTED_NOTE = "PLANTED-DETAIL-9f3a"
PLANTED_FLAG = "--planted-schema-flag"
ROWS = ("existing-run", "capabilities", "tool-findings", "egress-proxy")


class _Case(unittest.TestCase):
    def setUp(self):
        self.root = make_git_repo(self, files=dict(FILES, **{"panopticon.yml": MATRIX}))
        self.pano = os.path.join(self.root, ".panopticon")
        self.runs = os.path.join(self.pano, "runs")

    # -- what a run of this checkout leaves ----------------------------------------------

    def _our_run(self, host="claude", posture=True, flags=None, tools_ran=False):
        """A run this checkout's driver wrote: a stamped, untracked manifest and its folder."""
        manifest = our_manifest(self.root, run_manifest.build_manifest(
            target=self.root, review_root=self.root, host=host, security_mode="standard",
            flags=dict({"max_verify": None}, **(flags or {}))))
        run_manifest.write_manifest(self.root, manifest)
        tag = run_manifest.run_tag(manifest)
        folder = os.path.join(self.runs, tag)
        os.makedirs(folder)
        if posture:
            self._envelope(folder, host, note="fixture")
        if tools_ran:
            with open(os.path.join(folder, "tools-ran.json"), "w", encoding="utf-8") as fh:
                json.dump({"ran": True, "run_id": manifest["run_id"]}, fh)
        return tag

    @staticmethod
    def _envelope(folder, host, note, flag="--json-schema"):
        with open(os.path.join(folder, runio.HOST_CAPABILITIES), "w", encoding="utf-8") as fh:
            json.dump({"schema_version": 1, "host": host, "probed_at": "2026-09-15T00:00:00Z",
                       "capabilities": {name: {"state": hosts.PROVEN, "by": note, "detail": note}
                                        for name in hosts.CAPABILITIES},
                       hosts.CLI_FLAGS: {hosts.OUTPUT_SCHEMA: {
                           "advertised": True, "flag": flag,
                           hosts.SHAPE: hosts.SHAPE_PROVEN, hosts.SHAPE_DETAIL: note}}}, fh)

    # -- what a target can commit ---------------------------------------------------------

    def _plant(self, tag=PLANTED_TAG, host="claude", latest=True, complete=False, manifest=None,
               commit=True):
        """A run folder the TARGET ships: every control PROVEN on `host`, `runs/latest`
        pointing at it, optionally a finished report and a manifest. Committed with
        `git add -f`, past the `.panopticon/` ignore, unless `commit` is off."""
        folder = os.path.join(self.runs, tag)
        os.makedirs(folder)
        self._envelope(folder, host, note=PLANTED_NOTE, flag=PLANTED_FLAG)
        with open(os.path.join(folder, "tools-ran.json"), "w", encoding="utf-8") as fh:
            json.dump({"ran": True, "run_id": "planted"}, fh)
        if latest:
            link = os.path.join(self.runs, "latest")
            if os.path.lexists(link):
                os.unlink(link)
            os.symlink(tag, link)
        if complete:
            with open(os.path.join(self.pano, "%s-report.json" % tag), "w", encoding="utf-8") as fh:
                json.dump({"meta": {}, "findings": []}, fh)
        if manifest is not None:
            with open(os.path.join(self.pano, "run-manifest.json"), "w", encoding="utf-8") as fh:
                json.dump(manifest, fh)
        if commit:
            paths = [os.path.join(".panopticon", "runs", tag)]
            paths += [os.path.join(".panopticon", "runs", "latest")] if latest else []
            paths += [os.path.join(".panopticon", "%s-report.json" % tag)] if complete else []
            paths += [os.path.join(".panopticon", "run-manifest.json")] if manifest is not None else []
            self._git("add", "-f", "--", *paths)
            self._git("commit", "-q", "-m", "ship a run folder")
        return folder

    def _git(self, *argv):
        subprocess.run(["git", "-C", self.root, *argv], check=True, capture_output=True)

    def _plant_under_another_case(self, directory, manifest_name, complete=True):
        """The whole planted tree, committed under a spelling that differs only in case:
        `directory` for `.panopticon`, `manifest_name` for `run-manifest.json`. The manifest
        forges this checkout's path, so being tracked is all that gives it away.

        On a case-insensitive filesystem those ARE the files readiness reads. On a
        case-sensitive one they are not, so the same bytes are also put at the exact
        spelling, untracked: either way the files read are the target's, and the only
        tracked copy is the one spelled differently."""
        manifest = self._planted_manifest(self.root)
        tag = run_manifest.run_tag(manifest)
        there = os.path.join(self.root, directory)
        folder = os.path.join(there, "runs", tag)
        os.makedirs(folder)
        self._envelope(folder, "claude", note=PLANTED_NOTE, flag=PLANTED_FLAG)
        os.symlink(tag, os.path.join(there, "runs", "latest"))
        if complete:
            with open(os.path.join(there, "%s-report.json" % tag), "w", encoding="utf-8") as fh:
                json.dump({"meta": {}, "findings": []}, fh)
        with open(os.path.join(there, manifest_name), "w", encoding="utf-8") as fh:
            json.dump(manifest, fh)
        self._git("add", "-f", "--", directory)
        self._git("commit", "-q", "-m", "ship a run folder, spelled another way")
        tracked = subprocess.run(["git", "-C", self.root, "ls-files", "--", directory],
                                 check=True, capture_output=True, text=True).stdout.split()
        self.assertIn("%s/%s" % (directory, manifest_name), tracked)
        if not os.path.isdir(self.pano):                       # a case-sensitive filesystem
            shutil.copytree(there, self.pano, symlinks=True)
        exact = os.path.join(self.pano, "run-manifest.json")
        if not os.path.isfile(exact):
            shutil.copyfile(os.path.join(there, manifest_name), exact)
        self.assertTrue(os.path.isfile(exact))
        return tag

    def _planted_manifest(self, review_root, run_id="deadbeef0000", host="claude", **more):
        return dict({"schema_version": 1, "run_id": run_id, "host": host,
                     "review_root": review_root, "created": "2026-09-15T00:00:00Z",
                     "security_mode": "standard", "flags": {"online": True, "tools": True}}, **more)

    # -- the verb -------------------------------------------------------------------------

    def _readiness(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(readiness_checks, "DOCKER_RUNNER", _docker_runner()), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = driver.main(["readiness", self.root, *argv])
        self.assertIn(code, (0, 1), err.getvalue())
        return out.getvalue()

    def _both(self, *argv):
        """(the `--json` document, the table) for one invocation. The two must agree: each
        row's detail, as the document gives it, is on that row's line of the table."""
        doc = json.loads(self._readiness("--json", *argv))
        table = self._readiness(*argv)
        details = {"existing-run": doc["existing_run"]["detail"],
                   "capabilities": doc["capabilities"]["detail"],
                   "tool-findings": doc["run_plan"]["tool-findings"]["detail"],
                   "egress-proxy": doc["egress_proxy"]["detail"]}
        for label in ROWS:
            line, = [ln for ln in table.splitlines() if ln.split()[:1] == [label]]
            self.assertIn(details[label], line, label)
        return doc, table

    def _assert_nothing_stored_is_shown(self, doc, table, planted=(PLANTED_TAG,)):
        """No row vouches for the stored run, and nothing the target wrote is echoed."""
        self.assertEqual({"measured": False, "host": None, "states": {}, "unproven": []},
                         {key: doc["capabilities"][key]
                          for key in ("measured", "host", "states", "unproven")})
        self.assertIn("not measured", doc["capabilities"]["detail"])
        self.assertEqual({"tag": None, "status": "none", "pending": 0},
                         {key: doc["existing_run"][key] for key in ("tag", "status", "pending")})
        self.assertIsNone(doc["run_plan"]["tool-findings"]["count"])
        self.assertIn("not known until the tools phase runs",
                      doc["run_plan"]["tool-findings"]["detail"])
        self.assertEqual("skip", doc["egress_proxy"]["level"])
        for text in (json.dumps(doc), table):
            self.assertNotIn("PROVEN", text)
            self.assertNotIn("verified, not assumed", text)
            for word in (PLANTED_NOTE, PLANTED_FLAG, "complete:") + tuple(planted):
                self.assertNotIn(word, text)


class TestARunOfThisCheckoutIsRead(_Case):
    """The control: everything the other classes must not see is really there to be seen."""

    def test_its_posture_its_status_its_scan_and_its_flags_are_all_read(self):
        tag = self._our_run(flags={"online": True, "tools": True}, tools_ran=True)
        with mock.patch.object(verify_tools, "_tool_verify_queue", return_value=[("q", {})] * 3):
            doc, table = self._both()
        self.assertIs(True, doc["capabilities"]["measured"])
        self.assertEqual("claude", doc["capabilities"]["host"])
        self.assertIn("all measured and PROVEN", table)
        self.assertEqual((tag, "started"),
                         (doc["existing_run"]["tag"], doc["existing_run"]["status"]))
        self.assertEqual(3, doc["run_plan"]["tool-findings"]["count"])
        self.assertNotEqual("skip", doc["egress_proxy"]["level"])     # the run asked for --online
        self.assertEqual(("claude", "manifest"), (doc["host"], doc["selected_from"]))

    def test_a_finished_run_of_this_checkout_reads_as_complete(self):
        tag = self._our_run()
        with open(os.path.join(self.pano, "%s-report.json" % tag), "w", encoding="utf-8") as fh:
            json.dump({}, fh)
        doc, _table = self._both()
        self.assertEqual((tag, "complete"),
                         (doc["existing_run"]["tag"], doc["existing_run"]["status"]))

    def test_no_latest_symlink_is_needed(self):
        # The manifest names the folder. `latest` is never what decides.
        tag = self._our_run()
        self.assertFalse(os.path.lexists(os.path.join(self.runs, "latest")))
        doc, _table = self._both()
        self.assertEqual(tag, doc["existing_run"]["tag"])
        self.assertIs(True, doc["capabilities"]["measured"])


class TestAPlantedRunFolderIsNobodysRun(_Case):
    """One test per condition: the manifest loads, it is not foreign, and its tag is the
    folder's. Each reads as measured, or as a run, without that condition."""

    def test_a_folder_with_no_manifest(self):
        # The issue's reproduction, second half: `latest` and a PROVEN envelope, no manifest.
        self._plant(complete=True)
        doc, table = self._both()
        self._assert_nothing_stored_is_shown(doc, table)
        self.assertEqual(readiness.NOT_MEASURED_NOT_THIS_RUN, doc["capabilities"]["detail"])
        self.assertEqual(readiness.NO_RUN_OF_THIS_CHECKOUT, doc["existing_run"]["detail"])
        self.assertEqual(("claude", "default"), (doc["host"], doc["selected_from"]))

    def test_a_planted_finished_run_does_not_read_as_complete(self):
        # An operator who reads "complete" may skip the run.
        self._plant(complete=True)
        self.assertTrue(os.path.isfile(os.path.join(self.pano, "%s-report.json" % PLANTED_TAG)))
        doc, table = self._both()
        self.assertEqual("none", doc["existing_run"]["status"])
        self.assertIsNone(doc["existing_run"]["tag"])
        line, = [ln for ln in table.splitlines() if ln.split()[:1] == ["existing-run"]]
        self.assertIn("no run of this checkout found", line)
        self.assertNotIn("complete", line)
        self.assertNotIn(PLANTED_TAG, table)

    def test_a_folder_with_a_committed_manifest_stamped_for_another_checkout(self):
        # The issue's reproduction, first half: a foreign manifest, `review_root` elsewhere.
        manifest = self._planted_manifest("/somewhere/else")
        tag = run_manifest.run_tag(manifest)
        self._plant(tag=tag, complete=True, manifest=manifest)
        doc, table = self._both()
        self._assert_nothing_stored_is_shown(doc, table, planted=(tag, "deadbeef"))
        self.assertEqual(("claude", "default"), (doc["host"], doc["selected_from"]))

    def test_a_folder_with_a_committed_manifest_that_forges_this_checkouts_path(self):
        # A checkout path is public in CI, so the stamp can be forged. Being git-tracked
        # cannot: a manifest a driver wrote is never committed.
        manifest = self._planted_manifest(self.root)
        tag = run_manifest.run_tag(manifest)
        self._plant(tag=tag, complete=True, manifest=manifest)
        self.assertEqual(tag, run_manifest.run_tag(run_manifest.load_manifest(self.root)))
        doc, table = self._both()
        self._assert_nothing_stored_is_shown(doc, table, planted=(tag, "deadbeef"))

    def test_an_untracked_manifest_stamped_for_another_checkout(self):
        # A tree copied from another machine, run folder and manifest and all.
        manifest = self._planted_manifest("/somewhere/else")
        tag = run_manifest.run_tag(manifest)
        self._plant(tag=tag, complete=True, manifest=manifest, commit=False)
        doc, table = self._both()
        self._assert_nothing_stored_is_shown(doc, table, planted=(tag, "deadbeef"))

    def test_a_committed_manifest_whose_file_name_differs_only_in_case(self):
        # #3671 F1. A git pathspec is case-sensitive; APFS and NTFS are not. Asked for the
        # exact spelling, git said "no such tracked path" about the very file being read.
        tag = self._plant_under_another_case(".panopticon", "RUN-MANIFEST.json")
        manifest_file = run_manifest.manifest_path(self.root)
        self.assertTrue(runio._manifest_committed(self.root, manifest_file))
        self.assertIsNone(readiness._trusted_manifest(self.root))
        doc, table = self._both()
        self._assert_nothing_stored_is_shown(doc, table, planted=(tag, "deadbeef"))
        self.assertEqual(readiness.NOT_MEASURED_NOT_THIS_RUN, doc["capabilities"]["detail"])
        self.assertEqual(readiness.NO_RUN_OF_THIS_CHECKOUT, doc["existing_run"]["detail"])
        self.assertEqual(("claude", "default"), (doc["host"], doc["selected_from"]))

    def test_a_committed_manifest_whose_directory_differs_only_in_case(self):
        tag = self._plant_under_another_case(".Panopticon", "run-manifest.json")
        self.assertTrue(runio._manifest_committed(self.root, run_manifest.manifest_path(self.root)))
        self.assertIsNone(readiness._trusted_manifest(self.root))
        doc, table = self._both()
        self._assert_nothing_stored_is_shown(doc, table, planted=(tag, "deadbeef"))
        self.assertEqual(readiness.NOT_MEASURED_NOT_THIS_RUN, doc["capabilities"]["detail"])
        self.assertEqual(readiness.NO_RUN_OF_THIS_CHECKOUT, doc["existing_run"]["detail"])

    def test_an_untracked_manifest_is_still_untracked_whatever_else_is_committed(self):
        # The control for the two above: the case-blind question does not call our own,
        # untracked manifest tracked because other files of the tree are.
        self._our_run()
        self.assertFalse(runio._manifest_committed(self.root, run_manifest.manifest_path(self.root)))
        self._plant()                                        # tracked files beside it
        self.assertFalse(runio._manifest_committed(self.root, run_manifest.manifest_path(self.root)))
        self.assertIsNotNone(readiness._trusted_manifest(self.root))

    def test_a_planted_host_does_not_become_the_host_the_document_is_about(self):
        manifest = self._planted_manifest(self.root, host="kimi")
        self._plant(tag=run_manifest.run_tag(manifest), host="kimi", manifest=manifest)
        doc, _table = self._both()
        self.assertEqual(("claude", "default"), (doc["host"], doc["selected_from"]))
        self.assertIs(False, doc["capabilities"]["measured"])


class TestACommittedManifestUnderAnotherName(_Case):
    """#3684. `:(icase)` folds ASCII only; a filesystem folds more. APFS reads a long s
    (U+017F) as `s`, so a committed `run-manife\u017ft.json` was the manifest readiness read
    and git called it untracked. The filesystem is asked instead: a path git tracks in the
    manifest's directory that is the same file (device and inode) makes it committed."""

    LONG_S = "run-manife\u017ft.json"

    def _commit_beside(self, name, manifest, directory=".panopticon"):
        there = os.path.join(self.root, directory)
        os.makedirs(there, exist_ok=True)
        with open(os.path.join(there, name), "w", encoding="utf-8") as fh:
            json.dump(manifest, fh)
        self._git("add", "-f", "--", os.path.join(directory, name))
        self._git("commit", "-q", "-m", "ship a manifest under another name")
        return os.path.join(there, name)

    def _planted(self):
        manifest = self._planted_manifest(self.root)          # forges this checkout's path
        tag = run_manifest.run_tag(manifest)
        self._plant(tag=tag, complete=True)
        return manifest, tag

    def test_a_name_the_filesystem_folds_onto_ours(self):
        manifest, tag = self._planted()
        self._commit_beside(self.LONG_S, manifest)
        exact = run_manifest.manifest_path(self.root)
        if not os.path.isfile(exact):
            # This filesystem keeps the two names apart, so the committed file is another
            # file. A manifest of ours beside it is still ours, and still untracked.
            self._our_run()
            self.assertFalse(runio._manifest_committed(self.root, exact))
            self.assertIsNotNone(readiness._trusted_manifest(self.root))
            return
        self.assertTrue(runio._manifest_committed(self.root, exact))
        self.assertIsNone(readiness._trusted_manifest(self.root))
        doc, table = self._both()
        self._assert_nothing_stored_is_shown(doc, table, planted=(tag, "deadbeef"))
        self.assertEqual(readiness.NOT_MEASURED_NOT_THIS_RUN, doc["capabilities"]["detail"])
        self.assertEqual(readiness.NO_RUN_OF_THIS_CHECKOUT, doc["existing_run"]["detail"])
        self.assertEqual(("claude", "default"), (doc["host"], doc["selected_from"]))

    def test_a_hard_link_to_a_committed_file_is_that_file(self):
        # One file under two names, on any filesystem: what a fold is, without needing one.
        manifest, tag = self._planted()
        shipped = self._commit_beside("shipped.json", manifest)
        exact = hard_link_or_skip(shipped, run_manifest.manifest_path(self.root))
        self.assertTrue(runio._manifest_committed(self.root, exact))
        self.assertIsNone(readiness._trusted_manifest(self.root))
        doc, table = self._both()
        self._assert_nothing_stored_is_shown(doc, table, planted=(tag, "deadbeef"))

    def test_the_same_at_the_review_root_and_under_a_directory_spelled_in_another_case(self):
        # The listing is of the manifest's directory, under any case, or of the root.
        shipped = self._commit_beside("shipped.json", {}, directory=".")
        at_root = hard_link_or_skip(shipped, os.path.join(self.root, "manifest.json"))
        self.assertTrue(runio._manifest_committed(self.root, at_root))
        os.unlink(at_root)
        with open(at_root, "w", encoding="utf-8") as fh:
            fh.write("{}")
        self.assertFalse(runio._manifest_committed(self.root, at_root))
        asked = self._asked(at_root)
        self.assertEqual(["ls-files", "-z", "--", ":(icase)."], asked[-1][0])
        self._our_run()
        asked = self._asked(run_manifest.manifest_path(self.root))
        self.assertEqual([(["ls-files", "--error-unmatch", "--",
                            ":(icase).panopticon/run-manifest.json"], 30),
                          (["ls-files", "-z", "--", ":(icase).panopticon"], 30)], asked)

    def _asked(self, manifest_file):
        asked = []
        real = safe_git.probe

        def probe(target, args, **kw):
            asked.append((list(args), kw.get("timeout")))
            return real(target, args, **kw)

        with mock.patch.object(safe_git, "probe", side_effect=probe):
            runio._manifest_committed(self.root, manifest_file)
        return asked

    def test_a_committed_symlink_that_points_at_our_manifest_is_not_our_manifest(self):
        # `lstat`, never `stat`: the link is another directory entry. Followed, any tracked
        # link to an operator's own manifest would make that manifest read as committed.
        self._our_run()
        os.symlink("run-manifest.json", os.path.join(self.pano, "alias.json"))
        self._git("add", "-f", "--", ".panopticon/alias.json")
        self._git("commit", "-q", "-m", "a link to the manifest")
        self.assertFalse(runio._manifest_committed(self.root, run_manifest.manifest_path(self.root)))
        self.assertIsNotNone(readiness._trusted_manifest(self.root))

    def test_a_tracked_path_that_is_not_on_disk_is_not_our_manifest(self):
        self._our_run()
        folder = self._plant()
        shutil.rmtree(folder)                                  # tracked, and gone
        os.unlink(os.path.join(self.runs, "latest"))
        with open(folder, "w", encoding="utf-8") as fh:        # ...and a file where its
            fh.write("x")                                      # directory was: ENOTDIR
        self.assertFalse(runio._manifest_committed(self.root, run_manifest.manifest_path(self.root)))

    def test_more_tracked_paths_than_the_cap_reads_as_committed(self):
        self._our_run()
        self._plant()
        tracked = subprocess.run(["git", "-C", self.root, "ls-files", "--", ".panopticon"],
                                 check=True, capture_output=True, text=True).stdout.split()
        self.assertEqual(3, len(tracked))
        exact = run_manifest.manifest_path(self.root)
        with mock.patch.object(runio, "_TRACKED_BESIDE_MAX", 3):
            self.assertFalse(runio._manifest_committed(self.root, exact))
        with mock.patch.object(runio, "_TRACKED_BESIDE_MAX", 2):
            self.assertTrue(runio._manifest_committed(self.root, exact))
            self.assertIsNone(readiness._trusted_manifest(self.root))
        self.assertEqual(4096, runio._TRACKED_BESIDE_MAX)

    def test_a_path_that_cannot_be_stat_ed_reads_as_committed(self):
        self._our_run()
        self._plant()
        exact = run_manifest.manifest_path(self.root)
        real = os.lstat
        for refused in ("a tracked path", "the manifest"):
            def lstat(path, *args, _refused=refused, **kw):
                path = os.fspath(path)
                if _refused == "the manifest" and path == exact:
                    raise FileNotFoundError(2, "gone", path)
                if _refused == "a tracked path" and path.startswith(self.runs + os.sep):
                    raise PermissionError(13, "refused", path)
                return real(path, *args, **kw)

            with self.subTest(refused=refused), mock.patch.object(runio.os, "lstat", lstat):
                self.assertTrue(runio._manifest_committed(self.root, exact))

    def test_the_same_inode_number_on_another_device_is_another_file(self):
        self._our_run()
        self._plant()
        exact = run_manifest.manifest_path(self.root)
        ours, real = os.lstat(exact), os.lstat

        def lstat(path, *args, **kw):
            info = real(path, *args, **kw)
            if os.fspath(path).startswith(self.runs + os.sep):   # a tracked path: our inode
                fields = list(info)                             # number, on another device
                fields[1], fields[2] = ours.st_ino, ours.st_dev + 1
                return os.stat_result(fields)
            return info

        with mock.patch.object(runio.os, "lstat", lstat):
            self.assertFalse(runio._manifest_committed(self.root, exact))

    def test_a_listing_git_cannot_give_is_an_error_not_a_verdict(self):
        self._our_run()
        exact = run_manifest.manifest_path(self.root)
        real = safe_git.probe
        failing = mock.Mock(returncode=2, stdout="", stderr="boom")

        def probe(target, args, **kw):
            return failing if "-z" in args else real(target, args, **kw)

        with mock.patch.object(safe_git, "probe", side_effect=probe), \
                self.assertRaises(runio.DriverError) as caught:
            runio._manifest_committed(self.root, exact)
        self.assertIn("git check failed (exit 2): boom", str(caught.exception))
        for failure in (OSError("no git"), subprocess.TimeoutExpired("git", 30)):
            def probe(target, args, _failure=failure, **kw):
                if "-z" in args:
                    raise _failure
                return real(target, args, **kw)

            with self.subTest(failure=failure), \
                    mock.patch.object(safe_git, "probe", side_effect=probe), \
                    self.assertRaises(runio.DriverError):
                runio._manifest_committed(self.root, exact)


class TestTheFolderIsTheOneTheManifestNames(_Case):
    """`runs/latest` is a symlink in the reviewed tree. It never decides which folder is read."""

    def test_latest_pointed_at_a_planted_folder_is_not_followed(self):
        tag = self._our_run(posture=False)
        self._plant(complete=True)                           # `latest` -> the planted folder
        self.assertEqual(PLANTED_TAG, os.readlink(os.path.join(self.runs, "latest")))
        doc, table = self._both()
        # Our run, as it is: started, and not yet measured.
        self.assertEqual((tag, "started"),
                         (doc["existing_run"]["tag"], doc["existing_run"]["status"]))
        self.assertIs(False, doc["capabilities"]["measured"])
        self.assertEqual(readiness.NOT_MEASURED, doc["capabilities"]["detail"])
        self.assertIsNone(doc["run_plan"]["tool-findings"]["count"])
        for text in (json.dumps(doc), table):
            for word in ("PROVEN", PLANTED_TAG, PLANTED_NOTE, PLANTED_FLAG, "complete:"):
                self.assertNotIn(word, text)

    def test_our_own_posture_is_read_past_a_planted_latest(self):
        self._our_run()
        self._plant(host="agy")
        doc, table = self._both()
        self.assertIs(True, doc["capabilities"]["measured"])
        self.assertEqual("claude", doc["capabilities"]["host"])
        self.assertNotIn(PLANTED_NOTE, table)
        self.assertNotIn(PLANTED_FLAG, table)

    def test_our_manifest_with_its_folder_gone_is_no_run_to_resume(self):
        tag = self._our_run()
        shutil.rmtree(os.path.join(self.runs, tag))
        doc, table = self._both()
        self.assertEqual({"tag": None, "status": "none", "pending": 0},
                         {key: doc["existing_run"][key] for key in ("tag", "status", "pending")})
        self.assertEqual(readiness.OUR_RUN_FOLDER_MISSING, doc["existing_run"]["detail"])
        self.assertIs(False, doc["capabilities"]["measured"])
        self.assertEqual(readiness.NOT_MEASURED, doc["capabilities"]["detail"])
        # ...and it is said the same way whatever else the tree holds: the folder that is
        # missing is ours, so "not one a run here wrote" would be the wrong thing to say.
        self._plant(complete=True)
        doc, table = self._both()
        self.assertEqual(("none", readiness.OUR_RUN_FOLDER_MISSING),
                         (doc["existing_run"]["status"], doc["existing_run"]["detail"]))
        self.assertNotIn(PLANTED_TAG, table)
        self.assertNotIn("complete", table.lower().split("existing-run", 1)[1].splitlines()[0])

    def test_a_folder_one_run_id_away_from_ours_is_not_ours(self):
        tag = self._our_run(posture=False)
        near = tag[:-8] + ("0" * 8 if not tag.endswith("0" * 8) else "1" * 8)
        self._plant(tag=near, complete=True)
        doc, table = self._both()
        self.assertEqual(tag, doc["existing_run"]["tag"])
        self.assertEqual("started", doc["existing_run"]["status"])
        self.assertIs(False, doc["capabilities"]["measured"])
        self.assertNotIn(near, json.dumps(doc) + table)


class TestAnotherHostsRunAndAResetRun(_Case):
    """The run this checkout stores is still not THIS run when the document is about another
    host, or when `--reset` is about to discard it (#3668, and the three rows it left)."""

    def test_another_host_reads_none_of_the_stored_runs_rows(self):
        tag = self._our_run(flags={"online": True, "tools": True}, tools_ran=True)
        with mock.patch.object(verify_tools, "_tool_verify_queue") as queue:
            doc, table = self._both("--host", "agy")
        queue.assert_not_called()
        self.assertEqual(readiness.NOT_MEASURED_ON_HOST % "agy", doc["capabilities"]["detail"])
        self.assertIsNone(doc["run_plan"]["tool-findings"]["count"])
        self.assertEqual("skip", doc["egress_proxy"]["level"])
        self.assertNotIn("PROVEN", table)
        # The run is still this checkout's, and the row that describes it still does.
        self.assertEqual(tag, doc["existing_run"]["tag"])

    def test_a_bare_invocation_holds_the_envelope_to_the_manifests_host(self):
        # No `--host`: the document is about the manifest's host. A posture in that run's
        # folder that says it was measured on another host is not that host's posture.
        tag = self._our_run(host="agy", posture=False)
        self._envelope(os.path.join(self.runs, tag), "claude", note="fixture")
        doc, table = self._both()
        self.assertEqual(("agy", "manifest"), (doc["host"], doc["selected_from"]))
        self.assertIs(False, doc["capabilities"]["measured"])
        self.assertEqual(readiness.NOT_MEASURED_ON_HOST % "agy", doc["capabilities"]["detail"])
        self.assertNotIn("PROVEN", table)

    def test_reset_reads_none_of_the_stored_runs_rows(self):
        tag = self._our_run(flags={"online": True, "tools": True}, tools_ran=True)
        with mock.patch.object(verify_tools, "_tool_verify_queue") as queue:
            doc, table = self._both("--reset")
        queue.assert_not_called()
        self.assertEqual(readiness.NOT_MEASURED_AFTER_RESET, doc["capabilities"]["detail"])
        self.assertIsNone(doc["run_plan"]["tool-findings"]["count"])
        self.assertIn("not known until the tools phase runs",
                      doc["run_plan"]["tool-findings"]["detail"])
        self.assertEqual("skip", doc["egress_proxy"]["level"])
        self.assertNotIn("PROVEN", table)
        self.assertEqual(tag, doc["existing_run"]["tag"])       # what --reset would discard

    def test_reset_resolves_the_host_the_loop_would(self):
        # `driver loop --reset` mints the run from argv: the outgoing manifest's host does
        # not steer it. Readiness named the outgoing host.
        self._our_run(host="agy")
        self.assertEqual(("agy", "manifest"), self._host())
        self.assertEqual(("claude", "default"), self._host("--reset"))
        self.assertEqual(runio.resolve_host(None, self.root, True), self._host("--reset"))
        self.assertEqual(("agy", "--host"), self._host("--reset", "--host", "agy"))

    def test_an_explicit_online_flag_is_still_this_runs_own(self):
        # The flags given now describe this run, whatever the stored one asked for.
        self._our_run()
        self.assertEqual("skip", self._both()[0]["egress_proxy"]["level"])   # stored: not online
        for argv in (("--online", "--tools"), ("--reset", "--online", "--tools")):
            with self.subTest(argv=argv):
                doc, _table = self._both(*argv)
                self.assertNotEqual("skip", doc["egress_proxy"]["level"])

    def _host(self, *argv):
        doc = json.loads(self._readiness("--json", *argv))
        return doc["host"], doc["selected_from"]


class TestTheRowsHelpers(_Case):
    def test_nothing_stored_is_plain_not_measured_in_every_form(self):
        for argv in ((), ("--reset",), ("--host", "agy"), ("--host", "agy", "--reset")):
            with self.subTest(argv=argv):
                doc, _table = self._both(*argv)
                self.assertEqual(readiness.NOT_MEASURED, doc["capabilities"]["detail"])
                self.assertEqual("none -- no previous run in this tree",
                                 doc["existing_run"]["detail"])

    def test_a_manifest_that_names_no_host_is_the_default_hosts(self):
        manifest = {"run_id": "abcd1234", "review_root": self.root}
        self.assertEqual((manifest, None), readiness._own_run(manifest, "claude", False))
        self.assertEqual((None, readiness.NOT_MEASURED_ON_HOST % "agy"),
                         readiness._own_run(manifest, "agy", False))
        self.assertEqual((None, readiness.NOT_MEASURED_AFTER_RESET),
                         readiness._own_run(manifest, "claude", True))
        self.assertEqual((None, readiness.NOT_MEASURED_NOT_THIS_RUN),
                         readiness._own_run(None, "claude", False))

    def test_the_row_never_raises_on_something_that_is_not_a_manifest(self):
        for own in (None, {}, "claude", ["x"], 7):
            with self.subTest(own=own):
                row = readiness._capabilities_row(self.root, "claude", own)
                self.assertIs(False, row["measured"])


if __name__ == "__main__":
    unittest.main()
