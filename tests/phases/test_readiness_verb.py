"""#1637 P10: `driver readiness` -- the compact preflight a host reads BEFORE
it launches anything.

Run-13's controller had no way to ask "is this machine able to run a review",
so it answered the question by reading long documents and searching another
host's plugin trees, and still started a run whose scanner image was absent.
The verb answers all of it in one document: where the guide is, which
sub-skills are installed and where, what the committed matrix looks like,
whether a previous run is resumable, which host CLIs are on PATH, whether the
scanner image is pullable, and what the last run measured about the host.

Three properties this file exists to pin, because each is a way the verb could
quietly become something else:

* it LAUNCHES NOTHING. `shutil.which` only -- the PATH shims below exit 97 and
  append to a log, and the log must stay empty.
* it WRITES NOTHING under the target. A preflight that leaves artifacts is a
  run.
* the exit code is the whole point -- `driver readiness && driver loop` -- so
  a gating row that fails must take it to 1, and an informational one must not.
"""
import contextlib
import io
import json
import os
import unittest
from unittest import mock

import scripts.driver as driver
import scripts.phases.readiness as readiness
from scripts import hosts

from tools.git_repo import make_git_repo


_READINESS = "scripts.phases.readiness"

GROUPS_YML = ("groups:\n"
              "  Core:\n    match: ['src/**']\n    panels: [COD]\n"
              "  Tests:\n    match: ['tests/**']\n    panels: [TST]\n")

FILES = {"src/app.py": "def f():\n    return 1\n",
         "src/util.py": "def g():\n    return 2\n",
         "tests/test_app.py": "def test_f():\n    assert True\n"}


class _Probe:
    def __init__(self, returncode):
        self.returncode, self.stdout, self.stderr = returncode, "", ""


def _docker_runner(*, daemon=0, image=0):
    def runner(cmd, **_kw):
        if list(cmd[:3]) == ["docker", "image", "inspect"]:
            return _Probe(image)
        return _Probe(daemon)
    return runner


class _VerbCase(unittest.TestCase):

    def _repo(self, groups_yml=None):
        return make_git_repo(test_case=self, files=dict(FILES),
                             groups_yml=groups_yml, branch="main",
                             user_email="t@t", user_name="t")

    def _run(self, *argv, daemon=0, image=0):
        """(exit_code, stdout) for `driver readiness ...`."""
        out = io.StringIO()
        with mock.patch(_READINESS + ".DOCKER_RUNNER",
                        _docker_runner(daemon=daemon, image=image)), \
                contextlib.redirect_stdout(out):
            code = driver.main(["readiness", *argv])
        return code, out.getvalue()

    def _json(self, *argv, **kw):
        code, text = self._run(*argv, "--json", **kw)
        return code, json.loads(text)


class TestTheUnreadyMachine(_VerbCase):
    """No committed matrix, and Docker up with the image absent -- run-13's own
    environment, plus the setup step it had never run."""

    def test_it_exits_1_and_every_failing_row_carries_its_remedy(self):
        d = self._repo()
        code, body = self._json(d, image=1)
        self.assertEqual(1, code)
        self.assertIs(False, body["ready"])
        self.assertIn("docker pull ghcr.io/panopticon-scanner/panopticon-tools"
                      ":latest", body["tools_image"]["remedy"])
        self.assertIn("--no-tools", body["tools_image"]["remedy"])
        self.assertIs(True, body["tools_image"]["docker"])
        self.assertIs(False, body["tools_image"]["image"])
        self.assertIn("run `driver setup`", body["matrix"]["detail"])
        self.assertIs(False, body["matrix"]["ok"])

    def test_the_image_remedy_is_the_phase_s_own_text_not_a_second_copy(self):
        d = self._repo()
        _code, body = self._json(d, image=1)
        self.assertEqual(readiness.IMAGE_REMEDY, body["tools_image"]["remedy"])

    def test_a_dead_daemon_is_gating_too(self):
        d = self._repo()
        code, body = self._json(d, daemon=1, image=1)
        self.assertEqual(1, code)
        self.assertIs(False, body["tools_image"]["docker"])
        self.assertIn("--no-tools", body["tools_image"]["remedy"])

    def test_the_human_table_names_every_row_and_ends_with_the_verdict(self):
        d = self._repo()
        code, text = self._run(d, image=1)
        self.assertEqual(1, code)
        for row in ("guide", "sub-skills", "matrix", "existing-run", "cli",
                    "tools-image", "capabilities"):
            with self.subTest(row=row):
                self.assertIn(row, text)
        self.assertIn("NOT READY", text)
        # One document, not a wall: one line per row plus a header and a
        # verdict.
        self.assertLessEqual(len(text.strip().splitlines()), 9)


class TestTheReadyMachine(_VerbCase):

    def _with_a_finished_run(self, d, tag="claude-standard-repo-20260915-abcd1234"):
        folder = os.path.join(d, ".panopticon", "runs", tag)
        os.makedirs(folder)
        with open(os.path.join(folder, "host-capabilities.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"schema_version": 1, "host": "claude",
                       "probed_at": "2026-09-15T00:00:00Z",
                       "capabilities": {c: {"state": hosts.PROVEN, "by": "fixture",
                                            "detail": "fixture"}
                                        for c in hosts.CAPABILITIES}}, fh)
        os.symlink(tag, os.path.join(d, ".panopticon", "runs", "latest"))
        return tag, folder

    def test_it_exits_0_and_the_counts_and_tag_are_right(self):
        d = self._repo(groups_yml=GROUPS_YML)
        tag, _folder = self._with_a_finished_run(d)
        code, body = self._json(d)
        self.assertEqual(0, code, json.dumps(body, indent=2))
        self.assertIs(True, body["ready"])
        self.assertEqual(2, body["matrix"]["groups"])
        self.assertEqual(2, body["matrix"]["code_files"])
        self.assertEqual(1, body["matrix"]["tests_files"])
        self.assertEqual(tag, body["existing_run"]["tag"])
        self.assertEqual(0, body["existing_run"]["pending"])

    def test_the_last_run_s_capabilities_are_read_back_not_re_probed(self):
        d = self._repo(groups_yml=GROUPS_YML)
        self._with_a_finished_run(d)
        _code, body = self._json(d)
        self.assertIs(True, body["capabilities"]["measured"])
        self.assertEqual("claude", body["capabilities"]["host"])
        self.assertEqual({c: hosts.PROVEN for c in hosts.CAPABILITIES},
                         body["capabilities"]["states"])

    def test_with_no_artifact_the_capabilities_row_says_so(self):
        d = self._repo(groups_yml=GROUPS_YML)
        _code, body = self._json(d)
        self.assertIs(False, body["capabilities"]["measured"])
        self.assertIn("not measured", body["capabilities"]["detail"])
        self.assertEqual({}, body["capabilities"]["states"])

    def test_a_checkpointed_run_reports_what_is_still_pending(self):
        d = self._repo(groups_yml=GROUPS_YML)
        _tag, folder = self._with_a_finished_run(d)
        done = os.path.join(folder, "findings-Core-COD.json")
        with open(done, "w", encoding="utf-8") as fh:
            json.dump({"findings": []}, fh)
        with open(os.path.join(folder, "dispatch-request.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"schema_version": 1, "run_id": "x", "checkpoint": "review",
                       "group": None,
                       "entries": [{"id": "a", "out_file": done},
                                   {"id": "b", "out_file": os.path.join(
                                       folder, "findings-Core-SEC.json")},
                                   {"id": "c", "out_file": os.path.join(
                                       folder, "findings-Tests-TST.json")}]}, fh)
        code, body = self._json(d)
        self.assertEqual(0, code)
        self.assertEqual("checkpoint", body["existing_run"]["status"])
        self.assertEqual(2, body["existing_run"]["pending"])

    def test_a_ready_machine_says_so_in_the_table_too(self):
        d = self._repo(groups_yml=GROUPS_YML)
        code, text = self._run(d)
        self.assertEqual(0, code)
        self.assertIn("READY", text)
        self.assertNotIn("NOT READY", text)


class TestItLaunchesNothingAndWritesNothing(_VerbCase):

    def _shims(self, names=("claude", "codex", "kimi", "gemini", "agy", "docker")):
        import tempfile
        bin_dir = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, bin_dir, ignore_errors=True)
        log = os.path.join(bin_dir, "launches.log")
        for name in names:
            path = os.path.join(bin_dir, name)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write('#!/bin/sh\necho "$0 $@" >> %s\nexit 97\n' % log)
            os.chmod(path, 0o755)
        return bin_dir, log

    def test_the_cli_row_is_which_only(self):
        """The shims exit 97 and append to a log. `which` finds them; running
        one would be recorded. The log must not exist."""
        d = self._repo(groups_yml=GROUPS_YML)
        bin_dir, log = self._shims()
        with mock.patch.dict(os.environ, {"PATH": bin_dir}):
            code, body = self._json(d)
        self.assertEqual(0, code)
        self.assertFalse(os.path.exists(log),
                         "driver readiness launched a binary: %s"
                         % (open(log).read() if os.path.exists(log) else ""))
        rows = {r["host"]: r for r in body["cli"]}
        self.assertEqual(sorted(rows), ["claude", "codex", "kimi"])
        for host, row in rows.items():
            with self.subTest(host=host):
                self.assertIs(True, row["on_path"])
                self.assertEqual(os.path.join(bin_dir, host), row["path"])

    def test_a_cli_that_is_absent_is_reported_and_is_not_gating(self):
        import tempfile
        d = self._repo(groups_yml=GROUPS_YML)
        with tempfile.TemporaryDirectory() as empty:
            with mock.patch.dict(os.environ, {"PATH": empty}):
                code, body = self._json(d)
        self.assertEqual(0, code)          # session mode needs no binary
        self.assertEqual([False, False, False],
                         [r["on_path"] for r in body["cli"]])

    def test_it_writes_nothing_under_the_target(self):
        d = self._repo(groups_yml=GROUPS_YML)
        before = self._tree(d)
        self._json(d, image=1)
        self.assertEqual(before, self._tree(d))

    @staticmethod
    def _tree(root):
        out = []
        for dirpath, dirnames, filenames in os.walk(root):
            if ".git" in dirnames:
                dirnames.remove(".git")
            for name in sorted(filenames):
                path = os.path.join(dirpath, name)
                out.append((os.path.relpath(path, root), os.path.getsize(path)))
        return sorted(out)


class TestTheSubSkillLookup(_VerbCase):

    def test_it_finds_a_sub_skill_in_a_host_s_plugin_tree_and_says_where(self):
        import tempfile
        d = self._repo(groups_yml=GROUPS_YML)
        home = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, home, ignore_errors=True)
        found = os.path.join(home, ".claude", "plugins", "marketplace",
                             "superpowers", "skills", "writing-plans")
        os.makedirs(found)
        with open(os.path.join(found, "SKILL.md"), "w", encoding="utf-8") as fh:
            fh.write("---\nname: writing-plans\n---\n")
        with mock.patch.dict(os.environ, {"HOME": home}):
            _code, body = self._json(d)
        rows = {r["name"]: r for r in body["sub_skills"]}
        self.assertEqual(sorted(rows), sorted(readiness.REQUIRED_SUB_SKILLS))
        self.assertEqual(os.path.join(found, "SKILL.md"),
                         rows["superpowers:writing-plans"]["found_at"])
        self.assertIsNone(
            rows["superpowers:verification-before-completion"]["found_at"])

    def test_it_reaches_the_plugin_cache_layout_that_actually_ships(self):
        """The measured layout on a Claude Code workstation:
        `~/.claude/plugins/cache/<marketplace>/superpowers/<version>/skills/
        <leaf>/`. Five directories below the root -- deep enough that a star
        ladder grown by guesswork stops one level short, which is exactly what
        the first cut of this lookup did."""
        import tempfile
        d = self._repo(groups_yml=GROUPS_YML)
        home = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, home, ignore_errors=True)
        for leaf in ("writing-plans", "subagent-driven-development",
                     "verification-before-completion"):
            found = os.path.join(home, ".claude", "plugins", "cache",
                                 "claude-plugins-official", "superpowers",
                                 "6.3.0", "skills", leaf)
            os.makedirs(found)
            with open(os.path.join(found, "SKILL.md"), "w", encoding="utf-8") as fh:
                fh.write("---\nname: %s\n---\n" % leaf)
        with mock.patch.dict(os.environ, {"HOME": home}):
            _code, body = self._json(d)
        self.assertEqual([], [r["name"] for r in body["sub_skills"]
                              if r["found_at"] is None])

    def test_a_missing_sub_skill_is_never_gating(self):
        import tempfile
        d = self._repo(groups_yml=GROUPS_YML)
        with tempfile.TemporaryDirectory() as home:
            with mock.patch.dict(os.environ, {"HOME": home}):
                code, body = self._json(d)
        self.assertEqual(0, code)
        self.assertEqual([None] * 3, [r["found_at"] for r in body["sub_skills"]])

    def test_the_roots_are_the_ones_skill_md_tells_a_host_about(self):
        """P02 wrote the roots down for a human; this verb searches them. One
        list, or the doc and the code send a host to different directories."""
        from test_skill_md import SKILL_ROOTS
        documented = {r.replace("…/superpowers/", "").rstrip("/")
                      for r in SKILL_ROOTS}
        self.assertEqual(documented, set(readiness.SUB_SKILL_ROOTS))


class TestTheGuideRow(_VerbCase):

    def test_it_names_the_guide_inside_this_install_and_it_exists(self):
        d = self._repo(groups_yml=GROUPS_YML)
        _code, body = self._json(d)
        self.assertEqual(hosts.guide_path(), body["guide"]["path"])
        self.assertIs(True, body["guide"]["exists"])

    def test_a_missing_guide_is_gating(self):
        d = self._repo(groups_yml=GROUPS_YML)
        with mock.patch.object(hosts, "guide_path",
                               return_value="/nowhere/PANOPTICON.md"):
            code, body = self._json(d)
        self.assertEqual(1, code)
        self.assertIs(False, body["guide"]["exists"])
        self.assertIn("reinstall", body["guide"]["detail"].lower())


class TestTheVerbIsWiredLikeRunAndLoop(_VerbCase):

    def test_it_takes_target_and_host_and_json_and_nothing_else(self):
        args = driver.build_parser().parse_args(
            ["readiness", "/tmp", "--host", "claude", "--json"])
        self.assertEqual("readiness", args.verb)
        self.assertEqual("/tmp", args.target)
        self.assertEqual("claude", args.host)
        self.assertIs(True, args.json)
        # Not a run: none of `run`'s flags are accepted here.
        for flag in ("--no-tools", "--reset", "--security", "--pr"):
            with self.subTest(flag=flag):
                with self.assertRaises(SystemExit):
                    with contextlib.redirect_stderr(io.StringIO()):
                        driver.build_parser().parse_args(
                            ["readiness", "/tmp", flag, "x"])

    def test_target_defaults_to_the_current_directory(self):
        args = driver.build_parser().parse_args(["readiness"])
        self.assertEqual(".", args.target)

    def test_the_selected_host_leads_the_cli_list(self):
        d = self._repo(groups_yml=GROUPS_YML)
        _code, body = self._json(d, "--host", "kimi")
        self.assertEqual("kimi", body["host"])
        self.assertEqual("kimi", body["cli"][0]["host"])
        self.assertIs(True, body["cli"][0]["selected"])


if __name__ == "__main__":
    unittest.main()
