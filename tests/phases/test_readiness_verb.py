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


def _which(found):
    """Stub `shutil.which` -- LOOKUP only, so a test can state "this binary is
    here" without a file on disk and without any possibility of a launch."""
    return mock.patch("shutil.which", side_effect=lambda name, *a, **k: found.get(name))


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
        # F3: a run folder with nothing pending is `started`, never `none` --
        # `none` means "no run in this tree", and a --json consumer keying on
        # `status` alone must be able to tell the two apart.
        self.assertEqual("started", body["existing_run"]["status"])

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

    def test_every_cli_is_reported_absent_and_only_the_selected_one_gates(self):
        """An empty PATH. All three rows report `on_path: false`; only the
        host this invocation resolved to carries a remedy, and only it moves
        the exit code (fix round 2 -- a bare invocation resolves one, so this
        case exits 1 now where round 1 exited 0)."""
        import tempfile
        d = self._repo(groups_yml=GROUPS_YML)
        with tempfile.TemporaryDirectory() as empty:
            with mock.patch.dict(os.environ, {"PATH": empty}):
                code, body = self._json(d)
        self.assertEqual(1, code)
        self.assertEqual([False, False, False],
                         [r["on_path"] for r in body["cli"]])
        self.assertEqual(["claude"],
                         [r["host"] for r in body["cli"] if r["remedy"]])

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
        with _which({"kimi": "/opt/bin/kimi"}):
            _code, body = self._json(d, "--host", "kimi")
        self.assertEqual("kimi", body["host"])
        self.assertEqual("kimi", body["cli"][0]["host"])
        self.assertIs(True, body["cli"][0]["selected"])


if __name__ == "__main__":
    unittest.main()


class TestTheSelectedHostsBinaryIsGating(_VerbCase):
    """Fix round 1, F2. `--host H` is a statement about how the run will be
    driven, and `orchestrate._resolve_mode` resolves it to HEADLESS whenever
    `runners/<H>.py` exists -- a fact about this repo, not about the machine.
    So `driver readiness --host claude && driver loop --host claude` on a box
    without `claude` used to greenlight a loop that resolves to headless and
    then cannot launch: exactly the failure class P10 exists to remove.

    The selected host's row therefore GATES, and says both ways out. Every
    other host's row stays informational -- the operator did not ask about
    them, and `driver loop` will not pick them.
    """

    def test_the_selected_hosts_missing_binary_takes_the_exit_code_to_1(self):
        d = self._repo(groups_yml=GROUPS_YML)
        with _which({}):                      # nothing on PATH at all
            code, body = self._json(d, "--host", "claude")
        self.assertEqual(1, code)
        self.assertIn("cli", body["failed"])
        row = body["cli"][0]
        self.assertEqual("claude", row["host"])
        self.assertIs(True, row["selected"])
        self.assertIs(False, row["on_path"])

    def test_the_remedy_names_the_binary_and_the_exact_session_invocation(self):
        d = self._repo(groups_yml=GROUPS_YML)
        with _which({}):
            _code, text = self._run(d, "--host", "claude")
        for token in ("claude", "--mode session", "headless"):
            with self.subTest(token=token):
                self.assertIn(token, text)
        # The invocation has to be the one `orchestrate` really takes, not an
        # invented spelling.
        self.assertIn("driver loop --host claude --mode session", text)

    def test_the_selected_row_is_marked_in_the_table(self):
        d = self._repo(groups_yml=GROUPS_YML)
        with _which({"claude": "/opt/bin/claude", "codex": "/opt/bin/codex",
                     "kimi": "/opt/bin/kimi"}):
            code, text = self._run(d, "--host", "claude")
        self.assertEqual(0, code)
        cli_line = [ln for ln in text.splitlines() if ln.strip().startswith("cli")][0]
        self.assertIn("→ claude:", cli_line)
        self.assertNotIn("→ codex", cli_line)

    def test_a_present_binary_is_not_gating(self):
        d = self._repo(groups_yml=GROUPS_YML)
        with _which({"claude": "/opt/bin/claude"}):
            code, body = self._json(d, "--host", "claude")
        self.assertEqual(0, code)
        self.assertEqual([], body["failed"])
        self.assertEqual("/opt/bin/claude", body["cli"][0]["path"])

    def test_an_unselected_hosts_missing_binary_is_still_informational(self):
        d = self._repo(groups_yml=GROUPS_YML)
        with _which({"claude": "/opt/bin/claude"}):   # codex and kimi absent
            code, body = self._json(d, "--host", "claude")
        self.assertEqual(0, code)
        self.assertEqual([False, False],
                         [r["on_path"] for r in body["cli"] if not r["selected"]])

    def test_a_selected_host_with_no_cli_of_ours_still_gets_a_row(self):
        """`--host generic` used to list three hosts the operator did not ask
        about and say nothing about the one they did."""
        d = self._repo(groups_yml=GROUPS_YML)
        with _which({}):
            code, body = self._json(d, "--host", "generic")
        self.assertEqual(0, code)             # nothing to install; session only
        row = body["cli"][0]
        self.assertEqual("generic", row["host"])
        self.assertIs(True, row["selected"])
        self.assertIsNone(row["binary"])
        self.assertIsNone(row["on_path"])


class TestTheRowsThatSayNothingIsWrongSayItOnce(_VerbCase):
    """Fix round 1, F7. A field called `remedy` holding the string "ok"
    rendered as `tools-image   ok   ok`. There is no remedy when nothing is
    wrong, and `null` is how a JSON contract says that."""

    def test_a_healthy_tools_image_carries_no_remedy(self):
        d = self._repo(groups_yml=GROUPS_YML)
        _code, body = self._json(d)
        self.assertIs(True, body["tools_image"]["ok"])
        self.assertIsNone(body["tools_image"]["remedy"])

    def test_and_the_table_cell_is_blank_rather_than_a_stutter(self):
        d = self._repo(groups_yml=GROUPS_YML)
        _code, text = self._run(d)
        line = [ln for ln in text.splitlines()
                if ln.strip().startswith("tools-image")][0]
        self.assertEqual("tools-image   ok", line.strip())
        self.assertEqual(line, line.rstrip())      # no trailing whitespace


class TestTheNoGroupsRemedyNamesTheWayOut(_VerbCase):
    """Fix round 1, F4. `-f`/`-d`/`-g`/`--pr` reviews run fine without a
    committed matrix; only the whole-repo scope degrades to `._N` chunks. The
    verb shares no scope flag, so it reports the whole-repo answer -- and the
    remedy has to name the other way out, exactly as `tools_image`'s names
    `--no-tools`."""

    def test_it_names_the_scopes_that_need_no_matrix(self):
        d = self._repo()
        _code, body = self._json(d)
        detail = body["matrix"]["detail"]
        self.assertIn("run `driver setup`", detail)
        for token in ("-f", "-d", "-g", "--pr"):
            with self.subTest(token=token):
                self.assertIn(token, detail)


class TestTheAssumedHost(_VerbCase):
    """Fix round 2, item 1. A bare `driver readiness <target>` was the hole
    round 1 left open: with no `--host` there was no selected row, so the `cli`
    check was informational and the verb exited 0 on a machine with no host CLI
    at all -- while `driver loop <target>`, equally bare, resolves a host
    perfectly well (`--host`, else the run's manifest, else the driver's
    default) and would go looking for its binary.

    So the verb resolves the host through the SAME function the loop uses, and
    the document says which host it assumed and why.
    """

    def _manifest(self, d, host):
        with open(os.path.join(d, ".panopticon", "run-manifest.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"schema_version": 1, "run_id": "abcd1234",
                       "host": host, "review_root": d,
                       "created": "2026-09-15T00:00:00Z",
                       "security_mode": "standard", "flags": {}}, fh)

    def test_a_bare_invocation_gates_on_the_host_the_loop_would_pick(self):
        d = self._repo(groups_yml=GROUPS_YML)
        with _which({}):                       # nothing on PATH
            code, body = self._json(d)
        self.assertEqual(1, code)
        self.assertIn("cli", body["failed"])
        self.assertEqual("claude", body["host"])
        self.assertEqual("default", body["selected_from"])
        self.assertIs(True, body["cli"][0]["selected"])
        self.assertEqual("claude", body["cli"][0]["host"])

    def test_an_existing_runs_manifest_wins_over_the_static_default(self):
        d = self._repo(groups_yml=GROUPS_YML)
        self._manifest(d, "kimi")
        with _which({"kimi": "/opt/bin/kimi"}):   # claude deliberately absent
            code, body = self._json(d)
        self.assertEqual(0, code)
        self.assertEqual("kimi", body["host"])
        self.assertEqual("manifest", body["selected_from"])
        self.assertEqual("/opt/bin/kimi", body["cli"][0]["path"])

    def test_an_explicit_host_beats_the_manifest(self):
        d = self._repo(groups_yml=GROUPS_YML)
        self._manifest(d, "kimi")
        with _which({"codex": "/opt/bin/codex"}):
            code, body = self._json(d, "--host", "codex")
        self.assertEqual(0, code)
        self.assertEqual("codex", body["host"])
        self.assertEqual("--host", body["selected_from"])

    def test_the_header_says_which_host_was_assumed_and_why(self):
        d = self._repo(groups_yml=GROUPS_YML)
        with _which({"claude": "/opt/bin/claude"}):
            _code, text = self._run(d)
        header = text.splitlines()[0]
        self.assertIn("host claude", header)
        self.assertIn("default", header)

    def test_it_resolves_through_the_loops_own_function(self):
        """One definition, not two. `orchestrate.loop` and this verb ask the
        same `runio.resolve_host`, so no precedence can drift between the check
        and the thing it is checking."""
        import scripts.orchestrate as orchestrate
        import scripts.phases.runio as runio
        self.assertFalse(hasattr(orchestrate, "_resolve_host"),
                         "orchestrate kept a second copy of the resolver")
        self.assertTrue(callable(runio.resolve_host))


class TestAHealthyCliRowReadsOk(_VerbCase):
    """Fix round 2, item 2. `_cli_gate` never returned True, so a selected host
    whose binary was right there rendered `--` -- the same token the rows that
    are never checked use. A row that CAN fail and did not say `ok`, like every
    other gating row."""

    def test_the_row_reads_ok_when_the_binary_is_there(self):
        d = self._repo(groups_yml=GROUPS_YML)
        with _which({"claude": "/opt/bin/claude"}):
            code, text = self._run(d, "--host", "claude")
        self.assertEqual(0, code)
        line = [ln for ln in text.splitlines() if ln.strip().startswith("cli")][0]
        self.assertRegex(line, r"^  cli\s+ok\s+→ claude:")

    def test_a_host_with_no_cli_of_ours_reads_ok_too(self):
        d = self._repo(groups_yml=GROUPS_YML)
        with _which({}):
            code, text = self._run(d, "--host", "generic")
        self.assertEqual(0, code)
        line = [ln for ln in text.splitlines() if ln.strip().startswith("cli")][0]
        self.assertRegex(line, r"^  cli\s+ok\s+→ generic:")

    def test_only_the_informational_rows_still_read_dashes(self):
        d = self._repo(groups_yml=GROUPS_YML)
        with _which({"claude": "/opt/bin/claude"}):
            _code, text = self._run(d, "--host", "claude")
        dashed = sorted(ln.split()[0] for ln in text.splitlines()
                        if ln.startswith("  ") and " -- " in ln + " ")
        self.assertEqual(["capabilities", "existing-run", "sub-skills"], dashed)
