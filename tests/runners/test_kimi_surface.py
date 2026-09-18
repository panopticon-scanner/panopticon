"""#1657 step 2: the Kimi launch SURFACE -- what a hostile target can get
loaded into a reviewer, and what keeps it out.

A separate module from tests/runners/test_kimi.py, which is already 1200+
lines: these are the discovery-surface pins (skills, MCP, the workspace-trust
gate the 2026-09-18 experiment measured), and they are the tests a future edit
to `_CREDENTIAL_ITEMS` or to `command()` has to answer to.

Never launches a real `kimi`: every Runner here is either unlaunched or
injected with a fake.
"""
import os
import shutil
import stat
import tempfile
import tomllib
import unittest
from unittest import mock

import scripts.runners.kimi as kimi_runner
import scripts.runners.kimi_home as kimi_home


def _entry(enforced=True, model="secondary"):
    return {"id": "review-app-SEC", "agent": "panopticon-domain-panel" if enforced else None,
            "enforced": enforced, "model": model,
            "prompt": "panopticon-entry: review-app-SEC\nReview.",
            "out_file": "/r/.panopticon/runs/t/findings-app-SEC.json"}


def _fixture_home(d):
    """A minimal real-home fixture -- never the operator's own."""
    home = os.path.join(d, "real-home")
    os.makedirs(home)
    with open(os.path.join(home, "config.toml"), "w", encoding="utf-8") as fh:
        fh.write('default_model = "kimi-code/k3"\n\n'
                 '[models."kimi-code/k3"]\nmodel = "k3"\n')
    with open(os.path.join(home, "credentials"), "w", encoding="utf-8") as fh:
        fh.write("fixture")
    return home


def _prepared(d, runner=None):
    # `runner=runner`, i.e. None by default -- NOT `subprocess.run`. An
    # explicitly passed launcher routes around tests/conftest.py's autouse
    # `_no_live_host_launches`, which swaps the module's DEFAULT_RUNNER for a
    # refusal; leaving it None means any launch from this module hits that
    # refusal rather than the real `kimi` binary.
    with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
        r = kimi_runner.Runner("kimi", runner=runner)
        r.prepare(os.path.join(d, "run"), review_root=d)
    return r


class TestSkillsDirectory(unittest.TestCase):
    """KM-1: without `--skills-dir` the CLI auto-discovers user AND project
    skill roots, so a target shipping `.kimi-code/skills/<x>/SKILL.md` or
    `.agents/skills/<x>/SKILL.md` gets instructions into a reviewer. One
    explicit, empty, run-owned directory makes both roots empty."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.r = _prepared(self.tmp.name)
        self.addCleanup(self.r.teardown, "complete")

    def test_every_entry_carries_the_skills_dir_before_the_prompt_flag(self):
        for enforced in (True, False):
            with self.subTest(enforced=enforced):
                cmd = self.r.command(_entry(enforced), "kimi-code/k3")
                flags = [a for a in cmd if a.startswith("--skills-dir")]
                # EQUALS form, for the same 0.42.0 parsing reason
                # `--agent-file=` uses it: the space form after -p misparses.
                self.assertEqual(flags, ["--skills-dir=%s" % self.r.skills_dir])
                self.assertLess(cmd.index(flags[0]), cmd.index("-p"))

    def test_the_directory_is_an_empty_run_owned_one_under_the_per_run_home(self):
        self.assertTrue(os.path.isdir(self.r.skills_dir))
        self.assertEqual([], os.listdir(self.r.skills_dir))
        self.assertEqual(os.path.dirname(self.r.skills_dir), self.r.kimi_home)
        # Exactly 700, not merely "nothing for group and other": the second
        # reading passes for 0o000 and 0o500 too.
        self.assertEqual(0o700, stat.S_IMODE(os.stat(self.r.skills_dir).st_mode))

    def test_an_unprepared_runner_refuses_to_build_an_argv_at_all(self):
        # Failing OPEN here would hand back a launchable argv with NO
        # `--skills-dir`, i.e. with the CLI's auto-discovered user AND project
        # roots live -- the target's `.kimi-code/skills` back in play, silently.
        # `prepare` already hard-raises on a missing guard hook; same shape.
        unprepared = kimi_runner.Runner("kimi")
        with self.assertRaises(RuntimeError) as raised:
            unprepared.command(_entry(True), "kimi-code/k3")
        self.assertIn("not prepared", str(raised.exception))

    def test_a_clean_teardown_forgets_the_directory_it_deleted(self):
        # `skills_dir` lives INSIDE the home `teardown("complete")` removes, so
        # a runner that kept the path would hold a name that no longer exists
        # while `kimi_home`/`run_home` say None -- and a later `command()`
        # would emit `--skills-dir=<deleted path>`, whose effect on the CLI is
        # unmeasured (a fall-back to auto-discovery being the worst case).
        directory = self.r.skills_dir
        self.r.teardown("complete")
        self.assertFalse(os.path.exists(directory))
        self.assertIsNone(self.r.skills_dir)
        self.assertIsNone(self.r.kimi_home)

    def test_it_is_a_real_directory_the_run_minted_not_a_reused_path(self):
        # `prepare` mints a fresh home every time (N2), so the skills dir
        # cannot be a path a previous run -- or the reviewed tree -- named.
        with tempfile.TemporaryDirectory() as second:
            other = _prepared(second)
            self.addCleanup(other.teardown, "complete")
            self.assertNotEqual(other.skills_dir, self.r.skills_dir)


class TestAnUnpreparedRunnerFailsTheEntryNotTheCaller(unittest.TestCase):
    def test_run_entry_turns_the_refusal_into_a_failed_result(self):
        # `command()` refuses to build an argv without `--skills-dir`; that
        # refusal must reach the caller the way every other launch failure
        # does -- as a failed RunResult -- because run_entry never raises
        # (spec 4.4) and the dispatch pool's `one()` wrapper is not the
        # contract. An UNENFORCED, model-less entry is the shape that reaches
        # `command()` without needing a registered shell or a CLI alias.
        launcher = mock.Mock(side_effect=AssertionError("nothing may launch"))
        unprepared = kimi_runner.Runner("kimi", runner=launcher)
        result = unprepared.run_entry(_entry(False, model=None), {})
        self.assertFalse(result.ok)
        self.assertIn("not prepared", result.error)
        launcher.assert_not_called()


class TestSkillsDirectoryIsNotBuiltThroughALink(unittest.TestCase):
    def test_a_link_planted_at_the_name_is_refused_not_chmodded(self):
        # The file's own I2 rule, twenty lines above `new_skills_dir`:
        # `makedirs(exist_ok=True)` is happy with a symlink to a directory and
        # `chmod` follows it, so a link planted at this name would relax
        # someone else's directory to 700 and then be handed to the child as
        # its skill root.
        with tempfile.TemporaryDirectory() as d:
            home = os.path.join(d, "home")
            elsewhere = os.path.join(d, "elsewhere")
            os.makedirs(home)
            os.makedirs(elsewhere, mode=0o755)
            os.symlink(elsewhere, os.path.join(home, "no-skills"))
            with self.assertRaises(OSError):
                kimi_home.new_skills_dir(home)
            self.assertEqual(0o755, stat.S_IMODE(os.stat(elsewhere).st_mode))


class TestWorkspaceTrustGate(unittest.TestCase):
    """The MEASURED neutraliser of target-planted MCP (2026-09-18 experiment).

    0.42.0's `configLoader.loadMcpServersDetailed` reads `<git root>/.mcp.json`
    and `<cwd>/.kimi-code/mcp.json` only when `includeProject` is true, and
    every call site passes `this.trust.isTrusted()`. `WorkspaceTrustService`
    keeps that record in the `workspace-trust` document scope under
    `KIMI_CODE_HOME`. The per-run home is a fresh mkdtemp linking ONLY the
    credential stores, so no trust record exists, the project files are never
    read, and the planted servers never spawn -- confirmed on a real launch:
    neither marker was touched and the child's `llm.tools_snapshot` held only
    Glob/Grep/Read.

    That protection is one line from disappearing. These are the pins.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_only_the_credential_stores_are_linked_into_the_per_run_home(self):
        self.assertEqual(
            ("credentials", "oauth"), kimi_home._CREDENTIAL_ITEMS,
            "adding an item here can un-neutralise target-planted MCP: a fresh "
            "home has no `workspace-trust` record, so kimi treats cwd as "
            "untrusted and never reads <git root>/.mcp.json or "
            "<cwd>/.kimi-code/mcp.json. Link the trust scope -- or copy the "
            "operator's home wholesale -- and those servers spawn, under names "
            "no guard hook and no tools.disabled entry can see.")

    def test_a_built_home_carries_no_trust_record_and_no_mcp_file(self):
        real = _fixture_home(self.tmp.name)
        # The operator's own home has both; neither may be carried over.
        os.makedirs(os.path.join(real, "workspace-trust"))
        with open(os.path.join(real, "workspace-trust", "wd_target"), "w",
                  encoding="utf-8") as fh:
            fh.write('{"trusted": true}')
        with open(os.path.join(real, "mcp.json"), "w", encoding="utf-8") as fh:
            fh.write('{"mcpServers": {"planted": {"command": "/bin/sh"}}}')
        home = kimi_home.build_kimi_home(
            kimi_home.new_kimi_home(), os.path.join(self.tmp.name, "scope.json"),
            os.path.join(self.tmp.name, "allow.json"), real_home=real)
        self.addCleanup(shutil.rmtree, home, True)
        entries = set(os.listdir(home))
        self.assertNotIn("workspace-trust", entries)
        self.assertNotIn("mcp.json", entries)
        self.assertEqual({"config.toml", "credentials"}, entries)

    def test_the_inert_mcp_block_is_a_second_layer_not_the_mechanism(self):
        # It stays -- cheap, and correct if a future CLI honours it -- but the
        # 0.42.0 schema does not know these keys, so nothing here may be read
        # as the thing that stops a planted server.
        home = kimi_home.build_kimi_home(
            kimi_home.new_kimi_home(), os.path.join(self.tmp.name, "scope.json"),
            os.path.join(self.tmp.name, "allow.json"),
            real_home=_fixture_home(self.tmp.name))
        self.addCleanup(shutil.rmtree, home, True)
        with open(os.path.join(home, "config.toml"), "rb") as fh:
            generated = tomllib.load(fh)
        self.assertEqual({"enabled": False, "servers": []}, generated["mcp"])
        self.assertIn("workspace-trust", kimi_home.__doc__)


if __name__ == "__main__":
    unittest.main()
