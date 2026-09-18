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
import subprocess
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
    with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
        r = kimi_runner.Runner("kimi", runner=runner or subprocess.run)
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
        self.assertEqual(os.stat(self.r.skills_dir).st_mode & 0o077, 0)

    def test_an_unprepared_runner_refuses_to_build_an_argv_at_all(self):
        # Failing OPEN here would hand back a launchable argv with NO
        # `--skills-dir`, i.e. with the CLI's auto-discovered user AND project
        # roots live -- the target's `.kimi-code/skills` back in play, silently.
        # `prepare` already hard-raises on a missing guard hook; same shape.
        unprepared = kimi_runner.Runner("kimi")
        with self.assertRaises(RuntimeError) as raised:
            unprepared.command(_entry(True), "kimi-code/k3")
        self.assertIn("not prepared", str(raised.exception))

    def test_it_is_a_real_directory_the_run_minted_not_a_reused_path(self):
        # `prepare` mints a fresh home every time (N2), so the skills dir
        # cannot be a path a previous run -- or the reviewed tree -- named.
        with tempfile.TemporaryDirectory() as second:
            other = _prepared(second)
            self.addCleanup(other.teardown, "complete")
            self.assertNotEqual(other.skills_dir, self.r.skills_dir)


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
