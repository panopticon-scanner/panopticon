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
import subprocess
import tempfile
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

    def test_it_is_a_real_directory_the_run_minted_not_a_reused_path(self):
        # `prepare` mints a fresh home every time (N2), so the skills dir
        # cannot be a path a previous run -- or the reviewed tree -- named.
        with tempfile.TemporaryDirectory() as second:
            other = _prepared(second)
            self.addCleanup(other.teardown, "complete")
            self.assertNotEqual(other.skills_dir, self.r.skills_dir)


if __name__ == "__main__":
    unittest.main()
