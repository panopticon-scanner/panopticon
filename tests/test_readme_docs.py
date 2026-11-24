import os
import re
import unittest

import scripts.hosts as hosts
from tests._test_helpers import SKILL_ROOT as ROOT
from tests.doc_helpers import (
    _read_doc, _section,
)

class TestReadmeQuickStart(unittest.TestCase):
    """#512: the README Quick start must show real invocation flags, not the
    nonexistent --mode/--target selectors a new adopter would copy-paste."""

    def setUp(self):
        with open(os.path.join(ROOT, os.pardir, "README.md"), encoding="utf-8") as fh:
            self.text = fh.read()

    def _quick_start(self):
        # Scoped to the Quick start section: elsewhere `run_tools.py --target .`
        # is a legitimate internal tool invocation, not skill-invocation syntax.
        return _section(self.text, "## Quick start", "## Repository layout")

    def test_no_nonexistent_mode_or_target_flags(self):
        qs = self._quick_start()
        self.assertNotIn("--mode", qs)
        self.assertNotIn("--target", qs)

    def test_quick_start_uses_documented_flags(self):
        qs = self._quick_start()
        for flag in ("-f ", "-d ", "--files "):
            self.assertIn(flag, qs, flag)


class TestReadmeHostAccounts(unittest.TestCase):
    """#1573: README's "Supported agent platforms" bullet and its Codex
    install section both said the Codex/Kimi execution adapters were
    "rebuilding for 5.2" and sent Codex users to generic session mode --
    while docs/PANOPTICON.md and skill/SKILL.md already documented Codex's
    and Kimi's enforced headless runners as shipped (#1619/#1620). Three
    documents, incompatible accounts of the same execution path, and README
    was the stale one (run-13 COD-3215020638). Pin the fix at the door: every
    driver-selectable host is named in the platform list, and the
    already-shipped-adapter phrasing cannot drift back in unnoticed."""

    def setUp(self):
        with open(os.path.join(ROOT, os.pardir, "README.md"), encoding="utf-8") as fh:
            self.raw = fh.read()
        # Fold line-wrapped prose to one line before substring checks: a bold
        # span split across a markdown line wrap (`is being\nrebuilt for
        # 5.2`) must still be caught.
        self.normalized = re.sub(r"\s+", " ", self.raw)

    def test_names_every_driver_selectable_host(self):
        platforms = _section(self.raw, "## Supported agent platforms", "## Installation")
        for host in hosts.driver_hosts():
            self.assertIn(host, platforms,
                          "README's platform list omits driver host %r" % host)

    def test_no_stale_adapter_rebuild_language(self):
        for phrase in ("rebuilding for 5.2", "being rebuilt for 5.2",
                       "execution adapters return"):
            self.assertNotIn(phrase, self.normalized, phrase)


class TestDeltaDocs(unittest.TestCase):
    """#3735, #3736: delta review was withdrawn in 5.4 and its code removed in 5.5.
    SKILL.md, the guide and the README say so, name the refused flags, and show no delta
    command to copy. (#449 pinned the shipped delta flow here.)"""

    FLAGS = ("--pr", "--changes", "--base", "--gate-scope", "--diff-context")

    def setUp(self):
        self.skill = _read_doc()
        with open(os.path.join(ROOT, os.pardir, "README.md"), encoding="utf-8") as fh:
            self.readme = fh.read()

    def test_the_docs_say_delta_review_is_withdrawn(self):
        for text in (self.skill, self.readme):
            self.assertIn("#3735", text)
            self.assertIn("#3736", text)
            self.assertRegex(text, r"(?i)delta review was withdrawn in 5\.4")
            self.assertRegex(" ".join(text.split()), r"removed in 5\.5")
            # #3736: nothing says the code is still there, or that the mode comes back.
            for stale in ("unreachable", "is deleted in 5.5", "returns when it has been rebuilt",
                          "It returns when", "refuse_delta"):
                self.assertNotIn(stale, text, stale)
            for flag in self.FLAGS:
                self.assertIn(flag, text, flag)
        self.assertIn("`--reset` starts a whole-repository run", self.readme)
        self.assertIn("folder that was started as a delta review is not resumed",
                      " ".join(self.skill.split()))

    def test_no_command_to_copy_carries_a_delta_flag(self):
        """Every `driver.py` line in a fenced block of the README and the getting-started
        page runs as written in 5.4."""
        with open(os.path.join(ROOT, os.pardir, "docs", "GETTING-STARTED.md"),
                  encoding="utf-8") as fh:
            started = fh.read()
        commands = [line for text in (self.readme, started) for line in text.splitlines()
                    if line.startswith("python3 skill/scripts/driver.py ")]
        self.assertGreater(len(commands), 5)
        for line in commands:
            words = line.split("#")[0].split()
            for flag in self.FLAGS + ("-c",):
                self.assertNotIn(flag, words, line)

    def test_guard_install_is_session_rooted(self):
        # #956: hook registration is SESSION-rooted — a guard installed from a
        # temp worktree's cwd is inert. The doc must say install from the
        # session root and must not retain the old worktree-cwd instruction.
        self.assertIn("session root", self.skill)
        self.assertNotIn("install the write-guard from\n     that same cwd", self.skill)

    def test_readme_quick_start_scopes_without_a_diff(self):
        # Reuse TestReadmeQuickStart's Quick start boundary — the brief's
        # `.split("## ")[1]` split does not match this README's layout.
        qs = _section(self.readme, "## Quick start", "## Repository layout")
        self.assertIn("Panopticon is a whole-repository audit. Delta review was withdrawn in 5.4 "
                      "and removed in 5.5.", qs)
        self.assertIn("loop . --files a.py b.py", qs)
