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
        for flag in ("-f ", "-d ", "-c", "--pr ", "--base"):
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
    """#449: SKILL.md and README must describe the shipped delta-review
    behavior (base resolution, the diff-hunks.json artifact, and the
    disposable PR worktree) — not the pre-redirect HEAD~1/--files framing."""

    def setUp(self):
        self.skill = _read_doc()
        with open(os.path.join(ROOT, os.pardir, "README.md"), encoding="utf-8") as fh:
            self.readme = fh.read()

    def test_skill_documents_delta_flow(self):
        for token in ["--base", "--diff-context", "--gate-scope", "diff-hunks.json", "worktree"]:
            self.assertIn(token, self.skill, token)

    def test_pr_worktree_is_native_review_root(self):
        # #955's separate "stage groups.json+diff-hunks.json into the
        # worktree" step doesn't exist under the driver: the driver resolves
        # the worktree as review_root before any phase runs, so every phase
        # writes there natively from the start -- nothing to stage.
        self.assertIn("runs every phase natively inside it", self.skill)
        self.assertIn("no separate staging step", self.skill)

    def test_guard_install_is_session_rooted(self):
        # #956: hook registration is SESSION-rooted — a guard installed from a
        # temp worktree's cwd is inert. The doc must say install from the
        # session root and must not retain the old worktree-cwd instruction.
        self.assertIn("session root", self.skill)
        self.assertNotIn("install the write-guard from\n     that same cwd", self.skill)

    def test_delta_docs_warn_gate_needs_fail_on(self):
        # #957: without --fail-on the gate reads OFF; the delta pipeline notes
        # must say so where the synthesize commands are given (exact phrase —
        # a loose regex matched the Global-flags line vacuously).
        self.assertIn("or the gate stays OFF", self.skill)

    def test_readme_quick_start_shows_pr_and_base(self):
        # Reuse TestReadmeQuickStart's Quick start boundary — the brief's
        # `.split("## ")[1]` split does not match this README's layout.
        qs = _section(self.readme, "## Quick start", "## Repository layout")
        self.assertIn("--pr", qs)
        self.assertIn("--base", qs)
