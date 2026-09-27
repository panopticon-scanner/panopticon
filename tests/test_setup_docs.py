import unittest

from tests.doc_helpers import (
    _read_doc, _read_skill_md, _section,
)

class TestSetupDocs(unittest.TestCase):
    def test_skill_documents_setup_mode(self):
        # 5.0: the pre-driver `--setup` flag (with its "READY" checklist) was
        # implemented by the now-retired orchestrator.py and never existed on
        # driver.py's CLI -- `driver setup` (a subcommand) with its own
        # readiness gate is the only setup mode there is now.
        skill = _read_doc()
        self.assertIn("driver setup", skill)
        self.assertIn("readiness gate", skill)

    def test_skill_documents_driver_setup(self):
        skill = _read_doc()
        self.assertIn("driver setup", skill)
        self.assertIn("panopticon.yml.draft", skill)
        # #1681 Plan 1: the one-way remedy for a tree that still carries the
        # retired `.panopticon/groups.yml`. Setup, readiness and every run
        # refuse such a tree, so the verb that unblocks it has to be in the
        # guide the refusal sends the operator to.
        self.assertIn("migrate-config", skill)

    def test_the_settings_trust_classes_are_documented(self):
        # #1681 Plan 2, spec §8: a target reading this doc has to be able to
        # tell which of its own settings will be honoured BEFORE it commits
        # them, and an operator reading a report has to know where a refusal
        # shows up.
        setup = _section(_read_doc(), "## Driver setup (5.2)", "## Output")
        self.assertIn("trust classes", setup)
        self.assertIn("never loosen", setup)
        self.assertIn("meta.config", setup)
        for key in ("max_per_group", "max_groups", "security", "fail_on",
                    "gate_scope", "tools", "max_verify", "allow_unenforced"):
            self.assertIn(key, setup)
        self.assertIn("8-48", setup)
        self.assertIn("4-64", setup)
        # Final review, doc nit: the paragraph named four of the FIVE
        # `config_*` blocks the manifest actually carries, and the missing one
        # is the disclosures -- the block that holds every "nothing changes"
        # and "the command line wins" line, i.e. everything that happened to a
        # setting WITHOUT being a refusal or a clamp.
        for key in ("config_requested", "config_effective", "config_refused",
                    "config_clamped", "config_disclosures"):
            self.assertIn(key, setup)
        # A value equal to the built-in default is a disclosed no-op, not a
        # refusal (final review F4): it must not read as one here either.
        self.assertIn("equal to the default", setup)

    def test_the_sizes_paragraph_no_longer_claims_run_ignores_settings(self):
        # Plan 1 wired `driver run`'s max_per_group to `settings:`; the
        # parenthetical saying it does not was stale the day it shipped.
        setup = _section(_read_doc(), "## Driver setup (5.2)", "## Output")
        self.assertNotIn("does not read `settings:` yet", setup)


class TestInstalledFlowDocs(unittest.TestCase):
    """#495: SKILL states the <skill-dir> substitution contract once, and the
    repo-root cwd rule survives it."""

    def test_preamble_states_substitution_contract(self):
        skill = _read_doc()
        self.assertIn("Installed-flow substitution", skill)
        self.assertIn("INSTALL DIRECTORY", skill)
        self.assertIn("TARGET repo root", skill)


class TestCodexHostDocs(unittest.TestCase):
    """4.3.0's per-host Codex fan-out (`codex_runner.py`/`--advisor-queue`/
    `--advisor-model`) was manual-pipeline-only and was retired with the
    roles it dispatched. Codex and Kimi are first-class headless driver
    hosts since #1619/#1620 (`driver loop --host codex|kimi`); the skill's
    own front matter still has to name them, name `generic` as the session
    fallback, and keep the `--emit-host-agents` registration step that
    every family shares (#1573 pins the README half of the same account)."""

    def test_codex_and_kimi_named_alongside_the_generic_fallback_and_registration(self):
        skill = _read_doc()
        self.assertIn("--emit-host-agents", skill)
        self.assertIn("codex", skill.lower())
        self.assertIn("kimi", skill.lower())
        self.assertIn("generic", skill)


    def test_the_hard_link_rule_for_directory_grants_is_stated(self):
        # M-3 recorded this as an inherent limit: a hard link to a file outside
        # a directory grant "reads as a file in the grant, because it is one".
        # #1642 closed it, so the guide states the RULE instead -- including
        # which grant kind refuses what, and what it costs, because the
        # reviewer whose hard-linked build output stopped being readable is the
        # one who comes here to find out why.
        doc = _read_doc()
        self.assertIn("hard link", doc)
        self.assertIn("st_nlink", doc)
        self.assertIn("Exact grants are not narrowed this way", doc)
        self.assertNotIn("inherent to path-based confinement", doc)
        # Fix round 1 (F1): and the DIRECTORY-argument half, because an
        # operator deciding whether `--host claude` is safe against a prepared
        # tree reads this paragraph. It was a stated residual until #1683
        # closed it; what the paragraph must now carry is the rule and its two
        # limits, since a rule with an unstated cap is a promise, not a fence.
        self.assertIn("#1683", doc)
        self.assertNotIn("that residual is tracked as #1683", doc)
        self.assertIn("walks the granted directory ONCE", doc)
        self.assertIn("past 256 recorded files", doc)
        self.assertIn("planted AFTER the grant is issued is not in the list", doc)
        # Fix round 1 (A): and the operator's remedy, in the same words the
        # stderr line uses -- `phases/setup._HARD_LINK_REMEDY`.
        self.assertIn("git clone --no-hardlinks", doc)
        # Fix round 2 (B1): the fold is a security property an operator relies
        # on -- and so is its asymmetry, which is why both are stated.
        self.assertIn("case- and normalization-folded", doc)
        self.assertIn("the grant itself is never folded", doc)
        # Fix round 3 (N6): and what the skip line actually promises -- at most
        # eight named, inside a bounded block, the rest counted.
        self.assertIn("at most eight are named", doc)
        self.assertNotIn("apply the same rule to their own directory grants", doc)
        # Fix round 2 (N4): anchored on the phrase that STATES the limit, not
        # on the first line mentioning the issue -- a second #1683 reference
        # added above this one would silently move the checks to that paragraph.
        sentence = next(line for line in doc.splitlines()
                        if "traversed by the host's own tool" in line)
        for phrase in ("#1683", "Grep", "Glob", "Codex has no such gap"):
            self.assertIn(phrase, sentence)

    def test_the_headless_runner_sentence_has_its_antecedent(self):
        # M-8: "...session when it does not (Claude and Codex have headless
        # runners) -- `--mode headless` on such a host is an error". The
        # parenthetical replaced the phrase "such a host" referred to.
        self.assertIn("on a host without one", _read_skill_md())

    def test_the_codex_model_pin_documents_its_override(self):
        # I-8: the advisor slug is pinned to the installed build's bundled
        # catalog, and an absent slug fails every entry of that role closed.
        # Scoped to the sentence that states the fail-closed behaviour, not
        # the whole guide: PANOPTICON_MODEL_* is named elsewhere for a
        # different reason, so a doc-wide search would pass without the line.
        sentence = next(line for line in _read_doc().splitlines()
                        if "fails closed rather than silently selecting" in line)
        self.assertIn("PANOPTICON_MODEL_", sentence)

    def test_codex_is_documented_as_enforced_only(self):
        # I-1: a Codex reviewer entry without a registered shell cannot run at
        # all -- there is no unenforced fallback the way there is on Claude --
        # and neither surface said so.
        for text in (_read_doc(), _read_skill_md()):
            self.assertIn("enforced-only", text)
        # ...and that the up-front refusal stands down for `--setup`, whose
        # single setup-scan entry needs no registered shell -- a fresh machine
        # runs setup BEFORE it registers anything.
        exemption = next(line for line in _read_doc().splitlines()
                         if "enforced-only" in line)
        self.assertIn("`--setup` is exempt", exemption)
        self.assertIn("except under `--setup`", _read_skill_md())


class TestGuardFailClosedDocs(unittest.TestCase):
    def test_skill_documents_fail_closed_guard(self):
        self.assertIn("fail-closed while registered", _read_doc())


class TestReviewRootDocs(unittest.TestCase):
    def test_skill_documents_read_side_rooting(self):
        skill = _read_doc()
        self.assertIn("Repo root:", skill)
        self.assertIn("#975", skill)
