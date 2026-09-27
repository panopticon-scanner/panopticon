import os
import re
import unittest

from tests._test_helpers import SKILL_ROOT as ROOT
from tests.doc_helpers import (
    _read_doc, _read_skill_md, _registered_driver_flags,
    _section,
)

class TestAdvertisedFlagsExist(unittest.TestCase):
    """#1531: SKILL.md's frontmatter and quick reference advertised four flags
    `driver run` does not have -- `--mode`, `--out`, `--full`, `--max-verify`
    (that last one belongs to synthesize.py). The existing guard checked the
    README quick-start for `--mode`/`--target` only, which is why these
    survived. Derive the allowed set from the parser instead of listing it."""

    def setUp(self):
        with open(os.path.join(ROOT, "SKILL.md"), encoding="utf-8") as fh:
            self.text = fh.read()
        self.options, self.positionals = _registered_driver_flags()

    def test_quick_reference_advertises_only_real_flags(self):
        block = self.text.split("## Quick reference", 1)[1]
        advertised = set(re.findall(r"`?(--[a-z][a-z-]+)", block))
        unknown = sorted(advertised - self.options)
        self.assertEqual(
            unknown, [],
            "SKILL.md advertises flags `driver` does not register: %s. A new "
            "adopter copy-pastes these." % ", ".join(unknown))

    def test_frontmatter_arguments_are_real(self):
        block = _section(self.text, "arguments:", "disableModelInvocation:")
        named = re.findall(r"^\s*-\s*(\S+)", block, re.MULTILINE)
        self.assertTrue(named, "SKILL.md lost its frontmatter arguments list")
        unknown = [n for n in named
                   if n not in self.positionals and "--" + n not in self.options]
        self.assertEqual(
            unknown, [],
            "SKILL.md frontmatter names arguments the driver has no parser "
            "entry for: %s" % ", ".join(unknown))

    def test_the_guard_would_notice_a_planted_flag(self):
        advertised = {"--security", "--definitely-not-a-flag"}
        self.assertEqual(sorted(advertised - self.options),
                         ["--definitely-not-a-flag"])


class TestDocsMatchTheTree(unittest.TestCase):
    """#1531: three doc-vs-code drifts that a reader has no way to detect.
    Each is asserted against the thing it describes, not against a copy."""

    def test_readme_agents_table_names_every_agent(self):
        agents = sorted(f[:-3] for f in os.listdir(os.path.join(ROOT, "agents"))
                        if f.endswith(".md"))
        with open(os.path.join(ROOT, os.pardir, "README.md"), encoding="utf-8") as fh:
            line = [ln for ln in fh if "skill/agents/" in ln]
        self.assertTrue(line, "README lost its skill/agents/ row")
        missing = [a for a in agents if a not in line[0]]
        self.assertEqual(
            missing, [],
            "README's agents row omits %s; skill/agents/ holds %s"
            % (", ".join(missing), ", ".join(agents)))

    def test_contributing_python_matrix_matches_ci(self):
        root = os.path.join(ROOT, os.pardir)
        with open(os.path.join(root, ".github", "workflows", "ci.yml"),
                  encoding="utf-8") as fh:
            ci = fh.read()
        m = re.search(r"python-version:\s*\[([^\]]+)\]", ci)
        self.assertIsNotNone(m, "ci.yml lost its python-version matrix")
        versions = re.findall(r"[\d.]+", m.group(1))
        with open(os.path.join(root, "CONTRIBUTING.md"), encoding="utf-8") as fh:
            contributing = fh.read()
        sentence = [ln for ln in contributing.splitlines()
                    if "CI matrix runs on Python" in ln]
        self.assertTrue(sentence, "CONTRIBUTING lost its CI-matrix sentence")
        missing = [v for v in versions if v not in sentence[0]]
        self.assertEqual(
            missing, [],
            "CONTRIBUTING says %r but ci.yml runs %s"
            % (sentence[0].strip(), ", ".join(versions)))

    def test_checkpoint_comment_does_not_restate_the_kinds(self):
        # The comment listed three of the four CHECKPOINT_KINDS. A comment that
        # COPIES a constant drifts from it; one that names it cannot.
        with open(os.path.join(ROOT, "scripts", "phases", "engine.py"),
                  encoding="utf-8") as fh:
            engine = fh.read()
        line = [ln for ln in engine.splitlines() if "checkpoint: str" in ln]
        self.assertTrue(line, "engine.py lost its checkpoint field")
        self.assertIn("CHECKPOINT_KINDS", line[0],
                      "the checkpoint comment should name CHECKPOINT_KINDS "
                      "rather than restate its members: %s" % line[0].strip())


class TestDriverLoopContract(unittest.TestCase):
    def test_driver_loop_is_the_host_contract(self):
        doc = _read_doc()
        run_loop = doc[doc.index("## Driver run-loop"):doc.index("## Driver setup")]
        for token in ("python3 skill/scripts/driver.py loop", "--mode session", "driver persist",
                      "dispatch-ledger.jsonl", "usage.json", "--max-iterations", "--max-budget-usd",
                      "host-settings.json", "never touched"):
            with self.subTest(token=token):
                self.assertIn(token, run_loop)

    def test_the_budget_sentence_states_exact_sums_and_the_non_finite_stop(self):
        # #1648: the gate summed FLOAT currency and one NaN cost made
        # `total >= budget` False, so the control failed OPEN. Both halves of
        # the remedy are operator-visible and therefore documented: the sums
        # are exact, and a cost that is not money stops the run.
        run_loop = _section(_read_doc(), "## Driver run-loop", "## Driver setup")
        for token in ("exact decimal", "non-finite"):
            with self.subTest(token=token):
                self.assertIn(token, run_loop)

    def test_session_mode_contract_names_persist_and_the_gate(self):
        doc = _read_doc()
        run_loop = doc[doc.index("## Driver run-loop"):doc.index("## Driver setup")]
        self.assertIn('`dispatch`', run_loop)
        self.assertIn("driver persist <id>", run_loop)
        self.assertIn("refuses to advance", run_loop)
        self.assertIn("write_guard_hook.install", run_loop.replace("**", ""))  # still documented as what the LOOP does
        self.assertNotIn("Install the write-guard from the request's entries", run_loop)

    def test_the_guide_states_the_two_write_mediation_rules_1640_added(self):
        # #1640 fix round 1, F1: both sentences were written and NOTHING
        # pinned them. The Kimi parenthetical here is one of the longest in
        # the guide and gets re-edited; an edit that dropped either clause
        # would leave the suite green while the guide stopped stating a
        # control the code enforces -- and the next operator reading it would
        # believe their `[[mcp.servers]]` are carried into the reviewed run.
        # Pinned by PHRASE, not by line, so the paragraph stays editable.
        doc = _read_doc().replace("**", "")
        run_loop = doc[doc.index("## Driver run-loop"):doc.index("## Driver setup")]
        for phrase in ("component by component",
                       "must be a real directory, not a symlink",
                       "no component may be `..`",
                       "Operator MCP servers are disabled in the per-run home",
                       "`mcp.enabled = false`"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, run_loop)
        caps = doc[doc.index("## Host capabilities (5.2)"):doc.index("## Code layout (5.2)")]
        self.assertIn("`[mcp]` block is inert", caps)

    def test_the_thirteen_duties_are_stated_as_the_loops_work(self):
        doc = _read_doc().replace("**", "")
        run_loop = doc[doc.index("## Driver run-loop"):doc.index("## Driver setup")]
        for phrase in ("The loop arms", "The loop persists", "The loop re-checks the pending set",
                       "The loop tears the guards down", "The loop ledgers"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, run_loop)
        for stale in ("Then re-invoke `driver run` (step 1)", "run it after `validate` and before re-running synthesize",
                      "Do not add a second \"persist\" agent per entry"):
            with self.subTest(stale=stale):
                self.assertNotIn(stale, run_loop)

    def test_quick_reference_names_loop_and_persist(self):
        skill = _read_skill_md()
        self.assertIn("driver loop", skill)
        self.assertIn("driver persist", skill)
        self.assertIn("--mode {headless,session}", skill)
        # I8 (plan 6 final review): the mode DEFAULT is host-dependent --
        # headless where a runner exists, session where none does -- so a
        # reader must not be left assuming `driver loop --host generic` errors.
        self.assertIn("defaults to headless when the host has a headless", skill)
        # I6 (fix round 3): the persist verb's own --pr/--base, in the line a
        # reader copies the invocation from.
        self.assertIn("[--pr N] [--base REF]", skill)


class TestTheReadinessVerbIsAdvertised(unittest.TestCase):
    """#1637 P10: a preflight nobody is told about is a preflight nobody runs."""

    def test_the_quick_reference_leads_with_it_and_shows_the_exit_code_idiom(self):
        skill = _read_skill_md()
        quick = skill.split("## Quick reference", 1)[1]
        self.assertIn("`driver readiness [target] [--host NAME] [--json]`", quick)
        self.assertIn("driver readiness && driver loop", quick)
        # It has to come before the verbs it gates.
        self.assertLess(quick.index("driver readiness"), quick.index("driver setup"))

    def test_the_guide_says_what_it_reads_and_what_it_never_does(self):
        loop = _section(_read_doc(), "## Driver run-loop", "## Driver setup")
        self.assertIn("driver readiness", loop)
        for phrase in ("writes nothing", "launches nothing"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, loop)

    def test_the_guide_names_every_status_the_existing_run_row_can_report(self):
        """Fix round 1, F3: `started` joined the set, and a doc that lists the
        old four teaches a `--json` consumer to key on a value it will not
        see."""
        loop = _section(_read_doc(), "## Driver run-loop", "## Driver setup")
        for status in ("complete", "checkpoint", "error", "started", "none"):
            with self.subTest(status=status):
                self.assertIn("`%s`" % status, loop)

    def test_the_guide_says_a_bare_invocation_still_resolves_a_host(self):
        """Fix round 2: the docs said the `cli` row gates "only when `--host H`
        was passed", which is now false -- a bare invocation resolves the same
        host `driver loop` would and gates on it. That sentence is exactly what
        an operator running it bare would have relied on."""
        loop = _section(_read_doc(), "## Driver run-loop", "## Driver setup")
        self.assertIn("`selected_from`", loop)
        self.assertIn("runio.resolve_host", loop)
        self.assertNotIn("only when `--host H` was passed", loop)

    def test_the_guide_says_the_selected_hosts_cli_gates(self):
        """Fix round 1, F2. The guide previously said an absent host CLI never
        gates, which is now false for the host `--host` named -- and that is
        the sentence an operator would have trusted."""
        loop = _section(_read_doc(), "## Driver run-loop", "## Driver setup")
        self.assertIn("--mode session", loop)
        # Round 2 reworded this: the gate is on the RESOLVED host, with or
        # without the flag, so the sentence no longer speaks of `--host` alone.
        self.assertIn("resolves a host to headless", loop)


class TestIntegrityResidualDocs(unittest.TestCase):
    """#493's plan-integrity CLI (`--verify-plan`/`snapshot_out_files`/
    `content_mismatched_files`) was manual-pipeline-only (dispatch.py's
    `dispatch-plan*.json` glob + `synthesize --files` hash check); `driver
    run` never invokes it. The driver's own self-write safety net -- a
    malformed write fails its done-predicate and gets re-dispatched -- is
    documented in the run-loop section and is what this re-anchors to."""

    def test_skill_instructs_malformed_selfwrite_redispatch(self):
        skill = _read_doc()
        self.assertIn("_cell_done", skill)
        self.assertIn("_verify_cell_done", skill)
        self.assertIn("re-dispatched", skill)


class TestTheStampContractIsWrittenDown(unittest.TestCase):
    """D10 ruling 4: the role contract now differs between the two delivery
    paths, and an operator reading the guide has to be able to tell which one
    they are on."""

    def setUp(self):
        self.loop = _section(_read_doc(), "## Driver run-loop", "## Driver setup")

    def test_the_guide_says_who_owns_the_stamp_on_each_path(self):
        for phrase in ("the `_panopticon` stamp is the DRIVER's to fill",
                       'stamped_by: "controller"', "is never overwritten",
                       "self-written"):
            self.assertIn(phrase, self.loop, phrase)

    def test_the_guide_says_where_a_refused_reply_goes(self):
        # D10 ruling 1/2: an operator whose run refuses a reply has to be able
        # to find the reply, the row that names it, and the retry that quotes
        # it -- none of it is guessable from the stderr line alone.
        for phrase in ("runs/<tag>/rejected/<entry-id>-<attempt>.json",
                       "rejected_file", "prior_rejection"):
            self.assertIn(phrase, self.loop, phrase)
