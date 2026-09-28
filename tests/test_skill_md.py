import os
import re
import unittest

import scripts.hosts as hosts
from tests.doc_helpers import (
    _read_doc, _section,
)

class TestSkillMd(unittest.TestCase):
    def setUp(self):
        # 5.0 doc split: SKILL.md keeps the skill frontmatter + a brief overview;
        # the full user guide, driver spec, and schema contracts live in
        # docs/PANOPTICON.md. Body-content tests read the guide; frontmatter tests
        # read SKILL.md directly.
        self.text = _read_doc()
        skill_path = os.path.join(os.path.dirname(__file__), os.pardir, "skill", "SKILL.md")
        with open(skill_path, encoding="utf-8") as fh:
            self.skill_md = fh.read()

    def test_has_frontmatter_name(self):
        self.assertTrue(self.skill_md.startswith("---"))
        self.assertRegex(self.skill_md, r"(?m)^name:\s*panopticon\s*$")

    def test_references_scripts_and_agents(self):
        # 5.0: orchestrator.py is retired (Slice A); driver.py is the
        # collapsed doc's canonical entrypoint.
        for ref in [
            "scripts/driver.py",
            "scripts/synthesize.py",
            "scripts/dispatch.py",
            "agents/scout.md",
            "agents/advisor.md",
        ]:
            self.assertIn(ref, self.text, ref)

    def test_documents_bounded_floor_and_gate(self):
        self.assertIn("--full", self.text)
        self.assertIn("--fail-on", self.text)
        self.assertIn("--severity", self.text)

    def test_documents_tool_layer_and_flags(self):
        for token in ["--tools", "--no-tools", "--epss", "scripts/ingest_tools.py"]:
            self.assertIn(token, self.text, token)

    def test_documents_cost_ledger(self):
        # 4.3.2: meta.cost is the measured 4.x baseline for 5.x economics.
        self.assertIn("meta.cost", self.text)
        self.assertIn("{phase, role, model, count}", self.text)
        # Fix round 1: the ledger's own field is `denials` (what
        # Ledger.record writes) -- `permission_denials` names only the
        # incoming host envelope this field carries, and the doc must not
        # claim that's the key on disk.
        self.assertIn("denials", self.text)

    def test_an_unreadable_tools_manifest_is_documented_as_failing_certification(self):
        # #1644: the three levels have to stay separable in prose too --
        # absent, unreadable, and parseable-but-malformed are three different
        # facts with three different outcomes, and only the middle one is an
        # integrity failure.
        for token in ["unreadable tools manifest is an integrity failure",
                      "meta.integrity.tools_manifest_invalid",
                      "not computed from the scout's advisory list",
                      # Fix round 1 F1: the gate consequence is the half a
                      # reader must not have to infer. #1761 narrowed "every
                      # other entry" to every other SINKING entry -- seven keys
                      # in that section do not gate, and the sentence claimed
                      # they did.
                      "fails `integrity_ok` like every other SINKING entry",
                      "`synth/integrity.INTEGRITY_KEYS` says which",
                      "INCONCLUSIVE",
                      "ABSENT manifest", "malformed FIELDS"]:
            self.assertIn(token, self.text, token)

    def test_documents_the_host_capability_disclosure_and_that_it_does_not_gate(self):
        # #1344 F3b. This file is the operator-facing contract: it already
        # documents meta.cost, meta.coverage, meta.integrity and even the
        # terminal summary's `**Resume:**` presence/absence semantics as
        # consumer guarantees. F3b adds a fifth meta section and three more
        # surfaces, and a guarantee nobody wrote down is not one.
        for token in ["meta.host_capabilities", "host-capabilities.json",
                      "probed_at", "`**Host capabilities:**`",
                      "driver: host capabilities:", "host-capability:"]:
            self.assertIn(token, self.text, token)
        section = _section(self.text, "## Host capabilities (5.2)", "\n## ")
        # It DISCLOSES; it does not gate. Said out loud, because the ratchet to
        # gating is a real later decision (spec 12) and an operator reading
        # "refuted" has to know whether their build just broke.
        self.assertIn("not gating", section)
        # `probed_at` names when the posture was ESTABLISHED and has held from
        # -- an interval -- not when the probes last ran.
        # driver._establish_host_posture rewrites the artifact only when
        # `capabilities` moves, so on a resume a "when the probes ran" reading
        # is simply false: the stamp is the first invocation's. The interval
        # reading is the stronger claim as well as the true one, and this pins
        # the file against quietly reverting to the weaker, false one.
        self.assertIn("established", section)
        self.assertIn("continuously from `probed_at`", section)
        self.assertNotIn("`probed_at` is when the PROBES ran", section)
        # Every capability the registry measures, named -- so adding one to
        # hosts.CAPABILITIES without documenting it fails here.
        for capability in hosts.CAPABILITIES:
            with self.subTest(capability=capability):
                self.assertIn(capability, section)

    def test_documents_the_discovery_surface_probe_and_its_override(self):
        # #1657 step 3. The step-2 paragraph (#1717) promised a probe that
        # "will report a target's discoverable files run by run"; it exists
        # now, and it REFUSES. An operator whose run stops on a file their
        # target ships has to be able to find out here what stopped it and
        # what the override is -- the same pairing the shadow-shell refusal
        # already documents.
        for token in ["`target-discovery-surface`", "--allow-unenforced",
                      "refuses the run when the target ships a file no "
                      "control closes"]:
            self.assertIn(token, self.text, token)

    def test_documents_f4_model_binding_scope_and_the_return_persist_bridge(self):
        # #1344 F4. Three contract sentences changed: the entry shape gained
        # `files` and a derived `delivery`; the return-persist exception is no
        # longer one role but any write-capable role on a host that has not
        # proven artifact_write_guard; and model_binding now HAS a probe.
        for token in ["entry-model-bound", "`files`", "return_json",
                      "artifact_write_guard", "PANOPTICON_MODEL_"]:
            self.assertIn(token, self.text, token)
        section = _section(self.text, "## Host capabilities (5.2)", "\n## ")
        # The F3b sentence this plan makes false must be gone, not amended around.
        self.assertNotIn("`model_binding` have no probe yet", section)
        self.assertIn("registration silently wins", section)
        # R-F4-1: the one claude behaviour change is written down where an
        # operator will read it, not only in a plan file. Both "unenforced"
        # and "session" already occur elsewhere in this section (the
        # host_disclosure mood-quote, usage_ledger's transcript-session
        # sentence) so those tokens alone pass vacuously -- pin phrasing that
        # only the R-F4-1 sentence itself contains.
        self.assertIn("profile model", section)
        self.assertIn("calling session's model", section)

    def test_documents_the_retirement_bar_and_the_generic_fallback_history(self):
        section = _section(self.text, "## Host capabilities (5.2)", "\n## ")
        # Tokens that exist only in the sentences D1 rewrote (review round 1:
        # the base paragraph passed the old three assertions verbatim, so
        # they guarded nothing). "deprecated" survives only as history (D4's
        # original wording, superseded by D1 -- spec 8.3 option 1).
        self.assertIn("permanent, unenforced fallback", section)
        self.assertIn("owner ruling D1", section)
        self.assertIn("NO-REGRESSION GUARD", section)
        self.assertIn("test_generic_retirement_bar", section)
        self.assertIn("test_todays_shortfall_is_pinned_so_it_moves_consciously",
                      section)
        self.assertIn("deprecated", section)
        self.assertIn("#1070", section)

    def test_documents_the_read_guard(self):
        # #1344 plan 5: the read guard is a host duty alongside the write
        # guard, and read_scope_confined moves from unprobed-everywhere to
        # proven-on-claude. Both surfaces must say so. Plan 6: arming/tearing
        # down both guards is now the LOOP's job at every checkpoint, not a
        # hand-run "Fan-out (per checkpoint)" bullet list (deleted) -- anchor
        # on the run-loop section as a whole instead.
        doc = _read_doc().replace("**", "")
        run_loop = doc[doc.index("## Driver run-loop"):doc.index("## Driver setup")]
        self.assertIn("read_guard_hook.install", run_loop)
        self.assertIn("read_guard_hook.uninstall", run_loop)
        # Fix round 1: the marker-line binding contract (still live code --
        # read_guard_hook.adjudicate falls back to the transcript marker
        # whenever PANOPTICON_ENTRY_ID is absent) was dropped with the
        # deleted fan-out list and never re-homed. Session mode is exactly
        # where a host still spells this out by hand, so it belongs there.
        self.assertIn("panopticon-entry:", run_loop)
        self.assertIn('entry["marker"]', run_loop)
        caps = doc[doc.index("## Host capabilities (5.2)"):doc.index("## Code layout (5.2)")]
        self.assertIn("read-guard-armed", caps)
        self.assertNotIn("`read_scope_confined` is `unknown` on every host today", caps)
        self.assertNotIn("fails the deletion on `read_scope_confined` everywhere", caps)
        # #1621: this used to pin "today it fails the deletion **on gemini**
        # alone". The section now says the opposite -- the bar is met -- and
        # the old `assertIn("on gemini", caps)` went on passing on the
        # past-tense clause that replaced it, guarding nothing. Pin the
        # paragraph the retirement actually added, and pin the one thing in it
        # that is easy to overclaim: which entrypoints refuse a stale manifest.
        # (`caps` has already had its `**` stripped by the replace above.)
        #
        # #1624 moved that claim: the refusal was `driver loop`'s alone and
        # `driver run` "still proceeds"; now BOTH refuse it, in one sentence
        # the registry owns. The three assertions below are kept as they
        # were -- and they are exactly why the rest are needed, because both
        # entrypoint names appear under either claim, so a name substring
        # never said WHICH claim the doc was making. Pin the claim itself,
        # and pin the retired one as absent so the doc cannot drift back to a
        # `driver run` that proceeds.
        retired = _section(caps, "`gemini` is registered but not driver-selectable",
                           "\n\n")
        self.assertIn("`--host generic`", retired)
        self.assertIn("driver loop", retired)
        self.assertIn("driver run", retired)
        self.assertIn("both", retired)
        self.assertIn("in the same sentence", retired)
        self.assertIn("`--host generic --reset`", retired)
        self.assertIn("hosts.unselectable_host_message", retired)
        self.assertNotIn("still proceeds", retired)
        # Fix round 1: and the paragraph must keep the two cases apart. A name
        # with no registry ROW is not "no longer selectable" -- nothing was
        # retired -- and it never reaches either refusal, because
        # `run_manifest.load_manifest` discards such a manifest one layer
        # earlier. A reader who conflates them concludes the refusal has a gap
        # it does not have.
        self.assertIn("run_manifest.load_manifest", retired)
        self.assertIn("discards it as unusable", retired)

    def test_documents_the_read_guard_on_scout_and_setup_scan_checkpoints(self):
        # I4: coverage._scout_entry and setup._setup_scan_entry also emit
        # markers+scopes and their templates tell the agent the fence is
        # host-enforced -- the arming duty must be stated at those two
        # checkpoints too, not only generically for review/verify. Plan 6:
        # the "Fan-out (per checkpoint)" bullet list is gone (the loop does
        # this now), so the scout paragraph's end anchor is the next kept
        # paragraph instead.
        doc = _read_doc().replace("**", "")
        scout_para = doc[doc.index("At the `scout` checkpoint"):doc.index("A malformed self-write")]
        self.assertIn("read_guard_hook.install", scout_para)
        self.assertIn("read_guard_hook.uninstall", scout_para)
        setup_para = doc[doc.index("1. scan —"):doc.index("2. ingest —")]
        self.assertIn("read_guard_hook.install", setup_para)

    def test_documents_delivery_as_the_complete_return_persist_contract(self):
        # #1608: every return-persist entry carries the key; absence means
        # self-write. The token below exists only in the sentence this task adds.
        self.assertIn("absent means the agent self-writes", self.text)
        # Markdown emphasis must not hide a stale phrase from this guard -- the
        # retired sentence read "the two **return-persist** rounds", and a
        # literal substring check on raw text would let `**` split it right
        # past assertNotIn. Normalize before asserting.
        flat = self.text.replace("**", "")
        self.assertNotIn("the two return-persist rounds", flat)

    def test_documents_unloadable_verdicts_gate_enforced(self):
        # #979: un-loadable verdicts are not just surfaced — they dent the gate.
        self.assertIn("meta.coverage.verdicts.unloadable", self.text)

    def test_documents_redaction_at_the_inputs_and_over_the_whole_tree(self):
        # #1634: the doc used to imply redaction was a post-build pass over the
        # findings. It is two passes — the inputs, then the WHOLE report tree —
        # and the derived fields are why. A doc that names only one of them is
        # how the next producer gets written against the wrong contract.
        section = _section(self.text, "**Secret redaction",
                           "## Host capabilities (5.2)")
        for token in ["redact.redact_tree", "before", "build_report",
                      "summary.top_issues", "groups[].key_findings",
                      "render.redact_report_secrets", "whole report tree",
                      "any depth", "cross_panel", "meta.host_capabilities",
                      # F1: the verify-queue branch is why the placement of the
                      # input pass is load-bearing, not merely tidy.
                      "--emit-verify-queue", "verify-queue.json", "queue id",
                      # F3: the guarantee holds for structured data, not for
                      # prose that happens to contain a token-shaped substring.
                      "come back identical", "token-shaped substring", "#1572"]:
            self.assertIn(token, section, token)

    def test_description_is_trigger_only_and_host_neutral(self):
        m = re.search(r"(?m)^description:\s*(.+)$", self.skill_md)
        self.assertIsNotNone(m)
        desc = m.group(1)
        self.assertTrue(desc.startswith("Use when"), desc)
        self.assertNotIn("Kimi", desc)
        self.assertNotIn("→", desc)  # no workflow summary

    def test_driver_run_loop_documents_host_dispatch(self):
        # 5.0: the standalone `## Host dispatch` section (keyed to the
        # deleted manual pipeline) is gone -- host dispatch is now a
        # paragraph inside the driver run-loop. `driver run --host` only
        # accepts claude|generic; Gemini/Kimi/Codex are named as the generic
        # path's examples, not as separate --host values. Plan 6: the loop
        # names Claude as the concrete headless runner and falls back to
        # session mode (which every generic-path host uses) for everything
        # else, rather than a per-host dispatch bullet each.
        self.assertNotIn("## Host dispatch", self.text)
        loop = _section(self.text, "## Driver run-loop", "## Output")
        for host in ("Claude", "kimi", "generic"):
            self.assertIn(host, loop, host)

    def test_skill_md_names_the_python_packages_a_run_needs(self):
        # #1639 P15 I2: SKILL.md said the three sub-skills were the only
        # external things this skill asks for. Two Python packages are not
        # optional, and the one this PR made load-bearing fails AFTER the
        # review is paid for, so the operator meets it in the wrong place.
        deps = _section(self.skill_md, "## Dependencies", "Where hosts typically look")
        for token in ("pyyaml", "jsonschema", "pip install",
                      "driver readiness", "dependencies"):
            self.assertIn(token, deps, token)

    def test_the_guide_distinguishes_completion_validity_and_certification(self):
        # #1639 P15: the run-13 ledger's complaint was that final-schema
        # assurance lived in a controller-side check, and that terminal
        # completion, artifact validity and coverage certification were not
        # told apart anywhere an operator reads. The Output section is where
        # an operator meets an exit code, so the distinction is pinned HERE,
        # in the paragraph that has to carry it -- including the two artifacts
        # a reader would otherwise never know were validated (the hydrated
        # split union and the X0X sibling) and the fail-closed rule.
        out = _section(self.text, "## Output", "## Host capabilities")
        for token in (
            "Terminal completion, artifact validity and coverage certification",
            "report-schema.json",
            "x0x-report-schema.json",
            "hydrated",
            "artifact invalid: N schema errors",
            "fail-closed",
            # Fix round 1: the principle that makes a terminal schema failure
            # safe to have at all.
            "The schema pins the *controller's* output",
            "never a lever a reviewed repository or a reviewer can pull",
            "SCHEMA pre-write:",
            "SCHEMA artifact:",
        ):
            self.assertIn(token, out, token)
        # The exit code is stated with the others, not only in prose.
        self.assertIn("exits `1` on FAIL, `2` on INCONCLUSIVE, `4` when an "
                      "artifact it wrote fails its own published schema", out)

    def test_pins_round1_flags_and_render_advisor(self):
        for token in [
            "--gate-unverified",
            "--max-verify",
            "--render-advisor",
            "--host",
            "--verdicts-dir",
        ]:
            self.assertIn(token, self.text, token)

    def test_return_contract_by_role(self):
        # 5.0: driver fan-out (review/verify) is uniformly self-write; only
        # the scout checkpoint is read-only + return-persist (the scout
        # can't self-write). This supersedes the pipeline-era contract where
        # the advisor also RETURNED its JSON for the orchestrator to persist
        # -- under the driver the advisor self-writes its verdict just like
        # a reviewer -- and the old dot-notation `entry.out_file`, since
        # driver entries are dicts (`entry["out_file"]`).
        self.assertIn("self-writes** its own", self.text)
        self.assertIn('entry["out_file"]', self.text)
        self.assertIn("returns a one-line confirmation", self.text)
        self.assertIn("each scout is **read-only** and RETURNS", self.text)
        self.assertNotIn("their tool policy allows Bash", self.text)

    def test_host_dispatch_is_enforcement_conditional(self):
        # Plan 6: the loop dispatches through the runner's CLI (`--agent`),
        # not an SDK-style `subagent_type:` dispatch a host performed by hand.
        for token in ("enforced", "--agent", "--agents-dir", "--emit-host-agents"):
            self.assertIn(token, self.text, token)

    def test_clean_tree_check_and_hostile_guidance(self):
        self.assertIn("git status --porcelain", self.text)
        self.assertIn("treat the run as compromised", self.text)
        self.assertIn("enforcement registered", self.text)

    def test_all_four_roles_have_shell_dispatch_instructions(self):
        for token in ("panopticon-scout", "panopticon-advisor", "tree-baseline.txt"):
            self.assertIn(token, self.text, token)

    def test_all_script_commands_use_repo_root_prefix(self):
        # `python3 scripts/...` is ambiguous: from the repo root it hits the
        # WRONG directory (repo-root scripts/ = file_issues/triage, not the
        # pipeline). Every command must use the repo-root `skill/scripts/` prefix.
        offenders = [ln for ln in self.text.splitlines() if "python3 scripts/" in ln]
        self.assertEqual(offenders, [])

    def test_all_file_mentions_use_skill_prefix(self):
        # File MENTIONS must be repo-root-relative too, not just commands.
        # Both `agents/` and `scripts/` references must be prefixed with `skill/`.
        import re

        bare = [ln for ln in self.text.splitlines() if re.search(r"(?<!l)`(scripts|agents)/", ln)]
        self.assertEqual(bare, [], "bare scripts/ or agents/ path (run-from-where?): %r" % bare)

    def test_tool_scan_step_is_deterministic_not_optional(self):
        # 5.0: the tool scan is a driver PHASE (`tools`), not a numbered
        # manual-pipeline step -- re-anchored to the phase's own prose in
        # the driver run-loop, bounded by the next phase's backtick marker.
        loop = _section(self.text, "## Driver run-loop", "## Driver setup")
        tools = _section(loop, "`tools`**", "`review`**")
        self.assertNotIn("optional", tools.lower())
        self.assertIn("run_tools.py", tools)
        self.assertIn("--no-tools", tools)
        self.assertTrue("LOUD" in tools or "loudly" in tools.lower())

    def test_readiness_is_documented_as_the_loops_first_step(self):
        # #1637 P08: the guide is where an operator meets a refusal they have
        # not yet hit. Three things have to be findable: that it runs FIRST,
        # that it fails closed, and the exact command that clears it.
        loop = _section(self.text, "## Driver run-loop", "## Driver setup")
        self.assertIn("`readiness` → `discovery`", loop)
        readiness = _section(loop, "`readiness`**", "`discovery`**")
        self.assertIn("fails closed", readiness)
        self.assertIn("docker pull ghcr.io/panopticon-scanner/"
                      "panopticon-tools:latest", readiness)
        self.assertIn("docker build -t panopticon-tools", readiness)
        self.assertIn("readiness.json", readiness)
        # The opt-out is DISCLOSED, which is the whole argument for letting it
        # exist: a doc that names the flag without naming where the choice
        # shows up teaches operators to reach for it as a silencer.
        self.assertIn("--no-tools", readiness)
        self.assertIn("disclosed opt-out", readiness)
        self.assertIn("meta.tools.panels_with_scanner_context", readiness)
        self.assertIn("first step is the readiness checkpoint", loop)
        # F6: the sentence may not claim more than the code does --
        # `_establish_host_posture` runs before the engine and, on a host whose
        # probes interrogate its CLI, that is a real launch. Ruling 2's
        # guarantee is that readiness dispatches nothing, which is what the
        # doc now says.
        self.assertIn("Before any paid dispatch", loop)
        self.assertNotIn("arms a guard or launches anything", loop)

    def test_the_guides_gating_sentence_names_every_row_that_gates(self):
        """#2245 (ARC-1308156980): the guide enumerated four of the five gating
        rows, so an operator reading it could not predict which failing row
        exits 1 -- `dependencies` was missing, and a missing package is the one
        readiness failure a fresh checkout meets first.

        The names come from the code, not from a second list: `GATING_ROWS` is
        what `phases/readiness.preflight` builds `failed` from, in the order
        `failed` reports them. Either spelling counts, because the table labels
        `tools-image` with a hyphen while the `--json` document keys it
        `tools_image`.
        """
        import scripts.phases.readiness as readiness
        loop = _section(self.text, "## Driver run-loop", "## Driver setup")
        sentence = _section(loop, "Gating rows are", "marked `→` in the table")
        self.assertTrue(readiness.GATING_ROWS, "no gating rows to check")
        for name in readiness.GATING_ROWS:
            with self.subTest(row=name):
                self.assertTrue(
                    "`%s`" % name in sentence
                    or "`%s`" % name.replace("-", "_") in sentence,
                    "the guide's gating sentence does not name the gating row "
                    "%r, so the doc predicts a different exit code from the "
                    "code: %r" % (name, sentence))

    def test_the_evidence_chapter_spells_every_status_and_the_gate_eligible_set(self):
        """#2245 (ARC-2689115794): the chapter that ENUMERATES the statuses
        listed seven of eight, omitting `backup_scope_limited` -- the one status
        invented so an evidence-scope failure could not quietly decide a gate --
        and an operator reading only that list mis-predicts the gate on it.

        Both constants are read from `scripts.evidence`, so adding a ninth
        status or widening the default gate set fails here until the chapter
        says so. The bullet list and the gate sentence are checked separately:
        a status named in passing further down the chapter is not an entry in
        the list a reader counts.
        """
        import scripts.evidence as evidence
        chapter = _section(self.text, "## Evidence", "## Notes")
        statuses = _section(chapter, "how hard the claim was verified):",
                            "\nGrades and the CI gate ")
        for name in evidence.EVIDENCE_STATUSES:
            with self.subTest(status=name):
                self.assertIn("`%s`" % name, statuses,
                              "the evidence chapter's status list does not "
                              "name %r" % name)
        gate = _section(chapter, "Grades and the CI gate ", "Run a verify phase")
        for name in sorted(evidence.GATE_ELIGIBLE_DEFAULT):
            with self.subTest(gate_eligible=name):
                self.assertIn("`%s`" % name, gate,
                              "the chapter's gate sentence does not name the "
                              "gate-eligible status %r" % name)

    def test_the_test_inventory_diagnostic_is_documented(self):
        # #1638 P13: an operator who meets `Test inventory: X: empty` in a
        # report, or a `TST-X0X` INFO finding in the JSON, has to be able to
        # find out what it means and what fixes it -- which is the matrix,
        # not the target's test suite.
        loop = _section(self.text, "## Driver run-loop", "## Driver setup")
        review = _section(loop, "`review`**", "`synthesize`**")
        self.assertIn("meta.coverage.test_inventory", review)
        self.assertIn("panopticon.yml", review)
        # Fix round 1, F1: the state is DRIVER-computed and already published;
        # no agent files a finding for it, so the guide must not promise one
        # (an X0X from a non-TST cell was rewritten to that cell's domain and
        # clustered as a bogus OCRDb candidate).
        self.assertNotIn("TST-X0X", review)
        self.assertIn("no finding", review)

    def test_the_backup_evidence_closure_is_documented(self):
        # #1638 P16 (ruling D4): an operator reading a `backup_scope_limited`
        # finding has to be able to find out that the backup was granted a
        # BOUNDED closure, that the grant is recorded in the verdict, and that
        # a scope-limited NEEDS_MORE_INFO does not overrule the primary.
        loop = _section(self.text, "## Driver run-loop", "## Driver setup")
        verify = _section(loop, "`review`** / **`verify`**", "- **`synthesize`**")
        self.assertIn("bounded closure", verify)
        self.assertIn("evidence_scope", verify)
        self.assertIn("missing_evidence", verify)
        self.assertIn("backup_scope_limited", verify)
        # Fix round 1: the two honesty details an operator needs -- the entry
        # ceiling, and that the status is NOT counted as verified.
        self.assertIn("entry_truncated", verify)
        self.assertIn("coverage line", verify)
        # Fix round 4, N3: the CANONICAL shape list -- the one an advisor is
        # told to copy -- must be the whole shape. It named `floor_count` two
        # clauses earlier and then listed six keys.
        self.assertIn("evidence_scope: {granted, cap, truncated, entry_cap, "
                      "entry_truncated, floor_count}", verify)
        # #1688: a claim names `config.py`, not always the full repo-relative
        # path. The operator has to be able to find out how that name was
        # resolved -- and that two DIFFERENT files of one name resolve to
        # neither, with the ambiguity disclosed to the backup rather than
        # guessed at.
        self.assertIn("unique suffix", verify)
        self.assertIn("ambiguous", verify)

    def test_an_environmental_tool_skip_is_documented_as_retried(self):
        loop = _section(self.text, "## Driver run-loop", "## Driver setup")
        tools = _section(loop, "`tools`**", "`review`**")
        self.assertIn("environmental", tools.lower())
        self.assertIn("re-evaluated on the next `driver run`", tools)
        # F1/F2: the cadence and the non-destructive exit are the two things
        # an operator staring at a stalled run needs to find.
        self.assertIn("scoped to the **invocation**", tools)
        self.assertIn("non-destructive rescue", tools)
        self.assertIn("meta.tools.disabled_mid_run", tools)

    def test_discovery_is_documented_as_completing_only_on_a_valid_artifact(self):
        # #1643: the phase that "succeeds emptily" is the one an operator will
        # never think to check, so the guide has to say what completion
        # REQUIRES, that an empty delta scope is still a legitimate answer, and
        # what a second malformed round does.
        loop = _section(self.text, "## Driver run-loop", "## Driver setup")
        disco = _section(loop, "`discovery`**", "`coverage`**")
        for token in ["well-formed groups artifact", "`run_id`",
                      "at least one group", "empty delta",
                      # F6: `--files` selects a set too, so it may select none.
                      "`--files` whose list pruned to nothing",
                      "discovery produced no usable groups"]:
            self.assertIn(token, disco, token)
        # Ruling 3: the audit of the other parse-only predicates is part of the
        # same statement -- a reader must not conclude discovery was the only one.
        for token in ["`coverage` counts a group covered only when",
                      "`effective` list", "carrying a `summary`"]:
            self.assertIn(token, disco, token)

    def test_raw_captures_are_documented_as_redacted_before_they_are_written(self):
        # #1639 P11: `.panopticon/tools/` is what an operator copies into a CI
        # artifact, and the report's redaction never reached it. The guide has
        # to name the choke point, the pattern set it shares with the report,
        # the scanner-native half, and the two things a reader would otherwise
        # assume wrong -- that structure survives, and that the byte cap is
        # still measured on the RAW stream.
        loop = _section(self.text, "## Driver run-loop", "## Driver setup")
        tools = _section(loop, "`tools`**", "`review`**")
        for token in ["_redact_capture", "redact.redact_tree", "string-leaf",
                      "before they are written", "gitleaks", "--redact",
                      "ruleId", "byte-identical", "RAW stream",
                      "`redacted: true`", "last line break"]:
            self.assertIn(token, tools, token)

    def test_pip_audit_is_documented_as_auditing_a_generated_list(self):
        # #1646 (SEC-E3A): pip-audit RESOLVES what a requirements file names,
        # and an editable/local/VCS/URL requirement makes that run the reviewed
        # repo's build backend. The guide has to say that the file it is given
        # is GENERATED, that the audit is therefore partial, and where an
        # operator finds out by how much -- otherwise "pip-audit: produced"
        # keeps reading as "every declared dependency was checked".
        loop = _section(self.text, "## Driver run-loop", "## Driver setup")
        tools = _section(loop, "`tools`**", "`review`**")
        for token in ["generated", "sanitized", "PEP 517", "PEP 508",
                      "tools-manifest.json", "meta.tools.sanitized",
                      "requirement lines not audited", "one level",
                      # Fix round 1: the two controls the first cut lacked and
                      # the bounds on what it publishes. An operator reading
                      # "no URL, no path" has to learn that pip decides a name
                      # is an archive on a SUFFIX, and that the disclosure is
                      # capped rather than complete.
                      "ARCHIVE_EXTENSIONS", "archive name", "working directory",
                      "outside target", "1 MiB", "200"]:
            self.assertIn(token, tools, token)

    def test_online_adapter_egress_is_documented(self):
        # #1645 (SEC-C1A): the two ONLINE_ONLY adapters used to get Docker's
        # DEFAULT BRIDGE -- every service reachable from the runner's network.
        # The guide has to name the control (a per-run internal network and an
        # allowlisting proxy), the allowlist itself, where a reader finds the
        # posture, what happens when the egress cannot be built, and -- the
        # part a claim of "nothing else" would get wrong -- the two limits of
        # the containment: it is stated for a ROOTFUL daemon, and an internal
        # network still reaches its own gateway address.
        loop = _section(self.text, "## Driver run-loop", "## Driver setup")
        tools = _section(loop, "`tools`**", "`review`**")
        for token in ["default bridge", "--internal", "tinyproxy",
                      "FilterDefaultDeny Yes", "pypi.org",
                      "files.pythonhosted.org", "registry.npmjs.org",
                      "NO_PROXY", "meta.tools.network", "excluded_scope",
                      "fails closed", "rootful",
                      # Fix round 1, F1: Docker documents that an `--internal`
                      # network still permits communication with the gateway
                      # IP, so a host service bound there is NOT fenced by
                      # this control. The claim has to stop short of absolute.
                      "gateway",
                      # F10: which artifact carries which fact.
                      "tools-ran.json"]:
            self.assertIn(token, tools, token)

    def test_tools_dir_is_wired_into_synthesize_passes(self):
        # F-2: a scan that runs but is never ingested reads as clean. 5.0:
        # the tool scan is a driver PHASE now, wired into the driver's own
        # synthesize invocation -- re-anchored from the deleted `## Pipeline`
        # to the driver run-loop section.
        loop = _section(self.text, "## Driver run-loop", "## Output")
        self.assertIn("--tools-dir .panopticon/tools", loop)

    def test_documents_default_tool_path_fixture_prune(self):
        # The tool-ingest path prunes fixture-corpus findings by default (parity
        # with the #434 review prune); --include-fixtures is the redteam escape
        # hatch. Doc must not still tell users --tools-exclude is REQUIRED to
        # stop fixture CVEs reappearing on the tool path.
        self.assertIn("--include-fixtures", self.text)
        self.assertRegex(self.text, r"(?i)tool-path parity|prunes tool findings")
        self.assertNotIn("or tool findings on fixtures reappear on that path", self.text)

    def test_has_driver_run_loop_section(self):
        self.assertIn("## Driver run-loop", self.text)
        loop = _section(self.text, "## Driver run-loop", "## Output")
        # the controller loop + status protocol -- plan 6: `driver run` is
        # named as the primitive the loop calls, not given its own fully
        # qualified `driver.py run` invocation line (that belongs to `loop`
        # and `persist` now).
        self.assertIn("driver run", loop)
        for word in ("checkpoint", "dispatch-request.json", "re-invoke", "complete"):
            self.assertIn(word, loop)
        # C2 (plan 6 final review): the request path is a FIELD of the printed
        # `dispatch` status, not a fixed location -- a review's request is
        # per-run (`runs/<tag>/`) and `--setup`'s is a different file entirely
        # -- so the guide must send a session host to `dispatch_request`
        # rather than to a path it would hard-code and get wrong.
        self.assertIn("`dispatch_request` field", loop)
        # Fix round 2: the per-entry failure cap is a documented termination
        # condition, not an implementation detail -- an operator whose run
        # stops after three launches of one cell has to be able to find out
        # why, and that it is not something a flag can raise.
        self.assertIn("per-entry cap of 3 consecutive", loop)
        # #1623: `paused` is a TERMINAL status of its own, and an operator
        # whose run stopped has to be able to tell a host-wide outage (auth,
        # quota, rate limit: nothing charged, nothing lost, re-run it) from a
        # cell that genuinely cannot answer. Pinned to the code's own clause,
        # exactly as the interrupt sentence below is -- a guide that describes
        # a termination condition the loop no longer has is worse than silence.
        import scripts.runners.outage as outage
        self.assertIn("`paused`", loop)
        self.assertIn(outage.HOST_OUTAGE_CLAUSE, loop)
        # #1732: the SECOND stop rule ends a run the same way, for a
        # different cause and a different remedy -- an operator whose run
        # stopped has to be able to tell "wait for the host" from "fix the
        # launch", and the give-back is the part they act on.
        self.assertIn("%d ms" % outage.UNIFORM_FAST_MS, loop)
        self.assertIn("charges **nobody**", loop)
        # ...and the ledger row that makes an identical batch diagnosable at
        # all: the CLI's own words, which run 14's rows did not carry.
        self.assertIn("`stderr`", loop)
        self.assertIn("200", loop)
        # I6 (fix round 3): `driver persist` grew `--pr`/`--base` because a PR
        # run's review root is the worktree; a session host that does not pass
        # them gets "no entry in the current dispatch request" and no clue why.
        self.assertIn("pass the same `--pr`/`--base` to **both**", loop)
        # I8: same for the guide -- the documented default names the condition.
        self.assertIn("default: headless when the host has a headless runner, "
                      "otherwise session", loop)
        # unified guard-confined self-write (no write_mode/return handshake)
        self.assertIn("write-guard", loop)
        self.assertIn("self-write", loop)
        self.assertNotIn("write_mode", loop)
        # #1571: the confinement is PER ENTRY on both write guards, and the
        # guide used to describe the union as if it were per-agent. An
        # operator reading "its declared out_file" while the code enforced
        # "any out_file in the batch" is how the gap survived two self-scans.
        self.assertIn("bound to the entry", loop)
        self.assertIn("a peer entry's artifact is not writable", loop)
        # P07 (#1636): an operator has to be able to read that a completed
        # entry is already safe on disk -- the run-13 batch persisted nothing
        # for 42 minutes and an interruption lost all of it.
        self.assertIn("as each entry completes", loop)
        # #1662: the interrupt paragraph is pinned to the CODE's own sentence.
        # Nothing tied the two together before, which is how the guide came to
        # promise that every running child gets SIGTERM/SIGKILL -- true of the
        # seam, false of all three shipped runners. Read off the constant, not
        # re-typed: the `%d of %d` is the only part a prose sentence cannot
        # carry, so it is the only part dropped.
        import scripts.loop_batch as loop_batch
        clause = loop_batch.INTERRUPTED.split(";")[0].split("%d of %d ")[-1]
        self.assertEqual("entries had been handled and have been rolled back", clause)
        self.assertIn(clause, loop)
        # ...and the termination claim says whose children it can actually reach
        self.assertIn("registered a handle", loop)
        self.assertIn("process-group SIGINT", loop)
        # #1698: a kill that reaches no teardown leaves the batch's record, and
        # the next loop ROLLS IT BACK rather than overwriting it. The guide had
        # promised the opposite of both halves -- "keeps everything that already
        # finished" of a killed batch, and a record "removed when the batch
        # ends" full stop -- which is a resume reading a half-written reply as a
        # finished cell, described as working as intended.
        self.assertIn("rolls a crashed batch back before it resumes", loop)
        self.assertIn("read a half-written artifact as a finished cell", loop)
        self.assertIn("previous process stopped", loop)
        # ...and the three refusals an operator meets, pinned to the CODE's own
        # wording the way the interrupt sentence above is. A message reworded in
        # `loop_batch` without the guide following is how the last drift began.
        for clause, refusal in (("still running here", loop_batch.BATCH_OWNER_LIVE),
                                ("not this machine", loop_batch.BATCH_OWNER_ELSEWHERE),
                                ("no owner stamp", loop_batch.BATCH_OWNER_UNSTAMPED)):
            self.assertIn(clause, refusal)
            self.assertIn(clause, loop)
        # the live-owner refusal offers no `--reset` -- pointing an operator at
        # the run folder another loop is working in is the accident itself --
        # and the guide says so rather than leaving the omission to be read as
        # an oversight.
        self.assertNotIn("--reset", loop_batch.BATCH_OWNER_LIVE)
        self.assertIn("`--reset` is deliberately not offered", loop)
        # the fourth refusal, and setup's own folder
        self.assertIn("a record this batch would overwrite", loop)
        self.assertIn("`--setup --reset` sweeps them", loop)

    def test_driver_run_loop_documents_scout_return_persist(self):
        # The scout checkpoint is read-only + return-persist (the scout agent
        # can't self-write), distinct from the review/verify self-write
        # fan-out documented elsewhere in the same section.
        loop = _section(self.text, "## Driver run-loop", "## Output")
        self.assertIn("scout", loop)
        self.assertIn("ScopeProfile", loop)
        self.assertTrue("returns" in loop.lower() or "returned" in loop.lower(), loop)
        self.assertIn("read-only", loop)


class TestDocPolicyDocs(unittest.TestCase):
    def test_skill_documents_doc_severity_policy(self):
        skill = _read_doc()
        self.assertIn("--doc-paths", skill)
        self.assertIn("meta.coverage.doc_policy", skill)
