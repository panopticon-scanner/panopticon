import os
import re
import unittest

from conftest import SKILL_ROOT as ROOT   # #run7 TST-G1B: shared path anchor
import scripts.hosts as hosts

# #run7 QAL-D1C: the PANOPTICON.md guide was re-opened inline in 10 places.
# #1637 P01: it lives INSIDE the skill now (the repo-root path is a symlink
# onto it), so this anchor is `skill/docs/` -- the one constant that moved.
_DOC_PATH = hosts.guide_path()
# #1344 plan 5 T5: shared anchor for the dispatched-role template files.
AGENTS_DIR = os.path.join(ROOT, "agents")


def _read_doc():
    with open(_DOC_PATH, encoding="utf-8") as fh:
        return fh.read()


def _read_skill_md():
    with open(os.path.join(ROOT, "SKILL.md"), encoding="utf-8") as fh:
        return fh.read()


def _section(text, start, end):
    """Slice `text` between two heading markers, asserting BOTH exist first so a
    renamed marker fails loudly instead of raising an opaque IndexError (missing
    start) or silently over-scoping to the rest of the doc (missing end, a
    false-pass). #run7 ARC-A2B/TST-B3A."""
    assert start in text, "section marker not found: %r" % (start,)
    assert end in text, "section marker not found: %r" % (end,)
    return text.split(start, 1)[1].split(end, 1)[0]


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
                      # reader must not have to infer.
                      "fails `integrity_ok` like every other entry",
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

    def test_documents_the_retirement_bar_and_the_generic_deprecation(self):
        section = _section(self.text, "## Host capabilities (5.2)", "\n## ")
        # Tokens that exist only in the sentences this task adds.
        self.assertIn("test_generic_retirement_bar", section)
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

    def test_the_test_inventory_diagnostic_is_documented(self):
        # #1638 P13: an operator who meets `Test inventory: X: empty` in a
        # report, or a `TST-X0X` INFO finding in the JSON, has to be able to
        # find out what it means and what fixes it -- which is the matrix,
        # not the target's test suite.
        loop = _section(self.text, "## Driver run-loop", "## Driver setup")
        review = _section(loop, "`review`**", "`synthesize`**")
        self.assertIn("meta.coverage.test_inventory", review)
        self.assertIn("groups.yml", review)
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

    def test_driver_run_loop_documents_scout_return_persist(self):
        # The scout checkpoint is read-only + return-persist (the scout agent
        # can't self-write), distinct from the review/verify self-write
        # fan-out documented elsewhere in the same section.
        loop = _section(self.text, "## Driver run-loop", "## Output")
        self.assertIn("scout", loop)
        self.assertIn("ScopeProfile", loop)
        self.assertTrue("returns" in loop.lower() or "returned" in loop.lower(), loop)
        self.assertIn("read-only", loop)


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


class TestAdvisorDoc(unittest.TestCase):
    """#469: the advisor template must carry an explicit tool-claim branch --
    it drives tool_axis verdicts (tool_confirmed/rejected) but was written for
    agent claims only."""

    def test_advisor_has_tool_claim_guidance(self):
        with open(os.path.join(ROOT, "agents", "advisor.md"), encoding="utf-8") as fh:
            advisor = fh.read()
        self.assertIn("Tool claims", advisor)
        self.assertIn("tool:*", advisor)
        self.assertIn("pattern", advisor.lower())


class TestScoutDoc(unittest.TestCase):
    """#431: every schema-REQUIRED ScopeProfile field must be named in the
    scout template -- the schema and the prompt drift apart otherwise (the
    live failure: scouts omitted `languages`/`surfaces`)."""

    def test_scout_names_every_schema_required_field(self):
        import json as _json

        with open(
            os.path.join(ROOT, "reference", "scope-profile-schema.json"), encoding="utf-8"
        ) as fh:
            required = _json.load(fh)["required"]
        with open(os.path.join(ROOT, "agents", "scout.md"), encoding="utf-8") as fh:
            scout = fh.read()
        for field in required:
            self.assertIn(field, scout, field)


class TestReviewerScopeFence(unittest.TestCase):
    """#441: reviewer templates carry the scope fence."""

    def test_reviewer_templates_have_fence(self):
        # #run7 TST-A2A: domain-panel.md is the CURRENT 5.x dispatched reviewer;
        # its fence had zero coverage while two retired templates were checked.
        # #run10: those two retired templates are now deleted.
        for name in ("domain-panel.md",):
            with open(os.path.join(ROOT, "agents", name), encoding="utf-8") as fh:
                self.assertIn("Scope fence", fh.read(), name)

    def test_every_confined_role_states_the_enforced_fence(self):
        # Plan 5: the fence is host-enforced on claude (read_guard_hook); each
        # template tells the agent so, in words the denial reason echoes.
        roles = ("domain-panel.md", "domain-advisor.md", "scout.md", "advisor.md")
        self.assertTrue(roles, "a fence check over zero roles proves nothing")
        for name in roles:
            with self.subTest(template=name), open(os.path.join(AGENTS_DIR, name), encoding="utf-8") as fh:
                body = fh.read().replace("**", "")
                self.assertIn("confined", body)
                self.assertIn("Glob is not available", body)
                self.assertIn("grep a file by its path", body)
        with open(os.path.join(AGENTS_DIR, "setup-scan.md"), encoding="utf-8") as fh:
            body = fh.read().replace("**", "")
            self.assertIn("confined to the repository root", body)


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


class TestDocPolicyDocs(unittest.TestCase):
    def test_skill_documents_doc_severity_policy(self):
        skill = _read_doc()
        self.assertIn("--doc-paths", skill)
        self.assertIn("meta.coverage.doc_policy", skill)


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
        self.assertIn("groups.yml.draft", skill)


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
    `--advisor-model`) was manual-pipeline-only. `driver run --host` accepts
    only claude|generic today -- Codex isn't yet a first-class driver host,
    so it falls back to the generic/portable path; dispatch.py's legacy shell
    registration still covers it (`--emit-host-agents codex`, still true, is
    what this re-anchors to instead of the retired fan-out mechanism)."""

    def test_codex_documented_as_generic_fallback_with_legacy_registration(self):
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
        # Fix round 1 (F1): and the residual the rule does NOT cover, because
        # an operator deciding whether `--host claude` is safe against a
        # prepared tree reads this paragraph. The sentence it replaced claimed
        # parity with a broker that has no such gap.
        self.assertIn("#1683", doc)
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


def _registered_driver_flags():
    """Every option string `driver`'s parser actually registers, plus the
    positionals, keyed by the name a doc would use."""
    import scripts.driver as driver
    parser = driver.build_parser()
    options, positionals = set(), set()

    def _harvest(p):
        for action in p._actions:
            if action.option_strings:
                options.update(action.option_strings)
            elif action.dest not in ("command", "help"):
                positionals.add(action.dest)
        for group in p._subparsers._group_actions if p._subparsers else []:
            for sub in getattr(group, "choices", {}).values():
                _harvest(sub)

    _harvest(parser)
    return options, positionals


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


class TestClaudeSessionModeWorkflowTemplate(unittest.TestCase):
    """Claude family PR (#1344): session-mode dispatch on Claude Code is a
    shipped workflow template, mandated by SKILL.md, not an ad-hoc fan-out."""

    WORKFLOW = os.path.join(ROOT, "workflows", "dispatch.js")

    def test_the_dispatch_workflow_ships_with_its_meta_and_the_binding_rules(self):
        self.assertTrue(os.path.isfile(self.WORKFLOW), self.WORKFLOW)
        with open(self.WORKFLOW, encoding="utf-8") as fh:
            js = fh.read()
        self.assertIn("export const meta = {", js)
        for token in ("name: 'panopticon-dispatch'", "agentType", "prompt_file",
                      "e.marker + '\\n'", "return_json", "missing"):
            with self.subTest(token=token):
                self.assertIn(token, js)

    def test_the_dispatch_workflow_parses_as_javascript(self):
        import shutil
        import subprocess
        node = shutil.which("node")
        if not node:
            self.skipTest("node is not installed here; CI's runners have it")
        proc = subprocess.run([node, "--check", self.WORKFLOW], capture_output=True, text=True)
        self.assertEqual(0, proc.returncode, proc.stderr)

    def test_skill_md_mandates_the_workflow_for_session_mode_on_claude(self):
        skill = _read_skill_md()
        self.assertIn("skill/workflows/dispatch.js", skill)
        self.assertIn("Do not hand-dispatch entries with one-off Agent calls", skill)
        self.assertIn("marker, prompt_file, delivery, out_file", skill)

    def test_the_guide_names_the_workflow_and_grants_the_prompt_file_to_the_read_scope(self):
        doc = _read_doc()
        run_loop = _section(doc, "## Driver run-loop", "## Driver setup")
        self.assertIn("skill/workflows/dispatch.js", run_loop)
        self.assertIn("granted to the entry's read scope (`scope.reads`", run_loop)


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


class TestTheGuideResolvesInEveryInstallLayout(unittest.TestCase):
    """#1637 P01: `skill/` is what gets symlinked into `~/.claude/skills/`,
    `~/.kimi/skills/` and `~/.agents/skills/` (README), so SKILL.md's links are
    resolved relative to SKILL.md's OWN directory in every installed layout --
    and in the source checkout too. They pointed at `docs/PANOPTICON.md`, which
    lived at the REPO ROOT and never at `skill/docs/`, so the first read the
    skill instructs failed everywhere. The guide moved INTO the skill; the root
    path stays as a symlink so every root-level reference (README, DEVELOPMENT,
    docs/) keeps resolving to the same bytes.
    """

    ROOT_DOC = os.path.join(ROOT, os.pardir, "docs", "PANOPTICON.md")
    SKILL_DOC = os.path.join(ROOT, "docs", "PANOPTICON.md")

    def test_every_relative_link_in_skill_md_resolves_from_skill_mds_directory(self):
        skill_md = _read_skill_md()
        targets = sorted({
            t for t in re.findall(r"\]\(([^)]+)\)", skill_md)
            if not t.startswith(("http://", "https://", "#", "/"))})
        self.assertIn("docs/PANOPTICON.md", targets)
        missing = [t for t in targets
                   if not os.path.exists(os.path.join(ROOT, t.split("#", 1)[0]))]
        self.assertEqual(missing, [],
                         "SKILL.md link(s) that do not resolve from %s -- the "
                         "first read the skill instructs fails in every "
                         "installed layout:\n%s" % (ROOT, "\n".join(missing)))

    def test_the_guide_lives_inside_the_skill(self):
        self.assertTrue(os.path.isfile(self.SKILL_DOC), self.SKILL_DOC)

    def test_the_root_path_is_a_symlink_onto_the_very_same_file(self):
        self.assertTrue(os.path.islink(self.ROOT_DOC),
                        "%s must stay a symlink so README/DEVELOPMENT/docs "
                        "references keep resolving" % self.ROOT_DOC)
        self.assertTrue(os.path.samefile(self.ROOT_DOC, self.SKILL_DOC))
        self.assertEqual(os.readlink(self.ROOT_DOC),
                         os.path.join(os.pardir, "skill", "docs", "PANOPTICON.md"))

    def test_hosts_guide_path_names_that_file(self):
        self.assertEqual(os.path.realpath(hosts.guide_path()),
                         os.path.realpath(self.SKILL_DOC))
        self.assertTrue(os.path.isfile(hosts.guide_path()))


# #1637 P03: `superpowers:writing-plans` defaults to `docs/superpowers/plans/`,
# which in THIS repo is a symlink to a sibling private checkout a reviewing
# host cannot write. Run-13 improvised `.panopticon/scratch/`. The plan is a
# review artifact, so it belongs in the review's artifact space, and the skill
# has to say so in the same breath as it requires the sub-skill.
PLAN_LOCATION = (
    "Save the review plan to `.panopticon/runs/<tag>/plan.md` (or "
    "`.panopticon/scratch/<run>/` before a run exists) — never to "
    "`docs/superpowers/`, which is not this review's artifact space.")


class TestThePlanHasAHome(unittest.TestCase):
    """Whitespace-collapsed on both sides: SKILL.md wraps at 80 columns and the
    guide does not, and a sentence guard that also pinned the line breaks would
    fail on a re-wrap that changed nothing a reader sees."""

    @staticmethod
    def _flat(text):
        return " ".join(text.split())

    def test_skill_md_says_where_the_review_plan_goes(self):
        self.assertIn(PLAN_LOCATION, self._flat(_read_skill_md()))

    def test_the_guide_says_the_same_thing_in_the_same_words(self):
        self.assertIn(PLAN_LOCATION, self._flat(_read_doc()))


# #1637 P02: SKILL.md required three `superpowers:*` sub-skills and said
# nothing about where a host finds them or what to do when it cannot. Run-13's
# controller searched another host's plugin cache to answer both questions and
# then invented its own fallbacks. The roots below are where hosts TYPICALLY
# look -- read-only, never written, and `driver readiness` reports which ones
# it found (tests/phases/test_readiness_verb.py pins the code to this list).
SKILL_ROOTS = ("~/.claude/plugins/…/superpowers/", "~/.codex/skills/",
               "~/.agents/skills/", "~/.kimi/skills/")


class TestTheDependenciesSection(unittest.TestCase):

    def setUp(self):
        self.section = _section(_read_skill_md(), "## Dependencies",
                                "## Installed-flow substitution")

    def test_it_names_all_three_required_sub_skills(self):
        for name in ("superpowers:writing-plans",
                     "superpowers:subagent-driven-development",
                     "superpowers:verification-before-completion"):
            with self.subTest(name=name):
                self.assertIn(name, self.section)

    def test_it_names_the_roots_hosts_typically_look_in(self):
        for root in SKILL_ROOTS:
            with self.subTest(root=root):
                self.assertIn(root, self.section)

    def test_it_says_the_roots_are_read_only(self):
        self.assertIn("read-only", self.section.lower())

    def test_a_missing_sub_skill_is_a_documented_default_not_a_stop(self):
        """The whole point: an absent sub-skill must not send a host hunting
        through plugin trees, and must not silently change what the review
        did. Each of the three has a built-in answer, and the report says the
        sub-skill was unavailable."""
        for phrase in (".panopticon/runs/<tag>/plan.md",
                       "skill/workflows/dispatch.js",
                       "`validate` phase",
                       "Disclose"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, self.section)


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
