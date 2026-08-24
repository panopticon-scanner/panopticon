import os
import re
import unittest

ROOT = os.path.join(os.path.dirname(__file__), os.pardir, "skill")


class TestSkillMd(unittest.TestCase):
    def setUp(self):
        # 5.0 doc split: SKILL.md keeps the skill frontmatter + a brief overview;
        # the full user guide, driver spec, and schema contracts live in
        # docs/PANOPTICON.md. Body-content tests read the guide; frontmatter tests
        # read SKILL.md directly.
        with open(os.path.join(ROOT, os.pardir, "docs", "PANOPTICON.md"), encoding="utf-8") as fh:
            self.text = fh.read()
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

    def test_documents_unloadable_verdicts_gate_enforced(self):
        # #979: un-loadable verdicts are not just surfaced — they dent the gate.
        self.assertIn("meta.coverage.verdicts.unloadable", self.text)

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
        # accepts claude|generic; Kimi/Codex are named as the generic path's
        # examples, not as separate --host values.
        self.assertNotIn("## Host dispatch", self.text)
        loop = self.text.split("## Driver run-loop")[1].split("## Output")[0]
        for host in ("Claude", "Kimi", "generic"):
            self.assertIn(host, loop, host)

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
        for token in ("enforced", "subagent_type", "--agents-dir", "--emit-host-agents"):
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
        loop = self.text.split("## Driver run-loop")[1].split("## Driver setup")[0]
        tools = loop.split("`tools`**")[1].split("`review`**")[0]
        self.assertNotIn("optional", tools.lower())
        self.assertIn("run_tools.py", tools)
        self.assertIn("--no-tools", tools)
        self.assertTrue("LOUD" in tools or "loudly" in tools.lower())

    def test_tools_dir_is_wired_into_synthesize_passes(self):
        # F-2: a scan that runs but is never ingested reads as clean. 5.0:
        # the tool scan is a driver PHASE now, wired into the driver's own
        # synthesize invocation -- re-anchored from the deleted `## Pipeline`
        # to the driver run-loop section.
        loop = self.text.split("## Driver run-loop")[1].split("## Output")[0]
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
        loop = self.text.split("## Driver run-loop")[1].split("## Output")[0]
        # the controller loop + status protocol
        self.assertIn("driver.py run", loop)
        for word in ("checkpoint", "dispatch-request.json", "re-invoke", "complete"):
            self.assertIn(word, loop)
        # unified guard-confined self-write (no write_mode/return handshake)
        self.assertIn("write-guard", loop)
        self.assertIn("self-write", loop)
        self.assertNotIn("write_mode", loop)

    def test_driver_run_loop_documents_scout_return_persist(self):
        # The scout checkpoint is read-only + return-persist (the scout agent
        # can't self-write), distinct from the review/verify self-write
        # fan-out documented elsewhere in the same section.
        loop = self.text.split("## Driver run-loop")[1].split("## Output")[0]
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
        return self.text.split("## Quick start")[1].split("## Repository layout")[0]

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
        with open(os.path.join(ROOT, os.pardir, "docs", "PANOPTICON.md"), encoding="utf-8") as fh:
            self.skill = fh.read()
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
        qs = self.readme.split("## Quick start")[1].split("## Repository layout")[0]
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

    def test_panel_and_lens_templates_have_fence(self):
        # #run7 TST-A2A: domain-panel.md is the CURRENT 5.x dispatched reviewer;
        # its fence had zero coverage while two retired templates were checked.
        for name in ("panel-review.md", "lens-sweep.md", "domain-panel.md"):
            with open(os.path.join(ROOT, "agents", name), encoding="utf-8") as fh:
                self.assertIn("Scope fence", fh.read(), name)


class TestIntegrityResidualDocs(unittest.TestCase):
    """#493's plan-integrity CLI (`--verify-plan`/`snapshot_out_files`/
    `content_mismatched_files`) was manual-pipeline-only (dispatch.py's
    `dispatch-plan*.json` glob + `synthesize --files` hash check); `driver
    run` never invokes it. The driver's own self-write safety net -- a
    malformed write fails its done-predicate and gets re-dispatched -- is
    documented in the run-loop section and is what this re-anchors to."""

    def test_skill_instructs_malformed_selfwrite_redispatch(self):
        with open(os.path.join(ROOT, os.pardir, "docs", "PANOPTICON.md"), encoding="utf-8") as fh:
            skill = fh.read()
        self.assertIn("_cell_done", skill)
        self.assertIn("_verify_cell_done", skill)
        self.assertIn("re-dispatched", skill)


class TestDocPolicyDocs(unittest.TestCase):
    def test_skill_documents_doc_severity_policy(self):
        with open(os.path.join(ROOT, os.pardir, "docs", "PANOPTICON.md"), encoding="utf-8") as fh:
            skill = fh.read()
        self.assertIn("--doc-paths", skill)
        self.assertIn("meta.coverage.doc_policy", skill)


class TestSetupDocs(unittest.TestCase):
    def test_skill_documents_setup_mode(self):
        # 5.0: the pre-driver `--setup` flag (with its "READY" checklist) was
        # implemented by the now-retired orchestrator.py and never existed on
        # driver.py's CLI -- `driver setup` (a subcommand) with its own
        # readiness gate is the only setup mode there is now.
        with open(os.path.join(ROOT, os.pardir, "docs", "PANOPTICON.md"), encoding="utf-8") as fh:
            skill = fh.read()
        self.assertIn("driver setup", skill)
        self.assertIn("readiness gate", skill)

    def test_skill_documents_driver_setup(self):
        with open(os.path.join(ROOT, os.pardir, "docs", "PANOPTICON.md"), encoding="utf-8") as fh:
            skill = fh.read()
        self.assertIn("driver setup", skill)
        self.assertIn("groups.yml.draft", skill)


class TestInstalledFlowDocs(unittest.TestCase):
    """#495: SKILL states the <skill-dir> substitution contract once, and the
    repo-root cwd rule survives it."""

    def test_preamble_states_substitution_contract(self):
        with open(os.path.join(ROOT, os.pardir, "docs", "PANOPTICON.md"), encoding="utf-8") as fh:
            skill = fh.read()
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
        with open(os.path.join(ROOT, os.pardir, "docs", "PANOPTICON.md"), encoding="utf-8") as fh:
            skill = fh.read()
        self.assertIn("--emit-host-agents", skill)
        self.assertIn("codex", skill.lower())
        self.assertIn("kimi", skill.lower())
        self.assertIn("generic", skill)


class TestGuardFailClosedDocs(unittest.TestCase):
    def test_skill_documents_fail_closed_guard(self):
        with open(os.path.join(ROOT, os.pardir, "docs", "PANOPTICON.md"), encoding="utf-8") as fh:
            self.assertIn("fail-closed while registered", fh.read())


class TestReviewRootDocs(unittest.TestCase):
    def test_skill_documents_read_side_rooting(self):
        with open(os.path.join(ROOT, os.pardir, "docs", "PANOPTICON.md"), encoding="utf-8") as fh:
            skill = fh.read()
        self.assertIn("Repo root:", skill)
        self.assertIn("#975", skill)
