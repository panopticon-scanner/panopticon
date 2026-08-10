import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "skill", "scripts"))
import dispatch
import evidence


class TestDispatchPlan(unittest.TestCase):
    def _profile(self, depth="standard"):
        return {
            "group": "test_repo",
            "languages": ["python"],
            "surfaces": ["http_web"],
            "risk": "med",
            "depth": depth,
            "files": ["app.py"],
            "lenses": {
                "security": [
                    {"name": "known_vulns", "spawn": True, "priority": 1, "depth_threshold": "standard"},
                    {"name": "injection", "spawn": True, "priority": 2, "depth_threshold": "standard"},
                    {"name": "novel", "spawn": True, "priority": 3, "depth_threshold": "deep"},
                ]
            },
            "panels": ["security"],
            "tools": [],
            "has_deps": False,
        }

    def test_build_plan_emits_panels_in_priority_order(self):
        profile = {"group": "g", "files": ["a.py"], "depth": "standard",
                   "panels": ["test", "code", "security", "architecture"]}
        plan = dispatch.build_plan(profile, host="claude")
        panel_seq = [e["panel"] for e in plan if e["role"] == "panel_review"]
        self.assertEqual(panel_seq, ["security", "architecture", "code", "test"])

    def test_build_plan_emits_absolute_out_file_rooted_at_root(self):
        # #935: out_file must be ABSOLUTE and rooted at the explicit run root,
        # so a reviewer subagent resolves it identically from any cwd.
        root = os.path.join(os.sep, "run", "root")
        plan = dispatch.build_plan(self._profile(), host="kimi", root=root)
        self.assertTrue(plan)
        for e in plan:
            self.assertTrue(os.path.isabs(e["out_file"]), e["out_file"])
            self.assertEqual(os.path.dirname(e["out_file"]),
                             os.path.join(root, ".panopticon"))
            self.assertTrue(os.path.basename(e["out_file"]).startswith("findings-"))

    def test_build_plan_root_defaults_to_cwd(self):
        plan = dispatch.build_plan(self._profile(), host="kimi")
        for e in plan:
            self.assertEqual(os.path.dirname(e["out_file"]),
                             os.path.join(os.getcwd(), ".panopticon"))

    def test_build_plan_root_with_spaces(self):
        # The Tapestry workspace root contains a space (#935).
        root = os.path.join(os.sep, "tmp", "Mini Vault", "work")
        plan = dispatch.build_plan(self._profile(), host="kimi", root=root)
        for e in plan:
            self.assertEqual(os.path.dirname(e["out_file"]),
                             os.path.join(root, ".panopticon"))

    def test_build_plan_out_file_authorized_by_guard_across_cwd(self):
        # End-to-end #935: build_plan's absolute out_file, fed to the write-guard
        # allowlist, authorizes the reviewer's write even when the hook runs from
        # a DIFFERENT cwd than the run root. This is the actual regression: with
        # the old repo-relative out_file, allowlist_from_plan (run-root realpath)
        # and decide (elsewhere realpath) disagreed and the write was denied.
        import scripts.write_guard_hook as wg
        with tempfile.TemporaryDirectory() as run_root, \
                tempfile.TemporaryDirectory() as elsewhere:
            plan = dispatch.build_plan(self._profile(), host="kimi", root=run_root)
            allow = wg.allowlist_from_plan(plan)
            entry = plan[0]
            prev = os.getcwd()
            try:
                os.chdir(elsewhere)
                ok, _ = wg.decide("Write", entry["out_file"], allow)
            finally:
                os.chdir(prev)
            self.assertTrue(ok)

    def test_standard_emits_panel_review_and_two_sweeps(self):
        plan = dispatch.build_plan(self._profile("standard"), host="kimi")
        self.assertEqual(len(plan), 3)
        roles = [p["role"] for p in plan]
        self.assertEqual(roles.count("panel_review"), 1)
        self.assertEqual(roles.count("lens_sweep"), 2)

    def test_deep_emits_panel_review_and_three_sweeps(self):
        plan = dispatch.build_plan(self._profile("deep"), host="kimi")
        self.assertEqual(len(plan), 4)
        roles = [p["role"] for p in plan]
        self.assertEqual(roles.count("panel_review"), 1)
        self.assertEqual(roles.count("lens_sweep"), 3)

    def test_shallow_emits_only_panel_review(self):
        profile = {
            "group": "g1",
            "panels": ["code"],
            "depth": "shallow",
            "files": ["docs/readme.md"],
            "lenses": {
                "code": [
                    {"name": "style", "spawn": False, "priority": 1, "depth_threshold": "shallow"},
                ]
            },
            "tools": [],
            "has_deps": False,
        }
        plan = dispatch.build_plan(profile, host="kimi")
        self.assertEqual(len(plan), 1)
        self.assertEqual(plan[0]["role"], "panel_review")
        self.assertEqual(plan[0]["lenses"], ["style"])

    def test_panel_review_includes_non_spawned_lenses(self):
        profile = {
            "group": "g1",
            "panels": ["security"],
            "depth": "standard",
            "files": ["app.py"],
            "lenses": {
                "security": [
                    {"name": "known_vulns", "spawn": True, "priority": 1, "depth_threshold": "standard"},
                    {"name": "injection", "spawn": True, "priority": 2, "depth_threshold": "standard"},
                    {"name": "novel", "spawn": True, "priority": 3, "depth_threshold": "deep"},
                ]
            },
            "tools": [],
            "has_deps": False,
        }
        plan = dispatch.build_plan(profile, host="kimi")
        panel = [p for p in plan if p["role"] == "panel_review"][0]
        spawned = [p["lens"] for p in plan if p["role"] == "lens_sweep"]
        self.assertEqual(panel["lenses"], ["novel"])
        self.assertNotIn("novel", spawned)

    def test_models_resolved_per_host(self):
        with tempfile.TemporaryDirectory() as d:
            plan = dispatch.build_plan(self._profile("standard"), host="claude",
                                       agents_dir=d)
        advisor = [p for p in plan if p["role"] == "advisor"]
        self.assertEqual(len(advisor), 0)
        panel = [p for p in plan if p["role"] == "panel_review"][0]
        self.assertEqual(panel["model"]["model"], "sonnet")
        self.assertEqual(panel["agent"], "panel-review")
        sweep = [p for p in plan if p["role"] == "lens_sweep"][0]
        self.assertEqual(sweep["agent"], "lens-sweep")

    def test_main_writes_json_plan(self):
        profile = self._profile("standard")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as fh:
            json.dump(profile, fh)
            profile_path = fh.name
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as fh:
            out_path = fh.name
        # Register both reviewer shells in a temp agents-dir so the plan is
        # fully enforced and the #275 gate is a deterministic no-op here --
        # this test's purpose is main()'s plan-write path, not enforcement
        # gating (TestUnenforcedGate covers that). Without registration, the
        # unregistered-host gate would either refuse (rc 1) or, with
        # --allow-unenforced, write a REAL .panopticon/unenforced-ack.json
        # relative to the test process's cwd -- the repo root, since this
        # test does not chdir. Same registration pattern as
        # test_main_unwritable_out_directory_returns_one.
        reg = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, reg, ignore_errors=True)
        for name in ("panopticon-panel-review.md", "panopticon-lens-sweep.md"):
            with open(os.path.join(reg, name), "w") as fh:
                fh.write("---\nname: %s\n---\nbody\n" % name[:-3])
        try:
            rc = dispatch.main([profile_path, "--host", "kimi", "--out", out_path,
                                "--agents-dir", reg])
            self.assertEqual(rc, 0)
            with open(out_path) as fh:
                plan = json.load(fh)
            self.assertIsInstance(plan, list)
            self.assertGreaterEqual(len(plan), 3)
        finally:
            os.unlink(profile_path)
            os.unlink(out_path)

    def test_main_missing_profile_returns_one(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            rc = dispatch.main(["does-not-exist.json"])
        self.assertEqual(rc, 1)
        self.assertIn("does-not-exist.json", stderr.getvalue())

    def test_main_malformed_profile_returns_one(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as fh:
            fh.write("{not json")
            profile_path = fh.name
        try:
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                rc = dispatch.main([profile_path])
            self.assertEqual(rc, 1)
            self.assertIn("invalid JSON", stderr.getvalue())
        finally:
            os.unlink(profile_path)

    def test_main_template_failure_returns_one_cleanly(self):
        # build_plan() raises ValueError when a role template can't be found
        # (e.g. a corrupt/relocated install). main() must catch it and return
        # 1 with a clean stderr message, matching the sibling error paths --
        # not propagate a bare traceback.
        profile = self._profile("standard")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as fh:
            json.dump(profile, fh)
            profile_path = fh.name
        try:
            with tempfile.TemporaryDirectory() as empty_template_dir:
                with mock.patch.object(dispatch, "TEMPLATE_DIR", empty_template_dir):
                    stderr = io.StringIO()
                    with contextlib.redirect_stderr(stderr):
                        rc = dispatch.main([profile_path, "--host", "kimi"])
                    self.assertEqual(rc, 1)
                    self.assertIn("dispatch:", stderr.getvalue())
        finally:
            os.unlink(profile_path)

    def test_main_unwritable_out_directory_returns_one(self):
        profile = self._profile("standard")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as fh:
            json.dump(profile, fh)
            profile_path = fh.name
        # Register both reviewer shells in a temp agents-dir so the plan is
        # fully enforced and the #275 gate is a deterministic no-op here,
        # regardless of ambient host detection or real registrations on the
        # machine running the test (a bare CI runner has neither).
        reg = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, reg, ignore_errors=True)
        for name in ("panopticon-panel-review.md", "panopticon-lens-sweep.md"):
            with open(os.path.join(reg, name), "w") as fh:
                fh.write("---\nname: %s\n---\nbody\n" % name[:-3])
        try:
            # Use a path under /dev/null which cannot be created as a directory.
            out_path = "/dev/null/cannot-create/findings.json"
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                rc = dispatch.main([profile_path, "--out", out_path, "--agents-dir", reg])
            self.assertEqual(rc, 1)
            self.assertIn("cannot create output directory", stderr.getvalue())
        finally:
            os.unlink(profile_path)

    def test_emit_kimi_swarm_groups_entries_by_subagent_type(self):
        plan = [
            {
                "role": "panel_review",
                "agent": "panopticon-panel-review",
                "enforced": True,
                "model": {"model": "secondary"},
                "prompt": "panel prompt 1",
                "out_file": ".panopticon/findings-g-security-panel_review.json",
            },
            {
                "role": "panel_review",
                "agent": "panopticon-panel-review",
                "enforced": True,
                "model": {"model": "secondary"},
                "prompt": "panel prompt 2",
                "out_file": ".panopticon/findings-g-code-panel_review.json",
            },
            {
                "role": "lens_sweep",
                "agent": "lens-sweep",
                "enforced": False,
                "model": {"model": "primary"},
                "prompt": "lens prompt",
                "out_file": ".panopticon/findings-g-security-lens_sweep-injection.json",
            },
        ]
        swarm = dispatch.emit_kimi_swarm(plan)
        batches = swarm["batches"]
        self.assertEqual(len(batches), 2)

        swarm_batches = [b for b in batches if b.get("tool") == "AgentSwarm"]
        agent_batches = [b for b in batches if b.get("tool") == "Agent"]
        self.assertEqual(len(swarm_batches), 1)
        self.assertEqual(len(agent_batches), 1)

        panel_batch = swarm_batches[0]
        self.assertEqual(panel_batch["subagent_type"], "panopticon-panel-review")
        self.assertEqual(panel_batch["model"], "secondary")
        self.assertEqual(panel_batch["prompt_template"], "{{item}}")
        self.assertEqual(len(panel_batch["items"]), 2)
        self.assertEqual(panel_batch["items"][0], "panel prompt 1")

        lens_batch = agent_batches[0]
        self.assertEqual(lens_batch["subagent_type"], "explore")
        self.assertEqual(lens_batch["model"], "primary")
        self.assertEqual(lens_batch["prompt"], "lens prompt")

    def test_emit_kimi_swarm_carries_out_file_routing_per_item(self):
        # A batch merges entries from different groups, so item order is the
        # only other link back to out_file — and order is not a contract.
        plan = [
            {"role": "panel_review", "agent": "panopticon-panel-review",
             "enforced": True, "model": {"model": "secondary"},
             "prompt": "p1", "panel": "security", "group": "g-security",
             "out_file": ".panopticon/findings-g-security-panel_review.json"},
            {"role": "panel_review", "agent": "panopticon-panel-review",
             "enforced": True, "model": {"model": "secondary"},
             "prompt": "p2", "panel": "code", "group": "g-code",
             "out_file": ".panopticon/findings-g-code-panel_review.json"},
            {"role": "lens_sweep", "agent": "lens-sweep", "enforced": False,
             "model": {"model": "primary"}, "prompt": "l1", "panel": "security",
             "lens": "injection", "group": "g-security",
             "out_file": ".panopticon/findings-g-security-lens-injection.json"},
        ]
        swarm = dispatch.emit_kimi_swarm(plan)
        batch = [b for b in swarm["batches"] if b["tool"] == "AgentSwarm"][0]
        single = [b for b in swarm["batches"] if b["tool"] == "Agent"][0]

        self.assertEqual(len(batch["routing"]), len(batch["items"]))
        self.assertEqual(
            [r["out_file"] for r in batch["routing"]],
            [".panopticon/findings-g-security-panel_review.json",
             ".panopticon/findings-g-code-panel_review.json"])
        self.assertEqual([r["group"] for r in batch["routing"]],
                         ["g-security", "g-code"])
        # Agent (singleton) batches carry a single routing object.
        self.assertEqual(single["routing"]["out_file"],
                         ".panopticon/findings-g-security-lens-injection.json")
        self.assertEqual(single["routing"]["lens"], "injection")

    def test_emit_kimi_swarm_maps_unenforced_scout_and_advisor(self):
        plan = [
            {"role": "scout", "agent": "scout", "enforced": False,
             "model": {"model": "primary"}, "prompt": "s"},
            {"role": "advisor", "agent": "advisor", "enforced": False,
             "model": {"model": "secondary"}, "prompt": "a"},
        ]
        by_role = {b["routing"]["role"]: b["subagent_type"]
                   for b in dispatch.emit_kimi_swarm(plan)["batches"]}
        self.assertEqual(by_role["scout"], "explore")
        self.assertEqual(by_role["advisor"], "plan")

    def test_emit_kimi_swarm_downgrades_a_stale_enforced_entry(self):
        # `enforced` is a snapshot from plan-build time; registration can be
        # gone by the time the persisted plan is turned into a manifest.
        plan = [{"role": "panel_review", "agent": "panopticon-panel-review",
                 "enforced": True, "model": {"model": "secondary"},
                 "prompt": "p"}]
        with tempfile.TemporaryDirectory() as empty_dir:
            with contextlib.redirect_stderr(io.StringIO()) as err:
                swarm = dispatch.emit_kimi_swarm(
                    plan, agents_dir=empty_dir, verify_registration=True)
        self.assertEqual(swarm["batches"][0]["subagent_type"], "coder")
        self.assertIn("no longer registered", err.getvalue())

    def test_emit_kimi_swarm_rejects_a_malformed_plan(self):
        with self.assertRaises(ValueError):
            dispatch.emit_kimi_swarm({"not": "a list"})
        with self.assertRaises(ValueError):
            dispatch.emit_kimi_swarm(["not an object"])

    def test_cli_emit_kimi_swarm_writes_manifest_and_requires_out(self):
        # plan's panel_review entry is unenforced, so this must run with
        # --allow-unenforced (I3's gate on --emit-kimi-swarm) -- and, since
        # that path writes .panopticon/unenforced-ack.json relative to cwd,
        # this must chdir into the temp dir first (I1's hermeticity rule)
        # rather than drop a real ack into the repo root.
        plan = [{"role": "panel_review", "agent": "panopticon-panel-review",
                 "enforced": False, "model": {"model": "secondary"},
                 "prompt": "p", "out_file": ".panopticon/f.json"}]
        with tempfile.TemporaryDirectory() as d:
            plan_path = os.path.join(d, "dispatch-plan.json")
            out_path = os.path.join(d, "kimi-swarm.json")
            with open(plan_path, "w", encoding="utf-8") as fh:
                json.dump(plan, fh)

            cwd = os.getcwd()
            try:
                os.chdir(d)
                with contextlib.redirect_stderr(io.StringIO()) as err:
                    self.assertEqual(dispatch.main(["--emit-kimi-swarm", plan_path]), 2)
                self.assertIn("requires --out", err.getvalue())

                rc = dispatch.main(["--emit-kimi-swarm", plan_path, "--out", out_path,
                                    "--agents-dir", d, "--allow-unenforced"])
            finally:
                os.chdir(cwd)
            self.assertEqual(rc, 0)
            with open(out_path, encoding="utf-8") as fh:
                written = json.load(fh)
            self.assertEqual(written["batches"][0]["routing"]["out_file"],
                             ".panopticon/f.json")

            bad_path = os.path.join(d, "bad.json")
            with open(bad_path, "w", encoding="utf-8") as fh:
                fh.write("{not json")
            with contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(
                    dispatch.main(["--emit-kimi-swarm", bad_path, "--out", out_path]), 1)
            self.assertIn("cannot read plan", err.getvalue())


class TestDetectHost(unittest.TestCase):
    def _detect(self, env):
        with mock.patch.dict(os.environ, env, clear=True):
            return dispatch._detect_host()

    def _detect_with_stderr(self, env):
        with contextlib.redirect_stderr(io.StringIO()) as err:
            with mock.patch.dict(os.environ, env, clear=True):
                host = dispatch._detect_host()
        return host, err.getvalue()

    def test_warns_when_inferred_from_kimi_env(self):
        host, err = self._detect_with_stderr({"KIMI_CODE_VERSION": "1.0"})
        self.assertEqual(host, "kimi")
        self.assertIn("WARNING", err)
        self.assertIn("--host", err)

    def test_warns_when_inferred_from_claude_env(self):
        # clear=True matters: _detect_host checks Kimi first, so an ambient
        # KIMI_* var on the runner would otherwise decide this test.
        host, err = self._detect_with_stderr({"CLAUDECODE": "1"})
        self.assertEqual(host, "claude")
        self.assertIn("WARNING", err)
        self.assertIn("--host", err)

    def test_kimi_env(self):
        self.assertEqual(self._detect({"KIMI_CODE_VERSION": "1"}), "kimi")
        self.assertEqual(self._detect({"KIMI_SESSION_ID": "x"}), "kimi")

    def test_claude_env(self):
        self.assertEqual(self._detect({"CLAUDECODE": "1"}), "claude")
        self.assertEqual(self._detect({"CLAUDE_CODE_SESSION_ID": "abc"}), "claude")

    def test_no_env_is_generic_not_kimi(self):
        self.assertEqual(self._detect({}), "generic")

    def test_kimi_wins_over_claude_when_both(self):
        self.assertEqual(
            self._detect({"KIMI_SESSION_ID": "x", "CLAUDECODE": "1"}), "kimi")


class TestRenderPrompt(unittest.TestCase):
    def _entry_mapping(self):
        return {
            "panel": "security", "group": "g1",
            "file_list": "a.py, b.py", "security_mode": "standard",
            "depth": "standard", "lenses": "- known_vulns\n- novel",
            "lens": "injection",
            "out_file": ".panopticon/findings-g1-security-panel_review.json",
        }

    def test_rendered_panel_prompt_properties(self):
        p = dispatch.render_prompt("panel-review.md", self._entry_mapping())
        self.assertNotIn("---\nname:", p)               # frontmatter stripped
        self.assertIn("security", p)                     # {panel} filled
        self.assertIn("a.py, b.py", p)                   # {file_list} filled
        self.assertIn(".panopticon/findings-g1-security-panel_review.json", p)
        # tool-policy line injected, naming allowed and forbidden tools
        self.assertIn("Read", p)
        self.assertIn("must not use", p.lower())
        # no known placeholder tokens survive; JSON/regex braces in the body do
        for tok in dispatch.PLACEHOLDER_RE.findall(p):
            self.assertNotIn(tok, self._entry_mapping(), tok)

    def test_unfilled_placeholder_fails_fast(self):
        mapping = self._entry_mapping()
        del mapping["depth"]
        with self.assertRaises(ValueError) as ctx:
            dispatch.render_prompt("panel-review.md", mapping)
        self.assertIn("depth", str(ctx.exception))
        self.assertIn("panel-review.md", str(ctx.exception))

    def test_brace_safety_value_containing_placeholder_syntax(self):
        mapping = self._entry_mapping()
        mapping["file_list"] = "weird-{depth}-name.py"   # value contains {depth}
        p = dispatch.render_prompt("panel-review.md", mapping)
        self.assertIn("weird-{depth}-name.py", p)        # survives literally

    def test_build_plan_entries_carry_prompts(self):
        profile = {"group": "g1", "files": ["a.py"], "depth": "standard",
                   "panels": ["security"],
                   "lenses": {"security": [
                       {"name": "injection", "spawn": True, "priority": 1,
                        "depth_threshold": "shallow"},
                       {"name": "novel", "spawn": False, "priority": 2,
                        "depth_threshold": "standard"}]},
                   "security_mode": "standard"}
        with tempfile.TemporaryDirectory() as d:
            plan = dispatch.build_plan(profile, host="claude", agents_dir=d)
        self.assertTrue(plan)
        for entry in plan:
            self.assertIn("prompt", entry)
            self.assertNotIn("{file_list}", entry["prompt"])
        sweep = [e for e in plan if e["role"] == "lens_sweep"][0]
        self.assertIn("injection", sweep["prompt"])


class TestRenderGoldens(unittest.TestCase):
    def test_rendered_output_matches_goldens(self):
        base = {"panel": "security", "group": "g1", "file_list": "a.py, b.py",
                "security_mode": "standard", "depth": "standard",
                "lenses": "- known_vulns\n- novel", "lens": "injection"}
        # Distinct out_file per role: panel_review and lens_sweep write to
        # different files (lens_sweep is read-only and returns its findings
        # for the orchestrator to write), so their goldens must not share a
        # mapping.
        out_files = {
            "panel-review.md": ".panopticon/findings-g1-security-panel_review.json",
            "lens-sweep.md": ".panopticon/findings-g1-security-lens_sweep-injection.json",
            "scout.md": ".panopticon/scout-g1.json",
        }
        gdir = os.path.join(os.path.dirname(__file__), "goldens")
        for role, out_file in out_files.items():
            m = dict(base, out_file=out_file)
            expected = open(os.path.join(gdir, role[:-3] + ".rendered.txt"),
                            encoding="utf-8").read()
            self.assertEqual(dispatch.render_prompt(role, m), expected, role)


class TestRenderAdvisor(unittest.TestCase):
    # 16 hex chars: shape of evidence.finding_fingerprint's output (#443).
    # Hand-picked here (rather than computed) because this class tests
    # dispatch's rendering behavior in isolation from evidence -- the
    # TestQueueIdContractWithEvidence class below wires the two together.
    QID_1 = "a1b2c3d4e5f60001"
    QID_2 = "a1b2c3d4e5f60002"

    def _queue(self, tmp):
        queue = {"version": "4.2.0", "cut_by_max_verify": 0, "entries": [
            {"queue_id": self.QID_1, "priority": 1,
             "finding": {"id": "SEC-001", "title": "sqli", "severity": "HIGH",
                          "panel": "security", "category": "injection",
                          "location": {"file": "app.py", "line_start": 10},
                          "description": "raw query with {code_context} text"}},
            {"queue_id": self.QID_2, "priority": 3,
             "finding": {"id": "CD-002", "title": "leak", "severity": "LOW",
                          "panel": "code", "category": "correctness",
                          "location": {"file": "b.py", "line_start": 4}}},
        ]}
        qpath = os.path.join(tmp, "verify-queue.json")
        with open(qpath, "w") as fh:
            json.dump(queue, fh)
        return qpath

    def test_writes_one_prompt_per_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            qpath = self._queue(tmp)
            outdir = os.path.join(tmp, "advisor-prompts")
            written = dispatch.render_advisor_prompts(qpath, outdir)
            self.assertEqual([os.path.basename(p) for p in written],
                             [self.QID_1 + ".md", self.QID_2 + ".md"])
            text = open(written[0], encoding="utf-8").read()
            self.assertIn('"id": "SEC-001"', text)        # claim embedded
            self.assertIn("{code_context}", text)          # brace-safe: survives
            self.assertNotIn("{claim_json}", text)         # placeholder filled
            self.assertNotIn("---\nname:", text)           # frontmatter stripped

    def test_malformed_queue_fails_fast(self):
        with tempfile.TemporaryDirectory() as tmp:
            qpath = os.path.join(tmp, "bad.json")
            open(qpath, "w").write("{not json")
            with self.assertRaises(ValueError):
                dispatch.render_advisor_prompts(qpath, tmp)

    def test_cli_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            qpath = self._queue(tmp)
            outdir = os.path.join(tmp, "out")
            rc = dispatch.main(["--render-advisor", qpath, "--out", outdir])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.isfile(
                os.path.join(outdir, self.QID_1 + ".md")))

    def test_non_dict_queue_fails_fast(self):
        with tempfile.TemporaryDirectory() as tmp:
            qpath = os.path.join(tmp, "array.json")
            with open(qpath, "w") as fh:
                json.dump([], fh)
            with self.assertRaises(ValueError):
                dispatch.render_advisor_prompts(qpath, tmp)

    def test_non_dict_entry_fails_fast(self):
        with tempfile.TemporaryDirectory() as tmp:
            queue = {"version": "4.0.0", "cut_by_max_verify": 0, "entries": [None]}
            qpath = os.path.join(tmp, "bad-entry.json")
            with open(qpath, "w") as fh:
                json.dump(queue, fh)
            with self.assertRaises(ValueError):
                dispatch.render_advisor_prompts(qpath, tmp)

    def test_unsafe_queue_id_fails_fast(self):
        # queue_id is OUR artifact (built by evidence.build_verify_queue), but
        # render_advisor_prompts validates it anyway: a corrupt/tampered queue
        # file with a path-shaped queue_id must not reach os.path.join. The
        # fingerprint contract (#443) makes the check strictly tighter than
        # before -- no separators or dots survive it at all, not just the
        # traversal-shaped ones.
        with tempfile.TemporaryDirectory() as tmp:
            queue = {"version": "4.2.0", "cut_by_max_verify": 0, "entries": [
                {"queue_id": "../escape", "priority": 1,
                 "finding": {"id": "SEC-001", "title": "x", "severity": "HIGH",
                              "panel": "security", "category": "injection",
                              "location": {"file": "app.py", "line_start": 1}}},
            ]}
            qpath = os.path.join(tmp, "unsafe-queue.json")
            with open(qpath, "w") as fh:
                json.dump(queue, fh)
            with self.assertRaises(ValueError) as ctx:
                dispatch.render_advisor_prompts(qpath, tmp)
            self.assertIn("unsafe queue_id", str(ctx.exception))


class TestQueueIdResiduals(unittest.TestCase):
    """Round-2 parked residuals, updated for the fingerprint contract (#443).
    The old positional id's only unbounded-width component was the zero-padded
    position (`%03d` grows past 3 digits at 1000+ entries); under the new
    contract the only unbounded-width component is the collision suffix
    (evidence.build_verify_queue's `-<n>`), which can also grow past one
    digit. Non-string ids must still fail fast either way."""

    def _queue(self, tmp, entries):
        qpath = os.path.join(tmp, "q.json")
        with open(qpath, "w") as fh:
            json.dump({"version": "4.2.0", "cut_by_max_verify": 0,
                       "entries": entries}, fh)
        return qpath

    def test_multi_digit_collision_suffix_accepted(self):
        qid = "a1b2c3d4e5f60001-10"
        with tempfile.TemporaryDirectory() as tmp:
            qpath = self._queue(tmp, [{"queue_id": qid, "priority": 1,
                                       "finding": {"id": "AB-001", "title": "t"}}])
            written = dispatch.render_advisor_prompts(qpath, os.path.join(tmp, "o"))
        self.assertEqual(os.path.basename(written[0]), qid + ".md")

    def test_non_string_queue_id_raises_valueerror(self):
        with tempfile.TemporaryDirectory() as tmp:
            qpath = self._queue(tmp, [{"queue_id": 7, "priority": 1,
                                       "finding": {"id": "AB-001"}}])
            with self.assertRaises(ValueError):
                dispatch.render_advisor_prompts(qpath, os.path.join(tmp, "o"))

    def test_trailing_newline_queue_id_rejected(self):
        # Python's `$` matches before a trailing newline as well as at end of
        # string, so an otherwise-valid id with a "\n" glued on cleared a
        # `^...$` guard and reached the "%s.md" filename interpolation. \A/\Z
        # is the anchor pair that means what this check intends.
        for qid in ("a1b2c3d4e5f60001\n", "a1b2c3d4e5f60001-10\n"):
            with tempfile.TemporaryDirectory() as tmp:
                qpath = self._queue(tmp, [{"queue_id": qid, "priority": 1,
                                           "finding": {"id": "AB-001",
                                                       "title": "t"}}])
                with self.assertRaises(ValueError) as ctx:
                    dispatch.render_advisor_prompts(qpath, os.path.join(tmp, "o"))
                self.assertIn("unsafe queue_id", str(ctx.exception))


class TestQueueIdContractWithEvidence(unittest.TestCase):
    """Wires the two ends of the queue_id contract together. #443 broke this
    silently once: evidence.build_verify_queue's id format changed (positional
    -> fingerprint) but dispatch.render_advisor_prompts's validation regex
    still expected the old shape, and no test caught it because both sides
    were only exercised against hand-written fixtures matching each module's
    own assumptions. Building the queue for real and feeding it straight into
    the render path means the two modules can't silently diverge again."""

    def _finding(self, fid, **over):
        f = {"id": fid, "severity": "HIGH", "panel": "security",
             "category": "injection", "title": "t-" + fid,
             "location": {"file": fid + ".py", "line_start": 1}}
        f.update(over)
        return f

    def test_real_build_verify_queue_output_renders(self):
        findings = [self._finding("A"), self._finding("B", severity="LOW")]
        entries, cut = evidence.build_verify_queue(findings)
        with tempfile.TemporaryDirectory() as tmp:
            qpath = os.path.join(tmp, "verify-queue.json")
            evidence.write_verify_queue(entries, cut, qpath)
            written = dispatch.render_advisor_prompts(qpath, os.path.join(tmp, "o"))
        self.assertEqual(len(written), 2)
        self.assertEqual(sorted(os.path.basename(p) for p in written),
                         sorted("%s.md" % e["queue_id"] for e in entries))

    def test_real_collision_suffix_renders(self):
        # Two findings that collide in fingerprint (same panel/category/file/
        # title) still produce a queue dispatch.render_advisor_prompts accepts
        # end to end, filenames and all.
        a = self._finding("X")
        b = self._finding("Y", title=a["title"], location=dict(a["location"]))
        entries, cut = evidence.build_verify_queue([a, b])
        fp = evidence.finding_fingerprint(a)
        self.assertEqual(sorted(e["queue_id"] for e in entries),
                         sorted([fp, fp + "-1"]))                    # collision fired
        with tempfile.TemporaryDirectory() as tmp:
            qpath = os.path.join(tmp, "verify-queue.json")
            evidence.write_verify_queue(entries, cut, qpath)
            written = dispatch.render_advisor_prompts(qpath, os.path.join(tmp, "o"))
        self.assertEqual(len(written), 2)


class TestKimiDefaultAgentsDir(unittest.TestCase):
    def test_kimi_registration_dir_defaults_to_user_agents(self):
        expected = os.path.join(os.path.expanduser("~"), ".kimi-code", "agents")
        self.assertEqual(dispatch._registration_dir("kimi", None), expected)

    def test_claude_registration_dir_unchanged(self):
        expected = os.path.join(os.path.expanduser("~"), ".claude", "agents")
        self.assertEqual(dispatch._registration_dir("claude", None), expected)

    def test_explicit_agents_dir_overrides_kimi_default(self):
        self.assertEqual(dispatch._registration_dir("kimi", "/custom"), "/custom")


class TestEnforcedPlanEntries(unittest.TestCase):
    def _profile(self):
        return {"group": "g1", "files": ["a.py"], "depth": "standard",
                "panels": ["security"], "security_mode": "standard",
                "lenses": {"security": [
                    {"name": "injection", "spawn": True, "priority": 1,
                     "depth_threshold": "shallow"}]}}

    def test_enforced_true_when_registered(self):
        with tempfile.TemporaryDirectory() as d:
            dispatch.emit_host_agents("claude", d)
            plan = dispatch.build_plan(self._profile(), host="claude", agents_dir=d)
        for e in plan:
            self.assertTrue(e["enforced"], e["role"])
        panel = [e for e in plan if e["role"] == "panel_review"][0]
        self.assertEqual(panel["agent"], "panopticon-panel-review")

    def test_enforced_false_without_registration(self):
        with tempfile.TemporaryDirectory() as d:
            plan = dispatch.build_plan(self._profile(), host="claude", agents_dir=d)
        for e in plan:
            self.assertFalse(e["enforced"], e["role"])
        panel = [e for e in plan if e["role"] == "panel_review"][0]
        self.assertEqual(panel["agent"], "panel-review")  # legacy name preserved

    def test_partial_registration_is_per_role(self):
        with tempfile.TemporaryDirectory() as d:
            dispatch.emit_host_agents("claude", d)
            os.remove(os.path.join(d, "panopticon-lens-sweep.md"))
            plan = dispatch.build_plan(self._profile(), host="claude", agents_dir=d)
        by_role = {e["role"]: e for e in plan}
        self.assertTrue(by_role["panel_review"]["enforced"])
        self.assertFalse(by_role["lens_sweep"]["enforced"])

    def test_generic_host_never_enforced_by_default(self):
        plan = dispatch.build_plan(self._profile(), host="generic")
        for e in plan:
            self.assertFalse(e["enforced"])


class TestUnenforcedGate(unittest.TestCase):
    PROFILE = {"group": "g", "files": ["a.py"], "depth": "standard", "panels": ["code"]}

    def _run(self, extra_args, agents_dir):
        # empty agents_dir => unenforced; returns (rc, plan_path, ack_path, cwd used)
        # NOTE: uses mkdtemp (not a `with TemporaryDirectory()` around the
        # return) because returning from inside that context manager tears
        # the directory down before the caller can assert on the returned
        # paths -- addCleanup keeps it alive until the test finishes.
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        prof = os.path.join(d, "profile.json")
        with open(prof, "w") as fh:
            json.dump(self.PROFILE, fh)
        out = os.path.join(d, "plan.json")
        cwd = os.getcwd()
        try:
            os.chdir(d)
            rc = dispatch.main([prof, "--host", "claude",
                                "--agents-dir", agents_dir, "--out", out] + extra_args)
        finally:
            os.chdir(cwd)
        return rc, out, os.path.join(d, ".panopticon", "unenforced-ack.json")

    def test_unenforced_reviewer_hard_fails_without_flag(self):
        with tempfile.TemporaryDirectory() as empty:
            rc, out, ack = self._run([], empty)
        self.assertNotEqual(rc, 0)
        self.assertFalse(os.path.exists(out))       # no plan written
        self.assertFalse(os.path.exists(ack))

    def test_allow_unenforced_writes_plan_and_ack(self):
        with tempfile.TemporaryDirectory() as empty:
            rc, out, ack = self._run(["--allow-unenforced"], empty)
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.exists(out))
        with open(ack) as fh:
            data = json.load(fh)
        self.assertTrue(data["acknowledged"])
        self.assertIn("panel_review", data["roles"])
        # #680: the ack must record that the write-guard does NOT cover Bash in
        # this mode, so the accepted residual risk is explicit and auditable.
        self.assertFalse(data["write_guard_covers_bash"])
        self.assertIn("Bash", data["note"])

    def test_enforced_plan_emits_normally_no_ack(self):
        with tempfile.TemporaryDirectory() as reg:
            # register both reviewer shells so the plan is fully enforced
            for role_file in ("panel-review.md", "lens-sweep.md"):
                with open(os.path.join(reg, "panopticon-" + role_file), "w") as fh:
                    fh.write("---\nname: panopticon-%s\n---\nbody\n" % role_file[:-3])
            rc, out, ack = self._run([], reg)
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.exists(out))
        self.assertFalse(os.path.exists(ack))       # enforced => no ack marker

    def test_emit_kimi_swarm_refuses_unenforced_plan(self):
        # I3: --emit-kimi-swarm is an emission path too (plan -> dispatchable
        # manifest) and must carry the same refuse-by-default gate as the
        # plan-emit path -- it must not be a silent downgrade to unenforced
        # coder/explore profiles with rc 0.
        plan = [{"role": "panel_review", "agent": "panopticon-panel-review",
                 "enforced": False, "model": {"model": "secondary"},
                 "prompt": "p", "out_file": ".panopticon/f.json"}]
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        plan_path = os.path.join(d, "plan.json")
        with open(plan_path, "w", encoding="utf-8") as fh:
            json.dump(plan, fh)
        out_path = os.path.join(d, "swarm.json")
        ack_path = os.path.join(d, ".panopticon", "unenforced-ack.json")
        cwd = os.getcwd()
        try:
            os.chdir(d)
            rc_refused = dispatch.main(["--emit-kimi-swarm", plan_path, "--out", out_path])
        finally:
            os.chdir(cwd)
        self.assertNotEqual(rc_refused, 0)
        self.assertFalse(os.path.exists(out_path))
        self.assertFalse(os.path.exists(ack_path))

        try:
            os.chdir(d)
            rc_allowed = dispatch.main(["--emit-kimi-swarm", plan_path, "--out", out_path,
                                        "--allow-unenforced"])
        finally:
            os.chdir(cwd)
        self.assertEqual(rc_allowed, 0)
        self.assertTrue(os.path.exists(out_path))
        self.assertTrue(os.path.exists(ack_path))

    def test_emit_kimi_swarm_gates_stale_enforced_true_via_live_registration(self):
        # #649: a plan built while the shell WAS registered carries
        # enforced:true, but the registration dir has since been emptied. The
        # CLI gate must consult live registration (via --agents-dir), not the
        # stored flag, and refuse-by-default / warn+ack -- not silently
        # downgrade to an unenforced 'coder' profile with rc 0 and no ack.
        plan = [{"role": "panel_review", "agent": "panopticon-panel-review",
                 "enforced": True, "model": {"model": "secondary"},
                 "prompt": "p", "out_file": ".panopticon/f.json"}]
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        empty_reg = os.path.join(d, "agents-emptied")  # registration revoked
        os.makedirs(empty_reg)
        plan_path = os.path.join(d, "plan.json")
        with open(plan_path, "w", encoding="utf-8") as fh:
            json.dump(plan, fh)
        out_path = os.path.join(d, "swarm.json")
        ack_path = os.path.join(d, ".panopticon", "unenforced-ack.json")
        cwd = os.getcwd()

        try:
            os.chdir(d)
            rc_refused = dispatch.main(["--emit-kimi-swarm", plan_path,
                                        "--out", out_path, "--agents-dir", empty_reg])
        finally:
            os.chdir(cwd)
        self.assertNotEqual(rc_refused, 0)            # not a silent rc 0
        self.assertFalse(os.path.exists(out_path))
        self.assertFalse(os.path.exists(ack_path))

        try:
            os.chdir(d)
            rc_allowed = dispatch.main(["--emit-kimi-swarm", plan_path,
                                        "--out", out_path, "--agents-dir", empty_reg,
                                        "--allow-unenforced"])
        finally:
            os.chdir(cwd)
        self.assertEqual(rc_allowed, 0)
        self.assertTrue(os.path.exists(out_path))
        self.assertTrue(os.path.exists(ack_path))     # ack IS recorded now

    def test_emit_kimi_swarm_stale_enforced_true_passes_when_still_registered(self):
        # Control: same enforced:true plan, but the shell IS still registered in
        # --agents-dir -> no gating, no ack, clean emit.
        plan = [{"role": "panel_review", "agent": "panopticon-panel-review",
                 "enforced": True, "model": {"model": "secondary"},
                 "prompt": "p", "out_file": ".panopticon/f.json"}]
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        reg = os.path.join(d, "agents")
        os.makedirs(reg)
        with open(os.path.join(reg, "panopticon-panel-review.md"), "w") as fh:
            fh.write("---\nname: panopticon-panel-review\n---\nbody\n")
        plan_path = os.path.join(d, "plan.json")
        with open(plan_path, "w", encoding="utf-8") as fh:
            json.dump(plan, fh)
        out_path = os.path.join(d, "swarm.json")
        ack_path = os.path.join(d, ".panopticon", "unenforced-ack.json")
        cwd = os.getcwd()
        try:
            os.chdir(d)
            rc = dispatch.main(["--emit-kimi-swarm", plan_path,
                                "--out", out_path, "--agents-dir", reg])
        finally:
            os.chdir(cwd)
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.exists(out_path))
        self.assertFalse(os.path.exists(ack_path))    # enforced live => no ack


class TestEmitHostAgents(unittest.TestCase):
    def test_claude_files_written_for_all_roles(self):
        with tempfile.TemporaryDirectory() as d:
            written = dispatch.emit_host_agents("claude", d)
            names = sorted(os.path.basename(p) for p in written)
            self.assertEqual(names, ["panopticon-advisor.md", "panopticon-lens-sweep.md",
                                     "panopticon-panel-review.md", "panopticon-scout.md"])

    def test_claude_frontmatter_is_enforcement_shell(self):
        with tempfile.TemporaryDirectory() as d:
            dispatch.emit_host_agents("claude", d)
            text = open(os.path.join(d, "panopticon-panel-review.md")).read()
            self.assertIn("name: panopticon-panel-review", text)
            # panel_review holds scoped Write (#436): it self-writes its
            # out_file; the write-guard hook (Tasks 4-5) confines the write.
            self.assertIn("tools: Read, Grep, Glob, Write", text)
            self.assertIn("model: sonnet", text)
            self.assertNotIn("Bash", text.split("---")[1])  # no forbidden tool in frontmatter
            body = text.split("---", 2)[2]
            self.assertIn("Follow the dispatched task", body)
            self.assertIn("Bash", body)  # charter names the forbidden list

    def test_claude_models_follow_policy(self):
        with tempfile.TemporaryDirectory() as d:
            dispatch.emit_host_agents("claude", d)
            for fname, model in (("panopticon-scout.md", "haiku"),
                                 ("panopticon-lens-sweep.md", "haiku"),
                                 ("panopticon-panel-review.md", "sonnet"),
                                 ("panopticon-advisor.md", "opus")):
                self.assertIn("model: %s" % model,
                              open(os.path.join(d, fname)).read(), fname)

    def test_kimi_dialect_has_disallowed_tools(self):
        with tempfile.TemporaryDirectory() as d:
            dispatch.emit_host_agents("kimi", d)
            text = open(os.path.join(d, "panopticon-lens-sweep.md")).read()
            self.assertIn("disallowedTools:", text)
            self.assertIn("- Bash", text)

    def test_kimi_agent_file_includes_model_preference_and_when_to_use(self):
        with tempfile.TemporaryDirectory() as d:
            paths = dispatch.emit_host_agents("kimi", d)
            self.assertEqual(len(paths), 4)
            for p in paths:
                with open(p, encoding="utf-8") as fh:
                    content = fh.read()
                self.assertIn("whenToUse:", content)
                self.assertIn("override: false", content)
                self.assertIn("model_preference:", content)

            # role-specific preferences
            scout = os.path.join(d, "panopticon-scout.md")
            lens_sweep = os.path.join(d, "panopticon-lens-sweep.md")
            panel_review = os.path.join(d, "panopticon-panel-review.md")
            advisor = os.path.join(d, "panopticon-advisor.md")
            with open(scout, encoding="utf-8") as fh:
                self.assertIn("model_preference: primary", fh.read())
            with open(lens_sweep, encoding="utf-8") as fh:
                self.assertIn("model_preference: primary", fh.read())
            with open(panel_review, encoding="utf-8") as fh:
                self.assertIn("model_preference: secondary", fh.read())
            with open(advisor, encoding="utf-8") as fh:
                self.assertIn("model_preference: secondary", fh.read())

    def test_idempotent(self):
        with tempfile.TemporaryDirectory() as d:
            dispatch.emit_host_agents("claude", d)
            first = {p: open(os.path.join(d, p)).read() for p in os.listdir(d)}
            dispatch.emit_host_agents("claude", d)
            second = {p: open(os.path.join(d, p)).read() for p in os.listdir(d)}
            self.assertEqual(first, second)

    def test_unsupported_host_fails_fast(self):
        with self.assertRaises(ValueError):
            dispatch.emit_host_agents("generic", "/tmp/x")

    def test_cli_kimi_defaults_to_kimi_agents_dir(self):
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.object(dispatch, "KIMI_AGENTS_DIR", d):
            rc = dispatch.main(["--emit-host-agents", "kimi"])
            self.assertEqual(rc, 0)
            for fname in (
                "panopticon-scout.md",
                "panopticon-panel-review.md",
                "panopticon-lens-sweep.md",
                "panopticon-advisor.md",
            ):
                self.assertTrue(
                    os.path.isfile(os.path.join(d, fname)),
                    f"missing {fname}",
                )

    def test_cli_writes_to_out(self):
        with tempfile.TemporaryDirectory() as d:
            rc = dispatch.main(["--emit-host-agents", "claude", "--out", d])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.isfile(os.path.join(d, "panopticon-scout.md")))

    def test_emission_ignores_ambient_model_env_overrides(self):
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.dict(os.environ, {"PANOPTICON_MODEL_ADVISOR": "haiku"}):
            dispatch.emit_host_agents("claude", d)
            text = open(os.path.join(d, "panopticon-advisor.md")).read()
        self.assertIn("model: opus", text)
        self.assertNotIn("model: haiku", text)


class TestVerifyPlan(unittest.TestCase):
    """#493 R1/R2: dispatch-time plan re-verification + hash-bound ack."""

    def _entry(self, enforced=True, role="panel_review"):
        return {"role": role, "agent": "panopticon-panel-review",
                "enforced": enforced, "out_file": ".panopticon/x.json"}

    def test_enforced_flip_detected_when_shell_unregistered(self):
        with tempfile.TemporaryDirectory() as d:      # empty dir = nothing registered
            problems = dispatch.verify_plan([self._entry(enforced=True)],
                                            host="claude", agents_dir=d)
        self.assertEqual(len(problems), 1)
        self.assertIn("no registered shell", problems[0])

    def test_enforced_entry_with_live_shell_is_clean(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "panopticon-panel-review.md"), "w").write("x")
            problems = dispatch.verify_plan([self._entry(enforced=True)],
                                            host="claude", agents_dir=d)
        self.assertEqual(problems, [])

    def test_unenforced_reviewer_needs_hash_matching_ack(self):
        plan = [self._entry(enforced=False)]
        with tempfile.TemporaryDirectory() as d:
            no_ack = dispatch.verify_plan(plan, host="claude", agents_dir=d)
            stale = dispatch.verify_plan(plan, host="claude", agents_dir=d,
                                         ack={"acknowledged": True,
                                              "plan_sha256": "deadbeef"})
            good = dispatch.verify_plan(plan, host="claude", agents_dir=d,
                                        ack={"acknowledged": True,
                                             "plan_sha256": dispatch.plan_content_hash(plan)})
        self.assertEqual(len(no_ack), 1)
        self.assertEqual(len(stale), 1)
        self.assertEqual(good, [])

    def test_non_reviewer_roles_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            problems = dispatch.verify_plan(
                [{"role": "scout", "enforced": False}], host="claude", agents_dir=d)
        self.assertEqual(problems, [])
