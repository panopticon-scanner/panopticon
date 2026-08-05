import contextlib
import io
import json
import os
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
        try:
            rc = dispatch.main([profile_path, "--host", "kimi", "--out", out_path])
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
        try:
            # Use a path under /dev/null which cannot be created as a directory.
            out_path = "/dev/null/cannot-create/findings.json"
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                rc = dispatch.main([profile_path, "--out", out_path])
            self.assertEqual(rc, 1)
            self.assertIn("cannot create output directory", stderr.getvalue())
        finally:
            os.unlink(profile_path)


class TestDetectHost(unittest.TestCase):
    def _detect(self, env):
        with mock.patch.dict(os.environ, env, clear=True):
            return dispatch._detect_host()

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
            self.assertIn("tools: Read, Grep, Glob", text)
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

    def test_cli_kimi_requires_out(self):
        rc = dispatch.main(["--emit-host-agents", "kimi"])
        self.assertEqual(rc, 2)

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
