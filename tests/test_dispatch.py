import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "skill", "scripts"))
import dispatch


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
        plan = dispatch.build_plan(self._profile("standard"), host="claude")
        advisor = [p for p in plan if p["role"] == "advisor"]
        self.assertEqual(len(advisor), 0)
        panel = [p for p in plan if p["role"] == "panel_review"][0]
        self.assertEqual(panel["model"]["model"], "claude-sonnet")
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
        plan = dispatch.build_plan(profile, host="claude")
        self.assertTrue(plan)
        for entry in plan:
            self.assertIn("prompt", entry)
            self.assertNotIn("{file_list}", entry["prompt"])
        sweep = [e for e in plan if e["role"] == "lens_sweep"][0]
        self.assertIn("injection", sweep["prompt"])


class TestRenderGoldens(unittest.TestCase):
    def test_rendered_output_matches_goldens(self):
        mapping = {"panel": "security", "group": "g1", "file_list": "a.py, b.py",
                   "security_mode": "standard", "depth": "standard",
                   "lenses": "- known_vulns\n- novel", "lens": "injection",
                   "out_file": ".panopticon/findings-g1-security-panel_review.json"}
        gdir = os.path.join(os.path.dirname(__file__), "goldens")
        for role in ("panel-review.md", "lens-sweep.md", "scout.md"):
            m = dict(mapping)
            if role == "scout.md":
                m["out_file"] = ".panopticon/scout-g1.json"
            expected = open(os.path.join(gdir, role[:-3] + ".rendered.txt"),
                            encoding="utf-8").read()
            self.assertEqual(dispatch.render_prompt(role, m), expected, role)
