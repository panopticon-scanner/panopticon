import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "skill", "scripts"))
import orchestrator as orch
import dispatch


class TestDispatchIntegration(unittest.TestCase):
    def test_style_repo_caps_sweeps(self):
        with tempfile.TemporaryDirectory() as td:
            os.makedirs(os.path.join(td, "docs"))
            with open(os.path.join(td, "docs", "readme.md"), "w") as fh:
                fh.write("# hello")
            subprocess.run(["git", "init", td], capture_output=True)
            result = orch.build_result(td, "repo", ".", None, ["docs/readme.md"], [], 15)
            depth = result["groups"][0].get("depth", "standard")
            plan = dispatch.build_plan({
                "group": "root",
                "languages": [],
                "surfaces": [],
                "risk": "low",
                "depth": depth,
                "files": ["docs/readme.md"],
                "lenses": {"code": [{"name": "style", "spawn": True, "priority": 1, "depth_threshold": "shallow"}]},
                "panels": ["code"],
                "tools": [],
                "has_deps": False,
            }, host="kimi")
            sweep_count = sum(1 for p in plan if p["role"] == "lens_sweep")
            self.assertLessEqual(sweep_count, 1)

    def test_auth_repo_is_deep(self):
        profile = {
            "group": "root",
            "languages": ["python"],
            "surfaces": ["auth"],
            "risk": "high",
            "depth": "deep",
            "files": ["app/auth.py"],
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
        plan = dispatch.build_plan(profile, host="claude")
        models = {p["role"]: p["model"]["model"] for p in plan}
        self.assertEqual(models["lens_sweep"], "haiku")
        self.assertEqual(models["panel_review"], "sonnet")
        self.assertEqual(len([p for p in plan if p["role"] == "lens_sweep"]), 3)
