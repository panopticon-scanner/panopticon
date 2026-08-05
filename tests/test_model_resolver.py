import builtins
import contextlib
import io
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "skill", "scripts"))
import model_resolver as mr


class TestModelResolver(unittest.TestCase):
    def test_kimi_defaults(self):
        cfg = mr.resolve_model("kimi", "lens_sweep")
        self.assertEqual(cfg["model"], "primary")
        self.assertEqual(cfg["alias"], "kimi-for-coding")
        self.assertEqual(cfg["max_output_size"], 8192)
        advisor = mr.resolve_model("kimi", "advisor")
        self.assertEqual(advisor["model"], "secondary")
        self.assertEqual(advisor["alias"], "k3")

    def test_kimi_roles_resolve_to_primary_secondary(self):
        self.assertEqual(mr.resolve_model("kimi", "scout")["model"], "primary")
        self.assertEqual(mr.resolve_model("kimi", "lens_sweep")["model"], "primary")
        self.assertEqual(mr.resolve_model("kimi", "panel_review")["model"], "secondary")
        self.assertEqual(mr.resolve_model("kimi", "advisor")["model"], "secondary")

    def test_claude_roles_preserve_concrete_models(self):
        self.assertEqual(mr.resolve_model("claude", "scout")["model"], "haiku")
        self.assertEqual(mr.resolve_model("claude", "lens_sweep")["model"], "haiku")
        self.assertEqual(mr.resolve_model("claude", "panel_review")["model"], "sonnet")
        self.assertEqual(mr.resolve_model("claude", "advisor")["model"], "opus")

    def test_claude_defaults(self):
        self.assertEqual(mr.resolve_model("claude", "scout")["model"], "haiku")
        self.assertEqual(mr.resolve_model("claude", "lens_sweep")["model"], "haiku")
        self.assertEqual(mr.resolve_model("claude", "panel_review")["model"], "sonnet")
        self.assertEqual(mr.resolve_model("claude", "advisor")["model"], "opus")

    def test_unknown_host_falls_back(self):
        self.assertIsNone(mr.resolve_model("generic", "panel_review")["model"])
        self.assertIsNone(mr.resolve_model("someday-host", "scout")["model"])

    def test_cli_override(self):
        overrides = {"advisor": {"model": "custom-model"}}
        self.assertEqual(mr.resolve_model("kimi", "advisor", overrides)["model"], "custom-model")

    def test_env_override(self):
        os.environ["PANOPTICON_MODEL_ADVISOR"] = "env-advisor"
        try:
            self.assertEqual(mr.resolve_model("kimi", "advisor")["model"], "env-advisor")
        finally:
            del os.environ["PANOPTICON_MODEL_ADVISOR"]

    def test_cli_beats_env(self):
        os.environ["PANOPTICON_MODEL_ADVISOR"] = "env-advisor"
        try:
            self.assertEqual(
                mr.resolve_model("kimi", "advisor", {"advisor": {"model": "cli-advisor"}})["model"],
                "cli-advisor"
            )
        finally:
            del os.environ["PANOPTICON_MODEL_ADVISOR"]

    def test_missing_yaml_warns_and_falls_back(self):
        real_import = builtins.__import__

        def block_yaml(name, *args, **kwargs):
            if name == "yaml":
                raise ImportError("No module named 'yaml'")
            return real_import(name, *args, **kwargs)

        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            with patch.object(builtins, "__import__", side_effect=block_yaml):
                profiles = mr._load_profiles()
        self.assertEqual(profiles, {})
        self.assertIn("PyYAML not installed", stderr.getvalue())
        # Fallback still resolves a model.
        self.assertEqual(mr.resolve_model("kimi", "lens_sweep")["model"], "primary")

    def test_unreadable_profiles_warns_and_falls_back(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            with patch("builtins.open", side_effect=OSError("permission denied")):
                profiles = mr._load_profiles()
        self.assertEqual(profiles, {})
        self.assertIn("cannot read model profiles", stderr.getvalue())
        self.assertEqual(mr.resolve_model("kimi", "lens_sweep")["model"], "primary")

    def test_kimi_fallback_still_kimi_flavored(self):
        # With profiles unavailable, kimi host keeps its hardcoded models.
        with patch.object(mr, "_PROFILES", {}):
            self.assertEqual(mr.resolve_model("kimi", "advisor")["model"], "secondary")

    def test_claude_fallback_matches_policy_without_yaml(self):
        with patch.object(mr, "_PROFILES", {}):
            self.assertEqual(mr.resolve_model("claude", "advisor")["model"], "opus")
