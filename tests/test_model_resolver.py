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

    def test_claude_defaults_preserved(self):
        """Regression guard for the Kimi work: Claude must be untouched.

        Deliberately covers what test_claude_defaults does not — that the
        Kimi-only primary/secondary normalization never runs for Claude, so
        concrete model ids survive every override path.
        """
        self.assertEqual(
            mr.resolve_model("claude", "panel_review", {"panel_review": "opus"})["model"],
            "opus")
        with patch.dict(os.environ, {"PANOPTICON_MODEL_ADVISOR": "sonnet"},
                        clear=False):
            self.assertEqual(mr.resolve_model("claude", "advisor")["model"], "sonnet")
        self.assertEqual(mr.registration_model("claude", "panel_review"), "sonnet")

    def test_kimi_override_is_normalized_to_a_dispatch_tier(self):
        # k3 was panel_review's concrete alias before the tiers existed, so
        # passing it as a --model override is the likely operator mistake.
        cfg = mr.resolve_model("kimi", "panel_review", {"panel_review": "k3"})
        self.assertEqual(cfg["model"], "secondary")
        self.assertEqual(cfg["alias"], "k3")
        with contextlib.redirect_stderr(io.StringIO()) as err:
            unknown = mr.resolve_model("kimi", "scout", {"scout": "nonsense"})
        self.assertEqual(unknown["model"], "primary")
        self.assertIn("not a Kimi dispatch tier", err.getvalue())

    def test_registration_model_ignores_ambient_overrides(self):
        # Persisted registration files must not inherit a one-run override.
        with patch.dict(os.environ, {"PANOPTICON_MODEL_SCOUT": "secondary"},
                        clear=False):
            self.assertEqual(mr.resolve_model("kimi", "scout")["model"], "secondary")
            self.assertEqual(mr.registration_model("kimi", "scout"), "primary")

    def test_claude_defaults(self):
        self.assertEqual(mr.resolve_model("claude", "scout")["model"], "haiku")
        self.assertEqual(mr.resolve_model("claude", "lens_sweep")["model"], "haiku")
        self.assertEqual(mr.resolve_model("claude", "panel_review")["model"], "sonnet")
        # #1029: the per-finding tool-advisor is narrow single-claim work -> haiku
        self.assertEqual(mr.resolve_model("claude", "advisor")["model"], "haiku")

    def test_codex_defaults(self):
        self.assertEqual(mr.resolve_model("codex", "scout")["model"], "gpt-5.6-luna")
        panel = mr.resolve_model("codex", "panel_review")
        self.assertEqual(panel["model"], "gpt-5.6-terra")
        self.assertEqual(panel["model_reasoning_effort"], "high")
        advisor = mr.registration_config("codex", "advisor")
        self.assertEqual(advisor["model"], "gpt-5.6")
        self.assertEqual(advisor["model_reasoning_effort"], "high")

    def test_unknown_host_falls_back(self):
        self.assertIsNone(mr.resolve_model("generic", "panel_review")["model"])
        self.assertIsNone(mr.resolve_model("someday-host", "scout")["model"])

    # Override precedence is host-agnostic, but only Kimi constrains the
    # resulting value (primary|secondary), so these exercise it on claude,
    # where a concrete model id IS the contract. Kimi's normalization of an
    # out-of-contract override is covered by
    # test_kimi_override_is_normalized_to_a_dispatch_tier.
    def test_cli_override(self):
        overrides = {"advisor": {"model": "custom-model"}}
        self.assertEqual(mr.resolve_model("claude", "advisor", overrides)["model"], "custom-model")

    def test_env_override(self):
        os.environ["PANOPTICON_MODEL_ADVISOR"] = "env-advisor"
        try:
            self.assertEqual(mr.resolve_model("claude", "advisor")["model"], "env-advisor")
        finally:
            del os.environ["PANOPTICON_MODEL_ADVISOR"]

    def test_cli_beats_env(self):
        os.environ["PANOPTICON_MODEL_ADVISOR"] = "env-advisor"
        try:
            self.assertEqual(
                mr.resolve_model("claude", "advisor", {"advisor": {"model": "cli-advisor"}})["model"],
                "cli-advisor"
            )
        finally:
            del os.environ["PANOPTICON_MODEL_ADVISOR"]

    def test_kimi_override_precedence_still_applies_within_the_contract(self):
        os.environ["PANOPTICON_MODEL_ADVISOR"] = "primary"
        try:
            self.assertEqual(mr.resolve_model("kimi", "advisor")["model"], "primary")
            self.assertEqual(
                mr.resolve_model("kimi", "advisor", {"advisor": {"model": "secondary"}})["model"],
                "secondary")
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
            self.assertEqual(mr.resolve_model("claude", "advisor")["model"], "haiku")
