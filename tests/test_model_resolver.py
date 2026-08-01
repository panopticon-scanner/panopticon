import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "scripts"))
import model_resolver as mr


class TestModelResolver(unittest.TestCase):
    def test_kimi_defaults(self):
        cfg = mr.resolve_model("kimi", "lens_sweep")
        self.assertEqual(cfg["model"], "kimi-for-coding")
        self.assertEqual(cfg["max_output_size"], 8192)
        self.assertEqual(mr.resolve_model("kimi", "advisor")["model"], "k3")

    def test_claude_defaults(self):
        self.assertEqual(mr.resolve_model("claude", "lens_sweep")["model"], "claude-haiku")
        self.assertEqual(mr.resolve_model("claude", "panel_review")["model"], "claude-sonnet")
        self.assertEqual(mr.resolve_model("claude", "advisor")["model"], "claude-opus")

    def test_unknown_host_falls_back(self):
        cfg = mr.resolve_model("unknown", "lens_sweep")
        self.assertEqual(cfg["model"], "kimi-for-coding")

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
