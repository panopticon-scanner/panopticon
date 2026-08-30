import builtins
import contextlib
import io
import os
import unittest
from unittest import mock
from unittest.mock import patch

import scripts.dispatch as dispatch
import scripts.model_resolver as mr


class TestFallbackMatchesProfiles(unittest.TestCase):
    """The hardcoded fallback tables must agree with model-profiles.yml.

    #run10: nothing tied them together, and they drifted. The tables carried
    lens_sweep/panel_review long after #1441 made those unrequestable, while
    never gaining domain_panel/domain_advisor for kimi or codex -- so with the
    YAML unreadable, kimi's domain_advisor resolved to primary/131072 instead
    of the k3/524288 the YAML specifies: the adjudication role quietly demoted
    to a weaker model with a quarter of the context. Only claude had been kept
    current (#1036). This pins both directions so the next role change cannot
    land in one place only.
    """

    _TABLES = {"kimi": mr._KIMI_FALLBACK, "claude": mr._CLAUDE_FALLBACK,
               "codex": mr._CODEX_FALLBACK}

    def test_every_live_role_is_in_every_fallback_table(self):
        for host, table in self._TABLES.items():
            for role in dispatch.ROLE_FILES:
                self.assertIn(role, table, "%s fallback is missing %s" % (host, role))

    def test_fallback_tables_carry_no_unrequestable_roles(self):
        for host, table in self._TABLES.items():
            extra = set(table) - set(dispatch.ROLE_FILES)
            self.assertEqual(extra, set(),
                             "%s fallback has roles nothing can request: %s"
                             % (host, sorted(extra)))

    def test_fallback_equals_the_profile_for_every_live_role(self):
        hosts = (mr._profiles().get("hosts") or {})
        for host, table in self._TABLES.items():
            for role in dispatch.ROLE_FILES:
                self.assertEqual(
                    mr._as_model_dict(hosts[host][role]), table[role],
                    "%s/%s: model-profiles.yml and the fallback table disagree"
                    % (host, role))


class TestModelResolver(unittest.TestCase):
    def test_hardcoded_fallback_unknown_role_on_known_hosts(self):
        # #run7 TST-A2C: the per-host default arm for an UNKNOWN role was
        # untested -- every other test uses a role present in the lookup dict.
        self.assertEqual(mr._hardcoded_fallback("kimi", "banana")["model"], "primary")
        self.assertEqual(mr._hardcoded_fallback("claude", "banana")["model"], "sonnet")
        self.assertEqual(mr._hardcoded_fallback("codex", "banana")["model"],
                         "gpt-5.6-terra")
        # an unknown HOST still resolves to None (inherit session), never kimi
        self.assertIsNone(mr._hardcoded_fallback("bogus", "banana")["model"])

    def test_kimi_defaults(self):
        cfg = mr.resolve_model("kimi", "scout")
        self.assertEqual(cfg["model"], "primary")
        self.assertEqual(cfg["alias"], "kimi-for-coding")
        self.assertEqual(cfg["max_output_size"], 16384)
        advisor = mr.resolve_model("kimi", "advisor")
        self.assertEqual(advisor["model"], "secondary")
        self.assertEqual(advisor["alias"], "k3")

    def test_kimi_roles_resolve_to_primary_secondary(self):
        self.assertEqual(mr.resolve_model("kimi", "scout")["model"], "primary")
        self.assertEqual(mr.resolve_model("kimi", "domain_panel")["model"], "secondary")
        self.assertEqual(mr.resolve_model("kimi", "domain_advisor")["model"], "secondary")
        self.assertEqual(mr.resolve_model("kimi", "advisor")["model"], "secondary")

    def test_claude_defaults_preserved(self):
        """Regression guard for the Kimi work: Claude must be untouched.

        Deliberately covers what test_claude_defaults does not — that the
        Kimi-only primary/secondary normalization never runs for Claude, so
        concrete model ids survive every override path.
        """
        self.assertEqual(
            mr.resolve_model("claude", "domain_panel", {"domain_panel": "opus"})["model"],
            "opus")
        with patch.dict(os.environ, {"PANOPTICON_MODEL_ADVISOR": "sonnet"},
                        clear=False):
            self.assertEqual(mr.resolve_model("claude", "advisor")["model"], "sonnet")
        self.assertEqual(mr.registration_model("claude", "domain_panel"), "sonnet")

    def test_kimi_override_is_normalized_to_a_dispatch_tier(self):
        # k3 is the reviewer roles' concrete alias, so passing it as a --model
        # override is the likely operator mistake.
        cfg = mr.resolve_model("kimi", "domain_panel", {"domain_panel": "k3"})
        self.assertEqual(cfg["model"], "secondary")
        self.assertEqual(cfg["alias"], "k3")
        cfg_coding = mr.resolve_model("kimi", "domain_panel", {"domain_panel": "kimi-for-coding"})
        self.assertEqual(cfg_coding["model"], "primary")
        self.assertEqual(cfg_coding["alias"], "kimi-for-coding")
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
        self.assertEqual(mr.resolve_model("claude", "domain_panel")["model"], "sonnet")
        self.assertEqual(mr.resolve_model("claude", "domain_advisor")["model"], "opus")
        # #1029: the per-finding tool-advisor is narrow single-claim work -> haiku
        self.assertEqual(mr.resolve_model("claude", "advisor")["model"], "haiku")

    def test_codex_defaults(self):
        self.assertEqual(mr.resolve_model("codex", "scout")["model"], "gpt-5.6-luna")
        panel = mr.resolve_model("codex", "domain_panel")
        self.assertEqual(panel["model"], "gpt-5.6-terra")
        self.assertEqual(panel["model_reasoning_effort"], "high")
        advisor = mr.registration_config("codex", "advisor")
        self.assertEqual(advisor["model"], "gpt-5.6")
        self.assertEqual(advisor["model_reasoning_effort"], "high")

    def test_unknown_host_falls_back(self):
        self.assertIsNone(mr.resolve_model("generic", "domain_panel")["model"])
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
        with mock.patch.dict(os.environ, {"PANOPTICON_MODEL_ADVISOR": "env-advisor"}):
            self.assertEqual(mr.resolve_model("claude", "advisor")["model"], "env-advisor")

    def test_cli_beats_env(self):
        with mock.patch.dict(os.environ, {"PANOPTICON_MODEL_ADVISOR": "env-advisor"}):
            self.assertEqual(
                mr.resolve_model("claude", "advisor", {"advisor": {"model": "cli-advisor"}})["model"],
                "cli-advisor"
            )

    def test_kimi_override_precedence_still_applies_within_the_contract(self):
        with mock.patch.dict(os.environ, {"PANOPTICON_MODEL_ADVISOR": "primary"}):
            self.assertEqual(mr.resolve_model("kimi", "advisor")["model"], "primary")
            self.assertEqual(
                mr.resolve_model("kimi", "advisor", {"advisor": {"model": "secondary"}})["model"],
                "secondary")

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
        self.assertEqual(mr.resolve_model("kimi", "scout")["model"], "primary")

    def test_unreadable_profiles_warns_and_falls_back(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            with patch("builtins.open", side_effect=OSError("permission denied")):
                profiles = mr._load_profiles()
        self.assertEqual(profiles, {})
        self.assertIn("cannot read model profiles", stderr.getvalue())
        self.assertEqual(mr.resolve_model("kimi", "scout")["model"], "primary")

    def test_kimi_fallback_still_kimi_flavored(self):
        # With profiles unavailable, kimi host keeps its hardcoded models.
        with patch.object(mr, "_PROFILES", {}):
            self.assertEqual(mr.resolve_model("kimi", "advisor")["model"], "secondary")

    def test_claude_fallback_matches_policy_without_yaml(self):
        with patch.object(mr, "_PROFILES", {}):
            self.assertEqual(mr.resolve_model("claude", "advisor")["model"], "haiku")

    def test_claude_registration_model_covers_matrix_roles(self):   # #1036
        # domain_panel/domain_advisor now resolve via model_resolver (the single
        # owner that dispatch's emit path reads), both with the yml present and
        # via the hardcoded fallback — no more duplicate EMIT_MODEL_POLICY dict.
        self.assertEqual(mr.registration_model("claude", "domain_panel"), "sonnet")
        self.assertEqual(mr.registration_model("claude", "domain_advisor"), "opus")
        with patch.object(mr, "_PROFILES", {}):   # yml absent -> fallback
            self.assertEqual(mr.registration_model("claude", "domain_panel"), "sonnet")
            self.assertEqual(mr.registration_model("claude", "domain_advisor"), "opus")
