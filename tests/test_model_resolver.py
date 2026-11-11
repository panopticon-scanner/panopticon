import builtins
import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock
from unittest.mock import patch

import scripts.dispatch as dispatch
import scripts.model_resolver as mr
from scripts import hosts
from scripts.runners import agy as agy_runner
from scripts.runners import gemini as gemini_runner
from scripts.runners import gemini_home


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
               "codex": mr._CODEX_FALLBACK, "agy": mr._AGY_FALLBACK,
               "gemini": mr._GEMINI_FALLBACK}

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
        self.assertEqual(mr._hardcoded_fallback("claude", "banana")["model"],
                         "claude-sonnet-5-5")
        self.assertEqual(mr._hardcoded_fallback("codex", "banana"),
                         {"model": "gpt-6.1-sol", "model_reasoning_effort": "medium"})
        self.assertEqual(mr._hardcoded_fallback("agy", "banana"),
                         {"model": "gemini-4-argon-high", "tier": "pro"})
        self.assertEqual(mr._hardcoded_fallback("gemini", "banana"),
                         {"model": "gemini-3.8-flash"})
        # an unknown HOST still resolves to None (inherit session), never kimi
        self.assertIsNone(mr._hardcoded_fallback("bogus", "banana")["model"])

    def test_gemini_defaults(self):
        for role in ("scout", "advisor"):
            cfg = mr.resolve_model("gemini", role)
            self.assertEqual(cfg["model"], "gemini-3.8-flash")
        for role in ("domain_panel", "domain_advisor"):
            cfg = mr.resolve_model("gemini", role)
            self.assertEqual(cfg["model"], "gemini-4-carbon")
        self.assertIsNone(mr.resolve_model("gemini", "setup_scan")["model"])

    def test_agy_defaults(self):
        for role in ("scout", "advisor"):
            cfg = mr.resolve_model("agy", role)
            self.assertEqual(cfg["model"], "gemini-3.8-flash-medium")
            self.assertEqual(cfg["tier"], "flash")
        for role in ("domain_panel", "domain_advisor"):
            cfg = mr.resolve_model("agy", role)
            self.assertEqual(cfg["model"], "gemini-4-argon-high")
            self.assertEqual(cfg["tier"], "pro")
        self.assertIsNone(mr.resolve_model("agy", "setup_scan")["model"])

    def test_kimi_defaults(self):
        cfg = mr.resolve_model("kimi", "scout")
        self.assertEqual(cfg["model"], "primary")
        self.assertEqual(cfg["alias"], "k3-256k")
        self.assertEqual(cfg["max_output_size"], 16384)
        advisor = mr.resolve_model("kimi", "advisor")
        self.assertEqual(advisor["model"], "secondary")
        self.assertEqual(advisor["alias"], "k3.1-pro")

    def test_kimi_roles_resolve_to_primary_secondary(self):
        self.assertEqual(mr.resolve_model("kimi", "scout")["model"], "primary")
        self.assertEqual(mr.resolve_model("kimi", "domain_panel")["model"], "secondary")
        self.assertEqual(mr.resolve_model("kimi", "domain_advisor")["model"], "secondary")
        self.assertEqual(mr.resolve_model("kimi", "advisor")["model"], "secondary")

    def test_claude_overrides_remain_concrete_and_registration_stays_fixed(self):
        """One-run overrides survive while persisted shells stay reproducible."""
        self.assertEqual(
            mr.resolve_model("claude", "domain_panel", {"domain_panel": "opus"})["model"],
            "opus")
        with patch.dict(os.environ, {"PANOPTICON_MODEL_ADVISOR": "sonnet"},
                        clear=False):
            self.assertEqual(mr.resolve_model("claude", "advisor")["model"], "sonnet")
        self.assertEqual(mr.registration_model("claude", "domain_panel"),
                         "claude-sonnet-5-5")

    def test_kimi_override_is_normalized_to_a_dispatch_tier(self):
        # k3.1-pro is the reviewer roles' concrete alias, so passing it as a --model
        # override is the likely operator mistake.
        cfg = mr.resolve_model("kimi", "domain_panel", {"domain_panel": "k3.1-pro"})
        self.assertEqual(cfg["model"], "secondary")
        self.assertEqual(cfg["alias"], "k3.1-pro")
        cfg_coding = mr.resolve_model("kimi", "domain_panel", {"domain_panel": "k3-256k"})
        self.assertEqual(cfg_coding["model"], "primary")
        self.assertEqual(cfg_coding["alias"], "k3-256k")
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
        self.assertEqual(mr.resolve_model("claude", "scout")["model"], "claude-haiku-5-5")
        self.assertEqual(mr.resolve_model("claude", "domain_panel")["model"],
                         "claude-sonnet-5-5")
        self.assertEqual(mr.resolve_model("claude", "domain_advisor")["model"],
                         "claude-opus-5-5")
        # #1029: the per-finding tool-advisor is narrow single-claim work -> haiku
        self.assertEqual(mr.resolve_model("claude", "advisor")["model"],
                         "claude-haiku-5-5")

    def test_claude_defaults_are_fixed_ids_never_moving_aliases(self):
        aliases = {"haiku", "sonnet", "opus"}
        defaults = {
            mr.registration_model("claude", role)
            for role in dispatch.ROLE_FILES
        }
        self.assertTrue(aliases.isdisjoint(defaults))

    def test_codex_defaults(self):
        self.assertEqual(mr.resolve_model("codex", "scout")["model"], "gpt-6-luna")
        panel = mr.resolve_model("codex", "domain_panel")
        self.assertEqual(panel["model"], "gpt-6.1-sol")
        self.assertEqual(panel["model_reasoning_effort"], "high")
        advisor = mr.registration_config("codex", "advisor")
        self.assertEqual(advisor["model"], "gpt-6.1-sol")
        self.assertEqual(advisor["model_reasoning_effort"], "high")
        domain_advisor = mr.registration_config("codex", "domain_advisor")
        self.assertEqual(domain_advisor["model"], "gpt-6.1-sol")
        self.assertEqual(domain_advisor["model_reasoning_effort"], "high")

    def test_resolver_defaults_are_in_strict_host_catalogues(self):
        catalogues = {
            "agy": agy_runner.KNOWN_MODELS,
            "gemini": gemini_runner.KNOWN_MODELS,
        }
        for host, catalogue in catalogues.items():
            for role in dispatch.ROLE_FILES:
                model = mr.registration_model(host, role)
                if model is not None:
                    self.assertIn(model, catalogue, "%s/%s default is not allowlisted" % (host, role))

    def test_gemini_resolver_defaults_are_never_moving_aliases(self):
        defaults = {
            mr.registration_model("gemini", role)
            for role in dispatch.ROLE_FILES
        }
        self.assertTrue(gemini_home.MODEL_ALIASES.isdisjoint(defaults))

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

    def test_malformed_object_intent_names_key_without_exposing_value(self):
        key = "PANOPTICON_MODEL_ADVISOR"
        for value in (' {"model": ', '{"model": "secret-sentinel",}',
                      '{"model": "secret-sentinel"} trailing'):
            with self.subTest(value=value), mock.patch.dict(os.environ, {key: value}):
                with self.assertRaises(ValueError) as caught:
                    mr.resolve_model("claude", "advisor")
                self.assertIn(key, str(caught.exception))
                self.assertNotIn(value, str(caught.exception))
                self.assertNotIn("secret-sentinel", str(caught.exception))

    def test_an_override_effort_that_is_not_a_word_is_refused_before_host_work(self):
        # #2879: named, never echoed, on the malformed-object channel.
        key = "PANOPTICON_MODEL_DOMAIN_PANEL"
        for effort in ("secret-sentinel", "HIGH", "", 7, None, ["low"], "low\n"):
            value = json.dumps({"model": "gpt-6-sol", "model_reasoning_effort": effort})
            with self.subTest(effort=effort), mock.patch.dict(os.environ, {key: value}):
                with self.assertRaises(ValueError) as caught:
                    mr.validate_env_overrides()
                self.assertIn(key, str(caught.exception))
                self.assertNotIn("secret-sentinel", str(caught.exception))

    def test_an_override_effort_that_is_a_word_passes(self):
        for effort in ("low", "xhigh", "ultra"):
            value = json.dumps({"model": "gpt-6-sol", "model_reasoning_effort": effort})
            with self.subTest(effort=effort), \
                    mock.patch.dict(os.environ, {"PANOPTICON_MODEL_SCOUT": value}):
                mr.validate_env_overrides()

    def test_plain_ids_and_valid_objects_allow_surrounding_whitespace(self):
        key = "PANOPTICON_MODEL_ADVISOR"
        with mock.patch.dict(os.environ, {key: "  custom-model  "}):
            self.assertEqual(mr.resolve_model("claude", "advisor"),
                             {"model": "custom-model"})
        with mock.patch.dict(os.environ, {key: '  {"model":"custom-model","max_context_size":42}  '}):
            self.assertEqual(mr.resolve_model("claude", "advisor"),
                             {"model": "custom-model", "max_context_size": 42})

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

    def test_invalid_yaml_profile_warns_and_resolves_from_fresh_fallback(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "model-profiles.yml")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("hosts: [\n")
            stderr = io.StringIO()
            with patch.object(mr._version, "reference_path", return_value=path), \
                    patch.object(mr, "_PROFILES", None), \
                    contextlib.redirect_stderr(stderr):
                self.assertEqual(mr._load_profiles(), {})
                self.assertEqual(mr.resolve_model("kimi", "domain_advisor")["model"],
                                 "secondary")
                self.assertEqual(mr._PROFILES, {})
            self.assertIn("invalid YAML", stderr.getvalue())
            self.assertIn(path, stderr.getvalue())

    def test_kimi_fallback_still_kimi_flavored(self):
        # With profiles unavailable, kimi host keeps its hardcoded models.
        with patch.object(mr, "_PROFILES", {}):
            self.assertEqual(mr.resolve_model("kimi", "advisor")["model"], "secondary")

    def test_claude_fallback_matches_policy_without_yaml(self):
        with patch.object(mr, "_PROFILES", {}):
            self.assertEqual(mr.resolve_model("claude", "advisor")["model"],
                             "claude-haiku-5-5")

    def test_claude_registration_model_covers_matrix_roles(self):   # #1036
        # domain_panel/domain_advisor now resolve via model_resolver (the single
        # owner that dispatch's emit path reads), both with the yml present and
        # via the hardcoded fallback — no more duplicate EMIT_MODEL_POLICY dict.
        self.assertEqual(mr.registration_model("claude", "domain_panel"),
                         "claude-sonnet-5-5")
        self.assertEqual(mr.registration_model("claude", "domain_advisor"),
                         "claude-opus-5-5")
        with patch.object(mr, "_PROFILES", {}):   # yml absent -> fallback
            self.assertEqual(mr.registration_model("claude", "domain_panel"),
                             "claude-sonnet-5-5")
            self.assertEqual(mr.registration_model("claude", "domain_advisor"),
                             "claude-opus-5-5")


class TestUnknownHostsStayUnknown(unittest.TestCase):
    """#1344 F2: the resolver's 'never silently assume kimi' rule now has one
    definition of 'unknown host' rather than an implicit else-branch."""

    def test_a_host_the_registry_does_not_know_resolves_to_no_model(self):
        self.assertEqual({"model": None},
                         mr._hardcoded_fallback("no-such-host", "scout"))

    def test_a_known_host_with_no_fallback_table_also_resolves_to_no_model(self):
        # generic is in the registry and has no table (#3494 gave gemini its
        # own fallback table, restoring the row #1621 had retired). Falling
        # through to another host's table would be the bug this guards.
        for name in ("generic",):
            with self.subTest(host=name):
                self.assertEqual({"model": None},
                                 mr._hardcoded_fallback(name, "scout"))

    def test_every_registry_host_resolves_without_raising(self):
        for name in hosts.known_hosts():
            for role in ("scout", "advisor", "domain_panel", "domain_advisor"):
                with self.subTest(host=name, role=role):
                    self.assertIsInstance(
                        mr._hardcoded_fallback(name, role), dict)
