import builtins
import contextlib
import io
import json
import os
import runpy
import sys
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
                         {"model": "gemini-4-carbon", "effort": "high", "tier": "pro"})
        self.assertEqual(mr._hardcoded_fallback("gemini", "banana"),
                         {"model": "gemini-3.8-flash"})
        # The registered generic host still inherits the session model, never kimi.
        self.assertIsNone(mr._hardcoded_fallback("generic", "banana")["model"])

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
            self.assertEqual(cfg["model"], "gemini-4-carbon")       # #3564: base ID + effort
            self.assertEqual(cfg["effort"], "high")
            self.assertEqual(cfg["tier"], "pro")
        self.assertIsNone(mr.resolve_model("agy", "setup_scan")["model"])

    def test_strict_switch_reads_the_env_and_defaults_on_under_ci(self):
        # #3582: strict turns every ladder off; unset, CI is strict.
        for env, strict in (({}, False), ({"CI": "true"}, True), ({"GITHUB_ACTIONS": "true"}, True),
                            ({"CI": "false"}, False), ({"CI": "0"}, False),
                            ({"PANOPTICON_MODEL_STRICT": "1"}, True),
                            ({"PANOPTICON_MODEL_STRICT": "0", "CI": "true"}, False),
                            ({"PANOPTICON_MODEL_STRICT": "yes"}, True)):
            with self.subTest(env=env):
                self.assertIs(strict, mr.strict_models(env))
        with self.assertRaisesRegex(ValueError, "neither on .1. nor off .0."):
            mr.strict_models({"PANOPTICON_MODEL_STRICT": "maybe"})

    def test_strict_runs_and_operator_named_models_carry_no_ladder(self):
        for env in ({"PANOPTICON_MODEL_STRICT": "1"},
                    {"PANOPTICON_MODEL_STRICT": "", "CI": "true"}):
            with self.subTest(env=env), mock.patch.dict(os.environ, env):
                self.assertEqual({"model": "gemini-4-carbon", "effort": "high"},
                                 mr.entry_policy("agy", "domain_panel"))
        with mock.patch.dict(os.environ, {"PANOPTICON_MODEL_DOMAIN_PANEL":
                                          '{"model": "gemini-4-carbon", "effort": "high", '
                                          '"fallbacks": {"key": ["gemini-4-argon-high"]}}'}):
            self.assertNotIn("fallbacks", mr.entry_policy("agy", "domain_panel"))

    def test_fallback_ladders_are_validated_and_never_ignored(self):
        self.assertEqual([], mr.profile_problems())
        self.assertEqual({"key": ["gemini-4-argon-high"]},
                         mr.registration_config("agy", "domain_panel")["fallbacks"])
        self.assertEqual(mr._AGY_FALLBACK["domain_panel"]["fallbacks"],
                         mr.registration_config("agy", "domain_panel")["fallbacks"])
        for host, cfg, why in (
                ("agy", {"fallbacks": {"signin": ["gemini-4-argon"]}},
                 "route signin has no measured model list"),
                ("codex", {"fallbacks": {"key": ["gpt-6.1"]}},
                 "route key has no measured model list on codex .routes with one: none."),
                ("claude", {"fallbacks": {"api": ["claude-sonnet-5-5"]}}, "on claude"),
                ("kimi", {"fallbacks": {"key": ["k3"]}}, "on kimi"),
                ("gemini", {"fallbacks": {"key": ["gemini-3.8-flash"]}}, "on gemini"),
                ("agy", {"fallbacks": ["gemini-4-argon-high"]}, "not a route-to-ladder"),
                ("agy", {"fallbacks": {}}, "not a route-to-ladder"),
                ("agy", {"fallbacks": {"key": []}}, "not a non-empty list"),
                ("agy", {"fallbacks": {"key": ["Gemini 4"]}}, "not a non-empty list"),
                ("agy", {"fallbacks": {"key": ["a-1", "a-1"]}}, "repeats a model")):
            with self.subTest(host=host, cfg=cfg):
                self.assertRegex(mr.fallbacks_problem(host, cfg), why)
        self.assertIsNone(mr.fallbacks_problem("agy", {"model": "x"}))
        with mock.patch.dict(mr._AGY_FALLBACK, {"advisor": {
                "model": "gemini-3.8-flash-medium", "fallbacks": {"signin": ["x"]}}}), \
                mock.patch.object(mr, "_PROFILES", {"hosts": {}}):
            with self.assertRaisesRegex(ValueError, "model policy for agy advisor names fallbacks"):
                mr.entry_policy("agy", "advisor")
            self.assertEqual(1, len(mr.profile_problems()))

    def test_agy_entry_policy_carries_effort_only_where_set(self):
        # #3564: the entry gets `effort` beside `model` on agy, as codex gets its effort.
        for role in ("domain_panel", "domain_advisor"):
            # #3582: the suite runs with fallbacks on (conftest), so the ladder rides along.
            self.assertEqual({"model": "gemini-4-carbon", "effort": "high",
                              "fallbacks": {"key": ["gemini-4-argon-high"]}},
                             mr.entry_policy("agy", role))
        for role in ("scout", "advisor"):
            self.assertEqual({"model": "gemini-3.8-flash-medium"}, mr.entry_policy("agy", role))
        self.assertNotIn("effort", mr.entry_policy("gemini", "domain_panel"))
        self.assertNotIn("effort", mr.entry_policy("codex", "domain_panel"))
        # #3576: an operator-named agy model is marked, so the runner never substitutes it.
        with mock.patch.dict(os.environ, {"PANOPTICON_MODEL_DOMAIN_PANEL": "gemini-4-argon"}):
            self.assertEqual({"model": "gemini-4-argon", "model_override": True},
                             mr.entry_policy("agy", "domain_panel"))
        with mock.patch.dict(os.environ, {"PANOPTICON_MODEL_DOMAIN_PANEL":
                                          '{"model": "gemini-4-carbon", "effort": "medium"}'}):
            self.assertEqual({"model": "gemini-4-carbon", "effort": "medium",
                              "model_override": True},
                             mr.entry_policy("agy", "domain_panel"))
            self.assertNotIn("model_override", mr.entry_policy("gemini", "domain_panel"))
            # Only agy's runner takes `effort`: on any other host it never reaches the entry,
            # and codex, which has its own effort key, refuses it rather than drop it.
            for host in ("gemini", "claude", "kimi"):
                self.assertNotIn("effort", mr.entry_policy(host, "domain_panel"), host)
            with self.assertRaisesRegex(ValueError, "carries effort, which only agy reads"):
                mr.entry_policy("codex", "domain_panel")

    # --- #3571 review: an effort the host would drop or refuse is refused up front ---------------
    def _refused(self, value, host, why):
        key = "PANOPTICON_MODEL_DOMAIN_PANEL"
        with mock.patch.dict(os.environ, {key: value}):
            with self.assertRaises(ValueError) as caught:
                mr.validate_env_overrides(host)
        self.assertIn(key, str(caught.exception))
        self.assertIn(why, str(caught.exception))
        self.assertNotIn("secret-sentinel", str(caught.exception))

    def test_a_codex_effort_key_on_agy_is_refused_at_start_and_at_use(self):
        value = '{"model": "gemini-4-carbon", "model_reasoning_effort": "high"}'
        self._refused(value, "agy", "carries model_reasoning_effort, which only codex reads")
        with mock.patch.dict(os.environ, {"PANOPTICON_MODEL_DOMAIN_PANEL": value}):
            with self.assertRaisesRegex(ValueError, "agy domain_panel carries "
                                        "model_reasoning_effort"):
                mr.entry_policy("agy", "domain_panel")
            mr.validate_env_overrides("codex")          # codex's own key stays valid

    def test_an_agy_effort_key_on_another_host_is_refused(self):
        value = '{"model": "gpt-6-sol", "effort": "high"}'
        for host in ("codex", "gemini", "claude"):
            with self.subTest(host=host):
                self._refused(value, host, "carries effort, which only agy reads")

    def test_an_agy_effort_out_of_shape_is_refused_whatever_the_host(self):
        for value, why in (
                ('{"model": "gemini-4-carbon", "effort": "turbo"}', "effort must be one of"),
                ('{"model": "gemini-4-carbon", "effort": "secret-sentinel"}',
                 "effort must be one of"),
                ('{"model": "gemini-4-carbon", "effort": "High"}', "effort must be one of"),
                # #3564 capture: agy lists only low, medium and high.
                ('{"model": "gemini-4-carbon", "effort": "xhigh"}', "effort must be one of"),
                ('{"model": "gemini-4-carbon", "effort": "max"}', "effort must be one of"),
                ('{"model": "gemini-4-carbon-max", "effort": "high"}', "already names one"),
                ('{"model": "gemini-4-carbon", "effort": null}', "effort must be one of"),
                ('{"effort": "high"}', "with no model"),
                ('{"model": null, "effort": "high"}', "with no model"),
                ('{"model": "gemini-4-argon-high", "effort": "high"}', "already names one")):
            for host in ("agy", None):
                with self.subTest(value=value, host=host):
                    self._refused(value, host, why)

    def test_valid_effort_overrides_pass(self):
        key = "PANOPTICON_MODEL_DOMAIN_PANEL"
        for host, value in (("agy", '{"model": "gemini-4-carbon", "effort": "medium"}'),
                            (None, '{"model": "gemini-4-carbon", "effort": "low"}'),
                            ("agy", "gemini-4-argon-high"),
                            ("codex", '{"model": "gpt-6-sol", "model_reasoning_effort": "low"}')):
            with self.subTest(host=host, value=value), mock.patch.dict(os.environ, {key: value}):
                mr.validate_env_overrides(host)

    def test_the_driver_passes_its_host_to_the_check(self):
        import scripts.driver as driver
        seen = []

        def stop(host=None):
            seen.append(host)
            raise ValueError("stop")
        with mock.patch.object(driver.model_resolver, "validate_env_overrides", stop):
            status = driver.run(mock.Mock(host="agy", verb="run"))
        self.assertEqual(["agy"], seen)
        self.assertIn("stop", json.dumps(status))

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

    def test_registered_generic_host_inherits_the_session_model(self):
        self.assertIsNone(mr.resolve_model("generic", "domain_panel")["model"])

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


class TestUnknownHostsAreRefused(unittest.TestCase):
    """#3568: only registered hosts may enter the resolver."""

    ERROR = ("unknown host 'openrouter' "
             "(known: agy|claude|codex|gemini|generic|kimi)")

    def assert_unknown(self, call):
        with self.assertRaises(ValueError) as caught:
            call()
        self.assertEqual(str(caught.exception), self.ERROR)

    def test_registration_entry_points_refuse_an_unregistered_host(self):
        self.assert_unknown(lambda: mr.registration_config("openrouter", "scout"))
        self.assert_unknown(lambda: mr.registration_model("openrouter", "scout"))
        self.assertEqual(mr.registration_config("generic", "scout"), {"model": None})
        self.assertIsNone(mr.registration_model("generic", "scout"))

    def test_a_stale_profile_cannot_make_an_unregistered_host_resolvable(self):
        stale = {"hosts": {"someday": {"scout": {"model": "x"}}}}
        expected = ("unknown host 'someday' "
                    "(known: agy|claude|codex|gemini|generic|kimi)")
        with patch.object(mr, "_profiles", return_value=stale):
            for entry in (mr.registration_config, mr.registration_model,
                          mr.resolve_model):
                with self.subTest(entry=entry.__name__):
                    with self.assertRaises(ValueError) as caught:
                        entry("someday", "scout")
                    self.assertEqual(str(caught.exception), expected)

    def test_resolution_refuses_before_cli_and_environment_overrides(self):
        for resolver in (mr.resolve_model, mr._resolve_raw):
            with self.subTest(entry=resolver.__name__, override="cli"):
                self.assert_unknown(
                    lambda resolver=resolver: resolver(
                        "openrouter", "scout", {"scout": "override-model"}))
            with self.subTest(entry=resolver.__name__, override="environment"), \
                    patch.dict(os.environ,
                               {"PANOPTICON_MODEL_SCOUT": "override-model"}):
                self.assert_unknown(
                    lambda resolver=resolver: resolver("openrouter", "scout"))
        self.assertEqual(mr.resolve_model("generic", "scout"), {"model": None})
        self.assertEqual(mr._resolve_raw("generic", "scout"), {"model": None})

    def test_hardcoded_fallback_refuses_an_unregistered_host(self):
        self.assert_unknown(lambda: mr._hardcoded_fallback("openrouter", "scout"))
        self.assertEqual(mr._hardcoded_fallback("generic", "scout"), {"model": None})

    def test_run_by_path_cli_refuses_an_unregistered_host_without_a_traceback(self):
        def run(host):
            out, err = io.StringIO(), io.StringIO()
            with patch.object(sys, "argv", [mr.__file__, host, "scout"]), \
                    patch.dict(os.environ, {"PANOPTICON_MODEL_SCOUT": ""}), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                    self.assertRaises(SystemExit) as stopped:
                runpy.run_path(mr.__file__, run_name="__main__")
            return stopped.exception.code, out.getvalue(), err.getvalue()

        self.assertEqual(
            run("openrouter"),
            (2, "", "model_resolver: %s\n" % self.ERROR))
        self.assertEqual(run("generic"), (0, "{'model': None}\n", ""))

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
