import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

import scripts.runners.base as base
import scripts.runners.schema as schema_rules
import scripts._version as version


def _published():
    """One of the schemas panopticon publishes under skill/reference/."""
    return os.path.abspath(version.reference_path("advisor-verdict-schema.json"))


class TestTheOutputSchemaSeam(unittest.TestCase):
    """D10 ruling 3: ONE optional class attribute (docs/FAMILY-PR-GUARDRAILS.md
    section 3). A family whose CLI takes a constrained-output schema names its
    flag; a family that leaves it empty is unaffected."""

    def test_the_contract_declares_it_empty(self):
        self.assertEqual((), base.HostRunner.OUTPUT_SCHEMA_FLAG)

        class Bare(base.HostRunner):
            host = "bare"
        self.assertEqual((), Bare().OUTPUT_SCHEMA_FLAG)
        self.assertEqual([], schema_rules.schema_argv(Bare().OUTPUT_SCHEMA_FLAG,
                                              {"output_schema": _published()}))

    def test_a_declared_flag_takes_the_entrys_published_schema(self):
        self.assertEqual(["--x", _published()],
                         schema_rules.schema_argv(("--x",), {"output_schema": _published()}))

    def test_an_entry_naming_no_schema_gets_no_flag(self):
        for entry in ({}, {"output_schema": None}, {"output_schema": ""}, None):
            with self.subTest(entry=entry):
                self.assertEqual([], schema_rules.schema_argv(("--x",), entry))

    def test_a_path_outside_the_published_reference_dir_is_refused(self):
        # The entry travels through `.panopticon/dispatch-request.json`, inside
        # the reviewed tree. Nothing else on the argv is a path the target
        # could have named, and this one must not become the exception: only
        # the schemas panopticon publishes are ever passed to a host CLI.
        for path in ("/etc/passwd", os.path.join(os.path.dirname(_published()), "nope.json"),
                     os.path.join(os.path.dirname(_published()), os.pardir, "SKILL.md")):
            with self.subTest(path=path):
                self.assertEqual([], schema_rules.schema_argv(("--x",), {"output_schema": path}))

    def test_inline_hands_the_cli_the_schema_text_not_its_path(self):
        # MEASURED 2026-09-20 on claude 2.1.276: `--json-schema <schema>` takes
        # the JSON itself ("--json-schema is not valid JSON: JSON Parse error:
        # Unrecognized token '/'" on a path), while codex's `--output-schema
        # <FILE>` takes a path. Run 14 burned 3 x 103 tool-verify launches on
        # the path form before the driver gave up.
        argv = schema_rules.schema_argv(("--x",), {"output_schema": _published()}, inline=True)
        self.assertEqual("--x", argv[0])
        self.assertEqual(2, len(argv))
        self.assertNotEqual(_published(), argv[1])
        with open(_published(), encoding="utf-8") as fh:
            self.assertEqual(json.load(fh), json.loads(argv[1]))
        self.assertNotIn("\n", argv[1])

    def test_inline_still_refuses_an_unpublished_path(self):
        self.assertEqual([], schema_rules.schema_argv(("--x",), {"output_schema": "/etc/passwd"},
                                              inline=True))

    def test_inline_schema_applies_the_containment_rule_itself(self):
        # Not only via schema_argv: a helper that opened whatever it was handed
        # would turn the one target-chosen argv value into an arbitrary-file
        # read that reaches the CLI (review round 1, item 1).
        self.assertIsNone(schema_rules.inline_schema("/etc/passwd"))
        self.assertIsNone(schema_rules.inline_schema(None))
        self.assertIsNotNone(schema_rules.inline_schema(_published()))

    def test_inline_refuses_a_published_file_too_large_for_one_argv_token(self):
        # skill/reference/ also publishes ocrdb-0.5.0.json (176 KB compacted),
        # over Linux MAX_ARG_STRLEN: execve would answer E2BIG and the runner
        # would burn three launches per entry -- the run-14 failure mode by a
        # second road (review round 1, item 2).
        self.assertLess(0, schema_rules.INLINE_SCHEMA_MAX)
        tmp = tempfile.mkdtemp()
        try:
            big = os.path.join(tmp, "big-schema.json")
            with open(big, "w", encoding="utf-8") as fh:
                json.dump({"type": "object", "pad": "x" * (schema_rules.INLINE_SCHEMA_MAX + 1)}, fh)
            with mock.patch.object(schema_rules.version, "reference_path", return_value=tmp):
                self.assertIsNone(schema_rules.inline_schema(big))
                self.assertEqual([], schema_rules.schema_argv(("--x",), {"output_schema": big},
                                                      inline=True))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        published = os.path.join(os.path.dirname(_published()), "ocrdb-0.5.0.json")
        if os.path.isfile(published):
            self.assertIsNone(schema_rules.inline_schema(published))

    def test_inline_treats_an_unparsable_published_file_as_no_schema(self):
        # The persist layer validates the reply against the schema either way;
        # a launch without the flag is the fail-safe, a launch the CLI refuses
        # is three burned attempts per entry.
        tmp = tempfile.mkdtemp()
        try:
            bad = os.path.join(tmp, "broken-schema.json")
            with open(bad, "w", encoding="utf-8") as fh:
                fh.write("{not json")
            with mock.patch.object(schema_rules.version, "reference_path", return_value=tmp):
                self.assertEqual([], schema_rules.schema_argv(("--x",), {"output_schema": bad},
                                                      inline=True))
                # The path form is untouched: it hands over the (resolved)
                # file and lets the CLI be the one to choke on it.
                self.assertEqual(["--x", os.path.realpath(bad)],
                                 schema_rules.schema_argv(("--x",), {"output_schema": bad}))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestTheRegisteredAgentAllowlist(unittest.TestCase):
    """#1720: `entry["agent"]` arrives through
    `.panopticon/dispatch-request.json`, a file inside the REVIEWED TREE, and
    every family puts it on a launch's argv (kimi joins it into a filesystem
    path). The allowlist is the same containment idea `schema.published_schema`
    applies to the one other entry-derived argv value -- and it is DERIVED
    from `dispatch.ROLE_FILES`, so a role added or renamed there cannot leave
    a second, stale spelling here.
    """

    def test_the_allowlist_is_exactly_the_four_dispatch_role_shells(self):
        import scripts.dispatch as dispatch
        self.assertEqual(
            base.REGISTERED_AGENT_NAMES,
            frozenset(dispatch.registered_agent_name(role_file)
                      for role_file in dispatch.ROLE_FILES.values()))
        self.assertIn("panopticon-scout", base.REGISTERED_AGENT_NAMES)

    def test_registered_agent_answers_the_name_or_none(self):
        self.assertEqual("panopticon-scout",
                         base.registered_agent({"agent": "panopticon-scout"}))
        for value in ("panopticon-scout-evil", "../../tmp/evil", "/tmp/x", "", None, 7):
            self.assertIsNone(base.registered_agent({"agent": value}), value)
        self.assertIsNone(base.registered_agent({}))
        self.assertIsNone(base.registered_agent(None))

    def test_an_unhashable_agent_is_answered_none_and_never_raises(self):
        # Fix round 1, item 1. The request is JSON from inside the reviewed
        # tree, so `agent` can perfectly well be an array or an object --
        # and `value in <frozenset>` on one raises `TypeError: unhashable
        # type`, straight out of `run_entry`, which never raises (spec 4.4).
        # A type check that only a str reaches, before the membership test.
        for value in ([], {}, {"a": {"b": "panopticon-scout"}},
                      ["panopticon-scout"], set()):
            self.assertIsNone(base.registered_agent({"agent": value}), repr(value))

    def test_the_refusal_names_the_value_and_never_downgrades(self):
        result = base.refuse_unregistered_agent({"id": "review-app-SEC",
                                                 "agent": "../../tmp/evil"})
        self.assertFalse(result.ok)
        self.assertEqual("review-app-SEC", result.entry_id)
        self.assertIn("not a registered panopticon shell", result.error)
        self.assertIn(repr("../../tmp/evil"), result.error)

    def test_the_refusal_neutralises_a_value_that_is_trying_to_write_the_log(self):
        # Fix round 1, item 6: the value is the TARGET's, and it lands in the
        # operator's stderr and in the ledger row. `%r` renders a control
        # character, an ANSI escape or a newline as its escape sequence, so a
        # value cannot forge a second log line or repaint the terminal.
        result = base.refuse_unregistered_agent(
            {"id": "e", "agent": "panopticon-scout\x1b[2J\ndriver loop: all good"})
        self.assertNotIn("\x1b", result.error)
        self.assertNotIn("\n", result.error)
        self.assertIn("\\x1b", result.error)

    def test_the_refusal_still_truncates_and_redacts(self):
        long_value = "a" * 500
        result = base.refuse_unregistered_agent({"id": "e", "agent": long_value})
        self.assertIn(repr("a" * 200), result.error)
        self.assertNotIn("a" * 201, result.error)

    def test_refusal_redacts_tokens_before_taking_the_diagnostic_excerpt(self):
        token = "ghp_" + "A1b2" * 9
        for offset in (0, 150, 185, 197, 205):
            for roles in (None, ["scout"]):
                with self.subTest(offset=offset, roles=roles):
                    prefix = "x" * offset + " "
                    result = base.refuse_unregistered_agent(
                        {"id": "e", "agent": prefix + token + " suffix"}, roles=roles)
                    self.assertFalse(result.ok)
                    self.assertEqual(result.entry_id, "e")
                    self.assertNotIn(token, result.error)
                    self.assertNotIn("ghp", result.error)
                    self.assertNotIn("A1b2", result.error)
                    expected = (prefix + "[REDACTED_TOKEN] suffix")[:200]
                    self.assertIn(repr(expected), result.error)


class TestTheAgentIsBoundToItsCheckpointsRole(unittest.TestCase):
    """#1727: the allowlist alone lets any of the four shells stand in for any
    other -- a `verify` entry naming `panopticon-domain-panel` is a registered
    shell, so it launched, under a WRITE-granting charter the verify round
    never dispatches. The loop hands the runner the roles its checkpoint
    dispatches, and the same check narrows to them."""

    def test_roles_none_is_the_whole_allowlist(self):
        self.assertEqual("panopticon-scout",
                         base.registered_agent({"agent": "panopticon-scout"}, roles=None))
        self.assertEqual("panopticon-domain-panel",
                         base.registered_agent({"agent": "panopticon-domain-panel"}))

    def test_roles_narrows_to_exactly_those_shells(self):
        entry = {"agent": "panopticon-advisor"}
        self.assertEqual("panopticon-advisor",
                         base.registered_agent(entry, roles=("advisor",)))
        self.assertEqual("panopticon-advisor",
                         base.registered_agent(entry, roles=("advisor", "domain_advisor")))
        for roles in (("scout",), ("domain_panel",), ("domain_advisor",)):
            self.assertIsNone(base.registered_agent(entry, roles=roles), roles)

    def test_an_empty_role_tuple_accepts_nothing(self):
        # The `scan` checkpoint: its one entry is dispatched shell-less by
        # design, so NO name is right for it -- and an empty tuple must not
        # read as "unconstrained".
        for name in ("panopticon-scout", "panopticon-advisor",
                     "panopticon-domain-panel", "panopticon-domain-advisor"):
            self.assertIsNone(base.registered_agent({"agent": name}, roles=()), name)

    def test_an_unknown_role_key_narrows_rather_than_widens(self):
        self.assertIsNone(base.registered_agent({"agent": "panopticon-scout"},
                                                roles=("not_a_role",)))

    def test_the_refusal_names_the_shells_this_checkpoint_allows(self):
        result = base.refuse_unregistered_agent(
            {"id": "verify-app-SEC-primary", "agent": "panopticon-domain-panel"},
            roles=("advisor", "domain_advisor"))
        self.assertFalse(result.ok)
        self.assertEqual("verify-app-SEC-primary", result.entry_id)
        self.assertIn("not a registered panopticon shell for this checkpoint",
                      result.error)
        self.assertIn("allowed: panopticon-advisor, panopticon-domain-advisor",
                      result.error)
        self.assertIn(repr("panopticon-domain-panel"), result.error)

    def test_the_refusal_without_roles_is_word_for_word_what_it_was(self):
        for kwargs in ({}, {"roles": None}):
            result = base.refuse_unregistered_agent({"id": "e", "agent": "x"}, **kwargs)
            self.assertEqual(base.UNREGISTERED_AGENT % "x", result.error)

    def test_the_refusal_still_neutralises_a_hostile_value_with_roles_given(self):
        result = base.refuse_unregistered_agent(
            {"id": "e", "agent": "panopticon-scout\x1b[2J\ndriver loop: all good"},
            roles=("advisor",))
        self.assertNotIn("\x1b", result.error)
        self.assertNotIn("\n", result.error)

    def test_a_runner_carries_no_roles_until_the_loop_says_so(self):
        self.assertIsNone(base.HostRunner("claude").roles)
