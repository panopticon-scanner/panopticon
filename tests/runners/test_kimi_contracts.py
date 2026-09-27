import dataclasses
import os
import tempfile
import tomllib
import unittest
from unittest import mock

import scripts.hosts as hosts
import scripts.kimi_guard_hook as kimi_guard_hook
import scripts.runners.kimi as kimi_runner
import scripts.runners.kimi_home as kimi_home
from tests._test_helpers import (kimi_fixture_home as _fixture_home,
                           prepared_kimi as _prepared)

from tests.runners.kimi_support import STREAM, _entry

class TestDefaultAgentSurface(unittest.TestCase):
    """I1: `tools.disabled` is what confines an UNENFORCED entry -- the
    setup-scan is always unenforced, so this is the default path of every
    `driver setup`, not a corner. A three-name deny-list left 21 of 24 tools
    live, including an unguarded read tool and two egress tools."""

    def test_the_disabled_set_is_derived_as_the_complement_of_the_templates(self):
        vocabulary = set().union(*kimi_home.TOOL_VOCABULARY.values())
        allowed = kimi_home.allowed_tool_union()
        self.assertEqual(sorted(vocabulary - allowed), kimi_home.disabled_tools())
        self.assertEqual({"Read", "Grep", "Glob", "Write"}, allowed)

    def test_the_egress_persistence_and_unguarded_read_tools_are_closed(self):
        disabled = set(kimi_home.disabled_tools())
        for tool in ("FetchURL", "WebSearch", "CronCreate", "CronDelete",
                     "ReadMediaFile", "Skill", "Agent", "AgentSwarm", "Bash"):
            self.assertIn(tool, disabled)
        for tool in ("Read", "Grep", "Glob", "Write"):
            self.assertNotIn(tool, disabled)

    def test_the_armed_config_disables_everything_no_template_grants(self):
        with tempfile.TemporaryDirectory() as d:
            home = os.path.join(d, "home")
            kimi_home.build_kimi_home(home, os.path.join(d, "s.json"),
                                      os.path.join(d, "a.json"),
                                      real_home=_fixture_home(d))
            with open(os.path.join(home, "config.toml"), "rb") as fh:
                config = tomllib.load(fh)
        vocabulary = set().union(*kimi_home.TOOL_VOCABULARY.values())
        self.assertEqual(vocabulary,
                         set(config["tools"]["disabled"]) | kimi_home.allowed_tool_union())

    def test_the_read_matcher_covers_every_read_tool_the_hook_adjudicates(self):
        for tool in kimi_guard_hook._READ_TOOLS:
            self.assertIn(tool, kimi_home.READ_MATCHER.split("|"))


class TestOperatorConfigShape(unittest.TestCase):
    """M3: `~/.kimi-code/config.toml` is the operator's file, not ours. A shape
    the merge does not expect used to surface as a bare ValueError/TypeError
    from `dict()` -- loud (orchestrate reports it as an error status) but
    reading as a crash rather than as "your config has an unexpected shape"."""

    def _fixture(self, d, body):
        home = os.path.join(d, "real-home")
        os.makedirs(home, exist_ok=True)
        with open(os.path.join(home, "config.toml"), "w", encoding="utf-8") as fh:
            fh.write(body)
        return home

    def _build(self, d, body):
        return kimi_home.build_kimi_home(os.path.join(d, "home"),
                                         os.path.join(d, "s.json"),
                                         os.path.join(d, "a.json"),
                                         real_home=self._fixture(d, body))

    def test_a_tools_array_names_the_file_the_key_and_the_shape(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError) as caught:
                self._build(d, 'tools = ["Read"]\n')
        message = str(caught.exception)
        self.assertIn("config.toml", message)
        self.assertIn("`tools`", message)
        self.assertIn("expected a table", message)
        self.assertIn("list", message)

    def test_a_disabled_string_is_named(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError) as caught:
                self._build(d, '[tools]\ndisabled = "Bash"\n')
        self.assertIn("`tools.disabled`", str(caught.exception))
        self.assertIn("expected an array", str(caught.exception))

    def test_a_disabled_list_holding_non_strings_is_named(self):
        # N5: `_expect` checked that `tools.disabled` was an ARRAY, not what
        # was in it, so `[1, 2]` reached `sorted(set(...) | set(...))` and
        # raised "'<' not supported between instances of 'str' and 'int'" --
        # the unnamed crash M3 exists to remove.
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError) as caught:
                self._build(d, '[tools]\ndisabled = [1, 2]\n')
        message = str(caught.exception)
        self.assertIn("config.toml", message)
        self.assertIn("`tools.disabled`", message)
        self.assertIn("an array of strings", message)
        self.assertIn("int", message)

    def test_a_hooks_table_is_named_rather_than_silently_dropped(self):
        # `[hooks]` instead of `[[hooks]]`: the old filter iterated the dict's
        # KEYS, discarded them all as non-dicts, and armed a config whose
        # operator hooks had vanished without a word.
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError) as caught:
                self._build(d, '[hooks]\nevent = "Stop"\n')
        self.assertIn("`hooks`", str(caught.exception))

    def test_a_hooks_array_holding_non_tables_is_named(self):
        # R2-3: N5's `items=` went to `tools.disabled` and not to its twin.
        # `hooks = [1, 2]` passed the array check and was then silently
        # discarded by `[h for h in ... if isinstance(h, dict)]` -- the
        # operator's own hooks gone without a word, which is the failure M3
        # exists to remove, one level down.
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError) as caught:
                self._build(d, 'hooks = [1, 2]\n')
        message = str(caught.exception)
        self.assertIn("config.toml", message)
        self.assertIn("`hooks`", message)
        self.assertIn("an array of tables", message)
        self.assertIn("int", message)

    def test_a_config_with_the_expected_shapes_still_builds(self):
        with tempfile.TemporaryDirectory() as d:
            home = self._build(d, '[tools]\ndisabled = ["Something"]\n\n'
                                  '[[hooks]]\nevent = "Stop"\ncommand = "true"\n')
            with open(os.path.join(home, "config.toml"), "rb") as fh:
                config = tomllib.load(fh)
        self.assertIn("Something", config["tools"]["disabled"])
        self.assertEqual(3, len(config["hooks"]))


class TestAgentFileChildrenAreBoundGlobally(unittest.TestCase):
    """The PR claimed, unverified, that `tools.disabled` binds an
    `--agent-file=` child as well as the default agent. What can be settled
    without launching the CLI is the half that is ours: the config the runner
    writes puts the deny-list at the TOP level of the per-run home -- not under
    any agent-scoped table -- and that home is the one the enforced child is
    launched with. Whether kimi honours it there is the CLI's half, and stays
    recorded as unverified."""

    def test_an_enforced_launch_points_at_a_home_whose_deny_list_is_global(self):
        seen = {}

        def fake(cmd, **kw):
            seen["cmd"], seen["env"] = cmd, kw["env"]
            class P:
                returncode, stdout, stderr = 0, STREAM, ""
            return P()
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
            row = dataclasses.replace(hosts.HOSTS["kimi"], registration_dir=d)
            with open(os.path.join(d, "panopticon-domain-panel.md"), "w", encoding="utf-8") as fh:
                fh.write("---\nname: panopticon-domain-panel\n---\n")
            with mock.patch.dict(hosts.HOSTS, {"kimi": row}):
                r = kimi_runner.Runner("kimi", runner=fake)
                r.prepare(os.path.join(d, "run"), review_root=d)
                self.addCleanup(r.teardown, "complete")
                res = r.run_entry(_entry(True), {})
            self.assertTrue(res.ok)
            self.assertTrue(any(a.startswith("--agent-file=") for a in seen["cmd"]))
            with open(os.path.join(seen["env"]["KIMI_CODE_HOME"], "config.toml"), "rb") as fh:
                config = tomllib.load(fh)
        self.assertIn("Bash", config["tools"]["disabled"])          # top-level table
        self.assertNotIn("agents", config)                          # no per-agent override


class TestTheEntryAgentIsAllowlistedAndContained(unittest.TestCase):
    """#1720. `entry["agent"]` reaches this runner through
    `.panopticon/dispatch-request.json` -- a file inside the REVIEWED TREE --
    and `_shell_path` joined it into a filesystem path that `--agent-file=`
    then hands the CLI as the reviewer's GOVERNING INSTRUCTIONS. An absolute
    or `../` value loaded an attacker-chosen markdown file; a registered name
    symlinked out of the registration directory did the same thing one step
    later. Two rules, both fail-closed: the name must be one of the four
    registered shells, and the path it resolves to must stay inside the
    registration directory (`runners.schema.published_schema`'s containment rule,
    second application).
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.registration_dir = os.path.join(self.tmp.name, "kimi-agents")
        os.makedirs(self.registration_dir)
        self.launched = []
        self.r = _prepared(self.tmp.name, runner=self._fake())
        self.addCleanup(self.r.teardown, "complete")

    def _fake(self):
        def fake(cmd, **kw):
            self.launched.append(cmd)
            class P:
                returncode = 0
                stdout = STREAM
                stderr = ""
            return P()
        return fake

    def _run(self, agent):
        row = dataclasses.replace(hosts.HOSTS["kimi"],
                                  registration_dir=self.registration_dir)
        with mock.patch.dict(hosts.HOSTS, {"kimi": row}):
            return self.r.run_entry(dict(_entry(True), agent=agent), {})

    def _shell(self, name="panopticon-domain-panel"):
        return os.path.join(self.registration_dir, name + ".md")

    def test_a_traversal_or_foreign_agent_never_reaches_a_launch(self):
        for agent in ("../../tmp/evil", "/tmp/x", "panopticon-domain-panel-evil"):
            res = self._run(agent)
            self.assertFalse(res.ok, agent)
            self.assertIn("not a registered panopticon shell", res.error)
            self.assertIn(repr(agent), res.error)
        self.assertEqual([], self.launched)

    def test_an_enforced_entry_with_no_agent_is_refused_not_downgraded(self):
        res = self._run(None)
        self.assertFalse(res.ok)
        self.assertIn("not a registered panopticon shell", res.error)
        self.assertEqual([], self.launched)

    def test_a_json_array_or_object_agent_is_refused_rather_than_raising(self):
        # Fix round 1, item 1. The request is JSON, so `agent` can be an array
        # or an object -- and the membership test used to raise `TypeError:
        # unhashable type` out of `run_entry`, which never raises (spec 4.4).
        # It is a SECURITY refusal, not a crash.
        for agent in ([], {}, {"a": {"b": "panopticon-domain-panel"}},
                      ["panopticon-domain-panel"]):
            res = self._run(agent)
            self.assertFalse(res.ok, agent)
            self.assertIn("not a registered panopticon shell", res.error)
            self.assertIn(repr(str(agent)), res.error)
        self.assertEqual([], self.launched)

    def test_a_registered_name_whose_shell_escapes_the_directory_is_refused(self):
        outside = os.path.join(self.tmp.name, "planted.md")
        with open(outside, "w", encoding="utf-8") as fh:
            fh.write("# whatever the target wanted the reviewer to be told\n")
        os.symlink(outside, self._shell())
        res = self._run("panopticon-domain-panel")
        self.assertFalse(res.ok)
        self.assertIn("outside", res.error)
        self.assertEqual([], self.launched)

    def test_a_registered_shell_inside_the_directory_still_launches(self):
        with open(self._shell(), "w", encoding="utf-8") as fh:
            fh.write("# the registered shell\n")
        res = self._run("panopticon-domain-panel")
        self.assertTrue(res.ok, res.error)
        self.assertEqual(1, len(self.launched))
        self.assertIn("--agent-file=%s" % os.path.realpath(self._shell()),
                      self.launched[0])


class TestTheRolesTheLoopSetsReachTheKimiCheck(TestTheEntryAgentIsAllowlistedAndContained):
    """#1727, kimi's half: the name is also joined into `--agent-file=`, which
    IS the reviewer's governing instructions -- so a registered shell the
    checkpoint does not dispatch is a charter swap, refused before launch."""

    def test_a_registered_but_misrouted_shell_is_refused(self):
        self.r.roles = ("advisor", "domain_advisor")
        res = self._run("panopticon-domain-panel")
        self.assertFalse(res.ok)
        self.assertIn("not a registered panopticon shell for this checkpoint", res.error)
        self.assertIn("panopticon-advisor", res.error)
        self.assertEqual([], self.launched)

    def test_the_shell_path_refuses_a_misrouted_name_too(self):
        # `_shell_path` is the second application of the same allowlist; it
        # must narrow with the roles or the argv and the check disagree.
        self.r.roles = ("advisor",)
        self.assertIsNone(self.r._shell_path({"agent": "panopticon-domain-panel"}))
