import contextlib
import datetime
import io
import os
import tempfile
import tomllib
import unittest

import scripts.kimi_toml as kimi_toml
import scripts.runners.kimi_home as kimi_home
from tests._test_helpers import (kimi_fixture_home as _fixture_home)


class TestTomlEmission(unittest.TestCase):
    def test_unicode_and_literal_keys_round_trip(self):
        config = {
            "模型.名": {"路径/🚀": {"quoted \"key\"": "emoji 😀 /tmp/雪\tline\nnext\x7f\x00"}},
            "hooks": [{"event": "PreToolUse", "name.with.dot": "值"},
                      {"event": "Stop", "空 表": {}}],
            "nested": ["非拉丁", ["🚀", "\x00\x7f"]],
        }
        self.assertEqual(config, tomllib.loads(kimi_toml.dump_toml(config)))

    def test_lone_surrogates_are_refused(self):
        for config in ({"value": "bad \ud800"}, {"bad \ud800": "value"}):
            with self.subTest(config=config), self.assertRaisesRegex(ValueError, "surrogate"):
                kimi_toml.dump_toml(config)

    def test_dump_toml_round_trips_nested_tables_and_arrays(self):
        config = {"top": "value", "n": 3, "f": 1.5, "flag": True,
                  "arr": ["a", "b"],
                  "providers": {"managed:kimi-code": {"type": "kimi", "api_key": "",
                                                      "oauth": {"storage": "file"}}},
                  "hooks": [{"event": "PreToolUse", "matcher": "Read", "timeout": 30}]}
        back = tomllib.loads(kimi_toml.dump_toml(config))
        self.assertEqual(back, config)

    def test_keys_that_are_not_bare_are_quoted(self):
        back = tomllib.loads(kimi_toml.dump_toml({"models": {"kimi-code/k3": {"model": "k3"}}}))
        self.assertEqual(back["models"]["kimi-code/k3"]["model"], "k3")


class TestTomlEmissionRoundTrips(unittest.TestCase):
    """C2: the armed `config.toml` is the ONLY place Kimi's confinement lives,
    and this writer produces it from whatever the operator's own config holds.
    A shape it cannot emit is not a cosmetic bug: a config Kimi will not load
    is a run with the two `[[hooks]]` entries missing."""

    def test_a_nested_array_of_tables_round_trips(self):
        # `[[mcp.servers]]` is the standard MCP shape. The old writer emitted
        # the PARENT's path -- `[[mcp]]` -- which tomllib refuses with
        # "Cannot overwrite a value".
        config = {"mcp": {"servers": [{"name": "s1", "command": "a"},
                                      {"name": "s2", "command": "b"}]}}
        self.assertEqual(config, tomllib.loads(kimi_toml.dump_toml(config)))

    def test_a_scalar_after_an_array_of_tables_stays_in_its_own_table(self):
        # The old writer emitted array-of-tables headers from INSIDE the scalar
        # loop, so `y` was swallowed into the last `[[...]]`.
        config = {"a": {"list": [{"x": 1}], "y": 2}}
        self.assertEqual(config, tomllib.loads(kimi_toml.dump_toml(config)))

    def test_datetimes_dates_and_times_round_trip(self):
        config = {"last_update_check": datetime.datetime(2026, 9, 13, 12, 30, 5,
                                                         tzinfo=datetime.timezone.utc),
                  "naive": datetime.datetime(2026, 9, 13, 12, 30, 5),
                  "day": datetime.date(2026, 9, 13),
                  "clock": datetime.time(7, 5, 1)}
        self.assertEqual(config, tomllib.loads(kimi_toml.dump_toml(config)))

    def test_tables_three_deep_round_trip(self):
        config = {"providers": {"managed:kimi-code": {"oauth": {"storage": "file",
                                                                "key": "x"},
                                                      "api_key": "k"}},
                  "top": 1}
        self.assertEqual(config, tomllib.loads(kimi_toml.dump_toml(config)))

    def test_a_none_value_names_the_key_it_came_from(self):
        with self.assertRaises(TypeError) as caught:
            kimi_toml.dump_toml({"tools": {"disabled": None}})
        self.assertIn("disabled", str(caught.exception))

    def test_the_real_merged_config_drops_the_operators_mcp_servers(self):
        # #1640 (run-13 AGT-3297306866). This used to assert the OPPOSITE --
        # that two `[[mcp.servers]]` and `enabled = true` round-tripped into
        # the armed home -- which was true and was the defect: the per-run
        # home's confinement is `tools.disabled` plus two PreToolUse hooks,
        # and both adjudicate the CLI's own tool names. An MCP server's tools
        # are supplied at runtime by another process, under names neither has
        # heard, reaching the filesystem and the network through that process.
        # The writer's ability to emit the nested shape is still covered, by
        # `test_a_nested_array_of_tables_round_trips` above.
        with tempfile.TemporaryDirectory() as d:
            fixture = _fixture_home(d)
            with open(os.path.join(fixture, "config.toml"), "a", encoding="utf-8") as fh:
                fh.write('\n[[mcp.servers]]\nname = "s1"\n\n[[mcp.servers]]\nname = "s2"\n'
                         '\n[mcp]\nenabled = true\n')
            home = os.path.join(d, "home")
            with contextlib.redirect_stderr(io.StringIO()) as err:
                kimi_home.build_kimi_home(home, os.path.join(d, "s.json"),
                                          os.path.join(d, "a.json"), real_home=fixture)
            with open(os.path.join(home, "config.toml"), "rb") as fh:
                armed = tomllib.load(fh)
        self.assertEqual([], armed["mcp"]["servers"])
        self.assertFalse(armed["mcp"]["enabled"])
        self.assertEqual(2, len(armed["hooks"]))
        # The disclosure is a COUNT on one line, never a list: it shares the
        # operator's stderr with the run's own progress output, and a line
        # that grows with the operator's config would crowd it out.
        self.assertIn("2 operator MCP servers disabled in the per-run home",
                      err.getvalue())
        self.assertNotIn("s1", err.getvalue())

    def test_an_operator_config_with_no_mcp_block_discloses_nothing(self):
        # Nothing was dropped, so there is nothing to say; a line printed on
        # every run teaches the operator to skip the ones that matter.
        with tempfile.TemporaryDirectory() as d:
            home = os.path.join(d, "home")
            with contextlib.redirect_stderr(io.StringIO()) as err:
                kimi_home.build_kimi_home(home, os.path.join(d, "s.json"),
                                          os.path.join(d, "a.json"),
                                          real_home=_fixture_home(d))
            with open(os.path.join(home, "config.toml"), "rb") as fh:
                armed = tomllib.load(fh)
        self.assertEqual("", err.getvalue())
        self.assertEqual({"enabled": False, "servers": []}, armed["mcp"])

    def test_every_shape_it_scrubs_is_disclosed_exactly_once(self):
        # Fix round 1, F4. `dropped` counted only a real list, and the line
        # printed only when that count was truthy -- so a scalar `mcp`, a
        # hostile `servers`, and an `enabled = true` with no servers listed
        # were all replaced in TOTAL SILENCE. Those are the shapes an operator
        # is least likely to notice, and their MCP configuration is being
        # removed. One line each, naming the shape and the count; never two,
        # never none.
        shapes = (
            ({"enabled": True, "servers": [{"name": "s1"}, {"name": "s2"}]},
             "2 operator MCP servers disabled in the per-run home"),
            ({"enabled": True, "servers": [{"name": "s1"}]},
             "1 operator MCP server disabled in the per-run home"),
            ({"enabled": True, "servers": []},
             "`mcp.enabled` was set with no servers listed"),
            ({"enabled": True}, "`mcp.enabled` was set with no servers listed"),
            ({"enabled": False, "servers": "hostile"},
             "`mcp.servers` was a str, not an array"),
            ({"servers": {"a": 1}}, "`mcp.servers` was a dict, not an array"),
            ("whatever the operator put here", "`mcp` was a str, not a table"),
            ([1, 2, 3], "`mcp` was a list, not a table"),
        )
        for block, phrase in shapes:
            with self.subTest(block=repr(block)[:40]):
                stream = io.StringIO()
                self.assertEqual({"enabled": False, "servers": []},
                                 kimi_toml.mediated_mcp({"mcp": block}, disclose=stream))
                lines = stream.getvalue().splitlines()
                self.assertEqual(1, len(lines), lines)
                self.assertIn(phrase, lines[0])
                self.assertTrue(lines[0].startswith("driver loop: "), lines[0])
                self.assertNotIn("s1", lines[0])

    def test_nothing_to_scrub_says_nothing(self):
        # Two no-ops, and both must stay silent: an operator with no `[mcp]`
        # at all, and one whose block is already exactly what the per-run home
        # writes. A line on every run teaches its reader to skip the ones that
        # matter.
        for source in ({}, {"mcp": {"enabled": False, "servers": []}}):
            with self.subTest(source=source):
                stream = io.StringIO()
                kimi_toml.mediated_mcp(source, disclose=stream)
                self.assertEqual("", stream.getvalue())

    def test_the_inert_block_is_a_value_no_importer_can_move(self):
        # Every armed config gets its OWN dict and its OWN list: one config
        # mutating the block it was handed must not reach the next.
        #
        # Fix round 2 (N3): this used to be a module-level dict, and the guard
        # probes compare the armed file against it. A shared mutable bar is
        # one any importer could move for the rest of the process without
        # touching the probe or the runner -- so it is a function now. A
        # MappingProxyType would not have been enough: the `servers` list
        # inside it stays mutable, which is the same hazard one level down,
        # and it is exactly the key a planted server would go into.
        first, second = kimi_toml.inert_mcp(), kimi_toml.inert_mcp()
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["servers"], second["servers"])
        first["enabled"] = True
        first["servers"].append("planted")
        first["extra"] = "planted"
        self.assertEqual({"enabled": False, "servers": []}, kimi_toml.inert_mcp())
        self.assertEqual(kimi_toml.inert_mcp(), kimi_toml.mediated_mcp())
        self.assertIsNot(kimi_toml.mediated_mcp()["servers"],
                         kimi_toml.mediated_mcp()["servers"])

    def test_the_block_is_constructed_not_filtered(self):
        # Whatever the operator's `[mcp]` holds -- a scalar, a table this
        # writer could not emit, a per-server `enabled` flag -- the armed home
        # carries the same two keys. Preferring the block-level switch over a
        # per-server one is deliberate: it is one fact, and the probes refute
        # it by reading two keys rather than walking a list.
        merged = kimi_home.build_merged_config(
            {"mcp": "whatever the operator put here"}, "s.json", "a.json")
        self.assertEqual({"enabled": False, "servers": []}, merged["mcp"])
