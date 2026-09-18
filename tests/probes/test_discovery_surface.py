"""The `target-discovery-surface` probe (#1657 step 3, spec §8).

Three things are under test here and they fail for different reasons:

* the REGISTRY (`hosts.discovery_surface`) -- the spike's table as landed, its
  shapes, and the link from a CONTROLLED entry to a control that is pinned;
* the CONTROLS' liveness -- each control id asserted against the real runner's
  own `command()` argv (built, never launched) or its mechanism;
* the SCAN -- what a planted file does to the verdict.

No host binary, no docker, no network: every fixture is a temp directory.
"""
import unittest

from scripts import hosts


# The §3 table, as the spec writes it. Pinned VERBATIM rather than derived:
# "the table is the spec", and a table that can drift from the document it
# copies is a table nobody can read the document against. A row here moves
# only with the spec it came from.
_TABLE = (
    ("claude", ("CLAUDE.md", "**/CLAUDE.md"), hosts.OPEN, None, "CL-1"),
    ("claude", (".claude/settings.json", ".claude/settings.local.json"),
     hosts.CONTROLLED, "claude:setting-sources-user", "CL-2/CL-4"),
    ("claude", (".mcp.json",), hosts.CONTROLLED, "claude:strict-mcp-config", "CL-3"),
    ("claude", (".claude/agents/*",), hosts.OPEN, None, "CL-5"),
    ("claude", (".claude/skills/*/SKILL.md", ".claude/commands/**"),
     hosts.CONTROLLED, "claude:disable-slash-commands", "CL-6/CL-7"),
    ("claude", (".claude/hooks/**", ".claude/workflows/**", ".claude/plugins/**"),
     hosts.OPEN, None, "CL-8"),
    ("codex", ("AGENTS.md", "**/AGENTS.md"), hosts.CONTROLLED,
     "codex:cwd-outside-target", "CX-1"),
    ("codex", (".codex/skills/*/SKILL.md", ".agents/skills/*/SKILL.md"),
     hosts.CONTROLLED, "codex:cwd-outside-target", "CX-2/CX-3"),
    ("codex", (".codex/agents/*", ".agents/agents/*"), hosts.OPEN, None, "CX-6"),
    ("codex", (".codex/config.toml", ".rules"), hosts.CONTROLLED,
     "codex:ignore-user-config-and-rules", "CX-4/CX-5"),
    ("kimi", (".mcp.json", ".kimi-code/mcp.json"), hosts.CONTROLLED,
     "kimi:workspace-trust-gate", "KM-4"),
    ("kimi", ("AGENTS.md", "agents.md", "**/AGENTS.md", "**/.kimi-code/AGENTS.md"),
     hosts.OPEN, None, "KM-3"),
    ("kimi", (".kimi-code/skills/*/SKILL.md", ".agents/skills/*/SKILL.md"),
     hosts.CONTROLLED, "kimi:skills-dir", "KM-1"),
    ("kimi", (".kimi-code/agents/*", ".agents/agents/*"), hosts.OPEN, None, "KM-2"),
)


class TestTheRegistryTable(unittest.TestCase):
    """§3/§4: the registry owns the table; the probe owns no host knowledge."""

    def test_the_landed_table_is_the_spec_table(self):
        landed = tuple((name, tuple(e.pattern), e.kind, e.control, e.cell)
                       for name in hosts.known_hosts()
                       for e in hosts.spec(name).discovery_surface)
        self.assertEqual(_TABLE, landed)

    def test_every_entry_is_open_or_controlled_with_a_matching_control(self):
        # §4: a CONTROLLED entry names a control; an OPEN one names none. An
        # entry that got these the wrong way round would either disclose a
        # surface nothing closes or refuse on one that is closed.
        for name in hosts.known_hosts():
            for entry in hosts.spec(name).discovery_surface:
                with self.subTest(host=name, cell=entry.cell):
                    self.assertIn(entry.kind, (hosts.OPEN, hosts.CONTROLLED))
                    if entry.kind == hosts.OPEN:
                        self.assertIsNone(entry.control)
                    else:
                        self.assertTrue(entry.control)

    def test_every_cell_id_is_unique_per_host(self):
        for name in hosts.known_hosts():
            cells = [e.cell for e in hosts.spec(name).discovery_surface]
            with self.subTest(host=name):
                self.assertEqual(sorted(set(cells)), sorted(cells))

    def test_every_pattern_is_a_shape_the_scan_supports(self):
        # R2: a plain path is one `stat`, a `*` segment is one `listdir` on its
        # parent, and `**` -- at the head or at the tail, never in the middle
        # and never twice -- is the bounded walk. Nothing else is supported, so
        # a table entry using another shape must fail HERE rather than resolve
        # to nothing at 3am on a hostile target.
        for name in hosts.known_hosts():
            for entry in hosts.spec(name).discovery_surface:
                self.assertIsInstance(entry.pattern, tuple)
                self.assertTrue(entry.pattern)
                for pattern in entry.pattern:
                    with self.subTest(host=name, pattern=pattern):
                        self.assertTrue(hosts.supported_surface_pattern(pattern))

    def test_an_unsupported_pattern_shape_is_rejected(self):
        # The guard above is only worth having if it says no to something.
        for pattern in ("", "/etc/passwd", "../outside", "a/**/b", "**/a/**",
                        "pre*fix.md", "a/**b", "."):
            with self.subTest(pattern=pattern):
                self.assertFalse(hosts.supported_surface_pattern(pattern))

    def test_a_host_without_a_surface_has_an_empty_tuple(self):
        # generic and gemini discover nothing FOR US: no runner of ours
        # launches them at the target, so the probe is a no-op rather than a
        # row with an empty table to interpret.
        for name in ("generic", "gemini"):
            self.assertEqual((), hosts.spec(name).discovery_surface)
