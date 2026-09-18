"""The `target-discovery-surface` probe (#1657 step 3, spec §8).

Three things are under test here and they fail for different reasons:

* the REGISTRY (`hosts.discovery_surface`) -- the spike's table as landed, its
  shapes, and the link from a CONTROLLED entry to a control that is pinned;
* the CONTROLS' liveness -- each control id asserted against the real runner's
  own `command()` argv (built, never launched) or its mechanism;
* the SCAN -- what a planted file does to the verdict.

No host binary, no docker, no network: every fixture is a temp directory.
"""
import json
import os
import tempfile
from types import SimpleNamespace
import unittest

from scripts import hosts
import scripts.probes.common as probes_common


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


class TestTheControlsAreLive(unittest.TestCase):
    """§4: every CONTROLLED entry rests on a control, and every control is
    asserted against the thing that really closes the surface -- the runner's
    own `command()` argv, or the mechanism named in `CONTROLS`.

    Built, never launched: a control that stopped being passed must fail HERE,
    because the registry would otherwise go on calling its surface closed.
    """

    # Which control each check below covers. Hand-listed so a control added to
    # `CONTROLS` without a pin fails this module rather than being taken on
    # trust -- the exact drift §4 exists to prevent.
    _PINNED = {"claude:setting-sources-user", "claude:strict-mcp-config",
               "claude:disable-slash-commands", "codex:cwd-outside-target",
               "codex:ignore-user-config-and-rules", "kimi:workspace-trust-gate",
               "kimi:skills-dir"}

    def test_every_controlled_entry_names_a_control_that_is_pinned(self):
        for name in hosts.known_hosts():
            for entry in hosts.spec(name).discovery_surface:
                if entry.kind != hosts.CONTROLLED:
                    continue
                with self.subTest(host=name, cell=entry.cell):
                    self.assertIn(entry.control, probes_common.CONTROLS)
                    self.assertEqual(
                        name, probes_common.CONTROLS[entry.control].host,
                        "a row may only name a control of its OWN host")

    def test_every_control_has_a_liveness_check_here(self):
        self.assertEqual(self._PINNED, set(probes_common.CONTROLS))

    def test_the_claude_controls_are_on_every_claude_launch(self):
        import scripts.runners.claude as claude_runner
        entry = {"id": "review-app-SEC", "agent": "panopticon-domain-panel",
                 "enforced": True, "model": None, "prompt": "review"}
        argv = claude_runner.Runner("claude").command(
            entry, "/run/host-settings.json", max_turns=40)
        for control in ("claude:setting-sources-user", "claude:strict-mcp-config",
                        "claude:disable-slash-commands"):
            with self.subTest(control=control):
                self.assertTrue(probes_common.control_is_on(control, argv),
                                "%s: %s" % (control, argv))

    def test_the_kimi_skills_dir_control_is_on_every_kimi_launch(self):
        # Unprepared on purpose: `command()` is the builder under test, and a
        # prepared Runner would mkdtemp a per-run home and wrap SIGTERM for a
        # question about one argv token.
        import scripts.runners.kimi as kimi_runner
        runner = kimi_runner.Runner("kimi")
        runner.skills_dir = "/run/kimi-home/no-skills"
        argv = runner.command({"id": "e", "agent": "panopticon-domain-panel",
                               "enforced": True, "prompt": "review"}, "k3")
        self.assertTrue(probes_common.control_is_on("kimi:skills-dir", argv), argv)

    def test_the_kimi_workspace_trust_gate_is_pinned_to_the_per_run_home(self):
        # The MEASURED neutraliser of a target-planted `.mcp.json` /
        # `.kimi-code/mcp.json` (KM-4): the per-run home links ONLY the
        # credential stores, so it carries no `workspace-trust` record and
        # `loadMcpServersDetailed` never reads the project files.
        # tests/runners/test_kimi_surface.py holds the full pins; this is the
        # registry's end of the same wire.
        import scripts.runners.kimi_home as kimi_home
        self.assertEqual(("credentials", "oauth"), kimi_home._CREDENTIAL_ITEMS)

    def test_the_codex_controls_are_on_the_codex_launch(self):
        import scripts.codex_host as codex_host
        with tempfile.TemporaryDirectory() as target:
            root = os.path.realpath(target)
            entry = {"id": "setup-scan", "agent": None, "model": "gpt-test",
                     "prompt": "not on argv"}
            env = {"PATH": "/inherited/bin",
                   "PANOPTICON_ENTRY_ID": entry["id"],
                   "PANOPTICON_WRITE_ALLOWLIST": os.path.join(root, "write.json"),
                   "PANOPTICON_READ_SCOPE": os.path.join(root, "scope.json")}

            def _catalog(argv, **kwargs):
                return SimpleNamespace(returncode=0, stderr="", stdout=json.dumps(
                    {"models": [{"slug": "gpt-test", "base_instructions": "x",
                                 "apply_patch_tool_type": "freeform",
                                 "multi_agent_version": "v1",
                                 "tool_mode": "code_mode_only",
                                 "context_window": 123456}]}))

            argv = codex_host.command(entry, env, root, os.path.join(root, "run"),
                                      runner=_catalog)
            try:
                self.assertTrue(probes_common.control_is_on(
                    "codex:ignore-user-config-and-rules", argv), argv)
                # CX-1..CX-3's control is not a flag: it is WHERE the child
                # runs. `launch_cwd` is the one answer both `--cd` and the
                # process cwd take, so a scratch under the review root would
                # put the target's AGENTS.md and skills back in play.
                cwd = codex_host.launch_cwd(argv)
                self.assertFalse(
                    os.path.realpath(cwd).startswith(root + os.sep),
                    "codex:cwd-outside-target: %s is under %s" % (cwd, root))
            finally:
                codex_host.cleanup_command(argv)
