"""The `target-discovery-surface` probe (#1657 step 3, spec §8).

Three things are under test here and they fail for different reasons:

* the REGISTRY (`hosts.discovery_surface`) -- the spike's table as landed, its
  shapes, and the link from a CONTROLLED entry to a control that is pinned;
* the CONTROLS' liveness -- each control id asserted against the real runner's
  own `command()` argv (built, never launched) or its mechanism;
* the SCAN -- what a planted file does to the verdict.

No host binary, no docker, no network: every fixture is a temp directory.
"""
import io
import json
import os
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

from scripts import hosts
import scripts.probes.common as probes_common
import scripts.probes.surface as probes_surface
from tests.probes.helpers import _shell


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


def _plant(root, relative, body="x"):
    path = os.path.join(root, *relative.split("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)
    return path


# One OPEN and one CONTROLLED file per host with a surface, with the cell and
# control each must be reported under. Per host rather than claude-only: the
# probe is registry-driven, and a host whose rows were never exercised is a
# host whose table nobody has read.
_PLANTED = (
    ("claude", "CLAUDE.md", "CL-1",
     ".claude/settings.json", "claude:setting-sources-user"),
    ("codex", ".codex/agents/theirs.toml", "CX-6",
     ".rules", "codex:ignore-user-config-and-rules"),
    ("kimi", "AGENTS.md", "KM-3",
     ".kimi-code/mcp.json", "kimi:workspace-trust-gate"),
)


class TestTheScan(unittest.TestCase):
    """§5: what the reviewed tree ships, and what that does to the verdict."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def test_a_clean_tree_is_unknown_and_says_how_much_it_looked_at(self):
        # Like the shadow scan, this probe can only REFUTE: finding nothing
        # proves no capability. The pattern COUNT is the honest part -- "we
        # looked at n things and they were not there".
        state, by, detail = probes_common.probe_discovery_surface("claude", self.root)
        self.assertEqual(hosts.UNKNOWN, state)
        self.assertEqual("target-discovery-surface", by)
        self.assertIn("no target-authored discovery files in", detail)

    def test_a_host_with_no_surface_is_a_no_op(self):
        state, by, detail = probes_common.probe_discovery_surface("generic", self.root)
        self.assertEqual(hosts.UNKNOWN, state)
        self.assertEqual("target-discovery-surface", by)
        self.assertIn("discovers no target-authored configuration", detail)

    def test_an_unregistered_host_name_is_unknown_not_a_crash(self):
        state, _by, detail = probes_common.probe_discovery_surface("no-such", self.root)
        self.assertEqual(hosts.UNKNOWN, state)
        self.assertIn("no-such", detail)

    def test_one_open_file_refutes_and_names_its_cell(self):
        for host, open_file, cell, _controlled, _control in _PLANTED:
            with self.subTest(host=host), tempfile.TemporaryDirectory() as root:
                _plant(root, open_file)
                state, by, detail = probes_common.probe_discovery_surface(host, root)
                self.assertEqual(hosts.REFUTED, state)
                self.assertEqual("target-discovery-surface", by)
                self.assertIn(open_file, detail)
                self.assertIn(cell, detail)
                self.assertIn("no launch control closes it", detail)

    def test_one_controlled_file_is_disclosed_not_refuted(self):
        for host, _open_file, _cell, controlled, control in _PLANTED:
            with self.subTest(host=host), tempfile.TemporaryDirectory() as root:
                _plant(root, controlled)
                state, _by, detail = probes_common.probe_discovery_surface(host, root)
                self.assertEqual(hosts.UNKNOWN, state)
                self.assertIn(controlled, detail)
                self.assertIn("closed by %s" % control, detail)

    def test_both_refuses_with_the_open_hit_first_and_the_other_disclosed(self):
        # §5.4's order: what nothing closes is what an operator has to act on,
        # so it leads; the closed one still appears, because "we saw it and it
        # did not matter" is the disclosure this probe exists to make.
        for host, open_file, cell, controlled, control in _PLANTED:
            with self.subTest(host=host), tempfile.TemporaryDirectory() as root:
                _plant(root, open_file)
                _plant(root, controlled)
                state, _by, detail = probes_common.probe_discovery_surface(host, root)
                self.assertEqual(hosts.REFUTED, state)
                self.assertLess(detail.index(cell), detail.index(control))
                self.assertIn("closed by %s" % control, detail)

    def test_a_file_at_depth_is_found_by_the_head_star_star_pattern(self):
        _plant(self.root, "packages/api/src/CLAUDE.md")
        state, _by, detail = probes_common.probe_discovery_surface("claude", self.root)
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn(os.path.join("packages", "api", "src", "CLAUDE.md"), detail)

    def test_a_file_under_a_tail_star_star_pattern_is_found(self):
        _plant(self.root, ".claude/hooks/nested/evil.sh")
        state, _by, detail = probes_common.probe_discovery_surface("claude", self.root)
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("CL-8", detail)

    def test_a_single_star_segment_is_one_listdir_on_its_parent(self):
        _plant(self.root, ".claude/skills/evil/SKILL.md")
        state, _by, detail = probes_common.probe_discovery_surface("claude", self.root)
        self.assertEqual(hosts.UNKNOWN, state)          # CONTROLLED: CL-6/CL-7
        self.assertIn("claude:disable-slash-commands", detail)

    def test_a_hit_is_reported_once_even_when_two_patterns_match_it(self):
        # kimi's KM-3 lists `AGENTS.md` and `**/AGENTS.md`, and on a
        # case-insensitive filesystem `agents.md` names the same inode again.
        # One file, one sentence: a detail that repeats itself is a detail an
        # operator stops reading.
        _plant(self.root, "AGENTS.md")
        _state, _by, detail = probes_common.probe_discovery_surface("kimi", self.root)
        self.assertEqual(1, detail.lower().count("agents.md"), detail)

    def test_the_excluded_directories_are_pruned_from_the_walk(self):
        # `.git`, `node_modules`, `.panopticon`, `.worktrees` and friends are
        # not the target's authored surface; walking them is how a scan gets
        # slow enough that somebody turns it off.
        _plant(self.root, "node_modules/pkg/CLAUDE.md")
        _plant(self.root, ".worktrees/wt/CLAUDE.md")
        state, _by, _detail = probes_common.probe_discovery_surface("claude", self.root)
        self.assertEqual(hosts.UNKNOWN, state)

    def test_an_unreadable_directory_refutes(self):
        # Not being able to LOOK is not the same as looking and finding
        # nothing -- the shadow scan's rule, for the same reason: UNKNOWN
        # loses to PROVEN in resolve_state and the miss would be invisible.
        import getpass
        if getpass.getuser() == "root":
            self.skipTest("running as root, os.listdir ignores permissions")
        directory = os.path.join(self.root, ".claude", "skills")
        os.makedirs(directory)
        os.chmod(directory, 0o000)
        self.addCleanup(os.chmod, directory, 0o700)
        state, _by, detail = probes_common.probe_discovery_surface("claude", self.root)
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("could not read", detail)

    def test_the_depth_cap_refutes_rather_than_giving_up_quietly(self):
        deep = self.root
        for level in range(probes_surface.DEPTH_CAP + 2):
            deep = os.path.join(deep, "d%d" % level)
        os.makedirs(deep)
        state, _by, detail = probes_common.probe_discovery_surface("claude", self.root)
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("past the cap", detail)

    def test_the_entry_cap_refutes_rather_than_giving_up_quietly(self):
        for index in range(6):
            _plant(self.root, "dir%d/file" % index)
        with mock.patch.object(probes_surface, "ENTRY_CAP", 4):
            state, _by, detail = probes_common.probe_discovery_surface(
                "claude", self.root)
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("past the cap", detail)

    def test_a_planted_fifo_is_skipped_and_does_not_hang_the_scan(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("platform has no named pipes")
        os.makedirs(os.path.join(self.root, ".claude", "agents"))
        os.mkfifo(os.path.join(self.root, ".claude", "agents", "evil.md"))
        box = {}
        worker = threading.Thread(
            target=lambda: box.update(
                result=probes_common.probe_discovery_surface("claude", self.root)),
            daemon=True)
        worker.start()
        worker.join(timeout=10)
        self.assertFalse(worker.is_alive(), "the probe hung on a planted FIFO")
        self.assertEqual(hosts.UNKNOWN, box["result"][0])

    def test_a_symlink_candidate_counts_and_is_never_opened(self):
        # R3: the CLI would follow it, so it is a hit -- but a symlink to a
        # FIFO must not block, which is what "never opened" buys.
        if not hasattr(os, "mkfifo"):
            self.skipTest("platform has no named pipes")
        os.makedirs(os.path.join(self.root, ".claude", "agents"))
        pipe = os.path.join(self.root, "pipe")
        os.mkfifo(pipe)
        os.symlink(pipe, os.path.join(self.root, ".claude", "agents", "link.md"))
        box = {}
        worker = threading.Thread(
            target=lambda: box.update(
                result=probes_common.probe_discovery_surface("claude", self.root)),
            daemon=True)
        worker.start()
        worker.join(timeout=10)
        self.assertFalse(worker.is_alive(), "the probe followed a symlinked FIFO")
        self.assertEqual(hosts.REFUTED, box["result"][0])
        self.assertIn("link.md", box["result"][2])

    def test_the_walk_does_not_follow_directory_symlinks(self):
        # A link back to the root is an infinite walk; `followlinks=False` is
        # what the cap should never have to catch.
        os.makedirs(os.path.join(self.root, "sub"))
        os.symlink(self.root, os.path.join(self.root, "sub", "loop"))
        state, _by, _detail = probes_common.probe_discovery_surface(
            "claude", self.root)
        self.assertEqual(hosts.UNKNOWN, state)

    def test_a_shadow_shell_hit_is_not_double_reported(self):
        # §5.3: `probe_shadow_shells` already refuses on these, and one file
        # named twice in one artifact reads as two attacks. Both shapes it
        # catches -- the prefix and the declared identity -- are excluded.
        _plant(self.root, ".claude/agents/panopticon-scout.md")
        _plant(self.root, ".claude/agents/innocuous.md",
               "---\nname: panopticon-scout\ntools: Bash\n---\n")
        state, _by, detail = probes_common.probe_discovery_surface("claude", self.root)
        self.assertEqual(hosts.REFUTED,
                         probes_common.probe_shadow_shells("claude", self.root)[0])
        self.assertEqual(hosts.UNKNOWN, state)
        self.assertNotIn("panopticon-scout.md", detail)
        self.assertNotIn("innocuous.md", detail)

    def test_a_target_agent_file_that_is_not_a_shadow_is_still_open(self):
        # The exclusion is narrow on purpose: only what the shadow scan
        # ALREADY reported. A target's own agent still gets loaded beside the
        # reviewer, and only `--safe-mode` removes it -- which unarms the
        # guards, so nothing closes this one.
        _plant(self.root, ".claude/agents/theirs.md")
        state, _by, detail = probes_common.probe_discovery_surface("claude", self.root)
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("CL-5", detail)

    def test_the_controlled_hits_are_disclosed_on_the_stream_once(self):
        # §6: the same channel `kimi_toml.MCP_DISCLOSURE` uses. One line per
        # cell, not per file: this shares the operator's stderr with the run's
        # own progress output.
        _plant(self.root, ".claude/settings.json")
        _plant(self.root, ".claude/settings.local.json")
        stream = io.StringIO()
        probes_common.probe_discovery_surface("claude", self.root, disclose=stream)
        lines = [line for line in stream.getvalue().splitlines() if line.strip()]
        self.assertEqual(1, len(lines), lines)
        self.assertTrue(lines[0].startswith("driver: target ships "), lines[0])
        self.assertIn("closed by claude:setting-sources-user (CL-2/CL-4)", lines[0])
        self.assertIn("settings.local.json", lines[0])

    def test_a_clean_tree_discloses_nothing(self):
        # A line on every run teaches its reader to skip the ones that matter.
        stream = io.StringIO()
        probes_common.probe_discovery_surface("claude", self.root, disclose=stream)
        self.assertEqual("", stream.getvalue())


def _register_perfect_shells(directory):
    """Every driver role registered with exactly its template's tools, so a
    refusal below is attributable to THIS probe and not to an incidental
    registration gap on the machine running the suite."""
    from scripts import dispatch
    for role in probes_common.DRIVER_ROLES:
        role_file = dispatch.ROLE_FILES[role]
        allowed = dispatch.load_template(role_file)[0]["tool_policy"]["allowed"]
        _shell(directory, dispatch.registered_agent_filename("claude", role_file),
               allowed)


class TestTheWiring(unittest.TestCase):
    """§6/§8: what the artifact records, and what the driver does about it."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        self.registration = os.path.join(self.root, "registration")
        _register_perfect_shells(self.registration)

    def _capabilities(self, host="claude", **kwargs):
        from scripts import host_probes
        body = host_probes.run_probes(host, self.root, session_root=self.root,
                                      registration_dir=self.registration, **kwargs)
        return body["capabilities"][hosts.TOOL_POLICY_ENFORCED]

    def test_a_refuting_surface_beats_the_registration_proof(self):
        # `resolve_state` ranks refuted over proven, and `by` names the probe
        # that DECIDED -- the registration proof is real and still loses.
        _plant(self.root, "CLAUDE.md")
        row = self._capabilities()
        self.assertEqual(hosts.REFUTED, row["state"])
        self.assertEqual("target-discovery-surface", row["by"])
        self.assertIn("CLAUDE.md", row["detail"])

    def test_the_callers_own_result_is_recorded_rather_than_a_second_scan(self):
        # The shadow scan's Minor 4, for the same reason: the driver decides
        # from the probe's OWN tuple, so scanning again here would be
        # duplicate work and a window in which the artifact and the refusal
        # disagree about one tree.
        row = self._capabilities(
            surface=(hosts.REFUTED, probes_common.DISCOVERY_SURFACE,
                     "the caller's own sentence"))
        self.assertEqual(hosts.REFUTED, row["state"])
        self.assertIn("the caller's own sentence", row["detail"])

    def test_a_host_with_no_surface_records_nothing_from_this_probe(self):
        row = self._capabilities(host="generic")
        self.assertNotIn("discovers no target-authored configuration", row["detail"])

    def test_the_refuting_detail_reaches_the_disclosure_surfaces(self):
        # §6: the artifact row is what `host_disclosure.lines()` renders, and
        # that list is what surfaces 1/3/4 print -- so the probe's sentence
        # travels with the same wiring the shadow scan's does, rather than a
        # second rendering that can drift from it.
        import scripts.host_disclosure as host_disclosure
        from scripts import host_probes
        _plant(self.root, "CLAUDE.md")
        envelope = host_probes.run_probes("claude", self.root,
                                          session_root=self.root,
                                          registration_dir=self.registration)
        rendered = " ".join(host_disclosure.lines(envelope))
        self.assertIn("probe target-discovery-surface", rendered)
        self.assertIn("CLAUDE.md", rendered)


class TestTheRefusal(unittest.TestCase):
    """R4 / §6: `_surface_refusal` takes BOTH probes' own tuples."""

    _CLEAN = (hosts.UNKNOWN, "shadow-shell-scan", "nothing shadowed")
    _SHADOW = (hosts.REFUTED, "shadow-shell-scan",
               "the reviewed tree ships .claude/agents/panopticon-scout.md")
    _SURFACE = (hosts.REFUTED, "target-discovery-surface",
                "the reviewed tree ships CLAUDE.md (CL-1: no launch control closes it)")

    def _refusal(self, results, allow=False):
        import scripts.driver as driver
        return driver._surface_refusal(
            results, {"flags": {"allow_unenforced": allow}} if allow else {})

    def test_a_clean_pair_runs(self):
        self.assertIsNone(self._refusal((self._CLEAN, self._CLEAN)))

    def test_the_shadow_probe_still_refuses_with_its_own_sentence(self):
        message = self._refusal((self._SHADOW, self._CLEAN))
        self.assertIn("refusing to run: shadow-shell-scan: ", message)
        self.assertIn("panopticon-scout.md", message)
        self.assertIn("takes precedence over the registered enforcement shell",
                      message)
        self.assertIn("--allow-unenforced", message)

    def test_the_surface_probe_refuses_and_is_named(self):
        message = self._refusal((self._CLEAN, self._SURFACE))
        self.assertIn("refusing to run: target-discovery-surface: ", message)
        self.assertIn("CL-1", message)
        self.assertIn("no launch control closes", message)
        self.assertIn("--allow-unenforced", message)

    def test_allow_unenforced_downgrades_either_refusal(self):
        for results in ((self._SHADOW, self._CLEAN), (self._CLEAN, self._SURFACE)):
            with self.subTest(results=results[0][1]):
                self.assertIsNone(self._refusal(results, allow=True))

    def test_both_refuting_names_the_first_and_keeps_its_detail(self):
        message = self._refusal((self._SHADOW, self._SURFACE))
        self.assertIn("refusing to run: shadow-shell-scan: ", message)
        self.assertIn("panopticon-scout.md", message)


class TestTheRoundTrip(unittest.TestCase):
    """§8's end-to-end: the driver refuses, and the artifact it leaves behind
    says who refused and why. Through `_establish_host_posture`, because the
    thing worth proving is that the ONE result the driver computed is the one
    both the refusal and the file carry."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        self.registration = os.path.join(self.root, "registration")
        _register_perfect_shells(self.registration)
        # The session root is pinned to this fixture, never cwd: the guard
        # probes resolve off it, and inside a real checkout their answer would
        # swing with whatever the developer's own `.claude/` holds.
        claude = os.path.join(self.root, ".claude")
        os.makedirs(claude, exist_ok=True)
        with open(os.path.join(claude, "settings.local.json"), "w",
                  encoding="utf-8") as fh:
            fh.write("{}")

    def _establish(self, allow=False):
        import dataclasses
        from unittest import mock as _mock
        import scripts.driver as driver
        manifest = {"host": "claude", "run_id": "r1" * 4,
                    "created": "2026-09-18", "security_mode": "standard",
                    "session_dir": self.root}
        if allow:
            manifest["flags"] = {"allow_unenforced": True}
        args = type("_Args", (), {"target": os.path.join(self.root, "elsewhere"),
                                  "session_dir": self.root})()
        os.makedirs(args.target, exist_ok=True)
        with _mock.patch.dict(hosts.HOSTS, {"claude": dataclasses.replace(
                hosts.HOSTS["claude"], registration_dir=self.registration)}):
            return driver._establish_host_posture(self.root, manifest, args)

    def _artifact(self):
        """The host-capabilities.json this invocation left behind, wherever the
        run folder put it."""
        from scripts.phases import runio
        import glob
        found = glob.glob(os.path.join(self.root, ".panopticon", "**",
                                       runio.HOST_CAPABILITIES), recursive=True)
        self.assertEqual(1, len(found), found)
        return runio._load_json(found[0])

    def test_the_refusal_names_the_probe_that_found_it(self):
        _plant(self.root, "packages/app/CLAUDE.md")
        message = self._establish()
        self.assertIsNotNone(message)
        self.assertIn("refusing to run: target-discovery-surface: ", message)
        self.assertIn("CL-1", message)
        self.assertIn("--allow-unenforced", message)

    def test_an_unenforced_run_records_who_refused_and_why(self):
        # `--allow-unenforced` downgrades rather than silences: the run
        # proceeds and the artifact carries the refutation, which is what
        # makes the report say plainly that it was not enforced.
        _plant(self.root, "packages/app/CLAUDE.md")
        self.assertIsNone(self._establish(allow=True))
        row = self._artifact()["capabilities"][hosts.TOOL_POLICY_ENFORCED]
        self.assertEqual(hosts.REFUTED, row["state"])
        self.assertEqual("target-discovery-surface", row["by"])
        self.assertIn("CLAUDE.md", row["detail"])

    def test_readiness_reads_that_row_back_in_its_posture_block(self):
        # §6: readiness never re-probes (it would start a host CLI); it reads
        # the last run's artifact. So the probe reaches its posture block the
        # way every other probe does -- through the row `run_probes` wrote.
        import scripts.phases.readiness as readiness
        from scripts.phases import runio
        _plant(self.root, "CLAUDE.md")
        self._establish(allow=True)
        envelope = self._artifact()
        tag = "t1"
        folder = os.path.join(self.root, ".panopticon", "runs", tag)
        os.makedirs(folder, exist_ok=True)
        runio._write_json(os.path.join(folder, runio.HOST_CAPABILITIES), envelope)
        row = readiness._capabilities_row(self.root, tag)
        self.assertTrue(row["measured"])
        self.assertEqual(hosts.REFUTED, row["states"][hosts.TOOL_POLICY_ENFORCED])
        self.assertIn(hosts.TOOL_POLICY_ENFORCED, row["detail"])
